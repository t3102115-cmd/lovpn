<# Run elevated ON a disposable Windows lab VM. Never invoke remotely without console access.
Reboot continuation runs as SYSTEM. External hypervisor/switch capture covering power-on,
with independently generated traffic, is REQUIRED to assess the pre-BFE boot gap.
Local pktmon and postboot probes cannot prove absence of leakage before they start.
Sleep requires S1 and a working wake timer; otherwise report unsupported, not PASS.
DualNic requires two actual connected physical VM adapters and distinct lab uplinks.
#>
param(
    [ValidateSet('Reboot','Sleep','DualNic')][string]$Scenario,
    [Parameter(Mandatory)][string]$Dir,
    [string]$LoVpnPath = 'C:\Program Files\LoVPN\lovpn.exe',
    [string]$TunnelUrl = 'http://192.0.2.50:8080/',
    [string]$DirectUrl = 'http://1.1.1.1/',
    [string]$PrimaryAlias, [string]$SecondaryAlias,
    [string]$EndpointAddress, [int]$EndpointPort = 51820,
    [string[]]$AllowedLabAddresses = @(),
    [ValidateRange(180,900)][int]$WatchdogSeconds = 300,
    [switch]$LabOnlyRecovery, [switch]$ContinueBoot, [string]$ConfigPath
)
$ErrorActionPreference = 'Stop'
if (-not $LabOnlyRecovery) { throw 'Explicit -LabOnlyRecovery required; watchdog resets and releases protection.' }
. (Join-Path $PSScriptRoot 'vm-e2e-common.ps1')
if ($ConfigPath) {
    $c = Get-Content -LiteralPath $ConfigPath -Raw | ConvertFrom-Json
    $p = @{}; foreach ($v in $c.PSObject.Properties) { $p[$v.Name] = $v.Value }
    & $PSCommandPath @p -ContinueBoot -LabOnlyRecovery
    exit $LASTEXITCODE
}
if (-not $Scenario -or -not $EndpointAddress) { throw 'Scenario and EndpointAddress are required.' }
$identity = [Security.Principal.WindowsIdentity]::GetCurrent()
if (-not ([Security.Principal.WindowsPrincipal]::new($identity)).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) { throw 'Run elevated.' }
function Status {
    $r = Invoke-LabProcess $LoVpnPath @('--json','status') 10000
    if ($r.ExitCode -ne 0) { throw 'Status unavailable' }
    $r.Stdout | ConvertFrom-Json
}
function Assert-Armed($s) {
    if ($s.kill_switch -ne 'strict' -or $s.kill_switch_armed -ne $true -or $s.desired -ne 'connected') { throw 'Requires existing armed strict desired=connected; connect the imported lab profile first.' }
}
function Native([string]$exe, [string[]]$arguments) {
    $r = Invoke-LabProcess $exe $arguments 15000
    if ($r.ExitCode -ne 0) { throw "$exe failed: $($r.Stderr) $($r.Stdout)" }
    $r.Stdout
}
$powershell = "$env:SystemRoot\System32\WindowsPowerShell\v1.0\powershell.exe"
if (-not $ContinueBoot) {
    if (Test-Path -LiteralPath $Dir) { throw 'Use a fresh output directory for each run.' }
    New-Item -ItemType Directory -Path $Dir | Out-Null
    $Dir = (Resolve-Path $Dir).Path
    # Stage all dependencies: no user profile, mapped drive, or credentials needed at boot.
    foreach ($f in @('lifecycle-gate.ps1','lifecycle-probes.ps1','lifecycle-recover.ps1','vm-e2e-common.ps1','vm-e2e-recover.ps1')) {
        Copy-Item -LiteralPath (Join-Path $PSScriptRoot $f) -Destination $Dir
    }
    & icacls.exe $Dir /inheritance:r /grant:r '*S-1-5-18:(OI)(CI)F' '*S-1-5-32-544:(OI)(CI)F' | Out-Null
    if ($LASTEXITCODE -ne 0) { throw 'Cannot secure SYSTEM staging directory' }
    $s = Status; Assert-Armed $s
    if ($s.state -ne 'protected') { throw 'Start from protected state.' }
    $s | ConvertTo-Json -Depth 12 | Set-Content (Join-Path $Dir 'before.json')
    $id = [guid]::NewGuid().ToString('N')
    $recovery = 'LoVPN-Lifecycle-Recovery-' + $id
    $boot = 'LoVPN-Lifecycle-Boot-' + $id
    $config = @{ Scenario=$Scenario; Dir=$Dir; LoVpnPath=$LoVpnPath; TunnelUrl=$TunnelUrl; DirectUrl=$DirectUrl; PrimaryAlias=$PrimaryAlias; SecondaryAlias=$SecondaryAlias; EndpointAddress=$EndpointAddress; EndpointPort=$EndpointPort; AllowedLabAddresses=$AllowedLabAddresses; WatchdogSeconds=$WatchdogSeconds }
    $config | ConvertTo-Json | Set-Content (Join-Path $Dir 'config.json')
    $action = New-ScheduledTaskAction -Execute $powershell -Argument "-NoProfile -NonInteractive -ExecutionPolicy Bypass -File `"$Dir\lifecycle-recover.ps1`" -Dir `"$Dir`" -LabOnlyRecovery"
    Register-ScheduledTask -TaskName $recovery -Action $action -Trigger (New-ScheduledTaskTrigger -Once -At (Get-Date).AddSeconds($WatchdogSeconds)) -User SYSTEM -RunLevel Highest -Settings (New-ScheduledTaskSettingsSet -StartWhenAvailable -WakeToRun -ExecutionTimeLimit (New-TimeSpan -Minutes 2)) | Out-Null
    @{ recovery=$recovery; boot=$boot; bootTime=(Get-CimInstance Win32_OperatingSystem).LastBootUpTime.ToString('o'); deadline=(Get-Date).AddSeconds($WatchdogSeconds).ToString('o') } | ConvertTo-Json | Set-Content (Join-Path $Dir 'tasks.json')
    if ($Scenario -eq 'Reboot') {
        $action = New-ScheduledTaskAction -Execute $powershell -Argument "-NoProfile -NonInteractive -ExecutionPolicy Bypass -File `"$Dir\lifecycle-gate.ps1`" -Dir `"$Dir`" -ConfigPath `"$Dir\config.json`" -LabOnlyRecovery"
        Register-ScheduledTask -TaskName $boot -Action $action -Trigger (New-ScheduledTaskTrigger -AtStartup) -User SYSTEM -RunLevel Highest -Settings (New-ScheduledTaskSettingsSet -StartWhenAvailable -ExecutionTimeLimit (New-TimeSpan -Minutes 2)) | Out-Null
        # No disconnect/reset here: persist desired=connected and armed strict across shutdown.
        Assert-Armed (Status)
        Set-Content (Join-Path $Dir 'reboot-requested.txt') 'Local postboot evidence cannot prove pre-BFE gap. External continuous capture prerequisite remains outstanding.'
        Restart-Computer -Force
        return
    }
}
$tasks = Get-Content (Join-Path $Dir 'tasks.json') -Raw | ConvertFrom-Json
$receipt = @{ scenario=$Scenario; started=(Get-Date -Format o); success=$false; evidenceLimit='Local capture only while pktmon active; reboot pre-BFE gap and sleep interval require external capture. No full Phase4 certification.' }
$capture = $false; $probeProcess = $null; $disabled = $false
try {
    if ($ContinueBoot) {
        if ((Get-CimInstance Win32_OperatingSystem).LastBootUpTime.ToString('o') -eq $tasks.bootTime) { throw 'Continuation did not follow an actual reboot' }
        Unregister-ScheduledTask -TaskName $tasks.boot -Confirm:$false
    }
    Native 'pktmon.exe' @('start','--capture','--comp','nics','--pkt-size','0','--file-name',"$Dir\transition.etl") | Out-Null
    $capture = $true; Set-Content (Join-Path $Dir 'capture.active') 'active'
    $probeProcess = Start-Process $powershell -ArgumentList "-NoProfile -NonInteractive -ExecutionPolicy Bypass -File `"$Dir\lifecycle-probes.ps1`" -Dir `"$Dir`" -TunnelUrl `"$TunnelUrl`" -DirectUrl `"$DirectUrl`" -Seconds 120" -PassThru
    $end = (Get-Date).AddSeconds(10)
    while (-not (Test-Path "$Dir\probes.ready") -and (Get-Date) -lt $end) { Start-Sleep -Milliseconds 200 }
    if (-not (Test-Path "$Dir\probes.ready")) { throw 'Independent probes did not start' }
    Start-Sleep -Seconds 5
    if ($Scenario -eq 'DualNic') {
        if (-not $PrimaryAlias -or -not $SecondaryAlias -or $PrimaryAlias -eq $SecondaryAlias) { throw 'Provide distinct PrimaryAlias and SecondaryAlias' }
        $a = Get-NetAdapter -Name $PrimaryAlias; $b = Get-NetAdapter -Name $SecondaryAlias
        if (-not $a.HardwareInterface -or -not $b.HardwareInterface -or $a.Status -ne 'Up' -or $b.Status -ne 'Up') { throw 'Both physical VM NICs must be Up' }
        Get-NetRoute -DestinationPrefix '0.0.0.0/0' | ConvertTo-Json -Depth 5 | Set-Content "$Dir\routes-before.json"
        if (-not (Get-NetRoute -InterfaceIndex $b.ifIndex -DestinationPrefix '0.0.0.0/0' -ErrorAction SilentlyContinue)) { throw 'Secondary NIC requires a real default gateway' }
        Disable-NetAdapter -Name $PrimaryAlias -Confirm:$false; $disabled = $true
        if ((Get-NetAdapter -Name $PrimaryAlias).Status -ne 'Disabled') { throw 'Primary NIC did not disable' }
        $receipt.transition = 'Primary physical NIC disabled; secondary remained enabled'
    } elseif ($Scenario -eq 'Sleep') {
        $caps = Native 'powercfg.exe' @('/a'); $caps | Set-Content "$Dir\sleep-capabilities.txt"
        # Conservative localized-output gate; operator may need English Windows for S1 detection.
        $available = ($caps -split 'The following sleep states are not available')[0]
        if ($available -notmatch 'The following sleep states are available' -or $available -notmatch '(?m)^\s*Standby \(S1\)\s*$') { throw 'S1 not positively detected; unsupported/inconclusive' }
        $wakeName = $tasks.recovery + '-Wake'
        $wakeAction = New-ScheduledTaskAction -Execute $powershell -Argument "-NoProfile -NonInteractive -Command `"Set-Content -LiteralPath '$Dir\wake-receipt.txt' -Value (Get-Date -Format o)`""
        Register-ScheduledTask -TaskName $wakeName -Action $wakeAction -Trigger (New-ScheduledTaskTrigger -Once -At (Get-Date).AddSeconds(20)) -User SYSTEM -RunLevel Highest -Settings (New-ScheduledTaskSettingsSet -WakeToRun -StartWhenAvailable -ExecutionTimeLimit (New-TimeSpan -Minutes 1)) | Out-Null
        Add-Type -TypeDefinition 'using System.Runtime.InteropServices; public static class LifecycleSleep { [DllImport("powrprof.dll", SetLastError=true)] public static extern bool SetSuspendState(bool hibernate, bool force, bool disableWake); }'
        $receipt.suspendRequested = (Get-Date -Format o)
        if (-not [LifecycleSleep]::SetSuspendState($false,$false,$false)) { throw 'Suspend request failed' }
        $receipt.resumed = (Get-Date -Format o)
        Unregister-ScheduledTask -TaskName $wakeName -Confirm:$false
        Get-WinEvent -FilterHashtable @{LogName='System'; ProviderName='Microsoft-Windows-Power-Troubleshooter'; StartTime=[datetime]$receipt.suspendRequested} -ErrorAction Stop | Select-Object -First 3 TimeCreated,Id,Message | ConvertTo-Json | Set-Content "$Dir\resume-events.json"
    }
    $end = (Get-Date).AddSeconds(60)
    do { $s = Status; Assert-Armed $s; $s | ConvertTo-Json -Depth 12 | Set-Content "$Dir\after.json"; if ($s.state -eq 'protected') { break }; Start-Sleep -Seconds 2 } while ((Get-Date) -lt $end)
    if ($s.state -ne 'protected') { throw 'Protected state did not recover' }
    Start-Sleep -Seconds 10
    Set-Content "$Dir\probes.stop" 'stop'
    if (-not $probeProcess.WaitForExit(10000) -or $probeProcess.ExitCode -ne 0) { throw 'Independent probe process failed' }
    $probes = @(Get-Content "$Dir\probes.jsonl" | ForEach-Object { $_ | ConvertFrom-Json })
    if (@($probes | Where-Object { $_.probe -eq 'direct' -and $_.exit -eq 0 }).Count) { throw 'Direct probe unexpectedly succeeded' }
    if (-not @($probes | Where-Object { $_.probe -eq 'tunnel' -and $_.exit -eq 0 }).Count) { throw 'No tunnel positive control' }
    Native 'pktmon.exe' @('stop') | Out-Null; $capture = $false
    Remove-Item "$Dir\capture.active"
    Native 'pktmon.exe' @('etl2txt',"$Dir\transition.etl",'-o',"$Dir\transition.txt") | Out-Null
    $analysis = Read-LabCapture -Lines (Get-Content "$Dir\transition.txt") -PhysicalMacs @(Get-NetAdapter -Physical | ForEach-Object { $_.MacAddress.ToUpper() }) -AllowedLabAddresses $AllowedLabAddresses -EndpointAddress $EndpointAddress -EndpointPort $EndpointPort
    $analysis | ConvertTo-Json -Depth 5 | Set-Content "$Dir\capture-analysis.json"
    if ($analysis.Frames -eq 0 -or $analysis.Transport -eq 0 -or $analysis.Bad.Count -ne 0) { throw 'Capture empty, missing transport, or contains unexpected frames' }
    if ($Scenario -eq 'DualNic') {
        $secondaryCapture = Read-LabCapture -Lines (Get-Content "$Dir\transition.txt") -PhysicalMacs @($b.MacAddress.ToUpper()) -AllowedLabAddresses $AllowedLabAddresses -EndpointAddress $EndpointAddress -EndpointPort $EndpointPort
        $secondaryCapture | ConvertTo-Json -Depth 5 | Set-Content "$Dir\secondary-capture-analysis.json"
        if ($secondaryCapture.Transport -eq 0) { throw 'No observed transport on the real secondary NIC' }
    }
    $receipt.success = $true
} catch { $receipt.error = $_.Exception.Message } finally {
    Set-Content "$Dir\probes.stop" 'stop'
    if ($capture) { & pktmon.exe stop | Out-Null }
    if ($disabled) { Enable-NetAdapter -Name $PrimaryAlias -Confirm:$false }
    $receipt.finished = (Get-Date -Format o)
    $receipt | ConvertTo-Json -Depth 6 | Set-Content "$Dir\lifecycle-receipt.json"
    # Explicit lab recovery only AFTER evidence collection; retain watchdog if recovery fails.
    try {
        & "$Dir\vm-e2e-recover.ps1" -LoVpnPath $LoVpnPath -ReceiptPath "$Dir\recovery.json" -LabOnlyRecovery
        Unregister-ScheduledTask -TaskName $tasks.recovery -Confirm:$false
    } catch { Add-Content "$Dir\cleanup-error.txt" $_.Exception.Message }
}
if (-not $receipt.success) { throw "Lifecycle gate failed: $($receipt.error)" }
