<#
.SYNOPSIS
Install/upgrade a built LoVPN MSI, or uninstall it. Run elevated.
.DESCRIPTION
State and DPAPI keys are preserved. Firewall release is opt-in on uninstall only.
Build the MSI with scripts/build-msi.ps1; see packaging/windows/README.md.
#>
param(
    [string]$MsiPath = '',
    [switch]$Uninstall,
    [switch]$ReleaseFirewall,
    [switch]$Purge,
    [switch]$WhatIfOnly,
    [string]$LogPath = (Join-Path $env:TEMP 'lovpn-msi.log')
)
$ErrorActionPreference = 'Stop'
function Assert-CompatibleInstallation {
    $dir = Join-Path $env:ProgramFiles 'LoVPN'
    $manifest = Join-Path $dir 'compatibility.json'
    if (-not (Test-Path -LiteralPath $manifest -PathType Leaf)) { throw 'Historical/unmanaged binary: do not start or release an NRPT record. Reviewed migration required.' }
    foreach ($path in @($dir, $manifest, (Join-Path $dir 'lovpn-service.exe'))) {
        if ((Get-Item -LiteralPath $path).Attributes -band [IO.FileAttributes]::ReparsePoint) { throw 'Installer paths must not be reparse points.' }
    }
    $capability = Get-Content -Raw -LiteralPath $manifest | ConvertFrom-Json
    if ($capability.record_schema -ne 2 -or $capability.nrpt_journal -ne $true) { throw 'Service lacks declared NRPT v2 compatibility.' }
    $hash = (Get-FileHash -Algorithm SHA256 -LiteralPath (Join-Path $dir 'lovpn-service.exe')).Hash
    if ($hash -ne $capability.service_sha256) { throw 'Service differs from reviewed compatibility manifest; refusing execution.' }
    $state = Join-Path $env:ProgramData 'LoVPN'
    if (Test-Path -LiteralPath $state) {
        if ((Get-Item -LiteralPath $state).Attributes -band [IO.FileAttributes]::ReparsePoint) { throw 'State directory must not be a reparse point.' }
        $record = Join-Path $state 'session.json'
        if (Test-Path -LiteralPath $record) {
            $item = Get-Item -LiteralPath $record
            if ($item.Length -gt 32768 -or ($item.Attributes -band [IO.FileAttributes]::ReparsePoint)) { throw 'Unsafe/unreadable session record; protection left intact.' }
            $session = Get-Content -Raw -LiteralPath $record | ConvertFrom-Json
            if ($session.schema_version -notin @(1, 2)) { throw 'Unknown record schema; protection left intact.' }
            if ($null -ne $session.nrpt -and $session.schema_version -ne 2) { throw 'Invalid NRPT schema; protection left intact.' }
        }
    }
    # The daemon validates the complete journal. This preflight never rewrites it.
}
function Invoke-ScChecked([string[]]$Arguments) {
    & sc.exe @Arguments | Out-Host
    if ($LASTEXITCODE -ne 0) { throw "Service configuration failed ($LASTEXITCODE)." }
}
if ($Purge) { throw 'Automatic state purge is unsupported. Preserve keys; delete ProgramData\LoVPN manually only after explicit recovery and uninstall.' }
if ($ReleaseFirewall -and -not $Uninstall) { throw '-ReleaseFirewall requires -Uninstall.' }
if (-not (Test-Path -LiteralPath $MsiPath -PathType Leaf)) { throw 'Pass -MsiPath <built LoVPN MSI>.' }
$MsiPath = (Resolve-Path -LiteralPath $MsiPath).Path
Write-Host "Plan: $(if ($Uninstall) {'uninstall'} else {'install/upgrade'}) $MsiPath; preserve state and keys; release firewall=$ReleaseFirewall"
if ($WhatIfOnly) { return }
$principal = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())
if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) { throw 'Run elevated.' }
$service = Get-Service LoVPNClient -ErrorAction SilentlyContinue
if ($service) {
    Assert-CompatibleInstallation
    $image = (Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Services\LoVPNClient').ImagePath
    $expected = '"' + (Join-Path $env:ProgramFiles 'LoVPN\lovpn-service.exe') + '" service'
    if ($image -ne $expected) { throw 'Unmanaged service ImagePath; refusing takeover.' }
    # Disable boot/recovery starts before stopping. On MSI failure leave it stopped.
    Invoke-ScChecked -Arguments @('config', 'LoVPNClient', 'start=', 'disabled')
    Invoke-ScChecked -Arguments @('failure', 'LoVPNClient', 'reset=', '86400', 'actions=', 'none/0/none/0/none/0')
    Stop-Service LoVPNClient -ErrorAction Stop
    $service.WaitForStatus('Stopped', [TimeSpan]::FromSeconds(60))
    Assert-CompatibleInstallation
}
if ($ReleaseFirewall) {
    Assert-CompatibleInstallation
    & (Join-Path $env:ProgramFiles 'LoVPN\lovpn-service.exe') release
    if ($LASTEXITCODE -ne 0) { throw 'Firewall recovery failed; uninstall aborted.' }
}
$operation = if ($Uninstall) { '/x' } else { '/i' }
$arguments = @($operation, "`"$MsiPath`"", '/qn', '/norestart', '/L*v', "`"$LogPath`"")
$process = Start-Process msiexec.exe -ArgumentList $arguments -Wait -PassThru
if ($process.ExitCode -notin @(0, 3010)) { throw "MSI failed ($($process.ExitCode)); inspect $LogPath. No service is deliberately restarted. Verify compatibility before recovery. Explicit release is not rolled back." }
if ($process.ExitCode -eq 3010) { Write-Host 'Installation requires a reboot.' }
if (-not $Uninstall -and $process.ExitCode -eq 0) {
    Assert-CompatibleInstallation
    Invoke-ScChecked -Arguments @('config', 'LoVPNClient', 'start=', 'auto')
    Invoke-ScChecked -Arguments @('failure', 'LoVPNClient', 'reset=', '86400', 'actions=', 'restart/5000/restart/30000/none/0')
    Start-Service LoVPNClient -ErrorAction Stop
}
Write-Host 'MSI operation completed. State and keys retained.'
