<# Run elevated ON an isolated Windows lab VM. Task execution is independent of SSH.
   ProfilePath must refer to the existing imported lab profile, readable by SYSTEM.
   Use a unique OutputDirectory for every run. Recovery intentionally releases WFP.
#>
param(
    [Parameter(Mandatory)][string]$ProfilePath,
    [Parameter(Mandatory)][string]$OutputDirectory,
    [string]$Profile = 'vm', [string]$TunnelAlias = 'lovpn0',
    [string]$EndpointAddress = '172.16.8.1', [int]$EndpointPort = 51820,
    [string]$DecoyAddress = '192.0.2.50', [int]$DecoyPort = 8080,
    [string]$BaselineUrl = 'http://1.1.1.1/',
    [string[]]$AllowedLabAddresses = @('172.16.8.129','192.168.8.128','172.16.8.1','172.16.8.2','255.255.255.255','172.16.8.255','192.168.8.255'),
    [string]$LoVpnPath = 'C:\Program Files\LoVPN\lovpn.exe',
    [ValidateRange(600,3600)][int]$WatchdogSeconds = 900,
    [switch]$LabOnlyRecovery
)
$ErrorActionPreference = 'Stop'
if (-not $LabOnlyRecovery) { throw 'Use -LabOnlyRecovery only on a disposable isolated lab VM.' }
$principal = [Security.Principal.WindowsPrincipal]::new([Security.Principal.WindowsIdentity]::GetCurrent())
if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) { throw 'Run elevated.' }
$ProfilePath = (Resolve-Path -LiteralPath $ProfilePath).Path
if (Test-Path -LiteralPath $OutputDirectory) { throw 'Choose a fresh output directory for this run.' }
New-Item -ItemType Directory -Path $OutputDirectory | Out-Null
$OutputDirectory = (Resolve-Path -LiteralPath $OutputDirectory).Path
# Prevent non-admin modification of the SYSTEM task configuration and receipts.
& icacls.exe $OutputDirectory /inheritance:r /grant:r '*S-1-5-18:(OI)(CI)F' '*S-1-5-32-544:(OI)(CI)F' | Out-Null
if ($LASTEXITCODE -ne 0) { throw 'Could not secure output directory.' }
$config = @{}
foreach ($key in @('ProfilePath','Profile','TunnelAlias','EndpointAddress','EndpointPort','DecoyAddress','DecoyPort','BaselineUrl','AllowedLabAddresses','LoVpnPath','WatchdogSeconds')) { $config[$key] = Get-Variable -Name $key -ValueOnly }
# Strip PowerShell pipeline ETS metadata before JSON serialization. Otherwise Windows
# PowerShell can encode an array as {value: [...], Count: ...}, losing the allowlist.
$config['AllowedLabAddresses'] = @($AllowedLabAddresses | ForEach-Object { [string]$_ })
$config.Dir = $OutputDirectory; $config.LabOnlyRecovery = $true
$configPath = Join-Path $OutputDirectory 'run-config.json'
$config | ConvertTo-Json | Set-Content -LiteralPath $configPath
# Stage scripts in the secured directory so SYSTEM never executes user-writable code.
foreach ($file in @('vm-e2e.ps1','vm-e2e-recover.ps1','vm-e2e-common.ps1')) { Copy-Item -LiteralPath (Join-Path $PSScriptRoot $file) -Destination $OutputDirectory }
$taskName = 'LoVPN-Lab-E2E-' + [guid]::NewGuid().ToString('N')
$action = New-ScheduledTaskAction -Execute "$env:SystemRoot\System32\WindowsPowerShell\v1.0\powershell.exe" -Argument "-NoProfile -NonInteractive -ExecutionPolicy Bypass -File `"$(Join-Path $OutputDirectory 'vm-e2e.ps1')`" -ConfigPath `"$configPath`""
$settings = New-ScheduledTaskSettingsSet -ExecutionTimeLimit (New-TimeSpan -Seconds ($WatchdogSeconds - 30)) -StartWhenAvailable
Register-ScheduledTask -TaskName $taskName -Action $action -Settings $settings -User SYSTEM -RunLevel Highest | Out-Null
[pscustomobject]@{ task = $taskName; outputDirectory = $OutputDirectory; submitted = (Get-Date -Format o) } | ConvertTo-Json | Set-Content (Join-Path $OutputDirectory 'launch.json')
Start-ScheduledTask -TaskName $taskName
$deadline = (Get-Date).AddSeconds(30)
do {
    if (Test-Path (Join-Path $OutputDirectory 'ready.json')) { Get-Content (Join-Path $OutputDirectory 'launch.json'); return }
    Start-Sleep -Seconds 1
} while ((Get-Date) -lt $deadline)
throw "Task submitted ($taskName), but startup receipt absent after 30s. Inspect task and output; do not relaunch blindly."
