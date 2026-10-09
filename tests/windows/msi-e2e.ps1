<# Run only inside a fresh, disposable Windows VM, elevated, after taking a snapshot.
   Builds must use current NRPT v2 binaries. UpgradeMsi MUST be built with -TestHooks.
   Example (Windows PowerShell 5.1):
   .\tests\windows\msi-e2e.ps1 -BaseMsi C:\fixtures\base.msi `
     -UpgradeMsi C:\fixtures\upgrade-test.msi -ProfileFile C:\fixtures\test.toml `
     -ExpectedServerKey '<public server key>' -ConfirmDisposableVm
   Never run on a production host. Leaves the upgraded installation and evidence in place.
   Existing services/state/products are refused, including legacy vm-e2e installations.
   An operator must snapshot/back up and review migration separately, or provision a clean VM.
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory=$true)][string]$BaseMsi,
    [Parameter(Mandatory=$true)][string]$UpgradeMsi,
    [Parameter(Mandatory=$true)][string]$ProfileFile,
    [Parameter(Mandatory=$true)][string]$ExpectedServerKey,
    [string]$EvidenceDir = (Join-Path $env:TEMP ('lovpn-msi-' + [guid]::NewGuid())),
    [switch]$ConfirmDisposableVm
)
$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest
if (-not $ConfirmDisposableVm) { throw 'Explicit -ConfirmDisposableVm consent required; use an isolated disposable VM snapshot.' }
if ($env:OS -ne 'Windows_NT') { throw 'Windows VM required.' }
$identity = [Security.Principal.WindowsIdentity]::GetCurrent()
if (-not ([Security.Principal.WindowsPrincipal]$identity).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) { throw 'Run elevated.' }
$state = Join-Path $env:ProgramData 'LoVPN'
$install = Join-Path $env:ProgramFiles 'LoVPN'
$cli = Join-Path $install 'lovpn.exe'
$service = Join-Path $install 'lovpn-service.exe'
if ((Get-Service LoVPNClient -ErrorAction SilentlyContinue) -or (Test-Path $state) -or (Test-Path $install) -or (Test-Path 'HKLM:\Software\LoVPN\Installer')) {
    throw 'Existing installation/state refused. Legacy VM installs cannot be adopted: use a separate clean VM or an operator-reviewed migration outside this test.'
}
foreach ($path in @($BaseMsi, $UpgradeMsi, $ProfileFile)) {
    if (-not (Test-Path -LiteralPath $path -PathType Leaf)) { throw "Missing input: $path" }
}
$BaseMsi = (Resolve-Path -LiteralPath $BaseMsi).Path
$UpgradeMsi = (Resolve-Path -LiteralPath $UpgradeMsi).Path
$ProfileFile = (Resolve-Path -LiteralPath $ProfileFile).Path
$installer = New-Object -ComObject WindowsInstaller.Installer
function Read-Msi($path) {
    $db = $installer.OpenDatabase($path, 0)
    $properties = @{}
    $view = $db.OpenView('SELECT `Property`, `Value` FROM `Property`')
    $null = $view.Execute()
    while ($row = $view.Fetch()) { $properties[$row.StringData(1)] = $row.StringData(2) }
    $null = $view.Close()
    $view = $db.OpenView("SELECT ``Action`` FROM ``CustomAction`` WHERE ``Action`` = 'TestFail'")
    $null = $view.Execute(); $hook = $null -ne $view.Fetch(); $null = $view.Close()
    return @{ Version = [version]$properties.ProductVersion; Product = $properties.ProductCode; Upgrade = $properties.UpgradeCode; Hook = $hook }
}
$base = Read-Msi $BaseMsi; $upgrade = Read-Msi $UpgradeMsi
if ($base.Upgrade -ne '{BF421991-3830-485A-B38A-31B48F788D61}' -or $upgrade.Upgrade -ne $base.Upgrade -or $upgrade.Version -le $base.Version -or $upgrade.Product -eq $base.Product -or -not $upgrade.Hook) {
    throw 'Require related LoVPN packages with distinct ProductCodes, strictly increasing versions and upgrade TestHooks.'
}
# Related MSI products must also be absent, even if their files/service were removed.
if (@($installer.RelatedProducts($base.Upgrade)).Count -gt 0) { throw 'Registered LoVPN MSI product found; clean VM required.' }
if (Test-Path -LiteralPath $EvidenceDir) { throw 'EvidenceDir must be new.' }
$null = New-Item -ItemType Directory -Path $EvidenceDir
$script:receipts = @()
function Msi($name, $package, [string[]]$properties, [int]$expected) {
    $log = Join-Path $EvidenceDir ($name + '.log')
    $arguments = @('/i', ('"' + $package + '"'), '/qn', '/norestart', '/L*v', ('"' + $log + '"')) + $properties
    $process = Start-Process -FilePath "$env:SystemRoot\System32\msiexec.exe" -ArgumentList $arguments -Wait -PassThru
    $script:receipts += @{ phase = $name; native_exit_code = $process.ExitCode; expected = $expected }
    $script:receipts | ConvertTo-Json | Set-Content (Join-Path $EvidenceDir 'msi-return-codes.json')
    if ($process.ExitCode -ne $expected) { throw "$name returned native MSI code $($process.ExitCode), expected $expected. Inspect $log. Reboot-required codes are not silently accepted." }
}
function Cli([string[]]$arguments) {
    $output = & $cli @arguments
    if ($LASTEXITCODE -ne 0) { throw "CLI failed ($LASTEXITCODE)." }
    return $output
}
function Snapshot-State {
    $result = @{}
    foreach ($file in Get-ChildItem -LiteralPath $state -Recurse -File) {
        if ($file.Extension -in @('.key', '.toml') -or $file.Name -eq 'service.json') {
            $result[$file.FullName.Substring($state.Length)] = (Get-FileHash -LiteralPath $file.FullName -Algorithm SHA256).Hash
        }
    }
    if (@($result.Keys | Where-Object { $_ -like '*.key' }).Count -eq 0 -or @($result.Keys | Where-Object { $_ -like '*.toml' }).Count -eq 0) { throw 'Real key/profile baseline missing.' }
    return $result
}
function Assert-Preserved {
    $now = Snapshot-State
    if ($now.Count -ne $baseline.Count) { throw 'Persistent state file set changed.' }
    foreach ($key in $baseline.Keys) { if (-not $now.ContainsKey($key) -or $now[$key] -ne $baseline[$key]) { throw 'Persistent key/profile/owner state changed.' } }
}
function Assert-Recovery($phase) {
    Start-Service LoVPNClient
    $deadline = (Get-Date).AddSeconds(30)
    do {
        try { $status = (Cli @('--json', 'status')) | ConvertFrom-Json } catch { $status = $null }
        if ($null -ne $status -and $status.state -eq 'disconnected' -and -not $status.kill_switch_armed) { break }
        Start-Sleep -Seconds 1
    } while ((Get-Date) -lt $deadline)
    if ($null -eq $status -or $status.state -ne 'disconnected' -or $status.kill_switch_armed) { throw "$phase did not recover to disconnected/unarmed." }
    # Record only recovery fields, never private keys or full diagnostics.
    @{ phase = $phase; state = $status.state; kill_switch_armed = $status.kill_switch_armed } | ConvertTo-Json | Set-Content (Join-Path $EvidenceDir ($phase + '-status.json'))
    Stop-Service LoVPNClient
    & $service release | Out-Null
    if ($LASTEXITCODE -ne 0) { throw "$phase offline release failed ($LASTEXITCODE)." }
    Start-Service LoVPNClient
    $deadline = (Get-Date).AddSeconds(30)
    do {
        try { $status = (Cli @('--json', 'status')) | ConvertFrom-Json } catch { $status = $null }
        if ($null -ne $status -and $status.state -eq 'disconnected' -and -not $status.kill_switch_armed) { break }
        Start-Sleep -Seconds 1
    } while ((Get-Date) -lt $deadline)
    if ($null -eq $status -or $status.state -ne 'disconnected' -or $status.kill_switch_armed) { throw "$phase restart after offline release did not recover." }
}
try {
    Msi 'install' $BaseMsi @() 0
    if ((Get-ItemProperty 'HKLM:\Software\LoVPN\Installer').RecordSchema -ne '2' -or (Get-Content (Join-Path $install 'compatibility.json') -Raw | ConvertFrom-Json).record_schema -ne 2) { throw 'Base MSI is not NRPT v2 compatible.' }
    Assert-Recovery 'fresh-install'
    $null = Cli @('identity', 'generate', '--name', 'msi-e2e')
    $null = Cli @('profile', 'import', $ProfileFile, '--name', 'msi-e2e', '--expect-server-key', $ExpectedServerKey)
    $baseline = Snapshot-State
    $baseline | ConvertTo-Json | Set-Content (Join-Path $EvidenceDir 'state-sha256-baseline.json')
    $binaries = @{}
    foreach ($file in Get-ChildItem $install -File | Where-Object { $_.Extension -in @('.exe', '.dll') }) { $binaries[$file.Name] = (Get-FileHash $file.FullName).Hash }
    Assert-Recovery 'installed'
    Msi 'injected-upgrade-rollback' $UpgradeMsi @('LOVPN_TEST_FAIL=1') 1603
    if (-not (Select-String -LiteralPath (Join-Path $EvidenceDir 'injected-upgrade-rollback.log') -Pattern 'Action ended .*TestFail\. Return value 3' -Quiet)) { throw '1603 was not caused by the injected TestFail action.' }
    if ($installer.ProductState($base.Product) -ne 5 -or $installer.ProductState($upgrade.Product) -eq 5) { throw 'Rollback product registration mismatch.' }
    foreach ($name in $binaries.Keys) { if ((Get-FileHash (Join-Path $install $name)).Hash -ne $binaries[$name]) { throw 'Rollback did not restore original binaries.' } }
    Assert-Preserved
    Assert-Recovery 'rolled-back'
    Msi 'compatible-upgrade' $UpgradeMsi @() 0
    if ($installer.ProductState($upgrade.Product) -ne 5 -or $installer.ProductState($base.Product) -eq 5) { throw 'Upgrade product registration mismatch.' }
    Assert-Preserved
    Assert-Recovery 'upgraded'
    Msi 'downgrade-refused' $BaseMsi @() 1603
    if ($installer.ProductState($upgrade.Product) -ne 5) { throw 'Downgrade changed installed product.' }
    Assert-Preserved
    Assert-Recovery 'downgrade-refused'
    Set-Content (Join-Path $EvidenceDir 'result.txt') 'PASS: install, injected upgrade rollback, compatible upgrade, downgrade refusal, offline release and state preservation.'
    Write-Output "PASS: evidence in $EvidenceDir"
} catch {
    Set-Content (Join-Path $EvidenceDir 'result.txt') ('FAIL: ' + $_.Exception.Message)
    throw
}
