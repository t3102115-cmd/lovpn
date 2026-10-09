param(
    [Parameter(Mandatory=$true)][string]$Version,
    [Parameter(Mandatory=$true)][string]$DriverDll,
    [string]$SourceDir = (Join-Path $PSScriptRoot '..\target\release'),
    [string]$Output = (Join-Path $PSScriptRoot '..\target\LoVPN.msi'),
    [switch]$TestHooks,
    [switch]$ConfirmNrptV2Build
)
$ErrorActionPreference = 'Stop'
if (-not $ConfirmNrptV2Build) { throw 'Build current source and review NRPT v2 startup/offline recovery, then pass -ConfirmNrptV2Build. Historical binaries are unsafe.' }
$wixVersion = (& wix --version | Out-String).Trim()
if ($LASTEXITCODE -ne 0 -or $wixVersion -notmatch '^4\.0\.6(?:\+|$)') { throw 'This build requires pinned WiX 4.0.6 and matching Util extension.' }
if ($Version -notmatch '^\d+\.\d+\.\d+$') { throw 'Use a three-part MSI version.' }
$parts = $Version.Split('.') | ForEach-Object { [uint64]$_ }
if ($parts[0] -gt 255 -or $parts[1] -gt 255 -or $parts[2] -gt 65535) { throw 'MSI version limits are 255.255.65535.' }
foreach ($file in @('lovpn.exe','lovpn-service.exe','lovpn-ui.exe','lovpn-tray.exe')) {
    if (-not (Test-Path (Join-Path $SourceDir $file) -PathType Leaf)) { throw "Missing $file; run build-windows.ps1 natively." }
}
$hash = (Get-FileHash -LiteralPath $DriverDll -Algorithm SHA256).Hash.ToLowerInvariant()
if ($hash -ne 'b1b85e072c45d81358be29d94c599dc76652f912be8c0f0a41e2d5d89a6461d3') { throw 'Wrong WireGuardNT 1.1 amd64 digest.' }
$signature = Get-AuthenticodeSignature -LiteralPath $DriverDll
if ($signature.Status -ne 'Valid' -or $signature.SignerCertificate.Subject -notlike 'CN=WireGuard LLC,*') { throw 'Invalid WireGuard signature.' }
$SourceDir = (Resolve-Path $SourceDir).Path
$DriverDll = (Resolve-Path $DriverDll).Path
$Output = [IO.Path]::GetFullPath($Output)
$manifest = $Output + '.compatibility.json'
@{ record_schema = 2; nrpt_journal = $true; service_sha256 = (Get-FileHash -LiteralPath (Join-Path $SourceDir 'lovpn-service.exe') -Algorithm SHA256).Hash } | ConvertTo-Json | Set-Content -LiteralPath $manifest -Encoding UTF8
Push-Location (Join-Path $PSScriptRoot '..\packaging\windows')
try {
    $extra = @()
    if ($TestHooks) { $extra += @('-d', 'TestHooks=1') }
    & wix build LoVPN.wxs -arch x64 -ext WixToolset.Util.wixext/4.0.6 -d "Version=$Version" -d "SourceDir=$SourceDir" -d "DriverDll=$DriverDll" -d "Manifest=$manifest" -o $Output @extra
    if ($LASTEXITCODE -ne 0) { throw "WiX failed ($LASTEXITCODE)." }
} finally { Pop-Location }
