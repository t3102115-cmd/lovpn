# Build the Windows release binaries twice into different target directories and compare
# SHA-256. Same source, locked dependencies, toolchain and machine => identical bytes.
# /Brepro makes the MSVC linker deterministic; paths are remapped. Not proof of
# reproducibility across toolchains or machines.
$ErrorActionPreference = 'Stop'
Set-Location (Split-Path -Parent $PSScriptRoot)
$root = (Get-Location).Path
$work = Join-Path $env:TEMP ("lovpn-repro-" + [guid]::NewGuid())
$bins = 'lovpn-service.exe', 'lovpn.exe', 'lovpn-ui.exe', 'lovpn-tray.exe'
function Build($out) {
    $env:CARGO_TARGET_DIR = $out
    $env:RUSTFLAGS = "--remap-path-prefix=$root=/src --remap-path-prefix=$env:USERPROFILE\.cargo=/cargo --remap-path-prefix=$env:USERPROFILE\.rustup=/rustup -C link-arg=/Brepro"
    $env:SOURCE_DATE_EPOCH = '1'
    $ErrorActionPreference = 'Continue'   # cargo writes progress to stderr
    cargo build --locked --release -p lovpn-win -p lovpn-cli -p lovpn-ui -p lovpn-tray 2>&1 | Out-Null
    $ErrorActionPreference = 'Stop'
    if ($LASTEXITCODE -ne 0) { throw 'build failed' }
}
Build "$work\a"
Build "$work\b"
$status = 0
foreach ($bin in $bins) {
    $a = (Get-FileHash "$work\a\release\$bin").Hash.ToLower()
    $b = (Get-FileHash "$work\b\release\$bin").Hash.ToLower()
    if ($a -eq $b) { "SAME  $a  $bin" } else { "DIFF  $bin`: $a vs $b"; $status = 1 }
}
Remove-Item -Recurse -Force $work
exit $status
