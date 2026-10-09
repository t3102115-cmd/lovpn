# Side-effect-free syntax check; may also run with PowerShell 7 on Linux.
$ErrorActionPreference = 'Stop'
$failed = $false
foreach ($file in @('vm-e2e.ps1','vm-e2e-launch.ps1','vm-e2e-recover.ps1','vm-e2e-common.ps1','vm-e2e-self-test.ps1','vm-e2e-check.ps1')) {
    $tokens = $null; $parseErrors = $null
    [System.Management.Automation.Language.Parser]::ParseFile((Join-Path $PSScriptRoot $file), [ref]$tokens, [ref]$parseErrors) | Out-Null
    foreach ($parseError in $parseErrors) { Write-Output "$file : $parseError"; $failed = $true }
}
if ($failed) { exit 1 }
Write-Output 'PASS: Windows VM harness PowerShell syntax'
