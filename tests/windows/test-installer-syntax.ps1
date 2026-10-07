# Native parser check; no elevation or installation required.
$ErrorActionPreference = 'Stop'
$root = [IO.Path]::GetFullPath((Join-Path $PSScriptRoot '..\..'))
foreach ($relative in @('scripts\install-client.ps1', 'scripts\build-msi.ps1', 'packaging\windows\Initialize-State.ps1')) {
    $tokens = $null
    $errors = $null
    $null = [Management.Automation.Language.Parser]::ParseFile((Join-Path $root $relative), [ref]$tokens, [ref]$errors)
    if ($errors.Count -gt 0) { throw ($errors | Out-String) }
    Write-Host "PASS parser: $relative"
}
