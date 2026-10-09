param([Parameter(Mandatory)][string]$Dir, [switch]$LabOnlyRecovery)
$ErrorActionPreference = 'Stop'
if (-not $LabOnlyRecovery) { throw 'Explicit -LabOnlyRecovery required.' }
$c = Get-Content "$Dir\config.json" -Raw | ConvertFrom-Json
if ($c.Scenario -eq 'DualNic' -and $c.PrimaryAlias) {
    Enable-NetAdapter -Name $c.PrimaryAlias -Confirm:$false
}
& "$Dir\vm-e2e-recover.ps1" -LoVpnPath $c.LoVpnPath -ReceiptPath "$Dir\recovery.json" -LabOnlyRecovery
