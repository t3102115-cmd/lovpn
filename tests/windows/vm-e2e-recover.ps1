# Lab only: deliberately releases protection to restore VM management access.
param(
    [Parameter(Mandatory)][string]$LoVpnPath,
    [Parameter(Mandatory)][string]$ReceiptPath,
    [switch]$LabOnlyRecovery
)
$ErrorActionPreference = 'Stop'
. (Join-Path $PSScriptRoot 'vm-e2e-common.ps1')
if (-not $LabOnlyRecovery) { throw 'Recovery requires explicit -LabOnlyRecovery consent.' }
$success = $false; $detail = ''
try {
    $captureMarker = Join-Path (Split-Path -Parent $ReceiptPath) 'capture.active'
    if (Test-Path -LiteralPath $captureMarker) {
        $capture = Invoke-LabProcess -FilePath 'pktmon.exe' -Arguments @('stop') -TimeoutMilliseconds 10000
        if ($capture.ExitCode -eq 0) { Remove-Item -LiteralPath $captureMarker -ErrorAction SilentlyContinue }
    }
    # SCM recovery may still be restarting the service after the crash test.
    foreach ($attempt in 1..3) {
        try {
            $reset = Invoke-LabProcess -FilePath $LoVpnPath -Arguments @('reset')
            if ($reset.ExitCode -eq 0) {
                $statusFile = Join-Path (Split-Path -Parent $ReceiptPath) 'recovery-status.json'
                $status = Invoke-LabProcess -FilePath $LoVpnPath -Arguments @('--json','status') -TimeoutMilliseconds 10000
                Set-Content -LiteralPath $statusFile -Value $status.Stdout
                if ($status.ExitCode -eq 0) {
                    $state = $status.Stdout | ConvertFrom-Json
                    if (Test-LabRecoveredState $state) { $success = $true; $detail = ''; break }
                    $detail = 'reset did not restore disconnected/unarmed status'
                } else { $detail = "status exit=$($status.ExitCode): $($status.Stderr)" }
            } else { $detail = "reset exit=$($reset.ExitCode): $($reset.Stderr)" }
        } catch { $detail = $_.Exception.Message }
        Start-Sleep -Seconds 3
    }
} catch { $detail = $_.Exception.Message }
[pscustomobject]@{ finished = (Get-Date -Format o); success = $success; detail = $detail; labOnly = $true } | ConvertTo-Json | Set-Content -LiteralPath $ReceiptPath
if (-not $success) { throw "Lab recovery failed: $detail" }
