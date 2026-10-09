# Independent process: never consult LoVPN status to decide probe outcomes.
param([Parameter(Mandatory)][string]$Dir, [Parameter(Mandatory)][string]$TunnelUrl,
      [Parameter(Mandatory)][string]$DirectUrl, [ValidateRange(10,1800)][int]$Seconds = 180)
$ErrorActionPreference = 'Stop'
. (Join-Path $PSScriptRoot 'vm-e2e-common.ps1')
$end = (Get-Date).AddSeconds($Seconds)
Set-Content -LiteralPath (Join-Path $Dir 'probes.ready') -Value (Get-Date -Format o)
while ((Get-Date) -lt $end -and -not (Test-Path (Join-Path $Dir 'probes.stop'))) {
    foreach ($probe in @(@('tunnel',$TunnelUrl), @('direct',$DirectUrl))) {
        $r = Invoke-LabProcess 'curl.exe' @('--noproxy','*','--max-time','2','--silent','--output','NUL',$probe[1]) 4000
        [pscustomobject]@{ at = (Get-Date -Format o); probe = $probe[0]; exit = $r.ExitCode } |
            ConvertTo-Json -Compress | Add-Content -LiteralPath (Join-Path $Dir 'probes.jsonl')
    }
}
