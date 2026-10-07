<# Recovery scenario, run ON the Windows VM as Administrator/SYSTEM (see vm-e2e.ps1 for why it is
 autonomous): a strict kill switch is armed, the service is stopped and cannot help, and the
 user must still be able to get their internet back with `lovpn-service release`. #>
param([string]$Dir = $env:USERPROFILE, [string]$Profile = 'vm')
$Out = Join-Path $Dir 'vm-recovery.txt'
$lovpn = 'C:\Program Files\LoVPN\lovpn.exe'; $svc = 'C:\Program Files\LoVPN\lovpn-service.exe'
$script:fail = 0
Set-Content $Out "vm-recovery started $(Get-Date -Format o)"
function Log($m) { Add-Content $Out $m }
function Check($n, [bool]$ok, $d = '') { if ($ok) { Log "PASS  $n" } else { Log "FAIL  $n $d"; $script:fail++ } }
function Fetch([string]$u) { $r = & curl.exe -s --max-time 5 $u 2>$null; if ($LASTEXITCODE -eq 0) { [string]$r } else { $null } }
function St { try { & $lovpn --json status | ConvertFrom-Json } catch { $null } }

& $lovpn reset | Out-Null
Check 'R0 internet works before the test' ($null -ne (Fetch 'http://1.1.1.1/'))
& $lovpn connect $Profile | Out-Null
$end = (Get-Date).AddSeconds(40); do { $s = St; Start-Sleep 1 } until ($s.state -eq 'protected' -or (Get-Date) -gt $end)
Check 'R1 connected and protected with a strict kill switch' ($s.state -eq 'protected' -and $s.kill_switch_armed)
Check 'R1b tunnel works (positive control)' ((Fetch 'http://192.0.2.50:8080/') -like 'lovpn-decoy*')

Stop-Service LoVPNClient -Force
Start-Sleep 3
Check 'R2 service stopped' ((Get-Service LoVPNClient).Status -eq 'Stopped')
Check 'R3 with the service gone, the kill switch still blocks the internet' ($null -eq (Fetch 'http://1.1.1.1/'))
Check 'R3b ... and the tunnel path' ($null -eq (Fetch 'http://192.0.2.50:8080/'))

$rel = (& $svc release 2>&1) -join ' '
Check 'R4 offline release succeeds' ($LASTEXITCODE -eq 0) $rel
Check 'R5 internet works again without the service' ($null -ne (Fetch 'http://1.1.1.1/'))

Start-Service LoVPNClient
Start-Sleep 12
$s = St
Check 'R6 restarted service reports disconnected, not blocked' ($s.state -eq 'disconnected') ($s.state)
Check 'R7 the block does not come back after the service restarts' ($null -ne (Fetch 'http://1.1.1.1/'))
# A graceful stop must not leave the host route to the server behind, and a connect after a
# release must work (regression: a stale route made the next connect fail with add-route).
& $lovpn connect $Profile | Out-Null
$end = (Get-Date).AddSeconds(40); do { $s = St; Start-Sleep 1 } until ($s.state -eq 'protected' -or (Get-Date) -gt $end)
Check 'R8 protected again after the release and restart' ($s.state -eq 'protected') ($s.state)
Stop-Service LoVPNClient -Force
Start-Sleep 3
Check 'R9 graceful stop removed the host route to the server' ($null -eq (Get-NetRoute -DestinationPrefix '172.16.8.1/32' -ErrorAction SilentlyContinue))
& $svc release | Out-Null
Start-Service LoVPNClient
Start-Sleep 8
& $lovpn connect $Profile | Out-Null
$end = (Get-Date).AddSeconds(40); do { $s = St; Start-Sleep 1 } until ($s.state -eq 'protected' -or (Get-Date) -gt $end)
Check 'R10 connect after release and restart reaches PROTECTED' ($s.state -eq 'protected') ($s.state)
& $lovpn reset | Out-Null
Log "RESULT failures=$script:fail"
