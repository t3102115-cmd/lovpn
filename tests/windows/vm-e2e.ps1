<#
 End-to-end scenario for the Windows client, run ON the Windows VM as Administrator.
 It is autonomous because a strict kill switch (correctly) cuts off any outside control
 channel while a test is running. Results go to a file; a SYSTEM watchdog resets LoVPN if
 this script dies. Prerequisites: the service is installed, the profile 'vm' is imported
 and points at a reachable lab server (tests/windows/lab-server.sh), whose tunnel serves
 DNS on 10.66.0.1 (answering 192.0.2.50) and HTTP on the unroutable decoy 192.0.2.50:8080.
#>
param([string]$Dir = $env:USERPROFILE, [string]$Profile = 'vm')
$Out = Join-Path $Dir 'vm-e2e.txt'
$ErrorActionPreference = 'Continue'
$lovpn = 'C:\Program Files\LoVPN\lovpn.exe'
$script:fail = 0
Set-Content -Path $Out -Value "vm-e2e started $(Get-Date -Format o)"
function Log($m) { Add-Content -Path $Out -Value $m }
function Check($name, [bool]$ok, $detail = '') {
    if ($ok) { Log "PASS  $name" } else { Log "FAIL  $name $detail"; $script:fail++; Diag $name }
}
function St { try { (& $lovpn --json status | ConvertFrom-Json) } catch { $null } }
function Wait-State($want, $seconds) {
    $end = (Get-Date).AddSeconds($seconds)
    while ((Get-Date) -lt $end) {
        $s = St
        if ($s -and $s.state -eq $want) { return $s }
        Start-Sleep -Seconds 1
    }
    return St
}
# NOTE: do not name helpers `curl`: it is an alias in PowerShell and silently wins.
function Fetch([string]$url, [int]$t = 5) { $r = & curl.exe -s --max-time $t $url 2>$null; if ($LASTEXITCODE -eq 0) { return [string]$r } else { return $null } }
function Reachable([string]$url) { return ($null -ne (Fetch $url)) }
# Positive controls: the probes themselves must be able to succeed, or "blocked" means nothing.
function Diag($label) {
    Log "---- diagnostics: $label"
    Log ((& $lovpn status) -join "`n")
    Log ((Get-Content (Join-Path 'C:\ProgramData\LoVPN\logs' 'service.log') -Tail 8) -join "`n")
}
function Fail-Reason($s) { if ($s) { ($s.checks | Where-Object { $_.status -ne 'ok' -and $_.status -ne 'off' } | ForEach-Object { "$($_.name)=$($_.status):$($_.detail)" }) -join '; ' } else { 'no status' } }

# Independent leak detector: capture the physical NICs for the whole scenario (pktmon is
# part of Windows and sees frames below the firewall) and assert that nothing but the
# WireGuard transport (and this lab's management SSH) ever left the machine.
$etl = Join-Path $Dir 'leak.etl'; $txt = Join-Path $Dir 'leak.txt'
function Start-Capture {
    pktmon stop 2>&1 | Out-Null; pktmon filter remove 2>&1 | Out-Null
    Remove-Item $etl, $txt -ErrorAction SilentlyContinue
    pktmon start --capture --comp nics --pkt-size 0 --file-name $etl 2>&1 | Out-Null
}
function Stop-Capture-And-Analyse {
    pktmon stop 2>&1 | Out-Null
    pktmon etl2txt $etl -o $txt 2>&1 | Out-Null
    if (-not (Test-Path $txt)) { return $null }
    $okIp = { param($ip) ($ip -in '172.16.8.129','192.168.8.128','172.16.8.1','172.16.8.2','255.255.255.255','172.16.8.255','192.168.8.255') -or ($ip -match '^(22[4-9]|23\d)\.') }
    $mine = @(Get-NetAdapter -Physical | ForEach-Object { $_.MacAddress.ToUpper() })
    $bad = New-Object System.Collections.Generic.List[string]; $frames = 0; $transport = 0
    foreach ($l in (Get-Content $txt)) {
        if ($l -notmatch '^\s*([0-9A-F]{2}(?:-[0-9A-F]{2}){5}) > [0-9A-F-]{17}, ethertype (IPv4|IPv6)') { continue }
        # Only frames this machine SENT can leak; inbound frames are other hosts' traffic.
        if ($mine -notcontains $Matches[1]) { continue }
        $frames++
        if ($l -match 'ethertype IPv4 .*?: (\d+\.\d+\.\d+\.\d+)(?:\.(\d+))? > (\d+\.\d+\.\d+\.\d+)(?:\.(\d+))?') {
            $a = $Matches[1]; $ap = $Matches[2]; $b = $Matches[3]; $bp = $Matches[4]
            # DHCP (client 68 <-> server 67) is permitted by policy: it keeps the physical lease alive.
            $dhcp = ($l -match 'UDP') -and (($ap -eq '68' -and $bp -eq '67') -or ($ap -eq '67' -and $bp -eq '68'))
            $good = $dhcp -or ((& $okIp $a) -and (& $okIp $b) -and ($ap -ne '53') -and ($bp -ne '53'))
            if ($good -and -not $dhcp -and ($a -eq '172.16.8.1' -or $b -eq '172.16.8.1')) {
                $isTransport = ($ap -eq '51820' -or $bp -eq '51820')
                $good = $isTransport -or ($ap -eq '22' -or $bp -eq '22')
                if ($isTransport) { $transport++ }
            }
            if (-not $good) { $bad.Add($l.Trim()) }
        } elseif ($l -match 'ethertype IPv6 .*?: ([0-9a-f:]+)(?:\.\d+)? > ([0-9a-f:]+)') {
            if (($Matches[1] -notmatch '^(fe80|ff0|::)') -or ($Matches[2] -notmatch '^(fe80|ff0|::)')) { $bad.Add($l.Trim()) }
        }
    }
    return [pscustomobject]@{ Frames = $frames; Transport = $transport; Bad = $bad }
}

# --- A. baseline: disconnected, normal networking
& $lovpn reset | Out-Null
$s = St
Check 'A1 service reachable, state disconnected after reset' ($s.state -eq 'disconnected')
Check 'A2 plain internet works before connecting' (Reachable 'http://1.1.1.1/')

# A stale identical host route (left by a crash or an earlier session) must not break connecting.
$uplink = (Get-NetRoute -DestinationPrefix '0.0.0.0/0' | Sort-Object RouteMetric | Select-Object -First 1).InterfaceAlias
New-NetRoute -DestinationPrefix '172.16.8.1/32' -InterfaceAlias $uplink -NextHop '0.0.0.0' -RouteMetric 1 -ErrorAction SilentlyContinue | Out-Null
Check 'A3 setup: a stale host route to the server exists' ($null -ne (Get-NetRoute -DestinationPrefix '172.16.8.1/32' -ErrorAction SilentlyContinue))

# --- B. connect
Log ('connect: ' + ((& $lovpn connect $Profile 2>&1) -join ' | '))
$s = Wait-State 'protected' 40
Check 'B1 connect reaches PROTECTED (every check observed)' ($s.state -eq 'protected') (Fail-Reason $s)
Check 'B2 handshake observed' ($s.handshake_age_secs -ne $null)
Check 'B3 kill switch armed (strict)' ($s.kill_switch_armed -eq $true)
# From here on protection is established: anything that leaves the machine is a leak.
# (Frames from before this point can legitimately predate the firewall.)
Start-Capture

# --- C. connectivity and leak checks while protected
Check 'C1 unroutable decoy reachable (traffic really uses the tunnel)' ((Fetch 'http://192.0.2.50:8080/') -like 'lovpn-decoy*')
$dns = (Resolve-DnsName example.com -Type A -DnsOnly -ErrorAction SilentlyContinue | Select-Object -First 1).IPAddress
Check 'C2 system DNS answered by the tunnel resolver' ($dns -eq '192.0.2.50') "got $dns"
$v6 = & curl.exe -6 -s --max-time 5 https://ipv6.google.com -o NUL -w '%{http_code}' 2>$null
Check 'C3 IPv6 is blocked' ($v6 -ne '200' -and $v6 -ne '301')
$mtu = (Get-NetIPInterface -InterfaceAlias lovpn0 -AddressFamily IPv4).NlMtu
Check 'C4 tunnel MTU applied (1380)' ($mtu -eq 1380) "mtu=$mtu"

Check 'C0 probe positive control: tunnel-side fetch works' (Reachable 'http://192.0.2.50:8080/')

# --- D. disconnect keeps blocking in strict mode
& $lovpn disconnect | Out-Null
$s = St
Check 'D1 strict: state is BLOCKED after disconnect' ($s.state -eq 'blocked') (Fail-Reason $s)
Check 'D2 strict: internet blocked' (-not (Reachable 'http://1.1.1.1/'))
Check 'D3 strict: decoy blocked' (-not (Reachable 'http://192.0.2.50:8080/'))
$dns = (Resolve-DnsName example.com -Type A -DnsOnly -ErrorAction SilentlyContinue | Select-Object -First 1).IPAddress
Check 'D4 strict: DNS does not resolve' (-not $dns)

# --- E. reconnect from blocked
Log ('connect: ' + ((& $lovpn connect $Profile 2>&1) -join ' | '))
$s = Wait-State 'protected' 40
Check 'E1 reconnect after disconnect reaches PROTECTED' ($s.state -eq 'protected') (Fail-Reason $s)

# --- F. crash: kill the service; protection must hold and the service must resume
Get-Process lovpn-service -ErrorAction SilentlyContinue | Stop-Process -Force
Start-Sleep -Seconds 2
$s = Wait-State 'protected' 60
Check 'F3 service restarted by SCM and resumed to PROTECTED' ($s.state -eq 'protected') (Fail-Reason $s)

# --- G. explicit reconnect
& $lovpn reconnect | Out-Null
$s = Wait-State 'protected' 40
Check 'G1 reconnect returns to PROTECTED' ($s.state -eq 'protected') (Fail-Reason $s)
Check 'G2 kill switch still armed after reconnect' ($s.kill_switch_armed -eq $true)

# --- H. uplink change: remove the host route to the server, monitor must repair it
$ep = ((& $lovpn profile list | Select-String 'vm') | Out-String)
route delete 172.16.8.1 | Out-Null
$sawFail = $false
foreach ($i in 1..20) { $s = St; if ($s.state -ne 'protected') { $sawFail = $true; break }; Start-Sleep -Milliseconds 500 }
$s = Wait-State 'protected' 60
Check 'H1 lost server route is detected and repaired automatically' ($s.state -eq 'protected') (Fail-Reason $s)

# --- I. the adapter / routes are damaged behind our back (other software, admin action)
Disable-NetAdapter -Name lovpn0 -Confirm:$false -ErrorAction SilentlyContinue
$s = Wait-State 'protected' 60
Check 'I1 adapter disabled externally is repaired automatically' ($s.state -eq 'protected') (Fail-Reason $s)
Check 'I1b tunnel works again after repair' (Reachable 'http://192.0.2.50:8080/')
Remove-NetRoute -InterfaceAlias lovpn0 -DestinationPrefix '0.0.0.0/1' -Confirm:$false -ErrorAction SilentlyContinue
$s = Wait-State 'protected' 60
Check 'I2 tunnel default route removed externally is repaired automatically' ($s.state -eq 'protected') (Fail-Reason $s)
Check 'I2b tunnel works again after repair' (Reachable 'http://192.0.2.50:8080/')

# --- J. malformed / tampered profiles are refused and change nothing
$bad = Join-Path $Dir 'bad.toml'; Set-Content $bad 'schema_version = 99'
& $lovpn profile import $bad --name bad --expect-server-key AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE= 2>&1 | Out-Null
Check 'J1 malformed profile import refused' ($LASTEXITCODE -ne 0)
& $lovpn profile import (Join-Path $Dir 'vm.toml') --name tamper --expect-server-key AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE= 2>&1 | Out-Null
Check 'J2 wrong expected server key refused' ($LASTEXITCODE -ne 0)
$names = (& $lovpn --json profile list | ConvertFrom-Json).profiles.name
Check 'J3 refused imports left no profile behind' (($names -notcontains 'bad') -and ($names -notcontains 'tamper'))

# --- L. nothing leaked on the physical NICs during the whole protected scenario
$leak = Stop-Capture-And-Analyse
Check 'L0 packet capture produced frames (the detector can see traffic)' ($leak -and $leak.Frames -gt 0 -and $leak.Transport -gt 0) "frames=$($leak.Frames) transport=$($leak.Transport)"
Check 'L1 no packet left the physical NIC except WireGuard transport' ($leak -and $leak.Bad.Count -eq 0) (($leak.Bad | Select-Object -First 5) -join ' || ')

# --- K. release: back to normal networking
& $lovpn disconnect --release-kill-switch | Out-Null
$s = St
Check 'K1 release restores DISCONNECTED' ($s.state -eq 'disconnected') (Fail-Reason $s)
Check 'K2 internet works again after release' (Reachable 'http://1.1.1.1/')
$wfpFile = Join-Path $Dir 'wfp.xml'
Remove-Item $wfpFile -ErrorAction SilentlyContinue
netsh wfp show filters file=$wfpFile | Out-Null
Check 'K3a independent WFP dump was produced' (Test-Path $wfpFile)
Check 'K3 no LoVPN filters remain (independent WFP dump)' ((Test-Path $wfpFile) -and -not (Select-String -Path $wfpFile -Pattern 'LoVPN g' -Quiet))
Check 'K4 adapter removed after disconnect' (-not (Get-NetAdapter -Name lovpn0 -ErrorAction SilentlyContinue))

Log "RESULT failures=$script:fail"
Log "vm-e2e finished $(Get-Date -Format o)"
