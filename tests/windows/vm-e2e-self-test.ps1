# Native regression checks. No service, networking, packet capture or task changes.
$ErrorActionPreference = 'Stop'
. (Join-Path $PSScriptRoot 'vm-e2e-common.ps1')
function Assert-Lab([bool]$Condition, [string]$Name) {
    if (-not $Condition) { throw "FAIL: $Name" }
    Write-Output "PASS: $Name"
}
$mac = '00-0C-29-8D-53-8F'
$prefix = "$mac > 00-50-56-C0-00-08, ethertype IPv4 (0x0800), length 138: "
function Analyse-Fixture([string]$Payload) {
    Read-LabCapture -Lines @($prefix + $Payload) -PhysicalMacs @($mac) -AllowedLabAddresses @('172.16.8.129','255.255.255.255') -EndpointAddress '172.16.8.1' -EndpointPort 51820
}
$r = Analyse-Fixture '172.16.8.129.58673 > 172.16.8.1.51820: UDP, length 96'
Assert-Lab ($r.Frames -eq 1 -and $r.Transport -eq 1 -and $r.Bad.Count -eq 0) 'exact final01 WireGuard fixture'
$r = Analyse-Fixture '172.16.8.129.51820 > 172.16.8.1.58673: UDP, length 96'
Assert-Lab ($r.Transport -eq 1 -and $r.Bad.Count -eq 0) 'source transport port boundary'
$r = Analyse-Fixture '172.16.8.129.58673 > 172.16.8.1.22: TCP, length 96'
Assert-Lab ($r.Transport -eq 0 -and $r.Bad.Count -eq 0) 'existing management SSH exception'
$r = Analyse-Fixture '172.16.8.129.68 > 255.255.255.255.67: UDP, length 96'
Assert-Lab ($r.Transport -eq 0 -and $r.Bad.Count -eq 0) 'existing DHCP exception'
foreach ($payload in @(
    '172.16.8.129.58673 > 172.16.8.1.53: UDP, length 96',
    '172.16.8.129.58673 > 172.16.8.1.443: TCP, length 96',
    '172.16.8.129.58673 > 1.1.1.1.51820: UDP, length 96',
    '172.16.8.129.58673 > 172.16.8.1.51820.9: UDP, length 96',
    '172.16.8.129.58673 > 172.16.8.1.51820garbage: UDP, length 96',
    '172.16.8.129.58673 > 172.16.8.999.51820: UDP, length 96',
    '172.16.8.129.58673 > 172.16.8.1.99999: UDP, length 96',
    '172.16.8.129 > 172.16.8.1: ICMP, length 96'
)) {
    $r = Analyse-Fixture $payload
    Assert-Lab ($r.Bad.Count -eq 1 -and $r.Transport -eq 0) "reject $payload"
}
$r = Read-LabCapture -Lines @(('00-50-56-C0-00-08 > ' + $mac + ', ethertype IPv4 (0x0800), length 138: 1.1.1.1.443 > 172.16.8.129.58673: TCP')) -PhysicalMacs @($mac) -EndpointAddress '172.16.8.1' -EndpointPort 51820
Assert-Lab ($r.Frames -eq 0 -and $r.Bad.Count -eq 0) 'inbound frame ignored'
Assert-Lab (Test-LabRecoveredState ([pscustomobject]@{state='disconnected';kill_switch_armed=$false})) 'confirmed reset recovery'
foreach ($state in @($null, ([pscustomobject]@{state='disconnected'}), ([pscustomobject]@{state='disconnected';kill_switch_armed=$true}), ([pscustomobject]@{state='protected';kill_switch_armed=$false}))) {
    Assert-Lab (-not (Test-LabRecoveredState $state)) 'incomplete or protected state cannot claim recovery'
}
$shell = (Get-Process -Id $PID).Path
foreach ($code in @(0,7)) {
    # Repeat immediate exits to exercise the short-lived process regression.
    foreach ($iteration in 1..10) {
        $r = Invoke-LabProcess -FilePath $shell -Arguments @('-NoProfile','-NonInteractive','-Command', "[Console]::Out.Write('receipt'); [Console]::Error.Write('diagnostic'); exit $code")
        Assert-Lab ($r.ExitCode -eq $code -and $r.Stdout -eq 'receipt' -and $r.Stderr -eq 'diagnostic') "retained process exit=$code iteration=$iteration"
    }
}
$timedOut = $false
try { Invoke-LabProcess -FilePath $shell -Arguments @('-NoProfile','-NonInteractive','-Command','Start-Sleep -Seconds 10') -TimeoutMilliseconds 200 | Out-Null }
catch { $timedOut = $_.Exception.Message -like 'Process timed out*' }
Assert-Lab $timedOut 'bounded process timeout throws instead of returning successful exit'
