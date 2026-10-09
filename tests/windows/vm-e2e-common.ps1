# Pure helpers shared by the runner, recovery and native regression tests.
function Test-LabRecoveredState {
    param($State)
    return ($null -ne $State -and $State.state -eq 'disconnected' -and $State.kill_switch_armed -eq $false)
}

function Invoke-LabProcess {
    param([string]$FilePath, [string[]]$Arguments, [int]$TimeoutMilliseconds = 15000)
    $info = New-Object System.Diagnostics.ProcessStartInfo
    $info.FileName = $FilePath
    $info.UseShellExecute = $false
    $info.CreateNoWindow = $true
    $info.RedirectStandardOutput = $true
    $info.RedirectStandardError = $true
    $info.Arguments = (@($Arguments | ForEach-Object {
        # Windows CommandLineToArgvW quoting, including trailing backslashes.
        '"' + ([regex]::Replace([regex]::Replace($_, '(\\*)"', '$1$1\"'), '(\\+)$', '$1$1')) + '"'
    }) -join ' ')
    $process = New-Object System.Diagnostics.Process
    $process.StartInfo = $info
    try {
        if (-not $process.Start()) { throw 'Process failed to start' }
        # Retain the native handle before the process can exit. Avoid Start-Process's
        # short-lived process/ExitCode behavior on Windows PowerShell 5.1.
        $handle = $process.Handle
        $stdout = $process.StandardOutput.ReadToEndAsync()
        $stderr = $process.StandardError.ReadToEndAsync()
        if (-not $process.WaitForExit($TimeoutMilliseconds)) {
            $process.Kill()
            $null = $process.WaitForExit(2000)
            throw "Process timed out after ${TimeoutMilliseconds}ms: $FilePath"
        }
        $exitCode = $process.ExitCode
        if ($null -eq $exitCode) { throw "Missing exit code: $FilePath" }
        if (-not $stdout.Wait(2000) -or -not $stderr.Wait(2000)) { throw 'Process output did not close' }
        [pscustomobject]@{ ExitCode = [int]$exitCode; Stdout = $stdout.Result; Stderr = $stderr.Result }
    } finally { $process.Dispose() }
}

function Read-LabCapture {
    param([string[]]$Lines, [string[]]$PhysicalMacs, [string[]]$AllowedLabAddresses,
          [string]$EndpointAddress, [int]$EndpointPort)
    $bad = New-Object System.Collections.Generic.List[string]
    $frames = 0; $transport = 0
    # Exactly four bounded octets; ports must end at the tcpdump ':' delimiter.
    $octet = '(?:25[0-5]|2[0-4][0-9]|1[0-9]{2}|[1-9]?[0-9])'
    $ip = "$octet\.$octet\.$octet\.$octet"
    $ipv4 = "ethertype IPv4 [^:]*: (?<source>$ip)(?:\.(?<sourcePort>[0-9]{1,5}))? > (?<destination>$ip)(?:\.(?<destinationPort>[0-9]{1,5}))?:(?:\s|$)"
    foreach ($line in $Lines) {
        if ($line -notmatch '^\s*([0-9A-F]{2}(?:-[0-9A-F]{2}){5}) > [0-9A-F-]{17}, ethertype (IPv4|IPv6)') { continue }
        if ($PhysicalMacs -notcontains $Matches[1]) { continue }
        $family = $Matches[2]; $frames++
        if ($family -eq 'IPv4') {
            if ($line -notmatch $ipv4) { $bad.Add($line.Trim()); continue }
            $a = $Matches.source; $ap = $Matches.sourcePort
            $b = $Matches.destination; $bp = $Matches.destinationPort
            if (($ap -and [int]$ap -gt 65535) -or ($bp -and [int]$bp -gt 65535)) { $bad.Add($line.Trim()); continue }
            $dhcp = ($line -match '\bUDP\b') -and (($ap -eq '68' -and $bp -eq '67') -or ($ap -eq '67' -and $bp -eq '68'))
            $okA = ($a -in $AllowedLabAddresses -or $a -eq $EndpointAddress -or $a -match '^(22[4-9]|23\d)\.')
            $okB = ($b -in $AllowedLabAddresses -or $b -eq $EndpointAddress -or $b -match '^(22[4-9]|23\d)\.')
            $good = $dhcp -or ($okA -and $okB -and $ap -ne '53' -and $bp -ne '53')
            if ($good -and -not $dhcp -and ($a -eq $EndpointAddress -or $b -eq $EndpointAddress)) {
                $isTransport = ($ap -eq "$EndpointPort" -or $bp -eq "$EndpointPort")
                $good = $isTransport -or $ap -eq '22' -or $bp -eq '22'
                if ($isTransport) { $transport++ }
            }
            if (-not $good) { $bad.Add($line.Trim()) }
        } elseif ($line -match 'ethertype IPv6 .*?: ([0-9a-f:]+)(?:\.\d+)? > ([0-9a-f:]+)') {
            if ($Matches[1] -notmatch '^(fe80|ff0|::)' -or $Matches[2] -notmatch '^(fe80|ff0|::)') { $bad.Add($line.Trim()) }
        } else { $bad.Add($line.Trim()) }
    }
    [pscustomobject]@{ Frames = $frames; Transport = $transport; Bad = $bad }
}
