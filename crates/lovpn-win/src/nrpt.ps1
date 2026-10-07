param([string]$InputJson)
$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'
$WarningPreference = 'SilentlyContinue'
$InformationPreference = 'SilentlyContinue'
if (-not $InputJson) { $InputJson = [Console]::In.ReadToEnd() }
$request = $InputJson | ConvertFrom-Json
foreach ($command in @('Get-DnsClientNrptRule','Get-DnsClientNrptPolicy','Add-DnsClientNrptRule','Remove-DnsClientNrptRule','Clear-DnsClientCache')) {
    if (-not (Get-Command $command -ErrorAction SilentlyContinue)) { throw 'NRPT unsupported' }
}
$journal = $request.journal
$marker = 'LoVPN-NRPT-v1:' + $journal.owner
function Rules { @(Get-DnsClientNrptRule) }
function Effective { @(Get-DnsClientNrptPolicy -Effective) }
function SameServers($actual, $expected) {
    $a = @($actual | ForEach-Object { [regex]::Split([string]$_, '[,;\s]+') } | Where-Object { $_ -ne '' } | Sort-Object)
    $b = @($expected | Sort-Object)
    return (($a -join ',') -ceq ($b -join ','))
}
function Exact($rule, $scope) {
    # Effective policy exposes a scalar Namespace; local rules expose an array.
    $namespaces = @($rule.Namespace)
    return ($namespaces.Count -eq 1 -and [string]$namespaces[0] -ceq [string]$scope.namespace -and (SameServers $rule.NameServers $scope.servers) -and -not $rule.DnsSecValidationRequired -and -not $rule.DnsSecQueryIPsecRequired -and -not $rule.DirectAccessEnabled)
}
function Owned($rule) { return ($rule.DisplayName -ceq $marker -and $rule.Comment -ceq $marker) }
function Overlap($namespace, $scope) {
    $n = ([string]$namespace).ToLowerInvariant()
    # Unknown namespace kinds are conservatively treated as conflicts.
    if (-not $n.StartsWith('.') -or $n -eq '.') { return $true }
    return ($n -eq $scope -or $n.EndsWith($scope) -or $scope.EndsWith($n))
}
$rules = Rules
$owned = @($rules | Where-Object { Owned $_ })
# Marker tampering or any extra owned rule blocks deletion as well as installation.
foreach ($rule in $rules) {
    if ($rule.DisplayName -ceq $marker -or $rule.Comment -ceq $marker) {
        if (-not (Owned $rule) -or @($journal.scopes | Where-Object { Exact $rule $_ }).Count -ne 1) { throw 'NRPT ownership drift' }
    }
}
foreach ($scope in $journal.scopes) {
    if (@($owned | Where-Object { Exact $_ $scope }).Count -gt 1) { throw 'NRPT duplicate ownership' }
}
if ($request.action -eq 'restore') {
    foreach ($rule in $owned) {
        # Re-read immediately before removal; never remove an edited rule.
        $current = @(Rules | Where-Object { $_.Name -ceq $rule.Name })
        $scope = @($journal.scopes | Where-Object { Exact $rule $_ })[0]
        if ($current.Count -ne 1 -or -not (Owned $current[0]) -or -not (Exact $current[0] $scope)) { throw 'NRPT restoration drift' }
        Remove-DnsClientNrptRule -Name $rule.Name -Force -ErrorAction Stop | Out-Null
    }
    Clear-DnsClientCache | Out-Null
    if (@(Rules | Where-Object { $_.DisplayName -ceq $marker -or $_.Comment -ceq $marker }).Count -ne 0) { throw 'NRPT restoration incomplete' }
    @{owned_rules=0;effective_scopes=0} | ConvertTo-Json -Compress
    return
}
foreach ($scope in $journal.scopes) {
    foreach ($rule in $rules) {
        if (-not (Owned $rule)) {
            foreach ($n in $rule.Namespace) { if (Overlap $n $scope.namespace) { throw 'NRPT local policy conflict' } }
        }
    }
    foreach ($policy in (Effective)) {
        foreach ($n in $policy.Namespace) {
            if (Overlap $n $scope.namespace) {
                if (-not (Exact $policy $scope) -or @($owned | Where-Object { Exact $_ $scope }).Count -ne 1) { throw 'NRPT effective policy conflict' }
            }
        }
    }
}
if ($request.action -eq 'apply') {
    foreach ($scope in $journal.scopes) {
        if (@($owned | Where-Object { Exact $_ $scope }).Count -eq 0) {
            Add-DnsClientNrptRule -Namespace $scope.namespace -NameServers ($scope.servers -join ',') -DisplayName $marker -Comment $marker -ErrorAction Stop | Out-Null
        }
    }
    Clear-DnsClientCache | Out-Null
} elseif ($request.action -ne 'observe') { throw 'Unknown NRPT operation' }
$rules = Rules
$effective = Effective
foreach ($scope in $journal.scopes) {
    if (@($rules | Where-Object { (Owned $_) -and (Exact $_ $scope) }).Count -ne 1 -or @($effective | Where-Object { Exact $_ $scope }).Count -ne 1) { throw 'NRPT observation mismatch' }
    foreach ($policy in $effective) {
        foreach ($n in $policy.Namespace) { if ((Overlap $n $scope.namespace) -and -not (Exact $policy $scope)) { throw 'NRPT effective policy shadowing' } }
    }
}
@{owned_rules=@($journal.scopes).Count;effective_scopes=@($journal.scopes).Count} | ConvertTo-Json -Compress
