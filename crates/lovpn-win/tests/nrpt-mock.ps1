# Mock the Windows cmdlets, not the NRPT implementation. No host policy is modified.
$ErrorActionPreference = 'Stop'
$backend = [scriptblock]::Create('__BACKEND__')
$global:LocalRules = @()
$global:GpoRules = @()
$global:NextId = 0
$global:FailAdd = 0
$global:RemoveCount = 0
$global:FailRemove = 0
function Get-DnsClientNrptRule { $global:LocalRules }
function Get-DnsClientNrptPolicy {
    param([switch]$Effective)
    # Deliberately return scalar namespaces, matching effective CIM policy.
    foreach ($rule in $global:LocalRules) {
        [pscustomobject]@{ Namespace=[string]@($rule.Namespace)[0]; NameServers=$rule.NameServers }
    }
    $global:GpoRules
}
function Add-DnsClientNrptRule {
    [CmdletBinding()]
    param([string[]]$Namespace, [string]$NameServers, [string]$DisplayName, [string]$Comment)
    $global:NextId++
    if ($global:FailAdd -eq $global:NextId) { throw 'Injected partial apply' }
    $global:LocalRules += [pscustomobject]@{ Name="rule-$global:NextId"; Namespace=$Namespace; NameServers=$NameServers; DisplayName=$DisplayName; Comment=$Comment }
}
function Remove-DnsClientNrptRule {
    [CmdletBinding()]
    param([string]$Name, [switch]$Force)
    $global:RemoveCount++
    if ($global:RemoveCount -eq $global:FailRemove) { throw 'Injected partial restore' }
    $global:LocalRules = @($global:LocalRules | Where-Object { $_.Name -ne $Name })
}
function Clear-DnsClientCache { }
function Assert($condition, $label) { if (-not $condition) { throw $label } }
$journal = @{ owner='0123456789abcdef0123456789abcdef'; scopes=@(@{ namespace='.corp.example'; servers=@('10.0.0.53') }) }
function InvokeBackend($action, $intent = $journal) {
    $json = @{ action=$action; journal=$intent } | ConvertTo-Json -Depth 8 -Compress
    & $backend -InputJson $json | ConvertFrom-Json
}
function MustFail($action, $intent = $journal) {
    $failed = $false
    try { $null = InvokeBackend $action $intent } catch { $failed = $true }
    Assert $failed "Expected failure: $action"
}
$observed = InvokeBackend 'apply'
Assert ($observed.owned_rules -eq 1 -and $observed.effective_scopes -eq 1) 'Apply observation'
$null = InvokeBackend 'apply'
Assert ($global:LocalRules.Count -eq 1) 'Idempotent apply'
$null = InvokeBackend 'observe'
$null = InvokeBackend 'restore'
Assert ($global:LocalRules.Count -eq 0) 'Restore owned rule'
$null = InvokeBackend 'restore'
MustFail 'observe'

$null = InvokeBackend 'apply'
$global:LocalRules[0].NameServers = '10.0.0.99'
MustFail 'restore'
Assert ($global:LocalRules.Count -eq 1) 'Preserve modified rule'
$global:LocalRules = @()
$global:LocalRules += [pscustomobject]@{ Name='foreign'; Namespace=@('.child.corp.example'); NameServers='10.0.0.99'; DisplayName='foreign'; Comment='foreign' }
MustFail 'apply'
Assert ($global:LocalRules.Count -eq 1 -and $global:LocalRules[0].Name -eq 'foreign') 'Preserve foreign rule'
$global:LocalRules = @()
$global:GpoRules = @([pscustomobject]@{ Namespace='.corp.example'; NameServers='10.0.0.99' })
MustFail 'apply'
Assert ($global:LocalRules.Count -eq 0) 'GPO conflict must not install local policy'
$global:GpoRules = @()
$null = InvokeBackend 'apply'
$global:GpoRules = @([pscustomobject]@{ Namespace='.child.corp.example'; NameServers='10.0.0.99' })
MustFail 'observe'
$null = InvokeBackend 'restore'
Assert ($global:GpoRules.Count -eq 1 -and $global:LocalRules.Count -eq 0) 'Restoration preserves GPO'
$global:GpoRules = @()

$partial = @{ owner=$journal.owner; scopes=@($journal.scopes[0], @{ namespace='.other.example'; servers=@('10.0.0.54') }) }
$global:NextId = 0
$global:FailAdd = 2
MustFail 'apply' $partial
Assert ($global:LocalRules.Count -eq 1) 'Partial apply remains owned'
$null = InvokeBackend 'restore' $partial
Assert ($global:LocalRules.Count -eq 0) 'Partial apply recovery'
$global:FailAdd = 0

$null = InvokeBackend 'apply' $partial
$global:RemoveCount = 0
$global:FailRemove = 2
MustFail 'restore' $partial
Assert ($global:LocalRules.Count -eq 1) 'Partial restoration retains remaining owned rule'
$global:FailRemove = 0
$null = InvokeBackend 'restore' $partial
Assert ($global:LocalRules.Count -eq 0) 'Interrupted restoration can resume safely'

$null = InvokeBackend 'apply'
$duplicate = $global:LocalRules[0].PSObject.Copy()
$duplicate.Name = 'duplicate'
$global:LocalRules += $duplicate
MustFail 'restore'
Assert ($global:LocalRules.Count -eq 2) 'Ambiguous ownership must not delete'
Write-Output 'NRPT mock lifecycle passed'
