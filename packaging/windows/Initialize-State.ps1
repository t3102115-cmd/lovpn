param([Parameter(Mandatory=$true)][string]$OwnerSid)
$ErrorActionPreference = 'Stop'
try {
    if ($OwnerSid -notmatch '^S-1-\d+(?:-\d+)+$') { throw 'Invalid owner SID' }
    $null = New-Object Security.Principal.SecurityIdentifier($OwnerSid)
    $dir = Join-Path $env:ProgramData 'LoVPN'
    if ((Get-Item -LiteralPath $env:ProgramData).Attributes -band [IO.FileAttributes]::ReparsePoint) { throw 'ProgramData must not be a reparse point.' }
    # Existing state belongs to the service; never replace its ACL, owner or config.
    if (Test-Path -LiteralPath $dir) {
        throw 'Existing unmanaged state: refuse first install. Migrate/back up explicitly; MSI upgrades preserve managed state.'
    }
    $acl = New-Object Security.AccessControl.DirectorySecurity
    $acl.SetAccessRuleProtection($true, $false)
    foreach ($sid in @('S-1-5-18', 'S-1-5-32-544')) {
        $identity = New-Object Security.Principal.SecurityIdentifier($sid)
        $rule = New-Object Security.AccessControl.FileSystemAccessRule($identity, 'FullControl', 'ContainerInherit,ObjectInherit', 'None', 'Allow')
        $acl.AddAccessRule($rule)
    }
    $acl.SetOwner((New-Object Security.Principal.SecurityIdentifier('S-1-5-18')))
    # .NET Framework overload creates the directory with its private ACL atomically.
    $null = [IO.Directory]::CreateDirectory($dir, $acl)
    if ((Get-Item -LiteralPath $dir).Attributes -band [IO.FileAttributes]::ReparsePoint) { throw 'State directory must not be a reparse point.' }
    $actual = Get-Acl -LiteralPath $dir
    if (-not $actual.AreAccessRulesProtected -or $actual.GetOwner([Security.Principal.SecurityIdentifier]).Value -ne 'S-1-5-18') { throw 'State owner/ACL mismatch.' }
    foreach ($rule in $actual.GetAccessRules($true, $true, [Security.Principal.SecurityIdentifier])) {
        if ($rule.IdentityReference.Value -notin @('S-1-5-18', 'S-1-5-32-544') -or $rule.AccessControlType -ne 'Allow') { throw 'Unexpected state ACL.' }
    }
    $file = [IO.File]::Open((Join-Path $dir 'service.json'), [IO.FileMode]::CreateNew, [IO.FileAccess]::Write, [IO.FileShare]::None)
    try {
        $bytes = [Text.Encoding]::UTF8.GetBytes('{"owner_sid":"' + $OwnerSid + '"}')
        $file.Write($bytes, 0, $bytes.Length)
        $file.Flush($true)
    } finally { $file.Dispose() }
    exit 0
} catch { Write-Error $_; exit 1 }
