#requires -version 5.1
<#
.SYNOPSIS
  Local rights audit for hardening / GPO replacement:
  - Local group memberships (all groups) + explicit well-known high-risk groups (language independent)
  - User Rights Assignments (Allow + Deny) via secedit USER_RIGHTS
  - Cross-reference: Remote Desktop Users vs SeRemoteInteractiveLogonRight (+ Deny)
  - Flags non-local/domain principals in local groups (SID-based, machine SID baseline)
  - Findings + deterministic dedup
  - Output (main): currentrights_<HOSTNAME>_<TIMESTAMP>.csv
  - Output (context/test file): context_<HOSTNAME>_<TIMESTAMP>.txt   (OS + gpresult)

.NOTES
  Read-only. Run as Administrator for best results (secedit export can be blocked otherwise).
#>

[CmdletBinding()]
param(
    [string]$OutDir = 'C:\temp',
    [ValidateNotNullOrEmpty()]
    [string]$Delimiter = ',',     # set to ';' if you prefer Excel in DK environments
    [switch]$IncludeAllLocalGroups = $true,
    [switch]$IncludeWellKnownGroups = $true,
    [switch]$IncludeGpResultEvidence = $true
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

# ---------------------------
# Output paths
# ---------------------------
$hostname  = $env:COMPUTERNAME
$timestamp = Get-Date -Format 'yyyyMMdd_HHmmss'

if (-not (Test-Path $OutDir)) { New-Item -Path $OutDir -ItemType Directory -Force | Out-Null }

$outPathMain    = Join-Path $OutDir ("currentrights_{0}_{1}.csv" -f $hostname, $timestamp)
$outPathContext = Join-Path $OutDir ("context_{0}_{1}.txt" -f $hostname, $timestamp)

# Collect context in-memory; write at end
$contextLines = New-Object System.Collections.Generic.List[string]

function Add-ContextLine([string]$Line) {
    if ($null -ne $Line) { $contextLines.Add($Line) }
}

Add-ContextLine ("# Context file")
Add-ContextLine ("Hostname: {0}" -f $hostname)
Add-ContextLine ("Timestamp: {0}" -f (Get-Date -Format 'yyyy-MM-dd HH:mm:ss'))
Add-ContextLine ("OutDir: {0}" -f $OutDir)
Add-ContextLine ("MainCSV: {0}" -f $outPathMain)
Add-ContextLine ("---")

# ---------------------------
# Helpers
# ---------------------------
function Norm([string]$s) {
    if ([string]::IsNullOrWhiteSpace($s)) { return '' }
    return $s.Trim().ToLowerInvariant()
}

function Try-TranslateToSid {
    param([string]$NameOrSid)
    if ([string]::IsNullOrWhiteSpace($NameOrSid)) { return $null }

    $v = $NameOrSid.Trim()
    if ($v.StartsWith('*')) { $v = $v.Substring(1) }

    if ($v -match '^S-\d-\d+-.+') { return $v }

    try {
        return ([System.Security.Principal.NTAccount]$v).Translate([System.Security.Principal.SecurityIdentifier]).Value
    } catch {
        return $null
    }
}

function Try-TranslateToName {
    param([string]$SidOrName)
    if ([string]::IsNullOrWhiteSpace($SidOrName)) { return $null }

    $v = $SidOrName.Trim()
    if ($v.StartsWith('*')) { $v = $v.Substring(1) }

    if ($v -match '^S-\d-\d+-.+') {
        try {
            return ([System.Security.Principal.SecurityIdentifier]$v).Translate([System.Security.Principal.NTAccount]).Value
        } catch {
            return $null
        }
    }
    return $v
}

function Get-MachineSidBase {
    # Derive machine SID base from local Administrator account SID (RID 500),
    # without relying on localized "Administrator" name.
    try {
        $admin = Get-CimInstance Win32_UserAccount -Filter "LocalAccount=True AND SID LIKE 'S-1-5-21-%-500'" -ErrorAction Stop |
                 Select-Object -First 1
        if ($admin -and $admin.SID) {
            return ($admin.SID -replace '-500$','')
        }
    } catch {}
    return $null
}

$MachineSidBase = Get-MachineSidBase

function Classify-Principal {
    param(
        [string]$PrincipalRaw,
        [string]$PrincipalSid,
        [string]$PrincipalType
    )

    $raw = $PrincipalRaw
    $sid = $PrincipalSid

    $isBuiltin =
        ($raw -match '^(?i)BUILTIN\\') -or
        ($raw -match '^(?i)NT AUTHORITY\\') -or
        ($raw -match '^(?i)NT SERVICE\\') -or
        ($raw -match ('^(?i){0}\\' -f [regex]::Escape($hostname)))

    $isLocalSid = $false
    $isDomainSid = $false

    if ($sid -and $sid -match '^S-1-5-21-') {
        if ($MachineSidBase) {
            $sidBase = ($sid -replace '-\d+$','') # remove RID
            if ($sidBase -eq $MachineSidBase) { $isLocalSid = $true }
            else { $isDomainSid = $true }
        }
        else {
            $isDomainSid = $true
        }
    }

    $isGroup = $false
    if ($PrincipalType) { $isGroup = ($PrincipalType -match 'Group') }

    $isDomainLikeName =
        ($raw -match '^[^\\]+\\.+') -and (-not $isBuiltin)

    $isNonLocalPrincipal = (-not $isBuiltin) -and ($isDomainLikeName -or $isDomainSid)

    return @{
        IsBuiltinOrLocal     = $isBuiltin -or $isLocalSid
        IsNonLocalPrincipal  = $isNonLocalPrincipal
        IsDomainSid          = $isDomainSid
        IsDomainLikeName     = $isDomainLikeName
        IsGroupHint          = $isGroup
    }
}

# Deterministic dedup
$dedup = New-Object 'System.Collections.Generic.HashSet[string]'
$rows  = New-Object System.Collections.Generic.List[object]

function Add-Row {
    param(
        [Parameter(Mandatory)][string]$Category,
        [string]$LocalGroup,
        [string]$RightName,
        [string]$RightId,
        [string]$PrincipalRaw,
        [string]$PrincipalType,
        [string]$Source,
        [string]$Severity,
        [string]$FindingId,
        [string]$Evidence
    )

    $sid = Try-TranslateToSid -NameOrSid $PrincipalRaw
    $resolved = if ($sid) { (Try-TranslateToName -SidOrName $sid) } else { $PrincipalRaw }

    $cls = Classify-Principal -PrincipalRaw $resolved -PrincipalSid $sid -PrincipalType $PrincipalType

    $key = ('{0}|{1}|{2}|{3}|{4}|{5}|{6}' -f
        $hostname,
        (Norm $Category),
        (Norm $LocalGroup),
        (Norm $RightId),
        (Norm $resolved),
        (Norm $sid),
        (Norm $FindingId)
    )

    if ($dedup.Add($key)) {
        $rows.Add([pscustomobject]@{
            Hostname            = $hostname
            Category            = $Category
            LocalGroup          = $LocalGroup
            RightName           = $RightName
            RightId             = $RightId

            PrincipalRaw        = $PrincipalRaw
            PrincipalResolved   = $resolved
            PrincipalSid        = $sid
            PrincipalType       = $PrincipalType

            IsNonLocalPrincipal = $cls.IsNonLocalPrincipal
            IsDomainSid         = $cls.IsDomainSid
            IsDomainLikeName    = $cls.IsDomainLikeName
            IsGroupHint         = $cls.IsGroupHint

            Severity            = $Severity
            FindingId           = $FindingId
            Evidence            = $Evidence

            Source              = $Source
        })
    }
}

function Add-Finding {
    param(
        [Parameter(Mandatory)][string]$Severity,
        [Parameter(Mandatory)][string]$FindingId,
        [Parameter(Mandatory)][string]$Evidence
    )
    Add-Row -Category 'Finding' -LocalGroup '' -RightName '' -RightId '' -PrincipalRaw '' -PrincipalType '' `
        -Source 'FindingEngine' -Severity $Severity -FindingId $FindingId -Evidence $Evidence
}

# ---------------------------
# Context: OS info -> context file only (NOT CSV)
# ---------------------------
try {
    $os = Get-CimInstance Win32_OperatingSystem
    $cs = Get-CimInstance Win32_ComputerSystem

    Add-ContextLine "## OS / System"
    Add-ContextLine ("OS: {0}" -f $os.Caption)
    Add-ContextLine ("Version: {0}" -f $os.Version)
    Add-ContextLine ("Build: {0}" -f $os.BuildNumber)
    Add-ContextLine ("PartOfDomain: {0}" -f $cs.PartOfDomain)
    Add-ContextLine ("DomainOrWorkgroup: {0}" -f $cs.Domain)
    if ($MachineSidBase) { Add-ContextLine ("MachineSidBase: {0}" -f $MachineSidBase) }
    Add-ContextLine ("---")
}
catch {
    Add-ContextLine ("OS/System context failed: {0}" -f $_.Exception.Message)
    Add-ContextLine ("---")
}

# ---------------------------
# Context: gpresult -> context file only (NOT CSV)
# ---------------------------
if ($IncludeGpResultEvidence) {
    try {
        Add-ContextLine "## GPResult (Computer scope)"
        $gp = & gpresult.exe /R /SCOPE COMPUTER 2>$null
        $exit = $LASTEXITCODE

        if ($exit -eq 0 -and $gp) {
            Add-ContextLine ("gpresult ExitCode: {0}" -f $exit)
            Add-ContextLine (($gp -join "`n"))
        }
        else {
            Add-ContextLine ("gpresult failed or blocked. ExitCode={0}" -f $exit)
        }
        Add-ContextLine ("---")
    } catch {
        Add-ContextLine ("gpresult exception: {0}" -f $_.Exception.Message)
        Add-ContextLine ("---")
    }
}

# ---------------------------
# Well-known high-risk groups (language independent via SID)
# ---------------------------
$WellKnownLocalGroups = @{
    'Administrators'              = 'S-1-5-32-544'
    'Remote Desktop Users'        = 'S-1-5-32-555'
    'Distributed COM Users'       = 'S-1-5-32-562'
    'Remote Management Users'     = 'S-1-5-32-580'
    'Event Log Readers'           = 'S-1-5-32-573'
    'Backup Operators'            = 'S-1-5-32-551'
    'Server Operators'            = 'S-1-5-32-549'
    'Power Users'                 = 'S-1-5-32-547'
    'Performance Log Users'       = 'S-1-5-32-559'
    'Performance Monitor Users'   = 'S-1-5-32-558'
}

$hasLocalAccountsCmdlets = [bool](Get-Command Get-LocalGroup -ErrorAction SilentlyContinue)

# ---------------------------
# 1) Local groups membership (all groups)
# ---------------------------
if ($IncludeAllLocalGroups) {
    try {
        if ($hasLocalAccountsCmdlets) {
            foreach ($g in (Get-LocalGroup)) {
                try {
                    $members = Get-LocalGroupMember -Group $g.Name -ErrorAction Stop
                    if (-not $members -or $members.Count -eq 0) {
                        Add-Row -Category 'LocalGroupMember' -LocalGroup $g.Name -RightName '' -RightId '' -PrincipalRaw '' -PrincipalType '' `
                            -Source 'Get-LocalGroupMember (empty group)' -Severity '' -FindingId '' -Evidence ''
                        continue
                    }
                    foreach ($m in $members) {
                        Add-Row -Category 'LocalGroupMember' -LocalGroup $g.Name -RightName '' -RightId '' -PrincipalRaw $m.Name -PrincipalType $m.ObjectClass `
                            -Source 'Get-LocalGroupMember' -Severity '' -FindingId '' -Evidence ''
                    }
                } catch {
                    Add-Row -Category 'Error' -LocalGroup $g.Name -RightName '' -RightId '' -PrincipalRaw '' -PrincipalType '' `
                        -Source ("Get-LocalGroupMember failed: {0}" -f $_.Exception.Message) -Severity '' -FindingId '' -Evidence ''
                }
            }
        }
        else {
            $computer = [ADSI]("WinNT://$hostname,computer")
            foreach ($child in $computer.Children) {
                if ($child.SchemaClassName -ne 'group') { continue }
                $groupName = $child.Name[0]
                try {
                    $memberObjs = @($child.psbase.Invoke('Members'))
                    if (-not $memberObjs -or $memberObjs.Count -eq 0) {
                        Add-Row -Category 'LocalGroupMember' -LocalGroup $groupName -RightName '' -RightId '' -PrincipalRaw '' -PrincipalType '' `
                            -Source 'ADSI (empty group)' -Severity '' -FindingId '' -Evidence ''
                        continue
                    }
                    foreach ($mo in $memberObjs) {
                        $adsi = [ADSI]$mo
                        $principal = $adsi.Path.Replace('WinNT://','').Replace('/','\')
                        Add-Row -Category 'LocalGroupMember' -LocalGroup $groupName -RightName '' -RightId '' -PrincipalRaw $principal -PrincipalType $adsi.SchemaClassName `
                            -Source 'ADSI' -Severity '' -FindingId '' -Evidence ''
                    }
                } catch {
                    Add-Row -Category 'Error' -LocalGroup $groupName -RightName '' -RightId '' -PrincipalRaw '' -PrincipalType '' `
                        -Source ("ADSI enum failed: {0}" -f $_.Exception.Message) -Severity '' -FindingId '' -Evidence ''
                }
            }
        }
    }
    catch {
        Add-Row -Category 'Error' -LocalGroup '' -RightName '' -RightId '' -PrincipalRaw '' -PrincipalType '' `
            -Source ("Local group enumeration failed: {0}" -f $_.Exception.Message) -Severity '' -FindingId '' -Evidence ''
    }
}

# ---------------------------
# 1b) Explicit audit of well-known groups (even if empty / localized)
# ---------------------------
if ($IncludeWellKnownGroups) {
    foreach ($friendly in $WellKnownLocalGroups.Keys) {
        $sid = $WellKnownLocalGroups[$friendly]
        try {
            $nt = ([System.Security.Principal.SecurityIdentifier]$sid).Translate([System.Security.Principal.NTAccount]).Value
            $localGroupName = $nt.Split('\')[-1]

            $members = @()
            if ($hasLocalAccountsCmdlets -and (Get-Command Get-LocalGroupMember -ErrorAction SilentlyContinue)) {
                try { $members = Get-LocalGroupMember -Group $localGroupName -ErrorAction Stop } catch { $members = @() }
                if (-not $members -or $members.Count -eq 0) {
                    Add-Row -Category 'LocalGroupMember' -LocalGroup $localGroupName -RightName '' -RightId '' -PrincipalRaw '' -PrincipalType '' `
                        -Source 'WellKnownSID (empty group)' -Severity '' -FindingId '' -Evidence ("SID={0}" -f $sid)
                } else {
                    foreach ($m in $members) {
                        Add-Row -Category 'LocalGroupMember' -LocalGroup $localGroupName -RightName '' -RightId '' -PrincipalRaw $m.Name -PrincipalType $m.ObjectClass `
                            -Source 'WellKnownSID' -Severity '' -FindingId '' -Evidence ("SID={0}" -f $sid)
                    }
                }
            }
            else {
                try {
                    $grp = [ADSI]("WinNT://$hostname/$localGroupName,group")
                    $memberObjs = @($grp.psbase.Invoke('Members'))
                    if (-not $memberObjs -or $memberObjs.Count -eq 0) {
                        Add-Row -Category 'LocalGroupMember' -LocalGroup $localGroupName -RightName '' -RightId '' -PrincipalRaw '' -PrincipalType '' `
                            -Source 'WellKnownSID+ADSI (empty group)' -Severity '' -FindingId '' -Evidence ("SID={0}" -f $sid)
                    } else {
                        foreach ($mo in $memberObjs) {
                            $adsi = [ADSI]$mo
                            $principal = $adsi.Path.Replace('WinNT://','').Replace('/','\')
                            Add-Row -Category 'LocalGroupMember' -LocalGroup $localGroupName -RightName '' -RightId '' -PrincipalRaw $principal -PrincipalType $adsi.SchemaClassName `
                                -Source 'WellKnownSID+ADSI' -Severity '' -FindingId '' -Evidence ("SID={0}" -f $sid)
                        }
                    }
                } catch {
                    Add-Row -Category 'Error' -LocalGroup $localGroupName -RightName '' -RightId '' -PrincipalRaw '' -PrincipalType '' `
                        -Source ("WellKnownSID ADSI failed: {0}" -f $_.Exception.Message) -Severity '' -FindingId '' -Evidence ("SID={0}" -f $sid)
                }
            }
        }
        catch {
            Add-Row -Category 'Error' -LocalGroup $friendly -RightName '' -RightId '' -PrincipalRaw '' -PrincipalType '' `
                -Source ("WellKnownSID translate failed: {0}" -f $_.Exception.Message) -Severity '' -FindingId '' -Evidence ("SID={0}" -f $sid)
        }
    }
}

# ---------------------------
# 2) User Rights Assignments via secedit
# ---------------------------
$rightsMap = @{
    'SeServiceLogonRight'            = 'Log on as a service'
    'SeBatchLogonRight'              = 'Log on as a batch job'
    'SeRemoteInteractiveLogonRight'  = 'Allow log on through Remote Desktop Services'
    'SeInteractiveLogonRight'        = 'Log on locally'
    'SeNetworkLogonRight'            = 'Access this computer from the network'

    'SeDenyRemoteInteractiveLogonRight' = 'Deny log on through Remote Desktop Services'
    'SeDenyInteractiveLogonRight'       = 'Deny log on locally'
    'SeDenyNetworkLogonRight'           = 'Deny access to this computer from the network'

    'SeImpersonatePrivilege'          = 'Impersonate a client after authentication'
    'SeAssignPrimaryTokenPrivilege'   = 'Replace a process level token'
    'SeDebugPrivilege'                = 'Debug programs'
    'SeBackupPrivilege'               = 'Back up files and directories'
    'SeRestorePrivilege'              = 'Restore files and directories'
    'SeTakeOwnershipPrivilege'        = 'Take ownership of files or other objects'
    'SeLoadDriverPrivilege'           = 'Load and unload device drivers'
    'SeShutdownPrivilege'             = 'Shut down the system'
    'SeRemoteShutdownPrivilege'       = 'Force shutdown from a remote system'
}

$infPath = Join-Path $env:TEMP ("secedit_rights_{0}.inf" -f ([guid]::NewGuid().ToString('N')))
try {
    $null = & secedit.exe /export /cfg $infPath /areas USER_RIGHTS 2>$null
    $exit = $LASTEXITCODE

    if ($exit -ne 0 -or -not (Test-Path $infPath)) {
        Add-Row -Category 'Error' -LocalGroup '' -RightName '' -RightId '' -PrincipalRaw '' -PrincipalType '' `
            -Source 'secedit.exe' -Severity '' -FindingId '' -Evidence ("secedit export failed. ExitCode={0}" -f $exit)
    }
    else {
        $lines = Get-Content -LiteralPath $infPath -Encoding Unicode -ErrorAction Stop

        foreach ($rightId in $rightsMap.Keys) {
            $rightName = $rightsMap[$rightId]
            $match = $lines | Where-Object { $_ -match ("^\s*{0}\s*=" -f [regex]::Escape($rightId)) } | Select-Object -First 1
            if (-not $match) { continue }

            $parts = $match.Split('=',2)
            if ($parts.Count -ne 2) { continue }

            $rawList = $parts[1].Trim()
            if ([string]::IsNullOrWhiteSpace($rawList)) { continue }

            $principals = $rawList.Split(',') | ForEach-Object { $_.Trim() } | Where-Object { $_ -ne '' }
            foreach ($p in $principals) {
                $resolved = Try-TranslateToName -SidOrName $p
                Add-Row -Category 'UserRightAssignment' -LocalGroup '' -RightName $rightName -RightId $rightId -PrincipalRaw $resolved -PrincipalType '' `
                    -Source 'secedit /areas USER_RIGHTS' -Severity '' -FindingId '' -Evidence ''
            }
        }
    }
}
catch {
    Add-Row -Category 'Error' -LocalGroup '' -RightName '' -RightId '' -PrincipalRaw '' -PrincipalType '' `
        -Source ("User rights export/parse failed: {0}" -f $_.Exception.Message) -Severity '' -FindingId '' -Evidence ''
}
finally {
    if (Test-Path $infPath) { Remove-Item -LiteralPath $infPath -Force -ErrorAction SilentlyContinue }
}

# ---------------------------
# 3) Finding engine (non-local principals in high-risk local groups)
# ---------------------------
$highRiskGroupsSid = @(
    'S-1-5-32-544', # Administrators
    'S-1-5-32-555', # Remote Desktop Users
    'S-1-5-32-580', # Remote Management Users
    'S-1-5-32-573', # Event Log Readers
    'S-1-5-32-551', # Backup Operators
    'S-1-5-32-549'  # Server Operators
)

function Get-LocalizedLocalGroupNameFromSid([string]$sid) {
    try {
        $nt = ([System.Security.Principal.SecurityIdentifier]$sid).Translate([System.Security.Principal.NTAccount]).Value
        return $nt.Split('\')[-1]
    } catch { return $null }
}

foreach ($sid in $highRiskGroupsSid) {
    $gName = Get-LocalizedLocalGroupNameFromSid $sid
    if (-not $gName) { continue }

    $members = $rows | Where-Object { $_.Category -eq 'LocalGroupMember' -and (Norm $_.LocalGroup) -eq (Norm $gName) -and $_.PrincipalResolved }
    foreach ($m in $members) {
        if ($m.IsNonLocalPrincipal -eq $true) {
            Add-Finding -Severity 'High' -FindingId 'NonLocalPrincipalInHighRiskLocalGroup' -Evidence ("Group={0}; Principal={1}; SID={2}" -f $gName, $m.PrincipalResolved, $m.PrincipalSid)
        }
    }
}

# ---------------------------
# 4) Cross-reference: Remote Desktop Users vs SeRemoteInteractiveLogonRight (+ Deny)
# ---------------------------
try {
    $rduSid = 'S-1-5-32-555'
    $rduNt  = ([System.Security.Principal.SecurityIdentifier]$rduSid).Translate([System.Security.Principal.NTAccount]).Value
    $rduLocalName = $rduNt.Split('\')[-1]
    $rduGroupResolvedNorm = Norm $rduNt

    $rduMembers = $rows |
        Where-Object { $_.Category -eq 'LocalGroupMember' -and (Norm($_.LocalGroup) -eq (Norm($rduLocalName))) -and $_.PrincipalResolved } |
        Select-Object -ExpandProperty PrincipalResolved -Unique

    $allowRdp = $rows |
        Where-Object { $_.Category -eq 'UserRightAssignment' -and $_.RightId -eq 'SeRemoteInteractiveLogonRight' -and $_.PrincipalResolved } |
        Select-Object -ExpandProperty PrincipalResolved -Unique

    $denyRdp = $rows |
        Where-Object { $_.Category -eq 'UserRightAssignment' -and $_.RightId -eq 'SeDenyRemoteInteractiveLogonRight' -and $_.PrincipalResolved } |
        Select-Object -ExpandProperty PrincipalResolved -Unique

    $allowGroupCovered = ($allowRdp | ForEach-Object { Norm $_ }) -contains $rduGroupResolvedNorm
    $denyGroupCovered  = ($denyRdp  | ForEach-Object { Norm $_ }) -contains $rduGroupResolvedNorm

    Add-Row -Category 'CrossReference' -LocalGroup $rduLocalName -RightName $rightsMap['SeRemoteInteractiveLogonRight'] -RightId 'SeRemoteInteractiveLogonRight' `
        -PrincipalRaw $rduNt -PrincipalType 'Group' -Source 'CrossRefSummary' -Severity '' -FindingId '' `
        -Evidence ("AllowGroupCovered={0}; DenyGroupCovered={1}; Members={2}" -f $allowGroupCovered, $denyGroupCovered, ($rduMembers.Count))

    if ($denyGroupCovered) {
        Add-Finding -Severity 'High' -FindingId 'RDPDenyAppliedToRemoteDesktopUsersGroup' -Evidence ("Group={0} has SeDenyRemoteInteractiveLogonRight" -f $rduNt)
    }

    foreach ($m in $rduMembers) {
        $mNorm = Norm $m
        $isExplicitlyAllowed = (($allowRdp | ForEach-Object { Norm $_ }) -contains $mNorm)
        $isExplicitlyDenied  = (($denyRdp  | ForEach-Object { Norm $_ }) -contains $mNorm)

        $effectiveAllowed = ($allowGroupCovered -or $isExplicitlyAllowed) -and (-not ($denyGroupCovered -or $isExplicitlyDenied))

        Add-Row -Category 'CrossReference' -LocalGroup $rduLocalName -RightName $rightsMap['SeRemoteInteractiveLogonRight'] -RightId 'SeRemoteInteractiveLogonRight' `
            -PrincipalRaw $m -PrincipalType '' -Source 'CrossRefMember' -Severity '' -FindingId '' `
            -Evidence ("AllowGroupCovered={0}; ExplicitAllow={1}; DenyGroupCovered={2}; ExplicitDeny={3}; EffectiveAllowed={4}" -f $allowGroupCovered, $isExplicitlyAllowed, $denyGroupCovered, $isExplicitlyDenied, $effectiveAllowed)

        if (-not $effectiveAllowed) {
            Add-Finding -Severity 'Medium' -FindingId 'RDU_Member_NotEffectivelyAllowedForRDP' -Evidence ("Member={0}; AllowGroupCovered={1}; ExplicitAllow={2}; DenyGroupCovered={3}; ExplicitDeny={4}" -f $m, $allowGroupCovered, $isExplicitlyAllowed, $denyGroupCovered, $isExplicitlyDenied)
        }
    }

    if (-not $rduMembers -or $rduMembers.Count -eq 0) {
        Add-Finding -Severity 'Info' -FindingId 'RemoteDesktopUsersGroupEmpty' -Evidence ("Group={0} appears empty on host" -f $rduLocalName)
    }
}
catch {
    Add-Row -Category 'Error' -LocalGroup 'Remote Desktop Users' -RightName '' -RightId '' -PrincipalRaw '' -PrincipalType '' `
        -Source ("Cross-reference failed: {0}" -f $_.Exception.Message) -Severity '' -FindingId '' -Evidence ''
}

# ---------------------------
# 5) Findings for non-local principals assigned to high-risk USER_RIGHTS
# ---------------------------
$highRiskRights = @(
    'SeServiceLogonRight',
    'SeBatchLogonRight',
    'SeRemoteInteractiveLogonRight',
    'SeImpersonatePrivilege',
    'SeAssignPrimaryTokenPrivilege',
    'SeDebugPrivilege',
    'SeBackupPrivilege',
    'SeRestorePrivilege',
    'SeTakeOwnershipPrivilege',
    'SeLoadDriverPrivilege'
)

foreach ($rid in $highRiskRights) {
    $entries = $rows | Where-Object { $_.Category -eq 'UserRightAssignment' -and $_.RightId -eq $rid -and $_.PrincipalResolved }
    foreach ($e in $entries) {
        if ($e.IsNonLocalPrincipal -eq $true -or $e.IsDomainSid -eq $true -or $e.IsDomainLikeName -eq $true) {
            Add-Finding -Severity 'Medium' -FindingId 'NonLocalPrincipalAssignedToUserRight' -Evidence ("Right={0}; Principal={1}; SID={2}" -f $rid, $e.PrincipalResolved, $e.PrincipalSid)
        }
    }
}

# ---------------------------
# Export main CSV (NO OS/GPO categories exist anymore in rows)
# ---------------------------
$rows |
    Select-Object Hostname, Category, LocalGroup, RightName, RightId,
        PrincipalRaw, PrincipalResolved, PrincipalSid, PrincipalType,
        IsNonLocalPrincipal, IsDomainSid, IsDomainLikeName, IsGroupHint,
        Severity, FindingId, Evidence, Source |
    Export-Csv -LiteralPath $outPathMain -NoTypeInformation -Encoding UTF8 -Delimiter $Delimiter

# ---------------------------
# Write context file (OS + gpresult)
# ---------------------------
$contextLines | Set-Content -LiteralPath $outPathContext -Encoding UTF8

Write-Host "Saved main CSV:     $outPathMain"
Write-Host "Saved context file: $outPathContext"
