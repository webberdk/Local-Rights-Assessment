#requires -version 5.1
[CmdletBinding()]
param(
    [Parameter(Mandatory)]
    [string]$InputFolder,

    [Parameter(Mandatory)]
    [string]$CsvPath,

    [string]$Delimiter = ';',

    # Hvis Tanium bulk-download ligger i under-mapper
    [switch]$Recurse,

    # Hvis du vil ignorere filer der ikke kan parses (fortsæt og log)
    [switch]$ContinueOnError,

    # Hvis du vil have en separat error-log
    [string]$ErrorLogPath = ''
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

function Join-IfArray($v) {
    if ($null -eq $v) { return '' }
    if ($v -is [System.Array]) { return ($v -join '') }
    return [string]$v
}

function Safe-Get($obj, [string]$name) {
    if ($null -eq $obj) { return $null }
    $p = $obj.PSObject.Properties[$name]
    if ($null -eq $p) { return $null }
    return $p.Value
}

function Write-ErrLine([string]$msg) {
    if ([string]::IsNullOrWhiteSpace($ErrorLogPath)) { return }
    try {
        $dir = Split-Path -Parent $ErrorLogPath
        if ($dir -and -not (Test-Path $dir)) { New-Item -Path $dir -ItemType Directory -Force | Out-Null }
        Add-Content -Path $ErrorLogPath -Value $msg -Encoding UTF8
    } catch {
        # ignore logging failures
    }
}

if (-not (Test-Path -LiteralPath $InputFolder)) {
    throw "InputFolder not found: $InputFolder"
}

$gciParams = @{
    Path   = $InputFolder
    Filter = '*.json'
    File   = $true
}
if ($Recurse) { $gciParams.Recurse = $true }

$files = Get-ChildItem @gciParams | Sort-Object FullName
if (-not $files -or $files.Count -eq 0) {
    throw "No .json files found in: $InputFolder"
}

# Collect rows in memory (ok for typical Tanium batches; if huge, we can stream later)
$all = New-Object 'System.Collections.Generic.List[object]'

foreach ($f in $files) {
    try {
        $jsonText = Get-Content -LiteralPath $f.FullName -Raw -Encoding UTF8
        if ([string]::IsNullOrWhiteSpace($jsonText)) { throw "Empty file" }

        $payload = $jsonText | ConvertFrom-Json

        # Determine rows array
        $rows = @()
        if ($payload.PSObject.Properties.Name -contains 'rows') {
            $rows = @($payload.rows)
        } else {
            $rows = @($payload)  # fallback
        }

        # pull top-level meta if present
        $payloadHostname = Join-IfArray (Safe-Get $payload 'hostname')
        $payloadDomain   = Join-IfArray (Safe-Get $payload 'domainOrWorkgroup')

        foreach ($r in $rows) {
            # Row-level values, with payload fallback
            $rowHostname = Join-IfArray (Safe-Get $r 'Hostname')
            if ([string]::IsNullOrWhiteSpace($rowHostname)) { $rowHostname = $payloadHostname }

            $rowDomain = Join-IfArray (Safe-Get $r 'Domain')
            if ([string]::IsNullOrWhiteSpace($rowDomain)) { $rowDomain = $payloadDomain }

            $all.Add([pscustomobject]@{
                SourceFile          = $f.Name

                Hostname            = $rowHostname
                Domain              = $rowDomain
                Category            = Join-IfArray (Safe-Get $r 'Category')
                LocalGroup          = Join-IfArray (Safe-Get $r 'LocalGroup')
                RightName           = Join-IfArray (Safe-Get $r 'RightName')
                RightId             = Join-IfArray (Safe-Get $r 'RightId')

                PrincipalRaw        = Join-IfArray (Safe-Get $r 'PrincipalRaw')
                PrincipalResolved   = Join-IfArray (Safe-Get $r 'PrincipalResolved')
                PrincipalSid        = Join-IfArray (Safe-Get $r 'PrincipalSid')
                PrincipalType       = Join-IfArray (Safe-Get $r 'PrincipalType')

                IsNonLocalPrincipal = Join-IfArray (Safe-Get $r 'IsNonLocalPrincipal')
                IsDomainSid         = Join-IfArray (Safe-Get $r 'IsDomainSid')
                IsDomainLikeName    = Join-IfArray (Safe-Get $r 'IsDomainLikeName')
                IsGroupHint         = Join-IfArray (Safe-Get $r 'IsGroupHint')

                Severity            = Join-IfArray (Safe-Get $r 'Severity')
                FindingId           = Join-IfArray (Safe-Get $r 'FindingId')
                Evidence            = Join-IfArray (Safe-Get $r 'Evidence')
                Source              = Join-IfArray (Safe-Get $r 'Source')
            })
        }
    } catch {
        $msg = "ERROR; File=$($f.FullName); $($_.Exception.Message)"
        Write-Output $msg
        Write-ErrLine $msg

        if (-not $ContinueOnError) { throw }
        continue
    }
}

# Ensure output dir exists
$outDir = Split-Path -Parent $CsvPath
if ($outDir -and -not (Test-Path $outDir)) { New-Item -Path $outDir -ItemType Directory -Force | Out-Null }

# Export combined CSV
$all |
  Export-Csv -LiteralPath $CsvPath -NoTypeInformation -Delimiter $Delimiter -Encoding UTF8

Write-Output ("OK; Files={0}; Rows={1}; Csv={2}" -f $files.Count, $all.Count, $CsvPath)
if ($ErrorLogPath) {
    Write-Output ("ErrorLog={0}" -f $ErrorLogPath)
}
