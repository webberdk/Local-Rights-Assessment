# Get-current-rights

Collect and review local rights assignments and local group membership on Windows endpoints, then optionally merge the JSON output into a single CSV for analysis.

## Included scripts

- `get-local-rights.ps1`: Runs on a Windows host and emits a JSON payload to STDOUT containing:
  - Local group memberships for all groups plus well-known high‑risk groups (SID-based, locale-independent).
  - User Rights Assignments via `secedit`.
  - Cross‑checks and findings such as non-local principals in high‑risk groups or denied RDP access.
  - A chunked JSON format to avoid long-string truncation in Tanium exports.
- `Merge-LocalRightsAuditJsonToCsv.ps1`: Merges one or more JSON outputs (for example, Tanium bulk downloads) into a single CSV file.

## Requirements

- PowerShell 5.1+ on Windows.
- Permissions to query local groups and security policy.

## Usage

### Collect local rights (JSON)

```powershell
# Run locally and write JSON to a file
./get-local-rights.ps1 | Out-File -FilePath .\local-rights.json -Encoding utf8

# Optional parameters
./get-local-rights.ps1 -ChunkSize 48 -ChunkThreshold 60 -IncludeAllLocalGroups $true -IncludeWellKnownGroups $true
```

### Merge JSON into CSV

```powershell
# Merge all JSON files in a folder
./Merge-LocalRightsAuditJsonToCsv.ps1 -InputFolder .\downloads -CsvPath .\local-rights.csv

# Recurse into subfolders and log parse errors
./Merge-LocalRightsAuditJsonToCsv.ps1 -InputFolder .\downloads -CsvPath .\local-rights.csv -Recurse -ContinueOnError -ErrorLogPath .\merge-errors.log
```

## Output format (high level)

The JSON payload includes a `summary` section plus a `rows` array of findings and membership entries. Long strings may be returned as arrays of short strings (chunked) to keep exports safe; the merge script re-joins these values.

## Notes

- The collection script is read‑only and does not write files.
- The merge script expects valid JSON files from the collection script and will stop on errors unless `-ContinueOnError` is set.
