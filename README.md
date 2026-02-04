# Local-Rights-Assessment

Collect and review local rights assignments and local group membership on Windows endpoints, emitting CSV for analysis.

## Included scripts

- `get-local-rights.ps1`: Runs on a Windows host and emits CSV to STDOUT containing:
  - Local group memberships for all groups plus well-known high‑risk groups (SID-based, locale-independent).
  - User Rights Assignments via `secedit`.
  - Cross‑checks and findings such as non-local principals in high‑risk groups or denied RDP access.

## Requirements

- PowerShell 5.1+ on Windows.
- Permissions to query local groups and security policy.

## Usage

### Collect local rights (CSV)

```powershell
# Run locally and write CSV to a file
./get-local-rights.ps1 | Out-File -FilePath .\local-rights.csv -Encoding utf8

# Optional parameters
./get-local-rights.ps1 -IncludeAllLocalGroups $true -IncludeWellKnownGroups $true
```

## Output format (high level)

The CSV output includes one row per finding or membership entry, with columns such as host, domain, category, local group, right name/id, principal details, and evidence.

## Notes

- The collection script is read‑only and does not write files.
