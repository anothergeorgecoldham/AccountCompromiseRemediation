# Copilot instructions — AccountCompromiseRemediation

PowerShell 7.2+ toolkit for remediating compromised Entra ID / M365 accounts. Three entry scripts share six modules in `src/modules/`. No build step; tests run with Pester 5.

## Commands

```powershell
# Full test suite (129 tests)
Invoke-Pester -Path ./tests -Output Detailed

# Single test file
Invoke-Pester -Path ./tests/ACR.Preflight.Tests.ps1 -Output Detailed

# Single test by name (Pester -FullNameFilter matches the Describe→Context→It path)
Invoke-Pester -Path ./tests -FullNameFilter '*Test-ACRTargetUserLicenses*ServicePlans*' -Output Detailed

# Parse-check a script without executing it (use after editing any .ps1/.psm1)
$errors = $null; [System.Management.Automation.Language.Parser]::ParseFile('src/modules/ACR.Auth.psm1', [ref]$null, [ref]$errors); $errors
```

There is no linter, formatter, or build. The "build" is parse-checking + Pester. Always run the full suite after touching any module — modules are tightly coupled through a shared logging session.

## Architecture

**Three entry scripts, one engine.** `src/Invoke-AccountRemediation.ps1` (interactive, delegated auth), `src/Invoke-AccountRemediationAppAuth.ps1` (interactive, app-only cert auth — for low-privilege analysts), and `src/Invoke-AutoRemediation.ps1` (non-interactive, Managed Identity, JSON output, exit codes 0/1/2). They all import the same six modules and execute the same `$ActionDefinitions` map of remediation actions. The two interactive scripts are deliberately kept as parallel copies — do **not** extract a shared helper without explicit instruction; preserving byte-identical UX is a constraint.

**Run flow:** entry script → `Connect-ACR*` (auth) → `Start-ACRLog` (creates session-scoped state in `ACR.Logging`) → `Invoke-ACRPreflight` (returns `Ready=$true/$false`; blocks if false unless `-SkipPreflight`) → `Invoke-ACRForensicCollection` (7-day audit/sign-in/mailbox/unified logs) → loop over selected actions in `ACR.Remediation` → `Stop-ACRLog` (writes `action-log-*.json` and `rollback-journal-*.json` to disk) → `New-ACRHtmlReport`.

**Module responsibilities** (`src/modules/ACR.*.psm1`):
- `ACR.Auth` — Connect-MgGraph wrappers (Interactive / ManagedIdentity / AppAuth via cert) + EXO equivalents + `Get-ACROperatorIdentity` for app-auth runs.
- `ACR.Preflight` — Validates PS version, modules, Graph/EXO connectivity, target user & licenses, operator roles. The `-AuthMode AppOnly` switch swaps `Test-ACROperatorRoles` / `Test-ACROperatorPimRoles` for `Test-ACRAppAuthContext`.
- `ACR.Logging` — **Session singleton** in `$script:LogSession`; `Start-ACRLog` is mandatory before any Write-ACRAction call. Without an active session the action helpers warn and no-op.
- `ACR.Forensics` — Read-only Graph + EXO queries; results saved to `forensics/<UPN>_<timestamp>/`.
- `ACR.Remediation` — 20 numbered remediation actions; one `function <Verb>-ACR<Noun>` per action.
- `ACR.Reporting` — JSON/CSV exports + HTML summary report.

**Setup helper:** `src/Setup-ACRAppRegistration.ps1` is a separate one-time idempotent helper a Global Admin runs to provision the app registration consumed by `Invoke-AccountRemediationAppAuth.ps1`. It supports `-WhatIf` and re-runs add new keyCredentials rather than duplicating the app.

**Config:** `config/permissions.json` is the source of truth for required Graph delegated scopes, app role IDs (with hardcoded GUIDs for stable tenant-independent consent), and EXO directory roles. `config/app-auth.json` is gitignored — only the `.example` template is committed.

## Conventions

**Every remediation action must:**
1. Use the verb-noun pattern `Verb-ACR<Noun>` (e.g. `Reset-ACRPassword`, `Remove-ACRMailboxDelegates`). Note `Enforce-ACRMFA` uses an unapproved verb — Pester suppresses the warning at module load. Don't "fix" it; the name is part of the action map.
2. Call `Write-ACRAction -Action <Name> -Status Success|Failed|Skipped|Warning` for the human/audit trail.
3. Call `Write-ACRRollbackEntry` with `BeforeState` / `AfterState` / `RollbackInstructions` for any **mutating** operation. Read-only actions don't need a rollback entry.
4. Return a result via `New-ACRResult -Status -Message [-Details]` — never throw out of an action; callers iterate and aggregate.
5. Wrap the body in `try`/`catch`; on failure log Failed and return Failed — do not propagate exceptions.

**Logging session is implicit shared state.** `ACR.Logging` holds `$script:LogSession`. Tests must call `Stop-ACRLog` in `AfterEach` (see `tests/ACR.Logging.Tests.ps1`) — leaving a session open leaks across tests and produces confusing failures.

**Operator attribution under app-only auth.** When `AuthMode='AppOnly'`, every Graph call happens as the SP, so `Get-ACROperatorIdentity` captures the Windows identity (or `-OperatorUpn` override) and `Start-ACRLog -OperatorIdentity ... -AuthMode AppOnly` persists it to the action-log header **and** every rollback journal entry. Don't break this for app-auth changes.

**Permissions.json contract.** Two parallel sections: `delegatedPermissions` (Graph scopes for the interactive script) and `applicationPermissionsAppAuth.graphAppRoles` (app role assignments for the cert-auth flow, with literal `id` GUIDs). Keep them in sync when adding a new Graph call. `Setup-ACRAppRegistration.ps1` reads the `applicationPermissionsAppAuth` section to grant admin consent — adding a permission there with no `id` will break setup.

**Tests:** Pester 5 only. Mocks always use `-ModuleName` so they intercept calls inside the module under test. Many Graph cmdlets aren't installed locally — tests stub them in a `BeforeAll` block before importing the module (see `tests/ACR.Auth.Tests.ps1` and `tests/ACR.Auth.AppAuth.Tests.ps1` for the pattern). For cert-related tests, build a real `X509Certificate2` in-memory with `CertificateRequest.CreateSelfSigned()` rather than mocking — the SDK rejects PSCustomObject fakes.

**Never commit:** `forensics/`, `output/`, `logs/`, `rollback/`, `config/app-auth.json`, anything under `**/CREDENTIALS/`, `**/password-*.txt`. The `.gitignore` enforces this. Real customer audit data may exist locally — verify with `git ls-files | Select-String '^forensics/'` before pushing.

**Pre-existing inconsistency to leave alone:** `src/Invoke-AutoRemediation.ps1` line 206 references `$logSession.RollbackJournalPath` but `Start-ACRLog` produces `RollbackPath`. Out of scope for unrelated changes.
