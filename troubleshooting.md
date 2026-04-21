# Troubleshooting Guide

Common issues encountered when running the Account Compromise Remediation scripts, with diagnostic steps and solutions. Organized by symptom.

If the scripts fail, **always check the preflight output first** — most issues are caught there with actionable remediation hints.

---

## 📋 Table of Contents

1. [Authentication & Connection](#authentication--connection)
2. [Preflight Validation Failures](#preflight-validation-failures)
3. [Permissions & Admin Roles](#permissions--admin-roles)
4. [Module & Version Issues](#module--version-issues)
5. [Target User Issues](#target-user-issues)
6. [Exchange Online Issues](#exchange-online-issues)
7. [Action-Specific Failures](#action-specific-failures)
8. [App-Only / Certificate Auth](#app-only--certificate-auth-invoke-accountremediationappauthps1)
9. [Automation / Managed Identity](#automation--managed-identity)
10. [Performance, Throttling & Timeouts](#performance-throttling--timeouts)
11. [Output, Logs & Reports](#output-logs--reports)
12. [Getting More Help](#getting-more-help)

---

## Authentication & Connection

### Q: `Connect-MgGraph` opens browser but hangs / never returns
**Cause:** Conditional Access is blocking the device, MFA challenge popped up in a different window, or the browser is blocking popups.

**Fix:**
1. Close any stale browser sessions to `login.microsoftonline.com`.
2. Try `Connect-MgGraph -UseDeviceAuthentication` as a fallback (Graph SDK 2.x).
3. If behind a proxy, set `$env:HTTPS_PROXY` before running.
4. For accounts requiring compliant devices, the host machine must be Intune-managed.

---

### Q: `AADSTS65001: The user or administrator has not consented to use the application`
**Cause:** The Graph PowerShell SDK app registration requires admin consent for one or more of the scopes requested by this toolkit.

**Fix:**
1. Sign in as a Global Administrator and pre-consent the Microsoft Graph PowerShell app (app id `14d82eec-204b-4c2f-b7e8-296a70dab67e`) to the scopes in `config/permissions.json`.
2. Alternatively, have a Global Admin run the script once — the first run consents for the tenant.
3. For automation, register a dedicated app and grant the `Application` equivalents of the delegated scopes.

---

### Q: `Reset user password` fails with `403 Authorization_RequestDenied` even when running as Global Admin
**Cause:** Writing to the user `passwordProfile` via Microsoft Graph requires the **delegated scope `Directory.AccessAsUser.All`**. `User.ReadWrite.All` and `Directory.ReadWrite.All` alone are **not** sufficient — the Graph API returns `Authorization_RequestDenied` regardless of your directory role (including Global Admin) when this scope is absent from the token.

**Fix (automatic, this release):** `Directory.AccessAsUser.All` is now in the default requested scope list. Graph caches your prior consent, but connecting with a new scope triggers a fresh consent prompt automatically. Just disconnect and re-run the toolkit:

```powershell
# One-time re-consent — do this after upgrading
Disconnect-MgGraph -ErrorAction SilentlyContinue
# Then re-run the toolkit — it will prompt you to consent to the new scope:
.\src\Invoke-AccountRemediation.ps1 -UserPrincipalName <upn>
```

(Or if you prefer to consent outside the script: `Connect-MgGraph -Scopes 'Directory.AccessAsUser.All'`.)

If consent is declined for `Directory.AccessAsUser.All` (it is a high-privilege scope and may be blocked by tenant policy), password reset via Graph will not work — use the Microsoft 365 admin center or `Reset-MsolUserPassword` (legacy) as a manual fallback.

---

### Q: `Connect-ExchangeOnline` fails with `System.NullReferenceException` / `RuntimeBroker` error
**Cause:** Known bug in MSAL's WAM (Web Account Manager) broker on some Windows hosts — particularly when running from VSCode terminal, Windows Terminal, or certain PowerShell hosts where the parent window handle isn't passed correctly to the broker.

**Fix (automatic):** As of this release, `Connect-ACRExchangeOnline` detects this error and automatically retries with device-code authentication. You'll see a "device code" prompt — open the URL it shows, paste the code, and sign in.

**Manual workarounds if needed:**
```powershell
# Option A: use device code up front
Connect-ExchangeOnline -Device -ShowBanner:$false

# Option B: disable WAM globally for MSAL in this session (before any auth)
$env:AZURE_IDENTITY_DISABLE_MULTITENANTAUTH = 'true'

# Option C: upgrade EXO to a version that addresses the issue
Update-Module ExchangeOnlineManagement -Force
```
Run it from a vanilla `pwsh.exe` console (not Windows Terminal) if the issue persists.

---

### Q: Script crashes on exit with `Unhandled exception ... NullReferenceException ... ClearAllTokensAsync`
**Cause:** Same WAM broker bug as above, but hitting `Disconnect-ExchangeOnline` on the way out. The EXO module tries to clear cached tokens via the WAM broker on a background `ThreadPool` thread; that thread throws an unobserved `NullReferenceException` which PowerShell 7 treats as fatal and exits the process. Because it's a background-thread exception, it cannot be caught by `try/catch`.

**Fix (automatic):** As of this release, when `Connect-ACRExchangeOnline` falls back to device-code auth, the script records that and `Disconnect-ACR` skips the call to `Disconnect-ExchangeOnline`. The EXO session is torn down cleanly when the PowerShell process exits — so no session leaks, no crash.

You may still see the crash if you manually call `Disconnect-ExchangeOnline` yourself afterwards. Either don't, or simply close the shell window — the session ends with the process.

---

### Q: `Connect-ExchangeOnline` succeeds but `Get-Mailbox` fails with "unable to connect"
**Cause:** Modern auth with MFA in EXO requires cookies/sessions that may conflict with a previously-active session.

**Fix:**
1. Run `Disconnect-ExchangeOnline -Confirm:$false` and retry.
2. Ensure `ExchangeOnlineManagement` version is `>= 3.0.0` (`Update-Module ExchangeOnlineManagement`).
3. On PS 7 on macOS/Linux, Basic auth is disabled; modern auth is the only option.

---

## Preflight Validation Failures

### Q: Preflight reports `[✗] Module:Microsoft.Graph.Users Fail`
**Cause:** Required Graph submodule not installed or below minimum version (2.0.0).

**Fix:**
```powershell
Install-Module Microsoft.Graph -Scope CurrentUser -MinimumVersion 2.0.0 -AllowClobber
```
If you have old v1.x installed:
```powershell
Uninstall-Module Microsoft.Graph -AllVersions -ErrorAction SilentlyContinue
Install-Module Microsoft.Graph -Scope CurrentUser
```

---

### Q: Preflight reports `[!] GraphConnection Warning — missing N recommended scope(s)`
**Cause:** The current Graph session was established with a subset of scopes (e.g., from a prior `Connect-MgGraph` call in the same shell).

**Fix:**
1. Disconnect and reconnect with the correct scope set:
   ```powershell
   Disconnect-MgGraph
   # Then re-run the script; it will connect with the complete scope list.
   ```
2. If the scopes themselves cannot be granted, check that the operator has consent authority (Global Admin) OR that the tenant has already consented the Graph PowerShell app.

---

### Q: Preflight reports `[!] OperatorPimRoles — dormant PIM-eligible roles`
**Cause:** You have privileged roles assigned via Privileged Identity Management (PIM), but they're not currently active.

**Fix:**
1. Go to [Azure AD PIM → My roles](https://portal.azure.com/#view/Microsoft_Azure_PIMCommon/MemberActivationMenuBlade) and activate the required role(s) with a justification and duration (e.g., 1-4 hours).
2. After activation, re-run the preflight — roles will now appear active.
3. If justifying activation is slow, request a Global Admin permanently assign temporary admin rights for the incident response.

---

### Q: Preflight reports `[!] UnifiedAuditLog Warning — ingestion disabled`
**Cause:** Tenant-level audit log ingestion is off, so `Search-UnifiedAuditLog` returns nothing.

**Fix:**
```powershell
Connect-ExchangeOnline
Set-AdminAuditLogConfig -UnifiedAuditLogIngestionEnabled $true
```
Wait 30-60 minutes for it to become effective. Note: historical data before enabling won't be retroactively available.

---

## Permissions & Admin Roles

### Q: Script runs, but actions fail with `Authorization_RequestDenied` or `Insufficient privileges`
**Cause:** Operator lacks the required admin role for that action. Example: Global Reader can read data but not modify.

**Fix:**
Required roles per action category:
| Action | Required Role |
|--------|--------------|
| Password reset, account disable, revoke tokens | User Administrator, Privileged Authentication Administrator, Global Administrator |
| Remove MFA methods, enforce MFA | Authentication Administrator, Privileged Authentication Administrator |
| Remove app consents (admin scope) | Cloud Application Administrator, Application Administrator, Global Administrator |
| Mailbox actions (delegates, forwarding, rules) | Exchange Administrator, Global Administrator |
| Conditional Access, sign-in risk | Security Administrator, Conditional Access Administrator |
| Application credentials rotation | Application Administrator, Cloud Application Administrator |

Activate the correct PIM role or have a Global Admin run the affected action.

---

### Q: Error: `Can't modify password because account is synced from on-premises Active Directory`
**Cause:** The user is hybrid-synced. Cloud password reset is blocked unless Password Writeback is enabled in Azure AD Connect.

**Fix:**
1. Enable **Password Writeback** in Azure AD Connect → Optional Features.
2. Alternatively, reset the password in on-prem AD, then force a delta sync: `Start-ADSyncSyncCycle -PolicyType Delta`.
3. For hybrid users, consider also disabling the on-prem account until investigation completes.

---

### Q: Error setting `ForwardingSmtpAddress` on hybrid mailbox
**Cause:** Cloud attribute is read-only when the object is synced from on-prem.

**Fix:**
1. In on-prem Exchange: `Set-RemoteMailbox <identity> -ForwardingAddress $null`.
2. Or use `Set-Mailbox` in EXO with the `-ForwardingAddress` set to `$null` (works for mail-enabled user objects).
3. Some directory attributes require disabling DirSync for that specific attribute (not recommended).

---

## Module & Version Issues

### Q: `The term 'Connect-ExchangeOnline' is not recognized`
**Fix:**
```powershell
Install-Module ExchangeOnlineManagement -Scope CurrentUser -MinimumVersion 3.0.0
```

---

### Q: `Microsoft.PowerApps.Administration.PowerShell` fails to import on PowerShell 7
**Cause:** This module is only compatible with Windows PowerShell 5.1. Actions 13-15 use it via a compatibility shim (`Import-Module -UseWindowsPowerShell`).

**Fix:**
1. On Windows, ensure Windows PowerShell 5.1 is installed (it is on all Windows 10/11 and Server 2016+).
2. On macOS/Linux, Power Platform actions will return a Warning status and be skipped. Run those actions from a Windows host if needed.
3. Install the module from a Windows PowerShell 5.1 prompt:
   ```powershell
   Install-Module Microsoft.PowerApps.Administration.PowerShell -Scope CurrentUser
   ```

---

### Q: `Could not load type 'System.Net.Http.HttpClientHandler'` or `System.Management.Automation` errors
**Cause:** PowerShell version mismatch, often caused by a module built for .NET Framework loaded in PS 7 (.NET Core).

**Fix:**
1. Verify `$PSVersionTable.PSVersion` is `>= 7.2.0`.
2. Uninstall any Graph/EXO modules that were installed under Windows PowerShell and reinstall cleanly under PS 7.
3. Remove `$env:PSModulePath` entries pointing to `WindowsPowerShell\Modules` when running under PS 7.

---

## Target User Issues

### Q: Preflight fails with `TargetUser Fail — user not found`
**Cause:** UPN is wrong, user was already deleted, or the operator doesn't have `User.Read.All`.

**Fix:**
1. Verify UPN exactly — watch for homoglyphs (Cyrillic 'а' vs Latin 'a') in compromise scenarios.
2. Check deleted users: `Get-MgDirectoryDeletedItemAsUser -Filter "userPrincipalName eq '<upn>'"`.
3. Ensure operator has at least `User.Read.All` scope.

---

### Q: `TargetUser Warning — User is a Guest account`
**Cause:** B2B guest users don't have mailboxes, licenses, or group memberships in your tenant.

**Fix:**
For B2B guests:
- Skip all mailbox actions (5-9, 20) with `-Actions` flag.
- Focus on: `DisableAccount`, `RemoveUserConsentApps`, `RemoveAdminConsentApps`, `RevokeTokens`.
- Contact the guest's home tenant admin for full remediation.

---

### Q: Sign-in logs / audit logs empty for user
**Cause:** Either (a) user has no Entra ID P1+ license, (b) tenant audit is disabled, or (c) the time window has no activity.

**Fix:**
1. Check preflight `TargetUserLicenses` — if no Entra P1, sign-in logs aren't available.
2. Enable audit ingestion (see above).
3. Increase lookback: the default is 7 days. Edit `$script:LookbackDays` in `ACR.Remediation.psm1` if investigating older activity.

---

## Exchange Online Issues

### Q: Action 6 (Folder Permissions): `The specified folder could not be found in the store`
**Cause:** Folder name is localized (e.g., "Posteingang" in a German mailbox), but the script iterates English names.

**Fix:**
Run this once in the user's mailbox context to discover actual folder names:
```powershell
Get-MailboxFolderStatistics -Identity <upn> -FolderScope All |
    Select Name, FolderPath, FolderType
```
Then update the folder list in `Remove-ACRMailboxFolderPermissions` (line ~475 of `ACR.Remediation.psm1`) to include the localized names — or submit a PR using `FolderType` instead of `Name`.

---

### Q: Action 20 (Exchange Rules): `You cannot connect to Exchange Online because your account does not have sufficient privileges`
**Cause:** Operator is not an Exchange Administrator. The Graph Global Administrator role does *implicitly* grant Exchange admin access, but the EXO session may not have refreshed role claims.

**Fix:**
1. Disconnect all sessions: `Disconnect-ExchangeOnline -Confirm:$false` + close PowerShell window.
2. Wait 5 minutes for token propagation.
3. Re-run. If still failing, explicitly add the operator to the Exchange Administrator role.

---

### Q: `Search-UnifiedAuditLog` returns 0 results but I know the user had activity
**Cause:** Most common causes in order:
1. Tenant audit ingestion disabled (preflight catches this).
2. User has no license supporting audit logging (Basic, Kiosk F SKUs are limited).
3. Activity was within last ~30 minutes (there's an ingestion delay of up to 1-2 hours).
4. Search date range misaligned with user's timezone.

**Fix:**
```powershell
Search-UnifiedAuditLog -StartDate (Get-Date).AddDays(-30) -EndDate (Get-Date) -UserIds <upn> -ResultSize 100
```
If still empty after 24 hours of enabling audit, contact Microsoft Support.

---

## Action-Specific Failures

### Q: Action 4 (Remove App Passwords) always returns "Warning" status
**Cause:** This is **expected behavior**. App passwords are a legacy per-user MFA feature with no direct Graph or EXO cmdlet for programmatic removal.

**Fix (recommended):**
- Revoking refresh tokens (Action 2) invalidates existing app passwords indirectly by forcing re-authentication.
- For explicit removal, go to Azure Portal → the user → Authentication methods → delete app password entries manually.
- Better long-term: disable legacy authentication entirely via Conditional Access.

---

### Q: Action 8 (Outlook Add-ins) returns Warning with manual steps
**Cause:** Also **expected**. There's no reliable programmatic API to remove user-sideloaded Outlook add-ins across all types (Office Store, sideloaded, admin-deployed).

**Fix:**
Follow the manual steps in the output: Exchange Admin Center → Organization → Add-ins. For tenant-wide policy, use `Set-App` to block specific add-ins.

---

### Q: Action 10 (Disable Account) succeeds but user can still sign in for a few minutes
**Cause:** Entra ID caches authentication decisions. Existing access tokens remain valid until expiry (typically 1 hour).

**Fix:**
1. Always run `RevokeTokens` (Action 2) **before or alongside** `DisableAccount`.
2. For immediate effect on Microsoft 365 services, also revoke sessions via `Revoke-MgUserSignInSession`.

---

### Q: Action 11 (Remove MFA Methods) completes but user still has MFA methods
**Cause:** Some methods (e.g., Windows Hello for Business, FIDO2 keys registered via the device) cannot be removed through Graph. Also, `$MFA_Phone` per-user defaults set by admin may remain.

**Fix:**
- Verify with `Get-MgUserAuthenticationMethod -UserId <upn>`.
- Remove FIDO2 keys via Azure Portal → User → Authentication methods.
- Hardware tokens require admin revocation in Conditional Access / Passwordless settings.

---

### Q: Action 14 (Remove Power Apps) skipped with "Module not available"
**Cause:** You're running on PS 7 on non-Windows, OR the PowerApps module isn't installed.

**Fix:**
1. On Windows, install: `Install-Module Microsoft.PowerApps.Administration.PowerShell` (in a Windows PowerShell 5.1 prompt).
2. On non-Windows hosts, run Power Platform actions separately from a Windows host.
3. Ensure the operator has a Power Platform admin role or tenant admin role.

---

## App-Only / Certificate Auth (`Invoke-AccountRemediationAppAuth.ps1`)

### Q: `AADSTS65001: The user or administrator has not consented to use the application`
**Cause:** Admin consent for one or more Graph **application** permissions on the app registration is missing.

**Fix:**
1. Re-run the setup helper as a Global Admin: `.\src\Setup-ACRAppRegistration.ps1 -TenantId '<tenant>'`. It is idempotent and grants any missing role assignments.
2. Or manually in the Entra portal → App registrations → ACR app → API permissions → "Grant admin consent for <tenant>".

---

### Q: `AADSTS700016: Application with identifier '<id>' was not found in the directory '<tenant>'`
**Cause:** Wrong TenantId, wrong ClientId, or the app exists in a different tenant than configured.

**Fix:**
1. Verify `config/app-auth.json` matches the tenant where setup was run.
2. Override at the CLI: `-TenantId '...' -ClientId '...'`.
3. Re-run setup if the app was deleted.

---

### Q: Setup helper completes but `Connect-ExchangeOnline` fails with "User is not assigned to the role"
**Cause:** `New-ServicePrincipal -AppId -ServiceId` was not run inside Exchange Online, or the SP is not a member of an Exchange role group.

**Fix:**
1. Re-run setup with EXO step enabled (default), or manually:
   ```powershell
   Connect-ExchangeOnline   # interactive, as Global Admin
   New-ServicePrincipal -AppId <ClientId> -ServiceId <ServicePrincipalObjectId> -DisplayName "ACR App Auth"
   ```
2. Verify SP membership in the **Exchange Administrator** directory role (Entra portal → Roles → Exchange Administrator → Assignments).

---

### Q: `Certificate with thumbprint '<x>' not found in CurrentUser\My or LocalMachine\My`
**Cause:** The cert isn't installed on this workstation, or you ran setup as a different Windows user (cert lives in their `CurrentUser\My`).

**Fix:**
1. Verify the cert exists for the **same Windows user** that runs the script: `Get-ChildItem Cert:\CurrentUser\My | Where-Object Thumbprint -eq '<thumbprint>'`.
2. If you set up on another machine, re-run setup on this workstation. The helper adds a new keyCredential to the existing app registration — no duplicate apps are created.
3. If using an exportable PFX: `Import-PfxCertificate -FilePath cert.pfx -CertStoreLocation Cert:\CurrentUser\My`.

---

### Q: `Certificate '<x>' expired on <date>`
**Cause:** The cert lifetime (default 365 days) has elapsed.

**Fix:** Rotate per [Getting Started §4.4](getting-started.md#44-certificate-rotation). Re-run setup to mint a new cert and add it as an additional keyCredential, then update `config/app-auth.json` with the new thumbprint and remove the old keyCredential from the app.

---

### Q: Preflight reports `App is missing N recommended Graph application permission(s)`
**Cause:** Admin consent is partial — some app role assignments are missing.

**Fix:** Check the preflight `Details.MissingRoles` for the exact list. Re-run setup, or grant the missing roles in the Entra portal under the app's API permissions tab.

---

### Q: Action 1 (Reset password) fails for an admin user with `Insufficient privileges`
**Cause:** Graph application permission `User.ReadWrite.All` allows resetting non-admin user passwords. Resetting passwords of users in privileged Entra roles requires the SP to additionally hold the **Privileged Authentication Administrator** directory role.

**Fix:**
1. Assign the SP to "Privileged Authentication Administrator" in Entra (Roles → role → Assignments → Add).
2. Or escalate the password reset to a Global Admin out-of-band.

---

## Automation / Managed Identity

### Q: Auto-remediation script exits with code 2 and error "Managed Identity not available"
**Cause:** Running in an environment that doesn't support MI (local PC), or MI isn't assigned/enabled.

**Fix:**
1. For Azure Automation: ensure the Automation Account has a System-Assigned or User-Assigned managed identity, and Graph API permissions have been granted via PowerShell to that MI (see `getting-started.md` §4).
2. For Logic Apps: same applies to the Logic App's MI.
3. For local testing, use `Invoke-AccountRemediation.ps1` instead (interactive).

---

### Q: Managed Identity has Graph permissions but `Connect-ExchangeOnline -ManagedIdentity` fails
**Cause:** MI needs a separate role assignment in Exchange Online. Graph app roles don't automatically grant EXO access.

**Fix:**
Run as Global Admin (PowerShell 5.1):
```powershell
Connect-ExchangeOnline
# Grant the MI the Exchange.ManageAsApp role
New-ServicePrincipal -AppId <managed-identity-app-id> -ServiceId <mi-object-id> -DisplayName "ACR MI"
Add-RoleGroupMember -Identity "Organization Management" -Member "ACR MI"
```
Also ensure the MI's service principal has the `Exchange.ManageAsApp` application permission on Office 365 Exchange Online (00000002-0000-0ff1-ce00-000000000000).

---

### Q: Automation runbook times out after 3 hours
**Cause:** Azure Automation runbook default timeout; forensic collection over a large audit window can exceed this.

**Fix:**
1. Add `-SkipForensics` to the invocation if forensics runs separately.
2. Reduce `$script:LookbackDays` in `ACR.Remediation.psm1`.
3. Consider using Azure Automation Hybrid Worker for longer-running jobs.

---

## Performance, Throttling & Timeouts

### Q: Script slows down mid-run with `429 Too Many Requests` errors
**Cause:** Microsoft Graph / Exchange throttling — expected for bulk operations.

**Fix:**
- The scripts auto-retry with exponential backoff up to `$MaxRetries` (default 3).
- Increase if needed: `-MaxRetries 5 -RetryDelaySeconds 30`.
- Space out runs if remediating multiple users; use serial rather than parallel execution.

---

### Q: `Get-MgAuditLogSignIn` takes 5+ minutes to return
**Cause:** Sign-in log queries can be slow for busy users or large time windows.

**Fix:**
- Reduce the lookback window if 7 days is unnecessary.
- Sign-in logs are particularly slow near quota limits; check tenant audit retention.

---

## Output, Logs & Reports

### Q: HTML report is blank or missing sections
**Cause:** Forensics for one or more sources errored silently and returned empty.

**Fix:**
1. Check `<output-path>/logs/action-log.json` for errors in the collection phase.
2. Re-run with `$VerbosePreference = 'Continue'` to see per-source status.
3. Forensic data shape changed — verify you're on the latest code (post-audit fixes include property name alignment).

---

### Q: Rollback journal exists but I can't auto-reverse changes
**Cause:** By design — the journal is a **record of what was done**, not an executable rollback. Some actions (password reset, token revocation) cannot be reversed automatically.

**Fix:**
1. Read `<output-path>/logs/rollback-journal.json` — each entry has `BeforeState` and `RollbackInstructions` fields.
2. Manually execute the rollback commands using the captured state (e.g., re-add delegates using the saved `User` and `AccessRights`).
3. A future release may include `Invoke-ACRRollback.ps1` to partially automate this.

---

### Q: Action log entries show `status: Retry` — is that a failure?
**Cause:** A transient throttling error triggered a retry. The final entry for that action will show the real status.

**Fix:** Look for the final status entry for that action. If it ends in `Success`, no action needed. If `Failed`, investigate the error message in that entry.

---

## Getting More Help

If an issue isn't covered here:

1. **Enable verbose output:**
   ```powershell
   $VerbosePreference = 'Continue'
   .\src\Invoke-AccountRemediation.ps1 -UserPrincipalName <upn> -RunAll -DryRun
   ```
   Always try `-DryRun` first to preview the actions.

2. **Check the action log:** `<OutputPath>/logs/action-log.json` — structured JSON with timestamps and error details.

3. **Check the preflight result:** Rerun with `-SkipPreflight:$false` to see current environment state.

4. **Capture a transcript:**
   ```powershell
   Start-Transcript -Path .\acr-debug.log
   # run script
   Stop-Transcript
   ```
   Share `acr-debug.log` + `action-log.json` when reporting issues.

5. **Open an issue** with the above artifacts and these details:
   - PowerShell version (`$PSVersionTable.PSVersion`)
   - Module versions (`Get-Module Microsoft.Graph, ExchangeOnlineManagement -ListAvailable`)
   - Operator's directory role(s)
   - Target user type (cloud-only, hybrid, guest)
   - Which action failed and full error message
