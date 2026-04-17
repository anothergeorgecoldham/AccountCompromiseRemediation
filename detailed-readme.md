# Detailed Remediation Reference

This document describes each of the 20 remediation actions, including the PowerShell modules and cmdlets used, how they behave in interactive vs non-interactive mode, and any manual review steps required.

---

## Module Dependencies Overview

| PowerShell Module | Install Command | Used By |
|---|---|---|
| **Microsoft.Graph.Authentication** | `Install-Module Microsoft.Graph.Authentication` | Auth (both modes) |
| **Microsoft.Graph.Users** | `Install-Module Microsoft.Graph.Users` | Actions 1–3, 5–7, 11–12, 16–17, 18–19, 20 |
| **Microsoft.Graph.Users.Actions** | `Install-Module Microsoft.Graph.Users.Actions` | Action 2 (Revoke-MgUserSignInSession) |
| **Microsoft.Graph.Identity.SignIns** | `Install-Module Microsoft.Graph.Identity.SignIns` | Actions 3–4, 12, 18 (OAuth2 grants) |
| **Microsoft.Graph.Reports** | `Install-Module Microsoft.Graph.Reports` | Forensics (sign-in & audit logs) |
| **Microsoft.Graph.Mail** | `Install-Module Microsoft.Graph.Mail` | Actions 5–8, Forensics (mailbox) |
| **Microsoft.Graph.Calendar** | `Install-Module Microsoft.Graph.Calendar` | Action 10 (calendar sharing) |
| **Microsoft.Graph.Files** | `Install-Module Microsoft.Graph.Files` | Action 16 (SharePoint/OneDrive) |
| **Microsoft.Graph.Groups** | `Install-Module Microsoft.Graph.Groups` | Action 17 (Teams guests) |
| **Microsoft.Graph.Applications** | `Install-Module Microsoft.Graph.Applications` | Action 19 (app registration secrets) |
| **Microsoft.Graph.DeviceManagement** | `Install-Module Microsoft.Graph.DeviceManagement` | Action 11 (mobile devices) |
| **ExchangeOnlineManagement** (v2.0.3+) | `Install-Module ExchangeOnlineManagement` | Action 20, Forensics (unified audit log) |
| **Microsoft.PowerApps.Administration.PowerShell** ⚠ | `Install-Module Microsoft.PowerApps.Administration.PowerShell` | Actions 13–15 (Power Platform) |

> **⚠ PowerShell 7 Compatibility Note:** The `Microsoft.PowerApps.Administration.PowerShell` module only supports **Windows PowerShell 5.1** natively. When running on PowerShell 7+ on Windows, the scripts automatically use `Import-Module -UseWindowsPowerShell` to proxy calls through a WinPS 5.1 compatibility session. This means:
> - **Windows:** Actions 13–15 work on both PS 5.1 and PS 7+ (via compatibility proxy)
> - **Linux/macOS:** Actions 13–15 will fall back to Warning status with manual review instructions, as the compatibility proxy is Windows-only
> - All other actions (1–12, 16–20) work natively on PS 7.2+ across all platforms

---

## Authentication Differences

| Aspect | Interactive Script | Non-Interactive Script |
|---|---|---|
| **Function** | `Connect-ACRInteractive` | `Connect-ACRManagedIdentity` |
| **Cmdlet** | `Connect-MgGraph -Scopes <list>` | `Connect-MgGraph -Identity` |
| **Flow** | Browser-based delegated auth | Azure Managed Identity (no user interaction) |
| **Permissions** | Delegated permissions | Application permissions |
| **Retry logic** | None (operator present) | Exponential backoff on HTTP 429/503 |

---

## Remediation Actions Detail

### Action 1: Reset User Password

| Aspect | Detail |
|---|---|
| **Function** | `Reset-ACRPassword` |
| **Graph Module** | `Microsoft.Graph.Users` |
| **Key Cmdlet** | `Update-MgUser -UserId <UPN> -PasswordProfile @{...}` |
| **What it does** | Generates a cryptographically random 24-character password, sets it on the account, and requires change at next sign-in |
| **Interactive** | Operator selects from menu or uses `-Actions "ResetPassword"` |
| **Non-Interactive** | Runs automatically; result included in JSON output |
| **Rollback** | Logs that a reset occurred (password value is never logged). To rollback, an admin must communicate a new password to the user |

---

### Action 2: Revoke Refresh Tokens

| Aspect | Detail |
|---|---|
| **Function** | `Revoke-ACRRefreshTokens` |
| **Graph Module** | `Microsoft.Graph.Users.Actions` |
| **Key Cmdlet** | `Revoke-MgUserSignInSession -UserId <UPN>` |
| **What it does** | Invalidates all refresh tokens, forcing re-authentication on every device and application |
| **Interactive** | Operator selects from menu or uses `-Actions "RevokeTokens"` |
| **Non-Interactive** | Runs automatically; result included in JSON output |
| **Rollback** | Irreversible — user must re-authenticate. No data is lost |

---

### Action 3: Enforce Multi-Factor Authentication

| Aspect | Detail |
|---|---|
| **Function** | `Enforce-ACRMFA` |
| **Graph Module** | `Microsoft.Graph.Users` / `Microsoft.Graph.Identity.SignIns` |
| **Key Cmdlets** | `Get-MgUserAuthenticationMethod -UserId <UPN>` |
| **What it does** | Checks registered authentication methods to determine MFA status. If the user has only password-based methods or is excluded from Conditional Access MFA policies, it flags the account for manual review |
| **Interactive** | Displays MFA status and any issues; operator decides next steps |
| **Non-Interactive** | Logs MFA status and any warnings; flags for follow-up if exemptions are detected |
| **Rollback** | Read-only check — no changes to rollback |

---

### Action 4: Remove App Passwords

| Aspect | Detail |
|---|---|
| **Function** | `Remove-ACRAppPasswords` |
| **Graph Module** | `Microsoft.Graph.Identity.SignIns` |
| **Key Cmdlets** | `Get-MgUserAuthenticationMethod -UserId <UPN>`, `Remove-MgUserAuthenticationMethod -UserId <UPN> -AuthenticationMethodId <ID>` |
| **What it does** | Enumerates all authentication methods, identifies app password types (used for legacy authentication with per-user MFA), and removes them |
| **Interactive** | Operator selects from menu; shown count of removed app passwords |
| **Non-Interactive** | Runs automatically; count included in JSON output |
| **Rollback** | Logs the authentication method IDs that were removed. User can create new app passwords if needed via https://mysignins.microsoft.com |

---

### Action 5: Remove Mailbox Delegates

| Aspect | Detail |
|---|---|
| **Function** | `Remove-ACRMailboxDelegates` |
| **Graph Module** | `Microsoft.Graph.Mail` / `Microsoft.Graph.Identity.SignIns` |
| **Key Cmdlets** | `Get-MgUser -UserId <UPN>`, `Get-MgUserOauth2PermissionGrant -UserId <UPN> -All`, `Remove-MgOauth2PermissionGrant -OAuth2PermissionGrantId <ID>` |
| **What it does** | Identifies mailbox delegate permission grants (OAuth2 grants scoped to mail) and removes them |
| **Interactive** | Displays delegate list before removal; operator confirms via menu selection |
| **Non-Interactive** | Removes all identified delegates automatically |
| **Rollback** | Logs delegate email addresses and permission scopes. Re-add via `New-MgOauth2PermissionGrant` or Exchange Admin Center |

---

### Action 6: Remove Changed Mailbox Folder Permissions

| Aspect | Detail |
|---|---|
| **Function** | `Remove-ACRMailboxFolderPermissions` |
| **Graph Module** | `Microsoft.Graph.Mail` |
| **Key Cmdlets** | `Get-MgUserMailFolder -UserId <UPN> -All`, `Invoke-MgGraphRequest -Method GET /users/<UPN>/mailFolders/<ID>/permissions`, `Invoke-MgGraphRequest -Method DELETE .../permissions/<ID>` |
| **What it does** | Iterates through all mail folders, identifies non-default permissions (where a specific user/group was granted access), and removes them |
| **Interactive** | Operator selects from menu; shown count of removed permissions per folder |
| **Non-Interactive** | Runs automatically; details included in JSON output |
| **Rollback** | Logs folder name, granted user, and permission level for each removed permission |

---

### Action 7: Remove Automatic Email Forwarding

| Aspect | Detail |
|---|---|
| **Function** | `Remove-ACREmailForwarding` |
| **Graph Module** | `Microsoft.Graph.Users` / `Microsoft.Graph.Mail` |
| **Key Cmdlets** | `Get-MgUser -UserId <UPN>`, `Invoke-MgGraphRequest -Method GET /users/<UPN>/mailboxSettings`, `Get-MgUserMailFolder -UserId <UPN>`, `Get-MgUserMailFolderMessageRule -UserId <UPN> -MailFolderId Inbox`, `Remove-MgUserMailFolderMessageRule` |
| **What it does** | Checks two forwarding vectors: (1) SMTP forwarding address in mailbox settings, (2) Inbox rules that forward or redirect mail. Removes offending rules |
| **Interactive** | Displays forwarding addresses and rule names before removal |
| **Non-Interactive** | Removes all forwarding rules automatically |
| **Rollback** | Logs forwarding address and full rule definitions. Re-create via `New-MgUserMailFolderMessageRule` |

---

### Action 8: Remove Untrusted Outlook Add-ins

| Aspect | Detail |
|---|---|
| **Function** | `Remove-ACROutlookAddins` |
| **Graph Module** | `Microsoft.Graph.Mail` (via direct Graph requests) |
| **Key Cmdlets** | `Invoke-MgGraphRequest -Method GET /users/<UPN>/extensions` or add-in endpoints, `Invoke-MgGraphRequest -Method DELETE .../extensions/<ID>` |
| **What it does** | Queries user-installed (sideloaded) Outlook add-ins and removes those not managed by the organization |
| **Interactive** | Displays add-in names and IDs before removal |
| **Non-Interactive** | Removes all sideloaded add-ins automatically |
| **Rollback** | Logs add-in name and ID. Reinstall from Office Add-ins store if legitimate |

---

### Action 9: Remove Unknown Safe Senders Entries

| Aspect | Detail |
|---|---|
| **Function** | `Remove-ACRSafeSenders` |
| **Graph Module** | `Microsoft.Graph.Mail` (via direct Graph requests) |
| **Key Cmdlets** | `Invoke-MgGraphRequest -Method GET /users/<UPN>/mailFolders/junkemail/...` |
| **Fallback** | `Get-MailboxJunkEmailConfiguration -Identity <UPN>` (ExchangeOnlineManagement) |
| **What it does** | Attempts to retrieve the Safe Senders list via Graph API. If direct API access is unavailable, logs guidance for manual review via Exchange Online PowerShell |
| **Interactive** | Displays Safe Senders list for operator review with manual removal guidance |
| **Non-Interactive** | Logs the list contents and flags for manual follow-up |
| **Rollback** | Logs the Safe Senders list contents before any changes |
| **⚠ Note** | Full Safe Senders management may require Exchange Online PowerShell; Graph API support is limited |

---

### Action 10: Remove External Calendar Sharing

| Aspect | Detail |
|---|---|
| **Function** | `Remove-ACRCalendarSharing` |
| **Graph Module** | `Microsoft.Graph.Calendar` |
| **Key Cmdlets** | `Get-MgUserCalendar -UserId <UPN> -All`, `Get-MgUserCalendarPermission -UserId <UPN> -CalendarId <ID>`, `Remove-MgUserCalendarPermission -UserId <UPN> -CalendarId <ID> -CalendarPermissionId <PID>` |
| **What it does** | Retrieves all calendars for the user, enumerates sharing permissions, identifies external (non-default, non-owner) shares, and removes them |
| **Interactive** | Displays shared-with users and permission levels before removal |
| **Non-Interactive** | Removes all external calendar shares automatically |
| **Rollback** | Logs shared-with email addresses and role (e.g., Read, Write). Restore via Outlook or `New-MgUserCalendarPermission` |

---

### Action 11: Remove Unknown Synced Mobile Devices

| Aspect | Detail |
|---|---|
| **Function** | `Remove-ACRMobileDevices` |
| **Graph Module** | `Microsoft.Graph.DeviceManagement` |
| **Key Cmdlets** | `Get-MgUserManagedDevice -UserId <UPN> -All`, `Remove-MgUserManagedDevice -UserId <UPN> -ManagedDeviceId <ID>` |
| **What it does** | Retrieves all managed devices for the user, identifies devices enrolled within the forensic lookback window (last 7 days), and removes them |
| **Interactive** | Lists recently synced devices with model/OS info; operator selects from menu |
| **Non-Interactive** | Removes all recently enrolled devices automatically |
| **Rollback** | Logs device name, model, OS, serial number, and enrollment date. Device must be re-enrolled by the user |

---

### Action 12: Remove User-Consented Enterprise Apps

| Aspect | Detail |
|---|---|
| **Function** | `Remove-ACRUserConsentApps` |
| **Graph Module** | `Microsoft.Graph.Identity.SignIns` |
| **Key Cmdlets** | `Get-MgUserOauth2PermissionGrant -UserId <UPN> -All`, `Remove-MgOauth2PermissionGrant -OAuth2PermissionGrantId <ID>` |
| **What it does** | Retrieves all OAuth2 permission grants (user consent) for the user and removes them. These are the "This app wants to access your data" consents |
| **Interactive** | Displays app names, IDs, and granted scopes before removal |
| **Non-Interactive** | Removes all user-consented grants automatically |
| **Rollback** | Logs client app ID and granted scopes. Restore via `New-MgOauth2PermissionGrant` |

---

### Action 13: Remove Power Automate Workflows

| Aspect | Detail |
|---|---|
| **Function** | `Remove-ACRPowerAutomateFlows` |
| **Required Module** | `Microsoft.PowerApps.Administration.PowerShell` |
| **Key Cmdlets** | `Get-AdminPowerAppEnvironment`, `Get-AdminFlow -EnvironmentName <env>`, `Remove-AdminFlow -FlowName <ID> -EnvironmentName <env>` |
| **What it does** | Enumerates all Power Platform environments, finds flows owned by the target user created within the lookback window (7 days), and removes them |
| **Interactive** | Operator selects from menu; shows count of removed flows |
| **Non-Interactive** | Runs automatically; results in JSON output |
| **Rollback** | Logs flow name, display name, environment, and creation time. Re-create manually or restore from Power Automate version history |
| **⚠ Fallback** | If `Microsoft.PowerApps.Administration.PowerShell` is not installed, logs a Warning with manual installation/review instructions instead of failing |

---

### Action 14: Remove Newly Created Power Apps

| Aspect | Detail |
|---|---|
| **Function** | `Remove-ACRPowerApps` |
| **Required Module** | `Microsoft.PowerApps.Administration.PowerShell` |
| **Key Cmdlets** | `Get-AdminPowerAppEnvironment`, `Get-AdminPowerApp -EnvironmentName <env>`, `Remove-AdminPowerApp -AppName <ID> -EnvironmentName <env>` |
| **What it does** | Enumerates all Power Platform environments, finds Power Apps owned by the target user created within the lookback window (7 days), and removes them |
| **Interactive** | Operator selects from menu; shows count of removed apps |
| **Non-Interactive** | Runs automatically; results in JSON output |
| **Rollback** | Logs app name, display name, environment, and creation time. Power Apps cannot be restored once deleted — must be re-created manually |
| **⚠ Fallback** | If `Microsoft.PowerApps.Administration.PowerShell` is not installed, logs a Warning with manual installation/review instructions instead of failing |

---

### Action 15: Remove Power Apps Sharing

| Aspect | Detail |
|---|---|
| **Function** | `Remove-ACRPowerAppsSharing` |
| **Required Module** | `Microsoft.PowerApps.Administration.PowerShell` |
| **Key Cmdlets** | `Get-AdminPowerAppEnvironment`, `Get-AdminPowerApp -EnvironmentName <env>`, `Get-AdminPowerAppRoleAssignment -AppName <ID> -EnvironmentName <env>`, `Remove-AdminPowerAppRoleAssignment -RoleId <ID> -AppName <ID> -EnvironmentName <env>` |
| **What it does** | Finds all Power Apps owned by the target user across all environments, enumerates non-owner role assignments (shares), and removes them |
| **Interactive** | Operator selects from menu; shows count of removed sharing assignments |
| **Non-Interactive** | Runs automatically; results in JSON output |
| **Rollback** | Logs app name, principal ID, principal type, and role type for each removed share. Re-share via `Set-AdminPowerAppRoleAssignment` |
| **⚠ Fallback** | If `Microsoft.PowerApps.Administration.PowerShell` is not installed, logs a Warning with manual installation/review instructions instead of failing |

---

### Action 16: Remove SharePoint/OneDrive Sharing Links

| Aspect | Detail |
|---|---|
| **Function** | `Remove-ACRSharePointSharingLinks` |
| **Graph Module** | `Microsoft.Graph.Files` |
| **Key Cmdlets** | `Get-MgUserDrive -UserId <UPN>`, `Get-MgUserDriveItem -UserId <UPN> -DriveId <ID>`, `Get-MgUserDriveItemPermission -UserId <UPN> -DriveId <ID> -DriveItemId <ItemID>`, `Remove-MgUserDriveItemPermission` |
| **What it does** | Retrieves the user's OneDrive, lists recent items, checks for sharing link permissions, and removes link-based shares (anonymous or organization-wide) |
| **Interactive** | Displays shared items and link types before removal |
| **Non-Interactive** | Removes all sharing link permissions automatically |
| **Rollback** | Logs item path, link type, and scope. Re-create via OneDrive web UI or `Invoke-MgInviteDriveItem` |

---

### Action 17: Remove Guests from Groups and Teams

| Aspect | Detail |
|---|---|
| **Function** | `Remove-ACRTeamsGuests` |
| **Graph Module** | `Microsoft.Graph.Groups` / `Microsoft.Graph.Users` |
| **Key Cmdlets** | `Get-MgUserOwnedObject -UserId <UPN> -All`, `Get-MgGroupMember -GroupId <ID> -All`, `Get-MgUser -UserId <GuestID> -Property createdDateTime`, `Remove-MgGroupMemberByRef -GroupId <ID> -DirectoryObjectId <GuestID>` |
| **What it does** | Finds groups/Teams owned by the compromised user, identifies guest members added within the lookback window (7 days), and removes them |
| **Interactive** | Displays guest users and their groups before removal |
| **Non-Interactive** | Removes all recently added guests automatically |
| **Rollback** | Logs guest UPN, display name, group name, and add date. Re-invite via `New-MgGroupMember` or Teams admin center |

---

### Action 18: Remove Admin-Consented Enterprise Apps 🔒

| Aspect | Detail |
|---|---|
| **Function** | `Remove-ACRAdminConsentApps` |
| **Graph Module** | `Microsoft.Graph.Identity.SignIns` / `Microsoft.Graph.Users` |
| **Key Cmdlets** | `Get-MgUserMemberOf -UserId <ID> -All`, `Get-MgOauth2PermissionGrant -All`, `Remove-MgOauth2PermissionGrant -OAuth2PermissionGrantId <ID>` |
| **What it does** | First verifies the user holds an admin role. Then retrieves all tenant-wide (ConsentType = "AllPrincipals") OAuth2 permission grants, identifies those recently created, and removes them |
| **Interactive** | Only shown in menu if user is detected as admin. Displays app names and consent scopes |
| **Non-Interactive** | Runs only if `Get-ACRUserContext` detects admin roles; otherwise skipped automatically |
| **Rollback** | Logs app ID, display name, and consent scopes. Restore via Azure Portal > Enterprise Applications > Permissions, or `New-MgOauth2PermissionGrant -ConsentType AllPrincipals` |
| **🔒 Requires** | Global Administrator, Application Administrator, or Cloud Application Administrator role |

---

### Action 19: Remove App Registration Client Secrets 🔒

| Aspect | Detail |
|---|---|
| **Function** | `Remove-ACRAppRegistrationSecrets` |
| **Graph Module** | `Microsoft.Graph.Applications` / `Microsoft.Graph.Users` |
| **Key Cmdlets** | `Get-MgUserMemberOf -UserId <ID> -All`, `Get-MgUserOwnedObject -UserId <ID> -All`, `Get-MgApplication -ApplicationId <AppID>`, `Remove-MgApplicationPassword -ApplicationId <AppID> -BodyParameter @{KeyId=<KeyID>}` |
| **What it does** | First verifies the user holds an admin role. Then retrieves app registrations owned by the user, identifies client secrets added within the lookback window (7 days), and removes them |
| **Interactive** | Only shown in menu if user is detected as admin. Displays app names and secret metadata |
| **Non-Interactive** | Runs only if admin roles detected; otherwise skipped |
| **Rollback** | Logs app ID, app display name, and secret key ID (never logs the secret value). Applications using the removed secret will need a new one created |
| **🔒 Requires** | Global Administrator, Application Administrator, or Cloud Application Administrator role |

---

### Action 20: Remove Modified Exchange Rules 🔒

| Aspect | Detail |
|---|---|
| **Function** | `Remove-ACRExchangeRules` |
| **Graph Module** | `Microsoft.Graph.Users` (for role detection) |
| **Required Module** | `ExchangeOnlineManagement` |
| **Key Cmdlets** | `Get-TransportRule`, `Get-JournalRule`, `Get-InboxRule -Mailbox <UPN>` |
| **What it does** | First checks for ExchangeOnlineManagement module (gracefully warns if missing). Then verifies Exchange admin role. Inspects: (1) transport rules modified in last 7 days, (2) journal rules, (3) inbox rules for the mailbox. Reports findings for review |
| **Interactive** | Only shown in menu if user is detected as Exchange admin. Displays rules found |
| **Non-Interactive** | Runs only if Exchange admin roles detected AND ExchangeOnlineManagement module is available; otherwise logs a Warning with manual steps |
| **Rollback** | Logs rule names, types, and configuration details. Re-create via Exchange Admin Center or `New-TransportRule`/`New-JournalRule` |
| **🔒 Requires** | Exchange Administrator or Global Administrator role |
| **⚠ Note** | Falls back to manual instructions if `ExchangeOnlineManagement` module is not installed |

---

## Interactive vs Non-Interactive Behaviour Summary

| # | Action | Automated via Graph? | Interactive Behaviour | Non-Interactive Behaviour |
|---|--------|---------------------|----------------------|--------------------------|
| 1 | Reset Password | ✅ Yes | Menu select; shows confirmation | Auto-runs; JSON result |
| 2 | Revoke Tokens | ✅ Yes | Menu select; shows confirmation | Auto-runs; JSON result |
| 3 | Enforce MFA | ✅ Check only | Displays MFA status to operator | Logs status; flags if exempted |
| 4 | Remove App Passwords | ✅ Yes | Menu select; shows count removed | Auto-runs; JSON result |
| 5 | Remove Mailbox Delegates | ✅ Yes | Menu select; shows delegate list | Auto-runs; JSON result |
| 6 | Remove Folder Permissions | ✅ Yes | Menu select; shows permissions | Auto-runs; JSON result |
| 7 | Remove Email Forwarding | ✅ Yes | Menu select; shows rules | Auto-runs; JSON result |
| 8 | Remove Outlook Add-ins | ✅ Yes | Menu select; shows add-in list | Auto-runs; JSON result |
| 9 | Remove Safe Senders | ⚠ Partial | Displays list; manual guidance | Logs Warning; manual follow-up |
| 10 | Remove Calendar Sharing | ✅ Yes | Menu select; shows shared-with | Auto-runs; JSON result |
| 11 | Remove Mobile Devices | ✅ Yes | Menu select; shows device list | Auto-runs; JSON result |
| 12 | Remove User Consent Apps | ✅ Yes | Menu select; shows app list | Auto-runs; JSON result |
| 13 | Remove Power Automate | ✅ Yes (with PP module) | Menu select; shows removed flows | Auto-runs; JSON result (Warning if module missing) |
| 14 | Remove Power Apps | ✅ Yes (with PP module) | Menu select; shows removed apps | Auto-runs; JSON result (Warning if module missing) |
| 15 | Remove Power Apps Sharing | ✅ Yes (with PP module) | Menu select; shows removed shares | Auto-runs; JSON result (Warning if module missing) |
| 16 | Remove SP/OD Sharing Links | ✅ Yes | Menu select; shows shared items | Auto-runs; JSON result |
| 17 | Remove Teams Guests | ✅ Yes | Menu select; shows guest list | Auto-runs; JSON result |
| 18 | Remove Admin Consent Apps | ✅ Yes (admin only) | Shown only for admins | Runs if admin; skips otherwise |
| 19 | Remove App Reg Secrets | ✅ Yes (admin only) | Shown only for admins | Runs if admin; skips otherwise |
| 20 | Remove Exchange Rules | ⚠ Requires EXO module | Shown only for Exchange admins | Runs if EXO module + role; else Warning |

---

## Forensic Collection Modules

The forensic investigation phase (runs before remediation) uses these modules:

| Data Source | Module | Key Cmdlet |
|---|---|---|
| Sign-in logs | `Microsoft.Graph.Reports` | `Get-MgAuditLogSignIn -Filter "..." -All` |
| Directory audit logs | `Microsoft.Graph.Reports` | `Get-MgAuditLogDirectoryAudit -Filter "..." -All` |
| Mailbox settings & delegates | `Microsoft.Graph.Mail` / `Microsoft.Graph.Users` | `Get-MgUserMailboxSetting`, `Get-MgUser` |
| Mailbox folder permissions | `Microsoft.Graph.Mail` | `Get-MgUserMailFolder`, `Get-MgUserMailFolderPermission` |
| Inbox rules | `Microsoft.Graph.Mail` | `Get-MgUserMailFolderMessageRule` |
| Unified audit log (SP, OD, Teams, Power Platform) | `ExchangeOnlineManagement` | `Search-UnifiedAuditLog` |
