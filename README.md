# Account Compromise Remediation

PowerShell-based toolkit for remediating compromised Entra ID accounts. Provides both interactive and automated workflows to investigate and remediate account compromise incidents.

> **New here?** Start with the [Getting Started Guide](getting-started.md) for prerequisites, security best practices, Azure deployment, and Sentinel/Defender XDR integration.

## Prerequisites

- **PowerShell 7.2+**
- **Microsoft Graph PowerShell SDK**
  ```powershell
  Install-Module Microsoft.Graph -Scope CurrentUser
  ```
- **Exchange Online Management Module**
  ```powershell
  Install-Module ExchangeOnlineManagement -Scope CurrentUser
  ```
- **Power Platform Admin Module** *(optional, for Actions 13–15)*
  ```powershell
  Install-Module Microsoft.PowerApps.Administration.PowerShell -Scope CurrentUser
  ```
  > ⚠ This module only supports Windows PowerShell 5.1 natively. On PS 7+ (Windows), the scripts use `Import-Module -UseWindowsPowerShell` to proxy calls automatically. On non-Windows PS 7+, these actions fall back to manual review guidance.

## Quick Start

### Interactive Mode
```powershell
# Menu-based — select which actions to run
.\src\Invoke-AccountRemediation.ps1 -UserPrincipalName "user@contoso.com"

# Run all actions at once
.\src\Invoke-AccountRemediation.ps1 -UserPrincipalName "user@contoso.com" -RunAll

# Run specific actions only
.\src\Invoke-AccountRemediation.ps1 -UserPrincipalName "user@contoso.com" -Actions "ResetPassword","RevokeTokens","EnforceMFA"

# Skip forensic investigation
.\src\Invoke-AccountRemediation.ps1 -UserPrincipalName "user@contoso.com" -RunAll -SkipForensics
```

### Non-Interactive / Automation Mode
```powershell
# Called from Logic App or Azure Automation with Managed Identity
.\src\Invoke-AutoRemediation.ps1 -UserPrincipalName "user@contoso.com" -CorrelationId "abc-123" -AlertSource "Sentinel"
```

**Exit codes:**
| Code | Meaning |
|------|---------|
| 0 | All actions completed successfully |
| 1 | Partial success — some actions failed |
| 2 | Critical failure — remediation could not proceed |

## Required Permissions

See [`config/permissions.json`](config/permissions.json) for the full list.

**Key permissions:**
- `User.ReadWrite.All` — password reset, token revocation
- `AuditLog.Read.All` — forensic investigation
- `Directory.ReadWrite.All` — role detection, app management
- `MailboxSettings.ReadWrite` — mailbox delegate/forwarding cleanup
- Exchange Online admin roles for transport/journal rules

### Managed Identity Setup (for automation)
1. Create or use an existing Azure Automation Account or Logic App with Managed Identity enabled
2. Grant the Managed Identity the required Graph API application permissions
3. Assign Exchange Online admin roles as needed

## Project Structure

```
src/
  modules/
    ACR.Auth.psm1          # Authentication (interactive + Managed Identity)
    ACR.Forensics.psm1     # Forensic data collection (7-day lookback)
    ACR.Remediation.psm1   # Individual remediation action functions
    ACR.Logging.psm1       # Structured logging & rollback journal
    ACR.Reporting.psm1     # Report generation (JSON, CSV, HTML)
  Invoke-AccountRemediation.ps1   # Interactive script
  Invoke-AutoRemediation.ps1      # Non-interactive automation script
tests/                     # Pester 5 test suite
config/
  permissions.json         # Required API permissions reference
```

## Forensic Investigation

Before any remediation, both scripts collect 7 days of activity:
- **Sign-in logs** — risky sign-ins, unfamiliar locations/devices
- **Audit logs** — password changes, MFA changes, app consents, role assignments
- **Mailbox audit logs** — delegates, forwarding rules, folder permissions
- **Unified audit log** — SharePoint, OneDrive, Teams, Power Platform activity

Output is saved to a timestamped forensics folder:
```
forensics/
  <UPN>_<timestamp>/
    signin-logs.json / .csv
    audit-logs.json / .csv
    mailbox-audit.json / .csv
    unified-audit.json / .csv
    summary-report.html
```

## Rollback

All remediation actions log their before/after state to a rollback journal (`rollback-journal.json`). If a compromise turns out to be a false positive, an administrator can review the journal and manually reverse changes.

## Remediation Actions

| # | Action | Admin Only |
|---|--------|------------|
| 1 | Reset user password | No |
| 2 | Revoke refresh tokens | No |
| 3 | Enforce MFA (if exempted) | No |
| 4 | Remove app passwords | No |
| 5 | Remove mailbox delegates | No |
| 6 | Remove changed mailbox folder permissions | No |
| 7 | Remove automatic email forwarding | No |
| 8 | Remove untrusted Outlook add-ins | No |
| 9 | Remove unknown Safe Senders entries | No |
| 10 | Remove external calendar sharing/publishing | No |
| 11 | Remove unknown synced mobile devices | No |
| 12 | Remove user-consented enterprise apps | No |
| 13 | Remove Power Automate workflows | No |
| 14 | Remove Power Apps | No |
| 15 | Remove Power Apps sharing | No |
| 16 | Remove SharePoint/OneDrive sharing links | No |
| 17 | Remove guests from Groups and Teams | No |
| 18 | Remove admin-consented enterprise apps | Yes (Admin) |
| 19 | Remove app registration client secrets | Yes (Admin) |
| 20 | Remove modified journal/mail flow/mailbox rules | Yes (Exchange Admin) |

## Testing

```powershell
# Run all tests
Invoke-Pester -Path ./tests -Output Detailed

# Run tests for a specific module
Invoke-Pester -Path ./tests/ACR.Forensics.Tests.ps1 -Output Detailed
```

## Logic App Integration

The non-interactive script is designed to be called from an Azure Logic App:

1. **Trigger**: Microsoft Sentinel alert or XDR incident
2. **Action**: Run Azure Automation Runbook (`Invoke-AutoRemediation.ps1`)
3. **Parameters**: Pass `UserPrincipalName` from the alert entity, `CorrelationId` from the incident, `AlertSource` as the trigger source
4. **Output**: Parse the JSON output for status reporting and ticketing

## License

Internal use only. Not for distribution.
