# Getting Started

This guide walks you through setting up, running, and deploying the Account Compromise Remediation toolkit — from first-time prerequisites through production automation with Microsoft Sentinel and Defender XDR.

---

## Table of Contents

1. [Prerequisites](#1-prerequisites)
2. [Installation](#2-installation)
3. [Running Interactively — Security Best Practices](#3-running-interactively--security-best-practices)
4. [App-Only / Low-Privilege Operator Mode](#4-app-only--low-privilege-operator-mode)
5. [Deploying to Azure Automation — Best Practices](#5-deploying-to-azure-automation--best-practices)
6. [Integrating with Microsoft Sentinel](#6-integrating-with-microsoft-sentinel)
7. [Integrating with Microsoft Defender XDR](#7-integrating-with-microsoft-defender-xdr)
8. [Integrating with Microsoft Security Copilot](#8-integrating-with-microsoft-security-copilot)
9. [Operational Runbook — Before, During, and After](#9-operational-runbook--before-during-and-after)
10. [Troubleshooting](#10-troubleshooting)

---

## 1. Prerequisites

### 1.1 PowerShell Runtime

| Requirement | Minimum | Recommended |
|---|---|---|
| PowerShell | 7.2 | 7.4+ (latest LTS) |
| .NET Runtime | Included with PS 7 | — |
| OS | Windows, macOS, Linux | Windows (required for Power Platform actions 13–15) |

> **Why PowerShell 7?** The Microsoft Graph PowerShell SDK and ExchangeOnlineManagement v2+ are optimised for PS 7. Windows PowerShell 5.1 is only needed as a proxy backend for the Power Platform admin module, which the scripts handle automatically on Windows.

### 1.2 PowerShell Modules

| Module | Version | Required? | Purpose |
|---|---|---|---|
| `Microsoft.Graph` | 2.x+ | **Yes** | Core Graph API operations (17 of 20 actions + forensics) |
| `ExchangeOnlineManagement` | 2.0.3+ | **Yes** (for action 20 + unified audit) | Exchange transport/journal/inbox rules, unified audit log |
| `Microsoft.PowerApps.Administration.PowerShell` | Latest | Optional | Power Platform actions 13–15 (graceful fallback if missing) |
| `Pester` | 5.x | Dev/test only | Running the test suite |

### 1.3 Entra ID Permissions

The scripts require these Microsoft Graph API permissions. For the interactive script, these are **delegated** permissions; for the automation script, they are **application** permissions granted to the Managed Identity.

| Permission | Why |
|---|---|
| `User.ReadWrite.All` | Password reset, account property changes |
| `Directory.ReadWrite.All` | Role detection, directory object management |
| `AuditLog.Read.All` | Forensic sign-in and audit log collection |
| `MailboxSettings.ReadWrite` | Mailbox delegate and forwarding remediation |
| `Mail.ReadWrite` | Inbox rules, folder permissions, add-in removal |
| `Calendars.ReadWrite` | Calendar sharing remediation |
| `Sites.ReadWrite.All` | SharePoint/OneDrive sharing link removal |
| `UserAuthenticationMethod.ReadWrite.All` | MFA enforcement, app password removal |
| `RoleManagement.Read.Directory` | Admin role auto-detection |
| `Application.ReadWrite.All` | App registration secret and consent remediation |
| `Policy.ReadWrite.ConditionalAccess` | Conditional access policy checks |
| `DeviceManagementManagedDevices.ReadWrite.All` | Mobile device removal |

### 1.4 Admin Roles

| Role | Required For |
|---|---|
| **User Administrator** (or equivalent) | Standard remediation actions 1–17 |
| **Global Administrator** or **Application Administrator** | Admin actions 18–19 (app consent, app secrets) |
| **Exchange Administrator** or **Global Administrator** | Action 20 (transport/journal rules) |
| **Power Platform Administrator** | Actions 13–15 (flows, apps, sharing) |

### 1.5 Licensing

| Product | Required For |
|---|---|
| Microsoft Entra ID P1/P2 | Sign-in risk data, conditional access logs |
| Microsoft 365 E3/E5 | Mailbox audit, unified audit log, Teams/SharePoint data |
| Microsoft Defender for Office 365 | Enhanced mailbox forensics |
| Power Platform per-user or per-app plan | Power Platform admin operations |

---

## 2. Installation

### 2.1 Do the Scripts Auto-Install Modules?

**No.** The scripts import modules but do not install them automatically. This is by design — auto-installation in security tooling can introduce supply-chain risks. You should install and pin module versions in a controlled manner.

### 2.2 One-Time Setup (Workstation)

```powershell
# 1. Verify PowerShell version
$PSVersionTable.PSVersion  # Should be 7.2+

# 2. Install required modules
Install-Module Microsoft.Graph -Scope CurrentUser -Force
Install-Module ExchangeOnlineManagement -Scope CurrentUser -Force

# 3. (Optional) Install Power Platform module for actions 13-15
Install-Module Microsoft.PowerApps.Administration.PowerShell -Scope CurrentUser -Force

# 4. (Dev/test only) Install Pester for running tests
Install-Module Pester -Scope CurrentUser -Force -SkipPublisherCheck

# 5. Verify installations
Get-InstalledModule Microsoft.Graph, ExchangeOnlineManagement | Format-Table Name, Version
```

### 2.3 Pin Module Versions (Recommended for Production)

For reproducible deployments, pin specific module versions:

```powershell
# Check current versions
Get-InstalledModule Microsoft.Graph | Select-Object Name, Version

# Install a specific version
Install-Module Microsoft.Graph -RequiredVersion 2.24.0 -Scope CurrentUser -Force
```

### 2.4 Grant Admin Consent for Graph Permissions

Before first use, a Global Administrator must grant admin consent for the required permissions:

```powershell
# Interactive: consent is prompted on first Connect-MgGraph
# The admin signs in and approves the requested scopes

# For automation: grant application permissions to the Managed Identity
# See Section 4 for detailed steps
```

---

## 3. Running Interactively — Security Best Practices

### 3.1 Use a Privileged Access Workstation (PAW)

Per [Microsoft's Privileged Access strategy](https://learn.microsoft.com/en-us/security/privileged-access-workstations/privileged-access-deployment):

- Run the interactive script from a **Privileged Access Workstation (PAW)** or **Secure Admin Workstation (SAW)**, not from a general-purpose machine
- The workstation should have restricted internet access, endpoint detection, and no persistent browser sessions to personal accounts
- Use a hardened admin account with phishing-resistant MFA (FIDO2 key or certificate-based auth)

### 3.2 Use a Dedicated Break-Glass or Incident Response Account

- **Do not** use your day-to-day admin account for remediation. Use a dedicated incident response service account or a Privileged Identity Management (PIM) just-in-time elevation
- Enable PIM with time-boxed activation (e.g., 1 hour) so the elevated role expires automatically

```powershell
# Example: run from a PAW with a dedicated IR account
.\src\Invoke-AccountRemediation.ps1 -UserPrincipalName "compromised.user@contoso.com"
```

### 3.3 Review Forensics Before Remediating

Always run forensics first (don't use `-SkipForensics`) to preserve evidence:

```powershell
# Default behaviour: forensics runs first, then you select actions
.\src\Invoke-AccountRemediation.ps1 -UserPrincipalName "compromised.user@contoso.com"

# Review the HTML report BEFORE selecting remediation actions
# The report is saved to: output/<UPN>_<timestamp>/summary-report.html
```

### 3.4 Use the Menu for Selective Remediation

For a first-time or uncertain response, use the interactive menu rather than `-RunAll`:

```powershell
# Menu mode — review each action before executing
.\src\Invoke-AccountRemediation.ps1 -UserPrincipalName "compromised.user@contoso.com"

# Only when you're confident in the scope:
.\src\Invoke-AccountRemediation.ps1 -UserPrincipalName "compromised.user@contoso.com" -RunAll
```

### 3.5 Preserve the Rollback Journal

After remediation, the scripts produce three critical files:

| File | Purpose |
|---|---|
| `action-log_*.json` | Full audit trail of every action taken |
| `rollback-journal_*.json` | Before/after state for manual reversal |
| `transcript_*.log` | PowerShell transcript of the entire session |

**Store these files securely** — they are part of the incident record and may be needed for:
- False positive reversal (rollback)
- Legal/compliance review
- Post-incident lessons learned

### 3.6 Network and Session Hygiene

- Ensure your admin session is not intercepted: use a trusted network, VPN, or Azure Bastion
- Close the PowerShell session when done — the script calls `Disconnect-ACR` automatically, but verify no stale tokens remain
- Clear the PowerShell history if it contains sensitive output: `Clear-History`

---

## 4. App-Only / Low-Privilege Operator Mode

The default interactive script (`Invoke-AccountRemediation.ps1`) authenticates the **operator**, so every analyst must hold privileged Entra roles (User Admin, Exchange Admin, Application Admin, etc.). In real SOC operations this is undesirable — Tier-1/2 analysts should not carry Global Admin.

The third entry script — **`Invoke-AccountRemediationAppAuth.ps1`** — solves this. It authenticates as a dedicated **app registration using a client certificate**. The app holds the Graph application permissions and the EXO service-principal role; the analyst inherits the app's authority. Their personal roles are irrelevant.

> 💡 **When to use this mode**: any environment where the operator does not have (or should not have) Global Admin / Exchange Admin / Application Admin. Cert auth is non-interactive — no MFA prompt — so this mode also works on jumpboxes and PAWs.

### 4.1 One-time setup (Global Admin)

A single Global Admin (or Privileged Role Admin) runs `Setup-ACRAppRegistration.ps1` once per tenant. It is idempotent — safe to re-run.

```powershell
# Default settings: cert subject 'CN=ACR-AppAuth', app name 'ACR Account Remediation (App Auth)', 365-day cert
.\src\Setup-ACRAppRegistration.ps1 -TenantId 'contoso.onmicrosoft.com'

# Preview without changes
.\src\Setup-ACRAppRegistration.ps1 -TenantId 'contoso.onmicrosoft.com' -WhatIf

# Skip the EXO step if you don't need mailbox actions yet
.\src\Setup-ACRAppRegistration.ps1 -TenantId 'contoso.onmicrosoft.com' -SkipExchangeRole -SkipExchangeServicePrincipal
```

The setup helper performs nine steps:
1. Connects to Microsoft Graph as the running user (Global Admin / Privileged Role Admin required)
2. Generates a self-signed cert in `Cert:\CurrentUser\My` (2048-bit RSA, SHA-256, **non-exportable**, 365-day validity)
3. Creates (or reuses) the Entra app registration
4. Attaches the cert public key as a `keyCredential`
5. Creates the corresponding service principal
6. Grants admin consent for each Graph application permission listed in `config/permissions.json` (`applicationPermissionsAppAuth.graphAppRoles`)
7. Adds the SP to the **Exchange Administrator** directory role
8. Connects to Exchange Online and runs `New-ServicePrincipal -AppId -ServiceId` so EXO recognises the app
9. Writes `config/app-auth.json` with `tenantId` / `clientId` / `certificateThumbprint` / `organization`

Final summary prints the cert thumbprint, the app ObjectId, and rotation guidance. The real `config/app-auth.json` is **gitignored** — only the `.example` template is committed.

### 4.2 Running the app-auth script

```powershell
# Loads config/app-auth.json by default
.\src\Invoke-AccountRemediationAppAuth.ps1 -UserPrincipalName "user@contoso.com"

# All the same flags as the delegated script
.\src\Invoke-AccountRemediationAppAuth.ps1 -UserPrincipalName "user@contoso.com" -RunAll -DryRun

# Override config-file values from the CLI
.\src\Invoke-AccountRemediationAppAuth.ps1 `
    -UserPrincipalName "user@contoso.com" `
    -TenantId 'other-tenant.onmicrosoft.com' `
    -ClientId '<guid>' -CertificateThumbprint '<thumbprint>'

# Use an alternate config file (e.g. one per tenant)
.\src\Invoke-AccountRemediationAppAuth.ps1 -UserPrincipalName "user@contoso.com" `
    -ConfigPath 'C:\ACR\configs\contoso-app-auth.json'

# Override operator attribution (default: current Windows identity)
.\src\Invoke-AccountRemediationAppAuth.ps1 -UserPrincipalName "user@contoso.com" `
    -OperatorUpn 'jdoe@contoso.com'
```

**Operator attribution**: under app-only auth, every Graph call happens as the SP. To preserve human accountability, the script captures `[Security.Principal.WindowsIdentity]::GetCurrent().Name` (override with `-OperatorUpn`) and writes it to the action log header **and** every rollback journal entry. Reviewers can attribute actions to the analyst, not just the SPN.

### 4.3 Distributing certificates to additional analysts

Each analyst workstation needs the cert in `Cert:\CurrentUser\My`. The cert is provisioned **non-exportable** by default for security, so you can't simply export the PFX. Two options:

**Option A — Per-machine cert (recommended)**: Re-run `Setup-ACRAppRegistration.ps1` on each new workstation. The helper detects the existing app registration and **adds a new key credential** to it. No duplicate apps, no exportable PFXes, but each analyst's cert is independently revocable.

**Option B — Central exportable PFX**: Re-run setup with `-CertificateExportable` (slightly weaker security; the PFX file is now a transferable secret). Distribute via a secure channel (Privileged Identity vault, smartcard, etc.). Import on each workstation with `Import-PfxCertificate -FilePath <pfx> -CertStoreLocation Cert:\CurrentUser\My`.

> 🛡 **Hardening**: If you use Option B, store the PFX in a Privileged Access Workstation (PAW) only, ACL the cert's private-key file to a specific Windows group (e.g. `SOC-Analysts`), and rotate yearly.

### 4.4 Certificate rotation

Certs default to 365-day validity. To rotate before expiry:

```powershell
# On the original setup machine
.\src\Setup-ACRAppRegistration.ps1 -TenantId '...' -CertificateValidityDays 365
# Setup adds a new keyCredential alongside the old one
# Update config/app-auth.json (or the analyst-side configs) with the new thumbprint
# After all workstations are updated and verified, remove the old keyCredential
# from the app via the Entra portal (App registrations → Certificates & secrets)
```

Plan rotation 30 days before expiry. The script's preflight will warn (not block) when the cert is within 30 days of expiry.

### 4.5 What's still required

The app-auth flow does **not** eliminate every privileged action:
- **Power Platform actions (13–15)** require the PowerApps admin module, which has its own auth model. They will be skipped in app-only mode with manual guidance, just like today when the module is missing.
- **Resetting an admin user's password (Action 1 against an admin)** requires the SP to additionally hold the **Privileged Authentication Administrator** directory role. The setup helper does NOT assign this role by default — add it manually in the Entra portal if needed.

---

## 5. Deploying to Azure Automation — Best Practices

This section follows [Microsoft's Azure Automation security guidelines](https://learn.microsoft.com/en-us/azure/automation/automation-security-guidelines) and [Managed Identity best practices](https://learn.microsoft.com/en-us/azure/automation/enable-managed-identity-for-automation).

### 5.1 Create an Azure Automation Account

```bash
# Azure CLI
az automation account create \
  --name "acr-remediation-auto" \
  --resource-group "rg-security-automation" \
  --location "uksouth" \
  --sku "Basic"
```

### 5.2 Enable System-Assigned Managed Identity

```bash
az automation account identity assign \
  --name "acr-remediation-auto" \
  --resource-group "rg-security-automation" \
  --identity-type SystemAssigned
```

> **Why Managed Identity?** Run As accounts are deprecated. Managed Identity is credential-free, rotated by Azure, and auditable through Entra ID sign-in logs.

### 5.3 Grant Graph API Permissions to the Managed Identity

Use PowerShell to assign application permissions (this requires a Global Administrator):

```powershell
# Connect as Global Admin
Connect-MgGraph -Scopes "Application.ReadWrite.All","AppRoleAssignment.ReadWrite.All"

# Get the Managed Identity's service principal
$miObjectId = (az automation account show `
  --name "acr-remediation-auto" `
  --resource-group "rg-security-automation" `
  --query identity.principalId -o tsv)

# Get the Microsoft Graph service principal
$graphSp = Get-MgServicePrincipal -Filter "appId eq '00000003-0000-0000-c000-000000000000'"

# Define required permissions
$requiredPermissions = @(
    'User.ReadWrite.All'
    'Directory.ReadWrite.All'
    'AuditLog.Read.All'
    'MailboxSettings.ReadWrite'
    'Mail.ReadWrite'
    'Calendars.ReadWrite'
    'Sites.ReadWrite.All'
    'UserAuthenticationMethod.ReadWrite.All'
    'RoleManagement.Read.Directory'
    'Application.ReadWrite.All'
    'Policy.ReadWrite.ConditionalAccess'
    'DeviceManagementManagedDevices.ReadWrite.All'
)

# Assign each permission
foreach ($permName in $requiredPermissions) {
    $appRole = $graphSp.AppRoles | Where-Object { $_.Value -eq $permName }
    New-MgServicePrincipalAppRoleAssignment `
        -ServicePrincipalId $miObjectId `
        -PrincipalId $miObjectId `
        -ResourceId $graphSp.Id `
        -AppRoleId $appRole.Id
}
```

### 5.4 Import Modules into the Automation Account

```bash
# Import Microsoft.Graph modules (use the Azure Portal for complex dependency chains)
# Or via PowerShell:
az automation module create \
  --automation-account-name "acr-remediation-auto" \
  --resource-group "rg-security-automation" \
  --name "Microsoft.Graph.Authentication" \
  --content-link "https://www.powershellgallery.com/api/v2/package/Microsoft.Graph.Authentication"
```

> **Tip:** Use the Azure Portal → Automation Account → Modules → Browse Gallery for the simplest experience. Import `Microsoft.Graph.Authentication` first, then the sub-modules (`Microsoft.Graph.Users`, `Microsoft.Graph.Mail`, etc.).

### 5.5 Upload the Runbook Scripts

Upload `Invoke-AutoRemediation.ps1` and the `src/modules/` folder as PowerShell 7.2 runbooks:

```bash
az automation runbook create \
  --automation-account-name "acr-remediation-auto" \
  --resource-group "rg-security-automation" \
  --name "Invoke-AutoRemediation" \
  --type "PowerShell72" \
  --content @src/Invoke-AutoRemediation.ps1
```

> **Important:** When deploying to Azure Automation, ensure the module import paths in the script match the Automation Account module structure. You may need to adjust `$PSScriptRoot` references or upload modules as Automation Account modules.

### 5.6 Security Hardening (Per Microsoft Guidelines)

| Practice | Implementation |
|---|---|
| **Least privilege** | Grant only the specific Graph permissions listed above — not `*.ReadWrite.All` wildcards at subscription level |
| **Network isolation** | Enable Private Endpoints on the Automation Account; restrict inbound/outbound traffic |
| **Encryption** | Automation Account encrypts variables at rest by default. Use Key Vault for any additional secrets |
| **Audit logging** | Enable Diagnostic Settings → send to Log Analytics Workspace for full runbook execution audit |
| **RBAC** | Restrict who can edit/run runbooks using Azure RBAC (Automation Operator, Automation Contributor) |
| **No stored credentials** | Managed Identity eliminates the need for stored passwords or certificates |
| **Module pinning** | Pin specific module versions in the Automation Account to prevent unexpected updates |
| **Source control** | Link the Automation Account to a Git repository for version-controlled runbook deployment |

### 5.7 Test Before Production

```powershell
# Run a test job in Azure Portal or via CLI
az automation runbook start \
  --automation-account-name "acr-remediation-auto" \
  --resource-group "rg-security-automation" \
  --name "Invoke-AutoRemediation" \
  --parameters UserPrincipalName="test.user@contoso.com" CorrelationId="test-001" AlertSource="Manual"
```

Monitor the job output in the Azure Portal → Automation Account → Jobs.

---

## 6. Integrating with Microsoft Sentinel

### 6.1 Architecture Overview

```
┌─────────────────┐    Incident     ┌──────────────────┐    Trigger    ┌─────────────────────┐
│ Microsoft       │ ──────────────► │ Sentinel         │ ───────────► │ Azure Automation    │
│ Sentinel        │    Alert/       │ Playbook         │   Runbook    │ Invoke-Auto         │
│ (Analytics Rule)│    Incident     │ (Logic App)      │              │ Remediation.ps1     │
└─────────────────┘                 └──────────────────┘              └─────────────────────┘
                                           │                                    │
                                           ▼                                    ▼
                                    Parse entities                      Forensics → Remediate
                                    (UserPrincipalName)                 → JSON output
                                           │                                    │
                                           ▼                                    ▼
                                    Post-remediation                    Log to workspace
                                    (Teams/email/ticket)                + rollback journal
```

### 6.2 Create a Sentinel Playbook (Logic App)

1. **Navigate to:** Microsoft Sentinel → Automation → Create Playbook
2. **Trigger:** "When Microsoft Sentinel incident creation rule was triggered"
3. **Actions:**
   - **Parse incident entities** — extract the compromised account UPN from the incident entities array
   - **Run Azure Automation Runbook** — use the Azure Automation connector (not HTTP webhooks) for secure invocation with Managed Identity
   - **Parse JSON output** — parse the structured JSON returned by `Invoke-AutoRemediation.ps1`
   - **Conditional actions:**
     - If `status == "Success"` → add comment to incident, close incident
     - If `status == "PartialSuccess"` → add comment, assign to analyst for review
     - If `status == "Failed"` → escalate, send Teams alert
   - **Optional:** Post results to a Teams channel, ServiceNow ticket, or email

### 6.3 Recommended Analytics Rules to Trigger Remediation

| Analytics Rule | Signal Source | Trigger Condition |
|---|---|---|
| **User account compromised** | Entra ID Identity Protection | Risk level = High, risk state = atRisk |
| **Impossible travel** | Sign-in logs | Sign-ins from geographically impossible locations within short timeframe |
| **Suspicious inbox rule creation** | Unified audit log | New inbox rule with forwarding/redirect to external domain |
| **Anomalous token activity** | Entra ID sign-in logs | Token replay or unusual token characteristics |
| **Consent phishing** | Audit logs | User grants consent to unfamiliar OAuth app with broad scopes |
| **MFA fatigue / push spam** | Entra ID sign-in logs | Multiple denied MFA requests followed by an approval |

### 6.4 Sentinel-Specific Best Practices

- **Use the Azure Automation connector** in Logic Apps, not HTTP webhooks — the connector uses Managed Identity natively and is auditable
- **Add an approval step** for high-value targets (VIPs, admin accounts) — use a Teams Adaptive Card or email approval before executing remediation
- **Rate-limit playbook execution** — add a condition to check if remediation has already run for the same UPN in the last hour to avoid duplicate runs
- **Log playbook results to Log Analytics** — use the "Send Data" connector to write remediation outcomes to a custom table for reporting
- **Tag incidents** with remediation status — add labels like `remediation-complete`, `remediation-partial`, or `remediation-failed`

---

## 7. Integrating with Microsoft Defender XDR

### 7.1 Complementing Automatic Attack Disruption

Microsoft Defender XDR's built-in [Automatic Attack Disruption](https://learn.microsoft.com/en-us/defender-xdr/configure-attack-disruption) handles immediate containment (disabling compromised accounts, isolating devices) with high-confidence AI signals. This toolkit **complements** that by providing:

- **Deep forensic investigation** — 7 days of sign-in, audit, mailbox, and unified log collection
- **Comprehensive remediation** — beyond disabling the account, clean up delegates, forwarding, app consents, Power Platform artifacts, etc.
- **Evidence preservation** — structured exports and rollback journals for incident response

### 7.2 Integration Approach

| Defender XDR Action | This Toolkit's Role |
|---|---|
| Account disabled by attack disruption | Run this toolkit next: forensics + full cleanup of persistence mechanisms |
| Incident created in XDR | Forward to Sentinel → trigger playbook → invoke `Invoke-AutoRemediation.ps1` |
| Manual investigation in XDR portal | Use `Invoke-AccountRemediation.ps1` interactively alongside the XDR investigation |

### 7.3 Connecting Defender XDR to Sentinel

If you use both Defender XDR and Sentinel:

1. **Enable the Microsoft Defender XDR connector** in Sentinel to ingest incidents
2. Create an **automation rule** in Sentinel that triggers the remediation playbook when a Defender XDR incident with compromised-user entities is imported
3. The `CorrelationId` parameter in `Invoke-AutoRemediation.ps1` maps directly to the Defender XDR incident ID for traceability

### 7.4 Custom Detection Rules

Create custom detection rules in Defender XDR Advanced Hunting to trigger this toolkit:

```kusto
// Example: detect accounts with new forwarding rules + risky sign-ins
let riskyUsers = SigninLogs
    | where TimeGenerated > ago(1d)
    | where RiskLevelDuringSignIn in ("high", "medium")
    | distinct UserPrincipalName;
OfficeActivity
    | where TimeGenerated > ago(1d)
    | where Operation in ("New-InboxRule", "Set-InboxRule")
    | where UserId in (riskyUsers)
    | project UserPrincipalName = UserId, Operation, Parameters, TimeGenerated
```

Route matching incidents to Sentinel for automated playbook execution.

---

## 8. Integrating with Microsoft Security Copilot

### 8.1 Overview

[Microsoft Security Copilot](https://learn.microsoft.com/en-us/security-copilot/) is an AI-powered assistant that can investigate, summarise, and orchestrate security operations. This toolkit integrates with Copilot through its **custom plugin** and **Logic App automation** extensibility.

### 8.2 Use Cases

| Scenario | How It Works |
|---|---|
| **Copilot investigates, analyst remediates** | Copilot summarises the compromise indicators; the analyst uses the interactive script based on Copilot's recommendations |
| **Copilot triggers automated remediation** | Copilot invokes a Sentinel playbook that triggers `Invoke-AutoRemediation.ps1` |
| **Copilot reviews remediation results** | Feed the JSON output from `Invoke-AutoRemediation.ps1` back to Copilot for summarisation and next-step recommendations |

### 8.3 Building a Security Copilot Custom Plugin

Register a custom plugin that exposes the remediation toolkit as a Copilot skill:

```yaml
# Example plugin manifest (OpenAPI-based)
openapi: 3.0.0
info:
  title: Account Compromise Remediation
  description: Triggers automated account compromise remediation via Azure Automation
  version: 1.0.0
paths:
  /remediate:
    post:
      operationId: remediateCompromisedAccount
      summary: Run full account compromise remediation
      description: >
        Executes forensic investigation and remediation actions on a
        compromised Entra ID account via Azure Automation.
      parameters:
        - name: userPrincipalName
          in: query
          required: true
          schema:
            type: string
        - name: correlationId
          in: query
          schema:
            type: string
      responses:
        '200':
          description: Remediation result
```

The plugin backend is a Logic App that invokes the Azure Automation runbook and returns the JSON result.

### 8.4 Prompting Security Copilot

Once integrated, analysts can use natural language prompts:

> *"Run account compromise remediation for john.doe@contoso.com and summarise the results."*

> *"Show me the forensic report for the compromised account from incident INC-2024-0456."*

> *"What persistence mechanisms were found and remediated for jane.smith@contoso.com?"*

---

## 9. Operational Runbook — Before, During, and After

### 9.1 Before an Incident (Preparation)

- [ ] Install and test the scripts in a non-production environment
- [ ] Run the Pester test suite to verify: `Invoke-Pester -Path ./tests -Output Detailed`
- [ ] Pre-configure Managed Identity permissions and Automation Account
- [ ] Set up Sentinel playbook and test with a simulated alert
- [ ] Document your organisation's escalation path for confirmed vs. suspected compromise
- [ ] Train SOC analysts on using the interactive script
- [ ] Store the toolkit in a version-controlled, access-restricted repository

### 9.2 During an Incident

1. **Triage** — Confirm the compromise signal (Sentinel alert, user report, Defender XDR incident)
2. **Forensics first** — Run the toolkit. Review the HTML forensic report before taking action
3. **Assess scope** — Is this a standard user or admin? The script auto-detects. Admin compromises require actions 18–20
4. **Remediate** — Use the menu (interactive) or let automation handle it (non-interactive). Start with critical actions: reset password (1), revoke tokens (2), enforce MFA (3)
5. **Verify** — Check the action log. Were any actions "Failed" or "Warning"? Address those manually
6. **Communicate** — Notify the user that their password has been reset and they must re-authenticate. Coordinate with the help desk

### 9.3 After an Incident

- [ ] Preserve all output files (action log, rollback journal, forensic exports, HTML report) in your case management system
- [ ] Review the rollback journal — if the incident was a false positive, use the recorded before/after state to reverse changes
- [ ] Conduct a post-incident review (PIR). Questions to consider:
  - How did the compromise occur? (phishing, credential stuffing, token theft?)
  - Were any persistence mechanisms missed? (check actions with "Warning" status)
  - Did the automated playbook fire correctly? Were there delays?
  - Should additional analytics rules be created?
- [ ] Update Conditional Access policies, MFA requirements, or app consent settings based on findings
- [ ] If the attacker created any external sharing, forwarding, or app registrations, check the forensic data for indicators of further compromise in linked accounts

---

## 10. Troubleshooting

### Common Issues

| Issue | Cause | Resolution |
|---|---|---|
| `Connect-MgGraph` fails with scope errors | Admin consent not granted | A Global Admin must consent to the required scopes. Run `Connect-MgGraph -Scopes "..."` as a Global Admin first |
| `Insufficient privileges to complete the operation` | Missing API permissions | Verify all permissions in `config/permissions.json` are granted. Check both delegated and application permissions |
| `ExchangeOnlineManagement` cmdlets not found | Module not installed or not connected | `Install-Module ExchangeOnlineManagement; Connect-ExchangeOnline` |
| Power Platform actions return "Warning" | `Microsoft.PowerApps.Administration.PowerShell` not installed | Install the module. On PS 7+ (Windows), the `-UseWindowsPowerShell` proxy is used automatically |
| Power Platform actions fail on Linux/macOS | PS 7 compatibility proxy not available | Run Power Platform actions from a Windows host, or use the manual steps provided in the Warning output |
| `HTTP 429 Too Many Requests` in automation | Graph API throttling | The non-interactive script retries automatically. If persistent, increase `-RetryDelaySeconds` or reduce request concurrency |
| Managed Identity auth fails in Automation Account | Identity not enabled or permissions not assigned | Verify: Azure Portal → Automation Account → Identity → Status = On. Check app role assignments |
| Forensic data is empty | User has no activity in the lookback window, or audit logging is not enabled | Verify unified audit logging is enabled: [Turn on audit logging](https://learn.microsoft.com/en-us/purview/audit-log-enable-disable) |
| `Revoke-MgUserSignInSession` returns error | User object not found or soft-deleted | Verify the UPN is correct and the account exists in the tenant |

### Enabling Verbose Output

```powershell
# Interactive: add -Verbose for detailed logging
.\src\Invoke-AccountRemediation.ps1 -UserPrincipalName "user@contoso.com" -Verbose

# Automation: set preference variable
$VerbosePreference = 'Continue'
.\src\Invoke-AutoRemediation.ps1 -UserPrincipalName "user@contoso.com"
```

### Checking Module Versions

```powershell
Get-InstalledModule Microsoft.Graph, ExchangeOnlineManagement, Microsoft.PowerApps.Administration.PowerShell, Pester |
    Format-Table Name, Version, InstalledDate
```

---

## Further Reading

| Topic | Link |
|---|---|
| Microsoft incident response playbooks | https://learn.microsoft.com/en-us/security/operations/incident-response-playbooks |
| Entra ID compromised account response | https://learn.microsoft.com/en-us/entra/id-protection/howto-identity-protection-remediate-unblock |
| Azure Automation security guidelines | https://learn.microsoft.com/en-us/azure/automation/automation-security-guidelines |
| Managed Identity for Automation | https://learn.microsoft.com/en-us/azure/automation/enable-managed-identity-for-automation |
| Sentinel playbook best practices | https://learn.microsoft.com/en-us/azure/sentinel/automate-responses-with-playbooks |
| Defender XDR attack disruption | https://learn.microsoft.com/en-us/defender-xdr/configure-attack-disruption |
| Security Copilot custom plugins | https://learn.microsoft.com/en-us/security-copilot/extend-security-copilot |
| Privileged Access Workstations | https://learn.microsoft.com/en-us/security/privileged-access-workstations/privileged-access-deployment |
| Microsoft Graph API permissions ref | https://learn.microsoft.com/en-us/graph/permissions-reference |
