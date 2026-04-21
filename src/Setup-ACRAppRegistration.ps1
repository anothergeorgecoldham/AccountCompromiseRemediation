#Requires -Version 7.2

<#
.SYNOPSIS
    One-time setup for Invoke-AccountRemediationAppAuth.ps1.

.DESCRIPTION
    Provisions everything needed to run the app-only certificate-auth remediation
    script:

      1. Generates a self-signed certificate in Cert:\CurrentUser\My (or reuses one).
      2. Creates an Entra ID app registration (or reuses one with the same display name).
      3. Uploads the certificate's public key as the app's keyCredential.
      4. Creates the corresponding service principal in the tenant.
      5. Grants admin consent for the Microsoft Graph application permissions
         listed in config/permissions.json (applicationPermissionsAppAuth.graphAppRoles).
      6. Optionally assigns the SP to the Exchange Administrator directory role
         (required for app-only Exchange Online cmdlets).
      7. Optionally registers the SP in Exchange Online via New-ServicePrincipal
         (required for the EXO PowerShell module to recognise the SP).
      8. Writes config/app-auth.json with the resulting TenantId, ClientId,
         CertificateThumbprint, and Organization.

    The operator running THIS script must be a Global Administrator (or hold
    Application Administrator + Privileged Role Administrator + Exchange
    Administrator). Idempotent — safe to re-run.

.PARAMETER TenantId
    Target tenant (GUID or domain). If omitted, uses the current Graph context.

.PARAMETER Organization
    EXO organization domain (e.g. contoso.onmicrosoft.com). Stored in app-auth.json.

.PARAMETER AppDisplayName
    Display name of the app registration. Default 'ACR Account Remediation (App Auth)'.

.PARAMETER CertSubject
    Subject of the self-signed certificate. Default 'CN=ACR-AppAuth'.

.PARAMETER CertValidityDays
    Lifetime of the self-signed cert. Default 365.

.PARAMETER ReuseCertificateThumbprint
    Use an existing certificate (in CurrentUser\My) instead of generating one.

.PARAMETER ConfigOutputPath
    Where to write app-auth.json. Default config/app-auth.json relative to repo root.

.PARAMETER PermissionsPath
    Where to read the application permissions list. Default config/permissions.json.

.PARAMETER SkipExchangeRole
    Skip assigning the SP to the Exchange Administrator directory role.

.PARAMETER SkipExchangeServicePrincipal
    Skip the EXO 'New-ServicePrincipal' registration step.

.PARAMETER WhatIf
    Show what would be created without making changes.

.EXAMPLE
    .\Setup-ACRAppRegistration.ps1 -Organization contoso.onmicrosoft.com

.EXAMPLE
    .\Setup-ACRAppRegistration.ps1 -Organization contoso.onmicrosoft.com `
        -AppDisplayName 'ACR Prod' -CertValidityDays 730
#>

[CmdletBinding(SupportsShouldProcess = $true)]
param(
    [Parameter()][string]$TenantId,
    [Parameter()][string]$Organization,
    [Parameter()][string]$AppDisplayName = 'ACR Account Remediation (App Auth)',
    [Parameter()][string]$CertSubject    = 'CN=ACR-AppAuth',
    [Parameter()][int]   $CertValidityDays = 365,
    [Parameter()][string]$ReuseCertificateThumbprint,
    [Parameter()][string]$ConfigOutputPath,
    [Parameter()][string]$PermissionsPath,
    [Parameter()][switch]$SkipExchangeRole,
    [Parameter()][switch]$SkipExchangeServicePrincipal
)

$ErrorActionPreference = 'Stop'

# ── Module imports ───────────────────────────────────────────────────────────
$required = @(
    'Microsoft.Graph.Authentication',
    'Microsoft.Graph.Applications',
    'Microsoft.Graph.Identity.DirectoryManagement'
)
foreach ($m in $required) {
    if (-not (Get-Module -ListAvailable -Name $m)) {
        throw "Required module '$m' is not installed. Run: Install-Module $m -Scope CurrentUser"
    }
    Import-Module $m -ErrorAction Stop | Out-Null
}

# ── Resolve paths ────────────────────────────────────────────────────────────
$repoRoot = Split-Path -Parent $PSScriptRoot
if (-not $ConfigOutputPath) { $ConfigOutputPath = Join-Path $repoRoot 'config\app-auth.json' }
if (-not $PermissionsPath)  { $PermissionsPath  = Join-Path $repoRoot 'config\permissions.json' }
$ConfigOutputPath = [System.IO.Path]::GetFullPath($ConfigOutputPath)
$PermissionsPath  = [System.IO.Path]::GetFullPath($PermissionsPath)

if (-not (Test-Path $PermissionsPath)) {
    throw "permissions.json not found at $PermissionsPath"
}

$permsRoot = Get-Content $PermissionsPath -Raw | ConvertFrom-Json
$appAuthPerms = $permsRoot.applicationPermissionsAppAuth
if (-not $appAuthPerms -or -not $appAuthPerms.graphAppRoles) {
    throw "applicationPermissionsAppAuth.graphAppRoles missing in $PermissionsPath. Re-pull config/permissions.json from the repository."
}

$graphResourceAppId = '00000003-0000-0000-c000-000000000000'  # Microsoft Graph
$exchangeAdminRoleTemplateId = '29232cdf-9323-42fd-ade2-1d097af3e4de'

# ── Banner ───────────────────────────────────────────────────────────────────
function Write-Section {
    param([string]$Title)
    Write-Host ''
    Write-Host ('═' * 63) -ForegroundColor DarkCyan
    Write-Host " $Title" -ForegroundColor Cyan
    Write-Host ('═' * 63) -ForegroundColor DarkCyan
}

Write-Section 'ACR App Registration Setup'
Write-Host "  Repo root      : $repoRoot"
Write-Host "  App display    : $AppDisplayName"
Write-Host "  Cert subject   : $CertSubject"
Write-Host "  Output config  : $ConfigOutputPath"
Write-Host "  Permissions    : $PermissionsPath"
if ($Organization) { Write-Host "  EXO org        : $Organization" }
Write-Host ''

# ── Step 1: Connect to Graph as an admin ─────────────────────────────────────
Write-Section 'Step 1: Connect to Microsoft Graph (interactive admin login)'

$connectScopes = @(
    'Application.ReadWrite.All',
    'Directory.ReadWrite.All',
    'AppRoleAssignment.ReadWrite.All',
    'RoleManagement.ReadWrite.Directory'
)

$connectParams = @{ Scopes = $connectScopes; NoWelcome = $true; ErrorAction = 'Stop' }
if ($TenantId) { $connectParams['TenantId'] = $TenantId }

if ($PSCmdlet.ShouldProcess('Microsoft Graph', "Interactive admin sign-in (scopes: $($connectScopes -join ','))")) {
    Connect-MgGraph @connectParams | Out-Null
}
$ctx = Get-MgContext
if (-not $ctx) { throw 'Failed to obtain Graph context.' }
if (-not $TenantId) { $TenantId = $ctx.TenantId }
Write-Host "  [✓] Connected as $($ctx.Account) to tenant $TenantId" -ForegroundColor Green

# Verify operator privilege
try {
    $me = Get-MgUser -UserId $ctx.Account -ErrorAction Stop
    $myRoles = Get-MgUserMemberOf -UserId $me.Id -All -ErrorAction Stop |
        Where-Object { $_.AdditionalProperties.'@odata.type' -eq '#microsoft.graph.directoryRole' } |
        ForEach-Object { $_.AdditionalProperties.displayName }
    $required = @('Global Administrator','Application Administrator','Privileged Role Administrator')
    $hasRequired = $myRoles | Where-Object { $_ -in $required }
    if (-not $hasRequired) {
        Write-Warning "Operator '$($ctx.Account)' does not appear to hold Global/Application Administrator. App-role assignment will likely fail. Roles found: $($myRoles -join ', ')"
    } else {
        Write-Host "  [✓] Operator privilege OK ($($hasRequired -join ', '))" -ForegroundColor Green
    }
} catch {
    Write-Warning "Could not verify operator roles: $($_.Exception.Message). Continuing — Graph will reject if insufficient."
}

# ── Step 2: Certificate ──────────────────────────────────────────────────────
Write-Section 'Step 2: Certificate'

$cert = $null
if ($ReuseCertificateThumbprint) {
    $thumb = $ReuseCertificateThumbprint -replace '\s',''
    $cert = Get-ChildItem 'Cert:\CurrentUser\My' | Where-Object { $_.Thumbprint -eq $thumb } | Select-Object -First 1
    if (-not $cert) { throw "Certificate $thumb not found in CurrentUser\My." }
    Write-Host "  [✓] Reusing existing cert $($cert.Thumbprint) (subject=$($cert.Subject), expires $($cert.NotAfter.ToString('o')))" -ForegroundColor Green
} else {
    $existing = Get-ChildItem 'Cert:\CurrentUser\My' | Where-Object { $_.Subject -eq $CertSubject -and $_.NotAfter -gt (Get-Date).AddDays(30) } | Select-Object -First 1
    if ($existing) {
        $cert = $existing
        Write-Host "  [✓] Reusing existing cert with subject '$CertSubject' — thumbprint $($cert.Thumbprint), expires $($cert.NotAfter.ToString('o'))" -ForegroundColor Green
    } else {
        if ($PSCmdlet.ShouldProcess($CertSubject, "Generate self-signed certificate (validity ${CertValidityDays}d)")) {
            $cert = New-SelfSignedCertificate `
                -Subject $CertSubject `
                -CertStoreLocation 'Cert:\CurrentUser\My' `
                -KeyExportPolicy NonExportable `
                -KeySpec Signature `
                -KeyLength 2048 `
                -KeyAlgorithm RSA `
                -HashAlgorithm SHA256 `
                -NotAfter (Get-Date).AddDays($CertValidityDays) `
                -KeyUsage DigitalSignature
            Write-Host "  [✓] Generated cert thumbprint $($cert.Thumbprint), expires $($cert.NotAfter.ToString('o'))" -ForegroundColor Green
            Write-Host "      Private key is non-exportable. Cert lives in Cert:\CurrentUser\My on this machine only." -ForegroundColor Gray
        }
    }
}

# Public-cert bytes (Base64) for upload
$certB64 = [Convert]::ToBase64String($cert.RawData)

# ── Step 3: App registration ─────────────────────────────────────────────────
Write-Section 'Step 3: Entra App Registration'

$app = Get-MgApplication -Filter "displayName eq '$AppDisplayName'" -ErrorAction SilentlyContinue | Select-Object -First 1
if ($app) {
    Write-Host "  [✓] Reusing existing app '$AppDisplayName' (AppId=$($app.AppId), ObjectId=$($app.Id))" -ForegroundColor Green
} else {
    if ($PSCmdlet.ShouldProcess($AppDisplayName, 'Create Entra app registration')) {
        $app = New-MgApplication -DisplayName $AppDisplayName -SignInAudience 'AzureADMyOrg'
        Write-Host "  [✓] Created app '$AppDisplayName' (AppId=$($app.AppId), ObjectId=$($app.Id))" -ForegroundColor Green
    }
}

# ── Step 4: Upload certificate ───────────────────────────────────────────────
Write-Section 'Step 4: Attach certificate to app'

$existingKey = $null
if ($app.KeyCredentials) {
    $existingKey = $app.KeyCredentials | Where-Object {
        $_.CustomKeyIdentifier -and ([Convert]::ToBase64String($_.CustomKeyIdentifier) -eq [Convert]::ToBase64String($cert.GetCertHash()))
    } | Select-Object -First 1
}

if ($existingKey) {
    Write-Host "  [✓] Certificate already attached to app (keyId=$($existingKey.KeyId))" -ForegroundColor Green
} else {
    $newKey = @{
        Type        = 'AsymmetricX509Cert'
        Usage       = 'Verify'
        Key         = $cert.RawData
        DisplayName = "ACR cert ($($cert.Thumbprint.Substring(0,8))…)"
    }
    $merged = @($app.KeyCredentials) + $newKey | Where-Object { $_ }
    if ($PSCmdlet.ShouldProcess("App $($app.AppId)", 'Attach certificate as keyCredential')) {
        Update-MgApplication -ApplicationId $app.Id -KeyCredentials $merged
        Write-Host "  [✓] Certificate attached" -ForegroundColor Green
    }
}

# ── Step 5: Service principal ────────────────────────────────────────────────
Write-Section 'Step 5: Service Principal'

$sp = Get-MgServicePrincipal -Filter "appId eq '$($app.AppId)'" -ErrorAction SilentlyContinue | Select-Object -First 1
if ($sp) {
    Write-Host "  [✓] Reusing existing SP (ObjectId=$($sp.Id))" -ForegroundColor Green
} else {
    if ($PSCmdlet.ShouldProcess($app.AppId, 'Create service principal')) {
        $sp = New-MgServicePrincipal -AppId $app.AppId
        Write-Host "  [✓] Created SP (ObjectId=$($sp.Id))" -ForegroundColor Green
    }
}

# ── Step 6: Admin consent (Graph appRoleAssignments) ─────────────────────────
Write-Section 'Step 6: Grant admin consent for Graph application permissions'

$graphSp = Get-MgServicePrincipal -Filter "appId eq '$graphResourceAppId'" -ErrorAction Stop | Select-Object -First 1
if (-not $graphSp) { throw "Microsoft Graph service principal not found in tenant. Cannot grant consent." }

$existingAssignments = Get-MgServicePrincipalAppRoleAssignment -ServicePrincipalId $sp.Id -ErrorAction SilentlyContinue
$existingAppRoleIds = @($existingAssignments | Where-Object { $_.ResourceId -eq $graphSp.Id } | ForEach-Object { $_.AppRoleId.ToString() })

$granted = 0; $skipped = 0; $failed = 0
foreach ($role in $appAuthPerms.graphAppRoles) {
    $roleId = $role.id
    if ($existingAppRoleIds -contains $roleId) {
        Write-Host "  [=] $($role.name)  (already granted)" -ForegroundColor DarkGray
        $skipped++
        continue
    }
    if ($PSCmdlet.ShouldProcess("$($role.name) ($roleId)", 'Grant Graph app permission to SP')) {
        try {
            New-MgServicePrincipalAppRoleAssignment -ServicePrincipalId $sp.Id `
                -PrincipalId $sp.Id -ResourceId $graphSp.Id -AppRoleId $roleId -ErrorAction Stop | Out-Null
            Write-Host "  [✓] $($role.name)  ($($role.purpose))" -ForegroundColor Green
            $granted++
        } catch {
            Write-Warning "Could not grant $($role.name) — $($_.Exception.Message)"
            $failed++
        }
    }
}
Write-Host ''
Write-Host "  Granted: $granted   Already-present: $skipped   Failed: $failed" -ForegroundColor Cyan

# ── Step 7: Exchange Administrator directory role ────────────────────────────
if (-not $SkipExchangeRole) {
    Write-Section 'Step 7: Assign SP to Exchange Administrator directory role'
    try {
        # Activate the directory role if it exists only as a template
        $allRoles = Get-MgDirectoryRole -All -ErrorAction Stop
        $exoRole  = $allRoles | Where-Object { $_.RoleTemplateId -eq $exchangeAdminRoleTemplateId } | Select-Object -First 1
        if (-not $exoRole) {
            if ($PSCmdlet.ShouldProcess('Exchange Administrator', 'Activate directory role from template')) {
                $exoRole = New-MgDirectoryRole -RoleTemplateId $exchangeAdminRoleTemplateId -ErrorAction Stop
                Write-Host "  [✓] Activated directory role 'Exchange Administrator'" -ForegroundColor Green
            }
        }
        # Check existing membership
        $members = Get-MgDirectoryRoleMember -DirectoryRoleId $exoRole.Id -All -ErrorAction SilentlyContinue
        if ($members | Where-Object { $_.Id -eq $sp.Id }) {
            Write-Host "  [=] SP is already in Exchange Administrator" -ForegroundColor DarkGray
        } else {
            if ($PSCmdlet.ShouldProcess($sp.Id, 'Add SP to Exchange Administrator')) {
                $body = @{ '@odata.id' = "https://graph.microsoft.com/v1.0/directoryObjects/$($sp.Id)" }
                New-MgDirectoryRoleMemberByRef -DirectoryRoleId $exoRole.Id -BodyParameter $body -ErrorAction Stop | Out-Null
                Write-Host "  [✓] Added SP to Exchange Administrator" -ForegroundColor Green
            }
        }
    } catch {
        Write-Warning "Failed to assign Exchange Administrator role: $($_.Exception.Message)"
        Write-Warning "Mailbox/transport actions may fail. Assign manually in Entra portal: Roles & administrators → Exchange Administrator → Add the SP."
    }
} else {
    Write-Host ''
    Write-Host "  [–] Skipped Exchange Administrator role assignment (-SkipExchangeRole)" -ForegroundColor DarkYellow
}

# ── Step 8: EXO New-ServicePrincipal ─────────────────────────────────────────
if (-not $SkipExchangeServicePrincipal) {
    Write-Section 'Step 8: Register SP in Exchange Online'
    if (-not $Organization) {
        Write-Warning "Organization not specified — skipping EXO New-ServicePrincipal step. Re-run with -Organization <tenant.onmicrosoft.com> later, or run manually:"
        Write-Host "    Connect-ExchangeOnline -Organization <tenant.onmicrosoft.com>" -ForegroundColor Yellow
        Write-Host "    New-ServicePrincipal -AppId $($app.AppId) -ServiceId $($sp.Id) -DisplayName '$AppDisplayName'" -ForegroundColor Yellow
    } else {
        if (-not (Get-Module -ListAvailable -Name ExchangeOnlineManagement)) {
            Write-Warning "ExchangeOnlineManagement not installed — skipping. Install and run the New-ServicePrincipal command manually."
        } else {
            try {
                Import-Module ExchangeOnlineManagement -ErrorAction Stop
                if ($PSCmdlet.ShouldProcess($Organization, 'Connect to EXO interactively')) {
                    Connect-ExchangeOnline -Organization $Organization -ShowBanner:$false -ErrorAction Stop
                    $exoSp = Get-ServicePrincipal -ErrorAction SilentlyContinue | Where-Object { $_.AppId -eq $app.AppId } | Select-Object -First 1
                    if ($exoSp) {
                        Write-Host "  [=] EXO service principal already registered (Id=$($exoSp.ServiceId))" -ForegroundColor DarkGray
                    } else {
                        if ($PSCmdlet.ShouldProcess($app.AppId, 'Register SP in EXO via New-ServicePrincipal')) {
                            New-ServicePrincipal -AppId $app.AppId -ServiceId $sp.Id -DisplayName $AppDisplayName | Out-Null
                            Write-Host "  [✓] EXO service principal registered" -ForegroundColor Green
                        }
                    }
                }
            } catch {
                Write-Warning "EXO registration step failed: $($_.Exception.Message)"
                Write-Warning "Run manually: New-ServicePrincipal -AppId $($app.AppId) -ServiceId $($sp.Id) -DisplayName '$AppDisplayName'"
            } finally {
                try { Disconnect-ExchangeOnline -Confirm:$false -ErrorAction SilentlyContinue | Out-Null } catch { }
            }
        }
    }
} else {
    Write-Host ''
    Write-Host "  [–] Skipped EXO New-ServicePrincipal (-SkipExchangeServicePrincipal)" -ForegroundColor DarkYellow
}

# ── Step 9: Write app-auth.json ──────────────────────────────────────────────
Write-Section 'Step 9: Write config/app-auth.json'

$cfgDir = Split-Path -Parent $ConfigOutputPath
if (-not (Test-Path $cfgDir)) { New-Item -ItemType Directory -Path $cfgDir -Force | Out-Null }

$cfgObj = [ordered]@{
    tenantId              = $TenantId
    clientId              = $app.AppId
    certificateThumbprint = $cert.Thumbprint
    organization          = $Organization
    _generatedBy          = 'Setup-ACRAppRegistration.ps1'
    _generatedAt          = (Get-Date).ToUniversalTime().ToString('o')
    _appDisplayName       = $AppDisplayName
}

if ($PSCmdlet.ShouldProcess($ConfigOutputPath, 'Write app-auth.json')) {
    $cfgObj | ConvertTo-Json -Depth 4 | Set-Content -Path $ConfigOutputPath -Encoding UTF8
    Write-Host "  [✓] Wrote $ConfigOutputPath" -ForegroundColor Green
}

# ── Final summary ────────────────────────────────────────────────────────────
Write-Section 'Setup Complete'
Write-Host ''
Write-Host "  TenantId              : $TenantId"
Write-Host "  ClientId  (AppId)     : $($app.AppId)"
Write-Host "  ServicePrincipal Id   : $($sp.Id)"
Write-Host "  Certificate thumbprint: $($cert.Thumbprint)"
Write-Host "  Certificate expires   : $($cert.NotAfter.ToString('yyyy-MM-dd'))"
Write-Host "  Config written to     : $ConfigOutputPath"
Write-Host ''
Write-Host '  Hardening recommendations:' -ForegroundColor Yellow
Write-Host '   • The certificate''s private key is in Cert:\CurrentUser\My on this machine only.' -ForegroundColor DarkYellow
Write-Host '     To use from another analyst workstation, generate a separate cert there and add' -ForegroundColor DarkYellow
Write-Host '     it to the SAME app registration (re-run this script with -ReuseCertificateThumbprint).' -ForegroundColor DarkYellow
Write-Host '   • Restrict the cert''s private key ACL to your SOC group (certlm.msc → Manage Private Keys).' -ForegroundColor DarkYellow
Write-Host '   • Rotate the certificate before NotAfter; remove the old keyCredential from the app.' -ForegroundColor DarkYellow
Write-Host '   • Anyone with read access to the private key can perform every remediation action.' -ForegroundColor DarkYellow
Write-Host ''
Write-Host "  Next: .\Invoke-AccountRemediationAppAuth.ps1 -UserPrincipalName <upn> -DryRun" -ForegroundColor Green
Write-Host ''

try { Disconnect-MgGraph -ErrorAction SilentlyContinue | Out-Null } catch {}
