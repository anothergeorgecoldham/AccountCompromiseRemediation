#Requires -Version 7.2
#Requires -Modules Microsoft.Graph.Authentication

<#
.SYNOPSIS
    Authentication module for Account Compromise Remediation.

.DESCRIPTION
    Provides authentication functions for both interactive (browser login)
    and non-interactive (Managed Identity) scenarios, plus admin role detection.
#>

# Required Graph scopes for full remediation capabilities
$script:RequiredScopes = @(
    'User.ReadWrite.All'
    'Directory.ReadWrite.All'
    'Directory.AccessAsUser.All'    # Required to write passwordProfile (reset user password)
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

# Well-known Entra ID admin role template IDs
$script:AdminRoleTemplateIds = @{
    'GlobalAdministrator'       = '62e90394-69f5-4237-9190-012177145e10'
    'ExchangeAdministrator'     = '29232cdf-9323-42fd-ade2-1d097af3e4de'
    'UserAdministrator'         = 'fe930be7-5e62-47db-91af-98c3a49a38b1'
    'SecurityAdministrator'     = '194ae4cb-b126-40b2-bd5b-6091b380977d'
    'PrivilegedRoleAdministrator' = 'e8611ab8-c189-46e8-94e1-60213ab1f814'
    'ApplicationAdministrator'  = '9b895d92-2cd3-44c7-9d02-a6ac2d5ea5c3'
    'CloudApplicationAdministrator' = '158c047a-c907-4556-b7ef-446551a6b5f7'
    'HelpdeskAdministrator'     = '729827e3-9c14-49f7-bb1b-9608f156bbb8'
}

function Connect-ACRInteractive {
    <#
    .SYNOPSIS
        Connects to Microsoft Graph using interactive browser login.
    .DESCRIPTION
        Initiates an interactive browser-based authentication flow with the required
        Graph API scopes for remediation operations.
    .PARAMETER TenantId
        Optional tenant ID to target a specific tenant.
    .OUTPUTS
        [Microsoft.Graph.PowerShell.Authentication.AuthContext] The authentication context.
    .EXAMPLE
        Connect-ACRInteractive
        Connect-ACRInteractive -TenantId "contoso.onmicrosoft.com"
    #>
    [CmdletBinding()]
    param(
        [Parameter()]
        [string]$TenantId
    )

    $connectParams = @{
        Scopes      = $script:RequiredScopes
        ErrorAction = 'Stop'
    }

    if ($TenantId) {
        $connectParams['TenantId'] = $TenantId
    }

    try {
        Write-Verbose "Initiating interactive Graph authentication..."
        $context = Connect-MgGraph @connectParams
        Write-Verbose "Successfully connected to Microsoft Graph."
        return $context
    }
    catch {
        throw "Failed to connect to Microsoft Graph interactively: $_"
    }
}

function Connect-ACRManagedIdentity {
    <#
    .SYNOPSIS
        Connects to Microsoft Graph using a Managed Identity.
    .DESCRIPTION
        Authenticates using the Managed Identity assigned to the Azure resource
        (Automation Account, Logic App, etc.).
    .OUTPUTS
        [Microsoft.Graph.PowerShell.Authentication.AuthContext] The authentication context.
    .EXAMPLE
        Connect-ACRManagedIdentity
    #>
    [CmdletBinding()]
    param()

    try {
        Write-Verbose "Connecting to Microsoft Graph using Managed Identity..."
        $context = Connect-MgGraph -Identity -ErrorAction Stop
        Write-Verbose "Successfully connected via Managed Identity."
        return $context
    }
    catch {
        throw "Failed to connect via Managed Identity: $_"
    }
}

function Get-ACRUserContext {
    <#
    .SYNOPSIS
        Retrieves user details and detects admin role memberships.
    .DESCRIPTION
        Fetches the target user's profile and checks for admin directory role
        assignments. Returns a context object indicating whether the user is
        a standard user, admin, or Exchange admin.
    .PARAMETER UserPrincipalName
        The UPN of the target user to investigate.
    .OUTPUTS
        [PSCustomObject] with properties: User, IsAdmin, IsExchangeAdmin, AdminRoles
    .EXAMPLE
        $ctx = Get-ACRUserContext -UserPrincipalName "user@contoso.com"
        if ($ctx.IsAdmin) { Write-Host "Admin account detected" }
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$UserPrincipalName
    )

    try {
        Write-Verbose "Fetching user profile for $UserPrincipalName..."
        $user = Get-MgUser -UserId $UserPrincipalName -Property 'Id','DisplayName','UserPrincipalName','AccountEnabled','UserType' -ErrorAction Stop

        Write-Verbose "Checking directory role memberships..."
        $memberOf = Get-MgUserMemberOf -UserId $user.Id -All -ErrorAction Stop
        $directoryRoles = $memberOf | Where-Object {
            $_.AdditionalProperties.'@odata.type' -eq '#microsoft.graph.directoryRole'
        }

        $assignedRoleTemplateIds = $directoryRoles | ForEach-Object {
            $_.AdditionalProperties.roleTemplateId
        }

        $adminRoleNames = @()
        $isAdmin = $false
        $isExchangeAdmin = $false

        foreach ($roleName in $script:AdminRoleTemplateIds.Keys) {
            $templateId = $script:AdminRoleTemplateIds[$roleName]
            if ($assignedRoleTemplateIds -contains $templateId) {
                $adminRoleNames += $roleName
                $isAdmin = $true
                if ($roleName -eq 'ExchangeAdministrator') {
                    $isExchangeAdmin = $true
                }
            }
        }

        # Global Administrators implicitly have Exchange admin capabilities
        if ($adminRoleNames -contains 'GlobalAdministrator') {
            $isExchangeAdmin = $true
        }

        $context = [PSCustomObject]@{
            User              = $user
            UserId            = $user.Id
            UserPrincipalName = $user.UserPrincipalName
            DisplayName       = $user.DisplayName
            IsAdmin           = $isAdmin
            IsExchangeAdmin   = $isExchangeAdmin
            AdminRoles        = $adminRoleNames
        }

        if ($isAdmin) {
            Write-Verbose "Admin account detected. Roles: $($adminRoleNames -join ', ')"
        }
        else {
            Write-Verbose "Standard user account (no admin roles detected)."
        }

        return $context
    }
    catch {
        throw "Failed to retrieve user context for ${UserPrincipalName}: $_"
    }
}

function Disconnect-ACR {
    <#
    .SYNOPSIS
        Disconnects from Microsoft Graph and Exchange Online.
    .DESCRIPTION
        Cleans up active sessions. When Exchange Online was connected via device-code
        fallback (due to the WAM broker bug on this host), Disconnect-ExchangeOnline is
        skipped because its internal token-cleanup triggers an unhandled async exception
        that would crash the process. The EXO session will be cleaned up naturally when
        the PowerShell process exits.
    #>
    [CmdletBinding()]
    param()

    try {
        Disconnect-MgGraph -ErrorAction SilentlyContinue | Out-Null
        Write-Verbose "Disconnected from Microsoft Graph."
    }
    catch {
        Write-Verbose "Graph disconnect warning: $_"
    }

    if ($script:ACRExoUsedDeviceCode) {
        Write-Verbose "Skipping Disconnect-ExchangeOnline (device-code fallback was used; disconnect would trigger a known async crash). Close the shell to fully clean up."
        return
    }

    try {
        if (Get-Module -Name ExchangeOnlineManagement) {
            Disconnect-ExchangeOnline -Confirm:$false -ErrorAction SilentlyContinue | Out-Null
            Write-Verbose "Disconnected from Exchange Online."
        }
    }
    catch {
        Write-Verbose "EXO disconnect warning: $_"
    }
}

function Connect-ACRExchangeOnline {
    <#
    .SYNOPSIS
        Connects to Exchange Online for mailbox and transport rule operations.
    .DESCRIPTION
        Establishes an Exchange Online PowerShell session using interactive auth.
        Required for: mailbox delegates, folder permissions, forwarding, safe senders,
        transport rules, journal rules, inbox rules, and unified audit log.
    .PARAMETER UserPrincipalName
        Optional UPN hint for the admin account connecting.
    #>
    [CmdletBinding()]
    param(
        [Parameter()]
        [string]$UserPrincipalName
    )

    if (-not (Get-Module -ListAvailable -Name ExchangeOnlineManagement)) {
        Write-Warning "ExchangeOnlineManagement module is not installed. Some actions will be limited."
        return $false
    }

    try {
        Import-Module ExchangeOnlineManagement -ErrorAction Stop
        $connectParams = @{ ShowBanner = $false; ErrorAction = 'Stop' }
        if ($UserPrincipalName) { $connectParams['UserPrincipalName'] = $UserPrincipalName }
        Connect-ExchangeOnline @connectParams
        Write-Verbose "Connected to Exchange Online."
        $script:ACRExoUsedDeviceCode = $false
        return $true
    }
    catch {
        # Detect the WAM broker NullReferenceException (known issue on some Windows hosts)
        $errText = "$_"
        $isWamBug = $errText -match 'NullReferenceException|RuntimeBroker|Object reference not set'

        if ($isWamBug) {
            Write-Warning "Exchange Online interactive login failed due to a known WAM broker issue. Retrying with device code authentication..."
            try {
                $deviceParams = @{ ShowBanner = $false; ErrorAction = 'Stop'; Device = $true }
                if ($UserPrincipalName) { $deviceParams['UserPrincipalName'] = $UserPrincipalName }
                Connect-ExchangeOnline @deviceParams
                Write-Verbose "Connected to Exchange Online via device code."
                # Flag that we used device code — Disconnect-ExchangeOnline triggers the same WAM bug on a background thread during token cleanup, so we skip disconnect for this path.
                $script:ACRExoUsedDeviceCode = $true
                return $true
            } catch {
                Write-Warning "Device code fallback also failed: $_"
                return $false
            }
        }

        Write-Warning "Failed to connect to Exchange Online: $_"
        return $false
    }
}

function Connect-ACRExchangeOnlineMI {
    <#
    .SYNOPSIS
        Connects to Exchange Online using Managed Identity.
    .DESCRIPTION
        Establishes an Exchange Online PowerShell session using the Managed Identity
        assigned to the Azure Automation Account or Logic App.
    .PARAMETER Organization
        The tenant domain (e.g., contoso.onmicrosoft.com). Required for MI auth.
    #>
    [CmdletBinding()]
    param(
        [Parameter()]
        [string]$Organization
    )

    if (-not (Get-Module -ListAvailable -Name ExchangeOnlineManagement)) {
        Write-Warning "ExchangeOnlineManagement module is not installed. Some actions will be limited."
        return $false
    }

    try {
        Import-Module ExchangeOnlineManagement -ErrorAction Stop
        $connectParams = @{
            ManagedIdentity = $true
            ShowBanner      = $false
            ErrorAction     = 'Stop'
        }
        if ($Organization) { $connectParams['Organization'] = $Organization }
        Connect-ExchangeOnline @connectParams
        Write-Verbose "Connected to Exchange Online via Managed Identity."
        return $true
    }
    catch {
        Write-Warning "Failed to connect to Exchange Online via Managed Identity: $_"
        return $false
    }
}

function Test-ACRExchangeOnlineConnected {
    <#
    .SYNOPSIS
        Tests whether an active Exchange Online session exists.
    #>
    [CmdletBinding()]
    param()

    try {
        $null = Get-Command Get-Mailbox -ErrorAction Stop
        # Quick test that the session is live
        $null = Get-OrganizationConfig -ErrorAction Stop | Select-Object -First 1
        return $true
    }
    catch {
        return $false
    }
}

function Connect-ACRAppAuth {
    <#
    .SYNOPSIS
        Connects to Microsoft Graph using a certificate (app-only auth).
    .DESCRIPTION
        Authenticates as the configured app registration using a certificate held in
        the local Windows certificate store (Cert:\CurrentUser\My or
        Cert:\LocalMachine\My) or supplied as a file. The script then runs with
        the application permissions granted to the app registration, regardless of
        the operator's own Entra roles. This enables low-privilege analysts to
        execute the full remediation workflow.
    .PARAMETER TenantId
        Target tenant GUID or domain (required).
    .PARAMETER ClientId
        App registration's Application (client) ID (required).
    .PARAMETER CertificateThumbprint
        Thumbprint of the certificate in Cert:\CurrentUser\My or Cert:\LocalMachine\My.
        Either CertificateThumbprint or CertificatePath must be supplied.
    .PARAMETER CertificatePath
        Optional path to a .pfx/.cer file. If a .pfx is used a password may be
        required (passed via -CertificatePassword as a SecureString).
    .PARAMETER CertificatePassword
        Optional SecureString password for a .pfx file.
    .OUTPUTS
        The Microsoft Graph authentication context.
    .EXAMPLE
        Connect-ACRAppAuth -TenantId 'contoso.onmicrosoft.com' -ClientId '<guid>' -CertificateThumbprint '<thumbprint>'
    #>
    [CmdletBinding(DefaultParameterSetName = 'Thumbprint')]
    param(
        [Parameter(Mandatory)][string]$TenantId,
        [Parameter(Mandatory)][string]$ClientId,

        [Parameter(Mandatory, ParameterSetName = 'Thumbprint')]
        [string]$CertificateThumbprint,

        [Parameter(Mandatory, ParameterSetName = 'Path')]
        [string]$CertificatePath,

        [Parameter(ParameterSetName = 'Path')]
        [System.Security.SecureString]$CertificatePassword
    )

    $cert = $null

    if ($PSCmdlet.ParameterSetName -eq 'Thumbprint') {
        $thumb = $CertificateThumbprint -replace '\s',''
        foreach ($store in @('Cert:\CurrentUser\My','Cert:\LocalMachine\My')) {
            try {
                $found = Get-ChildItem $store -ErrorAction SilentlyContinue |
                    Where-Object { $_.Thumbprint -eq $thumb } | Select-Object -First 1
                if ($found) { $cert = $found; break }
            } catch { }
        }
        if (-not $cert) {
            throw "Certificate with thumbprint '$thumb' not found in CurrentUser\My or LocalMachine\My. Run Setup-ACRAppRegistration.ps1 to provision one, or import the cert and try again."
        }
        if ($cert.NotAfter -lt (Get-Date)) {
            throw "Certificate '$thumb' expired on $($cert.NotAfter.ToString('o'))."
        }
        if (-not $cert.HasPrivateKey) {
            throw "Certificate '$thumb' does not have an accessible private key in this user's context."
        }
    }
    else {
        if (-not (Test-Path $CertificatePath)) {
            throw "Certificate file not found: $CertificatePath"
        }
        try {
            if ($CertificatePassword) {
                $cert = [System.Security.Cryptography.X509Certificates.X509Certificate2]::new($CertificatePath, $CertificatePassword)
            } else {
                $cert = [System.Security.Cryptography.X509Certificates.X509Certificate2]::new($CertificatePath)
            }
        } catch {
            throw "Failed to load certificate from '$CertificatePath': $($_.Exception.Message)"
        }
    }

    try {
        Write-Verbose "Connecting to Microsoft Graph (app-only) — TenantId=$TenantId ClientId=$ClientId Thumbprint=$($cert.Thumbprint)"
        $context = Connect-MgGraph -TenantId $TenantId -ClientId $ClientId -Certificate $cert -NoWelcome -ErrorAction Stop
    } catch {
        throw "Failed to connect to Microsoft Graph with certificate auth: $($_.Exception.Message)"
    }

    $script:ACRAppAuthContext = [PSCustomObject]@{
        TenantId              = $TenantId
        ClientId              = $ClientId
        CertificateThumbprint = $cert.Thumbprint
        CertificateExpiry     = $cert.NotAfter
        AuthMode              = 'AppOnly'
    }

    Write-Verbose "Connected. Auth mode = AppOnly. Cert expires $($cert.NotAfter.ToString('o'))."
    return $context
}

function Connect-ACRExchangeOnlineApp {
    <#
    .SYNOPSIS
        Connects to Exchange Online using app-only certificate auth.
    .DESCRIPTION
        Establishes an Exchange Online PowerShell session as the app registration's
        service principal. The SP must have been added to an Exchange role group
        (e.g., Organization Management or Recipient Management) via
        New-ServicePrincipal in EXO during setup.
    .PARAMETER Organization
        Tenant primary domain, e.g. contoso.onmicrosoft.com (required).
    .PARAMETER AppId
        App registration's Application (client) ID (required).
    .PARAMETER CertificateThumbprint
        Thumbprint of the certificate (must be the same one used for Graph).
    .PARAMETER CertificatePath
        Alternative: file path to a .pfx/.cer. EXO does NOT accept a SecureString
        password via the cmdlet — use thumbprint with the cert in the local store
        if your .pfx is password-protected.
    .OUTPUTS
        Boolean — $true on success, $false on failure (with a warning emitted).
    #>
    [CmdletBinding(DefaultParameterSetName = 'Thumbprint')]
    param(
        [Parameter(Mandatory)][string]$Organization,
        [Parameter(Mandatory)][string]$AppId,

        [Parameter(Mandatory, ParameterSetName = 'Thumbprint')]
        [string]$CertificateThumbprint,

        [Parameter(Mandatory, ParameterSetName = 'Path')]
        [string]$CertificatePath
    )

    if (-not (Get-Module -ListAvailable -Name ExchangeOnlineManagement)) {
        Write-Warning "ExchangeOnlineManagement module is not installed. Mailbox/transport actions will be skipped."
        return $false
    }

    try {
        Import-Module ExchangeOnlineManagement -ErrorAction Stop
        $params = @{
            AppId        = $AppId
            Organization = $Organization
            ShowBanner   = $false
            ErrorAction  = 'Stop'
        }
        if ($PSCmdlet.ParameterSetName -eq 'Thumbprint') {
            $params['CertificateThumbprint'] = ($CertificateThumbprint -replace '\s','')
        } else {
            $params['CertificateFilePath'] = $CertificatePath
        }
        Connect-ExchangeOnline @params
        # App-only EXO does not trigger the WAM bug; safe to disconnect normally.
        $script:ACRExoUsedDeviceCode = $false
        Write-Verbose "Connected to Exchange Online (app-only) as $AppId in $Organization."
        return $true
    } catch {
        Write-Warning "Failed to connect to Exchange Online with app-only certificate auth: $($_.Exception.Message)"
        Write-Warning "Common causes: (1) the service principal has not been registered in EXO via 'New-ServicePrincipal -AppId <id> -ObjectId <spObjectId>'; (2) the SP is not a member of an Exchange role group; (3) certificate not present on this machine."
        return $false
    }
}

function Get-ACROperatorIdentity {
    <#
    .SYNOPSIS
        Resolves the human operator running an app-auth remediation session.
    .DESCRIPTION
        The script authenticates as a service principal, so the SPN identity does
        not identify the analyst. This function returns a structured identity for
        audit/attribution purposes. By default it captures the current Windows
        identity; pass -OperatorUpn to override (e.g., when the analyst's local
        username differs from their corporate UPN).
    .PARAMETER OperatorUpn
        Optional override for the operator's UPN/email/display name.
    .OUTPUTS
        [PSCustomObject] with DisplayName, Source, AuthMode, AppId, ServicePrincipalObjectId.
    #>
    [CmdletBinding()]
    param(
        [Parameter()][string]$OperatorUpn
    )

    if ($OperatorUpn) {
        $display = $OperatorUpn
        $source  = 'Override'
    } else {
        try {
            $display = [System.Security.Principal.WindowsIdentity]::GetCurrent().Name
        } catch {
            $display = $env:USERNAME
        }
        $source = 'WindowsIdentity'
    }

    $appId = $null
    $spObjectId = $null
    if ($script:ACRAppAuthContext) {
        $appId = $script:ACRAppAuthContext.ClientId
    }
    try {
        $ctx = Get-MgContext -ErrorAction SilentlyContinue
        if ($ctx -and $ctx.AuthType -eq 'AppOnly') {
            $authMode = 'AppOnly'
            if (-not $appId) { $appId = $ctx.ClientId }
        } else {
            $authMode = 'Delegated'
        }
    } catch {
        $authMode = 'Unknown'
    }

    [PSCustomObject]@{
        DisplayName               = $display
        Source                    = $source
        AuthMode                  = $authMode
        AppId                     = $appId
        ServicePrincipalObjectId  = $spObjectId
        Hostname                  = $env:COMPUTERNAME
        CapturedAt                = (Get-Date).ToUniversalTime().ToString('o')
    }
}

Export-ModuleMember -Function @(
    'Connect-ACRInteractive'
    'Connect-ACRManagedIdentity'
    'Connect-ACRExchangeOnline'
    'Connect-ACRExchangeOnlineMI'
    'Connect-ACRAppAuth'
    'Connect-ACRExchangeOnlineApp'
    'Get-ACROperatorIdentity'
    'Test-ACRExchangeOnlineConnected'
    'Get-ACRUserContext'
    'Disconnect-ACR'
)
