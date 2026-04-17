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
    #>
    [CmdletBinding()]
    param()

    try {
        Disconnect-MgGraph -ErrorAction SilentlyContinue
        Write-Verbose "Disconnected from Microsoft Graph."
    }
    catch {
        Write-Verbose "Graph disconnect warning: $_"
    }

    try {
        if (Get-Module -Name ExchangeOnlineManagement) {
            Disconnect-ExchangeOnline -Confirm:$false -ErrorAction SilentlyContinue
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
        return $true
    }
    catch {
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

Export-ModuleMember -Function @(
    'Connect-ACRInteractive'
    'Connect-ACRManagedIdentity'
    'Connect-ACRExchangeOnline'
    'Connect-ACRExchangeOnlineMI'
    'Test-ACRExchangeOnlineConnected'
    'Get-ACRUserContext'
    'Disconnect-ACR'
)
