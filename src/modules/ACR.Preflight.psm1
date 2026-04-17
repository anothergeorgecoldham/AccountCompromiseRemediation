<#
.SYNOPSIS
    Preflight validation for the Account Compromise Remediation toolkit.
.DESCRIPTION
    Validates the runtime environment, module versions, authentication state,
    operator permissions, and target user context BEFORE remediation runs.
    Returns a structured result with Pass/Fail/Warning per check, plus an
    overall readiness verdict. Fails fast on issues that would block execution.
#>

$script:MinPowerShellVersion = [Version]'7.2.0'

$script:RequiredModules = @(
    [PSCustomObject]@{ Name = 'Microsoft.Graph.Authentication';   MinVersion = [Version]'2.0.0'; Required = $true  }
    [PSCustomObject]@{ Name = 'Microsoft.Graph.Users';            MinVersion = [Version]'2.0.0'; Required = $true  }
    [PSCustomObject]@{ Name = 'Microsoft.Graph.Users.Actions';    MinVersion = [Version]'2.0.0'; Required = $true  }
    [PSCustomObject]@{ Name = 'Microsoft.Graph.Identity.SignIns'; MinVersion = [Version]'2.0.0'; Required = $true  }
    [PSCustomObject]@{ Name = 'Microsoft.Graph.Applications';     MinVersion = [Version]'2.0.0'; Required = $true  }
    [PSCustomObject]@{ Name = 'Microsoft.Graph.Reports';          MinVersion = [Version]'2.0.0'; Required = $true  }
    [PSCustomObject]@{ Name = 'Microsoft.Graph.DeviceManagement'; MinVersion = [Version]'2.0.0'; Required = $false }
    [PSCustomObject]@{ Name = 'ExchangeOnlineManagement';         MinVersion = [Version]'3.0.0'; Required = $true  }
    [PSCustomObject]@{ Name = 'Microsoft.PowerApps.Administration.PowerShell'; MinVersion = [Version]'2.0.0'; Required = $false }
)

$script:RequiredGraphScopes = @(
    'User.ReadWrite.All'
    'Directory.ReadWrite.All'
    'AuditLog.Read.All'
    'Application.ReadWrite.All'
    'DelegatedPermissionGrant.ReadWrite.All'
    'Policy.ReadWrite.ConditionalAccess'
    'RoleManagement.ReadWrite.Directory'
)

function New-ACRPreflightCheck {
    param(
        [Parameter(Mandatory)][string]$Name,
        [Parameter(Mandatory)][ValidateSet('Pass','Fail','Warning','Skipped')][string]$Status,
        [string]$Message = '',
        [hashtable]$Details = @{},
        [bool]$Blocking = $false
    )
    [PSCustomObject]@{
        Name      = $Name
        Status    = $Status
        Message   = $Message
        Details   = $Details
        Blocking  = $Blocking
        Timestamp = (Get-Date).ToUniversalTime()
    }
}

function Test-ACRPowerShellVersion {
    [CmdletBinding()]
    param()
    $current = $PSVersionTable.PSVersion
    if ($current -lt $script:MinPowerShellVersion) {
        return New-ACRPreflightCheck -Name 'PowerShellVersion' -Status 'Fail' -Blocking $true `
            -Message "PowerShell $current is below minimum $($script:MinPowerShellVersion)." `
            -Details @{ Current = "$current"; Minimum = "$($script:MinPowerShellVersion)" }
    }
    New-ACRPreflightCheck -Name 'PowerShellVersion' -Status 'Pass' `
        -Message "PowerShell $current OK." -Details @{ Current = "$current" }
}

function Test-ACRModuleVersions {
    [CmdletBinding()]
    param()
    $checks = @()
    foreach ($mod in $script:RequiredModules) {
        $installed = Get-Module -ListAvailable -Name $mod.Name |
            Sort-Object Version -Descending | Select-Object -First 1

        if (-not $installed) {
            $status   = if ($mod.Required) { 'Fail' } else { 'Warning' }
            $blocking = [bool]$mod.Required
            $checks += New-ACRPreflightCheck -Name "Module:$($mod.Name)" -Status $status -Blocking $blocking `
                -Message "Module '$($mod.Name)' is not installed." `
                -Details @{
                    Required       = $mod.Required
                    MinimumVersion = "$($mod.MinVersion)"
                    InstallCommand = "Install-Module $($mod.Name) -Scope CurrentUser -MinimumVersion $($mod.MinVersion)"
                }
            continue
        }

        if ($installed.Version -lt $mod.MinVersion) {
            $status   = if ($mod.Required) { 'Fail' } else { 'Warning' }
            $blocking = [bool]$mod.Required
            $checks += New-ACRPreflightCheck -Name "Module:$($mod.Name)" -Status $status -Blocking $blocking `
                -Message "Module '$($mod.Name)' $($installed.Version) is below minimum $($mod.MinVersion)." `
                -Details @{
                    Installed      = "$($installed.Version)"
                    MinimumVersion = "$($mod.MinVersion)"
                    UpgradeCommand = "Update-Module $($mod.Name) -Scope CurrentUser"
                }
            continue
        }

        $checks += New-ACRPreflightCheck -Name "Module:$($mod.Name)" -Status 'Pass' `
            -Message "$($mod.Name) $($installed.Version) OK." `
            -Details @{ Installed = "$($installed.Version)" }
    }
    return $checks
}

function Test-ACRGraphConnection {
    [CmdletBinding()]
    param(
        [string[]]$RequiredScopes = $script:RequiredGraphScopes
    )

    try {
        $context = Get-MgContext -ErrorAction Stop
    } catch {
        return New-ACRPreflightCheck -Name 'GraphConnection' -Status 'Fail' -Blocking $true `
            -Message "Not connected to Microsoft Graph. Run Connect-ACRInteractive or Connect-ACRManagedIdentity first." `
            -Details @{ Error = "$_" }
    }

    if (-not $context) {
        return New-ACRPreflightCheck -Name 'GraphConnection' -Status 'Fail' -Blocking $true `
            -Message "No active Microsoft Graph context."
    }

    $grantedScopes = @($context.Scopes)
    $missing = $RequiredScopes | Where-Object { $_ -notin $grantedScopes }

    if ($missing.Count -gt 0) {
        return New-ACRPreflightCheck -Name 'GraphConnection' -Status 'Warning' `
            -Message "Connected to Graph but missing $($missing.Count) recommended scope(s). Some actions may fail." `
            -Details @{
                TenantId      = $context.TenantId
                Account       = $context.Account
                MissingScopes = $missing
                GrantedScopes = $grantedScopes
            }
    }

    New-ACRPreflightCheck -Name 'GraphConnection' -Status 'Pass' `
        -Message "Graph connected as $($context.Account) to tenant $($context.TenantId)." `
        -Details @{
            TenantId = $context.TenantId
            Account  = $context.Account
            AuthType = "$($context.AuthType)"
        }
}

function Test-ACROperatorRoles {
    [CmdletBinding()]
    param()

    try {
        $context = Get-MgContext -ErrorAction Stop
        if (-not $context -or -not $context.Account) {
            return New-ACRPreflightCheck -Name 'OperatorRoles' -Status 'Skipped' `
                -Message 'No Graph context — cannot evaluate operator roles.'
        }

        # Managed Identity auth has no interactive account; skip role check
        if ($context.AuthType -eq 'AppOnly' -or [string]::IsNullOrWhiteSpace($context.Account)) {
            return New-ACRPreflightCheck -Name 'OperatorRoles' -Status 'Skipped' `
                -Message 'App-only / Managed Identity auth — role check skipped. Ensure MI has appropriate app roles.'
        }

        $me = Get-MgUser -UserId $context.Account -ErrorAction Stop
        $roles = Get-MgUserMemberOf -UserId $me.Id -All -ErrorAction Stop |
            Where-Object { $_.AdditionalProperties.'@odata.type' -eq '#microsoft.graph.directoryRole' }

        $roleNames = @($roles | ForEach-Object { $_.AdditionalProperties.displayName })

        $privileged = @(
            'Global Administrator', 'Security Administrator', 'User Administrator',
            'Privileged Authentication Administrator', 'Exchange Administrator',
            'Cloud Application Administrator', 'Application Administrator'
        )
        $matched = $roleNames | Where-Object { $_ -in $privileged }

        if (-not $matched -or $matched.Count -eq 0) {
            return New-ACRPreflightCheck -Name 'OperatorRoles' -Status 'Warning' `
                -Message "Operator '$($context.Account)' does not have a recognized privileged role. Many actions will likely fail." `
                -Details @{
                    Account = $context.Account
                    Roles   = $roleNames
                    Recommended = $privileged
                }
        }

        $hasExchangeAdmin = ($matched -contains 'Exchange Administrator') -or ($matched -contains 'Global Administrator')
        $status = if ($hasExchangeAdmin) { 'Pass' } else { 'Warning' }
        $msg = if ($hasExchangeAdmin) {
            "Operator has sufficient roles including Exchange admin capability."
        } else {
            "Operator has admin roles but no Exchange Administrator. Mailbox/transport actions may fail."
        }

        return New-ACRPreflightCheck -Name 'OperatorRoles' -Status $status `
            -Message $msg `
            -Details @{
                Account = $context.Account
                Roles   = $roleNames
                HasExchangeAdmin = $hasExchangeAdmin
            }
    }
    catch {
        return New-ACRPreflightCheck -Name 'OperatorRoles' -Status 'Warning' `
            -Message "Could not evaluate operator roles: $_" `
            -Details @{ Error = "$_" }
    }
}

function Test-ACRExchangeOnlineSession {
    [CmdletBinding()]
    param()

    if (-not (Get-Command Test-ACRExchangeOnlineConnected -ErrorAction SilentlyContinue)) {
        return New-ACRPreflightCheck -Name 'ExchangeOnlineSession' -Status 'Warning' `
            -Message 'Test-ACRExchangeOnlineConnected not available. EXO state cannot be verified.'
    }

    $connected = Test-ACRExchangeOnlineConnected
    if ($connected) {
        return New-ACRPreflightCheck -Name 'ExchangeOnlineSession' -Status 'Pass' `
            -Message 'Exchange Online session is active.'
    }
    New-ACRPreflightCheck -Name 'ExchangeOnlineSession' -Status 'Warning' `
        -Message 'Exchange Online is not connected. Actions 5-9 and 20 will be skipped with warnings.' `
        -Details @{ Remediation = 'Call Connect-ACRExchangeOnline (interactive) or Connect-ACRExchangeOnlineMI (automation).' }
}

function Test-ACRTargetUser {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$UserPrincipalName
    )

    try {
        $user = Get-MgUser -UserId $UserPrincipalName -Property 'Id,UserPrincipalName,DisplayName,AccountEnabled,UserType' -ErrorAction Stop
    } catch {
        return New-ACRPreflightCheck -Name 'TargetUser' -Status 'Fail' -Blocking $true `
            -Message "Target user '$UserPrincipalName' not found or inaccessible: $_" `
            -Details @{ UserPrincipalName = $UserPrincipalName; Error = "$_" }
    }

    $warnings = @()
    if ($user.UserType -eq 'Guest') {
        $warnings += 'User is a Guest account — many mailbox/license actions do not apply.'
    }
    if (-not $user.AccountEnabled) {
        $warnings += 'Account is already disabled.'
    }

    if ($warnings.Count -gt 0) {
        return New-ACRPreflightCheck -Name 'TargetUser' -Status 'Warning' `
            -Message ($warnings -join ' ') `
            -Details @{
                Id                = $user.Id
                UserPrincipalName = $user.UserPrincipalName
                DisplayName       = $user.DisplayName
                UserType          = $user.UserType
                AccountEnabled    = $user.AccountEnabled
            }
    }

    New-ACRPreflightCheck -Name 'TargetUser' -Status 'Pass' `
        -Message "Target user $($user.UserPrincipalName) ($($user.DisplayName)) exists and is enabled." `
        -Details @{
            Id                = $user.Id
            UserPrincipalName = $user.UserPrincipalName
            DisplayName       = $user.DisplayName
        }
}

function Test-ACRUnifiedAuditEnabled {
    [CmdletBinding()]
    param()

    if (-not (Get-Command Test-ACRExchangeOnlineConnected -ErrorAction SilentlyContinue) -or
        -not (Test-ACRExchangeOnlineConnected)) {
        return New-ACRPreflightCheck -Name 'UnifiedAuditLog' -Status 'Skipped' `
            -Message 'EXO not connected — cannot verify unified audit status.'
    }

    try {
        $config = Get-AdminAuditLogConfig -ErrorAction Stop
        if ($config.UnifiedAuditLogIngestionEnabled) {
            return New-ACRPreflightCheck -Name 'UnifiedAuditLog' -Status 'Pass' `
                -Message 'Unified audit log ingestion is enabled.'
        }
        return New-ACRPreflightCheck -Name 'UnifiedAuditLog' -Status 'Warning' `
            -Message 'Unified audit log ingestion is disabled at tenant level. Audit forensics will be empty.' `
            -Details @{ EnableCommand = 'Set-AdminAuditLogConfig -UnifiedAuditLogIngestionEnabled $true' }
    } catch {
        return New-ACRPreflightCheck -Name 'UnifiedAuditLog' -Status 'Warning' `
            -Message "Could not read audit log config: $_"
    }
}

function Test-ACRTargetUserLicenses {
    <#
    .SYNOPSIS
        Validates that the target user has licenses supporting the expected remediation actions.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$UserPrincipalName
    )

    try {
        $licenses = Get-MgUserLicenseDetail -UserId $UserPrincipalName -ErrorAction Stop
    } catch {
        return New-ACRPreflightCheck -Name 'TargetUserLicenses' -Status 'Warning' `
            -Message "Could not retrieve license details for ${UserPrincipalName}: $_"
    }

    if (-not $licenses -or $licenses.Count -eq 0) {
        return New-ACRPreflightCheck -Name 'TargetUserLicenses' -Status 'Warning' `
            -Message "Target user has no assigned licenses. Mailbox/audit/sign-in actions will likely return no data." `
            -Details @{ UserPrincipalName = $UserPrincipalName }
    }

    $skus = @($licenses | ForEach-Object { $_.SkuPartNumber })
    $hasExchange = $skus | Where-Object {
        $_ -match '^(SPE|SPB|ENTERPRISEPACK|STANDARDPACK|DEVELOPERPACK|EXCHANGESTANDARD|EXCHANGEENTERPRISE|M365_F)'
    }
    $hasEntraP1 = $skus | Where-Object {
        $_ -match '^(SPE|AAD_PREMIUM|EMS|EMSPREMIUM|ENTERPRISEPREMIUM|IDENTITY_THREAT_PROTECTION)'
    }

    $warnings = @()
    if (-not $hasExchange) {
        $warnings += 'No Exchange Online license detected — mailbox actions will fail.'
    }
    if (-not $hasEntraP1) {
        $warnings += 'No Entra ID P1 license detected — sign-in logs and risk data may be unavailable.'
    }

    if ($warnings.Count -gt 0) {
        return New-ACRPreflightCheck -Name 'TargetUserLicenses' -Status 'Warning' `
            -Message ($warnings -join ' ') `
            -Details @{
                UserPrincipalName = $UserPrincipalName
                AssignedSkus      = $skus
                HasExchange       = [bool]$hasExchange
                HasEntraP1        = [bool]$hasEntraP1
            }
    }

    New-ACRPreflightCheck -Name 'TargetUserLicenses' -Status 'Pass' `
        -Message "Target user has $($licenses.Count) license(s) covering Exchange + Entra ID P1." `
        -Details @{ AssignedSkus = $skus }
}

function Test-ACROperatorPimRoles {
    <#
    .SYNOPSIS
        Detects eligible-but-not-active PIM role assignments for the operator.
    .DESCRIPTION
        If the operator has privileged roles assigned via PIM that are NOT currently active,
        Get-MgUserMemberOf will not show them. This check queries the PIM eligibility
        endpoint to warn operators who may need to activate a role before proceeding.
    #>
    [CmdletBinding()]
    param()

    try {
        $context = Get-MgContext -ErrorAction Stop
        if (-not $context -or -not $context.Account -or $context.AuthType -eq 'AppOnly') {
            return New-ACRPreflightCheck -Name 'OperatorPimRoles' -Status 'Skipped' `
                -Message 'Skipped (no interactive context or app-only auth).'
        }

        $me = Get-MgUser -UserId $context.Account -ErrorAction Stop

        # Query PIM eligible role assignments for this principal
        $uri = "/v1.0/roleManagement/directory/roleEligibilityScheduleInstances?`$filter=principalId eq '$($me.Id)'"
        $resp = Invoke-MgGraphRequest -Method GET -Uri $uri -ErrorAction Stop
        $eligible = @($resp.value)

        if ($eligible.Count -eq 0) {
            return New-ACRPreflightCheck -Name 'OperatorPimRoles' -Status 'Pass' `
                -Message 'No dormant PIM-eligible roles detected for operator.'
        }

        # Get role definitions to translate IDs to names
        $roleNames = @()
        foreach ($e in $eligible) {
            try {
                $roleDef = Invoke-MgGraphRequest -Method GET `
                    -Uri "/v1.0/roleManagement/directory/roleDefinitions/$($e.roleDefinitionId)" `
                    -ErrorAction SilentlyContinue
                if ($roleDef.displayName) { $roleNames += $roleDef.displayName }
            } catch { }
        }

        return New-ACRPreflightCheck -Name 'OperatorPimRoles' -Status 'Warning' `
            -Message "Operator has $($eligible.Count) PIM-eligible role(s) that are not currently active. Activate via PIM portal if needed." `
            -Details @{
                EligibleRoles     = $roleNames
                ActivationGuide   = 'Go to https://portal.azure.com → Azure AD Privileged Identity Management → My Roles → Activate'
            }
    } catch {
        return New-ACRPreflightCheck -Name 'OperatorPimRoles' -Status 'Skipped' `
            -Message "Could not query PIM eligibility: $_ (may indicate tenant does not use PIM, or insufficient scopes)."
    }
}

function Invoke-ACRPreflight {
    <#
    .SYNOPSIS
        Runs all preflight checks and returns a consolidated result.
    .DESCRIPTION
        Validates PowerShell version, module installations, Graph + EXO connectivity,
        operator privileges, target user existence, and audit enablement. Returns a
        PSCustomObject with per-check results and an overall Ready flag.
    .PARAMETER UserPrincipalName
        Target user to validate (optional but strongly recommended).
    .PARAMETER SkipUserCheck
        Skips the target user existence check (use when running before UPN known).
    .PARAMETER SkipAuditCheck
        Skips the unified audit log enablement check (slow, requires EXO).
    .EXAMPLE
        $preflight = Invoke-ACRPreflight -UserPrincipalName 'user@contoso.com'
        if (-not $preflight.Ready) { throw 'Preflight failed — see $preflight.Checks' }
    #>
    [CmdletBinding()]
    param(
        [Parameter()][string]$UserPrincipalName,
        [switch]$SkipUserCheck,
        [switch]$SkipAuditCheck
    )

    $checks = @()

    $checks += Test-ACRPowerShellVersion
    $checks += Test-ACRModuleVersions
    $checks += Test-ACRGraphConnection
    $checks += Test-ACROperatorRoles
    $checks += Test-ACROperatorPimRoles
    $checks += Test-ACRExchangeOnlineSession

    if (-not $SkipAuditCheck) {
        $checks += Test-ACRUnifiedAuditEnabled
    }
    if ($UserPrincipalName -and -not $SkipUserCheck) {
        $checks += Test-ACRTargetUser -UserPrincipalName $UserPrincipalName
        $checks += Test-ACRTargetUserLicenses -UserPrincipalName $UserPrincipalName
    }

    $blockingFailures = @($checks | Where-Object { $_.Status -eq 'Fail' -and $_.Blocking })
    $failures         = @($checks | Where-Object { $_.Status -eq 'Fail' })
    $warnings         = @($checks | Where-Object { $_.Status -eq 'Warning' })
    $passes           = @($checks | Where-Object { $_.Status -eq 'Pass' })

    [PSCustomObject]@{
        Ready            = ($blockingFailures.Count -eq 0)
        Checks           = $checks
        PassCount        = $passes.Count
        WarningCount     = $warnings.Count
        FailCount        = $failures.Count
        BlockingFailures = $blockingFailures
        Timestamp        = (Get-Date).ToUniversalTime()
    }
}

function Format-ACRPreflightReport {
    <#
    .SYNOPSIS
        Formats the preflight result as a human-readable console report.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory, ValueFromPipeline)]$PreflightResult
    )

    $lines = @()
    $lines += ''
    $lines += '─── Preflight Results ─────────────────────────────────────────'
    foreach ($c in $PreflightResult.Checks) {
        $icon = switch ($c.Status) {
            'Pass'    { '[✓]' }
            'Fail'    { '[✗]' }
            'Warning' { '[!]' }
            'Skipped' { '[–]' }
        }
        $lines += "  $icon $($c.Name.PadRight(35)) $($c.Status.PadRight(8)) $($c.Message)"
    }
    $lines += '───────────────────────────────────────────────────────────────'
    $lines += "  Pass: $($PreflightResult.PassCount)  Warning: $($PreflightResult.WarningCount)  Fail: $($PreflightResult.FailCount)"
    $lines += "  Ready to proceed: $($PreflightResult.Ready)"
    $lines += ''
    $lines -join [Environment]::NewLine
}

Export-ModuleMember -Function @(
    'Invoke-ACRPreflight'
    'Format-ACRPreflightReport'
    'Test-ACRPowerShellVersion'
    'Test-ACRModuleVersions'
    'Test-ACRGraphConnection'
    'Test-ACROperatorRoles'
    'Test-ACROperatorPimRoles'
    'Test-ACRExchangeOnlineSession'
    'Test-ACRTargetUser'
    'Test-ACRTargetUserLicenses'
    'Test-ACRUnifiedAuditEnabled'
)
