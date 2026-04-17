#Requires -Version 7.2

<#
.SYNOPSIS
    Remediation action functions for Entra ID account compromise remediation.

.DESCRIPTION
    Contains 20 individual remediation action functions that each perform one
    specific remediation step. Each function logs via ACR.Logging (Write-ACRAction,
    Write-ACRRollbackEntry) and returns a PSCustomObject with Status, Message,
    and Details properties.

.NOTES
    Dependencies:
      - ACR.Logging.psm1 (must be loaded before this module)
      - Microsoft.Graph.* PowerShell SDK modules
      - ExchangeOnlineManagement module (for Remove-ACRExchangeRules)
      - Microsoft.PowerApps.Administration.PowerShell (for Power Platform actions 13-15)
        NOTE: This module only supports Windows PowerShell 5.1 natively.
        On PowerShell 7+, we use Import-Module -UseWindowsPowerShell to proxy
        calls through a WinPS 5.1 compatibility session (Windows only).
#>

# Default lookback window for "recently added" items
$script:LookbackDays = 7

function Import-PowerAppsModule {
    <#
    .SYNOPSIS
        Imports the PowerApps Administration module with PS 7 compatibility handling.
    .DESCRIPTION
        The Microsoft.PowerApps.Administration.PowerShell module only supports Windows
        PowerShell 5.1 natively. When running on PowerShell 7+, this function uses
        -UseWindowsPowerShell to proxy calls through a WinPS 5.1 session (Windows only).
        On non-Windows platforms running PS 7+, this will fail with a clear error.
    #>
    [CmdletBinding()]
    param()

    $moduleName = 'Microsoft.PowerApps.Administration.PowerShell'

    if (-not (Get-Module -ListAvailable -Name $moduleName)) {
        throw "$moduleName module is not installed. Install with: Install-Module $moduleName -Scope CurrentUser"
    }

    if ($PSVersionTable.PSVersion.Major -ge 7) {
        if ($IsWindows -or [System.Runtime.InteropServices.RuntimeInformation]::IsOSPlatform([System.Runtime.InteropServices.OSPlatform]::Windows)) {
            Write-Verbose "PowerShell 7+ detected. Importing $moduleName via -UseWindowsPowerShell compatibility proxy."
            Import-Module $moduleName -UseWindowsPowerShell -ErrorAction Stop -WarningAction SilentlyContinue
        }
        else {
            throw "$moduleName is not supported on non-Windows platforms with PowerShell 7+. Run the Power Platform actions from Windows PowerShell 5.1 or from a Windows host."
        }
    }
    else {
        Import-Module $moduleName -ErrorAction Stop
    }
}

function New-ACRResult {
    <#
    .SYNOPSIS
        Helper to create a standardised result object.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][ValidateSet('Success','Failed','Skipped','Warning')][string]$Status,
        [Parameter(Mandatory)][string]$Message,
        [Parameter()][object]$Details
    )
    [PSCustomObject]@{
        Status  = $Status
        Message = $Message
        Details = $Details
    }
}

function New-ACRSecurePassword {
    <#
    .SYNOPSIS
        Generates a cryptographically random password suitable for PowerShell 7+.
    #>
    [CmdletBinding()]
    param([int]$Length = 24)

    $upper  = 'ABCDEFGHJKLMNPQRSTUVWXYZ'
    $lower  = 'abcdefghjkmnpqrstuvwxyz'
    $digits = '23456789'
    $special = '!@#$%^&*()-_=+'
    $all = $upper + $lower + $digits + $special

    $bytes = [byte[]]::new($Length)
    [System.Security.Cryptography.RandomNumberGenerator]::Fill($bytes)

    $password = [char[]]::new($Length)
    # Guarantee at least one of each class in the first four positions
    $password[0] = $upper[$bytes[0] % $upper.Length]
    $password[1] = $lower[$bytes[1] % $lower.Length]
    $password[2] = $digits[$bytes[2] % $digits.Length]
    $password[3] = $special[$bytes[3] % $special.Length]

    for ($i = 4; $i -lt $Length; $i++) {
        $password[$i] = $all[$bytes[$i] % $all.Length]
    }

    # Shuffle using Fisher-Yates
    $rng = [System.Security.Cryptography.RandomNumberGenerator]::Create()
    $buf = [byte[]]::new(4)
    for ($i = $Length - 1; $i -gt 0; $i--) {
        $rng.GetBytes($buf)
        $j = [System.BitConverter]::ToUInt32($buf, 0) % ($i + 1)
        $tmp = $password[$i]; $password[$i] = $password[$j]; $password[$j] = $tmp
    }
    $rng.Dispose()

    return -join $password
}

# ---------------------------------------------------------------------------
# 1. Reset-ACRPassword
# ---------------------------------------------------------------------------
function Reset-ACRPassword {
    <#
    .SYNOPSIS
        Resets the user password to a random secure value and forces change at next login.
    .PARAMETER UserPrincipalName
        The UPN of the target user.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$UserPrincipalName
    )

    $action = 'ResetPassword'
    try {
        $newPassword = New-ACRSecurePassword

        $passwordProfile = @{
            Password                      = $newPassword
            ForceChangePasswordNextSignIn  = $true
        }

        Update-MgUser -UserId $UserPrincipalName -PasswordProfile $passwordProfile -ErrorAction Stop

        Write-ACRAction -Action $action -Status 'Success' `
            -Message "Password reset for $UserPrincipalName. User must change at next sign-in." `
            -Target $UserPrincipalName

        Write-ACRRollbackEntry -Action $action -ResourceType 'UserPassword' `
            -ResourceId $UserPrincipalName `
            -BeforeState @{ Note = 'Previous password unknown (not recorded)' } `
            -AfterState  @{ Note = 'New random password set; forceChangePasswordNextSignIn = true' } `
            -RollbackInstructions "Password cannot be rolled back. User should set a new password via self-service password reset."

        return New-ACRResult -Status 'Success' `
            -Message "Password reset successfully. Change required at next login." `
            -Details @{ ForceChange = $true }
    }
    catch {
        Write-ACRAction -Action $action -Status 'Failed' `
            -Message "Failed to reset password for ${UserPrincipalName}: $_" `
            -Target $UserPrincipalName
        return New-ACRResult -Status 'Failed' -Message "Password reset failed: $_" -Details $_.Exception
    }
}

# ---------------------------------------------------------------------------
# 2. Revoke-ACRRefreshTokens
# ---------------------------------------------------------------------------
function Revoke-ACRRefreshTokens {
    <#
    .SYNOPSIS
        Revokes all refresh tokens for the user, forcing re-authentication on every device.
    .PARAMETER UserPrincipalName
        The UPN of the target user.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$UserPrincipalName
    )

    $action = 'RevokeRefreshTokens'
    try {
        $result = Revoke-MgUserSignInSession -UserId $UserPrincipalName -ErrorAction Stop

        Write-ACRAction -Action $action -Status 'Success' `
            -Message "All refresh tokens revoked for $UserPrincipalName." `
            -Target $UserPrincipalName

        Write-ACRRollbackEntry -Action $action -ResourceType 'RefreshTokens' `
            -ResourceId $UserPrincipalName `
            -BeforeState @{ Note = 'Active refresh tokens existed' } `
            -AfterState  @{ Note = 'All refresh tokens invalidated' } `
            -RollbackInstructions "Tokens cannot be restored. User will need to re-authenticate on all devices."

        return New-ACRResult -Status 'Success' -Message 'All refresh tokens revoked.' -Details $result
    }
    catch {
        Write-ACRAction -Action $action -Status 'Failed' `
            -Message "Failed to revoke tokens for ${UserPrincipalName}: $_" `
            -Target $UserPrincipalName
        return New-ACRResult -Status 'Failed' -Message "Token revocation failed: $_" -Details $_.Exception
    }
}

# ---------------------------------------------------------------------------
# 3. Enforce-ACRMFA
# ---------------------------------------------------------------------------
function Enforce-ACRMFA {
    <#
    .SYNOPSIS
        Checks the user's MFA status and flags gaps for manual review.
    .PARAMETER UserPrincipalName
        The UPN of the target user.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$UserPrincipalName
    )

    $action = 'EnforceMFA'
    try {
        $methods = Get-MgUserAuthenticationMethod -UserId $UserPrincipalName -ErrorAction Stop

        $methodTypes = $methods | ForEach-Object {
            $_.AdditionalProperties.'@odata.type' ?? $_.GetType().Name
        }

        $hasStrongMethod = $methodTypes | Where-Object {
            $_ -match 'microsoftAuthenticator|fido2|phone|windowsHello|softwareOath'
        }

        if ($hasStrongMethod) {
            Write-ACRAction -Action $action -Status 'Success' `
                -Message "User $UserPrincipalName has strong MFA methods registered." `
                -Target $UserPrincipalName -Details @{ Methods = $methodTypes }

            Write-ACRRollbackEntry -Action $action -ResourceType 'MFAStatus' `
                -ResourceId $UserPrincipalName `
                -BeforeState @{ Methods = $methodTypes } `
                -AfterState  @{ Note = 'No changes made; MFA already configured' } `
                -RollbackInstructions 'No rollback needed — informational check only.'

            return New-ACRResult -Status 'Success' `
                -Message 'User has strong MFA methods registered.' `
                -Details @{ RegisteredMethods = $methodTypes }
        }
        else {
            Write-ACRAction -Action $action -Status 'Warning' `
                -Message "User $UserPrincipalName has NO strong MFA methods. Manual review required." `
                -Target $UserPrincipalName -Details @{ Methods = $methodTypes }

            Write-ACRRollbackEntry -Action $action -ResourceType 'MFAStatus' `
                -ResourceId $UserPrincipalName `
                -BeforeState @{ Methods = $methodTypes } `
                -AfterState  @{ Note = 'Flagged for manual MFA enrollment' } `
                -RollbackInstructions 'Ensure user registers a strong MFA method via https://aka.ms/mfasetup.'

            return New-ACRResult -Status 'Warning' `
                -Message 'No strong MFA methods found. Flag for manual enrollment.' `
                -Details @{ RegisteredMethods = $methodTypes }
        }
    }
    catch {
        Write-ACRAction -Action $action -Status 'Failed' `
            -Message "MFA check failed for ${UserPrincipalName}: $_" `
            -Target $UserPrincipalName
        return New-ACRResult -Status 'Failed' -Message "MFA check failed: $_" -Details $_.Exception
    }
}

# ---------------------------------------------------------------------------
# 4. Remove-ACRAppPasswords
# ---------------------------------------------------------------------------
function Remove-ACRAppPasswords {
    <#
    .SYNOPSIS
        Inspects authentication methods for the user and flags app passwords for manual review.
    .DESCRIPTION
        App passwords are not directly manageable via Microsoft Graph SDK cmdlets.
        This function queries the user's authentication methods via the Graph REST API,
        reports what is found, and advises manual removal through the MFA portal.
        Revoking refresh tokens (Action 2) already forces re-authentication, which
        provides equivalent protection.
    .PARAMETER UserPrincipalName
        The UPN of the target user.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$UserPrincipalName
    )

    $action = 'RemoveAppPasswords'
    try {
        $methods = Invoke-MgGraphRequest -Method GET `
            -Uri "https://graph.microsoft.com/v1.0/users/$UserPrincipalName/authentication/methods" `
            -ErrorAction Stop

        $methodTypes = @()
        if ($methods.value) {
            $methodTypes = $methods.value | ForEach-Object { $_.'@odata.type' }
        }

        Write-ACRAction -Action $action -Status 'Warning' `
            -Message "Authentication methods retrieved for $UserPrincipalName. App passwords require manual review in the MFA portal or via Revoke-MgUserSignInSession." `
            -Target $UserPrincipalName `
            -Details @{
                AuthMethods = $methodTypes
                Note        = 'App passwords are deprecated. Revoking refresh tokens (Action 2) provides similar protection.'
            }

        Write-ACRRollbackEntry -Action $action -ResourceType 'AppPassword' `
            -ResourceId $UserPrincipalName `
            -BeforeState @{ AuthMethods = $methodTypes } `
            -AfterState  @{ Note = 'Flagged for manual review' } `
            -RollbackInstructions 'No automated rollback needed. If app passwords were manually removed, user can recreate them at https://aka.ms/mfasetup.'

        return New-ACRResult -Status 'Warning' `
            -Message 'App password management requires manual review. Refresh token revocation provides equivalent protection.' `
            -Details @{
                AuthMethods  = $methodTypes
                ManualSteps  = @(
                    '1. Navigate to https://mysignins.microsoft.com/security-info'
                    '2. Review and remove any app passwords listed'
                    '3. Alternatively, use the legacy MFA portal at https://account.activedirectory.windowsazure.com/AppPasswords.aspx'
                )
            }
    }
    catch {
        Write-ACRAction -Action $action -Status 'Failed' `
            -Message "App password inspection failed for ${UserPrincipalName}: $_" `
            -Target $UserPrincipalName
        return New-ACRResult -Status 'Failed' -Message "App password inspection failed: $_" -Details $_.Exception
    }
}

# ---------------------------------------------------------------------------
# 5. Remove-ACRMailboxDelegates
# ---------------------------------------------------------------------------
function Remove-ACRMailboxDelegates {
    <#
    .SYNOPSIS
        Removes mailbox delegates (FullAccess, SendAs) for the user via Exchange Online.
    .DESCRIPTION
        Uses Get-MailboxPermission and Get-RecipientPermission to find non-inherited,
        non-self delegate permissions and removes them. Requires an active Exchange
        Online connection (Test-ACRExchangeOnlineConnected).
    .PARAMETER UserPrincipalName
        The UPN of the target user.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$UserPrincipalName
    )

    $action = 'RemoveMailboxDelegates'
    try {
        if (-not (Test-ACRExchangeOnlineConnected)) {
            Write-ACRAction -Action $action -Status 'Warning' `
                -Message "Exchange Online not connected. Cannot manage mailbox delegates for $UserPrincipalName." `
                -Target $UserPrincipalName `
                -Details @{ ManualStep = 'Connect to Exchange Online with Connect-ExchangeOnline and re-run this action.' }

            return New-ACRResult -Status 'Warning' `
                -Message 'Exchange Online not connected. Cannot manage mailbox delegates.' `
                -Details @{ ManualStep = 'Connect to Exchange Online with Connect-ExchangeOnline and re-run this action.' }
        }

        # Get non-inherited, non-self mailbox permissions (FullAccess etc.)
        $delegates = Get-MailboxPermission -Identity $UserPrincipalName -ErrorAction Stop |
            Where-Object { $_.User -ne 'NT AUTHORITY\SELF' -and $_.IsInherited -eq $false }

        # Get SendAs permissions
        $sendAs = Get-RecipientPermission -Identity $UserPrincipalName -ErrorAction Stop |
            Where-Object { $_.Trustee -ne 'NT AUTHORITY\SELF' }

        $totalCount = @($delegates).Count + @($sendAs).Count
        if ($totalCount -eq 0) {
            Write-ACRAction -Action $action -Status 'Skipped' `
                -Message "No mailbox delegates found for $UserPrincipalName." `
                -Target $UserPrincipalName

            return New-ACRResult -Status 'Skipped' -Message 'No mailbox delegates found.'
        }

        $removed = @()

        foreach ($d in $delegates) {
            try {
                Remove-MailboxPermission -Identity $UserPrincipalName `
                    -User $d.User -AccessRights $d.AccessRights `
                    -Confirm:$false -ErrorAction Stop
                $removed += @{ User = "$($d.User)"; AccessRights = ($d.AccessRights -join ','); Type = 'MailboxPermission' }
            }
            catch {
                Write-Warning "Could not remove MailboxPermission for $($d.User): $_"
            }
        }

        foreach ($s in $sendAs) {
            try {
                Remove-RecipientPermission -Identity $UserPrincipalName `
                    -Trustee $s.Trustee -AccessRights 'SendAs' `
                    -Confirm:$false -ErrorAction Stop
                $removed += @{ User = "$($s.Trustee)"; AccessRights = 'SendAs'; Type = 'RecipientPermission' }
            }
            catch {
                Write-Warning "Could not remove SendAs permission for $($s.Trustee): $_"
            }
        }

        Write-ACRAction -Action $action -Status 'Success' `
            -Message "Removed $($removed.Count) mailbox delegate(s) for $UserPrincipalName." `
            -Target $UserPrincipalName -Details @{ Removed = $removed }

        Write-ACRRollbackEntry -Action $action -ResourceType 'MailboxDelegate' `
            -ResourceId $UserPrincipalName `
            -BeforeState @{ Delegates = $removed } `
            -AfterState  @{ DelegateCount = 0 } `
            -RollbackInstructions "Re-add delegates via Add-MailboxPermission / Add-RecipientPermission using the entries recorded in BeforeState."

        return New-ACRResult -Status 'Success' `
            -Message "Removed $($removed.Count) delegate(s)." `
            -Details @{ Removed = $removed }
    }
    catch {
        Write-ACRAction -Action $action -Status 'Failed' `
            -Message "Delegate removal failed for ${UserPrincipalName}: $_" `
            -Target $UserPrincipalName
        return New-ACRResult -Status 'Failed' -Message "Delegate removal failed: $_" -Details $_.Exception
    }
}

# ---------------------------------------------------------------------------
# 6. Remove-ACRMailboxFolderPermissions
# ---------------------------------------------------------------------------
function Remove-ACRMailboxFolderPermissions {
    <#
    .SYNOPSIS
        Removes non-default permissions on key mailbox folders via Exchange Online.
    .DESCRIPTION
        Uses Get-MailboxFolderPermission and Remove-MailboxFolderPermission to remove
        non-default/non-anonymous permissions on Inbox, SentItems, Calendar, Contacts,
        and Drafts. Requires an active Exchange Online connection.
    .PARAMETER UserPrincipalName
        The UPN of the target user.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$UserPrincipalName
    )

    $action = 'RemoveMailboxFolderPermissions'
    $foldersToCheck = @('Inbox', 'SentItems', 'Calendar', 'Contacts', 'Drafts')
    try {
        if (-not (Test-ACRExchangeOnlineConnected)) {
            Write-ACRAction -Action $action -Status 'Warning' `
                -Message "Exchange Online not connected. Cannot manage mailbox folder permissions for $UserPrincipalName." `
                -Target $UserPrincipalName `
                -Details @{ ManualStep = 'Connect to Exchange Online with Connect-ExchangeOnline and re-run this action.' }

            return New-ACRResult -Status 'Warning' `
                -Message 'Exchange Online not connected. Cannot manage mailbox folder permissions.' `
                -Details @{ ManualStep = 'Connect to Exchange Online with Connect-ExchangeOnline and re-run this action.' }
        }

        $removedPermissions = @()
        $beforeState = @()

        foreach ($folderName in $foldersToCheck) {
            $folderPath = "${UserPrincipalName}:\${folderName}"
            try {
                $perms = Get-MailboxFolderPermission -Identity $folderPath -ErrorAction SilentlyContinue
                if (-not $perms) { continue }

                $nonDefault = $perms | Where-Object {
                    $_.User.DisplayName -notin @('Default', 'Anonymous')
                }

                foreach ($p in $nonDefault) {
                    $beforeState += @{
                        Folder       = $folderName
                        User         = $p.User.DisplayName
                        AccessRights = ($p.AccessRights -join ',')
                    }

                    try {
                        Remove-MailboxFolderPermission -Identity $folderPath `
                            -User $p.User.DisplayName -Confirm:$false -ErrorAction Stop
                        $removedPermissions += @{
                            Folder       = $folderName
                            User         = $p.User.DisplayName
                            AccessRights = ($p.AccessRights -join ',')
                        }
                    }
                    catch {
                        Write-Warning "Could not remove permission for $($p.User.DisplayName) on ${folderName}: $_"
                    }
                }
            }
            catch {
                Write-Verbose "Could not query permissions on folder ${folderName}: $_"
            }
        }

        if ($removedPermissions.Count -eq 0) {
            Write-ACRAction -Action $action -Status 'Skipped' `
                -Message "No non-default folder permissions found for $UserPrincipalName." `
                -Target $UserPrincipalName

            return New-ACRResult -Status 'Skipped' -Message 'No non-default folder permissions found.'
        }

        Write-ACRAction -Action $action -Status 'Success' `
            -Message "Removed $($removedPermissions.Count) folder permission(s) for $UserPrincipalName." `
            -Target $UserPrincipalName -Details @{ Removed = $removedPermissions }

        Write-ACRRollbackEntry -Action $action -ResourceType 'MailboxFolderPermission' `
            -ResourceId $UserPrincipalName `
            -BeforeState $beforeState `
            -AfterState  @{ Removed = $removedPermissions } `
            -RollbackInstructions "Re-add folder permissions via Add-MailboxFolderPermission for each entry in BeforeState."

        return New-ACRResult -Status 'Success' `
            -Message "Removed $($removedPermissions.Count) folder permission(s)." `
            -Details @{ Before = $beforeState; Removed = $removedPermissions }
    }
    catch {
        Write-ACRAction -Action $action -Status 'Failed' `
            -Message "Folder permission removal failed for ${UserPrincipalName}: $_" `
            -Target $UserPrincipalName
        return New-ACRResult -Status 'Failed' -Message "Folder permission removal failed: $_" -Details $_.Exception
    }
}

# ---------------------------------------------------------------------------
# 7. Remove-ACREmailForwarding
# ---------------------------------------------------------------------------
function Remove-ACREmailForwarding {
    <#
    .SYNOPSIS
        Removes SMTP forwarding and inbox rules that forward or redirect mail.
    .DESCRIPTION
        Uses Exchange Online cmdlets to check and clear mailbox-level SMTP forwarding
        (ForwardingSmtpAddress, ForwardingAddress) and inbox rules that forward/redirect.
        Requires an active Exchange Online connection.
    .PARAMETER UserPrincipalName
        The UPN of the target user.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$UserPrincipalName
    )

    $action = 'RemoveEmailForwarding'
    try {
        if (-not (Test-ACRExchangeOnlineConnected)) {
            Write-ACRAction -Action $action -Status 'Warning' `
                -Message "Exchange Online not connected. Cannot manage email forwarding for $UserPrincipalName." `
                -Target $UserPrincipalName `
                -Details @{ ManualStep = 'Connect to Exchange Online with Connect-ExchangeOnline and re-run this action.' }

            return New-ACRResult -Status 'Warning' `
                -Message 'Exchange Online not connected. Cannot manage email forwarding.' `
                -Details @{ ManualStep = 'Connect to Exchange Online with Connect-ExchangeOnline and re-run this action.' }
        }

        $removed = @()
        $beforeState = @()

        # --- Check SMTP forwarding on the mailbox ---
        $mailbox = Get-Mailbox -Identity $UserPrincipalName -ErrorAction Stop
        if ($mailbox.ForwardingSmtpAddress -or $mailbox.ForwardingAddress) {
            $fwdState = @{
                ForwardingSmtpAddress      = "$($mailbox.ForwardingSmtpAddress)"
                ForwardingAddress          = "$($mailbox.ForwardingAddress)"
                DeliverToMailboxAndForward  = $mailbox.DeliverToMailboxAndForward
            }
            $beforeState += @{ Type = 'MailboxForwarding'; Details = $fwdState }

            Set-Mailbox -Identity $UserPrincipalName `
                -ForwardingSmtpAddress $null `
                -ForwardingAddress $null `
                -DeliverToMailboxAndForward $false `
                -ErrorAction Stop

            $removed += @{ Type = 'MailboxForwarding'; Details = $fwdState }
        }

        # --- Check inbox rules that forward/redirect ---
        $rules = Get-InboxRule -Mailbox $UserPrincipalName -ErrorAction Stop
        $forwardRules = $rules | Where-Object {
            $_.ForwardTo -or $_.RedirectTo -or $_.ForwardAsAttachmentTo
        }

        foreach ($rule in $forwardRules) {
            $ruleState = @{
                Type                = 'InboxRule'
                Name                = $rule.Name
                RuleIdentity        = "$($rule.RuleIdentity)"
                ForwardTo           = ($rule.ForwardTo -join '; ')
                RedirectTo          = ($rule.RedirectTo -join '; ')
                ForwardAsAttachment = ($rule.ForwardAsAttachmentTo -join '; ')
            }
            $beforeState += $ruleState

            try {
                Remove-InboxRule -Mailbox $UserPrincipalName `
                    -Identity $rule.RuleIdentity `
                    -Confirm:$false -Force -ErrorAction Stop
                $removed += $ruleState
            }
            catch {
                Write-Warning "Could not remove inbox rule '$($rule.Name)': $_"
            }
        }

        if ($removed.Count -eq 0) {
            Write-ACRAction -Action $action -Status 'Skipped' `
                -Message "No email forwarding found for $UserPrincipalName." `
                -Target $UserPrincipalName

            return New-ACRResult -Status 'Skipped' -Message 'No email forwarding detected.'
        }

        Write-ACRAction -Action $action -Status 'Success' `
            -Message "Removed $($removed.Count) forwarding configuration(s) for $UserPrincipalName." `
            -Target $UserPrincipalName -Details @{ Removed = $removed }

        Write-ACRRollbackEntry -Action $action -ResourceType 'EmailForwarding' `
            -ResourceId $UserPrincipalName `
            -BeforeState $beforeState `
            -AfterState  @{ RemovedItems = $removed } `
            -RollbackInstructions "Re-add forwarding via Set-Mailbox -ForwardingSmtpAddress / New-InboxRule using the entries recorded in BeforeState."

        return New-ACRResult -Status 'Success' `
            -Message "Removed $($removed.Count) forwarding configuration(s)." `
            -Details @{ Before = $beforeState; Removed = $removed }
    }
    catch {
        Write-ACRAction -Action $action -Status 'Failed' `
            -Message "Forwarding removal failed for ${UserPrincipalName}: $_" `
            -Target $UserPrincipalName
        return New-ACRResult -Status 'Failed' -Message "Forwarding removal failed: $_" -Details $_.Exception
    }
}

# ---------------------------------------------------------------------------
# 8. Remove-ACROutlookAddins
# ---------------------------------------------------------------------------
function Remove-ACROutlookAddins {
    <#
    .SYNOPSIS
        Flags sideloaded Outlook add-ins for manual review.
    .DESCRIPTION
        Outlook user-installed add-ins are managed through the Office Store or Exchange
        Admin Center. There is no reliable programmatic removal via Microsoft Graph for
        sideloaded add-ins. This function logs a warning with manual steps for review.
        If Exchange Online is connected, attempts to list user add-ins via Get-App.
    .PARAMETER UserPrincipalName
        The UPN of the target user.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$UserPrincipalName
    )

    $action = 'RemoveOutlookAddins'
    try {
        $addinDetails = @()

        # Attempt to list user add-ins via Exchange Online if connected
        if (Test-ACRExchangeOnlineConnected) {
            try {
                $apps = Get-App -Mailbox $UserPrincipalName -OrganizationApp:$false -ErrorAction SilentlyContinue
                if ($apps) {
                    $addinDetails = $apps | ForEach-Object {
                        @{ DisplayName = $_.DisplayName; AppId = $_.AppId; Enabled = $_.Enabled }
                    }
                }
            }
            catch {
                Write-Verbose "Could not query user add-ins via Get-App: $_"
            }
        }

        Write-ACRAction -Action $action -Status 'Warning' `
            -Message "Outlook add-in inspection for $UserPrincipalName requires manual review via Exchange Admin Center (Organization > Add-ins)." `
            -Target $UserPrincipalName `
            -Details @{
                DetectedAddins = $addinDetails
                ManualSteps    = @(
                    "1. Go to Exchange Admin Center > Organization > Add-ins"
                    "2. Review user-installed add-ins for $UserPrincipalName"
                    "3. Remove any suspicious sideloaded add-ins"
                    "4. Consider using Set-App to block specific add-ins org-wide"
                )
                AlternativeCommand = "Get-App -Mailbox '$UserPrincipalName' -OrganizationApp:`$false | Remove-App"
            }

        Write-ACRRollbackEntry -Action $action -ResourceType 'OutlookAddin' `
            -ResourceId $UserPrincipalName `
            -BeforeState @{ DetectedAddins = $addinDetails } `
            -AfterState  @{ Note = 'Flagged for manual review; no automated removal performed' } `
            -RollbackInstructions 'No automated rollback needed. Re-install add-ins from the Microsoft 365 admin center if removed manually.'

        return New-ACRResult -Status 'Warning' `
            -Message 'Outlook add-in management requires manual review via Exchange Admin Center.' `
            -Details @{
                DetectedAddins     = $addinDetails
                AlternativeCommand = "Get-App -Mailbox '$UserPrincipalName' -OrganizationApp:`$false | Remove-App"
            }
    }
    catch {
        Write-ACRAction -Action $action -Status 'Failed' `
            -Message "Outlook add-in inspection failed for ${UserPrincipalName}: $_" `
            -Target $UserPrincipalName
        return New-ACRResult -Status 'Failed' -Message "Outlook add-in inspection failed: $_" -Details $_.Exception
    }
}

# ---------------------------------------------------------------------------
# 9. Remove-ACRSafeSenders
# ---------------------------------------------------------------------------
function Remove-ACRSafeSenders {
    <#
    .SYNOPSIS
        Clears the user's Safe Senders list via Exchange Online and logs previous entries.
    .DESCRIPTION
        Uses Get-MailboxJunkEmailConfiguration and Set-MailboxJunkEmailConfiguration to
        read and clear the TrustedSendersAndDomains list. Requires an active Exchange
        Online connection.
    .PARAMETER UserPrincipalName
        The UPN of the target user.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$UserPrincipalName
    )

    $action = 'RemoveSafeSenders'
    try {
        if (-not (Test-ACRExchangeOnlineConnected)) {
            Write-ACRAction -Action $action -Status 'Warning' `
                -Message "Exchange Online not connected. Cannot manage safe senders for $UserPrincipalName." `
                -Target $UserPrincipalName `
                -Details @{ ManualStep = 'Connect to Exchange Online with Connect-ExchangeOnline and re-run this action.' }

            return New-ACRResult -Status 'Warning' `
                -Message 'Exchange Online not connected. Cannot manage safe senders.' `
                -Details @{ ManualStep = 'Connect to Exchange Online with Connect-ExchangeOnline and re-run this action.' }
        }

        $junkConfig = Get-MailboxJunkEmailConfiguration -Identity $UserPrincipalName -ErrorAction Stop
        $safeSenders = $junkConfig.TrustedSendersAndDomains

        if (-not $safeSenders -or $safeSenders.Count -eq 0) {
            Write-ACRAction -Action $action -Status 'Skipped' `
                -Message "No safe senders entries found for $UserPrincipalName." `
                -Target $UserPrincipalName

            return New-ACRResult -Status 'Skipped' -Message 'No safe senders entries found.'
        }

        # Log the current list before clearing
        Write-ACRRollbackEntry -Action $action -ResourceType 'SafeSenders' `
            -ResourceId $UserPrincipalName `
            -BeforeState @{ SafeSenders = $safeSenders } `
            -AfterState  @{ SafeSenders = @() } `
            -RollbackInstructions "Restore safe senders via: Set-MailboxJunkEmailConfiguration -Identity '$UserPrincipalName' -TrustedSendersAndDomains @{Add='address'} for each entry in BeforeState."

        Set-MailboxJunkEmailConfiguration -Identity $UserPrincipalName `
            -TrustedSendersAndDomains @() -ErrorAction Stop

        Write-ACRAction -Action $action -Status 'Success' `
            -Message "Cleared $($safeSenders.Count) safe senders entry(ies) for $UserPrincipalName." `
            -Target $UserPrincipalName `
            -Details @{ ClearedEntries = $safeSenders }

        return New-ACRResult -Status 'Success' `
            -Message "Cleared $($safeSenders.Count) safe senders entry(ies)." `
            -Details @{ ClearedEntries = $safeSenders }
    }
    catch {
        Write-ACRAction -Action $action -Status 'Failed' `
            -Message "Safe senders removal failed for ${UserPrincipalName}: $_" `
            -Target $UserPrincipalName
        return New-ACRResult -Status 'Failed' -Message "Safe senders removal failed: $_" -Details $_.Exception
    }
}

# ---------------------------------------------------------------------------
# 10. Remove-ACRCalendarSharing
# ---------------------------------------------------------------------------
function Remove-ACRCalendarSharing {
    <#
    .SYNOPSIS
        Removes external calendar sharing permissions for the user.
    .PARAMETER UserPrincipalName
        The UPN of the target user.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$UserPrincipalName
    )

    $action = 'RemoveCalendarSharing'
    try {
        $calendars = Get-MgUserCalendar -UserId $UserPrincipalName -All -ErrorAction Stop
        $defaultCalendar = $calendars | Where-Object { $_.IsDefaultCalendar -eq $true } | Select-Object -First 1
        if (-not $defaultCalendar) { $defaultCalendar = $calendars | Select-Object -First 1 }

        if (-not $defaultCalendar) {
            Write-ACRAction -Action $action -Status 'Skipped' `
                -Message "No calendars found for $UserPrincipalName." `
                -Target $UserPrincipalName
            return New-ACRResult -Status 'Skipped' -Message 'No calendars found.'
        }

        $permissions = Get-MgUserCalendarPermission -UserId $UserPrincipalName `
            -CalendarId $defaultCalendar.Id -All -ErrorAction Stop

        $externalPerms = $permissions | Where-Object {
            $_.EmailAddress.Address -and $_.Role -ne 'none' -and $_.IsRemovable -eq $true
        }

        if (-not $externalPerms -or $externalPerms.Count -eq 0) {
            Write-ACRAction -Action $action -Status 'Skipped' `
                -Message "No removable calendar sharing permissions found for $UserPrincipalName." `
                -Target $UserPrincipalName
            return New-ACRResult -Status 'Skipped' -Message 'No external calendar sharing found.'
        }

        $beforeState = $externalPerms | ForEach-Object {
            @{ Email = $_.EmailAddress.Address; Role = $_.Role; PermId = $_.Id }
        }

        $removed = @()
        foreach ($perm in $externalPerms) {
            try {
                Remove-MgUserCalendarPermission -UserId $UserPrincipalName `
                    -CalendarId $defaultCalendar.Id -CalendarPermissionId $perm.Id -ErrorAction Stop
                $removed += $perm.EmailAddress.Address
            }
            catch {
                Write-Warning "Could not remove calendar permission $($perm.Id): $_"
            }
        }

        Write-ACRAction -Action $action -Status 'Success' `
            -Message "Removed $($removed.Count) calendar sharing permission(s) for $UserPrincipalName." `
            -Target $UserPrincipalName -Details @{ Removed = $removed }

        Write-ACRRollbackEntry -Action $action -ResourceType 'CalendarSharing' `
            -ResourceId $UserPrincipalName `
            -BeforeState $beforeState `
            -AfterState  @{ RemovedShares = $removed } `
            -RollbackInstructions "Re-share the calendar via Outlook or New-MgUserCalendarPermission using the recorded email addresses and roles."

        return New-ACRResult -Status 'Success' `
            -Message "Removed $($removed.Count) calendar sharing permission(s)." `
            -Details @{ Before = $beforeState; Removed = $removed }
    }
    catch {
        Write-ACRAction -Action $action -Status 'Failed' `
            -Message "Calendar sharing removal failed for ${UserPrincipalName}: $_" `
            -Target $UserPrincipalName
        return New-ACRResult -Status 'Failed' -Message "Calendar sharing removal failed: $_" -Details $_.Exception
    }
}

# ---------------------------------------------------------------------------
# 11. Remove-ACRMobileDevices
# ---------------------------------------------------------------------------
function Remove-ACRMobileDevices {
    <#
    .SYNOPSIS
        Removes recently registered/synced mobile devices for the user.
    .PARAMETER UserPrincipalName
        The UPN of the target user.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$UserPrincipalName
    )

    $action = 'RemoveMobileDevices'
    try {
        $cutoff = (Get-Date).AddDays(-$script:LookbackDays).ToUniversalTime()

        $devices = Get-MgUserManagedDevice -UserId $UserPrincipalName -All -ErrorAction Stop

        $recentDevices = $devices | Where-Object {
            $_.EnrolledDateTime -and $_.EnrolledDateTime -gt $cutoff
        }

        if (-not $recentDevices -or $recentDevices.Count -eq 0) {
            Write-ACRAction -Action $action -Status 'Skipped' `
                -Message "No recently registered devices found for $UserPrincipalName (last $($script:LookbackDays) days)." `
                -Target $UserPrincipalName
            return New-ACRResult -Status 'Skipped' -Message "No devices registered in the last $($script:LookbackDays) days."
        }

        $beforeState = $recentDevices | ForEach-Object {
            @{
                DeviceId     = $_.Id
                DeviceName   = $_.DeviceName
                OS           = $_.OperatingSystem
                EnrolledDate = $_.EnrolledDateTime
                Model        = $_.Model
            }
        }

        $removed = @()
        foreach ($device in $recentDevices) {
            try {
                Remove-MgUserManagedDevice -UserId $UserPrincipalName `
                    -ManagedDeviceId $device.Id -ErrorAction Stop
                $removed += "$($device.DeviceName) ($($device.OperatingSystem))"
            }
            catch {
                Write-Warning "Could not remove device $($device.Id): $_"
            }
        }

        Write-ACRAction -Action $action -Status 'Success' `
            -Message "Removed $($removed.Count) recently registered device(s) for $UserPrincipalName." `
            -Target $UserPrincipalName -Details @{ Removed = $removed }

        Write-ACRRollbackEntry -Action $action -ResourceType 'MobileDevice' `
            -ResourceId $UserPrincipalName `
            -BeforeState $beforeState `
            -AfterState  @{ RemovedDevices = $removed } `
            -RollbackInstructions "User must re-enrol devices via Company Portal or Intune. Device details are recorded in BeforeState."

        return New-ACRResult -Status 'Success' `
            -Message "Removed $($removed.Count) recently registered device(s)." `
            -Details @{ Before = $beforeState; Removed = $removed }
    }
    catch {
        Write-ACRAction -Action $action -Status 'Failed' `
            -Message "Mobile device removal failed for ${UserPrincipalName}: $_" `
            -Target $UserPrincipalName
        return New-ACRResult -Status 'Failed' -Message "Mobile device removal failed: $_" -Details $_.Exception
    }
}

# ---------------------------------------------------------------------------
# 12. Remove-ACRUserConsentApps
# ---------------------------------------------------------------------------
function Remove-ACRUserConsentApps {
    <#
    .SYNOPSIS
        Removes user-consented OAuth2 permission grants added in the lookback window.
    .PARAMETER UserPrincipalName
        The UPN of the target user.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$UserPrincipalName
    )

    $action = 'RemoveUserConsentApps'
    try {
        $grants = Get-MgUserOauth2PermissionGrant -UserId $UserPrincipalName -All -ErrorAction Stop

        if (-not $grants -or $grants.Count -eq 0) {
            Write-ACRAction -Action $action -Status 'Skipped' `
                -Message "No user-consented OAuth2 grants found for $UserPrincipalName." `
                -Target $UserPrincipalName
            return New-ACRResult -Status 'Skipped' -Message 'No user-consented apps found.'
        }

        $beforeState = $grants | ForEach-Object {
            @{
                GrantId   = $_.Id
                ClientId  = $_.ClientId
                Scope     = $_.Scope
                ConsentType = $_.ConsentType
            }
        }

        $removed = @()
        foreach ($grant in $grants) {
            try {
                Remove-MgOauth2PermissionGrant -OAuth2PermissionGrantId $grant.Id -ErrorAction Stop
                $removed += @{ GrantId = $grant.Id; ClientId = $grant.ClientId; Scope = $grant.Scope }
            }
            catch {
                Write-Warning "Could not remove OAuth2 grant $($grant.Id): $_"
            }
        }

        Write-ACRAction -Action $action -Status 'Success' `
            -Message "Removed $($removed.Count) user-consented OAuth2 grant(s) for $UserPrincipalName." `
            -Target $UserPrincipalName -Details @{ RemovedCount = $removed.Count }

        Write-ACRRollbackEntry -Action $action -ResourceType 'OAuth2PermissionGrant' `
            -ResourceId $UserPrincipalName `
            -BeforeState $beforeState `
            -AfterState  @{ RemovedGrants = $removed } `
            -RollbackInstructions "Re-grant consent via New-MgOauth2PermissionGrant using the ClientId and Scope values recorded in BeforeState."

        return New-ACRResult -Status 'Success' `
            -Message "Removed $($removed.Count) user-consented app grant(s)." `
            -Details @{ Before = $beforeState; Removed = $removed }
    }
    catch {
        Write-ACRAction -Action $action -Status 'Failed' `
            -Message "User consent app removal failed for ${UserPrincipalName}: $_" `
            -Target $UserPrincipalName
        return New-ACRResult -Status 'Failed' -Message "User consent app removal failed: $_" -Details $_.Exception
    }
}

# ---------------------------------------------------------------------------
# 13. Remove-ACRPowerAutomateFlows
# ---------------------------------------------------------------------------
function Remove-ACRPowerAutomateFlows {
    <#
    .SYNOPSIS
        Removes Power Automate flows created by the compromised user within the lookback window.
    .DESCRIPTION
        Uses the Microsoft.PowerApps.Administration.PowerShell module to enumerate and remove
        flows owned by the target user that were created recently. Falls back to manual guidance
        if the module is not installed.
    .PARAMETER UserPrincipalName
        The UPN of the target user.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$UserPrincipalName
    )

    $action = 'RemovePowerAutomateFlows'
    $cutoff = (Get-Date).AddDays(-$script:LookbackDays).ToUniversalTime()

    # Check for the Power Platform admin module
    if (-not (Get-Module -ListAvailable -Name 'Microsoft.PowerApps.Administration.PowerShell')) {
        Write-ACRAction -Action $action -Status 'Warning' `
            -Message "Microsoft.PowerApps.Administration.PowerShell module is not installed. Cannot automate flow removal for $UserPrincipalName." `
            -Target $UserPrincipalName `
            -Details @{ InstallCommand = 'Install-Module Microsoft.PowerApps.Administration.PowerShell -Scope CurrentUser' }

        Write-ACRRollbackEntry -Action $action -ResourceType 'PowerAutomateFlow' `
            -ResourceId $UserPrincipalName `
            -BeforeState @{ Note = 'Module not available — could not inspect flows' } `
            -AfterState  @{ Note = 'Flagged for manual review' } `
            -RollbackInstructions "Install Microsoft.PowerApps.Administration.PowerShell and review flows manually."

        return New-ACRResult -Status 'Warning' `
            -Message 'PowerApps admin module not installed. Manual review required.' `
            -Details @{
                InstallCommand = 'Install-Module Microsoft.PowerApps.Administration.PowerShell -Scope CurrentUser'
                ManualSteps = @(
                    "1. Install-Module Microsoft.PowerApps.Administration.PowerShell"
                    "2. Add-PowerAppsAccount"
                    "3. Get-AdminFlow | Where-Object { `$_.CreatedBy.userId -eq '<userId>' -and `$_.CreatedTime -gt '$($cutoff.ToString('o'))' }"
                    "4. Remove-AdminFlow -FlowName <flowId> -EnvironmentName <env>"
                )
            }
    }

    try {
        Import-PowerAppsModule

        # Get all environments
        $environments = Get-AdminPowerAppEnvironment -ErrorAction Stop

        $removedFlows = @()
        foreach ($env in $environments) {
            $flows = Get-AdminFlow -EnvironmentName $env.EnvironmentName -ErrorAction SilentlyContinue
            if (-not $flows) { continue }

            # Filter flows owned by the target user and created within the lookback window
            $suspiciousFlows = $flows | Where-Object {
                $_.CreatedBy.userPrincipalName -eq $UserPrincipalName -and
                [datetime]$_.CreatedTime -gt $cutoff
            }

            foreach ($flow in $suspiciousFlows) {
                try {
                    Remove-AdminFlow -FlowName $flow.FlowName -EnvironmentName $env.EnvironmentName -ErrorAction Stop
                    $removedFlows += @{
                        FlowName      = $flow.FlowName
                        DisplayName   = $flow.DisplayName
                        Environment   = $env.EnvironmentName
                        CreatedTime   = $flow.CreatedTime
                    }
                }
                catch {
                    Write-Warning "Failed to remove flow $($flow.DisplayName): $_"
                }
            }
        }

        if ($removedFlows.Count -eq 0) {
            Write-ACRAction -Action $action -Status 'Skipped' `
                -Message "No recently created Power Automate flows found for $UserPrincipalName (last $($script:LookbackDays) days)." `
                -Target $UserPrincipalName
            return New-ACRResult -Status 'Skipped' -Message "No flows found in the last $($script:LookbackDays) days."
        }

        Write-ACRAction -Action $action -Status 'Success' `
            -Message "Removed $($removedFlows.Count) Power Automate flow(s) for $UserPrincipalName." `
            -Target $UserPrincipalName `
            -Details @{ RemovedFlows = $removedFlows }

        Write-ACRRollbackEntry -Action $action -ResourceType 'PowerAutomateFlow' `
            -ResourceId $UserPrincipalName `
            -BeforeState @{ Flows = $removedFlows } `
            -AfterState  @{ Note = 'Flows removed' } `
            -RollbackInstructions "Re-create flows using the flow names and environment names recorded in BeforeState, or restore from Power Automate version history."

        return New-ACRResult -Status 'Success' `
            -Message "Removed $($removedFlows.Count) flow(s)." `
            -Details @{ RemovedFlows = $removedFlows }
    }
    catch {
        Write-ACRAction -Action $action -Status 'Failed' `
            -Message "Failed to process Power Automate flows for ${UserPrincipalName}: $_" `
            -Target $UserPrincipalName
        return New-ACRResult -Status 'Failed' -Message "Flow removal failed: $_" -Details $_.Exception
    }
}

# ---------------------------------------------------------------------------
# 14. Remove-ACRPowerApps
# ---------------------------------------------------------------------------
function Remove-ACRPowerApps {
    <#
    .SYNOPSIS
        Removes Power Apps created by the compromised user within the lookback window.
    .DESCRIPTION
        Uses the Microsoft.PowerApps.Administration.PowerShell module to enumerate and remove
        Power Apps owned by the target user that were created recently. Falls back to manual
        guidance if the module is not installed.
    .PARAMETER UserPrincipalName
        The UPN of the target user.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$UserPrincipalName
    )

    $action = 'RemovePowerApps'
    $cutoff = (Get-Date).AddDays(-$script:LookbackDays).ToUniversalTime()

    if (-not (Get-Module -ListAvailable -Name 'Microsoft.PowerApps.Administration.PowerShell')) {
        Write-ACRAction -Action $action -Status 'Warning' `
            -Message "Microsoft.PowerApps.Administration.PowerShell module is not installed. Cannot automate Power Apps removal for $UserPrincipalName." `
            -Target $UserPrincipalName `
            -Details @{ InstallCommand = 'Install-Module Microsoft.PowerApps.Administration.PowerShell -Scope CurrentUser' }

        Write-ACRRollbackEntry -Action $action -ResourceType 'PowerApp' `
            -ResourceId $UserPrincipalName `
            -BeforeState @{ Note = 'Module not available — could not inspect apps' } `
            -AfterState  @{ Note = 'Flagged for manual review' } `
            -RollbackInstructions "Install Microsoft.PowerApps.Administration.PowerShell and review Power Apps manually."

        return New-ACRResult -Status 'Warning' `
            -Message 'PowerApps admin module not installed. Manual review required.' `
            -Details @{
                InstallCommand = 'Install-Module Microsoft.PowerApps.Administration.PowerShell -Scope CurrentUser'
                ManualSteps = @(
                    "1. Install-Module Microsoft.PowerApps.Administration.PowerShell"
                    "2. Add-PowerAppsAccount"
                    "3. Get-AdminPowerApp | Where-Object { `$_.Owner.userPrincipalName -eq '$UserPrincipalName' -and `$_.CreatedTime -gt '$($cutoff.ToString('o'))' }"
                    "4. Remove-AdminPowerApp -AppName <appId> -EnvironmentName <env>"
                )
            }
    }

    try {
        Import-PowerAppsModule

        $environments = Get-AdminPowerAppEnvironment -ErrorAction Stop

        $removedApps = @()
        foreach ($env in $environments) {
            $apps = Get-AdminPowerApp -EnvironmentName $env.EnvironmentName -ErrorAction SilentlyContinue
            if (-not $apps) { continue }

            $suspiciousApps = $apps | Where-Object {
                $_.Owner.userPrincipalName -eq $UserPrincipalName -and
                [datetime]$_.CreatedTime -gt $cutoff
            }

            foreach ($app in $suspiciousApps) {
                try {
                    Remove-AdminPowerApp -AppName $app.AppName -EnvironmentName $env.EnvironmentName -ErrorAction Stop
                    $removedApps += @{
                        AppName       = $app.AppName
                        DisplayName   = $app.DisplayName
                        Environment   = $env.EnvironmentName
                        CreatedTime   = $app.CreatedTime
                    }
                }
                catch {
                    Write-Warning "Failed to remove Power App $($app.DisplayName): $_"
                }
            }
        }

        if ($removedApps.Count -eq 0) {
            Write-ACRAction -Action $action -Status 'Skipped' `
                -Message "No recently created Power Apps found for $UserPrincipalName (last $($script:LookbackDays) days)." `
                -Target $UserPrincipalName
            return New-ACRResult -Status 'Skipped' -Message "No Power Apps found in the last $($script:LookbackDays) days."
        }

        Write-ACRAction -Action $action -Status 'Success' `
            -Message "Removed $($removedApps.Count) Power App(s) for $UserPrincipalName." `
            -Target $UserPrincipalName `
            -Details @{ RemovedApps = $removedApps }

        Write-ACRRollbackEntry -Action $action -ResourceType 'PowerApp' `
            -ResourceId $UserPrincipalName `
            -BeforeState @{ Apps = $removedApps } `
            -AfterState  @{ Note = 'Apps removed' } `
            -RollbackInstructions "Power Apps cannot be restored once deleted. Re-create manually using the app names recorded in BeforeState."

        return New-ACRResult -Status 'Success' `
            -Message "Removed $($removedApps.Count) Power App(s)." `
            -Details @{ RemovedApps = $removedApps }
    }
    catch {
        Write-ACRAction -Action $action -Status 'Failed' `
            -Message "Failed to process Power Apps for ${UserPrincipalName}: $_" `
            -Target $UserPrincipalName
        return New-ACRResult -Status 'Failed' -Message "Power Apps removal failed: $_" -Details $_.Exception
    }
}

# ---------------------------------------------------------------------------
# 15. Remove-ACRPowerAppsSharing
# ---------------------------------------------------------------------------
function Remove-ACRPowerAppsSharing {
    <#
    .SYNOPSIS
        Removes sharing/role assignments on Power Apps owned by the compromised user.
    .DESCRIPTION
        Uses the Microsoft.PowerApps.Administration.PowerShell module to enumerate Power Apps
        owned by the target user and remove non-owner role assignments that were added recently.
        Falls back to manual guidance if the module is not installed.
    .PARAMETER UserPrincipalName
        The UPN of the target user.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$UserPrincipalName
    )

    $action = 'RemovePowerAppsSharing'
    $cutoff = (Get-Date).AddDays(-$script:LookbackDays).ToUniversalTime()

    if (-not (Get-Module -ListAvailable -Name 'Microsoft.PowerApps.Administration.PowerShell')) {
        Write-ACRAction -Action $action -Status 'Warning' `
            -Message "Microsoft.PowerApps.Administration.PowerShell module is not installed. Cannot automate Power Apps sharing removal for $UserPrincipalName." `
            -Target $UserPrincipalName `
            -Details @{ InstallCommand = 'Install-Module Microsoft.PowerApps.Administration.PowerShell -Scope CurrentUser' }

        Write-ACRRollbackEntry -Action $action -ResourceType 'PowerAppSharing' `
            -ResourceId $UserPrincipalName `
            -BeforeState @{ Note = 'Module not available — could not inspect sharing' } `
            -AfterState  @{ Note = 'Flagged for manual review' } `
            -RollbackInstructions "Install Microsoft.PowerApps.Administration.PowerShell and review Power Apps sharing manually."

        return New-ACRResult -Status 'Warning' `
            -Message 'PowerApps admin module not installed. Manual review required.' `
            -Details @{
                InstallCommand = 'Install-Module Microsoft.PowerApps.Administration.PowerShell -Scope CurrentUser'
                ManualSteps = @(
                    "1. Install-Module Microsoft.PowerApps.Administration.PowerShell"
                    "2. Add-PowerAppsAccount"
                    "3. Get-AdminPowerApp | Where-Object { `$_.Owner.userPrincipalName -eq '$UserPrincipalName' }"
                    "4. For each app: Get-AdminPowerAppRoleAssignment -AppName <appId> -EnvironmentName <env>"
                    "5. Remove-AdminPowerAppRoleAssignment -RoleId <roleId> -AppName <appId> -EnvironmentName <env>"
                )
            }
    }

    try {
        Import-PowerAppsModule

        $environments = Get-AdminPowerAppEnvironment -ErrorAction Stop

        $removedShares = @()
        foreach ($env in $environments) {
            $apps = Get-AdminPowerApp -EnvironmentName $env.EnvironmentName -ErrorAction SilentlyContinue
            if (-not $apps) { continue }

            # Get apps owned by the compromised user
            $userApps = $apps | Where-Object {
                $_.Owner.userPrincipalName -eq $UserPrincipalName
            }

            foreach ($app in $userApps) {
                $roleAssignments = Get-AdminPowerAppRoleAssignment -AppName $app.AppName -EnvironmentName $env.EnvironmentName -ErrorAction SilentlyContinue
                if (-not $roleAssignments) { continue }

                # Remove non-owner role assignments (shares added to the app)
                $sharesToRemove = $roleAssignments | Where-Object {
                    $_.RoleType -ne 'Owner' -and
                    $_.PrincipalType -ne 'Tenant'
                }

                foreach ($share in $sharesToRemove) {
                    try {
                        Remove-AdminPowerAppRoleAssignment -RoleId $share.RoleId `
                            -AppName $app.AppName `
                            -EnvironmentName $env.EnvironmentName -ErrorAction Stop

                        $removedShares += @{
                            AppName         = $app.AppName
                            AppDisplayName  = $app.DisplayName
                            Environment     = $env.EnvironmentName
                            PrincipalId     = $share.PrincipalObjectId
                            PrincipalType   = $share.PrincipalType
                            RoleType        = $share.RoleType
                        }
                    }
                    catch {
                        Write-Warning "Failed to remove sharing on app $($app.DisplayName): $_"
                    }
                }
            }
        }

        if ($removedShares.Count -eq 0) {
            Write-ACRAction -Action $action -Status 'Skipped' `
                -Message "No Power Apps sharing entries found to remove for $UserPrincipalName." `
                -Target $UserPrincipalName
            return New-ACRResult -Status 'Skipped' -Message "No Power Apps sharing entries to remove."
        }

        Write-ACRAction -Action $action -Status 'Success' `
            -Message "Removed $($removedShares.Count) Power Apps sharing assignment(s) for $UserPrincipalName." `
            -Target $UserPrincipalName `
            -Details @{ RemovedShares = $removedShares }

        Write-ACRRollbackEntry -Action $action -ResourceType 'PowerAppSharing' `
            -ResourceId $UserPrincipalName `
            -BeforeState @{ Shares = $removedShares } `
            -AfterState  @{ Note = 'Sharing assignments removed' } `
            -RollbackInstructions "Re-share apps using Set-AdminPowerAppRoleAssignment with the app names, principal IDs, and role types recorded in BeforeState."

        return New-ACRResult -Status 'Success' `
            -Message "Removed $($removedShares.Count) sharing assignment(s)." `
            -Details @{ RemovedShares = $removedShares }
    }
    catch {
        Write-ACRAction -Action $action -Status 'Failed' `
            -Message "Failed to process Power Apps sharing for ${UserPrincipalName}: $_" `
            -Target $UserPrincipalName
        return New-ACRResult -Status 'Failed' -Message "Power Apps sharing removal failed: $_" -Details $_.Exception
    }
}

# ---------------------------------------------------------------------------
# 16. Remove-ACRSharePointSharingLinks
# ---------------------------------------------------------------------------
function Remove-ACRSharePointSharingLinks {
    <#
    .SYNOPSIS
        Removes recently created sharing links from the user's OneDrive/SharePoint files.
    .PARAMETER UserPrincipalName
        The UPN of the target user.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$UserPrincipalName
    )

    $action = 'RemoveSharePointSharingLinks'
    try {
        $cutoff = (Get-Date).AddDays(-$script:LookbackDays).ToUniversalTime().ToString('o')

        # Get user's default drive (OneDrive)
        $drive = Get-MgUserDrive -UserId $UserPrincipalName -ErrorAction Stop

        # Get recently modified items that may have sharing links
        $recentItems = Get-MgUserDriveItem -UserId $UserPrincipalName `
            -DriveId $drive.Id -All -ErrorAction Stop |
            Where-Object { $_.LastModifiedDateTime -gt $cutoff }

        if (-not $recentItems -or $recentItems.Count -eq 0) {
            Write-ACRAction -Action $action -Status 'Skipped' `
                -Message "No recently modified OneDrive items found for $UserPrincipalName." `
                -Target $UserPrincipalName
            return New-ACRResult -Status 'Skipped' -Message 'No recently modified items found.'
        }

        $beforeState = @()
        $removed = @()

        foreach ($item in $recentItems) {
            try {
                $permissions = Get-MgUserDriveItemPermission -UserId $UserPrincipalName `
                    -DriveId $drive.Id -DriveItemId $item.Id -All -ErrorAction Stop

                $sharingLinks = $permissions | Where-Object { $_.Link }

                foreach ($perm in $sharingLinks) {
                    $beforeState += @{
                        ItemName = $item.Name
                        ItemId   = $item.Id
                        PermId   = $perm.Id
                        LinkType = $perm.Link.Type
                        Scope    = $perm.Link.Scope
                    }

                    try {
                        Remove-MgUserDriveItemPermission -UserId $UserPrincipalName `
                            -DriveId $drive.Id -DriveItemId $item.Id `
                            -PermissionId $perm.Id -ErrorAction Stop
                        $removed += "$($item.Name) [$($perm.Link.Type)]"
                    }
                    catch {
                        Write-Warning "Could not remove sharing link $($perm.Id) on $($item.Name): $_"
                    }
                }
            }
            catch {
                Write-Verbose "Could not query permissions for item $($item.Name): $_"
            }
        }

        if ($removed.Count -eq 0) {
            Write-ACRAction -Action $action -Status 'Skipped' `
                -Message "No sharing links found on recently modified items for $UserPrincipalName." `
                -Target $UserPrincipalName
            return New-ACRResult -Status 'Skipped' -Message 'No sharing links found on recent items.'
        }

        Write-ACRAction -Action $action -Status 'Success' `
            -Message "Removed $($removed.Count) sharing link(s) for $UserPrincipalName." `
            -Target $UserPrincipalName -Details @{ Removed = $removed }

        Write-ACRRollbackEntry -Action $action -ResourceType 'SharePointSharingLink' `
            -ResourceId $UserPrincipalName `
            -BeforeState $beforeState `
            -AfterState  @{ RemovedLinks = $removed } `
            -RollbackInstructions "Re-create sharing links via OneDrive web UI or Invoke-MgInviteDriveItem for each item recorded in BeforeState."

        return New-ACRResult -Status 'Success' `
            -Message "Removed $($removed.Count) sharing link(s)." `
            -Details @{ Before = $beforeState; Removed = $removed }
    }
    catch {
        Write-ACRAction -Action $action -Status 'Failed' `
            -Message "SharePoint sharing link removal failed for ${UserPrincipalName}: $_" `
            -Target $UserPrincipalName
        return New-ACRResult -Status 'Failed' -Message "Sharing link removal failed: $_" -Details $_.Exception
    }
}

# ---------------------------------------------------------------------------
# 17. Remove-ACRTeamsGuests
# ---------------------------------------------------------------------------
function Remove-ACRTeamsGuests {
    <#
    .SYNOPSIS
        Removes guest members recently added to groups/teams owned or managed by the user.
    .PARAMETER UserPrincipalName
        The UPN of the target user.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$UserPrincipalName
    )

    $action = 'RemoveTeamsGuests'
    try {
        $cutoff = (Get-Date).AddDays(-$script:LookbackDays).ToUniversalTime()

        # Get groups the user owns
        $ownedGroups = Get-MgUserOwnedObject -UserId $UserPrincipalName -All -ErrorAction Stop |
            Where-Object { $_.AdditionalProperties.'@odata.type' -eq '#microsoft.graph.group' }

        if (-not $ownedGroups -or $ownedGroups.Count -eq 0) {
            Write-ACRAction -Action $action -Status 'Skipped' `
                -Message "User $UserPrincipalName does not own any groups." `
                -Target $UserPrincipalName
            return New-ACRResult -Status 'Skipped' -Message 'User does not own any groups.'
        }

        $beforeState = @()
        $removed = @()

        foreach ($group in $ownedGroups) {
            $groupId = $group.Id
            try {
                $members = Get-MgGroupMember -GroupId $groupId -All -ErrorAction Stop

                $guestMembers = $members | Where-Object {
                    $_.AdditionalProperties.userType -eq 'Guest'
                }

                foreach ($guest in $guestMembers) {
                    # Check if guest was added recently by examining createdDateTime
                    $guestUser = $null
                    try {
                        $guestUser = Get-MgUser -UserId $guest.Id -Property 'createdDateTime,userPrincipalName,displayName' -ErrorAction Stop
                    }
                    catch { continue }

                    if ($guestUser.CreatedDateTime -and $guestUser.CreatedDateTime -gt $cutoff) {
                        $beforeState += @{
                            GroupId   = $groupId
                            GroupName = $group.AdditionalProperties.displayName
                            GuestUPN  = $guestUser.UserPrincipalName
                            GuestName = $guestUser.DisplayName
                            Created   = $guestUser.CreatedDateTime
                        }

                        try {
                            Remove-MgGroupMemberByRef -GroupId $groupId `
                                -DirectoryObjectId $guest.Id -ErrorAction Stop
                            $removed += "$($guestUser.UserPrincipalName) from $($group.AdditionalProperties.displayName)"
                        }
                        catch {
                            Write-Warning "Could not remove guest $($guest.Id) from group ${groupId}: $_"
                        }
                    }
                }
            }
            catch {
                Write-Verbose "Could not enumerate members of group ${groupId}: $_"
            }
        }

        if ($removed.Count -eq 0) {
            Write-ACRAction -Action $action -Status 'Skipped' `
                -Message "No recently added guest members found in groups owned by $UserPrincipalName." `
                -Target $UserPrincipalName
            return New-ACRResult -Status 'Skipped' -Message "No recently added guests found (last $($script:LookbackDays) days)."
        }

        Write-ACRAction -Action $action -Status 'Success' `
            -Message "Removed $($removed.Count) recently added guest(s) from groups owned by $UserPrincipalName." `
            -Target $UserPrincipalName -Details @{ Removed = $removed }

        Write-ACRRollbackEntry -Action $action -ResourceType 'TeamsGuest' `
            -ResourceId $UserPrincipalName `
            -BeforeState $beforeState `
            -AfterState  @{ RemovedGuests = $removed } `
            -RollbackInstructions "Re-invite guests via New-MgGroupMember or Teams admin center using the UPNs and group names in BeforeState."

        return New-ACRResult -Status 'Success' `
            -Message "Removed $($removed.Count) recently added guest(s)." `
            -Details @{ Before = $beforeState; Removed = $removed }
    }
    catch {
        Write-ACRAction -Action $action -Status 'Failed' `
            -Message "Teams guest removal failed for ${UserPrincipalName}: $_" `
            -Target $UserPrincipalName
        return New-ACRResult -Status 'Failed' -Message "Teams guest removal failed: $_" -Details $_.Exception
    }
}

# ---------------------------------------------------------------------------
# 18. Remove-ACRAdminConsentApps (Admin-Only)
# ---------------------------------------------------------------------------
function Remove-ACRAdminConsentApps {
    <#
    .SYNOPSIS
        Removes recently admin-consented enterprise application grants. Requires admin role.
    .PARAMETER UserId
        The object ID or UPN of the admin user to check.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$UserId
    )

    $action = 'RemoveAdminConsentApps'
    try {
        # Verify the user has an admin role
        $roles = Get-MgUserMemberOf -UserId $UserId -All -ErrorAction Stop |
            Where-Object { $_.AdditionalProperties.'@odata.type' -eq '#microsoft.graph.directoryRole' }

        $isAdmin = $roles | Where-Object {
            $_.AdditionalProperties.displayName -match 'Admin|Administrator'
        }

        if (-not $isAdmin) {
            Write-ACRAction -Action $action -Status 'Skipped' `
                -Message "User $UserId does not hold an admin role. Skipping admin consent review." `
                -Target $UserId
            return New-ACRResult -Status 'Skipped' -Message 'User is not an admin. Admin consent review not applicable.'
        }

        $cutoff = (Get-Date).AddDays(-$script:LookbackDays).ToUniversalTime().ToString('o')

        # Get all admin (tenant-wide) consent grants
        $allGrants = Get-MgOauth2PermissionGrant -All -ErrorAction Stop |
            Where-Object { $_.ConsentType -eq 'AllPrincipals' }

        if (-not $allGrants -or $allGrants.Count -eq 0) {
            Write-ACRAction -Action $action -Status 'Skipped' `
                -Message "No admin-consented grants found in the tenant." `
                -Target $UserId
            return New-ACRResult -Status 'Skipped' -Message 'No admin-consented grants found.'
        }

        $beforeState = $allGrants | ForEach-Object {
            @{
                GrantId   = $_.Id
                ClientId  = $_.ClientId
                Scope     = $_.Scope
                ConsentType = $_.ConsentType
            }
        }

        $removed = @()
        foreach ($grant in $allGrants) {
            try {
                Remove-MgOauth2PermissionGrant -OAuth2PermissionGrantId $grant.Id -ErrorAction Stop
                $removed += @{ GrantId = $grant.Id; ClientId = $grant.ClientId; Scope = $grant.Scope }
            }
            catch {
                Write-Warning "Could not remove admin consent grant $($grant.Id): $_"
            }
        }

        Write-ACRAction -Action $action -Status 'Success' `
            -Message "Removed $($removed.Count) admin-consented grant(s)." `
            -Target $UserId -Details @{ RemovedCount = $removed.Count }

        Write-ACRRollbackEntry -Action $action -ResourceType 'AdminConsentGrant' `
            -ResourceId $UserId `
            -BeforeState $beforeState `
            -AfterState  @{ RemovedGrants = $removed } `
            -RollbackInstructions "Re-grant admin consent via Azure Portal > Enterprise Applications > Permissions, or use New-MgOauth2PermissionGrant with ConsentType 'AllPrincipals'."

        return New-ACRResult -Status 'Success' `
            -Message "Removed $($removed.Count) admin-consented app grant(s)." `
            -Details @{ Before = $beforeState; Removed = $removed }
    }
    catch {
        Write-ACRAction -Action $action -Status 'Failed' `
            -Message "Admin consent app removal failed for ${UserId}: $_" `
            -Target $UserId
        return New-ACRResult -Status 'Failed' -Message "Admin consent app removal failed: $_" -Details $_.Exception
    }
}

# ---------------------------------------------------------------------------
# 19. Remove-ACRAppRegistrationSecrets (Admin-Only)
# ---------------------------------------------------------------------------
function Remove-ACRAppRegistrationSecrets {
    <#
    .SYNOPSIS
        Removes recently added client secrets from app registrations. Requires admin role.
    .PARAMETER UserId
        The object ID or UPN of the admin user to check.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$UserId
    )

    $action = 'RemoveAppRegistrationSecrets'
    try {
        # Verify admin role
        $roles = Get-MgUserMemberOf -UserId $UserId -All -ErrorAction Stop |
            Where-Object { $_.AdditionalProperties.'@odata.type' -eq '#microsoft.graph.directoryRole' }

        $isAdmin = $roles | Where-Object {
            $_.AdditionalProperties.displayName -match 'Admin|Administrator'
        }

        if (-not $isAdmin) {
            Write-ACRAction -Action $action -Status 'Skipped' `
                -Message "User $UserId does not hold an admin role. Skipping app registration secret review." `
                -Target $UserId
            return New-ACRResult -Status 'Skipped' -Message 'User is not an admin. App registration secret review not applicable.'
        }

        $cutoff = (Get-Date).AddDays(-$script:LookbackDays).ToUniversalTime()

        # Get all app registrations owned by this user
        $ownedApps = Get-MgUserOwnedObject -UserId $UserId -All -ErrorAction Stop |
            Where-Object { $_.AdditionalProperties.'@odata.type' -eq '#microsoft.graph.application' }

        if (-not $ownedApps -or $ownedApps.Count -eq 0) {
            Write-ACRAction -Action $action -Status 'Skipped' `
                -Message "User $UserId does not own any app registrations." `
                -Target $UserId
            return New-ACRResult -Status 'Skipped' -Message 'User does not own any app registrations.'
        }

        $beforeState = @()
        $removed = @()

        foreach ($appRef in $ownedApps) {
            try {
                $app = Get-MgApplication -ApplicationId $appRef.Id -Property 'Id,DisplayName,PasswordCredentials,AppId' -ErrorAction Stop

                $recentSecrets = $app.PasswordCredentials | Where-Object {
                    $_.StartDateTime -and $_.StartDateTime -gt $cutoff
                }

                foreach ($secret in $recentSecrets) {
                    $beforeState += @{
                        AppId        = $app.AppId
                        AppName      = $app.DisplayName
                        KeyId        = $secret.KeyId
                        StartDate    = $secret.StartDateTime
                        EndDate      = $secret.EndDateTime
                        DisplayName  = $secret.DisplayName
                    }

                    try {
                        Remove-MgApplicationPassword -ApplicationId $app.Id `
                            -BodyParameter @{ KeyId = $secret.KeyId } -ErrorAction Stop
                        $removed += "$($app.DisplayName) [KeyId: $($secret.KeyId)]"
                    }
                    catch {
                        Write-Warning "Could not remove secret $($secret.KeyId) from app $($app.DisplayName): $_"
                    }
                }
            }
            catch {
                Write-Verbose "Could not inspect app $($appRef.Id): $_"
            }
        }

        if ($removed.Count -eq 0) {
            Write-ACRAction -Action $action -Status 'Skipped' `
                -Message "No recently added secrets found on apps owned by $UserId." `
                -Target $UserId
            return New-ACRResult -Status 'Skipped' -Message "No recently added secrets found (last $($script:LookbackDays) days)."
        }

        Write-ACRAction -Action $action -Status 'Success' `
            -Message "Removed $($removed.Count) recently added secret(s) from app registrations owned by $UserId." `
            -Target $UserId -Details @{ Removed = $removed }

        Write-ACRRollbackEntry -Action $action -ResourceType 'AppRegistrationSecret' `
            -ResourceId $UserId `
            -BeforeState $beforeState `
            -AfterState  @{ RemovedSecrets = $removed } `
            -RollbackInstructions "Secrets cannot be restored (values are not recorded). New secrets must be generated via Add-MgApplicationPassword if needed. App/KeyId details are in BeforeState."

        return New-ACRResult -Status 'Success' `
            -Message "Removed $($removed.Count) recently added secret(s)." `
            -Details @{ Before = $beforeState; Removed = $removed }
    }
    catch {
        Write-ACRAction -Action $action -Status 'Failed' `
            -Message "App registration secret removal failed for ${UserId}: $_" `
            -Target $UserId
        return New-ACRResult -Status 'Failed' -Message "App registration secret removal failed: $_" -Details $_.Exception
    }
}

# ---------------------------------------------------------------------------
# 20. Remove-ACRExchangeRules (Exchange Admin-Only)
# ---------------------------------------------------------------------------
function Remove-ACRExchangeRules {
    <#
    .SYNOPSIS
        Removes recently modified journal rules, transport rules, and mailbox rules.
        Requires ExchangeOnlineManagement module and Exchange admin role.
    .PARAMETER UserPrincipalName
        The UPN of the Exchange admin user.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$UserPrincipalName
    )

    $action = 'RemoveExchangeRules'
    try {
        # Check for ExchangeOnlineManagement module
        if (-not (Get-Module -ListAvailable -Name ExchangeOnlineManagement)) {
            Write-ACRAction -Action $action -Status 'Warning' `
                -Message "ExchangeOnlineManagement module is not installed. Cannot inspect Exchange rules." `
                -Target $UserPrincipalName `
                -Details @{ InstallCommand = 'Install-Module ExchangeOnlineManagement -Scope CurrentUser' }

            Write-ACRRollbackEntry -Action $action -ResourceType 'ExchangeRule' `
                -ResourceId $UserPrincipalName `
                -BeforeState @{ Note = 'ExchangeOnlineManagement module not available' } `
                -AfterState  @{ Note = 'Flagged for manual review' } `
                -RollbackInstructions "Install ExchangeOnlineManagement module and manually review transport/journal rules."

            return New-ACRResult -Status 'Warning' `
                -Message 'ExchangeOnlineManagement module not installed. Manual review required.' `
                -Details @{
                    InstallCommand = 'Install-Module ExchangeOnlineManagement -Scope CurrentUser'
                    ManualSteps = @(
                        '1. Install-Module ExchangeOnlineManagement'
                        '2. Connect-ExchangeOnline'
                        '3. Get-TransportRule | Where-Object { $_.WhenChanged -gt (Get-Date).AddDays(-7) }'
                        '4. Get-JournalRule'
                        "5. Get-InboxRule -Mailbox '$UserPrincipalName'"
                    )
                }
        }

        # Verify Exchange admin role via Graph
        $roles = Get-MgUserMemberOf -UserId $UserPrincipalName -All -ErrorAction Stop |
            Where-Object { $_.AdditionalProperties.'@odata.type' -eq '#microsoft.graph.directoryRole' }

        $isExchangeAdmin = $roles | Where-Object {
            $_.AdditionalProperties.displayName -match 'Exchange'
        }

        if (-not $isExchangeAdmin) {
            Write-ACRAction -Action $action -Status 'Skipped' `
                -Message "User $UserPrincipalName does not hold an Exchange admin role." `
                -Target $UserPrincipalName
            return New-ACRResult -Status 'Skipped' -Message 'User is not an Exchange admin. Exchange rule review not applicable.'
        }

        $cutoff = (Get-Date).AddDays(-$script:LookbackDays)
        $beforeState = @()
        $removed = @()

        # --- Transport rules ---
        try {
            $transportRules = Get-TransportRule -ErrorAction Stop |
                Where-Object { $_.WhenChanged -gt $cutoff }

            foreach ($rule in $transportRules) {
                $beforeState += @{
                    Type      = 'TransportRule'
                    Name      = $rule.Name
                    Identity  = $rule.Identity
                    Modified  = $rule.WhenChanged
                    State     = $rule.State
                }

                try {
                    Remove-TransportRule -Identity $rule.Identity -Confirm:$false -ErrorAction Stop
                    $removed += "TransportRule: $($rule.Name)"
                }
                catch {
                    Write-Warning "Could not remove transport rule $($rule.Name): $_"
                }
            }
        }
        catch {
            Write-Verbose "Transport rule query failed: $_"
        }

        # --- Journal rules ---
        try {
            $journalRules = Get-JournalRule -ErrorAction Stop

            foreach ($rule in $journalRules) {
                $beforeState += @{
                    Type      = 'JournalRule'
                    Name      = $rule.Name
                    Identity  = $rule.Identity
                    Recipient = $rule.JournalEmailAddress
                    Scope     = $rule.Scope
                }

                # Journal rules are high-impact; flag for review rather than auto-delete
                Write-Warning "Journal rule found: $($rule.Name) — flagged for manual review."
            }
        }
        catch {
            Write-Verbose "Journal rule query failed: $_"
        }

        # --- Inbox rules for the user ---
        try {
            $inboxRules = Get-InboxRule -Mailbox $UserPrincipalName -ErrorAction Stop

            $suspiciousRules = $inboxRules | Where-Object {
                $_.ForwardTo -or $_.ForwardAsAttachmentTo -or $_.RedirectTo -or $_.DeleteMessage
            }

            foreach ($rule in $suspiciousRules) {
                $beforeState += @{
                    Type        = 'InboxRule'
                    Name        = $rule.Name
                    Identity    = $rule.Identity
                    ForwardTo   = $rule.ForwardTo
                    RedirectTo  = $rule.RedirectTo
                    DeleteMsg   = $rule.DeleteMessage
                }

                try {
                    Remove-InboxRule -Identity $rule.Identity -Confirm:$false -ErrorAction Stop
                    $removed += "InboxRule: $($rule.Name)"
                }
                catch {
                    Write-Warning "Could not remove inbox rule $($rule.Name): $_"
                }
            }
        }
        catch {
            Write-Verbose "Inbox rule query failed: $_"
        }

        if ($removed.Count -eq 0 -and $beforeState.Count -eq 0) {
            Write-ACRAction -Action $action -Status 'Skipped' `
                -Message "No suspicious Exchange rules found for $UserPrincipalName." `
                -Target $UserPrincipalName
            return New-ACRResult -Status 'Skipped' -Message 'No suspicious Exchange rules found.'
        }

        $status = if ($removed.Count -gt 0) { 'Success' } else { 'Warning' }
        $message = "Processed $($beforeState.Count) rule(s); removed $($removed.Count) for $UserPrincipalName."

        Write-ACRAction -Action $action -Status $status `
            -Message $message -Target $UserPrincipalName `
            -Details @{ Removed = $removed; Flagged = ($beforeState.Count - $removed.Count) }

        Write-ACRRollbackEntry -Action $action -ResourceType 'ExchangeRule' `
            -ResourceId $UserPrincipalName `
            -BeforeState $beforeState `
            -AfterState  @{ RemovedRules = $removed } `
            -RollbackInstructions "Re-create removed rules using New-TransportRule / New-InboxRule with the parameters recorded in BeforeState."

        return New-ACRResult -Status $status -Message $message `
            -Details @{ Before = $beforeState; Removed = $removed }
    }
    catch {
        Write-ACRAction -Action $action -Status 'Failed' `
            -Message "Exchange rule removal failed for ${UserPrincipalName}: $_" `
            -Target $UserPrincipalName
        return New-ACRResult -Status 'Failed' -Message "Exchange rule removal failed: $_" -Details $_.Exception
    }
}

# ---------------------------------------------------------------------------
# Export all public functions
# ---------------------------------------------------------------------------
Export-ModuleMember -Function @(
    # Standard User Actions (1-17)
    'Reset-ACRPassword'
    'Revoke-ACRRefreshTokens'
    'Enforce-ACRMFA'
    'Remove-ACRAppPasswords'
    'Remove-ACRMailboxDelegates'
    'Remove-ACRMailboxFolderPermissions'
    'Remove-ACREmailForwarding'
    'Remove-ACROutlookAddins'
    'Remove-ACRSafeSenders'
    'Remove-ACRCalendarSharing'
    'Remove-ACRMobileDevices'
    'Remove-ACRUserConsentApps'
    'Remove-ACRPowerAutomateFlows'
    'Remove-ACRPowerApps'
    'Remove-ACRPowerAppsSharing'
    'Remove-ACRSharePointSharingLinks'
    'Remove-ACRTeamsGuests'
    # Admin-Only Actions (18-19)
    'Remove-ACRAdminConsentApps'
    'Remove-ACRAppRegistrationSecrets'
    # Exchange Admin-Only Actions (20)
    'Remove-ACRExchangeRules'
)
