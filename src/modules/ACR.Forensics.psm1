#Requires -Version 7.2
#Requires -Modules Microsoft.Graph.Authentication, Microsoft.Graph.Reports, Microsoft.Graph.Users

<#
.SYNOPSIS
    Forensic data collection module for Account Compromise Remediation.

.DESCRIPTION
    Collects the last 7 days (configurable) of user activity from Entra ID,
    Exchange Online, and Microsoft 365 unified audit logs BEFORE remediation
    actions are taken. This preserves evidence for incident response and
    post-incident analysis.
#>

# Default lookback window in days for forensic data collection
$script:DefaultLookbackDays = 7

function Get-ACRSignInLogs {
    <#
    .SYNOPSIS
        Collects sign-in logs for a specified user.

    .DESCRIPTION
        Queries Microsoft Graph auditLogs/signIns filtered by the target user
        and a configurable lookback window. Returns structured objects containing
        timestamp, IP address, location, device info, application used, sign-in
        status, risk level, and conditional access evaluation results.

    .PARAMETER UserPrincipalName
        The UPN of the user whose sign-in logs to collect.

    .PARAMETER LookbackDays
        Number of days to look back from the current time. Defaults to 7.

    .EXAMPLE
        Get-ACRSignInLogs -UserPrincipalName "user@contoso.com"

    .EXAMPLE
        Get-ACRSignInLogs -UserPrincipalName "user@contoso.com" -LookbackDays 14
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [ValidateNotNullOrEmpty()]
        [string]$UserPrincipalName,

        [Parameter()]
        [ValidateRange(1, 90)]
        [int]$LookbackDays = $script:DefaultLookbackDays
    )

    $startDate = (Get-Date).AddDays(-$LookbackDays).ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ')
    $filter = "userPrincipalName eq '$UserPrincipalName' and createdDateTime ge $startDate"

    Write-Verbose "Collecting sign-in logs for $UserPrincipalName since $startDate..."

    try {
        $signIns = Get-MgAuditLogSignIn -Filter $filter -All -ErrorAction Stop

        $results = foreach ($entry in $signIns) {
            [PSCustomObject]@{
                Timestamp              = $entry.CreatedDateTime
                UserPrincipalName      = $entry.UserPrincipalName
                AppDisplayName         = $entry.AppDisplayName
                ClientAppUsed          = $entry.ClientAppUsed
                IpAddress              = $entry.IpAddress
                City                   = $entry.Location.City
                State                  = $entry.Location.State
                CountryOrRegion        = $entry.Location.CountryOrRegion
                DeviceDisplayName      = $entry.DeviceDetail.DisplayName
                DeviceBrowser          = $entry.DeviceDetail.Browser
                DeviceOperatingSystem  = $entry.DeviceDetail.OperatingSystem
                DeviceIsCompliant      = $entry.DeviceDetail.IsCompliant
                DeviceIsManaged        = $entry.DeviceDetail.IsManaged
                StatusErrorCode        = $entry.Status.ErrorCode
                StatusFailureReason    = $entry.Status.FailureReason
                RiskLevelDuringSignIn  = $entry.RiskLevelDuringSignIn
                RiskLevelAggregated    = $entry.RiskLevelAggregated
                RiskState              = $entry.RiskState
                ConditionalAccessStatus = $entry.ConditionalAccessStatus
                IsInteractive          = $entry.IsInteractive
                ResourceDisplayName    = $entry.ResourceDisplayName
                CorrelationId          = $entry.CorrelationId
                Id                     = $entry.Id
            }
        }

        Write-Verbose "Collected $($results.Count) sign-in log entries."
        return $results
    }
    catch {
        Write-Error "Failed to collect sign-in logs for ${UserPrincipalName}: $_"
        return @()
    }
}

function Get-ACRAuditLogs {
    <#
    .SYNOPSIS
        Collects directory audit logs initiated by a specified user.

    .DESCRIPTION
        Queries Microsoft Graph auditLogs/directoryAudits filtered by the
        initiating user's UPN and a configurable lookback window. Returns
        structured objects with activity display name, category, result,
        target resources, and timestamps.

    .PARAMETER UserPrincipalName
        The UPN of the user whose initiated audit events to collect.

    .PARAMETER LookbackDays
        Number of days to look back from the current time. Defaults to 7.

    .EXAMPLE
        Get-ACRAuditLogs -UserPrincipalName "user@contoso.com"

    .EXAMPLE
        Get-ACRAuditLogs -UserPrincipalName "user@contoso.com" -LookbackDays 30
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [ValidateNotNullOrEmpty()]
        [string]$UserPrincipalName,

        [Parameter()]
        [ValidateRange(1, 90)]
        [int]$LookbackDays = $script:DefaultLookbackDays
    )

    $startDate = (Get-Date).AddDays(-$LookbackDays).ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ')
    $filter = "initiatedBy/user/userPrincipalName eq '$UserPrincipalName' and activityDateTime ge $startDate"

    Write-Verbose "Collecting audit logs initiated by $UserPrincipalName since $startDate..."

    try {
        $audits = Get-MgAuditLogDirectoryAudit -Filter $filter -All -ErrorAction Stop

        $results = foreach ($entry in $audits) {
            $targetResources = foreach ($target in $entry.TargetResources) {
                [PSCustomObject]@{
                    DisplayName       = $target.DisplayName
                    Id                = $target.Id
                    Type              = $target.Type
                    UserPrincipalName = $target.UserPrincipalName
                    ModifiedProperties = $target.ModifiedProperties | ForEach-Object {
                        [PSCustomObject]@{
                            DisplayName = $_.DisplayName
                            OldValue    = $_.OldValue
                            NewValue    = $_.NewValue
                        }
                    }
                }
            }

            [PSCustomObject]@{
                Timestamp           = $entry.ActivityDateTime
                ActivityDisplayName = $entry.ActivityDisplayName
                Category            = $entry.Category
                Result              = $entry.Result
                ResultReason        = $entry.ResultReason
                OperationType       = $entry.OperationType
                LoggedByService     = $entry.LoggedByService
                InitiatedByUser     = $entry.InitiatedBy.User.UserPrincipalName
                InitiatedByApp      = $entry.InitiatedBy.App.DisplayName
                TargetResources     = $targetResources
                CorrelationId       = $entry.CorrelationId
                Id                  = $entry.Id
            }
        }

        Write-Verbose "Collected $($results.Count) audit log entries."
        return $results
    }
    catch {
        Write-Error "Failed to collect audit logs for ${UserPrincipalName}: $_"
        return @()
    }
}

function Get-ACRMailboxAudit {
    <#
    .SYNOPSIS
        Collects mailbox configuration data for forensic analysis.

    .DESCRIPTION
        Gathers mailbox delegates, folder permissions, inbox rules, and mail
        forwarding configuration for the specified user via Microsoft Graph.
        This data helps identify attacker persistence mechanisms such as
        unauthorized delegates, forwarding rules, or redirect rules.

    .PARAMETER UserPrincipalName
        The UPN of the user whose mailbox to audit.

    .PARAMETER LookbackDays
        Not directly used for mailbox config queries but included for
        interface consistency with other forensic functions.

    .EXAMPLE
        Get-ACRMailboxAudit -UserPrincipalName "user@contoso.com"
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [ValidateNotNullOrEmpty()]
        [string]$UserPrincipalName,

        [Parameter()]
        [ValidateRange(1, 90)]
        [int]$LookbackDays = $script:DefaultLookbackDays
    )

    Write-Verbose "Collecting mailbox forensic data for $UserPrincipalName..."

    $delegates = @()
    $folderPermissions = @()
    $inboxRules = @()
    $forwardingConfig = $null

    $exoConnected = Test-ACRExchangeOnlineConnected

    # Collect forwarding configuration via Exchange Online
    if ($exoConnected) {
        try {
            Write-Verbose "Retrieving mailbox forwarding configuration..."
            $mailbox = Get-Mailbox -Identity $UserPrincipalName -ErrorAction Stop
            $forwardingConfig = [PSCustomObject]@{
                ForwardingSmtpAddress      = $mailbox.ForwardingSmtpAddress
                ForwardingAddress          = $mailbox.ForwardingAddress
                DeliverToMailboxAndForward  = $mailbox.DeliverToMailboxAndForward
            }
            Write-Verbose "Mailbox forwarding configuration collected."
        }
        catch {
            Write-Warning "Failed to retrieve mailbox forwarding configuration for ${UserPrincipalName}: $_"
        }
    } else {
        Write-Warning "Exchange Online not connected. Skipping mailbox forwarding configuration collection."
    }

    # Collect mail folder permissions (Inbox, SentItems, Calendar, Contacts)
    if ($exoConnected) {
        foreach ($folderName in @('Inbox', 'SentItems', 'Calendar', 'Contacts')) {
            try {
                Write-Verbose "Retrieving permissions for $folderName folder..."
                $folderPath = "${UserPrincipalName}:\${folderName}"
                $perms = Get-MailboxFolderPermission -Identity $folderPath -ErrorAction SilentlyContinue
                $nonDefault = $perms | Where-Object { $_.User.DisplayName -notin @('Default', 'Anonymous') }
                foreach ($p in $nonDefault) {
                    $folderPermissions += [PSCustomObject]@{
                        Folder       = $folderName
                        User         = $p.User.DisplayName
                        AccessRights = ($p.AccessRights -join ', ')
                    }
                }
            }
            catch {
                Write-Verbose "Could not get permissions for ${folderName}: $_"
            }
        }
    } else {
        Write-Warning "Exchange Online not connected. Skipping mailbox folder permission collection."
    }

    # Collect inbox rules via Exchange Online
    if ($exoConnected) {
        try {
            Write-Verbose "Retrieving inbox rules..."
            $rules = Get-InboxRule -Mailbox $UserPrincipalName -ErrorAction Stop
            foreach ($r in $rules) {
                $inboxRules += [PSCustomObject]@{
                    Name          = $r.Name
                    Description   = $r.Description
                    IsEnabled     = $r.Enabled
                    ForwardTo     = ($r.ForwardTo -join '; ')
                    RedirectTo    = ($r.RedirectTo -join '; ')
                    DeleteMessage = $r.DeleteMessage
                    MoveToFolder  = $r.MoveToFolder
                }
            }
            Write-Verbose "Collected $($inboxRules.Count) inbox rules."
        }
        catch {
            Write-Warning "Failed to retrieve inbox rules for ${UserPrincipalName}: $_"
        }
    } else {
        Write-Warning "Exchange Online not connected. Skipping inbox rule collection."
    }

    # Collect delegates (users with SendAs / SendOnBehalf / Full Access)
    if ($exoConnected) {
        try {
            Write-Verbose "Retrieving mailbox delegates..."
            $delegatePerms = Get-MailboxPermission -Identity $UserPrincipalName -ErrorAction Stop |
                Where-Object { $_.User -ne 'NT AUTHORITY\SELF' -and $_.IsInherited -eq $false }
            foreach ($d in $delegatePerms) {
                $delegates += [PSCustomObject]@{
                    DelegateEmail = $d.User
                    AccessRights  = ($d.AccessRights -join ', ')
                    IsInherited   = $d.IsInherited
                }
            }
            Write-Verbose "Collected $($delegates.Count) delegate entries."
        }
        catch {
            Write-Warning "Failed to retrieve delegate information for ${UserPrincipalName}: $_"
        }
    } else {
        Write-Warning "Exchange Online not connected. Skipping delegate collection."
    }

    return [PSCustomObject]@{
        UserPrincipalName  = $UserPrincipalName
        CollectedAt        = (Get-Date).ToUniversalTime().ToString('o')
        Delegates          = $delegates
        FolderPermissions  = $folderPermissions
        InboxRules         = $inboxRules
        ForwardingConfig   = $forwardingConfig
    }
}

function Get-ACRUnifiedAuditLog {
    <#
    .SYNOPSIS
        Collects unified audit log entries for a specified user.

    .DESCRIPTION
        Wraps Search-UnifiedAuditLog from the ExchangeOnlineManagement module
        to collect audit events across SharePoint, OneDrive, Teams, and Power
        Platform. Requires an active Exchange Online PowerShell session.
        If the ExchangeOnlineManagement module is not loaded, returns a warning
        and an empty result set.

    .PARAMETER UserPrincipalName
        The UPN of the user whose audit log entries to collect.

    .PARAMETER LookbackDays
        Number of days to look back from the current time. Defaults to 7.

    .PARAMETER RecordTypes
        Optional array of record types to search. Defaults to common workloads:
        ExchangeItem, SharePointFileOperation, MicrosoftTeams, PowerBIAudit,
        AzureActiveDirectory, OneDrive.

    .EXAMPLE
        Get-ACRUnifiedAuditLog -UserPrincipalName "user@contoso.com"

    .EXAMPLE
        Get-ACRUnifiedAuditLog -UserPrincipalName "user@contoso.com" -RecordTypes @('SharePointFileOperation','MicrosoftTeams')
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [ValidateNotNullOrEmpty()]
        [string]$UserPrincipalName,

        [Parameter()]
        [ValidateRange(1, 90)]
        [int]$LookbackDays = $script:DefaultLookbackDays,

        [Parameter()]
        [string[]]$RecordTypes = @(
            'ExchangeItem'
            'SharePointFileOperation'
            'MicrosoftTeams'
            'PowerBIAudit'
            'AzureActiveDirectory'
            'OneDrive'
        )
    )

    # Verify Exchange Online connection is active
    if (-not (Test-ACRExchangeOnlineConnected)) {
        Write-Warning "Exchange Online not connected. Cannot search unified audit log."
        return [PSCustomObject]@{
            UserPrincipalName = $UserPrincipalName
            CollectedAt       = (Get-Date).ToUniversalTime().ToString('o')
            Available         = $false
            Entries           = @()
            Error             = 'Exchange Online not connected. Connect using Connect-ExchangeOnline before searching the unified audit log.'
        }
    }

    $startDate = (Get-Date).AddDays(-$LookbackDays)
    $endDate = Get-Date
    $allResults = [System.Collections.Generic.List[PSCustomObject]]::new()

    Write-Verbose "Collecting unified audit logs for $UserPrincipalName from $($startDate.ToString('o')) to $($endDate.ToString('o'))..."

    foreach ($recordType in $RecordTypes) {
        Write-Verbose "Searching record type: $recordType..."

        try {
            $sessionId = "ACR_$($UserPrincipalName)_$($recordType)_$(Get-Date -Format 'yyyyMMddHHmmss')"
            $pageCount = 0
            $maxPages = 100

            do {
                $pageCount++
                $searchResults = Search-UnifiedAuditLog `
                    -StartDate $startDate `
                    -EndDate $endDate `
                    -UserIds $UserPrincipalName `
                    -RecordType $recordType `
                    -SessionId $sessionId `
                    -SessionCommand 'ReturnLargeSet' `
                    -ResultSize 1000 `
                    -ErrorAction Stop

                if ($null -eq $searchResults -or $searchResults.Count -eq 0) {
                    break
                }

                foreach ($record in $searchResults) {
                    $auditData = $null
                    if ($record.AuditData) {
                        try {
                            $auditData = $record.AuditData | ConvertFrom-Json -ErrorAction SilentlyContinue
                        }
                        catch {
                            $auditData = $record.AuditData
                        }
                    }

                    $allResults.Add([PSCustomObject]@{
                        Timestamp    = $record.CreationDate
                        Operation    = $record.Operations
                        RecordType   = $record.RecordType
                        Workload     = $auditData.Workload
                        UserId       = $record.UserIds
                        TargetObject = $auditData.ObjectId
                        ClientIP     = $auditData.ClientIP
                        ResultStatus = $auditData.ResultStatus
                        Detail       = $auditData
                    })
                }

                Write-Verbose "  Page $pageCount`: retrieved $($searchResults.Count) records for $recordType."
            } while ($searchResults.Count -eq 1000 -and $pageCount -lt $maxPages)
        }
        catch {
            Write-Warning "Failed to search unified audit log for record type ${recordType}: $_"
        }
    }

    Write-Verbose "Collected $($allResults.Count) total unified audit log entries."

    return [PSCustomObject]@{
        UserPrincipalName = $UserPrincipalName
        CollectedAt       = (Get-Date).ToUniversalTime().ToString('o')
        Available         = $true
        Entries           = $allResults.ToArray()
        Error             = $null
    }
}

function Invoke-ACRForensicCollection {
    <#
    .SYNOPSIS
        Orchestrates a full forensic data collection for a compromised user account.

    .DESCRIPTION
        Calls all forensic collection functions (sign-in logs, audit logs, mailbox
        audit, unified audit log), saves results to a timestamped output folder,
        and returns a summary object. Handles partial failures gracefully — if one
        data source fails, the remaining sources are still collected.

    .PARAMETER UserPrincipalName
        The UPN of the user account to collect forensic data for.

    .PARAMETER LookbackDays
        Number of days to look back from the current time. Defaults to 7.

    .PARAMETER OutputBasePath
        Base directory for forensic output. A subfolder named
        <UPN>_<yyyyMMdd_HHmmss> will be created under this path.
        Defaults to 'forensics' in the current directory.

    .EXAMPLE
        Invoke-ACRForensicCollection -UserPrincipalName "user@contoso.com"

    .EXAMPLE
        Invoke-ACRForensicCollection -UserPrincipalName "user@contoso.com" -LookbackDays 14 -OutputBasePath "C:\Evidence"
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [ValidateNotNullOrEmpty()]
        [string]$UserPrincipalName,

        [Parameter()]
        [ValidateRange(1, 90)]
        [int]$LookbackDays = $script:DefaultLookbackDays,

        [Parameter()]
        [string]$OutputBasePath = 'forensics'
    )

    $timestamp = Get-Date -Format 'yyyyMMdd_HHmmss'
    $sanitizedUpn = $UserPrincipalName -replace '[\\/:*?"<>|@]', '_'
    $outputFolder = Join-Path $OutputBasePath "${sanitizedUpn}_${timestamp}"

    Write-Verbose "Creating forensic output directory: $outputFolder"
    New-Item -ItemType Directory -Path $outputFolder -Force | Out-Null

    $collectionStart = (Get-Date).ToUniversalTime()
    $errors = [System.Collections.Generic.List[string]]::new()

    # Sign-in logs
    Write-Verbose "--- Collecting sign-in logs ---"
    $signInLogs = $null
    try {
        $signInLogs = Get-ACRSignInLogs -UserPrincipalName $UserPrincipalName -LookbackDays $LookbackDays -Verbose:$VerbosePreference
        $signInPath = Join-Path $outputFolder 'sign-in-logs.json'
        $signInLogs | ConvertTo-Json -Depth 10 | Set-Content -Path $signInPath -Encoding UTF8
        Write-Verbose "Sign-in logs saved: $signInPath ($(@($signInLogs).Count) entries)"
    }
    catch {
        $errMsg = "Sign-in log collection failed: $_"
        Write-Warning $errMsg
        $errors.Add($errMsg)
    }

    # Audit logs
    Write-Verbose "--- Collecting audit logs ---"
    $auditLogs = $null
    try {
        $auditLogs = Get-ACRAuditLogs -UserPrincipalName $UserPrincipalName -LookbackDays $LookbackDays -Verbose:$VerbosePreference
        $auditPath = Join-Path $outputFolder 'audit-logs.json'
        $auditLogs | ConvertTo-Json -Depth 10 | Set-Content -Path $auditPath -Encoding UTF8
        Write-Verbose "Audit logs saved: $auditPath ($(@($auditLogs).Count) entries)"
    }
    catch {
        $errMsg = "Audit log collection failed: $_"
        Write-Warning $errMsg
        $errors.Add($errMsg)
    }

    # Mailbox audit
    Write-Verbose "--- Collecting mailbox audit data ---"
    $mailboxAudit = $null
    try {
        $mailboxAudit = Get-ACRMailboxAudit -UserPrincipalName $UserPrincipalName -LookbackDays $LookbackDays -Verbose:$VerbosePreference
        $mailboxPath = Join-Path $outputFolder 'mailbox-audit.json'
        $mailboxAudit | ConvertTo-Json -Depth 10 | Set-Content -Path $mailboxPath -Encoding UTF8
        Write-Verbose "Mailbox audit data saved: $mailboxPath"
    }
    catch {
        $errMsg = "Mailbox audit collection failed: $_"
        Write-Warning $errMsg
        $errors.Add($errMsg)
    }

    # Unified audit log
    Write-Verbose "--- Collecting unified audit log ---"
    $unifiedAuditLog = $null
    try {
        $unifiedAuditLog = Get-ACRUnifiedAuditLog -UserPrincipalName $UserPrincipalName -LookbackDays $LookbackDays -Verbose:$VerbosePreference
        $unifiedPath = Join-Path $outputFolder 'unified-audit-log.json'
        $unifiedAuditLog | ConvertTo-Json -Depth 10 | Set-Content -Path $unifiedPath -Encoding UTF8
        Write-Verbose "Unified audit log saved: $unifiedPath"
    }
    catch {
        $errMsg = "Unified audit log collection failed: $_"
        Write-Warning $errMsg
        $errors.Add($errMsg)
    }

    $collectionEnd = (Get-Date).ToUniversalTime()

    # Build summary
    $summary = [PSCustomObject]@{
        UserPrincipalName  = $UserPrincipalName
        LookbackDays       = $LookbackDays
        CollectionStartUtc = $collectionStart.ToString('o')
        CollectionEndUtc   = $collectionEnd.ToString('o')
        DurationSeconds    = [math]::Round(($collectionEnd - $collectionStart).TotalSeconds, 2)
        OutputPath         = (Resolve-Path $outputFolder).Path
        SignInLogs         = $signInLogs
        SignInLogCount      = @($signInLogs).Count
        AuditLogs          = $auditLogs
        AuditLogCount      = @($auditLogs).Count
        MailboxAudit       = $mailboxAudit
        UnifiedAuditLog    = $unifiedAuditLog
        UnifiedAuditAvailable = if ($unifiedAuditLog) { $unifiedAuditLog.Available } else { $false }
        UnifiedAuditCount  = if ($unifiedAuditLog -and $unifiedAuditLog.Entries) { $unifiedAuditLog.Entries.Count } else { 0 }
        Errors             = $errors.ToArray()
        HasErrors          = $errors.Count -gt 0
    }

    # Save summary metadata
    $summaryMeta = [PSCustomObject]@{
        UserPrincipalName     = $summary.UserPrincipalName
        LookbackDays          = $summary.LookbackDays
        CollectionStartUtc    = $summary.CollectionStartUtc
        CollectionEndUtc      = $summary.CollectionEndUtc
        DurationSeconds       = $summary.DurationSeconds
        OutputPath            = $summary.OutputPath
        SignInLogCount        = $summary.SignInLogCount
        AuditLogCount         = $summary.AuditLogCount
        UnifiedAuditAvailable = $summary.UnifiedAuditAvailable
        UnifiedAuditCount     = $summary.UnifiedAuditCount
        Errors                = $summary.Errors
    }
    $summaryPath = Join-Path $outputFolder 'collection-summary.json'
    $summaryMeta | ConvertTo-Json -Depth 5 | Set-Content -Path $summaryPath -Encoding UTF8

    Write-Verbose "Forensic collection complete. Output: $outputFolder"
    if ($errors.Count -gt 0) {
        Write-Warning "Collection completed with $($errors.Count) error(s). See Errors property for details."
    }

    return $summary
}

Export-ModuleMember -Function @(
    'Get-ACRSignInLogs'
    'Get-ACRAuditLogs'
    'Get-ACRMailboxAudit'
    'Get-ACRUnifiedAuditLog'
    'Invoke-ACRForensicCollection'
)
