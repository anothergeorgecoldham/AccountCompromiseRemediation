#Requires -Version 7.2

<#
.SYNOPSIS
    Reporting module for Account Compromise Remediation.

.DESCRIPTION
    Generates forensic reports in multiple formats (JSON, CSV, HTML) from data
    collected during Entra ID account compromise remediation. Provides risk
    analysis and professional incident reports suitable for security teams.
#>

#region Helper Functions

function ConvertTo-FlatObject {
    <#
    .SYNOPSIS
        Flattens a nested object into a single-level hashtable for CSV export.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [object]$InputObject,

        [Parameter()]
        [string]$Prefix = ''
    )

    $flat = [ordered]@{}

    if ($null -eq $InputObject) {
        return $flat
    }

    $properties = if ($InputObject -is [System.Collections.IDictionary]) {
        $InputObject.GetEnumerator() | ForEach-Object {
            [PSCustomObject]@{ Name = $_.Key; Value = $_.Value }
        }
    }
    elseif ($InputObject -is [PSCustomObject]) {
        $InputObject.PSObject.Properties
    }
    else {
        return $flat
    }

    foreach ($prop in $properties) {
        $key = if ($Prefix) { "${Prefix}_$($prop.Name)" } else { $prop.Name }
        $value = $prop.Value

        if ($null -eq $value) {
            $flat[$key] = $null
        }
        elseif ($value -is [PSCustomObject] -or $value -is [System.Collections.IDictionary]) {
            $nested = ConvertTo-FlatObject -InputObject $value -Prefix $key
            foreach ($nk in $nested.Keys) {
                $flat[$nk] = $nested[$nk]
            }
        }
        elseif ($value -is [System.Collections.IEnumerable] -and $value -isnot [string]) {
            $flat[$key] = ($value | ForEach-Object { "$_" }) -join '; '
        }
        else {
            $flat[$key] = $value
        }
    }

    return $flat
}

function Export-DataCategory {
    <#
    .SYNOPSIS
        Exports a single data category to JSON and CSV files.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$Name,

        [Parameter()]
        [object]$Data,

        [Parameter(Mandatory)]
        [string]$OutputPath
    )

    $files = @()

    if ($null -eq $Data) {
        $Data = @()
    }

    $dataArray = @($Data)

    # JSON export
    $jsonPath = Join-Path $OutputPath "$Name.json"
    $dataArray | ConvertTo-Json -Depth 10 -AsArray | Set-Content -Path $jsonPath -Encoding UTF8
    $files += $jsonPath
    Write-Verbose "Exported $($dataArray.Count) records to $jsonPath"

    # CSV export (flatten nested objects)
    $csvPath = Join-Path $OutputPath "$Name.csv"
    if ($dataArray.Count -eq 0) {
        '' | Set-Content -Path $csvPath -Encoding UTF8
    }
    else {
        $flatObjects = foreach ($item in $dataArray) {
            $flat = ConvertTo-FlatObject -InputObject $item
            [PSCustomObject]$flat
        }
        $flatObjects | Export-Csv -Path $csvPath -NoTypeInformation -Encoding UTF8
    }
    $files += $csvPath
    Write-Verbose "Exported $($dataArray.Count) records to $csvPath"

    return $files
}

#endregion

#region Public Functions

function Export-ACRForensicData {
    <#
    .SYNOPSIS
        Exports raw forensic data to JSON and CSV files.

    .DESCRIPTION
        Takes the forensic data PSCustomObject returned by Invoke-ACRForensicCollection
        and exports each data category (SignInLogs, AuditLogs, MailboxAudit, UnifiedAuditLog)
        to both JSON and CSV format. Nested objects are flattened for CSV compatibility.

    .PARAMETER ForensicData
        The PSCustomObject returned by Invoke-ACRForensicCollection. Expected properties:
        SignInLogs, AuditLogs, MailboxAudit (with Delegates, InboxRules, ForwardingConfig),
        and UnifiedAuditLog.

    .PARAMETER OutputPath
        Directory where exported files will be written. Created if it does not exist.

    .OUTPUTS
        [string[]] List of file paths created.

    .EXAMPLE
        $files = Export-ACRForensicData -ForensicData $forensics -OutputPath "C:\Reports\incident42"
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory, ValueFromPipeline)]
        [ValidateNotNull()]
        [PSCustomObject]$ForensicData,

        [Parameter(Mandatory)]
        [ValidateNotNullOrEmpty()]
        [string]$OutputPath
    )

    process {
        if (-not (Test-Path $OutputPath)) {
            New-Item -ItemType Directory -Path $OutputPath -Force | Out-Null
            Write-Verbose "Created output directory: $OutputPath"
        }

        $allFiles = [System.Collections.Generic.List[string]]::new()

        # Define data categories and their paths within the forensic data object
        $categories = @(
            @{ Name = 'SignInLogs';                Data = $ForensicData.SignInLogs }
            @{ Name = 'AuditLogs';                 Data = $ForensicData.AuditLogs }
            @{ Name = 'MailboxAudit_Delegates';    Data = $ForensicData.MailboxAudit?.Delegates }
            @{ Name = 'MailboxAudit_FolderPermissions'; Data = $ForensicData.MailboxAudit?.FolderPermissions }
            @{ Name = 'MailboxAudit_InboxRules';   Data = $ForensicData.MailboxAudit?.InboxRules }
            @{ Name = 'MailboxAudit_ForwardingConfig'; Data = $ForensicData.MailboxAudit?.ForwardingConfig }
            @{ Name = 'UnifiedAuditLog';           Data = $ForensicData.UnifiedAuditLog }
        )

        foreach ($category in $categories) {
            $files = Export-DataCategory -Name $category.Name -Data $category.Data -OutputPath $OutputPath
            foreach ($f in $files) {
                $allFiles.Add($f)
            }
        }

        Write-Verbose "Export complete. $($allFiles.Count) files created."
        return $allFiles.ToArray()
    }
}

function Get-ACRRiskIndicators {
    <#
    .SYNOPSIS
        Analyzes forensic data and returns key risk findings.

    .DESCRIPTION
        Examines sign-in logs, audit logs, mailbox audit data, and unified audit logs
        to identify risk indicators such as risky sign-ins, unfamiliar locations,
        forwarding rules, new delegates, suspicious app consents, password changes,
        and MFA changes. Returns a risk assessment with an overall risk level.

    .PARAMETER ForensicData
        The PSCustomObject returned by Invoke-ACRForensicCollection.

    .OUTPUTS
        [PSCustomObject] Risk indicator summary with OverallRiskLevel (High/Medium/Low).

    .EXAMPLE
        $risks = Get-ACRRiskIndicators -ForensicData $forensics
        if ($risks.OverallRiskLevel -eq 'High') { Write-Warning "High risk detected!" }
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory, ValueFromPipeline)]
        [ValidateNotNull()]
        [PSCustomObject]$ForensicData
    )

    process {
        # Risky sign-ins
        $signInLogs = @($ForensicData.SignInLogs | Where-Object { $_ })
        $riskySignIns = @($signInLogs | Where-Object {
            $_.RiskLevelDuringSignIn -in @('high', 'medium') -or
            $_.RiskState -in @('atRisk', 'confirmedCompromised')
        })

        # Unfamiliar locations (collect unique locations)
        $locations = @($signInLogs | Where-Object { $_.Location } | ForEach-Object {
            $loc = $_.Location
            $city = if ($loc -is [PSCustomObject]) { $loc.City } elseif ($loc -is [hashtable]) { $loc['City'] } else { $null }
            $country = if ($loc -is [PSCustomObject]) { $loc.CountryOrRegion } elseif ($loc -is [hashtable]) { $loc['CountryOrRegion'] } else { $null }
            [PSCustomObject]@{
                City    = $city
                Country = $country
                IP      = $_.IpAddress
            }
        } | Sort-Object -Property City, Country -Unique)

        # Failed sign-in attempts
        $failedSignIns = @($signInLogs | Where-Object {
            $_.Status.ErrorCode -ne 0 -or $_.ResultType -ne '0'
        })

        # Audit log analysis
        $auditLogs = @($ForensicData.AuditLogs | Where-Object { $_ })

        $passwordChanges = @($auditLogs | Where-Object {
            $_.ActivityDisplayName -match 'password' -or
            $_.OperationName -match 'password'
        })

        $mfaChanges = @($auditLogs | Where-Object {
            $_.ActivityDisplayName -match 'authentication method|MFA|multi-factor|StrongAuthentication' -or
            $_.OperationName -match 'authentication method|MFA|multi-factor|StrongAuthentication'
        })

        $appConsents = @($auditLogs | Where-Object {
            $_.ActivityDisplayName -match 'Consent to application|OAuth2PermissionGrant' -or
            $_.OperationName -match 'Consent to application|OAuth2PermissionGrant'
        })

        $roleChanges = @($auditLogs | Where-Object {
            $_.ActivityDisplayName -match 'role|member' -or
            $_.OperationName -match 'Add member to role|Remove member from role'
        })

        # Mailbox indicators
        $delegates = @($ForensicData.MailboxAudit?.Delegates | Where-Object { $_ })
        $inboxRules = @($ForensicData.MailboxAudit?.InboxRules | Where-Object { $_ })

        $forwardingConfig = $ForensicData.MailboxAudit?.ForwardingConfig
        $forwardingRules = @()
        if ($forwardingConfig) {
            $hasForwarding = (
                ($forwardingConfig.ForwardingSmtpAddress) -or
                ($forwardingConfig.ForwardingAddress) -or
                ($forwardingConfig.DeliverToMailboxAndForward -eq $true)
            )
            if ($hasForwarding) {
                $forwardingRules += $forwardingConfig
            }
        }

        # Also check inbox rules that forward
        $suspiciousInboxRules = @($inboxRules | Where-Object {
            $_.ForwardTo -or $_.RedirectTo -or
            ($_.DeleteMessage -eq $true) -or ($_.MoveToFolder -match 'RSS|Deleted|Junk')
        })
        $forwardingRules += @($inboxRules | Where-Object {
            $_.ForwardTo -or $_.RedirectTo
        })

        # Calculate overall risk level
        $riskScore = 0
        if ($riskySignIns.Count -gt 0)       { $riskScore += 3 }
        if ($forwardingRules.Count -gt 0)     { $riskScore += 3 }
        if ($delegates.Count -gt 0)           { $riskScore += 2 }
        if ($passwordChanges.Count -gt 0)     { $riskScore += 2 }
        if ($mfaChanges.Count -gt 0)          { $riskScore += 2 }
        if ($appConsents.Count -gt 0)         { $riskScore += 2 }
        if ($roleChanges.Count -gt 0)         { $riskScore += 3 }
        if ($failedSignIns.Count -gt 5)       { $riskScore += 1 }
        if ($suspiciousInboxRules.Count -gt 0) { $riskScore += 2 }

        $overallRisk = if ($riskScore -ge 5) { 'High' }
                       elseif ($riskScore -ge 2) { 'Medium' }
                       else { 'Low' }

        return [PSCustomObject]@{
            RiskySignIns         = [PSCustomObject]@{
                Count   = $riskySignIns.Count
                Details = $riskySignIns
            }
            UnfamiliarLocations  = [PSCustomObject]@{
                Count   = $locations.Count
                Details = $locations
            }
            FailedSignIns        = [PSCustomObject]@{
                Count   = $failedSignIns.Count
                Details = $failedSignIns
            }
            NewForwardingRules   = [PSCustomObject]@{
                Count   = $forwardingRules.Count
                Details = $forwardingRules
            }
            NewDelegates         = [PSCustomObject]@{
                Count   = $delegates.Count
                Details = $delegates
            }
            SuspiciousAppConsents = [PSCustomObject]@{
                Count   = $appConsents.Count
                Details = $appConsents
            }
            PasswordChanges      = [PSCustomObject]@{
                Count   = $passwordChanges.Count
                Details = $passwordChanges
            }
            MFAChanges           = [PSCustomObject]@{
                Count   = $mfaChanges.Count
                Details = $mfaChanges
            }
            RoleChanges          = [PSCustomObject]@{
                Count   = $roleChanges.Count
                Details = $roleChanges
            }
            SuspiciousInboxRules = [PSCustomObject]@{
                Count   = $suspiciousInboxRules.Count
                Details = $suspiciousInboxRules
            }
            RiskScore            = $riskScore
            OverallRiskLevel     = $overallRisk
        }
    }
}

function New-ACRHtmlReport {
    <#
    .SYNOPSIS
        Generates a comprehensive HTML summary report for account compromise remediation.

    .DESCRIPTION
        Creates a self-contained HTML report with embedded CSS that summarizes forensic
        findings, risk indicators, and optionally remediation actions taken. The report
        is designed for sharing with security teams and management.

    .PARAMETER ForensicData
        The PSCustomObject returned by Invoke-ACRForensicCollection.

    .PARAMETER UserContext
        The user context object from Get-ACRUserContext containing UPN, DisplayName,
        IsAdmin, and AdminRoles properties.

    .PARAMETER OutputPath
        Full file path (including filename) where the HTML report will be saved.

    .PARAMETER RemediationSummary
        Optional hashtable with remediation action results. Each key is the action name,
        and the value is a hashtable with Status, Message, and optional Timestamp.

    .OUTPUTS
        [string] The full path to the generated HTML report.

    .EXAMPLE
        $report = New-ACRHtmlReport -ForensicData $forensics -UserContext $ctx -OutputPath "C:\Reports\report.html"

    .EXAMPLE
        $remediation = @{
            'ResetPassword' = @{ Status = 'Success'; Message = 'Password reset completed' }
            'RevokeTokens'  = @{ Status = 'Success'; Message = 'All refresh tokens revoked' }
        }
        New-ACRHtmlReport -ForensicData $forensics -UserContext $ctx -OutputPath "C:\Reports\report.html" -RemediationSummary $remediation
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [ValidateNotNull()]
        [PSCustomObject]$ForensicData,

        [Parameter(Mandatory)]
        [ValidateNotNull()]
        [PSCustomObject]$UserContext,

        [Parameter(Mandatory)]
        [ValidateNotNullOrEmpty()]
        [string]$OutputPath,

        [Parameter()]
        [hashtable]$RemediationSummary
    )

    # Compute risk indicators
    $risk = Get-ACRRiskIndicators -ForensicData $ForensicData

    $reportTime = (Get-Date).ToUniversalTime().ToString('yyyy-MM-dd HH:mm:ss UTC')
    $upn = if ($UserContext.UserPrincipalName) { $UserContext.UserPrincipalName } else { 'N/A' }
    $displayName = if ($UserContext.DisplayName) { $UserContext.DisplayName } else { 'N/A' }
    $isAdmin = if ($UserContext.IsAdmin) { 'Yes' } else { 'No' }
    $adminRoles = if ($UserContext.AdminRoles -and $UserContext.AdminRoles.Count -gt 0) {
        ($UserContext.AdminRoles -join ', ')
    } else { 'None' }

    $riskClass = switch ($risk.OverallRiskLevel) {
        'High'   { 'severity-high' }
        'Medium' { 'severity-medium' }
        'Low'    { 'severity-low' }
    }

    # Build executive summary bullets
    $execFindings = [System.Collections.Generic.List[string]]::new()
    if ($risk.RiskySignIns.Count -gt 0) {
        $execFindings.Add("<li class=`"severity-high`"><strong>$($risk.RiskySignIns.Count)</strong> risky sign-in(s) detected</li>")
    }
    if ($risk.NewForwardingRules.Count -gt 0) {
        $execFindings.Add("<li class=`"severity-high`"><strong>$($risk.NewForwardingRules.Count)</strong> email forwarding rule(s) found</li>")
    }
    if ($risk.NewDelegates.Count -gt 0) {
        $execFindings.Add("<li class=`"severity-medium`"><strong>$($risk.NewDelegates.Count)</strong> mailbox delegate(s) detected</li>")
    }
    if ($risk.SuspiciousAppConsents.Count -gt 0) {
        $execFindings.Add("<li class=`"severity-medium`"><strong>$($risk.SuspiciousAppConsents.Count)</strong> suspicious app consent(s)</li>")
    }
    if ($risk.PasswordChanges.Count -gt 0) {
        $execFindings.Add("<li class=`"severity-medium`"><strong>$($risk.PasswordChanges.Count)</strong> password change event(s)</li>")
    }
    if ($risk.MFAChanges.Count -gt 0) {
        $execFindings.Add("<li class=`"severity-medium`"><strong>$($risk.MFAChanges.Count)</strong> MFA method change(s)</li>")
    }
    if ($risk.RoleChanges.Count -gt 0) {
        $execFindings.Add("<li class=`"severity-high`"><strong>$($risk.RoleChanges.Count)</strong> directory role change(s)</li>")
    }
    if ($risk.SuspiciousInboxRules.Count -gt 0) {
        $execFindings.Add("<li class=`"severity-medium`"><strong>$($risk.SuspiciousInboxRules.Count)</strong> suspicious inbox rule(s)</li>")
    }
    if ($execFindings.Count -eq 0) {
        $execFindings.Add('<li class="severity-low">No high-risk indicators detected</li>')
    }
    $execFindingsHtml = $execFindings -join "`n            "

    # Sign-in analysis section
    $signInLogs = @($ForensicData.SignInLogs | Where-Object { $_ })
    $signInCount = $signInLogs.Count
    $riskyCount = $risk.RiskySignIns.Count
    $failedCount = $risk.FailedSignIns.Count
    $locationCount = $risk.UnfamiliarLocations.Count

    $locationTableRows = ''
    if ($risk.UnfamiliarLocations.Count -gt 0) {
        foreach ($loc in $risk.UnfamiliarLocations.Details) {
            $city = [System.Web.HttpUtility]::HtmlEncode($loc.City)
            $country = [System.Web.HttpUtility]::HtmlEncode($loc.Country)
            $ip = [System.Web.HttpUtility]::HtmlEncode($loc.IP)
            $locationTableRows += "                    <tr><td>$city</td><td>$country</td><td>$ip</td></tr>`n"
        }
    }

    # Audit activity section
    $auditLogs = @($ForensicData.AuditLogs | Where-Object { $_ })

    # Mailbox section
    $delegates = @($ForensicData.MailboxAudit?.Delegates | Where-Object { $_ })
    $inboxRules = @($ForensicData.MailboxAudit?.InboxRules | Where-Object { $_ })

    $delegateRows = ''
    foreach ($d in $delegates) {
        $user = [System.Web.HttpUtility]::HtmlEncode("$($d.DelegateEmail)")
        $accessRights = [System.Web.HttpUtility]::HtmlEncode("$($d.AccessRights)")
        $delegateRows += "                    <tr><td>$user</td><td>$accessRights</td></tr>`n"
    }

    $inboxRuleRows = ''
    foreach ($r in $inboxRules) {
        $name = [System.Web.HttpUtility]::HtmlEncode("$($r.Name)")
        $fwd = [System.Web.HttpUtility]::HtmlEncode("$($r.ForwardTo)$($r.RedirectTo)")
        $delete = if ($r.DeleteMessage) { 'Yes' } else { 'No' }
        $enabled = if ($r.IsEnabled -eq $false) { 'No' } else { 'Yes' }
        $inboxRuleRows += "                    <tr><td>$name</td><td>$fwd</td><td>$delete</td><td>$enabled</td></tr>`n"
    }

    # Timeline of suspicious activities
    $timelineEntries = [System.Collections.Generic.List[PSCustomObject]]::new()

    foreach ($si in $risk.RiskySignIns.Details) {
        $ts = $si.CreatedDateTime
        if (-not $ts) { $ts = $si.Timestamp }
        $timelineEntries.Add([PSCustomObject]@{
            Timestamp   = $ts
            Category    = 'Risky Sign-In'
            Description = "Sign-in from IP $($si.IpAddress) - Risk: $($si.RiskLevelDuringSignIn)"
            Severity    = 'High'
        })
    }
    foreach ($pc in $risk.PasswordChanges.Details) {
        $ts = $pc.ActivityDateTime
        if (-not $ts) { $ts = $pc.Timestamp }
        $timelineEntries.Add([PSCustomObject]@{
            Timestamp   = $ts
            Category    = 'Password Change'
            Description = "$($pc.ActivityDisplayName)"
            Severity    = 'Medium'
        })
    }
    foreach ($mc in $risk.MFAChanges.Details) {
        $ts = $mc.ActivityDateTime
        if (-not $ts) { $ts = $mc.Timestamp }
        $timelineEntries.Add([PSCustomObject]@{
            Timestamp   = $ts
            Category    = 'MFA Change'
            Description = "$($mc.ActivityDisplayName)"
            Severity    = 'Medium'
        })
    }
    foreach ($ac in $risk.SuspiciousAppConsents.Details) {
        $ts = $ac.ActivityDateTime
        if (-not $ts) { $ts = $ac.Timestamp }
        $timelineEntries.Add([PSCustomObject]@{
            Timestamp   = $ts
            Category    = 'App Consent'
            Description = "$($ac.ActivityDisplayName)"
            Severity    = 'Medium'
        })
    }
    foreach ($rc in $risk.RoleChanges.Details) {
        $ts = $rc.ActivityDateTime
        if (-not $ts) { $ts = $rc.Timestamp }
        $timelineEntries.Add([PSCustomObject]@{
            Timestamp   = $ts
            Category    = 'Role Change'
            Description = "$($rc.ActivityDisplayName)"
            Severity    = 'High'
        })
    }

    $sortedTimeline = $timelineEntries | Sort-Object { $_.Timestamp }
    $timelineRows = ''
    foreach ($entry in $sortedTimeline) {
        $sevClass = switch ($entry.Severity) {
            'High'   { 'severity-high' }
            'Medium' { 'severity-medium' }
            default  { 'severity-low' }
        }
        $ts = [System.Web.HttpUtility]::HtmlEncode("$($entry.Timestamp)")
        $cat = [System.Web.HttpUtility]::HtmlEncode($entry.Category)
        $desc = [System.Web.HttpUtility]::HtmlEncode($entry.Description)
        $sev = [System.Web.HttpUtility]::HtmlEncode($entry.Severity)
        $timelineRows += "                    <tr><td>$ts</td><td>$cat</td><td>$desc</td><td class=`"$sevClass`">$sev</td></tr>`n"
    }

    # Remediation summary section
    $remediationHtml = ''
    if ($RemediationSummary -and $RemediationSummary.Count -gt 0) {
        $remediationRows = ''
        foreach ($action in $RemediationSummary.GetEnumerator() | Sort-Object Name) {
            $actionName = [System.Web.HttpUtility]::HtmlEncode($action.Key)
            $status = [System.Web.HttpUtility]::HtmlEncode("$($action.Value.Status)")
            $message = [System.Web.HttpUtility]::HtmlEncode("$($action.Value.Message)")
            $timestamp = [System.Web.HttpUtility]::HtmlEncode("$($action.Value.Timestamp)")
            $statusClass = switch ($action.Value.Status) {
                'Success' { 'severity-low' }
                'Failed'  { 'severity-high' }
                'Skipped' { 'severity-medium' }
                default   { '' }
            }
            $remediationRows += "                    <tr><td>$actionName</td><td class=`"$statusClass`">$status</td><td>$message</td><td>$timestamp</td></tr>`n"
        }

        $remediationHtml = @"

        <div class="section">
            <h2>&#128736; Remediation Actions</h2>
            <table>
                <thead>
                    <tr><th>Action</th><th>Status</th><th>Message</th><th>Timestamp</th></tr>
                </thead>
                <tbody>
$remediationRows
                </tbody>
            </table>
        </div>
"@
    }

    # Build the full HTML document
    $html = @"
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Account Compromise Remediation Report - $([System.Web.HttpUtility]::HtmlEncode($upn))</title>
    <style>
        :root {
            --color-high: #dc3545;
            --color-medium: #fd7e14;
            --color-low: #28a745;
            --color-bg: #f8f9fa;
            --color-border: #dee2e6;
            --color-header: #1a1a2e;
            --color-accent: #0d6efd;
        }
        * { margin: 0; padding: 0; box-sizing: border-box; }
        body {
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
            background: var(--color-bg);
            color: #212529;
            line-height: 1.6;
            padding: 0;
        }
        .report-header {
            background: var(--color-header);
            color: #fff;
            padding: 2rem 2.5rem;
        }
        .report-header h1 {
            font-size: 1.5rem;
            font-weight: 600;
            margin-bottom: 0.25rem;
        }
        .report-header .subtitle {
            font-size: 0.9rem;
            opacity: 0.8;
        }
        .user-info {
            display: flex;
            flex-wrap: wrap;
            gap: 2rem;
            background: #fff;
            border: 1px solid var(--color-border);
            border-radius: 6px;
            padding: 1.25rem 2rem;
            margin: 1.5rem 2rem 0;
        }
        .user-info .info-item { display: flex; flex-direction: column; }
        .user-info .info-label { font-size: 0.75rem; text-transform: uppercase; color: #6c757d; font-weight: 600; }
        .user-info .info-value { font-size: 1rem; font-weight: 500; }
        .container { max-width: 1200px; margin: 0 auto; padding: 1.5rem 2rem 3rem; }
        .section {
            background: #fff;
            border: 1px solid var(--color-border);
            border-radius: 6px;
            padding: 1.5rem 2rem;
            margin-bottom: 1.5rem;
        }
        .section h2 {
            font-size: 1.15rem;
            margin-bottom: 1rem;
            padding-bottom: 0.5rem;
            border-bottom: 2px solid var(--color-bg);
        }
        .risk-badge {
            display: inline-block;
            padding: 0.35rem 1rem;
            border-radius: 4px;
            font-weight: 700;
            font-size: 1rem;
            color: #fff;
        }
        .risk-badge.severity-high   { background: var(--color-high); }
        .risk-badge.severity-medium { background: var(--color-medium); }
        .risk-badge.severity-low    { background: var(--color-low); }
        .findings-list { list-style: none; padding: 0; }
        .findings-list li {
            padding: 0.4rem 0.75rem;
            margin-bottom: 0.35rem;
            border-left: 4px solid var(--color-border);
            border-radius: 2px;
        }
        .findings-list li.severity-high   { border-left-color: var(--color-high); background: #fff5f5; }
        .findings-list li.severity-medium { border-left-color: var(--color-medium); background: #fff8f0; }
        .findings-list li.severity-low    { border-left-color: var(--color-low); background: #f0fff4; }
        .stat-grid {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(180px, 1fr));
            gap: 1rem;
        }
        .stat-card {
            text-align: center;
            padding: 1rem;
            border-radius: 6px;
            border: 1px solid var(--color-border);
        }
        .stat-card .stat-value { font-size: 2rem; font-weight: 700; }
        .stat-card .stat-label { font-size: 0.8rem; color: #6c757d; text-transform: uppercase; }
        table {
            width: 100%;
            border-collapse: collapse;
            font-size: 0.9rem;
        }
        th, td {
            text-align: left;
            padding: 0.6rem 0.75rem;
            border-bottom: 1px solid var(--color-border);
        }
        th {
            background: var(--color-bg);
            font-weight: 600;
            font-size: 0.8rem;
            text-transform: uppercase;
            color: #495057;
        }
        tr:hover { background: #f1f3f5; }
        td.severity-high   { color: var(--color-high); font-weight: 600; }
        td.severity-medium { color: var(--color-medium); font-weight: 600; }
        td.severity-low    { color: var(--color-low); font-weight: 600; }
        .no-data { color: #6c757d; font-style: italic; padding: 1rem 0; }
        .footer {
            text-align: center;
            font-size: 0.8rem;
            color: #6c757d;
            padding: 1.5rem;
            border-top: 1px solid var(--color-border);
            margin-top: 2rem;
        }
        @media (max-width: 768px) {
            .user-info { flex-direction: column; gap: 0.75rem; }
            .container { padding: 1rem; }
            .stat-grid { grid-template-columns: repeat(2, 1fr); }
        }
    </style>
</head>
<body>
    <div class="report-header">
        <h1>&#128737; Account Compromise Remediation Report</h1>
        <p class="subtitle">Generated: $reportTime</p>
    </div>

    <div class="user-info">
        <div class="info-item">
            <span class="info-label">User Principal Name</span>
            <span class="info-value">$([System.Web.HttpUtility]::HtmlEncode($upn))</span>
        </div>
        <div class="info-item">
            <span class="info-label">Display Name</span>
            <span class="info-value">$([System.Web.HttpUtility]::HtmlEncode($displayName))</span>
        </div>
        <div class="info-item">
            <span class="info-label">Admin Account</span>
            <span class="info-value">$isAdmin</span>
        </div>
        <div class="info-item">
            <span class="info-label">Admin Roles</span>
            <span class="info-value">$([System.Web.HttpUtility]::HtmlEncode($adminRoles))</span>
        </div>
        <div class="info-item">
            <span class="info-label">Overall Risk</span>
            <span class="risk-badge $riskClass">$($risk.OverallRiskLevel)</span>
        </div>
    </div>

    <div class="container">

        <div class="section">
            <h2>&#128200; Executive Summary</h2>
            <p>Risk assessment for <strong>$([System.Web.HttpUtility]::HtmlEncode($upn))</strong> based on forensic data analysis (risk score: $($risk.RiskScore)).</p>
            <br>
            <ul class="findings-list">
            $execFindingsHtml
            </ul>
        </div>

        <div class="section">
            <h2>&#128272; Sign-In Analysis</h2>
            <div class="stat-grid">
                <div class="stat-card">
                    <div class="stat-value">$signInCount</div>
                    <div class="stat-label">Total Sign-Ins</div>
                </div>
                <div class="stat-card">
                    <div class="stat-value" style="color: var(--color-high);">$riskyCount</div>
                    <div class="stat-label">Risky Sign-Ins</div>
                </div>
                <div class="stat-card">
                    <div class="stat-value" style="color: var(--color-medium);">$failedCount</div>
                    <div class="stat-label">Failed Attempts</div>
                </div>
                <div class="stat-card">
                    <div class="stat-value">$locationCount</div>
                    <div class="stat-label">Unique Locations</div>
                </div>
            </div>
            $(if ($locationTableRows) { @"

            <br>
            <h3>Sign-In Locations</h3>
            <table>
                <thead>
                    <tr><th>City</th><th>Country</th><th>IP Address</th></tr>
                </thead>
                <tbody>
$locationTableRows
                </tbody>
            </table>
"@ } else { '<p class="no-data">No location data available.</p>' })
        </div>

        <div class="section">
            <h2>&#128221; Audit Activity Summary</h2>
            <div class="stat-grid">
                <div class="stat-card">
                    <div class="stat-value">$($auditLogs.Count)</div>
                    <div class="stat-label">Total Audit Events</div>
                </div>
                <div class="stat-card">
                    <div class="stat-value" style="color: var(--color-medium);">$($risk.PasswordChanges.Count)</div>
                    <div class="stat-label">Password Changes</div>
                </div>
                <div class="stat-card">
                    <div class="stat-value" style="color: var(--color-medium);">$($risk.MFAChanges.Count)</div>
                    <div class="stat-label">MFA Changes</div>
                </div>
                <div class="stat-card">
                    <div class="stat-value" style="color: var(--color-medium);">$($risk.SuspiciousAppConsents.Count)</div>
                    <div class="stat-label">App Consents</div>
                </div>
                <div class="stat-card">
                    <div class="stat-value" style="color: var(--color-high);">$($risk.RoleChanges.Count)</div>
                    <div class="stat-label">Role Changes</div>
                </div>
            </div>
        </div>

        <div class="section">
            <h2>&#128231; Mailbox Compromise Indicators</h2>
            $(if ($delegates.Count -gt 0) { @"

            <h3>Mailbox Delegates ($($delegates.Count))</h3>
            <table>
                <thead>
                    <tr><th>Delegate</th><th>Access Rights</th></tr>
                </thead>
                <tbody>
$delegateRows
                </tbody>
            </table>
            <br>
"@ } else { '<p class="no-data">No mailbox delegates found.</p>' })

            $(if ($risk.NewForwardingRules.Count -gt 0) { "<p class=`"severity-high`" style=`"padding:0.5rem;border-left:4px solid var(--color-high);background:#fff5f5;`"><strong>&#9888; Email forwarding detected!</strong> $($risk.NewForwardingRules.Count) forwarding configuration(s) found.</p><br>" } else { '' })

            $(if ($inboxRules.Count -gt 0) { @"

            <h3>Inbox Rules ($($inboxRules.Count))</h3>
            <table>
                <thead>
                    <tr><th>Rule Name</th><th>Forward To</th><th>Delete</th><th>Enabled</th></tr>
                </thead>
                <tbody>
$inboxRuleRows
                </tbody>
            </table>
"@ } else { '<p class="no-data">No inbox rules found.</p>' })
        </div>

        $(if ($sortedTimeline.Count -gt 0) { @"
        <div class="section">
            <h2>&#128337; Timeline of Suspicious Activities</h2>
            <table>
                <thead>
                    <tr><th>Timestamp</th><th>Category</th><th>Description</th><th>Severity</th></tr>
                </thead>
                <tbody>
$timelineRows
                </tbody>
            </table>
        </div>
"@ } else { @"
        <div class="section">
            <h2>&#128337; Timeline of Suspicious Activities</h2>
            <p class="no-data">No suspicious activities detected in the analysis period.</p>
        </div>
"@ })
$remediationHtml

        <div class="footer">
            <p>Account Compromise Remediation Report &mdash; Generated by ACR Toolkit &mdash; $reportTime</p>
            <p>This report is confidential and intended for authorized security personnel only.</p>
        </div>

    </div>
</body>
</html>
"@

    # Ensure output directory exists
    $outputDir = Split-Path $OutputPath -Parent
    if ($outputDir -and -not (Test-Path $outputDir)) {
        New-Item -ItemType Directory -Path $outputDir -Force | Out-Null
    }

    $html | Set-Content -Path $OutputPath -Encoding UTF8
    Write-Verbose "HTML report generated: $OutputPath"

    return $OutputPath
}

#endregion

Export-ModuleMember -Function @(
    'Export-ACRForensicData'
    'Get-ACRRiskIndicators'
    'New-ACRHtmlReport'
)
