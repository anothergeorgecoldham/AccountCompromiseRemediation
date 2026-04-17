#Requires -Version 7.2

<#
.SYNOPSIS
    Interactive account compromise remediation script for Microsoft 365 / Entra ID.

.DESCRIPTION
    Provides a menu-based interface for remediating compromised user accounts.
    Supports interactive menu selection, -RunAll for full automated remediation,
    and -Actions for targeted action execution.

.PARAMETER UserPrincipalName
    The UPN of the compromised user account.

.PARAMETER TenantId
    Optional Entra ID tenant identifier.

.PARAMETER RunAll
    Run all applicable remediation actions without showing the interactive menu.

.PARAMETER SkipForensics
    Skip the forensic collection phase.

.PARAMETER Actions
    Array of specific action names to run (e.g., "ResetPassword","RevokeTokens","EnforceMFA").

.PARAMETER OutputPath
    Base path for logs, forensics, and reports. Defaults to ./output.

.EXAMPLE
    .\Invoke-AccountRemediation.ps1 -UserPrincipalName john@contoso.com

.EXAMPLE
    .\Invoke-AccountRemediation.ps1 -UserPrincipalName john@contoso.com -RunAll

.EXAMPLE
    .\Invoke-AccountRemediation.ps1 -UserPrincipalName john@contoso.com -Actions "ResetPassword","RevokeTokens","EnforceMFA"
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [string]$UserPrincipalName,

    [Parameter()]
    [string]$TenantId,

    [Parameter()]
    [switch]$RunAll,

    [Parameter()]
    [switch]$SkipForensics,

    [Parameter()]
    [string[]]$Actions,

    [Parameter()]
    [string]$OutputPath = './output'
)

# ── Module Import ────────────────────────────────────────────────────────────
$modulesPath = Join-Path $PSScriptRoot 'modules'
foreach ($mod in @('ACR.Auth', 'ACR.Logging', 'ACR.Forensics', 'ACR.Reporting', 'ACR.Remediation')) {
    Import-Module (Join-Path $modulesPath "$mod.psm1") -Force -ErrorAction Stop
}

# ── Ensure output directory exists ───────────────────────────────────────────
$OutputPath = [System.IO.Path]::GetFullPath($OutputPath)
if (-not (Test-Path $OutputPath)) {
    New-Item -Path $OutputPath -ItemType Directory -Force | Out-Null
}

# ── Helper: display banner ───────────────────────────────────────────────────
function Show-Banner {
    param([string]$DisplayName, [string]$UPN, [PSCustomObject]$UserContext)

    Write-Host ''
    Write-Host '╔══════════════════════════════════════════════════════════════╗' -ForegroundColor Cyan
    Write-Host '║          Account Compromise Remediation - Interactive       ║' -ForegroundColor Cyan
    Write-Host '╚══════════════════════════════════════════════════════════════╝' -ForegroundColor Cyan
    Write-Host ''
    Write-Host "Target User: $DisplayName ($UPN)" -ForegroundColor Yellow

    $accountType = if ($UserContext.IsAdmin) {
        $roles = ($UserContext.AdminRoles -join ', ')
        "Administrator ($roles)"
    } else {
        'Standard User'
    }
    Write-Host "Account Type: $accountType" -ForegroundColor Yellow
    Write-Host ''
}

# ── Helper: display section header ───────────────────────────────────────────
function Show-SectionHeader {
    param([string]$Title)
    Write-Host ''
    Write-Host ('═' * 63) -ForegroundColor DarkCyan
    Write-Host " $Title" -ForegroundColor Cyan
    Write-Host ('═' * 63) -ForegroundColor DarkCyan
}

# ── Action Map ───────────────────────────────────────────────────────────────
# Each entry: Label, ScriptBlock, RequiredRole ('' = all, 'Admin', 'ExchangeAdmin')
# $UPN and $UserId are set at runtime before invocation.
$ActionDefinitions = [ordered]@{
    'ResetPassword'              = @{ Label = 'Reset user password';                              Role = '';              Block = { Reset-ACRPassword -UserPrincipalName $UPN } }
    'RevokeTokens'               = @{ Label = 'Revoke refresh tokens';                            Role = '';              Block = { Revoke-ACRRefreshTokens -UserPrincipalName $UPN } }
    'EnforceMFA'                 = @{ Label = 'Enforce multi-factor authentication';              Role = '';              Block = { Enforce-ACRMFA -UserPrincipalName $UPN } }
    'RemoveAppPasswords'         = @{ Label = 'Remove app passwords';                             Role = '';              Block = { Remove-ACRAppPasswords -UserPrincipalName $UPN } }
    'RemoveMailboxDelegates'     = @{ Label = 'Remove mailbox delegates';                         Role = '';              Block = { Remove-ACRMailboxDelegates -UserPrincipalName $UPN } }
    'RemoveMailboxFolderPerms'   = @{ Label = 'Remove changed mailbox folder permissions';        Role = '';              Block = { Remove-ACRMailboxFolderPermissions -UserPrincipalName $UPN } }
    'RemoveEmailForwarding'      = @{ Label = 'Remove automatic email forwarding';                Role = '';              Block = { Remove-ACREmailForwarding -UserPrincipalName $UPN } }
    'RemoveOutlookAddins'        = @{ Label = 'Remove untrusted Outlook add-ins';                 Role = '';              Block = { Remove-ACROutlookAddins -UserPrincipalName $UPN } }
    'RemoveSafeSenders'          = @{ Label = 'Remove unknown Safe Senders entries';              Role = '';              Block = { Remove-ACRSafeSenders -UserPrincipalName $UPN } }
    'RemoveCalendarSharing'      = @{ Label = 'Remove external calendar sharing';                 Role = '';              Block = { Remove-ACRCalendarSharing -UserPrincipalName $UPN } }
    'RemoveMobileDevices'        = @{ Label = 'Remove unknown synced mobile devices';             Role = '';              Block = { Remove-ACRMobileDevices -UserPrincipalName $UPN } }
    'RemoveUserConsentApps'      = @{ Label = 'Remove user-consented enterprise apps';            Role = '';              Block = { Remove-ACRUserConsentApps -UserPrincipalName $UPN } }
    'RemovePowerAutomateFlows'   = @{ Label = 'Remove Power Automate workflows';                  Role = '';              Block = { Remove-ACRPowerAutomateFlows -UserPrincipalName $UPN } }
    'RemovePowerApps'            = @{ Label = 'Remove Power Apps';                                Role = '';              Block = { Remove-ACRPowerApps -UserPrincipalName $UPN } }
    'RemovePowerAppsSharing'     = @{ Label = 'Remove Power Apps sharing';                        Role = '';              Block = { Remove-ACRPowerAppsSharing -UserPrincipalName $UPN } }
    'RemoveSharingLinks'         = @{ Label = 'Remove SharePoint/OneDrive sharing links';         Role = '';              Block = { Remove-ACRSharePointSharingLinks -UserPrincipalName $UPN } }
    'RemoveTeamsGuests'          = @{ Label = 'Remove guests from Groups and Teams';              Role = '';              Block = { Remove-ACRTeamsGuests -UserPrincipalName $UPN } }
    'RemoveAdminConsentApps'     = @{ Label = 'Remove admin-consented enterprise apps';           Role = 'Admin';         Block = { Remove-ACRAdminConsentApps -UserId $UserId } }
    'RemoveAppRegSecrets'        = @{ Label = 'Remove app registration client secrets';           Role = 'Admin';         Block = { Remove-ACRAppRegistrationSecrets -UserId $UserId } }
    'RemoveExchangeRules'        = @{ Label = 'Remove modified journal/mail flow rules';          Role = 'ExchangeAdmin'; Block = { Remove-ACRExchangeRules -UserPrincipalName $UPN } }
}

# ── Main Execution ───────────────────────────────────────────────────────────
$logSession  = $null
$userContext = $null

try {
    # ── 1. Authentication ────────────────────────────────────────────────────
    Show-SectionHeader 'Authentication'
    $connectParams = @{}
    if ($TenantId) { $connectParams['TenantId'] = $TenantId }
    Connect-ACRInteractive @connectParams
    Write-Host '  [✓] Successfully connected to Microsoft Graph' -ForegroundColor Green

    # Connect to Exchange Online (for mailbox operations, transport rules, audit)
    $exoConnected = Connect-ACRExchangeOnline
    if ($exoConnected) {
        Write-Host '  [✓] Successfully connected to Exchange Online' -ForegroundColor Green
    } else {
        Write-Host '  [!] Exchange Online not connected — some actions will be limited' -ForegroundColor Yellow
    }

    # ── 2. User Context ──────────────────────────────────────────────────────
    Show-SectionHeader 'Retrieving User Context'
    $userContext = Get-ACRUserContext -UserPrincipalName $UserPrincipalName
    $UPN    = $userContext.UserPrincipalName
    $UserId = $userContext.UserId

    Show-Banner -DisplayName $userContext.DisplayName -UPN $UPN -UserContext $userContext

    # ── 3. Start Logging ─────────────────────────────────────────────────────
    $logSession = Start-ACRLog -OutputPath $OutputPath -UserPrincipalName $UPN -AlertSource 'Manual'
    Write-Host "  [✓] Log session started — $($logSession.SessionId)" -ForegroundColor Green

    # ── 4. Forensic Investigation ────────────────────────────────────────────
    $forensicData   = $null
    $riskIndicators = $null
    $reportPath     = $null

    if (-not $SkipForensics) {
        Show-SectionHeader 'Phase 1: Forensic Investigation'

        Write-Host '  Collecting forensic data...' -ForegroundColor Gray
        $forensicData = Invoke-ACRForensicCollection -UserPrincipalName $UPN
        Write-Host '  [✓] Forensic collection complete' -ForegroundColor Green

        Write-Host '  Exporting forensic data (JSON/CSV)...' -ForegroundColor Gray
        $exportedFiles = Export-ACRForensicData -ForensicData $forensicData -OutputPath $OutputPath
        Write-Host "  [✓] Exported $($exportedFiles.Count) data files" -ForegroundColor Green

        Write-Host '  Analyzing risk indicators...' -ForegroundColor Gray
        $riskIndicators = Get-ACRRiskIndicators -ForensicData $forensicData

        Write-Host ''
        Write-Host "  Risk Level : $($riskIndicators.OverallRiskLevel)" -ForegroundColor $(
            switch ($riskIndicators.OverallRiskLevel) {
                'Critical' { 'Red' }
                'High'     { 'DarkYellow' }
                'Medium'   { 'Yellow' }
                default    { 'Green' }
            }
        )
        if ($riskIndicators.PSObject.Properties['HighRiskCount']) {
            Write-Host "  High-risk indicators : $($riskIndicators.HighRiskCount)" -ForegroundColor DarkYellow
        }
        if ($riskIndicators.PSObject.Properties['MediumRiskCount']) {
            Write-Host "  Medium-risk indicators: $($riskIndicators.MediumRiskCount)" -ForegroundColor Yellow
        }

        Write-Host '  Generating forensic HTML report...' -ForegroundColor Gray
        $reportPath = New-ACRHtmlReport -ForensicData $forensicData -UserContext $userContext -OutputPath $OutputPath
        Write-Host "  [✓] Report saved: $reportPath" -ForegroundColor Green
    } else {
        Write-Host ''
        Write-Host '  [–] Forensic collection skipped (-SkipForensics)' -ForegroundColor DarkYellow
    }

    # ── 5. Build applicable action list ──────────────────────────────────────
    $applicableActions = [ordered]@{}
    foreach ($key in $ActionDefinitions.Keys) {
        $def = $ActionDefinitions[$key]
        $include = switch ($def.Role) {
            'Admin'         { $userContext.IsAdmin }
            'ExchangeAdmin' { $userContext.IsExchangeAdmin }
            default         { $true }
        }
        if ($include) {
            $applicableActions[$key] = $def
        }
    }

    # ── 6. Action Selection ──────────────────────────────────────────────────
    $selectedKeys = @()

    if ($RunAll) {
        $selectedKeys = @($applicableActions.Keys)
        Write-Host ''
        Write-Host "  RunAll: $($selectedKeys.Count) actions queued" -ForegroundColor Cyan

    } elseif ($Actions -and $Actions.Count -gt 0) {
        # Validate provided action names
        $allKnown = @($ActionDefinitions.Keys)
        $invalid = $Actions | Where-Object { $_ -notin $allKnown }
        if ($invalid) {
            throw "Unknown action name(s): $($invalid -join ', '). Valid names: $($allKnown -join ', ')"
        }
        $notApplicable = $Actions | Where-Object { $_ -notin @($applicableActions.Keys) }
        if ($notApplicable) {
            Write-Warning "Skipping actions not applicable to this user's role: $($notApplicable -join ', ')"
        }
        $selectedKeys = $Actions | Where-Object { $_ -in @($applicableActions.Keys) }

    } else {
        # ── Interactive Menu ─────────────────────────────────────────────────
        Show-SectionHeader 'Available Remediation Actions'
        $menuKeys = @($applicableActions.Keys)
        for ($i = 0; $i -lt $menuKeys.Count; $i++) {
            $key = $menuKeys[$i]
            $def = $applicableActions[$key]
            $tag = switch ($def.Role) {
                'Admin'         { ' [Admin]' }
                'ExchangeAdmin' { ' [ExchangeAdmin]' }
                default         { '' }
            }
            $num = ($i + 1).ToString().PadLeft(3)
            Write-Host " $num.$tag $($def.Label)" -ForegroundColor White
        }
        Write-Host ('═' * 63) -ForegroundColor DarkCyan
        Write-Host "Enter action numbers (comma-separated), 'A' for all, or 'Q' to quit:" -ForegroundColor Cyan

        $selection = Read-Host ' '
        $selection = $selection.Trim()

        if ($selection -eq 'Q' -or $selection -eq 'q') {
            Write-Host '  Remediation cancelled by operator.' -ForegroundColor Yellow
            return
        } elseif ($selection -eq 'A' -or $selection -eq 'a') {
            $selectedKeys = $menuKeys
        } else {
            $nums = $selection -split ',' | ForEach-Object { $_.Trim() }
            foreach ($n in $nums) {
                $idx = 0
                if ([int]::TryParse($n, [ref]$idx) -and $idx -ge 1 -and $idx -le $menuKeys.Count) {
                    $selectedKeys += $menuKeys[$idx - 1]
                } else {
                    Write-Warning "Ignoring invalid selection: $n"
                }
            }
        }
    }

    if ($selectedKeys.Count -eq 0) {
        Write-Host '  No actions selected. Exiting.' -ForegroundColor Yellow
        return
    }

    # ── 7. Execute Remediation ───────────────────────────────────────────────
    Show-SectionHeader 'Phase 2: Remediation Execution'

    $results = [System.Collections.Generic.List[PSCustomObject]]::new()
    $total   = $selectedKeys.Count
    $current = 0

    foreach ($key in $selectedKeys) {
        $current++
        $def = $ActionDefinitions[$key]
        Write-Host "  [$current/$total] $($def.Label)..." -ForegroundColor White -NoNewline

        try {
            $result = & $def.Block
            $status = if ($result -and $result.Status) { $result.Status } else { 'Success' }
            $msg    = if ($result -and $result.Message) { $result.Message } else { 'Completed' }

            Write-ACRAction -Action $key -Status $status -Message $msg -Target $UPN

            $color = switch ($status) {
                'Success' { 'Green' }
                'Warning' { 'Yellow' }
                'NoAction' { 'DarkYellow' }
                default   { 'Red' }
            }
            Write-Host " $status" -ForegroundColor $color

            $results.Add([PSCustomObject]@{
                Action  = $key
                Label   = $def.Label
                Status  = $status
                Message = $msg
            })
        } catch {
            Write-Host ' Failed' -ForegroundColor Red
            Write-ACRAction -Action $key -Status 'Failed' -Message $_.Exception.Message -Target $UPN
            $results.Add([PSCustomObject]@{
                Action  = $key
                Label   = $def.Label
                Status  = 'Failed'
                Message = $_.Exception.Message
            })
        }
    }

    # ── 8. Summary ───────────────────────────────────────────────────────────
    Show-SectionHeader 'Remediation Summary'

    $succeeded = ($results | Where-Object { $_.Status -eq 'Success' }).Count
    $failed    = ($results | Where-Object { $_.Status -eq 'Failed' }).Count
    $other     = $results.Count - $succeeded - $failed

    Write-Host ''
    Write-Host "  Total: $($results.Count)   Success: $succeeded   Failed: $failed   Other: $other" -ForegroundColor Cyan
    Write-Host ''

    foreach ($r in $results) {
        $color = switch ($r.Status) {
            'Success'  { 'Green' }
            'Failed'   { 'Red' }
            'NoAction' { 'DarkYellow' }
            default    { 'Yellow' }
        }
        $statusPad = $r.Status.PadRight(10)
        Write-Host "  [$statusPad] $($r.Label)" -ForegroundColor $color
        if ($r.Status -eq 'Failed') {
            Write-Host "               $($r.Message)" -ForegroundColor DarkGray
        }
    }

    # ── 9. Post-Remediation Report ───────────────────────────────────────────
    Show-SectionHeader 'Generating Post-Remediation Report'

    $remediationSummary = [PSCustomObject]@{
        Actions     = $results
        TotalCount  = $results.Count
        SuccessCount = $succeeded
        FailedCount  = $failed
        OtherCount   = $other
        CompletedAt  = (Get-Date).ToUniversalTime()
    }

    $postReportPath = New-ACRHtmlReport -ForensicData $forensicData -UserContext $userContext `
        -OutputPath $OutputPath -RemediationSummary $remediationSummary
    Write-Host "  [✓] Post-remediation report: $postReportPath" -ForegroundColor Green

} finally {
    # ── 10. Finalize ─────────────────────────────────────────────────────────
    Write-Host ''

    if ($logSession) {
        $logSummary = Stop-ACRLog
        if ($logSummary) {
            Write-Host '  [✓] Log session closed' -ForegroundColor Green
        }
    }

    Show-SectionHeader 'Output Files'
    Write-Host "  Base path : $OutputPath" -ForegroundColor Gray
    if ($reportPath) {
        Write-Host "  Forensic report     : $reportPath" -ForegroundColor Gray
    }
    if ($postReportPath) {
        Write-Host "  Remediation report  : $postReportPath" -ForegroundColor Gray
    }
    Write-Host ''

    try { Disconnect-ACR } catch {
        Write-Warning "Disconnect failed: $($_.Exception.Message)"
    }

    Write-Host '  [✓] Disconnected. Remediation session complete.' -ForegroundColor Green
    Write-Host ''
}
