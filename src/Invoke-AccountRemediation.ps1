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
    [switch]$SkipPreflight,

    [Parameter()]
    [switch]$DryRun,

    [Parameter()]
    [int]$MaxRetries = 3,

    [Parameter()]
    [int]$RetryDelaySeconds = 10,

    [Parameter()]
    [string[]]$Actions,

    [Parameter()]
    [string]$OutputPath = './output'
)

# ── Module Import ────────────────────────────────────────────────────────────
$modulesPath = Join-Path $PSScriptRoot 'modules'
foreach ($mod in @('ACR.Auth', 'ACR.Logging', 'ACR.Preflight', 'ACR.Forensics', 'ACR.Reporting', 'ACR.Remediation')) {
    Import-Module (Join-Path $modulesPath "$mod.psm1") -Force -ErrorAction Stop
}

# ── Ensure output directory exists ───────────────────────────────────────────
$OutputPath = [System.IO.Path]::GetFullPath($OutputPath)
if (-not (Test-Path $OutputPath)) {
    New-Item -Path $OutputPath -ItemType Directory -Force | Out-Null
}

# ── Helper: retry wrapper for throttled calls ────────────────────────────────
function Invoke-ACRWithRetry {
    param(
        [Parameter(Mandatory)][string]$ActionName,
        [Parameter(Mandatory)][scriptblock]$ScriptBlock,
        [int]$MaxAttempts = $MaxRetries,
        [int]$BaseDelay = $RetryDelaySeconds
    )
    for ($attempt = 1; $attempt -le $MaxAttempts; $attempt++) {
        try {
            return & $ScriptBlock
        } catch {
            $isThrottled = $false
            $retryAfter = $null
            $ex = $_.Exception
            if ($ex.Response) {
                $statusCode = [int]$ex.Response.StatusCode
                if ($statusCode -eq 429 -or $statusCode -eq 503) {
                    $isThrottled = $true
                    $retryAfter = $ex.Response.Headers['Retry-After']
                }
            }
            if (-not $isThrottled -and $_.ToString() -match '(429|Too Many Requests|503|Service Unavailable)') {
                $isThrottled = $true
            }
            if ($isThrottled -and $attempt -lt $MaxAttempts) {
                $delay = if ($retryAfter) { [int]$retryAfter } else { $BaseDelay * $attempt }
                Write-Host " [throttled — retrying in ${delay}s]" -ForegroundColor DarkYellow -NoNewline
                Start-Sleep -Seconds $delay
                continue
            }
            throw
        }
    }
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

    # ── 1b. Preflight Validation ─────────────────────────────────────────────
    if (-not $SkipPreflight) {
        Show-SectionHeader 'Preflight Validation'
        $preflight = Invoke-ACRPreflight -UserPrincipalName $UserPrincipalName -SkipAuditCheck
        Write-Host (Format-ACRPreflightReport -PreflightResult $preflight)

        if (-not $preflight.Ready) {
            Write-Host ''
            Write-Host '  [✗] Preflight validation FAILED. Blocking issues detected:' -ForegroundColor Red
            foreach ($b in $preflight.BlockingFailures) {
                Write-Host "      - $($b.Name): $($b.Message)" -ForegroundColor Red
            }
            Write-Host ''
            Write-Host '  Resolve the above issues or re-run with -SkipPreflight to bypass (not recommended).' -ForegroundColor Yellow
            return
        }

        if ($preflight.WarningCount -gt 0) {
            Write-Host "  [!] $($preflight.WarningCount) preflight warning(s). Review output above before proceeding." -ForegroundColor Yellow
            $confirm = Read-Host 'Proceed anyway? [y/N]'
            if ($confirm -notmatch '^[Yy]') {
                Write-Host '  Aborted by operator. No changes were made.' -ForegroundColor Yellow
                return
            }
        }
    } else {
        Write-Host '  [–] Preflight validation skipped (-SkipPreflight)' -ForegroundColor DarkYellow
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
        $forensicReportFile = Join-Path $OutputPath ("forensic-report-{0:yyyyMMdd-HHmmss}.html" -f (Get-Date))
        $reportPath = New-ACRHtmlReport -ForensicData $forensicData -UserContext $userContext -OutputPath $forensicReportFile
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

    if ($DryRun) {
        Write-Host '  [DRY RUN MODE] The following actions WOULD be executed, but will NOT run:' -ForegroundColor Magenta
        foreach ($key in $selectedKeys) {
            $def = $ActionDefinitions[$key]
            Write-Host "    • $key — $($def.Label)" -ForegroundColor Magenta
        }
        Write-Host ''
        Write-Host '  No changes made. Re-run without -DryRun to execute.' -ForegroundColor Magenta
        return
    }

    $results = [System.Collections.Generic.List[PSCustomObject]]::new()
    $total   = $selectedKeys.Count
    $current = 0

    foreach ($key in $selectedKeys) {
        $current++
        $def = $ActionDefinitions[$key]
        Write-Host "  [$current/$total] $($def.Label)..." -ForegroundColor White -NoNewline

        try {
            $result = Invoke-ACRWithRetry -ActionName $key -ScriptBlock $def.Block
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

            if ($key -eq 'ResetPassword' -and $status -eq 'Success' -and $result.Details -and $result.Details.NewPassword) {
                $newPw = $result.Details.NewPassword
                $credDir = Join-Path $OutputPath 'CREDENTIALS'
                if (-not (Test-Path $credDir)) { New-Item -ItemType Directory -Path $credDir -Force | Out-Null }
                $safeUpn = ($UPN -replace '[^\w\.\-]', '_')
                $credFile = Join-Path $credDir ("password-{0}-{1:yyyyMMdd-HHmmss}.txt" -f $safeUpn, (Get-Date))
                $credBody = @"
ACR — Temporary password for $UPN
Generated : $((Get-Date).ToUniversalTime().ToString('yyyy-MM-dd HH:mm:ss UTC'))
Operator  : $env:USERNAME
Tenant    : $((Get-MgContext).TenantId)

NEW PASSWORD: $newPw

Notes:
- The user MUST change this password on first sign-in (ForceChangePasswordNextSignIn = true).
- Deliver this password to the user ONLY via a secure, out-of-band channel (e.g. verified phone call, in-person, Authenticated Secure Messaging). Do NOT email it to the account being remediated.
- Delete this file once the password has been delivered.
"@
                Set-Content -Path $credFile -Value $credBody -Encoding UTF8
                try {
                    $acl = New-Object System.Security.AccessControl.FileSecurity
                    $acl.SetAccessRuleProtection($true, $false)
                    $me  = [System.Security.Principal.WindowsIdentity]::GetCurrent().User
                    $rule = New-Object System.Security.AccessControl.FileSystemAccessRule(
                        $me, 'FullControl', 'Allow')
                    $acl.AddAccessRule($rule)
                    Set-Acl -Path $credFile -AclObject $acl
                } catch {
                    Write-Warning "Could not harden ACL on $credFile : $($_.Exception.Message). File exists but may be readable by other local admins."
                }

                Write-Host ''
                Write-Host '  ┌──────────────────────────────────────────────────────────┐' -ForegroundColor Yellow
                Write-Host '  │  NEW PASSWORD (shown ONCE — copy now and deliver securely) │' -ForegroundColor Yellow
                Write-Host '  └──────────────────────────────────────────────────────────┘' -ForegroundColor Yellow
                Write-Host ''
                Write-Host "      $newPw" -ForegroundColor Cyan
                Write-Host ''
                Write-Host "  Also saved to: $credFile" -ForegroundColor Gray
                Write-Host '  Deliver via a secure out-of-band channel (verified phone, in-person, etc).' -ForegroundColor DarkYellow
                Write-Host '  Delete the credential file after delivery.' -ForegroundColor DarkYellow
                Write-Host ''
            }
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

    $remediationSummary = @{}
    foreach ($r in $results) {
        $remediationSummary[$r.Action] = @{
            Status    = $r.Status
            Message   = $r.Message
            Label     = $r.Label
            Timestamp = (Get-Date).ToUniversalTime()
        }
    }

    $postReportFile = Join-Path $OutputPath ("remediation-report-{0:yyyyMMdd-HHmmss}.html" -f (Get-Date))
    $postReportPath = New-ACRHtmlReport -ForensicData $forensicData -UserContext $userContext `
        -OutputPath $postReportFile -RemediationSummary $remediationSummary
    Write-Host "  [✓] Post-remediation report: $postReportPath" -ForegroundColor Green

} catch {
    Write-Host ''
    Write-Host '  [✗] Remediation run encountered an error:' -ForegroundColor Red
    Write-Host "      $($_.Exception.Message)" -ForegroundColor Red
    if ($_.InvocationInfo -and $_.InvocationInfo.PositionMessage) {
        Write-Host "      $($_.InvocationInfo.PositionMessage)" -ForegroundColor DarkGray
    }
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
