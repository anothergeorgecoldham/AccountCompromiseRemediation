#Requires -Version 7.2
<#
.SYNOPSIS
    Non-interactive account compromise remediation for automation platforms.

.DESCRIPTION
    Executes the full remediation workflow for a compromised user account.
    Designed to be called from Azure Logic Apps, Sentinel playbooks, or
    Azure Automation runbooks via Managed Identity. Outputs structured JSON
    to stdout for downstream consumption.

.PARAMETER UserPrincipalName
    The UPN of the compromised user account to remediate.

.PARAMETER CorrelationId
    Optional ID to correlate with the source alert or incident.

.PARAMETER AlertSource
    Source system that triggered the remediation (e.g., Sentinel, XDR).

.PARAMETER OutputPath
    Base directory for logs, forensic data, and reports.

.PARAMETER SkipForensics
    Skip forensic collection phase.

.PARAMETER MaxRetries
    Maximum retry attempts for Graph API throttling errors.

.PARAMETER RetryDelaySeconds
    Base delay in seconds between retries (multiplied by attempt number).

.EXAMPLE
    ./Invoke-AutoRemediation.ps1 -UserPrincipalName "user@contoso.com" -AlertSource "Sentinel" -CorrelationId "abc-123"
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory)]
    [string]$UserPrincipalName,

    [string]$CorrelationId = [guid]::NewGuid().ToString(),

    [string]$AlertSource = "Automation",

    [string]$OutputPath = "./output",

    [switch]$SkipForensics,

    [Parameter()]
    [switch]$SkipPreflight,

    [Parameter()]
    [switch]$DryRun,

    [int]$MaxRetries = 3,

    [int]$RetryDelaySeconds = 30
)

$ErrorActionPreference = 'Continue'

# --- Module Import ---
$modulesPath = Join-Path $PSScriptRoot 'modules'
foreach ($mod in @('ACR.Auth', 'ACR.Logging', 'ACR.Preflight', 'ACR.Forensics', 'ACR.Reporting', 'ACR.Remediation')) {
    Import-Module (Join-Path $modulesPath "$mod.psm1") -Force -ErrorAction Stop
}

# --- Output Directory ---
if (-not (Test-Path $OutputPath)) {
    New-Item -Path $OutputPath -ItemType Directory -Force | Out-Null
}

# --- Helper: Invoke-WithRetry ---
function Invoke-WithRetry {
    param(
        [Parameter(Mandatory)][string]$ActionName,
        [Parameter(Mandatory)][scriptblock]$ScriptBlock,
        [int]$MaxAttempts = $MaxRetries,
        [int]$BaseDelay = $RetryDelaySeconds
    )

    for ($attempt = 1; $attempt -le $MaxAttempts; $attempt++) {
        try {
            $result = & $ScriptBlock
            return $result
        }
        catch {
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
                Write-Warning "[$ActionName] Throttled (attempt $attempt/$MaxAttempts). Retrying in ${delay}s..."
                Write-ACRAction -Action $ActionName -Status 'Retry' -Message "Throttled, retrying in ${delay}s (attempt $attempt/$MaxAttempts)"
                Start-Sleep -Seconds $delay
                continue
            }

            throw
        }
    }
}

# --- State ---
$actionResults = [System.Collections.Generic.List[object]]::new()
$errors = [System.Collections.Generic.List[object]]::new()
$successCount = 0
$failedCount = 0
$skippedCount = 0
$warningCount = 0
$forensicsPath = $null
$reportPath = $null
$riskLevel = 'Unknown'
$overallStatus = 'Failed'
$exitCode = 2
$userContext = $null

try {
    # --- Step 1: Authentication ---
    Write-Verbose "Authenticating via Managed Identity..."
    try {
        Connect-ACRManagedIdentity
    }
    catch {
        $errorJson = @{
            status        = 'Failed'
            correlationId = $CorrelationId
            error         = "Authentication failed: $($_.Exception.Message)"
            timestamp     = (Get-Date -Format 'o')
        } | ConvertTo-Json -Depth 5
        Write-Output $errorJson
        exit 2
    }

    # Connect to Exchange Online via Managed Identity
    Write-Verbose "Connecting to Exchange Online via Managed Identity..."
    $exoConnected = Connect-ACRExchangeOnlineMI
    if (-not $exoConnected) {
        Write-Warning "Exchange Online not connected — mailbox and transport rule actions will be limited."
    }

    # --- Step 1b: Preflight Validation ---
    $preflightSummary = $null
    if (-not $SkipPreflight) {
        Write-Verbose "Running preflight validation..."
        $preflight = Invoke-ACRPreflight -UserPrincipalName $UserPrincipalName -SkipAuditCheck
        $preflightSummary = @{
            ready    = $preflight.Ready
            passes   = $preflight.PassCount
            warnings = $preflight.WarningCount
            failures = $preflight.FailCount
            checks   = @($preflight.Checks | ForEach-Object {
                @{ name = $_.Name; status = $_.Status; message = $_.Message; blocking = $_.Blocking }
            })
        }

        if (-not $preflight.Ready) {
            $errorJson = @{
                status            = 'Failed'
                correlationId     = $CorrelationId
                userPrincipalName = $UserPrincipalName
                error             = "Preflight validation failed. Blocking issues: $(($preflight.BlockingFailures | ForEach-Object { $_.Name }) -join ', ')"
                preflight         = $preflightSummary
                timestamp         = (Get-Date -Format 'o')
            } | ConvertTo-Json -Depth 8
            Write-Output $errorJson
            exit 2
        }
    }

    # --- Step 2: User Context ---
    Write-Verbose "Retrieving user context for $UserPrincipalName..."
    try {
        $userContext = Get-ACRUserContext -UserPrincipalName $UserPrincipalName
    }
    catch {
        $errorJson = @{
            status             = 'Failed'
            correlationId      = $CorrelationId
            userPrincipalName  = $UserPrincipalName
            error              = "Failed to retrieve user context: $($_.Exception.Message)"
            timestamp          = (Get-Date -Format 'o')
        } | ConvertTo-Json -Depth 5
        Write-Output $errorJson
        exit 2
    }

    # --- Step 3: Start Logging ---
    Write-Verbose "Starting log session..."
    Start-ACRLog -OutputPath $OutputPath -UserPrincipalName $UserPrincipalName -CorrelationId $CorrelationId -AlertSource $AlertSource
    $logSession = Get-ACRLogSession
    $actionLogPath = if ($logSession) { $logSession.ActionLogPath } else { $null }
    $rollbackJournalPath = if ($logSession) { $logSession.RollbackJournalPath } else { $null }

    # --- Step 4: Forensic Investigation ---
    $forensicData = $null
    $riskIndicators = $null

    if (-not $SkipForensics) {
        Write-Verbose "Running forensic collection..."
        try {
            $forensicData = Invoke-WithRetry -ActionName 'ForensicCollection' -ScriptBlock {
                Invoke-ACRForensicCollection -UserPrincipalName $UserPrincipalName -OutputBasePath (Join-Path $OutputPath 'forensics')
            }
            $forensicsPath = Join-Path $OutputPath 'forensics'

            Export-ACRForensicData -ForensicData $forensicData -OutputPath $forensicsPath

            $riskIndicators = Get-ACRRiskIndicators -ForensicData $forensicData
            if ($riskIndicators -and $riskIndicators.RiskLevel) {
                $riskLevel = $riskIndicators.RiskLevel
            }

            $reportPath = Join-Path $OutputPath 'report.html'
            New-ACRHtmlReport -ForensicData $forensicData -UserContext $userContext -OutputPath $reportPath

            Write-ACRAction -Action 'ForensicCollection' -Status 'Success' -Message 'Forensic data collected and report generated'
        }
        catch {
            Write-Warning "Forensic collection failed: $($_.Exception.Message)"
            Write-ACRAction -Action 'ForensicCollection' -Status 'Warning' -Message "Forensic collection failed: $($_.Exception.Message)"
        }
    }
    else {
        Write-Verbose "Skipping forensic collection."
    }

    # --- Step 5: Build Remediation Action List ---
    $standardActions = @(
        @{ Name = 'ResetPassword';                   Function = { Reset-ACRPassword -UserPrincipalName $UserPrincipalName } }
        @{ Name = 'RevokeRefreshTokens';             Function = { Revoke-ACRRefreshTokens -UserPrincipalName $UserPrincipalName } }
        @{ Name = 'EnforceMFA';                      Function = { Enforce-ACRMFA -UserPrincipalName $UserPrincipalName } }
        @{ Name = 'RemoveAppPasswords';              Function = { Remove-ACRAppPasswords -UserPrincipalName $UserPrincipalName } }
        @{ Name = 'RemoveMailboxDelegates';          Function = { Remove-ACRMailboxDelegates -UserPrincipalName $UserPrincipalName } }
        @{ Name = 'RemoveMailboxFolderPermissions';  Function = { Remove-ACRMailboxFolderPermissions -UserPrincipalName $UserPrincipalName } }
        @{ Name = 'RemoveEmailForwarding';           Function = { Remove-ACREmailForwarding -UserPrincipalName $UserPrincipalName } }
        @{ Name = 'RemoveOutlookAddins';             Function = { Remove-ACROutlookAddins -UserPrincipalName $UserPrincipalName } }
        @{ Name = 'RemoveSafeSenders';               Function = { Remove-ACRSafeSenders -UserPrincipalName $UserPrincipalName } }
        @{ Name = 'RemoveCalendarSharing';           Function = { Remove-ACRCalendarSharing -UserPrincipalName $UserPrincipalName } }
        @{ Name = 'RemoveMobileDevices';             Function = { Remove-ACRMobileDevices -UserPrincipalName $UserPrincipalName } }
        @{ Name = 'RemoveUserConsentApps';           Function = { Remove-ACRUserConsentApps -UserPrincipalName $UserPrincipalName } }
        @{ Name = 'RemovePowerAutomateFlows';        Function = { Remove-ACRPowerAutomateFlows -UserPrincipalName $UserPrincipalName } }
        @{ Name = 'RemovePowerApps';                 Function = { Remove-ACRPowerApps -UserPrincipalName $UserPrincipalName } }
        @{ Name = 'RemovePowerAppsSharing';          Function = { Remove-ACRPowerAppsSharing -UserPrincipalName $UserPrincipalName } }
        @{ Name = 'RemoveSharePointSharingLinks';    Function = { Remove-ACRSharePointSharingLinks -UserPrincipalName $UserPrincipalName } }
        @{ Name = 'RemoveTeamsGuests';               Function = { Remove-ACRTeamsGuests -UserPrincipalName $UserPrincipalName } }
    )

    $adminActions = @(
        @{ Name = 'RemoveAdminConsentApps';        Function = { Remove-ACRAdminConsentApps -UserId $userContext.UserId } }
        @{ Name = 'RemoveAppRegistrationSecrets';  Function = { Remove-ACRAppRegistrationSecrets -UserId $userContext.UserId } }
    )

    $exchangeAdminActions = @(
        @{ Name = 'RemoveExchangeRules';  Function = { Remove-ACRExchangeRules -UserPrincipalName $UserPrincipalName } }
    )

    $allActions = [System.Collections.Generic.List[object]]::new()
    $standardActions | ForEach-Object { $allActions.Add($_) }

    if ($userContext.IsAdmin) {
        $adminActions | ForEach-Object { $allActions.Add($_) }
    }
    else {
        foreach ($a in $adminActions) {
            $skippedCount++
            $actionResults.Add(@{ name = $a.Name; status = 'Skipped'; message = 'User is not an admin' })
            Write-ACRAction -Action $a.Name -Status 'Skipped' -Message 'User is not an admin'
        }
    }

    if ($userContext.IsExchangeAdmin) {
        $exchangeAdminActions | ForEach-Object { $allActions.Add($_) }
    }
    else {
        foreach ($a in $exchangeAdminActions) {
            $skippedCount++
            $actionResults.Add(@{ name = $a.Name; status = 'Skipped'; message = 'User is not an Exchange admin' })
            Write-ACRAction -Action $a.Name -Status 'Skipped' -Message 'User is not an Exchange admin'
        }
    }

    # --- Step 6: Execute Remediation Actions ---
    if ($DryRun) {
        Write-Verbose "DRY RUN: skipping execution of $($allActions.Count) action(s)."
        foreach ($action in $allActions) {
            $actionResults.Add(@{ name = $action.Name; status = 'DryRun'; message = 'DryRun — not executed' })
            Write-ACRAction -Action $action.Name -Status 'DryRun' -Message 'DryRun — not executed'
        }
    } else {
        Write-Verbose "Executing $($allActions.Count) remediation actions..."
        foreach ($action in $allActions) {
            try {
                $actionResult = Invoke-WithRetry -ActionName $action.Name -ScriptBlock $action.Function
                $successCount++
                $actionResults.Add(@{ name = $action.Name; status = 'Success'; message = 'Completed successfully' })
                Write-ACRAction -Action $action.Name -Status 'Success' -Message 'Completed successfully'

                if ($action.Name -eq 'ResetPassword' -and $actionResult -and $actionResult.Details -and $actionResult.Details.NewPassword) {
                    try {
                        $credDir = Join-Path $OutputPath 'CREDENTIALS'
                        if (-not (Test-Path $credDir)) { New-Item -ItemType Directory -Path $credDir -Force | Out-Null }
                        $safeUpn = ($UserPrincipalName -replace '[^\w\.\-]', '_')
                        $credFile = Join-Path $credDir ("password-{0}-{1}.txt" -f $safeUpn, $CorrelationId)
                        $credBody = "ACR auto-remediation temporary password`r`nUser: $UserPrincipalName`r`nGenerated: $((Get-Date).ToUniversalTime().ToString('o'))`r`nCorrelationId: $CorrelationId`r`n`r`nNEW PASSWORD: $($actionResult.Details.NewPassword)`r`n`r`nDeliver to the user via a secure out-of-band channel. Delete this file after delivery."
                        Set-Content -Path $credFile -Value $credBody -Encoding UTF8
                        try {
                            $acl = New-Object System.Security.AccessControl.FileSecurity
                            $acl.SetAccessRuleProtection($true, $false)
                            $me = [System.Security.Principal.WindowsIdentity]::GetCurrent().User
                            $acl.AddAccessRule((New-Object System.Security.AccessControl.FileSystemAccessRule($me, 'FullControl', 'Allow')))
                            Set-Acl -Path $credFile -AclObject $acl
                        } catch {
                            Write-Warning "Could not harden ACL on credential file: $($_.Exception.Message)"
                        }
                        Write-Verbose "New password written to $credFile"
                    } catch {
                        Write-Warning "Failed to persist new password: $($_.Exception.Message)"
                    }
                }
            }
            catch {
                $failedCount++
                $errMsg = $_.Exception.Message
                $actionResults.Add(@{ name = $action.Name; status = 'Failed'; message = $errMsg })
                $errors.Add(@{ action = $action.Name; error = $errMsg })
                Write-ACRAction -Action $action.Name -Status 'Failed' -Message $errMsg
                Write-Warning "Action '$($action.Name)' failed: $errMsg"
            }
        }
    }

    # --- Step 7: Post-Remediation Report ---
    Write-Verbose "Generating post-remediation report..."
    try {
        $remediationSummary = @{
            Total   = $actionResults.Count
            Success = $successCount
            Failed  = $failedCount
            Skipped = $skippedCount
            Warning = $warningCount
            Actions = $actionResults
        }

        $postReportPath = Join-Path $OutputPath 'remediation-report.html'
        New-ACRHtmlReport -ForensicData $forensicData -UserContext $userContext -OutputPath $postReportPath -RemediationSummary $remediationSummary
        $reportPath = $postReportPath
    }
    catch {
        Write-Warning "Post-remediation report generation failed: $($_.Exception.Message)"
    }

    # --- Determine Overall Status ---
    if ($failedCount -eq 0) {
        $overallStatus = 'Success'
        $exitCode = 0
    }
    else {
        $overallStatus = 'PartialSuccess'
        $exitCode = 1
    }
}
catch {
    $overallStatus = 'Failed'
    $exitCode = 2
    $errors.Add(@{ action = 'Global'; error = $_.Exception.Message })
    Write-Warning "Critical failure: $($_.Exception.Message)"
}
finally {
    # --- Step 8: Finalize Logging ---
    try { Stop-ACRLog } catch { Write-Verbose "Stop-ACRLog: $($_.Exception.Message)" }
    try { Disconnect-ACR } catch { Write-Verbose "Disconnect-ACR: $($_.Exception.Message)" }

    # --- Step 9: Output Structured JSON ---
    $result = [ordered]@{
        status              = $overallStatus
        correlationId       = $CorrelationId
        userPrincipalName   = $UserPrincipalName
        alertSource         = $AlertSource
        timestamp           = (Get-Date -Format 'o')
        summary             = [ordered]@{
            total   = $actionResults.Count
            success = $successCount
            failed  = $failedCount
            skipped = $skippedCount
            warning = $warningCount
        }
        riskLevel           = $riskLevel
        forensicsPath       = $forensicsPath
        actionLogPath       = $actionLogPath
        rollbackJournalPath = $rollbackJournalPath
        reportPath          = $reportPath
        actions             = @($actionResults)
        errors              = @($errors)
        preflight           = $preflightSummary
    }

    Write-Output ($result | ConvertTo-Json -Depth 10)
}

exit $exitCode
