#Requires -Modules Pester

Describe 'ACR.Reporting Module' {

    BeforeAll {
        # Strip #Requires directives to avoid missing module errors
        $originalPath = Join-Path $PSScriptRoot '..\src\modules\ACR.Reporting.psm1'
        $moduleContent = Get-Content $originalPath -Raw
        $moduleContent = $moduleContent -replace '(?m)^#Requires\s.*$', ''
        $tempModulePath = Join-Path TestDrive: 'ACR.Reporting.psm1'
        Set-Content -Path $tempModulePath -Value $moduleContent -Encoding UTF8
        Import-Module $tempModulePath -Force

        # Helper to build a minimal forensic data object
        function script:New-TestForensicData {
            param(
                [array]$SignInLogs = @(),
                [array]$AuditLogs = @(),
                $MailboxAudit = $null,
                $UnifiedAuditLog = $null
            )

            if (-not $MailboxAudit) {
                $MailboxAudit = [PSCustomObject]@{
                    Delegates         = @()
                    InboxRules        = @()
                    FolderPermissions = @()
                    ForwardingConfig  = $null
                }
            }
            if (-not $UnifiedAuditLog) {
                $UnifiedAuditLog = [PSCustomObject]@{
                    Available = $false
                    Entries   = @()
                }
            }

            [PSCustomObject]@{
                SignInLogs      = $SignInLogs
                AuditLogs       = $AuditLogs
                MailboxAudit    = $MailboxAudit
                UnifiedAuditLog = $UnifiedAuditLog
            }
        }

        function script:New-TestUserContext {
            [PSCustomObject]@{
                UserPrincipalName = 'user@contoso.com'
                DisplayName       = 'Test User'
                UserId            = 'uid-123'
                IsAdmin           = $false
                IsExchangeAdmin   = $false
                AdminRoles        = @()
            }
        }
    }

    Context 'Export-ACRForensicData' {

        It 'Creates JSON and CSV files for each category' {
            $outPath = Join-Path TestDrive: 'export-test'
            $data = New-TestForensicData -SignInLogs @(
                [PSCustomObject]@{ Timestamp = '2024-01-01'; IpAddress = '1.2.3.4'; AppDisplayName = 'Test' }
            ) -AuditLogs @(
                [PSCustomObject]@{ Timestamp = '2024-01-01'; ActivityDisplayName = 'Reset password' }
            )

            $files = Export-ACRForensicData -ForensicData $data -OutputPath $outPath

            $files | Should -Not -BeNullOrEmpty
            # Should produce JSON files for categories with data
            $jsonFiles = $files | Where-Object { $_ -match '\.json$' }
            $jsonFiles.Count | Should -BeGreaterOrEqual 2
        }

        It 'Handles empty/null data' {
            $outPath = Join-Path TestDrive: 'export-empty'
            $data = New-TestForensicData

            # Should not throw even with empty data
            { Export-ACRForensicData -ForensicData $data -OutputPath $outPath } | Should -Not -Throw
        }
    }

    Context 'New-ACRHtmlReport' {

        It 'Generates valid HTML file' {
            $outPath = Join-Path TestDrive: 'report.html'
            $data = New-TestForensicData
            $ctx = New-TestUserContext

            $result = New-ACRHtmlReport -ForensicData $data -UserContext $ctx -OutputPath $outPath

            Test-Path $result | Should -BeTrue
            $html = Get-Content $result -Raw
            $html | Should -Match '<html'
            $html | Should -Match '</html>'
        }

        It 'Includes user info and risk indicators' {
            $outPath = Join-Path TestDrive: 'report-user.html'
            $data = New-TestForensicData
            $ctx = New-TestUserContext

            New-ACRHtmlReport -ForensicData $data -UserContext $ctx -OutputPath $outPath | Out-Null

            $html = Get-Content $outPath -Raw
            $html | Should -Match 'user@contoso.com'
            $html | Should -Match 'Test User'
            # Should contain risk level text
            $html | Should -Match '(High|Medium|Low)'
        }

        It 'Includes remediation summary when provided' {
            $outPath = Join-Path TestDrive: 'report-remediation.html'
            $data = New-TestForensicData
            $ctx = New-TestUserContext
            $remediation = @{
                Total   = 2
                Success = 1
                Failed  = 1
                Actions = @(
                    @{ name = 'ResetPassword'; status = 'Success'; message = 'Done' }
                    @{ name = 'RevokeTokens'; status = 'Failed'; message = 'Error' }
                )
            }

            New-ACRHtmlReport -ForensicData $data -UserContext $ctx -OutputPath $outPath -RemediationSummary $remediation | Out-Null

            $html = Get-Content $outPath -Raw
            $html | Should -Match '(ResetPassword|Remediation|Success|Failed)'
        }
    }

    Context 'Get-ACRRiskIndicators' {

        It 'Returns correct risk level for high-risk data' {
            $data = New-TestForensicData -SignInLogs @(
                [PSCustomObject]@{
                    RiskLevelDuringSignIn = 'high'
                    RiskState            = 'atRisk'
                    IpAddress            = '5.6.7.8'
                    Location             = $null
                    Status               = [PSCustomObject]@{ ErrorCode = 0 }
                    ResultType           = '0'
                }
            ) -AuditLogs @(
                [PSCustomObject]@{
                    ActivityDisplayName = 'Consent to application'
                    OperationName       = $null
                }
                [PSCustomObject]@{
                    ActivityDisplayName = 'Reset password'
                    OperationName       = $null
                }
            )
            $data.MailboxAudit = [PSCustomObject]@{
                Delegates        = @([PSCustomObject]@{ DelegateEmail = 'evil@bad.com' })
                InboxRules       = @([PSCustomObject]@{ ForwardTo = 'ext@evil.com'; ForwardAsAttachmentTo = $null; RedirectTo = $null; DeleteMessage = $false; MoveToFolder = $null })
                ForwardingConfig = [PSCustomObject]@{ ForwardingSmtpAddress = 'ext@evil.com'; ForwardingAddress = $null; DeliverToMailboxAndForward = $true }
            }

            $risk = Get-ACRRiskIndicators -ForensicData $data

            $risk.OverallRiskLevel | Should -Be 'High'
            $risk.RiskySignIns.Count | Should -BeGreaterThan 0
            $risk.NewForwardingRules.Count | Should -BeGreaterThan 0
        }

        It 'Returns Low for clean data' {
            $data = New-TestForensicData

            $risk = Get-ACRRiskIndicators -ForensicData $data

            $risk.OverallRiskLevel | Should -Be 'Low'
            $risk.RiskScore | Should -BeLessThan 2
        }

        It 'Handles null/empty forensic data' {
            $data = [PSCustomObject]@{
                SignInLogs      = $null
                AuditLogs       = $null
                MailboxAudit    = $null
                UnifiedAuditLog = $null
            }

            $risk = Get-ACRRiskIndicators -ForensicData $data

            $risk.OverallRiskLevel | Should -BeIn @('Low', 'Medium', 'High')
            $risk.RiskScore | Should -BeOfType [int]
        }
    }
}
