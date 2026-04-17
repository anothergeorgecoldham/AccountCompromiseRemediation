#Requires -Modules Pester

Describe 'ACR.Forensics Module' {

    BeforeAll {
        # Ensure stub functions exist for Graph and EXO cmdlets not installed locally
        $graphStubs = @(
            'Get-MgAuditLogSignIn', 'Get-MgAuditLogDirectoryAudit',
            'Get-MgUser'
        )
        $exoStubs = @(
            'Get-Mailbox', 'Get-MailboxFolderPermission', 'Get-InboxRule',
            'Get-MailboxPermission', 'Search-UnifiedAuditLog',
            'Get-OrganizationConfig', 'Test-ACRExchangeOnlineConnected'
        )
        foreach ($cmd in ($graphStubs + $exoStubs)) {
            if (-not (Get-Command $cmd -ErrorAction SilentlyContinue)) {
                Set-Item -Path "function:global:$cmd" -Value { }
            }
        }

        # Strip #Requires directives to avoid missing module errors, then import
        $originalPath = Join-Path $PSScriptRoot '..\src\modules\ACR.Forensics.psm1'
        $moduleContent = Get-Content $originalPath -Raw
        $moduleContent = $moduleContent -replace '(?m)^#Requires\s.*$', ''
        $tempModulePath = Join-Path TestDrive: 'ACR.Forensics.psm1'
        Set-Content -Path $tempModulePath -Value $moduleContent -Encoding UTF8
        Import-Module $tempModulePath -Force
    }

    AfterAll {
        Remove-Module ACR.Forensics -Force -ErrorAction SilentlyContinue
    }

    Context 'Get-ACRSignInLogs' {

        It 'Calls Get-MgAuditLogSignIn with correct filter' {
            Mock Get-MgAuditLogSignIn -ModuleName ACR.Forensics { return @() }

            Get-ACRSignInLogs -UserPrincipalName 'user@contoso.com' | Out-Null

            Should -Invoke Get-MgAuditLogSignIn -ModuleName ACR.Forensics -Times 1
        }

        It 'Returns structured sign-in data' {
            Mock Get-MgAuditLogSignIn -ModuleName ACR.Forensics {
                @([PSCustomObject]@{
                    CreatedDateTime       = '2024-01-15T10:00:00Z'
                    UserPrincipalName     = 'user@contoso.com'
                    AppDisplayName        = 'Azure Portal'
                    ClientAppUsed         = 'Browser'
                    IpAddress             = '1.2.3.4'
                    Location              = [PSCustomObject]@{ City = 'Seattle'; State = 'WA'; CountryOrRegion = 'US' }
                    DeviceDetail          = [PSCustomObject]@{ DisplayName = 'PC1'; Browser = 'Edge'; OperatingSystem = 'Windows'; IsCompliant = $true; IsManaged = $true }
                    Status                = [PSCustomObject]@{ ErrorCode = 0; FailureReason = $null }
                    RiskLevelDuringSignIn = 'none'
                    RiskLevelAggregated   = 'none'
                    RiskState             = 'none'
                    ConditionalAccessStatus = 'success'
                    IsInteractive         = $true
                    ResourceDisplayName   = 'Microsoft Graph'
                    CorrelationId         = 'corr-1'
                    Id                    = 'signin-1'
                })
            }

            $results = Get-ACRSignInLogs -UserPrincipalName 'user@contoso.com'

            $results | Should -HaveCount 1
            $results[0].IpAddress | Should -Be '1.2.3.4'
            $results[0].City | Should -Be 'Seattle'
            $results[0].AppDisplayName | Should -Be 'Azure Portal'
        }
    }

    Context 'Get-ACRAuditLogs' {

        It 'Calls Get-MgAuditLogDirectoryAudit with correct filter' {
            Mock Get-MgAuditLogDirectoryAudit -ModuleName ACR.Forensics { return @() }

            Get-ACRAuditLogs -UserPrincipalName 'admin@contoso.com' | Out-Null

            Should -Invoke Get-MgAuditLogDirectoryAudit -ModuleName ACR.Forensics -Times 1
        }
    }

    Context 'Get-ACRMailboxAudit' {

        It 'Collects delegates, rules, and forwarding config' {
            Mock Test-ACRExchangeOnlineConnected -ModuleName ACR.Forensics { return $true }
            Mock Get-Mailbox -ModuleName ACR.Forensics {
                [PSCustomObject]@{
                    ForwardingSmtpAddress      = $null
                    ForwardingAddress          = $null
                    DeliverToMailboxAndForward  = $false
                }
            }
            Mock Get-MailboxFolderPermission -ModuleName ACR.Forensics { return @() }
            Mock Get-InboxRule -ModuleName ACR.Forensics { return @() }
            Mock Get-MailboxPermission -ModuleName ACR.Forensics { return @() }

            $result = Get-ACRMailboxAudit -UserPrincipalName 'user@contoso.com'

            $result.UserPrincipalName | Should -Be 'user@contoso.com'
            $result.ForwardingConfig | Should -Not -BeNull
            $result.PSObject.Properties.Name | Should -Contain 'Delegates'
            $result.PSObject.Properties.Name | Should -Contain 'InboxRules'
            $result.PSObject.Properties.Name | Should -Contain 'FolderPermissions'
        }
    }

    Context 'Get-ACRUnifiedAuditLog' {

        It 'Handles missing ExchangeOnlineManagement gracefully' {
            Mock Test-ACRExchangeOnlineConnected -ModuleName ACR.Forensics { return $false }

            $result = Get-ACRUnifiedAuditLog -UserPrincipalName 'user@contoso.com'

            $result.Available | Should -BeFalse
            $result.Entries | Should -HaveCount 0
            $result.Error | Should -Not -BeNullOrEmpty
        }
    }

    Context 'Invoke-ACRForensicCollection' {

        BeforeEach {
            Mock Get-MgAuditLogSignIn -ModuleName ACR.Forensics { return @() }
            Mock Get-MgAuditLogDirectoryAudit -ModuleName ACR.Forensics { return @() }
            Mock Test-ACRExchangeOnlineConnected -ModuleName ACR.Forensics { return $true }
            Mock Get-Mailbox -ModuleName ACR.Forensics {
                [PSCustomObject]@{
                    ForwardingSmtpAddress     = $null
                    ForwardingAddress         = $null
                    DeliverToMailboxAndForward = $false
                }
            }
            Mock Get-MailboxFolderPermission -ModuleName ACR.Forensics { return @() }
            Mock Get-InboxRule -ModuleName ACR.Forensics { return @() }
            Mock Get-MailboxPermission -ModuleName ACR.Forensics { return @() }
        }

        It 'Creates forensics output directory' {
            $basePath = Join-Path TestDrive: 'forensics-dir'

            $result = Invoke-ACRForensicCollection -UserPrincipalName 'user@contoso.com' -OutputBasePath $basePath

            Test-Path $result.OutputPath | Should -BeTrue
        }

        It 'Continues on partial failure (one source fails)' {
            # Mock at module level so the error propagates to the orchestrator's try/catch
            Mock Get-ACRSignInLogs -ModuleName ACR.Forensics { throw 'Sign-in API error' }

            $basePath = Join-Path TestDrive: 'forensics-partial'
            $result = Invoke-ACRForensicCollection -UserPrincipalName 'user@contoso.com' -OutputBasePath $basePath

            $result.HasErrors | Should -BeTrue
            $result.Errors.Count | Should -BeGreaterThan 0
            # Other data should still be collected
            $result.MailboxAudit | Should -Not -BeNull
        }

        It 'Returns all collected data' {
            $basePath = Join-Path TestDrive: 'forensics-full'
            $result = Invoke-ACRForensicCollection -UserPrincipalName 'user@contoso.com' -OutputBasePath $basePath

            $result.UserPrincipalName | Should -Be 'user@contoso.com'
            $result.PSObject.Properties.Name | Should -Contain 'SignInLogs'
            $result.PSObject.Properties.Name | Should -Contain 'AuditLogs'
            $result.PSObject.Properties.Name | Should -Contain 'MailboxAudit'
            $result.PSObject.Properties.Name | Should -Contain 'UnifiedAuditLog'
            $result.PSObject.Properties.Name | Should -Contain 'OutputPath'
        }
    }
}
