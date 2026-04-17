#Requires -Modules Pester

Describe 'ACR.Remediation Module' {

    BeforeAll {
        # Ensure stub functions exist for all Graph and EXO cmdlets
        $graphStubs = @(
            'Get-MgUser', 'Update-MgUser', 'Revoke-MgUserSignInSession',
            'Get-MgUserAuthenticationMethod', 'Get-MgUserOauth2PermissionGrant',
            'Remove-MgOauth2PermissionGrant', 'Get-MgOauth2PermissionGrant',
            'Get-MgUserMemberOf', 'Invoke-MgGraphRequest'
        )
        $exoStubs = @(
            'Get-MailboxPermission', 'Remove-MailboxPermission',
            'Get-RecipientPermission', 'Remove-RecipientPermission',
            'Get-MailboxFolderPermission', 'Remove-MailboxFolderPermission',
            'Get-Mailbox', 'Set-Mailbox', 'Get-InboxRule', 'Remove-InboxRule',
            'Get-MailboxJunkEmailConfiguration', 'Set-MailboxJunkEmailConfiguration',
            'Get-App', 'Get-OrganizationConfig',
            'Test-ACRExchangeOnlineConnected'
        )
        foreach ($cmd in ($graphStubs + $exoStubs)) {
            if (-not (Get-Command $cmd -ErrorAction SilentlyContinue)) {
                Set-Item -Path "function:global:$cmd" -Value { }
            }
        }

        # Load Logging module normally (no missing dependencies)
        $loggingPath = Join-Path $PSScriptRoot '..\src\modules\ACR.Logging.psm1'
        Import-Module $loggingPath -Force

        # Strip #Requires for Remediation module
        $originalPath = Join-Path $PSScriptRoot '..\src\modules\ACR.Remediation.psm1'
        $moduleContent = Get-Content $originalPath -Raw
        $moduleContent = $moduleContent -replace '(?m)^#Requires\s.*$', ''
        $tempModulePath = Join-Path TestDrive: 'ACR.Remediation.psm1'
        Set-Content -Path $tempModulePath -Value $moduleContent -Encoding UTF8
        Import-Module $tempModulePath -Force
    }

    AfterAll {
        Remove-Module ACR.Remediation -Force -ErrorAction SilentlyContinue
        Remove-Module ACR.Logging -Force -ErrorAction SilentlyContinue
    }

    BeforeEach {
        # Start a fresh log session for each test so Write-ACRAction doesn't throw
        Mock Start-Transcript -ModuleName ACR.Logging {}
        Mock Stop-Transcript -ModuleName ACR.Logging {}
        $testDir = Join-Path TestDrive: "rem-$(Get-Random)"
        Start-ACRLog -OutputPath $testDir -UserPrincipalName 'test@contoso.com' | Out-Null
    }

    AfterEach {
        try { Stop-ACRLog } catch {}
    }

    Context 'Reset-ACRPassword' {

        It 'Calls Update-MgUser and logs action' {
            Mock Update-MgUser -ModuleName ACR.Remediation {}

            $result = Reset-ACRPassword -UserPrincipalName 'user@contoso.com'

            $result.Status | Should -Be 'Success'
            Should -Invoke Update-MgUser -ModuleName ACR.Remediation -Times 1
        }

        It 'Returns a result object with Status property' {
            Mock Update-MgUser -ModuleName ACR.Remediation {}

            $result = Reset-ACRPassword -UserPrincipalName 'user@contoso.com'

            $result.PSObject.Properties.Name | Should -Contain 'Status'
            $result.PSObject.Properties.Name | Should -Contain 'Message'
        }

        It 'Handles errors without throwing' {
            Mock Update-MgUser -ModuleName ACR.Remediation { throw 'Graph API error' }

            $result = Reset-ACRPassword -UserPrincipalName 'user@contoso.com'

            $result.Status | Should -Be 'Failed'
            $result.Message | Should -Match 'failed'
        }
    }

    Context 'Revoke-ACRRefreshTokens' {

        It 'Calls the correct Graph API' {
            Mock Revoke-MgUserSignInSession -ModuleName ACR.Remediation { return @{ Value = $true } }

            $result = Revoke-ACRRefreshTokens -UserPrincipalName 'user@contoso.com'

            $result.Status | Should -Be 'Success'
            Should -Invoke Revoke-MgUserSignInSession -ModuleName ACR.Remediation -Times 1
        }

        It 'Returns a result object with Status property' {
            Mock Revoke-MgUserSignInSession -ModuleName ACR.Remediation { return @{ Value = $true } }

            $result = Revoke-ACRRefreshTokens -UserPrincipalName 'user@contoso.com'

            $result.Status | Should -BeIn @('Success', 'Failed', 'Skipped', 'Warning')
        }

        It 'Handles errors without throwing' {
            Mock Revoke-MgUserSignInSession -ModuleName ACR.Remediation { throw 'Token revocation error' }

            $result = Revoke-ACRRefreshTokens -UserPrincipalName 'user@contoso.com'

            $result.Status | Should -Be 'Failed'
        }
    }

    Context 'Remove-ACRMailboxDelegates' {

        It 'Removes delegates and creates rollback entry' {
            Mock Test-ACRExchangeOnlineConnected -ModuleName ACR.Remediation { return $true }
            Mock Get-MailboxPermission -ModuleName ACR.Remediation {
                @([PSCustomObject]@{
                    User         = 'delegate@contoso.com'
                    AccessRights = @('FullAccess')
                    IsInherited  = $false
                })
            }
            Mock Get-RecipientPermission -ModuleName ACR.Remediation { return @() }
            Mock Remove-MailboxPermission -ModuleName ACR.Remediation {}

            $result = Remove-ACRMailboxDelegates -UserPrincipalName 'user@contoso.com'

            $result.Status | Should -Be 'Success'
            Should -Invoke Remove-MailboxPermission -ModuleName ACR.Remediation -Times 1

            # Verify rollback entry was created
            $session = Get-ACRLogSession
            $session.RollbackEntries.Count | Should -BeGreaterThan 0
        }

        It 'Returns a result object with Status property' {
            Mock Test-ACRExchangeOnlineConnected -ModuleName ACR.Remediation { return $true }
            Mock Get-MailboxPermission -ModuleName ACR.Remediation { return @() }
            Mock Get-RecipientPermission -ModuleName ACR.Remediation { return @() }

            $result = Remove-ACRMailboxDelegates -UserPrincipalName 'user@contoso.com'

            $result.PSObject.Properties.Name | Should -Contain 'Status'
        }
    }

    Context 'Remove-ACREmailForwarding' {

        It 'Detects and removes forwarding rules' {
            Mock Test-ACRExchangeOnlineConnected -ModuleName ACR.Remediation { return $true }
            Mock Get-Mailbox -ModuleName ACR.Remediation {
                [PSCustomObject]@{
                    ForwardingSmtpAddress     = $null
                    ForwardingAddress         = $null
                    DeliverToMailboxAndForward = $false
                }
            }
            Mock Set-Mailbox -ModuleName ACR.Remediation {}
            Mock Get-InboxRule -ModuleName ACR.Remediation {
                @([PSCustomObject]@{
                    Name                  = 'Fwd to ext'
                    RuleIdentity          = 'rule-1'
                    ForwardTo             = @('ext@evil.com')
                    RedirectTo            = $null
                    ForwardAsAttachmentTo = $null
                })
            }
            Mock Remove-InboxRule -ModuleName ACR.Remediation {}

            $result = Remove-ACREmailForwarding -UserPrincipalName 'user@contoso.com'

            $result.Status | Should -Be 'Success'
            Should -Invoke Remove-InboxRule -ModuleName ACR.Remediation -Times 1
        }

        It 'Handles errors without throwing' {
            Mock Test-ACRExchangeOnlineConnected -ModuleName ACR.Remediation { return $true }
            Mock Get-Mailbox -ModuleName ACR.Remediation { throw 'Mailbox not found' }

            $result = Remove-ACREmailForwarding -UserPrincipalName 'missing@contoso.com'

            $result.Status | Should -Be 'Failed'
        }
    }

    Context 'Remove-ACRUserConsentApps' {

        It 'Removes OAuth2 permission grants' {
            Mock Get-MgUserOauth2PermissionGrant -ModuleName ACR.Remediation {
                @(
                    [PSCustomObject]@{ Id = 'g1'; ClientId = 'c1'; Scope = 'User.Read'; ConsentType = 'Principal' }
                    [PSCustomObject]@{ Id = 'g2'; ClientId = 'c2'; Scope = 'Mail.Read'; ConsentType = 'Principal' }
                )
            }
            Mock Remove-MgOauth2PermissionGrant -ModuleName ACR.Remediation {}

            $result = Remove-ACRUserConsentApps -UserPrincipalName 'user@contoso.com'

            $result.Status | Should -Be 'Success'
            Should -Invoke Remove-MgOauth2PermissionGrant -ModuleName ACR.Remediation -Times 2
        }

        It 'Returns a result object with Status property' {
            Mock Get-MgUserOauth2PermissionGrant -ModuleName ACR.Remediation { return @() }

            $result = Remove-ACRUserConsentApps -UserPrincipalName 'user@contoso.com'

            $result.Status | Should -BeIn @('Success', 'Failed', 'Skipped', 'Warning')
        }
    }

    Context 'Remove-ACRAdminConsentApps' {

        It 'Skips for non-admin users' {
            Mock Get-MgUserMemberOf -ModuleName ACR.Remediation {
                @([PSCustomObject]@{
                    AdditionalProperties = @{
                        '@odata.type' = '#microsoft.graph.directoryRole'
                        'displayName' = 'User'
                    }
                })
            }

            $result = Remove-ACRAdminConsentApps -UserId 'user-id-1'

            $result.Status | Should -Be 'Skipped'
            $result.Message | Should -Match 'not an admin'
        }

        It 'Returns a result object with Status property' {
            Mock Get-MgUserMemberOf -ModuleName ACR.Remediation { return @() }

            $result = Remove-ACRAdminConsentApps -UserId 'user-id-1'

            $result.PSObject.Properties.Name | Should -Contain 'Status'
        }
    }

    Context 'Remove-ACRExchangeRules' {

        It 'Handles missing Exchange module' {
            Mock Get-Module -ModuleName ACR.Remediation { return $null } -ParameterFilter { $ListAvailable -and $Name -eq 'ExchangeOnlineManagement' }

            $result = Remove-ACRExchangeRules -UserPrincipalName 'admin@contoso.com'

            $result.Status | Should -Be 'Warning'
            $result.Message | Should -Match 'ExchangeOnlineManagement'
        }

        It 'Returns a result object with Status property' {
            Mock Get-Module -ModuleName ACR.Remediation { return $null } -ParameterFilter { $ListAvailable -and $Name -eq 'ExchangeOnlineManagement' }

            $result = Remove-ACRExchangeRules -UserPrincipalName 'admin@contoso.com'

            $result.PSObject.Properties.Name | Should -Contain 'Status'
        }
    }
}
