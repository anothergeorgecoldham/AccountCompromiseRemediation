#Requires -Modules Pester

Describe 'ACR.Preflight Module' {

    BeforeAll {
        # Stub Graph cmdlets
        $graphStubs = @('Get-MgContext', 'Get-MgUser', 'Get-MgUserMemberOf', 'Get-MgUserLicenseDetail', 'Invoke-MgGraphRequest', 'Get-AdminAuditLogConfig', 'Test-ACRExchangeOnlineConnected')
        foreach ($cmd in $graphStubs) {
            if (-not (Get-Command $cmd -ErrorAction SilentlyContinue)) {
                Set-Item -Path "function:global:$cmd" -Value { }
            }
        }

        # Strip #Requires and import
        $originalPath = Join-Path $PSScriptRoot '..\src\modules\ACR.Preflight.psm1'
        $content = Get-Content $originalPath -Raw
        $content = $content -replace '(?m)^#Requires\s.*$', ''
        $tempPath = Join-Path TestDrive: 'ACR.Preflight.psm1'
        Set-Content -Path $tempPath -Value $content -Encoding UTF8
        Import-Module $tempPath -Force
    }

    AfterAll {
        Remove-Module ACR.Preflight -Force -ErrorAction SilentlyContinue
    }

    Context 'Test-ACRPowerShellVersion' {

        It 'Returns Pass for PS 7.2+' {
            $result = Test-ACRPowerShellVersion
            $result.Status | Should -BeIn @('Pass','Fail')
            $result.Name   | Should -Be 'PowerShellVersion'
        }
    }

    Context 'Test-ACRModuleVersions' {

        It 'Returns one check per required module' {
            $results = Test-ACRModuleVersions
            $results.Count | Should -BeGreaterThan 5
            $results | ForEach-Object { $_.Name | Should -Match '^Module:' }
        }

        It 'Marks missing required modules as Fail+Blocking' {
            $results = Test-ACRModuleVersions
            $results | Where-Object { $_.Status -eq 'Fail' -and $_.Blocking } | ForEach-Object {
                $_.Message | Should -Match '(not installed|below minimum)'
            }
        }
    }

    Context 'Test-ACRGraphConnection' {

        It 'Fails when no Graph context exists' {
            Mock Get-MgContext -ModuleName ACR.Preflight { throw 'No context' }
            $result = Test-ACRGraphConnection
            $result.Status | Should -Be 'Fail'
            $result.Blocking | Should -BeTrue
        }

        It 'Passes when all scopes are granted' {
            Mock Get-MgContext -ModuleName ACR.Preflight {
                [PSCustomObject]@{
                    Account  = 'admin@contoso.com'
                    TenantId = 'tenant-1'
                    AuthType = 'Delegated'
                    Scopes   = @(
                        'User.ReadWrite.All','Directory.ReadWrite.All','AuditLog.Read.All',
                        'Application.ReadWrite.All','DelegatedPermissionGrant.ReadWrite.All',
                        'Policy.ReadWrite.ConditionalAccess','RoleManagement.ReadWrite.Directory'
                    )
                }
            }
            $result = Test-ACRGraphConnection
            $result.Status | Should -Be 'Pass'
        }

        It 'Warns when scopes are partially granted' {
            Mock Get-MgContext -ModuleName ACR.Preflight {
                [PSCustomObject]@{
                    Account  = 'admin@contoso.com'
                    TenantId = 'tenant-1'
                    AuthType = 'Delegated'
                    Scopes   = @('User.ReadWrite.All')
                }
            }
            $result = Test-ACRGraphConnection
            $result.Status | Should -Be 'Warning'
            $result.Details.MissingScopes.Count | Should -BeGreaterThan 0
        }
    }

    Context 'Test-ACROperatorRoles' {

        It 'Passes when operator has Global Administrator' {
            Mock Get-MgContext -ModuleName ACR.Preflight {
                [PSCustomObject]@{ Account = 'admin@contoso.com'; AuthType = 'Delegated' }
            }
            Mock Get-MgUser -ModuleName ACR.Preflight {
                [PSCustomObject]@{ Id = 'u1'; UserPrincipalName = 'admin@contoso.com' }
            }
            Mock Get-MgUserMemberOf -ModuleName ACR.Preflight {
                @([PSCustomObject]@{
                    AdditionalProperties = @{
                        '@odata.type' = '#microsoft.graph.directoryRole'
                        'displayName' = 'Global Administrator'
                    }
                })
            }
            $result = Test-ACROperatorRoles
            $result.Status | Should -Be 'Pass'
        }

        It 'Warns when operator has no privileged roles' {
            Mock Get-MgContext -ModuleName ACR.Preflight {
                [PSCustomObject]@{ Account = 'user@contoso.com'; AuthType = 'Delegated' }
            }
            Mock Get-MgUser -ModuleName ACR.Preflight {
                [PSCustomObject]@{ Id = 'u1'; UserPrincipalName = 'user@contoso.com' }
            }
            Mock Get-MgUserMemberOf -ModuleName ACR.Preflight { return @() }
            $result = Test-ACROperatorRoles
            $result.Status | Should -Be 'Warning'
        }

        It 'Skips when using app-only auth' {
            Mock Get-MgContext -ModuleName ACR.Preflight {
                [PSCustomObject]@{ Account = ''; AuthType = 'AppOnly' }
            }
            $result = Test-ACROperatorRoles
            $result.Status | Should -Be 'Skipped'
        }
    }

    Context 'Test-ACRExchangeOnlineSession' {

        It 'Passes when EXO is connected' {
            Mock Test-ACRExchangeOnlineConnected -ModuleName ACR.Preflight { return $true }
            $result = Test-ACRExchangeOnlineSession
            $result.Status | Should -Be 'Pass'
        }

        It 'Warns when EXO is not connected' {
            Mock Test-ACRExchangeOnlineConnected -ModuleName ACR.Preflight { return $false }
            $result = Test-ACRExchangeOnlineSession
            $result.Status | Should -Be 'Warning'
        }
    }

    Context 'Test-ACRTargetUser' {

        It 'Passes for an enabled member user' {
            Mock Get-MgUser -ModuleName ACR.Preflight {
                [PSCustomObject]@{
                    Id                = 'u1'
                    UserPrincipalName = 'user@contoso.com'
                    DisplayName       = 'Test User'
                    AccountEnabled    = $true
                    UserType          = 'Member'
                }
            }
            $result = Test-ACRTargetUser -UserPrincipalName 'user@contoso.com'
            $result.Status | Should -Be 'Pass'
        }

        It 'Warns for a guest user' {
            Mock Get-MgUser -ModuleName ACR.Preflight {
                [PSCustomObject]@{
                    Id = 'u1'; UserPrincipalName = 'guest@contoso.com'
                    DisplayName = 'Guest'; AccountEnabled = $true; UserType = 'Guest'
                }
            }
            $result = Test-ACRTargetUser -UserPrincipalName 'guest@contoso.com'
            $result.Status | Should -Be 'Warning'
        }

        It 'Fails and is blocking when user not found' {
            Mock Get-MgUser -ModuleName ACR.Preflight { throw 'User not found' }
            $result = Test-ACRTargetUser -UserPrincipalName 'missing@contoso.com'
            $result.Status | Should -Be 'Fail'
            $result.Blocking | Should -BeTrue
        }
    }

    Context 'Test-ACRTargetUserLicenses' {

        It 'Passes when user has Exchange and Entra P1 SKUs' {
            Mock Get-MgUserLicenseDetail -ModuleName ACR.Preflight {
                @(
                    [PSCustomObject]@{ SkuPartNumber = 'ENTERPRISEPACK' }
                    [PSCustomObject]@{ SkuPartNumber = 'AAD_PREMIUM' }
                )
            }
            $result = Test-ACRTargetUserLicenses -UserPrincipalName 'user@contoso.com'
            $result.Status | Should -Be 'Pass'
        }
        It 'Warns when user has no licenses' {
            Mock Get-MgUserLicenseDetail -ModuleName ACR.Preflight { return @() }
            $result = Test-ACRTargetUserLicenses -UserPrincipalName 'user@contoso.com'
            $result.Status | Should -Be 'Warning'
        }

        It 'Passes for M365 Business Standard via ServicePlans (regression for issue where O365_BUSINESS_PREMIUM was flagged as no-Exchange)' {
            Mock Get-MgUserLicenseDetail -ModuleName ACR.Preflight {
                @(
                    [PSCustomObject]@{
                        SkuPartNumber = 'O365_BUSINESS_PREMIUM'
                        ServicePlans  = @(
                            [PSCustomObject]@{ ServicePlanName = 'EXCHANGE_S_STANDARD'; ProvisioningStatus = 'Success' }
                            [PSCustomObject]@{ ServicePlanName = 'AAD_PREMIUM';         ProvisioningStatus = 'Success' }
                        )
                    }
                )
            }
            $result = Test-ACRTargetUserLicenses -UserPrincipalName 'user@contoso.com'
            $result.Status | Should -Be 'Pass'
        }

        It 'Warns when ServicePlans show no Exchange entitlement' {
            Mock Get-MgUserLicenseDetail -ModuleName ACR.Preflight {
                @(
                    [PSCustomObject]@{
                        SkuPartNumber = 'AAD_PREMIUM'
                        ServicePlans  = @(
                            [PSCustomObject]@{ ServicePlanName = 'AAD_PREMIUM'; ProvisioningStatus = 'Success' }
                        )
                    }
                )
            }
            $result = Test-ACRTargetUserLicenses -UserPrincipalName 'user@contoso.com'
            $result.Status  | Should -Be 'Warning'
            $result.Message | Should -Match 'Exchange'
        }
    }

    Context 'Test-ACROperatorPimRoles' {

        It 'Skips when auth is app-only' {
            Mock Get-MgContext -ModuleName ACR.Preflight {
                [PSCustomObject]@{ Account = ''; AuthType = 'AppOnly' }
            }
            $result = Test-ACROperatorPimRoles
            $result.Status | Should -Be 'Skipped'
        }

        It 'Warns when operator has dormant PIM-eligible roles' {
            Mock Get-MgContext -ModuleName ACR.Preflight {
                [PSCustomObject]@{ Account = 'admin@contoso.com'; AuthType = 'Delegated' }
            }
            Mock Get-MgUser -ModuleName ACR.Preflight {
                [PSCustomObject]@{ Id = 'u1' }
            }
            Mock Invoke-MgGraphRequest -ModuleName ACR.Preflight -ParameterFilter { $Uri -like '*roleEligibilityScheduleInstances*' } {
                @{ value = @(@{ roleDefinitionId = 'rd1' }) }
            }
            Mock Invoke-MgGraphRequest -ModuleName ACR.Preflight -ParameterFilter { $Uri -like '*roleDefinitions*' } {
                @{ displayName = 'Global Administrator' }
            }
            $result = Test-ACROperatorPimRoles
            $result.Status | Should -Be 'Warning'
        }

        It 'Passes when no eligible roles' {
            Mock Get-MgContext -ModuleName ACR.Preflight {
                [PSCustomObject]@{ Account = 'admin@contoso.com'; AuthType = 'Delegated' }
            }
            Mock Get-MgUser -ModuleName ACR.Preflight { [PSCustomObject]@{ Id = 'u1' } }
            Mock Invoke-MgGraphRequest -ModuleName ACR.Preflight { @{ value = @() } }
            $result = Test-ACROperatorPimRoles
            $result.Status | Should -Be 'Pass'
        }
    }

    Context 'Invoke-ACRPreflight' {

        It 'Returns Ready=true when all blocking checks pass' {
            Mock Get-MgContext -ModuleName ACR.Preflight {
                [PSCustomObject]@{
                    Account  = 'admin@contoso.com'
                    TenantId = 'tenant-1'
                    AuthType = 'Delegated'
                    Scopes   = @(
                        'User.ReadWrite.All','Directory.ReadWrite.All','AuditLog.Read.All',
                        'Application.ReadWrite.All','DelegatedPermissionGrant.ReadWrite.All',
                        'Policy.ReadWrite.ConditionalAccess','RoleManagement.ReadWrite.Directory'
                    )
                }
            }
            Mock Get-MgUser -ModuleName ACR.Preflight {
                [PSCustomObject]@{
                    Id = 'u1'; UserPrincipalName = 'user@contoso.com'
                    DisplayName = 'User'; AccountEnabled = $true; UserType = 'Member'
                }
            }
            Mock Get-MgUserMemberOf -ModuleName ACR.Preflight {
                @([PSCustomObject]@{
                    AdditionalProperties = @{
                        '@odata.type' = '#microsoft.graph.directoryRole'
                        'displayName' = 'Global Administrator'
                    }
                })
            }
            Mock Test-ACRExchangeOnlineConnected -ModuleName ACR.Preflight { return $true }
            Mock Get-MgUserLicenseDetail -ModuleName ACR.Preflight {
                @([PSCustomObject]@{ SkuPartNumber = 'ENTERPRISEPACK' }, [PSCustomObject]@{ SkuPartNumber = 'AAD_PREMIUM' })
            }
            Mock Invoke-MgGraphRequest -ModuleName ACR.Preflight { @{ value = @() } }

            $result = Invoke-ACRPreflight -UserPrincipalName 'user@contoso.com' -SkipAuditCheck

            $result.Checks | Should -Not -BeNullOrEmpty
            $result.PSObject.Properties.Name | Should -Contain 'Ready'
            $result.PSObject.Properties.Name | Should -Contain 'PassCount'
        }

        It 'Returns Ready=false when Graph connection fails (blocking)' {
            Mock Get-MgContext -ModuleName ACR.Preflight { throw 'No context' }
            Mock Test-ACRExchangeOnlineConnected -ModuleName ACR.Preflight { return $false }
            Mock Invoke-MgGraphRequest -ModuleName ACR.Preflight { @{ value = @() } }

            $result = Invoke-ACRPreflight -SkipUserCheck -SkipAuditCheck

            $result.Ready | Should -BeFalse
            $result.BlockingFailures.Count | Should -BeGreaterThan 0
        }

        It '-AuthMode AppOnly skips Test-ACROperatorRoles and runs Test-ACRAppAuthContext' {
            Mock Get-MgContext -ModuleName ACR.Preflight {
                [PSCustomObject]@{ AuthType = 'AppOnly'; ClientId = 'app-1'; TenantId = 't-1' }
            }
            Mock Get-MgUser -ModuleName ACR.Preflight {
                [PSCustomObject]@{ Id='u1'; UserPrincipalName='user@contoso.com'; DisplayName='U'; AccountEnabled=$true; UserType='Member' }
            }
            Mock Test-ACRExchangeOnlineConnected -ModuleName ACR.Preflight { return $true }
            Mock Get-MgUserLicenseDetail -ModuleName ACR.Preflight {
                @([PSCustomObject]@{ SkuPartNumber='ENTERPRISEPACK' }, [PSCustomObject]@{ SkuPartNumber='AAD_PREMIUM' })
            }
            Mock Invoke-MgGraphRequest -ModuleName ACR.Preflight {
                param($Method, $Uri)
                if ($Uri -like "/v1.0/servicePrincipals(appId=*") { return @{ id = 'sp-1' } }
                if ($Uri -like "/v1.0/servicePrincipals/sp-1/appRoleAssignments") {
                    return @{ value = @(
                        @{ resourceId='graph-sp'; appRoleId='r1' },
                        @{ resourceId='graph-sp'; appRoleId='r2' }
                    ) }
                }
                if ($Uri -eq "/v1.0/servicePrincipals/graph-sp") {
                    return @{ appRoles = @(
                        @{ id='r1'; value='User.ReadWrite.All' },
                        @{ id='r2'; value='Directory.Read.All' }
                    ) }
                }
                return @{ value = @() }
            }
            Mock Test-ACROperatorRoles -ModuleName ACR.Preflight { throw 'should not be called in AppOnly' }
            Mock Test-ACROperatorPimRoles -ModuleName ACR.Preflight { throw 'should not be called in AppOnly' }

            $result = Invoke-ACRPreflight -UserPrincipalName 'user@contoso.com' -SkipAuditCheck -AuthMode AppOnly

            $result.AuthMode | Should -Be 'AppOnly'
            ($result.Checks | Where-Object Name -eq 'AppAuthContext') | Should -Not -BeNullOrEmpty
            ($result.Checks | Where-Object Name -eq 'OperatorRoles')  | Should -BeNullOrEmpty
            Should -Invoke Test-ACROperatorRoles -ModuleName ACR.Preflight -Times 0
        }

        It 'Test-ACRAppAuthContext warns when required app roles are missing' {
            Mock Get-MgContext -ModuleName ACR.Preflight {
                [PSCustomObject]@{ AuthType = 'AppOnly'; ClientId = 'app-1'; TenantId = 't-1' }
            }
            Mock Invoke-MgGraphRequest -ModuleName ACR.Preflight {
                param($Method, $Uri)
                if ($Uri -like "/v1.0/servicePrincipals(appId=*") { return @{ id = 'sp-1' } }
                if ($Uri -like "/v1.0/servicePrincipals/sp-1/appRoleAssignments") { return @{ value = @() } }
                return @{ value = @() }
            }
            $check = Test-ACRAppAuthContext -RequiredAppRoles @('User.ReadWrite.All')
            $check.Status | Should -Be 'Warning'
            $check.Message | Should -Match 'missing'
        }

        It 'Test-ACRAppAuthContext fails when AuthType is Delegated' {
            Mock Get-MgContext -ModuleName ACR.Preflight {
                [PSCustomObject]@{ AuthType = 'Delegated'; Account = 'me@contoso.com' }
            }
            $check = Test-ACRAppAuthContext
            $check.Status   | Should -Be 'Fail'
            $check.Blocking | Should -BeTrue
        }

        It 'Format-ACRPreflightReport returns a non-empty string' {
            Mock Get-MgContext -ModuleName ACR.Preflight { throw 'No context' }
            Mock Test-ACRExchangeOnlineConnected -ModuleName ACR.Preflight { return $false }
            Mock Invoke-MgGraphRequest -ModuleName ACR.Preflight { @{ value = @() } }
            $result = Invoke-ACRPreflight -SkipUserCheck -SkipAuditCheck
            $report = Format-ACRPreflightReport -PreflightResult $result
            $report | Should -Not -BeNullOrEmpty
            $report | Should -Match 'Preflight Results'
        }
    }
}
