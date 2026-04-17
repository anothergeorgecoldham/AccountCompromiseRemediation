#Requires -Modules Pester

Describe 'ACR.Auth Module' {

    BeforeAll {
        # Ensure stub functions exist for Graph cmdlets not installed locally
        if (-not (Get-Command Get-MgUser -ErrorAction SilentlyContinue)) {
            function global:Get-MgUser { param([string]$UserId, [string[]]$Property, [string]$ErrorAction) }
        }
        if (-not (Get-Command Get-MgUserMemberOf -ErrorAction SilentlyContinue)) {
            function global:Get-MgUserMemberOf { param([string]$UserId, [switch]$All, [string]$ErrorAction) }
        }

        $modulePath = Join-Path $PSScriptRoot '..\src\modules\ACR.Auth.psm1'
        Import-Module $modulePath -Force
    }

    AfterAll {
        Remove-Module ACR.Auth -Force -ErrorAction SilentlyContinue
    }

    Context 'Connect-ACRInteractive' {

        BeforeEach {
            Mock Connect-MgGraph { return [PSCustomObject]@{ Account = 'user@contoso.com' } } -ModuleName ACR.Auth
        }

        It 'Calls Connect-MgGraph with correct scopes' {
            Connect-ACRInteractive | Out-Null

            Should -Invoke Connect-MgGraph -ModuleName ACR.Auth -Times 1 -ParameterFilter {
                $Scopes -contains 'User.ReadWrite.All' -and
                $Scopes -contains 'AuditLog.Read.All' -and
                $Scopes -contains 'Directory.ReadWrite.All'
            }
        }

        It 'Passes TenantId when provided' {
            Connect-ACRInteractive -TenantId 'contoso.onmicrosoft.com' | Out-Null

            Should -Invoke Connect-MgGraph -ModuleName ACR.Auth -Times 1 -ParameterFilter {
                $TenantId -eq 'contoso.onmicrosoft.com'
            }
        }

        It 'Throws on authentication failure' {
            Mock Connect-MgGraph { throw 'Auth failed' } -ModuleName ACR.Auth

            { Connect-ACRInteractive } | Should -Throw '*Failed to connect*'
        }
    }

    Context 'Connect-ACRManagedIdentity' {

        It 'Calls Connect-MgGraph -Identity' {
            Mock Connect-MgGraph { return [PSCustomObject]@{ Account = 'MI' } } -ModuleName ACR.Auth

            Connect-ACRManagedIdentity | Out-Null

            Should -Invoke Connect-MgGraph -ModuleName ACR.Auth -Times 1 -ParameterFilter {
                $Identity -eq $true
            }
        }

        It 'Throws on failure' {
            Mock Connect-MgGraph { throw 'MI auth failed' } -ModuleName ACR.Auth

            { Connect-ACRManagedIdentity } | Should -Throw '*Failed to connect via Managed Identity*'
        }
    }

    Context 'Get-ACRUserContext' {

        BeforeEach {
            Mock Get-MgUser -ModuleName ACR.Auth {
                [PSCustomObject]@{
                    Id                = 'user-id-123'
                    DisplayName       = 'Test User'
                    UserPrincipalName = 'test@contoso.com'
                    AccountEnabled    = $true
                    UserType          = 'Member'
                }
            }
        }

        It 'Returns correct user info' {
            Mock Get-MgUserMemberOf -ModuleName ACR.Auth { return @() }

            $ctx = Get-ACRUserContext -UserPrincipalName 'test@contoso.com'

            $ctx.UserPrincipalName | Should -Be 'test@contoso.com'
            $ctx.DisplayName | Should -Be 'Test User'
            $ctx.UserId | Should -Be 'user-id-123'
        }

        It 'Detects Global Administrator role' {
            Mock Get-MgUserMemberOf -ModuleName ACR.Auth {
                @([PSCustomObject]@{
                    Id = 'role-1'
                    AdditionalProperties = @{
                        '@odata.type'    = '#microsoft.graph.directoryRole'
                        'roleTemplateId' = '62e90394-69f5-4237-9190-012177145e10'
                        'displayName'    = 'Global Administrator'
                    }
                })
            }

            $ctx = Get-ACRUserContext -UserPrincipalName 'test@contoso.com'

            $ctx.IsAdmin | Should -BeTrue
            $ctx.AdminRoles | Should -Contain 'GlobalAdministrator'
        }

        It 'Detects Exchange Administrator role' {
            Mock Get-MgUserMemberOf -ModuleName ACR.Auth {
                @([PSCustomObject]@{
                    Id = 'role-2'
                    AdditionalProperties = @{
                        '@odata.type'    = '#microsoft.graph.directoryRole'
                        'roleTemplateId' = '29232cdf-9323-42fd-ade2-1d097af3e4de'
                        'displayName'    = 'Exchange Administrator'
                    }
                })
            }

            $ctx = Get-ACRUserContext -UserPrincipalName 'test@contoso.com'

            $ctx.IsAdmin | Should -BeTrue
            $ctx.IsExchangeAdmin | Should -BeTrue
            $ctx.AdminRoles | Should -Contain 'ExchangeAdministrator'
        }

        It 'Sets IsExchangeAdmin=true for Global Admins' {
            Mock Get-MgUserMemberOf -ModuleName ACR.Auth {
                @([PSCustomObject]@{
                    Id = 'role-1'
                    AdditionalProperties = @{
                        '@odata.type'    = '#microsoft.graph.directoryRole'
                        'roleTemplateId' = '62e90394-69f5-4237-9190-012177145e10'
                        'displayName'    = 'Global Administrator'
                    }
                })
            }

            $ctx = Get-ACRUserContext -UserPrincipalName 'test@contoso.com'

            $ctx.IsExchangeAdmin | Should -BeTrue
        }

        It 'Identifies standard users correctly' {
            Mock Get-MgUserMemberOf -ModuleName ACR.Auth { return @() }

            $ctx = Get-ACRUserContext -UserPrincipalName 'test@contoso.com'

            $ctx.IsAdmin | Should -BeFalse
            $ctx.IsExchangeAdmin | Should -BeFalse
            $ctx.AdminRoles | Should -HaveCount 0
        }
    }

    Context 'Disconnect-ACR' {

        It 'Calls Disconnect-MgGraph' {
            Mock Disconnect-MgGraph -ModuleName ACR.Auth {}

            Disconnect-ACR

            Should -Invoke Disconnect-MgGraph -ModuleName ACR.Auth -Times 1
        }
    }
}
