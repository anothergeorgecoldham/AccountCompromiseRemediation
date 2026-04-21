#Requires -Modules Pester

Describe 'Setup-ACRAppRegistration.ps1' {

    BeforeAll {
        $script:ScriptPath = Join-Path $PSScriptRoot '..\src\Setup-ACRAppRegistration.ps1'
        $script:Content    = Get-Content $script:ScriptPath -Raw
    }

    Context 'Script structure' {

        It 'Parses without errors' {
            $parseErrors = $null
            [System.Management.Automation.Language.Parser]::ParseFile($script:ScriptPath, [ref]$null, [ref]$parseErrors)
            $parseErrors | Should -HaveCount 0
        }

        It 'Requires PowerShell 7.2+' {
            $script:Content | Should -Match '#Requires\s+-Version\s+7\.2'
        }

        It 'Supports -WhatIf via SupportsShouldProcess' {
            $script:Content | Should -Match 'SupportsShouldProcess\s*=\s*\$true'
        }

        It 'References Microsoft Graph resource AppId' {
            $script:Content | Should -Match '00000003-0000-0000-c000-000000000000'
        }

        It 'References Exchange Administrator role template ID' {
            $script:Content | Should -Match '29232cdf-9323-42fd-ade2-1d097af3e4de'
        }

        It 'Reads the applicationPermissionsAppAuth section from permissions.json' {
            $script:Content | Should -Match 'applicationPermissionsAppAuth'
            $script:Content | Should -Match 'graphAppRoles'
        }

        It 'Uses New-MgServicePrincipalAppRoleAssignment to grant consent' {
            $script:Content | Should -Match 'New-MgServicePrincipalAppRoleAssignment'
        }

        It 'Calls New-ServicePrincipal in EXO step' {
            $script:Content | Should -Match 'New-ServicePrincipal\s+-AppId'
        }

        It 'Writes the resolved config to disk' {
            $script:Content | Should -Match 'tenantId\s*=\s*\$TenantId'
            $script:Content | Should -Match 'clientId\s*=\s*\$app\.AppId'
            $script:Content | Should -Match 'certificateThumbprint\s*=\s*\$cert\.Thumbprint'
        }

        It 'Handles cert reuse via -ReuseCertificateThumbprint' {
            $script:Content | Should -Match '\$ReuseCertificateThumbprint'
        }

        It 'Provides hardening guidance in the final summary' {
            $script:Content | Should -Match 'non-exportable'
            $script:Content | Should -Match 'Rotate'
        }
    }

    Context 'Permissions.json contract' {

        BeforeAll {
            $script:permsPath = Join-Path $PSScriptRoot '..\config\permissions.json'
            $script:perms = Get-Content $script:permsPath -Raw | ConvertFrom-Json
        }

        It 'permissions.json contains applicationPermissionsAppAuth.graphAppRoles' {
            $script:perms.applicationPermissionsAppAuth | Should -Not -BeNullOrEmpty
            $script:perms.applicationPermissionsAppAuth.graphAppRoles | Should -Not -BeNullOrEmpty
        }

        It 'Each role entry has name, id, purpose' {
            foreach ($r in $script:perms.applicationPermissionsAppAuth.graphAppRoles) {
                $r.name    | Should -Not -BeNullOrEmpty
                $r.id      | Should -Match '^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$'
                $r.purpose | Should -Not -BeNullOrEmpty
            }
        }

        It 'Includes core remediation permissions' {
            $names = $script:perms.applicationPermissionsAppAuth.graphAppRoles.name
            foreach ($req in 'User.ReadWrite.All','Directory.Read.All','AuditLog.Read.All','Application.ReadWrite.All','DelegatedPermissionGrant.ReadWrite.All') {
                $names | Should -Contain $req
            }
        }
    }
}
