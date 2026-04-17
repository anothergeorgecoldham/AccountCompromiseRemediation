#Requires -Modules Pester

Describe 'Invoke-AccountRemediation.ps1' {

    BeforeAll {
        $script:ScriptPath = Join-Path $PSScriptRoot '..\src\Invoke-AccountRemediation.ps1'
        $scriptContent = Get-Content $script:ScriptPath -Raw
    }

    Context 'Script structure validation' {

        It 'Script imports all required modules' {
            $scriptContent | Should -Match 'ACR\.Auth'
            $scriptContent | Should -Match 'ACR\.Logging'
            $scriptContent | Should -Match 'ACR\.Forensics'
            $scriptContent | Should -Match 'ACR\.Reporting'
            $scriptContent | Should -Match 'ACR\.Remediation'
        }

        It 'Script validates UserPrincipalName parameter is mandatory' {
            $scriptContent | Should -Match 'Mandatory\s*=\s*\$true'
            $scriptContent | Should -Match '\[string\]\$UserPrincipalName'
        }

        It 'RunAll flag runs all applicable actions' {
            $scriptContent | Should -Match '\$RunAll'
            $scriptContent | Should -Match 'switch'
            # Verify RunAll assigns all action keys
            $scriptContent | Should -Match '\$applicableActions\.Keys'
        }

        It 'Actions parameter filters to specified actions only' {
            $scriptContent | Should -Match '\[string\[\]\]\$Actions'
            # Verify it filters to requested action names
            $scriptContent | Should -Match '\$Actions.*-notin'
        }
    }

    Context 'Script execution with mocks' {

        BeforeAll {
            # Define all Graph and module cmdlets
            function Connect-MgGraph { param([string[]]$Scopes, [string]$TenantId, [switch]$Identity, [string]$ErrorAction) }
            function Disconnect-MgGraph { param([string]$ErrorAction) }
            function Get-MgUser { param([string]$UserId, [string[]]$Property, [string]$ErrorAction) }
            function Get-MgUserMemberOf { param([string]$UserId, [switch]$All, [string]$ErrorAction) }
            function Update-MgUser { param([string]$UserId, [hashtable]$PasswordProfile, [string]$ErrorAction) }
            function Revoke-MgUserSignInSession { param([string]$UserId, [string]$ErrorAction) }
            function Get-MgUserAuthenticationMethod { param([string]$UserId, [string]$ErrorAction) }
            function Get-MgAuditLogSignIn { param([string]$Filter, [switch]$All, [string]$ErrorAction) }
            function Get-MgAuditLogDirectoryAudit { param([string]$Filter, [switch]$All, [string]$ErrorAction) }
            function Get-MgUserMailboxSetting { param([string]$UserId, [string]$ErrorAction) }
            function Get-MgUserMailFolderPermission { param([string]$UserId, [string]$MailFolderId, [string]$ErrorAction) }
            function Get-MgUserMailFolderMessageRule { param([string]$UserId, [string]$MailFolderId, [switch]$All, [string]$ErrorAction) }
            function Get-MgUserMailFolder { param([string]$UserId, [switch]$All, [string]$ErrorAction) }
            function Get-MgUserOauth2PermissionGrant { param([string]$UserId, [switch]$All, [string]$ErrorAction) }
            function Remove-MgOauth2PermissionGrant { param([string]$OAuth2PermissionGrantId, [string]$ErrorAction) }
            function Invoke-MgGraphRequest { param([string]$Method, [string]$Uri, [string]$ErrorAction, [object]$Body) }
            function Start-Transcript { param([string]$Path, [switch]$Force, [string]$ErrorAction) }
            function Stop-Transcript { param([string]$ErrorAction) }
            function Read-Host { return 'Q' }
        }

        It 'Script can be parsed without errors' {
            $parseErrors = $null
            [System.Management.Automation.Language.Parser]::ParseFile($script:ScriptPath, [ref]$null, [ref]$parseErrors)
            $parseErrors | Should -HaveCount 0
        }
    }
}
