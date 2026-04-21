#Requires -Modules Pester

Describe 'Invoke-AccountRemediationAppAuth.ps1' {

    BeforeAll {
        $script:ScriptPath = Join-Path $PSScriptRoot '..\src\Invoke-AccountRemediationAppAuth.ps1'
        $script:Content    = Get-Content $script:ScriptPath -Raw
    }

    Context 'Script structure' {

        It 'Imports all ACR modules' {
            foreach ($m in 'ACR.Auth','ACR.Logging','ACR.Preflight','ACR.Forensics','ACR.Reporting','ACR.Remediation') {
                $script:Content | Should -Match ([regex]::Escape($m))
            }
        }

        It 'Has mandatory UserPrincipalName parameter' {
            $script:Content | Should -Match '\[Parameter\(Mandatory\s*=\s*\$true\)\]\s*\r?\n\s*\[string\]\$UserPrincipalName'
        }

        It 'Defines app-auth specific parameters' {
            foreach ($p in '\$ConfigPath','\$TenantId','\$ClientId','\$CertificateThumbprint','\$Organization','\$OperatorUpn') {
                $script:Content | Should -Match $p
            }
        }

        It 'Calls Connect-ACRAppAuth (not Connect-ACRInteractive)' {
            $script:Content | Should -Match 'Connect-ACRAppAuth'
            $script:Content | Should -Not -Match 'Connect-ACRInteractive'
        }

        It 'Calls Connect-ACRExchangeOnlineApp (not Connect-ACRExchangeOnline)' {
            $script:Content | Should -Match 'Connect-ACRExchangeOnlineApp'
        }

        It 'Passes -AuthMode AppOnly to preflight' {
            $script:Content | Should -Match 'Invoke-ACRPreflight[\s\S]*-AuthMode\s+AppOnly'
        }

        It 'Captures operator identity and passes it to Start-ACRLog' {
            $script:Content | Should -Match 'Get-ACROperatorIdentity'
            $script:Content | Should -Match 'Start-ACRLog[\s\S]*-OperatorIdentity'
        }

        It 'Parses without errors' {
            $parseErrors = $null
            [System.Management.Automation.Language.Parser]::ParseFile($script:ScriptPath, [ref]$null, [ref]$parseErrors)
            $parseErrors | Should -HaveCount 0
        }
    }

    Context 'Resolve-ACRAppAuthConfig (config + parameter override)' {

        BeforeAll {
            # Source the function out of the script in isolation
            $ast = [System.Management.Automation.Language.Parser]::ParseFile($script:ScriptPath, [ref]$null, [ref]$null)
            $func = $ast.FindAll({ param($n) $n -is [System.Management.Automation.Language.FunctionDefinitionAst] -and $n.Name -eq 'Resolve-ACRAppAuthConfig' }, $true) | Select-Object -First 1
            Invoke-Expression $func.Extent.Text
            # PSScriptRoot is referenced inside; supply a temp value for default config path probing
            $script:tempCfgDir = Join-Path $env:TEMP ("acr-app-auth-test-" + [guid]::NewGuid())
            New-Item -ItemType Directory -Path $script:tempCfgDir -Force | Out-Null
            $script:cfgPath = Join-Path $script:tempCfgDir 'app-auth.json'
        }

        AfterAll {
            if (Test-Path $script:tempCfgDir) { Remove-Item $script:tempCfgDir -Recurse -Force -ErrorAction SilentlyContinue }
        }

        It 'Loads all fields from config file' {
            @{
                tenantId = 't1'; clientId = 'c1'; certificateThumbprint = 'TH1'; organization = 'org1'
            } | ConvertTo-Json | Set-Content $script:cfgPath -Encoding UTF8

            $r = Resolve-ACRAppAuthConfig -ConfigPath $script:cfgPath
            $r.TenantId | Should -Be 't1'
            $r.ClientId | Should -Be 'c1'
            $r.CertificateThumbprint | Should -Be 'TH1'
            $r.Organization | Should -Be 'org1'
        }

        It 'Parameter overrides config-file value' {
            @{
                tenantId = 't1'; clientId = 'c1'; certificateThumbprint = 'TH1'; organization = 'org1'
            } | ConvertTo-Json | Set-Content $script:cfgPath -Encoding UTF8

            $r = Resolve-ACRAppAuthConfig -ConfigPath $script:cfgPath -TenantId 't-override'
            $r.TenantId | Should -Be 't-override'
            $r.ClientId | Should -Be 'c1'
        }

        It 'Throws when required field is missing in both config and params' {
            @{ organization = 'only-org' } | ConvertTo-Json | Set-Content $script:cfgPath -Encoding UTF8
            { Resolve-ACRAppAuthConfig -ConfigPath $script:cfgPath } | Should -Throw '*Missing required*'
        }

        It 'Works without a config file when all required params supplied' {
            $missing = Join-Path $script:tempCfgDir 'no-such-file.json'
            $r = Resolve-ACRAppAuthConfig -ConfigPath $missing -TenantId 't' -ClientId 'c' -CertificateThumbprint 'TH'
            $r.TenantId | Should -Be 't'
            $r.ClientId | Should -Be 'c'
            $r.CertificateThumbprint | Should -Be 'TH'
        }
    }
}
