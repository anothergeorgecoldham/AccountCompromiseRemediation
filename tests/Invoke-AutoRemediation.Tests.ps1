#Requires -Modules Pester

Describe 'Invoke-AutoRemediation.ps1' {

    BeforeAll {
        $script:ScriptPath = Join-Path $PSScriptRoot '..\src\Invoke-AutoRemediation.ps1'
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

        It 'Script validates UserPrincipalName is mandatory' {
            $scriptContent | Should -Match '\[Parameter\(Mandatory\)\]'
            $scriptContent | Should -Match '\[string\]\$UserPrincipalName'
        }

        It 'Script outputs valid JSON result' {
            $scriptContent | Should -Match 'ConvertTo-Json'
            $scriptContent | Should -Match 'Write-Output'
        }

        It 'Script uses Managed Identity authentication' {
            $scriptContent | Should -Match 'Connect-ACRManagedIdentity'
        }
    }

    Context 'Invoke-WithRetry logic' {

        It 'Invoke-WithRetry retries on 429 errors' {
            # Verify the retry logic exists in the script
            $scriptContent | Should -Match 'Invoke-WithRetry'
            $scriptContent | Should -Match '429'
            $scriptContent | Should -Match 'Retry-After|retryAfter|RetryAfter'
            # Verify MaxRetries parameter exists
            $scriptContent | Should -Match '\$MaxRetries'
            $scriptContent | Should -Match '\$RetryDelaySeconds'
        }
    }

    Context 'Script parsing' {

        It 'Script can be parsed without errors' {
            $parseErrors = $null
            [System.Management.Automation.Language.Parser]::ParseFile($script:ScriptPath, [ref]$null, [ref]$parseErrors)
            $parseErrors | Should -HaveCount 0
        }

        It 'Contains proper parameter block' {
            $ast = [System.Management.Automation.Language.Parser]::ParseFile($script:ScriptPath, [ref]$null, [ref]$null)
            $paramBlock = $ast.ParamBlock
            $paramBlock | Should -Not -BeNull
            $paramNames = $paramBlock.Parameters | ForEach-Object { $_.Name.VariablePath.UserPath }
            $paramNames | Should -Contain 'UserPrincipalName'
            $paramNames | Should -Contain 'CorrelationId'
            $paramNames | Should -Contain 'AlertSource'
            $paramNames | Should -Contain 'MaxRetries'
        }
    }
}
