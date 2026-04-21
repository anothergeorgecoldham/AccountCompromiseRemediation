#Requires -Modules Pester

Describe 'ACR.Auth Module — App-Auth functions' {

    BeforeAll {
        # Stubs for Graph cmdlets that may not be installed locally
        if (-not (Get-Command Connect-MgGraph -ErrorAction SilentlyContinue)) {
            function global:Connect-MgGraph { param([string]$TenantId, [string]$ClientId, [object]$Certificate, [switch]$NoWelcome, [switch]$Identity, [string[]]$Scopes, [string]$ErrorAction) }
        }
        if (-not (Get-Command Get-MgContext -ErrorAction SilentlyContinue)) {
            function global:Get-MgContext { }
        }
        if (-not (Get-Command Connect-ExchangeOnline -ErrorAction SilentlyContinue)) {
            function global:Connect-ExchangeOnline { param([string]$AppId, [string]$Organization, [string]$CertificateThumbprint, [string]$CertificateFilePath, [switch]$ShowBanner, [string]$ErrorAction) }
        }

        $modulePath = Join-Path $PSScriptRoot '..\src\modules\ACR.Auth.psm1'
        Import-Module $modulePath -Force
    }

    AfterAll {
        Remove-Module ACR.Auth -Force -ErrorAction SilentlyContinue
    }

    Context 'Connect-ACRAppAuth (thumbprint)' {

        BeforeAll {
            # Build a real X509Certificate2 with a private key, in-memory, no cert-store side effect.
            $rsa  = [System.Security.Cryptography.RSA]::Create(2048)
            $hash = [System.Security.Cryptography.HashAlgorithmName]::SHA256
            $pad  = [System.Security.Cryptography.RSASignaturePadding]::Pkcs1
            $req  = [System.Security.Cryptography.X509Certificates.CertificateRequest]::new(
                'CN=ACR-AppAuth-Test', $rsa, $hash, $pad)
            $script:goodCert = $req.CreateSelfSigned(
                [DateTimeOffset]::Now.AddDays(-1), [DateTimeOffset]::Now.AddDays(180))

            $req2 = [System.Security.Cryptography.X509Certificates.CertificateRequest]::new(
                'CN=ACR-AppAuth-Expired', $rsa, $hash, $pad)
            $script:expiredCert = $req2.CreateSelfSigned(
                [DateTimeOffset]::Now.AddDays(-30), [DateTimeOffset]::Now.AddDays(-1))

            # Cert without private key — round-trip via DER export
            $script:noKeyCert = [System.Security.Cryptography.X509Certificates.X509Certificate2]::new(
                $script:goodCert.Export([System.Security.Cryptography.X509Certificates.X509ContentType]::Cert))
        }

        BeforeEach {
            $thisCert = $script:goodCert
            Mock Get-ChildItem -ModuleName ACR.Auth { return @($thisCert) }.GetNewClosure()
            Mock Connect-MgGraph -ModuleName ACR.Auth { return [PSCustomObject]@{ AuthType = 'AppOnly'; ClientId = 'app-id'; TenantId = 'tenant-id' } }
        }

        It 'Connects with cert from CurrentUser store and AuthType=AppOnly' {
            $ctx = Connect-ACRAppAuth -TenantId 'contoso.onmicrosoft.com' -ClientId 'app-id' -CertificateThumbprint $script:goodCert.Thumbprint
            $ctx.AuthType | Should -Be 'AppOnly'
            Should -Invoke Connect-MgGraph -ModuleName ACR.Auth -Times 1 -ParameterFilter {
                $TenantId -eq 'contoso.onmicrosoft.com' -and $ClientId -eq 'app-id' -and $Certificate
            }
        }

        It 'Tolerates whitespace in the thumbprint' {
            $thumb = ($script:goodCert.Thumbprint -split '' | ForEach-Object { $_ }) -join ' '
            { Connect-ACRAppAuth -TenantId 't' -ClientId 'a' -CertificateThumbprint $thumb } | Should -Not -Throw
        }

        It 'Throws when cert not found' {
            Mock Get-ChildItem -ModuleName ACR.Auth { return @() }
            { Connect-ACRAppAuth -TenantId 't' -ClientId 'a' -CertificateThumbprint '0000000000000000000000000000000000000000' } |
                Should -Throw '*not found*'
        }

        It 'Throws when cert is expired' {
            $thisCert = $script:expiredCert
            Mock Get-ChildItem -ModuleName ACR.Auth { return @($thisCert) }.GetNewClosure()
            { Connect-ACRAppAuth -TenantId 't' -ClientId 'a' -CertificateThumbprint $script:expiredCert.Thumbprint } |
                Should -Throw '*expired*'
        }

        It 'Throws when cert lacks private key' {
            $thisCert = $script:noKeyCert
            Mock Get-ChildItem -ModuleName ACR.Auth { return @($thisCert) }.GetNewClosure()
            { Connect-ACRAppAuth -TenantId 't' -ClientId 'a' -CertificateThumbprint $script:noKeyCert.Thumbprint } |
                Should -Throw '*private key*'
        }
    }

    Context 'Connect-ACRExchangeOnlineApp' {

        BeforeEach {
            Mock Connect-ExchangeOnline -ModuleName ACR.Auth { return $null }
        }

        It 'Returns false when ExchangeOnlineManagement module is missing' {
            Mock Get-Module -ModuleName ACR.Auth { return $null } -ParameterFilter { $ListAvailable -and $Name -eq 'ExchangeOnlineManagement' }
            $r = Connect-ACRExchangeOnlineApp -Organization 'contoso.onmicrosoft.com' -AppId 'a' -CertificateThumbprint 'ABCD1234ABCD1234ABCD1234ABCD1234ABCD1234'
            $r | Should -BeFalse
        }

        It 'Calls Connect-ExchangeOnline with thumbprint when module is available' {
            Mock Get-Module -ModuleName ACR.Auth { return [PSCustomObject]@{ Name = 'ExchangeOnlineManagement' } }
            Mock Import-Module -ModuleName ACR.Auth { }
            Connect-ACRExchangeOnlineApp -Organization 'contoso.onmicrosoft.com' -AppId 'app-id' -CertificateThumbprint 'ABCD1234ABCD1234ABCD1234ABCD1234ABCD1234' | Out-Null
            Should -Invoke Connect-ExchangeOnline -ModuleName ACR.Auth -Times 1 -ParameterFilter {
                $AppId -eq 'app-id' -and $Organization -eq 'contoso.onmicrosoft.com' -and $CertificateThumbprint -eq 'ABCD1234ABCD1234ABCD1234ABCD1234ABCD1234'
            }
        }

        It 'Returns false on connection failure (does not throw)' {
            Mock Get-Module -ModuleName ACR.Auth { return [PSCustomObject]@{ Name = 'ExchangeOnlineManagement' } }
            Mock Import-Module -ModuleName ACR.Auth { }
            Mock Connect-ExchangeOnline -ModuleName ACR.Auth { throw 'AADSTS700016 Application not found' }
            $r = Connect-ACRExchangeOnlineApp -Organization 'contoso.onmicrosoft.com' -AppId 'app-id' -CertificateThumbprint 'ABCD1234ABCD1234ABCD1234ABCD1234ABCD1234'
            $r | Should -BeFalse
        }
    }

    Context 'Get-ACROperatorIdentity' {

        It 'Captures Windows identity by default' {
            Mock Get-MgContext -ModuleName ACR.Auth { return [PSCustomObject]@{ AuthType = 'AppOnly'; ClientId = 'a' } }
            $id = Get-ACROperatorIdentity
            $id.Source | Should -Be 'WindowsIdentity'
            $id.DisplayName | Should -Not -BeNullOrEmpty
            $id.AuthMode | Should -Be 'AppOnly'
        }

        It 'Honours -OperatorUpn override' {
            Mock Get-MgContext -ModuleName ACR.Auth { return [PSCustomObject]@{ AuthType = 'AppOnly'; ClientId = 'a' } }
            $id = Get-ACROperatorIdentity -OperatorUpn 'analyst@contoso.com'
            $id.Source | Should -Be 'Override'
            $id.DisplayName | Should -Be 'analyst@contoso.com'
        }

        It 'Reports AuthMode=Delegated when context is interactive' {
            Mock Get-MgContext -ModuleName ACR.Auth { return [PSCustomObject]@{ AuthType = 'Delegated'; Account = 'me@contoso.com' } }
            $id = Get-ACROperatorIdentity
            $id.AuthMode | Should -Be 'Delegated'
        }

        It 'Captures hostname and timestamp' {
            Mock Get-MgContext -ModuleName ACR.Auth { return [PSCustomObject]@{ AuthType = 'AppOnly'; ClientId = 'a' } }
            $id = Get-ACROperatorIdentity
            $id.Hostname   | Should -Be $env:COMPUTERNAME
            $id.CapturedAt | Should -Match '^\d{4}-\d{2}-\d{2}T'
        }
    }
}
