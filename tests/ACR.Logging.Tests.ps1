#Requires -Modules Pester

Describe 'ACR.Logging Module' {

    BeforeAll {
        $modulePath = Join-Path $PSScriptRoot '..\src\modules\ACR.Logging.psm1'
        Import-Module $modulePath -Force

        Mock Start-Transcript -ModuleName ACR.Logging {}
        Mock Stop-Transcript -ModuleName ACR.Logging {}
    }

    AfterAll {
        Remove-Module ACR.Logging -Force -ErrorAction SilentlyContinue
    }

    AfterEach {
        # Ensure each test starts with a clean session
        try { Stop-ACRLog } catch {}
    }

    Context 'Start-ACRLog' {

        It 'Creates output directory' {
            $testDir = Join-Path TestDrive: 'log-create-dir'

            $session = Start-ACRLog -OutputPath $testDir -UserPrincipalName 'user@contoso.com'

            Test-Path $testDir | Should -BeTrue
        }

        It 'Returns session object with correct properties' {
            $testDir = Join-Path TestDrive: 'log-session-props'

            $session = Start-ACRLog -OutputPath $testDir -UserPrincipalName 'user@contoso.com' -CorrelationId 'corr-123' -AlertSource 'Sentinel'

            $session.SessionId | Should -Not -BeNullOrEmpty
            $session.CorrelationId | Should -Be 'corr-123'
            $session.AlertSource | Should -Be 'Sentinel'
            $session.UserPrincipalName | Should -Be 'user@contoso.com'
            $session.StartTime | Should -Not -BeNullOrEmpty
            $session.OutputPath | Should -Be $testDir
            $session.Actions.GetType().Name | Should -Match 'List'
            $session.RollbackEntries.GetType().Name | Should -Match 'List'
            $session.Counters.Total | Should -Be 0
        }
    }

    Context 'Write-ACRAction' {

        It 'Adds entry to session and updates counters' {
            $testDir = Join-Path TestDrive: 'log-action'
            $session = Start-ACRLog -OutputPath $testDir -UserPrincipalName 'user@contoso.com'

            Write-ACRAction -Action 'ResetPassword' -Status 'Success' -Message 'Password reset completed'
            Write-ACRAction -Action 'RevokeTokens' -Status 'Failed' -Message 'Token revocation failed'

            $current = Get-ACRLogSession
            $current.Actions.Count | Should -Be 2
            $current.Counters.Total | Should -Be 2
            $current.Counters.Success | Should -Be 1
            $current.Counters.Failed | Should -Be 1
        }

        It 'Throws if no active session' {
            # Ensure no session exists
            { Write-ACRAction -Action 'Test' -Status 'Success' -Message 'Test' } | Should -Throw '*No active log session*'
        }
    }

    Context 'Write-ACRRollbackEntry' {

        It 'Records before/after state' {
            $testDir = Join-Path TestDrive: 'log-rollback'
            Start-ACRLog -OutputPath $testDir -UserPrincipalName 'user@contoso.com' | Out-Null

            Write-ACRRollbackEntry -Action 'RemoveDelegates' -ResourceType 'MailboxDelegate' `
                -ResourceId 'delegate@contoso.com' `
                -BeforeState @{ Permission = 'FullAccess' } `
                -AfterState @{ Permission = 'Removed' } `
                -RollbackInstructions 'Re-add delegate via EAC'

            $session = Get-ACRLogSession
            $session.RollbackEntries.Count | Should -Be 1
            $session.RollbackEntries[0].Action | Should -Be 'RemoveDelegates'
            $session.RollbackEntries[0].ResourceType | Should -Be 'MailboxDelegate'
            $session.RollbackEntries[0].BeforeState.Permission | Should -Be 'FullAccess'
            $session.RollbackEntries[0].AfterState.Permission | Should -Be 'Removed'
        }
    }

    Context 'Stop-ACRLog' {

        It 'Writes action log JSON to disk' {
            $testDir = Join-Path TestDrive: 'log-stop-action'
            $session = Start-ACRLog -OutputPath $testDir -UserPrincipalName 'user@contoso.com'

            Write-ACRAction -Action 'TestAction' -Status 'Success' -Message 'Done'
            $summary = Stop-ACRLog

            Test-Path $summary.ActionLogPath | Should -BeTrue
            $content = Get-Content $summary.ActionLogPath -Raw | ConvertFrom-Json
            $content.Actions.Count | Should -Be 1
            $content.Actions[0].Action | Should -Be 'TestAction'
        }

        It 'Writes rollback journal JSON to disk' {
            $testDir = Join-Path TestDrive: 'log-stop-rollback'
            Start-ACRLog -OutputPath $testDir -UserPrincipalName 'user@contoso.com' | Out-Null

            Write-ACRRollbackEntry -Action 'RemoveForwarding' -ResourceType 'ForwardingRule' `
                -ResourceId 'rule-1' -BeforeState @{ Fwd = 'ext@evil.com' } -AfterState @{ Fwd = $null }

            $summary = Stop-ACRLog
            Test-Path $summary.RollbackPath | Should -BeTrue
            $journal = Get-Content $summary.RollbackPath -Raw | ConvertFrom-Json
            $journal.Entries.Count | Should -Be 1
        }

        It 'Returns summary with correct counters' {
            $testDir = Join-Path TestDrive: 'log-stop-summary'
            Start-ACRLog -OutputPath $testDir -UserPrincipalName 'user@contoso.com' | Out-Null

            Write-ACRAction -Action 'A1' -Status 'Success' -Message 'OK'
            Write-ACRAction -Action 'A2' -Status 'Failed' -Message 'Err'
            Write-ACRAction -Action 'A3' -Status 'Skipped' -Message 'N/A'

            $summary = Stop-ACRLog
            $summary.Counters.Total | Should -Be 3
            $summary.Counters.Success | Should -Be 1
            $summary.Counters.Failed | Should -Be 1
            $summary.Counters.Skipped | Should -Be 1
        }
    }

    Context 'Full Lifecycle' {

        It 'Start → multiple actions → rollback entries → Stop → verify files' {
            $testDir = Join-Path TestDrive: 'log-lifecycle'

            $session = Start-ACRLog -OutputPath $testDir -UserPrincipalName 'lifecycle@contoso.com' `
                -CorrelationId 'lc-001' -AlertSource 'XDR'

            $session.SessionId | Should -Not -BeNullOrEmpty

            Write-ACRAction -Action 'ResetPassword' -Status 'Success' -Message 'Reset done'
            Write-ACRAction -Action 'RevokeTokens' -Status 'Success' -Message 'Tokens revoked'
            Write-ACRAction -Action 'RemoveDelegates' -Status 'Warning' -Message 'Partial'

            Write-ACRRollbackEntry -Action 'ResetPassword' -ResourceType 'UserPassword' `
                -ResourceId 'lifecycle@contoso.com' `
                -BeforeState @{ Note = 'Unknown' } -AfterState @{ Note = 'Random password set' }

            Write-ACRRollbackEntry -Action 'RemoveDelegates' -ResourceType 'MailboxDelegate' `
                -ResourceId 'delegate@evil.com' `
                -BeforeState @{ Role = 'FullAccess' } -AfterState @{ Role = 'Removed' }

            $summary = Stop-ACRLog

            # Verify counters
            $summary.Counters.Total | Should -Be 3
            $summary.Counters.Success | Should -Be 2
            $summary.Counters.Warning | Should -Be 1

            # Verify action log file
            $actionLog = Get-Content $summary.ActionLogPath -Raw | ConvertFrom-Json
            $actionLog.CorrelationId | Should -Be 'lc-001'
            $actionLog.AlertSource | Should -Be 'XDR'
            $actionLog.UserPrincipalName | Should -Be 'lifecycle@contoso.com'
            $actionLog.Actions.Count | Should -Be 3

            # Verify rollback journal file
            $journal = Get-Content $summary.RollbackPath -Raw | ConvertFrom-Json
            $journal.Entries.Count | Should -Be 2
            $journal.UserPrincipalName | Should -Be 'lifecycle@contoso.com'
        }
    }
}
