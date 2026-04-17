#Requires -Version 7.2

<#
.SYNOPSIS
    Logging and rollback journal module for Account Compromise Remediation.

.DESCRIPTION
    Provides structured JSON logging for all remediation actions, plus a
    rollback journal that records before/after state for manual reversal.
#>

$script:LogSession = $null

function Start-ACRLog {
    <#
    .SYNOPSIS
        Initializes a new logging session for a remediation run.
    .PARAMETER OutputPath
        Directory where log files will be written.
    .PARAMETER UserPrincipalName
        The UPN of the target user being remediated.
    .PARAMETER CorrelationId
        Optional correlation ID for linking to external alerts/incidents.
    .PARAMETER AlertSource
        Optional source identifier (e.g., "Sentinel", "XDR", "Manual").
    .OUTPUTS
        [PSCustomObject] The log session object.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$OutputPath,

        [Parameter(Mandatory)]
        [string]$UserPrincipalName,

        [Parameter()]
        [string]$CorrelationId = [guid]::NewGuid().ToString(),

        [Parameter()]
        [string]$AlertSource = 'Manual'
    )

    if (-not (Test-Path $OutputPath)) {
        New-Item -ItemType Directory -Path $OutputPath -Force | Out-Null
    }

    $timestamp = Get-Date -Format 'yyyyMMdd_HHmmss'
    $sessionId = [guid]::NewGuid().ToString('N').Substring(0, 8)

    $script:LogSession = [PSCustomObject]@{
        SessionId         = $sessionId
        CorrelationId     = $CorrelationId
        AlertSource       = $AlertSource
        UserPrincipalName = $UserPrincipalName
        StartTime         = (Get-Date).ToUniversalTime().ToString('o')
        EndTime           = $null
        OutputPath        = $OutputPath
        ActionLogPath     = Join-Path $OutputPath "action-log_${timestamp}.json"
        RollbackPath      = Join-Path $OutputPath "rollback-journal_${timestamp}.json"
        TranscriptPath    = Join-Path $OutputPath "transcript_${timestamp}.log"
        Actions           = [System.Collections.Generic.List[PSCustomObject]]::new()
        RollbackEntries   = [System.Collections.Generic.List[PSCustomObject]]::new()
        Counters          = @{
            Total     = 0
            Success   = 0
            Failed    = 0
            Skipped   = 0
            Warning   = 0
        }
    }

    # Start PowerShell transcript
    try {
        Start-Transcript -Path $script:LogSession.TranscriptPath -Force -ErrorAction Stop | Out-Null
    }
    catch {
        Write-Warning "Could not start transcript: $_"
    }

    Write-Verbose "ACR Log session started: $sessionId"
    return $script:LogSession
}

function Write-ACRAction {
    <#
    .SYNOPSIS
        Logs a remediation action with its result.
    .PARAMETER Action
        Name of the remediation action (e.g., "ResetPassword", "RevokeTokens").
    .PARAMETER Status
        Result status: Success, Failed, Skipped, Warning.
    .PARAMETER Message
        Human-readable description of what happened.
    .PARAMETER Details
        Optional additional details (object/hashtable).
    .PARAMETER Target
        The specific target of the action (e.g., a delegate email, an app ID).
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$Action,

        [Parameter(Mandatory)]
        [ValidateSet('Success', 'Failed', 'Skipped', 'Warning')]
        [string]$Status,

        [Parameter(Mandatory)]
        [string]$Message,

        [Parameter()]
        [object]$Details,

        [Parameter()]
        [string]$Target
    )

    if (-not $script:LogSession) {
        throw "No active log session. Call Start-ACRLog first."
    }

    $entry = [PSCustomObject]@{
        Timestamp = (Get-Date).ToUniversalTime().ToString('o')
        Action    = $Action
        Status    = $Status
        Message   = $Message
        Target    = $Target
        Details   = $Details
    }

    $script:LogSession.Actions.Add($entry)
    $script:LogSession.Counters.Total++
    $script:LogSession.Counters[$Status]++

    # Write to console with color coding
    $color = switch ($Status) {
        'Success' { 'Green' }
        'Failed'  { 'Red' }
        'Skipped' { 'Yellow' }
        'Warning' { 'DarkYellow' }
    }

    Write-Host "[$Status] $Action" -ForegroundColor $color -NoNewline
    Write-Host " - $Message"
}

function Write-ACRRollbackEntry {
    <#
    .SYNOPSIS
        Records a rollback journal entry with before/after state.
    .PARAMETER Action
        The remediation action that was performed.
    .PARAMETER ResourceType
        Type of resource modified (e.g., "MailboxDelegate", "ForwardingRule").
    .PARAMETER ResourceId
        Identifier of the specific resource.
    .PARAMETER BeforeState
        State of the resource before remediation.
    .PARAMETER AfterState
        State of the resource after remediation.
    .PARAMETER RollbackInstructions
        Human-readable instructions for how to undo this change.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$Action,

        [Parameter(Mandatory)]
        [string]$ResourceType,

        [Parameter()]
        [string]$ResourceId,

        [Parameter()]
        [object]$BeforeState,

        [Parameter()]
        [object]$AfterState,

        [Parameter()]
        [string]$RollbackInstructions
    )

    if (-not $script:LogSession) {
        throw "No active log session. Call Start-ACRLog first."
    }

    $entry = [PSCustomObject]@{
        Timestamp            = (Get-Date).ToUniversalTime().ToString('o')
        Action               = $Action
        ResourceType         = $ResourceType
        ResourceId           = $ResourceId
        BeforeState          = $BeforeState
        AfterState           = $AfterState
        RollbackInstructions = $RollbackInstructions
    }

    $script:LogSession.RollbackEntries.Add($entry)
    Write-Verbose "Rollback entry recorded: $Action on $ResourceType ($ResourceId)"
}

function Stop-ACRLog {
    <#
    .SYNOPSIS
        Finalizes the logging session and writes all logs to disk.
    .OUTPUTS
        [PSCustomObject] Summary of the logging session.
    #>
    [CmdletBinding()]
    param()

    if (-not $script:LogSession) {
        Write-Warning "No active log session to stop."
        return
    }

    $script:LogSession.EndTime = (Get-Date).ToUniversalTime().ToString('o')

    # Write action log
    $actionLog = [PSCustomObject]@{
        SessionId         = $script:LogSession.SessionId
        CorrelationId     = $script:LogSession.CorrelationId
        AlertSource       = $script:LogSession.AlertSource
        UserPrincipalName = $script:LogSession.UserPrincipalName
        StartTime         = $script:LogSession.StartTime
        EndTime           = $script:LogSession.EndTime
        Summary           = $script:LogSession.Counters
        Actions           = $script:LogSession.Actions
    }
    $actionLog | ConvertTo-Json -Depth 10 | Set-Content -Path $script:LogSession.ActionLogPath -Encoding UTF8

    # Write rollback journal
    $rollbackJournal = [PSCustomObject]@{
        SessionId         = $script:LogSession.SessionId
        UserPrincipalName = $script:LogSession.UserPrincipalName
        GeneratedAt       = $script:LogSession.EndTime
        Entries           = $script:LogSession.RollbackEntries
    }
    $rollbackJournal | ConvertTo-Json -Depth 10 | Set-Content -Path $script:LogSession.RollbackPath -Encoding UTF8

    # Stop transcript
    try {
        Stop-Transcript -ErrorAction SilentlyContinue | Out-Null
    }
    catch {
        # Transcript may not have started successfully
    }

    $summary = [PSCustomObject]@{
        SessionId      = $script:LogSession.SessionId
        ActionLogPath  = $script:LogSession.ActionLogPath
        RollbackPath   = $script:LogSession.RollbackPath
        TranscriptPath = $script:LogSession.TranscriptPath
        Counters       = $script:LogSession.Counters
    }

    Write-Verbose "ACR Log session finalized. Action log: $($script:LogSession.ActionLogPath)"

    $script:LogSession = $null
    return $summary
}

function Get-ACRLogSession {
    <#
    .SYNOPSIS
        Returns the current active log session.
    #>
    [CmdletBinding()]
    param()
    return $script:LogSession
}

Export-ModuleMember -Function @(
    'Start-ACRLog'
    'Write-ACRAction'
    'Write-ACRRollbackEntry'
    'Stop-ACRLog'
    'Get-ACRLogSession'
)
