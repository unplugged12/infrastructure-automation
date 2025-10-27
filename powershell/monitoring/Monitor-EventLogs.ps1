<#
.SYNOPSIS
    Monitor Windows Event Logs with filtering, alerting, and SIEM integration

.DESCRIPTION
    Comprehensive Windows Event Log monitoring script that filters events by ID, source,
    and severity level, searches for specific patterns, and provides multiple output
    formats for integration with monitoring systems and SIEM platforms.

    This script performs the following operations:
    - Monitors Windows Event Logs (Application, System, Security, Custom)
    - Filters events by EventID, Source, Level, and custom patterns
    - Searches log entries for specific text patterns using regex
    - Sends email digest reports with event summaries
    - Exports events to CSV, JSON, or XML formats
    - Provides historical trend analysis of event occurrences
    - Integrates with SIEM systems via structured data export
    - Supports remote computer monitoring
    - Generates HTML reports with event visualizations

    RISK LEVEL: Low

    This script performs read-only operations on Event Logs. It does not modify
    system configuration, clear logs, or make any changes to the system.

.PARAMETER LogName
    Name of the Event Log to monitor (Application, System, Security, or custom log name).
    Default: Application

.PARAMETER EventID
    Specific Event ID(s) to filter. Accepts single ID or array of IDs.
    Example: 1000 or @(1000, 1001, 1002)

.PARAMETER Source
    Event source to filter (e.g., "Application Error", "Service Control Manager").

.PARAMETER Level
    Event level to filter: Critical (1), Error (2), Warning (3), Information (4), Verbose (5).
    Accepts single level or array of levels.

.PARAMETER Pattern
    Regular expression pattern to search for in event messages.
    Example: "failed|error|timeout"

.PARAMETER Hours
    Number of hours to look back for events.
    Default: 24

.PARAMETER StartTime
    Specific start time for event search (overrides Hours parameter).
    Example: (Get-Date).AddDays(-7)

.PARAMETER EndTime
    Specific end time for event search.
    Default: Current time

.PARAMETER ComputerName
    Computer name(s) to query. Supports multiple computers and pipeline input.
    Default: Local computer

.PARAMETER MaxEvents
    Maximum number of events to retrieve.
    Default: 1000

.PARAMETER EmailTo
    Email address(es) to send digest reports.

.PARAMETER EmailFrom
    Sender email address for reports.
    Default: eventlog-monitor@domain.local

.PARAMETER SmtpServer
    SMTP server for email delivery.
    Default: smtp.domain.local

.PARAMETER SmtpPort
    SMTP server port.
    Default: 25

.PARAMETER OutputFormat
    Output format: CSV, JSON, XML, HTML, or GridView.
    Default: GridView

.PARAMETER OutputPath
    Path to save exported events. Required for CSV, JSON, XML, HTML formats.

.PARAMETER GroupBy
    Group events by: EventID, Source, Level, Computer, or Hour.
    Useful for trend analysis and summaries.

.PARAMETER IncludeStatistics
    Include statistical summary in output (event counts, top sources, trends).

.PARAMETER SiemFormat
    Export in SIEM-compatible format (Common Event Format - CEF or JSON).
    Values: CEF, JSON, None
    Default: None

.EXAMPLE
    .\Monitor-EventLogs.ps1 -LogName Application -Level Error -Hours 24

    Monitor Application log for all Error events in the past 24 hours.
    Display results in GridView.

.EXAMPLE
    .\Monitor-EventLogs.ps1 -LogName System -EventID 1000,1001,1002 -OutputFormat CSV -OutputPath "C:\Reports\events.csv"

    Export specific Event IDs from System log to CSV file.

.EXAMPLE
    .\Monitor-EventLogs.ps1 -LogName Security -Level @(1,2) -Hours 48 -EmailTo "security@company.com"

    Monitor Security log for Critical and Error events in past 48 hours and email digest.

.EXAMPLE
    .\Monitor-EventLogs.ps1 -LogName Application -Pattern "failed|error|exception" -OutputFormat HTML -OutputPath "C:\Reports\errors.html"

    Search Application log for events matching pattern and generate HTML report.

.EXAMPLE
    Get-Content servers.txt | .\Monitor-EventLogs.ps1 -LogName System -Level Warning -GroupBy Computer

    Monitor System log on multiple servers and group results by computer.

.EXAMPLE
    .\Monitor-EventLogs.ps1 -LogName Application -Hours 168 -GroupBy EventID -IncludeStatistics -OutputFormat JSON -OutputPath "C:\Reports\weekly.json"

    Generate weekly statistics report with event grouping and export to JSON.

.INPUTS
    System.String - Computer names can be piped to the script

.OUTPUTS
    PSCustomObject with properties:
    - TimeCreated: When event occurred
    - LogName: Source log name
    - EventID: Event identifier
    - Level: Severity level (Critical, Error, Warning, Information)
    - Source: Event source/provider
    - Message: Full event message
    - ComputerName: Computer where event occurred
    - UserName: User associated with event (if applicable)

.NOTES
    Author: SysAdmin Toolkit
    Created: 2025-10-06
    Modified: 2025-10-06
    Version: 1.0.0
    Risk Level: Low ✅

    Prerequisites:
        - PowerShell 5.1 or later (PowerShell 7+ recommended)
        - Event Log Readers group membership or Administrator privileges
        - Remote computer monitoring requires:
          * Remote Event Log Management (Windows Firewall exception)
          * Network connectivity to target computers
          * Appropriate permissions on remote systems

    Security Considerations:
        - Security log monitoring requires elevated privileges
        - Some events may contain sensitive information
        - Consider data privacy regulations when exporting logs
        - Limit access to exported files containing security events

    Performance Notes:
        - Large event logs can slow query performance
        - Use MaxEvents parameter to limit result set
        - Filter by EventID or Source for faster queries
        - Remote queries are slower than local queries

    SIEM Integration:
        - Splunk: Use JSON format with timestamp normalization
        - ELK Stack: Export as JSON for Logstash ingestion
        - QRadar: Use CEF format for event import
        - ArcSight: CEF format compatible

    Change Log:
        1.0.0 - 2025-10-06 - Initial release
              - Event log filtering by multiple criteria
              - Pattern-based message searching
              - Email digest reporting
              - CSV/JSON/XML/HTML export
              - SIEM format support (CEF, JSON)
              - Statistical analysis and grouping
              - Remote computer support

.LINK
    https://github.com/unplugged12/sysadmin-toolkit

.LINK
    Get-WinEvent

.LINK
    Get-EventLog
#>

[CmdletBinding(DefaultParameterSetName='Default')]
param(
    [Parameter(Mandatory = $false, HelpMessage = "Event log name to monitor")]
    [string]$LogName = 'Application',

    [Parameter(Mandatory = $false, HelpMessage = "Event ID(s) to filter")]
    [int[]]$EventID,

    [Parameter(Mandatory = $false, HelpMessage = "Event source/provider to filter")]
    [string]$Source,

    [Parameter(Mandatory = $false, HelpMessage = "Event level: 1=Critical, 2=Error, 3=Warning, 4=Information")]
    [ValidateSet(1, 2, 3, 4, 5)]
    [int[]]$Level,

    [Parameter(Mandatory = $false, HelpMessage = "Regex pattern to search in event messages")]
    [string]$Pattern,

    [Parameter(Mandatory = $false, HelpMessage = "Hours to look back for events")]
    [int]$Hours = 24,

    [Parameter(Mandatory = $false, HelpMessage = "Start time for event search")]
    [DateTime]$StartTime,

    [Parameter(Mandatory = $false, HelpMessage = "End time for event search")]
    [DateTime]$EndTime = (Get-Date),

    [Parameter(Mandatory = $false, ValueFromPipeline = $true, HelpMessage = "Computer name(s) to query")]
    [string[]]$ComputerName = @($env:COMPUTERNAME),

    [Parameter(Mandatory = $false, HelpMessage = "Maximum number of events to retrieve")]
    [int]$MaxEvents = 1000,

    [Parameter(Mandatory = $false, HelpMessage = "Email address(es) for digest reports")]
    [string[]]$EmailTo,

    [Parameter(Mandatory = $false, HelpMessage = "Sender email address")]
    [string]$EmailFrom = "eventlog-monitor@domain.local",

    [Parameter(Mandatory = $false, HelpMessage = "SMTP server address")]
    [string]$SmtpServer = "smtp.domain.local",

    [Parameter(Mandatory = $false, HelpMessage = "SMTP server port")]
    [int]$SmtpPort = 25,

    [Parameter(Mandatory = $false, HelpMessage = "Output format")]
    [ValidateSet('CSV', 'JSON', 'XML', 'HTML', 'GridView')]
    [string]$OutputFormat = 'GridView',

    [Parameter(Mandatory = $false, HelpMessage = "Path to save output")]
    [string]$OutputPath,

    [Parameter(Mandatory = $false, HelpMessage = "Group events by field")]
    [ValidateSet('EventID', 'Source', 'Level', 'Computer', 'Hour', 'None')]
    [string]$GroupBy = 'None',

    [Parameter(Mandatory = $false, HelpMessage = "Include statistical summary")]
    [switch]$IncludeStatistics,

    [Parameter(Mandatory = $false, HelpMessage = "SIEM export format")]
    [ValidateSet('CEF', 'JSON', 'None')]
    [string]$SiemFormat = 'None'
)

begin {
    # Initialize
    $allEvents = @()
    $startTimeActual = if ($StartTime) { $StartTime } else { (Get-Date).AddHours(-$Hours) }

    Write-Verbose "Event Log Monitor Starting..."
    Write-Verbose "Log: $LogName | Start: $startTimeActual | End: $EndTime"

    # Function to build filter hashtable
    function Build-EventFilter {
        param(
            [string]$Log,
            [DateTime]$Start,
            [DateTime]$End,
            [int[]]$EventIDs,
            [int[]]$Levels,
            [string]$Provider
        )

        $filterHash = @{
            LogName = $Log
            StartTime = $Start
            EndTime = $End
        }

        if ($EventIDs) {
            $filterHash['ID'] = $EventIDs
        }

        if ($Levels) {
            $filterHash['Level'] = $Levels
        }

        if ($Provider) {
            $filterHash['ProviderName'] = $Provider
        }

        return $filterHash
    }

    # Function to convert event level to friendly name
    function Get-LevelName {
        param([int]$LevelValue)

        switch ($LevelValue) {
            1 { 'Critical' }
            2 { 'Error' }
            3 { 'Warning' }
            4 { 'Information' }
            5 { 'Verbose' }
            default { 'Unknown' }
        }
    }

    # Function to retrieve events
    function Get-FilteredEvents {
        param(
            [string]$Computer,
            [hashtable]$Filter,
            [string]$MessagePattern,
            [int]$Max
        )

        try {
            Write-Verbose "Querying $Computer for events in $($Filter.LogName) log..."

            # Build filter hashtable for Get-WinEvent
            $getWinEventParams = @{
                FilterHashtable = $Filter
                ComputerName = $Computer
                MaxEvents = $Max
                ErrorAction = 'Stop'
            }

            $events = Get-WinEvent @getWinEventParams

            # Filter by pattern if specified
            if ($MessagePattern) {
                Write-Verbose "Applying pattern filter: $MessagePattern"
                $events = $events | Where-Object { $_.Message -match $MessagePattern }
            }

            # Convert to custom objects for easier handling
            foreach ($event in $events) {
                [PSCustomObject]@{
                    TimeCreated  = $event.TimeCreated
                    LogName      = $event.LogName
                    EventID      = $event.Id
                    Level        = Get-LevelName -LevelValue $event.Level
                    LevelValue   = $event.Level
                    Source       = $event.ProviderName
                    Message      = $event.Message
                    ComputerName = $Computer
                    UserName     = if ($event.UserId) { $event.UserId.Value } else { 'N/A' }
                    TaskCategory = $event.TaskDisplayName
                    RecordID     = $event.RecordId
                }
            }

            Write-Verbose "Retrieved $($events.Count) events from $Computer"
        }
        catch {
            Write-Warning "Failed to query events from ${Computer}: $_"
            @()
        }
    }

    # Function to generate statistics
    function Get-EventStatistics {
        param($Events)

        if ($Events.Count -eq 0) {
            return $null
        }

        $stats = [PSCustomObject]@{
            TotalEvents = $Events.Count
            TimeRange = "$($Events[-1].TimeCreated) to $($Events[0].TimeCreated)"
            Computers = ($Events.ComputerName | Select-Object -Unique).Count
            TopEventIDs = ($Events | Group-Object EventID | Sort-Object Count -Descending | Select-Object -First 5 | ForEach-Object { "$($_.Name) ($($_.Count))" }) -join ', '
            TopSources = ($Events | Group-Object Source | Sort-Object Count -Descending | Select-Object -First 5 | ForEach-Object { "$($_.Name) ($($_.Count))" }) -join ', '
            ByLevel = @{
                Critical = ($Events | Where-Object LevelValue -eq 1).Count
                Error = ($Events | Where-Object LevelValue -eq 2).Count
                Warning = ($Events | Where-Object LevelValue -eq 3).Count
                Information = ($Events | Where-Object LevelValue -eq 4).Count
            }
        }

        return $stats
    }

    # Function to send email digest
    function Send-EventDigest {
        param($Events, $Statistics)

        if (-not $EmailTo -or $Events.Count -eq 0) { return }

        try {
            $subject = "Event Log Digest - $LogName - $($Events.Count) Events"

            $body = "Event Log Monitoring Digest`n"
            $body += "Generated: $(Get-Date)`n`n"

            if ($Statistics) {
                $body += "=== Statistics ===`n"
                $body += "Total Events: $($Statistics.TotalEvents)`n"
                $body += "Time Range: $($Statistics.TimeRange)`n"
                $body += "Computers Monitored: $($Statistics.Computers)`n"
                $body += "Critical: $($Statistics.ByLevel.Critical) | Error: $($Statistics.ByLevel.Error) | Warning: $($Statistics.ByLevel.Warning) | Info: $($Statistics.ByLevel.Information)`n"
                $body += "`nTop Event IDs: $($Statistics.TopEventIDs)`n"
                $body += "Top Sources: $($Statistics.TopSources)`n`n"
            }

            $body += "=== Recent Events ===`n"
            $recentEvents = $Events | Select-Object -First 20
            foreach ($event in $recentEvents) {
                $body += "[$($event.Level)] $($event.TimeCreated) - $($event.Source) - EventID $($event.EventID)`n"
                $body += "  Computer: $($event.ComputerName)`n"
                $body += "  Message: $($event.Message.Substring(0, [Math]::Min(200, $event.Message.Length)))...`n`n"
            }

            if ($Events.Count -gt 20) {
                $body += "`n... and $($Events.Count - 20) more events. See attached report for details.`n"
            }

            $mailParams = @{
                To = $EmailTo
                From = $EmailFrom
                Subject = $subject
                Body = $body
                SmtpServer = $SmtpServer
                Port = $SmtpPort
            }

            Send-MailMessage @mailParams -ErrorAction Stop
            Write-Host "Email digest sent to $($EmailTo -join ', ')" -ForegroundColor Green
        }
        catch {
            Write-Warning "Failed to send email digest: $_"
        }
    }

    # Function to convert to CEF format (Common Event Format for SIEM)
    function ConvertTo-CEF {
        param($Events)

        $cefEvents = foreach ($event in $Events) {
            $severity = switch ($event.LevelValue) {
                1 { 10 }  # Critical
                2 { 8 }   # Error
                3 { 5 }   # Warning
                4 { 2 }   # Information
                default { 0 }
            }

            # CEF format: CEF:Version|Device Vendor|Device Product|Device Version|Signature ID|Name|Severity|Extension
            "CEF:0|Microsoft|Windows|NT 10.0|$($event.EventID)|$($event.Source)|$severity|" +
            "rt=$($event.TimeCreated.ToString('MMM dd yyyy HH:mm:ss')) " +
            "dvc=$($event.ComputerName) " +
            "msg=$($event.Message.Replace('|', '\|').Replace('=', '\='))"
        }

        return $cefEvents -join "`n"
    }

    # Function to generate HTML report
    function ConvertTo-HtmlReport {
        param($Events, $Statistics)

        $html = @"
<!DOCTYPE html>
<html>
<head>
    <title>Event Log Report - $LogName</title>
    <style>
        body { font-family: Arial, sans-serif; margin: 20px; }
        h1 { color: #333; }
        .summary { background-color: #e7f3ff; padding: 15px; border-radius: 5px; margin-bottom: 20px; }
        table { border-collapse: collapse; width: 100%; margin-top: 20px; }
        th { background-color: #4CAF50; color: white; padding: 12px; text-align: left; position: sticky; top: 0; }
        td { border: 1px solid #ddd; padding: 8px; font-size: 12px; }
        tr:nth-child(even) { background-color: #f2f2f2; }
        .critical { background-color: #f8d7da; font-weight: bold; }
        .error { background-color: #f8d7da; }
        .warning { background-color: #fff3cd; }
        .information { background-color: #d1ecf1; }
        .message { max-width: 400px; overflow: hidden; text-overflow: ellipsis; }
    </style>
</head>
<body>
    <h1>Event Log Report: $LogName</h1>
"@

        if ($Statistics) {
            $html += @"
    <div class="summary">
        <h2>Summary Statistics</h2>
        <p><strong>Total Events:</strong> $($Statistics.TotalEvents)</p>
        <p><strong>Time Range:</strong> $($Statistics.TimeRange)</p>
        <p><strong>Computers:</strong> $($Statistics.Computers)</p>
        <p><strong>By Level:</strong> Critical: $($Statistics.ByLevel.Critical), Error: $($Statistics.ByLevel.Error), Warning: $($Statistics.ByLevel.Warning), Info: $($Statistics.ByLevel.Information)</p>
        <p><strong>Top Event IDs:</strong> $($Statistics.TopEventIDs)</p>
        <p><strong>Top Sources:</strong> $($Statistics.TopSources)</p>
    </div>
"@
        }

        $html += @"
    <table>
        <tr>
            <th>Time</th>
            <th>Computer</th>
            <th>Level</th>
            <th>Event ID</th>
            <th>Source</th>
            <th>Message</th>
        </tr>
"@

        foreach ($event in $Events) {
            $levelClass = $event.Level.ToLower()
            $messagePreview = $event.Message.Substring(0, [Math]::Min(200, $event.Message.Length))
            $html += @"
        <tr class="$levelClass">
            <td>$($event.TimeCreated.ToString('yyyy-MM-dd HH:mm:ss'))</td>
            <td>$($event.ComputerName)</td>
            <td>$($event.Level)</td>
            <td>$($event.EventID)</td>
            <td>$($event.Source)</td>
            <td class="message">$messagePreview</td>
        </tr>
"@
        }

        $html += @"
    </table>
</body>
</html>
"@

        return $html
    }
}

process {
    # Query events from each computer
    foreach ($computer in $ComputerName) {
        Write-Host "Querying event log '$LogName' on $computer..." -ForegroundColor Cyan

        $filter = Build-EventFilter -Log $LogName -Start $startTimeActual -End $EndTime `
                                     -EventIDs $EventID -Levels $Level -Provider $Source

        $events = Get-FilteredEvents -Computer $computer -Filter $filter `
                                      -MessagePattern $Pattern -Max $MaxEvents

        $allEvents += $events

        Write-Host "Retrieved $($events.Count) events from $computer" -ForegroundColor Green
    }
}

end {
    if ($allEvents.Count -eq 0) {
        Write-Warning "No events found matching the specified criteria."
        exit 0
    }

    Write-Host "`nTotal events retrieved: $($allEvents.Count)" -ForegroundColor Cyan

    # Generate statistics if requested
    $statistics = if ($IncludeStatistics) {
        Get-EventStatistics -Events $allEvents
    } else {
        $null
    }

    # Group events if requested
    if ($GroupBy -ne 'None') {
        Write-Host "Grouping events by: $GroupBy" -ForegroundColor Cyan

        $grouped = switch ($GroupBy) {
            'EventID' { $allEvents | Group-Object EventID | Select-Object Name, Count, @{N='Events';E={$_.Group}} }
            'Source' { $allEvents | Group-Object Source | Select-Object Name, Count, @{N='Events';E={$_.Group}} }
            'Level' { $allEvents | Group-Object Level | Select-Object Name, Count, @{N='Events';E={$_.Group}} }
            'Computer' { $allEvents | Group-Object ComputerName | Select-Object Name, Count, @{N='Events';E={$_.Group}} }
            'Hour' { $allEvents | Group-Object {$_.TimeCreated.ToString('yyyy-MM-dd HH:00')} | Select-Object Name, Count, @{N='Events';E={$_.Group}} }
        }

        $grouped | Format-Table Name, Count -AutoSize
    }

    # Handle output format
    switch ($OutputFormat) {
        'CSV' {
            if (-not $OutputPath) {
                Write-Error "OutputPath is required for CSV format"
                exit 1
            }
            $allEvents | Export-Csv -Path $OutputPath -NoTypeInformation -Force
            Write-Host "Events exported to CSV: $OutputPath" -ForegroundColor Green
        }
        'JSON' {
            if ($SiemFormat -eq 'JSON') {
                $output = $allEvents | ConvertTo-Json -Depth 10
            } else {
                $output = $allEvents | ConvertTo-Json -Depth 10
            }

            if ($OutputPath) {
                $output | Set-Content -Path $OutputPath -Force
                Write-Host "Events exported to JSON: $OutputPath" -ForegroundColor Green
            } else {
                Write-Output $output
            }
        }
        'XML' {
            if (-not $OutputPath) {
                Write-Error "OutputPath is required for XML format"
                exit 1
            }
            $allEvents | Export-Clixml -Path $OutputPath -Force
            Write-Host "Events exported to XML: $OutputPath" -ForegroundColor Green
        }
        'HTML' {
            $htmlReport = ConvertTo-HtmlReport -Events $allEvents -Statistics $statistics

            if ($OutputPath) {
                $htmlReport | Set-Content -Path $OutputPath -Force
                Write-Host "HTML report saved: $OutputPath" -ForegroundColor Green
            } else {
                Write-Output $htmlReport
            }
        }
        'GridView' {
            $allEvents | Out-GridView -Title "Event Log Monitor - $LogName"
        }
    }

    # Export in SIEM format if requested
    if ($SiemFormat -eq 'CEF') {
        $cefOutput = ConvertTo-CEF -Events $allEvents
        $cefPath = if ($OutputPath) {
            $OutputPath -replace '\.\w+$', '.cef'
        } else {
            "events_$(Get-Date -Format 'yyyyMMdd_HHmmss').cef"
        }
        $cefOutput | Set-Content -Path $cefPath -Force
        Write-Host "CEF format exported: $cefPath" -ForegroundColor Green
    }

    # Send email digest
    Send-EventDigest -Events $allEvents -Statistics $statistics

    # Display statistics
    if ($statistics) {
        Write-Host "`n=== Event Statistics ===" -ForegroundColor Yellow
        Write-Host "Total Events: $($statistics.TotalEvents)"
        Write-Host "Time Range: $($statistics.TimeRange)"
        Write-Host "Computers: $($statistics.Computers)"
        Write-Host "Critical: $($statistics.ByLevel.Critical) | Error: $($statistics.ByLevel.Error) | Warning: $($statistics.ByLevel.Warning) | Info: $($statistics.ByLevel.Information)"
        Write-Host "Top Event IDs: $($statistics.TopEventIDs)"
        Write-Host "Top Sources: $($statistics.TopSources)"
    }

    Write-Host "`nEvent log monitoring completed successfully." -ForegroundColor Green
}
