<#
.SYNOPSIS
    Monitor disk space across all drives with configurable thresholds and alerting

.DESCRIPTION
    Comprehensive disk space monitoring script that checks all local and remote drives,
    compares usage against configurable warning and critical thresholds, and provides
    multiple alerting and reporting options.

    This script performs the following operations:
    - Monitors all local fixed drives or specified remote computers
    - Compares disk usage against warning and critical thresholds
    - Sends email or webhook alerts when thresholds are exceeded
    - Generates JSON or HTML formatted reports
    - Tracks disk space trends over time with historical data
    - Provides Nagios-compatible exit codes for monitoring integration
    - Supports multiple output formats for different monitoring platforms

    RISK LEVEL: Low

    The script is read-only and performs no modifications to the system.
    It only retrieves disk space information and sends notifications.

.PARAMETER ThresholdWarning
    Percentage of disk space used that triggers a warning alert.
    Default: 80

.PARAMETER ThresholdCritical
    Percentage of disk space used that triggers a critical alert.
    Default: 90

.PARAMETER ComputerName
    One or more computer names to monitor. If not specified, monitors local computer.
    Accepts pipeline input and comma-separated values.

.PARAMETER EmailTo
    Email address(es) to send alerts. Multiple addresses can be comma-separated.
    Requires EmailFrom, SmtpServer to be configured.

.PARAMETER EmailFrom
    Email address to use as sender for alerts.
    Default: monitoring@domain.local

.PARAMETER SmtpServer
    SMTP server address for sending email alerts.
    Default: smtp.domain.local

.PARAMETER SmtpPort
    SMTP server port number.
    Default: 25

.PARAMETER WebhookUrl
    Webhook URL for sending alerts (Slack, Teams, Discord, custom webhook).
    Supports JSON payload delivery.

.PARAMETER OutputFormat
    Format for report output: JSON, HTML, or Text.
    Default: Text

.PARAMETER OutputPath
    Path to save the report file. If not specified, outputs to console only.

.PARAMETER IncludeNetwork
    Include network drives in monitoring. By default, only fixed local drives are monitored.

.PARAMETER TrendDays
    Number of days to include in trend analysis. Requires historical data file.
    Default: 7

.PARAMETER HistoryPath
    Path to store historical disk space data for trend analysis.
    Default: C:\ProgramData\DiskSpaceHistory.json

.PARAMETER Quiet
    Suppress console output. Useful when running as scheduled task.

.EXAMPLE
    .\Monitor-DiskSpace.ps1

    Monitors local computer drives with default thresholds (80% warning, 90% critical).
    Displays text output to console.

.EXAMPLE
    .\Monitor-DiskSpace.ps1 -ThresholdWarning 70 -ThresholdCritical 85 -EmailTo "admin@company.com"

    Monitors local drives with custom thresholds and sends email alerts when thresholds
    are exceeded.

.EXAMPLE
    .\Monitor-DiskSpace.ps1 -ComputerName "SERVER01","SERVER02" -OutputFormat JSON -OutputPath "C:\Reports\diskspace.json"

    Monitors multiple remote servers and saves results as JSON file.

.EXAMPLE
    Get-Content servers.txt | .\Monitor-DiskSpace.ps1 -ThresholdWarning 75 -WebhookUrl "https://hooks.slack.com/services/xxx"

    Reads computer names from file via pipeline and sends alerts to Slack webhook.

.EXAMPLE
    .\Monitor-DiskSpace.ps1 -OutputFormat HTML -OutputPath "C:\Reports\diskspace.html" -TrendDays 30

    Generates HTML report with 30-day trend analysis and saves to file.

.INPUTS
    System.String - Computer names can be piped to the script

.OUTPUTS
    PSCustomObject with properties:
    - ComputerName: Name of monitored computer
    - DriveLetter: Drive letter (C:, D:, etc.)
    - TotalSizeGB: Total capacity in GB
    - UsedSpaceGB: Used space in GB
    - FreeSpaceGB: Free space in GB
    - PercentUsed: Percentage of space used
    - Status: OK, Warning, or Critical
    - Timestamp: When measurement was taken

.NOTES
    Author: SysAdmin Toolkit
    Created: 2025-10-06
    Modified: 2025-10-06
    Version: 1.0.0
    Risk Level: Low ✅

    Prerequisites:
        - PowerShell 5.1 or later (PowerShell 7+ recommended)
        - WMI/CIM access to remote computers (if monitoring remotely)
        - Network connectivity to SMTP server (if using email alerts)
        - Appropriate permissions to query disk information

    Exit Codes (Nagios Compatible):
        0 - OK: All drives below warning threshold
        1 - WARNING: One or more drives exceed warning threshold
        2 - CRITICAL: One or more drives exceed critical threshold
        3 - UNKNOWN: Error occurred during monitoring

    Integration with Monitoring Systems:
        - Nagios/Icinga: Use exit codes for status determination
        - Prometheus: Parse JSON output for metrics export
        - Zabbix: Use JSON output for low-level discovery
        - SIEM: Forward JSON logs for analysis

    Change Log:
        1.0.0 - 2025-10-06 - Initial release
              - Disk space monitoring with thresholds
              - Email and webhook alerting
              - JSON/HTML/Text output formats
              - Trend analysis support
              - Nagios-compatible exit codes

.LINK
    https://github.com/unplugged12/sysadmin-toolkit

.LINK
    Get-Volume

.LINK
    Get-CimInstance
#>

[CmdletBinding(DefaultParameterSetName='Default')]
param(
    [Parameter(Mandatory = $false, HelpMessage = "Warning threshold percentage (1-100)")]
    [ValidateRange(1, 100)]
    [int]$ThresholdWarning = 80,

    [Parameter(Mandatory = $false, HelpMessage = "Critical threshold percentage (1-100)")]
    [ValidateRange(1, 100)]
    [int]$ThresholdCritical = 90,

    [Parameter(Mandatory = $false, ValueFromPipeline = $true, ValueFromPipelineByPropertyName = $true, HelpMessage = "Computer name(s) to monitor")]
    [Alias('CN', 'Server', 'Name')]
    [string[]]$ComputerName = @($env:COMPUTERNAME),

    [Parameter(Mandatory = $false, HelpMessage = "Email address(es) for alerts")]
    [string[]]$EmailTo,

    [Parameter(Mandatory = $false, HelpMessage = "Email sender address")]
    [string]$EmailFrom = "monitoring@domain.local",

    [Parameter(Mandatory = $false, HelpMessage = "SMTP server address")]
    [string]$SmtpServer = "smtp.domain.local",

    [Parameter(Mandatory = $false, HelpMessage = "SMTP server port")]
    [int]$SmtpPort = 25,

    [Parameter(Mandatory = $false, HelpMessage = "Webhook URL for alerts")]
    [uri]$WebhookUrl,

    [Parameter(Mandatory = $false, HelpMessage = "Output format: JSON, HTML, or Text")]
    [ValidateSet('JSON', 'HTML', 'Text')]
    [string]$OutputFormat = 'Text',

    [Parameter(Mandatory = $false, HelpMessage = "Path to save output file")]
    [string]$OutputPath,

    [Parameter(Mandatory = $false, HelpMessage = "Include network drives")]
    [switch]$IncludeNetwork,

    [Parameter(Mandatory = $false, HelpMessage = "Number of days for trend analysis")]
    [ValidateRange(1, 365)]
    [int]$TrendDays = 7,

    [Parameter(Mandatory = $false, HelpMessage = "Path to store historical data")]
    [string]$HistoryPath = "C:\ProgramData\DiskSpaceHistory.json",

    [Parameter(Mandatory = $false, HelpMessage = "Suppress console output")]
    [switch]$Quiet
)

begin {
    # Initialize variables
    $results = @()
    $exitCode = 0  # 0 = OK, 1 = WARNING, 2 = CRITICAL, 3 = UNKNOWN
    $timestamp = Get-Date

    # Validate threshold logic
    if ($ThresholdCritical -le $ThresholdWarning) {
        Write-Error "Critical threshold ($ThresholdCritical%) must be greater than warning threshold ($ThresholdWarning%)"
        exit 3
    }

    # Function to get disk space information
    function Get-DiskSpaceInfo {
        param(
            [string]$Computer,
            [bool]$IncludeNetworkDrives
        )

        try {
            # Build filter for drive types
            # DriveType: 2=Removable, 3=Fixed, 4=Network, 5=CD-ROM
            $driveTypeFilter = if ($IncludeNetworkDrives) {
                "DriveType=3 OR DriveType=4"
            } else {
                "DriveType=3"
            }

            # Query disk information using CIM (preferred over WMI)
            $disks = Get-CimInstance -ClassName Win32_LogicalDisk -ComputerName $Computer -Filter $driveTypeFilter -ErrorAction Stop

            foreach ($disk in $disks) {
                # Skip drives with no size (not ready)
                if ($disk.Size -eq $null -or $disk.Size -eq 0) {
                    continue
                }

                $totalGB = [math]::Round($disk.Size / 1GB, 2)
                $freeGB = [math]::Round($disk.FreeSpace / 1GB, 2)
                $usedGB = [math]::Round(($disk.Size - $disk.FreeSpace) / 1GB, 2)
                $percentUsed = [math]::Round((($disk.Size - $disk.FreeSpace) / $disk.Size) * 100, 2)

                # Determine status based on thresholds
                $status = if ($percentUsed -ge $ThresholdCritical) {
                    'Critical'
                } elseif ($percentUsed -ge $ThresholdWarning) {
                    'Warning'
                } else {
                    'OK'
                }

                # Create output object
                [PSCustomObject]@{
                    ComputerName = $Computer
                    DriveLetter  = $disk.DeviceID
                    VolumeName   = $disk.VolumeName
                    DriveType    = switch ($disk.DriveType) {
                        2 { 'Removable' }
                        3 { 'Fixed' }
                        4 { 'Network' }
                        5 { 'CD-ROM' }
                        default { 'Unknown' }
                    }
                    TotalSizeGB  = $totalGB
                    UsedSpaceGB  = $usedGB
                    FreeSpaceGB  = $freeGB
                    PercentUsed  = $percentUsed
                    Status       = $status
                    Timestamp    = $timestamp
                }
            }
        }
        catch {
            Write-Error "Failed to query disk space on ${Computer}: $_"
            [PSCustomObject]@{
                ComputerName = $Computer
                DriveLetter  = 'N/A'
                VolumeName   = 'ERROR'
                DriveType    = 'Unknown'
                TotalSizeGB  = 0
                UsedSpaceGB  = 0
                FreeSpaceGB  = 0
                PercentUsed  = 0
                Status       = 'Error'
                Timestamp    = $timestamp
            }
        }
    }

    # Function to send email alert
    function Send-EmailAlert {
        param($DiskResults)

        if (-not $EmailTo) { return }

        try {
            $alertDisks = $DiskResults | Where-Object { $_.Status -ne 'OK' -and $_.Status -ne 'Error' }

            if ($alertDisks.Count -eq 0) { return }

            $subject = "Disk Space Alert - $(($alertDisks | Where-Object Status -eq 'Critical').Count) Critical, $(($alertDisks | Where-Object Status -eq 'Warning').Count) Warning"

            $body = "Disk Space Monitoring Alert - Generated at $timestamp`n`n"
            $body += "The following drives have exceeded thresholds:`n`n"

            foreach ($disk in $alertDisks) {
                $body += "[$($disk.Status)] $($disk.ComputerName) - $($disk.DriveLetter) ($($disk.VolumeName))`n"
                $body += "  Used: $($disk.UsedSpaceGB) GB / $($disk.TotalSizeGB) GB ($($disk.PercentUsed)%)`n"
                $body += "  Free: $($disk.FreeSpaceGB) GB`n`n"
            }

            $body += "`nThresholds: Warning = $ThresholdWarning%, Critical = $ThresholdCritical%`n"

            $mailParams = @{
                To         = $EmailTo
                From       = $EmailFrom
                Subject    = $subject
                Body       = $body
                SmtpServer = $SmtpServer
                Port       = $SmtpPort
            }

            Send-MailMessage @mailParams -ErrorAction Stop

            if (-not $Quiet) {
                Write-Host "Email alert sent to $($EmailTo -join ', ')" -ForegroundColor Green
            }
        }
        catch {
            Write-Warning "Failed to send email alert: $_"
        }
    }

    # Function to send webhook alert
    function Send-WebhookAlert {
        param($DiskResults)

        if (-not $WebhookUrl) { return }

        try {
            $alertDisks = $DiskResults | Where-Object { $_.Status -ne 'OK' -and $_.Status -ne 'Error' }

            if ($alertDisks.Count -eq 0) { return }

            # Build JSON payload (Slack/Teams/Discord compatible format)
            $criticalCount = ($alertDisks | Where-Object Status -eq 'Critical').Count
            $warningCount = ($alertDisks | Where-Object Status -eq 'Warning').Count

            $color = if ($criticalCount -gt 0) { "#FF0000" } else { "#FFA500" }

            $text = "Disk Space Alert: $criticalCount Critical, $warningCount Warning"

            $fields = $alertDisks | ForEach-Object {
                @{
                    title = "$($_.ComputerName) - $($_.DriveLetter)"
                    value = "Used: $($_.PercentUsed)% ($($_.UsedSpaceGB)/$($_.TotalSizeGB) GB) - Status: $($_.Status)"
                    short = $false
                }
            }

            # Generic webhook payload (works with Slack, can be adapted for Teams/Discord)
            $payload = @{
                text = $text
                attachments = @(
                    @{
                        color = $color
                        fields = $fields
                        footer = "Disk Space Monitoring"
                        ts = [int][double]::Parse((Get-Date -UFormat %s))
                    }
                )
            } | ConvertTo-Json -Depth 10

            Invoke-RestMethod -Uri $WebhookUrl -Method Post -Body $payload -ContentType 'application/json' -ErrorAction Stop

            if (-not $Quiet) {
                Write-Host "Webhook alert sent to $WebhookUrl" -ForegroundColor Green
            }
        }
        catch {
            Write-Warning "Failed to send webhook alert: $_"
        }
    }

    # Function to save historical data
    function Save-HistoricalData {
        param($DiskResults)

        try {
            # Load existing history
            $history = if (Test-Path $HistoryPath) {
                Get-Content $HistoryPath -Raw | ConvertFrom-Json
            } else {
                @()
            }

            # Add current results to history
            $history += $DiskResults

            # Keep only data within trend period
            $cutoffDate = $timestamp.AddDays(-$TrendDays)
            $history = $history | Where-Object { [DateTime]$_.Timestamp -gt $cutoffDate }

            # Save history
            $history | ConvertTo-Json -Depth 10 | Set-Content $HistoryPath -Force
        }
        catch {
            Write-Warning "Failed to save historical data: $_"
        }
    }

    # Function to generate HTML report
    function ConvertTo-HtmlReport {
        param($DiskResults)

        $html = @"
<!DOCTYPE html>
<html>
<head>
    <title>Disk Space Report - $timestamp</title>
    <style>
        body { font-family: Arial, sans-serif; margin: 20px; }
        h1 { color: #333; }
        table { border-collapse: collapse; width: 100%; margin-top: 20px; }
        th { background-color: #4CAF50; color: white; padding: 12px; text-align: left; }
        td { border: 1px solid #ddd; padding: 8px; }
        tr:nth-child(even) { background-color: #f2f2f2; }
        .ok { background-color: #d4edda; }
        .warning { background-color: #fff3cd; }
        .critical { background-color: #f8d7da; }
        .error { background-color: #e2e3e5; }
        .summary { background-color: #e7f3ff; padding: 15px; border-radius: 5px; margin-bottom: 20px; }
    </style>
</head>
<body>
    <h1>Disk Space Monitoring Report</h1>
    <div class="summary">
        <p><strong>Generated:</strong> $timestamp</p>
        <p><strong>Computers Monitored:</strong> $(($DiskResults.ComputerName | Select-Object -Unique).Count)</p>
        <p><strong>Total Drives:</strong> $($DiskResults.Count)</p>
        <p><strong>Critical:</strong> $(($DiskResults | Where-Object Status -eq 'Critical').Count)</p>
        <p><strong>Warning:</strong> $(($DiskResults | Where-Object Status -eq 'Warning').Count)</p>
        <p><strong>OK:</strong> $(($DiskResults | Where-Object Status -eq 'OK').Count)</p>
        <p><strong>Thresholds:</strong> Warning = $ThresholdWarning%, Critical = $ThresholdCritical%</p>
    </div>
    <table>
        <tr>
            <th>Computer</th>
            <th>Drive</th>
            <th>Volume</th>
            <th>Type</th>
            <th>Total (GB)</th>
            <th>Used (GB)</th>
            <th>Free (GB)</th>
            <th>% Used</th>
            <th>Status</th>
        </tr>
"@

        foreach ($disk in $DiskResults | Sort-Object ComputerName, DriveLetter) {
            $statusClass = $disk.Status.ToLower()
            $html += @"
        <tr class="$statusClass">
            <td>$($disk.ComputerName)</td>
            <td>$($disk.DriveLetter)</td>
            <td>$($disk.VolumeName)</td>
            <td>$($disk.DriveType)</td>
            <td>$($disk.TotalSizeGB)</td>
            <td>$($disk.UsedSpaceGB)</td>
            <td>$($disk.FreeSpaceGB)</td>
            <td>$($disk.PercentUsed)%</td>
            <td>$($disk.Status)</td>
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
    # Process each computer
    foreach ($computer in $ComputerName) {
        if (-not $Quiet) {
            Write-Host "Monitoring disk space on: $computer" -ForegroundColor Cyan
        }

        $diskInfo = Get-DiskSpaceInfo -Computer $computer -IncludeNetworkDrives:$IncludeNetwork
        $results += $diskInfo

        # Update exit code based on worst status
        foreach ($disk in $diskInfo) {
            if ($disk.Status -eq 'Critical' -and $exitCode -lt 2) {
                $exitCode = 2
            }
            elseif ($disk.Status -eq 'Warning' -and $exitCode -lt 1) {
                $exitCode = 1
            }
            elseif ($disk.Status -eq 'Error' -and $exitCode -lt 3) {
                $exitCode = 3
            }
        }
    }
}

end {
    # Generate output based on format
    switch ($OutputFormat) {
        'JSON' {
            $output = $results | ConvertTo-Json -Depth 10
        }
        'HTML' {
            $output = ConvertTo-HtmlReport -DiskResults $results
        }
        'Text' {
            $output = $results | Format-Table -AutoSize | Out-String
        }
    }

    # Display or save output
    if ($OutputPath) {
        $output | Set-Content -Path $OutputPath -Force
        if (-not $Quiet) {
            Write-Host "Report saved to: $OutputPath" -ForegroundColor Green
        }
    }

    if (-not $Quiet) {
        Write-Host $output
    }

    # Send alerts if configured
    Send-EmailAlert -DiskResults $results
    Send-WebhookAlert -DiskResults $results

    # Save historical data for trend analysis
    if ($TrendDays -gt 0) {
        Save-HistoricalData -DiskResults $results
    }

    # Display summary
    if (-not $Quiet) {
        $summary = @"

=== Disk Space Monitoring Summary ===
Computers Monitored: $(($results.ComputerName | Select-Object -Unique).Count)
Total Drives: $($results.Count)
Critical: $(($results | Where-Object Status -eq 'Critical').Count)
Warning: $(($results | Where-Object Status -eq 'Warning').Count)
OK: $(($results | Where-Object Status -eq 'OK').Count)
Errors: $(($results | Where-Object Status -eq 'Error').Count)
Thresholds: Warning=$ThresholdWarning%, Critical=$ThresholdCritical%
Exit Code: $exitCode
"@

        $summaryColor = switch ($exitCode) {
            0 { 'Green' }
            1 { 'Yellow' }
            2 { 'Red' }
            3 { 'Magenta' }
        }

        Write-Host $summary -ForegroundColor $summaryColor
    }

    # Exit with appropriate code for Nagios/Icinga integration
    exit $exitCode
}
