<#
.SYNOPSIS
    Deploys Windows Updates with advanced management features including scheduling, backup, and rollback.

.DESCRIPTION
    Comprehensive Windows Update deployment script that provides enterprise-grade patch management
    capabilities. This script handles Windows Update deployment with category filtering,
    maintenance window enforcement, pre-patch backups, rollback capability, and compliance reporting.

    Key Features:
    - Category-based update filtering (Security, Critical, Drivers, etc.)
    - Pre-patch system restore point creation
    - Maintenance window enforcement with time-based scheduling
    - Automatic and scheduled reboot management
    - WSUS integration support
    - Rollback capability via restore points
    - Detailed compliance reporting with CSV/JSON output
    - Dry-run mode for testing (WhatIf)

    RISK LEVEL: High

    Security Warnings:
    - Installs system updates that may require reboots
    - Requires elevated privileges (Administrator)
    - Can impact system availability during patching
    - Creates system restore points (requires disk space)
    - May modify critical system files
    - Reboot operations can disrupt running services

.PARAMETER Categories
    Specifies which update categories to install. Multiple categories can be selected.
    Valid categories: Security, Critical, Updates, ServicePacks, Drivers, FeaturePacks, Tools, DefinitionUpdates
    Default: @('Security', 'Critical')

.PARAMETER AutoReboot
    Automatically reboots the system if required after installing updates.
    If not specified, user will be prompted before rebooting.

.PARAMETER MaintenanceWindow
    Defines the maintenance window during which updates can be installed.
    Format: "HH:MM-HH:MM" (24-hour format)
    Example: "22:00-06:00" for 10 PM to 6 AM
    If current time is outside this window, script will exit.

.PARAMETER CreateRestorePoint
    Creates a system restore point before installing updates.
    Highly recommended for rollback capability.

.PARAMETER RebootDelay
    Number of minutes to delay automatic reboot after update installation.
    Allows time for graceful service shutdown and user notification.
    Default: 5 minutes

.PARAMETER WSUSServer
    Specifies WSUS server URL to use for updates instead of Windows Update.
    Format: "http://wsusserver:8530"
    Requires that the system is configured to use WSUS.

.PARAMETER OutputFormat
    Format for compliance report output.
    Valid values: CSV, JSON, Console
    Default: Console

.PARAMETER OutputPath
    Path where compliance report will be saved (for CSV/JSON output).
    Default: "$env:TEMP\WindowsUpdateReport_$(Get-Date -Format 'yyyyMMdd_HHmmss')"

.PARAMETER ExcludeKB
    Array of KB numbers to exclude from installation.
    Example: @('KB5000001', 'KB5000002')

.PARAMETER MaxUpdates
    Maximum number of updates to install in a single run.
    Useful for testing or limiting scope.
    Default: 0 (no limit)

.EXAMPLE
    .\Deploy-WindowsUpdates.ps1 -Categories Security,Critical -CreateRestorePoint -WhatIf

    Performs a dry-run showing which security and critical updates would be installed,
    and indicates that a restore point would be created.

.EXAMPLE
    .\Deploy-WindowsUpdates.ps1 -Categories Security -AutoReboot -RebootDelay 10 -CreateRestorePoint

    Installs security updates, creates a restore point, and automatically reboots the system
    after a 10-minute delay if required.

.EXAMPLE
    .\Deploy-WindowsUpdates.ps1 -MaintenanceWindow "22:00-06:00" -Categories Security,Critical,Updates -AutoReboot -CreateRestorePoint

    Installs security, critical, and regular updates only during the maintenance window
    (10 PM to 6 AM), creates a restore point, and automatically reboots if needed.

.EXAMPLE
    .\Deploy-WindowsUpdates.ps1 -WSUSServer "http://wsus.contoso.com:8530" -Categories Security -OutputFormat CSV -OutputPath "C:\Reports\Updates.csv"

    Retrieves updates from WSUS server, installs security updates, and saves a CSV report
    to the specified path.

.EXAMPLE
    .\Deploy-WindowsUpdates.ps1 -ExcludeKB @('KB5000001','KB5000002') -Categories Critical

    Installs critical updates while excluding specific KB articles that may have known issues.

.INPUTS
    None. This script does not accept pipeline input.

.OUTPUTS
    System.Management.Automation.PSCustomObject
    Returns update installation results and compliance information.

.NOTES
    Author: SysAdmin Toolkit Team
    Created: 2025-10-06
    Modified: 2025-10-06
    Version: 1.0.0
    Risk Level: High 🔴

    Prerequisites:
        - PowerShell 5.1 or later (PowerShell 7+ recommended)
        - Administrator privileges required
        - PSWindowsUpdate module (will attempt to install if missing)
        - Sufficient disk space for updates and restore point
        - Network connectivity to Windows Update or WSUS server
        - At least 300MB free space on system drive for restore point

    Security Considerations:
        - Always test in non-production environment first
        - Create restore point before applying updates
        - Verify updates in maintenance window before production deployment
        - Monitor reboot operations to ensure services restart properly
        - Maintain backup access method (console/IPMI) in case of issues
        - Review excluded KBs regularly for applicability
        - Audit all patch operations via event logs

    Exit Codes:
        0 - Success (updates installed or no updates available)
        1 - General error
        2 - Invalid parameters
        3 - Insufficient permissions
        4 - Outside maintenance window
        5 - PSWindowsUpdate module installation failed
        6 - Restore point creation failed

    Rollback Procedure:
        If updates cause issues:
        1. Boot into Safe Mode if system won't start normally
        2. Open System Restore: rstrui.exe
        3. Select the restore point created by this script
        4. Follow wizard to restore system
        5. Alternatively, use: Restore-Computer -RestorePoint <ID>
        6. Review Windows Update history to identify problematic updates
        7. Hide problematic updates to prevent reinstallation

    Change Log:
        1.0.0 - 2025-10-06 - Initial release
                           - Category-based filtering
                           - Restore point creation
                           - Maintenance window support
                           - WSUS integration
                           - Compliance reporting

.LINK
    https://github.com/unplugged12/sysadmin-toolkit

.LINK
    https://docs.microsoft.com/en-us/windows/deployment/update/

.LINK
    https://www.powershellgallery.com/packages/PSWindowsUpdate
#>

[CmdletBinding(SupportsShouldProcess = $true)]
param(
    [Parameter(Mandatory = $false, HelpMessage = "Update categories to install")]
    [ValidateSet('Security', 'Critical', 'Updates', 'ServicePacks', 'Drivers', 'FeaturePacks', 'Tools', 'DefinitionUpdates')]
    [string[]]$Categories = @('Security', 'Critical'),

    [Parameter(Mandatory = $false)]
    [switch]$AutoReboot,

    [Parameter(Mandatory = $false, HelpMessage = "Maintenance window in HH:MM-HH:MM format")]
    [ValidatePattern('^\d{2}:\d{2}-\d{2}:\d{2}$')]
    [string]$MaintenanceWindow,

    [Parameter(Mandatory = $false)]
    [switch]$CreateRestorePoint,

    [Parameter(Mandatory = $false)]
    [ValidateRange(1, 1440)]
    [int]$RebootDelay = 5,

    [Parameter(Mandatory = $false)]
    [ValidatePattern('^https?://')]
    [string]$WSUSServer,

    [Parameter(Mandatory = $false)]
    [ValidateSet('CSV', 'JSON', 'Console')]
    [string]$OutputFormat = 'Console',

    [Parameter(Mandatory = $false)]
    [string]$OutputPath = "$env:TEMP\WindowsUpdateReport_$(Get-Date -Format 'yyyyMMdd_HHmmss')",

    [Parameter(Mandatory = $false)]
    [string[]]$ExcludeKB = @(),

    [Parameter(Mandatory = $false)]
    [int]$MaxUpdates = 0
)

#Requires -RunAsAdministrator

#region Functions

function Write-Log {
    param(
        [string]$Message,
        [ValidateSet('Info', 'Warning', 'Error', 'Success')]
        [string]$Level = 'Info'
    )

    $timestamp = Get-Date -Format 'yyyy-MM-dd HH:mm:ss'
    $color = switch ($Level) {
        'Info'    { 'Cyan' }
        'Warning' { 'Yellow' }
        'Error'   { 'Red' }
        'Success' { 'Green' }
    }

    $logMessage = "[$timestamp] [$Level] $Message"
    Write-Host $logMessage -ForegroundColor $color

    # Also log to Windows Event Log
    try {
        $eventSource = 'WindowsUpdateDeployment'
        if (-not [System.Diagnostics.EventLog]::SourceExists($eventSource)) {
            New-EventLog -LogName Application -Source $eventSource -ErrorAction SilentlyContinue
        }

        $eventType = switch ($Level) {
            'Error'   { 'Error' }
            'Warning' { 'Warning' }
            default   { 'Information' }
        }

        Write-EventLog -LogName Application -Source $eventSource -EntryType $eventType -EventId 1000 -Message $Message -ErrorAction SilentlyContinue
    }
    catch {
        # Silent fail for event log issues
    }
}

function Test-MaintenanceWindow {
    param([string]$Window)

    if ([string]::IsNullOrEmpty($Window)) {
        return $true
    }

    try {
        $parts = $Window -split '-'
        $startTime = [datetime]::ParseExact($parts[0], 'HH:mm', $null)
        $endTime = [datetime]::ParseExact($parts[1], 'HH:mm', $null)
        $currentTime = Get-Date

        $currentMinutes = $currentTime.Hour * 60 + $currentTime.Minute
        $startMinutes = $startTime.Hour * 60 + $startTime.Minute
        $endMinutes = $endTime.Hour * 60 + $endTime.Minute

        # Handle windows that span midnight
        if ($endMinutes -lt $startMinutes) {
            return ($currentMinutes -ge $startMinutes -or $currentMinutes -le $endMinutes)
        }
        else {
            return ($currentMinutes -ge $startMinutes -and $currentMinutes -le $endMinutes)
        }
    }
    catch {
        Write-Log "Failed to parse maintenance window: $_" -Level Error
        return $false
    }
}

function Install-PSWindowsUpdateModule {
    Write-Log "Checking for PSWindowsUpdate module..." -Level Info

    if (-not (Get-Module -ListAvailable -Name PSWindowsUpdate)) {
        Write-Log "PSWindowsUpdate module not found. Attempting to install..." -Level Warning

        if ($PSCmdlet.ShouldProcess("PSWindowsUpdate module", "Install from PowerShell Gallery")) {
            try {
                Install-Module -Name PSWindowsUpdate -Force -Scope CurrentUser -AllowClobber -ErrorAction Stop
                Write-Log "PSWindowsUpdate module installed successfully." -Level Success
            }
            catch {
                Write-Log "Failed to install PSWindowsUpdate module: $_" -Level Error
                return $false
            }
        }
        else {
            Write-Log "PSWindowsUpdate module installation skipped (WhatIf mode)." -Level Info
            return $true
        }
    }

    try {
        Import-Module PSWindowsUpdate -ErrorAction Stop
        Write-Log "PSWindowsUpdate module loaded successfully." -Level Success
        return $true
    }
    catch {
        Write-Log "Failed to import PSWindowsUpdate module: $_" -Level Error
        return $false
    }
}

function New-SystemRestorePoint {
    param([string]$Description)

    if ($PSCmdlet.ShouldProcess("System Restore Point", "Create '$Description'")) {
        try {
            Write-Log "Creating system restore point: $Description" -Level Info

            # Enable System Restore if not enabled
            $systemDrive = $env:SystemDrive
            Enable-ComputerRestore -Drive $systemDrive -ErrorAction SilentlyContinue

            # Create restore point
            Checkpoint-Computer -Description $Description -RestorePointType MODIFY_SETTINGS -ErrorAction Stop

            Write-Log "System restore point created successfully." -Level Success
            return $true
        }
        catch {
            Write-Log "Failed to create restore point: $_" -Level Error
            Write-Log "Continuing without restore point. Manual backup recommended." -Level Warning
            return $false
        }
    }
    else {
        Write-Log "Restore point creation skipped (WhatIf mode)." -Level Info
        return $true
    }
}

function Get-AvailableUpdates {
    param(
        [string[]]$Categories,
        [string[]]$ExcludeKB,
        [int]$MaxUpdates
    )

    Write-Log "Searching for available updates in categories: $($Categories -join ', ')" -Level Info

    try {
        # Build filter criteria
        $criteria = "IsInstalled=0 and IsHidden=0"

        # Get updates
        $updates = Get-WindowsUpdate -Category $Categories -Criteria $criteria -Verbose:$false

        # Filter out excluded KBs
        if ($ExcludeKB.Count -gt 0) {
            $updates = $updates | Where-Object {
                $kb = $_.KBArticleIDs -join ','
                $isExcluded = $false
                foreach ($excludedKB in $ExcludeKB) {
                    if ($kb -match $excludedKB) {
                        $isExcluded = $true
                        break
                    }
                }
                -not $isExcluded
            }
            Write-Log "Excluded $($ExcludeKB.Count) KB articles from installation." -Level Info
        }

        # Limit number of updates
        if ($MaxUpdates -gt 0 -and $updates.Count -gt $MaxUpdates) {
            Write-Log "Limiting to first $MaxUpdates updates (out of $($updates.Count) available)." -Level Warning
            $updates = $updates | Select-Object -First $MaxUpdates
        }

        return $updates
    }
    catch {
        Write-Log "Failed to retrieve available updates: $_" -Level Error
        return @()
    }
}

function Install-Updates {
    param(
        [object[]]$Updates,
        [bool]$AcceptAll = $true
    )

    if ($Updates.Count -eq 0) {
        Write-Log "No updates available to install." -Level Info
        return @{
            Success = $true
            UpdatesInstalled = 0
            RebootRequired = $false
        }
    }

    Write-Log "Installing $($Updates.Count) update(s)..." -Level Info

    if ($PSCmdlet.ShouldProcess("$($Updates.Count) Windows Update(s)", "Install")) {
        try {
            $result = Install-WindowsUpdate -KBArticleID $Updates.KBArticleIDs -AcceptAll:$AcceptAll -IgnoreReboot -Verbose:$false

            $rebootRequired = Get-WURebootStatus -Silent

            Write-Log "Update installation completed. Installed: $($result.Count), Reboot Required: $rebootRequired" -Level Success

            return @{
                Success = $true
                UpdatesInstalled = $result.Count
                RebootRequired = $rebootRequired
                Results = $result
            }
        }
        catch {
            Write-Log "Update installation failed: $_" -Level Error
            return @{
                Success = $false
                UpdatesInstalled = 0
                RebootRequired = $false
                Error = $_.Exception.Message
            }
        }
    }
    else {
        Write-Log "Update installation skipped (WhatIf mode). Would have installed:" -Level Info
        foreach ($update in $Updates) {
            Write-Log "  - $($update.Title) (KB$($update.KBArticleIDs -join ','))" -Level Info
        }

        return @{
            Success = $true
            UpdatesInstalled = 0
            RebootRequired = $false
            WhatIf = $true
        }
    }
}

function Start-PendingReboot {
    param(
        [bool]$AutoReboot,
        [int]$DelayMinutes
    )

    if ($PSCmdlet.ShouldProcess("Computer", "Restart after $DelayMinutes minute(s)")) {
        if ($AutoReboot) {
            Write-Log "System will reboot in $DelayMinutes minute(s)..." -Level Warning

            $delaySeconds = $DelayMinutes * 60
            $message = "Windows Updates have been installed. System will reboot in $DelayMinutes minutes. Save your work."

            # Send notification to logged-in users
            msg * $message

            # Schedule reboot
            shutdown /r /t $delaySeconds /c $message /d p:2:17

            Write-Log "Reboot scheduled for $(Get-Date).AddMinutes($DelayMinutes)" -Level Info
        }
        else {
            Write-Log "Reboot is required but AutoReboot was not specified." -Level Warning
            Write-Log "Please reboot the system manually to complete update installation." -Level Warning

            $response = Read-Host "Would you like to reboot now? (Y/N)"
            if ($response -eq 'Y' -or $response -eq 'y') {
                Write-Log "User confirmed reboot. Restarting system..." -Level Info
                Restart-Computer -Force
            }
        }
    }
    else {
        Write-Log "Reboot skipped (WhatIf mode). System would have rebooted in $DelayMinutes minutes." -Level Info
    }
}

function Export-ComplianceReport {
    param(
        [object]$Results,
        [string]$Format,
        [string]$Path
    )

    try {
        switch ($Format) {
            'CSV' {
                if ($PSCmdlet.ShouldProcess($Path, "Export CSV report")) {
                    $Results | Export-Csv -Path "$Path.csv" -NoTypeInformation -Force
                    Write-Log "Compliance report exported to: $Path.csv" -Level Success
                }
            }
            'JSON' {
                if ($PSCmdlet.ShouldProcess($Path, "Export JSON report")) {
                    $Results | ConvertTo-Json -Depth 10 | Out-File -FilePath "$Path.json" -Force
                    Write-Log "Compliance report exported to: $Path.json" -Level Success
                }
            }
            'Console' {
                Write-Log "Update Installation Summary:" -Level Info
                $Results | Format-Table -AutoSize
            }
        }
    }
    catch {
        Write-Log "Failed to export compliance report: $_" -Level Error
    }
}

#endregion

#region Main Script

try {
    Write-Log "=== Windows Update Deployment Started ===" -Level Info
    Write-Log "Categories: $($Categories -join ', ')" -Level Info
    Write-Log "Auto-Reboot: $AutoReboot" -Level Info
    Write-Log "Create Restore Point: $CreateRestorePoint" -Level Info

    # Check maintenance window
    if (-not (Test-MaintenanceWindow -Window $MaintenanceWindow)) {
        Write-Log "Current time is outside maintenance window ($MaintenanceWindow). Exiting." -Level Warning
        exit 4
    }

    # Install/Import PSWindowsUpdate module
    if (-not (Install-PSWindowsUpdateModule)) {
        Write-Log "Cannot proceed without PSWindowsUpdate module." -Level Error
        exit 5
    }

    # Create restore point if requested
    if ($CreateRestorePoint) {
        $restorePointDescription = "Before Windows Updates - $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')"
        if (-not (New-SystemRestorePoint -Description $restorePointDescription)) {
            if (-not $PSBoundParameters.ContainsKey('WhatIf')) {
                Write-Log "Restore point creation failed. Continue anyway? (Y/N)" -Level Warning
                $response = Read-Host
                if ($response -ne 'Y' -and $response -ne 'y') {
                    Write-Log "Deployment cancelled by user." -Level Warning
                    exit 6
                }
            }
        }
    }

    # Configure WSUS server if specified
    if ($WSUSServer) {
        Write-Log "Configuring WSUS server: $WSUSServer" -Level Info
        if ($PSCmdlet.ShouldProcess($WSUSServer, "Configure WSUS server")) {
            try {
                Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate" -Name "WUServer" -Value $WSUSServer -Force
                Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate" -Name "WUStatusServer" -Value $WSUSServer -Force
                Write-Log "WSUS server configured successfully." -Level Success
            }
            catch {
                Write-Log "Failed to configure WSUS server: $_" -Level Error
            }
        }
    }

    # Get available updates
    $availableUpdates = Get-AvailableUpdates -Categories $Categories -ExcludeKB $ExcludeKB -MaxUpdates $MaxUpdates

    if ($availableUpdates.Count -eq 0) {
        Write-Log "No updates available. System is up to date." -Level Success
        exit 0
    }

    Write-Log "Found $($availableUpdates.Count) update(s) to install:" -Level Info
    foreach ($update in $availableUpdates) {
        Write-Log "  - $($update.Title) [KB$($update.KBArticleIDs -join ',')]" -Level Info
    }

    # Install updates
    $installResult = Install-Updates -Updates $availableUpdates -AcceptAll $true

    # Export compliance report
    $reportData = [PSCustomObject]@{
        Timestamp = Get-Date -Format 'yyyy-MM-dd HH:mm:ss'
        ComputerName = $env:COMPUTERNAME
        UpdatesAvailable = $availableUpdates.Count
        UpdatesInstalled = $installResult.UpdatesInstalled
        RebootRequired = $installResult.RebootRequired
        Categories = $Categories -join ', '
        Success = $installResult.Success
        RestorePointCreated = $CreateRestorePoint
    }

    Export-ComplianceReport -Results $reportData -Format $OutputFormat -Path $OutputPath

    # Handle reboot if required
    if ($installResult.RebootRequired) {
        Write-Log "System reboot is required to complete update installation." -Level Warning
        Start-PendingReboot -AutoReboot $AutoReboot -DelayMinutes $RebootDelay
    }

    Write-Log "=== Windows Update Deployment Completed ===" -Level Success
    exit 0
}
catch {
    Write-Log "Fatal error during update deployment: $_" -Level Error
    Write-Log "Stack Trace: $($_.ScriptStackTrace)" -Level Error
    exit 1
}

#endregion
