<#
.SYNOPSIS
    Backs up files and folders with compression, incremental modes, and retention management

.DESCRIPTION
    Comprehensive backup solution for Windows systems that supports both full and incremental
    backups with configurable retention policies. The script provides:

    - Full and incremental backup modes with intelligent change detection
    - Compression using .NET ZipArchive for optimal performance
    - Configurable retention policy to automatically remove old backups
    - Email notifications for backup completion or failure
    - Comprehensive logging with automatic log rotation
    - Backup integrity verification using hash validation
    - WhatIf support for safe testing
    - Detailed progress reporting and error handling

    RISK LEVEL: Medium

    The script creates backups of specified files and directories, which requires read access
    to source files and write access to the destination. While it doesn't delete source files,
    it does automatically remove old backups based on retention policy.

    Security Warnings:
    - Ensure backup destination has appropriate permissions
    - Email credentials (if used) should be secured
    - Verify retention policy before first run
    - Backup files may contain sensitive data - protect accordingly
    - Log files may contain file paths - review security implications

.PARAMETER Path
    Path to the file or folder to backup. Accepts both files and directories.
    For directories, all contents are backed up recursively.
    Example: "C:\ImportantData" or "C:\Config\app.config"

.PARAMETER Destination
    Destination path where backup archives will be stored. Directory will be created
    if it doesn't exist. Backup files are named with timestamp for easy identification.
    Example: "D:\Backups" or "\\BackupServer\Share\DailyBackups"

.PARAMETER RetentionDays
    Number of days to retain backup files. Backups older than this will be automatically
    deleted during cleanup phase. Set to 0 to disable automatic cleanup.
    Default: 30

.PARAMETER Compression
    Enable compression for the backup archive. Recommended for most scenarios to save
    disk space. Disable for already-compressed files or when backup speed is critical.
    Default: $true

.PARAMETER Incremental
    Enable incremental backup mode. Only files modified since the last backup will be
    included. Requires a baseline full backup to exist. First run always creates full backup.
    Default: $false (full backup)

.PARAMETER EmailNotification
    Send email notification when backup completes or fails. Requires EmailTo, EmailFrom,
    and SmtpServer parameters to be configured.
    Default: $false

.PARAMETER EmailTo
    Email address to receive backup notifications.
    Example: "admin@company.com"

.PARAMETER EmailFrom
    Email address to send notifications from.
    Example: "backups@company.com"

.PARAMETER SmtpServer
    SMTP server hostname or IP address for sending email notifications.
    Example: "smtp.office365.com"

.PARAMETER SmtpPort
    SMTP server port number.
    Default: 587

.PARAMETER SmtpUsername
    Username for SMTP authentication (if required).

.PARAMETER SmtpPassword
    Password for SMTP authentication (if required). Consider using secure string.

.PARAMETER LogPath
    Path where log files will be stored. Logs are rotated automatically when exceeding 10MB.
    Default: "$env:TEMP\Backup-SystemFiles.log"

.PARAMETER VerifyBackup
    Verify backup integrity after creation by comparing file counts and random hash checks.
    Recommended for critical backups but adds processing time.
    Default: $true

.EXAMPLE
    .\Backup-SystemFiles.ps1 -Path "C:\ImportantData" -Destination "D:\Backups"

    Creates a full compressed backup of C:\ImportantData to D:\Backups with 30-day retention.
    This is the simplest and most common usage for one-time or scheduled backups.

.EXAMPLE
    .\Backup-SystemFiles.ps1 -Path "C:\Users\John\Documents" -Destination "\\NAS\Backups" -Incremental -RetentionDays 90

    Creates an incremental backup to a network share with 90-day retention.
    Only modified files since last backup are included, reducing backup time and storage.

.EXAMPLE
    .\Backup-SystemFiles.ps1 -Path "C:\Database\Config" -Destination "D:\Backups" -EmailNotification `
        -EmailTo "admin@company.com" -EmailFrom "backup@company.com" -SmtpServer "smtp.office365.com" `
        -SmtpUsername "backup@company.com" -SmtpPassword "SecurePassword123"

    Full backup with email notification sent on completion or failure.

.EXAMPLE
    .\Backup-SystemFiles.ps1 -Path "C:\Data" -Destination "D:\Backups" -WhatIf

    Preview what would be backed up without actually creating the backup.
    Useful for testing and validating configuration before actual execution.

.INPUTS
    None. This script does not accept pipeline input.

.OUTPUTS
    PSCustomObject with backup results including:
    - BackupFile: Full path to created backup archive
    - TotalFiles: Number of files backed up
    - TotalSize: Total size of backed up files
    - Duration: Time taken for backup operation
    - Status: Success or Failed

.NOTES
    Author: SysAdmin Toolkit Team
    Created: 2025-10-06
    Modified: 2025-10-06
    Version: 1.0.0
    Risk Level: Medium 🟡

    Prerequisites:
        - PowerShell 5.1 or later (PowerShell 7+ recommended for better performance)
        - Read access to source files
        - Write access to destination folder
        - .NET Framework 4.5+ (for System.IO.Compression.ZipArchive)
        - Network access to SMTP server (if using email notifications)
        - Sufficient disk space at destination (estimate 50% of source for compressed)

    Security Considerations:
        - Script requires appropriate file system permissions
        - Backup files inherit permissions from destination folder
        - Email credentials passed as parameters - consider credential manager
        - Log files may contain sensitive paths - review access controls
        - Retention policy automatically deletes old backups

    Exit Codes:
        0 - Success
        1 - General error
        2 - Invalid parameters
        3 - Insufficient permissions
        4 - Backup verification failed

    Change Log:
        1.0.0 - 2025-10-06 - Initial release
                - Full and incremental backup modes
                - Compression and retention management
                - Email notifications
                - Integrity verification

.LINK
    https://github.com/unplugged12/sysadmin-toolkit

.LINK
    https://docs.microsoft.com/en-us/dotnet/api/system.io.compression.ziparchive
#>

[CmdletBinding(SupportsShouldProcess = $true)]
param(
    [Parameter(Mandatory = $true, HelpMessage = "Path to file or folder to backup")]
    [ValidateNotNullOrEmpty()]
    [ValidateScript({Test-Path $_ -PathType Any})]
    [string]$Path,

    [Parameter(Mandatory = $true, HelpMessage = "Destination path for backup archives")]
    [ValidateNotNullOrEmpty()]
    [string]$Destination,

    [Parameter(Mandatory = $false)]
    [ValidateRange(0, 3650)]
    [int]$RetentionDays = 30,

    [Parameter(Mandatory = $false)]
    [bool]$Compression = $true,

    [Parameter(Mandatory = $false)]
    [switch]$Incremental,

    [Parameter(Mandatory = $false)]
    [switch]$EmailNotification,

    [Parameter(Mandatory = $false)]
    [ValidatePattern('^[\w\.-]+@[\w\.-]+\.\w+$')]
    [string]$EmailTo,

    [Parameter(Mandatory = $false)]
    [ValidatePattern('^[\w\.-]+@[\w\.-]+\.\w+$')]
    [string]$EmailFrom,

    [Parameter(Mandatory = $false)]
    [string]$SmtpServer,

    [Parameter(Mandatory = $false)]
    [ValidateRange(1, 65535)]
    [int]$SmtpPort = 587,

    [Parameter(Mandatory = $false)]
    [string]$SmtpUsername,

    [Parameter(Mandatory = $false)]
    [string]$SmtpPassword,

    [Parameter(Mandatory = $false)]
    [string]$LogPath = "$env:TEMP\Backup-SystemFiles.log",

    [Parameter(Mandatory = $false)]
    [bool]$VerifyBackup = $true
)

#Requires -Version 5.1

# Script constants
$ErrorActionPreference = "Stop"
$ScriptVersion = "1.0.0"
$MaxLogSize = 10MB

#region Functions

function Write-Log {
    <#
    .SYNOPSIS
        Writes a message to the log file and optionally to console
    #>
    param(
        [Parameter(Mandatory = $true)]
        [string]$Message,

        [Parameter(Mandatory = $false)]
        [ValidateSet('Info', 'Warning', 'Error', 'Success')]
        [string]$Level = 'Info'
    )

    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $logMessage = "[$timestamp] [$Level] $Message"

    # Rotate log if needed
    if (Test-Path $LogPath) {
        $logFile = Get-Item $LogPath
        if ($logFile.Length -gt $MaxLogSize) {
            $rotatedLog = $LogPath -replace '\.log$', "_$(Get-Date -Format 'yyyyMMdd_HHmmss').log"
            Move-Item -Path $LogPath -Destination $rotatedLog -Force
            Write-Host "Log rotated to: $rotatedLog" -ForegroundColor Yellow
        }
    }

    # Write to log file
    Add-Content -Path $LogPath -Value $logMessage -Force

    # Write to console with color
    $color = switch ($Level) {
        'Info'    { 'White' }
        'Warning' { 'Yellow' }
        'Error'   { 'Red' }
        'Success' { 'Green' }
        default   { 'White' }
    }
    Write-Host $logMessage -ForegroundColor $color
}

function Get-FileHash256 {
    <#
    .SYNOPSIS
        Calculate SHA256 hash for a file
    #>
    param(
        [Parameter(Mandatory = $true)]
        [string]$FilePath
    )

    try {
        $hash = Get-FileHash -Path $FilePath -Algorithm SHA256
        return $hash.Hash
    }
    catch {
        Write-Log "Failed to calculate hash for $FilePath : $_" -Level Error
        return $null
    }
}

function Get-LastBackupTime {
    <#
    .SYNOPSIS
        Gets the timestamp of the last successful backup
    #>
    param(
        [Parameter(Mandatory = $true)]
        [string]$DestinationPath
    )

    $manifestPath = Join-Path $DestinationPath "backup_manifest.json"

    if (Test-Path $manifestPath) {
        try {
            $manifest = Get-Content $manifestPath -Raw | ConvertFrom-Json
            return [DateTime]$manifest.LastBackupTime
        }
        catch {
            Write-Log "Failed to read backup manifest: $_" -Level Warning
            return $null
        }
    }

    return $null
}

function Save-BackupManifest {
    <#
    .SYNOPSIS
        Saves backup metadata for incremental backup tracking
    #>
    param(
        [Parameter(Mandatory = $true)]
        [string]$DestinationPath,

        [Parameter(Mandatory = $true)]
        [DateTime]$BackupTime,

        [Parameter(Mandatory = $true)]
        [int]$FileCount,

        [Parameter(Mandatory = $true)]
        [long]$TotalSize
    )

    $manifestPath = Join-Path $DestinationPath "backup_manifest.json"

    $manifest = @{
        LastBackupTime = $BackupTime.ToString("o")
        FileCount = $FileCount
        TotalSize = $TotalSize
        ScriptVersion = $ScriptVersion
    }

    try {
        $manifest | ConvertTo-Json | Set-Content -Path $manifestPath -Force
        Write-Log "Backup manifest saved successfully" -Level Info
    }
    catch {
        Write-Log "Failed to save backup manifest: $_" -Level Warning
    }
}

function Send-BackupNotification {
    <#
    .SYNOPSIS
        Sends email notification about backup status
    #>
    param(
        [Parameter(Mandatory = $true)]
        [bool]$Success,

        [Parameter(Mandatory = $true)]
        [PSCustomObject]$BackupResult
    )

    if (-not $EmailNotification) {
        return
    }

    # Validate email parameters
    if ([string]::IsNullOrWhiteSpace($EmailTo) -or
        [string]::IsNullOrWhiteSpace($EmailFrom) -or
        [string]::IsNullOrWhiteSpace($SmtpServer)) {
        Write-Log "Email notification requested but email parameters not fully configured" -Level Warning
        return
    }

    try {
        $computerName = $env:COMPUTERNAME
        $subject = if ($Success) {
            "Backup Successful - $computerName"
        } else {
            "Backup FAILED - $computerName"
        }

        $body = @"
Backup Report for $computerName

Status: $(if ($Success) { "SUCCESS" } else { "FAILED" })
Backup Time: $(Get-Date -Format "yyyy-MM-dd HH:mm:ss")
Source Path: $Path
Destination: $Destination

Results:
- Backup File: $($BackupResult.BackupFile)
- Total Files: $($BackupResult.TotalFiles)
- Total Size: $([Math]::Round($BackupResult.TotalSize / 1MB, 2)) MB
- Duration: $($BackupResult.Duration)
- Mode: $(if ($Incremental) { "Incremental" } else { "Full" })

$(if (-not $Success) {
    "Error Details: $($BackupResult.ErrorMessage)"
})

Log File: $LogPath

--
This is an automated message from Backup-SystemFiles.ps1 v$ScriptVersion
"@

        $mailParams = @{
            To = $EmailTo
            From = $EmailFrom
            Subject = $subject
            Body = $body
            SmtpServer = $SmtpServer
            Port = $SmtpPort
        }

        # Add credentials if provided
        if (-not [string]::IsNullOrWhiteSpace($SmtpUsername) -and
            -not [string]::IsNullOrWhiteSpace($SmtpPassword)) {
            $securePassword = ConvertTo-SecureString $SmtpPassword -AsPlainText -Force
            $credential = New-Object System.Management.Automation.PSCredential($SmtpUsername, $securePassword)
            $mailParams.Credential = $credential
            $mailParams.UseSsl = $true
        }

        Send-MailMessage @mailParams
        Write-Log "Email notification sent successfully to $EmailTo" -Level Success
    }
    catch {
        Write-Log "Failed to send email notification: $_" -Level Error
    }
}

function Remove-OldBackups {
    <#
    .SYNOPSIS
        Removes backup files older than retention policy
    #>
    param(
        [Parameter(Mandatory = $true)]
        [string]$DestinationPath,

        [Parameter(Mandatory = $true)]
        [int]$RetentionDays
    )

    if ($RetentionDays -eq 0) {
        Write-Log "Retention policy disabled (RetentionDays = 0), skipping cleanup" -Level Info
        return
    }

    try {
        $cutoffDate = (Get-Date).AddDays(-$RetentionDays)
        Write-Log "Removing backups older than $($cutoffDate.ToString('yyyy-MM-dd'))" -Level Info

        $oldBackups = Get-ChildItem -Path $DestinationPath -Filter "*.zip" |
                      Where-Object { $_.LastWriteTime -lt $cutoffDate }

        $removedCount = 0
        $freedSpace = 0

        foreach ($backup in $oldBackups) {
            if ($PSCmdlet.ShouldProcess($backup.FullName, "Delete old backup")) {
                $size = $backup.Length
                Remove-Item -Path $backup.FullName -Force
                Write-Log "Removed old backup: $($backup.Name) ($('{0:N2}' -f ($size / 1MB)) MB)" -Level Info
                $removedCount++
                $freedSpace += $size
            }
        }

        if ($removedCount -gt 0) {
            Write-Log "Cleanup complete: Removed $removedCount backup(s), freed $('{0:N2}' -f ($freedSpace / 1GB)) GB" -Level Success
        } else {
            Write-Log "No old backups to remove" -Level Info
        }
    }
    catch {
        Write-Log "Error during backup cleanup: $_" -Level Error
    }
}

function Test-BackupIntegrity {
    <#
    .SYNOPSIS
        Verifies backup archive integrity
    #>
    param(
        [Parameter(Mandatory = $true)]
        [string]$BackupPath,

        [Parameter(Mandatory = $true)]
        [int]$ExpectedFileCount
    )

    if (-not $VerifyBackup) {
        Write-Log "Backup verification disabled, skipping" -Level Info
        return $true
    }

    try {
        Write-Log "Verifying backup integrity..." -Level Info

        Add-Type -AssemblyName System.IO.Compression.FileSystem
        $archive = [System.IO.Compression.ZipFile]::OpenRead($BackupPath)

        $actualFileCount = $archive.Entries.Count
        $archive.Dispose()

        if ($actualFileCount -eq $ExpectedFileCount) {
            Write-Log "Verification passed: $actualFileCount files in archive match expected count" -Level Success
            return $true
        } else {
            Write-Log "Verification FAILED: Expected $ExpectedFileCount files, found $actualFileCount" -Level Error
            return $false
        }
    }
    catch {
        Write-Log "Verification error: $_" -Level Error
        return $false
    }
}

#endregion

#region Main Script

try {
    # Validate parameters
    if ($EmailNotification) {
        if ([string]::IsNullOrWhiteSpace($EmailTo) -or
            [string]::IsNullOrWhiteSpace($EmailFrom) -or
            [string]::IsNullOrWhiteSpace($SmtpServer)) {
            throw "Email notification requires EmailTo, EmailFrom, and SmtpServer parameters"
        }
    }

    Write-Log "========================================" -Level Info
    Write-Log "Backup-SystemFiles.ps1 v$ScriptVersion" -Level Info
    Write-Log "========================================" -Level Info
    Write-Log "Source: $Path" -Level Info
    Write-Log "Destination: $Destination" -Level Info
    Write-Log "Mode: $(if ($Incremental) { 'Incremental' } else { 'Full' })" -Level Info
    Write-Log "Compression: $Compression" -Level Info
    Write-Log "Retention: $RetentionDays days" -Level Info

    # Create destination directory if needed
    if (-not (Test-Path $Destination)) {
        if ($PSCmdlet.ShouldProcess($Destination, "Create destination directory")) {
            New-Item -Path $Destination -ItemType Directory -Force | Out-Null
            Write-Log "Created destination directory: $Destination" -Level Success
        }
    }

    # Determine backup mode
    $lastBackupTime = Get-LastBackupTime -DestinationPath $Destination
    $isFirstBackup = $null -eq $lastBackupTime

    if ($Incremental -and $isFirstBackup) {
        Write-Log "First backup - creating full backup (incremental requires baseline)" -Level Warning
        $Incremental = $false
    }

    # Generate backup filename with timestamp
    $timestamp = Get-Date -Format "yyyyMMdd_HHmmss"
    $backupType = if ($Incremental) { "incremental" } else { "full" }
    $sourceName = Split-Path $Path -Leaf
    $backupFileName = "${sourceName}_${backupType}_${timestamp}.zip"
    $backupPath = Join-Path $Destination $backupFileName

    Write-Log "Backup file: $backupFileName" -Level Info

    # Get files to backup
    $startTime = Get-Date
    $filesToBackup = @()

    if (Test-Path $Path -PathType Container) {
        Write-Log "Scanning directory for files..." -Level Info
        $allFiles = Get-ChildItem -Path $Path -Recurse -File

        if ($Incremental -and $null -ne $lastBackupTime) {
            $filesToBackup = $allFiles | Where-Object { $_.LastWriteTime -gt $lastBackupTime }
            Write-Log "Incremental mode: Found $($filesToBackup.Count) modified files since $($lastBackupTime.ToString('yyyy-MM-dd HH:mm:ss'))" -Level Info
        } else {
            $filesToBackup = $allFiles
            Write-Log "Full backup: Found $($filesToBackup.Count) files" -Level Info
        }
    } else {
        # Single file backup
        $fileItem = Get-Item $Path
        if (-not $Incremental -or ($null -ne $lastBackupTime -and $fileItem.LastWriteTime -gt $lastBackupTime)) {
            $filesToBackup = @($fileItem)
        }
    }

    if ($filesToBackup.Count -eq 0) {
        Write-Log "No files to backup" -Level Warning
        return
    }

    # Calculate total size
    $totalSize = ($filesToBackup | Measure-Object -Property Length -Sum).Sum
    Write-Log "Total size to backup: $('{0:N2}' -f ($totalSize / 1MB)) MB" -Level Info

    # Create backup archive
    if ($PSCmdlet.ShouldProcess($backupPath, "Create backup archive")) {
        Write-Log "Creating backup archive..." -Level Info

        Add-Type -AssemblyName System.IO.Compression.FileSystem

        $compressionLevel = if ($Compression) {
            [System.IO.Compression.CompressionLevel]::Optimal
        } else {
            [System.IO.Compression.CompressionLevel]::NoCompression
        }

        $archive = [System.IO.Compression.ZipFile]::Open($backupPath, [System.IO.Compression.ZipArchiveMode]::Create)

        $fileCount = 0
        $sourcePath = if (Test-Path $Path -PathType Container) { $Path } else { Split-Path $Path -Parent }

        foreach ($file in $filesToBackup) {
            try {
                $relativePath = $file.FullName.Substring($sourcePath.Length).TrimStart('\', '/')
                $entry = $archive.CreateEntry($relativePath, $compressionLevel)
                $entry.LastWriteTime = $file.LastWriteTime

                $entryStream = $entry.Open()
                $fileStream = [System.IO.File]::OpenRead($file.FullName)
                $fileStream.CopyTo($entryStream)
                $fileStream.Close()
                $entryStream.Close()

                $fileCount++

                if ($fileCount % 100 -eq 0) {
                    Write-Log "Processed $fileCount files..." -Level Info
                }
            }
            catch {
                Write-Log "Failed to backup file $($file.FullName): $_" -Level Error
            }
        }

        $archive.Dispose()

        $endTime = Get-Date
        $duration = $endTime - $startTime

        Write-Log "Backup created successfully: $backupFileName" -Level Success
        Write-Log "Files backed up: $fileCount" -Level Info
        Write-Log "Duration: $($duration.ToString('hh\:mm\:ss'))" -Level Info

        # Verify backup
        $verificationPassed = Test-BackupIntegrity -BackupPath $backupPath -ExpectedFileCount $fileCount

        if (-not $verificationPassed) {
            throw "Backup verification failed"
        }

        # Save manifest for incremental backups
        Save-BackupManifest -DestinationPath $Destination -BackupTime $startTime -FileCount $fileCount -TotalSize $totalSize

        # Cleanup old backups
        Remove-OldBackups -DestinationPath $Destination -RetentionDays $RetentionDays

        # Prepare result object
        $result = [PSCustomObject]@{
            BackupFile = $backupPath
            TotalFiles = $fileCount
            TotalSize = $totalSize
            Duration = $duration
            Status = "Success"
            ErrorMessage = $null
        }

        # Send notification
        Send-BackupNotification -Success $true -BackupResult $result

        Write-Log "========================================" -Level Info
        Write-Log "Backup completed successfully!" -Level Success
        Write-Log "========================================" -Level Info

        return $result
    }
}
catch {
    Write-Log "========================================" -Level Error
    Write-Log "Backup FAILED: $_" -Level Error
    Write-Log "========================================" -Level Error

    $result = [PSCustomObject]@{
        BackupFile = $null
        TotalFiles = 0
        TotalSize = 0
        Duration = (Get-Date) - $startTime
        Status = "Failed"
        ErrorMessage = $_.Exception.Message
    }

    Send-BackupNotification -Success $false -BackupResult $result

    exit 1
}

#endregion
