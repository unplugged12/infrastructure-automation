<#
.SYNOPSIS
    Repairs Folder Redirection paths after an Active Directory username (sAMAccountName) change.

.DESCRIPTION
    Production-ready script that safely remediates Folder Redirection paths when a user's
    sAMAccountName has been renamed in Active Directory. Validates SID identity, handles
    folder renames/merges, repairs NTFS ACLs, and provides comprehensive logging.

.PARAMETER RootPath
    UNC path to the Folder Redirection root (e.g., \\yoda\Redir)

.PARAMETER OldSam
    Previous sAMAccountName (e.g., miguelitoc)

.PARAMETER NewSam
    New sAMAccountName (e.g., meguelitoc)

.PARAMETER WhatIf
    Test/dry-run mode - no changes will be made

.PARAMETER LogPath
    Path to log file (default: C:\Logs\FR-Repair.log)

.PARAMETER Backup
    Create ZIP backup of folders before making changes

.PARAMETER SMBTimeoutSec
    Timeout in seconds for SMB share reachability check (default: 10)

.PARAMETER VerboseOutput
    Enable detailed console output

.PARAMETER SkipADCheck
    Emergency bypass for AD verification (use with caution)

.PARAMETER AclOnly
    Run ACL verification/repair only (skip rename/merge operations)

.PARAMETER SkipOldUserCheck
    Skip old username AD lookup entirely (use new user SID only)

.PARAMETER SkipElevationCheck
    Skip the runtime administrator privilege check (intended for automated testing scenarios only)

.EXAMPLE
    .\Repair-FolderRedirectionAfterRename.ps1 -RootPath \\yoda\Redir -OldSam miguelitoc -NewSam meguelitoc -WhatIf -VerboseOutput

.EXAMPLE
    .\Repair-FolderRedirectionAfterRename.ps1 -RootPath \\yoda\Redir -OldSam miguelitoc -NewSam meguelitoc -Backup -VerboseOutput

.EXAMPLE
    .\Repair-FolderRedirectionAfterRename.ps1 -RootPath \\yoda\Redir -NewSam meguelitoc -AclOnly -WhatIf

.EXAMPLE
    .\Repair-FolderRedirectionAfterRename.ps1 -RootPath \\yoda\Redir -NewSam meguelitoc -AclOnly

.NOTES
    Requires: ActiveDirectory module, Administrator rights on file server
    Exit Codes: 0=Success, 10=SMB unreachable, 11=AD lookup failure (new user only),
                12=SID mismatch, 13=Open files, 20=Operation failed

.CHANGELOG
    2025-09-29 - AI Agent
      - Made Step 2 robust: old user missing no longer causes failure (ExitCode 11)
      - Added -AclOnly mode for ACL verification/repair without rename/merge operations
      - Added -SkipOldUserCheck switch to bypass old username AD lookup entirely
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory)]
    [string]$RootPath,

    [Parameter(Mandatory=$false)]
    [string]$OldSam,

    [Parameter(Mandatory)]
    [string]$NewSam,

    [switch]$WhatIf,

    [string]$LogPath = "$env:SystemDrive\Logs\FR-Repair.log",

    [switch]$Backup,

    [int]$SMBTimeoutSec = 10,

    [switch]$VerboseOutput,

    [switch]$SkipADCheck,

    [switch]$AclOnly,

    [switch]$SkipOldUserCheck,

    [switch]$SkipElevationCheck
)

# Script-level variables
$script:ExitCode = 0
$script:TranscriptStarted = $false
$script:UserSID = $null

#region Helper Functions

function Write-Log {
    param(
        [string]$Message,
        [ValidateSet('INFO','WARN','ERROR','SUCCESS')]
        [string]$Level = 'INFO'
    )

    $timestamp = Get-Date -Format 'yyyy-MM-dd HH:mm:ss'
    $logEntry = "[$timestamp] [$Level] $Message"

    # Console output
    switch ($Level) {
        'ERROR'   { Write-Host $logEntry -ForegroundColor Red }
        'WARN'    { Write-Host $logEntry -ForegroundColor Yellow }
        'SUCCESS' { Write-Host $logEntry -ForegroundColor Green }
        default   {
            if ($VerboseOutput) {
                Write-Host $logEntry -ForegroundColor Cyan
            }
        }
    }

    # File output
    try {
        Add-Content -Path $LogPath -Value $logEntry -ErrorAction Stop
    }
    catch {
        Write-Warning "Failed to write to log file: $_"
    }
}

function Test-IsAdministrator {
    try {
        $identity = [System.Security.Principal.WindowsIdentity]::GetCurrent()
        $principal = [System.Security.Principal.WindowsPrincipal]::new($identity)
        return $principal.IsInRole([System.Security.Principal.WindowsBuiltInRole]::Administrator)
    }
    catch {
        Write-Warning "Unable to determine administrator privileges: $_"
        return $false
    }
}

function Assert-Administrator {
    if (-not (Test-IsAdministrator)) {
        Write-Log "Administrator privileges are required to run this script." -Level ERROR
        $script:ExitCode = 20
        throw "Administrator privileges required"
    }
}

function Get-ActualFolderName {
    param(
        [string]$ParentPath,
        [string]$FolderName
    )

    try {
        $items = Get-ChildItem -Path $ParentPath -Directory -Force -ErrorAction Stop
        $match = $items | Where-Object { $_.Name -ieq $FolderName } | Select-Object -First 1

        if ($match) {
            return $match.Name
        }
        return $null
    }
    catch {
        Write-Log "Could not enumerate parent directory: $_" -Level WARN
        return $null
    }
}

function Get-FolderStats {
    param(
        [string]$Path,
        [switch]$Fast
    )

    if (-not (Test-Path $Path)) {
        return @{
            Exists = $false
            FileCount = 0
            SizeMB = 0
            LastWrite = $null
        }
    }

    try {
        if ($Fast) {
            # Fast mode: just check a few items for decision making
            $sampleFiles = Get-ChildItem -Path $Path -File -Force -ErrorAction Stop | Select-Object -First 20
            return @{
                Exists = $true
                FileCount = $sampleFiles.Count
                SizeMB = [math]::Round(($sampleFiles | Measure-Object -Property Length -Sum).Sum / 1MB, 2)
                LastWrite = ($sampleFiles | Sort-Object LastWriteTime -Descending | Select-Object -First 1).LastWriteTime
                IsSample = $true
            }
        }
        else {
            $files = Get-ChildItem -Path $Path -Recurse -File -Force -ErrorAction Stop
            $size = ($files | Measure-Object -Property Length -Sum).Sum
            $lastWrite = ($files | Sort-Object LastWriteTime -Descending | Select-Object -First 1).LastWriteTime

            return @{
                Exists = $true
                FileCount = $files.Count
                SizeMB = [math]::Round($size / 1MB, 2)
                LastWrite = $lastWrite
                IsSample = $false
            }
        }
    }
    catch {
        Write-Log "Warning: Could not fully enumerate $Path - $_" -Level WARN
        return @{
            Exists = $true
            FileCount = -1
            SizeMB = -1
            LastWrite = $null
            IsSample = $false
        }
    }
}

function Test-OpenFiles {
    param([string]$Path)

    # Check if running on file server with SMB cmdlets
    if (-not (Get-Command Get-SmbOpenFile -ErrorAction SilentlyContinue)) {
        Write-Log "Get-SmbOpenFile not available - skipping open file check" -Level WARN
        return @()
    }

    try {
        $openFiles = Get-SmbOpenFile | Where-Object { $_.Path -like "$Path*" }
        return $openFiles
    }
    catch {
        Write-Log "Could not check for open files: $_" -Level WARN
        return @()
    }
}

function Invoke-WithRetry {
    param(
        [scriptblock]$ScriptBlock,
        [int]$MaxRetries = 3,
        [int]$InitialDelaySec = 2
    )

    $attempt = 1
    $delay = $InitialDelaySec

    while ($attempt -le $MaxRetries) {
        try {
            return & $ScriptBlock
        }
        catch {
            if ($attempt -eq $MaxRetries) {
                throw
            }
            Write-Log "Attempt $attempt failed: $_ - Retrying in $delay seconds..." -Level WARN
            Start-Sleep -Seconds $delay
            $delay *= 2
            $attempt++
        }
    }
}

function New-BackupArchive {
    param(
        [string]$SourcePath,
        [string]$BackupRoot,
        [string]$UserName
    )

    if (-not (Test-Path $SourcePath)) {
        Write-Log "Skipping backup - source path does not exist: $SourcePath" -Level WARN
        return $null
    }

    $backupDir = Join-Path $BackupRoot "_backups"
    if (-not (Test-Path $backupDir)) {
        if ($WhatIf) {
            Write-Log "[WHATIF] Would create backup directory: $backupDir" -Level INFO
        }
        else {
            New-Item -ItemType Directory -Path $backupDir -Force | Out-Null
        }
    }

    $timestamp = Get-Date -Format 'yyyyMMddHHmmss'
    $zipName = "${UserName}_${timestamp}.zip"
    $zipPath = Join-Path $backupDir $zipName

    try {
        if ($WhatIf) {
            $stats = Get-FolderStats -Path $SourcePath -Fast
            Write-Log "[WHATIF] Would create backup: $zipPath (approx. $($stats.SizeMB) MB)" -Level INFO
            return $zipPath
        }

        Write-Log "Creating backup archive: $zipPath" -Level INFO
        Compress-Archive -Path "$SourcePath\*" -DestinationPath $zipPath -CompressionLevel Optimal -Force
        Write-Log "Backup created successfully: $zipPath" -Level SUCCESS
        return $zipPath
    }
    catch {
        Write-Log "Backup failed: $_" -Level ERROR
        return $null
    }
}

function Repair-FolderACL {
    param(
        [string]$Path,
        [System.Security.Principal.SecurityIdentifier]$UserSID
    )

    Write-Log "Verifying ACL on: $Path" -Level INFO

    try {
        $acl = Get-Acl -Path $Path
        $modified = $false

        # Check for user SID with Modify or FullControl
        if ($UserSID) {
            $userRule = $acl.Access | Where-Object {
                try {
                    $_.IdentityReference.Translate([System.Security.Principal.SecurityIdentifier]).Value -eq $UserSID.Value -and
                    $_.FileSystemRights -match 'Modify|FullControl' -and
                    $_.AccessControlType -eq 'Allow'
                }
                catch {
                    $false
                }
            }

            if (-not $userRule) {
                Write-Log "Adding Modify rights for user SID: $UserSID" -Level INFO
                $rule = New-Object System.Security.AccessControl.FileSystemAccessRule(
                    $UserSID,
                    'Modify',
                    'ContainerInherit,ObjectInherit',
                    'None',
                    'Allow'
                )
                $acl.AddAccessRule($rule)
                $modified = $true
            }
        }
        else {
            Write-Log "User SID not available - skipping user ACE verification" -Level WARN
        }

        # Ensure SYSTEM has FullControl
        $systemSID = New-Object System.Security.Principal.SecurityIdentifier('S-1-5-18')
        $systemRule = $acl.Access | Where-Object {
            try {
                $_.IdentityReference.Translate([System.Security.Principal.SecurityIdentifier]).Value -eq $systemSID.Value -and
                $_.FileSystemRights -match 'FullControl' -and
                $_.AccessControlType -eq 'Allow'
            }
            catch {
                $false
            }
        }

        if (-not $systemRule) {
            Write-Log "Adding FullControl rights for SYSTEM" -Level INFO
            $rule = New-Object System.Security.AccessControl.FileSystemAccessRule(
                $systemSID,
                'FullControl',
                'ContainerInherit,ObjectInherit',
                'None',
                'Allow'
            )
            $acl.AddAccessRule($rule)
            $modified = $true
        }

        # Ensure Administrators have FullControl
        $adminSID = New-Object System.Security.Principal.SecurityIdentifier('S-1-5-32-544')
        $adminRule = $acl.Access | Where-Object {
            try {
                $_.IdentityReference.Translate([System.Security.Principal.SecurityIdentifier]).Value -eq $adminSID.Value -and
                $_.FileSystemRights -match 'FullControl' -and
                $_.AccessControlType -eq 'Allow'
            }
            catch {
                $false
            }
        }

        if (-not $adminRule) {
            Write-Log "Adding FullControl rights for Administrators" -Level INFO
            $rule = New-Object System.Security.AccessControl.FileSystemAccessRule(
                $adminSID,
                'FullControl',
                'ContainerInherit,ObjectInherit',
                'None',
                'Allow'
            )
            $acl.AddAccessRule($rule)
            $modified = $true
        }

        if ($modified) {
            if ($WhatIf) {
                Write-Log "[WHATIF] Would update ACL on: $Path" -Level INFO
            }
            else {
                Set-Acl -Path $Path -AclObject $acl
                Write-Log "ACL updated successfully" -Level SUCCESS
            }
        }
        else {
            Write-Log "ACL is correct - no changes needed" -Level INFO
        }

        return $true
    }
    catch {
        Write-Log "ACL repair failed: $_" -Level ERROR
        return $false
    }
}

function Merge-Folders {
    param(
        [string]$SourcePath,
        [string]$DestPath
    )

    Write-Log "Merging $SourcePath into $DestPath" -Level INFO

    if ($WhatIf) {
        Write-Log "[WHATIF] Would merge folders" -Level INFO
        return $true
    }

    try {
        $conflicts = @()
        $items = Get-ChildItem -Path $SourcePath -Recurse -Force

        foreach ($item in $items) {
            $relativePath = $item.FullName.Substring($SourcePath.Length).TrimStart('\')
            $destItem = Join-Path $DestPath $relativePath

            if ($item.PSIsContainer) {
                if (-not (Test-Path $destItem)) {
                    New-Item -ItemType Directory -Path $destItem -Force | Out-Null
                }
            }
            else {
                if (Test-Path $destItem) {
                    # Conflict - compare timestamps
                    $destFile = Get-Item $destItem
                    if ($item.LastWriteTime -gt $destFile.LastWriteTime) {
                        # Source is newer - replace
                        Write-Log "Replacing older file: $relativePath" -Level INFO
                        Move-Item -Path $item.FullName -Destination $destItem -Force -ErrorAction Stop
                    }
                    elseif ($item.LastWriteTime -eq $destFile.LastWriteTime -and $item.Length -eq $destFile.Length) {
                        # Identical - just delete source
                        Remove-Item -Path $item.FullName -Force -ErrorAction Stop
                    }
                    else {
                        # Destination is newer - move source to conflicts
                        $conflictDir = Join-Path $DestPath "conflicts"
                        if (-not (Test-Path $conflictDir)) {
                            New-Item -ItemType Directory -Path $conflictDir -Force | Out-Null
                        }
                        $conflictPath = Join-Path $conflictDir $relativePath
                        $conflictParent = Split-Path $conflictPath -Parent
                        if (-not (Test-Path $conflictParent)) {
                            New-Item -ItemType Directory -Path $conflictParent -Force | Out-Null
                        }
                        Move-Item -Path $item.FullName -Destination $conflictPath -Force -ErrorAction Stop
                        $conflicts += $relativePath
                        Write-Log "Conflict preserved: $relativePath -> conflicts\" -Level WARN
                    }
                }
                else {
                    $destParent = Split-Path $destItem -Parent
                    if (-not (Test-Path $destParent)) {
                        New-Item -ItemType Directory -Path $destParent -Force | Out-Null
                    }
                    Move-Item -Path $item.FullName -Destination $destItem -Force -ErrorAction Stop
                }
            }
        }

        # Write conflict report if any
        if ($conflicts.Count -gt 0) {
            $reportPath = Join-Path $DestPath "conflict_report.csv"
            $conflicts | ForEach-Object {
                [PSCustomObject]@{
                    FileName = $_
                    OriginalLocation = Join-Path $SourcePath $_
                    ConflictLocation = Join-Path (Join-Path $DestPath "conflicts") $_
                    Timestamp = Get-Date -Format 'yyyy-MM-dd HH:mm:ss'
                }
            } | Export-Csv -Path $reportPath -NoTypeInformation
            Write-Log "Conflict report written: $reportPath" -Level INFO
        }

        Write-Log "Merge completed successfully" -Level SUCCESS
        return $true
    }
    catch {
        Write-Log "Merge failed: $_" -Level ERROR
        return $false
    }
}

#endregion

#region Main Script

try {
    # Initialize logging
    Write-Host "`n=== Folder Redirection Repair Script ===" -ForegroundColor Cyan
    Write-Host "Started: $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')" -ForegroundColor Cyan
    Write-Host "Machine: $env:COMPUTERNAME | User: $env:USERNAME`n" -ForegroundColor Cyan

    $logDir = Split-Path $LogPath -Parent
    if (-not (Test-Path $logDir)) {
        New-Item -ItemType Directory -Path $logDir -Force | Out-Null
    }

    # Start transcript
    $transcriptPath = Join-Path $logDir "FR-Repair-Transcript-$(Get-Date -Format 'yyyyMMddHHmmss').log"
    Start-Transcript -Path $transcriptPath -Force | Out-Null
    $script:TranscriptStarted = $true

    Write-Log "=== Script Parameters ===" -Level INFO
    Write-Log "RootPath: $RootPath" -Level INFO
    Write-Log "OldSam: $OldSam" -Level INFO
    Write-Log "NewSam: $NewSam" -Level INFO
    Write-Log "WhatIf: $WhatIf" -Level INFO
    Write-Log "Backup: $Backup" -Level INFO
    Write-Log "SkipADCheck: $SkipADCheck" -Level INFO
    Write-Log "AclOnly: $AclOnly" -Level INFO
    Write-Log "SkipOldUserCheck: $SkipOldUserCheck" -Level INFO
    Write-Log "SkipElevationCheck: $SkipElevationCheck" -Level INFO

    # Validate parameter combinations
    if ($AclOnly -and (-not $OldSam)) {
        $OldSam = $NewSam  # In ACL-only mode, old username is optional
    }

    if (-not $AclOnly -and -not $OldSam) {
        Write-Log "OldSam parameter is required for rename/merge operations" -Level ERROR
        $script:ExitCode = 20
        throw "OldSam parameter required when not using -AclOnly"
    }

    # Check for same username
    if (-not $AclOnly -and $OldSam -and ($OldSam -ceq $NewSam)) {
        Write-Log "Old and new usernames are identical - no changes needed" -Level SUCCESS
        Write-Host "`nSUCCESS: Old and new usernames are identical. ExitCode=0`n" -ForegroundColor Green
        $script:ExitCode = 0
        exit 0
    }

    if ($SkipElevationCheck) {
        Write-Log "Elevation check skipped per -SkipElevationCheck switch" -Level WARN
    }
    else {
        Assert-Administrator
    }

    # Step 1: Connectivity check
    Write-Log "=== Step 1: Connectivity Check ===" -Level INFO

    $testStart = Get-Date
    $pathReachable = $false

    while (((Get-Date) - $testStart).TotalSeconds -lt $SMBTimeoutSec) {
        if (Test-Path $RootPath -ErrorAction SilentlyContinue) {
            $pathReachable = $true
            break
        }
        Start-Sleep -Milliseconds 500
    }

    if (-not $pathReachable) {
        Write-Log "SMB path unreachable: $RootPath (timeout: ${SMBTimeoutSec}s)" -Level ERROR
        $script:ExitCode = 10
        throw "SMB path unreachable"
    }

    Write-Log "SMB path confirmed reachable: $RootPath" -Level SUCCESS

    # Step 2: AD/SID verification (Robust)
    if (-not $SkipADCheck) {
        Write-Log "=== Step 2: AD/SID Verification ===" -Level INFO

        if (-not (Get-Module ActiveDirectory -ListAvailable)) {
            Write-Log "ActiveDirectory module not available" -Level ERROR
            $script:ExitCode = 11
            throw "ActiveDirectory module required"
        }

        Import-Module ActiveDirectory -ErrorAction Stop

        # Always try to get new user first
        $newUser = $null
        $oldUser = $null

        try {
            $newUser = Get-ADUser -Identity $NewSam -Properties SID -ErrorAction Stop
            Write-Log "New user found: $($newUser.DistinguishedName) | SID: $($newUser.SID)" -Level INFO
        }
        catch {
            Write-Log "Could not find new user: $NewSam - $_" -Level ERROR
            $script:ExitCode = 11
            throw "AD lookup failed for new username"
        }

        # Try to get old user only if not skipped
        if (-not $SkipOldUserCheck -and $OldSam -and ($OldSam -ne $NewSam)) {
            try {
                $oldUser = Get-ADUser -Identity $OldSam -Properties SID -ErrorAction Stop
                Write-Log "Old user found: $($oldUser.DistinguishedName) | SID: $($oldUser.SID)" -Level INFO
            }
            catch {
                Write-Log "Old user '$OldSam' not found in AD. Assuming rename already completed; proceeding with new user only." -Level WARN
                $oldUser = $null
            }
        }
        elseif ($SkipOldUserCheck) {
            Write-Log "Old user check skipped per -SkipOldUserCheck" -Level INFO
        }

        # If both users found, verify SIDs match
        if ($oldUser -and $newUser) {
            if ($oldUser.SID.Value -ne $newUser.SID.Value) {
                Write-Log "SID MISMATCH - This is not a rename operation!" -Level ERROR
                Write-Log "Old SID: $($oldUser.SID.Value)" -Level ERROR
                Write-Log "New SID: $($newUser.SID.Value)" -Level ERROR
                $script:ExitCode = 12
                throw "SID mismatch detected: old ($($oldUser.SID.Value)) vs new ($($newUser.SID.Value)). This is not a simple rename."
            }
            Write-Log "SID verification passed - confirmed account rename" -Level SUCCESS
        }

        # Use new user's SID for all downstream operations
        $script:UserSID = $newUser.SID
        Write-Log "Using SID for ACL operations: $($script:UserSID.Value)" -Level INFO
    }
    else {
        Write-Log "=== Step 2: AD/SID Verification (SKIPPED) ===" -Level WARN
        Write-Log "WARNING: AD check bypassed - ACL repair will be limited" -Level WARN

        # Try to resolve SID via WMI/CIM as fallback
        try {
            $user = Get-CimInstance -ClassName Win32_UserAccount -Filter "Name='$NewSam'" | Select-Object -First 1
            if ($user) {
                $script:UserSID = New-Object System.Security.Principal.SecurityIdentifier($user.SID)
                Write-Log "Resolved user SID via WMI: $($script:UserSID.Value)" -Level INFO
            }
        }
        catch {
            Write-Log "Could not resolve SID via WMI - ACL repair will skip user ACE" -Level WARN
        }
    }

    # ACL-Only Mode Short-Circuit
    if ($AclOnly) {
        Write-Log "=== ACL-Only Mode ===" -Level INFO
        $targetPath = Join-Path $RootPath $NewSam

        if (-not (Test-Path -LiteralPath $targetPath)) {
            Write-Log "Target path not found: $targetPath" -Level ERROR
            $script:ExitCode = 20
            throw "Target path does not exist: $targetPath"
        }

        Write-Host "[ACL] Verifying permissions on $targetPath ..." -ForegroundColor Cyan

        $acl = Get-Acl -LiteralPath $targetPath

        # Define required ACEs
        $required = @()
        if ($script:UserSID) {
            $required += @{
                Id = $script:UserSID.Value
                IdDisplay = "User ($NewSam)"
                Rights = 'Modify'
                IsSID = $true
            }
        }
        $required += @{
            Id = 'S-1-5-18'
            IdDisplay = 'NT AUTHORITY\SYSTEM'
            Rights = 'FullControl'
            IsSID = $true
        }
        $required += @{
            Id = 'S-1-5-32-544'
            IdDisplay = 'BUILTIN\Administrators'
            Rights = 'FullControl'
            IsSID = $true
        }

        # Check current ACL
        $report = foreach ($r in $required) {
            $present = $false
            foreach ($ace in $acl.Access) {
                try {
                    $aceSid = $ace.IdentityReference.Translate([System.Security.Principal.SecurityIdentifier]).Value
                    if ($aceSid -eq $r.Id -and
                        -not $ace.IsInherited -and
                        $ace.AccessControlType -eq 'Allow' -and
                        ($ace.FileSystemRights.ToString() -match $r.Rights)) {
                        $present = $true
                        break
                    }
                }
                catch {
                    # Identity couldn't be translated, skip
                }
            }
            [PSCustomObject]@{
                Identity = $r.IdDisplay
                RequiredRights = $r.Rights
                Present = $present
                SID = $r.Id
                IsSID = $r.IsSID
            }
        }

        $report | Format-Table -AutoSize

        if ($WhatIf) {
            Write-Host "[ACL] WhatIf: would add missing ACEs shown as Present=False." -ForegroundColor Yellow
            Write-Log "[WHATIF] ACL audit complete - no changes made" -Level INFO
            Write-Host "`nSUCCESS: ACL audit complete. ExitCode=0`n" -ForegroundColor Green
            $script:ExitCode = 0
            exit 0
        }

        # Apply missing ACEs
        $changed = $false
        foreach ($row in $report | Where-Object { -not $_.Present }) {
            $rights = $row.RequiredRights
            $identity = if ($row.IsSID) {
                New-Object System.Security.Principal.SecurityIdentifier($row.SID)
            } else {
                $row.Identity
            }

            $rule = New-Object System.Security.AccessControl.FileSystemAccessRule(
                $identity,
                $rights,
                ([System.Security.AccessControl.InheritanceFlags]::ContainerInherit -bor [System.Security.AccessControl.InheritanceFlags]::ObjectInherit),
                [System.Security.AccessControl.PropagationFlags]::None,
                [System.Security.AccessControl.AccessControlType]::Allow
            )
            $acl.AddAccessRule($rule)
            Write-Log "Added $rights for $($row.Identity)" -Level SUCCESS
            Write-Host "[ACL] Added $rights for $($row.Identity)" -ForegroundColor Green
            $changed = $true
        }

        if ($changed) {
            Set-Acl -LiteralPath $targetPath -AclObject $acl
            Write-Log "Permissions updated on $targetPath" -Level SUCCESS
            Write-Host "[ACL] Permissions updated." -ForegroundColor Green
        }
        else {
            Write-Log "All required permissions already present on $targetPath" -Level SUCCESS
            Write-Host "[ACL] All required permissions already present. No changes made." -ForegroundColor Green
        }

        Write-Host "`nSUCCESS: ACL-only mode completed for $targetPath. ExitCode=0`n" -ForegroundColor Green
        $script:ExitCode = 0
        exit 0
    }

    # Step 3: Folder discovery
    Write-Log "=== Step 3: Folder Discovery ===" -Level INFO

    # Get actual folder names from filesystem (case-sensitive)
    $actualOldName = Get-ActualFolderName -ParentPath $RootPath -FolderName $OldSam
    $actualNewName = Get-ActualFolderName -ParentPath $RootPath -FolderName $NewSam

    Write-Log "Filesystem check - Old folder name: $(if($actualOldName){'['+$actualOldName+']'}else{'[not found]'})" -Level INFO
    Write-Log "Filesystem check - New folder name: $(if($actualNewName){'['+$actualNewName+']'}else{'[not found]'})" -Level INFO

    # Determine actual paths
    $oldPath = if ($actualOldName) { Join-Path $RootPath $actualOldName } else { Join-Path $RootPath $OldSam }
    $newPath = Join-Path $RootPath $NewSam

    Write-Log "Old path: $oldPath" -Level INFO
    Write-Log "New path: $newPath" -Level INFO

    # Check if this is a case-only rename (same folder, different case)
    $isCaseOnlyRename = $false
    if ($actualOldName -and $actualOldName -ine $NewSam -and $actualOldName -ieq $NewSam) {
        $isCaseOnlyRename = $true
        Write-Log "Detected case-only rename: [$actualOldName] -> [$NewSam]" -Level INFO
    }

    # Check if both names exist as separate folders (should only happen if case-sensitive or truly different)
    $oldExists = $actualOldName -ne $null -and (Test-Path $oldPath)
    $newExists = $actualNewName -ne $null -and (Test-Path $newPath) -and (-not $isCaseOnlyRename)

    Write-Log "Old folder exists: $oldExists" -Level INFO
    Write-Log "New folder exists: $newExists" -Level INFO

    # Get stats
    $oldStats = if ($oldExists) { Get-FolderStats -Path $oldPath -Fast } else { @{Exists=$false; FileCount=0; SizeMB=0} }
    $newStats = if ($newExists) { Get-FolderStats -Path $newPath -Fast } else { @{Exists=$false; FileCount=0; SizeMB=0} }

    Write-Log "Old folder: Exists=$($oldStats.Exists), Files=$($oldStats.FileCount), Size=$($oldStats.SizeMB)MB" -Level INFO
    Write-Log "New folder: Exists=$($newStats.Exists), Files=$($newStats.FileCount), Size=$($newStats.SizeMB)MB" -Level INFO

    # Step 4: Open handle check
    Write-Log "=== Step 4: Open Handle Check ===" -Level INFO

    $openOld = @()
    $openNew = @()

    if ($oldExists) {
        $openOld = Test-OpenFiles -Path $oldPath
    }
    if ($newExists) {
        $openNew = Test-OpenFiles -Path $newPath
    }

    $totalOpen = $openOld.Count + $openNew.Count

    if ($totalOpen -gt 0) {
        Write-Log "Found $totalOpen open files:" -Level WARN
        $openOld + $openNew | ForEach-Object {
            Write-Log "  FileId: $($_.FileId) | ClientIP: $($_.ClientComputerName) | User: $($_.ClientUserName)" -Level WARN
        }

        if (-not $WhatIf) {
            Write-Log "Cannot proceed with open files. Close files or use: Close-SmbOpenFile -FileId <id>" -Level ERROR
            $script:ExitCode = 13
            throw "Open files detected"
        }
        else {
            Write-Log "[WHATIF] Would abort due to open files in production run" -Level WARN
        }
    }
    else {
        Write-Log "No open files detected" -Level SUCCESS
    }

    # Step 5: Decision matrix
    Write-Log "=== Step 5: Operation Planning ===" -Level INFO

    $operation = $null

    if (-not $oldExists -and -not $newExists) {
        Write-Log "Neither folder exists - nothing to do" -Level INFO
        $operation = "none"
    }
    elseif ($isCaseOnlyRename) {
        Write-Log "Plan: CASE-RENAME [$actualOldName] -> [$NewSam]" -Level INFO
        $operation = "case-rename"
    }
    elseif ($oldExists -and -not $newExists) {
        Write-Log "Plan: RENAME $oldPath -> $newPath" -Level INFO
        $operation = "rename"
    }
    elseif (-not $oldExists -and $newExists) {
        Write-Log "Plan: VALIDATE $newPath (only new folder exists)" -Level INFO
        $operation = "validate"
    }
    elseif ($oldExists -and $newExists) {
        if ($newStats.FileCount -le 10 -and $newStats.SizeMB -lt 5) {
            Write-Log "Plan: MERGE (new folder is small: $($newStats.FileCount) files, $($newStats.SizeMB)MB)" -Level INFO
            $operation = "merge"
        }
        else {
            Write-Log "Plan: MERGE WITH CONFLICTS (both folders have content)" -Level INFO
            $operation = "merge-conflicts"
        }
    }

    if ($WhatIf) {
        Write-Log "[WHATIF] Preview of planned operations:" -Level INFO
        Write-Log "[WHATIF] Operation: $operation" -Level INFO
        Write-Log "[WHATIF] No changes will be made in WhatIf mode" -Level INFO
    }

    # Step 6: Backup
    if ($Backup -and $oldExists) {
        Write-Log "=== Step 6: Backup ===" -Level INFO
        $backupPath = New-BackupArchive -SourcePath $oldPath -BackupRoot $RootPath -UserName $NewSam
        if ($backupPath) {
            Write-Log "Backup path: $backupPath" -Level SUCCESS
        }
    }

    # Step 7: Execute changes
    Write-Log "=== Step 7: Execute Changes ===" -Level INFO

    $finalPath = $newPath

    switch ($operation) {
        "none" {
            Write-Log "No changes required" -Level SUCCESS
        }

        "rename" {
            Invoke-WithRetry -ScriptBlock {
                if ($WhatIf) {
                    Write-Log "[WHATIF] Would rename: $oldPath -> $newPath" -Level INFO
                }
                else {
                    Write-Log "Executing rename: $oldPath -> $newPath" -Level INFO
                    Rename-Item -Path $oldPath -NewName $NewSam -Force -ErrorAction Stop
                    Write-Log "Rename completed successfully" -Level SUCCESS
                }
            }
        }

        "case-rename" {
            # NTFS requires temp rename for case-only changes
            $tempName = "${NewSam}_TEMP_$(Get-Random -Minimum 1000 -Maximum 9999)"
            $tempPath = Join-Path $RootPath $tempName

            Invoke-WithRetry -ScriptBlock {
                if ($WhatIf) {
                    Write-Log "[WHATIF] Would rename: [$actualOldName] -> [$tempName] -> [$NewSam]" -Level INFO
                }
                else {
                    Write-Log "Executing case-rename via temp: [$actualOldName] -> [$tempName] -> [$NewSam]" -Level INFO
                    Rename-Item -Path $oldPath -NewName $tempName -Force -ErrorAction Stop
                    Write-Log "  Step 1/2: Renamed to temp name" -Level INFO
                    Start-Sleep -Milliseconds 500
                    Rename-Item -Path $tempPath -NewName $NewSam -Force -ErrorAction Stop
                    Write-Log "  Step 2/2: Renamed to final name" -Level INFO
                    Write-Log "Case-rename completed successfully" -Level SUCCESS
                }
            }
        }

        "validate" {
            Write-Log "Validating existing folder: $newPath" -Level INFO
        }

        { $_ -in "merge", "merge-conflicts" } {
            if (-not (Test-Path $newPath)) {
                if ($WhatIf) {
                    Write-Log "[WHATIF] Would create: $newPath" -Level INFO
                }
                else {
                    New-Item -ItemType Directory -Path $newPath -Force | Out-Null
                }
            }

            $mergeSuccess = Merge-Folders -SourcePath $oldPath -DestPath $newPath

            if ($mergeSuccess -and -not $WhatIf) {
                # Remove old folder after successful merge (should be empty now)
                Write-Log "Removing old folder: $oldPath" -Level INFO
                try {
                    Remove-Item -Path $oldPath -Recurse -Force -ErrorAction Stop
                    Write-Log "Old folder removed" -Level SUCCESS
                }
                catch {
                    Write-Log "Could not remove old folder (may have remaining items): $_" -Level WARN
                }
            }
        }
    }

    # Step 8: ACL verification/repair
    if ($operation -ne "none" -and (Test-Path $finalPath)) {
        Write-Log "=== Step 8: ACL Verification ===" -Level INFO

        if (-not $WhatIf) {
            $aclSuccess = Repair-FolderACL -Path $finalPath -UserSID $script:UserSID
            if (-not $aclSuccess) {
                Write-Log "ACL repair encountered issues - manual verification recommended" -Level WARN
            }
        }
        else {
            Write-Log "[WHATIF] Would verify/repair ACLs on: $finalPath" -Level INFO
        }
    }

    # Step 9: Post-checks
    Write-Log "=== Step 9: Post-Checks ===" -Level INFO

    if (Test-Path $finalPath) {
        $finalStats = Get-FolderStats -Path $finalPath
        Write-Log "Final folder: $finalPath" -Level INFO
        Write-Log "  Files: $($finalStats.FileCount)" -Level INFO
        Write-Log "  Size: $($finalStats.SizeMB) MB" -Level INFO
        Write-Log "  Last Modified: $($finalStats.LastWrite)" -Level INFO

        $script:ExitCode = 0
        $statusMsg = if ($WhatIf) { "[WHATIF] " } else { "" }
        $statusMsg += "SUCCESS: Redirected folder is now $finalPath (files: $($finalStats.FileCount), size: $($finalStats.SizeMB) MB). ExitCode=0"
        Write-Log $statusMsg -Level SUCCESS
        Write-Host "`n$statusMsg`n" -ForegroundColor Green
    }
    elseif ($operation -eq "none") {
        Write-Log "No folder exists at either location - may need manual intervention" -Level WARN
        $script:ExitCode = 0
        Write-Host "`nSUCCESS: No changes required. ExitCode=0`n" -ForegroundColor Green
    }
    else {
        Write-Log "Warning: Final path does not exist: $finalPath" -Level WARN
    }
}
catch {
    Write-Log "=== SCRIPT FAILED ===" -Level ERROR
    Write-Log "Error: $($_.Exception.Message)" -Level ERROR
    Write-Log "Type: $($_.Exception.GetType().FullName)" -Level ERROR
    Write-Log "Target: $($_.TargetObject)" -Level ERROR
    Write-Log "Stack: $($_.ScriptStackTrace)" -Level ERROR

    if ($script:ExitCode -eq 0) {
        $script:ExitCode = 20
    }

    Write-Host "`nFAILURE: Script terminated with errors. ExitCode=$script:ExitCode" -ForegroundColor Red
    Write-Host "Check logs: $LogPath`n" -ForegroundColor Yellow
}
finally {
    if ($script:TranscriptStarted) {
        Stop-Transcript | Out-Null
    }

    Write-Host "Completed: $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')" -ForegroundColor Cyan
    Write-Host "Log: $LogPath" -ForegroundColor Cyan
    if ($script:TranscriptStarted) {
        Write-Host "Transcript: $transcriptPath`n" -ForegroundColor Cyan
    }

    exit $script:ExitCode
}

#endregion
