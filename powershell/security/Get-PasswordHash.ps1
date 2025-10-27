<#
.SYNOPSIS
    Extracts Windows password database files (SAM or NTDS.dit) for forensic analysis or password auditing.

.DESCRIPTION
    This script creates a Volume Shadow Copy to extract locked password database files from
    Windows systems. On domain controllers, it copies the NTDS.dit file; on member servers
    or workstations, it copies the SAM file. Both operations also copy the SYSTEM registry hive
    required for decryption.

    ⚠️ CRITICAL WARNING: This script performs HIGHLY SENSITIVE security operations:
    - Extracts password hashes from Active Directory or local accounts
    - Creates Volume Shadow Copies of system files
    - Accesses locked system databases
    - Outputs files that can be used for password cracking
    - Could be used for malicious purposes if mishandled

    This script should ONLY be used for:
    - Authorized security audits and penetration testing
    - Password strength analysis with proper approval
    - Forensic investigations with legal authorization
    - Incident response activities

    NEVER run this script without explicit authorization and proper legal documentation.

.PARAMETER DestinationPath
    Directory path where the extracted password files will be saved.
    - Must be an existing directory
    - Requires write permissions
    - Ensure the destination is secured and encrypted
    - Files: sam/ntds and system (registry hive)

.EXAMPLE
    Get-PasswordFile -DestinationPath "C:\SecureAudit"

    Extracts password files to C:\SecureAudit directory. On a domain controller, creates
    ntds and system files. On other systems, creates sam and system files.

.EXAMPLE
    Get-PasswordFile -DestinationPath "C:\Forensics" -Verbose

    Extracts password files with detailed logging for audit trail purposes.

.NOTES
    Author: SysAdmin Team
    Version: 1.0.0
    Created: 2020-01-01
    Modified: 2025-01-09
    Risk Level: High 🔴 (CRITICAL SECURITY TOOL)

    Prerequisites:
    - PowerShell 5.1 or later
    - Administrator privileges (REQUIRED)
    - Volume Shadow Copy Service (VSS) must be available
    - Sufficient disk space for shadow copy creation
    - On Domain Controllers: NTDS database location accessible

    Security Considerations:
    - ⚠️ CRITICAL: Extracts password hashes that can be used for offline cracking
    - ⚠️ Creates sensitive files that MUST be secured and encrypted
    - ⚠️ Requires administrator privileges (potential for abuse)
    - ⚠️ Legal implications if used without proper authorization
    - ✅ Mitigation: Use only for authorized security assessments
    - ✅ Approval: Obtain written authorization before use
    - ✅ Audit: Log all executions with Start-Transcript
    - ✅ Security: Encrypt extracted files immediately
    - ✅ Cleanup: Securely delete files after analysis (use cipher /w)
    - ✅ Testing: NEVER use on production systems without approval

    Legal Notice:
    Unauthorized use of this script may violate computer fraud and abuse laws.
    Ensure you have proper authorization and legal documentation before execution.

    Change Log:
    - v1.0.0 (2020-01-01): Initial version using VSS and Copy-RawItem

.LINK
    https://github.com/yourusername/sysadmin-toolkit

.LINK
    https://gallery.technet.microsoft.com/scriptcenter/Copy-RawItem-Private-NET-78917643
#>

function Get-PasswordFile {
<#
.SYNOPSIS

    Copies either the SAM or NTDS.dit and system files to a specified directory.

.PARAMETER DestinationPath

    Specifies the directory to the location where the password files are to be copied.

.OUTPUTS

    None or an object representing the copied items.

.EXAMPLE

    Get-PasswordFile "c:\temp"

#>

    [CmdletBinding()]
    Param
    (
        [Parameter(Mandatory = $true, Position = 0)]
        [ValidateScript({Test-Path $_ -PathType 'Container'})]
        [ValidateNotNullOrEmpty()]
        [String]
        $DestinationPath
    )

    # Audit Logging Configuration
    $AuditLogDir = "C:\Logs\SecurityAudit"
    $AuditLogFile = Join-Path $AuditLogDir "PasswordHashExtraction_$(Get-Date -Format 'yyyyMMdd_HHmmss').log"

    # Ensure audit log directory exists
    if (!(Test-Path $AuditLogDir)) {
        try {
            New-Item -ItemType Directory -Path $AuditLogDir -Force | Out-Null
        }
        catch {
            Write-Error "Failed to create audit log directory: $($_.Exception.Message)"
            return
        }
    }

    # Function to write audit log
    function Write-AuditLog {
        param(
            [Parameter(Mandatory=$true)]
            [string]$Message,

            [Parameter(Mandatory=$false)]
            [ValidateSet("INFO", "WARNING", "ERROR", "CRITICAL")]
            [string]$Level = "INFO"
        )

        $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
        $username = [System.Security.Principal.WindowsIdentity]::GetCurrent().Name
        $computer = $env:COMPUTERNAME
        $logMessage = "[$timestamp] [$Level] [User: $username] [Computer: $computer] $Message"

        try {
            Add-Content -Path $AuditLogFile -Value $logMessage -ErrorAction Stop

            # Write to console
            switch ($Level) {
                "CRITICAL" { Write-Host $logMessage -ForegroundColor Magenta }
                "ERROR"    { Write-Host $logMessage -ForegroundColor Red }
                "WARNING"  { Write-Host $logMessage -ForegroundColor Yellow }
                default    { Write-Host $logMessage -ForegroundColor White }
            }
        }
        catch {
            Write-Warning "Failed to write to audit log: $($_.Exception.Message)"
        }
    }

    # Log operation start
    Write-AuditLog "Password hash extraction initiated - Destination: $DestinationPath" -Level "CRITICAL"
    Write-Host "`n========================================" -ForegroundColor Magenta
    Write-Host "CRITICAL SECURITY OPERATION" -ForegroundColor Magenta
    Write-Host "========================================`n" -ForegroundColor Magenta 
  
        #Define Copy-RawItem helper function from http://gallery.technet.microsoft.com/scriptcenter/Copy-RawItem-Private-NET-78917643 
        function Copy-RawItem
        { 
  
        [CmdletBinding()] 
        [OutputType([System.IO.FileSystemInfo])] 
        Param ( 
            [Parameter(Mandatory = $True, Position = 0)] 
            [ValidateNotNullOrEmpty()] 
            [String]
            $Path, 
  
            [Parameter(Mandatory = $True, Position = 1)] 
            [ValidateNotNullOrEmpty()] 
            [String]
            $Destination, 
  
            [Switch]
            $FailIfExists
        ) 
  
        # Get a reference to the internal method - Microsoft.Win32.Win32Native.CopyFile() 
        $mscorlib = [AppDomain]::CurrentDomain.GetAssemblies() | ? {$_.Location -and ($_.Location.Split('\')[-1] -eq 'mscorlib.dll')} 
        $Win32Native = $mscorlib.GetType('Microsoft.Win32.Win32Native') 
        $CopyFileMethod = $Win32Native.GetMethod('CopyFile', ([Reflection.BindingFlags] 'NonPublic, Static'))  
  
        # Perform the copy 
        $CopyResult = $CopyFileMethod.Invoke($null, @($Path, $Destination, ([Bool] $PSBoundParameters['FailIfExists']))) 
  
        $HResult = [System.Runtime.InteropServices.Marshal]::GetLastWin32Error() 
  
        if ($CopyResult -eq $False -and $HResult -ne 0) 
        { 
            # An error occured. Display the Win32 error set by CopyFile 
            throw ( New-Object ComponentModel.Win32Exception ) 
        } 
        else
        { 
            Write-Output (Get-ChildItem $Destination) 
        } 
    } 
   
    # Enhanced admin rights check
    Write-AuditLog "Checking administrator privileges..." -Level "INFO"

    $isAdmin = ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator")

    if (-NOT $isAdmin) {
        $errorMsg = "Administrator privileges required but not detected"
        Write-AuditLog $errorMsg -Level "ERROR"
        Write-AuditLog "Operation aborted - Insufficient privileges" -Level "ERROR"
        Write-Error $errorMsg
        Write-Error "This script must be run with elevated credentials (Run as Administrator)"
        return
    }

    Write-AuditLog "Administrator privileges confirmed" -Level "INFO"

    # Verify destination path is writable
    try {
        $testFile = Join-Path $DestinationPath ".test_$(Get-Random).tmp"
        "test" | Out-File -FilePath $testFile -ErrorAction Stop
        Remove-Item -Path $testFile -Force -ErrorAction SilentlyContinue
        Write-AuditLog "Destination path verified writable: $DestinationPath" -Level "INFO"
    }
    catch {
        $errorMsg = "Destination path is not writable: $DestinationPath"
        Write-AuditLog $errorMsg -Level "ERROR"
        Write-Error $errorMsg
        return
    }
         
    # Get and configure VSS service with error handling
    try {
        Write-AuditLog "Checking Volume Shadow Copy Service (VSS) status..." -Level "INFO"

        $vssService = Get-Service -Name VSS -ErrorAction Stop
        $VssStatus = $vssService.Status
        $VssStartMode = $vssService.StartType

        Write-AuditLog "VSS Service status: $VssStatus, Start type: $VssStartMode" -Level "INFO"

        if ($VssStartMode -eq "Disabled") {
            Write-AuditLog "VSS service is disabled, enabling..." -Level "WARNING"
            Set-Service VSS -StartupType Manual -ErrorAction Stop
            Write-AuditLog "VSS service startup type changed to Manual" -Level "INFO"
        }

        if ($VssStatus -ne "Running") {
            Write-AuditLog "Starting VSS service..." -Level "INFO"
            Start-Service VSS -ErrorAction Stop
            Start-Sleep -Seconds 2
            Write-AuditLog "VSS service started successfully" -Level "INFO"
        }
    }
    catch {
        $errorMsg = "Failed to configure VSS service: $($_.Exception.Message)"
        Write-AuditLog $errorMsg -Level "ERROR"
        Write-Error $errorMsg
        return
    } 
  
        #Check to see if we are on a DC 
        $DomainRole = (Get-WmiObject Win32_ComputerSystem).DomainRole 
        $IsDC = $False
        if ($DomainRole -gt 3) { 
            $IsDC = $True
            $NTDSLocation = (Get-ItemProperty HKLM:\SYSTEM\CurrentControlSet\services\NTDS\Parameters)."DSA Database File"
            $FileDrive = ($NTDSLocation).Substring(0,3) 
        } else {$FileDrive = $Env:HOMEDRIVE + '\'} 
      
        # Create a volume shadow copy with enhanced error handling
        try {
            Write-AuditLog "Creating volume shadow copy for drive: $FileDrive" -Level "CRITICAL"
            $WmiClass = [WMICLASS]"root\cimv2:Win32_ShadowCopy"
            $ShadowCopy = $WmiClass.create($FileDrive, "ClientAccessible")
            $ReturnValue = $ShadowCopy.ReturnValue

            if ($ReturnValue -ne 0) {
                $errorMsg = "Shadow copy creation failed with return code: $ReturnValue"
                Write-AuditLog $errorMsg -Level "ERROR"

                # Provide detailed error explanations
                switch ($ReturnValue) {
                    1 { $explanation = "Access Denied - Insufficient permissions" }
                    2 { $explanation = "Invalid Argument - Check drive path" }
                    3 { $explanation = "Specified volume not found or not supported" }
                    8 { $explanation = "Out of Memory - Insufficient system resources" }
                    9 { $explanation = "Maximum number of shadow copies reached" }
                    10 { $explanation = "Provider already registered" }
                    11 { $explanation = "Provider not registered" }
                    12 { $explanation = "Provider error" }
                    default { $explanation = "Unknown error code" }
                }

                Write-AuditLog "Error explanation: $explanation" -Level "ERROR"
                Write-Error "$errorMsg - $explanation"

                # Restore VSS service state before exiting
                if ($VssStatus -eq "Stopped") {
                    Stop-Service VSS -ErrorAction SilentlyContinue
                }
                if ($VssStartMode -eq "Disabled") {
                    Set-Service VSS -StartupType Disabled -ErrorAction SilentlyContinue
                }

                return
            }

            Write-AuditLog "Shadow copy created successfully (Return code: $ReturnValue)" -Level "INFO"
        }
        catch {
            $errorMsg = "Exception during shadow copy creation: $($_.Exception.Message)"
            Write-AuditLog $errorMsg -Level "ERROR"
            Write-Error $errorMsg
            return
        }  
      
        #Get the DeviceObject Address 
        $ShadowID = $ShadowCopy.ShadowID 
        $ShadowVolume = (Get-WmiObject Win32_ShadowCopy | Where-Object {$_.ID -eq $ShadowID}).DeviceObject 
      
            # Copy password database files with error handling
            try {
                if ($IsDC -ne $true) {
                    # Workstation/Member Server - Copy SAM and SYSTEM
                    Write-AuditLog "System type: Workstation/Member Server - Copying SAM database" -Level "CRITICAL"

                    $SamPath = Join-Path $ShadowVolume "\Windows\System32\Config\sam"
                    $SystemPath = Join-Path $ShadowVolume "\Windows\System32\Config\system"

                    Write-AuditLog "Source SAM path: $SamPath" -Level "INFO"
                    Write-AuditLog "Source SYSTEM path: $SystemPath" -Level "INFO"

                    # Verify source files exist
                    if (!(Test-Path $SamPath)) {
                        throw "SAM file not found at: $SamPath"
                    }
                    if (!(Test-Path $SystemPath)) {
                        throw "SYSTEM file not found at: $SystemPath"
                    }

                    # Copy SAM file
                    Write-AuditLog "Copying SAM file to: $DestinationPath\sam" -Level "CRITICAL"
                    Copy-RawItem $SamPath "$DestinationPath\sam"
                    Write-AuditLog "SAM file copied successfully" -Level "CRITICAL"

                    # Copy SYSTEM file
                    Write-AuditLog "Copying SYSTEM file to: $DestinationPath\system" -Level "CRITICAL"
                    Copy-RawItem $SystemPath "$DestinationPath\system"
                    Write-AuditLog "SYSTEM file copied successfully" -Level "CRITICAL"

                    # Verify copied files exist
                    $samDest = "$DestinationPath\sam"
                    $systemDest = "$DestinationPath\system"

                    if ((Test-Path $samDest) -and (Test-Path $systemDest)) {
                        $samSize = (Get-Item $samDest).Length
                        $systemSize = (Get-Item $systemDest).Length
                        Write-AuditLog "Files verified - SAM: $samSize bytes, SYSTEM: $systemSize bytes" -Level "CRITICAL"
                    }
                    else {
                        throw "File copy verification failed - destination files not found"
                    }
                }
                else {
                    # Domain Controller - Copy NTDS.dit and SYSTEM
                    Write-AuditLog "System type: Domain Controller - Copying NTDS.dit database" -Level "CRITICAL"

                    $NTDSPath = Join-Path $ShadowVolume "\Windows\NTDS\NTDS.dit"
                    $SystemPath = Join-Path $ShadowVolume "\Windows\System32\Config\system"

                    Write-AuditLog "Source NTDS path: $NTDSPath" -Level "INFO"
                    Write-AuditLog "Source SYSTEM path: $SystemPath" -Level "INFO"

                    # Verify source files exist
                    if (!(Test-Path $NTDSPath)) {
                        throw "NTDS.dit file not found at: $NTDSPath"
                    }
                    if (!(Test-Path $SystemPath)) {
                        throw "SYSTEM file not found at: $SystemPath"
                    }

                    # Copy NTDS.dit file
                    Write-AuditLog "Copying NTDS.dit file to: $DestinationPath\ntds" -Level "CRITICAL"
                    Copy-RawItem $NTDSPath "$DestinationPath\ntds"
                    Write-AuditLog "NTDS.dit file copied successfully" -Level "CRITICAL"

                    # Copy SYSTEM file
                    Write-AuditLog "Copying SYSTEM file to: $DestinationPath\system" -Level "CRITICAL"
                    Copy-RawItem $SystemPath "$DestinationPath\system"
                    Write-AuditLog "SYSTEM file copied successfully" -Level "CRITICAL"

                    # Verify copied files exist
                    $ntdsDest = "$DestinationPath\ntds"
                    $systemDest = "$DestinationPath\system"

                    if ((Test-Path $ntdsDest) -and (Test-Path $systemDest)) {
                        $ntdsSize = (Get-Item $ntdsDest).Length
                        $systemSize = (Get-Item $systemDest).Length
                        Write-AuditLog "Files verified - NTDS: $ntdsSize bytes, SYSTEM: $systemSize bytes" -Level "CRITICAL"
                    }
                    else {
                        throw "File copy verification failed - destination files not found"
                    }
                }
            }
            catch {
                $errorMsg = "File copy operation failed: $($_.Exception.Message)"
                Write-AuditLog $errorMsg -Level "ERROR"
                Write-Error $errorMsg

                # Attempt to clean up partial copies
                Write-AuditLog "Cleaning up partial file copies..." -Level "WARNING"
                Remove-Item "$DestinationPath\sam" -Force -ErrorAction SilentlyContinue
                Remove-Item "$DestinationPath\ntds" -Force -ErrorAction SilentlyContinue
                Remove-Item "$DestinationPath\system" -Force -ErrorAction SilentlyContinue

                # Restore VSS service state
                if ($VssStatus -eq "Stopped") {
                    Stop-Service VSS -ErrorAction SilentlyContinue
                }
                if ($VssStartMode -eq "Disabled") {
                    Set-Service VSS -StartupType Disabled -ErrorAction SilentlyContinue
                }

                return
            }

        # Restore VSS service to previous state
        try {
            Write-AuditLog "Restoring VSS service to original state..." -Level "INFO"

            if ($VssStatus -eq "Stopped") {
                Stop-Service VSS -ErrorAction Stop
                Write-AuditLog "VSS service stopped" -Level "INFO"
            }

            if ($VssStartMode -eq "Disabled") {
                Set-Service VSS -StartupType Disabled -ErrorAction Stop
                Write-AuditLog "VSS service startup type restored to Disabled" -Level "INFO"
            }
        }
        catch {
            Write-AuditLog "Warning: Failed to restore VSS service state: $($_.Exception.Message)" -Level "WARNING"
        }

        # Log successful completion
        Write-AuditLog "========================================" -Level "CRITICAL"
        Write-AuditLog "PASSWORD HASH EXTRACTION COMPLETED SUCCESSFULLY" -Level "CRITICAL"
        Write-AuditLog "Destination: $DestinationPath" -Level "CRITICAL"
        Write-AuditLog "Audit log: $AuditLogFile" -Level "CRITICAL"
        Write-AuditLog "========================================" -Level "CRITICAL"

        Write-Host "`n========================================" -ForegroundColor Green
        Write-Host "OPERATION COMPLETED SUCCESSFULLY" -ForegroundColor Green
        Write-Host "========================================" -ForegroundColor Green
        Write-Host "Extracted files location: $DestinationPath" -ForegroundColor Yellow
        Write-Host "Audit log location: $AuditLogFile" -ForegroundColor Yellow
        Write-Host "`nWARNING: Secure these files immediately!" -ForegroundColor Red
        Write-Host "- Encrypt the destination folder" -ForegroundColor Red
        Write-Host "- Limit access to authorized personnel only" -ForegroundColor Red
        Write-Host "- Delete files securely after analysis (cipher /w)" -ForegroundColor Red
        Write-Host "========================================`n" -ForegroundColor Green
}