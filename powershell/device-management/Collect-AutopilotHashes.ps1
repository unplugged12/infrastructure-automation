<#
.SYNOPSIS
    Automated Windows Autopilot hardware hash collection with PowerShell 7 installation and prerequisite checking.

.DESCRIPTION
    Comprehensive Autopilot hardware hash collection script that operates in three phases:
    1. PowerShell 7 Installation: Checks for and installs PowerShell 7 on remote computers using winget
    2. Prerequisite Validation: Verifies Get-WindowsAutopilotInfo script and PSGallery access
    3. Hash Collection: Collects hardware hashes from all online computers with PowerShell 7

    The script uses parallel processing for efficient bulk collection, creates detailed reports for
    each phase, and handles computers with or without internet access (via offline script mode).

    This script automates device enrollment preparation for Windows Autopilot deployment.

.PARAMETER SkipPSInstall
    Skip the PowerShell 7 installation check phase. Use this if you know all computers already have PS7 installed.
    Optional switch parameter.

.PARAMETER ThrottleLimit
    Maximum number of concurrent operations to run in parallel during hash collection.
    Optional. Default: 5
    Recommended values: 5-10 for most networks, lower for slower networks or DCs.

.PARAMETER OutputDir
    Directory path where all output files (CSV, logs, reports) will be saved.
    Optional. Default: "C:\Autopilot"
    Creates directory if it doesn't exist.

.PARAMETER OfflinePath
    Path to a local copy of Get-WindowsAutopilotInfo.ps1 script for offline installation.
    Use this for computers without internet/PSGallery access.
    Optional. If not specified, script will attempt online installation from PSGallery.

.EXAMPLE
    .\Collect-AutopilotHashes.ps1

    Run with default settings: Check/install PS7, verify prerequisites, collect hashes from all computers
    in the configured OU. Output to C:\Autopilot with throttle limit of 5.

.EXAMPLE
    .\Collect-AutopilotHashes.ps1 -SkipPSInstall -ThrottleLimit 10 -OutputDir "D:\AutopilotData"

    Skip PS7 installation check, use higher concurrency (10), and save results to custom directory.

.EXAMPLE
    .\Collect-AutopilotHashes.ps1 -OfflinePath "C:\Scripts\Get-WindowsAutopilotInfo.ps1" -Verbose

    Use offline script for computers without PSGallery access, with detailed logging.

.NOTES
    Author: SysAdmin Team
    Version: 1.0.0
    Created: 2024-06-01
    Modified: 2025-01-09
    Risk Level: Medium 🟡

    Prerequisites:
    - PowerShell 5.1 or later on local machine (PowerShell 7+ recommended)
    - Administrator privileges
    - Active Directory PowerShell Module
    - WinRM enabled on target computers
    - Credentials with admin rights on remote computers
    - Network connectivity to target computers
    - Target computers need winget (for PS7 installation) or offline script

    Security Considerations:
    - ⚠️ Installs software (PowerShell 7) on remote computers
    - ⚠️ Requires domain admin or equivalent credentials
    - ⚠️ Accesses WMI/CIM on remote computers
    - ⚠️ May install scripts from PSGallery on remote systems
    - ✅ Mitigation: Use -WhatIf during testing, review OU scope before execution
    - ✅ Testing: Test on small OU subset first
    - ✅ Audit: All operations are logged to AutopilotScript.log
    - ✅ Approval: Verify change management approval for software installation

    Output Files:
    - AutopilotHardwareHashes.csv: Hardware hash data for Intune import
    - PS7InstallationReport.csv: PowerShell 7 installation status per computer
    - AutopilotPrereqReport.csv: Prerequisite check results
    - AutopilotScript.log: Detailed operation log
    - AutopilotError.log: Error messages and failures

    Change Log:
    - v1.0.0 (2024-06-01): Initial version with PS7 auto-install and parallel processing

.LINK
    https://github.com/yourusername/sysadmin-toolkit

.LINK
    https://docs.microsoft.com/en-us/mem/autopilot/add-devices
#>

param(
    [Parameter(Mandatory=$false)]
    [switch]$SkipPSInstall,
    
    [Parameter(Mandatory=$false)]
    [int]$ThrottleLimit = 5,
    
    [Parameter(Mandatory=$false)]
    [string]$OutputDir = "C:\Autopilot",
    
    [Parameter(Mandatory=$false)]
    [string]$OfflinePath
)

# Check if running as administrator
$isAdmin = ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator")
if (-not $isAdmin) {
    Write-Error "This script requires administrator privileges. Please restart PowerShell as administrator."
    exit 1
}

# Load credential once before passing into threads
$Credential = Get-Credential -Message "Enter credentials with admin rights on remote computers"

# Directory and log paths
$OutputFile = "$OutputDir\AutopilotHardwareHashes.csv"
$LogFile = "$OutputDir\AutopilotScript.log"
$ErrorFile = "$OutputDir\AutopilotError.log"
$PrereqReportFile = "$OutputDir\AutopilotPrereqReport.csv"
$PS7ReportFile = "$OutputDir\PS7InstallationReport.csv"

# Ensure output directory exists
If (!(Test-Path $OutputDir)) {
    New-Item -ItemType Directory -Path $OutputDir | Out-Null
}

# Initialize log files
"[$(Get-Date)] Starting Autopilot hardware hash collection process" | Out-File -FilePath $LogFile
"[$(Get-Date)] Starting PowerShell 7 installation check" | Out-File -FilePath $LogFile -Append

# Initialize the CSV with header
if (!(Test-Path $OutputFile)) {
    "Device Serial Number,Windows Product ID,Hardware Hash" | Out-File -FilePath $OutputFile -Encoding UTF8
}

# Initialize PS7 report
"ComputerName,IsOnline,HasPS7,PS7Version,WinGetAvailable,InstallAttempted,InstallSuccess,ErrorDetails" | 
    Out-File -FilePath $PS7ReportFile -Encoding UTF8

# Get list of computers
$ComputerList = Get-ADComputer -SearchBase "OU=TestOU,DC=company,DC=local" -Filter * | Select-Object -ExpandProperty Name
$TotalComputers = $ComputerList.Count
Write-Host "Found $TotalComputers computers to process"

# Create a global lock object for file access synchronization
$Global:FileLock = [System.Object]::new()

#==============================================================================
# PHASE 1: Check and Install PowerShell 7
#==============================================================================

if (-not $SkipPSInstall) {
    Write-Host "PHASE 1: Checking and installing PowerShell 7 on remote computers..." -ForegroundColor Cyan
    
    # PowerShell 7 check and install scriptblock
    $PS7InstallScriptBlock = {
        param (
            $Computer,
            $Cred,
            $PS7ReportFile,
            $LogFile,
            $FileLock
        )
        
        $PS7Result = [PSCustomObject]@{
            ComputerName = $Computer
            IsOnline = $false
            HasPS7 = $false
            PS7Version = ""
            WinGetAvailable = $false
            InstallAttempted = $false
            InstallSuccess = $false
            ErrorDetails = ""
        }
        
        # Check if online
        $PS7Result.IsOnline = Test-Connection -ComputerName $Computer -Count 1 -Quiet
        
        if ($PS7Result.IsOnline) {
            try {
                # Check for PowerShell 7
                $PS7Check = Invoke-Command -ComputerName $Computer -Credential $Cred -ScriptBlock {
                    $PS7Paths = @(
                        "C:\Program Files\PowerShell\7\pwsh.exe",
                        "${env:ProgramFiles}\PowerShell\7\pwsh.exe",
                        "${env:ProgramFiles(x86)}\PowerShell\7\pwsh.exe"
                    )
                    
                    $PS7Exe = $PS7Paths | Where-Object { Test-Path $_ } | Select-Object -First 1
                    
                    if ($PS7Exe) {
                        try {
                            $versionInfo = (& $PS7Exe -Command '$PSVersionTable.PSVersion' | Out-String).Trim()
                            return @{
                                HasPS7 = $true
                                Version = $versionInfo
                            }
                        } catch {
                            return @{
                                HasPS7 = $true
                                Version = "Unknown"
                            }
                        }
                    } else {
                        # Check if winget is available for install
                        $hasWinget = $null -ne (Get-Command -Name winget -ErrorAction SilentlyContinue)
                        
                        return @{
                            HasPS7 = $false
                            Version = ""
                            WinGetAvailable = $hasWinget
                        }
                    }
                }
                
                $PS7Result.HasPS7 = $PS7Check.HasPS7
                $PS7Result.PS7Version = $PS7Check.Version
                
                # If PS7 is not installed, try to install it
                if (-not $PS7Result.HasPS7) {
                    $PS7Result.WinGetAvailable = $PS7Check.WinGetAvailable
                    
                    if ($PS7Check.WinGetAvailable) {
                        $PS7Result.InstallAttempted = $true
                        
                        # Install PowerShell 7 using winget
                        $installResult = Invoke-Command -ComputerName $Computer -Credential $Cred -ScriptBlock {
                            try {
                                # Silent install with winget - fix the parameter to use --silent
                                $process = Start-Process -FilePath "winget" -ArgumentList "install Microsoft.PowerShell --silent --accept-source-agreements --accept-package-agreements" -Wait -PassThru -NoNewWindow
                                
                                # Return success based on exit code
                                return @{
                                    Success = ($process.ExitCode -eq 0)
                                    ExitCode = $process.ExitCode
                                }
                            } catch {
                                return @{
                                    Success = $false
                                    Error = $_.Exception.Message
                                }
                            }
                        }
                        
                        $PS7Result.InstallSuccess = $installResult.Success
                        if (-not $installResult.Success) {
                            $PS7Result.ErrorDetails = "Exit code: $($installResult.ExitCode), $($installResult.Error)"
                        }
                    } else {
                        $PS7Result.ErrorDetails = "WinGet not available for installation"
                    }
                }
            }
            catch {
                $PS7Result.ErrorDetails = $_.Exception.Message
            }
        }
        
        # Export the PS7 result - use global lock object
        [System.Threading.Monitor]::Enter($FileLock)
        try {
            "$($PS7Result.ComputerName),$($PS7Result.IsOnline),$($PS7Result.HasPS7),$($PS7Result.PS7Version),$($PS7Result.WinGetAvailable),$($PS7Result.InstallAttempted),$($PS7Result.InstallSuccess),$($PS7Result.ErrorDetails)" | 
                Add-Content -Path $PS7ReportFile
        }
        finally {
            [System.Threading.Monitor]::Exit($FileLock)
        }
        
        return $PS7Result
    }
    
    # Run PS7 checks and installs
    $PS7Results = @()
    $PS7Progress = 0
    
    foreach ($Computer in $ComputerList) {
        $PS7Progress++
        Write-Progress -Activity "Checking PowerShell 7 installation" -Status "$PS7Progress of $TotalComputers" -PercentComplete (($PS7Progress / $TotalComputers) * 100)
        $Result = & $PS7InstallScriptBlock $Computer $Credential $PS7ReportFile $LogFile $Global:FileLock
        $PS7Results += $Result
    }
    
    Write-Progress -Activity "Checking PowerShell 7 installation" -Completed
    
    # Summarize PS7 results
    $OnlineCount = ($PS7Results | Where-Object { $_.IsOnline }).Count
    $PS7ReadyCount = ($PS7Results | Where-Object { $_.IsOnline -and $_.HasPS7 }).Count
    $PS7InstalledCount = ($PS7Results | Where-Object { $_.InstallAttempted -and $_.InstallSuccess }).Count
    $PS7FailedCount = ($PS7Results | Where-Object { $_.InstallAttempted -and -not $_.InstallSuccess }).Count
    
    Write-Host "PowerShell 7 Installation Summary:" -ForegroundColor Green
    Write-Host "Total computers: $TotalComputers"
    Write-Host "Online computers: $OnlineCount"
    Write-Host "Already have PowerShell 7: $PS7ReadyCount"
    Write-Host "Successfully installed PowerShell 7: $PS7InstalledCount"
    Write-Host "Failed to install PowerShell 7: $PS7FailedCount"
    Write-Host "Detailed report saved to: $PS7ReportFile"
    
    # Filter computer list for next phase - only include those with PS7
    $ReadyComputers = @($PS7Results | Where-Object { $_.IsOnline -and ($_.HasPS7 -or $_.InstallSuccess) } | Select-Object -ExpandProperty ComputerName)
    
    if ($ReadyComputers.Count -eq 0) {
        Write-Host "No computers have PowerShell 7 installed. Cannot proceed with Autopilot collection." -ForegroundColor Red
        exit 1
    }
    
    Write-Host "$($ReadyComputers.Count) computers are ready for Autopilot collection with PowerShell 7."
} else {
    # Skip PS7 installation check
    Write-Host "Skipping PowerShell 7 installation check. All online computers will be processed." -ForegroundColor Yellow
    $ReadyComputers = $ComputerList
}

#==============================================================================
# PHASE 2: Execute Autopilot Collection using PowerShell 7
#==============================================================================
Write-Host "`nPHASE 2: Checking prerequisites for Autopilot collection..." -ForegroundColor Cyan

# Initialize prereq report
"ComputerName,IsOnline,HasAutopilotInfo,NeedsInstallation,CanAccessPSGallery,HasWMIAccess" | 
    Out-File -FilePath $PrereqReportFile -Encoding UTF8

# Create synchronized hashtable for tracking progress
$ProgressData = [hashtable]::Synchronized(@{
    CompletedCount = 0
    SuccessCount = 0
    FailedCount = 0
    Started = Get-Date
})

# Prereq check scriptblock for PowerShell 7
$PrereqScriptBlock = {
    param (
        $Computer,
        $Cred,
        $PrereqReportFile,
        $LogFile,
        $FileLock
    )
    
    $PrereqResult = [PSCustomObject]@{
        ComputerName = $Computer
        IsOnline = $false
        HasAutopilotInfo = $false
        NeedsInstallation = $true
        CanAccessPSGallery = $false
        HasWMIAccess = $false
    }
    
    # Check if online
    $PrereqResult.IsOnline = Test-Connection -ComputerName $Computer -Count 1 -Quiet
    
    if ($PrereqResult.IsOnline) {
        try {
            # Get path to PowerShell 7
            $PS7Path = Invoke-Command -ComputerName $Computer -Credential $Cred -ScriptBlock {
                $PS7Paths = @(
                    "C:\Program Files\PowerShell\7\pwsh.exe",
                    "${env:ProgramFiles}\PowerShell\7\pwsh.exe",
                    "${env:ProgramFiles(x86)}\PowerShell\7\pwsh.exe"
                )
                
                return $PS7Paths | Where-Object { Test-Path $_ } | Select-Object -First 1
            }
            
            if (-not $PS7Path) {
                throw "PowerShell 7 not found on $Computer"
            }
            
            # Test WMI access using PowerShell 7
            $WMITest = Invoke-Command -ComputerName $Computer -Credential $Cred -ScriptBlock {
                param($PS7Path)
                
                $result = & $PS7Path -Command {
                    Get-WmiObject -Class Win32_BIOS -ErrorAction Stop | Out-Null
                    return $true
                } -ErrorAction Stop
                
                return $result
            } -ArgumentList $PS7Path
            
            $PrereqResult.HasWMIAccess = $WMITest
            
            # Check if script is already installed using PowerShell 7
            $ScriptStatus = Invoke-Command -ComputerName $Computer -Credential $Cred -ScriptBlock {
                param($PS7Path)
                
                $scriptResult = & $PS7Path -Command {
                    # Enable TLS 1.2 for PSGallery access
                    [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
                    
                    $HasScript = Get-Command Get-WindowsAutopilotInfo -ErrorAction SilentlyContinue
                    $PSGalleryAccess = $false
                    
                    try {
                        # Try to access PSGallery
                        $PSGalleryTest = Find-Module -Name PowerShellGet -Repository PSGallery -ErrorAction Stop
                        $PSGalleryAccess = $true
                    } catch {
                        $PSGalleryAccess = $false
                    }
                    
                    return @{
                        HasScript = ($HasScript -ne $null)
                        PSGalleryAccess = $PSGalleryAccess
                    }
                }
                
                return $scriptResult
            } -ArgumentList $PS7Path
            
            $PrereqResult.HasAutopilotInfo = $ScriptStatus.HasScript
            $PrereqResult.NeedsInstallation = -not $ScriptStatus.HasScript
            $PrereqResult.CanAccessPSGallery = $ScriptStatus.PSGalleryAccess
        }
        catch {
            Add-Content -Path $LogFile -Value "[$(Get-Date)] Prereq check for $Computer failed: $($_.Exception.Message)"
        }
    }
    
    # Export the prereq result
    [System.Threading.Monitor]::Enter($FileLock)
    try {
        "$($PrereqResult.ComputerName),$($PrereqResult.IsOnline),$($PrereqResult.HasAutopilotInfo),$($PrereqResult.NeedsInstallation),$($PrereqResult.CanAccessPSGallery),$($PrereqResult.HasWMIAccess)" | 
            Add-Content -Path $PrereqReportFile
    }
    finally {
        [System.Threading.Monitor]::Exit($FileLock)
    }
    
    return $PrereqResult
}

# Run prereq checks on computers with PowerShell 7
$PrereqResults = @()
$PrereqProgress = 0
$TotalReadyComputers = $ReadyComputers.Count

foreach ($Computer in $ReadyComputers) {
    $PrereqProgress++
    Write-Progress -Activity "Checking prerequisites for Autopilot collection" -Status "$PrereqProgress of $TotalReadyComputers" -PercentComplete (($PrereqProgress / $TotalReadyComputers) * 100)
    $Result = & $PrereqScriptBlock $Computer $Credential $PrereqReportFile $LogFile $Global:FileLock
    $PrereqResults += $Result
}

Write-Progress -Activity "Checking prerequisites for Autopilot collection" -Completed

# Summarize prereq results
$OnlineCount = ($PrereqResults | Where-Object { $_.IsOnline }).Count
$ReadyCount = ($PrereqResults | Where-Object { $_.IsOnline -and ($_.HasAutopilotInfo -or $_.CanAccessPSGallery) -and $_.HasWMIAccess }).Count
$NeedInstallCount = ($PrereqResults | Where-Object { $_.IsOnline -and $_.NeedsInstallation -and $_.CanAccessPSGallery }).Count
$NoGalleryAccessCount = ($PrereqResults | Where-Object { $_.IsOnline -and $_.NeedsInstallation -and -not $_.CanAccessPSGallery }).Count

Write-Host "Prerequisite Check Summary:" -ForegroundColor Green
Write-Host "Total computers with PowerShell 7: $TotalReadyComputers"
Write-Host "Online computers: $OnlineCount"
Write-Host "Ready for collection: $ReadyCount"
Write-Host "Need script installation (with PSGallery access): $NeedInstallCount"
Write-Host "Unable to install script (no PSGallery access): $NoGalleryAccessCount"
Write-Host "Detailed report saved to: $PrereqReportFile"

if ($NoGalleryAccessCount -gt 0) {
    Write-Host "`nWarning: $NoGalleryAccessCount computers need the script but cannot access PowerShell Gallery." -ForegroundColor Yellow
    Write-Host "Options:" -ForegroundColor Yellow
    Write-Host "1. Prepare those computers manually with the script"
    Write-Host "2. Use -OfflinePath parameter to install from local file (requires download)"
    Write-Host "3. Continue anyway (script will fail on those computers)`n"
    
    $Continue = Read-Host "Do you want to continue? (Y/N)"
    if ($Continue -ne "Y" -and $Continue -ne "y") {
        Write-Host "Script execution cancelled by user. See $PrereqReportFile for details." -ForegroundColor Red
        exit 1
    }
}

#==============================================================================
# PHASE 3: Collect hardware hashes with PowerShell 7
#==============================================================================
Write-Host "`nPHASE 3: Collecting Autopilot hardware hashes using PowerShell 7..." -ForegroundColor Cyan

# Filter computer list to only include online computers with PowerShell 7
$ProcessComputers = $PrereqResults | Where-Object { $_.IsOnline } | Select-Object -ExpandProperty ComputerName
$ProcessComputerCount = $ProcessComputers.Count

# Create separate script blocks for computers with and without the script
$WithScriptBlock = {
    param (
        $Computer,
        $Cred,
        $OutputFile,
        $ErrorFile,
        $LogFile,
        $ProgressData,
        $FileLock
    )
    try {
        # Get path to PowerShell 7
        $PS7Path = Invoke-Command -ComputerName $Computer -Credential $Cred -ScriptBlock {
            $PS7Paths = @(
                "C:\Program Files\PowerShell\7\pwsh.exe",
                "${env:ProgramFiles}\PowerShell\7\pwsh.exe",
                "${env:ProgramFiles(x86)}\PowerShell\7\pwsh.exe"
            )
            
            return $PS7Paths | Where-Object { Test-Path $_ } | Select-Object -First 1
        }
        
        if (-not $PS7Path) {
            throw "PowerShell 7 not found on $Computer"
        }
        
        # Run remotely using PowerShell 7
        $Result = Invoke-Command -ComputerName $Computer -Credential $Cred -ScriptBlock {
            param($PS7Path, $RemoteOutputFile)
            
            # Create a temporary directory on the remote system
            $TempDir = "C:\Windows\Temp\AutopilotTemp"
            if (!(Test-Path $TempDir)) {
                New-Item -ItemType Directory -Path $TempDir -Force | Out-Null
            }
            
            $TempFile = "$TempDir\AutopilotHWID.csv"
            
            $autopilotResult = & $PS7Path -Command {
                param($TempFile)
                
                # Execute the Autopilot script
                Get-WindowsAutopilotInfo -OutputFile $TempFile
                
                # Check if file was created successfully
                if (Test-Path $TempFile) {
                    $Data = Import-Csv $TempFile
                    return $Data
                } else {
                    throw "Failed to create Autopilot data file"
                }
            } -Args $TempFile
            
            # Clean up temp file
            if (Test-Path $TempFile) {
                Remove-Item -Path $TempFile -Force
            }
            
            return $autopilotResult
        } -ArgumentList $PS7Path, $OutputFile
        
        if ($Result) {
            # Use a lock to prevent race conditions when writing to CSV
            [System.Threading.Monitor]::Enter($FileLock)
            try {
                foreach ($Entry in $Result) {
                    "$($Entry.'Device Serial Number'),$($Entry.'Windows Product ID'),$($Entry.'Hardware Hash')" | 
                        Add-Content -Path $OutputFile
                }
            }
            finally {
                [System.Threading.Monitor]::Exit($FileLock)
            }
            
            $Message = "[$(Get-Date)] $Computer successfully processed using PowerShell 7."
            
            [System.Threading.Monitor]::Enter($FileLock)
            try {
                Add-Content -Path $LogFile -Value $Message
            }
            finally {
                [System.Threading.Monitor]::Exit($FileLock)
            }
            
            $ProgressData.SuccessCount++
        } else {
            $Message = "[$(Get-Date)] $Computer returned no data."
            
            [System.Threading.Monitor]::Enter($FileLock)
            try {
                Add-Content -Path $ErrorFile -Value $Message
                Add-Content -Path $LogFile -Value $Message
            }
            finally {
                [System.Threading.Monitor]::Exit($FileLock)
            }
            
            $ProgressData.FailedCount++
        }
    }
    catch {
        $Message = "[$(Get-Date)] $Computer failed: $($_.Exception.Message)"
        
        [System.Threading.Monitor]::Enter($FileLock)
        try {
            Add-Content -Path $ErrorFile -Value $Message
            Add-Content -Path $LogFile -Value $Message
        }
        finally {
            [System.Threading.Monitor]::Exit($FileLock)
        }
        
        $ProgressData.FailedCount++
    }
    finally {
        # Update progress counter
        $ProgressData.CompletedCount++
    }
}

$InstallScriptBlock = {
    param (
        $Computer,
        $Cred,
        $OutputFile,
        $ErrorFile,
        $LogFile,
        $ProgressData,
        $FileLock,
        $OfflinePath
    )
    try {
        # Get path to PowerShell 7
        $PS7Path = Invoke-Command -ComputerName $Computer -Credential $Cred -ScriptBlock {
            $PS7Paths = @(
                "C:\Program Files\PowerShell\7\pwsh.exe",
                "${env:ProgramFiles}\PowerShell\7\pwsh.exe",
                "${env:ProgramFiles(x86)}\PowerShell\7\pwsh.exe"
            )
            
            return $PS7Paths | Where-Object { Test-Path $_ } | Select-Object -First 1
        }
        
        if (-not $PS7Path) {
            throw "PowerShell 7 not found on $Computer"
        }
        
        # Create a temporary directory on the remote system
        $TempDir = Invoke-Command -ComputerName $Computer -Credential $Cred -ScriptBlock {
            $TempPath = "C:\Windows\Temp\AutopilotTemp"
            if (!(Test-Path $TempPath)) {
                New-Item -ItemType Directory -Path $TempPath -Force | Out-Null
            }
            return $TempPath
        }
        
        # If offline path is provided, copy the script to the remote machine
        if ($OfflinePath) {
            $DestPath = "$TempDir\Get-WindowsAutopilotInfo.ps1"
            
            # Copy the script to the remote machine
            try {
                Copy-Item -Path $OfflinePath -Destination "\\$Computer\C$\Windows\Temp\AutopilotTemp\Get-WindowsAutopilotInfo.ps1" -Force
                $UseOfflinePath = $true
            }
            catch {
                $Message = "[$(Get-Date)] Failed to copy offline script to $Computer: $($_.Exception.Message)"
                
                [System.Threading.Monitor]::Enter($FileLock)
                try {
                    Add-Content -Path $ErrorFile -Value $Message
                    Add-Content -Path $LogFile -Value $Message
                }
                finally {
                    [System.Threading.Monitor]::Exit($FileLock)
                }
                
                $UseOfflinePath = $false
            }
        } else {
            $UseOfflinePath = $false
        }
        
        # Run remotely using PowerShell 7
        $Result = Invoke-Command -ComputerName $Computer -Credential $Cred -ScriptBlock {
            param($PS7Path, $UseOffline, $OfflineScriptPath)
            
            $TempDir = "C:\Windows\Temp\AutopilotTemp"
            $TempFile = "$TempDir\AutopilotHWID.csv"
            
            $autopilotResult = & $PS7Path -Command {
                param($TempFile, $UseOffline, $OfflineScriptPath)
                
                # Enable TLS 1.2 for PSGallery access
                [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
                
                # Install or use the script
                if (-not (Get-Command Get-WindowsAutopilotInfo -ErrorAction SilentlyContinue)) {
                    if ($UseOffline -and (Test-Path $OfflineScriptPath)) {
                        # Use the offline script
                        . $OfflineScriptPath
                    } else {
                        # Install from PSGallery
                        Install-Script -Name Get-WindowsAutopilotInfo -Force -ErrorAction Stop
                    }
                }
                
                # Now run the script
                Get-WindowsAutopilotInfo -OutputFile $TempFile
                
                # Check if file was created successfully
                if (Test-Path $TempFile) {
                    $Data = Import-Csv $TempFile
                    return $Data
                } else {
                    throw "Failed to create Autopilot data file"
                }
            } -Args $TempFile, $UseOffline, $OfflineScriptPath
            
            # Clean up temp file
            if (Test-Path $TempFile) {
                Remove-Item -Path $TempFile -Force
            }
            
            return $autopilotResult
        } -ArgumentList $PS7Path, $UseOfflinePath, "C:\Windows\Temp\AutopilotTemp\Get-WindowsAutopilotInfo.ps1"
        
        if ($Result) {
            # Use a lock to prevent race conditions when writing to CSV
            [System.Threading.Monitor]::Enter($FileLock)
            try {
                foreach ($Entry in $Result) {
                    "$($Entry.'Device Serial Number'),$($Entry.'Windows Product ID'),$($Entry.'Hardware Hash')" | 
                        Add-Content -Path $OutputFile
                }
            }
            finally {
                [System.Threading.Monitor]::Exit($FileLock)
            }
            
            $InstallType = if ($UseOfflinePath) { "offline script" } else { "PSGallery" }
            $Message = "[$(Get-Date)] $Computer successfully processed with installation using $InstallType."
            
            [System.Threading.Monitor]::Enter($FileLock)
            try {
                Add-Content -Path $LogFile -Value $Message
            }
            finally {
                [System.Threading.Monitor]::Exit($FileLock)
            }
            
            $ProgressData.SuccessCount++
        } else {
            $Message = "[$(Get-Date)] $Computer returned no data."
            
            [System.Threading.Monitor]::Enter($FileLock)
            try {
                Add-Content -Path $ErrorFile -Value $Message
                Add-Content -Path $LogFile -Value $Message
            }
            finally {
                [System.Threading.Monitor]::Exit($FileLock)
            }
            
            $ProgressData.FailedCount++
        }
    }
    catch {
        $Message = "[$(Get-Date)] $Computer failed during script install or execution: $($_.Exception.Message)"
        
        [System.Threading.Monitor]::Enter($FileLock)
        try {
            Add-Content -Path $ErrorFile -Value $Message
            Add-Content -Path $LogFile -Value $Message
        }
        finally {
            [System.Threading.Monitor]::Exit($FileLock)
        }
        
        $ProgressData.FailedCount++
    }
    finally {
        # Update progress counter
        $ProgressData.CompletedCount++
    }
}

# Reset progress data for collection phase
$ProgressData.CompletedCount = 0
$ProgressData.SuccessCount = 0
$ProgressData.FailedCount = 0
$ProgressData.Started = Get-Date

# Start progress timer
$ProgressTimer = New-Object System.Diagnostics.Stopwatch
$ProgressTimer.Start()

# Create a runspace for displaying progress while main thread handles processing
$ProgressRunspace = [runspacefactory]::CreateRunspace()
$ProgressRunspace.Open()
$ProgressRunspace.SessionStateProxy.SetVariable('ProgressData', $ProgressData)
$ProgressRunspace.SessionStateProxy.SetVariable('ProcessComputerCount', $ProcessComputerCount)
$ProgressRunspace.SessionStateProxy.SetVariable('ProgressTimer', $ProgressTimer)

$ProgressPowerShell = [powershell]::Create().AddScript({
    while ($ProgressData.CompletedCount -lt $ProcessComputerCount) {
        $PercentComplete = [math]::Round(($ProgressData.CompletedCount / $ProcessComputerCount) * 100, 1)
        $ElapsedTime = $ProgressTimer.Elapsed
        $EstimatedRemaining = "Unknown"
        
        if ($ProgressData.CompletedCount -gt 0) {
            $AvgTimePerComputer = $ElapsedTime.TotalSeconds / $ProgressData.CompletedCount
            $RemainingSeconds = $AvgTimePerComputer * ($ProcessComputerCount - $ProgressData.CompletedCount)
            $EstimatedRemaining = [timespan]::FromSeconds($RemainingSeconds).ToString("hh\:mm\:ss")
        }
        
        Write-Progress -Activity "Collecting Autopilot Hardware Hashes using PowerShell 7" `
            -Status "$($ProgressData.CompletedCount) of $ProcessComputerCount computers processed ($PercentComplete%). Success: $($ProgressData.SuccessCount) Failed: $($ProgressData.FailedCount)" `
            -PercentComplete $PercentComplete `
            -CurrentOperation "Elapsed: $($ElapsedTime.ToString("hh\:mm\:ss")) - Estimated Remaining: $EstimatedRemaining"
        
        Start-Sleep -Seconds 1
    }
    
    # Complete the progress bar
    Write-Progress -Activity "Collecting Autopilot Hardware Hashes using PowerShell 7" -Completed
})

# Start the progress display runspace
$ProgressPowerShell.Runspace = $ProgressRunspace
$ProgressHandle = $ProgressPowerShell.BeginInvoke()

# Group computers by whether they need script installation
$ComputersWithScript = @($PrereqResults | Where-Object { $_.IsOnline -and $_.HasAutopilotInfo } | Select-Object -ExpandProperty ComputerName)
$ComputersNeedInstall = @($PrereqResults | Where-Object { $_.IsOnline -and -not $_.HasAutopilotInfo -and $_.CanAccessPSGallery } | Select-Object -ExpandProperty ComputerName)

# Process computers that already have the script first (faster)
if ($ComputersWithScript.Count -gt 0) {
    $ComputersWithScript | ForEach-Object -Parallel {
        & $using:WithScriptBlock $_ $using:Credential $using:OutputFile $using:ErrorFile $using:LogFile $using:ProgressData $using:Global:FileLock
    } -ThrottleLimit $ThrottleLimit
}

# Then process computers that need script installation
if ($ComputersNeedInstall.Count -gt 0) {
    $ComputersNeedInstall | ForEach-Object -Parallel {
        & $using:InstallScriptBlock $_ $using:Credential $using:OutputFile $using:ErrorFile $using:LogFile $using:ProgressData $using:Global:FileLock $using:OfflinePath
    } -ThrottleLimit ($ThrottleLimit / 2)  # Lower throttle limit for computers that need installation
}

# Clean up progress display runspace
$ProgressPowerShell.EndInvoke($ProgressHandle)
$ProgressPowerShell.Dispose()
$ProgressRunspace.Close()
$ProgressRunspace.Dispose()

# Display final summary
$ElapsedTime = $ProgressTimer.Elapsed
Write-Host "`nAutopilot hardware hash collection using PowerShell 7 complete!" -ForegroundColor Green
Write-Host "Duration: $($ElapsedTime.ToString("hh\:mm\:ss"))"
Write-Host "Total Computers Processed: $ProcessComputerCount"
Write-Host "Successful: $($ProgressData.SuccessCount)"
Write-Host "Failed: $($ProgressData.FailedCount)"
Write-Host "Results saved to $OutputFile"
Write-Host "Log file: $LogFile"
Write-Host "Error log: $ErrorFile"
Write-Host "PowerShell 7 installation report: $PS7ReportFile"
Write-Host "Prerequisite report: $PrereqReportFile"

# Add summary to log file
"[$(Get-Date)] Collection complete. Duration: $($ElapsedTime.ToString("hh\:mm\:ss")), Success: $($ProgressData.SuccessCount), Failed: $($ProgressData.FailedCount)" | Add-Content -Path $LogFile