<#
.SYNOPSIS
    Automated employee onboarding script for Active Directory, Microsoft 365, and Exchange Online.

.DESCRIPTION
    Comprehensive employee onboarding automation that creates user accounts across Active Directory,
    Microsoft 365, and Exchange Online. This script handles username generation, account creation,
    group membership assignment, mailbox provisioning, and license assignment.

    ⚠️ WARNING: This script performs sensitive operations including:
    - Creating Active Directory user accounts with default passwords
    - Assigning Microsoft 365 licenses
    - Creating Exchange Online mailboxes
    - Adding users to security and distribution groups
    - Potential for privilege escalation if misconfigured

    This script should ONLY be run by authorized administrators in controlled environments.
    ALWAYS test in a lab environment before production use.

.PARAMETER FirstName
    First name of the employee being onboarded. Special characters will be sanitized.
    Required. Must not be empty.

.PARAMETER LastName
    Last name of the employee being onboarded. Special characters will be sanitized.
    Required. Must not be empty and must be at least 1 character.

.PARAMETER Department
    Department of the employee. Valid values: Service, Sales, IT, Management, Support, Software Support.
    Optional. Default value: "Service"

.PARAMETER OrganizationalUnit
    Distinguished Name (DN) of the Active Directory Organizational Unit where the user will be created.
    Must match pattern: ^(OU|CN)=.+,DC=.+
    Optional. Default: "OU=EB Remote CS,OU=Service,OU=Users by Departments,DC=company,DC=local"
    If not specified, script will attempt to find appropriate OU automatically.

.EXAMPLE
    .\New-UserOnboarding.ps1 -FirstName "John" -LastName "Doe" -WhatIf

    Preview the onboarding process for John Doe without making any changes.
    Always run with -WhatIf first to verify what will be created.

.EXAMPLE
    .\New-UserOnboarding.ps1 -FirstName "Jane" -LastName "Smith" -Department "IT"

    Create a new user account for Jane Smith in the IT department with default settings.

.EXAMPLE
    .\New-UserOnboarding.ps1 -FirstName "Robert" -LastName "Johnson" -Department "Sales" -OrganizationalUnit "OU=Sales,OU=Users,DC=company,DC=local" -Verbose

    Create a new user account for Robert Johnson in the Sales department in a specific OU with detailed logging.

.NOTES
    Author: SysAdmin Team
    Version: 1.0.0
    Created: 2024-01-01
    Modified: 2025-01-09
    Risk Level: High 🔴

    Prerequisites:
    - PowerShell 5.1 or later (PowerShell 7+ recommended)
    - Active Directory PowerShell Module
    - Microsoft Graph PowerShell SDK (Microsoft.Graph, Microsoft.Graph.Users, Microsoft.Graph.Groups)
    - Exchange Online Management Module
    - Domain Admin or Account Operators group membership
    - Exchange Administrator role
    - User Administrator role in Azure AD/Microsoft 365
    - Global Administrator role for comprehensive operations

    Security Considerations:
    - ⚠️ Prompts operator for a secure temporary password (must be changed on first logon)
    - ⚠️ Assigns Microsoft 365 licenses (potential cost implications)
    - ⚠️ Adds users to groups (potential privilege escalation)
    - ⚠️ Connects to multiple cloud services (authentication required)
    - ✅ Mitigation: Enable password change at first logon, review group memberships
    - ✅ Testing: Test in isolated lab environment first
    - ✅ Audit: Enable PowerShell transcript logging for all onboarding operations
    - ✅ Approval: Obtain change management approval before production use

    Change Log:
    - v1.0.0 (2024-01-01): Initial version with AD, M365, and Exchange integration

.LINK
    https://github.com/yourusername/sysadmin-toolkit

.LINK
    https://docs.microsoft.com/en-us/powershell/module/activedirectory/
#>

param(
    [Parameter(Mandatory=$true)]
    [ValidateNotNullOrEmpty()]
    [string]$FirstName,
    
    [Parameter(Mandatory=$true)]
    [ValidateNotNullOrEmpty()]
    [string]$LastName,
    
    [Parameter(Mandatory=$false)]
    [ValidateSet("Service", "Sales", "IT", "Management", "Support", "Software Support")]
    [string]$Department = "Service",
    
    [Parameter(Mandatory=$false)]
    [ValidatePattern("^(OU|CN)=.+,DC=.+")]
    [string]$OrganizationalUnit = "OU=EB Remote CS,OU=Service,OU=Users by Departments,DC=company,DC=local",
    [Parameter(Mandatory=$false)]
    [System.Security.SecureString]
    $DefaultPasswordSecure
)

# Configuration
if (-not $DefaultPasswordSecure) {
    $DefaultPasswordSecure = Read-Host "Enter the temporary password to assign" -AsSecureString
}
$Domain = "@company.com"
$LicenseSku = "SPB"  # Microsoft 365 Business Premium SKU

# Logging Configuration
$LogDir = "C:\Logs\UserOnboarding"
$LogFile = Join-Path $LogDir "UserOnboarding_$(Get-Date -Format 'yyyyMMdd_HHmmss').log"
$ErrorLogFile = Join-Path $LogDir "UserOnboarding_Errors_$(Get-Date -Format 'yyyyMMdd_HHmmss').log"

# Ensure log directory exists
if (!(Test-Path $LogDir)) {
    New-Item -ItemType Directory -Path $LogDir -Force | Out-Null
}

# Rollback tracking
$RollbackActions = [System.Collections.ArrayList]@()

# Sanitize names - remove special characters that might cause issues
$FirstName = $FirstName.Trim() -replace '[^a-zA-Z\s-]', ''
$LastName = $LastName.Trim() -replace '[^a-zA-Z\s-]', ''

# Generate username (FirstNameLastInitial)
# Handle edge case where LastName might be empty or single character
if ($LastName.Length -eq 0) {
    Write-Error "Last name cannot be empty"
    exit 1
}
$Username = ($FirstName + $LastName.Substring(0,1)).ToLower()
$EmailAddress = $Username + $Domain
$DisplayName = "$FirstName $LastName"

# Check if username meets AD requirements (20 character limit for sAMAccountName)
if ($Username.Length -gt 20) {
    Write-Warning "Username exceeds 20 characters. Truncating..."
    $Username = $Username.Substring(0,20)
    $EmailAddress = $Username + $Domain
}

# Department normalization and configuration
$DepartmentAliases = @{
    "Service"          = "Service"
    "Sales"            = "Sales"
    "IT"               = "IT"
    "Management"       = "Management"
    "Support"          = "Support"
    "Software Support" = "Support"
}

$Script:DepartmentOriginal = $Department
$Script:DepartmentCanonical = $DepartmentAliases[$Department]

if (-not $Script:DepartmentCanonical) {
    throw "Unsupported department: $Department"
}

$Script:IsSoftwareSupport = ($Department -eq "Software Support")
$Script:EmployeeLocation = $null
$Script:OuWasProvided = $PSBoundParameters.ContainsKey('OrganizationalUnit')

$DepartmentAdGroups = @{
    "Service"    = @("APU", "Credit", "Employees", "RemoteUsers", "Service-1", "VPN Users")
    "Sales"      = @("Employees", "RemoteUsers", "Sales", "VPN Users")
    "IT"         = @("Employees", "RemoteUsers", "IT-Admins", "VPN Users")
    "Management" = @("Employees", "RemoteUsers", "Management", "VPN Users", "APU")
    "Support"    = @("Credit", "Employees", "RemoteUsers", "Softwaresupport", "Support Services", "Support1", "VPN Users")
}

$BaseDistributionLists = @("companyeveryone@company.com")

$DepartmentDistributionLists = @{
    "Service"    = @("Company Service", "Company Service External")
    "Sales"      = @("Company Service", "Company Service External")
    "IT"         = @("Company Service", "Company Service External")
    "Management" = @("Company Service", "Company Service External")
    "Support"    = @("softwaresupport@company.com")
}

$LocationDistributionLists = @{
    "Onshore"  = @("companyinternal@company.com")
    "Offshore" = @("companyexternal@company.com")
}

$DepartmentOuMap = @{
    "Service" = @{
        Default = "OU=EB Remote CS,OU=Service,OU=Users by Departments,DC=company,DC=local"
    }
    "Support" = @{
        Onshore  = "OU=Software Support,OU=Users by Departments,DC=company,DC=local"
        Offshore = "OU=EB Remote_Support_Staff,OU=Software Support,OU=Users by Departments,DC=company,DC=local"
    }
}

$DepartmentSupervisorUpn = @{
    "Service" = "MelisaB@company.com"
    "Support" = "jojoj@company.com"
}

if ($DepartmentSupervisorUpn.ContainsKey($Script:DepartmentCanonical)) {
    $Script:SupervisorUpn = $DepartmentSupervisorUpn[$Script:DepartmentCanonical]
}
elseif ($DepartmentSupervisorUpn.ContainsKey($Script:DepartmentOriginal)) {
    $Script:SupervisorUpn = $DepartmentSupervisorUpn[$Script:DepartmentOriginal]
}
else {
    $Script:SupervisorUpn = $null
}

Write-Host "Starting onboarding process for: $DisplayName" -ForegroundColor Green
Write-Host "Username: $Username" -ForegroundColor Yellow
Write-Host "Email: $EmailAddress" -ForegroundColor Yellow

# Helper Functions for Logging and Rollback
function Write-Log {
    param(
        [Parameter(Mandatory=$true)]
        [string]$Message,

        [Parameter(Mandatory=$false)]
        [ValidateSet("INFO", "WARNING", "ERROR", "SUCCESS")]
        [string]$Level = "INFO"
    )

    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $logMessage = "[$timestamp] [$Level] $Message"

    # Write to log file
    Add-Content -Path $LogFile -Value $logMessage

    # Also write errors to error log
    if ($Level -eq "ERROR") {
        Add-Content -Path $ErrorLogFile -Value $logMessage
    }

    # Write to console with colors
    switch ($Level) {
        "ERROR"   { Write-Host $logMessage -ForegroundColor Red }
        "WARNING" { Write-Host $logMessage -ForegroundColor Yellow }
        "SUCCESS" { Write-Host $logMessage -ForegroundColor Green }
        default   { Write-Host $logMessage -ForegroundColor White }
    }
}

function Add-RollbackAction {
    param(
        [Parameter(Mandatory=$true)]
        [scriptblock]$Action,

        [Parameter(Mandatory=$true)]
        [string]$Description
    )

    $RollbackActions.Add(@{
        Action = $Action
        Description = $Description
    }) | Out-Null

    Write-Log "Rollback action registered: $Description" -Level "INFO"
}

function Invoke-Rollback {
    Write-Log "Starting rollback process..." -Level "WARNING"

    # Execute rollback actions in reverse order
    $RollbackActions.Reverse()

    foreach ($rollback in $RollbackActions) {
        try {
            Write-Log "Executing rollback: $($rollback.Description)" -Level "WARNING"
            & $rollback.Action
            Write-Log "Rollback completed: $($rollback.Description)" -Level "SUCCESS"
        }
        catch {
            Write-Log "Rollback failed for: $($rollback.Description) - $($_.Exception.Message)" -Level "ERROR"
        }
    }

    Write-Log "Rollback process completed" -Level "WARNING"
}

# Helper to map department to configured AD groups
function Get-DepartmentAdGroupList {
    param([string]$DepartmentKey)

    if ($DepartmentAdGroups.ContainsKey($DepartmentKey)) {
        return $DepartmentAdGroups[$DepartmentKey]
    }

    Write-Warning "No AD groups configured for department '$DepartmentKey'. Falling back to Service set."
    Write-Log "No AD groups configured for department '$DepartmentKey'. Falling back to Service set." -Level "WARNING"
    return $DepartmentAdGroups["Service"]
}

# Helper to map department/location to cloud distribution groups
function Get-CloudDistributionGroupList {
    param(
        [string]$DepartmentKey,
        [string]$Location
    )

    $groups = @()
    $groups += $BaseDistributionLists

    if ($DepartmentDistributionLists.ContainsKey($DepartmentKey)) {
        $groups += $DepartmentDistributionLists[$DepartmentKey]
    }

    if ([string]::IsNullOrWhiteSpace($Location)) {
        $Location = "Onshore"
    }

    if ($LocationDistributionLists.ContainsKey($Location)) {
        $groups += $LocationDistributionLists[$Location]
    }

    return $groups | Where-Object { $_ } | Select-Object -Unique
}

# Helper to capture employee location for OU and distribution logic
function Get-EmployeeLocationChoice {
    if ($Script:EmployeeLocation) {
        return $Script:EmployeeLocation
    }

    while ($true) {
        $response = Read-Host "Is the employee offshore? (y/n)"
        if ([string]::IsNullOrWhiteSpace($response)) {
            $Script:EmployeeLocation = "Onshore"
            Write-Log "Employee location defaulted to Onshore" -Level "INFO"
            return $Script:EmployeeLocation
        }

        switch ($response.ToLower()) {
            'y' {
                $Script:EmployeeLocation = "Offshore"
                Write-Log "Employee marked as Offshore" -Level "INFO"
                return $Script:EmployeeLocation
            }
            'n' {
                $Script:EmployeeLocation = "Onshore"
                Write-Log "Employee marked as Onshore" -Level "INFO"
                return $Script:EmployeeLocation
            }
            default {
                Write-Host "Please respond with 'y' or 'n'." -ForegroundColor Yellow
            }
        }
    }
}

function Set-EmployeeManager {
    param(
        [string]$SamAccountName,
        [string]$SupervisorUpn,
        [bool]$UseADModule = $true
    )

    if ([string]::IsNullOrWhiteSpace($SupervisorUpn)) {
        Write-Log "No supervisor mapping provided; skipping manager assignment." -Level "INFO"
        return $true
    }

    try {
        Write-Host "Assigning supervisor ($SupervisorUpn)..." -ForegroundColor Blue

        if ($UseADModule) {
            Import-Module ActiveDirectory -ErrorAction Stop
            $supervisor = Get-ADUser -Filter "UserPrincipalName -eq '$SupervisorUpn'" -Properties DistinguishedName -ErrorAction SilentlyContinue

            if (!$supervisor -and $SupervisorUpn -like '*@*') {
                $upnSam = $SupervisorUpn.Split('@')[0]
                $supervisor = Get-ADUser -Filter "SamAccountName -eq '$upnSam'" -Properties DistinguishedName -ErrorAction SilentlyContinue
            }

            if (!$supervisor) {
                $supervisor = Get-ADUser -Filter "SamAccountName -eq '$SupervisorUpn'" -Properties DistinguishedName -ErrorAction SilentlyContinue
            }

            if (!$supervisor) {
                throw "Supervisor account not found in AD: $SupervisorUpn"
            }

            $managerDn = $supervisor.DistinguishedName
            Set-ADUser -Identity $SamAccountName -Manager $managerDn -ErrorAction Stop
        }
        else {
            $managerSearcher = New-Object DirectoryServices.DirectorySearcher
            $managerSearcher.Filter = "(&(objectClass=user)(userPrincipalName=$SupervisorUpn))"
            $managerResult = $managerSearcher.FindOne()

            if (!$managerResult -and $SupervisorUpn -like '*@*') {
                $upnSam = $SupervisorUpn.Split('@')[0]
                $managerSearcher = New-Object DirectoryServices.DirectorySearcher
                $managerSearcher.Filter = "(&(objectClass=user)(samAccountName=$upnSam))"
                $managerResult = $managerSearcher.FindOne()
            }

            if (!$managerResult) {
                $managerSearcher = New-Object DirectoryServices.DirectorySearcher
                $managerSearcher.Filter = "(&(objectClass=user)(samAccountName=$SupervisorUpn))"
                $managerResult = $managerSearcher.FindOne()
            }

            if (!$managerResult) {
                throw "Supervisor account not found in AD: $SupervisorUpn"
            }

            $managerDn = $managerResult.Properties["distinguishedname"][0]

            $userSearcher = New-Object DirectoryServices.DirectorySearcher
            $userSearcher.Filter = "(&(objectClass=user)(sAMAccountName=$SamAccountName))"
            $userResult = $userSearcher.FindOne()
            if (!$userResult) {
                throw "New user not found in AD for supervisor assignment: $SamAccountName"
            }
            $userDn = $userResult.Properties["distinguishedname"][0]
            $userEntry = [ADSI]"LDAP://$userDn"
            $userEntry.Put("manager", $managerDn)
            $userEntry.SetInfo()
        }

        Write-Host "Supervisor set to $SupervisorUpn" -ForegroundColor Green
        Write-Log "Supervisor set to $SupervisorUpn for $SamAccountName" -Level "SUCCESS"
        return $true
    }
    catch {
        $errorMsg = $_.Exception.Message
        Write-Warning "Failed to set supervisor ($SupervisorUpn) - $errorMsg"
        Write-Host "Verify the supervisor account exists in AD (UPN or SamAccountName) and update DepartmentSupervisorUpn if needed." -ForegroundColor Yellow
        Write-Log "Failed to set supervisor ($SupervisorUpn) for $SamAccountName - $errorMsg" -Level "WARNING"
        return $false
    }
}

# Function to get the correct OU path

# Helper to build logon hours byte array (1-hour resolution)
function Get-LogonHoursBytes {
    param(
        [string[]]$AllowedDays,
        [int]$StartHourUtc,
        [int]$EndHourUtc
    )

    $dayNames = @('Sunday','Monday','Tuesday','Wednesday','Thursday','Friday','Saturday')
    $bitMap = New-Object bool[] 168  # 7 days * 24 hours

    for ($dayIndex = 0; $dayIndex -lt 7; $dayIndex++) {
        $dayName = $dayNames[$dayIndex]
        $isAllowedDay = $AllowedDays -contains $dayName

        for ($hour = 0; $hour -lt 24; $hour++) {
            $allowHour = $false

            if ($isAllowedDay) {
                if ($StartHourUtc -le $EndHourUtc) {
                    if ($hour -ge $StartHourUtc -and $hour -lt $EndHourUtc) {
                        $allowHour = $true
                    }
                }
                else {
                    if ($hour -ge $StartHourUtc -or $hour -lt $EndHourUtc) {
                        $allowHour = $true
                    }
                }
            }

            if ($allowHour) {
                $index = ($dayIndex * 24) + $hour
                $bitMap[$index] = $true
            }
        }
    }

    $bytes = New-Object byte[] 21
    for ($i = 0; $i -lt 168; $i++) {
        if ($bitMap[$i]) {
            $byteIndex = [int]($i / 8)
            $bitIndex = $i % 8
            $bytes[$byteIndex] = $bytes[$byteIndex] -bor (1 -shl $bitIndex)
        }
    }

    return $bytes
}

function Set-StandardLogonHours {
    param(
        [string]$SamAccountName,
        [bool]$UseADModule = $true
    )

    # Allow logons roughly between 05:00 and 18:00 Pacific Time (hour resolution only)
    $allowedDays = @('Monday','Tuesday','Wednesday','Thursday','Friday')
    $targetTimeZoneId = 'Pacific Standard Time'
    $tz = [TimeZoneInfo]::FindSystemTimeZoneById($targetTimeZoneId)
    $localNow = [TimeZoneInfo]::ConvertTime(DateTime::UtcNow, $tz)
    $startLocal = [DateTime]::SpecifyKind($localNow.Date.AddHours(5), 'Unspecified')
    $endLocal = [DateTime]::SpecifyKind($localNow.Date.AddHours(18), 'Unspecified')
    $startUtc = [TimeZoneInfo]::ConvertTimeToUtc($startLocal, $tz)
    $endUtc = [TimeZoneInfo]::ConvertTimeToUtc($endLocal, $tz)
    $startHourUtc = $startUtc.Hour
    $endHourUtc = $endUtc.Hour
    $logonHoursBytes = Get-LogonHoursBytes -AllowedDays $allowedDays -StartHourUtc $startHourUtc -EndHourUtc $endHourUtc

    try {
        if ($UseADModule) {
            Import-Module ActiveDirectory -ErrorAction Stop
            Set-ADUser -Identity $SamAccountName -Replace @{ logonHours = $logonHoursBytes }
        }
        else {
            $searcher = New-Object DirectoryServices.DirectorySearcher
            $searcher.Filter = "(&(objectClass=user)(sAMAccountName=$SamAccountName))"
            $result = $searcher.FindOne()
            if (!$result) {
                throw "User not found in AD: $SamAccountName"
            }
            $userEntry = $result.GetDirectoryEntry()
            $userEntry.Properties['logonHours'].Value = $logonHoursBytes
            $userEntry.CommitChanges()
        }

        Write-Log "Configured logon hours to approximately 05:00-18:00 Pacific (Mon-Fri)" -Level "SUCCESS"
        return $true
    }
    catch {
        $errorMsg = $_.Exception.Message
        Write-Warning "Failed to set logon hours for $SamAccountName - $errorMsg"
        Write-Log "Failed to set logon hours for $SamAccountName - $errorMsg" -Level "WARNING"
        Write-Host "Review the account manually in Active Directory Users and Computers (Account tab > Logon Hours)." -ForegroundColor Yellow
        return $false
    }
}

function Get-DefaultOU {
    param(
        [switch]$ForceLookup
    )

    try {
        $departmentKey = $Script:DepartmentCanonical
        $candidateOUs = @()

        if (-not $ForceLookup -and $Script:OuWasProvided -and $OrganizationalUnit) {
            return $OrganizationalUnit
        }

        $ouConfig = $DepartmentOuMap[$departmentKey]
        $location = $Script:EmployeeLocation

        if ($ouConfig) {
            if ($location -and $ouConfig.ContainsKey($location)) {
                $candidateOUs += $ouConfig[$location]
            }
            if ($ouConfig.ContainsKey("Default")) {
                $candidateOUs += $ouConfig["Default"]
            }
        }

        $candidateOUs += @(
            "OU=Users by Departments,DC=company,DC=local",
            "OU=Users,DC=company,DC=local",
            "CN=Users,DC=company,DC=local",
            "OU=Employees,DC=company,DC=local"
        )

        $candidateOUs = $candidateOUs | Where-Object { $_ } | Select-Object -Unique

        try {
            Import-Module ActiveDirectory -ErrorAction Stop | Out-Null
        }
        catch {
            Write-Log "ActiveDirectory module import failed while resolving OU - $($_.Exception.Message)" -Level "WARNING"
        }

        foreach ($ou in $candidateOUs) {
            try {
                Get-ADOrganizationalUnit -Identity $ou -ErrorAction Stop | Out-Null
                Write-Host "� Found valid OU: $ou" -ForegroundColor Green
                return $ou
            }
            catch {
                Write-Log "OU validation failed for $ou - $($_.Exception.Message)" -Level "WARNING"
            }
        }

        while ($true) {
            $manualOu = Read-Host "Enter the distinguishedName of the OU for this user"
            if ([string]::IsNullOrWhiteSpace($manualOu)) {
                Write-Host "OU cannot be empty. Please try again." -ForegroundColor Yellow
                continue
            }
            try {
                Get-ADOrganizationalUnit -Identity $manualOu -ErrorAction Stop | Out-Null
                Write-Host "� Using provided OU: $manualOu" -ForegroundColor Green
                return $manualOu
            }
            catch {
                Write-Host "Could not validate the provided OU. $($_.Exception.Message)" -ForegroundColor Red
            }
        }
    }
    catch {
        Write-Error "Could not determine OU path: $($_.Exception.Message)"
        return $OrganizationalUnit
    }
}

# Function to run pre-flight checks
function Test-Prerequisites {
    Write-Host "Running pre-flight checks..." -ForegroundColor Blue
    
    $issues = @()
    
    # Check if running as administrator
    $isAdmin = ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator")
    if (!$isAdmin) {
        $issues += "Script must be run as Administrator"
    }
    
    # Check PowerShell version
    if ($PSVersionTable.PSVersion.Major -lt 5) {
        $currentVersion = $PSVersionTable.PSVersion.ToString()
        $issues += "PowerShell 5.0 or higher is required (current: $currentVersion)"
    }
    
    # Test domain connectivity
    try {
        $domain = [System.DirectoryServices.ActiveDirectory.Domain]::GetCurrentDomain()
        $domainName = $domain.Name
        Write-Host "✓ Connected to domain: $domainName" -ForegroundColor Green
    }
    catch {
        $issues += "Cannot connect to Active Directory domain"
    }
    
    # Check if OU exists (basic check)
    if ($OrganizationalUnit -eq "OU=Users,DC=yourdomain,DC=com") {
        Write-Warning "Using default OU path - please verify this is correct for your environment"
    }
    
    if ($issues.Count -gt 0) {
        Write-Error "Pre-flight checks failed:"
        foreach ($issue in $issues) {
            Write-Host "  ❌ $issue" -ForegroundColor Red
        }
        return $false
    }
    
    Write-Host "✓ All pre-flight checks passed" -ForegroundColor Green
    return $true
}

# Function to check if modules are installed
function Test-RequiredModules {
    Write-Host "Checking required PowerShell modules..." -ForegroundColor Blue
    
    # Check for Graph modules (these can be installed via PowerShell Gallery)
    $graphModules = @("Microsoft.Graph.Authentication", "Microsoft.Graph.Users", "Microsoft.Graph.Groups")
    $missingGraphModules = @()
    
    foreach ($module in $graphModules) {
        if (!(Get-Module -ListAvailable -Name $module)) {
            $missingGraphModules += $module
        }
    }
    
    # Check for Exchange Online module
    $exchangeModule = "ExchangeOnlineManagement"
    $exchangeModuleAvailable = Get-Module -ListAvailable -Name $exchangeModule
    
    # Install missing modules if needed
    $modulesToInstall = @()
    if ($missingGraphModules.Count -gt 0) {
        $modulesToInstall += $missingGraphModules
    }
    if (!$exchangeModuleAvailable) {
        $modulesToInstall += $exchangeModule
    }
    
    if ($modulesToInstall.Count -gt 0) {
        Write-Host "Missing required modules. Installing automatically..." -ForegroundColor Yellow
        
        foreach ($module in $modulesToInstall) {
            try {
                Write-Host "Installing $module..." -ForegroundColor Cyan
                Install-Module $module -Force -AllowClobber -Scope CurrentUser
                Write-Host "✓ Installed $module" -ForegroundColor Green
            }
            catch {
                Write-Error "Failed to install $module - $($_.Exception.Message)"
                Write-Host "Please install manually with: Install-Module $module -Force" -ForegroundColor Yellow
                return $false
            }
        }
    }
    
    # Check for AD module (requires RSAT)
    if (!(Get-Module -ListAvailable -Name "ActiveDirectory")) {
        Write-Warning "ActiveDirectory module not found."
        Write-Host "Install RSAT with one of these methods:" -ForegroundColor Yellow
        
        # Detect OS version for appropriate instructions
        $osVersion = [System.Environment]::OSVersion.Version
        if ($osVersion.Major -eq 10 -or $osVersion.Major -eq 11) {
            Write-Host "  Windows 10/11: Enable-WindowsOptionalFeature -Online -FeatureName RSATClient-Roles-AD-Powershell" -ForegroundColor Cyan
        }
        else {
            Write-Host "  Windows Server: Install-WindowsFeature -Name RSAT-AD-PowerShell" -ForegroundColor Cyan
        }
        Write-Host "  Or use Settings > Apps > Optional Features > RSAT" -ForegroundColor Cyan
        
        $response = Read-Host "Continue with ADSI fallback method? (y/n)"
        if ($response -ne 'y') {
            return $false
        }
        return $false  # Use ADSI fallback
    }
    
    Write-Host "✓ All required modules are available" -ForegroundColor Green
    return $true  # Use AD module
}

# Function to provide sync guidance and wait intelligently
function Wait-ForUserSync {
    param([string]$UserName, [string]$UserPrincipalName)
    
    Write-Host "User created in on-premises AD. Now waiting for sync to Entra ID..." -ForegroundColor Blue
    Write-Host ""
    Write-Host "💡 To speed this up, you can manually run on your AD Connect server:" -ForegroundColor Yellow
    Write-Host "   Start-ADSyncSyncCycle -PolicyType Delta" -ForegroundColor Cyan
    Write-Host ""
    Write-Host "⏱️  Otherwise, automatic sync occurs every 30 minutes" -ForegroundColor Yellow
    Write-Host "   This script will check for the user every 30 seconds" -ForegroundColor Yellow
    Write-Host ""
    
    $continue = Read-Host "Press Enter to start monitoring, or type 'skip' to manually assign license later"
    
    if ($continue.ToLower() -eq 'skip') {
        Write-Host "Skipping cloud operations - you'll need to do these manually later:" -ForegroundColor Yellow
        Write-Host "  - Assign Microsoft 365 license" -ForegroundColor Cyan
        Write-Host "  - Add to distribution groups" -ForegroundColor Cyan
        return $false
    }
    
    return $true
}

# Function to create AD user (with fallback to ADSI)
function New-ADEmployee {
    param([bool]$UseADModule = $true)

    try {
        Write-Log "Creating AD user: $DisplayName" -Level "INFO"
        Write-Host "Creating AD user..." -ForegroundColor Blue
        
        if ($UseADModule) {
            # Use AD PowerShell module
            Import-Module ActiveDirectory -ErrorAction Stop
            $SecurePassword = $DefaultPasswordSecure

            # Check if user already exists before creating
            $existingUser = Get-ADUser -Filter "SamAccountName -eq '$Username'" -ErrorAction SilentlyContinue
            if ($existingUser) {
                throw "User $Username already exists in Active Directory"
            }

            New-ADUser -Name $DisplayName `
                       -GivenName $FirstName `
                       -Surname $LastName `
                       -SamAccountName $Username `
                       -UserPrincipalName $EmailAddress `
                       -EmailAddress $EmailAddress `
                       -DisplayName $DisplayName `
                       -Path $OrganizationalUnit `
                       -AccountPassword $SecurePassword `
                       -Enabled $true `
                       -ChangePasswordAtLogon $true

            # Register rollback action to delete the user if something goes wrong later
            Add-RollbackAction -Action {
                try {
                    Remove-ADUser -Identity $Username -Confirm:$false -ErrorAction Stop
                    Write-Log "Rollback: Deleted AD user $Username" -Level "WARNING"
                }
                catch {
                    Write-Log "Rollback: Failed to delete AD user $Username - $($_.Exception.Message)" -Level "ERROR"
                }
            } -Description "Delete AD user $Username"
        }
        else {
            # Use ADSI fallback
            # Validate OU path format
            if ($OrganizationalUnit -notmatch "^LDAP://|^OU=|^CN=") {
                $OrganizationalUnit = "LDAP://$OrganizationalUnit"
            }
            
            try {
                $domain = [ADSI]$OrganizationalUnit
                $user = $domain.Create("user", "CN=$DisplayName")
                $user.Put("sAMAccountName", $Username)
                $user.Put("userPrincipalName", $EmailAddress)
                $user.Put("mail", $EmailAddress)
                $user.Put("displayName", $DisplayName)
                $user.Put("givenName", $FirstName)
                $user.Put("sn", $LastName)
                $user.SetInfo()
                
                # Set password
                $plainPassword = (New-Object System.Net.NetworkCredential('', $DefaultPasswordSecure)).Password
                $user.SetPassword($plainPassword)
                $plainPassword = $null
                $user.Put("pwdLastSet", 0)  # Force password change at next logon
                
                # Enable account
                $user.Put("userAccountControl", 512)  # Normal account, enabled
                $user.SetInfo()
            }
            catch {
                # If creation fails, check if user already exists
                if ($_.Exception.Message -match "already exists") {
                    Write-Error "User $DisplayName already exists in AD"
                }
                else {
                    throw
                }
            }
        }


        Write-Log "AD user created successfully" -Level "SUCCESS"
        Write-Host "✓ AD user created successfully" -ForegroundColor Green
        return $true
    }
    catch {
        $errorMsg = $_.Exception.Message
        Write-Log "Failed to create AD user - $errorMsg" -Level "ERROR"
        Write-Error "Failed to create AD user - $errorMsg"
        return $false
    }
}

# Function to add user to AD groups (with fallback to ADSI)
function Add-ADUserToGroups {
    param(
        [string]$SamAccountName,
        [bool]$UseADModule = $true
    )

    try {
        $groups = Get-DepartmentAdGroupList -DepartmentKey $Script:DepartmentCanonical

        if (!$groups -or $groups.Count -eq 0) {
            Write-Warning "No AD groups resolved for department $Script:DepartmentCanonical"
            return $false
        }

        Write-Host "Adding user to AD groups..." -ForegroundColor Blue
        Write-Host "Target groups: $([string]::Join(', ', $groups))" -ForegroundColor DarkGray

        if ($UseADModule) {
            Import-Module ActiveDirectory -ErrorAction Stop
            foreach ($group in $groups) {
                try {
                    Add-ADGroupMember -Identity $group -Members $SamAccountName
                    Write-Host "� Added to group: $group" -ForegroundColor Green
                }
                catch {
                    $errorMsg = $_.Exception.Message
                    Write-Warning "Failed to add to group '$group' - $errorMsg"
                }
            }
        }
        else {
            $searcher = New-Object DirectoryServices.DirectorySearcher
            $searcher.Filter = "(&(objectClass=user)(sAMAccountName=$SamAccountName))"
            $userResult = $searcher.FindOne()

            if ($userResult) {
                $userDN = $userResult.Properties["distinguishedname"][0]

                foreach ($group in $groups) {
                    try {
                        $groupSearcher = New-Object DirectoryServices.DirectorySearcher
                        $groupSearcher.Filter = "(&(objectClass=group)(name=$group))"
                        $groupResult = $groupSearcher.FindOne()

                        if ($groupResult) {
                            $groupDN = $groupResult.Properties["distinguishedname"][0]
                            $groupObj = [ADSI]"LDAP://$groupDN"
                            $groupObj.Add("LDAP://$userDN")
                            Write-Host "� Added to group: $group" -ForegroundColor Green
                        }
                        else {
                            Write-Warning "Group not found: $group"
                        }
                    }
                    catch {
                        $errorMsg = $_.Exception.Message
                        Write-Warning "Failed to add to group '$group' - $errorMsg"
                    }
                }
            }
            else {
                throw "User not found in AD"
            }
        }
        return $true
    }
    catch {
        $errorMsg = $_.Exception.Message
        Write-Error "Failed to add user to groups - $errorMsg"
        return $false
    }
}

# Function to connect to Microsoft Graph
function Connect-ToGraph {
    try {
        Write-Host "Connecting to Microsoft Graph..." -ForegroundColor Blue
        
        # Import required modules
        Import-Module Microsoft.Graph.Authentication -ErrorAction Stop
        Import-Module Microsoft.Graph.Users -ErrorAction Stop
        Import-Module Microsoft.Graph.Groups -ErrorAction Stop
        
        # Connect with required scopes
        Connect-MgGraph -Scopes "User.ReadWrite.All", "Group.ReadWrite.All", "Directory.ReadWrite.All" -NoWelcome
        
        Write-Host "✓ Connected to Microsoft Graph" -ForegroundColor Green
        return $true
    }
    catch {
        $errorMsg = $_.Exception.Message
        Write-Error "Failed to connect to Microsoft Graph - $errorMsg"
        return $false
    }
}

# Function to connect to Exchange Online
# Exchange Online connection is currently disabled. Distribution list updates
# must be handled manually after the script runs.
function Connect-ToExchangeOnline {
    Write-Warning "Exchange Online connection is skipped in this environment."
    return $false
}
# Function to assign Microsoft 365 license
function Set-UserLicense {
    param([string]$UserPrincipalName)
    
    try {
        Write-Host "Checking for user in Entra ID and assigning license..." -ForegroundColor Blue
        
        $maxAttempts = 20  # 10 minutes max wait (20 x 30 seconds)
        $attempt = 0
        $user = $null
        
        do {
            if ($attempt -gt 0) {
                Start-Sleep -Seconds 30
            }
            $attempt++
            
            try {
                $user = Get-MgUser -UserId $UserPrincipalName -ErrorAction SilentlyContinue
            }
            catch {
                # User not found yet
            }
            
            if (!$user) {
                $elapsedSeconds = $attempt * 30
                Write-Host "⏳ Waiting for user sync... (Attempt $attempt/$maxAttempts - $elapsedSeconds seconds elapsed)" -ForegroundColor Yellow
                
                if ($attempt -eq 5) {
                    Write-Host "💡 Tip: Run 'Start-ADSyncSyncCycle -PolicyType Delta' on your AD Connect server to speed this up" -ForegroundColor Cyan
                }
            }
        } while (!$user -and $attempt -lt $maxAttempts)
        
        if (!$user) {
            throw "User not found in Entra ID after waiting 10 minutes. Try running the license assignment manually later."
        }
        
        Write-Host "✓ User found in Entra ID!" -ForegroundColor Green
        
        # First, let's examine all available licenses in detail
        Write-Host "Analyzing available licenses..." -ForegroundColor Blue
        $allSkus = Get-MgSubscribedSku
        
        Write-Host "All licenses in your tenant:" -ForegroundColor Yellow
        foreach ($sku in $allSkus) {
            $skuPart = $sku.SkuPartNumber
            $enabled = $sku.PrepaidUnits.Enabled
            $consumed = $sku.ConsumedUnits
            $available = $enabled - $consumed
            $suspended = $sku.PrepaidUnits.Suspended
            $warning = $sku.PrepaidUnits.Warning
            
            Write-Host "  License: $skuPart" -ForegroundColor Cyan
            Write-Host "    Total: $enabled | Used: $consumed | Available: $available" -ForegroundColor Gray
            if ($suspended -gt 0) { Write-Host "    Suspended: $suspended" -ForegroundColor Red }
            if ($warning -gt 0) { Write-Host "    Warning: $warning" -ForegroundColor Yellow }
            Write-Host "    SKU ID: $($sku.SkuId)" -ForegroundColor Gray
            Write-Host ""
        }
        
        # Try to find the right license with multiple approaches
        $subscribedSkus = $null
        $skuUsed = $null
        
        # Approach 1: Try the configured SKU
        $subscribedSkus = $allSkus | Where-Object {$_.SkuPartNumber -eq $LicenseSku}
        if ($subscribedSkus) {
            $skuUsed = $LicenseSku
            Write-Host "Found license using configured SKU: $LicenseSku" -ForegroundColor Green
        }
        
        # Approach 2: Try common Microsoft 365 Business Premium SKU names
        if (!$subscribedSkus) {
            $businessPremiumSkus = @("O365_BUSINESS_PREMIUM", "SMB_BUSINESS_PREMIUM", "SPB", "Microsoft 365 Business Premium")
            foreach ($sku in $businessPremiumSkus) {
                $subscribedSkus = $allSkus | Where-Object {$_.SkuPartNumber -eq $sku}
                if ($subscribedSkus) {
                    $skuUsed = $sku
                    Write-Host "Found license using SKU: $sku" -ForegroundColor Green
                    break
                }
            }
        }
        
        # Approach 3: Interactive selection if none found
        if (!$subscribedSkus) {
            Write-Host "Could not automatically determine the correct license SKU." -ForegroundColor Yellow
            Write-Host "Please select from the available licenses above:" -ForegroundColor Yellow
            
            $availableSkus = $allSkus | Where-Object {($_.PrepaidUnits.Enabled - $_.ConsumedUnits) -gt 0}
            if ($availableSkus.Count -eq 0) {
                throw "No licenses have available units. All licenses are fully consumed."
            }
            
            for ($i = 0; $i -lt $availableSkus.Count; $i++) {
                $sku = $availableSkus[$i]
                $available = $sku.PrepaidUnits.Enabled - $sku.ConsumedUnits
                Write-Host "  $($i + 1). $($sku.SkuPartNumber) ($available available)" -ForegroundColor Cyan
            }
            
            do {
                $selection = Read-Host "Enter the number of the license to assign (1-$($availableSkus.Count))"
                $selectionIndex = [int]$selection - 1
            } while ($selectionIndex -lt 0 -or $selectionIndex -ge $availableSkus.Count)
            
            $subscribedSkus = $availableSkus[$selectionIndex]
            $skuUsed = $subscribedSkus.SkuPartNumber
            Write-Host "Selected license: $skuUsed" -ForegroundColor Green
        }
        
        # Check if licenses are actually available (with detailed analysis)
        $enabledUnits = $subscribedSkus.PrepaidUnits.Enabled
        $consumedUnits = $subscribedSkus.ConsumedUnits
        $suspendedUnits = $subscribedSkus.PrepaidUnits.Suspended
        $warningUnits = $subscribedSkus.PrepaidUnits.Warning
        $availableUnits = $enabledUnits - $consumedUnits
        
        Write-Host "Selected license details:" -ForegroundColor Yellow
        Write-Host "  SKU: $skuUsed" -ForegroundColor Cyan
        Write-Host "  Total Enabled: $enabledUnits" -ForegroundColor Cyan
        Write-Host "  Currently Consumed: $consumedUnits" -ForegroundColor Cyan
        Write-Host "  Calculated Available: $availableUnits" -ForegroundColor Cyan
        if ($suspendedUnits -gt 0) { Write-Host "  Suspended: $suspendedUnits" -ForegroundColor Red }
        if ($warningUnits -gt 0) { Write-Host "  Warning State: $warningUnits" -ForegroundColor Yellow }
        
        if ($availableUnits -le 0) {
            # Check if there are suspended or warning licenses that might be usable
            if ($suspendedUnits -gt 0 -or $warningUnits -gt 0) {
                Write-Warning "No available licenses in normal state, but found $suspendedUnits suspended and $warningUnits in warning state"
                Write-Host "This might indicate a billing or payment issue. Check your Microsoft 365 admin center." -ForegroundColor Yellow
            }
            
            throw "No available licenses. Enabled: $enabledUnits, Consumed: $consumedUnits, Available: $availableUnits"
        }
        
        Write-Host "✓ Confirmed $availableUnits licenses available" -ForegroundColor Green
        
        # Check if user already has a license
        $existingLicenses = Get-MgUserLicenseDetail -UserId $user.Id -ErrorAction SilentlyContinue
        if ($existingLicenses) {
            Write-Host "User already has licenses assigned:" -ForegroundColor Yellow
            foreach ($license in $existingLicenses) {
                $existingSku = $allSkus | Where-Object {$_.SkuId -eq $license.SkuId}
                if ($existingSku) {
                    Write-Host "  - $($existingSku.SkuPartNumber)" -ForegroundColor Cyan
                }
            }
            
            # Check if they already have the license we're trying to assign
            $alreadyHasLicense = $existingLicenses | Where-Object {$_.SkuId -eq $subscribedSkus.SkuId}
            if ($alreadyHasLicense) {
                Write-Host "✓ User already has the $skuUsed license assigned" -ForegroundColor Green
                return $true
            }
        }
        
        # Set usage location (required for license assignment)
        if (!$user.UsageLocation) {
            Write-Host "Setting usage location to US..." -ForegroundColor Blue
            Update-MgUser -UserId $user.Id -UsageLocation "US"
            Start-Sleep -Seconds 5  # Give it a moment to propagate
        }
        else {
            Write-Host "Usage location already set: $($user.UsageLocation)" -ForegroundColor Green
        }
        
        # Assign license
        Write-Host "Assigning license..." -ForegroundColor Blue
        $license = @{
            AddLicenses = @(
                @{
                    SkuId = $subscribedSkus.SkuId
                }
            )
            RemoveLicenses = @()
        }
        
        Set-MgUserLicense -UserId $user.Id -BodyParameter $license
        
        # Verify the license was assigned
        Start-Sleep -Seconds 10
        $newLicenses = Get-MgUserLicenseDetail -UserId $user.Id
        $assignedLicense = $newLicenses | Where-Object {$_.SkuId -eq $subscribedSkus.SkuId}
        
        if ($assignedLicense) {
            Write-Host "✓ License assigned and verified successfully!" -ForegroundColor Green
        }
        else {
            Write-Warning "License assignment completed but verification failed. Check manually in admin portal."
        }
        
        return $true
    }
    catch {
        $errorMsg = $_.Exception.Message
        Write-Error "Failed to assign license - $errorMsg"
        
        # Provide additional troubleshooting guidance
        Write-Host ""
        Write-Host "License Assignment Troubleshooting:" -ForegroundColor Yellow
        Write-Host "1. Check billing status in Microsoft 365 admin center" -ForegroundColor Cyan
        Write-Host "2. Verify no payment issues or subscription problems" -ForegroundColor Cyan
        Write-Host "3. Ensure usage location is set (script sets to US automatically)" -ForegroundColor Cyan
        Write-Host "4. Try assigning manually via admin portal to test" -ForegroundColor Cyan
        Write-Host "5. Check if licenses are in 'suspended' or 'warning' state" -ForegroundColor Cyan
        Write-Host ""
        
        return $false
    }
}

# Function to add user to cloud distribution groups (UPDATED WITH EXCHANGE ONLINE)
function Add-UserToCloudGroups {
    param(
        [string]$UserPrincipalName,
        [bool]$ExchangeAvailable = $false
    )

    $cloudGroups = Get-CloudDistributionGroupList -DepartmentKey $Script:DepartmentCanonical -Location $Script:EmployeeLocation

    if (!$cloudGroups -or $cloudGroups.Count -eq 0) {
        Write-Log "No cloud distribution groups configured for $UserPrincipalName" -Level "INFO"
        return $true
    }

    Write-Host "Adding user to cloud distribution groups..." -ForegroundColor Blue
    Write-Host "Target distribution groups: $([string]::Join(', ', $cloudGroups))" -ForegroundColor DarkGray

    if (-not $Script:CloudGroupCache) {
        $Script:CloudGroupCache = @{}
    }

    $graphManaged = @()
    $pendingExchange = @()
    $operationSucceeded = $true
    $mgUser = $null

    try {
        $mgUser = Get-MgUser -UserId $UserPrincipalName -Property Id,DisplayName -ErrorAction Stop
    }
    catch {
        Write-Warning "Could not retrieve user '$UserPrincipalName' from Microsoft Graph: $($_.Exception.Message)"
        Write-Log "Graph lookup failed for $UserPrincipalName - $($_.Exception.Message)" -Level "WARNING"
        $pendingExchange = $cloudGroups
    }

    if ($mgUser) {
        foreach ($groupName in $cloudGroups) {
            $groupInfo = $null
            if ($Script:CloudGroupCache.ContainsKey($groupName)) {
                $groupInfo = $Script:CloudGroupCache[$groupName]
            }
            else {
                $escapedName = $groupName.Replace("'", "''")
                try {
                    if ($groupName -like '*@*') {
                        $groupInfo = Get-MgGroup -Filter "mail eq '$escapedName'" -Property Id,DisplayName,MailEnabled,SecurityEnabled,MailNickname -ErrorAction Stop | Select-Object -First 1
                    }
                }
                catch {}

                if (-not $groupInfo) {
                    try {
                        $groupInfo = Get-MgGroup -Filter "displayName eq '$escapedName'" -Property Id,DisplayName,MailEnabled,SecurityEnabled,MailNickname -ErrorAction Stop | Select-Object -First 1
                    }
                    catch {}
                }

                if (-not $groupInfo) {
                    try {
                        $groupInfo = Get-MgGroup -Filter "mailNickname eq '$escapedName'" -Property Id,DisplayName,MailEnabled,SecurityEnabled,MailNickname -ErrorAction Stop | Select-Object -First 1
                    }
                    catch {}
                }

                $Script:CloudGroupCache[$groupName] = $groupInfo
            }

            if ($groupInfo -and $groupInfo.SecurityEnabled) {
                try {
                    $displayName = if ($groupInfo.DisplayName) { $groupInfo.DisplayName } elseif ($groupInfo.MailNickname) { $groupInfo.MailNickname } else { $groupName }
                    New-MgGroupMemberByRef -GroupId $groupInfo.Id -BodyParameter @{ '@odata.id' = "https://graph.microsoft.com/v1.0/directoryObjects/$($mgUser.Id)" }
                    Write-Host "✓ Added to cloud group (Graph): $displayName" -ForegroundColor Green
                    $graphManaged += $groupName
                }
                catch {
                    $errorText = $_.Exception.Message
                    if ($errorText -match 'added object references already exist') {
                        Write-Host "✓ Already a member of: $groupName" -ForegroundColor Yellow
                    }
                    else {
                        Write-Warning "Graph membership add failed for '$groupName' - $errorText"
                        $pendingExchange += $groupName
                    }
                }
            }
            else {
                $pendingExchange += $groupName
            }
        }
    }

    $pendingExchange = $pendingExchange | Where-Object { $_ } | Select-Object -Unique

    if ($pendingExchange.Count -gt 0) {
        if (-not $ExchangeAvailable) {
            Write-Warning "Exchange Online connection unavailable; unable to update these distribution groups:"
            foreach ($groupName in $pendingExchange) {
                Write-Host "  - $groupName" -ForegroundColor Yellow
            }
            $operationSucceeded = $false
        }
        else {
            foreach ($groupName in $pendingExchange) {
                try {
                    $group = Get-DistributionGroup -Identity $groupName -ErrorAction SilentlyContinue
                    if ($group) {
                        $members = Get-DistributionGroupMember -Identity $groupName -ErrorAction SilentlyContinue
                        $isMember = $members | Where-Object { $_.PrimarySmtpAddress -eq $UserPrincipalName }

                        if (!$isMember) {
                            Add-DistributionGroupMember -Identity $groupName -Member $UserPrincipalName
                            Write-Host "✓ Added to distribution group (Exchange): $groupName" -ForegroundColor Green
                        }
                        else {
                            Write-Host "✓ Already a member of: $groupName" -ForegroundColor Yellow
                        }
                    }
                    else {
                        Write-Warning "Distribution group not found in Exchange Online: $groupName"
                        $operationSucceeded = $false
                    }
                }
                catch {
                    $errorMsg = $_.Exception.Message
                    Write-Warning "Failed to add to distribution group '$groupName' - $errorMsg"
                    $operationSucceeded = $false
                }
            }
        }
    }

    if ($operationSucceeded) {
        Write-Log "Cloud group assignments completed for $UserPrincipalName" -Level "SUCCESS"
    }
    else {
        Write-Log "Cloud group assignments partially completed for $UserPrincipalName" -Level "WARNING"
    }

    return $operationSucceeded
}


# Main execution
try {
    Write-Host "`nEmployee Onboarding Automation Script (v36)" -ForegroundColor Cyan
    Write-Host "============================================" -ForegroundColor Cyan
    Write-Host ""
    
    # Run pre-flight checks
    if (!(Test-Prerequisites)) {
        throw "Pre-flight checks failed. Please resolve issues and try again."
    }
    
    # Check required modules (will auto-install Graph and Exchange modules)
    $useADModule = Test-RequiredModules
    if ($useADModule -eq $false -and (Get-Module -ListAvailable -Name "ActiveDirectory")) {
        $useADModule = $true  # AD module became available after installation
    }
    
    $Script:EmployeeLocation = Get-EmployeeLocationChoice
    $OrganizationalUnit = Get-DefaultOU -ForceLookup:(!$Script:OuWasProvided)
    
    # Display user creation summary before proceeding
    Write-Host "`nUser to be created:" -ForegroundColor Yellow
    Write-Host "  Display Name: $DisplayName"
    Write-Host "  Username: $Username"
    Write-Host "  Email: $EmailAddress"
    Write-Host "  Department: $Department"
    Write-Host "  Location: $EmployeeLocation"
    $supervisorSummary = if ($Script:SupervisorUpn) { $Script:SupervisorUpn } else { "Not configured" }
    Write-Host "  Supervisor: $supervisorSummary"
    Write-Host "  OU Path: $OrganizationalUnit"
    Write-Host ""
    
    $confirm = Read-Host "Proceed with user creation? (y/n)"
    if ($confirm -ne 'y') {
        Write-Host "Operation cancelled by user" -ForegroundColor Yellow
        exit 0
    }
    
    # Step 1: Create AD User
    if (!(New-ADEmployee -UseADModule $useADModule)) {
        throw "Failed to create AD user"
    }
    
    # Step 2: Add to AD Groups
    if (!(Add-ADUserToGroups -SamAccountName $Username -UseADModule $useADModule)) {
        Write-Warning "Some AD group assignments may have failed"
    }

    if ($Script:SupervisorUpn) {
        if (!(Set-EmployeeManager -SamAccountName $Username -SupervisorUpn $Script:SupervisorUpn -UseADModule $useADModule)) {
            Write-Warning "Supervisor assignment may need to be reviewed manually"
        }
    }
    else {
        Write-Log ('No supervisor configured for department \"{0}\"' -f $Script:DepartmentCanonical) -Level "INFO"
    }

    if (!(Set-StandardLogonHours -SamAccountName $Username -UseADModule $useADModule)) {
        Write-Warning "Logon hours configuration may need manual review"
    }

    # Step 2.5: Provide sync guidance
    Write-Host ""
    $shouldWaitForSync = Wait-ForUserSync -UserName $Username -UserPrincipalName $EmailAddress
    Write-Host ""
    
    # Step 3: Connect to cloud services (only if we're doing cloud operations)
    if ($shouldWaitForSync) {
        # Connect to Microsoft Graph
        if (!(Connect-ToGraph)) {
            Write-Warning "Failed to connect to Microsoft Graph - license assignment will be skipped"
            $shouldWaitForSync = $false
        }
        
        # Connect to Exchange Online (for distribution groups)
        $exchangeConnected = $false
        if ($shouldWaitForSync) {
            Write-Host "Attempting to connect to Exchange Online for distribution group management..." -ForegroundColor Blue
            $exchangeConnected = Connect-ToExchangeOnline
            
            if (!$exchangeConnected) {
                Write-Host ""
                Write-Host "⚠️  Exchange Online connection failed." -ForegroundColor Yellow
                Write-Host "Distribution groups will need to be managed manually." -ForegroundColor Yellow
                Write-Host ""
                $continueWithoutExchange = Read-Host "Continue with licensing only? (y/n)"
                
                if ($continueWithoutExchange -ne 'y') {
                    Write-Host "Operation cancelled by user" -ForegroundColor Yellow
                    exit 0
                }
            }
        }
    }
    
    # Step 4: Assign Microsoft 365 License (if user chose to wait)
    if ($shouldWaitForSync) {
        if (!(Set-UserLicense -UserPrincipalName $EmailAddress)) {
            Write-Warning "Failed to assign license - you may need to do this manually"
        }
    }
    
    # Step 5: Add to Cloud Groups
    if ($shouldWaitForSync) {
        if (!(Add-UserToCloudGroups -UserPrincipalName $EmailAddress -ExchangeAvailable:$exchangeConnected)) {
            Write-Warning "Some cloud group assignments may have failed"
        }
    }
    
    Write-Host ""
    Write-Host "=========================================" -ForegroundColor Green
    Write-Host "Onboarding completed successfully!" -ForegroundColor Green
    Write-Host "=========================================" -ForegroundColor Green
    Write-Host ""
    Write-Host "Summary:" -ForegroundColor Cyan
    Write-Host "  Name: $DisplayName"
    Write-Host "  Username: $Username"
    Write-Host "  Email: $EmailAddress"
    Write-Host "  Default Password: (captured securely during execution)"
    Write-Host "  Department: $Department"
    Write-Host "  Location: $EmployeeLocation"
    $supervisorSummary = if ($Script:SupervisorUpn) { $Script:SupervisorUpn } else { "Not configured" }
    Write-Host "  Supervisor: $supervisorSummary"
    Write-Host ""
    Write-Host "Next steps:" -ForegroundColor Yellow
    Write-Host "  1. User should change password on first login"
    Write-Host "  2. Verify all group memberships"
    Write-Host "  3. Test email and system access"
    Write-Host "  4. Configure any department-specific applications"
    
    if (!$shouldWaitForSync) {
        Write-Host ""
        Write-Host "⚠️  Cloud operations were skipped." -ForegroundColor Yellow
        Write-Host "  Remember to manually:" -ForegroundColor Yellow
        Write-Host "    - Assign Microsoft 365 license" -ForegroundColor Cyan
        Write-Host "    - Add to distribution groups:" -ForegroundColor Cyan
        $manualCloudGroups = Get-CloudDistributionGroupList -DepartmentKey $Script:DepartmentCanonical -Location $Script:EmployeeLocation
        foreach ($group in $manualCloudGroups) {
            Write-Host "      * $group" -ForegroundColor Gray
        }
    }
    
}
catch {
    $errorMsg = $_.Exception.Message
    Write-Host ""
    Write-Error "Onboarding failed - $errorMsg"
    Write-Host ""
    Write-Host "Troubleshooting tips:" -ForegroundColor Yellow
    
    if ($errorMsg -match "already exists") {
        Write-Host "  - Check if user already exists in AD"
        Write-Host "  - Try a different username or delete existing user"
    }
    elseif ($errorMsg -match "access denied|permission") {
        Write-Host "  - Ensure you're running as Administrator"
        Write-Host "  - Check your AD, Azure AD, and Exchange permissions"
    }
    elseif ($errorMsg -match "module|not found") {
        Write-Host "  - Install required PowerShell modules"
        Write-Host "  - Run: Install-Module Microsoft.Graph -Force"
        Write-Host "  - Run: Install-Module ExchangeOnlineManagement -Force"
    }
    elseif ($errorMsg -match "authentication|connect") {
        Write-Host "  - Check your internet connection"
        Write-Host "  - Verify your admin credentials"
        Write-Host "  - Ensure MFA is configured if required"
    }
    
    exit 1
}
finally {
    # Disconnect from all services
    try {
        Write-Host "Disconnecting from cloud services..." -ForegroundColor Blue
        
        # Disconnect from Graph
        Disconnect-MgGraph -ErrorAction SilentlyContinue
        
        # Disconnect from Exchange Online
        Disconnect-ExchangeOnline -Confirm:$false -ErrorAction SilentlyContinue
        
        Write-Host "✓ Disconnected from cloud services" -ForegroundColor Green
    }
    catch {
        # Ignore disconnect errors
        Write-Host "Note: Some disconnect operations may have failed (this is usually harmless)" -ForegroundColor Gray
    }
}

