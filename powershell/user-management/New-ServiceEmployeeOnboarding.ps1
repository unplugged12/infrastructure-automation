<#
.SYNOPSIS
    Simplified service employee onboarding script for Active Directory and Azure AD.

.DESCRIPTION
    Streamlined employee onboarding automation for service department users. Creates Active Directory
    user accounts, adds them to predefined AD and Azure AD groups, and assigns Microsoft 365 licenses.

    This script is a simplified version of the comprehensive onboarding script, designed specifically
    for service department employees with standardized group memberships and licensing.

    ⚠️ WARNING: This script performs sensitive operations including:
    - Creating Active Directory user accounts with default passwords
    - Adding users to multiple security and distribution groups
    - Assigning Microsoft 365 Business Premium licenses
    - Potential for privilege escalation if groups are misconfigured

.EXAMPLE
    .\New-ServiceEmployeeOnboarding.ps1

    Prompts for first name and last name, then creates a new service employee with standard
    group memberships and M365 license. Username format: FirstNameLastInitial

.EXAMPLE
    .\New-ServiceEmployeeOnboarding.ps1 -Verbose

    Same as above with detailed logging of each operation.

.NOTES
    Author: SysAdmin Team
    Version: 1.0.0
    Created: 2024-02-01
    Modified: 2025-01-09
    Risk Level: High 🔴

    Prerequisites:
    - PowerShell 5.1 or later
    - Active Directory PowerShell Module
    - AzureAD PowerShell Module
    - Permissions to create AD users
    - Azure AD administrator credentials
    - Available M365 Business Premium licenses

    Security Considerations:
    - ⚠️ Creates accounts with default password "<REPLACE_WITH_SECURE_PASSWORD>"
    - ⚠️ Assigns M365 licenses (cost implications)
    - ⚠️ Adds users to groups including VPN Users and RemoteUsers
    - ⚠️ Requires Azure AD admin credentials
    - ✅ Mitigation: Password must be changed at first logon
    - ✅ Testing: Test in lab environment first
    - ✅ Audit: Log all onboarding operations
    - ✅ Approval: Verify user authorization before running

    Default Configuration:
    - Password: <REPLACE_WITH_SECURE_PASSWORD> (must change at first logon)
    - Domain: company.com / company.local
    - OU: OU=Employees,DC=company,DC=local
    - AD Groups: APU, Credit, Employees, RemoteUsers, Service-1, VPN Users
    - Email Groups: Companyeveryone, CompanyService, Company Service External, Company External
    - License: Microsoft 365 Business Premium (SMB_BUSINESS_PREMIUM)

    Change Log:
    - v1.0.0 (2024-02-01): Initial version for service department

.LINK
    https://github.com/yourusername/sysadmin-toolkit
#>

# Import required modules
Import-Module ActiveDirectory
Import-Module AzureAD

# Connect to Azure AD
$AzureADCredentials = Get-Credential
Connect-AzureAD -Credential $AzureADCredentials

# Input options
$FirstName = Read-Host "Enter the user's first name"
$LastName = Read-Host "Enter the user's last name"

# Generate username and email
$LastInitial = $LastName.Substring(0,1)
$Username = "$FirstName$LastInitial"
$EmailAddress = "$($Username)@company.com"

# Set temporary password
$TemporaryPassword = "<REPLACE_WITH_SECURE_PASSWORD>"

# Specify AD domain and OU
$Domain = "company.local"
$OU = "OU=Employees,DC=company,DC=local"

# Create new AD user
New-ADUser -Name $Username `
           -GivenName $FirstName `
           -Surname $LastName `
           -SamAccountName $Username `
           -UserPrincipalName "$Username@$Domain" `
           -EmailAddress $EmailAddress `
           -AccountPassword (ConvertTo-SecureString $TemporaryPassword -AsPlainText -Force) `
           -PasswordNeverExpires $false `
           -ChangePasswordAtLogon $true `
           -Enabled $true `
           -Path $OU

# Add user to AD groups
$ADGroups = @("APU", "Credit", "Employees", "RemoteUsers", "Service-1", "VPN Users")
foreach ($Group in $ADGroups) {
    Add-ADGroupMember -Identity $Group -Members $Username
}

# Get the Azure AD user object
$AzureADUser = Get-AzureADUser -ObjectId "$EmailAddress"

# Add user to Microsoft 365 email groups
$EmailGroups = @("Companyeveryone", "CompanyService", "Company Service External", "Company External")
foreach ($Group in $EmailGroups) {
    $GroupObj = Get-AzureADGroup -SearchString $Group
    Add-AzureADGroupMember -ObjectId $GroupObj.ObjectId -RefObjectId $AzureADUser.ObjectId
}

# Assign Microsoft 365 Business Premium license
# Get the SKU for Microsoft 365 Business Premium
$LicenseSku = Get-AzureADSubscribedSku | Where-Object {$_.SkuPartNumber -eq "SMB_BUSINESS_PREMIUM"}
Set-AzureADUserLicense -ObjectId $AzureADUser.ObjectId -AddLicenses @{"SkuId" = $LicenseSku.SkuId}

Write-Host "User $Username has been successfully onboarded."
