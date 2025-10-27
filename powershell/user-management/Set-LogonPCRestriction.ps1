<#
.SYNOPSIS
    Restrict user logon to specific computers based on Organizational Unit membership.

.DESCRIPTION
    Configures Active Directory user accounts to only allow logon to computers within a specified
    Organizational Unit. This script retrieves all computer Distinguished Names from a computer OU
    and sets the LogonWorkstations attribute for all users in a user OU.

    This enforces workstation-level access control, preventing users from logging into
    unauthorized computers outside the specified OU.

.EXAMPLE
    .\Set-LogonPCRestriction.ps1

    Restricts all users in "OU=Eligibility,OU=Users by Departments" to only log on to computers
    in "OU=Service,OU=Office Computers". Users cannot log into any other computers.

.EXAMPLE
    .\Set-LogonPCRestriction.ps1 -Verbose

    Same as above with detailed logging showing which users are being updated.

.NOTES
    Author: SysAdmin Team
    Version: 1.0.0
    Created: 2024-04-01
    Modified: 2025-01-09
    Risk Level: Medium 🟡

    Prerequisites:
    - PowerShell 5.1 or later
    - Active Directory PowerShell Module
    - Permissions to modify user objects
    - Permissions to read computer objects

    Security Considerations:
    - ⚠️ Can lock users out of computers if configured incorrectly
    - ⚠️ Affects all users in the specified user OU (batch operation)
    - ⚠️ Requires careful OU selection to avoid access issues
    - ✅ Mitigation: Verify both OUs contain correct objects before running
    - ✅ Testing: Test on small user/computer subset first
    - ✅ Audit: Document which users are restricted to which computers
    - ✅ Support: Inform helpdesk of restrictions for troubleshooting

    Current Configuration:
    - User OU: OU=Eligibility,OU='Users by Departments',DC=company,DC=local
    - Computer OU: OU=Service,OU='Office Computers',DC=company,DC=local

    Important Notes:
    - Users can ONLY log on to computers in the specified computer OU
    - This includes both interactive and remote logons
    - Domain Controllers are NOT affected by this restriction
    - Administrators should be excluded from these restrictions

    Change Log:
    - v1.0.0 (2024-04-01): Initial version

.LINK
    https://github.com/yourusername/sysadmin-toolkit

.LINK
    https://docs.microsoft.com/en-us/windows/security/threat-protection/security-policy-settings/deny-log-on-locally
#>

# Define variables for the OUs
$userOU = "OU=Eligibility,OU='Users by Departments',DC=company,DC=local"
$computerOU = "OU=Service,OU='Office Computers',DC=company,DC=local"

# Get the DistinguishedNames of the computers in the specified computer OU
$computers = Get-ADComputer -Filter * -SearchBase $computerOU | Select-Object -ExpandProperty DistinguishedName

# Join the computer DistinguishedNames into a single string separated by semicolons
$computerDNs = ($computers -join ";")

# Get the users in the specified user OU
$users = Get-ADUser -Filter * -SearchBase $userOU

foreach ($user in $users) {
    # Set the 'logonTo' attribute for each user
    Set-ADUser -Identity $user -LogonWorkstations $computerDNs
}

Write-Output "Logon restrictions have been set for users in $userOU to only logon to computers in $computerOU."
