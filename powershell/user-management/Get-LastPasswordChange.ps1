<#
.SYNOPSIS
    Query the last password change date for an Active Directory user account.

.DESCRIPTION
    Simple utility script to retrieve and display the last password update date and time for
    a specified Active Directory user. Prompts for username interactively and displays the
    PasswordLastSet attribute.

    This is a read-only reporting script safe for production use. Requires the Active Directory
    PowerShell module (RSAT).

.EXAMPLE
    .\Get-LastPasswordChange.ps1

    Prompts for a username, then displays when that user's password was last changed.
    Example output: "The last password update for user 'jdoe' was on 01/15/2025 10:30:42 AM"

.EXAMPLE
    .\Get-LastPasswordChange.ps1 | Tee-Object -FilePath "C:\Reports\PasswordAudit.txt"

    Run the script and save the output to a text file for audit purposes.

.NOTES
    Author: SysAdmin Team
    Version: 1.0.0
    Created: 2023-01-01
    Modified: 2025-01-09
    Risk Level: Low ✅

    Prerequisites:
    - Active Directory PowerShell Module (RSAT)
    - Read permissions on user objects in Active Directory
    - Domain connectivity

    Security Considerations:
    - ✅ Read-only operation, no modifications performed
    - ✅ Safe for production use
    - ✅ Requires only basic AD user read permissions

    Change Log:
    - v1.0.0 (2023-01-01): Initial version

.LINK
    https://github.com/yourusername/sysadmin-toolkit
#>

# Check if the Active Directory module is loaded, if not, attempt to load it
if (-not (Get-Module -Name ActiveDirectory)) {
    Import-Module ActiveDirectory -ErrorAction SilentlyContinue
}

# Check if the module was loaded successfully
if (-not (Get-Module -Name ActiveDirectory)) {
    Write-Host "Active Directory module is not loaded. Please install the RSAT feature to proceed."
    exit
}

# Prompt the user for the username to query
$username = Read-Host "Please enter the username to check the last password update date and time"

try {
    # Retrieve the user's password last set date
    $user = Get-ADUser -Identity $username -Properties "PasswordLastSet"

    if ($user -ne $null) {
        Write-Host "The last password update for user '$username' was on $($user.PasswordLastSet)"
    } else {
        Write-Host "User '$username' not found."
    }
} catch {
    Write-Host "An error occurred: $_"
}
