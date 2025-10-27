<#
.SYNOPSIS
    Configure Active Directory user logon hours to restrict access based on time and day.

.DESCRIPTION
    Sets logon hour restrictions for all users in a specified Organizational Unit. This script
    creates a 21-byte array representing a weekly schedule (168 hours = 7 days × 24 hours) and
    sets allowed logon hours from 5:00 AM to 6:00 PM, Monday through Saturday in Pacific Time.

    The script handles timezone conversion from Pacific Time to UTC for proper enforcement
    across different geographic locations. Logon hours are stored in UTC in Active Directory.

    ⚠️ WARNING: This script modifies user account logon hours which can prevent users from
    logging in outside allowed times. Test on a small OU first.

.EXAMPLE
    .\Set-LogonHours.ps1

    Sets logon hours for all users in OU=TestOU,DC=company,DC=local to allow access
    Monday-Saturday, 5 AM to 6 PM Pacific Time.

.EXAMPLE
    .\Set-LogonHours.ps1 -Verbose

    Same as above but with detailed logging showing byte array values and each user update.

.NOTES
    Author: SysAdmin Team
    Version: 1.0.0
    Created: 2024-05-01
    Modified: 2025-01-09
    Risk Level: Medium 🟡

    Prerequisites:
    - PowerShell 5.1 or later
    - Active Directory PowerShell Module
    - Permissions to modify user objects in target OU
    - Understanding of logon hours and timezone implications

    Security Considerations:
    - ⚠️ Can lock users out if hours are set incorrectly
    - ⚠️ Affects all users in the specified OU (batch operation)
    - ⚠️ Timezone conversion critical for proper enforcement
    - ✅ Mitigation: Test on small OU first, verify timezone settings
    - ✅ Testing: Run on non-production OU first
    - ✅ Audit: Enable logging to track changes
    - ✅ Documentation: Document allowed hours clearly for helpdesk

    Current Configuration:
    - Allowed Hours: 5:00 AM - 6:00 PM Pacific Time
    - Allowed Days: Monday through Saturday
    - Denied: Sunday all day, nights/early mornings
    - Timezone: Pacific Time (UTC-8)
    - Target OU: OU=TestOU,DC=company,DC=local

    Customization:
    Modify the following variables to change behavior:
    - $timeZoneOffset: Change timezone (-8 for PST, -5 for EST, etc.)
    - Conditional logic (lines 34-36): Change allowed hours and days
    - $distinguishedName: Change target OU

    Change Log:
    - v1.0.0 (2024-05-01): Initial version with PST support

.LINK
    https://github.com/yourusername/sysadmin-toolkit

.LINK
    https://docs.microsoft.com/en-us/windows/win32/adschema/a-logonhours
#>

# Initialize a 21-byte array with all bits set to 0 (logon denied)
$logonHours = New-Object byte[] 21

# Timezone offset (for PST, UTC-8)
$timeZoneOffset = -8

# Set logon hours from 5:00 AM to 6:00 PM (Monday to Saturday) in Pacific Time
for ($day = 0; $day -lt 7; $day++) {
    for ($hour = 0; $hour -lt 24; $hour++) {
        # Convert hour to UTC
        $utcHour = $hour - $timeZoneOffset
        if ($utcHour -lt 0) {
            $utcHour += 24
            $adjustedDay = $day - 1
        } elseif ($utcHour -ge 24) {
            $utcHour -= 24
            $adjustedDay = $day + 1
        } else {
            $adjustedDay = $day
        }

        # Ensure the day is within the valid range (0-6)
        if ($adjustedDay -lt 0) {
            $adjustedDay += 7
        } elseif ($adjustedDay -gt 6) {
            $adjustedDay -= 7
        }

        $index = ($adjustedDay * 24) + $utcHour
        $byteIndex = [Math]::Floor($index / 8)
        $bitOffset = $index % 8

        # Set bit for allowed logon hours (5 AM to 6 PM, Monday to Saturday in PT)
        if (($day -ge 1 -and $day -lt 6 -and $hour -ge 5 -and $hour -lt 18) -or
            ($day -eq 6 -and $hour -ge 5 -and $hour -lt 18)) {
            $logonHours[$byteIndex] = $logonHours[$byteIndex] -bor (1 -shl $bitOffset)
        }
    }
}

# Log the logon hours for verification
for ($i = 0; $i -lt $logonHours.Length; $i++) {
    Write-Host "Byte ${i}: $($logonHours[$i])"
}

# Hash table for logon hours
$hashTable = @{
    "logonHours" = $logonHours
}

# Modify users in the specified OU
$distinguishedName = "OU=TestOU,DC=company,DC=local"
$users = Get-ADUser -Filter * -SearchBase $distinguishedName

foreach ($user in $users) {
    try {
        Set-ADUser -Identity $user.DistinguishedName -Replace $hashTable
        Write-Host "Updated logon hours for user: $($user.DistinguishedName)"
    } catch {
        Write-Warning "Failed to update user: $($user.DistinguishedName). Error: $_"
    }
}
