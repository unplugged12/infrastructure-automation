<#
.SYNOPSIS
    Remove Windows.old folder by clearing junction points and taking ownership.

.DESCRIPTION
    Multi-step process to safely remove the Windows.old folder which often cannot be deleted
    due to junction points and permission issues. This script:
    1. Uses Sysinternals junction.exe to list all junction points
    2. Removes all junctions and symbolic links
    3. Takes ownership of the folder
    4. Grants full control permissions
    5. Deletes the entire Windows.old folder

    This script is a documented procedure, not a fully automated script. Follow the steps
    manually or adapt to your needs.

.EXAMPLE
    # Step 1: List all junctions
    junction.exe -s -q c:\windows.old > %UserProfile%\desktop\junc.txt

    # Step 2: Run the PowerShell junction removal loop
    # (See script body)

    # Step 3: Take ownership
    takeown /f c:\windows.old /r /d y

    # Step 4: Grant permissions
    cacls c:\windows.old /t /g everyone:F

    # Step 5: Remove folder
    rmdir /s /q c:\windows.old

.NOTES
    Author: SysAdmin Team
    Version: 1.0.0
    Created: 2022-05-01
    Modified: 2025-01-09
    Risk Level: Medium 🟡

    Prerequisites:
    - Sysinternals junction.exe utility
    - Administrator privileges
    - PowerShell 3.0 or later
    - Sufficient disk space for operations
    - Windows.old folder exists

    Security Considerations:
    - ⚠️ Permanently deletes Windows.old (no recovery)
    - ⚠️ Modifies file ownership and permissions
    - ⚠️ Removes junction points (may affect system links)
    - ⚠️ Requires administrative privileges
    - ✅ Mitigation: Backup important data from Windows.old first
    - ✅ Testing: Verify junction.exe path and Windows.old location
    - ✅ Audit: Document deletion for compliance
    - ✅ Rollback: Not possible after deletion

    Required Tools:
    - junction.exe from Sysinternals Suite
    - Place junction.exe in accessible location
    - Update paths in script for your environment

    Change Log:
    - v1.0.0 (2022-05-01): Initial documented procedure

.LINK
    https://github.com/yourusername/sysadmin-toolkit

.LINK
    https://docs.microsoft.com/en-us/sysinternals/downloads/junction
#>

#First of all, run Sysinternals junction.exe utility to get a list of all junctions in a text file, junc.txt on my desktop.

junction.exe -s -q c:\windows.old > %UserProfile%\desktop\junc.txt
#Then, run the following script in PowerShell to remove all junction points and single symbolic links on the system.

foreach ($line in [System.IO.File]::ReadLines("$env:userprofile\desktop\junc.txt"))
 {
     if ($line -match "^\\\\")
     {
         $file = $line -replace "(: JUNCTION)|(: SYMBOLIC LINK)",""
         & $env:userprofile\desktop\pstools\junction.exe -d "$file"
     }
 }
#Replace with the correct path for junction.exe utility and the junc.txt files, if needed.

#Once that’s done, run the following to take over ownership of the windows.old folder.

takeown /f c:\windows.old /r /d y
#And reassign the full control rights to everyone.

cacls c:\windows.old /t /g everyone:F
#Then, finally to remove the whole folder.

rmdir /s /q c:\windows.old