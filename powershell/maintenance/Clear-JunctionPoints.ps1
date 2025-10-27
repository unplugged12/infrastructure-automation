<#
.SYNOPSIS
    Clear junction points and symbolic links from a directory.

.DESCRIPTION
    Reads a text file containing junction point listings (from Sysinternals junction.exe) and
    removes each junction point or symbolic link. This is useful for preparing directories
    for deletion or cleaning up orphaned links.

    The script parses junction.exe output and calls junction.exe -d to delete each link.

.EXAMPLE
    # First, create the junction list:
    junction.exe -s -q C:\FolderToClean > C:\Users\Appserver\junc.txt

    # Then run this script:
    .\Clear-JunctionPoints.ps1

    Removes all junctions and symbolic links listed in the junc.txt file.

.NOTES
    Author: SysAdmin Team
    Version: 1.0.0
    Created: 2022-06-01
    Modified: 2025-01-09
    Risk Level: Medium 🟡

    Prerequisites:
    - Sysinternals junction.exe utility
    - Administrator privileges recommended
    - PowerShell 3.0 or later
    - junction.exe must be in C:\junction\ (or update path)
    - junc.txt must exist in C:\Users\Appserver\ (or update path)

    Security Considerations:
    - ⚠️ Removes junction points (may break application links)
    - ⚠️ Deletes symbolic links (may affect system functionality)
    - ⚠️ Requires proper junction.exe path configuration
    - ⚠️ Hardcoded paths may not match your environment
    - ✅ Mitigation: Review junc.txt contents before execution
    - ✅ Testing: Test on non-production systems first
    - ✅ Audit: Log junction deletions for troubleshooting
    - ✅ Rollback: Recreate junctions manually if needed

    File Paths to Customize:
    - Input: C:\Users\Appserver\junc.txt
    - junction.exe: C:\junction\junction.exe

    Change Log:
    - v1.0.0 (2022-06-01): Initial version

.LINK
    https://github.com/yourusername/sysadmin-toolkit

.LINK
    https://docs.microsoft.com/en-us/sysinternals/downloads/junction
#>

foreach ($line in [System.IO.File]::ReadLines("$env:C:\Users\Appserver\junc.txt"))
{
    if ($line -match "^\\\\")
    {
        $file = $line -replace "(: JUNCTION)|(: SYMBOLIC LINK)",""
        & $env:C:\junction\junction.exe -d "$file"
    }
}