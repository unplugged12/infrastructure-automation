<#
.SYNOPSIS
    Pester tests for Repair-FolderRedirectionAfterRename.ps1

.DESCRIPTION
    PowerShell 5.1 compatible Pester tests that validate:
    - Robust AD/SID verification (old user missing, SID mismatch, etc.)
    - ACL-only mode with WhatIf and actual repair
    - Exit codes
    - Idempotency

.NOTES
    Run with: Invoke-Pester -Path .\Tests\Repair-FR.Tests.ps1
#>

BeforeAll {
    $script:ScriptPath = Join-Path $PSScriptRoot '..\Repair-FolderRedirectionAfterRename.ps1'

    # Mock data
    $script:MockOldSID = 'S-1-5-21-123456789-123456789-123456789-1001'
    $script:MockNewSID = 'S-1-5-21-123456789-123456789-123456789-1001'
    $script:MockDifferentSID = 'S-1-5-21-123456789-123456789-123456789-9999'

    # Helper to create mock AD user
    function New-MockADUser {
        param([string]$Sam, [string]$SID)
        [PSCustomObject]@{
            SamAccountName = $Sam
            SID = [PSCustomObject]@{ Value = $SID }
            DistinguishedName = "CN=$Sam,OU=Users,DC=test,DC=local"
        }
    }
}

Describe "Repair-FolderRedirectionAfterRename - AD/SID Verification" {

    Context "Old user missing, new user present (normal rename completed)" {
        It "Should continue with WARN and use new user SID (not ExitCode 11)" {
            Mock Get-ADUser -ParameterFilter { $Identity -eq 'olduser' } {
                throw "User not found"
            }
            Mock Get-ADUser -ParameterFilter { $Identity -eq 'newuser' } {
                New-MockADUser -Sam 'newuser' -SID $script:MockNewSID
            }
            Mock Test-Path { $true }
            Mock Get-ActualFolderName { 'olduser' }
            Mock Get-FolderStats { @{Exists=$true; FileCount=5; SizeMB=10} }
            Mock Test-OpenFiles { @() }
            Mock Rename-Item { }
            Mock Get-Acl { [PSCustomObject]@{ Access = @() } }
            Mock Set-Acl { }
            Mock Start-Transcript { }
            Mock Stop-Transcript { }

            # Should not throw and should exit 0
            $result = & $script:ScriptPath -RootPath '\\test\share' -OldSam 'olduser' -NewSam 'newuser' -WhatIf -VerboseOutput 2>&1

            # Check for warning about old user
            $result | Should -Match "Old user.*not found.*Assuming rename"

            # Should have found new user
            $result | Should -Match "New user found"

            $LASTEXITCODE | Should -Be 0
        }
    }

    Context "Both users present with matching SIDs" {
        It "Should verify SIDs match and proceed normally" {
            Mock Get-ADUser -ParameterFilter { $Identity -eq 'olduser' } {
                New-MockADUser -Sam 'olduser' -SID $script:MockOldSID
            }
            Mock Get-ADUser -ParameterFilter { $Identity -eq 'newuser' } {
                New-MockADUser -Sam 'newuser' -SID $script:MockNewSID
            }
            Mock Test-Path { $true }
            Mock Get-ActualFolderName { 'olduser' }
            Mock Get-FolderStats { @{Exists=$true; FileCount=5; SizeMB=10} }
            Mock Test-OpenFiles { @() }
            Mock Rename-Item { }
            Mock Get-Acl { [PSCustomObject]@{ Access = @() } }
            Mock Set-Acl { }
            Mock Start-Transcript { }
            Mock Stop-Transcript { }

            $result = & $script:ScriptPath -RootPath '\\test\share' -OldSam 'olduser' -NewSam 'newuser' -WhatIf -VerboseOutput 2>&1

            $result | Should -Match "SID verification passed"
            $LASTEXITCODE | Should -Be 0
        }
    }

    Context "Both users present with DIFFERENT SIDs" {
        It "Should fail with ExitCode 12 (SID mismatch)" {
            Mock Get-ADUser -ParameterFilter { $Identity -eq 'user1' } {
                New-MockADUser -Sam 'user1' -SID $script:MockOldSID
            }
            Mock Get-ADUser -ParameterFilter { $Identity -eq 'user2' } {
                New-MockADUser -Sam 'user2' -SID $script:MockDifferentSID
            }
            Mock Test-Path { $true }
            Mock Start-Transcript { }
            Mock Stop-Transcript { }

            $result = & $script:ScriptPath -RootPath '\\test\share' -OldSam 'user1' -NewSam 'user2' -VerboseOutput 2>&1

            $result | Should -Match "SID MISMATCH"
            $result | Should -Match "not a simple rename"
            $LASTEXITCODE | Should -Be 12
        }
    }

    Context "New user missing" {
        It "Should fail with ExitCode 11" {
            Mock Get-ADUser {
                throw "User not found"
            }
            Mock Test-Path { $true }
            Mock Start-Transcript { }
            Mock Stop-Transcript { }

            $result = & $script:ScriptPath -RootPath '\\test\share' -OldSam 'olduser' -NewSam 'nonexistent' -VerboseOutput 2>&1

            $result | Should -Match "Could not find new user"
            $LASTEXITCODE | Should -Be 11
        }
    }

    Context "SkipOldUserCheck switch" {
        It "Should skip old user lookup and use new user SID only" {
            Mock Get-ADUser -ParameterFilter { $Identity -eq 'newuser' } {
                New-MockADUser -Sam 'newuser' -SID $script:MockNewSID
            }
            Mock Test-Path { $true }
            Mock Get-ActualFolderName { 'olduser' }
            Mock Get-FolderStats { @{Exists=$true; FileCount=5; SizeMB=10} }
            Mock Test-OpenFiles { @() }
            Mock Rename-Item { }
            Mock Get-Acl { [PSCustomObject]@{ Access = @() } }
            Mock Set-Acl { }
            Mock Start-Transcript { }
            Mock Stop-Transcript { }

            $result = & $script:ScriptPath -RootPath '\\test\share' -OldSam 'olduser' -NewSam 'newuser' -SkipOldUserCheck -WhatIf -VerboseOutput 2>&1

            $result | Should -Match "Old user check skipped"
            $result | Should -Not -Match "Old user found"
            $LASTEXITCODE | Should -Be 0
        }
    }
}

Describe "Repair-FolderRedirectionAfterRename - ACL-Only Mode" {

    BeforeAll {
        # Mock ACL with missing user permission
        $script:MockAclMissingUser = [PSCustomObject]@{
            Access = @(
                [PSCustomObject]@{
                    IdentityReference = [PSCustomObject]@{
                        Value = 'NT AUTHORITY\SYSTEM'
                    }
                    FileSystemRights = 'FullControl'
                    IsInherited = $false
                    AccessControlType = 'Allow'
                },
                [PSCustomObject]@{
                    IdentityReference = [PSCustomObject]@{
                        Value = 'BUILTIN\Administrators'
                    }
                    FileSystemRights = 'FullControl'
                    IsInherited = $false
                    AccessControlType = 'Allow'
                }
            )
        }

        # Mock ACL with all required permissions
        $script:MockAclComplete = [PSCustomObject]@{
            Access = @(
                [PSCustomObject]@{
                    IdentityReference = [PSCustomObject]@{
                        Value = 'S-1-5-21-123456789-123456789-123456789-1001'
                    }
                    FileSystemRights = 'Modify'
                    IsInherited = $false
                    AccessControlType = 'Allow'
                },
                [PSCustomObject]@{
                    IdentityReference = [PSCustomObject]@{
                        Value = 'NT AUTHORITY\SYSTEM'
                    }
                    FileSystemRights = 'FullControl'
                    IsInherited = $false
                    AccessControlType = 'Allow'
                },
                [PSCustomObject]@{
                    IdentityReference = [PSCustomObject]@{
                        Value = 'BUILTIN\Administrators'
                    }
                    FileSystemRights = 'FullControl'
                    IsInherited = $false
                    AccessControlType = 'Allow'
                }
            )
        }
    }

    Context "ACL-Only mode with WhatIf (audit)" {
        It "Should display audit table and exit 0 without making changes" {
            Mock Get-ADUser {
                New-MockADUser -Sam 'testuser' -SID $script:MockNewSID
            }
            Mock Test-Path { $true }
            Mock Get-Acl { $script:MockAclMissingUser }
            Mock Set-Acl { }
            Mock Start-Transcript { }
            Mock Stop-Transcript { }

            $result = & $script:ScriptPath -RootPath '\\test\share' -NewSam 'testuser' -AclOnly -WhatIf -VerboseOutput 2>&1

            # Should show ACL mode
            $result | Should -Match "ACL-Only Mode"

            # Should show audit table with Present column
            $result | Should -Match "Present"

            # Should indicate WhatIf
            $result | Should -Match "WhatIf.*would add missing ACEs"

            # Should not call Set-Acl
            Assert-MockCalled Set-Acl -Times 0

            $LASTEXITCODE | Should -Be 0
        }
    }

    Context "ACL-Only mode without WhatIf (repair)" {
        It "Should add missing ACEs and exit 0" {
            Mock Get-ADUser {
                New-MockADUser -Sam 'testuser' -SID $script:MockNewSID
            }
            Mock Test-Path { $true }
            Mock Get-Acl { $script:MockAclMissingUser }

            $setAclCalled = $false
            Mock Set-Acl { $setAclCalled = $true }
            Mock Start-Transcript { }
            Mock Stop-Transcript { }

            $result = & $script:ScriptPath -RootPath '\\test\share' -NewSam 'testuser' -AclOnly -VerboseOutput 2>&1

            # Should show ACL mode
            $result | Should -Match "ACL-Only Mode"

            # Should indicate permissions were added
            $result | Should -Match "Added.*for"

            # Should call Set-Acl to apply changes
            $setAclCalled | Should -Be $true

            $LASTEXITCODE | Should -Be 0
        }
    }

    Context "ACL-Only mode - Idempotency check" {
        It "Should report no changes needed when all ACEs present" {
            Mock Get-ADUser {
                New-MockADUser -Sam 'testuser' -SID $script:MockNewSID
            }
            Mock Test-Path { $true }
            Mock Get-Acl { $script:MockAclComplete }
            Mock Set-Acl { }
            Mock Start-Transcript { }
            Mock Stop-Transcript { }

            $result = & $script:ScriptPath -RootPath '\\test\share' -NewSam 'testuser' -AclOnly -VerboseOutput 2>&1

            # Should show all present
            $result | Should -Match "All required permissions already present"

            # Should not call Set-Acl (no changes)
            Assert-MockCalled Set-Acl -Times 0

            $LASTEXITCODE | Should -Be 0
        }
    }

    Context "ACL-Only mode - Target path missing" {
        It "Should fail with ExitCode 20" {
            Mock Get-ADUser {
                New-MockADUser -Sam 'testuser' -SID $script:MockNewSID
            }
            Mock Test-Path { $false }
            Mock Start-Transcript { }
            Mock Stop-Transcript { }

            $result = & $script:ScriptPath -RootPath '\\test\share' -NewSam 'testuser' -AclOnly -VerboseOutput 2>&1

            $result | Should -Match "Target path not found"
            $LASTEXITCODE | Should -Be 20
        }
    }
}

Describe "Repair-FolderRedirectionAfterRename - Exit Codes" {

    Context "SMB path unreachable" {
        It "Should exit with code 10" {
            Mock Test-Path { $false }
            Mock Start-Transcript { }
            Mock Stop-Transcript { }

            $result = & $script:ScriptPath -RootPath '\\nonexistent\share' -OldSam 'old' -NewSam 'new' -SMBTimeoutSec 1 -VerboseOutput 2>&1

            $result | Should -Match "SMB path unreachable"
            $LASTEXITCODE | Should -Be 10
        }
    }

    Context "Open files detected" {
        It "Should exit with code 13 when not in WhatIf mode" {
            Mock Get-ADUser {
                New-MockADUser -Sam 'testuser' -SID $script:MockNewSID
            }
            Mock Test-Path { $true }
            Mock Get-ActualFolderName { 'olduser' }
            Mock Get-FolderStats { @{Exists=$true; FileCount=5; SizeMB=10} }
            Mock Test-OpenFiles {
                @(
                    [PSCustomObject]@{
                        FileId = 123
                        ClientComputerName = 'WORKSTATION1'
                        ClientUserName = 'testuser'
                    }
                )
            }
            Mock Start-Transcript { }
            Mock Stop-Transcript { }

            $result = & $script:ScriptPath -RootPath '\\test\share' -OldSam 'olduser' -NewSam 'newuser' -VerboseOutput 2>&1

            $result | Should -Match "Found.*open file"
            $result | Should -Match "Cannot proceed with open files"
            $LASTEXITCODE | Should -Be 13
        }
    }
}

Describe "Repair-FolderRedirectionAfterRename - Integration" {

    Context "Full workflow with old user missing" {
        It "Should complete rename with warning about old user" {
            Mock Get-ADUser -ParameterFilter { $Identity -eq 'olduser' } {
                throw "User not found"
            }
            Mock Get-ADUser -ParameterFilter { $Identity -eq 'newuser' } {
                New-MockADUser -Sam 'newuser' -SID $script:MockNewSID
            }
            Mock Test-Path { $true }
            Mock Get-ActualFolderName -ParameterFilter { $FolderName -eq 'olduser' } { 'olduser' }
            Mock Get-ActualFolderName -ParameterFilter { $FolderName -eq 'newuser' } { $null }
            Mock Get-FolderStats { @{Exists=$true; FileCount=10; SizeMB=50; LastWrite=(Get-Date)} }
            Mock Test-OpenFiles { @() }
            Mock Rename-Item { }
            Mock Get-Acl { [PSCustomObject]@{ Access = @() } }
            Mock Set-Acl { }
            Mock Start-Transcript { }
            Mock Stop-Transcript { }

            $result = & $script:ScriptPath -RootPath '\\test\share' -OldSam 'olduser' -NewSam 'newuser' -WhatIf -VerboseOutput 2>&1

            # Should warn about old user
            $result | Should -Match "Old user.*not found"

            # Should plan rename operation
            $result | Should -Match "Plan: RENAME"

            # Should show success
            $result | Should -Match "SUCCESS"

            $LASTEXITCODE | Should -Be 0
        }
    }
}
