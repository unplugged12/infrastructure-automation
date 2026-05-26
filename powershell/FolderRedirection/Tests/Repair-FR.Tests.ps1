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

    if (-not (Get-Command Get-ADUser -ErrorAction SilentlyContinue)) {
        # The stub MUST declare -Identity (and the other params the script passes)
        # so that Pester -ParameterFilter blocks referencing $Identity bind correctly.
        # Without a real -Identity parameter, the argument lands in $args, $Identity is
        # $null in the filter, no parameterized mock matches, and this throwing stub runs.
        function Get-ADUser {
            param(
                [string]$Identity,
                [string[]]$Properties
            )
            throw "Get-ADUser is not available in this environment. Tests must mock it."
        }
    }

    # The script under test defines these helper functions internally and then
    # invokes its main logic in the same run. Pester's Mock can only intercept a
    # command that already resolves in the session at mock-definition time, so we
    # declare matching stubs here. When the script is invoked via & $ScriptPath,
    # Pester's mocks (keyed by command name) override the script's own definitions.
    # These stubs are never executed when a test sets up a Mock for the same name.
    function Get-ActualFolderName { param([string]$FolderName, [string]$RootPath) $FolderName }
    function Get-FolderStats { param([string]$Path) @{ Exists = $false; FileCount = 0; SizeMB = 0 } }
    function Test-OpenFiles { param([string]$Path) @() }

    function Initialize-ADModuleMocks {
        Mock Get-Module -ParameterFilter { $Name -eq 'ActiveDirectory' -and $ListAvailable } {
            @([pscustomobject]@{
                Name = 'ActiveDirectory'
                Version = [version]'1.0.0.0'
            })
        }

        Mock Import-Module -ParameterFilter { $Name -eq 'ActiveDirectory' } { }
    }
}

Describe "Repair-FolderRedirectionAfterRename - AD/SID Verification" {

    BeforeEach {
        Initialize-ADModuleMocks
    }

    Context "Old user missing, new user present (normal rename completed)" {
        It "Should continue with WARN and use new user SID (not ExitCode 11)" {
            Mock Get-ADUser -ParameterFilter { $Identity -eq 'olduser' } {
                throw "User not found"
            }
            Mock Get-ADUser -ParameterFilter { $Identity -eq 'newuser' } {
                New-MockADUser -Sam 'newuser' -SID 'S-1-5-21-123456789-123456789-123456789-1001'
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
            $result = (& $script:ScriptPath -RootPath '\\test\share' -OldSam 'olduser' -NewSam 'newuser' -WhatIf -VerboseOutput -SkipElevationCheck *>&1) | Out-String

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
                New-MockADUser -Sam 'olduser' -SID 'S-1-5-21-123456789-123456789-123456789-1001'
            }
            Mock Get-ADUser -ParameterFilter { $Identity -eq 'newuser' } {
                New-MockADUser -Sam 'newuser' -SID 'S-1-5-21-123456789-123456789-123456789-1001'
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

            $result = (& $script:ScriptPath -RootPath '\\test\share' -OldSam 'olduser' -NewSam 'newuser' -WhatIf -VerboseOutput -SkipElevationCheck *>&1) | Out-String

            $result | Should -Match "SID verification passed"
            $LASTEXITCODE | Should -Be 0
        }
    }

    Context "Both users present with DIFFERENT SIDs" {
        It "Should fail with ExitCode 12 (SID mismatch)" {
            Mock Get-ADUser -ParameterFilter { $Identity -eq 'user1' } {
                New-MockADUser -Sam 'user1' -SID 'S-1-5-21-123456789-123456789-123456789-1001'
            }
            Mock Get-ADUser -ParameterFilter { $Identity -eq 'user2' } {
                New-MockADUser -Sam 'user2' -SID 'S-1-5-21-123456789-123456789-123456789-9999'
            }
            Mock Test-Path { $true }
            Mock Start-Transcript { }
            Mock Stop-Transcript { }

            $result = (& $script:ScriptPath -RootPath '\\test\share' -OldSam 'user1' -NewSam 'user2' -VerboseOutput -SkipElevationCheck *>&1) | Out-String

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

            $result = (& $script:ScriptPath -RootPath '\\test\share' -OldSam 'olduser' -NewSam 'nonexistent' -VerboseOutput -SkipElevationCheck *>&1) | Out-String

            $result | Should -Match "Could not find new user"
            $LASTEXITCODE | Should -Be 11
        }
    }

    Context "SkipOldUserCheck switch" {
        It "Should skip old user lookup and use new user SID only" {
            Mock Get-ADUser -ParameterFilter { $Identity -eq 'newuser' } {
                New-MockADUser -Sam 'newuser' -SID 'S-1-5-21-123456789-123456789-123456789-1001'
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

            $result = (& $script:ScriptPath -RootPath '\\test\share' -OldSam 'olduser' -NewSam 'newuser' -SkipOldUserCheck -WhatIf -VerboseOutput -SkipElevationCheck *>&1) | Out-String

            $result | Should -Match "Old user check skipped"
            $result | Should -Not -Match "Old user found"
            $LASTEXITCODE | Should -Be 0
        }
    }
}

Describe "Repair-FolderRedirectionAfterRename - ACL-Only Mode" {

    BeforeAll {
        # ACL fixtures are exposed as functions (not $script: variables) because a
        # mock body that runs while the script-under-test is executing resolves
        # $script: against the SCRIPT's scope, not this test file's — so a
        # $script:MockAcl* reference would come back $null. Functions resolve by
        # name from any scope, so the Get-Acl mocks call these instead.
        #
        # The fixtures faithfully emulate the System.Security.AccessControl shape
        # the script actually uses:
        #   - $ace.IdentityReference.Translate([SecurityIdentifier]).Value  (line ~720)
        #   - $acl.AddAccessRule($rule)                                     (line ~769)
        # so the non-WhatIf repair path can run against the mock.
        function New-MockAce {
            param([string]$IdentitySid, [string]$Rights)
            $idRef = [PSCustomObject]@{ Value = $IdentitySid }
            # Translate() just returns an object exposing .Value = the SID string.
            $idRef | Add-Member -MemberType ScriptMethod -Name Translate -Value {
                param($type) [PSCustomObject]@{ Value = $this.Value }
            }
            [PSCustomObject]@{
                IdentityReference = $idRef
                FileSystemRights  = $Rights
                IsInherited       = $false
                AccessControlType = 'Allow'
            }
        }

        function New-MockAcl {
            param([object[]]$Aces)
            $acl = [PSCustomObject]@{ Access = @($Aces) }
            # The script mutates the ACL via AddAccessRule before Set-Acl; provide
            # a no-op so the repair path completes without a real DirectorySecurity.
            $acl | Add-Member -MemberType ScriptMethod -Name AddAccessRule -Value { param($rule) }
            $acl
        }

        # SYSTEM (S-1-5-18) and Administrators (S-1-5-32-544) present; user ACE absent.
        function New-MockAclMissingUser {
            New-MockAcl -Aces @(
                (New-MockAce -IdentitySid 'S-1-5-18'      -Rights 'FullControl'),
                (New-MockAce -IdentitySid 'S-1-5-32-544'  -Rights 'FullControl')
            )
        }

        # User (Modify), SYSTEM and Administrators (FullControl) all present.
        function New-MockAclComplete {
            New-MockAcl -Aces @(
                (New-MockAce -IdentitySid 'S-1-5-21-123456789-123456789-123456789-1001' -Rights 'Modify'),
                (New-MockAce -IdentitySid 'S-1-5-18'     -Rights 'FullControl'),
                (New-MockAce -IdentitySid 'S-1-5-32-544' -Rights 'FullControl')
            )
        }
    }

    BeforeEach {
        Initialize-ADModuleMocks
    }

    Context "ACL-Only mode with WhatIf (audit)" {
        It "Should display audit table and exit 0 without making changes" {
            Mock Get-ADUser {
                New-MockADUser -Sam 'testuser' -SID 'S-1-5-21-123456789-123456789-123456789-1001'
            }
            Mock Test-Path { $true }
            Mock Get-Acl { New-MockAclMissingUser }
            Mock Set-Acl { }
            Mock Start-Transcript { }
            Mock Stop-Transcript { }

            $result = (& $script:ScriptPath -RootPath '\\test\share' -NewSam 'testuser' -AclOnly -WhatIf -VerboseOutput -SkipElevationCheck *>&1) | Out-String

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
                New-MockADUser -Sam 'testuser' -SID 'S-1-5-21-123456789-123456789-123456789-1001'
            }
            Mock Test-Path { $true }
            Mock Get-Acl { New-MockAclMissingUser }
            Mock Set-Acl { }
            Mock Start-Transcript { }
            Mock Stop-Transcript { }

            $result = (& $script:ScriptPath -RootPath '\\test\share' -NewSam 'testuser' -AclOnly -VerboseOutput -SkipElevationCheck *>&1) | Out-String

            # Should show ACL mode
            $result | Should -Match "ACL-Only Mode"

            # Should indicate permissions were added
            $result | Should -Match "Added.*for"

            # Should call Set-Acl to apply changes (assert via Pester, not a
            # closure variable — a Mock body cannot mutate the It-scope variable).
            Assert-MockCalled Set-Acl -Times 1 -Exactly

            $LASTEXITCODE | Should -Be 0
        }
    }

    Context "ACL-Only mode - Idempotency check" {
        It "Should report no changes needed when all ACEs present" {
            Mock Get-ADUser {
                New-MockADUser -Sam 'testuser' -SID 'S-1-5-21-123456789-123456789-123456789-1001'
            }
            Mock Test-Path { $true }
            Mock Get-Acl { New-MockAclComplete }
            Mock Set-Acl { }
            Mock Start-Transcript { }
            Mock Stop-Transcript { }

            $result = (& $script:ScriptPath -RootPath '\\test\share' -NewSam 'testuser' -AclOnly -VerboseOutput -SkipElevationCheck *>&1) | Out-String

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
                New-MockADUser -Sam 'testuser' -SID 'S-1-5-21-123456789-123456789-123456789-1001'
            }
            # Share root reachable (Step 1 SMB check passes) but the per-user
            # target folder is missing, so ACL-only mode fails with ExitCode 20.
            Mock Test-Path -ParameterFilter { $LiteralPath -like '*testuser*' -or $Path -like '*testuser*' } { $false }
            Mock Test-Path { $true }
            Mock Start-Transcript { }
            Mock Stop-Transcript { }

            $result = (& $script:ScriptPath -RootPath '\\test\share' -NewSam 'testuser' -AclOnly -VerboseOutput -SkipElevationCheck *>&1) | Out-String

            $result | Should -Match "Target path not found"
            $LASTEXITCODE | Should -Be 20
        }
    }
}

Describe "Repair-FolderRedirectionAfterRename - Exit Codes" {

    BeforeEach {
        Initialize-ADModuleMocks
    }

    Context "SMB path unreachable" {
        It "Should exit with code 10" {
            Mock Test-Path { $false }
            Mock Start-Transcript { }
            Mock Stop-Transcript { }

            $result = (& $script:ScriptPath -RootPath '\\nonexistent\share' -OldSam 'old' -NewSam 'new' -SMBTimeoutSec 1 -VerboseOutput -SkipElevationCheck *>&1) | Out-String

            $result | Should -Match "SMB path unreachable"
            $LASTEXITCODE | Should -Be 10
        }
    }

    Context "Open files detected" {
        It "Should exit with code 13 when not in WhatIf mode" {
            Mock Get-ADUser {
                New-MockADUser -Sam 'testuser' -SID 'S-1-5-21-123456789-123456789-123456789-1001'
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

            $result = (& $script:ScriptPath -RootPath '\\test\share' -OldSam 'olduser' -NewSam 'newuser' -VerboseOutput -SkipElevationCheck *>&1) | Out-String

            $result | Should -Match "Found.*open file"
            $result | Should -Match "Cannot proceed with open files"
            $LASTEXITCODE | Should -Be 13
        }
    }
}

Describe "Repair-FolderRedirectionAfterRename - Integration" {

    BeforeEach {
        Initialize-ADModuleMocks
    }

    Context "Full workflow with old user missing" {
        It "Should complete rename with warning about old user" {
            Mock Get-ADUser -ParameterFilter { $Identity -eq 'olduser' } {
                throw "User not found"
            }
            Mock Get-ADUser -ParameterFilter { $Identity -eq 'newuser' } {
                New-MockADUser -Sam 'newuser' -SID 'S-1-5-21-123456789-123456789-123456789-1001'
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

            $result = (& $script:ScriptPath -RootPath '\\test\share' -OldSam 'olduser' -NewSam 'newuser' -WhatIf -VerboseOutput -SkipElevationCheck *>&1) | Out-String

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
