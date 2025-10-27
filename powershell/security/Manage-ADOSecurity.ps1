<#
Azure DevOps Security Management Tool - Usage Guide
--------------------------------------------------
Prerequisites
  - Azure CLI with the azure-devops extension (run `az extension add --name azure-devops` once)
  - Active login via `az login` to the tenant that owns https://dev.azure.com/tpsapps
  - Permissions to view or modify security groups in that organization

Quick Start (interactive)
  1. Run `./Manage-ADOSecurity.ps1`
  2. Choose a menu option (Find, Add, or Remove Project Administrators)
  3. Provide the requested user emails and projects when prompted
  4. Review the summary and audit-log path printed at completion

Automation Examples
  - `./Manage-ADOSecurity.ps1 -Mode FindAdmin -UserEmail user@contoso.com`
    Lists every project where the user is a Project Administrator.
  - `./Manage-ADOSecurity.ps1 -Mode FindAdmin -UserEmail user@contoso.com -Projects "ProjectA,ProjectB"`
    Limits the scan to the specified projects.
  - `./Manage-ADOSecurity.ps1 -Mode AddAdmin -UserEmails "user1@contoso.com,user2@contoso.com" -Projects "ProjectA"`
    Adds multiple users to Project Administrators (prompts for confirmation).
  - Append `-DryRun` to preview changes or `-Confirm:$false` to skip prompts in automation.

Outputs & Logging
  - All activity is written to an audit log under `C:\temp` (Windows) or `/tmp/claude-ado-security` (Linux/macOS).
  - Use `-Verbose` to trace REST calls, descriptor lookups, and membership checks.

For implementation details, search this file for `Helper:` and `Utility:` comment headings.
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory = $false)]
    [ValidateSet("FindAdmin", "AddAdmin", "RemoveAdmin", "ManageGroups", "ManageTeams", "BatchOps")]
    [string]$Mode,

    [Parameter(Mandatory = $false)]
    [string]$UserEmail,

    [Parameter(Mandatory = $false)]
    [string]$UserEmails,

    [Parameter(Mandatory = $false)]
    [string]$Projects,

    [Parameter(Mandatory = $false)]
    [string]$Groups,

    [Parameter(Mandatory = $false)]
    [string]$Teams,

    [Parameter(Mandatory = $false)]
    [string]$CsvFile,

    [Parameter(Mandatory = $false)]
    [switch]$DryRun,

    [Parameter(Mandatory = $false)]
    [switch]$Confirm = $true
)

# Global Variables
$script:OrganizationUrl = "https://dev.azure.com/tpsapps"
$script:VssApiUrl = "https://vssps.dev.azure.com/tpsapps"
$script:AccessToken = $null
$script:Headers = $null
$script:ProjectDescriptorCache = @{}
$script:LogFile = $null

# Initialize logging
function Initialize-AuditLogging {
    $username = $env:USERNAME
    $timestamp = Get-Date -Format "yyyyMMdd_HHmmss"

    # Use cross-platform temporary directory
    $tempPath = if ($IsWindows -or $env:OS -eq "Windows_NT") {
        "C:\temp"
    } else {
        "/tmp/claude-ado-security"
    }

    $script:LogFile = Join-Path $tempPath "${username}_${timestamp}.log"

    # Create temp directory if it doesn't exist
    if (-not (Test-Path $tempPath)) {
        New-Item -Path $tempPath -ItemType Directory -Force | Out-Null
    }

    Write-AuditLog -Action "Session Start" -User $env:USERNAME -Project "N/A" -Group "N/A" -Result "Log initialized"
}

function Write-AuditLog {
    param(
        [string]$Action,
        [string]$User,
        [string]$Project,
        [string]$Group,
        [string]$Result
    )

    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $logEntry = "[$timestamp] ACTION: $Action | USER: $User | PROJECT: $Project | GROUP: $Group | RESULT: $Result"

    try {
        Add-Content -Path $script:LogFile -Value $logEntry -Encoding UTF8
    }
    catch {
        Write-Warning "Failed to write to audit log: $_"
    }
}

function Test-Prerequisites {
    Write-Host "Checking prerequisites..." -ForegroundColor Yellow

    # Check if Azure CLI is installed
    try {
        $azVersion = az --version --only-show-errors
        if ($LASTEXITCODE -ne 0 -or -not $azVersion) {
            throw "Azure CLI not found or failed to execute"
        }
        Write-Host "✓ Azure CLI is installed" -ForegroundColor Green
    }
    catch {
        Write-Host "✗ Azure CLI is not installed or not in PATH" -ForegroundColor Red
        Write-Host "Please install Azure CLI from https://docs.microsoft.com/en-us/cli/azure/install-azure-cli" -ForegroundColor Yellow
        return $false
    }

    # Check if azure-devops extension is installed
    try {
        $extensions = az extension list --output json --only-show-errors
        if ($LASTEXITCODE -ne 0 -or -not $extensions) {
            throw "Failed to list Azure CLI extensions"
        }

        $extensionList = $extensions | ConvertFrom-Json -Depth 10
        $devopsExtension = $extensionList | Where-Object { $_.name -eq "azure-devops" }

        if (-not $devopsExtension) {
            Write-Host "Azure DevOps extension not found. Installing..." -ForegroundColor Yellow
            az extension add --name azure-devops --only-show-errors
            if ($LASTEXITCODE -ne 0) {
                throw "Failed to install Azure DevOps extension"
            }
            Write-Host "✓ Azure DevOps extension installed" -ForegroundColor Green
        } else {
            Write-Host "✓ Azure DevOps extension is installed" -ForegroundColor Green
        }
    }
    catch {
        Write-Host "✗ Failed to check or install Azure DevOps extension: $_" -ForegroundColor Red
        return $false
    }

    return $true
}

function Initialize-Authentication {
    Write-Host "Validating authentication..." -ForegroundColor Yellow

    try {
        az devops configure --defaults organization=$script:OrganizationUrl --only-show-errors
        if ($LASTEXITCODE -ne 0) {
            throw "Failed to configure Azure DevOps organization context"
        }

        $accountJson = az account show --output json --only-show-errors
        if ($LASTEXITCODE -ne 0 -or -not $accountJson) {
            throw "Azure CLI is not logged in. Run 'az login' to authenticate."
        }

        $account = $accountJson | ConvertFrom-Json -Depth 10
        if ($account.name) {
            Write-Host ("Azure subscription context: {0}" -f $account.name) -ForegroundColor DarkGray
        }

        $tokenResponse = az account get-access-token --resource "499b84ac-1321-427f-aa17-267ca6975798" --output json --only-show-errors
        if ($LASTEXITCODE -ne 0 -or -not $tokenResponse) {
            throw "Failed to get access token - az account get-access-token returned exit code $LASTEXITCODE"
        }

        $tokenObject = $tokenResponse | ConvertFrom-Json -Depth 10
        if (-not $tokenObject.accessToken) {
            throw "Access token not found in response"
        }

        $script:AccessToken = $tokenObject.accessToken
        $script:Headers = @{
            Authorization = "Bearer $($script:AccessToken)"
            'Content-Type' = 'application/json'
            Accept = 'application/json'
        }

        $profileUri = "https://app.vssps.visualstudio.com/_apis/profile/profiles/me?api-version=7.1-preview.3"
        $profile = Invoke-RestMethod -Uri $profileUri -Headers $script:Headers -Method Get -ErrorAction Stop

        $email = $profile.emailAddress
        if (-not $email -and $profile.properties.'Email.Internal') {
            $email = $profile.properties.'Email.Internal'.value
        }

        Write-Host ("Authenticated as: {0} ({1})" -f $profile.displayName, $email) -ForegroundColor Green
        Write-Host "[+] API access token obtained" -ForegroundColor Green
        return $true
    }
    catch {
        Write-Host "[!] Authentication failed. Please run 'az login' first." -ForegroundColor Red
        Write-Host ("Error: {0}" -f $_) -ForegroundColor Red
        return $false
    }
}

function Invoke-ADORestApi {
    param(
        [string]$Uri,
        [string]$Method = "GET",
        [object]$Body = $null,
        [int]$RetryCount = 1
    )

    if ([string]::IsNullOrWhiteSpace($Uri)) {
        Write-Error "API URI cannot be null or empty"
        return $null
    }

    # Validate URI format and scheme
    try {
        $uriObject = [System.Uri]$Uri
        if ($uriObject.Scheme -notin @('https')) {
            Write-Error "URI must use HTTPS scheme: $Uri"
            return $null
        }
    } catch {
        Write-Error "Invalid URI format: $Uri"
        return $null
    }

    if (-not $script:Headers) {
        Write-Error "API headers not initialized. Authentication may have failed."
        return $null
    }

    for ($i = 0; $i -le $RetryCount; $i++) {
        try {
            Write-Verbose "API Call: $Method $Uri (Attempt $($i + 1))"

            $params = @{
                Uri = $Uri
                Method = $Method
                Headers = $script:Headers
                TimeoutSec = 30
            }

            if ($Body -and ($Method -eq "POST" -or $Method -eq "PUT" -or $Method -eq "PATCH")) {
                $params.Body = $Body | ConvertTo-Json -Depth 10
                Write-Verbose "Request Body: $($params.Body)"
            }

            # Use Invoke-WebRequest with SkipHttpErrorCheck to capture error details
            $params.SkipHttpErrorCheck = $true
            $webResponse = Invoke-WebRequest @params

            # Check if the response was successful
            if ($webResponse.StatusCode -ge 200 -and $webResponse.StatusCode -lt 300) {
                Write-Verbose "API call successful"
                # Parse JSON response if content exists
                if ($webResponse.Content) {
                    return ($webResponse.Content | ConvertFrom-Json)
                }
                return $null
            }
            else {
                # Response was an error, throw to trigger catch block
                $errorBody = $webResponse.Content
                Write-Verbose "HTTP $($webResponse.StatusCode): $errorBody"
                throw "Response status code does not indicate success: $($webResponse.StatusCode) ($($webResponse.StatusDescription))."
            }
        }
        catch {
            $statusCode = $null
            $errorDetails = $null

            # Try to extract status code from our custom thrown error or from exception response
            if ($_.Exception.Message -match "Response status code does not indicate success: (\d+)") {
                $statusCode = [int]$Matches[1]
            }
            elseif ($_.Exception.Response) {
                $statusCode = $_.Exception.Response.StatusCode.value__

                # Try to read the error response body
                try {
                    $reader = [System.IO.StreamReader]::new($_.Exception.Response.GetResponseStream())
                    $errorDetails = $reader.ReadToEnd()
                    $reader.Close()
                } catch {
                    $errorDetails = $null
                }
            }

            Write-Verbose "API call failed with status code: $statusCode, Error: $($_.Exception.Message)"
            if ($errorDetails) {
                Write-Verbose "Error response body: $errorDetails"
            }

            switch ($statusCode) {
                401 {
                    Write-Warning "Authentication expired. Please re-authenticate with 'az login'"
                    Write-AuditLog -Action "API Error" -User $env:USERNAME -Project "N/A" -Group "N/A" -Result "Authentication expired"
                    return $null
                }
                403 {
                    Write-Warning "Access denied. You may not have sufficient permissions for this operation."
                    Write-AuditLog -Action "API Error" -User $env:USERNAME -Project "N/A" -Group "N/A" -Result "Access denied (403)"
                    return $null
                }
                404 {
                    Write-Verbose "Resource not found (404): $Uri"
                    return $null
                }
                429 {
                    # Implement proper Retry-After header support
                    $retryAfter = 5  # Default fallback
                    if ($_.Exception.Response.Headers -and $_.Exception.Response.Headers['Retry-After']) {
                        try {
                            $retryAfter = [int]$_.Exception.Response.Headers['Retry-After']
                        } catch {
                            $retryAfter = [Math]::Min([Math]::Pow(2, $i + 1), 30)  # Exponential backoff, capped at 30s
                        }
                    } else {
                        $retryAfter = [Math]::Min([Math]::Pow(2, $i + 1), 30)  # Exponential backoff
                    }
                    Write-Verbose "Rate limit exceeded, waiting $retryAfter seconds before retry..."
                    Start-Sleep -Seconds $retryAfter
                }
                { $_ -ge 500 } {
                    Write-Verbose "Server error ($statusCode), will retry if attempts remain"
                }
                default {
                    $errorMsg = if ($errorDetails) {
                        "API error ($statusCode): $errorDetails"
                    } else {
                        "API error ($statusCode): $($_.Exception.Message)"
                    }
                    Write-Verbose $errorMsg
                }
            }

            if ($i -lt $RetryCount) {
                $waitTime = if ($statusCode -eq 429) { 5 } else { 2 }
                Write-Verbose "Retrying in $waitTime seconds... (Attempt $($i + 1)/$($RetryCount + 1))"
                Start-Sleep -Seconds $waitTime
            }
            else {
                $errorMsg = "API call failed after $($RetryCount + 1) attempts: $($_.Exception.Message)"
                Write-Error $errorMsg
                Write-AuditLog -Action "API Error" -User $env:USERNAME -Project "N/A" -Group "N/A" -Result $errorMsg
                return $null
            }
        }
    }
}

function Get-ADOUser {
    param([string]$Email)

    Write-Verbose "Looking up user: $Email"

    if ([string]::IsNullOrWhiteSpace($Email)) {
        return $null
    }

    try {
        $encodedEmail = [System.Uri]::EscapeDataString($Email)
        $usersUri = "$( $script:VssApiUrl)/_apis/graph/users?searchTerm=$encodedEmail&api-version=7.1-preview.1"
        $response = Invoke-ADORestApi -Uri $usersUri
        if (-not $response -or -not $response.value) {
            Write-Verbose "User lookup returned no results for $Email"
            return $null
        }

        $user = $response.value | Where-Object { $_.mailAddress -and ($_.mailAddress -ieq $Email) } | Select-Object -First 1
        if (-not $user) {
            $user = $response.value | Select-Object -First 1
        }

        if (-not $user) {
            Write-Verbose "No user objects returned for $Email"
            return $null
        }

        $mailAddress = if ($user.mailAddress) { $user.mailAddress } elseif ($user.signInAddress) { $user.signInAddress } else { $Email }

        return @{
            DisplayName = $user.displayName
            MailAddress = $mailAddress
            Descriptor  = $user.descriptor
            Id          = $user.originId
        }
    }
    catch {
        Write-Verbose "Failed to find user ${Email}: $_"
        return $null
    }
}

function Get-ADOProjects {
    Write-Verbose "Retrieving projects from organization"

    try {
        $projectsUri = "$( $script:OrganizationUrl)/_apis/projects?api-version=7.1-preview.4"
        $projectsResponse = Invoke-ADORestApi -Uri $projectsUri
        if (-not $projectsResponse -or -not $projectsResponse.value) {
            Write-Verbose "Project query returned no results"
            return @()
        }

        return $projectsResponse.value | ForEach-Object {
            @{
                Id = $_.id
                Name = $_.name
                Description = $_.description
                State = $_.state
            }
        }
    }
    catch {
        Write-Error "Failed to retrieve projects: $_"
        return @()
    }
}

# Helper: Resolve and cache the Graph descriptor for a project (properties -> Graph fallback).
function Get-ProjectDescriptor {
    param([string]$ProjectId)

    if ([string]::IsNullOrWhiteSpace($ProjectId)) {
        return $null
    }

    if ($script:ProjectDescriptorCache.ContainsKey($ProjectId)) {
        return $script:ProjectDescriptorCache[$ProjectId]
    }

    $propertiesUri = "{0}/_apis/projects/{1}/properties?keys=System.TeamProjectDescriptor&api-version=7.1-preview.1" -f $script:OrganizationUrl, $ProjectId
    $propertiesResponse = Invoke-ADORestApi -Uri $propertiesUri
    if ($propertiesResponse -and $propertiesResponse.value) {
        $descriptorProperty = $propertiesResponse.value | Where-Object { $_.name -eq 'System.TeamProjectDescriptor' } | Select-Object -First 1
        if ($descriptorProperty -and $descriptorProperty.value) {
            $script:ProjectDescriptorCache[$ProjectId] = $descriptorProperty.value
            return $script:ProjectDescriptorCache[$ProjectId]
        }
    }

    Write-Verbose "Descriptor not found via project properties for $ProjectId. Attempting Graph descriptor lookup."
    $encodedProjectId = [System.Uri]::EscapeDataString($ProjectId)
    $descriptorUri = "{0}/_apis/graph/descriptors/{1}?api-version=7.1-preview.1" -f $script:VssApiUrl, $encodedProjectId
    $descriptorResponse = Invoke-ADORestApi -Uri $descriptorUri -RetryCount 0
    if ($descriptorResponse -and $descriptorResponse.value) {
        $script:ProjectDescriptorCache[$ProjectId] = $descriptorResponse.value
        return $script:ProjectDescriptorCache[$ProjectId]
    }

    Write-Verbose "Unable to resolve descriptor for project $ProjectId"
    return $null
}


# Helper: Return project-scoped Graph groups using the shared descriptor lookup.
function Get-ProjectSecurityGroups {
    param([string]$ProjectId)

    Write-Verbose "Getting security groups for project: $ProjectId"

    if ([string]::IsNullOrWhiteSpace($ProjectId)) {
        return @()
    }

    try {
        $descriptorValue = Get-ProjectDescriptor -ProjectId $ProjectId
        if (-not $descriptorValue) {
            return @()
        }

        $encodedDescriptor = [System.Uri]::EscapeDataString($descriptorValue)
        $groupsUri = "{0}/_apis/graph/groups?scopeDescriptor={1}&api-version=7.1-preview.1" -f $script:VssApiUrl, $encodedDescriptor
        $groupsResponse = Invoke-ADORestApi -Uri $groupsUri

        if (-not $groupsResponse -or -not $groupsResponse.value) {
            return @()
        }

        return $groupsResponse.value | ForEach-Object {
            @{
                Descriptor    = $_.descriptor
                DisplayName   = $_.displayName
                Description   = $_.description
                PrincipalName = $_.principalName
            }
        }
    }
    catch {
        Write-Verbose "Failed to get security groups for project ${ProjectId}: $_"
        return @()
    }
}

# Helper: Provide all acceptable naming patterns for Project Administrators groups.
function Get-AdminGroupNameCandidates {
    param([string]$ProjectName)

    $trimmedName = if ($null -eq $ProjectName) { '' } else { $ProjectName.Trim() }
    return @(
        "[$trimmedName]\\Project Administrators",
        "$trimmedName Project Administrators",
        'Project Administrators'
    )
}

# Utility: Find the Project Administrators group for a project using robust matching.
function Get-ProjectAdministratorsGroup {
    param([string]$ProjectId, [string]$ProjectName)

    $groups = Get-ProjectSecurityGroups -ProjectId $ProjectId

    Write-Verbose "Searching for Project Administrators group in project: $ProjectName"
    Write-Verbose "Found $($groups.Count) security groups in project"

    if ($groups.Count -gt 0) {
        $groupNames = $groups | ForEach-Object { $_.DisplayName }
        Write-Verbose "Available groups: $($groupNames -join ', ')"
    }

    $candidates = Get-AdminGroupNameCandidates -ProjectName $ProjectName
    $adminGroup = $groups | Where-Object { $candidates -contains $_.DisplayName }

    if (-not $adminGroup) {
        $candidateSet = $candidates | ForEach-Object { $_.Trim().ToLowerInvariant() }
        $adminGroup = $groups | Where-Object { $candidateSet -contains $_.DisplayName.Trim().ToLowerInvariant() }
    }

    if (-not $adminGroup) {
        Write-Verbose "Standard name match failed, attempting contains/principal match"
        $comparisonName = $ProjectName.Trim()
        $adminGroup = $groups | Where-Object {
            $_.DisplayName -like "*Project Administrators*" -and (
                $_.DisplayName -like "*$comparisonName*" -or $_.PrincipalName -like "*$comparisonName*" -or $_.PrincipalName -eq 'Project Administrators'
            )
        }
    }

    if (-not $adminGroup) {
        $comparisonName = $ProjectName.Trim()
        $adminGroup = $groups | Where-Object {
            $_.PrincipalName -eq "[$comparisonName]\\Project Administrators" -or $_.PrincipalName -eq 'Project Administrators'
        }
    }

    if ($adminGroup) {
        Write-Verbose "Found Project Administrators group: $($adminGroup.DisplayName) (Descriptor: $($adminGroup.Descriptor))"
    }
    else {
        Write-Verbose "Could not find Project Administrators group for project: $ProjectName"
    }

    return $adminGroup
}

# Utility: Confirm membership via direct lookup first, then breadth-first nested group walk.
function Test-GroupMembership {
    param(
        [string]$UserDescriptor,
        [string]$GroupDescriptor
    )

    Write-Verbose "=== Starting membership check ==="
    Write-Verbose "User Descriptor: $UserDescriptor"
    Write-Verbose "Group Descriptor: $GroupDescriptor"

    if ([string]::IsNullOrWhiteSpace($UserDescriptor) -or [string]::IsNullOrWhiteSpace($GroupDescriptor)) {
        Write-Verbose "Empty descriptor provided - returning false"
        return $false
    }

    if (-not $script:Headers) {
        Write-Verbose "Headers not initialized; cannot query membership"
        return $false
    }

    try {
        $encodedUser = [System.Uri]::EscapeDataString($UserDescriptor)
        $groupsToProcess = [System.Collections.Generic.Queue[string]]::new()
        $visitedGroups = [System.Collections.Generic.HashSet[string]]::new()
        $enqueuedGroups = [System.Collections.Generic.HashSet[string]]::new()

        $groupsToProcess.Enqueue($GroupDescriptor)
        $enqueuedGroups.Add($GroupDescriptor) | Out-Null

        while ($groupsToProcess.Count -gt 0) {
            $currentGroup = $groupsToProcess.Dequeue()
            if (-not $visitedGroups.Add($currentGroup)) {
                Write-Verbose "Group $currentGroup already processed"
                continue
            }

            $encodedGroup = [System.Uri]::EscapeDataString($currentGroup)
            $membershipUri = "{0}/_apis/graph/memberships/{1}/{2}?api-version=7.1-preview.1" -f $script:VssApiUrl, $encodedUser, $encodedGroup
            Write-Verbose "Direct membership URI: $membershipUri"
            $directResponse = Invoke-ADORestApi -Uri $membershipUri -RetryCount 0
            if ($directResponse) {
                Write-Verbose "Direct membership lookup succeeded for group $currentGroup"
                return $true
            }

            Write-Verbose "Direct membership lookup returned no match for group $currentGroup. Enumerating members..."

            $membersBaseUri = "{0}/_apis/graph/groups/{1}/members?api-version=7.1-preview.1" -f $script:VssApiUrl, $encodedGroup
            $continuationToken = $null

            do {
                $requestUri = $membersBaseUri
                if ($continuationToken) {
                    $encodedToken = [System.Uri]::EscapeDataString($continuationToken)
                    $requestUri = "$membersBaseUri&continuationToken=$encodedToken"
                }

                Write-Verbose "Enumerating group members via: $requestUri"

                $headers = @{}
                foreach ($key in $script:Headers.Keys) {
                    $headers[$key] = $script:Headers[$key]
                }
                $headers['Accept'] = 'application/json'

                $webResponse = Invoke-WebRequest -Uri $requestUri -Headers $headers -Method Get -TimeoutSec 30 -SkipHttpErrorCheck
                if (-not $webResponse -or -not $webResponse.Content) {
                    Write-Verbose "Group membership request returned no content for group $currentGroup"
                    break
                }

                # Check if response is successful before parsing as JSON
                if ($webResponse.StatusCode -lt 200 -or $webResponse.StatusCode -ge 300) {
                    Write-Verbose "Group membership request returned status code $($webResponse.StatusCode) for group $currentGroup"
                    break
                }

                # Verify content type is JSON
                $contentType = $webResponse.Headers['Content-Type']
                if ($contentType -and $contentType -notmatch 'application/json') {
                    Write-Verbose "Group membership request returned non-JSON content type: $contentType"
                    break
                }

                $body = $webResponse.Content | ConvertFrom-Json -Depth 10
                $pageCount = if ($body -and $body.value) { $body.value.Count } else { 0 }
                Write-Verbose "Retrieved $pageCount member records in current page for group $currentGroup"

                if ($body -and $body.value) {
                    foreach ($member in $body.value) {
                        if ($member.descriptor -eq $UserDescriptor) {
                            Write-Verbose "User descriptor found within group $currentGroup"
                            return $true
                        }

                        if ($member.subjectKind -eq 'Group' -and $member.descriptor) {
                            if (-not $visitedGroups.Contains($member.descriptor) -and -not $enqueuedGroups.Contains($member.descriptor)) {
                                Write-Verbose "Queueing nested group $($member.descriptor) for membership evaluation"
                                $groupsToProcess.Enqueue($member.descriptor)
                                $enqueuedGroups.Add($member.descriptor) | Out-Null
                            }
                        }
                    }
                }

                $continuationHeader = $webResponse.Headers['x-ms-continuationtoken']
                if ($continuationHeader) {
                    $continuationToken = if ($continuationHeader -is [System.Array]) { $continuationHeader[0] } else { $continuationHeader }
                    Write-Verbose "Continuation token detected for group $currentGroup, fetching next page"
                }
                else {
                    $continuationToken = $null
                }
            } while ($continuationToken)
        }

        Write-Verbose "User descriptor not found after evaluating nested group memberships"
        return $false
    }
    catch {
        Write-Verbose "Failed to check group membership: $_"
        return $false
    }
}

function Add-ADOUserToGroup {
    param(
        [string]$UserDescriptor,
        [string]$GroupDescriptor,
        [string]$ProjectName,
        [string]$GroupName,
        [string]$UserEmail,
        [switch]$DryRun
    )

    if ($DryRun) {
        Write-Host "[+] Would add $UserEmail to $GroupName in $ProjectName" -ForegroundColor Yellow
        return $true
    }

    try {
        # Add verbose logging to debug descriptor values
        Write-Verbose "Add-ADOUserToGroup: UserDescriptor=$UserDescriptor"
        Write-Verbose "Add-ADOUserToGroup: GroupDescriptor=$GroupDescriptor"

        # Use concatenation to avoid PowerShell 7 ternary operator conflict with ?
        # Graph Memberships API requires preview version
        $membershipUri = "$($script:VssApiUrl)/_apis/graph/memberships/$UserDescriptor/${GroupDescriptor}" + "?api-version=7.1-preview.1"
        $response = Invoke-ADORestApi -Uri $membershipUri -Method "PUT"

        if ($response) {
            Write-Host "✓ Added $UserEmail to $GroupName in $ProjectName" -ForegroundColor Green
            Write-AuditLog -Action "Add User" -User $UserEmail -Project $ProjectName -Group $GroupName -Result "Success"
            return $true
        }
        else {
            Write-Host "✗ Failed to add $UserEmail to $GroupName in $ProjectName" -ForegroundColor Red
            Write-AuditLog -Action "Add User" -User $UserEmail -Project $ProjectName -Group $GroupName -Result "Failed - API error"
            return $false
        }
    }
    catch {
        Write-Host "✗ Error adding $UserEmail to $GroupName in $ProjectName`: $_" -ForegroundColor Red
        Write-AuditLog -Action "Add User" -User $UserEmail -Project $ProjectName -Group $GroupName -Result "Failed - $($_.Exception.Message)"
        return $false
    }
}

function Remove-ADOUserFromGroup {
    param(
        [string]$UserDescriptor,
        [string]$GroupDescriptor,
        [string]$ProjectName,
        [string]$GroupName,
        [string]$UserEmail,
        [switch]$DryRun
    )

    if ($DryRun) {
        Write-Host "[-] Would remove $UserEmail from $GroupName in $ProjectName" -ForegroundColor Yellow
        return $true
    }

    try {
        $membershipUri = "$($script:VssApiUrl)/_apis/graph/memberships/$UserDescriptor/$GroupDescriptor?api-version=7.0"
        $response = Invoke-ADORestApi -Uri $membershipUri -Method "DELETE"

        Write-Host "✓ Removed $UserEmail from $GroupName in $ProjectName" -ForegroundColor Green
        Write-AuditLog -Action "Remove User" -User $UserEmail -Project $ProjectName -Group $GroupName -Result "Success"
        return $true
    }
    catch {
        Write-Host "✗ Error removing $UserEmail from $GroupName in $ProjectName`: $_" -ForegroundColor Red
        Write-AuditLog -Action "Remove User" -User $UserEmail -Project $ProjectName -Group $GroupName -Result "Failed - $($_.Exception.Message)"
        return $false
    }
}

function Show-InteractiveMenu {
    Clear-Host
    Write-Host "===========================================" -ForegroundColor Cyan
    Write-Host "Azure DevOps User Security Management" -ForegroundColor Cyan
    Write-Host "===========================================" -ForegroundColor Cyan
    Write-Host "Organization: tpsapps" -ForegroundColor White
    Write-Host ""
    Write-Host "Please select an option:" -ForegroundColor Yellow
    Write-Host "1. Find user's Project Administrator memberships" -ForegroundColor White
    Write-Host "2. Add user(s) to Project Administrators" -ForegroundColor White
    Write-Host "3. Remove user(s) from Project Administrators" -ForegroundColor White
    Write-Host "4. Manage other security groups" -ForegroundColor White
    Write-Host "5. Manage team memberships" -ForegroundColor White
    Write-Host "6. Batch operations (multiple users)" -ForegroundColor White
    Write-Host "0. Exit" -ForegroundColor White
    Write-Host ""

    do {
        $selection = Read-Host "Enter selection"
        if ($selection -match '^[0-6]$') {
            return [int]$selection
        }
        Write-Host "Invalid selection. Please enter 0-6." -ForegroundColor Red
    } while ($true)
}

function Test-EmailAddress {
    param([string]$Email)

    if ([string]::IsNullOrWhiteSpace($Email)) {
        return $false
    }

    # Comprehensive email validation regex (RFC-compliant)
    $emailRegex = '^[a-zA-Z0-9.!#$%&''*+/=?^_`{|}~-]+@[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?(?:\.[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)*$'
    return $Email -match $emailRegex
}

function Get-UserEmails {
    param([string]$UserEmailInput)

    if (-not $UserEmailInput) {
        return @()
    }

    # Split by comma and trim whitespace
    $emails = $UserEmailInput -split ',' | ForEach-Object { $_.Trim() }
    $validEmails = @()

    foreach ($email in $emails) {
        if ($email -ne '') {
            if (Test-EmailAddress -Email $email) {
                $validEmails += $email
            } else {
                Write-Warning "Invalid email format: $email"
            }
        }
    }

    return $validEmails
}

function Get-ProjectSelection {
    param(
        [array]$Projects,
        [string]$ProjectsInput = $null
    )

    if ($ProjectsInput) {
        # Command line mode - parse project names
        $selectedProjectNames = $ProjectsInput -split ',' | ForEach-Object { $_.Trim() }
        $selectedProjects = @()

        foreach ($name in $selectedProjectNames) {
            $project = $Projects | Where-Object { $_.Name -eq $name }
            if ($project) {
                $selectedProjects += $project
            }
            else {
                Write-Warning "Project '$name' not found"
            }
        }
        return $selectedProjects
    }

    # Interactive mode
    Write-Host "Available projects:" -ForegroundColor Yellow
    for ($i = 0; $i -lt $Projects.Count; $i++) {
        Write-Host "$($i + 1). $($Projects[$i].Name)" -ForegroundColor White
    }
    Write-Host ""

    do {
        $input = Read-Host "Enter project numbers (comma-separated, e.g., 1,3,5) or 'all' for all projects"

        if ($input.ToLower() -eq 'all') {
            return $Projects
        }

        try {
            $numbers = $input -split ',' | ForEach-Object { [int]$_.Trim() }
            $selectedProjects = @()

            foreach ($num in $numbers) {
                if ($num -ge 1 -and $num -le $Projects.Count) {
                    $selectedProjects += $Projects[$num - 1]
                }
                else {
                    throw "Invalid project number: $num"
                }
            }

            if ($selectedProjects.Count -gt 0) {
                return $selectedProjects
            }
        }
        catch {
            Write-Host "Invalid input. Please enter valid project numbers." -ForegroundColor Red
        }
    } while ($true)
}

function Show-PreviewAndConfirm {
    param(
        [array]$Users,
        [array]$Projects,
        [string]$Action,
        [string]$GroupName = "Project Administrators",
        [switch]$DryRun,
        [switch]$SkipConfirmation
    )

    if ($DryRun) {
        Write-Host ""
        Write-Host "DRY RUN MODE - No changes will be made" -ForegroundColor Yellow
        Write-Host ""
    }

    Write-Host "The following changes would be applied:" -ForegroundColor Cyan
    Write-Host ""

    foreach ($user in $Users) {
        foreach ($project in $Projects) {
            $symbol = if ($Action -eq "Add") { "[+]" } else { "[-]" }
            $color = if ($Action -eq "Add") { "Green" } else { "Red" }
            Write-Host "$symbol $Action $($user.MailAddress) $($Action.ToLower() -replace 'remove', 'from') $GroupName in $($project.Name)" -ForegroundColor $color
        }
    }

    Write-Host ""

    if ($DryRun) {
        Write-Host "To execute these changes, run again without -DryRun flag." -ForegroundColor Yellow
        return $false
    }

    if ($SkipConfirmation) {
        return $true
    }

    # Show appropriate confirmation prompt
    $userCount = $Users.Count
    $projectCount = $Projects.Count
    $totalOperations = $userCount * $projectCount

    if ($Action -eq "Add") {
        $confirmText = "Are you sure you want to add $userCount user(s) to $GroupName in $projectCount project(s)? (Total: $totalOperations operations) (Y/N)"
        $response = Read-Host $confirmText
    }
    else {
        Write-Host "WARNING: You are about to remove admin access!" -ForegroundColor Red
        $confirmText = "Are you sure you want to remove $userCount user(s) from $GroupName in $projectCount project(s)? This cannot be undone. (Y/N)"
        $response = Read-Host $confirmText
    }

    return $response.ToUpper() -eq 'Y'
}

# Mode Handlers
function Invoke-FindAdminMode {
    param(
        [string]$UserEmail,
        [string]$ProjectsFilter
    )

    if (-not $UserEmail) {
        $UserEmail = Read-Host "Enter user email address"
    }

    Write-Host "Finding Project Administrator memberships for: $UserEmail" -ForegroundColor Cyan
    Write-Host ""

    $user = Get-ADOUser -Email $UserEmail
    if (-not $user) {
        Write-Host "Error: User '$UserEmail' not found in Azure DevOps organization" -ForegroundColor Red
        return
    }

    $projects = Get-ADOProjects
    if ($ProjectsFilter) {
        $filterNames = $ProjectsFilter -split ',' | ForEach-Object { $_.Trim() } | Where-Object { $_ }
        if ($filterNames.Count -gt 0) {
            $filteredProjects = $projects | Where-Object { $filterNames -contains $_.Name }
            if ($filteredProjects.Count -eq 0) {
                Write-Host "Warning: None of the specified projects were found." -ForegroundColor Yellow
            }
            else {
                if ($filteredProjects.Count -lt $projects.Count) {
                    Write-Host "Filtering to $($filteredProjects.Count) project(s) per -Projects parameter." -ForegroundColor Gray
                }
                $projects = $filteredProjects
            }
        }
    }

    if (-not $projects -or $projects.Count -eq 0) {
        Write-Host "Error: Could not retrieve projects" -ForegroundColor Red
        return
    }

    Write-Host "Checking $($projects.Count) projects..." -ForegroundColor Yellow
    $adminProjects = @()

    foreach ($project in $projects) {
        $currentIndex = $projects.IndexOf($project)
        Write-Progress -Activity "Checking project memberships" -Status "Checking $($project.Name)" -PercentComplete (($currentIndex / $projects.Count) * 100)

        $adminGroup = Get-ProjectAdministratorsGroup -ProjectId $project.Id -ProjectName $project.Name
        if ($adminGroup) {
            $isMember = Test-GroupMembership -UserDescriptor $user.Descriptor -GroupDescriptor $adminGroup.Descriptor
            if ($isMember) {
                $adminProjects += $project.Name
            }
        }
    }

    Write-Progress -Completed -Activity "Checking project memberships"

    if ($adminProjects.Count -gt 0) {
        Write-Host "User: $UserEmail is Project Administrator in:" -ForegroundColor Green
        foreach ($projectName in $adminProjects) {
            Write-Host "- $projectName" -ForegroundColor White
        }
    }
    else {
        Write-Host "User: $UserEmail is not a Project Administrator in any projects." -ForegroundColor Yellow
    }

    Write-AuditLog -Action "Find Admin" -User $UserEmail -Project "Multiple" -Group "Project Administrators" -Result "Found in $($adminProjects.Count) projects"
}

function Invoke-AddAdminMode {
    param(
        [string]$UserEmailInput,
        [string]$ProjectsInput
    )

    # Get user emails
    if (-not $UserEmailInput) {
        $UserEmailInput = Read-Host "Enter user email address(es) (comma-separated)"
    }

    $userEmails = Get-UserEmails -UserEmailInput $UserEmailInput
    if ($userEmails.Count -eq 0) {
        Write-Host "No valid user emails provided" -ForegroundColor Red
        return
    }

    Write-Host "Adding users to Project Administrators..." -ForegroundColor Cyan
    Write-Host ""

    # Validate all users first
    $validUsers = @()
    foreach ($email in $userEmails) {
        $user = Get-ADOUser -Email $email
        if ($user) {
            $validUsers += $user
            Write-Host "✓ Found user: $($user.DisplayName) ($($user.MailAddress))" -ForegroundColor Green
        }
        else {
            Write-Host "✗ User not found: $email" -ForegroundColor Red
        }
    }

    if ($validUsers.Count -eq 0) {
        Write-Host "No valid users found. Exiting." -ForegroundColor Red
        return
    }

    # Get all projects
    $allProjects = Get-ADOProjects
    if (-not $allProjects) {
        Write-Host "Error: Could not retrieve projects" -ForegroundColor Red
        return
    }

    # Get project selection
    $selectedProjects = Get-ProjectSelection -Projects $allProjects -ProjectsInput $ProjectsInput

    if ($selectedProjects.Count -eq 0) {
        Write-Host "No projects selected. Exiting." -ForegroundColor Red
        return
    }

    # Show preview and get confirmation
    $skipConfirmation = $script:Confirm -eq $false
    $proceed = Show-PreviewAndConfirm -Users $validUsers -Projects $selectedProjects -Action "Add" -DryRun:$DryRun -SkipConfirmation:$skipConfirmation

    if (-not $proceed) {
        return
    }

    # Execute the changes
    $successCount = 0
    $totalOperations = $validUsers.Count * $selectedProjects.Count

    Write-Host "Executing changes..." -ForegroundColor Yellow
    Write-Host ""

    foreach ($user in $validUsers) {
        foreach ($project in $selectedProjects) {
            Write-Progress -Activity "Adding users to Project Administrators" -Status "Processing $($user.MailAddress) in $($project.Name)" -PercentComplete (($successCount / $totalOperations) * 100)

            $adminGroup = Get-ProjectAdministratorsGroup -ProjectId $project.Id -ProjectName $project.Name
            if ($adminGroup) {
                # Check if user is already a member
                $isMember = Test-GroupMembership -UserDescriptor $user.Descriptor -GroupDescriptor $adminGroup.Descriptor
                if ($isMember) {
                    Write-Host "⚠ $($user.MailAddress) is already a Project Administrator in $($project.Name)" -ForegroundColor Yellow
                    Write-AuditLog -Action "Add User" -User $user.MailAddress -Project $project.Name -Group "Project Administrators" -Result "Already member"
                }
                else {
                    $success = Add-ADOUserToGroup -UserDescriptor $user.Descriptor -GroupDescriptor $adminGroup.Descriptor -ProjectName $project.Name -GroupName "Project Administrators" -UserEmail $user.MailAddress -DryRun:$DryRun
                    if ($success) {
                        $successCount++
                    }
                }
            }
            else {
                Write-Host "✗ Could not find Project Administrators group in $($project.Name)" -ForegroundColor Red
                Write-AuditLog -Action "Add User" -User $user.MailAddress -Project $project.Name -Group "Project Administrators" -Result "Failed - Group not found"
            }
        }
    }

    Write-Progress -Completed -Activity "Adding users to Project Administrators"
    Write-Host ""
    Write-Host "Operation completed. Successfully processed $successCount out of $totalOperations operations." -ForegroundColor Green
}

function Invoke-RemoveAdminMode {
    param(
        [string]$UserEmailInput,
        [string]$ProjectsInput
    )

    # Get user emails
    if (-not $UserEmailInput) {
        $UserEmailInput = Read-Host "Enter user email address(es) (comma-separated)"
    }

    $userEmails = Get-UserEmails -UserEmailInput $UserEmailInput
    if ($userEmails.Count -eq 0) {
        Write-Host "No valid user emails provided" -ForegroundColor Red
        return
    }

    Write-Host "Removing users from Project Administrators..." -ForegroundColor Cyan
    Write-Host ""

    # Validate all users first
    $validUsers = @()
    foreach ($email in $userEmails) {
        $user = Get-ADOUser -Email $email
        if ($user) {
            $validUsers += $user
            Write-Host "✓ Found user: $($user.DisplayName) ($($user.MailAddress))" -ForegroundColor Green
        }
        else {
            Write-Host "✗ User not found: $email" -ForegroundColor Red
        }
    }

    if ($validUsers.Count -eq 0) {
        Write-Host "No valid users found. Exiting." -ForegroundColor Red
        return
    }

    # Get all projects
    $allProjects = Get-ADOProjects
    if (-not $allProjects) {
        Write-Host "Error: Could not retrieve projects" -ForegroundColor Red
        return
    }

    # If no specific projects provided, find where users are currently admins
    if (-not $ProjectsInput -and -not $script:Projects) {
        Write-Host "Finding projects where users are currently Project Administrators..." -ForegroundColor Yellow

        $adminProjects = @()
        foreach ($user in $validUsers) {
            foreach ($project in $allProjects) {
                $adminGroup = Get-ProjectAdministratorsGroup -ProjectId $project.Id -ProjectName $project.Name
                if ($adminGroup) {
                    $isMember = Test-GroupMembership -UserDescriptor $user.Descriptor -GroupDescriptor $adminGroup.Descriptor
                    if ($isMember -and ($adminProjects | Where-Object { $_.Id -eq $project.Id }) -eq $null) {
                        $adminProjects += $project
                    }
                }
            }
        }

        if ($adminProjects.Count -eq 0) {
            Write-Host "Users are not Project Administrators in any projects." -ForegroundColor Yellow
            return
        }

        Write-Host ""
        Write-Host "Found admin access in the following projects:" -ForegroundColor Yellow
        foreach ($project in $adminProjects) {
            Write-Host "- $($project.Name)" -ForegroundColor White
        }
        Write-Host ""

        $selectedProjects = Get-ProjectSelection -Projects $adminProjects
    }
    else {
        $selectedProjects = Get-ProjectSelection -Projects $allProjects -ProjectsInput $ProjectsInput
    }

    if ($selectedProjects.Count -eq 0) {
        Write-Host "No projects selected. Exiting." -ForegroundColor Red
        return
    }

    # Show preview and get confirmation
    $skipConfirmation = $script:Confirm -eq $false
    $proceed = Show-PreviewAndConfirm -Users $validUsers -Projects $selectedProjects -Action "Remove" -DryRun:$DryRun -SkipConfirmation:$skipConfirmation

    if (-not $proceed) {
        return
    }

    # Execute the changes
    $successCount = 0
    $totalOperations = $validUsers.Count * $selectedProjects.Count

    Write-Host "Executing changes..." -ForegroundColor Yellow
    Write-Host ""

    foreach ($user in $validUsers) {
        foreach ($project in $selectedProjects) {
            Write-Progress -Activity "Removing users from Project Administrators" -Status "Processing $($user.MailAddress) in $($project.Name)" -PercentComplete (($successCount / $totalOperations) * 100)

            $adminGroup = Get-ProjectAdministratorsGroup -ProjectId $project.Id -ProjectName $project.Name
            if ($adminGroup) {
                # Check if user is actually a member
                $isMember = Test-GroupMembership -UserDescriptor $user.Descriptor -GroupDescriptor $adminGroup.Descriptor
                if (-not $isMember) {
                    Write-Host "⚠ $($user.MailAddress) is not a Project Administrator in $($project.Name)" -ForegroundColor Yellow
                    Write-AuditLog -Action "Remove User" -User $user.MailAddress -Project $project.Name -Group "Project Administrators" -Result "Not a member"
                }
                else {
                    $success = Remove-ADOUserFromGroup -UserDescriptor $user.Descriptor -GroupDescriptor $adminGroup.Descriptor -ProjectName $project.Name -GroupName "Project Administrators" -UserEmail $user.MailAddress -DryRun:$DryRun
                    if ($success) {
                        $successCount++
                    }
                }
            }
            else {
                Write-Host "✗ Could not find Project Administrators group in $($project.Name)" -ForegroundColor Red
                Write-AuditLog -Action "Remove User" -User $user.MailAddress -Project $project.Name -Group "Project Administrators" -Result "Failed - Group not found"
            }
        }
    }

    Write-Progress -Completed -Activity "Removing users from Project Administrators"
    Write-Host ""
    Write-Host "Operation completed. Successfully processed $successCount out of $totalOperations operations." -ForegroundColor Green
}

function Test-ScriptParameters {
    # Validate Mode parameter
    if ($Mode) {
        $validModes = @("FindAdmin", "AddAdmin", "RemoveAdmin", "ManageGroups", "ManageTeams", "BatchOps")
        if ($Mode -notin $validModes) {
            Write-Error "Invalid mode: $Mode. Valid modes: $($validModes -join ', ')"
            return $false
        }
    }

    # Validate UserEmail parameter
    if ($UserEmail -and -not (Test-EmailAddress -Email $UserEmail)) {
        Write-Error "Invalid email format: $UserEmail"
        return $false
    }

    # Validate UserEmails parameter
    if ($UserEmails) {
        $emails = Get-UserEmails -UserEmailInput $UserEmails
        if ($emails.Count -eq 0) {
            Write-Error "No valid email addresses found in: $UserEmails"
            return $false
        }
    }

    # Validate conflicting parameters
    if ($UserEmail -and $UserEmails) {
        Write-Error "Cannot specify both UserEmail and UserEmails parameters"
        return $false
    }

    return $true
}

# Main execution
function Main {
    Write-Host "Azure DevOps User Security Management Tool" -ForegroundColor Cyan
    Write-Host "=========================================" -ForegroundColor Cyan
    Write-Host ""

    # Validate parameters
    if (-not (Test-ScriptParameters)) {
        Write-Host "Parameter validation failed. Exiting." -ForegroundColor Red
        exit 1
    }

    # Initialize logging
    try {
        Initialize-AuditLogging
    }
    catch {
        Write-Warning "Failed to initialize audit logging: $_"
        Write-Warning "Continuing without audit logging..."
    }

    # Check prerequisites
    if (-not (Test-Prerequisites)) {
        Write-Host "Prerequisites check failed. Exiting." -ForegroundColor Red
        Write-AuditLog -Action "Error" -User $env:USERNAME -Project "N/A" -Group "N/A" -Result "Prerequisites check failed"
        exit 1
    }

    # Initialize authentication
    if (-not (Initialize-Authentication)) {
        Write-Host "Authentication failed. Exiting." -ForegroundColor Red
        Write-AuditLog -Action "Error" -User $env:USERNAME -Project "N/A" -Group "N/A" -Result "Authentication failed"
        exit 1
    }

    Write-Host ""
    Write-Host "Audit log: $script:LogFile" -ForegroundColor Gray
    Write-Host ""

    # Handle automation mode
    if ($Mode) {
        switch ($Mode) {
            "FindAdmin" {
                Invoke-FindAdminMode -UserEmail $UserEmail -ProjectsFilter $Projects
            }
            "AddAdmin" {
                $emailInput = if ($UserEmail) { $UserEmail } elseif ($UserEmails) { $UserEmails } else { $null }
                Invoke-AddAdminMode -UserEmailInput $emailInput -ProjectsInput $Projects
            }
            "RemoveAdmin" {
                $emailInput = if ($UserEmail) { $UserEmail } elseif ($UserEmails) { $UserEmails } else { $null }
                Invoke-RemoveAdminMode -UserEmailInput $emailInput -ProjectsInput $Projects
            }
            "ManageGroups" {
                Write-Host "ManageGroups mode - Coming soon" -ForegroundColor Yellow
            }
            "ManageTeams" {
                Write-Host "ManageTeams mode - Coming soon" -ForegroundColor Yellow
            }
            "BatchOps" {
                Write-Host "BatchOps mode - Coming soon" -ForegroundColor Yellow
            }
            default {
                Write-Host "Invalid mode: $Mode" -ForegroundColor Red
                Write-Host "Valid modes: FindAdmin, AddAdmin, RemoveAdmin, ManageGroups, ManageTeams, BatchOps" -ForegroundColor Yellow
            }
        }
        return
    }

    # Interactive mode
    do {
        $selection = Show-InteractiveMenu

        switch ($selection) {
            1 { Invoke-FindAdminMode }
            2 { Invoke-AddAdminMode }
            3 { Invoke-RemoveAdminMode }
            4 { Write-Host "Manage groups mode - Coming soon" -ForegroundColor Yellow }
            5 { Write-Host "Manage teams mode - Coming soon" -ForegroundColor Yellow }
            6 { Write-Host "Batch operations mode - Coming soon" -ForegroundColor Yellow }
            0 {
                Write-Host "Goodbye!" -ForegroundColor Green
                Write-AuditLog -Action "Session End" -User $env:USERNAME -Project "N/A" -Group "N/A" -Result "Script completed"
                exit 0
            }
        }

        if ($selection -ne 0) {
            Write-Host ""
            Read-Host "Press Enter to continue"
        }
    } while ($selection -ne 0)
}

# Run the main function
if ($MyInvocation.InvocationName -ne '.') {
    Main
}


