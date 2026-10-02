<#
.SYNOPSIS
Prepares read-only Microsoft 365 access for ai-security-scanner.

.DESCRIPTION
Run it as a Global Administrator of the tenant you want to scan:

    powershell -ExecutionPolicy Bypass -File .\microsoft365-read-only.ps1

You sign in on Microsoft's own page through the Microsoft Graph PowerShell SDK,
so this script never sees your password. It makes sure the tenant has a
single-tenant app registration named ai-security-scanner that allows public
client flows, asks only for the Microsoft Graph delegated sign-in and read
permissions the scan uses, and has admin consent for them. It then prints the two IDs for step 2
of the app's connection guide and saves them as a setup file the app can import.

Running it again adds only what is missing. It never removes or replaces
anything; when something is in the way, it stops and says what to change.

.PARAMETER TenantId
The tenant to prepare. Leave it out to use the tenant you sign in to.

.PARAMETER UseDeviceCode
Sign in with a code on another device, for a shell that cannot open a browser.
On Windows the script always signs in this way, so Windows does not offer to
let the organization manage the computer.
#>
[CmdletBinding()]
param(
    [ValidatePattern('^$|^[0-9a-fA-F]{8}-([0-9a-fA-F]{4}-){3}[0-9a-fA-F]{12}$')]
    [string] $TenantId = '',
    [switch] $UseDeviceCode
)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version 2.0

$AppName = 'ai-security-scanner'
$GraphAppId = '00000003-0000-0000-c000-000000000000'
$SetupFile = 'ai-security-scanner-microsoft365-setup.json'
# The Microsoft Graph delegated permissions the Microsoft 365 sign-in verifies.
$ReadPermissions = @(
    'AdministrativeUnit.Read.All'
    'Application.Read.All'
    'AuditLog.Read.All'
    'Directory.Read.All'
    'Domain.Read.All'
    'Group.Read.All'
    'IdentityRiskEvent.Read.All'
    'Organization.Read.All'
    'Policy.Read.All'
    'PrivilegedAccess.Read.AzureADGroup'
    'PrivilegedEligibilitySchedule.Read.AzureADGroup'
    'Reports.Read.All'
    'RoleManagement.Read.Directory'
    'RoleManagementPolicy.Read.AzureADGroup'
    'RoleManagementPolicy.Read.Directory'
    'SecurityEvents.Read.All'
    'User.Read.All'
)
# The sign-in also asks for these OpenID Connect permissions, which reach no
# tenant data. With consent for them too, no user is stopped for approval.
$SignInPermissions = @('openid', 'profile', 'offline_access')
$AppPermissions = @($SignInPermissions + $ReadPermissions)
# What this script signs in with to register the app and grant consent.
$SetupScopes = @('Application.ReadWrite.All', 'DelegatedPermissionGrant.ReadWrite.All')

function Stop-Setup([string] $Reason) {
    throw $Reason
}

# The scanner refuses to sign in when its token holds a permission like these.
function Test-WritePermission([string] $Name) {
    $lower = $Name.ToLowerInvariant()
    return $lower.Contains('readwrite') -or $lower.EndsWith('.write') -or
        $lower.EndsWith('.write.all') -or $lower.Contains('accessasuser')
}

function Invoke-Graph([string] $Method, [string] $Uri, $Body = $null) {
    $request = @{ Method = $Method; Uri = $Uri; OutputType = 'HashTable' }
    if ($null -ne $Body) {
        $request['Body'] = ConvertTo-Json -InputObject $Body -Depth 10 -Compress
        $request['ContentType'] = 'application/json'
    }
    Invoke-MgGraphRequest @request
}

function Get-GraphList([string] $Uri) {
    while ($Uri) {
        $page = Invoke-Graph GET $Uri
        foreach ($item in @($page['value'])) {
            if ($null -ne $item) { $item }
        }
        $Uri = $page['@odata.nextLink']
    }
}

function Get-Filter([string] $Expression) {
    '$filter=' + [uri]::EscapeDataString($Expression)
}

function Split-Scope($Scope) {
    @(([string] $Scope) -split '\s+' | Where-Object { $_ })
}

function Connect-Tenant {
    $installed = Get-Module -ListAvailable -Name Microsoft.Graph.Authentication |
        Where-Object { $_.Version -ge [version] '2.0.0' }
    if (-not $installed) {
        Write-Host 'Installing the Microsoft Graph PowerShell sign-in module for your user account...'
        if ($PSVersionTable.PSEdition -ne 'Core') {
            [Net.ServicePointManager]::SecurityProtocol = [Net.ServicePointManager]::SecurityProtocol -bor [Net.SecurityProtocolType]::Tls12
        }
        Install-Module -Name Microsoft.Graph.Authentication -MinimumVersion 2.0.0 -Scope CurrentUser -Repository PSGallery
    }
    Import-Module Microsoft.Graph.Authentication -MinimumVersion 2.0.0

    $connect = @{ Scopes = $SetupScopes; ContextScope = 'Process'; NoWelcome = $true }
    if ($TenantId) { $connect['TenantId'] = $TenantId }
    # On Windows, the Microsoft Graph sign-in window belongs to Windows itself,
    # and it offers to add the account to Windows and let the organization manage
    # the computer. A sign-in with a one-time code stays in the browser.
    $onWindows = [Environment]::OSVersion.Platform -eq [PlatformID]::Win32NT
    if ($UseDeviceCode -or $onWindows -or "$env:AZUREPS_HOST_ENVIRONMENT" -like 'cloud-shell*') { $connect['UseDeviceCode'] = $true }
    Write-Host "Sign in on Microsoft's page as a Global Administrator of the tenant to scan."
    # Connect-MgGraph writes the one-time code and its page to its output, not
    # to the console, so discarding that output hid the code and the sign-in
    # timed out. Show it, and keep it out of what this function returns.
    Connect-MgGraph @connect | ForEach-Object { Write-Host $_ }
    $context = Get-MgContext
    if (-not $context -or -not $context.TenantId) { Stop-Setup 'the Microsoft sign-in did not finish.' }
    return [string] $context.TenantId
}

function Set-ReadOnlyApp {
    $graph = Invoke-Graph GET "/v1.0/servicePrincipals(appId='$GraphAppId')?`$select=id,oauth2PermissionScopes"
    $scopeIds = @{}
    $scopeNames = @{}
    foreach ($scope in @($graph['oauth2PermissionScopes'])) {
        $scopeIds[$scope['value']] = $scope['id']
        $scopeNames[$scope['id']] = $scope['value']
    }
    foreach ($name in $AppPermissions) {
        if (-not $scopeIds.ContainsKey($name)) { Stop-Setup "Microsoft Graph in this tenant does not offer the permission $name." }
    }

    # 1. The app registration.
    $apps = @(Get-GraphList ("/v1.0/applications?" + (Get-Filter "displayName eq '$AppName'") +
            '&$select=id,appId,isFallbackPublicClient,requiredResourceAccess'))
    if ($apps.Count -gt 1) {
        Stop-Setup "this tenant has $($apps.Count) app registrations named $AppName. Rename or delete the ones you do not use, then run this script again."
    }
    if ($apps.Count -eq 0) {
        $app = Invoke-Graph POST '/v1.0/applications' @{
            displayName            = $AppName
            signInAudience         = 'AzureADMyOrg'
            isFallbackPublicClient = $true
            requiredResourceAccess = @(@{
                    resourceAppId  = $GraphAppId
                    resourceAccess = @($AppPermissions | ForEach-Object { @{ id = $scopeIds[$_]; type = 'Scope' } })
                })
        }
        Write-Host "Registered the app $AppName with public client flows and its Microsoft Graph sign-in and read permissions."
    } else {
        $app = $apps[0]
        $changed = $false
        $resources = @($app['requiredResourceAccess'] | Where-Object { $null -ne $_ })
        $graphAccess = @($resources | Where-Object { $_['resourceAppId'] -eq $GraphAppId } |
            ForEach-Object { @($_['resourceAccess']) } | Where-Object { $null -ne $_ })
        $requested = @($graphAccess | Where-Object { $_['type'] -eq 'Scope' } |
            ForEach-Object { $scopeNames[$_['id']] } | Where-Object { $_ })
        $writes = @($requested | Where-Object { Test-WritePermission $_ })
        if ($writes.Count) {
            Stop-Setup "the app $AppName also asks for $($writes -join ', '), which can change your tenant, so the scanner would refuse to sign in. In the Microsoft Entra admin center, open App registrations, then $AppName, then API permissions, and remove them. Then run this script again."
        }
        if (-not $app['isFallbackPublicClient']) {
            Invoke-Graph PATCH "/v1.0/applications/$($app['id'])" @{ isFallbackPublicClient = $true } | Out-Null
            Write-Host "Turned on public client flows for $AppName."
            $changed = $true
        }
        $missing = @($AppPermissions | Where-Object { $requested -notcontains $_ })
        if ($missing.Count) {
            $access = @($graphAccess | ForEach-Object { @{ id = $_['id']; type = $_['type'] } }) +
                @($missing | ForEach-Object { @{ id = $scopeIds[$_]; type = 'Scope' } })
            $updated = @($resources | Where-Object { $_['resourceAppId'] -ne $GraphAppId }) +
                @(@{ resourceAppId = $GraphAppId; resourceAccess = $access })
            Invoke-Graph PATCH "/v1.0/applications/$($app['id'])" @{ requiredResourceAccess = $updated } | Out-Null
            Write-Host "Added $($missing -join ', ') to $AppName."
            $changed = $true
        }
        if (-not $changed) { Write-Host "The app $AppName is already in place." }
    }
    $appId = [string] $app['appId']

    # 2. The app's service principal. A new app registration takes a few
    # seconds to reach every Microsoft Entra replica, so creating it may retry.
    $principal = @(Get-GraphList ("/v1.0/servicePrincipals?" + (Get-Filter "appId eq '$appId'") + '&$select=id,appId')) |
        Select-Object -First 1
    for ($attempt = 1; -not $principal; $attempt++) {
        try {
            $principal = Invoke-Graph POST '/v1.0/servicePrincipals' @{ appId = $appId }
        } catch {
            if ($attempt -ge 10) { throw }
            Start-Sleep -Seconds 3
        }
    }

    # 3. Admin consent for those permissions, for every user in the tenant.
    $grants = @(Get-GraphList ("/v1.0/oauth2PermissionGrants?" + (Get-Filter "clientId eq '$($principal['id'])'")) |
        Where-Object { $_['resourceId'] -eq $graph['id'] })
    $grantedWrites = @($grants | ForEach-Object { Split-Scope $_['scope'] } |
        Where-Object { Test-WritePermission $_ } | Select-Object -Unique)
    if ($grantedWrites.Count) {
        Stop-Setup "the app $AppName already has consent for $($grantedWrites -join ', '), which can change your tenant, so the scanner would refuse to sign in. In the Microsoft Entra admin center, open Enterprise applications, then $AppName, then Permissions, and revoke that consent. Then run this script again."
    }
    $tenantGrant = @($grants | Where-Object { $_['consentType'] -eq 'AllPrincipals' }) | Select-Object -First 1
    if (-not $tenantGrant) {
        Invoke-Graph POST '/v1.0/oauth2PermissionGrants' @{
            clientId    = $principal['id']
            consentType = 'AllPrincipals'
            resourceId  = $graph['id']
            scope       = $AppPermissions -join ' '
        } | Out-Null
        Write-Host 'Granted admin consent for the sign-in and read permissions.'
    } else {
        $granted = Split-Scope $tenantGrant['scope']
        $missing = @($AppPermissions | Where-Object { $granted -notcontains $_ })
        if ($missing.Count) {
            Invoke-Graph PATCH "/v1.0/oauth2PermissionGrants/$($tenantGrant['id'])" @{ scope = (@($granted) + $missing) -join ' ' } | Out-Null
            Write-Host "Granted admin consent for $($missing -join ', ')."
        } else {
            Write-Host 'Admin consent is already in place.'
        }
    }
    return $appId
}

$failed = $false
try {
    $tenant = Connect-Tenant
    $appId = Set-ReadOnlyApp

    $setup = [ordered]@{
        schema_version    = '1.0.0'
        provider          = 'microsoft365'
        connection_method = 'existing_read_only'
        details           = [ordered]@{ tenant_id = $tenant; public_client_id = $appId }
    }
    $path = Join-Path (Get-Location).Path $SetupFile
    [IO.File]::WriteAllText($path, (ConvertTo-Json -InputObject $setup -Depth 5), (New-Object Text.UTF8Encoding $false))

    Write-Host ''
    Write-Host "Read-only Microsoft 365 access is ready. Enter these values in step 2 of the app's connection guide:"
    Write-Host ''
    Write-Host "  Tenant ID:                $tenant"
    Write-Host "  Application (client) ID:  $appId"
    Write-Host ''
    Write-Host "To hand these values to someone else, send $path. They import it"
    Write-Host 'with Choose setup file, under "Someone else manages this account?" in step 1.'
} catch {
    $reason = $_.Exception.Message
    if ($_.ErrorDetails -and $_.ErrorDetails.Message) { $reason = "$reason $($_.ErrorDetails.Message)" }
    Write-Host ''
    Write-Host "Stopped: $reason" -ForegroundColor Red
    $failed = $true
} finally {
    if (Get-Command Disconnect-MgGraph -ErrorAction SilentlyContinue) {
        Disconnect-MgGraph -ErrorAction SilentlyContinue | Out-Null
    }
}
if ($failed) { exit 1 }
