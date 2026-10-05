<#
.SYNOPSIS
Prepares read-only Microsoft 365 access for ai-security-scanner.

.DESCRIPTION
Run it as a Global Administrator of the tenant you want to scan:

    powershell -ExecutionPolicy Bypass -File .\microsoft365-read-only.ps1

You sign in on Microsoft's own page, so this script never sees your password.
It makes sure the tenant has a single-tenant app registration named
ai-security-scanner that allows public client flows, asks only for the
Microsoft Graph delegated sign-in and read permissions the scan uses, and has
admin consent for them. It then prints the two IDs for step 2 of the app's
connection guide and saves them as a setup file the app can import.

Each run also saves a separate cleanup record without passwords or tokens.
Keep it to revoke this setup with microsoft365-cleanup.ps1 after the scan.

Running it again adds only what is missing. It never removes or replaces
anything; when something is in the way, it stops and says what to change.

.PARAMETER TenantId
The tenant to prepare. Leave it out to use the tenant you sign in to.

.PARAMETER Temporary
Create a separate application for this scan so cleanup cannot interrupt another
scan using the usual shared application. Recommended for automatic cleanup.

.PARAMETER UseDeviceCode
Sign in with a code on another device, for a shell that cannot open a browser.
On Windows the script always signs in this way, so Windows does not offer to
let the organization manage the computer.
#>
[CmdletBinding()]
param(
    [ValidatePattern('^$|^[0-9a-fA-F]{8}-([0-9a-fA-F]{4}-){3}[0-9a-fA-F]{12}$')]
    [string] $TenantId = '',
    [switch] $UseDeviceCode,
    [switch] $FunctionsOnly,
    [switch] $Temporary
)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version 2.0
if ($PSVersionTable.PSEdition -ne 'Core') {
    # Windows PowerShell 5.1 can still offer TLS 1.0, which Microsoft refuses.
    [Net.ServicePointManager]::SecurityProtocol = [Net.ServicePointManager]::SecurityProtocol -bor [Net.SecurityProtocolType]::Tls12
}

$AppName = 'ai-security-scanner'
$GraphAppId = '00000003-0000-0000-c000-000000000000'
# Microsoft Graph PowerShell's own public client, which Connect-MgGraph signs in with.
$GraphPowerShellClientId = '14d82eec-204b-4c2f-b7e8-296a70dab67e'
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

$script:CleanupReceipt = $null
$script:CleanupReceiptPath = $null
$script:AllowCleanupRefresh = $false
$script:CleanupRefreshToken = $null
$script:CleanupAccessExpiresAt = $null
$script:CleanupRefreshDeadline = $null

function Save-CleanupReceipt {
    # Replace atomically, so an interrupted write does not erase the previous journal.
    $temporary = "$script:CleanupReceiptPath.$([guid]::NewGuid()).tmp"
    try {
        $bytes = [Text.Encoding]::UTF8.GetBytes((ConvertTo-Json -InputObject $script:CleanupReceipt -Depth 30))
        $file = [IO.File]::Open($temporary, [IO.FileMode]::CreateNew, [IO.FileAccess]::Write, [IO.FileShare]::None)
        try { $file.Write($bytes, 0, $bytes.Length); $file.Flush($true) } finally { $file.Dispose() }
        if ([IO.File]::Exists($script:CleanupReceiptPath)) {
            [IO.File]::Replace($temporary, $script:CleanupReceiptPath, [NullString]::Value)
        } else { [IO.File]::Move($temporary, $script:CleanupReceiptPath) }
    } finally {
        if ([IO.File]::Exists($temporary)) { [IO.File]::Delete($temporary) }
    }
}

function ConvertTo-ReceiptMap($Value) {
    if ($null -eq $Value) { return $null }
    if ($Value -is [Management.Automation.PSCustomObject]) {
        $map = @{}
        foreach ($property in $Value.PSObject.Properties) { $map[$property.Name] = ConvertTo-ReceiptMap $property.Value }
        return $map
    }
    if ($Value -is [array]) { return , @($Value | ForEach-Object { ConvertTo-ReceiptMap $_ }) }
    return $Value
}

function Get-GraphErrorStatus($Record) {
    $exception = $Record.Exception
    for ($depth = 0; $exception -and $depth -lt 8; $depth++) {
        $response = $exception.PSObject.Properties['Response']
        $status = $exception.PSObject.Properties['ResponseStatusCode']
        if ($status) { return [int] $status.Value }
        if ($response -and $response.Value) { return [int] $response.Value.StatusCode }
        $exception = $exception.InnerException
    }
    return 0
}

function Clear-CleanupSignIn {
    if ($script:CleanupRefreshToken) { $script:CleanupRefreshToken.Dispose() }
    $script:CleanupRefreshToken = $null
    $script:CleanupAccessExpiresAt = $null
}

function Save-CleanupSignIn($Answer) {
    if (-not $script:AllowCleanupRefresh) { return }
    if ($Answer.PSObject.Properties['refresh_token'] -and $Answer.refresh_token) {
        if ($script:CleanupRefreshToken) { $script:CleanupRefreshToken.Dispose() }
        $script:CleanupRefreshToken = ConvertTo-SecureString -String $Answer.refresh_token -AsPlainText -Force
    }
    $script:CleanupAccessExpiresAt = (Get-Date).AddSeconds([int] $Answer.expires_in)
}

function Update-CleanupSignIn([switch] $Force) {
    if (-not $script:CleanupRefreshToken) { return }
    if (-not $Force -and (Get-Date).AddSeconds(60) -lt $script:CleanupAccessExpiresAt) { return }
    if ((Get-Date) -ge $script:CleanupRefreshDeadline) { throw 'The cleanup sign-in window ended. Keep the receipt and sign in again to finish.' }
    $plain = $null
    $answer = $null
    try {
        $plain = (New-Object -TypeName Net.NetworkCredential -ArgumentList @('', $script:CleanupRefreshToken)).Password
        $answer = Invoke-RestMethod -Method Post -Uri "https://login.microsoftonline.com/$TenantId/oauth2/v2.0/token" -Body @{
            grant_type = 'refresh_token'; client_id = $GraphPowerShellClientId; refresh_token = $plain
            scope = ((@($SetupScopes | ForEach-Object { "https://graph.microsoft.com/$_" }) + @('offline_access')) -join ' ')
        }
        Connect-MgGraph -AccessToken (ConvertTo-SecureString -String $answer.access_token -AsPlainText -Force) -NoWelcome | Out-Null
        if ((Get-MgContext).TenantId -ne $TenantId) { throw 'The refreshed sign-in returned a different tenant.' }
        Save-CleanupSignIn $answer
    } catch {
        throw 'Microsoft could not renew this cleanup sign-in. Keep the receipt and sign in again; no completion is assumed.'
    } finally { $plain = $null; $answer = $null }
}

function Send-GraphRequest([string] $Method, [string] $Uri, $Body = $null) {
    if ($Uri -notmatch '^(/v1\.0/|https://graph\.microsoft\.com/v1\.0/)') {
        throw 'Refusing a Graph URL outside the Microsoft Graph v1.0 endpoint.'
    }
    $request = @{ Method = $Method; Uri = $Uri; OutputType = 'HashTable' }
    if ($null -ne $Body) {
        $request['Body'] = ConvertTo-Json -InputObject $Body -Depth 10 -Compress
        $request['ContentType'] = 'application/json'
    }
    Update-CleanupSignIn
    try { Invoke-MgGraphRequest @request } catch {
        if ((Get-GraphErrorStatus $_) -ne 401 -or -not $script:CleanupRefreshToken) { throw }
        # Only a definite authentication rejection is retried here. Never
        # repeat a mutation after a timeout or an uncertain server response.
        Update-CleanupSignIn -Force
        Invoke-MgGraphRequest @request
    }
}

function Get-SetupPropertyValues($Object, [string] $Name) {
    if ($Name -eq 'requiredResourceAccess') {
        return @($Object[$Name] | ForEach-Object {
            $resource = $_
            foreach ($permission in @($resource['resourceAccess'])) {
                "$($resource['resourceAppId'])/$($permission['type'])/$($permission['id'])"
            }
        } | Sort-Object -Unique)
    }
    if ($Name -eq 'scope') { return @(Split-Scope $Object[$Name] | Sort-Object -Unique) }
    return , $Object[$Name]
}

function Assert-SetupSnapshot($Current, $Expected, $Properties) {
    if (-not $Expected -or $Current['id'] -ne $Expected['id']) { throw 'The setup resource changed while it was being read. Retry setup.' }
    foreach ($key in @('appId', 'clientId', 'resourceId', 'consentType', 'principalId') + @($Properties)) {
        $left = ConvertTo-Json -InputObject @(Get-SetupPropertyValues $Current $key) -Depth 10 -Compress
        $right = ConvertTo-Json -InputObject @(Get-SetupPropertyValues $Expected $key) -Depth 10 -Compress
        if ($left -cne $right) { throw 'The setup resource changed while it was being read. No stale update was sent; retry setup.' }
    }
}

function Invoke-Graph([string] $Method, [string] $Uri, $Body = $null, $Expected = $null) {
    $action = $null
    if ($script:CleanupReceipt -and $Method -in @('POST', 'PATCH')) {
        if ($Uri -notmatch '^/v1\.0/(applications|servicePrincipals|oauth2PermissionGrants)(/[^/?]+)?$') {
            throw 'This setup mutation has no cleanup journal support.'
        }
        $kind = $Matches[1]
        $before = if ($Method -eq 'PATCH') { Send-GraphRequest GET $Uri } else { $null }
        if ($Method -eq 'PATCH') { Assert-SetupSnapshot $before $Expected $Body.Keys }
        $action = @{
            method = $Method; kind = $kind; id = if ($before) { $before['id'] } else { $null }
            before = if ($before) {
                # Only retain fields changed by setup, plus the object's identity. No tokens or credentials.
                $snapshot = @{ id = $before['id'] }
                foreach ($key in @('appId', 'clientId', 'resourceId', 'consentType', 'principalId') + @($Body.Keys)) {
                    $snapshot[$key] = $before[$key]
                }
                $snapshot
            } else { $null }
            after = $Body; state = 'pending'
        }
        $script:CleanupReceipt['actions'] += , $action
        Save-CleanupReceipt
    }
    try { $answer = Send-GraphRequest $Method $Uri $Body } catch {
        # A definite rejection needs no undo. A lost response remains pending
        # until cleanup can identify the resource; do not infer absence from it.
        if ($action -and (Get-GraphErrorStatus $_) -in @(400, 401, 403, 404, 405, 422)) {
            $action['state'] = 'not_applied'
            Save-CleanupReceipt
        }
        throw
    }
    if ($action) {
        if ($Method -eq 'POST') {
            $action['id'] = $answer['id']
            if ($kind -eq 'applications') { $action['after']['appId'] = $answer['appId'] }
        }
        $action['state'] = 'ready'
        Save-CleanupReceipt
    }
    return $answer
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

# Microsoft's sign-in service answers a code that is still waiting, or was
# refused, with HTTP 400 and a JSON body naming the error. Invoke-RestMethod puts
# that body in ErrorDetails.
function Get-SignInRefusal($Record) {
    if (-not $Record.ErrorDetails -or -not $Record.ErrorDetails.Message) { return $null }
    try { $body = ConvertFrom-Json -InputObject $Record.ErrorDetails.Message } catch { return $null }
    if (-not $body -or -not $body.PSObject.Properties['error']) { return $null }
    $description = [string] $body.error
    if ($body.PSObject.Properties['error_description']) {
        # The description ends with trace and correlation IDs nobody needs here.
        $description = ([string] $body.error_description) -replace '(?s)\s*Trace ID:.*$', ''
    }
    [pscustomobject]@{ Error = [string] $body.error; Description = $description }
}

# Signs in with a one-time code and returns the access token. Windows PowerShell
# 5.1 ended the whole process with a StackOverflowException inside
# Connect-MgGraph -UseDeviceCode, so the script asks Microsoft's sign-in service
# for the code itself and hands Connect-MgGraph only the token.
function Get-SignInToken {
    $tenant = if ($TenantId) { $TenantId } else { 'organizations' }
    $endpoint = "https://login.microsoftonline.com/$tenant/oauth2/v2.0"
    $scope = @($SetupScopes | ForEach-Object { "https://graph.microsoft.com/$_" }) -join ' '
    if ($script:AllowCleanupRefresh) { $scope += ' offline_access' }
    $code = Invoke-RestMethod -Method Post -Uri "$endpoint/devicecode" -Body @{ client_id = $GraphPowerShellClientId; scope = $scope }
    Write-Host $code.message
    $interval = [Math]::Max(1, [int] $code.interval)
    $deadline = (Get-Date).AddSeconds([int] $code.expires_in)
    while ((Get-Date) -lt $deadline) {
        Start-Sleep -Seconds $interval
        try {
            $answer = Invoke-RestMethod -Method Post -Uri "$endpoint/token" -Body @{
                grant_type  = 'urn:ietf:params:oauth:grant-type:device_code'
                client_id   = $GraphPowerShellClientId
                device_code = $code.device_code
            }
            Save-CleanupSignIn $answer
            return [string] $answer.access_token
        } catch {
            $refusal = Get-SignInRefusal $_
            if (-not $refusal) { throw }
            if ($refusal.Error -eq 'slow_down') {
                $interval += 5
            } elseif ($refusal.Error -ne 'authorization_pending') {
                Stop-Setup "Microsoft stopped the sign-in: $($refusal.Description)"
            }
        }
    }
    Stop-Setup 'the one-time code expired before the sign-in finished. Run this script again.'
}

function Connect-Tenant {
    $installed = Get-Module -ListAvailable -Name Microsoft.Graph.Authentication |
        Where-Object { $_.Version -ge [version] '2.0.0' }
    if (-not $installed) {
        Write-Host 'Installing the Microsoft Graph PowerShell sign-in module for your user account...'
        Install-Module -Name Microsoft.Graph.Authentication -MinimumVersion 2.0.0 -Scope CurrentUser -Repository PSGallery
    }
    Import-Module Microsoft.Graph.Authentication -MinimumVersion 2.0.0

    Write-Host "Sign in on Microsoft's page as a Global Administrator of the tenant to scan."
    # On Windows, the Microsoft Graph sign-in window belongs to Windows itself,
    # and it offers to add the account to Windows and let the organization manage
    # the computer. A sign-in with a one-time code stays in the browser.
    $onWindows = [Environment]::OSVersion.Platform -eq [PlatformID]::Win32NT
    if ($UseDeviceCode -or $onWindows -or "$env:AZUREPS_HOST_ENVIRONMENT" -like 'cloud-shell*') {
        $token = Get-SignInToken
        Connect-MgGraph -AccessToken (ConvertTo-SecureString -String $token -AsPlainText -Force) -NoWelcome | Out-Null
        $token = $null
    } else {
        $connect = @{ Scopes = $SetupScopes; ContextScope = 'Process'; NoWelcome = $true }
        if ($TenantId) { $connect['TenantId'] = $TenantId }
        Connect-MgGraph @connect | Out-Null
    }
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
            description            = "ai-security-scanner setup $($script:CleanupReceipt['operation_id'])"
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
            Invoke-Graph PATCH "/v1.0/applications/$($app['id'])" @{ isFallbackPublicClient = $true } $app | Out-Null
            Write-Host "Turned on public client flows for $AppName."
            $changed = $true
        }
        $missing = @($AppPermissions | Where-Object { $requested -notcontains $_ })
        if ($missing.Count) {
            $access = @($graphAccess | ForEach-Object { @{ id = $_['id']; type = $_['type'] } }) +
                @($missing | ForEach-Object { @{ id = $scopeIds[$_]; type = 'Scope' } })
            $updated = @($resources | Where-Object { $_['resourceAppId'] -ne $GraphAppId }) +
                @(@{ resourceAppId = $GraphAppId; resourceAccess = $access })
            Invoke-Graph PATCH "/v1.0/applications/$($app['id'])" @{ requiredResourceAccess = $updated } $app | Out-Null
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
    for ($attempt = 1; -not $principal -and $attempt -le 10; $attempt++) {
        try {
            $principal = Invoke-Graph POST '/v1.0/servicePrincipals' @{ appId = $appId; tags = @("ai-security-scanner-setup:$($script:CleanupReceipt['operation_id'])") }
        } catch {
            $status = Get-GraphErrorStatus $_
            if ($status -in @(401, 403)) { throw }
            $visible = @(Get-GraphList ("/v1.0/servicePrincipals?" + (Get-Filter "appId eq '$appId'")))
            if ($visible.Count) {
                if ($visible.Count -ne 1 -or @($visible[0]['tags']) -notcontains "ai-security-scanner-setup:$($script:CleanupReceipt['operation_id'])") {
                    throw 'Another setup created this service principal. Keep the partial receipt and review it before continuing.'
                }
                # A lost response (or a failed ready-save) is recoverable from
                # the operation's server-side marker, never from appId alone.
                $principal = $visible[0]
                $intent = @($script:CleanupReceipt['actions'] | Where-Object { $_['kind'] -eq 'servicePrincipals' -and $_['after']['appId'] -eq $appId }) | Select-Object -Last 1
                $intent['id'] = $principal['id']; $intent['state'] = 'ready'
                Save-CleanupReceipt
                break
            }
            # Only a definite replication rejection is safe to retry as POST.
            if ($status -ne 400 -or $attempt -ge 10) { throw }
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
            Invoke-Graph PATCH "/v1.0/oauth2PermissionGrants/$($tenantGrant['id'])" @{ scope = (@($granted) + $missing) -join ' ' } $tenantGrant | Out-Null
            Write-Host "Granted admin consent for $($missing -join ', ')."
        } else {
            Write-Host 'Admin consent is already in place.'
        }
    }
    return $appId
}

if ($FunctionsOnly) { return }

$failed = $false
$setupLock = $null
$connectedToTenant = $false
$receiptLock = $null
try {
    # Serialize setups that share an import file, and prevent cleanup from
    # consuming an in-flight journal. Lock files remain to avoid Unix inode races.
    $setupLock = [IO.File]::Open((Join-Path (Get-Location).Path '.ai-security-scanner-microsoft365-setup.lock'), [IO.FileMode]::OpenOrCreate, [IO.FileAccess]::ReadWrite, [IO.FileShare]::None)
    $connectedToTenant = $true
    $tenant = Connect-Tenant
    if ($TenantId -and $tenant -ne $TenantId) { throw 'Signed in to a different tenant; no setup changes were made.' }
    $operation = [guid]::NewGuid().ToString()
    if ($Temporary) { $AppName = "ai-security-scanner-$operation" }
    $script:CleanupReceiptPath = Join-Path (Get-Location).Path "ai-security-scanner-microsoft365-cleanup-$operation.json"
    $receiptLock = [IO.File]::Open("$script:CleanupReceiptPath.lock", [IO.FileMode]::OpenOrCreate, [IO.FileAccess]::ReadWrite, [IO.FileShare]::None)
    $script:CleanupReceipt = @{
        schema_version = '1.0.0'; provider = 'microsoft365'; tenant_id = $tenant
        operation_id = $operation; state = 'setup_in_progress'; actions = @()
        graph_powershell = 'not_tracked_before_sign_in'; graph_powershell_grant_ids = @(); report = $null; setup_file = $null; watch = $null
    }
    Save-CleanupReceipt
    $appId = Set-ReadOnlyApp

    $setup = [ordered]@{
        schema_version    = '1.0.0'
        provider          = 'microsoft365'
        connection_method = 'existing_read_only'
        details           = [ordered]@{ tenant_id = $tenant; public_client_id = $appId }
    }
    $path = Join-Path (Get-Location).Path $SetupFile
    [IO.File]::WriteAllText($path, (ConvertTo-Json -InputObject $setup -Depth 5), (New-Object Text.UTF8Encoding $false))

    $script:CleanupReceipt['setup_file'] = @{ path = $path; sha256 = (Get-FileHash -LiteralPath $path -Algorithm SHA256).Hash }
    $script:CleanupReceipt['state'] = 'ready'
    Save-CleanupReceipt
    Write-Host "Cleanup record: $script:CleanupReceiptPath"
    if (@($script:CleanupReceipt['actions'] | Where-Object { $_['state'] -ne 'not_applied' }).Count) {
        Write-Host 'Keep this record. microsoft365-cleanup.ps1 uses it to undo only this setup.'
    } else { Write-Host 'This run changed nothing. This record revokes nothing; keep the receipt from the setup that originally created access.' }
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
    if ($script:CleanupReceiptPath) { Write-Host "Keep the partial cleanup record: $script:CleanupReceiptPath" }
    $failed = $true
} finally {
    if ($connectedToTenant -and (Get-Command Disconnect-MgGraph -ErrorAction SilentlyContinue)) {
        Disconnect-MgGraph -ErrorAction SilentlyContinue | Out-Null
    }
    Clear-CleanupSignIn
    if ($receiptLock) { $receiptLock.Dispose() }
    if ($setupLock) { $setupLock.Dispose() }
}
if ($failed) { exit 1 }
