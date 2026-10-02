# Answers the Microsoft Graph calls `cloud-setup/microsoft365-read-only.ps1`
# makes, in the shapes the Microsoft Graph v1.0 reference documents for
# applications, servicePrincipals and oauth2PermissionGrants, and the device
# authorization requests it sends Microsoft's sign-in service. State lives in the
# JSON file named by FAKE_GRAPH_STATE; every Graph request is appended to
# `calls` and every sign-in request to `login`.

$script:Connected = $false

function Read-FakeState {
    Get-Content -Raw -LiteralPath $env:FAKE_GRAPH_STATE | ConvertFrom-Json -AsHashtable
}

function Save-FakeState($State) {
    Set-Content -LiteralPath $env:FAKE_GRAPH_STATE -Value (ConvertTo-Json -InputObject $State -Depth 20)
}

function New-FakeId { [guid]::NewGuid().ToString() }

function Read-TokenClaims([string] $Token) {
    $payload = ($Token -split '\.')[1].Replace('-', '+').Replace('_', '/')
    $payload += '=' * ((4 - $payload.Length % 4) % 4)
    [Text.Encoding]::UTF8.GetString([Convert]::FromBase64String($payload)) | ConvertFrom-Json -AsHashtable
}

function Connect-MgGraph {
    param(
        [string[]] $Scopes,
        [string] $TenantId,
        [string] $ContextScope,
        [switch] $NoWelcome,
        [switch] $UseDeviceCode,
        [securestring] $AccessToken
    )
    # Windows PowerShell 5.1 ended the process with a StackOverflowException in
    # the real module's device-code sign-in.
    if ($UseDeviceCode) { throw 'the script must not use Connect-MgGraph -UseDeviceCode' }
    $state = Read-FakeState
    if ($AccessToken) {
        $token = [Net.NetworkCredential]::new('', $AccessToken).Password
        if ($token -ne $state['signIn']['token']) { throw 'Connect-MgGraph was handed a token the sign-in did not issue' }
        # Like the real module (JwtHelpers.DecodeJWT), the context comes from the token's claims.
        $claims = Read-TokenClaims $token
        $state['connect'] = @{ accessToken = $true; tenantId = $claims['tid']; scopes = @($claims['scp'] -split ' ') }
    } else {
        $state['connect'] = @{
            scopes       = @($Scopes)
            tenantId     = $TenantId
            contextScope = $ContextScope
        }
    }
    Save-FakeState $state
    $script:Connected = $true
}

function Get-MgContext {
    if (-not $script:Connected) { return $null }
    $state = Read-FakeState
    $tenant = if ($state['connect']['accessToken']) { $state['connect']['tenantId'] } else { $state['tenantId'] }
    [pscustomobject]@{ TenantId = $tenant; Scopes = @($state['connect']['scopes']) }
}

# Microsoft's device authorization endpoints, in the shapes its identity
# platform documents: the code, then HTTP 400 `authorization_pending` for each of
# `signIn.pending` polls, then the token, or `signIn.refusal` instead of the
# token. A zero interval keeps the test fast; the script waits at least a second.
function Invoke-RestMethod {
    param([string] $Method, [string] $Uri, $Body)
    $state = Read-FakeState
    $state['login'] += , @{ method = $Method; uri = $Uri; body = $Body }
    $signIn = $state['signIn']
    switch -Regex ($Uri) {
        '^https://login\.microsoftonline\.com/[^/]+/oauth2/v2\.0/devicecode$' {
            Save-FakeState $state
            return [pscustomobject]@{
                user_code        = 'FAKECODE1'
                device_code      = 'fake-device-code'
                verification_uri = 'https://login.microsoft.com/device'
                expires_in       = 900
                interval         = 0
                message          = 'To sign in, use a web browser to open the page https://login.microsoft.com/device and enter the code FAKECODE1 to authenticate.'
            }
        }
        '^https://login\.microsoftonline\.com/[^/]+/oauth2/v2\.0/token$' {
            if ($Body['device_code'] -ne 'fake-device-code') { throw 'the token request did not carry the issued device code' }
            $refusal = $null
            if ($signIn['pending'] -gt 0) {
                $signIn['pending'] -= 1
                $refusal = @{
                    error             = 'authorization_pending'
                    error_description = 'AADSTS70016: OAuth 2.0 device flow error. Authorization is pending. Continue polling. Trace ID: 00000000-0000-0000-0000-000000000000 Correlation ID: 00000000-0000-0000-0000-000000000000 Timestamp: 2026-10-02 22:00:00Z'
                }
            } elseif ($signIn['refusal']) {
                $refusal = $signIn['refusal']
            }
            Save-FakeState $state
            if ($refusal) {
                $record = [Management.Automation.ErrorRecord]::new(
                    [Exception]::new('Response status code does not indicate success: 400 (Bad Request).'),
                    'WebCmdletWebResponseException,Microsoft.PowerShell.Commands.InvokeRestMethodCommand',
                    'InvalidOperation', $null)
                $record.ErrorDetails = [Management.Automation.ErrorDetails]::new((ConvertTo-Json -InputObject $refusal -Compress))
                throw $record
            }
            return [pscustomobject]@{ token_type = 'Bearer'; expires_in = 3599; access_token = $signIn['token'] }
        }
        default { throw "the fake does not answer $Method $Uri" }
    }
}

function Disconnect-MgGraph {
    $state = Read-FakeState
    $state['disconnected'] = $true
    Save-FakeState $state
    $script:Connected = $false
}

function Invoke-MgGraphRequest {
    param(
        [string] $Method,
        [string] $Uri,
        $Body,
        [string] $ContentType,
        [string] $OutputType
    )
    if (-not $script:Connected) { throw 'Authentication needed. Please call Connect-MgGraph.' }
    $state = Read-FakeState
    $state['calls'] += , @{ method = $Method; uri = $Uri; body = $Body }
    Save-FakeState $state
    if ($OutputType -ne 'HashTable') { throw "the fake answers only -OutputType HashTable, not $OutputType" }

    $relative = $Uri -replace '^https://graph\.microsoft\.com/', '' -replace '^/', ''
    $path, $query = $relative -split '\?', 2
    $filter = $null
    if ($query) {
        foreach ($pair in $query -split '&') {
            $name, $value = $pair -split '=', 2
            if ($name -eq '$filter') {
                $decoded = [uri]::UnescapeDataString($value)
                if ($decoded -notmatch "^(\w+) eq '([^']*)'$") { throw "unsupported filter $decoded" }
                $filter = @{ property = $Matches[1]; value = $Matches[2] }
            }
        }
    }
    $request = if ($Body) { ConvertFrom-Json -InputObject $Body -AsHashtable } else { $null }
    $list = {
        param([string] $Collection)
        $items = @($state[$Collection] | Where-Object { $null -ne $_ })
        if ($filter) { $items = @($items | Where-Object { $_[$filter.property] -eq $filter.value }) }
        @{ '@odata.context' = "https://graph.microsoft.com/v1.0/`$metadata#$Collection"; value = $items }
    }

    switch -Regex ("$Method $path") {
        "^GET v1\.0/servicePrincipals\(appId='00000003-0000-0000-c000-000000000000'\)$" {
            return $state['graphServicePrincipal']
        }
        '^GET v1\.0/applications$' { return & $list 'applications' }
        '^POST v1\.0/applications$' {
            $app = @{
                id                     = New-FakeId
                appId                  = New-FakeId
                displayName            = $request['displayName']
                signInAudience         = $request['signInAudience']
                isFallbackPublicClient = $request['isFallbackPublicClient']
                requiredResourceAccess = @($request['requiredResourceAccess'])
            }
            $state['applications'] += , $app
            Save-FakeState $state
            return $app
        }
        '^PATCH v1\.0/applications/([^/]+)$' {
            $id = $Matches[1]
            $app = @($state['applications'] | Where-Object { $_['id'] -eq $id })[0]
            if (-not $app) { throw 'Response status code does not indicate success: NotFound (Not Found).' }
            foreach ($key in $request.Keys) { $app[$key] = $request[$key] }
            Save-FakeState $state
            return $null
        }
        '^GET v1\.0/servicePrincipals$' { return & $list 'servicePrincipals' }
        '^POST v1\.0/servicePrincipals$' {
            if ($state['replicationDelays'] -gt 0) {
                $state['replicationDelays'] -= 1
                Save-FakeState $state
                throw 'Response status code does not indicate success: BadRequest (Bad Request).'
            }
            if (-not @($state['applications'] | Where-Object { $_['appId'] -eq $request['appId'] }).Count) {
                throw 'Response status code does not indicate success: BadRequest (Bad Request).'
            }
            $principal = @{ id = New-FakeId; appId = $request['appId'] }
            $state['servicePrincipals'] += , $principal
            Save-FakeState $state
            return $principal
        }
        '^GET v1\.0/oauth2PermissionGrants$' { return & $list 'oauth2PermissionGrants' }
        '^POST v1\.0/oauth2PermissionGrants$' {
            $grant = @{
                id          = New-FakeId
                clientId    = $request['clientId']
                consentType = $request['consentType']
                principalId = $null
                resourceId  = $request['resourceId']
                scope       = $request['scope']
            }
            $state['oauth2PermissionGrants'] += , $grant
            Save-FakeState $state
            return $grant
        }
        '^PATCH v1\.0/oauth2PermissionGrants/([^/]+)$' {
            $id = $Matches[1]
            $grant = @($state['oauth2PermissionGrants'] | Where-Object { $_['id'] -eq $id })[0]
            if (-not $grant) { throw 'Response status code does not indicate success: NotFound (Not Found).' }
            $grant['scope'] = $request['scope']
            Save-FakeState $state
            return $null
        }
        default { throw "the fake does not answer $Method $Uri" }
    }
}

Export-ModuleMember -Function Connect-MgGraph, Get-MgContext, Invoke-MgGraphRequest, Disconnect-MgGraph, Invoke-RestMethod
