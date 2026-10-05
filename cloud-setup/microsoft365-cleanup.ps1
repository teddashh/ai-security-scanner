<#
.SYNOPSIS
Undo a recorded Microsoft 365 setup, optionally after one scan and report export.
.DESCRIPTION
Sign in on Microsoft's page. No administrator token is saved or given to the scanner.
Use -WhatIf to preview planned changes without waiting for the scan. Keep the JSON receipt to retry interrupted
cleanup. Existing applications and consent keep their original permissions.

-WaitForRun reads the installed scanner CLI's status for exactly CaseId and RunId.
Once terminal, it exports an HTML report, then revokes setup access. A failed HTML
export is reported separately; the saved case evidence is retained and access is
still revoked. An unknown or active scan, including a paused scan, is never treated
as finished. Keep this PowerShell window open until it reports completion.

-RevokeNow explicitly skips the scan-status and report-export gate, including on
retry. It can interrupt a scan that still uses this access. Ordinary retries retain
the original gate. During a wait, device-code access can refresh in memory only,
for at most the selected wait plus 15 minutes; Microsoft can require a new login.

Graph PowerShell's own consent predates the setup journal. To remove its two setup
permissions, first inspect -ListGraphPowerShellGrants, then pass the exact approved
-GraphPowerShellGrantId values. Other scopes and other grants are preserved.
#>
[CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = 'Medium')]
param(
    [Parameter(Mandatory = $true)] [string] $ReceiptPath,
    [switch] $UseDeviceCode,
    [switch] $WaitForRun,
    [switch] $RevokeNow,
    [string] $CaseId,
    [string] $RunId,
    [string] $DataDir,
    [string] $ReportPath,
    [string] $CliPath = 'ai-security-scanner-cli',
    [ValidateSet('en', 'zh-Hant')] [string] $Locale = 'zh-Hant',
    [ValidateRange(1, 480)] [int] $WaitMinutes = 120,
    [ValidateRange(1, 60)] [int] $PollSeconds = 5,
    [switch] $ListGraphPowerShellGrants,
    [string[]] $GraphPowerShellGrantId = @()
)
$ErrorActionPreference = 'Stop'
Set-StrictMode -Version 2.0
. (Join-Path $PSScriptRoot 'microsoft365-read-only.ps1') -FunctionsOnly -UseDeviceCode:$UseDeviceCode

function Assert-Identifier([string] $Id, [switch] $Grant) {
    $pattern = if ($Grant) { '^[a-zA-Z0-9_-]{1,256}$' } else { '^[0-9a-fA-F]{8}-([0-9a-fA-F]{4}-){3}[0-9a-fA-F]{12}$' }
    if ($Id -notmatch $pattern) { throw 'The cleanup record contains an invalid resource ID.' }
}

function Get-OptionalGraph([string] $Uri) {
    try { return Send-GraphRequest GET $Uri } catch {
        # Only an HTTP 404 means gone. A login failure, 403, timeout, or malformed
        # response must remain a failed cleanup, never an apparent success.
        if ((Get-GraphErrorStatus $_) -eq 404) { return $null }
        throw
    }
}

function Save-Progress { Save-CleanupReceipt }

function Invoke-Removal([string] $Method, [string] $Uri, $Body = $null) {
    if ($PSCmdlet.ShouldProcess($Uri, "$Method recorded setup change")) {
        Send-GraphRequest $Method $Uri $Body | Out-Null
        return $true
    }
    return $false
}

function Same-Values($Left, $Right) {
    return (@($Left | Sort-Object -Unique) -join "`n") -ceq (@($Right | Sort-Object -Unique) -join "`n")
}

function Access-Keys($Resources) {
    @($Resources | ForEach-Object {
        $resource = $_
        foreach ($permission in @($resource['resourceAccess'])) {
            "$($resource['resourceAppId'])/$($permission['type'])/$($permission['id'])"
        }
    })
}

function Resolve-Action($Action) {
    if ($Action['id']) { return }
    # Recover an uncertain POST using the exact recorded relationship. The app
    # carries a unique creation marker, so its display name is never ownership.
    $body = $Action['after']
    switch ($Action['kind']) {
        'applications' {
            $found = @(Get-GraphList ("/v1.0/applications?" + (Get-Filter "displayName eq '$($body['displayName'])'")) |
                Where-Object { $_['description'] -eq $body['description'] })
        }
        'servicePrincipals' {
            $found = @(Get-GraphList ("/v1.0/servicePrincipals?" + (Get-Filter "appId eq '$($body['appId'])'")) |
                Where-Object { @($_['tags']) -contains "ai-security-scanner-setup:$($script:CleanupReceipt['operation_id'])" })
        }
        'oauth2PermissionGrants' {
            $found = @(Get-GraphList ("/v1.0/oauth2PermissionGrants?" + (Get-Filter "clientId eq '$($body['clientId'])'")) |
                Where-Object { $_['resourceId'] -eq $body['resourceId'] -and $_['consentType'] -eq $body['consentType'] -and [string] $_['principalId'] -eq [string] $body['principalId'] })
        }
    }
    if ($found.Count -gt 1) { throw 'More than one resource matches a pending creation. Cleanup needs review.' }
    if (-not $found.Count) {
        # A missing POST response followed by an empty eventually-consistent
        # list is not proof the POST failed. Leave it pending for review/retry.
        throw 'A creation response was not recorded and its resource is not visible. Keep the record and retry cleanup.'
    }
    Assert-Identifier $found[0]['id'] -Grant:($Action['kind'] -eq 'oauth2PermissionGrants')
    $Action['id'] = $found[0]['id']
    if ($Action['kind'] -eq 'applications') { $Action['after']['appId'] = $found[0]['appId'] }
    if (-not $WhatIfPreference) { Save-Progress }
}

function Assert-OwnedApplication($Action, $Current) {
    if (-not $Current) { return }
    $after = $Action['after']
    if ($Current['appId'] -ne $after['appId'] -or $Current['description'] -ne $after['description']) {
        throw 'The application no longer matches this setup creation record.'
    }
    if (-not (Same-Values @(Access-Keys $Current['requiredResourceAccess']) @(Access-Keys $after['requiredResourceAccess'])) -or
        $Current['isFallbackPublicClient'] -ne $after['isFallbackPublicClient'] -or $Current['signInAudience'] -ne $after['signInAudience']) {
        throw 'The created application settings have changed. Review it before cleanup.'
    }
    foreach ($key in @('passwordCredentials', 'keyCredentials', 'identifierUris', 'appRoles')) {
        if (@($Current[$key] | Where-Object { $null -ne $_ }).Count) { throw 'The created application has additional credentials or configuration. Review it before cleanup.' }
    }
    foreach ($key in @('web', 'spa', 'publicClient')) {
        if ($Current[$key] -and @($Current[$key]['redirectUris'] | Where-Object { $_ }).Count) { throw 'The created application now has redirect URLs. Review it before cleanup.' }
    }
    if (@(Get-GraphList "/v1.0/applications/$($Action['id'])/federatedIdentityCredentials").Count) {
        throw 'The created application now has federated credentials. Review it before cleanup.'
    }
    if ($Current['api'] -and @($Current['api']['oauth2PermissionScopes'] | Where-Object { $null -ne $_ }).Count) {
        throw 'The created application now exposes an API. Review it before cleanup.'
    }
}

function Assert-OwnedPrincipal($Action, $Current) {
    if (-not $Current) { return }
    if (@(Get-GraphList "/v1.0/servicePrincipals/$($Action['id'])/appRoleAssignedTo").Count -or
        @(Get-GraphList ("/v1.0/oauth2PermissionGrants?" + (Get-Filter "resourceId eq '$($Action['id'])'"))).Count) {
        throw 'The created service principal now grants access to others. Review it before cleanup.'
    }
        if ($Current['appId'] -ne $Action['after']['appId'] -or @($Current['tags']) -notcontains "ai-security-scanner-setup:$($script:CleanupReceipt['operation_id'])") {
            throw 'Service principal identity or creation marker changed.'
        }
        foreach ($key in @('passwordCredentials', 'keyCredentials', 'replyUrls')) {
            if (@($Current[$key] | Where-Object { $null -ne $_ }).Count) { throw 'The created service principal has additional credentials or configuration. Review it before deletion.' }
        }
}

function Undo-Action($Action) {
    Resolve-Action $Action
    Assert-Identifier $Action['id'] -Grant:($Action['kind'] -eq 'oauth2PermissionGrants')
    $uri = "/v1.0/$($Action['kind'])/$($Action['id'])"
    $current = Get-OptionalGraph $uri
    if (-not $current) { return $true }
    if ($current['id'] -ne $Action['id']) { throw 'Graph returned a different resource ID.' }
    $after = $Action['after']
    $before = $Action['before']
    if ($Action['kind'] -eq 'oauth2PermissionGrants') {
        $identity = if ($before) { $before } else { $after }
        foreach ($key in @('clientId', 'resourceId', 'consentType', 'principalId')) {
            if ([string] $current[$key] -ne [string] $identity[$key]) { throw 'Consent identity changed; nothing was revoked for this grant.' }
        }
        $original = if ($before) { @(Split-Scope $before['scope']) } else { @() }
        $added = @(Split-Scope $after['scope'] | Where-Object { $original -cnotcontains $_ })
        $remaining = @(Split-Scope $current['scope'] | Where-Object { $added -cnotcontains $_ })
        if (Same-Values $remaining @(Split-Scope $current['scope'])) { return $true }
        if ($remaining.Count) {
            if (-not (Invoke-Removal PATCH $uri @{ scope = $remaining -join ' ' })) { return $false }
            $check = Send-GraphRequest GET $uri
            if (-not (Same-Values $remaining @(Split-Scope $check['scope']))) { throw 'Microsoft has not confirmed the reduced consent yet. Retry cleanup.' }
            return $true
        }
    } elseif ($Action['kind'] -eq 'applications') {
        if ($current['appId'] -ne $(if ($Action['method'] -eq 'PATCH') { $before['appId'] } else { $after['appId'] })) { throw 'Application identity changed.' }
        if ($Action['method'] -eq 'PATCH') {
            $patch = @{}
            if ($after.ContainsKey('requiredResourceAccess')) {
                $original = @(Access-Keys $before['requiredResourceAccess'])
                $added = @(Access-Keys $after['requiredResourceAccess'] | Where-Object { $original -notcontains $_ })
                $remaining = @($current['requiredResourceAccess'] | ForEach-Object {
                    $resource = $_
                    $access = @($resource['resourceAccess'] | Where-Object {
                        $added -notcontains "$($resource['resourceAppId'])/$($_['type'])/$($_['id'])"
                    })
                    if ($access.Count) { @{ resourceAppId = $resource['resourceAppId']; resourceAccess = $access } }
                })
                if (-not (Same-Values @(Access-Keys $current['requiredResourceAccess']) @(Access-Keys $remaining))) {
                    $patch['requiredResourceAccess'] = $remaining
                }
            }
            if ($after.ContainsKey('isFallbackPublicClient') -and $current['isFallbackPublicClient'] -eq $after['isFallbackPublicClient']) {
                $patch['isFallbackPublicClient'] = $before['isFallbackPublicClient']
            }
            if (-not $patch.Count) { return $true }
            if (-not (Invoke-Removal PATCH $uri $patch)) { return $false }
            $check = Send-GraphRequest GET $uri
            if (($patch.ContainsKey('requiredResourceAccess') -and -not (Same-Values @(Access-Keys $check['requiredResourceAccess']) @(Access-Keys $patch['requiredResourceAccess']))) -or
                ($patch.ContainsKey('isFallbackPublicClient') -and $check['isFallbackPublicClient'] -ne $patch['isFallbackPublicClient'])) {
                throw 'Microsoft has not confirmed the restored application settings yet. Retry cleanup.'
            }
            return $true
        }
        Assert-OwnedApplication $Action $current
    } elseif ($Action['kind'] -eq 'servicePrincipals') {
        Assert-OwnedPrincipal $Action $current
        $otherGrants = @(Get-GraphList ("/v1.0/oauth2PermissionGrants?" + (Get-Filter "clientId eq '$($current['id'])'")) | ForEach-Object {
            # A filtered Graph list can lag behind an individually confirmed deletion.
            Get-OptionalGraph "/v1.0/oauth2PermissionGrants/$($_['id'])"
        } | Where-Object { $null -ne $_ })
        $otherRoles = @(Get-GraphList "$uri/appRoleAssignments")
        if ($otherGrants.Count -or $otherRoles.Count) { throw 'The service principal still has consent or app roles. Review those before deleting it.' }
    }
    if (-not (Invoke-Removal DELETE $uri)) { return $false }
    for ($attempt = 0; $attempt -lt 4; $attempt++) {
        if (-not (Get-OptionalGraph $uri)) { return $true }
        if ($attempt -lt 3) { Start-Sleep -Seconds 1 }
    }
    throw 'Microsoft has not confirmed the deletion yet. Retry cleanup.'
}

function Invoke-ScannerCli([string[]] $Arguments) {
    $encoding = [Console]::OutputEncoding
    try {
        [Console]::OutputEncoding = New-Object Text.UTF8Encoding $false
        $output = & $CliPath --data-dir $DataDir --json @Arguments
        $exitCode = $LASTEXITCODE
    } finally { [Console]::OutputEncoding = $encoding }
    if ($exitCode -ne 0) { throw 'The scanner CLI could not complete the request. No active scan is assumed finished.' }
    return ($output -join "`n" | ConvertFrom-Json)
}

function Wait-AndExport {
    $deadline = (Get-Date).AddMinutes($WaitMinutes)
    while ($true) {
        $status = Invoke-ScannerCli @('scan', 'status', '--case-id', $CaseId, '--run-id', $RunId)
        if ($status.case_id -ne $CaseId -or @($status.runs).Count -ne 1 -or $status.runs[0].id -ne $RunId -or $status.runs[0].case_id -ne $CaseId) {
            throw 'The scanner returned a different case or run. Cleanup stopped.'
        }
        $run = $status.runs[0]
        $active = @($run.engine_runs | Where-Object { $_.status -notin @('completed', 'partially_completed', 'failed', 'cancelled', 'not_executed') })
        if ($run.completed_at -and -not $active.Count) { break }
        if ($WhatIfPreference) { Write-Host 'The selected scan is not finished. Apply will wait; preview does not wait or export.'; return }
        if ((Get-Date) -ge $deadline) { throw 'The scan is still unfinished. Access has not been revoked; keep the record and retry after the scan finishes or is cancelled, or explicitly choose -RevokeNow.' }
        Start-Sleep -Seconds $PollSeconds
    }
    if ($WhatIfPreference) { Write-Host 'The selected scan is finished. Apply will export its report before revoking access.'; return }
    $saved = $script:CleanupReceipt['report']
    if ($saved -and $saved['case_id'] -eq $CaseId -and $saved['run_id'] -eq $RunId -and $saved['path'] -eq $ReportPath -and
        (Test-Path -LiteralPath $ReportPath -PathType Leaf) -and (Get-FileHash -LiteralPath $ReportPath -Algorithm SHA256).Hash -eq $saved['sha256']) {
        Write-Host "Report already saved: $ReportPath"
        return
    }
    try {
        $export = Invoke-ScannerCli @('export', 'create', '--case-id', $CaseId, '--run-id', $RunId, '--format', 'html', '--redaction', 'standard', '--locale', $Locale, '--destination', $ReportPath)
        if ($export.case_id -ne $CaseId -or $export.run_id -ne $RunId -or $export.path -ne $ReportPath -or
            -not (Test-Path -LiteralPath $ReportPath -PathType Leaf) -or (Get-FileHash -LiteralPath $ReportPath -Algorithm SHA256).Hash -ne $export.sha256) {
            throw 'The exported report could not be verified.'
        }
        $script:CleanupReceipt['report'] = @{ case_id = $CaseId; run_id = $RunId; path = $ReportPath; sha256 = $export.sha256 }
        Save-Progress
        Write-Host "Report saved: $ReportPath"
    } catch {
        $script:ReportFailure = $true
        Write-Warning 'HTML export failed. The saved case evidence is retained; cleanup will still revoke setup access.'
    }
}

$failed = $false
$lock = $null
$connected = $false
$script:ReportFailure = $false
try {
    $script:CleanupReceiptPath = $ExecutionContext.SessionState.Path.GetUnresolvedProviderPathFromPSPath($ReceiptPath)
    # Both invocations keep this lock file. Removing it would allow a third
    # process to race a second holder on Unix. It contains no credentials.
    $lock = [IO.File]::Open("$script:CleanupReceiptPath.lock", [IO.FileMode]::OpenOrCreate, [IO.FileAccess]::ReadWrite, [IO.FileShare]::None)
    $receipt = ConvertTo-ReceiptMap ([IO.File]::ReadAllText($script:CleanupReceiptPath, [Text.Encoding]::UTF8) | ConvertFrom-Json)
    if ($receipt['schema_version'] -ne '1.0.0' -or $receipt['provider'] -ne 'microsoft365') { throw 'Not a supported Microsoft 365 cleanup record.' }
    Assert-Identifier $receipt['tenant_id']
    Assert-Identifier $receipt['operation_id']
    $TenantId = $receipt['tenant_id']
    foreach ($action in $receipt['actions']) {
        if ($action['kind'] -notin @('applications', 'servicePrincipals', 'oauth2PermissionGrants') -or
            $action['method'] -notin @('POST', 'PATCH') -or $action['state'] -notin @('pending', 'ready', 'completed', 'not_applied')) { throw 'Unsupported cleanup action.' }
        if ($action['method'] -eq 'PATCH') {
            $before = $action['before']; $after = $action['after']
            if (-not ($before -is [Collections.IDictionary]) -or -not ($after -is [Collections.IDictionary]) -or $before['id'] -ne $action['id']) {
                throw 'A cleanup update is missing its original snapshot.'
            }
            $allowed = if ($action['kind'] -eq 'applications') { @('requiredResourceAccess', 'isFallbackPublicClient') } else { @('scope') }
            if (-not $after.Count) { throw 'Empty cleanup update.' }
            foreach ($key in $after.Keys) {
                if ($allowed -notcontains $key -or -not $before.ContainsKey($key)) { throw 'Unsupported or incomplete cleanup update.' }
            }
            if ($action['kind'] -eq 'applications') { Assert-Identifier $before['appId'] }
            if ($action['kind'] -eq 'oauth2PermissionGrants') {
                foreach ($key in @('clientId', 'resourceId')) { Assert-Identifier $before[$key] }
                if ($before['consentType'] -ne 'AllPrincipals' -or $before['principalId']) { throw 'Unexpected scanner consent identity.' }
                foreach ($scope in @(Split-Scope $after['scope'] | Where-Object { @(Split-Scope $before['scope']) -cnotcontains $_ })) {
                    if ($AppPermissions -cnotcontains $scope) { throw 'The record would revoke a permission this setup never adds.' }
                }
            }
        } elseif ($action['before']) { throw 'A creation record unexpectedly contains a prior resource.' }
        if ($action['kind'] -eq 'servicePrincipals' -and $action['method'] -ne 'POST') { throw 'Unsupported principal cleanup action.' }
        if ($action['id']) { Assert-Identifier $action['id'] -Grant:($action['kind'] -eq 'oauth2PermissionGrants') }
        if ($action['kind'] -eq 'applications' -and $action['method'] -eq 'POST' -and
            $action['after']['description'] -ne "ai-security-scanner setup $($receipt['operation_id'])") { throw 'Missing application creation marker.' }
        foreach ($key in @('appId', 'clientId', 'resourceId')) {
            if ($action['after'][$key]) { Assert-Identifier $action['after'][$key] }
        }
    }
    $additionalHelperIds = @($GraphPowerShellGrantId | Where-Object { @($receipt['graph_powershell_grant_ids']) -notcontains $_ })
    $GraphPowerShellGrantId = @(@($receipt['graph_powershell_grant_ids']) + $GraphPowerShellGrantId | Where-Object { $_ } | Select-Object -Unique)
    foreach ($id in $GraphPowerShellGrantId) { Assert-Identifier $id -Grant }
    if ($RevokeNow -and $WaitForRun) { throw 'Choose either -WaitForRun or -RevokeNow.' }
    if ($WaitForRun -and (-not $CaseId -or -not $RunId -or -not $DataDir -or -not $ReportPath)) {
        throw '-WaitForRun needs CaseId, RunId, DataDir, and ReportPath.'
    }
    if ($WaitForRun) {
        $ReportPath = $ExecutionContext.SessionState.Path.GetUnresolvedProviderPathFromPSPath($ReportPath)
        $DataDir = $ExecutionContext.SessionState.Path.GetUnresolvedProviderPathFromPSPath($DataDir)
        $watch = @{ case_id = $CaseId; run_id = $RunId; data_dir = $DataDir; report_path = $ReportPath }
        if ($receipt['watch']) {
            foreach ($key in $watch.Keys) {
                if ($receipt['watch'][$key] -ne $watch[$key]) { throw 'This record is already watching a different scan or report path.' }
            }
        }
        $receipt['watch'] = $watch
    } elseif ($receipt['watch'] -and -not $ListGraphPowerShellGrants -and -not $RevokeNow) {
        # A retry cannot bypass the completion check simply by omitting flags.
        $WaitForRun = $true
        $CaseId = $receipt['watch']['case_id']; $RunId = $receipt['watch']['run_id']
        $DataDir = $receipt['watch']['data_dir']; $ReportPath = $receipt['watch']['report_path']
    }
    $script:CleanupReceipt = $receipt
    if ($RevokeNow -and -not $WhatIfPreference) {
        $receipt['immediate_revocation_requested_at'] = (Get-Date).ToUniversalTime().ToString('o')
        Save-Progress
        Write-Host 'Immediate revocation selected. This can interrupt a scan; no report export will be attempted.'
    }
    if ($receipt['state'] -eq 'completed' -and -not $additionalHelperIds.Count -and -not $ListGraphPowerShellGrants -and
        -not @($receipt['actions'] | Where-Object { $_['state'] -notin @('completed', 'not_applied') }).Count) {
        # Logging in again could grant the helper permissions we just revoked.
        # A completed retry therefore performs no Graph login at all.
        if ($WaitForRun) { Wait-AndExport }
        if ($script:ReportFailure) { throw 'Access cleanup was already completed, but HTML export still needs attention.' }
        Write-Host 'This cleanup record is already complete. No Microsoft sign-in was needed.'
        return
    }
    # Inspecting grants after completion can itself re-consent the helper.
    # Record that before authentication, even if the following operation is a
    # preview. A later retry must not trust the previous completed shortcut.
    if ($receipt['state'] -eq 'completed') {
        $receipt['state'] = 'cleanup_pending'
        $receipt['graph_powershell'] = 'recheck_needed'
        Save-Progress
    }
    $script:AllowCleanupRefresh = [bool] ($WaitForRun -and -not $WhatIfPreference)
    $script:CleanupRefreshDeadline = (Get-Date).AddMinutes($WaitMinutes + 15)
    $connected = $true
    if ((Connect-Tenant) -ne $TenantId) { throw 'Signed in to a different tenant; nothing was removed.' }
    $helper = @(Get-GraphList ("/v1.0/servicePrincipals?" + (Get-Filter "appId eq '$GraphPowerShellClientId'")))
    $helperGrants = @()
    if ($helper.Count -eq 1) {
        $graph = Send-GraphRequest GET "/v1.0/servicePrincipals(appId='$GraphAppId')?`$select=id"
        $helperGrants = @(Get-GraphList ("/v1.0/oauth2PermissionGrants?" + (Get-Filter "clientId eq '$($helper[0]['id'])'")) |
            Where-Object { $_['resourceId'] -eq $graph['id'] })
    }
    if ($ListGraphPowerShellGrants) {
        $helperGrants | ForEach-Object { [pscustomobject]@{ GrantId = $_['id']; AppliesTo = $_['consentType']; UserId = $_['principalId']; Permissions = $_['scope'] } } | Format-List | Out-Host
        return
    }
    if (-not $receipt['graph_powershell_targets']) { $receipt['graph_powershell_targets'] = @{} }
    foreach ($id in $GraphPowerShellGrantId) {
        $selected = @($helperGrants | Where-Object { $_['id'] -eq $id })
        if ($selected.Count) {
            $receipt['graph_powershell_targets'][$id] = @{
                clientId = $selected[0]['clientId']; resourceId = $selected[0]['resourceId']
                consentType = $selected[0]['consentType']; principalId = $selected[0]['principalId']
            }
        } else {
            $prior = $receipt['graph_powershell_targets'][$id]
            if ($prior) {
                $replacement = @($helperGrants | Where-Object {
                    $_['clientId'] -eq $prior['clientId'] -and $_['resourceId'] -eq $prior['resourceId'] -and
                    $_['consentType'] -eq $prior['consentType'] -and [string] $_['principalId'] -eq [string] $prior['principalId'] -and
                    @((Split-Scope $_['scope']) | Where-Object { $SetupScopes -contains $_ }).Count -gt 0 -and $GraphPowerShellGrantId -notcontains $_['id']
                })
                if ($replacement.Count) {
                    throw "Microsoft issued a new helper consent record for a previously selected identity. Review and select these GrantId values: $(@($replacement | ForEach-Object { $_['id'] }) -join ', ')."
                }
            }
        }
        if (-not $selected.Count) {
            if (Get-OptionalGraph "/v1.0/oauth2PermissionGrants/$id") { throw 'A selected grant does not belong to Microsoft Graph PowerShell and Microsoft Graph.' }
            if ($additionalHelperIds -contains $id) { throw 'A newly selected Graph PowerShell GrantId was not found. Check its exact ID before cleanup.' }
        }
    }
    if (-not $WhatIfPreference) {
        $receipt['state'] = 'cleanup_pending'
        $receipt['graph_powershell_grant_ids'] = $GraphPowerShellGrantId
        Save-Progress
    }
    if ($WaitForRun) { Wait-AndExport }
    foreach ($action in $receipt['actions']) {
        if ($action['state'] -notin @('completed', 'not_applied')) { Write-Host "Undo $($action['method']) $($action['kind']) $($action['id'])" }
    }
    # Resolve all uncertain creations before deleting their parent resources.
    foreach ($action in $receipt['actions']) { if ($action['state'] -notin @('completed', 'not_applied')) { Resolve-Action $action } }
    # Check newly created apps before changing their grants or principals. If
    # someone has repurposed an app, even a partial teardown would be harmful.
    foreach ($action in $receipt['actions']) {
        if ($action['kind'] -eq 'applications' -and $action['method'] -eq 'POST' -and $action['state'] -notin @('completed', 'not_applied')) {
            Assert-OwnedApplication $action (Get-OptionalGraph "/v1.0/applications/$($action['id'])")
        } elseif ($action['kind'] -eq 'servicePrincipals' -and $action['state'] -notin @('completed', 'not_applied')) {
            Assert-OwnedPrincipal $action (Get-OptionalGraph "/v1.0/servicePrincipals/$($action['id'])")
        }
    }
    for ($index = $receipt['actions'].Count - 1; $index -ge 0; $index--) {
        $action = $receipt['actions'][$index]
        if ($action['state'] -in @('completed', 'not_applied')) { continue }
        if (Undo-Action $action) {
            if (-not $WhatIfPreference) { $action['state'] = 'completed'; Save-Progress }
        } elseif ($WhatIfPreference) {
            if ($action['method'] -eq 'PATCH') { continue }
            # Created parents cannot be checked as empty until their grants are
            # removed. Every remaining action was listed above.
            Write-Host 'Remaining parent removals will be checked after their recorded consent is removed.'
            break
        } else { throw 'Cleanup was declined. The remaining changes are still recorded.' }
    }
    Update-CleanupSignIn
    Clear-CleanupSignIn
    foreach ($id in $GraphPowerShellGrantId) {
        $grant = Get-OptionalGraph "/v1.0/oauth2PermissionGrants/$id"
        if (-not $grant) { continue }
        if ($helper.Count -ne 1 -or $grant['clientId'] -ne $helper[0]['id'] -or $grant['resourceId'] -ne $graph['id']) { throw 'Graph PowerShell grant identity changed.' }
        # Explicit exact-ID authorization is necessary here: sign-in consent
        # happens before we can read its previous state, so ownership is unknown.
        $action = @{
            kind = 'oauth2PermissionGrants'; method = 'PATCH'; id = $id; state = 'ready'
            before = @{ clientId = $grant['clientId']; resourceId = $grant['resourceId']; consentType = $grant['consentType']; principalId = $grant['principalId']; scope = '' }
            after = @{ scope = $SetupScopes -join ' ' }
        }
        if (Undo-Action $action) {
            if (-not $WhatIfPreference) { $receipt['graph_powershell'] = 'selected_setup_scopes_removed'; Save-Progress }
        } elseif (-not $WhatIfPreference) { throw 'Graph PowerShell cleanup was declined.' }
    }
    if (-not $WhatIfPreference) {
        $retained = @()
        if ($helper.Count -eq 1) {
            foreach ($listed in @(Get-GraphList ("/v1.0/oauth2PermissionGrants?" + (Get-Filter "clientId eq '$($helper[0]['id'])'")))) {
                if ($listed['resourceId'] -ne $graph['id']) { continue }
                $live = Get-OptionalGraph "/v1.0/oauth2PermissionGrants/$($listed['id'])"
                if (-not $live) { continue }
                $writes = @(Split-Scope $live['scope'] | Where-Object { $SetupScopes -contains $_ })
                if ($writes.Count) {
                    if ($GraphPowerShellGrantId -contains $live['id']) { throw 'A selected helper grant still has setup permissions. Cleanup remains pending.' }
                    $retained += , @{ id = $live['id']; consent_type = $live['consentType']; principal_id = $live['principalId']; setup_scopes = $writes }
                    Write-Host "Unselected Graph PowerShell setup permissions remain: GrantId $($live['id']) ($($live['consentType']))."
                }
            }
        }
        $receipt['graph_powershell_retained_grants'] = $retained
        if ($retained.Count) { $receipt['graph_powershell'] = 'unselected_setup_scopes_remain' }
        $setup = $receipt['setup_file']
        if ($setup -and (Test-Path -LiteralPath $setup['path'] -PathType Leaf)) {
            $expected = Join-Path ([IO.Path]::GetDirectoryName($script:CleanupReceiptPath)) 'ai-security-scanner-microsoft365-setup.json'
            if ($setup['path'] -eq $expected -and (Get-FileHash -LiteralPath $expected -Algorithm SHA256).Hash -eq $setup['sha256']) {
                if ($PSCmdlet.ShouldProcess($expected, 'Remove the setup file whose access was revoked')) { [IO.File]::Delete($expected) }
            } else { Write-Host 'Kept the setup file because it has changed since this setup.' }
        }
        $receipt['state'] = 'completed'
        Save-Progress
        if (@($receipt['actions'] | Where-Object { $_['state'] -eq 'completed' }).Count) {
            Write-Host 'Recorded setup changes removed. Reports and case evidence are retained.'
        } else { Write-Host 'This setup added no access. No scanner access was revoked; use the receipt that originally created it.' }
        if (-not $GraphPowerShellGrantId.Count) { Write-Host 'Graph PowerShell consent was not selected for removal. Use -ListGraphPowerShellGrants to review it.' }
        Write-Host 'Already-issued access tokens can remain valid until they expire.'
        if ($script:ReportFailure) { throw 'Access cleanup finished, but HTML export failed. Export the saved case from the app.' }
    }
} catch {
    Write-Host "Cleanup incomplete: $($_.Exception.Message)" -ForegroundColor Red
    Write-Host 'Keep the cleanup record and rerun after resolving this error.'
    $failed = $true
} finally {
    if ($connected -and (Get-Command Disconnect-MgGraph -ErrorAction SilentlyContinue)) { Disconnect-MgGraph -ErrorAction SilentlyContinue | Out-Null }
    Clear-CleanupSignIn
    if ($lock) { $lock.Dispose() }
}
if ($failed) { exit 1 }
