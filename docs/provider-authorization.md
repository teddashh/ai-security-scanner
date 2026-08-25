# Provider-native authorization and isolated bootstrap

`ai-security-scanner` supports AWS, Azure, Google Cloud, and Microsoft 365 without accepting a provider password, long-lived access key, refresh token, application secret, or administrator credential through the frontend. The preferred path uses the provider's public-client protocol. The optional bootstrap path runs in the separately packaged `ai-security-scanner-bootstrap-broker` process when a dedicated read-only identity must be created.

This feature does not ship sample OAuth client IDs. Azure, Microsoft 365, and Google deployments must register their own public client. Values such as all-zero UUIDs, example Google client IDs, and unknown JSON fields are rejected.

## Connection setup file

The desktop UI leads with a one-file handoff instead of asking an ordinary user to transcribe cloud identifiers. The user copies the provider-specific request and JSON template from the application, an IT or cloud administrator fills in the non-secret coordinates, and the user imports that file before continuing to the provider-hosted sign-in page. Manual entry remains available as a secondary path.

The file is read once in the webview, is never persisted, and is discarded after its values fill the existing non-secret authorization state. It is limited to 64 KiB, four levels, 64 JSON nodes, exact keys, and schema version `1.0.0`. Any field name containing a password, secret, token, key, credential, certificate, or private-material term is rejected recursively. The backend still performs its existing provider-specific validation and live read-only authorization checks.

The exact top-level shape is:

```json
{
  "schema_version": "1.0.0",
  "provider": "azure",
  "connection_method": "existing_read_only",
  "details": {
    "tenant_id": "11111111-2222-4333-8444-555555555555",
    "public_client_id": "aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee",
    "subscription_id": "22222222-3333-4444-8555-666666666666"
  }
}
```

`connection_method` is either `existing_read_only` or `temporary_read_only`. The application shows the exact template for the selected provider and method. Its accepted `details` fields are:

| Provider | Existing read-only | Temporary read-only |
|---|---|---|
| AWS | `start_url`, `region`, `account_id`, `role_name` | Same fields |
| Azure | `tenant_id`, `public_client_id`, `subscription_id` | Same fields |
| Google Cloud | `public_client_id`, `organization_id` | Existing fields plus `project_id` |
| Microsoft 365 | `tenant_id`, `public_client_id` | Same fields |

AWS `role_arn` is derived locally from the region, account, and role. Google Cloud `redirect_uri` is generated locally for the current loopback listener. Neither value belongs in the IT handoff file.

## Security boundary

- Provider login happens only on the provider-hosted HTTPS page.
- Device codes, PKCE verifier/state/code, refresh tokens, client secrets, access tokens, AWS session credentials, and scanner capability handles have no serde representation. They stay in zeroizing process memory and have redacted `Debug` output.
- Provider HTTP requests have a fixed host allowlist, no redirects, no environment proxy, bounded responses, and short timeouts.
- A provider credential must expire in at most one hour. A verification proof must be fresh and match the exact credential, provider, profile, resource, source, case, and engine set.
- Tokens never enter frontend state, SQLite, case artifacts, logs, environment variables, command-line arguments, or cleanup ledgers.
- A source is marked connected only after live provider identity and semantic permission checks succeed. A scanner gets credentials only through an exact `case_id + source_id + engine_id` checkout. The checkout is bounded and automatically expires.

The scanner runtime path is:

`begin/poll provider flow → live identity and permission verification → SourceAuthorizationBindings::install → resolve_execution_credentials → checkout_now(case, source, engine) → one scanner process`

An engine cannot reuse a capability issued to another case, source, profile, or engine. Additional or write-capable permissions fail closed where the provider exposes them.

## Live provider discovery

The installed capability also binds the fixed backend engine ID `provider-native-discovery`. `start_discovery` checks the exact case, source, provider, profile, provider identity, verification-proof digest, engine binding, and credential expiry before checking out that engine. This engine is not a shell executable and cannot be selected by the frontend as an arbitrary scanner.

The live client uses only these fixed read operations:

- AWS Organizations `ListAccounts` at the fixed `organizations.us-east-1.amazonaws.com` endpoint, signed with the verified short-lived role session.
- Azure Resource Manager `List Resources` for the exact verified subscription.
- Google Cloud Resource Manager `folders.list` and `projects.list`, breadth-first from the exact verified organization and then from each provider-returned child folder.
- Microsoft Graph `organization` plus a bounded `users` projection for the verified tenant.

Every operation has fixed fields, response-size and record limits, at most eight successful pages, one retry for a short transient-status allowlist, a two-minute aggregate deadline, and strict provider-host/path/query validation for continuation links. Google list APIs return direct children only, so discovery exhausts `nextPageToken` independently for folders and projects at every exact parent. Every returned `parent` must equal the requested organization/folder and every folder/project must be `ACTIVE`; a mismatched parent, duplicate identity/token, non-active resource, pending parent beyond the page bound, or any unexhausted pagination makes the capture partial/failed rather than complete. Redirects and environment proxies remain disabled. `cancel_discovery` sets the case-bound cancellation flag; the worker checks it before each request and retry.

The raw response body is synced first to a private `0600` SHA-256-addressed file. Only then may the capture client inspect a pagination token. The case stores a non-secret manifest of immutable page references, HTTP statuses, operations, hashes, and capture completeness. The ordinary source-specific snapshot connector reopens and verifies those files and performs canonical parsing and candidate-only reconciliation. There is no in-memory asset shortcut around the artifact boundary.

A complete response with no supported resource records is `connected but empty`, never scanned or green. Azure still retains the exact verified `Enabled` subscription as an attributable subscription asset when its resource inventory is empty; the resource record count remains zero. Expired/missing authorization becomes `needs_reauthorization`; transport, malformed-response, unsafe-pagination, storage, cancellation, and partial-capture outcomes remain failed/unknown coverage. Already captured pages and prior assets are retained. After restart, raw evidence remains available for offline re-parsing, but the process-memory capability is absent and a new live request requires reauthorization.

## Released source boundaries

Every live capability belongs to exactly one `case_id + source_id`. A source holds one exact live
provider proof at a time; authorizing another native provider coordinate requires another explicit
source rather than widening the existing proof.

| Provider source | Released boundary | Current limit and execution rule |
|---|---|---|
| AWS Organizations | One Organizations-enabled caller account per source. Standalone-account onboarding is not a released source profile. | `ListAccounts` may discover organization members, but every scanner execution still requires a short-lived caller credential whose STS account equals that one exact account. A child member therefore needs its own exact-caller source/capability before it can run; organization enumeration alone never authorizes the child. |
| Azure | One exact tenant plus subscription coordinate per source. | ARM must return that exact subscription with case-sensitive `state == Enabled`. Each Prowler execution contains one subscription; another subscription requires another source/capability. |
| Google Cloud | One exact organization per source. Organization-less project onboarding is not a released source profile. | Discovery is bounded to 1,000 provider records and Prowler splits approved projects into one exact-project execution each. The capability hard cap is 1,001 checkouts: one discovery plus at most one execution per bounded record. |
| Microsoft 365 | One exact tenant per source. | Discovery and M365 scanners cannot reuse the tenant capability for another tenant; another tenant requires another source/capability. |

AWS, Azure, and Microsoft 365 retain the smaller eight-checkout ceiling. The higher GCP ceiling is
not a reusable session or an unbounded allowance: expiry, exact case/source/engine checks, exact
asset planning, and revocation remain mandatory for every checkout.

## Operator prerequisites

### AWS preferred flow

Provide an exact IAM Identity Center start URL, region, 12-digit account ID, assigned role name, and role ARN. The assigned read-only role must include the pinned inventory reads plus `iam:SimulatePrincipalPolicy`, because the scanner verifies both required reads and prohibited writes without mutating the account.

The application dynamically registers a public IAM Identity Center OIDC client, starts device authorization, exchanges the device code, confirms that the exact account/role is assigned, obtains short-lived role credentials, calls STS `GetCallerIdentity`, and calls IAM `SimulatePrincipalPolicy`.

Official protocol references:

- [RegisterClient](https://docs.aws.amazon.com/singlesignon/latest/OIDCAPIReference/API_RegisterClient.html)
- [StartDeviceAuthorization](https://docs.aws.amazon.com/singlesignon/latest/OIDCAPIReference/API_StartDeviceAuthorization.html)
- [CreateToken](https://docs.aws.amazon.com/singlesignon/latest/OIDCAPIReference/API_CreateToken.html)
- [ListAccountRoles](https://docs.aws.amazon.com/singlesignon/latest/PortalAPIReference/API_ListAccountRoles.html) and [GetRoleCredentials](https://docs.aws.amazon.com/singlesignon/latest/PortalAPIReference/API_GetRoleCredentials.html)
- [GetCallerIdentity](https://docs.aws.amazon.com/STS/latest/APIReference/API_GetCallerIdentity.html)
- [SimulatePrincipalPolicy](https://docs.aws.amazon.com/IAM/latest/APIReference/API_SimulatePrincipalPolicy.html)

### Azure preferred flow

Register a tenant-specific public client, enable device-code/public-client use, and grant the delegated Graph read scopes requested by the application. Supply its real client ID, tenant ID, and exact subscription ID. The backend performs Microsoft device authorization, verifies `/me` and `/organization`, exchanges the in-memory refresh token for an Azure Resource Manager token, verifies the subscription, and lists role assignments for the exact principal.

The accepted scan principal has exactly the built-in Reader role (`acdd72a7-3385-48ef-bd42-f606fba81ae7`) and Security Reader role (`39bc4728-0917-49c7-9d2c-d95423bc2eb4`) at the assessed subscription. Owner, Contributor, User Access Administrator, or another unexpected role fails authorization.

- [Microsoft device authorization grant](https://learn.microsoft.com/en-us/entra/identity-platform/v2-oauth2-device-code)
- [Microsoft identity platform authorization code flow](https://learn.microsoft.com/en-us/entra/identity-platform/v2-oauth2-auth-code-flow)
- [List Azure role assignments for a scope](https://learn.microsoft.com/en-us/rest/api/authorization/role-assignments/list-for-scope?view=rest-authorization-2022-04-01)
- [Azure built-in roles](https://learn.microsoft.com/en-us/azure/role-based-access-control/built-in-roles)

### Google Cloud preferred flow

Register a Google OAuth Desktop client and supply its real client ID, numeric organization ID, and an exact random-port loopback redirect URI. The backend binds that loopback listener before returning the authorization URL, uses PKCE S256 plus state, and receives the code directly from the browser callback. The code never passes through the webview.

The backend verifies Google user identity and the exact organization resource. It calls `organizations.testIamPermissions` only for permissions whose resource is that organization: `resourcemanager.organizations.get`, `resourcemanager.folders.list`, and `resourcemanager.projects.list`, plus denial of `resourcemanager.organizations.setIamPolicy`. The discovery reads cover the complete folder/project hierarchy without claiming that project-scoped permissions were proved at the organization boundary.

Immediately before Prowler starts, the cloud launcher calls `projects.testIamPermissions` on the single immutable project in the execution scope. It requires `resourcemanager.projects.get` and `resourcemanager.projects.getIamPolicy`, and rejects credentials that hold the pinned project mutations (`resourcemanager.projects.setIamPolicy`, `resourcemanager.projects.delete`, `iam.serviceAccounts.create`, or `iam.serviceAccountKeys.create`). It then performs the exact `projects.get` and `projects.getIamPolicy` reads; a missing permission, a prohibited mutation, a mismatched/inactive project, or a failed live read stops the engine.

- [OAuth 2.0 for desktop apps](https://developers.google.com/identity/protocols/oauth2/native-app)
- [Google OAuth 2.0 overview](https://developers.google.com/identity/protocols/oauth2)
- [organizations.testIamPermissions](https://cloud.google.com/resource-manager/reference/rest/v3/organizations/testIamPermissions)
- [folders.list](https://cloud.google.com/resource-manager/reference/rest/v3/folders/list)
- [projects.list](https://cloud.google.com/resource-manager/reference/rest/v3/projects/list)
- [projects.testIamPermissions](https://cloud.google.com/resource-manager/reference/rest/v3/projects/testIamPermissions)
- [projects.getIamPolicy](https://cloud.google.com/resource-manager/reference/rest/v3/projects/getIamPolicy)

### Microsoft 365 preferred flow

Register a tenant-specific public client, enable device authorization, and grant only the requested delegated read permissions. The backend rejects known `ReadWrite`, write, and user-impersonation permissions. It verifies `/me`, `/organization`, and live read probes for audit metadata, authorization policy, and directory role definitions.

The pinned read set includes directory, application, audit log, domain, group, risk event, organization, policy, reports, role-management, security-event, administrative-unit, and user reads.

- [Microsoft Graph permissions reference](https://learn.microsoft.com/en-us/graph/permissions-reference)
- [Get the signed-in user](https://learn.microsoft.com/en-us/graph/api/user-get?view=graph-rest-1.0)
- [Get organization](https://learn.microsoft.com/en-us/graph/api/organization-get?view=graph-rest-1.0)

## Desktop/API surface

The native application exposes these Tauri commands and matching methods in `src/services/scanner.ts`:

- `begin_provider_authorization`: validates the existing read-only source, starts AWS/Microsoft device authorization or binds the Google loopback listener, and returns only a non-secret prompt and session ID.
- `poll_provider_authorization`: polls provider state. On success it performs live verification, installs the backend-only capability, and marks the matching source connected.
- `cancel_provider_authorization`, `provider_authorization_status`, and `revoke_provider_authorization`: manage only in-memory authorization state.
- `start_discovery`: uses a live capability for the four provider sources or a previously preserved snapshot for other sources, always parsing through the artifact-backed connector.
- `cancel_discovery`: requests cancellation of the active case-bound provider discovery worker without deleting already preserved pages.
- `plan_provider_bootstrap`: returns a non-secret, hash-pinned provider mutation plan.
- `execute_provider_bootstrap`: launches the isolated broker with cleared environment, forwards safe prompt lines through `provider://bootstrap-message`, consumes the broker's one-shot binary authorization frame, installs it, and returns the non-secret proof and cleanup-ledger path.
- `cleanup_provider_bootstrap`: reauthenticates in the isolated broker and updates every exact cleanup item durably.
- `list_provider_bootstrap_cleanup`: returns only operation/provider/case/schema/status/count/timestamp summaries; resource IDs, endpoints, and credentials remain backend-only. The CLI exposes the same projection through `bootstrap cleanup-list CASE_ID` and `bootstrap cleanup-show CASE_ID OPERATION_ID`.

The Assets and coverage view exposes both paths without accepting a password or client secret. It binds the selected case source to a fixed engine set and the provider-specific bounded checkout ceiling described above, shows only the non-secret user code or PKCE authorization URL, polls at the provider-supplied interval, and makes revocation visible. Provider links are opened by the operating-system browser through Tauri's opener capability. Both the frontend validator and the Tauri permission scope restrict those links to the AWS, Microsoft, and Google provider hosts used by these flows.

The bootstrap tab first shows the immutable operation list, provider endpoint hosts, embedded template hash, expiry, and cleanup obligations. Only a separate confirmation starts the isolated process. That confirmation is an authorization boundary for a provider mutation, not a development or release gate.

Preferred authorization sessions and installed capabilities are intentionally process-memory-only. Restarting the desktop application requires reauthorization. A short-lived CLI process cannot persist a capability safely; automation should invoke the broker protocol from a parent process that immediately consumes the one-shot frame and performs the bound work in that same process.

## Isolated bootstrap broker

The broker accepts exactly one bounded JSON command on stdin and no command-line arguments. Operator configuration contains only account coordinates and public client IDs. It refuses to start if known provider secret environment variables exist.

For `execute`, stdout must be an anonymous pipe. Unix verifies a FIFO descriptor and Windows verifies `FILE_TYPE_PIPE`; a terminal, regular file, or shell redirection is rejected so scanner material cannot be persisted accidentally. stdout contains one bounded non-JSON authorization frame; human prompts and generic errors use stderr. Core dumps are disabled, the process is non-dumpable, and privilege gain through exec is disabled on Unix.

The provider flows are:

- AWS: IAM Identity Center admin device flow → nonmutating admin permission simulation → exact CloudFormation stack → wait for `CREATE_COMPLETE` → `AssumeRole` for at most one hour → destroy admin session material → STS/IAM scanner verification.
- Azure: Microsoft admin device flow → Graph and ARM nonmutating permission probes → exact application and service principal → exact Reader and Security Reader assignments → client-credentials ARM token → immediately remove the temporary password → destroy admin material → validate token tenant/object claims, subscription, and exact RBAC.
- Google Cloud: admin Desktop PKCE → organization/project permission probes → exact service account → etag-preserving organization IAM update for the six pinned read-only roles → `generateAccessToken` for the read-only cloud scope → destroy admin material → verify the exact service account, organization, and semantic permissions. The operator must already have `iam.serviceAccounts.getAccessToken` for the created service account; the broker does not create a broad token-creator grant.
- Microsoft 365: admin device flow → live Graph permission probes → exact application and service principal → dynamically resolve the official Microsoft Graph application-role IDs by permission name → assign only the pinned read roles → client-credentials Graph token → immediately remove the temporary password → destroy admin material → verify the exact service principal, tenant, and read probes. No delegated grant or directory role is created.

Relevant creation/token APIs:

- [Microsoft Graph create servicePrincipal](https://learn.microsoft.com/en-us/graph/api/serviceprincipal-post-serviceprincipals?view=graph-rest-1.0)
- [Microsoft Graph addPassword](https://learn.microsoft.com/en-us/graph/api/application-addpassword?view=graph-rest-1.0)
- [Google IAM create service account](https://cloud.google.com/iam/docs/reference/rest/v1/projects.serviceAccounts/create)
- [Google IAM Credentials generateAccessToken](https://cloud.google.com/iam/docs/reference/credentials/rest/v1/projects.serviceAccounts/generateAccessToken)

## Durable cleanup

Before provider mutation begins, the broker creates a private cleanup journal. It binds the journal to non-secret provider coordinates (AWS account/region, Azure tenant/subscription, GCP organization/project, or Microsoft 365 tenant). After every provider response that creates or assigns a resource, it atomically rewrites the journal with the exact returned ID and exact cleanup endpoint. The immutable fields carry an integrity digest; missing or changed integrity, target relationships, provider context, methods, or endpoints fail closed. The file mode is `0600` on Unix and symlink destinations are rejected. It contains no password, external ID, access key, token, authorization code, or refresh token.

Successful execution replaces the journal with the full ledger. If bootstrap stops first, the same `1.0.0-partial` journal is directly resumable after application restart; recovery never performs discovery or widens the recorded set. Each bootstrap operation has its own private `cleanup-<operation-id>.json` ledger, so AWS, Azure, GCP, and Microsoft 365 obligations in one case cannot overwrite one another. Cleanup reauthenticates and permits only allowlisted operations reconstructed from that operation's provider-returned resource IDs and provider context. Modified endpoints, methods, targets, wildcard IDs, or provider/resource mismatches are rejected. Attempt start and result are each persisted immediately, so a crash between them remains visibly retryable. HTTP `404` is idempotent completion; provider/network failures remain retryable. A full ledger is complete only after resources are removed and the exact short-lived scanner credential expiry has elapsed.

Cleanup order removes Azure/Microsoft assignments before service principals and applications; removes Google organization bindings with the current etag before deleting the service account; and deletes the AWS stack before verifying the exact role is absent. Password removal is retried safely even though the normal creation flow removes it immediately.

Changing an administrator password is not cleanup by itself. Existing sessions, refresh tokens, application credentials, grants, roles, and provider identities must be handled as separate exact obligations.
