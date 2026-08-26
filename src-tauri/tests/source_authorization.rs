use ai_security_scanner_lib::adapters::builtin_adapter_registry;
use ai_security_scanner_lib::artifact_store::ArtifactStore;
use ai_security_scanner_lib::case_service::{
    CaseService, ScanPlanRequest, ScopeApprovalRequest, SourceMutation,
};
use ai_security_scanner_lib::connectors::SnapshotConnectorRegistry;
use ai_security_scanner_lib::container_runtime::{
    CancellationToken, FakeContainerRuntime, FakeRunBehavior, NetworkPolicy, ResourceLimits,
    RuntimeCall,
};
use ai_security_scanner_lib::discovery::{
    DiscoveredAsset, DiscoveredRelation, DiscoveryAssetRef, DiscoveryBatch, run_connector,
};
use ai_security_scanner_lib::domain::{
    AssetIdentifier, AssetKind, CreateCaseRequest, DataClass, RelationKind, ScanPermission,
    SourceConnectionStatus, SourceKind,
};
use ai_security_scanner_lib::orchestrator::{EngineExecutionRequest, ExecutionStage, Orchestrator};
use ai_security_scanner_lib::registry::EngineRegistry;
use ai_security_scanner_lib::source_authorization::discovery::capture_provider_inventory;
use ai_security_scanner_lib::source_authorization::provider::{
    AwsNativeAuthorizationConfig, GcpNativeAuthorizationConfig, MicrosoftNativeAuthorizationConfig,
    PollAuthorization, ProviderHttp, ProviderHttpRequest, ProviderHttpResponse,
    begin_aws_native_authorization, begin_gcp_native_authorization,
    begin_microsoft_native_authorization, complete_gcp_native_authorization,
    poll_aws_native_authorization, poll_microsoft_native_authorization, verify_bootstrap_gcp_token,
};
use ai_security_scanner_lib::source_authorization::session::{
    BeginProviderAuthorizationRequest, ProviderAuthorizationConfig, ProviderAuthorizationPrompt,
    ProviderAuthorizationSessions,
};
use ai_security_scanner_lib::source_authorization::{
    PROVIDER_RESOURCE_SCOPE_METADATA_KEY, ProviderSourceProfile, SourceAuthorizationBindings,
    SourceAuthorizationRequest, read_verified_authorization_one_shot,
    write_verified_authorization_one_shot,
};
use ai_security_scanner_lib::{bootstrap::BootstrapProvider, error::AppError, storage::Storage};
use chrono::{DateTime, Duration, Utc};
use serde_json::json;
use std::collections::{BTreeMap, BTreeSet, VecDeque};
use std::fs;
use std::sync::Mutex;
use std::sync::atomic::AtomicBool;
use url::Url;
use zeroize::Zeroizing;

struct ExpectedResponse {
    method: &'static str,
    path_contains: &'static str,
    response: ProviderHttpResponse,
}

struct FixtureHttp {
    expected: Mutex<VecDeque<ExpectedResponse>>,
}

impl FixtureHttp {
    fn new(responses: Vec<ExpectedResponse>) -> Self {
        Self {
            expected: Mutex::new(responses.into()),
        }
    }

    fn exhausted(&self) -> bool {
        self.expected.lock().unwrap().is_empty()
    }
}

impl ProviderHttp for FixtureHttp {
    fn execute(&self, request: ProviderHttpRequest) -> Result<ProviderHttpResponse, AppError> {
        let expected = self
            .expected
            .lock()
            .unwrap()
            .pop_front()
            .expect("unexpected provider request");
        assert_eq!(format!("{:?}", request.method()), expected.method);
        assert!(
            request.url().as_str().contains(expected.path_contains),
            "{} did not contain {}",
            request.url(),
            expected.path_contains
        );
        let debug = format!("{request:?}");
        assert!(!debug.contains("fixture-secret"));
        assert!(!debug.contains("fixture-token"));
        Ok(expected.response)
    }
}

fn expected(method: &'static str, path: &'static str, body: serde_json::Value) -> ExpectedResponse {
    ExpectedResponse {
        method,
        path_contains: path,
        response: ProviderHttpResponse::new(200, serde_json::to_vec(&body).unwrap())
            .with_request_header("request-id", format!("req-{}", path.len())),
    }
}

fn aws_config() -> AwsNativeAuthorizationConfig {
    AwsNativeAuthorizationConfig {
        start_url: "https://security.awsapps.com/start".into(),
        region: "us-east-1".into(),
        account_id: "111122223333".into(),
        role_name: "security-audit-reader".into(),
        role_arn: "arn:aws:iam::111122223333:role/security-audit-reader".into(),
    }
}

fn microsoft_config(profile: ProviderSourceProfile) -> MicrosoftNativeAuthorizationConfig {
    MicrosoftNativeAuthorizationConfig {
        tenant_id: "11111111-1111-4111-8111-111111111111".into(),
        public_client_id: "22222222-2222-4222-8222-222222222222".into(),
        profile,
        subscription_id: (profile == ProviderSourceProfile::AzureTenantReadOnlyAccessToken)
            .then(|| "33333333-3333-4333-8333-333333333333".into()),
    }
}

fn gcp_config() -> GcpNativeAuthorizationConfig {
    GcpNativeAuthorizationConfig {
        public_client_id: "123456789012-abcdefghijklmnopqrstuvwxyz.apps.googleusercontent.com"
            .into(),
        redirect_uri: "http://127.0.0.1:49152/oauth2/callback".into(),
        organization_id: "123456789012".into(),
    }
}

fn aws_simulation_xml(include_prohibited_allow: bool) -> String {
    let required = [
        "organizations:ListAccounts",
        "ec2:DescribeRegions",
        "iam:GenerateCredentialReport",
        "iam:GetAccessKeyLastUsed",
        "iam:GetAccountAuthorizationDetails",
        "iam:GetAccountPasswordPolicy",
        "iam:GetAccountSummary",
        "iam:GetCredentialReport",
        "iam:GetGroupPolicy",
        "iam:GetRole",
        "iam:GetRolePolicy",
        "iam:GetUser",
        "iam:GetUserPolicy",
        "iam:ListAccessKeys",
        "iam:ListAccountAliases",
        "iam:ListAttachedGroupPolicies",
        "iam:ListAttachedRolePolicies",
        "iam:ListAttachedUserPolicies",
        "iam:ListGroupPolicies",
        "iam:ListGroups",
        "iam:ListGroupsForUser",
        "iam:ListPolicyTags",
        "iam:ListRolePolicies",
        "iam:ListRoles",
        "iam:ListSSHPublicKeys",
        "iam:ListUserPolicies",
        "iam:ListUsers",
        "config:DescribeConfigurationRecorders",
        "securityhub:GetFindings",
        "cloudtrail:DescribeTrails",
    ];
    let prohibited = [
        "iam:CreateUser",
        "iam:AttachRolePolicy",
        "s3:PutObject",
        "ec2:RunInstances",
        "organizations:CreateAccount",
    ];
    let members = required
        .iter()
        .map(|action| {
            format!("<member><EvalActionName>{action}</EvalActionName><EvalDecision>allowed</EvalDecision></member>")
        })
        .chain(prohibited.iter().enumerate().map(|(index, action)| {
            let decision = if include_prohibited_allow && index == 0 {
                "allowed"
            } else {
                "implicitDeny"
            };
            format!("<member><EvalActionName>{action}</EvalActionName><EvalDecision>{decision}</EvalDecision></member>")
        }))
        .collect::<String>();
    format!(
        "<SimulatePrincipalPolicyResponse><EvaluationResults>{members}</EvaluationResults></SimulatePrincipalPolicyResponse>"
    )
}

fn verified_aws(
    now: DateTime<Utc>,
) -> ai_security_scanner_lib::source_authorization::VerifiedProviderAuthorization {
    let fixture = FixtureHttp::new(vec![
        expected(
            "Post",
            "/client/register",
            json!({
                "clientId":"fixture-client",
                "clientSecret":"fixture-secret-client",
                "clientIdIssuedAt": now.timestamp(),
                "clientSecretExpiresAt": (now + Duration::minutes(15)).timestamp()
            }),
        ),
        expected(
            "Post",
            "/device_authorization",
            json!({
                "deviceCode":"fixture-secret-device",
                "userCode":"ABCD-EFGH",
                "verificationUri":"https://oidc.us-east-1.amazonaws.com/verify",
                "verificationUriComplete":"https://oidc.us-east-1.amazonaws.com/verify?user_code=ABCD-EFGH",
                "expiresIn":600,
                "interval":1
            }),
        ),
        expected(
            "Post",
            "/token",
            json!({
                "accessToken":"fixture-token-sso",
                "expiresIn":600,
                "tokenType":"Bearer"
            }),
        ),
        expected(
            "Get",
            "/assignment/roles",
            json!({"roleList":[{"accountId":"111122223333","roleName":"security-audit-reader"}]}),
        ),
        expected(
            "Get",
            "/federation/credentials",
            json!({"roleCredentials":{
                "accessKeyId":"ASIAFIXTURE",
                "secretAccessKey":"fixture-secret-aws",
                "sessionToken":"fixture-token-session",
                "expiration":(now + Duration::minutes(30)).timestamp_millis()
            }}),
        ),
        ExpectedResponse {
            method: "Post",
            path_contains: "sts.us-east-1.amazonaws.com",
            response: ProviderHttpResponse::new(
                200,
                b"<GetCallerIdentityResponse><GetCallerIdentityResult><Arn>arn:aws:sts::111122223333:assumed-role/security-audit-reader/session</Arn><Account>111122223333</Account></GetCallerIdentityResult></GetCallerIdentityResponse>".to_vec(),
            ),
        },
        ExpectedResponse {
            method: "Post",
            path_contains: "iam.amazonaws.com",
            response: ProviderHttpResponse::new(200, aws_simulation_xml(false).into_bytes()),
        },
    ]);
    let (_, mut pending) = begin_aws_native_authorization(&fixture, aws_config(), now).unwrap();
    let authorization = match poll_aws_native_authorization(&fixture, &mut pending, now).unwrap() {
        PollAuthorization::Complete(value) => value,
        PollAuthorization::Pending { .. } => panic!("fixture should complete"),
    };
    assert!(fixture.exhausted());
    authorization
}

fn graph_identity_responses() -> Vec<ExpectedResponse> {
    vec![
        expected(
            "Get",
            "/me?",
            json!({"id":"44444444-4444-4444-8444-444444444444","userPrincipalName":"reader@tenant.invalid"}),
        ),
        expected(
            "Get",
            "/organization?",
            json!({"value":[{"id":"11111111-1111-4111-8111-111111111111"}]}),
        ),
    ]
}

fn verified_azure(
    now: DateTime<Utc>,
) -> ai_security_scanner_lib::source_authorization::VerifiedProviderAuthorization {
    let graph_scopes = "openid profile offline_access User.Read Organization.Read.All";
    let mut responses = vec![
        expected(
            "Post",
            "/devicecode",
            json!({
                "device_code":"fixture-secret-device",
                "user_code":"ABCD-EFGH",
                "verification_uri":"https://login.microsoftonline.com/common/oauth2/deviceauth",
                "expires_in":600,
                "interval":1
            }),
        ),
        expected(
            "Post",
            "/token",
            json!({
                "access_token":"fixture-token-graph",
                "refresh_token":"fixture-secret-refresh",
                "expires_in":3600,
                "scope":graph_scopes,
                "token_type":"Bearer"
            }),
        ),
    ];
    responses.extend(graph_identity_responses());
    responses.extend([
        expected(
            "Post",
            "/token",
            json!({
                "access_token":"fixture-token-arm",
                "expires_in":1800,
                "scope":"https://management.azure.com/.default",
                "token_type":"Bearer"
            }),
        ),
        expected(
            "Get",
            "/subscriptions/33333333-3333-4333-8333-333333333333?",
            json!({
                "subscriptionId":"33333333-3333-4333-8333-333333333333",
                "state":"Enabled"
            }),
        ),
        expected(
            "Get",
            "/roleAssignments?",
            json!({"value":[
                {"properties":{"principalId":"44444444-4444-4444-8444-444444444444","roleDefinitionId":"/providers/Microsoft.Authorization/roleDefinitions/acdd72a7-3385-48ef-bd42-f606fba81ae7"}},
                {"properties":{"principalId":"44444444-4444-4444-8444-444444444444","roleDefinitionId":"/providers/Microsoft.Authorization/roleDefinitions/39bc4728-0917-49c7-9d2c-d95423bc2eb4"}}
            ]}),
        ),
    ]);
    let fixture = FixtureHttp::new(responses);
    let (_, mut pending) = begin_microsoft_native_authorization(
        &fixture,
        microsoft_config(ProviderSourceProfile::AzureTenantReadOnlyAccessToken),
        now,
    )
    .unwrap();
    let authorization =
        match poll_microsoft_native_authorization(&fixture, &mut pending, now).unwrap() {
            PollAuthorization::Complete(value) => value,
            PollAuthorization::Pending { .. } => panic!("fixture should complete"),
        };
    assert!(fixture.exhausted());
    authorization
}

#[test]
fn azure_authorization_rejects_every_non_enabled_subscription_state() {
    for state in ["Disabled", "PastDue", "enabled"] {
        let now = Utc::now();
        let graph_scopes = "openid profile offline_access User.Read Organization.Read.All";
        let mut responses = vec![
            expected(
                "Post",
                "/devicecode",
                json!({
                    "device_code":"fixture-secret-device",
                    "user_code":"ABCD-EFGH",
                    "verification_uri":"https://login.microsoftonline.com/common/oauth2/deviceauth",
                    "expires_in":600,
                    "interval":1
                }),
            ),
            expected(
                "Post",
                "/token",
                json!({
                    "access_token":"fixture-token-graph",
                    "refresh_token":"fixture-secret-refresh",
                    "expires_in":3600,
                    "scope":graph_scopes,
                    "token_type":"Bearer"
                }),
            ),
        ];
        responses.extend(graph_identity_responses());
        responses.extend([
            expected(
                "Post",
                "/token",
                json!({
                    "access_token":"fixture-token-arm",
                    "expires_in":1800,
                    "scope":"https://management.azure.com/.default",
                    "token_type":"Bearer"
                }),
            ),
            expected(
                "Get",
                "/subscriptions/33333333-3333-4333-8333-333333333333?",
                json!({
                    "subscriptionId":"33333333-3333-4333-8333-333333333333",
                    "state":state
                }),
            ),
        ]);
        let fixture = FixtureHttp::new(responses);
        let (_, mut pending) = begin_microsoft_native_authorization(
            &fixture,
            microsoft_config(ProviderSourceProfile::AzureTenantReadOnlyAccessToken),
            now,
        )
        .unwrap();
        let error = poll_microsoft_native_authorization(&fixture, &mut pending, now).unwrap_err();
        assert!(
            matches!(error, AppError::NotAuthorized(_)),
            "{state}: {error}"
        );
        assert!(
            error.to_string().contains("Enabled state"),
            "{state}: {error}"
        );
        assert!(fixture.exhausted(), "{state}");
    }
}

fn microsoft365_permissions() -> Vec<&'static str> {
    vec![
        "AdministrativeUnit.Read.All",
        "Application.Read.All",
        "AuditLog.Read.All",
        "Directory.Read.All",
        "Domain.Read.All",
        "Group.Read.All",
        "IdentityRiskEvent.Read.All",
        "Organization.Read.All",
        "Policy.Read.All",
        "Reports.Read.All",
        "RoleManagement.Read.Directory",
        "SecurityEvents.Read.All",
        "User.Read.All",
    ]
}

fn verified_microsoft365(
    now: DateTime<Utc>,
) -> ai_security_scanner_lib::source_authorization::VerifiedProviderAuthorization {
    let scope = format!(
        "openid profile offline_access {}",
        microsoft365_permissions().join(" ")
    );
    let mut responses = vec![
        expected(
            "Post",
            "/devicecode",
            json!({
                "device_code":"fixture-secret-device",
                "user_code":"ABCD-EFGH",
                "verification_uri":"https://login.microsoftonline.com/common/oauth2/deviceauth",
                "expires_in":600,
                "interval":1
            }),
        ),
        expected(
            "Post",
            "/token",
            json!({
                "access_token":"fixture-token-graph",
                "refresh_token":"fixture-secret-refresh",
                "expires_in":1800,
                "scope":scope,
                "token_type":"Bearer"
            }),
        ),
    ];
    responses.extend(graph_identity_responses());
    responses.extend([
        expected("Get", "/auditLogs/", json!({"value":[]})),
        expected("Get", "/policies/", json!({"id":"policy"})),
        expected("Get", "/roleManagement/", json!({"value":[]})),
    ]);
    let fixture = FixtureHttp::new(responses);
    let (_, mut pending) = begin_microsoft_native_authorization(
        &fixture,
        microsoft_config(ProviderSourceProfile::Microsoft365TenantReadOnlyAccessToken),
        now,
    )
    .unwrap();
    let authorization =
        match poll_microsoft_native_authorization(&fixture, &mut pending, now).unwrap() {
            PollAuthorization::Complete(value) => value,
            PollAuthorization::Pending { .. } => panic!("fixture should complete"),
        };
    assert!(fixture.exhausted());
    authorization
}

fn verified_gcp(
    now: DateTime<Utc>,
) -> ai_security_scanner_lib::source_authorization::VerifiedProviderAuthorization {
    let fixture = FixtureHttp::new(vec![
        expected(
            "Post",
            "oauth2.googleapis.com/token",
            json!({
                "access_token":"fixture-token-gcp",
                "expires_in":1800,
                "scope":"openid https://www.googleapis.com/auth/userinfo.email https://www.googleapis.com/auth/cloud-platform.read-only",
                "token_type":"Bearer"
            }),
        ),
        expected(
            "Get",
            "openidconnect.googleapis.com",
            json!({"sub":"google-subject-123","email":"reader@example.invalid"}),
        ),
        expected(
            "Get",
            "/organizations/123456789012",
            json!({"name":"organizations/123456789012"}),
        ),
        expected(
            "Post",
            ":testIamPermissions",
            json!({"permissions":[
                "resourcemanager.organizations.get",
                "resourcemanager.folders.list",
                "resourcemanager.projects.list"
            ]}),
        ),
    ]);
    let (prompt, pending) = begin_gcp_native_authorization(gcp_config(), now).unwrap();
    let state = Url::parse(&prompt.authorization_url)
        .unwrap()
        .query_pairs()
        .find(|(key, _)| key == "state")
        .unwrap()
        .1
        .into_owned();
    let authorization = complete_gcp_native_authorization(
        &fixture,
        pending,
        Zeroizing::new("fixture-secret-code".into()),
        &state,
        now,
    )
    .unwrap();
    assert!(fixture.exhausted());
    authorization
}

fn install_verified(
    verified_authorization: ai_security_scanner_lib::source_authorization::VerifiedProviderAuthorization,
    engines: &[&str],
    now: DateTime<Utc>,
) -> ai_security_scanner_lib::source_authorization::InstalledSourceAuthorization {
    SourceAuthorizationBindings::default()
        .install(
            SourceAuthorizationRequest {
                case_id: "case-1".into(),
                source_id: "source-1".into(),
                allowed_engine_ids: engines.iter().map(|value| (*value).to_owned()).collect(),
                max_checkouts: 1,
                verified_authorization,
            },
            now,
        )
        .unwrap()
}

#[test]
fn all_four_provider_profiles_complete_live_identity_and_permission_verification() {
    let now = Utc::now();
    let cases = [
        (verified_aws(now), vec!["prowler"]),
        (
            verified_azure(now),
            vec!["provider-native-discovery", "prowler"],
        ),
        (
            verified_gcp(now),
            vec!["provider-native-discovery", "prowler"],
        ),
        (verified_microsoft365(now), vec!["maester"]),
    ];
    for (authorization, engines) in cases {
        let verification = authorization.verification().clone();
        assert!(!verification.required_permissions_verified.is_empty());
        assert_eq!(verification.evidence_sha256.len(), 64);
        let installed = install_verified(authorization, &engines, now);
        assert_eq!(installed.provider_verification, verification);
        let serialized = serde_json::to_string(&installed).unwrap();
        assert!(!serialized.contains("fixture-token"));
        assert!(!serialized.contains("fixture-secret"));
        assert!(!serialized.contains("asscap_v1_"));
    }
}

#[test]
fn azure_and_gcp_profiles_release_only_discovery_and_narrow_prowler() {
    let released = BTreeSet::from(["provider-native-discovery", "prowler"]);
    assert_eq!(
        ProviderSourceProfile::AzureTenantReadOnlyAccessToken.allowed_engine_ids(),
        released
    );
    assert_eq!(
        ProviderSourceProfile::GcpOrganizationReadOnlyAccessToken.allowed_engine_ids(),
        released
    );

    let now = Utc::now();
    for (verified_authorization, environment_key) in [
        (verified_azure(now), "AZURE_ACCESS_TOKEN"),
        (verified_gcp(now), "GOOGLE_OAUTH_ACCESS_TOKEN"),
    ] {
        let bindings = SourceAuthorizationBindings::default();
        let installed = bindings
            .install(
                SourceAuthorizationRequest {
                    case_id: "case-1".into(),
                    source_id: "source-1".into(),
                    allowed_engine_ids: released.iter().map(ToString::to_string).collect(),
                    max_checkouts: 1,
                    verified_authorization,
                },
                now,
            )
            .unwrap();
        assert_eq!(
            installed.allowed_engine_ids,
            released.iter().map(ToString::to_string).collect()
        );
        let credentials = bindings
            .checkout("case-1", "source-1", "prowler", now)
            .unwrap();
        assert_eq!(
            credentials.environment_keys().collect::<Vec<_>>(),
            [environment_key]
        );
    }

    for verified_authorization in [verified_azure(now), verified_gcp(now)] {
        let result = SourceAuthorizationBindings::default().install(
            SourceAuthorizationRequest {
                case_id: "case-1".into(),
                source_id: "source-1".into(),
                allowed_engine_ids: BTreeSet::from(["cloudquery".into()]),
                max_checkouts: 1,
                verified_authorization,
            },
            now,
        );
        assert!(matches!(result, Err(AppError::NotAuthorized(_))));
    }
}

#[test]
fn empty_azure_resources_still_produce_an_exact_plannable_subscription() {
    let now = Utc::now();
    let verified_authorization = verified_azure(now);
    let verification = verified_authorization.verification().clone();
    let temporary = tempfile::tempdir().unwrap();
    let storage = Storage::open(temporary.path().join("casework.db")).unwrap();
    let engines = EngineRegistry::load_builtin().unwrap();
    let adapters = builtin_adapter_registry().unwrap();
    let artifacts = ArtifactStore::open(temporary.path().join("artifacts")).unwrap();
    let service = CaseService::new(
        &storage,
        &engines,
        &adapters,
        artifacts.root(),
        temporary.path().join("integrity-signing-key"),
    );
    let case = service
        .create_case(&CreateCaseRequest {
            title: "Empty Azure subscription".into(),
            organization_name: "Example organization".into(),
            employee_range: "1-10".into(),
            assessment_intent: None,
            data_classes: vec![DataClass::General],
            requested_activities: vec![],
            source_kinds: vec![],
            not_applicable_source_kinds: vec![],
            declared_assets: vec![],
            notes: None,
        })
        .unwrap();
    let source = service
        .upsert_source(
            &case.id,
            SourceMutation {
                id: None,
                kind: SourceKind::AzureTenant,
                label: "Azure read-only source".into(),
                status: SourceConnectionStatus::Connected,
                read_only: true,
                metadata: BTreeMap::from([
                    (
                        "provider_profile".into(),
                        serde_json::to_value(ProviderSourceProfile::AzureTenantReadOnlyAccessToken)
                            .unwrap(),
                    ),
                    (
                        "provider_identity".into(),
                        serde_json::Value::String(verification.provider_identity.clone()),
                    ),
                    (
                        PROVIDER_RESOURCE_SCOPE_METADATA_KEY.into(),
                        serde_json::Value::String(verification.resource_scope.clone()),
                    ),
                    (
                        "verification_evidence_sha256".into(),
                        serde_json::Value::String(verification.evidence_sha256.clone()),
                    ),
                ]),
            },
        )
        .unwrap();
    let bindings = SourceAuthorizationBindings::default();
    let installed = bindings
        .install(
            SourceAuthorizationRequest {
                case_id: case.id.clone(),
                source_id: source.id.clone(),
                allowed_engine_ids: BTreeSet::from([
                    "provider-native-discovery".into(),
                    "prowler".into(),
                ]),
                max_checkouts: 2,
                verified_authorization,
            },
            now,
        )
        .unwrap();
    let discovery_credentials = bindings
        .checkout(&case.id, &source.id, "provider-native-discovery", now)
        .unwrap();

    let connector_root = temporary.path().join("connector-artifacts");
    fs::create_dir(&connector_root).unwrap();
    let registry = SnapshotConnectorRegistry::new(&connector_root).unwrap();
    let http = FixtureHttp::new(vec![
        expected(
            "Get",
            "/subscriptions/33333333-3333-4333-8333-333333333333?",
            json!({
                "subscriptionId":"33333333-3333-4333-8333-333333333333",
                "displayName":"Empty production subscription",
                "state":"Enabled"
            }),
        ),
        expected(
            "Get",
            "/subscriptions/33333333-3333-4333-8333-333333333333/resources?",
            json!({"value":[]}),
        ),
    ]);
    let mut persist = |_: &str, _: u16, bytes: &[u8], profile: &str, observed_at: DateTime<Utc>| {
        registry
            .ingest_provider_response(&SourceKind::AzureTenant, bytes, profile, observed_at)
            .map_err(|error| AppError::Storage(error.to_string()))
    };
    let capture = capture_provider_inventory(
        &http,
        &installed,
        &discovery_credentials,
        &AtomicBool::new(false),
        now,
        &mut persist,
    );
    assert!(capture.complete(), "{capture:?}");
    assert_eq!(capture.record_count, 0);
    assert_eq!(capture.successful_pages, 2);
    assert!(http.exhausted());
    service
        .attach_live_provider_capture(
            &case.id,
            &source.id,
            capture.artifact_set.expect("Azure capture artifacts"),
        )
        .unwrap();
    let captured_source = service
        .show_case(&case.id)
        .unwrap()
        .data_sources
        .into_iter()
        .find(|candidate| candidate.id == source.id)
        .unwrap();
    let batch = run_connector(
        &registry.connector_for(&SourceKind::AzureTenant),
        &captured_source,
    )
    .unwrap();
    assert_eq!(batch.assets.len(), 1);
    assert!(
        batch
            .notices
            .iter()
            .any(|notice| notice.contains("connected but empty"))
    );
    service.reconcile_discovery_batch(&case.id, &batch).unwrap();
    let discovered = service.show_case(&case.id).unwrap();
    let subscription = discovered.assets.first().unwrap();
    assert_eq!(subscription.kind, AssetKind::Subscription);
    assert_eq!(subscription.provider.as_deref(), Some("azure"));
    assert!(subscription.discovered_from.contains(&source.id));
    assert!(subscription.identifiers.iter().any(|identifier| {
        identifier.namespace == "azure_subscription_id"
            && identifier.value == "33333333-3333-4333-8333-333333333333"
    }));
    service
        .approve_scope(
            &case.id,
            ScopeApprovalRequest {
                asset_id: subscription.id.clone(),
                permissions: vec![
                    ScanPermission::InventoryRead,
                    ScanPermission::ConfigurationRead,
                ],
                confirmed_by: "Fixture owner".into(),
                expires_at: None,
                authorization_reference: None,
                notes: None,
                external_scope: None,
            },
        )
        .unwrap();
    let plan = service
        .plan_scan(
            &case.id,
            ScanPlanRequest {
                engine_ids: vec!["prowler".into()],
            },
        )
        .unwrap();
    assert!(plan.not_executed.is_empty());
    assert_eq!(plan.executable.len(), 1);
    assert_eq!(plan.executable[0].assets[0].id, subscription.id);
    let runtime_credentials = bindings
        .checkout(&case.id, &source.id, "prowler", now)
        .unwrap();
    assert_eq!(
        runtime_credentials.environment_keys().collect::<Vec<_>>(),
        ["AZURE_ACCESS_TOKEN"]
    );
}

fn provider_ocsf_fixture(provider: &str, native_id: &str) -> Vec<u8> {
    serde_json::to_vec(&json!([{
        "category_name": "Findings",
        "class_name": "Detection Finding",
        "metadata": {
            "event_code": "fixture_iam_check",
            "product": {
                "name": "Prowler",
                "uid": "prowler",
                "vendor_name": "Prowler",
                "version": "5.39.1"
            },
            "version": "1.5.0"
        },
        "finding_info": {
            "analytic": {
                "name": "fixture_iam_check",
                "uid": "fixture_iam_check",
                "type": "Rule",
                "type_id": 1
            },
            "title": "Fixture IAM check",
            "uid": format!("{provider}-fixture-finding")
        },
        "cloud": {
            "account": { "uid": native_id },
            "provider": provider,
            "region": "global"
        },
        "resources": [{
            "name": "fixture-resource",
            "type": "Cloud Resource",
            "uid": format!("{provider}:{native_id}:fixture")
        }],
        "severity": "High",
        "status": "New",
        "status_code": "FAIL"
    }]))
    .unwrap()
}

#[test]
fn azure_and_gcp_ui_capability_checkout_reaches_narrow_prowler_dispatch() {
    for provider in ["azure", "gcp"] {
        let now = Utc::now();
        let (
            source_kind,
            target_kind,
            target_namespace,
            target_id,
            expected_profile,
            expected_environment_key,
            expected_execution_profile,
            verified_authorization,
        ) = match provider {
            "azure" => (
                SourceKind::AzureTenant,
                AssetKind::Subscription,
                "azure_subscription_id",
                "33333333-3333-4333-8333-333333333333",
                ProviderSourceProfile::AzureTenantReadOnlyAccessToken,
                "AZURE_ACCESS_TOKEN",
                "azure_iam_service_static_token_exact_subscription",
                verified_azure(now),
            ),
            "gcp" => (
                SourceKind::GcpOrganization,
                AssetKind::Project,
                "gcp_project_id",
                "security-prod-123",
                ProviderSourceProfile::GcpOrganizationReadOnlyAccessToken,
                "GOOGLE_OAUTH_ACCESS_TOKEN",
                "gcp_iam_four_checks_exact_project",
                verified_gcp(now),
            ),
            _ => unreachable!(),
        };
        let verification = verified_authorization.verification().clone();
        assert_eq!(verification.profile, expected_profile);

        let temporary = tempfile::tempdir().unwrap();
        let storage = Storage::open(temporary.path().join("casework.db")).unwrap();
        let engines = EngineRegistry::load_builtin().unwrap();
        let adapters = builtin_adapter_registry().unwrap();
        let artifacts = ArtifactStore::open(temporary.path().join("artifacts")).unwrap();
        let service = CaseService::new(
            &storage,
            &engines,
            &adapters,
            artifacts.root(),
            temporary.path().join("integrity-signing-key"),
        );
        let case = service
            .create_case(&CreateCaseRequest {
                title: format!("{provider} Prowler integration"),
                organization_name: "Example organization".into(),
                employee_range: "1-10".into(),
                assessment_intent: None,
                data_classes: vec![DataClass::General],
                requested_activities: vec![],
                source_kinds: vec![],
                not_applicable_source_kinds: vec![],
                declared_assets: vec![],
                notes: None,
            })
            .unwrap();
        let source = service
            .upsert_source(
                &case.id,
                SourceMutation {
                    id: None,
                    kind: source_kind.clone(),
                    label: format!("{provider} read-only source"),
                    status: SourceConnectionStatus::Connected,
                    read_only: true,
                    metadata: BTreeMap::from([
                        (
                            "provider_profile".into(),
                            serde_json::to_value(expected_profile).unwrap(),
                        ),
                        (
                            "provider_identity".into(),
                            serde_json::Value::String(verification.provider_identity.clone()),
                        ),
                        (
                            PROVIDER_RESOURCE_SCOPE_METADATA_KEY.into(),
                            serde_json::Value::String(verification.resource_scope.clone()),
                        ),
                        (
                            "verification_evidence_sha256".into(),
                            serde_json::Value::String(verification.evidence_sha256.clone()),
                        ),
                    ]),
                },
            )
            .unwrap();

        let (assets, relations) = if provider == "azure" {
            (
                vec![DiscoveredAsset {
                    observation_key: "subscription".into(),
                    kind: target_kind.clone(),
                    name: "Azure subscription".into(),
                    provider: Some(provider.into()),
                    region: None,
                    stable_identifier: AssetIdentifier {
                        namespace: target_namespace.into(),
                        value: target_id.into(),
                    },
                    additional_identifiers: vec![],
                    internet_exposed: None,
                    contains_sensitive_data: None,
                    metadata: BTreeMap::new(),
                }],
                vec![],
            )
        } else {
            (
                vec![
                    DiscoveredAsset {
                        observation_key: "organization".into(),
                        kind: AssetKind::CloudOrganization,
                        name: "GCP organization".into(),
                        provider: Some(provider.into()),
                        region: None,
                        stable_identifier: AssetIdentifier {
                            namespace: "gcp_organization_id".into(),
                            value: "123456789012".into(),
                        },
                        additional_identifiers: vec![],
                        internet_exposed: None,
                        contains_sensitive_data: None,
                        metadata: BTreeMap::new(),
                    },
                    DiscoveredAsset {
                        observation_key: "folder-security".into(),
                        kind: AssetKind::Other,
                        name: "Security folder".into(),
                        provider: Some(provider.into()),
                        region: None,
                        stable_identifier: AssetIdentifier {
                            namespace: "gcp_folder_id".into(),
                            value: "100".into(),
                        },
                        additional_identifiers: vec![],
                        internet_exposed: None,
                        contains_sensitive_data: None,
                        metadata: BTreeMap::new(),
                    },
                    DiscoveredAsset {
                        observation_key: "folder-production".into(),
                        kind: AssetKind::Other,
                        name: "Production folder".into(),
                        provider: Some(provider.into()),
                        region: None,
                        stable_identifier: AssetIdentifier {
                            namespace: "gcp_folder_id".into(),
                            value: "200".into(),
                        },
                        additional_identifiers: vec![],
                        internet_exposed: None,
                        contains_sensitive_data: None,
                        metadata: BTreeMap::new(),
                    },
                    DiscoveredAsset {
                        observation_key: "project".into(),
                        kind: target_kind.clone(),
                        name: "GCP project".into(),
                        provider: Some(provider.into()),
                        region: None,
                        stable_identifier: AssetIdentifier {
                            namespace: target_namespace.into(),
                            value: target_id.into(),
                        },
                        additional_identifiers: vec![],
                        internet_exposed: None,
                        contains_sensitive_data: None,
                        metadata: BTreeMap::new(),
                    },
                ],
                vec![
                    DiscoveredRelation {
                        from: DiscoveryAssetRef::Observation("organization".into()),
                        to: DiscoveryAssetRef::Observation("folder-security".into()),
                        kind: RelationKind::Contains,
                        evidence_ids: vec!["fixture-provider-folder-root".into()],
                    },
                    DiscoveredRelation {
                        from: DiscoveryAssetRef::Observation("folder-security".into()),
                        to: DiscoveryAssetRef::Observation("folder-production".into()),
                        kind: RelationKind::Contains,
                        evidence_ids: vec!["fixture-provider-folder-child".into()],
                    },
                    DiscoveredRelation {
                        from: DiscoveryAssetRef::Observation("folder-production".into()),
                        to: DiscoveryAssetRef::Observation("project".into()),
                        kind: RelationKind::Contains,
                        evidence_ids: vec!["fixture-provider-project-parent".into()],
                    },
                    // The artifact-backed connector derives this transitive edge only
                    // after proving the unique folder path to the exact organization.
                    DiscoveredRelation {
                        from: DiscoveryAssetRef::Observation("organization".into()),
                        to: DiscoveryAssetRef::Observation("project".into()),
                        kind: RelationKind::Contains,
                        evidence_ids: vec![
                            "fixture-provider-folder-root".into(),
                            "fixture-provider-folder-child".into(),
                            "fixture-provider-project-parent".into(),
                        ],
                    },
                ],
            )
        };
        service
            .reconcile_discovery_batch(
                &case.id,
                &DiscoveryBatch {
                    source_id: source.id.clone(),
                    source_kind,
                    connector_id: format!("fixture-{provider}-discovery"),
                    connector_version: "1".into(),
                    observed_at: now,
                    assets,
                    relations,
                    notices: vec![],
                },
            )
            .unwrap();
        let discovered = service.show_case(&case.id).unwrap();
        let target_asset_id = discovered
            .assets
            .iter()
            .find(|asset| {
                asset.identifiers.iter().any(|identifier| {
                    identifier.namespace == target_namespace && identifier.value == target_id
                })
            })
            .unwrap()
            .id
            .clone();
        service
            .approve_scope(
                &case.id,
                ScopeApprovalRequest {
                    asset_id: target_asset_id,
                    permissions: vec![
                        ScanPermission::InventoryRead,
                        ScanPermission::ConfigurationRead,
                    ],
                    confirmed_by: "Fixture owner".into(),
                    expires_at: None,
                    authorization_reference: None,
                    notes: None,
                    external_scope: None,
                },
            )
            .unwrap();

        // Mirrors the exact allowed_engine_ids emitted by ProviderAuthorizationPanel.
        let ui_engine_bindings =
            BTreeSet::from(["provider-native-discovery".to_owned(), "prowler".to_owned()]);
        let bindings = SourceAuthorizationBindings::default();
        let installed = bindings
            .install(
                SourceAuthorizationRequest {
                    case_id: case.id.clone(),
                    source_id: source.id.clone(),
                    allowed_engine_ids: ui_engine_bindings.clone(),
                    max_checkouts: 1,
                    verified_authorization,
                },
                now,
            )
            .unwrap();
        assert_eq!(installed.allowed_engine_ids, ui_engine_bindings);

        let plan = service
            .plan_scan(
                &case.id,
                ScanPlanRequest {
                    engine_ids: vec!["prowler".into()],
                },
            )
            .unwrap();
        assert!(plan.not_executed.is_empty(), "provider {provider}");
        assert_eq!(plan.executable.len(), 1, "provider {provider}");
        let execution = &plan.executable[0];
        assert_eq!(execution.assets.len(), 1);
        assert_eq!(execution.assets[0].provider.as_deref(), Some(provider));
        assert_eq!(execution.assets[0].kind, target_kind);
        let execution_contract = execution
            .manifest
            .provider_execution_contract(Some(provider), &execution.assets[0].kind)
            .unwrap();
        assert_eq!(execution_contract.profile, expected_execution_profile);

        let credentials = bindings
            .checkout(&execution.case_id, &source.id, &execution.manifest.id, now)
            .unwrap();
        assert_eq!(
            credentials.environment_keys().collect::<Vec<_>>(),
            [expected_environment_key]
        );
        assert!(
            bindings
                .status(&case.id, &source.id, now)
                .unwrap()
                .is_none()
        );

        let runtime = FakeContainerRuntime::default();
        runtime.set_behavior(FakeRunBehavior {
            exit_code: Some(0),
            stdout: vec![],
            stderr: vec![],
            output_files: BTreeMap::from([(
                "prowler.ocsf.json".into(),
                provider_ocsf_fixture(provider, target_id),
            )]),
        });
        let network = NetworkPolicy::managed(
            format!("fixture-{provider}-network"),
            format!("fixture-{provider}-policy"),
            execution_contract.network_destinations.clone(),
            "socks5h://172.29.0.1:1080",
        )
        .unwrap();
        let limits = ResourceLimits {
            memory_mb: execution.manifest.estimated_memory_mb,
            tmpfs_mb: execution.manifest.estimated_disk_mb.clamp(16, 4_096),
            ..ResourceLimits::default()
        };
        let orchestrator = Orchestrator::new(&runtime, &artifacts, &adapters);
        let report = orchestrator
            .execute(
                &EngineExecutionRequest {
                    case_id: &execution.case_id,
                    scan_run_id: &execution.scan_run_id,
                    engine_run_id: &execution.engine_run_id,
                    manifest: &execution.manifest,
                    assets: &execution.assets,
                    scope_grants: &execution.scope_grants,
                    workspace: None,
                    network_policy: &network,
                    resource_limits: &limits,
                    credentials: &credentials,
                    attempt: execution.attempt,
                },
                &CancellationToken::default(),
            )
            .unwrap();
        assert_eq!(report.checkpoint.stage, ExecutionStage::Completed);
        assert_eq!(report.findings.len(), 1);
        assert_eq!(
            report.findings[0].asset_ids,
            [execution.assets[0].id.clone()]
        );
        assert!(
            runtime
                .calls()
                .iter()
                .any(|call| matches!(call, RuntimeCall::Run(_)))
        );
    }
}

#[test]
fn capability_is_exactly_bound_and_secret_surfaces_remain_redacted() {
    let now = Utc::now();
    let bindings = SourceAuthorizationBindings::default();
    let request = SourceAuthorizationRequest {
        case_id: "case-1".into(),
        source_id: "source-1".into(),
        allowed_engine_ids: BTreeSet::from(["prowler".into()]),
        max_checkouts: 1,
        verified_authorization: verified_aws(now),
    };
    let debug = format!("{request:?}");
    assert!(!debug.contains("fixture-secret"));
    assert!(!debug.contains("fixture-token"));
    bindings.install(request, now).unwrap();
    assert!(
        bindings
            .checkout("case-2", "source-1", "prowler", now)
            .is_err()
    );
    assert!(
        bindings
            .checkout("case-1", "source-2", "prowler", now)
            .is_err()
    );
    assert!(
        bindings
            .checkout("case-1", "source-1", "maester", now)
            .is_err()
    );
    let credentials = bindings
        .checkout("case-1", "source-1", "prowler", now)
        .unwrap();
    let credential_debug = format!("{credentials:?}");
    assert!(!credential_debug.contains("fixture-secret"));
    assert!(
        bindings
            .checkout("case-1", "source-1", "prowler", now)
            .is_err()
    );
}

#[test]
fn case_wide_revocation_removes_only_the_selected_cases_capabilities() {
    let now = Utc::now();
    let bindings = SourceAuthorizationBindings::default();
    for (case_id, source_id) in [("case-1", "source-1"), ("case-2", "source-2")] {
        bindings
            .install(
                SourceAuthorizationRequest {
                    case_id: case_id.into(),
                    source_id: source_id.into(),
                    allowed_engine_ids: BTreeSet::from(["prowler".into()]),
                    max_checkouts: 2,
                    verified_authorization: verified_aws(now),
                },
                now,
            )
            .unwrap();
    }

    assert_eq!(bindings.revoke_case("case-1", now).unwrap(), 1);
    assert!(
        bindings
            .status("case-1", "source-1", now)
            .unwrap()
            .is_none()
    );
    assert!(
        bindings
            .checkout("case-1", "source-1", "prowler", now)
            .is_err()
    );
    assert!(
        bindings
            .status("case-2", "source-2", now)
            .unwrap()
            .is_some()
    );
    assert!(
        bindings
            .checkout("case-2", "source-2", "prowler", now)
            .is_ok()
    );
    assert_eq!(bindings.revoke_case("case-1", now).unwrap(), 0);
}

#[test]
fn case_wide_session_cancel_drops_only_matching_pending_secret_flows() {
    let now = Utc::now();
    let fixture = FixtureHttp::new(
        ["case-1", "case-2"]
            .into_iter()
            .flat_map(|_| {
                [
                    expected(
                        "Post",
                        "/client/register",
                        json!({
                            "clientId":"fixture-client",
                            "clientSecret":"fixture-secret-client",
                            "clientIdIssuedAt":now.timestamp(),
                            "clientSecretExpiresAt":(now + Duration::minutes(15)).timestamp()
                        }),
                    ),
                    expected(
                        "Post",
                        "/device_authorization",
                        json!({
                            "deviceCode":"fixture-secret-device",
                            "userCode":"ABCD-EFGH",
                            "verificationUri":"https://oidc.us-east-1.amazonaws.com/verify",
                            "verificationUriComplete":"https://oidc.us-east-1.amazonaws.com/verify?user_code=ABCD-EFGH",
                            "expiresIn":600,
                            "interval":1
                        }),
                    ),
                ]
            })
            .collect(),
    );
    let sessions = ProviderAuthorizationSessions::default();
    let mut ids = Vec::new();
    for (case_id, source_id) in [("case-1", "source-1"), ("case-2", "source-2")] {
        let prompt = sessions
            .begin(
                &fixture,
                BeginProviderAuthorizationRequest {
                    case_id: case_id.into(),
                    source_id: source_id.into(),
                    allowed_engine_ids: BTreeSet::from(["prowler".into()]),
                    max_checkouts: 1,
                    authorization: ProviderAuthorizationConfig::Aws {
                        config: aws_config(),
                    },
                },
                now,
            )
            .unwrap();
        let ProviderAuthorizationPrompt::Device { session_id, .. } = prompt else {
            panic!("AWS authorization must use a device prompt");
        };
        ids.push(session_id);
    }
    assert!(fixture.exhausted());

    assert_eq!(sessions.cancel_case("case-1").unwrap(), 1);
    assert!(!sessions.cancel(&ids[0]).unwrap());
    assert!(sessions.cancel(&ids[1]).unwrap());
    assert_eq!(sessions.cancel_case("case-1").unwrap(), 0);
}

#[test]
fn provider_permission_failure_never_issues_a_capability() {
    let now = Utc::now();
    let fixture = FixtureHttp::new(vec![
        expected(
            "Post",
            "oauth2.googleapis.com/token",
            json!({
                "access_token":"fixture-token-gcp",
                "expires_in":1800,
                "scope":"openid https://www.googleapis.com/auth/userinfo.email https://www.googleapis.com/auth/cloud-platform.read-only",
                "token_type":"Bearer"
            }),
        ),
        expected(
            "Get",
            "openidconnect.googleapis.com",
            json!({"sub":"subject"}),
        ),
        expected(
            "Get",
            "/organizations/123456789012",
            json!({"name":"organizations/123456789012"}),
        ),
        expected(
            "Post",
            ":testIamPermissions",
            json!({"permissions":[
                "resourcemanager.organizations.get",
                "resourcemanager.folders.list",
                "resourcemanager.projects.list",
                "resourcemanager.organizations.setIamPolicy"
            ]}),
        ),
    ]);
    let (prompt, pending) = begin_gcp_native_authorization(gcp_config(), now).unwrap();
    let state = Url::parse(&prompt.authorization_url)
        .unwrap()
        .query_pairs()
        .find(|(key, _)| key == "state")
        .unwrap()
        .1
        .into_owned();
    let error = complete_gcp_native_authorization(
        &fixture,
        pending,
        Zeroizing::new("fixture-code".into()),
        &state,
        now,
    )
    .unwrap_err();
    assert!(error.to_string().contains("prohibited mutation"));
}

#[test]
fn secret_fields_and_long_lived_tokens_are_rejected() {
    let secret_config = r#"{
      "tenant_id":"11111111-1111-4111-8111-111111111111",
      "public_client_id":"22222222-2222-4222-8222-222222222222",
      "profile":"microsoft365_tenant_read_only_access_token",
      "subscription_id":null,
      "client_secret":"must-never-be-accepted"
    }"#;
    assert!(serde_json::from_str::<MicrosoftNativeAuthorizationConfig>(secret_config).is_err());

    let now = Utc::now();
    let fixture = FixtureHttp::new(vec![
        expected(
            "Post",
            "/devicecode",
            json!({
                "device_code":"fixture-device",
                "user_code":"ABCD",
                "verification_uri":"https://login.microsoftonline.com/common/oauth2/deviceauth",
                "expires_in":600,
                "interval":1
            }),
        ),
        expected(
            "Post",
            "/token",
            json!({
                "access_token":"fixture-token",
                "expires_in":7200,
                "scope":format!("openid profile offline_access {}", microsoft365_permissions().join(" ")),
                "token_type":"Bearer"
            }),
        ),
    ]);
    let (_, mut pending) = begin_microsoft_native_authorization(
        &fixture,
        microsoft_config(ProviderSourceProfile::Microsoft365TenantReadOnlyAccessToken),
        now,
    )
    .unwrap();
    assert!(poll_microsoft_native_authorization(&fixture, &mut pending, now).is_err());
}

#[test]
fn device_poll_pending_is_explicit_and_does_not_fabricate_verification() {
    let now = Utc::now();
    let fixture = FixtureHttp::new(vec![
        expected(
            "Post",
            "/devicecode",
            json!({
                "device_code":"fixture-device",
                "user_code":"ABCD",
                "verification_uri":"https://login.microsoftonline.com/common/oauth2/deviceauth",
                "expires_in":600,
                "interval":3
            }),
        ),
        ExpectedResponse {
            method: "Post",
            path_contains: "/token",
            response: ProviderHttpResponse::new(
                400,
                serde_json::to_vec(&json!({"error":"authorization_pending"})).unwrap(),
            ),
        },
    ]);
    let (_, mut pending) = begin_microsoft_native_authorization(
        &fixture,
        microsoft_config(ProviderSourceProfile::Microsoft365TenantReadOnlyAccessToken),
        now,
    )
    .unwrap();
    assert!(matches!(
        poll_microsoft_native_authorization(&fixture, &mut pending, now).unwrap(),
        PollAuthorization::Pending {
            retry_after_seconds: 3
        }
    ));
}

#[test]
fn public_configuration_contains_no_embedded_client_ids() {
    let source = include_str!("../src/source_authorization/provider.rs");
    assert!(!source.contains("00001111-aaaa-2222-bbbb-3333cccc4444"));
    assert!(source.contains("operator-registered OAuth Desktop client ID"));
    assert_eq!(
        BootstrapProvider::Aws,
        aws_config()
            .role_arn
            .starts_with("arn:")
            .then_some(BootstrapProvider::Aws)
            .unwrap()
    );
}

#[test]
fn bootstrap_scanner_material_crosses_only_the_bounded_one_shot_frame() {
    let now = Utc::now();
    let fixture = FixtureHttp::new(vec![
        expected(
            "Get",
            "iam.googleapis.com/v1/projects/-/serviceAccounts/",
            json!({
                "name":"projects/fixture-project/serviceAccounts/ai-security-scanner-case@fixture-project.iam.gserviceaccount.com",
                "email":"ai-security-scanner-case@fixture-project.iam.gserviceaccount.com",
                "uniqueId":"123456789012345678901"
            }),
        ),
        expected(
            "Get",
            "/organizations/123456789012",
            json!({"name":"organizations/123456789012"}),
        ),
        expected(
            "Post",
            ":testIamPermissions",
            json!({"permissions":[
                "resourcemanager.organizations.get",
                "resourcemanager.folders.list",
                "resourcemanager.projects.list"
            ]}),
        ),
    ]);
    let authorization = verify_bootstrap_gcp_token(
        &fixture,
        &gcp_config(),
        "ai-security-scanner-case@fixture-project.iam.gserviceaccount.com".into(),
        "123456789012345678901".into(),
        Zeroizing::new("fixture-token-bootstrap".into()),
        1800,
        now,
    )
    .unwrap();
    let mut frame = Vec::new();
    write_verified_authorization_one_shot(&mut frame, authorization).unwrap();
    assert!(
        frame
            .windows(b"fixture-token-bootstrap".len())
            .any(|window| { window == b"fixture-token-bootstrap" })
    );
    // The pipe frame is intentionally binary and non-serde. It is consumed
    // directly into the in-memory capability service and never rendered.
    assert!(serde_json::from_slice::<serde_json::Value>(&frame).is_err());
    let decoded = read_verified_authorization_one_shot(frame.as_slice()).unwrap();
    let installed = install_verified(decoded, &["provider-native-discovery"], now);
    let status = serde_json::to_string(&installed).unwrap();
    assert!(!status.contains("fixture-token-bootstrap"));
    assert!(fixture.exhausted());
}

#[test]
fn one_gcp_discovery_plus_nine_exact_projects_complete_the_bounded_lifecycle() {
    let now = Utc::now();
    let verified_authorization = verified_gcp(now);
    let verification = verified_authorization.verification().clone();
    let temporary = tempfile::tempdir().unwrap();
    let storage = Storage::open(temporary.path().join("casework.db")).unwrap();
    let engines = EngineRegistry::load_builtin().unwrap();
    let adapters = builtin_adapter_registry().unwrap();
    let artifacts = ArtifactStore::open(temporary.path().join("artifacts")).unwrap();
    let service = CaseService::new(
        &storage,
        &engines,
        &adapters,
        artifacts.root(),
        temporary.path().join("integrity-signing-key"),
    );
    let case = service
        .create_case(&CreateCaseRequest {
            title: "Nine-project GCP lifecycle".into(),
            organization_name: "Example organization".into(),
            employee_range: "1-10".into(),
            assessment_intent: None,
            data_classes: vec![DataClass::General],
            requested_activities: vec![],
            source_kinds: vec![],
            not_applicable_source_kinds: vec![],
            declared_assets: vec![],
            notes: None,
        })
        .unwrap();
    let source = service
        .upsert_source(
            &case.id,
            SourceMutation {
                id: None,
                kind: SourceKind::GcpOrganization,
                label: "GCP organization source".into(),
                status: SourceConnectionStatus::Connected,
                read_only: true,
                metadata: BTreeMap::from([
                    (
                        "provider_profile".into(),
                        serde_json::to_value(
                            ProviderSourceProfile::GcpOrganizationReadOnlyAccessToken,
                        )
                        .unwrap(),
                    ),
                    (
                        "provider_identity".into(),
                        serde_json::Value::String(verification.provider_identity.clone()),
                    ),
                    (
                        PROVIDER_RESOURCE_SCOPE_METADATA_KEY.into(),
                        serde_json::Value::String(verification.resource_scope.clone()),
                    ),
                    (
                        "verification_evidence_sha256".into(),
                        serde_json::Value::String(verification.evidence_sha256.clone()),
                    ),
                ]),
            },
        )
        .unwrap();

    let organization_key = "organization".to_owned();
    let mut discovered_assets = vec![DiscoveredAsset {
        observation_key: organization_key.clone(),
        kind: AssetKind::CloudOrganization,
        name: "GCP organization 123456789012".into(),
        provider: Some("gcp".into()),
        region: None,
        stable_identifier: AssetIdentifier {
            namespace: "gcp_organization_id".into(),
            value: "123456789012".into(),
        },
        additional_identifiers: vec![],
        internet_exposed: None,
        contains_sensitive_data: None,
        metadata: BTreeMap::new(),
    }];
    let mut discovered_relations = Vec::new();
    let expected_project_ids = (0..9)
        .map(|index| format!("security-project-{index:02}"))
        .collect::<BTreeSet<_>>();
    for project_id in &expected_project_ids {
        let project_key = format!("project:{project_id}");
        discovered_assets.push(DiscoveredAsset {
            observation_key: project_key.clone(),
            kind: AssetKind::Project,
            name: project_id.clone(),
            provider: Some("gcp".into()),
            region: None,
            stable_identifier: AssetIdentifier {
                namespace: "gcp_project_id".into(),
                value: project_id.clone(),
            },
            additional_identifiers: vec![],
            internet_exposed: None,
            contains_sensitive_data: None,
            metadata: BTreeMap::new(),
        });
        discovered_relations.push(DiscoveredRelation {
            from: DiscoveryAssetRef::Observation(organization_key.clone()),
            to: DiscoveryAssetRef::Observation(project_key),
            kind: RelationKind::Contains,
            evidence_ids: vec!["fixture-gcp-hierarchy".into()],
        });
    }
    service
        .reconcile_discovery_batch(
            &case.id,
            &DiscoveryBatch {
                source_id: source.id.clone(),
                source_kind: SourceKind::GcpOrganization,
                connector_id: "fixture-gcp-nine-projects".into(),
                connector_version: "1".into(),
                observed_at: now,
                assets: discovered_assets,
                relations: discovered_relations,
                notices: vec![],
            },
        )
        .unwrap();
    let discovered = service.show_case(&case.id).unwrap();
    let projects = discovered
        .assets
        .iter()
        .filter(|asset| asset.kind == AssetKind::Project)
        .collect::<Vec<_>>();
    assert_eq!(projects.len(), 9);
    for project in projects {
        service
            .approve_scope(
                &case.id,
                ScopeApprovalRequest {
                    asset_id: project.id.clone(),
                    permissions: vec![
                        ScanPermission::InventoryRead,
                        ScanPermission::ConfigurationRead,
                    ],
                    confirmed_by: "Fixture owner".into(),
                    expires_at: None,
                    authorization_reference: None,
                    notes: None,
                    external_scope: None,
                },
            )
            .unwrap();
    }

    let plan = service
        .plan_scan(
            &case.id,
            ScanPlanRequest {
                engine_ids: vec!["prowler".into()],
            },
        )
        .unwrap();
    assert!(plan.not_executed.is_empty(), "{:?}", plan.not_executed);
    assert_eq!(plan.executable.len(), 9);
    let planned_project_ids = plan
        .executable
        .iter()
        .map(|execution| {
            assert_eq!(execution.assets.len(), 1);
            assert_eq!(execution.assets[0].provider.as_deref(), Some("gcp"));
            execution.assets[0]
                .identifiers
                .iter()
                .find(|identifier| identifier.namespace == "gcp_project_id")
                .unwrap()
                .value
                .clone()
        })
        .collect::<BTreeSet<_>>();
    assert_eq!(planned_project_ids, expected_project_ids);

    let bindings = SourceAuthorizationBindings::default();
    let installed = bindings
        .install(
            SourceAuthorizationRequest {
                case_id: case.id.clone(),
                source_id: source.id.clone(),
                allowed_engine_ids: BTreeSet::from([
                    "provider-native-discovery".into(),
                    "prowler".into(),
                ]),
                max_checkouts: 10,
                verified_authorization,
            },
            now,
        )
        .unwrap();
    assert_eq!(installed.max_checkouts, 10);
    bindings
        .checkout(&case.id, &source.id, "provider-native-discovery", now)
        .unwrap();

    let runtime = FakeContainerRuntime::default();
    let orchestrator = Orchestrator::new(&runtime, &artifacts, &adapters);
    for execution in &plan.executable {
        let project_id = execution.assets[0]
            .identifiers
            .iter()
            .find(|identifier| identifier.namespace == "gcp_project_id")
            .unwrap()
            .value
            .clone();
        let contract = execution
            .manifest
            .provider_execution_contract(Some("gcp"), &AssetKind::Project)
            .unwrap();
        assert_eq!(contract.profile, "gcp_iam_four_checks_exact_project");
        let credentials = bindings
            .checkout(&case.id, &source.id, "prowler", now)
            .unwrap();
        runtime.set_behavior(FakeRunBehavior {
            exit_code: Some(0),
            stdout: vec![],
            stderr: vec![],
            output_files: BTreeMap::from([(
                "prowler.ocsf.json".into(),
                provider_ocsf_fixture("gcp", &project_id),
            )]),
        });
        let network = NetworkPolicy::managed(
            format!("fixture-gcp-network-{project_id}"),
            format!("fixture-gcp-policy-{project_id}"),
            contract.network_destinations.clone(),
            "socks5h://172.29.0.1:1080",
        )
        .unwrap();
        let report = orchestrator
            .execute(
                &EngineExecutionRequest {
                    case_id: &execution.case_id,
                    scan_run_id: &execution.scan_run_id,
                    engine_run_id: &execution.engine_run_id,
                    manifest: &execution.manifest,
                    assets: &execution.assets,
                    scope_grants: &execution.scope_grants,
                    workspace: None,
                    network_policy: &network,
                    resource_limits: &ResourceLimits {
                        memory_mb: execution.manifest.estimated_memory_mb,
                        tmpfs_mb: execution.manifest.estimated_disk_mb.clamp(16, 4_096),
                        ..ResourceLimits::default()
                    },
                    credentials: &credentials,
                    attempt: execution.attempt,
                },
                &CancellationToken::default(),
            )
            .unwrap();
        assert_eq!(report.checkpoint.stage, ExecutionStage::Completed);
        assert_eq!(report.findings.len(), 1);
        assert_eq!(
            report.findings[0].asset_ids,
            [execution.assets[0].id.clone()]
        );
    }
    assert_eq!(
        runtime
            .calls()
            .iter()
            .filter(|call| matches!(call, RuntimeCall::Run(_)))
            .count(),
        9
    );
    assert!(
        bindings
            .status(&case.id, &source.id, now)
            .unwrap()
            .is_none()
    );
    assert!(matches!(
        bindings.checkout(&case.id, &source.id, "prowler", now),
        Err(AppError::NotAuthorized(_))
    ));
}
