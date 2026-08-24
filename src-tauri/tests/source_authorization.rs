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
    ProviderSourceProfile, SourceAuthorizationBindings, SourceAuthorizationRequest,
    read_verified_authorization_one_shot, write_verified_authorization_one_shot,
};
use ai_security_scanner_lib::{bootstrap::BootstrapProvider, error::AppError};
use chrono::{DateTime, Duration, Utc};
use serde_json::json;
use std::collections::{BTreeSet, VecDeque};
use std::sync::Mutex;
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
            json!({"subscriptionId":"33333333-3333-4333-8333-333333333333"}),
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
                "resourcemanager.projects.get",
                "cloudasset.assets.searchAllResources",
                "iam.roles.get"
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
        (verified_azure(now), vec!["provider-native-discovery"]),
        (verified_gcp(now), vec!["provider-native-discovery"]),
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
fn azure_and_gcp_profiles_do_not_claim_aws_only_scanner_images() {
    let discovery_only = BTreeSet::from(["provider-native-discovery"]);
    assert_eq!(
        ProviderSourceProfile::AzureTenantReadOnlyAccessToken.allowed_engine_ids(),
        discovery_only
    );
    assert_eq!(
        ProviderSourceProfile::GcpOrganizationReadOnlyAccessToken.allowed_engine_ids(),
        discovery_only
    );

    for verified_authorization in [verified_azure(Utc::now()), verified_gcp(Utc::now())] {
        let result = SourceAuthorizationBindings::default().install(
            SourceAuthorizationRequest {
                case_id: "case-1".into(),
                source_id: "source-1".into(),
                allowed_engine_ids: BTreeSet::from(["prowler".into()]),
                max_checkouts: 1,
                verified_authorization,
            },
            Utc::now(),
        );
        assert!(matches!(result, Err(AppError::NotAuthorized(_))));
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
                "resourcemanager.projects.get",
                "cloudasset.assets.searchAllResources",
                "iam.roles.get",
                "iam.serviceAccountKeys.create"
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
                "resourcemanager.projects.get",
                "cloudasset.assets.searchAllResources",
                "iam.roles.get"
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
