//! Provider-native public-client authorization and live read-only verification.
//!
//! This module intentionally uses the providers' documented protocol endpoints
//! directly. Deployments must supply their own non-secret public OAuth client
//! registration where the provider requires one; no sample or placeholder
//! client identifier is accepted.

use super::{
    ProviderSecretMaterial, ProviderSourceProfile, ProviderVerificationState,
    SecretEnvironmentValue, VerifiedProviderAuthorization,
};
use crate::bootstrap::BootstrapProvider;
use crate::credential_vault::ReadOnlyCredentialSource;
use crate::error::{AppError, AppResult};
use base64::Engine as _;
use chrono::{DateTime, Duration, Utc};
use reqwest::blocking::Client;
use reqwest::header::{HeaderName, HeaderValue};
use serde::{Deserialize, Deserializer, Serialize};
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet};
use std::fmt;
use std::io::Read;
use std::time::Duration as StdDuration;
use url::Url;
use zeroize::Zeroizing;

const MAX_PROVIDER_RESPONSE_BYTES: usize = 1024 * 1024;
const MICROSOFT_GRAPH_ROOT: &str = "https://graph.microsoft.com/v1.0";
const MICROSOFT_ARM_ROOT: &str = "https://management.azure.com";
const GOOGLE_AUTH_ENDPOINT: &str = "https://accounts.google.com/o/oauth2/v2/auth";
const GOOGLE_TOKEN_ENDPOINT: &str = "https://oauth2.googleapis.com/token";
const GOOGLE_USERINFO_ENDPOINT: &str = "https://openidconnect.googleapis.com/v1/userinfo";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProviderHttpMethod {
    Get,
    Post,
    Put,
    Delete,
}

impl ProviderHttpMethod {
    fn as_reqwest(self) -> reqwest::Method {
        match self {
            Self::Get => reqwest::Method::GET,
            Self::Post => reqwest::Method::POST,
            Self::Put => reqwest::Method::PUT,
            Self::Delete => reqwest::Method::DELETE,
        }
    }
}

/// A provider request whose authentication headers and body stay in zeroizing
/// memory. Debug output exposes only method and endpoint.
pub struct ProviderHttpRequest {
    method: ProviderHttpMethod,
    url: Url,
    headers: Vec<(String, Zeroizing<String>)>,
    body: Zeroizing<Vec<u8>>,
}

impl ProviderHttpRequest {
    pub fn method(&self) -> ProviderHttpMethod {
        self.method
    }

    pub fn url(&self) -> &Url {
        &self.url
    }

    /// Intended for an in-process HTTP transport or implementation fixture.
    /// Callers must never log or persist this data.
    pub fn sensitive_headers(&self) -> impl Iterator<Item = (&str, &str)> {
        self.headers
            .iter()
            .map(|(name, value)| (name.as_str(), value.as_str()))
    }

    /// Intended for an in-process HTTP transport or implementation fixture.
    /// Callers must never log or persist this data.
    pub fn sensitive_body(&self) -> &[u8] {
        self.body.as_slice()
    }
}

impl fmt::Debug for ProviderHttpRequest {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ProviderHttpRequest")
            .field("method", &self.method)
            .field("url", &self.url)
            .field("headers", &"[REDACTED]")
            .field("body", &"[REDACTED]")
            .finish()
    }
}

pub struct ProviderHttpResponse {
    pub status: u16,
    /// Only non-secret provider request/correlation headers belong here.
    pub request_headers: BTreeMap<String, String>,
    body: Zeroizing<Vec<u8>>,
}

impl ProviderHttpResponse {
    pub fn new(status: u16, body: impl Into<Vec<u8>>) -> Self {
        Self {
            status,
            request_headers: BTreeMap::new(),
            body: Zeroizing::new(body.into()),
        }
    }

    pub fn with_request_header(
        mut self,
        name: impl Into<String>,
        value: impl Into<String>,
    ) -> Self {
        self.request_headers.insert(name.into(), value.into());
        self
    }

    pub(crate) fn body(&self) -> &[u8] {
        self.body.as_slice()
    }
}

impl fmt::Debug for ProviderHttpResponse {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ProviderHttpResponse")
            .field("status", &self.status)
            .field("request_headers", &self.request_headers)
            .field("body", &"[REDACTED]")
            .finish()
    }
}

pub trait ProviderHttp: Send + Sync {
    fn execute(&self, request: ProviderHttpRequest) -> AppResult<ProviderHttpResponse>;
}

pub struct ReqwestProviderHttp {
    client: Client,
}

impl ReqwestProviderHttp {
    pub fn new() -> AppResult<Self> {
        Self::with_timeout(
            StdDuration::from_secs(10),
            StdDuration::from_secs(30),
            "ai-security-scanner/0.1 provider-authorization",
        )
    }

    pub fn new_discovery() -> AppResult<Self> {
        Self::with_timeout(
            StdDuration::from_secs(5),
            StdDuration::from_secs(10),
            "ai-security-scanner/0.1 provider-discovery",
        )
    }

    fn with_timeout(
        connect_timeout: StdDuration,
        timeout: StdDuration,
        user_agent: &str,
    ) -> AppResult<Self> {
        let client = Client::builder()
            .redirect(reqwest::redirect::Policy::none())
            .no_proxy()
            .connect_timeout(connect_timeout)
            .timeout(timeout)
            .user_agent(user_agent)
            .build()
            .map_err(|_| AppError::NotAvailable("provider HTTP client could not start".into()))?;
        Ok(Self { client })
    }
}

impl ProviderHttp for ReqwestProviderHttp {
    fn execute(&self, request: ProviderHttpRequest) -> AppResult<ProviderHttpResponse> {
        validate_provider_endpoint(&request.url)?;
        let mut builder = self
            .client
            .request(request.method.as_reqwest(), request.url.clone());
        for (name, value) in &request.headers {
            let name = HeaderName::from_bytes(name.as_bytes()).map_err(|_| {
                AppError::InvalidRequest("provider HTTP header name is invalid".into())
            })?;
            let value = HeaderValue::from_str(value.as_str()).map_err(|_| {
                AppError::InvalidRequest("provider HTTP header value is invalid".into())
            })?;
            builder = builder.header(name, value);
        }
        if !request.body.is_empty() {
            builder = builder.body(request.body.to_vec());
        }
        let response = builder.send().map_err(|_| {
            AppError::NotAvailable("provider endpoint could not be reached safely".into())
        })?;
        if response
            .content_length()
            .is_some_and(|length| length > MAX_PROVIDER_RESPONSE_BYTES as u64)
        {
            return Err(AppError::NotAvailable(
                "provider response exceeded the authorization limit".into(),
            ));
        }
        let status = response.status().as_u16();
        let mut request_headers = BTreeMap::new();
        for name in [
            "x-amzn-requestid",
            "x-amz-request-id",
            "request-id",
            "x-ms-request-id",
            "x-guploader-uploadid",
        ] {
            if let Some(value) = response
                .headers()
                .get(name)
                .and_then(|value| value.to_str().ok())
                && safe_metadata(value, 256)
            {
                request_headers.insert(name.to_owned(), value.to_owned());
            }
        }
        let mut body = Zeroizing::new(Vec::new());
        response
            .take(MAX_PROVIDER_RESPONSE_BYTES as u64 + 1)
            .read_to_end(&mut body)
            .map_err(|_| AppError::NotAvailable("provider response could not be read".into()))?;
        if body.len() > MAX_PROVIDER_RESPONSE_BYTES {
            return Err(AppError::NotAvailable(
                "provider response exceeded the authorization limit".into(),
            ));
        }
        Ok(ProviderHttpResponse {
            status,
            request_headers,
            body,
        })
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct AwsNativeAuthorizationConfig {
    pub start_url: String,
    pub region: String,
    pub account_id: String,
    pub role_name: String,
    pub role_arn: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct MicrosoftNativeAuthorizationConfig {
    pub tenant_id: String,
    pub public_client_id: String,
    pub profile: ProviderSourceProfile,
    pub subscription_id: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct GcpNativeAuthorizationConfig {
    pub public_client_id: String,
    pub redirect_uri: String,
    pub organization_id: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct DeviceAuthorizationPrompt {
    pub provider: BootstrapProvider,
    pub verification_uri: String,
    pub verification_uri_complete: Option<String>,
    pub user_code: String,
    pub expires_at: DateTime<Utc>,
    pub poll_interval_seconds: u64,
    pub safety_notice: String,
}

pub struct AwsPendingDeviceAuthorization {
    pub(crate) config: AwsNativeAuthorizationConfig,
    client_id: Zeroizing<String>,
    client_secret: Zeroizing<String>,
    device_code: Zeroizing<String>,
    expires_at: DateTime<Utc>,
    poll_interval_seconds: u64,
}

impl fmt::Debug for AwsPendingDeviceAuthorization {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("AwsPendingDeviceAuthorization")
            .field("config", &self.config)
            .field("secrets", &"[REDACTED]")
            .field("expires_at", &self.expires_at)
            .finish()
    }
}

pub struct MicrosoftPendingDeviceAuthorization {
    config: MicrosoftNativeAuthorizationConfig,
    device_code: Zeroizing<String>,
    expires_at: DateTime<Utc>,
    poll_interval_seconds: u64,
    requested_scopes: Vec<String>,
}

impl fmt::Debug for MicrosoftPendingDeviceAuthorization {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("MicrosoftPendingDeviceAuthorization")
            .field("config", &self.config)
            .field("device_code", &"[REDACTED]")
            .field("expires_at", &self.expires_at)
            .field("requested_scopes", &self.requested_scopes)
            .finish()
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct GooglePkcePrompt {
    pub provider: BootstrapProvider,
    pub authorization_url: String,
    pub redirect_uri: String,
    pub expires_at: DateTime<Utc>,
    pub safety_notice: String,
}

pub struct GooglePendingPkceAuthorization {
    config: GcpNativeAuthorizationConfig,
    code_verifier: Zeroizing<String>,
    state: Zeroizing<String>,
    expires_at: DateTime<Utc>,
}

impl fmt::Debug for GooglePendingPkceAuthorization {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("GooglePendingPkceAuthorization")
            .field("config", &self.config)
            .field("secrets", &"[REDACTED]")
            .field("expires_at", &self.expires_at)
            .finish()
    }
}

pub enum PollAuthorization<T> {
    Pending { retry_after_seconds: u64 },
    Complete(T),
}

impl<T> fmt::Debug for PollAuthorization<T> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Pending {
                retry_after_seconds,
            } => formatter
                .debug_struct("Pending")
                .field("retry_after_seconds", retry_after_seconds)
                .finish(),
            Self::Complete(_) => formatter.write_str("Complete([REDACTED_AUTHORIZATION])"),
        }
    }
}

pub fn begin_aws_native_authorization(
    http: &dyn ProviderHttp,
    config: AwsNativeAuthorizationConfig,
    now: DateTime<Utc>,
) -> AppResult<(DeviceAuthorizationPrompt, AwsPendingDeviceAuthorization)> {
    validate_aws_config(&config)?;
    let oidc_root = format!("https://oidc.{}.amazonaws.com", config.region);
    let register = execute_json::<AwsRegisterClientResponse>(
        http,
        json_request(
            ProviderHttpMethod::Post,
            &format!("{oidc_root}/client/register"),
            &serde_json::json!({
                "clientName": "ai-security-scanner",
                "clientType": "public",
                "grantTypes": ["urn:ietf:params:oauth:grant-type:device_code"],
                "scopes": ["sso:account:access"]
            }),
            Vec::new(),
        )?,
        &[200],
        "AWS IAM Identity Center client registration",
    )?;
    if register.client_id.is_empty() || register.client_secret.is_empty() {
        return Err(AppError::NotAuthorized(
            "AWS IAM Identity Center returned an incomplete public-client registration".into(),
        ));
    }
    let device = execute_json::<AwsDeviceResponse>(
        http,
        json_request(
            ProviderHttpMethod::Post,
            &format!("{oidc_root}/device_authorization"),
            &serde_json::json!({
                "clientId": register.client_id.as_str(),
                "clientSecret": register.client_secret.as_str(),
                "startUrl": config.start_url
            }),
            Vec::new(),
        )?,
        &[200],
        "AWS IAM Identity Center device authorization",
    )?;
    validate_device_response(&device.verification_uri, device.expires_in, device.interval)?;
    let expires_at = now + Duration::seconds(i64::from(device.expires_in.min(900)));
    let prompt = DeviceAuthorizationPrompt {
        provider: BootstrapProvider::Aws,
        verification_uri: device.verification_uri,
        verification_uri_complete: device.verification_uri_complete,
        user_code: device.user_code,
        expires_at,
        poll_interval_seconds: u64::from(device.interval.clamp(1, 30)),
        safety_notice: "Sign in only on the AWS-hosted access portal. The displayed device code is single-use and expires shortly; never paste an AWS key or password into ai-security-scanner.".into(),
    };
    let pending = AwsPendingDeviceAuthorization {
        config,
        client_id: register.client_id,
        client_secret: register.client_secret,
        device_code: device.device_code,
        expires_at,
        poll_interval_seconds: prompt.poll_interval_seconds,
    };
    Ok((prompt, pending))
}

pub fn poll_aws_native_authorization(
    http: &dyn ProviderHttp,
    pending: &mut AwsPendingDeviceAuthorization,
    now: DateTime<Utc>,
) -> AppResult<PollAuthorization<VerifiedProviderAuthorization>> {
    match poll_aws_role_credentials(http, pending, now)? {
        PollAuthorization::Pending {
            retry_after_seconds,
        } => Ok(PollAuthorization::Pending {
            retry_after_seconds,
        }),
        PollAuthorization::Complete(credentials) => verify_aws_credentials(
            http,
            &pending.config,
            credentials,
            ReadOnlyCredentialSource::ProviderNative,
            now,
            "aws_iam_identity_center_device_code",
        )
        .map(PollAuthorization::Complete),
    }
}

pub(crate) fn poll_aws_role_credentials(
    http: &dyn ProviderHttp,
    pending: &mut AwsPendingDeviceAuthorization,
    now: DateTime<Utc>,
) -> AppResult<PollAuthorization<AwsRoleCredentials>> {
    if now >= pending.expires_at {
        return Err(AppError::NotAuthorized(
            "AWS device authorization expired before completion".into(),
        ));
    }
    let oidc_root = format!("https://oidc.{}.amazonaws.com", pending.config.region);
    let response = http.execute(json_request(
        ProviderHttpMethod::Post,
        &format!("{oidc_root}/token"),
        &serde_json::json!({
            "clientId": pending.client_id.as_str(),
            "clientSecret": pending.client_secret.as_str(),
            "deviceCode": pending.device_code.as_str(),
            "grantType": "urn:ietf:params:oauth:grant-type:device_code"
        }),
        Vec::new(),
    )?)?;
    if response.status == 400 && oauth_error(&response)? == "authorization_pending" {
        return Ok(PollAuthorization::Pending {
            retry_after_seconds: pending.poll_interval_seconds,
        });
    }
    let token: AwsTokenResponse =
        decode_success_json(&response, &[200], "AWS IAM Identity Center token exchange")?;
    let portal_root = format!("https://portal.sso.{}.amazonaws.com", pending.config.region);
    let roles: AwsRoleListResponse = execute_json(
        http,
        request(
            ProviderHttpMethod::Get,
            &format!(
                "{portal_root}/assignment/roles?account_id={}&max_result=100",
                pending.config.account_id
            ),
            vec![("x-amz-sso_bearer_token".into(), token.access_token.clone())],
            Zeroizing::new(Vec::new()),
        )?,
        &[200],
        "AWS account role listing",
    )?;
    if !roles.role_list.iter().any(|role| {
        role.account_id == pending.config.account_id && role.role_name == pending.config.role_name
    }) {
        return Err(AppError::NotAuthorized(
            "the AWS account/role is not assigned to the authenticated IAM Identity Center user"
                .into(),
        ));
    }
    let credentials_response: AwsRoleCredentialsResponse = execute_json(
        http,
        request(
            ProviderHttpMethod::Get,
            &format!(
                "{portal_root}/federation/credentials?account_id={}&role_name={}",
                pending.config.account_id,
                aws_query_encode(&pending.config.role_name)
            ),
            vec![("x-amz-sso_bearer_token".into(), token.access_token)],
            Zeroizing::new(Vec::new()),
        )?,
        &[200],
        "AWS short-lived role credential retrieval",
    )?;
    Ok(PollAuthorization::Complete(
        credentials_response.role_credentials,
    ))
}

pub fn begin_microsoft_native_authorization(
    http: &dyn ProviderHttp,
    config: MicrosoftNativeAuthorizationConfig,
    now: DateTime<Utc>,
) -> AppResult<(
    DeviceAuthorizationPrompt,
    MicrosoftPendingDeviceAuthorization,
)> {
    validate_microsoft_config(&config)?;
    let requested_scopes = microsoft_requested_scopes(config.profile);
    let endpoint = format!(
        "https://login.microsoftonline.com/{}/oauth2/v2.0/devicecode",
        config.tenant_id
    );
    let response: MicrosoftDeviceResponse = execute_json(
        http,
        form_request(
            ProviderHttpMethod::Post,
            &endpoint,
            &[
                ("client_id", config.public_client_id.as_str()),
                ("scope", requested_scopes.join(" ").as_str()),
            ],
            Vec::new(),
        )?,
        &[200],
        "Microsoft device authorization",
    )?;
    validate_device_response(
        &response.verification_uri,
        response.expires_in,
        response.interval,
    )?;
    let expires_at = now + Duration::seconds(i64::from(response.expires_in.min(900)));
    let prompt = DeviceAuthorizationPrompt {
        provider: config.profile.provider(),
        verification_uri: response.verification_uri,
        verification_uri_complete: None,
        user_code: response.user_code,
        expires_at,
        poll_interval_seconds: u64::from(response.interval.clamp(1, 30)),
        safety_notice: "Sign in only at microsoft.com. This public-client flow never asks ai-security-scanner for a Microsoft password or application secret.".into(),
    };
    let pending = MicrosoftPendingDeviceAuthorization {
        config,
        device_code: response.device_code,
        expires_at,
        poll_interval_seconds: prompt.poll_interval_seconds,
        requested_scopes,
    };
    Ok((prompt, pending))
}

pub fn poll_microsoft_native_authorization(
    http: &dyn ProviderHttp,
    pending: &mut MicrosoftPendingDeviceAuthorization,
    now: DateTime<Utc>,
) -> AppResult<PollAuthorization<VerifiedProviderAuthorization>> {
    if now >= pending.expires_at {
        return Err(AppError::NotAuthorized(
            "Microsoft device authorization expired before completion".into(),
        ));
    }
    let endpoint = format!(
        "https://login.microsoftonline.com/{}/oauth2/v2.0/token",
        pending.config.tenant_id
    );
    let response = http.execute(form_request(
        ProviderHttpMethod::Post,
        &endpoint,
        &[
            ("grant_type", "urn:ietf:params:oauth:grant-type:device_code"),
            ("client_id", pending.config.public_client_id.as_str()),
            ("device_code", pending.device_code.as_str()),
        ],
        Vec::new(),
    )?)?;
    if response.status == 400 && oauth_error(&response)? == "authorization_pending" {
        return Ok(PollAuthorization::Pending {
            retry_after_seconds: pending.poll_interval_seconds,
        });
    }
    let mut graph_token: OAuthTokenResponse =
        decode_success_json(&response, &[200], "Microsoft device token exchange")?;
    require_scopes(&graph_token.scope, &pending.requested_scopes)?;
    let authorization = match pending.config.profile {
        ProviderSourceProfile::Microsoft365TenantReadOnlyAccessToken => verify_microsoft365_token(
            http,
            &pending.config,
            graph_token,
            ReadOnlyCredentialSource::ProviderNative,
            now,
            "microsoft_device_code",
        )?,
        ProviderSourceProfile::AzureTenantReadOnlyAccessToken => {
            let refresh_token = graph_token.refresh_token.take().ok_or_else(|| {
                AppError::NotAuthorized(
                    "Microsoft public-client registration did not issue the in-memory refresh token required to request an Azure Resource Manager token"
                        .into(),
                )
            })?;
            let identity = microsoft_graph_identity(http, &graph_token.access_token)?;
            let arm_response: OAuthTokenResponse = execute_json(
                http,
                form_request(
                    ProviderHttpMethod::Post,
                    &endpoint,
                    &[
                        ("grant_type", "refresh_token"),
                        ("client_id", pending.config.public_client_id.as_str()),
                        ("refresh_token", refresh_token.as_str()),
                        ("scope", "https://management.azure.com/.default"),
                    ],
                    Vec::new(),
                )?,
                &[200],
                "Azure Resource Manager token exchange",
            )?;
            verify_azure_token(
                http,
                &pending.config,
                identity,
                arm_response,
                ReadOnlyCredentialSource::ProviderNative,
                now,
                "microsoft_device_code_refresh_to_arm",
            )?
        }
        _ => {
            return Err(AppError::InvalidRequest(
                "Microsoft device flow supports only Azure and Microsoft 365 profiles".into(),
            ));
        }
    };
    Ok(PollAuthorization::Complete(authorization))
}

pub fn begin_gcp_native_authorization(
    config: GcpNativeAuthorizationConfig,
    now: DateTime<Utc>,
) -> AppResult<(GooglePkcePrompt, GooglePendingPkceAuthorization)> {
    validate_gcp_config(&config)?;
    let verifier_bytes = random_bytes::<48>()?;
    let state_bytes = random_bytes::<32>()?;
    let code_verifier = Zeroizing::new(
        base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(verifier_bytes.as_slice()),
    );
    let state = Zeroizing::new(
        base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(state_bytes.as_slice()),
    );
    let challenge = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .encode(Sha256::digest(code_verifier.as_bytes()));
    let scopes = google_requested_scopes();
    let mut url = Url::parse(GOOGLE_AUTH_ENDPOINT)
        .map_err(|_| AppError::Internal("Google authorization endpoint is invalid".into()))?;
    url.query_pairs_mut()
        .append_pair("client_id", &config.public_client_id)
        .append_pair("redirect_uri", &config.redirect_uri)
        .append_pair("response_type", "code")
        .append_pair("scope", &scopes.join(" "))
        .append_pair("code_challenge", &challenge)
        .append_pair("code_challenge_method", "S256")
        .append_pair("state", state.as_str())
        .append_pair("access_type", "online")
        .append_pair("include_granted_scopes", "false")
        .append_pair("prompt", "consent");
    let expires_at = now + Duration::minutes(10);
    let prompt = GooglePkcePrompt {
        provider: BootstrapProvider::Gcp,
        authorization_url: url.into(),
        redirect_uri: config.redirect_uri.clone(),
        expires_at,
        safety_notice: "Open only the accounts.google.com authorization URL. The desktop PKCE flow requires an operator-registered OAuth Desktop client ID but no client secret.".into(),
    };
    let pending = GooglePendingPkceAuthorization {
        config,
        code_verifier,
        state,
        expires_at,
    };
    Ok((prompt, pending))
}

pub fn complete_gcp_native_authorization(
    http: &dyn ProviderHttp,
    pending: GooglePendingPkceAuthorization,
    authorization_code: Zeroizing<String>,
    returned_state: &str,
    now: DateTime<Utc>,
) -> AppResult<VerifiedProviderAuthorization> {
    if now >= pending.expires_at || returned_state != pending.state.as_str() {
        return Err(AppError::NotAuthorized(
            "Google PKCE callback is expired or has an invalid state binding".into(),
        ));
    }
    if authorization_code.is_empty() || authorization_code.len() > 16 * 1024 {
        return Err(AppError::InvalidRequest(
            "Google authorization code is missing or oversized".into(),
        ));
    }
    let token: OAuthTokenResponse = execute_json(
        http,
        form_request(
            ProviderHttpMethod::Post,
            GOOGLE_TOKEN_ENDPOINT,
            &[
                ("client_id", pending.config.public_client_id.as_str()),
                ("code", authorization_code.as_str()),
                ("code_verifier", pending.code_verifier.as_str()),
                ("grant_type", "authorization_code"),
                ("redirect_uri", pending.config.redirect_uri.as_str()),
            ],
            Vec::new(),
        )?,
        &[200],
        "Google PKCE token exchange",
    )?;
    require_scopes(&token.scope, &google_requested_scopes())?;
    verify_gcp_token(
        http,
        &pending.config,
        token,
        ReadOnlyCredentialSource::ProviderNative,
        now,
        "google_desktop_authorization_code_pkce",
    )
}

/// Verifies already-issued temporary AWS credentials. This is used by the
/// isolated broker after it creates/assumes its dedicated role; it performs the
/// same live checks as the preferred IAM Identity Center path.
pub fn verify_bootstrap_aws_credentials(
    http: &dyn ProviderHttp,
    config: &AwsNativeAuthorizationConfig,
    access_key_id: Zeroizing<String>,
    secret_access_key: Zeroizing<String>,
    session_token: Zeroizing<String>,
    expires_at: DateTime<Utc>,
    now: DateTime<Utc>,
) -> AppResult<VerifiedProviderAuthorization> {
    validate_aws_config(config)?;
    verify_aws_credentials(
        http,
        config,
        AwsRoleCredentials {
            access_key_id,
            secret_access_key,
            session_token,
            expiration: expires_at.timestamp_millis(),
        },
        ReadOnlyCredentialSource::VerifiedBootstrap,
        now,
        "isolated_bootstrap_assume_role",
    )
}

/// Verifies a broker-created Azure ARM token. `identity` must have been read by
/// the broker from Microsoft Graph using the same administrative sign-in before
/// the dedicated scanner token was minted; the ARM role-assignment checks still
/// bind the scanner principal itself.
pub fn verify_bootstrap_azure_token(
    http: &dyn ProviderHttp,
    config: &MicrosoftNativeAuthorizationConfig,
    principal_id: String,
    tenant_id: String,
    access_token: Zeroizing<String>,
    expires_in_seconds: u32,
    now: DateTime<Utc>,
) -> AppResult<VerifiedProviderAuthorization> {
    validate_microsoft_config(config)?;
    validate_microsoft_application_token_claims(&access_token, &principal_id, &tenant_id)?;
    let identity_endpoint = format!("{MICROSOFT_GRAPH_ROOT}/servicePrincipals/{principal_id}");
    verify_azure_token(
        http,
        config,
        MicrosoftIdentity {
            principal_id,
            tenant_id,
            principal_label: "dedicated-service-principal".into(),
            identity_endpoint,
            request_ids: Vec::new(),
        },
        OAuthTokenResponse {
            access_token,
            expires_in: expires_in_seconds,
            scope: "https://management.azure.com/.default".into(),
            token_type: "Bearer".into(),
            refresh_token: None,
        },
        ReadOnlyCredentialSource::VerifiedBootstrap,
        now,
        "isolated_bootstrap_client_credentials",
    )
}

fn validate_microsoft_application_token_claims(
    token: &Zeroizing<String>,
    expected_principal_id: &str,
    expected_tenant_id: &str,
) -> AppResult<()> {
    let payload = token.split('.').nth(1).ok_or_else(|| {
        AppError::NotAuthorized("Microsoft application access token is not a JWT".into())
    })?;
    let decoded = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(payload)
        .map(Zeroizing::new)
        .map_err(|_| AppError::NotAuthorized("Microsoft token claims are malformed".into()))?;
    let claims: MicrosoftApplicationTokenClaims = serde_json::from_slice(decoded.as_slice())
        .map_err(|_| AppError::NotAuthorized("Microsoft token claims are malformed".into()))?;
    if claims.tid != expected_tenant_id || claims.oid != expected_principal_id {
        return Err(AppError::NotAuthorized(
            "Microsoft application token subject does not match the broker-created principal"
                .into(),
        ));
    }
    Ok(())
}

pub fn verify_bootstrap_gcp_token(
    http: &dyn ProviderHttp,
    config: &GcpNativeAuthorizationConfig,
    service_account_email: String,
    service_account_unique_id: String,
    access_token: Zeroizing<String>,
    expires_in_seconds: u32,
    now: DateTime<Utc>,
) -> AppResult<VerifiedProviderAuthorization> {
    validate_gcp_config(config)?;
    verify_gcp_service_account_token(
        http,
        config,
        service_account_email,
        service_account_unique_id,
        OAuthTokenResponse {
            access_token,
            expires_in: expires_in_seconds,
            scope: "https://www.googleapis.com/auth/cloud-platform.read-only".into(),
            token_type: "Bearer".into(),
            refresh_token: None,
        },
        ReadOnlyCredentialSource::VerifiedBootstrap,
        now,
        "isolated_bootstrap_generate_access_token",
    )
}

#[allow(clippy::too_many_arguments)]
pub fn verify_bootstrap_microsoft365_token(
    http: &dyn ProviderHttp,
    config: &MicrosoftNativeAuthorizationConfig,
    service_principal_id: String,
    tenant_id: String,
    access_token: Zeroizing<String>,
    expires_in_seconds: u32,
    granted_application_permissions: Vec<String>,
    now: DateTime<Utc>,
) -> AppResult<VerifiedProviderAuthorization> {
    validate_microsoft_config(config)?;
    let mut permissions = granted_application_permissions;
    permissions.sort();
    permissions.dedup();
    validate_microsoft_read_scopes(&permissions, &microsoft365_required_permissions())?;
    let identity = microsoft_graph_application_identity(
        http,
        &access_token,
        &service_principal_id,
        &tenant_id,
    )?;
    verify_microsoft365_token_with_identity(
        http,
        config,
        identity,
        OAuthTokenResponse {
            access_token,
            expires_in: expires_in_seconds,
            scope: permissions.join(" "),
            token_type: "Bearer".into(),
            refresh_token: None,
        },
        ReadOnlyCredentialSource::VerifiedBootstrap,
        now,
        "isolated_bootstrap_client_credentials",
    )
}

fn verify_aws_credentials(
    http: &dyn ProviderHttp,
    config: &AwsNativeAuthorizationConfig,
    credentials: AwsRoleCredentials,
    credential_source: ReadOnlyCredentialSource,
    now: DateTime<Utc>,
    authentication_method: &str,
) -> AppResult<VerifiedProviderAuthorization> {
    let provider_expiry = DateTime::<Utc>::from_timestamp_millis(credentials.expiration)
        .ok_or_else(|| AppError::NotAuthorized("AWS role credential expiry is invalid".into()))?;
    let expires_at = bounded_expiry(now, provider_expiry)?;
    let aws_credentials = AwsSigningCredentials {
        access_key_id: credentials.access_key_id,
        secret_access_key: credentials.secret_access_key,
        session_token: credentials.session_token,
    };
    let sts_body = Zeroizing::new(b"Action=GetCallerIdentity&Version=2011-06-15".to_vec());
    let sts_url = format!("https://sts.{}.amazonaws.com/", config.region);
    let sts_response = http.execute(aws_signed_request(
        ProviderHttpMethod::Post,
        &sts_url,
        "sts",
        &config.region,
        sts_body,
        &aws_credentials,
        now,
    )?)?;
    ensure_status(&sts_response, &[200], "AWS STS identity verification")?;
    let sts_xml = std::str::from_utf8(sts_response.body())
        .map_err(|_| AppError::NotAuthorized("AWS STS returned non-UTF-8 XML".into()))?;
    let account = xml_first(sts_xml, "Account")?;
    let caller_arn = xml_first(sts_xml, "Arn")?;
    if account != config.account_id
        || !caller_arn.starts_with(&format!("arn:aws:sts::{}:assumed-role/", config.account_id))
        || !caller_arn.contains(&format!("/{}/", config.role_name))
    {
        return Err(AppError::NotAuthorized(
            "AWS STS identity does not match the configured account and read-only role".into(),
        ));
    }

    let required = aws_required_permissions();
    let prohibited = aws_prohibited_permissions();
    let mut pairs = vec![
        ("Action".to_owned(), "SimulatePrincipalPolicy".to_owned()),
        ("Version".to_owned(), "2010-05-08".to_owned()),
        ("PolicySourceArn".to_owned(), config.role_arn.clone()),
    ];
    for (index, action) in required.iter().chain(prohibited.iter()).enumerate() {
        pairs.push((format!("ActionNames.member.{}", index + 1), action.clone()));
    }
    pairs.sort_by(|left, right| left.0.cmp(&right.0).then(left.1.cmp(&right.1)));
    let iam_body = Zeroizing::new(
        pairs
            .iter()
            .map(|(key, value)| format!("{}={}", aws_query_encode(key), aws_query_encode(value)))
            .collect::<Vec<_>>()
            .join("&")
            .into_bytes(),
    );
    let iam_response = http.execute(aws_signed_request(
        ProviderHttpMethod::Post,
        "https://iam.amazonaws.com/",
        "iam",
        "us-east-1",
        iam_body,
        &aws_credentials,
        now,
    )?)?;
    ensure_status(&iam_response, &[200], "AWS IAM read-only policy simulation")?;
    let iam_xml = std::str::from_utf8(iam_response.body())
        .map_err(|_| AppError::NotAuthorized("AWS IAM returned non-UTF-8 XML".into()))?;
    let decisions = aws_simulation_decisions(iam_xml)?;
    for permission in &required {
        if decisions.get(permission).map(String::as_str) != Some("allowed") {
            return Err(AppError::NotAuthorized(format!(
                "AWS read-only profile is missing required permission {permission}"
            )));
        }
    }
    for permission in &prohibited {
        if decisions.get(permission).map(String::as_str) == Some("allowed") {
            return Err(AppError::NotAuthorized(format!(
                "AWS credential permits prohibited mutation {permission}"
            )));
        }
    }
    let identity = config.role_arn.clone();
    let proof = build_proof(
        BootstrapProvider::Aws,
        ProviderSourceProfile::AwsOrganizationReadOnlySession,
        authentication_method,
        &identity,
        &caller_arn,
        &format!("aws-account:{}", config.account_id),
        now,
        expires_at,
        &sts_url,
        vec!["https://iam.amazonaws.com/".into()],
        required,
        prohibited,
        collect_request_ids([&sts_response, &iam_response]),
    )?;
    VerifiedProviderAuthorization::new_verified(
        ProviderSourceProfile::AwsOrganizationReadOnlySession,
        credential_source,
        identity,
        expires_at,
        proof,
        ProviderSecretMaterial::new(vec![
            SecretEnvironmentValue::new("AWS_ACCESS_KEY_ID", aws_credentials.access_key_id),
            SecretEnvironmentValue::new("AWS_SECRET_ACCESS_KEY", aws_credentials.secret_access_key),
            SecretEnvironmentValue::new("AWS_SESSION_TOKEN", aws_credentials.session_token),
        ]),
    )
}

fn verify_azure_token(
    http: &dyn ProviderHttp,
    config: &MicrosoftNativeAuthorizationConfig,
    identity: MicrosoftIdentity,
    token: OAuthTokenResponse,
    credential_source: ReadOnlyCredentialSource,
    now: DateTime<Utc>,
    authentication_method: &str,
) -> AppResult<VerifiedProviderAuthorization> {
    if config.profile != ProviderSourceProfile::AzureTenantReadOnlyAccessToken
        || identity.tenant_id != config.tenant_id
    {
        return Err(AppError::NotAuthorized(
            "Azure token identity does not match the configured tenant".into(),
        ));
    }
    validate_bearer_token(&token)?;
    let subscription_id = config.subscription_id.as_deref().ok_or_else(|| {
        AppError::InvalidRequest(
            "Azure authorization requires an exact subscription_id in operator configuration"
                .into(),
        )
    })?;
    let expires_at = bounded_expiry(now, now + Duration::seconds(i64::from(token.expires_in)))?;
    let subscription_endpoint =
        format!("{MICROSOFT_ARM_ROOT}/subscriptions/{subscription_id}?api-version=2022-12-01");
    let subscription_response =
        http.execute(bearer_get(&subscription_endpoint, &token.access_token)?)?;
    let subscription: AzureSubscription = decode_success_json(
        &subscription_response,
        &[200],
        "Azure subscription identity verification",
    )?;
    if subscription.subscription_id != subscription_id {
        return Err(AppError::NotAuthorized(
            "Azure Resource Manager returned a different subscription identity".into(),
        ));
    }
    let assignments_endpoint = format!(
        "{MICROSOFT_ARM_ROOT}/subscriptions/{subscription_id}/providers/Microsoft.Authorization/roleAssignments?api-version=2022-04-01&%24filter=assignedTo%28%27{}%27%29",
        identity.principal_id
    );
    let assignments_response =
        http.execute(bearer_get(&assignments_endpoint, &token.access_token)?)?;
    let assignments: AzureRoleAssignments = decode_success_json(
        &assignments_response,
        &[200],
        "Azure role assignment verification",
    )?;
    const READER: &str = "acdd72a7-3385-48ef-bd42-f606fba81ae7";
    const SECURITY_READER: &str = "39bc4728-0917-49c7-9d2c-d95423bc2eb4";
    let mut role_ids = BTreeSet::new();
    for assignment in assignments.value {
        if assignment.properties.principal_id != identity.principal_id {
            continue;
        }
        let role_id = assignment
            .properties
            .role_definition_id
            .rsplit('/')
            .next()
            .unwrap_or_default()
            .to_ascii_lowercase();
        if ![READER, SECURITY_READER].contains(&role_id.as_str()) {
            return Err(AppError::NotAuthorized(format!(
                "Azure principal has an additional unapproved role assignment {}",
                safe_label(&role_id)
            )));
        }
        role_ids.insert(role_id);
    }
    if !role_ids.contains(READER) || !role_ids.contains(SECURITY_READER) {
        return Err(AppError::NotAuthorized(
            "Azure principal must have exactly the Reader and Security Reader profiles at the assessed subscription scope"
                .into(),
        ));
    }
    let provider_identity = format!(
        "tenant:{}/service-principal:{}",
        identity.tenant_id, identity.principal_id
    );
    let required = vec![
        format!("azure-rbac-role:{READER}"),
        format!("azure-rbac-role:{SECURITY_READER}"),
    ];
    let prohibited = vec![
        "azure-rbac-role:owner".into(),
        "azure-rbac-role:contributor".into(),
        "azure-rbac-role:user-access-administrator".into(),
    ];
    let mut request_ids = identity.request_ids;
    request_ids.extend(collect_request_ids([
        &subscription_response,
        &assignments_response,
    ]));
    request_ids.sort();
    request_ids.dedup();
    let proof = build_proof(
        BootstrapProvider::Azure,
        ProviderSourceProfile::AzureTenantReadOnlyAccessToken,
        authentication_method,
        &provider_identity,
        &identity.principal_id,
        &format!("azure-subscription:{subscription_id}"),
        now,
        expires_at,
        &identity.identity_endpoint,
        vec![subscription_endpoint, assignments_endpoint],
        required,
        prohibited,
        request_ids,
    )?;
    VerifiedProviderAuthorization::new_verified(
        ProviderSourceProfile::AzureTenantReadOnlyAccessToken,
        credential_source,
        provider_identity,
        expires_at,
        proof,
        ProviderSecretMaterial::new(vec![SecretEnvironmentValue::new(
            "AZURE_ACCESS_TOKEN",
            token.access_token,
        )]),
    )
}

fn verify_microsoft365_token(
    http: &dyn ProviderHttp,
    config: &MicrosoftNativeAuthorizationConfig,
    token: OAuthTokenResponse,
    credential_source: ReadOnlyCredentialSource,
    now: DateTime<Utc>,
    authentication_method: &str,
) -> AppResult<VerifiedProviderAuthorization> {
    if config.profile != ProviderSourceProfile::Microsoft365TenantReadOnlyAccessToken {
        return Err(AppError::InvalidRequest(
            "Microsoft 365 verification requires the Microsoft 365 source profile".into(),
        ));
    }
    validate_bearer_token(&token)?;
    let identity = microsoft_graph_identity(http, &token.access_token)?;
    verify_microsoft365_token_with_identity(
        http,
        config,
        identity,
        token,
        credential_source,
        now,
        authentication_method,
    )
}

fn verify_microsoft365_token_with_identity(
    http: &dyn ProviderHttp,
    config: &MicrosoftNativeAuthorizationConfig,
    identity: MicrosoftIdentity,
    token: OAuthTokenResponse,
    credential_source: ReadOnlyCredentialSource,
    now: DateTime<Utc>,
    authentication_method: &str,
) -> AppResult<VerifiedProviderAuthorization> {
    validate_bearer_token(&token)?;
    let granted = normalize_scopes(&token.scope);
    let required = microsoft365_required_permissions();
    validate_microsoft_read_scopes(&granted, &required)?;
    if identity.tenant_id != config.tenant_id {
        return Err(AppError::NotAuthorized(
            "Microsoft Graph organization does not match the configured tenant".into(),
        ));
    }
    let probes = [
        format!("{MICROSOFT_GRAPH_ROOT}/auditLogs/directoryAudits?%24top=1&%24select=id"),
        format!("{MICROSOFT_GRAPH_ROOT}/policies/authorizationPolicy?%24select=id"),
        format!(
            "{MICROSOFT_GRAPH_ROOT}/roleManagement/directory/roleDefinitions?%24top=1&%24select=id"
        ),
    ];
    let mut request_ids = identity.request_ids;
    for (index, endpoint) in probes.iter().enumerate() {
        let response = http.execute(bearer_get(endpoint, &token.access_token)?)?;
        ensure_status(
            &response,
            &[200],
            match index {
                0 => "Microsoft 365 audit metadata permission probe",
                1 => "Microsoft 365 policy permission probe",
                _ => "Microsoft 365 role management permission probe",
            },
        )?;
        request_ids.extend(collect_request_ids([&response]));
    }
    request_ids.sort();
    request_ids.dedup();
    let expires_at = bounded_expiry(now, now + Duration::seconds(i64::from(token.expires_in)))?;
    let provider_identity = format!(
        "tenant:{}/principal:{}",
        identity.tenant_id, identity.principal_id
    );
    let prohibited = microsoft_prohibited_scopes();
    let proof = build_proof(
        BootstrapProvider::Microsoft365,
        ProviderSourceProfile::Microsoft365TenantReadOnlyAccessToken,
        authentication_method,
        &provider_identity,
        &identity.principal_id,
        &format!("microsoft365-tenant:{}", identity.tenant_id),
        now,
        expires_at,
        &identity.identity_endpoint,
        probes.into_iter().collect(),
        required,
        prohibited,
        request_ids,
    )?;
    VerifiedProviderAuthorization::new_verified(
        ProviderSourceProfile::Microsoft365TenantReadOnlyAccessToken,
        credential_source,
        provider_identity,
        expires_at,
        proof,
        ProviderSecretMaterial::new(vec![SecretEnvironmentValue::new(
            "MSGRAPH_ACCESS_TOKEN",
            token.access_token,
        )]),
    )
}

fn verify_gcp_token(
    http: &dyn ProviderHttp,
    config: &GcpNativeAuthorizationConfig,
    token: OAuthTokenResponse,
    credential_source: ReadOnlyCredentialSource,
    now: DateTime<Utc>,
    authentication_method: &str,
) -> AppResult<VerifiedProviderAuthorization> {
    validate_bearer_token(&token)?;
    let userinfo_response =
        http.execute(bearer_get(GOOGLE_USERINFO_ENDPOINT, &token.access_token)?)?;
    let userinfo: GoogleUserInfo =
        decode_success_json(&userinfo_response, &[200], "Google identity verification")?;
    if userinfo.sub.is_empty() || userinfo.sub.len() > 256 {
        return Err(AppError::NotAuthorized(
            "Google identity endpoint returned an invalid subject".into(),
        ));
    }
    verify_gcp_token_with_identity(
        http,
        config,
        token,
        userinfo.sub,
        GOOGLE_USERINFO_ENDPOINT.into(),
        collect_request_ids([&userinfo_response]),
        credential_source,
        now,
        authentication_method,
    )
}

#[allow(clippy::too_many_arguments)]
fn verify_gcp_service_account_token(
    http: &dyn ProviderHttp,
    config: &GcpNativeAuthorizationConfig,
    service_account_email: String,
    service_account_unique_id: String,
    token: OAuthTokenResponse,
    credential_source: ReadOnlyCredentialSource,
    now: DateTime<Utc>,
    authentication_method: &str,
) -> AppResult<VerifiedProviderAuthorization> {
    validate_bearer_token(&token)?;
    if !valid_service_account_email(&service_account_email)
        || service_account_unique_id.is_empty()
        || service_account_unique_id.len() > 64
        || !service_account_unique_id
            .bytes()
            .all(|byte| byte.is_ascii_digit())
    {
        return Err(AppError::InvalidRequest(
            "broker-created Google service account identity is malformed".into(),
        ));
    }
    let encoded_email: String =
        url::form_urlencoded::byte_serialize(service_account_email.as_bytes()).collect();
    let identity_endpoint =
        format!("https://iam.googleapis.com/v1/projects/-/serviceAccounts/{encoded_email}");
    let identity_response = http.execute(bearer_get(&identity_endpoint, &token.access_token)?)?;
    let identity: GoogleServiceAccount = decode_success_json(
        &identity_response,
        &[200],
        "Google service account identity verification",
    )?;
    if identity.email != service_account_email
        || identity.unique_id != service_account_unique_id
        || identity.name.is_empty()
    {
        return Err(AppError::NotAuthorized(
            "Google IAM returned a different service account identity".into(),
        ));
    }
    verify_gcp_token_with_identity(
        http,
        config,
        token,
        service_account_unique_id,
        identity_endpoint,
        collect_request_ids([&identity_response]),
        credential_source,
        now,
        authentication_method,
    )
}

#[allow(clippy::too_many_arguments)]
fn verify_gcp_token_with_identity(
    http: &dyn ProviderHttp,
    config: &GcpNativeAuthorizationConfig,
    token: OAuthTokenResponse,
    subject_id: String,
    identity_endpoint: String,
    mut request_ids: Vec<String>,
    credential_source: ReadOnlyCredentialSource,
    now: DateTime<Utc>,
    authentication_method: &str,
) -> AppResult<VerifiedProviderAuthorization> {
    let organization_endpoint = format!(
        "https://cloudresourcemanager.googleapis.com/v3/organizations/{}",
        config.organization_id
    );
    let organization_response =
        http.execute(bearer_get(&organization_endpoint, &token.access_token)?)?;
    let organization: GoogleOrganization = decode_success_json(
        &organization_response,
        &[200],
        "Google Cloud organization identity verification",
    )?;
    if organization.name != format!("organizations/{}", config.organization_id) {
        return Err(AppError::NotAuthorized(
            "Google Cloud returned a different organization identity".into(),
        ));
    }
    let required = gcp_required_permissions();
    let prohibited = gcp_prohibited_permissions();
    let all_permissions = required
        .iter()
        .chain(prohibited.iter())
        .cloned()
        .collect::<Vec<_>>();
    let permission_endpoint = format!("{organization_endpoint}:testIamPermissions");
    let permission_response = http.execute(json_request(
        ProviderHttpMethod::Post,
        &permission_endpoint,
        &serde_json::json!({"permissions": all_permissions}),
        vec![bearer_header(&token.access_token)],
    )?)?;
    let permissions: GoogleTestIamPermissions = decode_success_json(
        &permission_response,
        &[200],
        "Google Cloud read-only IAM permission verification",
    )?;
    let held: BTreeSet<_> = permissions.permissions.into_iter().collect();
    for permission in &required {
        if !held.contains(permission) {
            return Err(AppError::NotAuthorized(format!(
                "Google Cloud read-only profile is missing required permission {permission}"
            )));
        }
    }
    for permission in &prohibited {
        if held.contains(permission) {
            return Err(AppError::NotAuthorized(format!(
                "Google Cloud credential permits prohibited mutation {permission}"
            )));
        }
    }
    let expires_at = bounded_expiry(now, now + Duration::seconds(i64::from(token.expires_in)))?;
    let provider_identity = format!("principal:{subject_id}");
    request_ids.extend(collect_request_ids([
        &organization_response,
        &permission_response,
    ]));
    request_ids.sort();
    request_ids.dedup();
    let proof = build_proof(
        BootstrapProvider::Gcp,
        ProviderSourceProfile::GcpOrganizationReadOnlyAccessToken,
        authentication_method,
        &provider_identity,
        &subject_id,
        &format!("gcp-organization:{}", config.organization_id),
        now,
        expires_at,
        &identity_endpoint,
        vec![organization_endpoint, permission_endpoint],
        required,
        prohibited,
        request_ids,
    )?;
    VerifiedProviderAuthorization::new_verified(
        ProviderSourceProfile::GcpOrganizationReadOnlyAccessToken,
        credential_source,
        provider_identity,
        expires_at,
        proof,
        ProviderSecretMaterial::new(vec![SecretEnvironmentValue::new(
            "GOOGLE_OAUTH_ACCESS_TOKEN",
            token.access_token,
        )]),
    )
}

fn microsoft_graph_identity(
    http: &dyn ProviderHttp,
    token: &Zeroizing<String>,
) -> AppResult<MicrosoftIdentity> {
    let me_endpoint = format!("{MICROSOFT_GRAPH_ROOT}/me?%24select=id,userPrincipalName");
    let me_response = http.execute(bearer_get(&me_endpoint, token)?)?;
    let me: MicrosoftMe = decode_success_json(
        &me_response,
        &[200],
        "Microsoft Graph principal identity verification",
    )?;
    let organization_endpoint = format!("{MICROSOFT_GRAPH_ROOT}/organization?%24select=id");
    let organization_response = http.execute(bearer_get(&organization_endpoint, token)?)?;
    let organization: MicrosoftOrganizations = decode_success_json(
        &organization_response,
        &[200],
        "Microsoft Graph tenant identity verification",
    )?;
    let tenant_id = organization
        .value
        .into_iter()
        .next()
        .map(|organization| organization.id)
        .ok_or_else(|| {
            AppError::NotAuthorized("Microsoft Graph returned no tenant organization".into())
        })?;
    if !valid_uuid(&me.id) || !valid_uuid(&tenant_id) {
        return Err(AppError::NotAuthorized(
            "Microsoft Graph returned malformed principal or tenant identity".into(),
        ));
    }
    Ok(MicrosoftIdentity {
        principal_id: me.id,
        tenant_id,
        principal_label: me.user_principal_name.unwrap_or_else(|| "principal".into()),
        identity_endpoint: me_endpoint,
        request_ids: collect_request_ids([&me_response, &organization_response]),
    })
}

fn microsoft_graph_application_identity(
    http: &dyn ProviderHttp,
    token: &Zeroizing<String>,
    expected_principal_id: &str,
    expected_tenant_id: &str,
) -> AppResult<MicrosoftIdentity> {
    if !valid_uuid(expected_principal_id) || !valid_uuid(expected_tenant_id) {
        return Err(AppError::InvalidRequest(
            "broker-created Microsoft service principal identity is malformed".into(),
        ));
    }
    let identity_endpoint = format!(
        "{MICROSOFT_GRAPH_ROOT}/servicePrincipals/{expected_principal_id}?%24select=id,appId"
    );
    let principal_response = http.execute(bearer_get(&identity_endpoint, token)?)?;
    let principal: MicrosoftServicePrincipal = decode_success_json(
        &principal_response,
        &[200],
        "Microsoft Graph application identity verification",
    )?;
    let organization_endpoint = format!("{MICROSOFT_GRAPH_ROOT}/organization?%24select=id");
    let organization_response = http.execute(bearer_get(&organization_endpoint, token)?)?;
    let organization: MicrosoftOrganizations = decode_success_json(
        &organization_response,
        &[200],
        "Microsoft Graph tenant identity verification",
    )?;
    let tenant_id = organization
        .value
        .into_iter()
        .next()
        .map(|organization| organization.id)
        .ok_or_else(|| {
            AppError::NotAuthorized("Microsoft Graph returned no tenant organization".into())
        })?;
    if principal.id != expected_principal_id || tenant_id != expected_tenant_id {
        return Err(AppError::NotAuthorized(
            "Microsoft Graph application identity does not match the broker-created principal"
                .into(),
        ));
    }
    Ok(MicrosoftIdentity {
        principal_id: principal.id,
        tenant_id,
        principal_label: principal.app_id,
        identity_endpoint,
        request_ids: collect_request_ids([&principal_response, &organization_response]),
    })
}

fn validate_aws_config(config: &AwsNativeAuthorizationConfig) -> AppResult<()> {
    let start_url = Url::parse(&config.start_url).map_err(|_| {
        AppError::InvalidRequest("AWS IAM Identity Center start_url is invalid".into())
    })?;
    let host = start_url.host_str().unwrap_or_default();
    if start_url.scheme() != "https"
        || !host.ends_with(".awsapps.com")
        || start_url.username() != ""
        || start_url.password().is_some()
        || start_url.fragment().is_some()
    {
        return Err(AppError::InvalidRequest(
            "AWS start_url must be the provider-hosted HTTPS awsapps.com access portal".into(),
        ));
    }
    if !valid_aws_region(&config.region)
        || config.account_id.len() != 12
        || !config.account_id.bytes().all(|byte| byte.is_ascii_digit())
        || config.role_name.is_empty()
        || config.role_name.len() > 64
        || !config.role_name.bytes().all(|byte| {
            byte.is_ascii_alphanumeric()
                || matches!(byte, b'+' | b'=' | b',' | b'.' | b'@' | b'-' | b'_')
        })
    {
        return Err(AppError::InvalidRequest(
            "AWS region, account ID, or role name is invalid".into(),
        ));
    }
    let role_prefix = format!("arn:aws:iam::{}:role/", config.account_id);
    if !config.role_arn.starts_with(&role_prefix)
        || config.role_arn.len() > 2048
        || config
            .role_arn
            .rsplit('/')
            .next()
            .is_none_or(|name| name != config.role_name)
    {
        return Err(AppError::InvalidRequest(
            "AWS role_arn must exactly identify the configured account and role name".into(),
        ));
    }
    Ok(())
}

fn validate_microsoft_config(config: &MicrosoftNativeAuthorizationConfig) -> AppResult<()> {
    if !matches!(
        config.profile,
        ProviderSourceProfile::AzureTenantReadOnlyAccessToken
            | ProviderSourceProfile::Microsoft365TenantReadOnlyAccessToken
    ) || !valid_uuid(&config.tenant_id)
        || !valid_uuid(&config.public_client_id)
        || config.tenant_id == "00000000-0000-0000-0000-000000000000"
        || config.public_client_id == "00000000-0000-0000-0000-000000000000"
    {
        return Err(AppError::InvalidRequest(
            "a real tenant-specific Microsoft public-client registration is required".into(),
        ));
    }
    match config.profile {
        ProviderSourceProfile::AzureTenantReadOnlyAccessToken => {
            if config
                .subscription_id
                .as_deref()
                .is_none_or(|id| !valid_uuid(id))
            {
                return Err(AppError::InvalidRequest(
                    "Azure authorization requires an exact subscription UUID".into(),
                ));
            }
        }
        ProviderSourceProfile::Microsoft365TenantReadOnlyAccessToken => {
            if config.subscription_id.is_some() {
                return Err(AppError::InvalidRequest(
                    "Microsoft 365 authorization must not include an Azure subscription".into(),
                ));
            }
        }
        _ => unreachable!(),
    }
    Ok(())
}

fn validate_gcp_config(config: &GcpNativeAuthorizationConfig) -> AppResult<()> {
    if config.public_client_id.len() < 20
        || config.public_client_id.len() > 512
        || !config
            .public_client_id
            .ends_with(".apps.googleusercontent.com")
        || config
            .public_client_id
            .to_ascii_lowercase()
            .contains("example")
        || config.organization_id.is_empty()
        || config.organization_id.len() > 32
        || !config
            .organization_id
            .bytes()
            .all(|byte| byte.is_ascii_digit())
    {
        return Err(AppError::InvalidRequest(
            "a real Google OAuth Desktop client ID and numeric organization ID are required".into(),
        ));
    }
    let redirect = Url::parse(&config.redirect_uri)
        .map_err(|_| AppError::InvalidRequest("Google loopback redirect URI is invalid".into()))?;
    if redirect.scheme() != "http"
        || !matches!(
            redirect.host_str(),
            Some("127.0.0.1") | Some("[::1]") | Some("::1")
        )
        || redirect.port().is_none()
        || redirect.username() != ""
        || redirect.password().is_some()
        || redirect.query().is_some()
        || redirect.fragment().is_some()
    {
        return Err(AppError::InvalidRequest(
            "Google Desktop OAuth redirect must be an exact random-port loopback HTTP URI".into(),
        ));
    }
    Ok(())
}

fn valid_service_account_email(value: &str) -> bool {
    let Some((local, domain)) = value.split_once('@') else {
        return false;
    };
    !local.is_empty()
        && local.len() <= 63
        && local
            .bytes()
            .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'-')
        && domain.ends_with(".iam.gserviceaccount.com")
        && domain.len() <= 253
        && domain.bytes().all(|byte| {
            byte.is_ascii_lowercase() || byte.is_ascii_digit() || matches!(byte, b'-' | b'.')
        })
}

fn validate_provider_endpoint(url: &Url) -> AppResult<()> {
    if url.scheme() != "https" || url.username() != "" || url.password().is_some() {
        return Err(AppError::NotAuthorized(
            "provider requests require credential-free HTTPS endpoint URLs".into(),
        ));
    }
    let host = url.host_str().unwrap_or_default().to_ascii_lowercase();
    let exact = [
        "login.microsoftonline.com",
        "graph.microsoft.com",
        "management.azure.com",
        "accounts.google.com",
        "oauth2.googleapis.com",
        "openidconnect.googleapis.com",
        "cloudresourcemanager.googleapis.com",
        "iam.googleapis.com",
        "iamcredentials.googleapis.com",
        "iam.amazonaws.com",
    ];
    let aws_regional = [
        "oidc.",
        "portal.sso.",
        "sts.",
        "cloudformation.",
        "organizations.",
    ]
    .iter()
    .any(|prefix| host.starts_with(prefix) && host.ends_with(".amazonaws.com"));
    if !exact.contains(&host.as_str()) && !aws_regional {
        return Err(AppError::NotAuthorized(format!(
            "provider endpoint host is outside the fixed authorization allowlist: {}",
            safe_label(&host)
        )));
    }
    Ok(())
}

fn validate_device_response(uri: &str, expires_in: u32, interval: u32) -> AppResult<()> {
    let uri = Url::parse(uri)
        .map_err(|_| AppError::NotAuthorized("provider returned an invalid login URI".into()))?;
    validate_provider_endpoint(&uri)?;
    if expires_in == 0 || expires_in > 900 || interval == 0 || interval > 30 {
        return Err(AppError::NotAuthorized(
            "provider returned an unsafe device-code lifetime or polling interval".into(),
        ));
    }
    Ok(())
}

fn validate_bearer_token(token: &OAuthTokenResponse) -> AppResult<()> {
    if !token.token_type.eq_ignore_ascii_case("bearer")
        || token.access_token.is_empty()
        || token.access_token.len() > 128 * 1024
        || token.expires_in == 0
        || token.expires_in > 3600
    {
        return Err(AppError::NotAuthorized(
            "provider returned an invalid or longer-than-one-hour bearer credential".into(),
        ));
    }
    Ok(())
}

fn bounded_expiry(now: DateTime<Utc>, provider_expiry: DateTime<Utc>) -> AppResult<DateTime<Utc>> {
    if provider_expiry <= now || provider_expiry > now + Duration::hours(1) {
        return Err(AppError::NotAuthorized(
            "provider scanner credential must expire within one hour".into(),
        ));
    }
    Ok(provider_expiry)
}

fn microsoft_requested_scopes(profile: ProviderSourceProfile) -> Vec<String> {
    match profile {
        ProviderSourceProfile::AzureTenantReadOnlyAccessToken => [
            "openid",
            "profile",
            "offline_access",
            "User.Read",
            "Organization.Read.All",
        ]
        .into_iter()
        .map(str::to_owned)
        .collect(),
        ProviderSourceProfile::Microsoft365TenantReadOnlyAccessToken => {
            let mut scopes = vec!["openid".into(), "profile".into(), "offline_access".into()];
            scopes.extend(microsoft365_required_permissions());
            scopes
        }
        _ => Vec::new(),
    }
}

fn microsoft365_required_permissions() -> Vec<String> {
    [
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
    .into_iter()
    .map(str::to_owned)
    .collect()
}

fn microsoft_prohibited_scopes() -> Vec<String> {
    [
        "Directory.ReadWrite.All",
        "Application.ReadWrite.All",
        "RoleManagement.ReadWrite.Directory",
        "Policy.ReadWrite.ConditionalAccess",
        "User.ReadWrite.All",
        "Group.ReadWrite.All",
    ]
    .into_iter()
    .map(str::to_owned)
    .collect()
}

fn validate_microsoft_read_scopes(granted: &[String], required: &[String]) -> AppResult<()> {
    let granted_set: BTreeSet<_> = granted
        .iter()
        .map(|scope| scope.to_ascii_lowercase())
        .collect();
    for permission in required {
        if !granted_set.contains(&permission.to_ascii_lowercase()) {
            return Err(AppError::NotAuthorized(format!(
                "Microsoft token is missing required read permission {permission}"
            )));
        }
    }
    for permission in microsoft_prohibited_scopes() {
        if granted_set.contains(&permission.to_ascii_lowercase()) {
            return Err(AppError::NotAuthorized(format!(
                "Microsoft token includes prohibited write permission {permission}"
            )));
        }
    }
    for permission in granted {
        let lower = permission.to_ascii_lowercase();
        if lower.contains("readwrite")
            || lower.ends_with(".write")
            || lower.ends_with(".write.all")
            || lower.contains("accessasuser")
        {
            return Err(AppError::NotAuthorized(format!(
                "Microsoft token contains a non-read-only permission {}",
                safe_label(permission)
            )));
        }
    }
    Ok(())
}

fn google_requested_scopes() -> Vec<String> {
    [
        "openid",
        "https://www.googleapis.com/auth/userinfo.email",
        "https://www.googleapis.com/auth/cloud-platform.read-only",
    ]
    .into_iter()
    .map(str::to_owned)
    .collect()
}

fn aws_required_permissions() -> Vec<String> {
    [
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
    ]
    .into_iter()
    .map(str::to_owned)
    .collect()
}

fn aws_prohibited_permissions() -> Vec<String> {
    [
        "iam:CreateUser",
        "iam:AttachRolePolicy",
        "s3:PutObject",
        "ec2:RunInstances",
        "organizations:CreateAccount",
    ]
    .into_iter()
    .map(str::to_owned)
    .collect()
}

fn gcp_required_permissions() -> Vec<String> {
    [
        "resourcemanager.organizations.get",
        "resourcemanager.projects.get",
        "cloudasset.assets.searchAllResources",
        "iam.roles.get",
    ]
    .into_iter()
    .map(str::to_owned)
    .collect()
}

fn gcp_prohibited_permissions() -> Vec<String> {
    [
        "resourcemanager.organizations.setIamPolicy",
        "resourcemanager.projects.setIamPolicy",
        "iam.serviceAccounts.create",
        "iam.serviceAccountKeys.create",
        "resourcemanager.projects.delete",
    ]
    .into_iter()
    .map(str::to_owned)
    .collect()
}

fn normalize_scopes(scopes: &str) -> Vec<String> {
    let mut values = scopes
        .split_ascii_whitespace()
        .filter(|scope| !scope.is_empty())
        .map(|scope| scope.rsplit('/').next().unwrap_or(scope).to_owned())
        .collect::<Vec<_>>();
    values.sort_by_key(|scope| scope.to_ascii_lowercase());
    values.dedup_by(|left, right| left.eq_ignore_ascii_case(right));
    values
}

fn require_scopes(granted: &str, required: &[String]) -> AppResult<()> {
    let values = normalize_scopes(granted);
    let normalized_required = required
        .iter()
        .map(|scope| scope.rsplit('/').next().unwrap_or(scope).to_owned())
        .collect::<Vec<_>>();
    let value_set: BTreeSet<_> = values
        .iter()
        .map(|scope| scope.to_ascii_lowercase())
        .collect();
    for scope in normalized_required {
        if !value_set.contains(&scope.to_ascii_lowercase()) {
            return Err(AppError::NotAuthorized(format!(
                "provider token omitted requested scope {}",
                safe_label(&scope)
            )));
        }
    }
    Ok(())
}

#[allow(clippy::too_many_arguments)]
fn build_proof(
    provider: BootstrapProvider,
    profile: ProviderSourceProfile,
    authentication_method: &str,
    provider_identity: &str,
    subject_id: &str,
    resource_scope: &str,
    verified_at: DateTime<Utc>,
    credential_expires_at: DateTime<Utc>,
    identity_endpoint: &str,
    mut permission_endpoints: Vec<String>,
    mut required_permissions_verified: Vec<String>,
    mut prohibited_permissions_denied: Vec<String>,
    mut provider_request_ids: Vec<String>,
) -> AppResult<ProviderVerificationState> {
    for value in [
        authentication_method,
        provider_identity,
        subject_id,
        resource_scope,
        identity_endpoint,
    ] {
        if !safe_metadata(value, 2048) {
            return Err(AppError::NotAuthorized(
                "provider verification metadata is malformed".into(),
            ));
        }
    }
    permission_endpoints.sort();
    permission_endpoints.dedup();
    required_permissions_verified.sort();
    required_permissions_verified.dedup();
    prohibited_permissions_denied.sort();
    prohibited_permissions_denied.dedup();
    provider_request_ids.retain(|value| safe_metadata(value, 256));
    provider_request_ids.sort();
    provider_request_ids.dedup();
    let mut proof = ProviderVerificationState {
        schema_version: "1.0.0".into(),
        provider,
        profile,
        authentication_method: authentication_method.into(),
        provider_identity: provider_identity.into(),
        subject_id: subject_id.into(),
        resource_scope: resource_scope.into(),
        verified_at,
        credential_expires_at,
        identity_endpoint: identity_endpoint.into(),
        permission_endpoints,
        required_permissions_verified,
        prohibited_permissions_denied,
        provider_request_ids,
        evidence_sha256: String::new(),
    };
    let canonical = serde_json::to_vec(&proof)
        .map_err(|_| AppError::Internal("verification proof could not be encoded".into()))?;
    proof.evidence_sha256 = hex::encode(Sha256::digest(canonical));
    Ok(proof)
}

pub(crate) fn request(
    method: ProviderHttpMethod,
    url: &str,
    headers: Vec<(String, Zeroizing<String>)>,
    body: Zeroizing<Vec<u8>>,
) -> AppResult<ProviderHttpRequest> {
    let url = Url::parse(url)
        .map_err(|_| AppError::InvalidRequest("provider endpoint URL is invalid".into()))?;
    validate_provider_endpoint(&url)?;
    Ok(ProviderHttpRequest {
        method,
        url,
        headers,
        body,
    })
}

pub(crate) fn json_request(
    method: ProviderHttpMethod,
    url: &str,
    body: &serde_json::Value,
    mut headers: Vec<(String, Zeroizing<String>)>,
) -> AppResult<ProviderHttpRequest> {
    headers.push((
        "content-type".into(),
        Zeroizing::new("application/json".into()),
    ));
    let body = serde_json::to_vec(body)
        .map(Zeroizing::new)
        .map_err(|_| AppError::Internal("provider JSON request could not be encoded".into()))?;
    request(method, url, headers, body)
}

pub(crate) fn serializable_json_request<T: Serialize>(
    method: ProviderHttpMethod,
    url: &str,
    body: &T,
    mut headers: Vec<(String, Zeroizing<String>)>,
) -> AppResult<ProviderHttpRequest> {
    headers.push((
        "content-type".into(),
        Zeroizing::new("application/json".into()),
    ));
    let body = serde_json::to_vec(body)
        .map(Zeroizing::new)
        .map_err(|_| AppError::Internal("provider JSON request could not be encoded".into()))?;
    request(method, url, headers, body)
}

pub(crate) fn form_request(
    method: ProviderHttpMethod,
    url: &str,
    fields: &[(&str, &str)],
    mut headers: Vec<(String, Zeroizing<String>)>,
) -> AppResult<ProviderHttpRequest> {
    headers.push((
        "content-type".into(),
        Zeroizing::new("application/x-www-form-urlencoded".into()),
    ));
    let mut serializer = url::form_urlencoded::Serializer::new(String::new());
    for (key, value) in fields {
        serializer.append_pair(key, value);
    }
    request(
        method,
        url,
        headers,
        Zeroizing::new(serializer.finish().into_bytes()),
    )
}

pub(crate) fn bearer_get(url: &str, token: &Zeroizing<String>) -> AppResult<ProviderHttpRequest> {
    request(
        ProviderHttpMethod::Get,
        url,
        vec![bearer_header(token)],
        Zeroizing::new(Vec::new()),
    )
}

pub(crate) fn bearer_header(token: &Zeroizing<String>) -> (String, Zeroizing<String>) {
    let mut value = Zeroizing::new(String::with_capacity(7 + token.len()));
    value.push_str("Bearer ");
    value.push_str(token.as_str());
    ("authorization".into(), value)
}

pub(crate) fn execute_json<T: for<'de> Deserialize<'de>>(
    http: &dyn ProviderHttp,
    request: ProviderHttpRequest,
    statuses: &[u16],
    operation: &str,
) -> AppResult<T> {
    let response = http.execute(request)?;
    decode_success_json(&response, statuses, operation)
}

pub(crate) fn decode_success_json<T: for<'de> Deserialize<'de>>(
    response: &ProviderHttpResponse,
    statuses: &[u16],
    operation: &str,
) -> AppResult<T> {
    ensure_status(response, statuses, operation)?;
    serde_json::from_slice(response.body()).map_err(|_| {
        AppError::NotAuthorized(format!(
            "{operation} returned a malformed or incomplete response"
        ))
    })
}

pub(crate) fn ensure_status(
    response: &ProviderHttpResponse,
    statuses: &[u16],
    operation: &str,
) -> AppResult<()> {
    if statuses.contains(&response.status) {
        Ok(())
    } else {
        Err(AppError::NotAuthorized(format!(
            "{operation} failed with provider HTTP status {}",
            response.status
        )))
    }
}

pub(crate) fn oauth_error(response: &ProviderHttpResponse) -> AppResult<String> {
    #[derive(Deserialize)]
    #[serde(deny_unknown_fields)]
    struct OAuthError {
        error: String,
        #[serde(default)]
        error_description: Option<String>,
        #[serde(default)]
        error_codes: Vec<i64>,
        #[serde(default)]
        timestamp: Option<String>,
        #[serde(default)]
        trace_id: Option<String>,
        #[serde(default)]
        correlation_id: Option<String>,
        #[serde(default)]
        error_uri: Option<String>,
    }
    let parsed: OAuthError = serde_json::from_slice(response.body())
        .map_err(|_| AppError::NotAuthorized("provider OAuth exchange failed".into()))?;
    let _ = (
        parsed.error_description,
        parsed.error_codes,
        parsed.timestamp,
        parsed.trace_id,
        parsed.correlation_id,
        parsed.error_uri,
    );
    Ok(parsed.error)
}

pub(crate) struct AwsSigningCredentials {
    pub(crate) access_key_id: Zeroizing<String>,
    pub(crate) secret_access_key: Zeroizing<String>,
    pub(crate) session_token: Zeroizing<String>,
}

#[allow(clippy::too_many_arguments)]
pub(crate) fn aws_signed_request(
    method: ProviderHttpMethod,
    url: &str,
    service: &str,
    region: &str,
    body: Zeroizing<Vec<u8>>,
    credentials: &AwsSigningCredentials,
    now: DateTime<Utc>,
) -> AppResult<ProviderHttpRequest> {
    let parsed =
        Url::parse(url).map_err(|_| AppError::Internal("AWS endpoint URL is invalid".into()))?;
    validate_provider_endpoint(&parsed)?;
    let host = parsed
        .host_str()
        .ok_or_else(|| AppError::Internal("AWS endpoint host is missing".into()))?;
    let amz_date = now.format("%Y%m%dT%H%M%SZ").to_string();
    let date = now.format("%Y%m%d").to_string();
    let content_type = "application/x-www-form-urlencoded; charset=utf-8";
    let canonical_headers = format!(
        "content-type:{content_type}\nhost:{host}\nx-amz-date:{amz_date}\nx-amz-security-token:{}\n",
        credentials.session_token.as_str()
    );
    let signed_headers = "content-type;host;x-amz-date;x-amz-security-token";
    let payload_hash = hex::encode(Sha256::digest(body.as_slice()));
    let canonical_request = format!(
        "{}\n{}\n{}\n{}\n{}\n{}",
        match method {
            ProviderHttpMethod::Get => "GET",
            ProviderHttpMethod::Post => "POST",
            ProviderHttpMethod::Put => "PUT",
            ProviderHttpMethod::Delete => "DELETE",
        },
        if parsed.path().is_empty() {
            "/"
        } else {
            parsed.path()
        },
        parsed.query().unwrap_or_default(),
        canonical_headers,
        signed_headers,
        payload_hash
    );
    let credential_scope = format!("{date}/{region}/{service}/aws4_request");
    let string_to_sign = format!(
        "AWS4-HMAC-SHA256\n{amz_date}\n{credential_scope}\n{}",
        hex::encode(Sha256::digest(canonical_request.as_bytes()))
    );
    let mut prefixed_secret =
        Zeroizing::new(Vec::with_capacity(4 + credentials.secret_access_key.len()));
    prefixed_secret.extend_from_slice(b"AWS4");
    prefixed_secret.extend_from_slice(credentials.secret_access_key.as_bytes());
    let date_key = Zeroizing::new(hmac_sha256(&prefixed_secret, date.as_bytes()));
    let region_key = Zeroizing::new(hmac_sha256(date_key.as_slice(), region.as_bytes()));
    let service_key = Zeroizing::new(hmac_sha256(region_key.as_slice(), service.as_bytes()));
    let signing_key = Zeroizing::new(hmac_sha256(service_key.as_slice(), b"aws4_request"));
    let signature = hex::encode(hmac_sha256(
        signing_key.as_slice(),
        string_to_sign.as_bytes(),
    ));
    let authorization = Zeroizing::new(format!(
        "AWS4-HMAC-SHA256 Credential={}/{}, SignedHeaders={}, Signature={}",
        credentials.access_key_id.as_str(),
        credential_scope,
        signed_headers,
        signature
    ));
    request(
        method,
        url,
        vec![
            ("content-type".into(), Zeroizing::new(content_type.into())),
            ("x-amz-date".into(), Zeroizing::new(amz_date)),
            (
                "x-amz-security-token".into(),
                credentials.session_token.clone(),
            ),
            ("authorization".into(), authorization),
        ],
        body,
    )
}

fn hmac_sha256(key: &[u8], data: &[u8]) -> [u8; 32] {
    const BLOCK: usize = 64;
    let mut normalized = Zeroizing::new([0_u8; BLOCK]);
    if key.len() > BLOCK {
        normalized[..32].copy_from_slice(&Sha256::digest(key));
    } else {
        normalized[..key.len()].copy_from_slice(key);
    }
    let mut inner_pad = Zeroizing::new([0_u8; BLOCK]);
    let mut outer_pad = Zeroizing::new([0_u8; BLOCK]);
    for index in 0..BLOCK {
        inner_pad[index] = normalized[index] ^ 0x36;
        outer_pad[index] = normalized[index] ^ 0x5c;
    }
    let mut inner = Sha256::new();
    inner.update(inner_pad.as_slice());
    inner.update(data);
    let inner_hash = Zeroizing::new(inner.finalize().to_vec());
    let mut outer = Sha256::new();
    outer.update(outer_pad.as_slice());
    outer.update(inner_hash.as_slice());
    outer.finalize().into()
}

pub(crate) fn aws_query_encode(value: &str) -> String {
    let mut encoded = String::with_capacity(value.len());
    for byte in value.bytes() {
        if byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.' | b'~') {
            encoded.push(char::from(byte));
        } else {
            encoded.push('%');
            encoded.push_str(&format!("{byte:02X}"));
        }
    }
    encoded
}

pub(crate) fn xml_first(xml: &str, tag: &str) -> AppResult<String> {
    let start = format!("<{tag}>");
    let end = format!("</{tag}>");
    let value = xml
        .split_once(&start)
        .and_then(|(_, suffix)| suffix.split_once(&end).map(|(value, _)| value))
        .ok_or_else(|| AppError::NotAuthorized(format!("AWS XML omitted {tag}")))?;
    if !safe_metadata(value, 2048) || value.contains('&') || value.contains('<') {
        return Err(AppError::NotAuthorized(format!(
            "AWS XML {tag} value is malformed"
        )));
    }
    Ok(value.into())
}

pub(crate) fn aws_simulation_decisions(xml: &str) -> AppResult<BTreeMap<String, String>> {
    let mut decisions = BTreeMap::new();
    let mut cursor = xml;
    while let Some((_, after_start)) = cursor.split_once("<member>") {
        let Some((member, rest)) = after_start.split_once("</member>") else {
            return Err(AppError::NotAuthorized(
                "AWS policy simulation XML is truncated".into(),
            ));
        };
        if member.contains("<EvalActionName>") {
            let action = xml_first(member, "EvalActionName")?;
            let decision = xml_first(member, "EvalDecision")?;
            if decisions.insert(action, decision).is_some() {
                return Err(AppError::NotAuthorized(
                    "AWS policy simulation duplicated an action decision".into(),
                ));
            }
        }
        cursor = rest;
    }
    if decisions.is_empty() {
        return Err(AppError::NotAuthorized(
            "AWS policy simulation returned no decisions".into(),
        ));
    }
    Ok(decisions)
}

fn collect_request_ids<'a>(
    responses: impl IntoIterator<Item = &'a ProviderHttpResponse>,
) -> Vec<String> {
    responses
        .into_iter()
        .flat_map(|response| response.request_headers.values().cloned())
        .filter(|value| safe_metadata(value, 256))
        .collect()
}

pub(crate) fn random_bytes<const N: usize>() -> AppResult<Zeroizing<[u8; N]>> {
    let mut bytes = Zeroizing::new([0_u8; N]);
    getrandom::fill(bytes.as_mut())
        .map_err(|_| AppError::Internal("operating system random source failed".into()))?;
    Ok(bytes)
}

fn safe_metadata(value: &str, limit: usize) -> bool {
    !value.is_empty()
        && value.len() <= limit
        && !value.chars().any(char::is_control)
        && !value.contains('\0')
}

fn safe_label(value: &str) -> String {
    value
        .chars()
        .filter(|character| !character.is_control())
        .take(128)
        .collect()
}

fn valid_uuid(value: &str) -> bool {
    uuid::Uuid::parse_str(value).is_ok()
}

fn valid_aws_region(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 32
        && value
            .bytes()
            .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'-')
        && value.contains('-')
}

fn deserialize_zeroizing<'de, D>(deserializer: D) -> Result<Zeroizing<String>, D::Error>
where
    D: Deserializer<'de>,
{
    String::deserialize(deserializer).map(Zeroizing::new)
}

fn deserialize_optional_zeroizing<'de, D>(
    deserializer: D,
) -> Result<Option<Zeroizing<String>>, D::Error>
where
    D: Deserializer<'de>,
{
    Option::<String>::deserialize(deserializer).map(|value| value.map(Zeroizing::new))
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct AwsRegisterClientResponse {
    #[serde(deserialize_with = "deserialize_zeroizing")]
    client_id: Zeroizing<String>,
    #[serde(deserialize_with = "deserialize_zeroizing")]
    client_secret: Zeroizing<String>,
    #[allow(dead_code)]
    client_id_issued_at: Option<i64>,
    #[allow(dead_code)]
    client_secret_expires_at: Option<i64>,
    #[allow(dead_code)]
    authorization_endpoint: Option<String>,
    #[allow(dead_code)]
    token_endpoint: Option<String>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct AwsDeviceResponse {
    #[serde(deserialize_with = "deserialize_zeroizing")]
    device_code: Zeroizing<String>,
    user_code: String,
    verification_uri: String,
    verification_uri_complete: Option<String>,
    expires_in: u32,
    interval: u32,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct AwsTokenResponse {
    #[serde(deserialize_with = "deserialize_zeroizing")]
    access_token: Zeroizing<String>,
    #[allow(dead_code)]
    expires_in: u32,
    #[allow(dead_code)]
    token_type: String,
    #[serde(default, deserialize_with = "deserialize_optional_zeroizing")]
    #[allow(dead_code)]
    refresh_token: Option<Zeroizing<String>>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct AwsRoleListResponse {
    #[serde(default)]
    role_list: Vec<AwsRoleInfo>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct AwsRoleInfo {
    account_id: String,
    role_name: String,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct AwsRoleCredentialsResponse {
    role_credentials: AwsRoleCredentials,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct AwsRoleCredentials {
    #[serde(deserialize_with = "deserialize_zeroizing")]
    pub(crate) access_key_id: Zeroizing<String>,
    #[serde(deserialize_with = "deserialize_zeroizing")]
    pub(crate) secret_access_key: Zeroizing<String>,
    #[serde(deserialize_with = "deserialize_zeroizing")]
    pub(crate) session_token: Zeroizing<String>,
    pub(crate) expiration: i64,
}

#[derive(Deserialize)]
struct MicrosoftDeviceResponse {
    #[serde(deserialize_with = "deserialize_zeroizing")]
    device_code: Zeroizing<String>,
    user_code: String,
    verification_uri: String,
    expires_in: u32,
    interval: u32,
    #[allow(dead_code)]
    message: Option<String>,
}

#[derive(Deserialize)]
struct OAuthTokenResponse {
    #[serde(deserialize_with = "deserialize_zeroizing")]
    access_token: Zeroizing<String>,
    expires_in: u32,
    #[serde(default)]
    scope: String,
    token_type: String,
    #[serde(default, deserialize_with = "deserialize_optional_zeroizing")]
    refresh_token: Option<Zeroizing<String>>,
}

struct MicrosoftIdentity {
    principal_id: String,
    tenant_id: String,
    #[allow(dead_code)]
    principal_label: String,
    identity_endpoint: String,
    request_ids: Vec<String>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct MicrosoftMe {
    id: String,
    user_principal_name: Option<String>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct MicrosoftServicePrincipal {
    id: String,
    app_id: String,
}

#[derive(Deserialize)]
struct MicrosoftApplicationTokenClaims {
    tid: String,
    oid: String,
}

#[derive(Deserialize)]
struct MicrosoftOrganizations {
    value: Vec<MicrosoftOrganization>,
}

#[derive(Deserialize)]
struct MicrosoftOrganization {
    id: String,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct AzureSubscription {
    subscription_id: String,
}

#[derive(Deserialize)]
struct AzureRoleAssignments {
    value: Vec<AzureRoleAssignment>,
}

#[derive(Deserialize)]
struct AzureRoleAssignment {
    properties: AzureRoleAssignmentProperties,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct AzureRoleAssignmentProperties {
    principal_id: String,
    role_definition_id: String,
}

#[derive(Deserialize)]
struct GoogleUserInfo {
    sub: String,
    #[allow(dead_code)]
    email: Option<String>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct GoogleServiceAccount {
    name: String,
    email: String,
    unique_id: String,
}

#[derive(Deserialize)]
struct GoogleOrganization {
    name: String,
}

#[derive(Deserialize)]
struct GoogleTestIamPermissions {
    #[serde(default)]
    permissions: Vec<String>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hmac_matches_rfc_4231_vector() {
        let key = [0x0b_u8; 20];
        let result = hmac_sha256(&key, b"Hi There");
        assert_eq!(
            hex::encode(result),
            "b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7"
        );
    }

    #[test]
    fn operator_configs_reject_unknown_secret_fields_and_placeholders() {
        let microsoft = r#"{
          "tenant_id":"11111111-1111-4111-8111-111111111111",
          "public_client_id":"22222222-2222-4222-8222-222222222222",
          "profile":"microsoft365_tenant_read_only_access_token",
          "subscription_id":null,
          "client_secret":"must-not-be-accepted"
        }"#;
        assert!(serde_json::from_str::<MicrosoftNativeAuthorizationConfig>(microsoft).is_err());
        let placeholder = MicrosoftNativeAuthorizationConfig {
            tenant_id: "00000000-0000-0000-0000-000000000000".into(),
            public_client_id: "00000000-0000-0000-0000-000000000000".into(),
            profile: ProviderSourceProfile::Microsoft365TenantReadOnlyAccessToken,
            subscription_id: None,
        };
        assert!(validate_microsoft_config(&placeholder).is_err());
    }

    #[test]
    fn request_debug_is_redacted() {
        let request = form_request(
            ProviderHttpMethod::Post,
            GOOGLE_TOKEN_ENDPOINT,
            &[("code", "must-never-leak")],
            vec![(
                "authorization".into(),
                Zeroizing::new("Bearer must-never-leak".into()),
            )],
        )
        .unwrap();
        let debug = format!("{request:?}");
        assert!(!debug.contains("must-never-leak"));
        assert!(debug.contains("[REDACTED]"));
    }
}
