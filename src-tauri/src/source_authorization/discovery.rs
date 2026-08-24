//! Bounded provider-native inventory capture.
//!
//! This client accepts only an already-installed, unexpired source capability
//! and backend-owned scanner credentials. Every HTTP response is handed to a
//! durable artifact sink before pagination metadata or asset records are
//! inspected. Asset parsing remains the connector registry's responsibility.

use super::provider::{
    AwsSigningCredentials, ProviderHttp, ProviderHttpMethod, ProviderHttpRequest,
    ProviderHttpResponse, aws_query_encode, aws_signed_request, bearer_get,
};
use super::{InstalledSourceAuthorization, PROVIDER_DISCOVERY_ENGINE_ID, ProviderSourceProfile};
use crate::connectors::{
    LIVE_PROVIDER_ARTIFACT_SET_SCHEMA, LiveProviderArtifactPage, LiveProviderArtifactSet,
    MAX_LIVE_PROVIDER_PAGES, SnapshotArtifactReference,
};
use crate::container_runtime::ScannerCredentialSet;
use crate::error::{AppError, AppResult};
use chrono::{DateTime, Utc};
use serde_json::Value;
use std::collections::HashMap;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::{Duration as StdDuration, Instant};
use url::Url;
use uuid::Uuid;
use zeroize::Zeroizing;

pub const AWS_LIVE_PROFILE: &str = "aws-organizations-list-accounts";
pub const AZURE_LIVE_PROFILE: &str = "azure-resource-manager-resources";
pub const GCP_LIVE_PROFILE: &str = "gcp-resource-manager-projects";
pub const MICROSOFT365_LIVE_PROFILE: &str = "microsoft-graph-directory-inventory";

const MAX_SUCCESS_PAGES: usize = 8;
const MAX_PAGE_BYTES: usize = 1024 * 1024;
const MAX_CAPTURE_BYTES: usize = 12 * 1024 * 1024;
const MAX_RECORDS: usize = 1_000;
const MAX_RETRIES: usize = 1;
const MAX_CAPTURE_WALL_TIME: StdDuration = StdDuration::from_secs(120);
const AWS_OPERATION: &str = "organizations:ListAccounts";
const AZURE_OPERATION: &str = "resource-manager:ListResources";
const GCP_OPERATION: &str = "cloud-resource-manager:ListProjects";
const M365_ORGANIZATION_OPERATION: &str = "microsoft-graph:GetOrganization";
const M365_USERS_OPERATION: &str = "microsoft-graph:ListUsers";

#[derive(Default)]
pub struct ProviderDiscoveryJobs {
    active: Mutex<HashMap<String, Arc<AtomicBool>>>,
}

impl std::fmt::Debug for ProviderDiscoveryJobs {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("ProviderDiscoveryJobs")
            .field(
                "active_case_count",
                &self.active.lock().map(|active| active.len()).ok(),
            )
            .finish()
    }
}

impl ProviderDiscoveryJobs {
    pub fn is_active(&self, case_id: &str) -> AppResult<bool> {
        Ok(self
            .active
            .lock()
            .map_err(|_| AppError::Internal("provider discovery job lock was poisoned".into()))?
            .contains_key(case_id))
    }

    pub fn begin(&self, case_id: &str) -> AppResult<Arc<AtomicBool>> {
        if case_id.is_empty()
            || case_id.len() > 128
            || !case_id
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_'))
        {
            return Err(AppError::InvalidRequest(
                "case id is invalid for provider discovery".into(),
            ));
        }
        let mut active = self
            .active
            .lock()
            .map_err(|_| AppError::Internal("provider discovery job lock was poisoned".into()))?;
        if active.contains_key(case_id) {
            return Err(AppError::NotAvailable(
                "provider discovery is already active for this case".into(),
            ));
        }
        let cancelled = Arc::new(AtomicBool::new(false));
        active.insert(case_id.into(), cancelled.clone());
        Ok(cancelled)
    }

    pub fn cancel(&self, case_id: &str) -> AppResult<bool> {
        let active = self
            .active
            .lock()
            .map_err(|_| AppError::Internal("provider discovery job lock was poisoned".into()))?;
        Ok(active.get(case_id).is_some_and(|cancelled| {
            cancelled.store(true, Ordering::Release);
            true
        }))
    }

    /// Atomically signals and removes a case-bound discovery job during case
    /// teardown. Its worker keeps the same shared cancellation flag and cannot
    /// re-register itself after the case record is removed.
    pub fn cancel_case(&self, case_id: &str) -> AppResult<bool> {
        let cancelled = self
            .active
            .lock()
            .map_err(|_| AppError::Internal("provider discovery job lock was poisoned".into()))?
            .remove(case_id);
        if let Some(cancelled) = cancelled {
            cancelled.store(true, Ordering::Release);
            Ok(true)
        } else {
            Ok(false)
        }
    }

    pub fn finish(&self, case_id: &str) -> AppResult<()> {
        self.active
            .lock()
            .map_err(|_| AppError::Internal("provider discovery job lock was poisoned".into()))?
            .remove(case_id);
        Ok(())
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LiveProviderFailureKind {
    Authorization,
    Unavailable,
    InvalidResponse,
    Storage,
    Cancelled,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LiveProviderFailure {
    pub kind: LiveProviderFailureKind,
    pub code: &'static str,
    pub message: String,
}

#[derive(Debug, Clone)]
pub struct LiveProviderCapture {
    pub artifact_set: Option<LiveProviderArtifactSet>,
    pub successful_pages: usize,
    pub record_count: usize,
    pub notices: Vec<String>,
    pub failure: Option<LiveProviderFailure>,
}

impl LiveProviderCapture {
    pub fn complete(&self) -> bool {
        self.failure.is_none()
            && self
                .artifact_set
                .as_ref()
                .is_some_and(|artifacts| artifacts.complete)
    }
}

type PersistPage<'a> =
    dyn FnMut(&str, u16, &[u8], &str, DateTime<Utc>) -> AppResult<SnapshotArtifactReference> + 'a;

pub fn capture_provider_inventory(
    http: &dyn ProviderHttp,
    authorization: &InstalledSourceAuthorization,
    credentials: &ScannerCredentialSet,
    cancelled: &AtomicBool,
    now: DateTime<Utc>,
    persist_page: &mut PersistPage<'_>,
) -> LiveProviderCapture {
    let (profile, operation) = profile_and_operation(authorization.profile);
    let mut capture =
        CaptureAccumulator::new(http, profile, operation, cancelled, now, persist_page);
    if let Err(failure) = validate_authorization(authorization, credentials, now) {
        capture.failure = Some(failure);
        return capture.finish();
    }

    let result = match authorization.profile {
        ProviderSourceProfile::AwsOrganizationReadOnlySession => {
            capture_aws(&mut capture, credentials)
        }
        ProviderSourceProfile::AzureTenantReadOnlyAccessToken => {
            capture_azure(&mut capture, authorization, credentials)
        }
        ProviderSourceProfile::GcpOrganizationReadOnlyAccessToken => {
            capture_gcp(&mut capture, authorization, credentials)
        }
        ProviderSourceProfile::Microsoft365TenantReadOnlyAccessToken => {
            capture_microsoft365(&mut capture, credentials)
        }
    };
    if let Err(failure) = result {
        capture.failure = Some(failure);
    }
    capture.finish()
}

struct CaptureAccumulator<'a> {
    http: &'a dyn ProviderHttp,
    profile: &'static str,
    operation: &'static str,
    cancelled: &'a AtomicBool,
    observed_at: DateTime<Utc>,
    started: Instant,
    total_bytes: usize,
    http_success_pages: usize,
    eligible_pages: usize,
    record_count: usize,
    pages: Vec<LiveProviderArtifactPage>,
    notices: Vec<String>,
    failure: Option<LiveProviderFailure>,
    persist_page: &'a mut PersistPage<'a>,
}

impl<'a> CaptureAccumulator<'a> {
    fn new(
        http: &'a dyn ProviderHttp,
        profile: &'static str,
        operation: &'static str,
        cancelled: &'a AtomicBool,
        observed_at: DateTime<Utc>,
        persist_page: &'a mut PersistPage<'a>,
    ) -> Self {
        Self {
            http,
            profile,
            operation,
            cancelled,
            observed_at,
            started: Instant::now(),
            total_bytes: 0,
            http_success_pages: 0,
            eligible_pages: 0,
            record_count: 0,
            pages: Vec::new(),
            notices: Vec::new(),
            failure: None,
            persist_page,
        }
    }

    fn check_active(&self) -> Result<(), LiveProviderFailure> {
        if self.cancelled.load(Ordering::Acquire) {
            return Err(failure(
                LiveProviderFailureKind::Cancelled,
                "provider_discovery_cancelled",
                "provider discovery was cancelled; any already-preserved pages remain attributable partial evidence",
            ));
        }
        if self.started.elapsed() > MAX_CAPTURE_WALL_TIME {
            return Err(failure(
                LiveProviderFailureKind::Unavailable,
                "provider_discovery_deadline",
                "provider discovery exceeded its bounded wall-clock deadline",
            ));
        }
        Ok(())
    }

    fn request<F>(
        &mut self,
        operation: &'static str,
        mut build: F,
    ) -> Result<ProviderHttpResponse, LiveProviderFailure>
    where
        F: FnMut() -> AppResult<ProviderHttpRequest>,
    {
        for attempt in 0..=MAX_RETRIES {
            self.check_active()?;
            let request = build().map_err(map_request_error)?;
            match self.http.execute(request) {
                Ok(response) => {
                    self.preserve_response(operation, &response)?;
                    if transient_status(response.status) && attempt < MAX_RETRIES {
                        thread::sleep(StdDuration::from_millis(50));
                        continue;
                    }
                    if response.status != 200 {
                        return Err(failure(
                            LiveProviderFailureKind::Unavailable,
                            "provider_inventory_http_status",
                            format!(
                                "read-only provider inventory operation returned HTTP {}",
                                response.status
                            ),
                        ));
                    }
                    self.http_success_pages += 1;
                    if self.http_success_pages > MAX_SUCCESS_PAGES {
                        return Err(failure(
                            LiveProviderFailureKind::InvalidResponse,
                            "provider_inventory_page_limit",
                            "provider inventory exceeded the successful page limit",
                        ));
                    }
                    return Ok(response);
                }
                Err(_) if attempt < MAX_RETRIES => {
                    thread::sleep(StdDuration::from_millis(50));
                }
                Err(_) => {
                    return Err(failure(
                        LiveProviderFailureKind::Unavailable,
                        "provider_inventory_transport",
                        "provider inventory endpoint could not be reached within the bounded retry policy",
                    ));
                }
            }
        }
        unreachable!("bounded retry loop always returns")
    }

    fn preserve_response(
        &mut self,
        operation: &str,
        response: &ProviderHttpResponse,
    ) -> Result<(), LiveProviderFailure> {
        let bytes = response.body();
        if bytes.is_empty() || bytes.len() > MAX_PAGE_BYTES {
            return Err(failure(
                LiveProviderFailureKind::InvalidResponse,
                "provider_inventory_response_size",
                "provider inventory response was empty or exceeded the one-megabyte page limit",
            ));
        }
        self.total_bytes = self.total_bytes.checked_add(bytes.len()).ok_or_else(|| {
            failure(
                LiveProviderFailureKind::InvalidResponse,
                "provider_inventory_capture_size",
                "provider inventory response byte count overflowed",
            )
        })?;
        if self.total_bytes > MAX_CAPTURE_BYTES || self.pages.len() >= MAX_LIVE_PROVIDER_PAGES {
            return Err(failure(
                LiveProviderFailureKind::InvalidResponse,
                "provider_inventory_capture_limit",
                "provider inventory capture exceeded its aggregate page or byte limit",
            ));
        }
        let reference = (self.persist_page)(
            operation,
            response.status,
            bytes,
            self.profile,
            self.observed_at,
        )
        .map_err(|_| {
            failure(
                LiveProviderFailureKind::Storage,
                "provider_inventory_artifact_storage",
                "provider response could not be durably stored before parsing",
            )
        })?;
        self.pages.push(LiveProviderArtifactPage {
            sequence: u16::try_from(self.pages.len() + 1).expect("bounded page count"),
            operation: operation.into(),
            http_status: response.status,
            parser_eligible: false,
            artifact: reference,
        });
        Ok(())
    }

    fn mark_last_parser_eligible(&mut self) -> Result<(), LiveProviderFailure> {
        let page = self.pages.last_mut().ok_or_else(|| {
            failure(
                LiveProviderFailureKind::Storage,
                "provider_inventory_artifact_order",
                "provider response was not preserved before response validation",
            )
        })?;
        if page.http_status != 200 {
            return Err(malformed("provider inventory status"));
        }
        if !page.parser_eligible {
            page.parser_eligible = true;
            self.eligible_pages += 1;
        }
        Ok(())
    }

    fn add_records(&mut self, count: usize) -> Result<(), LiveProviderFailure> {
        self.record_count = self.record_count.checked_add(count).ok_or_else(|| {
            failure(
                LiveProviderFailureKind::InvalidResponse,
                "provider_inventory_record_count",
                "provider inventory record count overflowed",
            )
        })?;
        if self.record_count > MAX_RECORDS {
            return Err(failure(
                LiveProviderFailureKind::InvalidResponse,
                "provider_inventory_record_limit",
                "provider inventory exceeded the one-thousand-record limit",
            ));
        }
        Ok(())
    }

    fn finish(self) -> LiveProviderCapture {
        let complete = self.failure.is_none();
        let artifact_set = (!self.pages.is_empty()).then(|| LiveProviderArtifactSet {
            schema_version: LIVE_PROVIDER_ARTIFACT_SET_SCHEMA.into(),
            capture_id: format!("live-provider-{}", Uuid::new_v4()),
            profile: self.profile.into(),
            operation: self.operation.into(),
            observed_at: self.observed_at,
            complete,
            pages: self.pages,
        });
        LiveProviderCapture {
            artifact_set,
            successful_pages: self.eligible_pages,
            record_count: self.record_count,
            notices: self.notices,
            failure: self.failure,
        }
    }
}

fn capture_aws(
    capture: &mut CaptureAccumulator<'_>,
    credentials: &ScannerCredentialSet,
) -> Result<(), LiveProviderFailure> {
    let signing = AwsSigningCredentials {
        access_key_id: secret(credentials, "AWS_ACCESS_KEY_ID")?,
        secret_access_key: secret(credentials, "AWS_SECRET_ACCESS_KEY")?,
        session_token: secret(credentials, "AWS_SESSION_TOKEN")?,
    };
    let mut next_token: Option<String> = None;
    for page in 0..MAX_SUCCESS_PAGES {
        let mut pairs = vec![
            ("Action", "ListAccounts".to_owned()),
            ("MaxResults", "20".to_owned()),
            ("Version", "2016-11-28".to_owned()),
        ];
        if let Some(token) = next_token.as_deref() {
            pairs.push(("NextToken", token.to_owned()));
        }
        pairs.sort_by(|left, right| left.0.cmp(right.0));
        let body = pairs
            .iter()
            .map(|(key, value)| format!("{}={}", aws_query_encode(key), aws_query_encode(value)))
            .collect::<Vec<_>>()
            .join("&")
            .into_bytes();
        let observed_at = capture.observed_at;
        let response = capture.request(AWS_OPERATION, || {
            aws_signed_request(
                ProviderHttpMethod::Post,
                "https://organizations.us-east-1.amazonaws.com/",
                "organizations",
                "us-east-1",
                Zeroizing::new(body.clone()),
                &signing,
                observed_at,
            )
        })?;
        let xml = std::str::from_utf8(response.body()).map_err(|_| malformed("AWS XML"))?;
        capture.add_records(aws_account_count(xml)?)?;
        capture.mark_last_parser_eligible()?;
        next_token = xml_optional_tag(xml, "NextToken")?;
        if next_token.is_none() {
            return Ok(());
        }
        if page + 1 == MAX_SUCCESS_PAGES {
            return Err(page_limit());
        }
    }
    unreachable!("bounded AWS page loop")
}

fn capture_azure(
    capture: &mut CaptureAccumulator<'_>,
    authorization: &InstalledSourceAuthorization,
    credentials: &ScannerCredentialSet,
) -> Result<(), LiveProviderFailure> {
    let subscription_id = scoped_id(
        &authorization.provider_verification.resource_scope,
        "azure-subscription:",
        |value| uuid::Uuid::parse_str(value).is_ok(),
    )?;
    let token = secret(credentials, "AZURE_ACCESS_TOKEN")?;
    let initial = format!(
        "https://management.azure.com/subscriptions/{subscription_id}/resources?api-version=2021-04-01&%24top=100"
    );
    let mut endpoint = initial;
    for page in 0..MAX_SUCCESS_PAGES {
        let request_endpoint = endpoint.clone();
        let response =
            capture.request(AZURE_OPERATION, || bearer_get(&request_endpoint, &token))?;
        let document = json_document(response.body(), "Azure Resource Manager JSON")?;
        capture.add_records(array_len(&document, "value")?)?;
        capture.mark_last_parser_eligible()?;
        let next = optional_string(&document, "nextLink")?;
        let Some(next) = next else {
            return Ok(());
        };
        endpoint = validate_azure_next_link(&next, &subscription_id)?;
        if page + 1 == MAX_SUCCESS_PAGES {
            return Err(page_limit());
        }
    }
    unreachable!("bounded Azure page loop")
}

fn capture_gcp(
    capture: &mut CaptureAccumulator<'_>,
    authorization: &InstalledSourceAuthorization,
    credentials: &ScannerCredentialSet,
) -> Result<(), LiveProviderFailure> {
    let organization_id = scoped_id(
        &authorization.provider_verification.resource_scope,
        "gcp-organization:",
        |value| !value.is_empty() && value.len() <= 32 && value.bytes().all(|b| b.is_ascii_digit()),
    )?;
    let token = secret(credentials, "GOOGLE_OAUTH_ACCESS_TOKEN")?;
    let mut page_token: Option<String> = None;
    for page in 0..MAX_SUCCESS_PAGES {
        let mut endpoint = format!(
            "https://cloudresourcemanager.googleapis.com/v3/projects?parent=organizations%2F{organization_id}&pageSize=100"
        );
        if let Some(value) = page_token.as_deref() {
            endpoint.push_str("&pageToken=");
            endpoint.extend(url::form_urlencoded::byte_serialize(value.as_bytes()));
        }
        let response = capture.request(GCP_OPERATION, || bearer_get(&endpoint, &token))?;
        let document = json_document(response.body(), "Google Resource Manager JSON")?;
        capture.add_records(array_len_optional(&document, "projects")?)?;
        capture.mark_last_parser_eligible()?;
        page_token = optional_pagination_token(&document, "nextPageToken")?;
        if page_token.is_none() {
            return Ok(());
        }
        if page + 1 == MAX_SUCCESS_PAGES {
            return Err(page_limit());
        }
    }
    unreachable!("bounded Google page loop")
}

fn capture_microsoft365(
    capture: &mut CaptureAccumulator<'_>,
    credentials: &ScannerCredentialSet,
) -> Result<(), LiveProviderFailure> {
    let token = secret(credentials, "MSGRAPH_ACCESS_TOKEN")?;
    let organization_endpoint =
        "https://graph.microsoft.com/v1.0/organization?%24select=id%2CdisplayName";
    let organization = capture.request(M365_ORGANIZATION_OPERATION, || {
        bearer_get(organization_endpoint, &token)
    })?;
    let organization_document = json_document(organization.body(), "Microsoft Graph JSON")?;
    let organization_count = array_len(&organization_document, "value")?;
    if organization_count != 1 {
        return Err(malformed("Microsoft Graph organization identity"));
    }
    capture.add_records(organization_count)?;
    capture.mark_last_parser_eligible()?;

    let mut endpoint = "https://graph.microsoft.com/v1.0/users?%24select=id%2CdisplayName%2CuserPrincipalName%2CuserType%2CaccountEnabled&%24top=100".to_owned();
    for page in 0..(MAX_SUCCESS_PAGES - 1) {
        let request_endpoint = endpoint.clone();
        let response = capture.request(M365_USERS_OPERATION, || {
            bearer_get(&request_endpoint, &token)
        })?;
        let document = json_document(response.body(), "Microsoft Graph JSON")?;
        capture.add_records(array_len(&document, "value")?)?;
        capture.mark_last_parser_eligible()?;
        let next = optional_string(&document, "@odata.nextLink")?;
        let Some(next) = next else {
            return Ok(());
        };
        endpoint = validate_graph_next_link(&next)?;
        if page + 1 == MAX_SUCCESS_PAGES - 1 {
            return Err(page_limit());
        }
    }
    unreachable!("bounded Microsoft Graph page loop")
}

fn profile_and_operation(profile: ProviderSourceProfile) -> (&'static str, &'static str) {
    match profile {
        ProviderSourceProfile::AwsOrganizationReadOnlySession => (AWS_LIVE_PROFILE, AWS_OPERATION),
        ProviderSourceProfile::AzureTenantReadOnlyAccessToken => {
            (AZURE_LIVE_PROFILE, AZURE_OPERATION)
        }
        ProviderSourceProfile::GcpOrganizationReadOnlyAccessToken => {
            (GCP_LIVE_PROFILE, GCP_OPERATION)
        }
        ProviderSourceProfile::Microsoft365TenantReadOnlyAccessToken => (
            MICROSOFT365_LIVE_PROFILE,
            "microsoft-graph:DirectoryInventory",
        ),
    }
}

fn validate_authorization(
    authorization: &InstalledSourceAuthorization,
    credentials: &ScannerCredentialSet,
    now: DateTime<Utc>,
) -> Result<(), LiveProviderFailure> {
    if authorization.case_id.is_empty()
        || authorization.source_id.is_empty()
        || authorization.source_kind != authorization.profile.source_kind()
        || authorization.provider != authorization.profile.provider()
        || authorization.provider_verification.profile != authorization.profile
        || authorization.provider_verification.provider != authorization.provider
        || authorization.provider_verification.credential_expires_at != authorization.expires_at
        || authorization.expires_at <= now
        || !authorization
            .allowed_engine_ids
            .contains(PROVIDER_DISCOVERY_ENGINE_ID)
    {
        return Err(failure(
            LiveProviderFailureKind::Authorization,
            "provider_discovery_authorization_binding",
            "live provider authorization is expired or does not match its case/source/provider/profile/engine binding",
        ));
    }
    let expected = match authorization.profile {
        ProviderSourceProfile::AwsOrganizationReadOnlySession => [
            "AWS_ACCESS_KEY_ID",
            "AWS_SECRET_ACCESS_KEY",
            "AWS_SESSION_TOKEN",
        ]
        .as_slice(),
        ProviderSourceProfile::AzureTenantReadOnlyAccessToken => ["AZURE_ACCESS_TOKEN"].as_slice(),
        ProviderSourceProfile::GcpOrganizationReadOnlyAccessToken => {
            ["GOOGLE_OAUTH_ACCESS_TOKEN"].as_slice()
        }
        ProviderSourceProfile::Microsoft365TenantReadOnlyAccessToken => {
            ["MSGRAPH_ACCESS_TOKEN"].as_slice()
        }
    };
    let mut actual = credentials.environment_keys().collect::<Vec<_>>();
    actual.sort_unstable();
    let mut expected = expected.to_vec();
    expected.sort_unstable();
    if actual != expected {
        return Err(failure(
            LiveProviderFailureKind::Authorization,
            "provider_discovery_credential_profile",
            "backend credential keys do not match the verified provider profile",
        ));
    }
    Ok(())
}

fn secret(
    credentials: &ScannerCredentialSet,
    key: &str,
) -> Result<Zeroizing<String>, LiveProviderFailure> {
    credentials
        .provider_secret(key)
        .map(|value| Zeroizing::new(value.to_owned()))
        .ok_or_else(|| {
            failure(
                LiveProviderFailureKind::Authorization,
                "provider_discovery_missing_credential",
                "verified provider credential set is incomplete",
            )
        })
}

fn scoped_id<F>(scope: &str, prefix: &str, validate: F) -> Result<String, LiveProviderFailure>
where
    F: FnOnce(&str) -> bool,
{
    let value = scope.strip_prefix(prefix).unwrap_or_default();
    if !validate(value) {
        return Err(failure(
            LiveProviderFailureKind::Authorization,
            "provider_discovery_resource_scope",
            "verified provider resource scope is malformed",
        ));
    }
    Ok(value.to_owned())
}

fn json_document(bytes: &[u8], label: &str) -> Result<Value, LiveProviderFailure> {
    serde_json::from_slice(bytes).map_err(|_| malformed(label))
}

fn array_len(document: &Value, key: &str) -> Result<usize, LiveProviderFailure> {
    document
        .get(key)
        .and_then(Value::as_array)
        .map(Vec::len)
        .ok_or_else(|| malformed("provider inventory array"))
}

fn array_len_optional(document: &Value, key: &str) -> Result<usize, LiveProviderFailure> {
    match document.get(key) {
        None => Ok(0),
        Some(Value::Array(values)) => Ok(values.len()),
        Some(_) => Err(malformed("provider inventory array")),
    }
}

fn optional_string(document: &Value, key: &str) -> Result<Option<String>, LiveProviderFailure> {
    match document.get(key) {
        None | Some(Value::Null) => Ok(None),
        Some(Value::String(value))
            if !value.is_empty()
                && value.len() <= 16 * 1024
                && !value.chars().any(char::is_control) =>
        {
            Ok(Some(value.clone()))
        }
        Some(_) => Err(malformed("provider pagination link")),
    }
}

fn optional_pagination_token(
    document: &Value,
    key: &str,
) -> Result<Option<String>, LiveProviderFailure> {
    let value = optional_string(document, key)?;
    if value.as_deref().is_some_and(|value| {
        value.len() > 4_096 || value.bytes().any(|byte| byte.is_ascii_control())
    }) {
        return Err(malformed("provider pagination token"));
    }
    Ok(value)
}

fn validate_azure_next_link(
    value: &str,
    subscription_id: &str,
) -> Result<String, LiveProviderFailure> {
    let url = fixed_pagination_url(value, "management.azure.com")?;
    if !url
        .path()
        .eq_ignore_ascii_case(&format!("/subscriptions/{subscription_id}/resources"))
    {
        return Err(malformed("Azure pagination path"));
    }
    validate_query_keys(&url, &["api-version", "$top", "$skiptoken"])?;
    let api_version = url
        .query_pairs()
        .find(|(key, _)| key == "api-version")
        .map(|(_, value)| value.into_owned());
    if api_version.as_deref() != Some("2021-04-01") {
        return Err(malformed("Azure pagination API version"));
    }
    Ok(url.into())
}

fn validate_graph_next_link(value: &str) -> Result<String, LiveProviderFailure> {
    let url = fixed_pagination_url(value, "graph.microsoft.com")?;
    if url.path() != "/v1.0/users" {
        return Err(malformed("Microsoft Graph pagination path"));
    }
    validate_query_keys(&url, &["$select", "$top", "$skiptoken", "$skip"])?;
    let select = url
        .query_pairs()
        .find(|(key, _)| key == "$select")
        .map(|(_, value)| value.into_owned());
    if select.as_deref() != Some("id,displayName,userPrincipalName,userType,accountEnabled") {
        return Err(malformed("Microsoft Graph pagination projection"));
    }
    Ok(url.into())
}

fn fixed_pagination_url(value: &str, host: &str) -> Result<Url, LiveProviderFailure> {
    let url = Url::parse(value).map_err(|_| malformed("provider pagination URL"))?;
    if url.scheme() != "https"
        || url.host_str() != Some(host)
        || url.port().is_some()
        || !url.username().is_empty()
        || url.password().is_some()
        || url.fragment().is_some()
    {
        return Err(malformed("provider pagination authority"));
    }
    Ok(url)
}

fn validate_query_keys(url: &Url, allowed: &[&str]) -> Result<(), LiveProviderFailure> {
    let pairs = url.query_pairs().collect::<Vec<_>>();
    if pairs.is_empty()
        || pairs.len() > 8
        || pairs.iter().any(|(key, value)| {
            !allowed.contains(&key.as_ref())
                || value.is_empty()
                || value.len() > 8_192
                || value.bytes().any(|byte| byte.is_ascii_control())
        })
    {
        return Err(malformed("provider pagination query"));
    }
    Ok(())
}

fn aws_account_count(xml: &str) -> Result<usize, LiveProviderFailure> {
    if !xml.contains("<ListAccountsResponse") || !xml.contains("</ListAccountsResponse>") {
        return Err(malformed("AWS ListAccounts XML"));
    }
    let accounts = xml
        .split_once("<Accounts>")
        .and_then(|(_, suffix)| suffix.split_once("</Accounts>").map(|(value, _)| value))
        .unwrap_or_default();
    Ok(accounts.matches("<member>").count())
}

fn xml_optional_tag(xml: &str, tag: &str) -> Result<Option<String>, LiveProviderFailure> {
    let start = format!("<{tag}>");
    let end = format!("</{tag}>");
    let Some((_, suffix)) = xml.split_once(&start) else {
        return Ok(None);
    };
    let (value, _) = suffix
        .split_once(&end)
        .ok_or_else(|| malformed("AWS pagination token"))?;
    if value.is_empty()
        || value.len() > 4_096
        || value.chars().any(char::is_control)
        || value.contains(['<', '>', '&'])
    {
        return Err(malformed("AWS pagination token"));
    }
    Ok(Some(value.to_owned()))
}

fn transient_status(status: u16) -> bool {
    matches!(status, 429 | 500 | 502 | 503 | 504)
}

fn page_limit() -> LiveProviderFailure {
    failure(
        LiveProviderFailureKind::InvalidResponse,
        "provider_inventory_page_limit",
        "provider inventory returned another page after the bounded page limit",
    )
}

fn malformed(label: &str) -> LiveProviderFailure {
    failure(
        LiveProviderFailureKind::InvalidResponse,
        "provider_inventory_malformed_response",
        format!("{label} was malformed or outside the response contract"),
    )
}

fn map_request_error(error: AppError) -> LiveProviderFailure {
    let kind = if matches!(error, AppError::NotAuthorized(_)) {
        LiveProviderFailureKind::Authorization
    } else {
        LiveProviderFailureKind::InvalidResponse
    };
    failure(
        kind,
        "provider_inventory_request_contract",
        "provider inventory request could not be constructed within the fixed endpoint contract",
    )
}

fn failure(
    kind: LiveProviderFailureKind,
    code: &'static str,
    message: impl Into<String>,
) -> LiveProviderFailure {
    LiveProviderFailure {
        kind,
        code,
        message: message.into(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::connectors::SnapshotConnectorRegistry;
    use crate::container_runtime::{CredentialSource, ScannerCredential};
    use crate::credential_vault::ReadOnlyCredentialSource;
    use crate::discovery::run_connector;
    use crate::domain::{DataSource, SourceConnectionStatus, SourceKind};
    use std::collections::{BTreeMap, BTreeSet, VecDeque};
    use std::fs;
    use std::sync::Mutex;

    struct FixtureHttp {
        responses: Mutex<VecDeque<ProviderHttpResponse>>,
        requests: Mutex<Vec<String>>,
        events: Arc<Mutex<Vec<String>>>,
    }

    impl FixtureHttp {
        fn new(responses: Vec<ProviderHttpResponse>, events: Arc<Mutex<Vec<String>>>) -> Self {
            Self {
                responses: Mutex::new(responses.into()),
                requests: Mutex::new(Vec::new()),
                events,
            }
        }
    }

    impl ProviderHttp for FixtureHttp {
        fn execute(&self, request: ProviderHttpRequest) -> AppResult<ProviderHttpResponse> {
            assert!(!format!("{request:?}").contains("fixture-secret"));
            let summary = format!("{:?} {}", request.method(), request.url());
            self.requests.lock().unwrap().push(summary.clone());
            self.events.lock().unwrap().push(format!("http:{summary}"));
            self.responses
                .lock()
                .unwrap()
                .pop_front()
                .ok_or_else(|| AppError::Internal("fixture response queue exhausted".into()))
        }
    }

    fn now() -> DateTime<Utc> {
        Utc::now()
    }

    fn authorization(profile: ProviderSourceProfile) -> InstalledSourceAuthorization {
        let timestamp = now();
        let resource_scope = match profile {
            ProviderSourceProfile::AwsOrganizationReadOnlySession => "aws-account:111111111111",
            ProviderSourceProfile::AzureTenantReadOnlyAccessToken => {
                "azure-subscription:22222222-2222-4222-8222-222222222222"
            }
            ProviderSourceProfile::GcpOrganizationReadOnlyAccessToken => {
                "gcp-organization:123456789012"
            }
            ProviderSourceProfile::Microsoft365TenantReadOnlyAccessToken => {
                "microsoft365-tenant:33333333-3333-4333-8333-333333333333"
            }
        };
        let provider = profile.provider();
        InstalledSourceAuthorization {
            schema_version: "2.0.0".into(),
            case_id: "case-live".into(),
            source_id: "source-live".into(),
            provider,
            source_kind: profile.source_kind(),
            profile,
            credential_source: ReadOnlyCredentialSource::ProviderNative,
            provider_identity: "fixture-provider-identity".into(),
            permissions: profile.permissions(),
            expires_at: timestamp + chrono::Duration::minutes(30),
            allowed_engine_ids: BTreeSet::from([PROVIDER_DISCOVERY_ENGINE_ID.into()]),
            max_checkouts: 8,
            provider_verification: super::super::ProviderVerificationState {
                schema_version: "2.0.0".into(),
                provider,
                profile,
                authentication_method: "fixture".into(),
                provider_identity: "fixture-provider-identity".into(),
                subject_id: "fixture-subject".into(),
                resource_scope: resource_scope.into(),
                verified_at: timestamp,
                credential_expires_at: timestamp + chrono::Duration::minutes(30),
                identity_endpoint: "https://fixture.invalid/identity".into(),
                permission_endpoints: vec!["https://fixture.invalid/permissions".into()],
                required_permissions_verified: vec!["inventory.read".into()],
                prohibited_permissions_denied: vec!["inventory.write".into()],
                provider_request_ids: vec![],
                evidence_sha256: "a".repeat(64),
            },
            safety_notice: "fixture".into(),
        }
    }

    fn credentials(profile: ProviderSourceProfile) -> ScannerCredentialSet {
        let expiry = now() + chrono::Duration::minutes(30);
        let values = match profile {
            ProviderSourceProfile::AwsOrganizationReadOnlySession => vec![
                ("AWS_ACCESS_KEY_ID", "AKIAFIXTURE000000000"),
                ("AWS_SECRET_ACCESS_KEY", "fixture-secret-aws"),
                ("AWS_SESSION_TOKEN", "fixture-session"),
            ],
            ProviderSourceProfile::AzureTenantReadOnlyAccessToken => {
                vec![("AZURE_ACCESS_TOKEN", "fixture-secret-azure")]
            }
            ProviderSourceProfile::GcpOrganizationReadOnlyAccessToken => {
                vec![("GOOGLE_OAUTH_ACCESS_TOKEN", "fixture-secret-gcp")]
            }
            ProviderSourceProfile::Microsoft365TenantReadOnlyAccessToken => {
                vec![("MSGRAPH_ACCESS_TOKEN", "fixture-secret-m365")]
            }
        };
        ScannerCredentialSet::new(
            values
                .into_iter()
                .map(|(key, value)| {
                    ScannerCredential::ephemeral_read_only(
                        key,
                        value,
                        expiry,
                        CredentialSource::ExternalReadOnlyGrant,
                    )
                })
                .collect::<AppResult<Vec<_>>>()
                .unwrap(),
        )
        .unwrap()
    }

    fn responses(profile: ProviderSourceProfile) -> Vec<ProviderHttpResponse> {
        match profile {
            ProviderSourceProfile::AwsOrganizationReadOnlySession => vec![
                ProviderHttpResponse::new(
                    200,
                    br#"<ListAccountsResponse><ListAccountsResult><Accounts><member><Id>123456789012</Id><Arn>arn:aws:organizations::111111111111:account/o-example/123456789012</Arn><Email>raw-only@example.test</Email><Name>Production</Name><Status>ACTIVE</Status></member></Accounts></ListAccountsResult></ListAccountsResponse>"#.to_vec(),
                ),
            ],
            ProviderSourceProfile::AzureTenantReadOnlyAccessToken => vec![
                ProviderHttpResponse::new(
                    200,
                    br#"{"value":[{"id":"/subscriptions/22222222-2222-4222-8222-222222222222/resourceGroups/example/providers/Microsoft.Storage/storageAccounts/evidence","name":"evidence","type":"Microsoft.Storage/storageAccounts","location":"eastus"}]}"#.to_vec(),
                ),
            ],
            ProviderSourceProfile::GcpOrganizationReadOnlyAccessToken => vec![
                ProviderHttpResponse::new(
                    200,
                    br#"{"projects":[{"name":"projects/987654321","parent":"organizations/123456789012","projectId":"example-prod-123","displayName":"Production","state":"ACTIVE"}]}"#.to_vec(),
                ),
            ],
            ProviderSourceProfile::Microsoft365TenantReadOnlyAccessToken => vec![
                ProviderHttpResponse::new(
                    200,
                    br#"{"value":[{"id":"33333333-3333-4333-8333-333333333333","displayName":"Example tenant"}]}"#.to_vec(),
                ),
                ProviderHttpResponse::new(
                    200,
                    br#"{"value":[{"id":"44444444-4444-4444-8444-444444444444","displayName":"Ada Example","userPrincipalName":"ada@example.test","userType":"Member","accountEnabled":true}]}"#.to_vec(),
                ),
            ],
        }
    }

    fn capture_fixture(
        profile: ProviderSourceProfile,
    ) -> (
        LiveProviderCapture,
        SnapshotConnectorRegistry,
        Arc<Mutex<Vec<String>>>,
    ) {
        let temp = tempfile::tempdir().unwrap();
        let root = temp.keep().join("connector-artifacts");
        fs::create_dir(&root).unwrap();
        let registry = SnapshotConnectorRegistry::new(&root).unwrap();
        let events = Arc::new(Mutex::new(Vec::new()));
        let http = FixtureHttp::new(responses(profile), events.clone());
        let authorization = authorization(profile);
        let credentials = credentials(profile);
        let source_kind = profile.source_kind();
        let registry_for_sink = registry.clone();
        let events_for_sink = events.clone();
        let mut persist = move |operation: &str,
                                status: u16,
                                bytes: &[u8],
                                parser_profile: &str,
                                observed_at: DateTime<Utc>| {
            events_for_sink
                .lock()
                .unwrap()
                .push(format!("persist:{operation}:{status}"));
            registry_for_sink
                .ingest_provider_response(&source_kind, bytes, parser_profile, observed_at)
                .map_err(|error| AppError::Storage(error.to_string()))
        };
        let capture = capture_provider_inventory(
            &http,
            &authorization,
            &credentials,
            &AtomicBool::new(false),
            now(),
            &mut persist,
        );
        (capture, registry, events)
    }

    #[test]
    fn all_four_provider_fixtures_are_preserved_before_connector_parsing() {
        for profile in [
            ProviderSourceProfile::AwsOrganizationReadOnlySession,
            ProviderSourceProfile::AzureTenantReadOnlyAccessToken,
            ProviderSourceProfile::GcpOrganizationReadOnlyAccessToken,
            ProviderSourceProfile::Microsoft365TenantReadOnlyAccessToken,
        ] {
            let (capture, registry, events) = capture_fixture(profile);
            assert!(capture.complete(), "{profile:?}: {capture:?}");
            let artifacts = capture.artifact_set.expect("artifact set");
            assert!(
                artifacts
                    .pages
                    .iter()
                    .all(|page| page.artifact.sha256.is_some())
            );
            let event_log = events.lock().unwrap();
            assert_eq!(event_log.len() % 2, 0);
            for pair in event_log.chunks(2) {
                assert!(pair[0].starts_with("http:"), "{pair:?}");
                assert!(pair[1].starts_with("persist:"), "{pair:?}");
            }
            drop(event_log);

            let mut source = DataSource {
                id: "source-live".into(),
                kind: profile.source_kind(),
                label: "Live provider".into(),
                status: SourceConnectionStatus::Connected,
                connected_at: Some(now()),
                last_discovered_at: None,
                read_only: true,
                metadata: BTreeMap::new(),
            };
            artifacts.insert_into(&mut source).unwrap();
            let batch = run_connector(&registry.connector_for(&source.kind), &source)
                .expect("preserved provider pages parse through connector");
            assert!(!batch.assets.is_empty());
            assert!(
                batch
                    .notices
                    .iter()
                    .any(|notice| notice.contains("durably preserved"))
            );
            assert!(batch.assets.iter().all(|asset| {
                !serde_json::to_string(asset)
                    .unwrap()
                    .contains("fixture-secret")
            }));
        }
    }

    #[cfg(unix)]
    #[test]
    fn raw_provider_artifacts_are_content_addressed_and_private() {
        use std::os::unix::fs::PermissionsExt;
        let (capture, registry, _) =
            capture_fixture(ProviderSourceProfile::AzureTenantReadOnlyAccessToken);
        let set = capture.artifact_set.unwrap();
        let reference = &set.pages[0].artifact;
        assert!(
            reference
                .canonical_relative_path
                .contains(reference.sha256.as_deref().unwrap())
        );
        let path = registry
            .artifact_root()
            .join(&reference.canonical_relative_path);
        assert_eq!(
            fs::metadata(path).unwrap().permissions().mode() & 0o777,
            0o600
        );
    }

    #[test]
    fn connected_empty_gcp_response_is_complete_but_never_claims_an_asset() {
        let temp = tempfile::tempdir().unwrap();
        let root = temp.path().join("artifacts");
        fs::create_dir(&root).unwrap();
        let registry = SnapshotConnectorRegistry::new(&root).unwrap();
        let events = Arc::new(Mutex::new(Vec::new()));
        let http = FixtureHttp::new(
            vec![ProviderHttpResponse::new(200, br#"{}"#.to_vec())],
            events,
        );
        let profile = ProviderSourceProfile::GcpOrganizationReadOnlyAccessToken;
        let source_kind = profile.source_kind();
        let mut sink =
            |_: &str, _: u16, bytes: &[u8], parser_profile: &str, observed_at: DateTime<Utc>| {
                registry
                    .ingest_provider_response(&source_kind, bytes, parser_profile, observed_at)
                    .map_err(|error| AppError::Storage(error.to_string()))
            };
        let capture = capture_provider_inventory(
            &http,
            &authorization(profile),
            &credentials(profile),
            &AtomicBool::new(false),
            now(),
            &mut sink,
        );
        assert!(capture.complete());
        assert_eq!(capture.record_count, 0);
        let mut source = DataSource {
            id: "source-live".into(),
            kind: source_kind,
            label: "Empty provider".into(),
            status: SourceConnectionStatus::Connected,
            connected_at: Some(now()),
            last_discovered_at: None,
            read_only: true,
            metadata: BTreeMap::new(),
        };
        capture
            .artifact_set
            .unwrap()
            .insert_into(&mut source)
            .unwrap();
        let batch = run_connector(&registry.connector_for(&source.kind), &source).unwrap();
        assert!(batch.assets.is_empty());
        assert!(
            batch
                .notices
                .iter()
                .any(|notice| notice.contains("connected but empty"))
        );
    }

    #[test]
    fn malformed_oversized_and_cross_host_pagination_fail_after_safe_capture() {
        let cases = [
            (
                ProviderHttpResponse::new(200, br#"{"value":not-json}"#.to_vec()),
                "provider_inventory_malformed_response",
                true,
            ),
            (
                ProviderHttpResponse::new(200, vec![b'x'; MAX_PAGE_BYTES + 1]),
                "provider_inventory_response_size",
                false,
            ),
            (
                ProviderHttpResponse::new(
                    200,
                    br#"{"value":[],"nextLink":"https://attacker.invalid/subscriptions/22222222-2222-4222-8222-222222222222/resources?api-version=2021-04-01"}"#.to_vec(),
                ),
                "provider_inventory_malformed_response",
                true,
            ),
        ];
        for (response, expected_code, persisted) in cases {
            let temp = tempfile::tempdir().unwrap();
            let root = temp.path().join("artifacts");
            fs::create_dir(&root).unwrap();
            let registry = SnapshotConnectorRegistry::new(&root).unwrap();
            let events = Arc::new(Mutex::new(Vec::new()));
            let http = FixtureHttp::new(vec![response], events);
            let profile = ProviderSourceProfile::AzureTenantReadOnlyAccessToken;
            let auth = authorization(profile);
            let creds = credentials(profile);
            let mut sink = |_: &str,
                            _: u16,
                            bytes: &[u8],
                            parser_profile: &str,
                            observed_at: DateTime<Utc>| {
                registry
                    .ingest_provider_response(
                        &SourceKind::AzureTenant,
                        bytes,
                        parser_profile,
                        observed_at,
                    )
                    .map_err(|error| AppError::Storage(error.to_string()))
            };
            let capture = capture_provider_inventory(
                &http,
                &auth,
                &creds,
                &AtomicBool::new(false),
                now(),
                &mut sink,
            );
            assert_eq!(capture.failure.as_ref().unwrap().code, expected_code);
            assert_eq!(capture.artifact_set.is_some(), persisted);
        }
    }

    #[test]
    fn expired_binding_and_cancellation_make_no_provider_request() {
        let profile = ProviderSourceProfile::GcpOrganizationReadOnlyAccessToken;
        let events = Arc::new(Mutex::new(Vec::new()));
        let http = FixtureHttp::new(responses(profile), events.clone());
        let mut auth = authorization(profile);
        auth.expires_at = now() - chrono::Duration::seconds(1);
        auth.provider_verification.credential_expires_at = auth.expires_at;
        let mut sink = |_: &str, _: u16, _: &[u8], _: &str, _: DateTime<Utc>| {
            Err(AppError::Internal("sink must not run".into()))
        };
        let capture = capture_provider_inventory(
            &http,
            &auth,
            &credentials(profile),
            &AtomicBool::new(false),
            now(),
            &mut sink,
        );
        assert_eq!(
            capture.failure.unwrap().kind,
            LiveProviderFailureKind::Authorization
        );
        assert!(events.lock().unwrap().is_empty());

        let events = Arc::new(Mutex::new(Vec::new()));
        let http = FixtureHttp::new(responses(profile), events.clone());
        let cancelled = AtomicBool::new(true);
        let capture = capture_provider_inventory(
            &http,
            &authorization(profile),
            &credentials(profile),
            &cancelled,
            now(),
            &mut sink,
        );
        assert_eq!(
            capture.failure.unwrap().kind,
            LiveProviderFailureKind::Cancelled
        );
        assert!(events.lock().unwrap().is_empty());
    }

    #[test]
    fn cancellation_registry_is_case_bound_and_restart_empty() {
        let jobs = ProviderDiscoveryJobs::default();
        let cancelled = jobs.begin("case-live").unwrap();
        assert!(jobs.begin("case-live").is_err());
        assert!(jobs.cancel("case-live").unwrap());
        assert!(cancelled.load(Ordering::Acquire));
        jobs.finish("case-live").unwrap();
        assert!(!jobs.cancel("case-live").unwrap());

        // Process-memory job and credential state intentionally do not survive
        // a fresh registry instance.
        let restarted = ProviderDiscoveryJobs::default();
        assert!(!restarted.cancel("case-live").unwrap());
    }
}
