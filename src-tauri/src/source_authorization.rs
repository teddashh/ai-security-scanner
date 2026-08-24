//! Verified provider authorization and source-bound credential capabilities.
//!
//! Provider credentials enter this module only after a provider-hosted flow and
//! live, non-mutating identity/permission checks implemented in [`provider`].
//! Secret-bearing types deliberately implement neither serde nor revealing
//! `Debug`; only non-secret proof metadata may cross the UI or persistence
//! boundary.

pub mod discovery;
pub mod provider;
pub mod session;

use crate::bootstrap::{BootstrapProvider, ReadOnlyCapability};
use crate::container_runtime::{CredentialSource, ScannerCredential, ScannerCredentialSet};
use crate::credential_vault::ReadOnlyCredentialSource;
use crate::domain::SourceKind;
use crate::error::{AppError, AppResult};
use chrono::{DateTime, Duration, Utc};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::fmt;
use std::fmt::Write as _;
use std::io::{Read, Write};
use std::str::FromStr;
use std::sync::Mutex;
use zeroize::Zeroizing;

const CAPABILITY_PREFIX: &str = "asscap_v1_";
const CAPABILITY_RANDOM_BYTES: usize = 32;
const MAX_AUTHORIZATION_LIFETIME: Duration = Duration::hours(1);
const MAX_VERIFICATION_AGE: Duration = Duration::minutes(10);
const MAX_CHECKOUTS: u8 = 8;
const MAX_SECRET_BYTES: usize = 128 * 1024;
pub const PROVIDER_DISCOVERY_ENGINE_ID: &str = "provider-native-discovery";

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum ProviderSourceProfile {
    AwsOrganizationReadOnlySession,
    AzureTenantReadOnlyAccessToken,
    GcpOrganizationReadOnlyAccessToken,
    Microsoft365TenantReadOnlyAccessToken,
}

impl ProviderSourceProfile {
    pub fn provider(self) -> BootstrapProvider {
        match self {
            Self::AwsOrganizationReadOnlySession => BootstrapProvider::Aws,
            Self::AzureTenantReadOnlyAccessToken => BootstrapProvider::Azure,
            Self::GcpOrganizationReadOnlyAccessToken => BootstrapProvider::Gcp,
            Self::Microsoft365TenantReadOnlyAccessToken => BootstrapProvider::Microsoft365,
        }
    }

    pub fn source_kind(self) -> SourceKind {
        match self {
            Self::AwsOrganizationReadOnlySession => SourceKind::AwsOrganization,
            Self::AzureTenantReadOnlyAccessToken => SourceKind::AzureTenant,
            Self::GcpOrganizationReadOnlyAccessToken => SourceKind::GcpOrganization,
            Self::Microsoft365TenantReadOnlyAccessToken => SourceKind::Microsoft365Tenant,
        }
    }

    pub fn permissions(self) -> Vec<ReadOnlyCapability> {
        vec![
            ReadOnlyCapability::Inventory,
            ReadOnlyCapability::Configuration,
            ReadOnlyCapability::IdentityAndAccess,
            ReadOnlyCapability::SecurityPosture,
            ReadOnlyCapability::AuditMetadata,
        ]
    }

    pub fn allowed_engine_ids(self) -> BTreeSet<&'static str> {
        match self {
            Self::AwsOrganizationReadOnlySession => [
                "cloudquery",
                "cloudsplaining",
                PROVIDER_DISCOVERY_ENGINE_ID,
                "prowler",
                "scoutsuite",
                "steampipe",
            ]
            .into_iter()
            .collect(),
            // The released Azure and GCP token profiles currently feed only
            // provider-native discovery. Upstream multi-cloud support is not
            // an executable release contract for our AWS-only images.
            Self::AzureTenantReadOnlyAccessToken | Self::GcpOrganizationReadOnlyAccessToken => {
                [PROVIDER_DISCOVERY_ENGINE_ID].into_iter().collect()
            }
            Self::Microsoft365TenantReadOnlyAccessToken => {
                ["maester", PROVIDER_DISCOVERY_ENGINE_ID, "scubagear"]
                    .into_iter()
                    .collect()
            }
        }
    }

    fn required_environment_keys(self) -> BTreeSet<&'static str> {
        match self {
            Self::AwsOrganizationReadOnlySession => [
                "AWS_ACCESS_KEY_ID",
                "AWS_SECRET_ACCESS_KEY",
                "AWS_SESSION_TOKEN",
            ]
            .into_iter()
            .collect(),
            Self::AzureTenantReadOnlyAccessToken => ["AZURE_ACCESS_TOKEN"].into_iter().collect(),
            Self::GcpOrganizationReadOnlyAccessToken => {
                ["GOOGLE_OAUTH_ACCESS_TOKEN"].into_iter().collect()
            }
            Self::Microsoft365TenantReadOnlyAccessToken => {
                ["MSGRAPH_ACCESS_TOKEN"].into_iter().collect()
            }
        }
    }
}

/// Provider-signed proof metadata. This is deliberately sufficient to explain
/// what was checked, while containing no token, key, authorization code, or
/// client secret.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct ProviderVerificationState {
    pub schema_version: String,
    pub provider: BootstrapProvider,
    pub profile: ProviderSourceProfile,
    pub authentication_method: String,
    pub provider_identity: String,
    pub subject_id: String,
    pub resource_scope: String,
    pub verified_at: DateTime<Utc>,
    pub credential_expires_at: DateTime<Utc>,
    pub identity_endpoint: String,
    pub permission_endpoints: Vec<String>,
    pub required_permissions_verified: Vec<String>,
    pub prohibited_permissions_denied: Vec<String>,
    pub provider_request_ids: Vec<String>,
    pub evidence_sha256: String,
}

/// A provider secret accepted only through the Rust backend. It cannot be
/// cloned, serialized, or printed.
pub struct SecretEnvironmentValue {
    key: String,
    value: Zeroizing<String>,
}

impl SecretEnvironmentValue {
    pub fn new(key: impl Into<String>, value: Zeroizing<String>) -> Self {
        Self {
            key: key.into(),
            value,
        }
    }
}

impl fmt::Debug for SecretEnvironmentValue {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("SecretEnvironmentValue")
            .field("key", &"[REDACTED_UNTIL_ALLOWLISTED]")
            .field("value", &"[REDACTED]")
            .finish()
    }
}

pub struct ProviderSecretMaterial {
    entries: Vec<SecretEnvironmentValue>,
}

impl ProviderSecretMaterial {
    pub fn new(entries: Vec<SecretEnvironmentValue>) -> Self {
        Self { entries }
    }
}

impl fmt::Debug for ProviderSecretMaterial {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ProviderSecretMaterial")
            .field("entry_count", &self.entries.len())
            .field("values", &"[REDACTED]")
            .finish()
    }
}

/// Secret-bearing provider result. Only provider clients in this crate can
/// construct it after live verification. It cannot cross a serde boundary.
pub struct VerifiedProviderAuthorization {
    provider: BootstrapProvider,
    source_kind: SourceKind,
    profile: ProviderSourceProfile,
    credential_source: ReadOnlyCredentialSource,
    provider_identity: String,
    expires_at: DateTime<Utc>,
    verification: ProviderVerificationState,
    secret_material: ProviderSecretMaterial,
}

impl fmt::Debug for VerifiedProviderAuthorization {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("VerifiedProviderAuthorization")
            .field("provider", &self.provider)
            .field("source_kind", &self.source_kind)
            .field("profile", &self.profile)
            .field("credential_source", &self.credential_source)
            .field("provider_identity", &self.provider_identity)
            .field("expires_at", &self.expires_at)
            .field("verification", &self.verification)
            .field("secret_material", &"[REDACTED]")
            .finish()
    }
}

impl VerifiedProviderAuthorization {
    pub(crate) fn new_verified(
        profile: ProviderSourceProfile,
        credential_source: ReadOnlyCredentialSource,
        provider_identity: String,
        expires_at: DateTime<Utc>,
        verification: ProviderVerificationState,
        secret_material: ProviderSecretMaterial,
    ) -> AppResult<Self> {
        let provider = profile.provider();
        let source_kind = profile.source_kind();
        if verification.provider != provider
            || verification.profile != profile
            || verification.provider_identity != provider_identity
            || verification.credential_expires_at != expires_at
        {
            return Err(AppError::NotAuthorized(
                "provider verification proof does not match the scanner credential".into(),
            ));
        }
        validate_provider_identity(&provider_identity)?;
        Ok(Self {
            provider,
            source_kind,
            profile,
            credential_source,
            provider_identity,
            expires_at,
            verification,
            secret_material,
        })
    }

    pub fn verification(&self) -> &ProviderVerificationState {
        &self.verification
    }
}

/// Backend-only request. Its verified authorization cannot be deserialized or
/// supplied by the webview.
pub struct SourceAuthorizationRequest {
    pub case_id: String,
    pub source_id: String,
    pub allowed_engine_ids: BTreeSet<String>,
    pub max_checkouts: u8,
    pub verified_authorization: VerifiedProviderAuthorization,
}

impl fmt::Debug for SourceAuthorizationRequest {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("SourceAuthorizationRequest")
            .field("case_id", &self.case_id)
            .field("source_id", &self.source_id)
            .field("allowed_engine_ids", &self.allowed_engine_ids)
            .field("max_checkouts", &self.max_checkouts)
            .field("verified_authorization", &self.verified_authorization)
            .finish()
    }
}

/// Process-memory capability. It intentionally implements no serde traits.
pub struct SourceCapabilityHandle(Zeroizing<String>);

impl SourceCapabilityHandle {
    fn from_random_bytes(bytes: &[u8; CAPABILITY_RANDOM_BYTES]) -> Self {
        let mut encoded = Zeroizing::new(String::with_capacity(
            CAPABILITY_PREFIX.len() + CAPABILITY_RANDOM_BYTES * 2,
        ));
        encoded.push_str(CAPABILITY_PREFIX);
        for byte in bytes {
            write!(&mut *encoded, "{byte:02x}").expect("writing to a String cannot fail");
        }
        Self(encoded)
    }

    fn decoded(&self) -> AppResult<Zeroizing<[u8; CAPABILITY_RANDOM_BYTES]>> {
        let encoded = self.0.strip_prefix(CAPABILITY_PREFIX).ok_or_else(|| {
            AppError::NotAuthorized("source capability handle is malformed".into())
        })?;
        if encoded.len() != CAPABILITY_RANDOM_BYTES * 2
            || !encoded.bytes().all(|byte| byte.is_ascii_hexdigit())
        {
            return Err(AppError::NotAuthorized(
                "source capability handle is malformed".into(),
            ));
        }
        let mut decoded = Zeroizing::new([0_u8; CAPABILITY_RANDOM_BYTES]);
        hex::decode_to_slice(encoded, decoded.as_mut())
            .map_err(|_| AppError::NotAuthorized("source capability handle is malformed".into()))?;
        Ok(decoded)
    }
}

impl Clone for SourceCapabilityHandle {
    fn clone(&self) -> Self {
        Self(self.0.clone())
    }
}

impl fmt::Debug for SourceCapabilityHandle {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("SourceCapabilityHandle([REDACTED])")
    }
}

impl FromStr for SourceCapabilityHandle {
    type Err = AppError;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        let handle = Self(Zeroizing::new(value.to_owned()));
        handle.decoded()?;
        Ok(handle)
    }
}

#[derive(Clone)]
pub struct SourceAuthorizationReceipt {
    pub schema_version: String,
    pub case_id: String,
    pub source_id: String,
    pub provider: BootstrapProvider,
    pub source_kind: SourceKind,
    pub profile: ProviderSourceProfile,
    pub credential_source: ReadOnlyCredentialSource,
    pub provider_identity: String,
    pub permissions: Vec<ReadOnlyCapability>,
    pub expires_at: DateTime<Utc>,
    pub capability_handle: SourceCapabilityHandle,
    pub allowed_engine_ids: BTreeSet<String>,
    pub max_checkouts: u8,
    pub provider_verification: ProviderVerificationState,
    pub safety_notice: String,
}

impl fmt::Debug for SourceAuthorizationReceipt {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("SourceAuthorizationReceipt")
            .field("case_id", &self.case_id)
            .field("source_id", &self.source_id)
            .field("provider", &self.provider)
            .field("profile", &self.profile)
            .field("provider_identity", &self.provider_identity)
            .field("expires_at", &self.expires_at)
            .field("capability_handle", &self.capability_handle)
            .field("provider_verification", &self.provider_verification)
            .finish_non_exhaustive()
    }
}

pub struct SourceCredentialCheckout<'a> {
    pub case_id: &'a str,
    pub source_id: &'a str,
    pub engine_id: &'a str,
    pub profile: ProviderSourceProfile,
    pub permissions: &'a [ReadOnlyCapability],
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct SourceAuthorizationRevocation {
    pub provider: BootstrapProvider,
    pub source_kind: SourceKind,
    pub case_id: String,
    pub source_id: String,
    pub revoked_at: DateTime<Utc>,
    pub completed_checkouts: u8,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct InstalledSourceAuthorization {
    pub schema_version: String,
    pub case_id: String,
    pub source_id: String,
    pub provider: BootstrapProvider,
    pub source_kind: SourceKind,
    pub profile: ProviderSourceProfile,
    pub credential_source: ReadOnlyCredentialSource,
    pub provider_identity: String,
    pub permissions: Vec<ReadOnlyCapability>,
    pub expires_at: DateTime<Utc>,
    pub allowed_engine_ids: BTreeSet<String>,
    pub max_checkouts: u8,
    pub provider_verification: ProviderVerificationState,
    pub safety_notice: String,
}

impl From<&SourceAuthorizationReceipt> for InstalledSourceAuthorization {
    fn from(receipt: &SourceAuthorizationReceipt) -> Self {
        Self {
            schema_version: receipt.schema_version.clone(),
            case_id: receipt.case_id.clone(),
            source_id: receipt.source_id.clone(),
            provider: receipt.provider,
            source_kind: receipt.source_kind.clone(),
            profile: receipt.profile,
            credential_source: receipt.credential_source,
            provider_identity: receipt.provider_identity.clone(),
            permissions: receipt.permissions.clone(),
            expires_at: receipt.expires_at,
            allowed_engine_ids: receipt.allowed_engine_ids.clone(),
            max_checkouts: receipt.max_checkouts,
            provider_verification: receipt.provider_verification.clone(),
            safety_notice: receipt.safety_notice.clone(),
        }
    }
}

struct StoredSourceAuthorization {
    provider: BootstrapProvider,
    source_kind: SourceKind,
    profile: ProviderSourceProfile,
    credential_source: ReadOnlyCredentialSource,
    case_id: String,
    source_id: String,
    permissions: Vec<ReadOnlyCapability>,
    expires_at: DateTime<Utc>,
    allowed_engine_ids: BTreeSet<String>,
    max_checkouts: u8,
    completed_checkouts: u8,
    credentials: BTreeMap<String, Zeroizing<String>>,
}

#[derive(Default)]
pub struct SourceAuthorizationVault {
    entries: Mutex<HashMap<[u8; 32], StoredSourceAuthorization>>,
}

#[derive(Default)]
pub struct SourceAuthorizationBindings {
    vault: SourceAuthorizationVault,
    receipts: Mutex<HashMap<(String, String), InstalledBinding>>,
}

struct InstalledBinding {
    receipt: SourceAuthorizationReceipt,
    completed_checkouts: u8,
}

impl fmt::Debug for SourceAuthorizationBindings {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("SourceAuthorizationBindings")
            .field(
                "binding_count",
                &self.receipts.lock().map(|values| values.len()).ok(),
            )
            .field("vault", &self.vault)
            .finish()
    }
}

impl SourceAuthorizationBindings {
    pub fn install(
        &self,
        request: SourceAuthorizationRequest,
        now: DateTime<Utc>,
    ) -> AppResult<InstalledSourceAuthorization> {
        let receipt = self.vault.issue(request, now)?;
        let status = InstalledSourceAuthorization::from(&receipt);
        let key = (receipt.case_id.clone(), receipt.source_id.clone());
        let previous = self
            .receipts
            .lock()
            .map_err(|_| AppError::Internal("source authorization lock was poisoned".into()))?
            .insert(
                key,
                InstalledBinding {
                    receipt,
                    completed_checkouts: 0,
                },
            );
        if let Some(previous) = previous {
            let _ = self.vault.revoke(&previous.receipt.capability_handle, now);
        }
        Ok(status)
    }

    pub fn install_now(
        &self,
        request: SourceAuthorizationRequest,
    ) -> AppResult<InstalledSourceAuthorization> {
        self.install(request, Utc::now())
    }

    pub fn checkout(
        &self,
        case_id: &str,
        source_id: &str,
        engine_id: &str,
        now: DateTime<Utc>,
    ) -> AppResult<ScannerCredentialSet> {
        let key = (case_id.to_owned(), source_id.to_owned());
        let receipt = self
            .receipts
            .lock()
            .map_err(|_| AppError::Internal("source authorization lock was poisoned".into()))?
            .get(&key)
            .map(|binding| binding.receipt.clone())
            .ok_or_else(|| {
                AppError::NotAuthorized(
                    "connected source has no live backend authorization capability".into(),
                )
            })?;
        let credentials = self.vault.checkout(
            &receipt.capability_handle,
            SourceCredentialCheckout {
                case_id,
                source_id,
                engine_id,
                profile: receipt.profile,
                permissions: &receipt.permissions,
            },
            now,
        )?;
        let mut receipts = self
            .receipts
            .lock()
            .map_err(|_| AppError::Internal("source authorization lock was poisoned".into()))?;
        if let Some(binding) = receipts.get_mut(&key) {
            binding.completed_checkouts = binding.completed_checkouts.saturating_add(1);
            if binding.completed_checkouts >= binding.receipt.max_checkouts {
                receipts.remove(&key);
            }
        }
        Ok(credentials)
    }

    pub fn checkout_now(
        &self,
        case_id: &str,
        source_id: &str,
        engine_id: &str,
    ) -> AppResult<ScannerCredentialSet> {
        self.checkout(case_id, source_id, engine_id, Utc::now())
    }

    pub fn status(
        &self,
        case_id: &str,
        source_id: &str,
        now: DateTime<Utc>,
    ) -> AppResult<Option<InstalledSourceAuthorization>> {
        let mut receipts = self
            .receipts
            .lock()
            .map_err(|_| AppError::Internal("source authorization lock was poisoned".into()))?;
        let key = (case_id.to_owned(), source_id.to_owned());
        if receipts
            .get(&key)
            .is_some_and(|binding| binding.receipt.expires_at <= now)
        {
            receipts.remove(&key);
            return Ok(None);
        }
        Ok(receipts
            .get(&key)
            .map(|binding| InstalledSourceAuthorization::from(&binding.receipt)))
    }

    pub fn revoke_source(
        &self,
        case_id: &str,
        source_id: &str,
        now: DateTime<Utc>,
    ) -> AppResult<SourceAuthorizationRevocation> {
        let binding = self
            .receipts
            .lock()
            .map_err(|_| AppError::Internal("source authorization lock was poisoned".into()))?
            .remove(&(case_id.to_owned(), source_id.to_owned()))
            .ok_or_else(|| {
                AppError::NotAuthorized("source has no live authorization to revoke".into())
            })?;
        self.vault.revoke(&binding.receipt.capability_handle, now)
    }

    /// Revokes and zeroizes every live capability installed for one case.
    pub fn revoke_case(&self, case_id: &str, now: DateTime<Utc>) -> AppResult<usize> {
        let removed = {
            let mut receipts = self
                .receipts
                .lock()
                .map_err(|_| AppError::Internal("source authorization lock was poisoned".into()))?;
            let keys = receipts
                .keys()
                .filter(|(bound_case_id, _)| bound_case_id == case_id)
                .cloned()
                .collect::<Vec<_>>();
            keys.into_iter()
                .filter_map(|key| receipts.remove(&key))
                .collect::<Vec<_>>()
        };
        for binding in &removed {
            self.vault.revoke(&binding.receipt.capability_handle, now)?;
        }
        Ok(removed.len())
    }

    pub fn purge_expired(&self, now: DateTime<Utc>) -> AppResult<usize> {
        let purged = self.vault.purge_expired(now)?;
        self.receipts
            .lock()
            .map_err(|_| AppError::Internal("source authorization lock was poisoned".into()))?
            .retain(|_, binding| binding.receipt.expires_at > now);
        Ok(purged)
    }
}

impl fmt::Debug for SourceAuthorizationVault {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("SourceAuthorizationVault")
            .field(
                "active_capability_count",
                &self.entries.lock().map(|entries| entries.len()).ok(),
            )
            .finish()
    }
}

impl SourceAuthorizationVault {
    pub fn issue(
        &self,
        request: SourceAuthorizationRequest,
        now: DateTime<Utc>,
    ) -> AppResult<SourceAuthorizationReceipt> {
        validate_request(&request, now)?;
        let SourceAuthorizationRequest {
            case_id,
            source_id,
            allowed_engine_ids,
            max_checkouts,
            verified_authorization,
        } = request;
        let VerifiedProviderAuthorization {
            provider,
            source_kind,
            profile,
            credential_source,
            provider_identity,
            expires_at,
            verification,
            secret_material,
        } = verified_authorization;
        let credentials = validate_secret_material(profile, secret_material)?;
        let permissions = profile.permissions();
        let stored = StoredSourceAuthorization {
            provider,
            source_kind: source_kind.clone(),
            profile,
            credential_source,
            case_id: case_id.clone(),
            source_id: source_id.clone(),
            permissions: permissions.clone(),
            expires_at,
            allowed_engine_ids: allowed_engine_ids.clone(),
            max_checkouts,
            completed_checkouts: 0,
            credentials,
        };

        let mut entries = self.entries.lock().map_err(|_| {
            AppError::Internal("source authorization vault lock was poisoned".into())
        })?;
        let mut stored = Some(stored);
        for _ in 0..4 {
            let mut random = Zeroizing::new([0_u8; CAPABILITY_RANDOM_BYTES]);
            getrandom::fill(random.as_mut())
                .map_err(|_| AppError::Internal("operating system random source failed".into()))?;
            let digest = capability_digest(random.as_ref());
            if entries.contains_key(&digest) {
                continue;
            }
            let handle = SourceCapabilityHandle::from_random_bytes(&random);
            entries.insert(
                digest,
                stored
                    .take()
                    .ok_or_else(|| AppError::Internal("authorization state was consumed".into()))?,
            );
            return Ok(SourceAuthorizationReceipt {
                schema_version: "2.0.0".into(),
                case_id,
                source_id,
                provider,
                source_kind,
                profile,
                credential_source,
                provider_identity,
                permissions,
                expires_at,
                capability_handle: handle,
                allowed_engine_ids,
                max_checkouts,
                provider_verification: verification,
                safety_notice: "Provider identity and the pinned read-only permission profile were verified with non-mutating provider APIs. The capability remains case/source/engine-bound and expires within one hour.".into(),
            });
        }
        Err(AppError::Internal(
            "random source capability collision limit reached".into(),
        ))
    }

    pub fn issue_now(
        &self,
        request: SourceAuthorizationRequest,
    ) -> AppResult<SourceAuthorizationReceipt> {
        self.issue(request, Utc::now())
    }

    pub fn checkout(
        &self,
        handle: &SourceCapabilityHandle,
        request: SourceCredentialCheckout<'_>,
        now: DateTime<Utc>,
    ) -> AppResult<ScannerCredentialSet> {
        let digest = capability_digest(handle.decoded()?.as_ref());
        let mut entries = self.entries.lock().map_err(|_| {
            AppError::Internal("source authorization vault lock was poisoned".into())
        })?;
        let (credentials, exhausted) = {
            let stored = entries.get_mut(&digest).ok_or_else(|| {
                AppError::NotAuthorized(
                    "source capability is invalid, revoked, or exhausted".into(),
                )
            })?;
            authorize_checkout(stored, &request, now)?;
            let credentials = scanner_credentials(stored)?;
            stored.completed_checkouts =
                stored.completed_checkouts.checked_add(1).ok_or_else(|| {
                    AppError::Internal("source authorization checkout counter overflowed".into())
                })?;
            (
                credentials,
                stored.completed_checkouts >= stored.max_checkouts,
            )
        };
        if exhausted {
            entries.remove(&digest);
        }
        Ok(credentials)
    }

    pub fn revoke(
        &self,
        handle: &SourceCapabilityHandle,
        revoked_at: DateTime<Utc>,
    ) -> AppResult<SourceAuthorizationRevocation> {
        let digest = capability_digest(handle.decoded()?.as_ref());
        let stored = self
            .entries
            .lock()
            .map_err(|_| AppError::Internal("source authorization vault lock was poisoned".into()))?
            .remove(&digest)
            .ok_or_else(|| {
                AppError::NotAuthorized(
                    "source capability is invalid, revoked, or exhausted".into(),
                )
            })?;
        Ok(SourceAuthorizationRevocation {
            provider: stored.provider,
            source_kind: stored.source_kind,
            case_id: stored.case_id,
            source_id: stored.source_id,
            revoked_at,
            completed_checkouts: stored.completed_checkouts,
        })
    }

    pub fn purge_expired(&self, now: DateTime<Utc>) -> AppResult<usize> {
        let mut entries = self.entries.lock().map_err(|_| {
            AppError::Internal("source authorization vault lock was poisoned".into())
        })?;
        let before = entries.len();
        entries.retain(|_, stored| stored.expires_at > now);
        Ok(before - entries.len())
    }
}

fn validate_request(request: &SourceAuthorizationRequest, now: DateTime<Utc>) -> AppResult<()> {
    validate_identifier(&request.case_id, "case")?;
    validate_identifier(&request.source_id, "source")?;
    let verified = &request.verified_authorization;
    validate_provider_identity(&verified.provider_identity)?;
    if verified.provider != verified.profile.provider()
        || verified.source_kind != verified.profile.source_kind()
        || verified.verification.provider != verified.provider
        || verified.verification.profile != verified.profile
    {
        return Err(AppError::NotAuthorized(
            "provider verification proof and source profile do not match".into(),
        ));
    }
    if verified.expires_at <= now || verified.expires_at > now + MAX_AUTHORIZATION_LIFETIME {
        return Err(AppError::NotAuthorized(
            "source authorization expiry must be within the next hour".into(),
        ));
    }
    if verified.verification.verified_at > now + Duration::minutes(1)
        || verified.verification.verified_at < now - MAX_VERIFICATION_AGE
        || verified.verification.credential_expires_at != verified.expires_at
        || verified.verification.evidence_sha256.len() != 64
        || !verified
            .verification
            .evidence_sha256
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit())
        || verified
            .verification
            .required_permissions_verified
            .is_empty()
        || verified.verification.permission_endpoints.is_empty()
    {
        return Err(AppError::NotAuthorized(
            "provider verification proof is stale, incomplete, or malformed".into(),
        ));
    }
    if !(1..=MAX_CHECKOUTS).contains(&request.max_checkouts) {
        return Err(AppError::InvalidRequest(format!(
            "source capability checkout limit must be between 1 and {MAX_CHECKOUTS}"
        )));
    }
    if request.allowed_engine_ids.is_empty() {
        return Err(AppError::InvalidRequest(
            "source capability must allow at least one engine".into(),
        ));
    }
    let profile_engines = verified.profile.allowed_engine_ids();
    for engine_id in &request.allowed_engine_ids {
        validate_identifier(engine_id, "engine")?;
        if !profile_engines.contains(engine_id.as_str()) {
            return Err(AppError::NotAuthorized(format!(
                "engine {engine_id} is outside the provider read-only source profile"
            )));
        }
    }
    Ok(())
}

fn validate_secret_material(
    profile: ProviderSourceProfile,
    secret_material: ProviderSecretMaterial,
) -> AppResult<BTreeMap<String, Zeroizing<String>>> {
    let required_keys = profile.required_environment_keys();
    let mut credentials = BTreeMap::new();
    for entry in secret_material.entries {
        if !required_keys.contains(entry.key.as_str()) {
            return Err(AppError::NotAuthorized(
                "a credential environment key is outside the provider scanner allowlist".into(),
            ));
        }
        if entry.value.trim().is_empty()
            || entry.value.len() > MAX_SECRET_BYTES
            || entry.value.contains('\0')
        {
            return Err(AppError::InvalidRequest(
                "provider scanner credential is empty, oversized, or contains a NUL byte".into(),
            ));
        }
        if credentials.insert(entry.key, entry.value).is_some() {
            return Err(AppError::InvalidRequest(
                "duplicate provider scanner credential key".into(),
            ));
        }
    }
    let supplied_keys: BTreeSet<&str> = credentials.keys().map(String::as_str).collect();
    if supplied_keys != required_keys {
        return Err(AppError::NotAuthorized(
            "provider scanner credential keys do not exactly match the verified profile".into(),
        ));
    }
    Ok(credentials)
}

fn validate_provider_identity(identity: &str) -> AppResult<()> {
    if identity.trim().is_empty() || identity.len() > 512 || identity.chars().any(char::is_control)
    {
        return Err(AppError::InvalidRequest(
            "provider identity label is missing, too long, or contains control characters".into(),
        ));
    }
    let compact: String = identity
        .to_ascii_lowercase()
        .chars()
        .filter(char::is_ascii_alphanumeric)
        .collect();
    if ["password", "static", "longlived"]
        .iter()
        .any(|marker| compact.contains(marker))
    {
        return Err(AppError::NotAuthorized(
            "password and static long-lived identities are forbidden".into(),
        ));
    }
    Ok(())
}

fn validate_identifier(value: &str, label: &str) -> AppResult<()> {
    if value.is_empty()
        || value.len() > 128
        || !value.chars().all(|character| {
            character.is_ascii_alphanumeric() || matches!(character, '-' | '_' | '.')
        })
    {
        return Err(AppError::InvalidRequest(format!(
            "source authorization {label} identifier is invalid"
        )));
    }
    Ok(())
}

fn authorize_checkout(
    stored: &StoredSourceAuthorization,
    request: &SourceCredentialCheckout<'_>,
    now: DateTime<Utc>,
) -> AppResult<()> {
    if now >= stored.expires_at {
        return Err(AppError::NotAuthorized(
            "source capability is expired".into(),
        ));
    }
    if request.case_id != stored.case_id || request.source_id != stored.source_id {
        return Err(AppError::NotAuthorized(
            "source capability is bound to a different case or source".into(),
        ));
    }
    if request.profile != stored.profile
        || canonical_permissions(request.permissions) != stored.permissions
    {
        return Err(AppError::NotAuthorized(
            "source capability has a different read-only permission profile".into(),
        ));
    }
    if !stored.allowed_engine_ids.contains(request.engine_id) {
        return Err(AppError::NotAuthorized(
            "engine is outside the source capability".into(),
        ));
    }
    if stored.completed_checkouts >= stored.max_checkouts {
        return Err(AppError::NotAuthorized(
            "source capability checkout limit is exhausted".into(),
        ));
    }
    Ok(())
}

fn scanner_credentials(stored: &StoredSourceAuthorization) -> AppResult<ScannerCredentialSet> {
    let source = match stored.credential_source {
        ReadOnlyCredentialSource::ProviderNative => CredentialSource::ExternalReadOnlyGrant,
        ReadOnlyCredentialSource::VerifiedBootstrap => CredentialSource::EphemeralScanRole,
    };
    ScannerCredentialSet::new(
        stored
            .credentials
            .iter()
            .map(|(key, value)| {
                ScannerCredential::from_vault(key.clone(), value.clone(), stored.expires_at, source)
            })
            .collect::<AppResult<Vec<_>>>()?,
    )
}

fn canonical_permissions(permissions: &[ReadOnlyCapability]) -> Vec<ReadOnlyCapability> {
    let mut seen = [false; 5];
    for permission in permissions {
        seen[permission_rank(*permission)] = true;
    }
    [
        ReadOnlyCapability::Inventory,
        ReadOnlyCapability::Configuration,
        ReadOnlyCapability::IdentityAndAccess,
        ReadOnlyCapability::SecurityPosture,
        ReadOnlyCapability::AuditMetadata,
    ]
    .into_iter()
    .filter(|permission| seen[permission_rank(*permission)])
    .collect()
}

fn permission_rank(permission: ReadOnlyCapability) -> usize {
    match permission {
        ReadOnlyCapability::Inventory => 0,
        ReadOnlyCapability::Configuration => 1,
        ReadOnlyCapability::IdentityAndAccess => 2,
        ReadOnlyCapability::SecurityPosture => 3,
        ReadOnlyCapability::AuditMetadata => 4,
    }
}

fn capability_digest(random: &[u8]) -> [u8; 32] {
    Sha256::digest(random).into()
}

const BROKER_FRAME_MAGIC: &[u8; 12] = b"ASSBROKER2\0\0";
const MAX_BROKER_FRAME_BYTES: usize = 256 * 1024;

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct BrokerFrameMetadata {
    provider: BootstrapProvider,
    source_kind: SourceKind,
    profile: ProviderSourceProfile,
    credential_source: ReadOnlyCredentialSource,
    provider_identity: String,
    expires_at: DateTime<Utc>,
    verification: ProviderVerificationState,
}

/// Consumes a broker-verified scanner authorization and writes it to an
/// already-established anonymous pipe. Secret values use a bounded binary
/// frame rather than serde. Callers must never target a regular file, terminal,
/// socket path, or frontend stream.
pub fn write_verified_authorization_one_shot(
    mut writer: impl Write,
    authorization: VerifiedProviderAuthorization,
) -> AppResult<()> {
    if authorization.credential_source != ReadOnlyCredentialSource::VerifiedBootstrap {
        return Err(AppError::NotAuthorized(
            "the broker one-shot channel accepts only verified bootstrap credentials".into(),
        ));
    }
    let VerifiedProviderAuthorization {
        provider,
        source_kind,
        profile,
        credential_source,
        provider_identity,
        expires_at,
        verification,
        secret_material,
    } = authorization;
    let metadata = serde_json::to_vec(&BrokerFrameMetadata {
        provider,
        source_kind,
        profile,
        credential_source,
        provider_identity,
        expires_at,
        verification,
    })
    .map_err(|_| AppError::Internal("broker metadata could not be encoded".into()))?;
    if metadata.len() > 64 * 1024 || secret_material.entries.len() > 8 {
        return Err(AppError::InvalidRequest(
            "broker one-shot frame exceeds the fixed boundary".into(),
        ));
    }
    writer.write_all(BROKER_FRAME_MAGIC)?;
    write_u32(&mut writer, metadata.len())?;
    writer.write_all(&metadata)?;
    write_u32(&mut writer, secret_material.entries.len())?;
    let mut written = BROKER_FRAME_MAGIC.len() + 8 + metadata.len();
    for entry in secret_material.entries {
        if entry.key.len() > 256 || entry.value.len() > MAX_SECRET_BYTES {
            return Err(AppError::InvalidRequest(
                "broker scanner credential exceeds the fixed boundary".into(),
            ));
        }
        written = written
            .checked_add(8 + entry.key.len() + entry.value.len())
            .ok_or_else(|| AppError::InvalidRequest("broker frame size overflowed".into()))?;
        if written > MAX_BROKER_FRAME_BYTES {
            return Err(AppError::InvalidRequest(
                "broker one-shot frame exceeds the fixed boundary".into(),
            ));
        }
        write_u32(&mut writer, entry.key.len())?;
        writer.write_all(entry.key.as_bytes())?;
        write_u32(&mut writer, entry.value.len())?;
        writer.write_all(entry.value.as_bytes())?;
    }
    writer.flush()?;
    Ok(())
}

/// Reads exactly one broker frame from an anonymous pipe. The returned object
/// remains non-serializable and must be installed directly into the process
/// memory vault.
pub fn read_verified_authorization_one_shot(
    mut reader: impl Read,
) -> AppResult<VerifiedProviderAuthorization> {
    let mut magic = [0_u8; BROKER_FRAME_MAGIC.len()];
    reader.read_exact(&mut magic)?;
    if &magic != BROKER_FRAME_MAGIC {
        return Err(AppError::NotAuthorized(
            "broker one-shot frame magic is invalid".into(),
        ));
    }
    let metadata_len = read_u32(&mut reader)?;
    if metadata_len == 0 || metadata_len > 64 * 1024 {
        return Err(AppError::InvalidRequest(
            "broker metadata frame length is invalid".into(),
        ));
    }
    let mut metadata_bytes = vec![0_u8; metadata_len];
    reader.read_exact(&mut metadata_bytes)?;
    let metadata: BrokerFrameMetadata = serde_json::from_slice(&metadata_bytes)
        .map_err(|_| AppError::NotAuthorized("broker metadata frame is malformed".into()))?;
    if metadata.credential_source != ReadOnlyCredentialSource::VerifiedBootstrap {
        return Err(AppError::NotAuthorized(
            "broker frame did not contain a bootstrap credential".into(),
        ));
    }
    let entry_count = read_u32(&mut reader)?;
    if entry_count == 0 || entry_count > 8 {
        return Err(AppError::InvalidRequest(
            "broker credential count is invalid".into(),
        ));
    }
    let mut entries = Vec::with_capacity(entry_count);
    let mut read = BROKER_FRAME_MAGIC.len() + 8 + metadata_len;
    for _ in 0..entry_count {
        let key_len = read_u32(&mut reader)?;
        if key_len == 0 || key_len > 256 {
            return Err(AppError::InvalidRequest(
                "broker credential key length is invalid".into(),
            ));
        }
        let mut key_bytes = vec![0_u8; key_len];
        reader.read_exact(&mut key_bytes)?;
        let key = String::from_utf8(key_bytes)
            .map_err(|_| AppError::InvalidRequest("broker credential key is invalid".into()))?;
        let value_len = read_u32(&mut reader)?;
        if value_len == 0 || value_len > MAX_SECRET_BYTES {
            return Err(AppError::InvalidRequest(
                "broker credential value length is invalid".into(),
            ));
        }
        read = read
            .checked_add(8 + key_len + value_len)
            .ok_or_else(|| AppError::InvalidRequest("broker frame size overflowed".into()))?;
        if read > MAX_BROKER_FRAME_BYTES {
            return Err(AppError::InvalidRequest(
                "broker one-shot frame exceeds the fixed boundary".into(),
            ));
        }
        let mut value_bytes = Zeroizing::new(vec![0_u8; value_len]);
        reader.read_exact(&mut value_bytes)?;
        let value = String::from_utf8(std::mem::take(&mut *value_bytes))
            .map(Zeroizing::new)
            .map_err(|_| AppError::InvalidRequest("broker credential value is invalid".into()))?;
        entries.push(SecretEnvironmentValue::new(key, value));
    }
    let mut trailing = [0_u8; 1];
    if reader.read(&mut trailing)? != 0 {
        return Err(AppError::InvalidRequest(
            "broker one-shot pipe contained trailing data".into(),
        ));
    }
    if metadata.provider != metadata.profile.provider()
        || metadata.source_kind != metadata.profile.source_kind()
    {
        return Err(AppError::NotAuthorized(
            "broker metadata profile does not match the provider".into(),
        ));
    }
    VerifiedProviderAuthorization::new_verified(
        metadata.profile,
        metadata.credential_source,
        metadata.provider_identity,
        metadata.expires_at,
        metadata.verification,
        ProviderSecretMaterial::new(entries),
    )
}

fn write_u32(writer: &mut impl Write, value: usize) -> AppResult<()> {
    let value = u32::try_from(value)
        .map_err(|_| AppError::InvalidRequest("broker frame integer overflowed".into()))?;
    writer.write_all(&value.to_be_bytes())?;
    Ok(())
}

fn read_u32(reader: &mut impl Read) -> AppResult<usize> {
    let mut bytes = [0_u8; 4];
    reader.read_exact(&mut bytes)?;
    Ok(u32::from_be_bytes(bytes) as usize)
}
