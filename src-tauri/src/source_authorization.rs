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
use crate::domain::{Asset, AssetKind, SourceKind};
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
const RESERVATION_PREFIX: &str = "assres_v1_";
const RESERVATION_RANDOM_BYTES: usize = 16;
const MAX_AUTHORIZATION_LIFETIME: Duration = Duration::hours(1);
const MAX_VERIFICATION_AGE: Duration = Duration::minutes(10);
const MAX_SECRET_BYTES: usize = 128 * 1024;
pub const PROVIDER_DISCOVERY_ENGINE_ID: &str = "provider-native-discovery";
/// One live capture can preserve at most this many provider records. GCP can
/// turn every record into one exact-project Prowler execution, so its
/// capability ceiling reserves one additional checkout for discovery itself.
pub const PROVIDER_DISCOVERY_RECORD_LIMIT: usize = 1_000;
pub const DEFAULT_PROVIDER_CHECKOUT_LIMIT: u16 = 8;
pub const GCP_PROVIDER_CHECKOUT_LIMIT: u16 = PROVIDER_DISCOVERY_RECORD_LIMIT as u16 + 1;
pub const PROVIDER_CHECKOUT_HARD_LIMIT: u16 = GCP_PROVIDER_CHECKOUT_LIMIT;
/// Persisted, non-secret provider resource coordinate used to fail closed
/// before a provider-bound engine is planned or receives credentials.
pub const PROVIDER_RESOURCE_SCOPE_METADATA_KEY: &str = "provider_resource_scope";

/// Requires a one-account AWS execution whose immutable account coordinate is
/// exactly the account proven by the installed provider capability.
pub fn validate_aws_execution_target(assets: &[Asset], resource_scope: &str) -> AppResult<()> {
    let [asset] = assets else {
        return Err(AppError::NotAuthorized(
            "AWS engine execution must contain exactly one account asset".into(),
        ));
    };
    if asset.kind != AssetKind::CloudAccount || asset.provider.as_deref() != Some("aws") {
        return Err(AppError::NotAuthorized(
            "AWS engine execution target is not an exact AWS account".into(),
        ));
    }
    let mut account_ids = asset
        .identifiers
        .iter()
        .filter(|identifier| identifier.namespace == "aws_account_id")
        .map(|identifier| identifier.value.as_str());
    let account_id = account_ids.next().ok_or_else(|| {
        AppError::NotAuthorized(
            "AWS account target has no exact provider account identifier".into(),
        )
    })?;
    if account_ids.next().is_some()
        || account_id.len() != 12
        || !account_id.bytes().all(|byte| byte.is_ascii_digit())
    {
        return Err(AppError::NotAuthorized(
            "AWS account target has an ambiguous or malformed provider account identifier".into(),
        ));
    }
    if resource_scope != format!("aws-account:{account_id}") {
        return Err(AppError::NotAuthorized(
            "AWS credential proof is bound to a different account than the execution target".into(),
        ));
    }
    Ok(())
}

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
            Self::AzureTenantReadOnlyAccessToken | Self::GcpOrganizationReadOnlyAccessToken => {
                [PROVIDER_DISCOVERY_ENGINE_ID, "prowler"]
                    .into_iter()
                    .collect()
            }
            Self::Microsoft365TenantReadOnlyAccessToken => {
                ["maester", PROVIDER_DISCOVERY_ENGINE_ID, "scubagear"]
                    .into_iter()
                    .collect()
            }
        }
    }

    /// Checkout copies remain short-lived and case/source/engine-bound. The
    /// higher GCP ceiling is only large enough for one bounded discovery plus
    /// one exact-project execution per maximum discovery record.
    pub const fn max_checkouts(self) -> u16 {
        match self {
            Self::GcpOrganizationReadOnlyAccessToken => GCP_PROVIDER_CHECKOUT_LIMIT,
            _ => DEFAULT_PROVIDER_CHECKOUT_LIMIT,
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
    pub max_checkouts: u16,
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

/// Private identity for one installed capability generation. This is the
/// digest already used as the in-memory vault key; it never crosses a public
/// API or serialization boundary.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
struct SourceCapabilityGeneration([u8; 32]);

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
    pub max_checkouts: u16,
    pub provider_verification: ProviderVerificationState,
    pub safety_notice: String,
    capability_generation: SourceCapabilityGeneration,
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

/// Backend-only, non-secret identity snapshot for one exact installed source
/// capability generation. The public authorization metadata may be inspected
/// by backend policy code; the generation remains private so a caller cannot
/// forge or weaken the binding. This type intentionally implements no serde
/// traits.
///
/// ```compile_fail
/// use ai_security_scanner_lib::source_authorization::SourceAuthorizationBindingSnapshot;
/// fn requires_serialize<T: serde::Serialize>() {}
/// requires_serialize::<SourceAuthorizationBindingSnapshot>();
/// ```
#[derive(Clone)]
pub struct SourceAuthorizationBindingSnapshot {
    authorization: InstalledSourceAuthorization,
    capability_generation: SourceCapabilityGeneration,
}

impl SourceAuthorizationBindingSnapshot {
    pub fn authorization(&self) -> &InstalledSourceAuthorization {
        &self.authorization
    }
}

impl fmt::Debug for SourceAuthorizationBindingSnapshot {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("SourceAuthorizationBindingSnapshot([REDACTED])")
    }
}

/// Typed, backend-only failure classification for generation-bound provider
/// preflight. It contains no provider, target, identity, or secret text.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SourceCheckoutPreflightFailure {
    CapabilityUnavailable,
    BindingMismatch,
    Internal,
}

/// One prospective provider credential checkout. It contains only exact,
/// non-secret binding coordinates; capability handles and credentials remain
/// private to [`SourceAuthorizationBindings`]. Repeated entries intentionally
/// represent repeated execution groups and each consume one future checkout.
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct SourceCheckoutDemand<'a> {
    pub case_id: &'a str,
    pub source_id: &'a str,
    pub engine_id: &'a str,
}

/// One checkout demand bound to the exact source authorization generation
/// that passed provider identity, proof, and target validation. Repeated
/// entries intentionally reserve repeated execution groups.
pub struct BoundSourceCheckoutDemand<'a> {
    pub case_id: &'a str,
    pub source_id: &'a str,
    pub engine_id: &'a str,
    pub binding: &'a SourceAuthorizationBindingSnapshot,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct SourceAuthorizationRevocation {
    pub provider: BootstrapProvider,
    pub source_kind: SourceKind,
    pub case_id: String,
    pub source_id: String,
    pub revoked_at: DateTime<Utc>,
    pub completed_checkouts: u16,
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
    pub max_checkouts: u16,
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
    max_checkouts: u16,
    completed_checkouts: u16,
    reserved_checkouts: u16,
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
    reservations: Mutex<HashMap<String, StoredCheckoutReservation>>,
}

struct InstalledBinding {
    receipt: SourceAuthorizationReceipt,
    completed_checkouts: u16,
}

/// Opaque process-memory identity for one checkout reservation. The random
/// value is not a credential, but remains redacted so logs cannot become a
/// control channel for reservation lifecycle operations. It intentionally
/// implements no serde traits.
#[derive(Clone, PartialEq, Eq, Hash)]
pub struct SourceCheckoutReservationHandle(String);

impl fmt::Debug for SourceCheckoutReservationHandle {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("SourceCheckoutReservationHandle([REDACTED])")
    }
}

#[derive(Clone)]
struct StoredCheckoutReservation {
    reserved_at: DateTime<Utc>,
    allocations: Vec<StoredCheckoutReservationAllocation>,
}

#[derive(Clone)]
struct StoredCheckoutReservationAllocation {
    case_id: String,
    source_id: String,
    capability_generation: SourceCapabilityGeneration,
    count: u16,
}

struct ReservedScannerCredential {
    case_id: String,
    source_id: String,
    engine_id: String,
    credentials: Option<ScannerCredentialSet>,
}

/// Owned, backend-only credentials for an atomically reserved demand batch.
/// Entries retain the original demand order, including exact duplicates.
/// Each exact case/source/engine entry can be taken once; unclaimed entries
/// are dropped with their [`Zeroizing`] secret values. This type deliberately
/// implements neither `Debug` nor serde traits.
///
/// ```compile_fail
/// use ai_security_scanner_lib::source_authorization::ReservedScannerCredentialBundle;
/// fn requires_debug<T: std::fmt::Debug>() {}
/// requires_debug::<ReservedScannerCredentialBundle>();
/// ```
///
/// ```compile_fail
/// use ai_security_scanner_lib::source_authorization::ReservedScannerCredentialBundle;
/// fn requires_serialize<T: serde::Serialize>() {}
/// requires_serialize::<ReservedScannerCredentialBundle>();
/// ```
pub struct ReservedScannerCredentialBundle {
    credentials: Vec<ReservedScannerCredential>,
}

impl ReservedScannerCredentialBundle {
    /// Takes the first still-owned credential set matching the exact binding
    /// coordinates. Repeated identical demands can therefore be retrieved in
    /// order, once each, without weakening the case/source/engine binding.
    pub fn take(
        &mut self,
        case_id: &str,
        source_id: &str,
        engine_id: &str,
    ) -> AppResult<ScannerCredentialSet> {
        validate_identifier(case_id, "case")?;
        validate_identifier(source_id, "source")?;
        validate_identifier(engine_id, "engine")?;
        self.credentials
            .iter_mut()
            .find(|entry| {
                entry.case_id == case_id
                    && entry.source_id == source_id
                    && entry.engine_id == engine_id
                    && entry.credentials.is_some()
            })
            .and_then(|entry| entry.credentials.take())
            .ok_or_else(|| {
                AppError::NotAuthorized(
                    "reservation has no unclaimed credential set for the exact case, source, and engine"
                        .into(),
                )
            })
    }

    pub fn remaining(&self) -> usize {
        self.credentials
            .iter()
            .filter(|entry| entry.credentials.is_some())
            .count()
    }
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
        let new_generation = receipt.capability_generation;
        let mut receipts = self
            .receipts
            .lock()
            .map_err(|_| AppError::Internal("source authorization lock was poisoned".into()))?;
        let mut entries = self.vault.entries.lock().map_err(|_| {
            AppError::Internal("source authorization vault lock was poisoned".into())
        })?;
        if let Some(previous) = receipts.get(&key) {
            let previous_generation = previous.receipt.capability_generation;
            if let Some(previous_stored) = entries.get(&previous_generation.0) {
                if let Err(error) = validate_installed_binding(previous_stored, previous) {
                    entries.remove(&new_generation.0);
                    return Err(error);
                }
                if previous_stored.reserved_checkouts > 0 {
                    entries.remove(&new_generation.0);
                    return Err(AppError::NotAuthorized(
                        "source authorization cannot be replaced while a checkout reservation is active"
                            .into(),
                    ));
                }
                entries.remove(&previous_generation.0);
            } else if previous.completed_checkouts < previous.receipt.max_checkouts {
                entries.remove(&new_generation.0);
                return Err(AppError::NotAuthorized(
                    "installed source authorization generation is no longer available".into(),
                ));
            }
        }
        receipts.insert(
            key,
            InstalledBinding {
                receipt,
                completed_checkouts: 0,
            },
        );
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
        validate_identifier(case_id, "case")?;
        validate_identifier(source_id, "source")?;
        validate_identifier(engine_id, "engine")?;
        let key = (case_id.to_owned(), source_id.to_owned());
        let mut receipts = self
            .receipts
            .lock()
            .map_err(|_| AppError::Internal("source authorization lock was poisoned".into()))?;
        let mut entries = self.vault.entries.lock().map_err(|_| {
            AppError::Internal("source authorization vault lock was poisoned".into())
        })?;
        let (credentials, generation, exhausted) = {
            let binding = receipts.get_mut(&key).ok_or_else(|| {
                AppError::NotAuthorized(
                    "connected source has no live backend authorization capability".into(),
                )
            })?;
            let generation = binding.receipt.capability_generation;
            let stored = entries.get_mut(&generation.0).ok_or_else(|| {
                AppError::NotAuthorized(
                    "source capability is invalid, revoked, or exhausted".into(),
                )
            })?;
            validate_installed_binding(stored, binding)?;
            authorize_checkout(
                stored,
                &SourceCredentialCheckout {
                    case_id,
                    source_id,
                    engine_id,
                    profile: binding.receipt.profile,
                    permissions: &binding.receipt.permissions,
                },
                now,
            )?;
            let credentials = scanner_credentials(stored)?;
            stored.completed_checkouts =
                stored.completed_checkouts.checked_add(1).ok_or_else(|| {
                    AppError::Internal("source authorization checkout counter overflowed".into())
                })?;
            binding.completed_checkouts =
                binding.completed_checkouts.checked_add(1).ok_or_else(|| {
                    AppError::Internal("source authorization checkout counter overflowed".into())
                })?;
            (
                credentials,
                generation,
                stored.completed_checkouts >= stored.max_checkouts
                    && stored.reserved_checkouts == 0,
            )
        };
        if exhausted {
            entries.remove(&generation.0);
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

    /// Captures the exact installed authorization generation after verifying
    /// that it is live and has at least one unreserved checkout. A missing
    /// case/source binding is represented by `Ok(None)`; a stale vault entry,
    /// expiry, or exhausted capacity is `CapabilityUnavailable`.
    pub fn binding_snapshot(
        &self,
        case_id: &str,
        source_id: &str,
        now: DateTime<Utc>,
    ) -> Result<Option<SourceAuthorizationBindingSnapshot>, SourceCheckoutPreflightFailure> {
        validate_trusted_identifier(case_id, "case")?;
        validate_trusted_identifier(source_id, "source")?;
        let receipts = self
            .receipts
            .lock()
            .map_err(|_| SourceCheckoutPreflightFailure::Internal)?;
        let entries = self
            .vault
            .entries
            .lock()
            .map_err(|_| SourceCheckoutPreflightFailure::Internal)?;
        let reservations = self
            .reservations
            .lock()
            .map_err(|_| SourceCheckoutPreflightFailure::Internal)?;
        let Some(binding) = receipts.get(&(case_id.to_owned(), source_id.to_owned())) else {
            return Ok(None);
        };
        if binding.receipt.case_id != case_id || binding.receipt.source_id != source_id {
            return Err(SourceCheckoutPreflightFailure::BindingMismatch);
        }
        let generation = binding.receipt.capability_generation;
        let stored = entries
            .get(&generation.0)
            .ok_or(SourceCheckoutPreflightFailure::CapabilityUnavailable)?;
        validate_bound_installed_binding(stored, binding)?;
        validate_stored_reservation_invariant(stored, generation, &reservations)?;
        if now >= stored.expires_at {
            return Err(SourceCheckoutPreflightFailure::CapabilityUnavailable);
        }
        let unavailable = stored
            .completed_checkouts
            .checked_add(stored.reserved_checkouts)
            .ok_or(SourceCheckoutPreflightFailure::Internal)?;
        if unavailable >= stored.max_checkouts {
            return Err(SourceCheckoutPreflightFailure::CapabilityUnavailable);
        }
        Ok(Some(SourceAuthorizationBindingSnapshot {
            authorization: InstalledSourceAuthorization::from(&binding.receipt),
            capability_generation: generation,
        }))
    }

    /// Atomically validates a duplicate-preserving demand batch against the
    /// exact generations captured before planning. The receipts, vault, and
    /// reservation registries remain locked in that order for the complete
    /// validation snapshot.
    pub fn validate_bound_checkout_demands(
        &self,
        demands: &[BoundSourceCheckoutDemand<'_>],
        now: DateTime<Utc>,
    ) -> Result<(), SourceCheckoutPreflightFailure> {
        validate_bound_demand_identifiers(demands)?;
        let receipts = self
            .receipts
            .lock()
            .map_err(|_| SourceCheckoutPreflightFailure::Internal)?;
        let entries = self
            .vault
            .entries
            .lock()
            .map_err(|_| SourceCheckoutPreflightFailure::Internal)?;
        let reservations = self
            .reservations
            .lock()
            .map_err(|_| SourceCheckoutPreflightFailure::Internal)?;
        validate_bound_checkout_demands_locked(demands, now, &receipts, &entries, &reservations)?;
        Ok(())
    }

    /// Atomically validates and reserves an exact generation-bound demand
    /// batch. A concurrent reinstall changes the generation and returns
    /// `BindingMismatch`; credentials from that replacement are never
    /// materialized or reserved by this call.
    pub fn reserve_bound_checkout_demands(
        &self,
        demands: &[BoundSourceCheckoutDemand<'_>],
        now: DateTime<Utc>,
    ) -> Result<
        (
            SourceCheckoutReservationHandle,
            ReservedScannerCredentialBundle,
        ),
        SourceCheckoutPreflightFailure,
    > {
        validate_bound_demand_identifiers(demands)?;
        if demands.is_empty() {
            return Err(SourceCheckoutPreflightFailure::Internal);
        }
        let receipts = self
            .receipts
            .lock()
            .map_err(|_| SourceCheckoutPreflightFailure::Internal)?;
        let mut entries = self
            .vault
            .entries
            .lock()
            .map_err(|_| SourceCheckoutPreflightFailure::Internal)?;
        let mut reservations = self
            .reservations
            .lock()
            .map_err(|_| SourceCheckoutPreflightFailure::Internal)?;
        let allocations = validate_bound_checkout_demands_locked(
            demands,
            now,
            &receipts,
            &entries,
            &reservations,
        )?;

        let mut credential_entries = Vec::with_capacity(demands.len());
        for demand in demands {
            let stored = entries
                .get(&demand.binding.capability_generation.0)
                .ok_or(SourceCheckoutPreflightFailure::CapabilityUnavailable)?;
            let credentials = scanner_credentials(stored).map_err(|error| match error {
                AppError::NotAuthorized(_) => SourceCheckoutPreflightFailure::CapabilityUnavailable,
                _ => SourceCheckoutPreflightFailure::Internal,
            })?;
            credential_entries.push(ReservedScannerCredential {
                case_id: demand.case_id.to_owned(),
                source_id: demand.source_id.to_owned(),
                engine_id: demand.engine_id.to_owned(),
                credentials: Some(credentials),
            });
        }
        let handle = new_checkout_reservation_handle(&reservations)
            .map_err(|_| SourceCheckoutPreflightFailure::Internal)?;
        for allocation in &allocations {
            let stored = entries
                .get_mut(&allocation.capability_generation.0)
                .ok_or(SourceCheckoutPreflightFailure::Internal)?;
            stored.reserved_checkouts = stored
                .reserved_checkouts
                .checked_add(allocation.count)
                .ok_or(SourceCheckoutPreflightFailure::Internal)?;
        }
        reservations.insert(
            handle.0.clone(),
            StoredCheckoutReservation {
                reserved_at: now,
                allocations,
            },
        );
        Ok((
            handle,
            ReservedScannerCredentialBundle {
                credentials: credential_entries,
            },
        ))
    }

    /// Atomically reserves checkout capacity and materializes one owned,
    /// backend-only credential set for every demand. The returned bundle keeps
    /// exact demand order and duplicates. Ordinary checkout (including
    /// provider discovery) cannot consume capacity held by this reservation.
    ///
    /// Dispatch callers must use this exact activation-safe sequence:
    ///
    /// 1. reserve, keeping the handle outside the worker;
    /// 2. persist the run/job record; on failure, release and drop the bundle;
    /// 3. spawn a worker blocked on a one-shot activation channel, while the
    ///    dispatcher still owns the bundle; on spawn failure, release and drop
    ///    the bundle;
    /// 4. commit immediately before sending the bundle through that channel;
    /// 5. send the bundle and activate only after commit succeeds. A commit
    ///    validation failure atomically releases the reservation; close the
    ///    channel and drop the bundle so the inactive worker exits. If the send
    ///    itself fails after commit, capacity remains consumed and the returned
    ///    bundle is dropped while the job records a dispatch failure.
    pub fn reserve_checkout_demands(
        &self,
        demands: &[SourceCheckoutDemand<'_>],
        now: DateTime<Utc>,
    ) -> AppResult<(
        SourceCheckoutReservationHandle,
        ReservedScannerCredentialBundle,
    )> {
        if demands.is_empty() {
            return Err(AppError::InvalidRequest(
                "provider checkout reservation requires at least one demand".into(),
            ));
        }
        let mut grouped = BTreeMap::<(&str, &str), Vec<&str>>::new();
        for demand in demands {
            validate_identifier(demand.case_id, "case")?;
            validate_identifier(demand.source_id, "source")?;
            validate_identifier(demand.engine_id, "engine")?;
            grouped
                .entry((demand.case_id, demand.source_id))
                .or_default()
                .push(demand.engine_id);
        }

        let receipts = self
            .receipts
            .lock()
            .map_err(|_| AppError::Internal("source authorization lock was poisoned".into()))?;
        let mut entries = self.vault.entries.lock().map_err(|_| {
            AppError::Internal("source authorization vault lock was poisoned".into())
        })?;
        let mut reservations = self.reservations.lock().map_err(|_| {
            AppError::Internal("source checkout reservation lock was poisoned".into())
        })?;

        let mut allocations = Vec::with_capacity(grouped.len());
        for ((case_id, source_id), engine_ids) in &grouped {
            let key = ((*case_id).to_owned(), (*source_id).to_owned());
            let binding = receipts.get(&key).ok_or_else(|| {
                AppError::NotAuthorized(
                    "connected source has no live backend authorization capability".into(),
                )
            })?;
            let generation = binding.receipt.capability_generation;
            let stored = entries.get(&generation.0).ok_or_else(|| {
                AppError::NotAuthorized(
                    "source capability is invalid, revoked, or exhausted".into(),
                )
            })?;
            validate_installed_binding(stored, binding)?;
            for engine_id in engine_ids {
                authorize_checkout(
                    stored,
                    &SourceCredentialCheckout {
                        case_id,
                        source_id,
                        engine_id,
                        profile: binding.receipt.profile,
                        permissions: &binding.receipt.permissions,
                    },
                    now,
                )?;
            }
            let count = u16::try_from(engine_ids.len()).map_err(|_| {
                AppError::InvalidRequest(
                    "provider checkout reservation demand count is too large".into(),
                )
            })?;
            let unavailable = stored
                .completed_checkouts
                .checked_add(stored.reserved_checkouts)
                .ok_or_else(|| {
                    AppError::Internal("source authorization checkout counter overflowed".into())
                })?;
            let remaining = stored.max_checkouts.saturating_sub(unavailable);
            if count > remaining {
                return Err(AppError::NotAuthorized(format!(
                    "source capability has {remaining} unreserved checkout(s) remaining but this scan requires {count}"
                )));
            }
            allocations.push(StoredCheckoutReservationAllocation {
                case_id: (*case_id).to_owned(),
                source_id: (*source_id).to_owned(),
                capability_generation: generation,
                count,
            });
        }

        let mut credential_entries = Vec::with_capacity(demands.len());
        for demand in demands {
            let binding = receipts
                .get(&(demand.case_id.to_owned(), demand.source_id.to_owned()))
                .ok_or_else(|| {
                    AppError::NotAuthorized(
                        "connected source has no live backend authorization capability".into(),
                    )
                })?;
            let stored = entries
                .get(&binding.receipt.capability_generation.0)
                .ok_or_else(|| {
                    AppError::NotAuthorized(
                        "source capability is invalid, revoked, or exhausted".into(),
                    )
                })?;
            credential_entries.push(ReservedScannerCredential {
                case_id: demand.case_id.to_owned(),
                source_id: demand.source_id.to_owned(),
                engine_id: demand.engine_id.to_owned(),
                credentials: Some(scanner_credentials(stored)?),
            });
        }

        let handle = new_checkout_reservation_handle(&reservations)?;
        for allocation in &allocations {
            let stored = entries
                .get_mut(&allocation.capability_generation.0)
                .ok_or_else(|| {
                    AppError::Internal(
                        "validated source capability disappeared during reservation".into(),
                    )
                })?;
            stored.reserved_checkouts = stored
                .reserved_checkouts
                .checked_add(allocation.count)
                .ok_or_else(|| {
                    AppError::Internal("source authorization reservation counter overflowed".into())
                })?;
        }
        reservations.insert(
            handle.0.clone(),
            StoredCheckoutReservation {
                reserved_at: now,
                allocations,
            },
        );
        Ok((
            handle,
            ReservedScannerCredentialBundle {
                credentials: credential_entries,
            },
        ))
    }

    pub fn reserve_checkout_demands_now(
        &self,
        demands: &[SourceCheckoutDemand<'_>],
    ) -> AppResult<(
        SourceCheckoutReservationHandle,
        ReservedScannerCredentialBundle,
    )> {
        self.reserve_checkout_demands(demands, Utc::now())
    }

    /// Releases capacity without consuming a checkout. Use this after run
    /// persistence or inactive-worker spawn fails.
    pub fn release_checkout_reservation(
        &self,
        handle: &SourceCheckoutReservationHandle,
    ) -> AppResult<()> {
        let _receipts = self
            .receipts
            .lock()
            .map_err(|_| AppError::Internal("source authorization lock was poisoned".into()))?;
        let mut entries = self.vault.entries.lock().map_err(|_| {
            AppError::Internal("source authorization vault lock was poisoned".into())
        })?;
        let mut reservations = self.reservations.lock().map_err(|_| {
            AppError::Internal("source checkout reservation lock was poisoned".into())
        })?;
        if !reservations.contains_key(&handle.0) {
            return Err(AppError::NotAuthorized(
                "source checkout reservation is invalid or finalized".into(),
            ));
        }
        let reservation = reservations
            .remove(&handle.0)
            .expect("reservation remained present while its lock was held");
        release_reservation_allocations(&mut entries, &reservation.allocations);
        Ok(())
    }

    /// Commits a successfully dispatched inactive worker's capacity. This is
    /// all-or-nothing: exact installed generations and expiry are rechecked
    /// before any checkout is consumed. A validation failure atomically
    /// releases all still-live allocations for this reservation.
    pub fn commit_checkout_reservation(
        &self,
        handle: &SourceCheckoutReservationHandle,
        now: DateTime<Utc>,
    ) -> AppResult<()> {
        let mut receipts = self
            .receipts
            .lock()
            .map_err(|_| AppError::Internal("source authorization lock was poisoned".into()))?;
        let mut entries = self.vault.entries.lock().map_err(|_| {
            AppError::Internal("source authorization vault lock was poisoned".into())
        })?;
        let mut reservations = self.reservations.lock().map_err(|_| {
            AppError::Internal("source checkout reservation lock was poisoned".into())
        })?;
        let reservation = reservations.get(&handle.0).cloned().ok_or_else(|| {
            AppError::NotAuthorized("source checkout reservation is invalid or finalized".into())
        })?;

        let validation = (|| {
            if now < reservation.reserved_at {
                return Err(AppError::NotAuthorized(
                    "source checkout reservation cannot be committed before it was created".into(),
                ));
            }
            for allocation in &reservation.allocations {
                let key = (allocation.case_id.clone(), allocation.source_id.clone());
                let binding = receipts.get(&key).ok_or_else(|| {
                    AppError::NotAuthorized(
                        "source authorization changed before checkout dispatch".into(),
                    )
                })?;
                if binding.receipt.capability_generation != allocation.capability_generation {
                    return Err(AppError::NotAuthorized(
                        "source authorization generation changed before checkout dispatch".into(),
                    ));
                }
                let stored = entries
                    .get(&allocation.capability_generation.0)
                    .ok_or_else(|| {
                        AppError::NotAuthorized(
                            "reserved source capability is invalid, revoked, or expired".into(),
                        )
                    })?;
                validate_installed_binding(stored, binding)?;
                if now >= stored.expires_at {
                    return Err(AppError::NotAuthorized(
                        "reserved source capability expired before checkout dispatch".into(),
                    ));
                }
                if stored.reserved_checkouts < allocation.count
                    || stored
                        .completed_checkouts
                        .checked_add(allocation.count)
                        .is_none_or(|completed| completed > stored.max_checkouts)
                {
                    return Err(AppError::Internal(
                        "source checkout reservation capacity invariant failed".into(),
                    ));
                }
            }
            Ok(())
        })();

        if let Err(error) = validation {
            reservations.remove(&handle.0);
            release_reservation_allocations(&mut entries, &reservation.allocations);
            return Err(error);
        }

        let mut exhausted = Vec::new();
        for allocation in &reservation.allocations {
            let key = (allocation.case_id.clone(), allocation.source_id.clone());
            let binding = receipts
                .get_mut(&key)
                .expect("commit validation retained the exact installed binding");
            let stored = entries
                .get_mut(&allocation.capability_generation.0)
                .expect("commit validation retained the exact vault generation");
            stored.reserved_checkouts -= allocation.count;
            stored.completed_checkouts += allocation.count;
            binding.completed_checkouts += allocation.count;
            if stored.completed_checkouts >= stored.max_checkouts && stored.reserved_checkouts == 0
            {
                exhausted.push(allocation.capability_generation);
            }
        }
        reservations.remove(&handle.0);
        for generation in exhausted {
            entries.remove(&generation.0);
        }
        Ok(())
    }

    /// Validates all prospective provider checkout groups as one
    /// non-consuming snapshot. Demands are aggregated by exact case/source
    /// binding so repeated groups cannot individually pass while collectively
    /// exceeding the capability's remaining checkout count.
    pub fn validate_checkout_demands(
        &self,
        demands: &[SourceCheckoutDemand<'_>],
        now: DateTime<Utc>,
    ) -> AppResult<()> {
        let mut grouped = BTreeMap::<(&str, &str), Vec<&str>>::new();
        for demand in demands {
            validate_identifier(demand.case_id, "case")?;
            validate_identifier(demand.source_id, "source")?;
            validate_identifier(demand.engine_id, "engine")?;
            grouped
                .entry((demand.case_id, demand.source_id))
                .or_default()
                .push(demand.engine_id);
        }

        let receipts = self
            .receipts
            .lock()
            .map_err(|_| AppError::Internal("source authorization lock was poisoned".into()))?;
        let entries = self.vault.entries.lock().map_err(|_| {
            AppError::Internal("source authorization vault lock was poisoned".into())
        })?;
        for ((case_id, source_id), engine_ids) in grouped {
            let binding = receipts
                .get(&(case_id.to_owned(), source_id.to_owned()))
                .ok_or_else(|| {
                    AppError::NotAuthorized(
                        "connected source has no live backend authorization capability".into(),
                    )
                })?;
            let stored = entries
                .get(&binding.receipt.capability_generation.0)
                .ok_or_else(|| {
                    AppError::NotAuthorized(
                        "source capability is invalid, revoked, or exhausted".into(),
                    )
                })?;
            validate_installed_binding(stored, binding)?;
            for engine_id in &engine_ids {
                authorize_checkout(
                    stored,
                    &SourceCredentialCheckout {
                        case_id,
                        source_id,
                        engine_id,
                        profile: binding.receipt.profile,
                        permissions: &binding.receipt.permissions,
                    },
                    now,
                )?;
            }
            let unavailable = stored
                .completed_checkouts
                .checked_add(stored.reserved_checkouts)
                .ok_or_else(|| {
                    AppError::Internal("source authorization checkout counter overflowed".into())
                })?;
            let remaining = usize::from(stored.max_checkouts.saturating_sub(unavailable));
            if engine_ids.len() > remaining {
                return Err(AppError::NotAuthorized(format!(
                    "source capability has {remaining} checkout(s) remaining but this scan requires {}",
                    engine_ids.len()
                )));
            }
        }
        Ok(())
    }

    pub fn status(
        &self,
        case_id: &str,
        source_id: &str,
        now: DateTime<Utc>,
    ) -> AppResult<Option<InstalledSourceAuthorization>> {
        validate_identifier(case_id, "case")?;
        validate_identifier(source_id, "source")?;
        let mut receipts = self
            .receipts
            .lock()
            .map_err(|_| AppError::Internal("source authorization lock was poisoned".into()))?;
        let key = (case_id.to_owned(), source_id.to_owned());
        if receipts
            .get(&key)
            .is_some_and(|binding| binding.receipt.expires_at <= now)
        {
            let mut entries = self.vault.entries.lock().map_err(|_| {
                AppError::Internal("source authorization vault lock was poisoned".into())
            })?;
            let generation = receipts
                .get(&key)
                .expect("expired binding remained present while its lock was held")
                .receipt
                .capability_generation;
            let mut reservations = self.reservations.lock().map_err(|_| {
                AppError::Internal("source checkout reservation lock was poisoned".into())
            })?;
            let reservation_ids = reservations
                .iter()
                .filter(|(_, reservation)| {
                    reservation
                        .allocations
                        .iter()
                        .any(|allocation| allocation.capability_generation == generation)
                })
                .map(|(reservation_id, _)| reservation_id.clone())
                .collect::<Vec<_>>();
            for reservation_id in reservation_ids {
                if let Some(reservation) = reservations.remove(&reservation_id) {
                    release_reservation_allocations(&mut entries, &reservation.allocations);
                }
            }
            receipts.remove(&key);
            entries.remove(&generation.0);
            return Ok(None);
        }
        let Some(binding) = receipts.get(&key) else {
            return Ok(None);
        };
        let entries = self.vault.entries.lock().map_err(|_| {
            AppError::Internal("source authorization vault lock was poisoned".into())
        })?;
        if let Some(stored) = entries.get(&binding.receipt.capability_generation.0) {
            validate_installed_binding(stored, binding)?;
        } else if binding.completed_checkouts < binding.receipt.max_checkouts {
            return Err(AppError::NotAuthorized(
                "installed source authorization generation is no longer available".into(),
            ));
        }
        Ok(Some(InstalledSourceAuthorization::from(&binding.receipt)))
    }

    pub fn revoke_source(
        &self,
        case_id: &str,
        source_id: &str,
        now: DateTime<Utc>,
    ) -> AppResult<SourceAuthorizationRevocation> {
        validate_identifier(case_id, "case")?;
        validate_identifier(source_id, "source")?;
        let key = (case_id.to_owned(), source_id.to_owned());
        let mut receipts = self
            .receipts
            .lock()
            .map_err(|_| AppError::Internal("source authorization lock was poisoned".into()))?;
        let mut entries = self.vault.entries.lock().map_err(|_| {
            AppError::Internal("source authorization vault lock was poisoned".into())
        })?;
        let binding = receipts.get(&key).ok_or_else(|| {
            AppError::NotAuthorized("source has no live authorization to revoke".into())
        })?;
        let generation = binding.receipt.capability_generation;
        if let Some(stored) = entries.get(&generation.0) {
            validate_installed_binding(stored, binding)?;
            if stored.reserved_checkouts > 0 {
                return Err(AppError::NotAuthorized(
                    "source authorization cannot be revoked while a checkout reservation is active"
                        .into(),
                ));
            }
        } else if binding.completed_checkouts < binding.receipt.max_checkouts {
            return Err(AppError::NotAuthorized(
                "installed source authorization generation is no longer available".into(),
            ));
        }
        let binding = receipts
            .remove(&key)
            .expect("validated source binding remained present while its lock was held");
        entries.remove(&generation.0);
        Ok(SourceAuthorizationRevocation {
            provider: binding.receipt.provider,
            source_kind: binding.receipt.source_kind,
            case_id: binding.receipt.case_id,
            source_id: binding.receipt.source_id,
            revoked_at: now,
            completed_checkouts: binding.completed_checkouts,
        })
    }

    /// Revokes and zeroizes every live capability installed for one case.
    pub fn revoke_case(&self, case_id: &str, now: DateTime<Utc>) -> AppResult<usize> {
        validate_identifier(case_id, "case")?;
        let mut receipts = self
            .receipts
            .lock()
            .map_err(|_| AppError::Internal("source authorization lock was poisoned".into()))?;
        let mut entries = self.vault.entries.lock().map_err(|_| {
            AppError::Internal("source authorization vault lock was poisoned".into())
        })?;
        let keys = receipts
            .keys()
            .filter(|(bound_case_id, _)| bound_case_id == case_id)
            .cloned()
            .collect::<Vec<_>>();
        for key in &keys {
            let binding = receipts
                .get(key)
                .expect("case revocation key came from the binding map");
            let generation = binding.receipt.capability_generation;
            if let Some(stored) = entries.get(&generation.0) {
                validate_installed_binding(stored, binding)?;
                if stored.reserved_checkouts > 0 {
                    return Err(AppError::NotAuthorized(
                        "case authorization cannot be revoked while a checkout reservation is active"
                            .into(),
                    ));
                }
            } else if binding.completed_checkouts < binding.receipt.max_checkouts {
                return Err(AppError::NotAuthorized(
                    "installed source authorization generation is no longer available".into(),
                ));
            }
        }
        for key in &keys {
            let binding = receipts
                .remove(key)
                .expect("validated case binding remained present while its lock was held");
            entries.remove(&binding.receipt.capability_generation.0);
        }
        let _ = now;
        Ok(keys.len())
    }

    pub fn purge_expired(&self, now: DateTime<Utc>) -> AppResult<usize> {
        let mut receipts = self
            .receipts
            .lock()
            .map_err(|_| AppError::Internal("source authorization lock was poisoned".into()))?;
        let mut entries = self.vault.entries.lock().map_err(|_| {
            AppError::Internal("source authorization vault lock was poisoned".into())
        })?;
        let mut reservations = self.reservations.lock().map_err(|_| {
            AppError::Internal("source checkout reservation lock was poisoned".into())
        })?;
        let expired_generations = entries
            .iter()
            .filter(|(_, stored)| stored.expires_at <= now)
            .map(|(generation, _)| SourceCapabilityGeneration(*generation))
            .collect::<BTreeSet<_>>();
        let reservation_ids = reservations
            .iter()
            .filter(|(_, reservation)| {
                reservation.allocations.iter().any(|allocation| {
                    expired_generations.contains(&allocation.capability_generation)
                })
            })
            .map(|(reservation_id, _)| reservation_id.clone())
            .collect::<Vec<_>>();
        for reservation_id in reservation_ids {
            if let Some(reservation) = reservations.remove(&reservation_id) {
                release_reservation_allocations(&mut entries, &reservation.allocations);
            }
        }
        let before = entries.len();
        entries.retain(|_, stored| stored.expires_at > now);
        receipts.retain(|_, binding| binding.receipt.expires_at > now);
        Ok(before - entries.len())
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
            reserved_checkouts: 0,
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
                capability_generation: SourceCapabilityGeneration(digest),
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
        let mut entries = self.entries.lock().map_err(|_| {
            AppError::Internal("source authorization vault lock was poisoned".into())
        })?;
        let stored = entries.get(&digest).ok_or_else(|| {
            AppError::NotAuthorized("source capability is invalid, revoked, or exhausted".into())
        })?;
        if stored.reserved_checkouts > 0 {
            return Err(AppError::NotAuthorized(
                "source capability cannot be revoked while a checkout reservation is active".into(),
            ));
        }
        let stored = entries
            .remove(&digest)
            .expect("validated source capability remained present while its lock was held");
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
    let profile_checkout_limit = verified.profile.max_checkouts();
    if !(1..=profile_checkout_limit).contains(&request.max_checkouts) {
        return Err(AppError::InvalidRequest(format!(
            "source capability checkout limit for this provider profile must be between 1 and {profile_checkout_limit} (global hard limit {PROVIDER_CHECKOUT_HARD_LIMIT})"
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

fn validate_trusted_identifier(
    value: &str,
    label: &str,
) -> Result<(), SourceCheckoutPreflightFailure> {
    validate_identifier(value, label).map_err(|_| SourceCheckoutPreflightFailure::Internal)
}

fn validate_bound_demand_identifiers(
    demands: &[BoundSourceCheckoutDemand<'_>],
) -> Result<(), SourceCheckoutPreflightFailure> {
    for demand in demands {
        validate_trusted_identifier(demand.case_id, "case")?;
        validate_trusted_identifier(demand.source_id, "source")?;
        validate_trusted_identifier(demand.engine_id, "engine")?;
        if demand.case_id != demand.binding.authorization.case_id
            || demand.source_id != demand.binding.authorization.source_id
            || !demand
                .binding
                .authorization
                .allowed_engine_ids
                .contains(demand.engine_id)
        {
            return Err(SourceCheckoutPreflightFailure::BindingMismatch);
        }
    }
    Ok(())
}

fn validate_bound_checkout_demands_locked(
    demands: &[BoundSourceCheckoutDemand<'_>],
    now: DateTime<Utc>,
    receipts: &HashMap<(String, String), InstalledBinding>,
    entries: &HashMap<[u8; 32], StoredSourceAuthorization>,
    reservations: &HashMap<String, StoredCheckoutReservation>,
) -> Result<Vec<StoredCheckoutReservationAllocation>, SourceCheckoutPreflightFailure> {
    let mut grouped = BTreeMap::<(&str, &str), Vec<&BoundSourceCheckoutDemand<'_>>>::new();
    for demand in demands {
        grouped
            .entry((demand.case_id, demand.source_id))
            .or_default()
            .push(demand);
    }

    let mut allocations = Vec::with_capacity(grouped.len());
    for ((case_id, source_id), grouped_demands) in grouped {
        let first = grouped_demands
            .first()
            .ok_or(SourceCheckoutPreflightFailure::Internal)?;
        if grouped_demands.iter().any(|demand| {
            demand.binding.capability_generation != first.binding.capability_generation
                || demand.binding.authorization != first.binding.authorization
        }) {
            return Err(SourceCheckoutPreflightFailure::BindingMismatch);
        }
        let binding = receipts
            .get(&(case_id.to_owned(), source_id.to_owned()))
            .ok_or(SourceCheckoutPreflightFailure::CapabilityUnavailable)?;
        if binding.receipt.capability_generation != first.binding.capability_generation {
            return Err(SourceCheckoutPreflightFailure::BindingMismatch);
        }
        if InstalledSourceAuthorization::from(&binding.receipt) != first.binding.authorization {
            return Err(SourceCheckoutPreflightFailure::BindingMismatch);
        }
        let stored = entries
            .get(&first.binding.capability_generation.0)
            .ok_or(SourceCheckoutPreflightFailure::CapabilityUnavailable)?;
        validate_bound_installed_binding(stored, binding)?;
        validate_stored_reservation_invariant(
            stored,
            first.binding.capability_generation,
            reservations,
        )?;
        if now >= stored.expires_at {
            return Err(SourceCheckoutPreflightFailure::CapabilityUnavailable);
        }
        if grouped_demands
            .iter()
            .any(|demand| !stored.allowed_engine_ids.contains(demand.engine_id))
        {
            return Err(SourceCheckoutPreflightFailure::BindingMismatch);
        }
        let count = u16::try_from(grouped_demands.len())
            .map_err(|_| SourceCheckoutPreflightFailure::Internal)?;
        let unavailable = stored
            .completed_checkouts
            .checked_add(stored.reserved_checkouts)
            .ok_or(SourceCheckoutPreflightFailure::Internal)?;
        let required = unavailable
            .checked_add(count)
            .ok_or(SourceCheckoutPreflightFailure::Internal)?;
        if required > stored.max_checkouts {
            return Err(SourceCheckoutPreflightFailure::CapabilityUnavailable);
        }
        allocations.push(StoredCheckoutReservationAllocation {
            case_id: case_id.to_owned(),
            source_id: source_id.to_owned(),
            capability_generation: first.binding.capability_generation,
            count,
        });
    }
    Ok(allocations)
}

fn validate_bound_installed_binding(
    stored: &StoredSourceAuthorization,
    binding: &InstalledBinding,
) -> Result<(), SourceCheckoutPreflightFailure> {
    let receipt = &binding.receipt;
    if stored.case_id != receipt.case_id
        || stored.source_id != receipt.source_id
        || stored.provider != receipt.provider
        || stored.source_kind != receipt.source_kind
        || stored.profile != receipt.profile
        || stored.credential_source != receipt.credential_source
        || stored.expires_at != receipt.expires_at
        || stored.permissions != canonical_permissions(&receipt.permissions)
        || stored.allowed_engine_ids != receipt.allowed_engine_ids
        || stored.max_checkouts != receipt.max_checkouts
        || receipt.provider != receipt.profile.provider()
        || receipt.source_kind != receipt.profile.source_kind()
        || receipt.permissions != receipt.profile.permissions()
        || receipt.allowed_engine_ids.iter().any(|engine_id| {
            !receipt
                .profile
                .allowed_engine_ids()
                .contains(engine_id.as_str())
        })
        || receipt.provider_verification.provider != receipt.provider
        || receipt.provider_verification.profile != receipt.profile
        || receipt.provider_verification.provider_identity != receipt.provider_identity
        || receipt.provider_verification.credential_expires_at != receipt.expires_at
    {
        return Err(SourceCheckoutPreflightFailure::BindingMismatch);
    }
    if stored.completed_checkouts != binding.completed_checkouts
        || stored.max_checkouts == 0
        || stored.completed_checkouts > stored.max_checkouts
        || stored.reserved_checkouts > stored.max_checkouts
        || stored
            .completed_checkouts
            .checked_add(stored.reserved_checkouts)
            .is_none_or(|unavailable| unavailable > stored.max_checkouts)
    {
        return Err(SourceCheckoutPreflightFailure::Internal);
    }
    Ok(())
}

fn validate_stored_reservation_invariant(
    stored: &StoredSourceAuthorization,
    generation: SourceCapabilityGeneration,
    reservations: &HashMap<String, StoredCheckoutReservation>,
) -> Result<(), SourceCheckoutPreflightFailure> {
    let mut reserved = 0_u16;
    for allocation in reservations
        .values()
        .flat_map(|reservation| reservation.allocations.iter())
        .filter(|allocation| allocation.capability_generation == generation)
    {
        if allocation.case_id != stored.case_id
            || allocation.source_id != stored.source_id
            || allocation.count == 0
        {
            return Err(SourceCheckoutPreflightFailure::Internal);
        }
        reserved = reserved
            .checked_add(allocation.count)
            .ok_or(SourceCheckoutPreflightFailure::Internal)?;
    }
    if reserved != stored.reserved_checkouts {
        return Err(SourceCheckoutPreflightFailure::Internal);
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
    let unavailable = stored
        .completed_checkouts
        .checked_add(stored.reserved_checkouts)
        .ok_or_else(|| {
            AppError::Internal("source authorization checkout counter overflowed".into())
        })?;
    if unavailable >= stored.max_checkouts {
        return Err(AppError::NotAuthorized(
            "source capability checkout limit is exhausted or reserved".into(),
        ));
    }
    Ok(())
}

fn validate_installed_binding(
    stored: &StoredSourceAuthorization,
    binding: &InstalledBinding,
) -> AppResult<()> {
    let receipt = &binding.receipt;
    if stored.case_id != receipt.case_id
        || stored.source_id != receipt.source_id
        || stored.provider != receipt.provider
        || stored.source_kind != receipt.source_kind
        || stored.profile != receipt.profile
        || stored.credential_source != receipt.credential_source
        || stored.expires_at != receipt.expires_at
        || stored.permissions != canonical_permissions(&receipt.permissions)
        || stored.allowed_engine_ids != receipt.allowed_engine_ids
        || stored.max_checkouts != receipt.max_checkouts
        || stored.completed_checkouts != binding.completed_checkouts
    {
        return Err(AppError::NotAuthorized(
            "installed source authorization metadata does not match its vault generation".into(),
        ));
    }
    Ok(())
}

fn new_checkout_reservation_handle(
    reservations: &HashMap<String, StoredCheckoutReservation>,
) -> AppResult<SourceCheckoutReservationHandle> {
    for _ in 0..4 {
        let mut random = [0_u8; RESERVATION_RANDOM_BYTES];
        getrandom::fill(&mut random)
            .map_err(|_| AppError::Internal("operating system random source failed".into()))?;
        let mut value = String::with_capacity(
            RESERVATION_PREFIX.len() + RESERVATION_RANDOM_BYTES.saturating_mul(2),
        );
        value.push_str(RESERVATION_PREFIX);
        for byte in random {
            write!(&mut value, "{byte:02x}").expect("writing to a String cannot fail");
        }
        if !reservations.contains_key(&value) {
            return Ok(SourceCheckoutReservationHandle(value));
        }
    }
    Err(AppError::Internal(
        "random source checkout reservation collision limit reached".into(),
    ))
}

fn release_reservation_allocations(
    entries: &mut HashMap<[u8; 32], StoredSourceAuthorization>,
    allocations: &[StoredCheckoutReservationAllocation],
) {
    for allocation in allocations {
        if let Some(stored) = entries.get_mut(&allocation.capability_generation.0)
            && stored.case_id == allocation.case_id
            && stored.source_id == allocation.source_id
        {
            stored.reserved_checkouts = stored.reserved_checkouts.saturating_sub(allocation.count);
        }
    }
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::domain::AssetIdentifier;

    fn verified_for_limit_test(
        profile: ProviderSourceProfile,
        now: DateTime<Utc>,
    ) -> VerifiedProviderAuthorization {
        let (provider_identity, resource_scope, credential_key) = match profile {
            ProviderSourceProfile::AwsOrganizationReadOnlySession => (
                "arn:aws:sts::111122223333:assumed-role/security-audit-reader/session",
                "aws-account:111122223333",
                "AWS_ACCESS_KEY_ID",
            ),
            ProviderSourceProfile::AzureTenantReadOnlyAccessToken => (
                "azure-reader@example.invalid",
                "azure-subscription:33333333-3333-4333-8333-333333333333",
                "AZURE_ACCESS_TOKEN",
            ),
            ProviderSourceProfile::GcpOrganizationReadOnlyAccessToken => (
                "reader@example.invalid",
                "gcp-organization:123456789012",
                "GOOGLE_OAUTH_ACCESS_TOKEN",
            ),
            ProviderSourceProfile::Microsoft365TenantReadOnlyAccessToken => (
                "m365-reader@example.invalid",
                "microsoft365-tenant:11111111-1111-4111-8111-111111111111",
                "MSGRAPH_ACCESS_TOKEN",
            ),
        };
        let expires_at = now + Duration::minutes(30);
        let verification = ProviderVerificationState {
            schema_version: "1.0.0".into(),
            provider: profile.provider(),
            profile,
            authentication_method: "fixture_short_lived_token".into(),
            provider_identity: provider_identity.into(),
            subject_id: "fixture-subject".into(),
            resource_scope: resource_scope.into(),
            verified_at: now,
            credential_expires_at: expires_at,
            identity_endpoint: "https://provider.invalid/identity".into(),
            permission_endpoints: vec!["https://provider.invalid/permissions".into()],
            required_permissions_verified: vec!["inventory.read".into()],
            prohibited_permissions_denied: vec!["inventory.write".into()],
            provider_request_ids: vec!["fixture-request".into()],
            evidence_sha256: "a".repeat(64),
        };
        let mut entries = vec![SecretEnvironmentValue::new(
            credential_key,
            Zeroizing::new("fixture-ephemeral-credential".into()),
        )];
        if profile == ProviderSourceProfile::AwsOrganizationReadOnlySession {
            entries.extend([
                SecretEnvironmentValue::new(
                    "AWS_SECRET_ACCESS_KEY",
                    Zeroizing::new("fixture-ephemeral-secret".into()),
                ),
                SecretEnvironmentValue::new(
                    "AWS_SESSION_TOKEN",
                    Zeroizing::new("fixture-ephemeral-session".into()),
                ),
            ]);
        }
        VerifiedProviderAuthorization::new_verified(
            profile,
            ReadOnlyCredentialSource::ProviderNative,
            provider_identity.into(),
            expires_at,
            verification,
            ProviderSecretMaterial::new(entries),
        )
        .unwrap()
    }

    fn aws_account_asset(id: &str, account_id: &str) -> Asset {
        Asset {
            id: id.into(),
            kind: AssetKind::CloudAccount,
            name: format!("AWS account {account_id}"),
            provider: Some("aws".into()),
            region: None,
            identifiers: vec![AssetIdentifier {
                namespace: "aws_account_id".into(),
                value: account_id.into(),
            }],
            discovered_from: vec!["source-aws".into()],
            candidate: false,
            owner_confirmed: true,
            internet_exposed: None,
            contains_sensitive_data: None,
            metadata: BTreeMap::new(),
        }
    }

    #[test]
    fn aws_target_scope_requires_one_exact_matching_account() {
        let account = aws_account_asset("asset-1", "111122223333");
        validate_aws_execution_target(std::slice::from_ref(&account), "aws-account:111122223333")
            .unwrap();

        assert!(matches!(
            validate_aws_execution_target(
                std::slice::from_ref(&account),
                "aws-account:444455556666"
            ),
            Err(AppError::NotAuthorized(_))
        ));
        assert!(matches!(
            validate_aws_execution_target(
                &[
                    account.clone(),
                    aws_account_asset("asset-2", "444455556666")
                ],
                "aws-account:111122223333"
            ),
            Err(AppError::NotAuthorized(_))
        ));

        let mut ambiguous = account;
        ambiguous.identifiers.push(AssetIdentifier {
            namespace: "aws_account_id".into(),
            value: "444455556666".into(),
        });
        assert!(matches!(
            validate_aws_execution_target(&[ambiguous], "aws-account:111122223333"),
            Err(AppError::NotAuthorized(_))
        ));
    }

    #[test]
    fn provider_checkout_limits_are_profile_bounded_with_a_global_hard_cap() {
        let now = Utc::now();
        assert_eq!(
            ProviderSourceProfile::AwsOrganizationReadOnlySession.max_checkouts(),
            8
        );
        assert_eq!(
            ProviderSourceProfile::GcpOrganizationReadOnlyAccessToken.max_checkouts(),
            PROVIDER_DISCOVERY_RECORD_LIMIT as u16 + 1
        );
        assert_eq!(
            ProviderSourceProfile::GcpOrganizationReadOnlyAccessToken.max_checkouts(),
            PROVIDER_CHECKOUT_HARD_LIMIT
        );

        let aws_too_many = SourceAuthorizationBindings::default().install(
            SourceAuthorizationRequest {
                case_id: "case-aws".into(),
                source_id: "source-aws".into(),
                allowed_engine_ids: BTreeSet::from(["prowler".into()]),
                max_checkouts: 9,
                verified_authorization: verified_for_limit_test(
                    ProviderSourceProfile::AwsOrganizationReadOnlySession,
                    now,
                ),
            },
            now,
        );
        assert!(matches!(aws_too_many, Err(AppError::InvalidRequest(_))));

        let gcp_too_many = SourceAuthorizationBindings::default().install(
            SourceAuthorizationRequest {
                case_id: "case-gcp-overflow".into(),
                source_id: "source-gcp-overflow".into(),
                allowed_engine_ids: BTreeSet::from(["prowler".into()]),
                max_checkouts: PROVIDER_CHECKOUT_HARD_LIMIT + 1,
                verified_authorization: verified_for_limit_test(
                    ProviderSourceProfile::GcpOrganizationReadOnlyAccessToken,
                    now,
                ),
            },
            now,
        );
        assert!(matches!(gcp_too_many, Err(AppError::InvalidRequest(_))));

        let bindings = SourceAuthorizationBindings::default();
        bindings
            .install(
                SourceAuthorizationRequest {
                    case_id: "case-gcp-nine-projects".into(),
                    source_id: "source-gcp-nine-projects".into(),
                    allowed_engine_ids: BTreeSet::from([
                        PROVIDER_DISCOVERY_ENGINE_ID.into(),
                        "prowler".into(),
                    ]),
                    max_checkouts: 10,
                    verified_authorization: verified_for_limit_test(
                        ProviderSourceProfile::GcpOrganizationReadOnlyAccessToken,
                        now,
                    ),
                },
                now,
            )
            .unwrap();
        bindings
            .checkout(
                "case-gcp-nine-projects",
                "source-gcp-nine-projects",
                PROVIDER_DISCOVERY_ENGINE_ID,
                now,
            )
            .unwrap();
        for _ in 0..9 {
            bindings
                .checkout(
                    "case-gcp-nine-projects",
                    "source-gcp-nine-projects",
                    "prowler",
                    now,
                )
                .unwrap();
        }
        assert!(
            bindings
                .status("case-gcp-nine-projects", "source-gcp-nine-projects", now,)
                .unwrap()
                .is_some()
        );
        assert!(matches!(
            bindings.checkout(
                "case-gcp-nine-projects",
                "source-gcp-nine-projects",
                "prowler",
                now,
            ),
            Err(AppError::NotAuthorized(_))
        ));
    }

    fn install_aws_test_binding(
        bindings: &SourceAuthorizationBindings,
        case_id: &str,
        source_id: &str,
        max_checkouts: u16,
        now: DateTime<Utc>,
    ) {
        bindings
            .install(
                aws_test_request(case_id, source_id, max_checkouts, now),
                now,
            )
            .unwrap();
    }

    fn aws_test_request(
        case_id: &str,
        source_id: &str,
        max_checkouts: u16,
        now: DateTime<Utc>,
    ) -> SourceAuthorizationRequest {
        SourceAuthorizationRequest {
            case_id: case_id.into(),
            source_id: source_id.into(),
            allowed_engine_ids: BTreeSet::from(["prowler".into()]),
            max_checkouts,
            verified_authorization: verified_for_limit_test(
                ProviderSourceProfile::AwsOrganizationReadOnlySession,
                now,
            ),
        }
    }

    #[test]
    fn checkout_demand_validation_aggregates_each_execution_group_without_consuming() {
        let now = Utc::now();
        let bindings = SourceAuthorizationBindings::default();
        install_aws_test_binding(&bindings, "case-capacity", "source-capacity", 2, now);

        let three_groups = [
            SourceCheckoutDemand {
                case_id: "case-capacity",
                source_id: "source-capacity",
                engine_id: "prowler",
            },
            SourceCheckoutDemand {
                case_id: "case-capacity",
                source_id: "source-capacity",
                engine_id: "prowler",
            },
            SourceCheckoutDemand {
                case_id: "case-capacity",
                source_id: "source-capacity",
                engine_id: "prowler",
            },
        ];
        assert!(matches!(
            bindings.validate_checkout_demands(&three_groups, now),
            Err(AppError::NotAuthorized(_))
        ));

        let two_groups = &three_groups[..2];
        bindings.validate_checkout_demands(two_groups, now).unwrap();
        bindings.validate_checkout_demands(two_groups, now).unwrap();
        bindings
            .checkout("case-capacity", "source-capacity", "prowler", now)
            .unwrap();
        assert!(matches!(
            bindings.validate_checkout_demands(two_groups, now),
            Err(AppError::NotAuthorized(_))
        ));
        bindings
            .validate_checkout_demands(&two_groups[..1], now)
            .unwrap();
        bindings
            .checkout("case-capacity", "source-capacity", "prowler", now)
            .unwrap();
    }

    #[test]
    fn checkout_demand_validation_is_exact_across_bindings_engines_and_expiry() {
        let now = Utc::now();
        let bindings = SourceAuthorizationBindings::default();
        install_aws_test_binding(&bindings, "case-batch", "source-a", 1, now);
        install_aws_test_binding(&bindings, "case-batch", "source-b", 2, now);

        bindings
            .validate_checkout_demands(
                &[
                    SourceCheckoutDemand {
                        case_id: "case-batch",
                        source_id: "source-a",
                        engine_id: "prowler",
                    },
                    SourceCheckoutDemand {
                        case_id: "case-batch",
                        source_id: "source-b",
                        engine_id: "prowler",
                    },
                    SourceCheckoutDemand {
                        case_id: "case-batch",
                        source_id: "source-b",
                        engine_id: "prowler",
                    },
                ],
                now,
            )
            .unwrap();
        assert!(matches!(
            bindings.validate_checkout_demands(
                &[SourceCheckoutDemand {
                    case_id: "case-other",
                    source_id: "source-a",
                    engine_id: "prowler",
                }],
                now,
            ),
            Err(AppError::NotAuthorized(_))
        ));
        assert!(matches!(
            bindings.validate_checkout_demands(
                &[SourceCheckoutDemand {
                    case_id: "case-batch",
                    source_id: "source-a",
                    engine_id: "scoutsuite",
                }],
                now,
            ),
            Err(AppError::NotAuthorized(_))
        ));
        assert!(matches!(
            bindings.validate_checkout_demands(
                &[SourceCheckoutDemand {
                    case_id: "case-batch",
                    source_id: "source-a",
                    engine_id: "prowler",
                }],
                now + Duration::minutes(31),
            ),
            Err(AppError::NotAuthorized(_))
        ));
    }

    #[test]
    fn checkout_reservation_is_atomic_under_contention() {
        use std::sync::{Arc, Barrier};
        use std::thread;

        let now = Utc::now();
        let bindings = Arc::new(SourceAuthorizationBindings::default());
        install_aws_test_binding(&bindings, "case-race", "source-race", 1, now);
        let start = Arc::new(Barrier::new(3));
        let finish = Arc::new(Barrier::new(3));
        let mut workers = Vec::new();
        for _ in 0..2 {
            let worker_bindings = Arc::clone(&bindings);
            let worker_start = Arc::clone(&start);
            let worker_finish = Arc::clone(&finish);
            workers.push(thread::spawn(move || {
                let demand = [SourceCheckoutDemand {
                    case_id: "case-race",
                    source_id: "source-race",
                    engine_id: "prowler",
                }];
                worker_start.wait();
                let result = worker_bindings.reserve_checkout_demands(&demand, now).map(
                    |(handle, bundle)| {
                        drop(bundle);
                        handle
                    },
                );
                worker_finish.wait();
                result
            }));
        }
        start.wait();
        finish.wait();
        let results = workers
            .into_iter()
            .map(|worker| worker.join().unwrap())
            .collect::<Vec<_>>();
        assert_eq!(results.iter().filter(|result| result.is_ok()).count(), 1);
        assert_eq!(results.iter().filter(|result| result.is_err()).count(), 1);
        let handle = results.into_iter().find_map(Result::ok).unwrap();
        bindings.release_checkout_reservation(&handle).unwrap();
    }

    #[test]
    fn reservation_blocks_ordinary_and_discovery_checkout_until_release() {
        let now = Utc::now();
        let bindings = SourceAuthorizationBindings::default();
        let mut request = aws_test_request("case-held", "source-held", 1, now);
        request
            .allowed_engine_ids
            .insert(PROVIDER_DISCOVERY_ENGINE_ID.into());
        bindings.install(request, now).unwrap();
        let demand = [SourceCheckoutDemand {
            case_id: "case-held",
            source_id: "source-held",
            engine_id: "prowler",
        }];
        let (handle, bundle) = bindings.reserve_checkout_demands(&demand, now).unwrap();
        assert!(matches!(
            bindings.checkout(
                "case-held",
                "source-held",
                PROVIDER_DISCOVERY_ENGINE_ID,
                now,
            ),
            Err(AppError::NotAuthorized(_))
        ));
        assert!(matches!(
            bindings.reserve_checkout_demands(&demand, now),
            Err(AppError::NotAuthorized(_))
        ));
        bindings.release_checkout_reservation(&handle).unwrap();
        drop(bundle);
        bindings
            .checkout(
                "case-held",
                "source-held",
                PROVIDER_DISCOVERY_ENGINE_ID,
                now,
            )
            .unwrap();
    }

    #[test]
    fn duplicate_reservation_credentials_are_exact_one_shot_and_redacted() {
        let now = Utc::now();
        let bindings = SourceAuthorizationBindings::default();
        install_aws_test_binding(&bindings, "case-duplicates", "source-duplicates", 2, now);
        let demands = [
            SourceCheckoutDemand {
                case_id: "case-duplicates",
                source_id: "source-duplicates",
                engine_id: "prowler",
            },
            SourceCheckoutDemand {
                case_id: "case-duplicates",
                source_id: "source-duplicates",
                engine_id: "prowler",
            },
        ];
        let (handle, mut bundle) = bindings.reserve_checkout_demands(&demands, now).unwrap();
        assert_eq!(
            format!("{handle:?}"),
            "SourceCheckoutReservationHandle([REDACTED])"
        );
        assert_eq!(bundle.remaining(), 2);
        assert!(matches!(
            bundle.take("case-duplicates", "source-other", "prowler"),
            Err(AppError::NotAuthorized(_))
        ));
        let first = bundle
            .take("case-duplicates", "source-duplicates", "prowler")
            .unwrap();
        let second = bundle
            .take("case-duplicates", "source-duplicates", "prowler")
            .unwrap();
        assert_eq!(bundle.remaining(), 0);
        assert!(matches!(
            bundle.take("case-duplicates", "source-duplicates", "prowler"),
            Err(AppError::NotAuthorized(_))
        ));
        assert_eq!(
            first.provider_secret("AWS_SESSION_TOKEN"),
            Some("fixture-ephemeral-session")
        );
        assert_eq!(
            second.provider_secret("AWS_SESSION_TOKEN"),
            Some("fixture-ephemeral-session")
        );
        assert!(!format!("{first:?}").contains("fixture-ephemeral-session"));
        bindings.release_checkout_reservation(&handle).unwrap();
    }

    #[test]
    fn commit_consumes_capacity_but_preserves_nonsecret_status_tombstone() {
        let now = Utc::now();
        let bindings = SourceAuthorizationBindings::default();
        install_aws_test_binding(&bindings, "case-commit", "source-commit", 1, now);
        let generation = bindings
            .receipts
            .lock()
            .unwrap()
            .get(&("case-commit".into(), "source-commit".into()))
            .unwrap()
            .receipt
            .capability_generation;
        let demand = [SourceCheckoutDemand {
            case_id: "case-commit",
            source_id: "source-commit",
            engine_id: "prowler",
        }];
        let (handle, mut bundle) = bindings.reserve_checkout_demands(&demand, now).unwrap();
        bindings.commit_checkout_reservation(&handle, now).unwrap();
        assert!(
            bindings
                .status("case-commit", "source-commit", now)
                .unwrap()
                .is_some()
        );
        assert!(
            !bindings
                .vault
                .entries
                .lock()
                .unwrap()
                .contains_key(&generation.0)
        );
        assert!(matches!(
            bindings.checkout("case-commit", "source-commit", "prowler", now),
            Err(AppError::NotAuthorized(_))
        ));
        assert!(matches!(
            bindings.commit_checkout_reservation(&handle, now),
            Err(AppError::NotAuthorized(_))
        ));
        assert!(
            !bundle
                .take("case-commit", "source-commit", "prowler")
                .unwrap()
                .is_empty()
        );
    }

    #[test]
    fn active_reservation_blocks_reinstall_and_revoke_then_release_restores_both() {
        let now = Utc::now();
        let bindings = SourceAuthorizationBindings::default();
        install_aws_test_binding(&bindings, "case-lifecycle", "source-lifecycle", 1, now);
        let original_generation = bindings
            .receipts
            .lock()
            .unwrap()
            .get(&("case-lifecycle".into(), "source-lifecycle".into()))
            .unwrap()
            .receipt
            .capability_generation;
        let demand = [SourceCheckoutDemand {
            case_id: "case-lifecycle",
            source_id: "source-lifecycle",
            engine_id: "prowler",
        }];
        let (handle, bundle) = bindings.reserve_checkout_demands(&demand, now).unwrap();
        assert!(matches!(
            bindings.install(
                aws_test_request("case-lifecycle", "source-lifecycle", 1, now),
                now
            ),
            Err(AppError::NotAuthorized(_))
        ));
        assert!(matches!(
            bindings.revoke_source("case-lifecycle", "source-lifecycle", now),
            Err(AppError::NotAuthorized(_))
        ));
        assert!(
            bindings
                .receipts
                .lock()
                .unwrap()
                .get(&("case-lifecycle".into(), "source-lifecycle".into()))
                .unwrap()
                .receipt
                .capability_generation
                == original_generation
        );
        bindings.release_checkout_reservation(&handle).unwrap();
        drop(bundle);
        bindings
            .install(
                aws_test_request("case-lifecycle", "source-lifecycle", 1, now),
                now,
            )
            .unwrap();
        let replacement_generation = bindings
            .receipts
            .lock()
            .unwrap()
            .get(&("case-lifecycle".into(), "source-lifecycle".into()))
            .unwrap()
            .receipt
            .capability_generation;
        assert!(original_generation != replacement_generation);
        bindings
            .revoke_source("case-lifecycle", "source-lifecycle", now)
            .unwrap();
    }

    #[test]
    fn failed_expired_commit_atomically_releases_and_exhausted_tombstones_reinstall_revoke_purge() {
        let now = Utc::now();
        let bindings = SourceAuthorizationBindings::default();
        install_aws_test_binding(&bindings, "case-expiry", "source-expiry", 1, now);
        let expiry_generation = bindings
            .receipts
            .lock()
            .unwrap()
            .get(&("case-expiry".into(), "source-expiry".into()))
            .unwrap()
            .receipt
            .capability_generation;
        let expiry_demand = [SourceCheckoutDemand {
            case_id: "case-expiry",
            source_id: "source-expiry",
            engine_id: "prowler",
        }];
        let (expired_handle, expired_bundle) = bindings
            .reserve_checkout_demands(&expiry_demand, now)
            .unwrap();
        assert!(matches!(
            bindings.commit_checkout_reservation(&expired_handle, now + Duration::minutes(31)),
            Err(AppError::NotAuthorized(_))
        ));
        assert!(bindings.reservations.lock().unwrap().is_empty());
        assert_eq!(
            bindings
                .vault
                .entries
                .lock()
                .unwrap()
                .get(&expiry_generation.0)
                .unwrap()
                .reserved_checkouts,
            0
        );
        drop(expired_bundle);

        install_aws_test_binding(&bindings, "case-tombstone", "source-tombstone", 1, now);
        let tombstone_demand = [SourceCheckoutDemand {
            case_id: "case-tombstone",
            source_id: "source-tombstone",
            engine_id: "prowler",
        }];
        let (handle, bundle) = bindings
            .reserve_checkout_demands(&tombstone_demand, now)
            .unwrap();
        bindings.commit_checkout_reservation(&handle, now).unwrap();
        drop(bundle);
        bindings
            .install(
                aws_test_request("case-tombstone", "source-tombstone", 1, now),
                now,
            )
            .unwrap();
        bindings
            .revoke_source("case-tombstone", "source-tombstone", now)
            .unwrap();

        install_aws_test_binding(&bindings, "case-purge", "source-purge", 1, now);
        let purge_demand = [SourceCheckoutDemand {
            case_id: "case-purge",
            source_id: "source-purge",
            engine_id: "prowler",
        }];
        let (purge_handle, purge_bundle) = bindings
            .reserve_checkout_demands(&purge_demand, now)
            .unwrap();
        bindings
            .commit_checkout_reservation(&purge_handle, now)
            .unwrap();
        drop(purge_bundle);
        bindings.purge_expired(now + Duration::minutes(31)).unwrap();
        assert!(
            bindings
                .status("case-purge", "source-purge", now + Duration::minutes(31))
                .unwrap()
                .is_none()
        );
    }

    #[test]
    fn purge_preserves_unexpired_reservation_then_invalidates_expired_batch_atomically() {
        let now = Utc::now();
        let later = now + Duration::minutes(15);
        let bindings = SourceAuthorizationBindings::default();
        install_aws_test_binding(&bindings, "case-purge-batch", "source-early", 1, now);
        install_aws_test_binding(&bindings, "case-purge-batch", "source-late", 1, later);
        let demands = [
            SourceCheckoutDemand {
                case_id: "case-purge-batch",
                source_id: "source-early",
                engine_id: "prowler",
            },
            SourceCheckoutDemand {
                case_id: "case-purge-batch",
                source_id: "source-late",
                engine_id: "prowler",
            },
        ];
        let (handle, bundle) = bindings.reserve_checkout_demands(&demands, later).unwrap();

        assert_eq!(bindings.purge_expired(later).unwrap(), 0);
        assert!(
            bindings
                .reservations
                .lock()
                .unwrap()
                .contains_key(&handle.0)
        );
        assert!(matches!(
            bindings.checkout("case-purge-batch", "source-late", "prowler", later),
            Err(AppError::NotAuthorized(_))
        ));

        bindings.purge_expired(now + Duration::minutes(31)).unwrap();
        assert!(
            !bindings
                .reservations
                .lock()
                .unwrap()
                .contains_key(&handle.0)
        );
        assert!(
            bindings
                .status(
                    "case-purge-batch",
                    "source-early",
                    now + Duration::minutes(31)
                )
                .unwrap()
                .is_none()
        );
        bindings
            .checkout(
                "case-purge-batch",
                "source-late",
                "prowler",
                now + Duration::minutes(31),
            )
            .unwrap();
        drop(bundle);
    }

    #[test]
    fn binding_snapshot_is_nonsecret_redacted_and_distinguishes_missing_binding() {
        let now = Utc::now();
        let bindings = SourceAuthorizationBindings::default();
        assert!(
            bindings
                .binding_snapshot("case-missing", "source-missing", now)
                .unwrap()
                .is_none()
        );
        assert!(matches!(
            bindings.binding_snapshot("bad/case", "source-missing", now),
            Err(SourceCheckoutPreflightFailure::Internal)
        ));

        install_aws_test_binding(&bindings, "case-snapshot", "source-snapshot", 1, now);
        let snapshot = bindings
            .binding_snapshot("case-snapshot", "source-snapshot", now)
            .unwrap()
            .unwrap();
        assert_eq!(
            format!("{snapshot:?}"),
            "SourceAuthorizationBindingSnapshot([REDACTED])"
        );
        assert_eq!(snapshot.authorization().case_id, "case-snapshot");
        assert_eq!(snapshot.authorization().source_id, "source-snapshot");
        assert!(
            snapshot
                .authorization()
                .allowed_engine_ids
                .contains("prowler")
        );
    }

    #[test]
    fn bound_reservation_rejects_reinstalled_generation_without_reserving_replacement() {
        let now = Utc::now();
        let bindings = SourceAuthorizationBindings::default();
        install_aws_test_binding(&bindings, "case-bound-race", "source-bound-race", 1, now);
        let old_snapshot = bindings
            .binding_snapshot("case-bound-race", "source-bound-race", now)
            .unwrap()
            .unwrap();
        let old_generation = old_snapshot.capability_generation;

        bindings
            .install(
                aws_test_request("case-bound-race", "source-bound-race", 1, now),
                now,
            )
            .unwrap();
        let new_generation = bindings
            .receipts
            .lock()
            .unwrap()
            .get(&("case-bound-race".into(), "source-bound-race".into()))
            .unwrap()
            .receipt
            .capability_generation;
        assert!(old_generation != new_generation);

        let demand = [BoundSourceCheckoutDemand {
            case_id: "case-bound-race",
            source_id: "source-bound-race",
            engine_id: "prowler",
            binding: &old_snapshot,
        }];
        assert!(matches!(
            bindings.validate_bound_checkout_demands(&demand, now),
            Err(SourceCheckoutPreflightFailure::BindingMismatch)
        ));
        assert!(matches!(
            bindings.reserve_bound_checkout_demands(&demand, now),
            Err(SourceCheckoutPreflightFailure::BindingMismatch)
        ));
        assert!(bindings.reservations.lock().unwrap().is_empty());
        assert_eq!(
            bindings
                .vault
                .entries
                .lock()
                .unwrap()
                .get(&new_generation.0)
                .unwrap()
                .reserved_checkouts,
            0
        );
    }

    #[test]
    fn bound_reservation_succeeds_with_duplicate_preserving_owned_credentials() {
        let now = Utc::now();
        let bindings = SourceAuthorizationBindings::default();
        install_aws_test_binding(
            &bindings,
            "case-bound-success",
            "source-bound-success",
            2,
            now,
        );
        let snapshot = bindings
            .binding_snapshot("case-bound-success", "source-bound-success", now)
            .unwrap()
            .unwrap();
        let demands = [
            BoundSourceCheckoutDemand {
                case_id: "case-bound-success",
                source_id: "source-bound-success",
                engine_id: "prowler",
                binding: &snapshot,
            },
            BoundSourceCheckoutDemand {
                case_id: "case-bound-success",
                source_id: "source-bound-success",
                engine_id: "prowler",
                binding: &snapshot,
            },
        ];
        bindings
            .validate_bound_checkout_demands(&demands, now)
            .unwrap();
        let (handle, mut credentials) = bindings
            .reserve_bound_checkout_demands(&demands, now)
            .unwrap();
        assert_eq!(credentials.remaining(), 2);
        credentials
            .take("case-bound-success", "source-bound-success", "prowler")
            .unwrap();
        credentials
            .take("case-bound-success", "source-bound-success", "prowler")
            .unwrap();
        assert_eq!(credentials.remaining(), 0);
        bindings.release_checkout_reservation(&handle).unwrap();
    }

    #[test]
    fn bound_preflight_classifies_expiry_exhaustion_and_capacity_without_strings() {
        let now = Utc::now();

        let expiry_bindings = SourceAuthorizationBindings::default();
        install_aws_test_binding(
            &expiry_bindings,
            "case-bound-expiry",
            "source-bound-expiry",
            1,
            now,
        );
        let expiry_snapshot = expiry_bindings
            .binding_snapshot("case-bound-expiry", "source-bound-expiry", now)
            .unwrap()
            .unwrap();
        let expiry_demand = [BoundSourceCheckoutDemand {
            case_id: "case-bound-expiry",
            source_id: "source-bound-expiry",
            engine_id: "prowler",
            binding: &expiry_snapshot,
        }];
        assert_eq!(
            expiry_bindings
                .validate_bound_checkout_demands(&expiry_demand, now + Duration::minutes(31)),
            Err(SourceCheckoutPreflightFailure::CapabilityUnavailable)
        );
        assert!(matches!(
            expiry_bindings.binding_snapshot(
                "case-bound-expiry",
                "source-bound-expiry",
                now + Duration::minutes(31)
            ),
            Err(SourceCheckoutPreflightFailure::CapabilityUnavailable)
        ));

        let exhausted_bindings = SourceAuthorizationBindings::default();
        install_aws_test_binding(
            &exhausted_bindings,
            "case-bound-exhausted",
            "source-bound-exhausted",
            1,
            now,
        );
        exhausted_bindings
            .checkout(
                "case-bound-exhausted",
                "source-bound-exhausted",
                "prowler",
                now,
            )
            .unwrap();
        assert!(matches!(
            exhausted_bindings.binding_snapshot(
                "case-bound-exhausted",
                "source-bound-exhausted",
                now
            ),
            Err(SourceCheckoutPreflightFailure::CapabilityUnavailable)
        ));

        let capacity_bindings = SourceAuthorizationBindings::default();
        install_aws_test_binding(
            &capacity_bindings,
            "case-bound-capacity",
            "source-bound-capacity",
            1,
            now,
        );
        let capacity_snapshot = capacity_bindings
            .binding_snapshot("case-bound-capacity", "source-bound-capacity", now)
            .unwrap()
            .unwrap();
        let capacity_demands = [
            BoundSourceCheckoutDemand {
                case_id: "case-bound-capacity",
                source_id: "source-bound-capacity",
                engine_id: "prowler",
                binding: &capacity_snapshot,
            },
            BoundSourceCheckoutDemand {
                case_id: "case-bound-capacity",
                source_id: "source-bound-capacity",
                engine_id: "prowler",
                binding: &capacity_snapshot,
            },
        ];
        assert_eq!(
            capacity_bindings.validate_bound_checkout_demands(&capacity_demands, now),
            Err(SourceCheckoutPreflightFailure::CapabilityUnavailable)
        );
        assert!(matches!(
            capacity_bindings.reserve_bound_checkout_demands(&capacity_demands, now),
            Err(SourceCheckoutPreflightFailure::CapabilityUnavailable)
        ));
        assert!(capacity_bindings.reservations.lock().unwrap().is_empty());
    }

    #[test]
    fn bound_preflight_classifies_coordinate_profile_engine_and_internal_invariants() {
        let now = Utc::now();
        let bindings = SourceAuthorizationBindings::default();
        install_aws_test_binding(&bindings, "case-bound-types", "source-bound-types", 2, now);
        let snapshot = bindings
            .binding_snapshot("case-bound-types", "source-bound-types", now)
            .unwrap()
            .unwrap();

        let wrong_engine = [BoundSourceCheckoutDemand {
            case_id: "case-bound-types",
            source_id: "source-bound-types",
            engine_id: "scoutsuite",
            binding: &snapshot,
        }];
        assert_eq!(
            bindings.validate_bound_checkout_demands(&wrong_engine, now),
            Err(SourceCheckoutPreflightFailure::BindingMismatch)
        );
        let wrong_source = [BoundSourceCheckoutDemand {
            case_id: "case-bound-types",
            source_id: "source-other",
            engine_id: "prowler",
            binding: &snapshot,
        }];
        assert_eq!(
            bindings.validate_bound_checkout_demands(&wrong_source, now),
            Err(SourceCheckoutPreflightFailure::BindingMismatch)
        );

        let mut altered_profile = snapshot.clone();
        altered_profile.authorization.profile =
            ProviderSourceProfile::AzureTenantReadOnlyAccessToken;
        let wrong_profile = [BoundSourceCheckoutDemand {
            case_id: "case-bound-types",
            source_id: "source-bound-types",
            engine_id: "prowler",
            binding: &altered_profile,
        }];
        assert_eq!(
            bindings.validate_bound_checkout_demands(&wrong_profile, now),
            Err(SourceCheckoutPreflightFailure::BindingMismatch)
        );

        let mut altered_permissions = snapshot.clone();
        altered_permissions.authorization.permissions.pop();
        let wrong_permissions = [BoundSourceCheckoutDemand {
            case_id: "case-bound-types",
            source_id: "source-bound-types",
            engine_id: "prowler",
            binding: &altered_permissions,
        }];
        assert_eq!(
            bindings.validate_bound_checkout_demands(&wrong_permissions, now),
            Err(SourceCheckoutPreflightFailure::BindingMismatch)
        );

        let generation = snapshot.capability_generation;
        bindings
            .vault
            .entries
            .lock()
            .unwrap()
            .get_mut(&generation.0)
            .unwrap()
            .reserved_checkouts = 1;
        let valid_shape = [BoundSourceCheckoutDemand {
            case_id: "case-bound-types",
            source_id: "source-bound-types",
            engine_id: "prowler",
            binding: &snapshot,
        }];
        assert_eq!(
            bindings.validate_bound_checkout_demands(&valid_shape, now),
            Err(SourceCheckoutPreflightFailure::Internal)
        );
    }
}
