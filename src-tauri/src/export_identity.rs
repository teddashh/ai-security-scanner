use crate::error::{AppError, AppResult};
use base64::Engine as _;
use base64::engine::general_purpose::STANDARD as BASE64;
use chrono::{DateTime, Utc};
use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::fs::{self, File, OpenOptions};
use std::io::{self, Read, Write};
use std::path::{Path, PathBuf};
use zeroize::{Zeroize, Zeroizing};

pub const LOCAL_SIGNING_IDENTITY_SCHEMA_VERSION: &str = "1";
const LOCAL_SIGNING_IDENTITY_ANCHOR_SCHEMA_VERSION: &str = "1";
const LOCAL_SIGNING_ROTATION_INTENT_SCHEMA_VERSION: &str = "1";
const IDENTITY_ALGORITHM: &str = "Ed25519";
const MAX_IDENTITY_DOCUMENT_BYTES: u64 = 64 * 1024;
const MAX_ROTATION_INTENT_BYTES: u64 = 160 * 1024;
const MAX_IDENTITY_DEPTH: usize = 8;
const IDENTITY_NOTICE: &str = "This is a local export-integrity identity. It does not prove scanner correctness, completeness, authorship, organizational identity, audit status, or compliance.";

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum SigningIdentityContinuityEvent {
    Generated,
    LegacyKeyAdopted,
    RotatedAfterConfirmedKeyLoss,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct LocalSigningIdentityDocument {
    pub schema_version: String,
    pub algorithm: String,
    pub key_id: String,
    pub public_key_base64: String,
    pub established_at: DateTime<Utc>,
    pub continuity_event: SigningIdentityContinuityEvent,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub previous_identity: Option<Box<LocalSigningIdentityDocument>>,
    pub self_signature_base64: String,
    pub notice: String,
}

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct LocalSigningIdentitySummary {
    pub algorithm: String,
    pub key_id: String,
    pub public_key_base64: String,
    pub established_at: DateTime<Utc>,
    pub continuity_event: SigningIdentityContinuityEvent,
    pub previous_key_id: Option<String>,
    pub notice: String,
}

/// A second, owner-only continuity record deliberately stored separately from
/// the user-facing identity document. Deleting the document therefore cannot
/// make a key that was already managed look like an unclaimed legacy key.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
struct LocalSigningIdentityAnchor {
    schema_version: String,
    identity_document_sha256: String,
    identity: LocalSigningIdentityDocument,
}

/// Durable two-phase rotation record. It is itself a strict owner-only secret
/// file, allowing an interrupted rotation to recover the exact candidate
/// rather than silently blessing whichever private key later appears at the
/// primary path.
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct LocalSigningRotationIntent {
    schema_version: String,
    acknowledged_previous_key_id: String,
    previous_identity_sha256: String,
    candidate_key_id: String,
    candidate_public_key_base64: String,
    candidate_private_key_base64: String,
    candidate_identity_sha256: String,
    candidate_identity: LocalSigningIdentityDocument,
}

impl Drop for LocalSigningRotationIntent {
    fn drop(&mut self) {
        self.candidate_private_key_base64.zeroize();
    }
}

#[derive(Serialize)]
struct UnsignedIdentityDocument<'a> {
    schema_version: &'a str,
    algorithm: &'a str,
    key_id: &'a str,
    public_key_base64: &'a str,
    established_at: DateTime<Utc>,
    continuity_event: SigningIdentityContinuityEvent,
    previous_identity: &'a Option<Box<LocalSigningIdentityDocument>>,
    notice: &'a str,
}

pub(crate) struct LocalSigningIdentity {
    pub signing_key: SigningKey,
    pub document: LocalSigningIdentityDocument,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum SigningKeyProtection {
    Managed,
    ExactLegacy,
}

struct SigningKeyRecord {
    signing_key: SigningKey,
    protection: SigningKeyProtection,
    file: File,
}

pub fn ensure_local_signing_identity(
    signing_key_path: impl AsRef<Path>,
) -> AppResult<LocalSigningIdentitySummary> {
    let signing_key_path = signing_key_path.as_ref();
    let identity = load_or_create_local_signing_identity(signing_key_path)?;
    Ok(summary(&identity.document))
}

pub(crate) fn load_or_create_local_signing_identity(
    signing_key_path: &Path,
) -> AppResult<LocalSigningIdentity> {
    if let Some(parent) = signing_key_path
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
    {
        fs::create_dir_all(parent)?;
    }
    let identity_path = signing_identity_document_path(signing_key_path);
    let anchor_path = signing_identity_anchor_path(signing_key_path);
    if let Some(intent) =
        read_rotation_intent_if_present(&signing_rotation_intent_path(signing_key_path))?
    {
        return Err(AppError::NotAvailable(format!(
            "local export-integrity identity rotation from {} to {} is incomplete; rerun the explicit rotation command with the same acknowledged lost key ID",
            intent.acknowledged_previous_key_id, intent.candidate_key_id
        )));
    }

    let existing_document = read_identity_document_if_present(&identity_path)?;
    let existing_anchor = read_identity_anchor_if_present(&anchor_path)?;
    if let (Some(document), Some(anchor)) = (&existing_document, &existing_anchor) {
        ensure_anchor_matches_identity(anchor, document)?;
    }
    let key = read_signing_key_record_if_present(signing_key_path)?;

    match (existing_document, existing_anchor, key) {
        (Some(document), anchor, Some(key)) => {
            let anchor = match anchor {
                Some(anchor) => anchor,
                None => {
                    let anchor = identity_anchor(&document)?;
                    create_identity_anchor(&anchor_path, &anchor)?;
                    anchor
                }
            };
            finish_loaded_identity(key, document, &anchor)
        }
        (Some(document), _, None) => Err(missing_key_error(signing_key_path, &document.key_id)),
        (None, Some(anchor), Some(key))
            if key.protection == SigningKeyProtection::Managed
                && signing_key_matches_identity(&key.signing_key, &anchor.identity) =>
        {
            // A managed key can only become visible after its anchor and
            // public document were made durable. If the public copy is later
            // lost, the protected anchor therefore proves the exact document
            // that belongs to this exact managed private key. Recreate only
            // that byte-equivalent document; never infer or rotate identity.
            let identity =
                finish_loaded_identity(key, anchor.identity.clone(), &anchor)?;
            create_identity_document(&identity_path, &identity.document)?;
            Ok(identity)
        }
        (None, Some(anchor), Some(key))
            if key.protection == SigningKeyProtection::ExactLegacy
                && anchor.identity.continuity_event
                    == SigningIdentityContinuityEvent::LegacyKeyAdopted
                && signing_key_matches_identity(&key.signing_key, &anchor.identity) =>
        {
            // The anchor is written before the public document during legacy
            // adoption. This exact state is the only missing-document recovery
            // that may finish automatically, and the key is still provably the
            // bounded N-1 predecessor.
            create_identity_document(&identity_path, &anchor.identity)?;
            finish_loaded_identity(key, anchor.identity.clone(), &anchor)
        }
        (None, Some(anchor), Some(_)) => Err(AppError::NotAuthorized(format!(
            "local export-integrity identity document is missing and the retained private key does not exactly match the protected continuity anchor for key {}; the document will not be reconstructed",
            anchor.identity.key_id
        ))),
        (None, Some(anchor), None) => {
            Err(missing_key_error(signing_key_path, &anchor.identity.key_id))
        }
        (None, None, Some(key)) if key.protection == SigningKeyProtection::ExactLegacy => {
            let document = signed_identity_document(
                &key.signing_key,
                SigningIdentityContinuityEvent::LegacyKeyAdopted,
                None,
                Utc::now(),
            )?;
            let anchor = identity_anchor(&document)?;
            // Anchor first and key hardening last make every interruption
            // distinguishable from a never-adopted legacy key.
            create_identity_anchor(&anchor_path, &anchor)?;
            create_identity_document(&identity_path, &document)?;
            finish_loaded_identity(key, document, &anchor)
        }
        (None, None, Some(_)) => Err(AppError::NotAuthorized(
            "local export-integrity identity document and continuity anchor are missing for a managed private key; the key will not be silently adopted".into(),
        )),
        (None, None, None) => {
            let mut secret = [0_u8; 32];
            getrandom::fill(&mut secret).map_err(|error| {
                AppError::Internal(format!("could not generate local signing key: {error}"))
            })?;
            let signing_key = SigningKey::from_bytes(&secret);
            let document = signed_identity_document(
                &signing_key,
                SigningIdentityContinuityEvent::Generated,
                None,
                Utc::now(),
            )?;
            let anchor = identity_anchor(&document)?;
            // Public continuity is durable before the private key becomes
            // visible. If creation is interrupted, the exact lost identity is
            // known and cannot be replaced implicitly.
            create_identity_anchor(&anchor_path, &anchor)?;
            create_identity_document(&identity_path, &document)?;
            let write_result = write_private_new_file(signing_key_path, &secret);
            secret.zeroize();
            write_result?;
            let key = read_signing_key_record_if_present(signing_key_path)?.ok_or_else(|| {
                AppError::Internal("new local signing key was not persisted".into())
            })?;
            finish_loaded_identity(key, document, &anchor)
        }
    }
}

/// Establish a new local signer only after the caller confirms the exact lost
/// key ID from the still-verifiable public identity document. Existing private
/// keys are never overwritten. A retry may finish a prior interrupted rotation
/// when the new strict private key already exists but the old public identity
/// is still current.
pub fn rotate_local_signing_identity_after_confirmed_loss(
    signing_key_path: impl AsRef<Path>,
    acknowledged_lost_key_id: &str,
) -> AppResult<LocalSigningIdentitySummary> {
    let signing_key_path = signing_key_path.as_ref();
    let identity_path = signing_identity_document_path(signing_key_path);
    let anchor_path = signing_identity_anchor_path(signing_key_path);
    let intent_path = signing_rotation_intent_path(signing_key_path);
    let intent = match read_rotation_intent_if_present(&intent_path)? {
        Some(intent) => {
            let previous = intent
                .candidate_identity
                .previous_identity
                .as_deref()
                .cloned()
                .ok_or_else(|| {
                    AppError::NotAuthorized(
                        "rotation intent candidate has no predecessor identity".into(),
                    )
                })?;
            validate_rotation_intent(&intent, &previous, acknowledged_lost_key_id)?;
            intent
        }
        None => {
            let previous = durable_identity_for_rotation(&identity_path, &anchor_path)?;
            if previous.key_id != acknowledged_lost_key_id {
                return Err(AppError::InvalidRequest(format!(
                    "acknowledged lost key ID does not match the durable identity; expected {}",
                    previous.key_id
                )));
            }
            if identity_depth(&previous) >= MAX_IDENTITY_DEPTH {
                return Err(AppError::NotAvailable(
                    "local signing identity history reached its bounded depth; retain the existing identity document and obtain specialist review before another rotation".into(),
                ));
            }
            if let Some(existing) = read_signing_key_record_if_present(signing_key_path)? {
                let observed = key_id(&existing.signing_key.verifying_key());
                if observed == previous.key_id {
                    return Err(AppError::InvalidRequest(
                        "the acknowledged signing key is still present and valid; rotation was not performed"
                            .into(),
                    ));
                }
                return Err(AppError::NotAuthorized(format!(
                    "private key {} does not match the durable identity and no rotation intent binds it; the mismatching key will not be endorsed",
                    observed
                )));
            }
            let intent = new_rotation_intent(previous)?;
            create_rotation_intent(&intent_path, &intent)?;
            intent
        }
    };
    finish_rotation(
        signing_key_path,
        &identity_path,
        &anchor_path,
        &intent_path,
        intent,
    )
}

pub fn signing_identity_document_path(signing_key_path: &Path) -> PathBuf {
    let mut path = signing_key_path.as_os_str().to_os_string();
    path.push(".identity.json");
    PathBuf::from(path)
}

fn signing_identity_anchor_path(signing_key_path: &Path) -> PathBuf {
    path_with_suffix(signing_key_path, ".identity-anchor.json")
}

fn signing_rotation_intent_path(signing_key_path: &Path) -> PathBuf {
    path_with_suffix(signing_key_path, ".rotation-intent.json")
}

fn path_with_suffix(path: &Path, suffix: &str) -> PathBuf {
    let mut result = path.as_os_str().to_os_string();
    result.push(suffix);
    PathBuf::from(result)
}

fn identity_document_sha256(document: &LocalSigningIdentityDocument) -> AppResult<String> {
    Ok(hex::encode(Sha256::digest(serde_json::to_vec(document)?)))
}

fn identity_anchor(
    document: &LocalSigningIdentityDocument,
) -> AppResult<LocalSigningIdentityAnchor> {
    verify_identity_document(document, 1)?;
    Ok(LocalSigningIdentityAnchor {
        schema_version: LOCAL_SIGNING_IDENTITY_ANCHOR_SCHEMA_VERSION.into(),
        identity_document_sha256: identity_document_sha256(document)?,
        identity: document.clone(),
    })
}

fn validate_identity_anchor(anchor: &LocalSigningIdentityAnchor) -> AppResult<()> {
    if anchor.schema_version != LOCAL_SIGNING_IDENTITY_ANCHOR_SCHEMA_VERSION {
        return Err(AppError::InvalidRequest(
            "local signing identity anchor has an unsupported schema".into(),
        ));
    }
    verify_identity_document(&anchor.identity, 1)?;
    if anchor.identity_document_sha256 != identity_document_sha256(&anchor.identity)? {
        return Err(AppError::NotAuthorized(
            "local signing identity anchor digest does not match its identity".into(),
        ));
    }
    Ok(())
}

fn ensure_anchor_matches_identity(
    anchor: &LocalSigningIdentityAnchor,
    identity: &LocalSigningIdentityDocument,
) -> AppResult<()> {
    validate_identity_anchor(anchor)?;
    verify_identity_document(identity, 1)?;
    if anchor.identity != *identity
        || anchor.identity_document_sha256 != identity_document_sha256(identity)?
    {
        return Err(AppError::NotAuthorized(
            "local signing identity document does not match its durable continuity anchor".into(),
        ));
    }
    Ok(())
}

fn signing_key_matches_identity(
    signing_key: &SigningKey,
    identity: &LocalSigningIdentityDocument,
) -> bool {
    let verifying_key = signing_key.verifying_key();
    identity.key_id == key_id(&verifying_key)
        && identity.public_key_base64 == BASE64.encode(verifying_key.as_bytes())
}

fn finish_loaded_identity(
    key: SigningKeyRecord,
    document: LocalSigningIdentityDocument,
    anchor: &LocalSigningIdentityAnchor,
) -> AppResult<LocalSigningIdentity> {
    ensure_anchor_matches_identity(anchor, &document)?;
    if !signing_key_matches_identity(&key.signing_key, &document) {
        return Err(AppError::NotAuthorized(
            "local export-integrity key does not match its durable public identity; explicit recovery is required".into(),
        ));
    }
    if key.protection == SigningKeyProtection::ExactLegacy {
        harden_exact_legacy_signing_key(&key.file)?;
    }
    verify_managed_signing_key_file(&key.file, 32)?;
    Ok(LocalSigningIdentity {
        signing_key: key.signing_key,
        document,
    })
}

fn missing_key_error(_path: &Path, key_id: &str) -> AppError {
    AppError::NotAvailable(format!(
        "local export-integrity private key is missing; it cannot be recreated without changing signer identity. Use the explicit identity-rotation command and acknowledge this exact lost key ID: {}",
        key_id
    ))
}

fn durable_identity_for_rotation(
    identity_path: &Path,
    anchor_path: &Path,
) -> AppResult<LocalSigningIdentityDocument> {
    let identity = read_identity_document_if_present(identity_path)?;
    let anchor = read_identity_anchor_if_present(anchor_path)?;
    match (identity, anchor) {
        (Some(identity), Some(anchor)) => {
            ensure_anchor_matches_identity(&anchor, &identity)?;
            Ok(identity)
        }
        (Some(identity), None) => {
            let anchor = identity_anchor(&identity)?;
            create_identity_anchor(anchor_path, &anchor)?;
            Ok(identity)
        }
        (None, Some(anchor)) => {
            validate_identity_anchor(&anchor)?;
            Ok(anchor.identity)
        }
        (None, None) => Err(AppError::InvalidRequest(
            "local signing identity rotation requires an existing durable public identity or continuity anchor".into(),
        )),
    }
}

fn new_rotation_intent(
    previous: LocalSigningIdentityDocument,
) -> AppResult<LocalSigningRotationIntent> {
    let mut secret = [0_u8; 32];
    getrandom::fill(&mut secret).map_err(|error| {
        AppError::Internal(format!(
            "could not generate rotation candidate key: {error}"
        ))
    })?;
    let signing_key = SigningKey::from_bytes(&secret);
    let candidate_identity = signed_identity_document(
        &signing_key,
        SigningIdentityContinuityEvent::RotatedAfterConfirmedKeyLoss,
        Some(Box::new(previous.clone())),
        Utc::now(),
    )?;
    let intent = LocalSigningRotationIntent {
        schema_version: LOCAL_SIGNING_ROTATION_INTENT_SCHEMA_VERSION.into(),
        acknowledged_previous_key_id: previous.key_id.clone(),
        previous_identity_sha256: identity_document_sha256(&previous)?,
        candidate_key_id: candidate_identity.key_id.clone(),
        candidate_public_key_base64: candidate_identity.public_key_base64.clone(),
        candidate_private_key_base64: BASE64.encode(secret),
        candidate_identity_sha256: identity_document_sha256(&candidate_identity)?,
        candidate_identity,
    };
    secret.zeroize();
    validate_rotation_intent(&intent, &previous, &previous.key_id)?;
    Ok(intent)
}

fn rotation_intent_signing_key(intent: &LocalSigningRotationIntent) -> AppResult<SigningKey> {
    let mut decoded = Zeroizing::new(
        BASE64
            .decode(&intent.candidate_private_key_base64)
            .map_err(|error| {
                AppError::InvalidRequest(format!(
                    "rotation intent candidate key is invalid base64: {error}"
                ))
            })?,
    );
    let mut secret = [0_u8; 32];
    if decoded.len() != secret.len() {
        return Err(AppError::InvalidRequest(
            "rotation intent candidate key must contain exactly 32 bytes".into(),
        ));
    }
    secret.copy_from_slice(&decoded);
    decoded.zeroize();
    let key = SigningKey::from_bytes(&secret);
    secret.zeroize();
    Ok(key)
}

fn validate_rotation_intent(
    intent: &LocalSigningRotationIntent,
    previous: &LocalSigningIdentityDocument,
    acknowledged_lost_key_id: &str,
) -> AppResult<()> {
    if intent.schema_version != LOCAL_SIGNING_ROTATION_INTENT_SCHEMA_VERSION
        || intent.acknowledged_previous_key_id != acknowledged_lost_key_id
        || previous.key_id != acknowledged_lost_key_id
        || intent.previous_identity_sha256 != identity_document_sha256(previous)?
    {
        return Err(AppError::NotAuthorized(
            "rotation intent does not match the exact acknowledged predecessor identity".into(),
        ));
    }
    verify_identity_document(previous, 1)?;
    verify_identity_document(&intent.candidate_identity, 1)?;
    if intent.candidate_identity.continuity_event
        != SigningIdentityContinuityEvent::RotatedAfterConfirmedKeyLoss
        || intent.candidate_identity.previous_identity.as_deref() != Some(previous)
        || intent.candidate_key_id != intent.candidate_identity.key_id
        || intent.candidate_public_key_base64 != intent.candidate_identity.public_key_base64
        || intent.candidate_identity_sha256 != identity_document_sha256(&intent.candidate_identity)?
    {
        return Err(AppError::NotAuthorized(
            "rotation intent candidate is not exactly bound to its predecessor identity".into(),
        ));
    }
    let signing_key = rotation_intent_signing_key(intent)?;
    if !signing_key_matches_identity(&signing_key, &intent.candidate_identity) {
        return Err(AppError::NotAuthorized(
            "rotation intent candidate private key does not match its bound public identity".into(),
        ));
    }
    Ok(())
}

fn finish_rotation(
    signing_key_path: &Path,
    identity_path: &Path,
    anchor_path: &Path,
    intent_path: &Path,
    intent: LocalSigningRotationIntent,
) -> AppResult<LocalSigningIdentitySummary> {
    let previous = intent
        .candidate_identity
        .previous_identity
        .as_deref()
        .cloned()
        .ok_or_else(|| {
            AppError::NotAuthorized("rotation intent candidate has no predecessor".into())
        })?;
    validate_rotation_intent(&intent, &previous, &intent.acknowledged_previous_key_id)?;
    let candidate_key = rotation_intent_signing_key(&intent)?;
    match read_signing_key_record_if_present(signing_key_path)? {
        Some(existing)
            if existing.protection == SigningKeyProtection::Managed
                && signing_key_matches_identity(
                    &existing.signing_key,
                    &intent.candidate_identity,
                ) => {}
        Some(existing) => {
            return Err(AppError::NotAuthorized(format!(
                "primary signing key {} is not the exact managed candidate bound by the durable rotation intent",
                key_id(&existing.signing_key.verifying_key())
            )));
        }
        None => {
            let mut secret = candidate_key.to_bytes();
            let result = write_private_new_file(signing_key_path, &secret);
            secret.zeroize();
            result?;
        }
    }

    match read_identity_document_if_present(identity_path)? {
        Some(current) if current == intent.candidate_identity => {}
        Some(current) if current == previous => {
            replace_identity_document(identity_path, &intent.candidate_identity)?;
        }
        None => create_identity_document(identity_path, &intent.candidate_identity)?,
        Some(_) => {
            return Err(AppError::NotAuthorized(
                "public identity is neither the rotation predecessor nor its bound candidate"
                    .into(),
            ));
        }
    }

    let candidate_anchor = identity_anchor(&intent.candidate_identity)?;
    match read_identity_anchor_if_present(anchor_path)? {
        Some(current) if current == candidate_anchor => {}
        Some(current) if current.identity == previous => {
            replace_identity_anchor(anchor_path, &candidate_anchor)?;
        }
        None => create_identity_anchor(anchor_path, &candidate_anchor)?,
        Some(_) => {
            return Err(AppError::NotAuthorized(
                "continuity anchor is neither the rotation predecessor nor its bound candidate"
                    .into(),
            ));
        }
    }

    let key = read_signing_key_record_if_present(signing_key_path)?
        .ok_or_else(|| AppError::Internal("rotated signing key was not persisted".into()))?;
    let identity = read_identity_document_if_present(identity_path)?
        .ok_or_else(|| AppError::Internal("rotated public identity was not persisted".into()))?;
    let anchor = read_identity_anchor_if_present(anchor_path)?
        .ok_or_else(|| AppError::Internal("rotated continuity anchor was not persisted".into()))?;
    if key.protection != SigningKeyProtection::Managed
        || !signing_key_matches_identity(&key.signing_key, &identity)
        || identity != intent.candidate_identity
    {
        return Err(AppError::NotAuthorized(
            "rotated signing identity failed its exact readback".into(),
        ));
    }
    ensure_anchor_matches_identity(&anchor, &identity)?;
    remove_managed_private_file(intent_path)?;
    Ok(summary(&identity))
}

fn summary(document: &LocalSigningIdentityDocument) -> LocalSigningIdentitySummary {
    LocalSigningIdentitySummary {
        algorithm: document.algorithm.clone(),
        key_id: document.key_id.clone(),
        public_key_base64: document.public_key_base64.clone(),
        established_at: document.established_at,
        continuity_event: document.continuity_event,
        previous_key_id: document
            .previous_identity
            .as_ref()
            .map(|previous| previous.key_id.clone()),
        notice: document.notice.clone(),
    }
}

fn signed_identity_document(
    signing_key: &SigningKey,
    continuity_event: SigningIdentityContinuityEvent,
    previous_identity: Option<Box<LocalSigningIdentityDocument>>,
    established_at: DateTime<Utc>,
) -> AppResult<LocalSigningIdentityDocument> {
    let public_key = signing_key.verifying_key();
    let mut document = LocalSigningIdentityDocument {
        schema_version: LOCAL_SIGNING_IDENTITY_SCHEMA_VERSION.into(),
        algorithm: IDENTITY_ALGORITHM.into(),
        key_id: key_id(&public_key),
        public_key_base64: BASE64.encode(public_key.as_bytes()),
        established_at,
        continuity_event,
        previous_identity,
        self_signature_base64: String::new(),
        notice: IDENTITY_NOTICE.into(),
    };
    validate_identity_event_shape(&document)?;
    let payload = identity_signature_payload(&document)?;
    document.self_signature_base64 = BASE64.encode(signing_key.sign(&payload).to_bytes());
    verify_identity_document(&document, 1)?;
    Ok(document)
}

fn identity_signature_payload(document: &LocalSigningIdentityDocument) -> AppResult<Vec<u8>> {
    serde_json::to_vec(&UnsignedIdentityDocument {
        schema_version: &document.schema_version,
        algorithm: &document.algorithm,
        key_id: &document.key_id,
        public_key_base64: &document.public_key_base64,
        established_at: document.established_at,
        continuity_event: document.continuity_event,
        previous_identity: &document.previous_identity,
        notice: &document.notice,
    })
    .map_err(Into::into)
}

pub(crate) fn verify_identity_document(
    document: &LocalSigningIdentityDocument,
    depth: usize,
) -> AppResult<()> {
    if depth > MAX_IDENTITY_DEPTH {
        return Err(AppError::InvalidRequest(
            "local signing identity history exceeds its bounded depth".into(),
        ));
    }
    if document.schema_version != LOCAL_SIGNING_IDENTITY_SCHEMA_VERSION
        || document.algorithm != IDENTITY_ALGORITHM
        || document.notice != IDENTITY_NOTICE
    {
        return Err(AppError::InvalidRequest(
            "local signing identity document has an unsupported contract".into(),
        ));
    }
    validate_identity_event_shape(document)?;
    if let Some(previous) = &document.previous_identity {
        verify_identity_document(previous, depth + 1)?;
        if previous.key_id == document.key_id {
            return Err(AppError::InvalidRequest(
                "local signing identity rotation reused the previous key".into(),
            ));
        }
    }
    let public_bytes = BASE64
        .decode(&document.public_key_base64)
        .map_err(|error| {
            AppError::InvalidRequest(format!("invalid identity public key: {error}"))
        })?;
    let public_bytes: [u8; 32] = public_bytes.try_into().map_err(|_| {
        AppError::InvalidRequest("identity public key must contain exactly 32 bytes".into())
    })?;
    let verifying_key = VerifyingKey::from_bytes(&public_bytes).map_err(|error| {
        AppError::InvalidRequest(format!("invalid identity public key: {error}"))
    })?;
    if document.key_id != key_id(&verifying_key) {
        return Err(AppError::InvalidRequest(
            "identity key ID does not match its public key".into(),
        ));
    }
    let signature = BASE64
        .decode(&document.self_signature_base64)
        .map_err(|error| {
            AppError::InvalidRequest(format!("invalid identity signature: {error}"))
        })?;
    let signature = Signature::try_from(signature.as_slice()).map_err(|error| {
        AppError::InvalidRequest(format!("invalid identity signature: {error}"))
    })?;
    verifying_key
        .verify(&identity_signature_payload(document)?, &signature)
        .map_err(|_| AppError::InvalidRequest("identity self-signature is invalid".into()))
}

fn validate_identity_event_shape(document: &LocalSigningIdentityDocument) -> AppResult<()> {
    let valid = match document.continuity_event {
        SigningIdentityContinuityEvent::Generated
        | SigningIdentityContinuityEvent::LegacyKeyAdopted => document.previous_identity.is_none(),
        SigningIdentityContinuityEvent::RotatedAfterConfirmedKeyLoss => {
            document.previous_identity.is_some()
        }
    };
    if !valid {
        return Err(AppError::InvalidRequest(
            "local signing identity continuity event has an invalid predecessor shape".into(),
        ));
    }
    Ok(())
}

fn identity_depth(document: &LocalSigningIdentityDocument) -> usize {
    1 + document
        .previous_identity
        .as_ref()
        .map_or(0, |previous| identity_depth(previous))
}

fn key_id(verifying_key: &VerifyingKey) -> String {
    hex::encode(Sha256::digest(verifying_key.as_bytes()))
}

fn read_identity_document_if_present(
    identity_path: &Path,
) -> AppResult<Option<LocalSigningIdentityDocument>> {
    let Some(bytes) = read_private_file_if_present(identity_path, MAX_IDENTITY_DOCUMENT_BYTES)?
    else {
        return Ok(None);
    };
    let document: LocalSigningIdentityDocument =
        serde_json::from_slice(&bytes).map_err(|error| {
            AppError::InvalidRequest(format!(
                "local signing identity document is invalid JSON: {error}"
            ))
        })?;
    verify_identity_document(&document, 1)?;
    Ok(Some(document))
}

fn create_identity_document(path: &Path, document: &LocalSigningIdentityDocument) -> AppResult<()> {
    let mut bytes = serde_json::to_vec_pretty(document)?;
    bytes.push(b'\n');
    match write_private_new_file(path, &bytes) {
        Ok(()) => Ok(()),
        Err(error) if error.kind() == io::ErrorKind::AlreadyExists => {
            let observed = read_identity_document_if_present(path)?.ok_or_else(|| {
                AppError::Internal("concurrent identity creation did not persist a document".into())
            })?;
            if observed != *document {
                return Err(AppError::NotAuthorized(
                    "concurrent local signing identity differs from the expected identity".into(),
                ));
            }
            Ok(())
        }
        Err(error) => Err(error.into()),
    }
}

fn read_identity_anchor_if_present(path: &Path) -> AppResult<Option<LocalSigningIdentityAnchor>> {
    let Some(bytes) = read_private_file_if_present(path, MAX_IDENTITY_DOCUMENT_BYTES)? else {
        return Ok(None);
    };
    let anchor: LocalSigningIdentityAnchor = serde_json::from_slice(&bytes).map_err(|error| {
        AppError::InvalidRequest(format!(
            "local signing identity anchor is invalid JSON: {error}"
        ))
    })?;
    validate_identity_anchor(&anchor)?;
    Ok(Some(anchor))
}

fn create_identity_anchor(path: &Path, anchor: &LocalSigningIdentityAnchor) -> AppResult<()> {
    validate_identity_anchor(anchor)?;
    let mut bytes = serde_json::to_vec_pretty(anchor)?;
    bytes.push(b'\n');
    match write_private_new_file(path, &bytes) {
        Ok(()) => Ok(()),
        Err(error) if error.kind() == io::ErrorKind::AlreadyExists => {
            let observed = read_identity_anchor_if_present(path)?.ok_or_else(|| {
                AppError::Internal("concurrent identity anchor creation was not persisted".into())
            })?;
            if observed != *anchor {
                return Err(AppError::NotAuthorized(
                    "concurrent local signing identity anchor differs from the expected identity"
                        .into(),
                ));
            }
            Ok(())
        }
        Err(error) => Err(error.into()),
    }
}

fn read_rotation_intent_if_present(path: &Path) -> AppResult<Option<LocalSigningRotationIntent>> {
    let Some(bytes) = read_private_file_if_present(path, MAX_ROTATION_INTENT_BYTES)? else {
        return Ok(None);
    };
    let intent = serde_json::from_slice(&bytes).map_err(|error| {
        AppError::InvalidRequest(format!(
            "local signing rotation intent is invalid JSON: {error}"
        ))
    })?;
    Ok(Some(intent))
}

fn create_rotation_intent(path: &Path, intent: &LocalSigningRotationIntent) -> AppResult<()> {
    let previous = intent
        .candidate_identity
        .previous_identity
        .as_deref()
        .ok_or_else(|| AppError::InvalidRequest("rotation candidate has no predecessor".into()))?;
    validate_rotation_intent(intent, previous, &intent.acknowledged_previous_key_id)?;
    let mut bytes = Zeroizing::new(serde_json::to_vec_pretty(intent)?);
    bytes.push(b'\n');
    match write_private_new_file(path, &bytes) {
        Ok(()) => Ok(()),
        Err(error) if error.kind() == io::ErrorKind::AlreadyExists => Err(AppError::NotAuthorized(
            "a concurrent rotation intent already exists; rerun the same explicit rotation command"
                .into(),
        )),
        Err(error) => Err(error.into()),
    }
}

fn replace_identity_document(
    path: &Path,
    document: &LocalSigningIdentityDocument,
) -> AppResult<()> {
    let mut temporary = path.as_os_str().to_os_string();
    temporary.push(format!(".next-{}", document.key_id));
    let temporary = PathBuf::from(temporary);
    let mut bytes = serde_json::to_vec_pretty(document)?;
    bytes.push(b'\n');
    match write_private_new_file(&temporary, &bytes) {
        Ok(()) => {}
        Err(error) if error.kind() == io::ErrorKind::AlreadyExists => {
            let observed = read_identity_document_if_present(&temporary)?.ok_or_else(|| {
                AppError::NotAuthorized(
                    "identity rotation staging path exists without a valid document".into(),
                )
            })?;
            if observed != *document {
                return Err(AppError::NotAuthorized(
                    "identity rotation staging document differs from the expected rotation".into(),
                ));
            }
        }
        Err(error) => return Err(error.into()),
    }
    replace_file_atomically(&temporary, path)?;
    Ok(())
}

fn replace_identity_anchor(path: &Path, anchor: &LocalSigningIdentityAnchor) -> AppResult<()> {
    validate_identity_anchor(anchor)?;
    let temporary = path_with_suffix(path, &format!(".next-{}", anchor.identity.key_id));
    let mut bytes = serde_json::to_vec_pretty(anchor)?;
    bytes.push(b'\n');
    match write_private_new_file(&temporary, &bytes) {
        Ok(()) => {}
        Err(error) if error.kind() == io::ErrorKind::AlreadyExists => {
            let observed = read_identity_anchor_if_present(&temporary)?.ok_or_else(|| {
                AppError::NotAuthorized(
                    "identity anchor staging path exists without a valid document".into(),
                )
            })?;
            if observed != *anchor {
                return Err(AppError::NotAuthorized(
                    "identity anchor staging document differs from the expected rotation".into(),
                ));
            }
        }
        Err(error) => return Err(error.into()),
    }
    replace_file_atomically(&temporary, path)?;
    Ok(())
}

fn remove_managed_private_file(path: &Path) -> AppResult<()> {
    let Some(_) = read_private_file_if_present(path, MAX_ROTATION_INTENT_BYTES)? else {
        return Ok(());
    };
    fs::remove_file(path).map_err(|error| {
        AppError::NotAvailable(format!(
            "completed identity rotation but could not remove its protected intent file: {error}"
        ))
    })?;
    sync_parent_directory(path)?;
    Ok(())
}

fn read_private_file_if_present(
    path: &Path,
    maximum: u64,
) -> AppResult<Option<Zeroizing<Vec<u8>>>> {
    let mut file = match open_private_file(path) {
        Ok(file) => file,
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(None),
        Err(error) => {
            return Err(AppError::NotAuthorized(format!(
                "private identity file could not be opened safely: {error}"
            )));
        }
    };
    let before = verify_private_file(&file, maximum)?;
    let mut bytes = Zeroizing::new(Vec::with_capacity(before.size as usize));
    (&mut file).take(maximum + 1).read_to_end(&mut bytes)?;
    if bytes.len() as u64 != before.size || bytes.len() as u64 > maximum {
        return Err(AppError::NotAuthorized(
            "private identity file changed while it was read".into(),
        ));
    }
    let after = verify_private_file(&file, maximum)?;
    if before != after {
        return Err(AppError::NotAuthorized(
            "private identity file changed while it was verified".into(),
        ));
    }
    Ok(Some(bytes))
}

fn write_private_new_file(path: &Path, bytes: &[u8]) -> io::Result<()> {
    let mut file = create_private_file(path)?;
    file.write_all(bytes)?;
    file.sync_all()?;
    let observed = verify_private_file(&file, bytes.len() as u64)
        .map_err(|error| io::Error::other(error.to_string()))?;
    if observed.size != bytes.len() as u64 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "private identity file length changed while it was created",
        ));
    }
    sync_parent_directory(path)?;
    Ok(())
}

#[cfg(unix)]
fn sync_parent_directory(path: &Path) -> io::Result<()> {
    use std::os::unix::fs::OpenOptionsExt;
    let parent = path.parent().ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::InvalidInput,
            "private file path has no parent",
        )
    })?;
    let canonical_parent = if parent.as_os_str().is_empty() {
        Path::new(".").canonicalize()?
    } else {
        parent.canonicalize()?
    };
    let directory = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_DIRECTORY | libc::O_NOFOLLOW)
        .open(canonical_parent)?;
    directory.sync_all()
}

#[cfg(not(unix))]
fn sync_parent_directory(_path: &Path) -> io::Result<()> {
    Ok(())
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct PrivateFileSnapshot {
    size: u64,
    identity_high: u64,
    identity_low: u64,
    links: u64,
}

fn read_signing_key_record_if_present(path: &Path) -> AppResult<Option<SigningKeyRecord>> {
    let mut file = match open_signing_key_file(path) {
        Ok(file) => file,
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(None),
        Err(error) => {
            return Err(AppError::NotAuthorized(format!(
                "local signing key could not be opened safely: {error}"
            )));
        }
    };
    let (before, protection) = classify_signing_key_file(&file, 32)?;
    let mut bytes = Zeroizing::new(Vec::with_capacity(before.size as usize));
    (&mut file).take(33).read_to_end(&mut bytes)?;
    let (after, observed_protection) = classify_signing_key_file(&file, 32)?;
    if before != after || protection != observed_protection || bytes.len() != 32 {
        return Err(AppError::NotAuthorized(
            "local Ed25519 key changed while its exact protection and bytes were verified".into(),
        ));
    }
    let mut secret = [0_u8; 32];
    secret.copy_from_slice(&bytes);
    bytes.zeroize();
    let signing_key = SigningKey::from_bytes(&secret);
    secret.zeroize();
    Ok(Some(SigningKeyRecord {
        signing_key,
        protection,
        file,
    }))
}

#[cfg(unix)]
fn open_signing_key_file(path: &Path) -> io::Result<File> {
    use std::os::unix::fs::OpenOptionsExt;
    OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW)
        .open(path)
}

#[cfg(windows)]
fn open_signing_key_file(path: &Path) -> io::Result<File> {
    use std::os::windows::fs::OpenOptionsExt;
    use windows_sys::Win32::Storage::FileSystem::{
        FILE_FLAG_OPEN_REPARSE_POINT, FILE_GENERIC_READ, FILE_GENERIC_WRITE, FILE_SHARE_READ,
        READ_CONTROL, WRITE_DAC,
    };
    let mut options = OpenOptions::new();
    options
        .read(true)
        // FlushFileBuffers requires write access on Windows. Keep that access
        // on this already owner-authorized handle so the legacy ACL change can
        // be made durable without reopening the path after verification.
        .access_mode(FILE_GENERIC_READ | FILE_GENERIC_WRITE | READ_CONTROL | WRITE_DAC)
        .share_mode(FILE_SHARE_READ)
        .custom_flags(FILE_FLAG_OPEN_REPARSE_POINT);
    options.open(path)
}

#[cfg(not(any(unix, windows)))]
fn open_signing_key_file(path: &Path) -> io::Result<File> {
    File::open(path)
}

#[cfg(unix)]
fn classify_signing_key_file(
    file: &File,
    maximum: u64,
) -> AppResult<(PrivateFileSnapshot, SigningKeyProtection)> {
    use std::os::unix::fs::{MetadataExt, PermissionsExt};
    let metadata = file.metadata()?;
    // SAFETY: geteuid has no preconditions.
    let effective_uid = unsafe { libc::geteuid() };
    let mode = metadata.permissions().mode() & 0o777;
    if !metadata.is_file()
        || metadata.uid() != effective_uid
        || metadata.nlink() != 1
        || metadata.len() == 0
        || metadata.len() > maximum
    {
        return Err(AppError::NotAuthorized(
            "local signing key must be a bounded, single-link, current-user regular file".into(),
        ));
    }
    let protection = match mode {
        0o400 => SigningKeyProtection::Managed,
        0o600 => SigningKeyProtection::ExactLegacy,
        _ => {
            return Err(AppError::NotAuthorized(
                "local signing key mode is neither the managed owner-read-only mode nor the exact legacy owner-only mode".into(),
            ));
        }
    };
    Ok((
        PrivateFileSnapshot {
            size: metadata.len(),
            identity_high: metadata.dev(),
            identity_low: metadata.ino(),
            links: metadata.nlink(),
        },
        protection,
    ))
}

#[cfg(windows)]
fn classify_signing_key_file(
    file: &File,
    maximum: u64,
) -> AppResult<(PrivateFileSnapshot, SigningKeyProtection)> {
    let information = windows_file_information(file)?;
    validate_windows_private_file_information(&information, maximum)?;
    let protection = if verify_windows_current_user_only_file(file).is_ok() {
        SigningKeyProtection::Managed
    } else {
        verify_exact_legacy_windows_private_file(file).map_err(|error| {
            AppError::NotAuthorized(format!(
                "local signing key Windows ACL is neither managed nor the exact bounded legacy ACL: {error}"
            ))
        })?;
        SigningKeyProtection::ExactLegacy
    };
    Ok((
        PrivateFileSnapshot {
            size: information.size,
            identity_high: u64::from(information.volume_serial),
            identity_low: information.file_index,
            links: u64::from(information.links),
        },
        protection,
    ))
}

#[cfg(not(any(unix, windows)))]
fn classify_signing_key_file(
    file: &File,
    maximum: u64,
) -> AppResult<(PrivateFileSnapshot, SigningKeyProtection)> {
    Ok((
        verify_private_file(file, maximum)?,
        SigningKeyProtection::Managed,
    ))
}

#[cfg(unix)]
fn harden_exact_legacy_signing_key(file: &File) -> AppResult<()> {
    use std::os::unix::fs::PermissionsExt;
    let (_, protection) = classify_signing_key_file(file, 32)?;
    if protection != SigningKeyProtection::ExactLegacy {
        return Err(AppError::NotAuthorized(
            "only the exact legacy signing-key mode may be hardened".into(),
        ));
    }
    file.set_permissions(fs::Permissions::from_mode(0o400))?;
    file.sync_all()?;
    verify_managed_signing_key_file(file, 32)
}

#[cfg(windows)]
fn harden_exact_legacy_signing_key(file: &File) -> AppResult<()> {
    harden_legacy_windows_private_file(file)?;
    verify_managed_signing_key_file(file, 32)
}

#[cfg(not(any(unix, windows)))]
fn harden_exact_legacy_signing_key(_file: &File) -> AppResult<()> {
    Err(AppError::NotAvailable(
        "legacy signing-key hardening is unsupported on this platform".into(),
    ))
}

fn verify_managed_signing_key_file(file: &File, maximum: u64) -> AppResult<()> {
    let (_, protection) = classify_signing_key_file(file, maximum)?;
    if protection != SigningKeyProtection::Managed {
        return Err(AppError::NotAuthorized(
            "local signing key did not reach its managed owner-only protection state".into(),
        ));
    }
    Ok(())
}

#[cfg(unix)]
fn open_private_file(path: &Path) -> io::Result<File> {
    use std::os::unix::fs::OpenOptionsExt;
    OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW)
        .open(path)
}

#[cfg(windows)]
fn open_private_file(path: &Path) -> io::Result<File> {
    use std::os::windows::fs::OpenOptionsExt;
    use windows_sys::Win32::Storage::FileSystem::{
        FILE_FLAG_OPEN_REPARSE_POINT, FILE_GENERIC_READ, FILE_SHARE_READ, READ_CONTROL, WRITE_DAC,
    };
    let mut options = OpenOptions::new();
    options
        .read(true)
        .access_mode(FILE_GENERIC_READ | READ_CONTROL | WRITE_DAC)
        .share_mode(FILE_SHARE_READ)
        .custom_flags(FILE_FLAG_OPEN_REPARSE_POINT);
    let file = options.open(path)?;
    verify_windows_current_user_only_file(&file)?;
    Ok(file)
}

#[cfg(not(any(unix, windows)))]
fn open_private_file(path: &Path) -> io::Result<File> {
    File::open(path)
}

#[cfg(unix)]
fn create_private_file(path: &Path) -> io::Result<File> {
    use std::os::unix::fs::OpenOptionsExt;
    OpenOptions::new()
        .read(true)
        .write(true)
        .create_new(true)
        .mode(0o400)
        .custom_flags(libc::O_NOFOLLOW)
        .open(path)
}

#[cfg(windows)]
fn create_private_file(path: &Path) -> io::Result<File> {
    create_windows_current_user_only_file(path)
}

#[cfg(not(any(unix, windows)))]
fn create_private_file(path: &Path) -> io::Result<File> {
    OpenOptions::new()
        .read(true)
        .write(true)
        .create_new(true)
        .open(path)
}

#[cfg(unix)]
fn verify_private_file(file: &File, maximum: u64) -> AppResult<PrivateFileSnapshot> {
    use std::os::unix::fs::{MetadataExt, PermissionsExt};
    let metadata = file.metadata()?;
    // SAFETY: geteuid has no preconditions and does not dereference memory.
    let effective_uid = unsafe { libc::geteuid() };
    let mode = metadata.permissions().mode() & 0o777;
    if !metadata.is_file()
        || metadata.uid() != effective_uid
        || metadata.nlink() != 1
        || !matches!(mode, 0o400 | 0o600)
        || metadata.len() == 0
        || metadata.len() > maximum
    {
        return Err(AppError::NotAuthorized(
            "private identity file must be a nonempty, single-link, current-user-only regular file"
                .into(),
        ));
    }
    Ok(PrivateFileSnapshot {
        size: metadata.len(),
        identity_high: metadata.dev(),
        identity_low: metadata.ino(),
        links: metadata.nlink(),
    })
}

#[cfg(windows)]
fn verify_private_file(file: &File, maximum: u64) -> AppResult<PrivateFileSnapshot> {
    let information = windows_file_information(file).map_err(AppError::from)?;
    validate_windows_private_file_information(&information, maximum).map_err(|error| {
        AppError::NotAuthorized(format!("private identity file is unsafe: {error}"))
    })?;
    verify_windows_current_user_only_file(file).map_err(|error| {
        AppError::NotAuthorized(format!(
            "private identity file has unsafe Windows ownership or permissions: {error}"
        ))
    })?;
    Ok(PrivateFileSnapshot {
        size: information.size,
        identity_high: u64::from(information.volume_serial),
        identity_low: information.file_index,
        links: u64::from(information.links),
    })
}

#[cfg(windows)]
fn validate_windows_private_file_information(
    information: &WindowsFileInformation,
    maximum: u64,
) -> io::Result<()> {
    use windows_sys::Win32::Storage::FileSystem::{
        FILE_ATTRIBUTE_DIRECTORY, FILE_ATTRIBUTE_REPARSE_POINT,
    };
    if information.attributes & (FILE_ATTRIBUTE_DIRECTORY | FILE_ATTRIBUTE_REPARSE_POINT) != 0
        || information.links != 1
        || information.size == 0
        || information.size > maximum
    {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "expected a nonempty, single-link, non-reparse regular file",
        ));
    }
    Ok(())
}

#[cfg(not(any(unix, windows)))]
fn verify_private_file(file: &File, maximum: u64) -> AppResult<PrivateFileSnapshot> {
    let metadata = file.metadata()?;
    if !metadata.is_file() || metadata.len() == 0 || metadata.len() > maximum {
        return Err(AppError::NotAuthorized(
            "private identity file must be a bounded regular file".into(),
        ));
    }
    Ok(PrivateFileSnapshot {
        size: metadata.len(),
        identity_high: 0,
        identity_low: 0,
        links: 1,
    })
}

#[cfg(not(windows))]
fn replace_file_atomically(temporary: &Path, destination: &Path) -> io::Result<()> {
    if temporary.parent() != destination.parent() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "identity replacement must stay in one exact directory",
        ));
    }
    fs::rename(temporary, destination)?;
    sync_parent_directory(destination)
}

#[cfg(windows)]
fn replace_file_atomically(temporary: &Path, destination: &Path) -> io::Result<()> {
    use std::os::windows::ffi::OsStrExt;
    use windows_sys::Win32::Storage::FileSystem::{
        MOVEFILE_REPLACE_EXISTING, MOVEFILE_WRITE_THROUGH, MoveFileExW,
    };
    let temporary_parent = temporary.parent().ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::InvalidInput,
            "replacement path has no parent",
        )
    })?;
    let destination_parent = destination.parent().ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::InvalidInput,
            "destination path has no parent",
        )
    })?;
    if temporary_parent != destination_parent {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "Windows identity replacement must stay in one exact directory",
        ));
    }
    let parent = temporary_parent.canonicalize()?;
    let exact_temporary = parent.join(temporary.file_name().ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::InvalidInput,
            "replacement path has no file name",
        )
    })?);
    let exact_destination = parent.join(destination.file_name().ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::InvalidInput,
            "destination path has no file name",
        )
    })?);
    let mut destination = exact_destination
        .as_os_str()
        .encode_wide()
        .collect::<Vec<_>>();
    let mut temporary = exact_temporary
        .as_os_str()
        .encode_wide()
        .collect::<Vec<_>>();
    if destination.contains(&0) || temporary.contains(&0) {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "Windows identity path contains a NUL code unit",
        ));
    }
    destination.push(0);
    temporary.push(0);
    // SAFETY: both paths are NUL-terminated, share one canonical directory,
    // and remain live for the call. MOVEFILE_WRITE_THROUGH is supported for
    // MoveFileExW; the durable rotation intent makes either the old or new
    // post-interruption state exactly recoverable on retry.
    if unsafe {
        MoveFileExW(
            temporary.as_ptr(),
            destination.as_ptr(),
            MOVEFILE_REPLACE_EXISTING | MOVEFILE_WRITE_THROUGH,
        )
    } == 0
    {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

#[cfg(windows)]
#[derive(Clone)]
struct WindowsSid {
    storage: Vec<u32>,
}

#[cfg(windows)]
impl WindowsSid {
    fn as_ptr(&self) -> windows_sys::Win32::Security::PSID {
        self.storage.as_ptr().cast_mut().cast()
    }
}

#[cfg(windows)]
struct WindowsAcl(*mut windows_sys::Win32::Security::ACL);

#[cfg(windows)]
impl Drop for WindowsAcl {
    fn drop(&mut self) {
        use windows_sys::Win32::Foundation::LocalFree;
        // SAFETY: SetEntriesInAclW allocated this ACL with LocalAlloc.
        unsafe { LocalFree(self.0.cast()) };
    }
}

#[cfg(windows)]
fn windows_current_user_sid() -> io::Result<WindowsSid> {
    use std::os::windows::io::{AsRawHandle, FromRawHandle, OwnedHandle};
    use windows_sys::Win32::Foundation::ERROR_INSUFFICIENT_BUFFER;
    use windows_sys::Win32::Security::{
        CopySid, GetLengthSid, GetTokenInformation, IsValidSid, TOKEN_QUERY, TOKEN_USER, TokenUser,
    };
    use windows_sys::Win32::System::Threading::{GetCurrentProcess, OpenProcessToken};
    let mut raw_token = std::ptr::null_mut();
    // SAFETY: output storage is valid and GetCurrentProcess returns a pseudo-handle.
    if unsafe { OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &raw mut raw_token) } == 0 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: OpenProcessToken returned a uniquely owned handle.
    let token = unsafe { OwnedHandle::from_raw_handle(raw_token) };
    let mut required = 0_u32;
    // SAFETY: null probe is the documented size query.
    let probe = unsafe {
        GetTokenInformation(
            token.as_raw_handle(),
            TokenUser,
            std::ptr::null_mut(),
            0,
            &raw mut required,
        )
    };
    let probe_error = io::Error::last_os_error();
    if probe != 0
        || required < std::mem::size_of::<TOKEN_USER>() as u32
        || probe_error.raw_os_error() != Some(ERROR_INSUFFICIENT_BUFFER as i32)
    {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "Windows returned an invalid current-user token size",
        ));
    }
    let mut information = vec![0_usize; (required as usize).div_ceil(std::mem::size_of::<usize>())];
    // SAFETY: buffer is aligned and provides required writable bytes.
    if unsafe {
        GetTokenInformation(
            token.as_raw_handle(),
            TokenUser,
            information.as_mut_ptr().cast(),
            required,
            &raw mut required,
        )
    } == 0
    {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: successful TokenUser query initialized TOKEN_USER.
    let token_user = unsafe { &*information.as_ptr().cast::<TOKEN_USER>() };
    if token_user.User.Sid.is_null() || unsafe { IsValidSid(token_user.User.Sid) } == 0 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "Windows returned an invalid current-user SID",
        ));
    }
    // SAFETY: SID was validated.
    let length = unsafe { GetLengthSid(token_user.User.Sid) };
    let mut storage = vec![0_u32; (length as usize).div_ceil(std::mem::size_of::<u32>())];
    // SAFETY: destination is aligned and large enough; source SID remains live.
    if unsafe { CopySid(length, storage.as_mut_ptr().cast(), token_user.User.Sid) } == 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(WindowsSid { storage })
}

#[cfg(windows)]
fn windows_well_known_sid(
    kind: windows_sys::Win32::Security::WELL_KNOWN_SID_TYPE,
) -> io::Result<WindowsSid> {
    use windows_sys::Win32::Security::{CreateWellKnownSid, SECURITY_MAX_SID_SIZE};
    let mut storage =
        vec![0_u32; (SECURITY_MAX_SID_SIZE as usize).div_ceil(std::mem::size_of::<u32>())];
    let mut length = u32::try_from(storage.len() * std::mem::size_of::<u32>())
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "Windows SID is too large"))?;
    // SAFETY: storage exposes length writable bytes; these well-known SIDs need no domain SID.
    if unsafe {
        CreateWellKnownSid(
            kind,
            std::ptr::null_mut(),
            storage.as_mut_ptr().cast(),
            &raw mut length,
        )
    } == 0
    {
        return Err(io::Error::last_os_error());
    }
    Ok(WindowsSid { storage })
}

#[cfg(windows)]
fn windows_current_user_acl(user: &WindowsSid) -> io::Result<WindowsAcl> {
    use windows_sys::Win32::Security::Authorization::{
        EXPLICIT_ACCESS_W, NO_MULTIPLE_TRUSTEE, SET_ACCESS, SetEntriesInAclW, TRUSTEE_IS_SID,
        TRUSTEE_IS_USER, TRUSTEE_W,
    };
    use windows_sys::Win32::Security::NO_INHERITANCE;
    use windows_sys::Win32::Storage::FileSystem::FILE_ALL_ACCESS;
    let explicit = EXPLICIT_ACCESS_W {
        grfAccessPermissions: FILE_ALL_ACCESS,
        grfAccessMode: SET_ACCESS,
        grfInheritance: NO_INHERITANCE,
        Trustee: TRUSTEE_W {
            pMultipleTrustee: std::ptr::null_mut(),
            MultipleTrusteeOperation: NO_MULTIPLE_TRUSTEE,
            TrusteeForm: TRUSTEE_IS_SID,
            TrusteeType: TRUSTEE_IS_USER,
            ptstrName: user.as_ptr().cast(),
        },
    };
    let mut acl = std::ptr::null_mut();
    // SAFETY: explicit and output storage are valid; user SID remains live.
    let status =
        unsafe { SetEntriesInAclW(1, &raw const explicit, std::ptr::null(), &raw mut acl) };
    if status != 0 {
        return Err(io::Error::from_raw_os_error(status as i32));
    }
    if acl.is_null() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "Windows returned a null current-user ACL",
        ));
    }
    Ok(WindowsAcl(acl))
}

#[cfg(windows)]
fn create_windows_current_user_only_file(path: &Path) -> io::Result<File> {
    use std::os::windows::ffi::OsStrExt;
    use std::os::windows::io::FromRawHandle;
    use windows_sys::Win32::Foundation::{FALSE, INVALID_HANDLE_VALUE, TRUE};
    use windows_sys::Win32::Security::{
        InitializeSecurityDescriptor, SE_DACL_PROTECTED, SECURITY_ATTRIBUTES, SECURITY_DESCRIPTOR,
        SetSecurityDescriptorControl, SetSecurityDescriptorDacl, SetSecurityDescriptorOwner,
    };
    use windows_sys::Win32::Storage::FileSystem::{
        CREATE_NEW, CreateFileW, DELETE, FILE_ATTRIBUTE_NORMAL, FILE_GENERIC_READ,
        FILE_GENERIC_WRITE, FILE_SHARE_NONE, READ_CONTROL, WRITE_DAC,
    };
    use windows_sys::Win32::System::SystemServices::SECURITY_DESCRIPTOR_REVISION;
    let user = windows_current_user_sid()?;
    let acl = windows_current_user_acl(&user)?;
    let mut descriptor = SECURITY_DESCRIPTOR::default();
    // SAFETY: descriptor is writable storage.
    if unsafe {
        InitializeSecurityDescriptor(
            std::ptr::addr_of_mut!(descriptor).cast(),
            SECURITY_DESCRIPTOR_REVISION,
        )
    } == 0
    {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: descriptor and user SID remain live through CreateFileW.
    if unsafe {
        SetSecurityDescriptorOwner(
            std::ptr::addr_of_mut!(descriptor).cast(),
            user.as_ptr(),
            FALSE,
        )
    } == 0
        || unsafe {
            SetSecurityDescriptorDacl(
                std::ptr::addr_of_mut!(descriptor).cast(),
                TRUE,
                acl.0,
                FALSE,
            )
        } == 0
        || unsafe {
            SetSecurityDescriptorControl(
                std::ptr::addr_of_mut!(descriptor).cast(),
                SE_DACL_PROTECTED,
                SE_DACL_PROTECTED,
            )
        } == 0
    {
        return Err(io::Error::last_os_error());
    }
    let attributes = SECURITY_ATTRIBUTES {
        nLength: std::mem::size_of::<SECURITY_ATTRIBUTES>() as u32,
        lpSecurityDescriptor: std::ptr::addr_of_mut!(descriptor).cast(),
        bInheritHandle: FALSE,
    };
    let parent = path.parent().ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::InvalidInput,
            "private identity path has no parent",
        )
    })?;
    let file_name = path.file_name().ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::InvalidInput,
            "private identity path has no file name",
        )
    })?;
    let canonical_parent = if parent.as_os_str().is_empty() {
        Path::new(".").canonicalize()?
    } else {
        parent.canonicalize()?
    };
    let exact_path = canonical_parent.join(file_name);
    let mut encoded = exact_path.as_os_str().encode_wide().collect::<Vec<_>>();
    if encoded.contains(&0) {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "Windows identity path contains a NUL code unit",
        ));
    }
    encoded.push(0);
    // SAFETY: path and security descriptor backing storage remain live.
    let raw = unsafe {
        CreateFileW(
            encoded.as_ptr(),
            FILE_GENERIC_READ | FILE_GENERIC_WRITE | DELETE | READ_CONTROL | WRITE_DAC,
            FILE_SHARE_NONE,
            &raw const attributes,
            CREATE_NEW,
            FILE_ATTRIBUTE_NORMAL,
            std::ptr::null_mut(),
        )
    };
    if raw == INVALID_HANDLE_VALUE {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: CreateFileW returned a uniquely owned handle.
    let file = unsafe { File::from_raw_handle(raw) };
    let information = windows_file_information(&file)?;
    use windows_sys::Win32::Storage::FileSystem::{
        FILE_ATTRIBUTE_DIRECTORY, FILE_ATTRIBUTE_REPARSE_POINT,
    };
    if information.size != 0
        || information.links != 1
        || information.attributes & (FILE_ATTRIBUTE_DIRECTORY | FILE_ATTRIBUTE_REPARSE_POINT) != 0
    {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "new Windows identity is not an empty single-link regular file",
        ));
    }
    verify_windows_current_user_only_file(&file)?;
    Ok(file)
}

#[cfg(windows)]
#[derive(Debug, Clone, Copy)]
struct WindowsFileInformation {
    volume_serial: u32,
    file_index: u64,
    size: u64,
    links: u32,
    attributes: u32,
}

#[cfg(windows)]
fn windows_file_information(file: &File) -> io::Result<WindowsFileInformation> {
    use std::os::windows::io::AsRawHandle;
    use windows_sys::Win32::Storage::FileSystem::{
        BY_HANDLE_FILE_INFORMATION, GetFileInformationByHandle,
    };
    let mut information = BY_HANDLE_FILE_INFORMATION::default();
    // SAFETY: file owns a valid handle and output storage is correctly sized.
    if unsafe { GetFileInformationByHandle(file.as_raw_handle(), &raw mut information) } == 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(WindowsFileInformation {
        volume_serial: information.dwVolumeSerialNumber,
        file_index: (u64::from(information.nFileIndexHigh) << 32)
            | u64::from(information.nFileIndexLow),
        size: (u64::from(information.nFileSizeHigh) << 32) | u64::from(information.nFileSizeLow),
        links: information.nNumberOfLinks,
        attributes: information.dwFileAttributes,
    })
}

#[cfg(windows)]
fn windows_security_descriptor(file: &File) -> io::Result<Vec<usize>> {
    use std::ffi::c_void;
    use std::os::windows::io::AsRawHandle;
    use windows_sys::Win32::Foundation::LocalFree;
    use windows_sys::Win32::Security::Authorization::{GetSecurityInfo, SE_FILE_OBJECT};
    use windows_sys::Win32::Security::{
        DACL_SECURITY_INFORMATION, GetSecurityDescriptorLength, IsValidSecurityDescriptor,
        OWNER_SECURITY_INFORMATION,
    };
    struct Descriptor(*mut c_void);
    impl Drop for Descriptor {
        fn drop(&mut self) {
            // SAFETY: GetSecurityInfo allocated this descriptor with LocalAlloc.
            unsafe { LocalFree(self.0) };
        }
    }
    let mut raw_descriptor = std::ptr::null_mut();
    // SAFETY: file handle and output storage are valid.
    let status = unsafe {
        GetSecurityInfo(
            file.as_raw_handle(),
            SE_FILE_OBJECT,
            OWNER_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION,
            std::ptr::null_mut(),
            std::ptr::null_mut(),
            std::ptr::null_mut(),
            std::ptr::null_mut(),
            &raw mut raw_descriptor,
        )
    };
    if status != 0 {
        return Err(io::Error::from_raw_os_error(status as i32));
    }
    let descriptor = Descriptor(raw_descriptor);
    if descriptor.0.is_null() || unsafe { IsValidSecurityDescriptor(descriptor.0) } == 0 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "Windows returned an invalid identity security descriptor",
        ));
    }
    // SAFETY: descriptor was validated.
    let length = unsafe { GetSecurityDescriptorLength(descriptor.0) } as usize;
    let mut copy = vec![0_usize; length.div_ceil(std::mem::size_of::<usize>())];
    // SAFETY: copy has at least length bytes and descriptor owns length readable bytes.
    unsafe {
        std::ptr::copy_nonoverlapping(
            descriptor.0.cast::<u8>(),
            copy.as_mut_ptr().cast::<u8>(),
            length,
        )
    };
    Ok(copy)
}

#[cfg(windows)]
fn verify_windows_current_user_only_file(file: &File) -> io::Result<()> {
    let user = windows_current_user_sid()?;
    let descriptor = windows_security_descriptor(file)?;
    verify_windows_current_user_only_descriptor(descriptor, &user)
}

#[cfg(windows)]
fn verify_windows_current_user_only_descriptor(
    mut descriptor_storage: Vec<usize>,
    user: &WindowsSid,
) -> io::Result<()> {
    use std::ffi::c_void;
    use windows_sys::Win32::Security::{
        ACCESS_ALLOWED_ACE, ACE_HEADER, ACL, ACL_SIZE_INFORMATION, AclSizeInformation, EqualSid,
        GetAce, GetAclInformation, GetLengthSid, GetSecurityDescriptorControl,
        GetSecurityDescriptorDacl, GetSecurityDescriptorOwner, IsValidAcl,
        IsValidSecurityDescriptor, IsValidSid, SE_DACL_PROTECTED, SE_SELF_RELATIVE,
    };
    use windows_sys::Win32::Storage::FileSystem::FILE_ALL_ACCESS;
    use windows_sys::Win32::System::SystemServices::{
        ACCESS_ALLOWED_ACE_TYPE, SECURITY_DESCRIPTOR_REVISION,
    };
    if descriptor_storage.is_empty() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "identity file security descriptor is empty",
        ));
    }
    let descriptor = descriptor_storage.as_mut_ptr().cast::<c_void>();
    // SAFETY: descriptor_storage remains live and aligned for this verification.
    if unsafe { IsValidSecurityDescriptor(descriptor) } == 0 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "identity file security descriptor is invalid",
        ));
    }
    let mut owner = std::ptr::null_mut();
    let mut owner_defaulted = 0;
    // SAFETY: descriptor is valid and output storage is writable.
    if unsafe { GetSecurityDescriptorOwner(descriptor, &raw mut owner, &raw mut owner_defaulted) }
        == 0
        || owner.is_null()
        || unsafe { IsValidSid(owner) } == 0
        || unsafe { EqualSid(owner, user.as_ptr()) } == 0
        || owner_defaulted != 0
    {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "identity file owner is not the explicit current Windows user",
        ));
    }
    let mut control = 0_u16;
    let mut revision = 0_u32;
    // SAFETY: descriptor is valid and output storage is writable.
    if unsafe { GetSecurityDescriptorControl(descriptor, &raw mut control, &raw mut revision) } == 0
        || revision != SECURITY_DESCRIPTOR_REVISION
        || control & (SE_DACL_PROTECTED | SE_SELF_RELATIVE)
            != (SE_DACL_PROTECTED | SE_SELF_RELATIVE)
    {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "identity file DACL is not protected",
        ));
    }
    let mut present = 0;
    let mut defaulted = 0;
    let mut dacl = std::ptr::null_mut::<ACL>();
    // SAFETY: descriptor is valid and output storage is writable.
    if unsafe {
        GetSecurityDescriptorDacl(
            descriptor,
            &raw mut present,
            &raw mut dacl,
            &raw mut defaulted,
        )
    } == 0
        || present == 0
        || defaulted != 0
        || dacl.is_null()
        || unsafe { IsValidAcl(dacl) } == 0
    {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "identity file has no explicit valid DACL",
        ));
    }
    let mut information = ACL_SIZE_INFORMATION::default();
    // SAFETY: DACL and output storage are valid.
    if unsafe {
        GetAclInformation(
            dacl,
            (&raw mut information).cast(),
            std::mem::size_of::<ACL_SIZE_INFORMATION>() as u32,
            AclSizeInformation,
        )
    } == 0
        || information.AceCount != 1
    {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "identity file DACL must contain exactly one access rule",
        ));
    }
    let mut raw_ace = std::ptr::null_mut::<c_void>();
    // SAFETY: valid DACL reports exactly one ACE.
    if unsafe { GetAce(dacl, 0, &raw mut raw_ace) } == 0 || raw_ace.is_null() {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: GetAce returned a pointer into the valid DACL.
    let header = unsafe { &*raw_ace.cast::<ACE_HEADER>() };
    if u32::from(header.AceType) != ACCESS_ALLOWED_ACE_TYPE
        || header.AceFlags != 0
        || usize::from(header.AceSize) < std::mem::size_of::<ACCESS_ALLOWED_ACE>()
    {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "identity file DACL contains an unexpected access rule",
        ));
    }
    // SAFETY: ACE type and size establish the fixed prefix.
    let allowed = unsafe { &*raw_ace.cast::<ACCESS_ALLOWED_ACE>() };
    let sid = std::ptr::addr_of!(allowed.SidStart).cast_mut().cast();
    if allowed.Mask != FILE_ALL_ACCESS
        || unsafe { IsValidSid(sid) } == 0
        || unsafe { EqualSid(sid, user.as_ptr()) } == 0
    {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "identity file DACL grants access to an unexpected principal",
        ));
    }
    // SAFETY: SID was validated.
    let sid_length = unsafe { GetLengthSid(sid) } as usize;
    let expected = std::mem::size_of::<ACCESS_ALLOWED_ACE>()
        .checked_sub(std::mem::size_of::<u32>())
        .and_then(|prefix| prefix.checked_add(sid_length))
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "Windows ACE overflow"))?;
    if usize::from(header.AceSize) != expected {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "identity file DACL contains a malformed SID boundary",
        ));
    }
    Ok(())
}

#[cfg(windows)]
fn verify_exact_legacy_windows_private_file(file: &File) -> io::Result<()> {
    use std::ffi::c_void;
    use windows_sys::Win32::Security::{
        ACCESS_ALLOWED_ACE, ACE_HEADER, ACL, ACL_SIZE_INFORMATION, AclSizeInformation,
        CONTAINER_INHERIT_ACE, EqualSid, GetAce, GetAclInformation, GetSecurityDescriptorDacl,
        GetSecurityDescriptorOwner, INHERIT_ONLY_ACE, INHERITED_ACE, IsValidAcl, IsValidSid,
        NO_PROPAGATE_INHERIT_ACE, OBJECT_INHERIT_ACE, WinBuiltinAdministratorsSid,
        WinLocalSystemSid,
    };
    use windows_sys::Win32::System::SystemServices::ACCESS_ALLOWED_ACE_TYPE;
    let information = windows_file_information(file)?;
    use windows_sys::Win32::Storage::FileSystem::{
        FILE_ALL_ACCESS, FILE_ATTRIBUTE_DIRECTORY, FILE_ATTRIBUTE_REPARSE_POINT,
    };
    if information.size != 32
        || information.links != 1
        || information.attributes & (FILE_ATTRIBUTE_DIRECTORY | FILE_ATTRIBUTE_REPARSE_POINT) != 0
    {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "legacy Windows identity file is not a bounded single-link regular file",
        ));
    }
    let user = windows_current_user_sid()?;
    let system = windows_well_known_sid(WinLocalSystemSid)?;
    let administrators = windows_well_known_sid(WinBuiltinAdministratorsSid)?;
    let mut descriptor = windows_security_descriptor(file)?;
    let descriptor = descriptor.as_mut_ptr().cast::<c_void>();
    let mut owner = std::ptr::null_mut();
    let mut owner_defaulted = 0;
    // SAFETY: descriptor and output storage are valid.
    if unsafe { GetSecurityDescriptorOwner(descriptor, &raw mut owner, &raw mut owner_defaulted) }
        == 0
        || owner.is_null()
        || unsafe { IsValidSid(owner) } == 0
        || unsafe { EqualSid(owner, user.as_ptr()) } == 0
        || owner_defaulted != 0
    {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "legacy Windows identity file is not owned by the current user",
        ));
    }
    let mut present = 0;
    let mut defaulted = 0;
    let mut dacl = std::ptr::null_mut::<ACL>();
    // SAFETY: descriptor and output storage are valid.
    if unsafe {
        GetSecurityDescriptorDacl(
            descriptor,
            &raw mut present,
            &raw mut dacl,
            &raw mut defaulted,
        )
    } == 0
        || present == 0
        || defaulted != 0
        || dacl.is_null()
        || unsafe { IsValidAcl(dacl) } == 0
    {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "legacy Windows identity file has no valid DACL",
        ));
    }
    let mut acl_information = ACL_SIZE_INFORMATION::default();
    // SAFETY: DACL and output storage are valid.
    if unsafe {
        GetAclInformation(
            dacl,
            (&raw mut acl_information).cast(),
            std::mem::size_of::<ACL_SIZE_INFORMATION>() as u32,
            AclSizeInformation,
        )
    } == 0
        || acl_information.AceCount != 3
    {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "legacy Windows identity DACL is outside the bounded migration policy",
        ));
    }
    let mut saw_user = false;
    let mut saw_system = false;
    let mut saw_administrators = false;
    for index in 0..acl_information.AceCount {
        let mut raw_ace = std::ptr::null_mut::<c_void>();
        // SAFETY: index is bounded by the DACL's reported ACE count.
        if unsafe { GetAce(dacl, index, &raw mut raw_ace) } == 0 || raw_ace.is_null() {
            return Err(io::Error::last_os_error());
        }
        // SAFETY: GetAce returned a pointer into the valid DACL.
        let header = unsafe { &*raw_ace.cast::<ACE_HEADER>() };
        let allowed_legacy_flags = OBJECT_INHERIT_ACE
            | CONTAINER_INHERIT_ACE
            | NO_PROPAGATE_INHERIT_ACE
            | INHERIT_ONLY_ACE
            | INHERITED_ACE;
        if u32::from(header.AceType) != ACCESS_ALLOWED_ACE_TYPE
            || u32::from(header.AceFlags) & !allowed_legacy_flags != 0
            || usize::from(header.AceSize) < std::mem::size_of::<ACCESS_ALLOWED_ACE>()
        {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "legacy Windows identity DACL contains a non-allow rule",
            ));
        }
        // SAFETY: ACE type and size establish the fixed prefix.
        let allowed = unsafe { &*raw_ace.cast::<ACCESS_ALLOWED_ACE>() };
        let sid = std::ptr::addr_of!(allowed.SidStart).cast_mut().cast();
        if allowed.Mask != FILE_ALL_ACCESS || unsafe { IsValidSid(sid) } == 0 {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "legacy Windows identity DACL grants unexpected access",
            ));
        }
        // SAFETY: SID was validated.
        let sid_length = unsafe { windows_sys::Win32::Security::GetLengthSid(sid) } as usize;
        let expected = std::mem::size_of::<ACCESS_ALLOWED_ACE>()
            .checked_sub(std::mem::size_of::<u32>())
            .and_then(|prefix| prefix.checked_add(sid_length))
            .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "Windows ACE overflow"))?;
        if usize::from(header.AceSize) != expected {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "legacy Windows identity DACL contains a malformed SID boundary",
            ));
        }
        let is_user = unsafe { EqualSid(sid, user.as_ptr()) } != 0;
        let is_system = unsafe { EqualSid(sid, system.as_ptr()) } != 0;
        let is_administrators = unsafe { EqualSid(sid, administrators.as_ptr()) } != 0;
        if (!is_user && !is_system && !is_administrators)
            || (is_user && saw_user)
            || (is_system && saw_system)
            || (is_administrators && saw_administrators)
        {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "legacy Windows identity DACL names an unexpected or duplicate principal",
            ));
        }
        saw_user |= is_user;
        saw_system |= is_system;
        saw_administrators |= is_administrators;
    }
    if !saw_user || !saw_system || !saw_administrators {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "legacy Windows identity DACL is not the exact current-user, LocalSystem, and Builtin Administrators predecessor ACL",
        ));
    }
    Ok(())
}

#[cfg(windows)]
fn harden_legacy_windows_private_file(file: &File) -> io::Result<()> {
    use std::os::windows::io::AsRawHandle;
    use windows_sys::Win32::Security::Authorization::{SE_FILE_OBJECT, SetSecurityInfo};
    use windows_sys::Win32::Security::{
        DACL_SECURITY_INFORMATION, PROTECTED_DACL_SECURITY_INFORMATION,
    };
    verify_exact_legacy_windows_private_file(file)?;
    let user = windows_current_user_sid()?;
    let acl = windows_current_user_acl(&user)?;
    // SAFETY: file handle is open with WRITE_DAC; ACL remains live for the call.
    let status = unsafe {
        SetSecurityInfo(
            file.as_raw_handle(),
            SE_FILE_OBJECT,
            DACL_SECURITY_INFORMATION | PROTECTED_DACL_SECURITY_INFORMATION,
            std::ptr::null_mut(),
            std::ptr::null_mut(),
            acl.0,
            std::ptr::null_mut(),
        )
    };
    if status != 0 {
        return Err(io::Error::from_raw_os_error(status as i32));
    }
    file.sync_all()?;
    verify_windows_current_user_only_file(file)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeSet;

    fn overwrite_managed_test_file(path: &Path, bytes: &[u8]) {
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(path, fs::Permissions::from_mode(0o600)).unwrap();
        }
        fs::write(path, bytes).unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(path, fs::Permissions::from_mode(0o400)).unwrap();
        }
    }

    #[cfg(windows)]
    fn windows_test_acl(
        principals: &[(
            &WindowsSid,
            windows_sys::Win32::Security::Authorization::TRUSTEE_TYPE,
        )],
    ) -> WindowsAcl {
        use windows_sys::Win32::Security::Authorization::{
            EXPLICIT_ACCESS_W, NO_MULTIPLE_TRUSTEE, SET_ACCESS, SetEntriesInAclW, TRUSTEE_IS_SID,
            TRUSTEE_W,
        };
        use windows_sys::Win32::Security::NO_INHERITANCE;
        use windows_sys::Win32::Storage::FileSystem::FILE_ALL_ACCESS;
        let entries = principals
            .iter()
            .map(|(sid, trustee_type)| EXPLICIT_ACCESS_W {
                grfAccessPermissions: FILE_ALL_ACCESS,
                grfAccessMode: SET_ACCESS,
                grfInheritance: NO_INHERITANCE,
                Trustee: TRUSTEE_W {
                    pMultipleTrustee: std::ptr::null_mut(),
                    MultipleTrusteeOperation: NO_MULTIPLE_TRUSTEE,
                    TrusteeForm: TRUSTEE_IS_SID,
                    TrusteeType: *trustee_type,
                    ptstrName: sid.as_ptr().cast(),
                },
            })
            .collect::<Vec<_>>();
        let mut acl = std::ptr::null_mut();
        // SAFETY: entries and their backing SID values remain live for the call.
        let status = unsafe {
            SetEntriesInAclW(
                entries.len() as u32,
                entries.as_ptr(),
                std::ptr::null(),
                &raw mut acl,
            )
        };
        assert_eq!(status, 0, "could not build the Windows test ACL");
        assert!(!acl.is_null(), "Windows returned a null test ACL");
        WindowsAcl(acl)
    }

    #[cfg(windows)]
    fn windows_test_set_dacl(
        path: &Path,
        principals: &[(
            &WindowsSid,
            windows_sys::Win32::Security::Authorization::TRUSTEE_TYPE,
        )],
    ) {
        use std::os::windows::fs::OpenOptionsExt;
        use std::os::windows::io::AsRawHandle;
        use windows_sys::Win32::Security::Authorization::{SE_FILE_OBJECT, SetSecurityInfo};
        use windows_sys::Win32::Security::{
            DACL_SECURITY_INFORMATION, PROTECTED_DACL_SECURITY_INFORMATION,
        };
        use windows_sys::Win32::Storage::FileSystem::{
            FILE_FLAG_OPEN_REPARSE_POINT, FILE_GENERIC_READ, FILE_SHARE_DELETE, FILE_SHARE_READ,
            FILE_SHARE_WRITE, READ_CONTROL, WRITE_DAC,
        };
        let file = OpenOptions::new()
            .read(true)
            .access_mode(FILE_GENERIC_READ | READ_CONTROL | WRITE_DAC)
            .share_mode(FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE)
            .custom_flags(FILE_FLAG_OPEN_REPARSE_POINT)
            .open(path)
            .unwrap();
        let acl = windows_test_acl(principals);
        // SAFETY: file is open with WRITE_DAC and the ACL remains live for the call.
        let status = unsafe {
            SetSecurityInfo(
                file.as_raw_handle(),
                SE_FILE_OBJECT,
                DACL_SECURITY_INFORMATION | PROTECTED_DACL_SECURITY_INFORMATION,
                std::ptr::null_mut(),
                std::ptr::null_mut(),
                acl.0,
                std::ptr::null_mut(),
            )
        };
        assert_eq!(status, 0, "could not install the Windows test ACL");
    }

    #[test]
    fn creates_stable_self_signed_public_identity() {
        let temporary = tempfile::tempdir().unwrap();
        let key_path = temporary.path().join("integrity-signing-key");
        let first = ensure_local_signing_identity(&key_path).unwrap();
        let second = ensure_local_signing_identity(&key_path).unwrap();
        assert_eq!(first, second);
        assert_eq!(
            first.continuity_event,
            SigningIdentityContinuityEvent::Generated
        );
        assert_eq!(fs::read(&key_path).unwrap().len(), 32);
        let document =
            read_identity_document_if_present(&signing_identity_document_path(&key_path))
                .unwrap()
                .unwrap();
        assert_eq!(document.key_id, first.key_id);
        verify_identity_document(&document, 1).unwrap();
    }

    #[test]
    fn public_summary_has_an_exact_path_free_non_secret_contract() {
        let temporary = tempfile::tempdir().unwrap();
        let key_path = temporary.path().join("integrity-signing-key");
        let summary = ensure_local_signing_identity(&key_path).unwrap();
        let value = serde_json::to_value(&summary).unwrap();
        let fields = value
            .as_object()
            .unwrap()
            .keys()
            .map(String::as_str)
            .collect::<BTreeSet<_>>();
        assert_eq!(
            fields,
            BTreeSet::from([
                "algorithm",
                "continuity_event",
                "established_at",
                "key_id",
                "notice",
                "previous_key_id",
                "public_key_base64",
            ])
        );
        let encoded = serde_json::to_string(&summary).unwrap();
        assert!(!encoded.contains(temporary.path().to_string_lossy().as_ref()));
        assert!(!encoded.contains(&BASE64.encode(fs::read(key_path).unwrap())));
    }

    #[cfg(unix)]
    #[test]
    fn adopts_an_existing_legacy_key_without_changing_it() {
        use std::os::unix::fs::PermissionsExt;
        let temporary = tempfile::tempdir().unwrap();
        let key_path = temporary.path().join("integrity-signing-key");
        let original = [7_u8; 32];
        fs::write(&key_path, original).unwrap();
        fs::set_permissions(&key_path, fs::Permissions::from_mode(0o600)).unwrap();
        let identity = ensure_local_signing_identity(&key_path).unwrap();
        assert_eq!(
            identity.continuity_event,
            SigningIdentityContinuityEvent::LegacyKeyAdopted
        );
        assert_eq!(fs::read(&key_path).unwrap(), original);
        assert_eq!(
            fs::metadata(&key_path).unwrap().permissions().mode() & 0o777,
            0o400
        );
        assert!(signing_identity_anchor_path(&key_path).is_file());
        assert!(!signing_rotation_intent_path(&key_path).exists());
    }

    #[test]
    fn missing_private_key_never_silently_changes_identity() {
        let temporary = tempfile::tempdir().unwrap();
        let key_path = temporary.path().join("integrity-signing-key");
        let identity = ensure_local_signing_identity(&key_path).unwrap();
        fs::remove_file(&key_path).unwrap();
        let error = ensure_local_signing_identity(&key_path).unwrap_err();
        assert!(error.to_string().contains(&identity.key_id));
        assert!(!key_path.exists());
    }

    #[test]
    fn retained_managed_key_and_anchor_restore_the_exact_deleted_identity() {
        let temporary = tempfile::tempdir().unwrap();
        let key_path = temporary.path().join("integrity-signing-key");
        let identity = ensure_local_signing_identity(&key_path).unwrap();
        let original_key = fs::read(&key_path).unwrap();
        let identity_path = signing_identity_document_path(&key_path);
        let original_document = fs::read(&identity_path).unwrap();
        fs::remove_file(&identity_path).unwrap();

        let restored = ensure_local_signing_identity(&key_path).unwrap();
        assert_eq!(restored, identity);
        assert_eq!(fs::read(&key_path).unwrap(), original_key);
        assert_eq!(fs::read(&identity_path).unwrap(), original_document);
        assert!(signing_identity_anchor_path(&key_path).is_file());
    }

    #[test]
    fn retained_managed_key_mismatch_never_restores_a_deleted_identity() {
        let temporary = tempfile::tempdir().unwrap();
        let key_path = temporary.path().join("integrity-signing-key");
        let identity = ensure_local_signing_identity(&key_path).unwrap();
        let identity_path = signing_identity_document_path(&key_path);
        let anchor_path = signing_identity_anchor_path(&key_path);
        let original_anchor = fs::read(&anchor_path).unwrap();
        fs::remove_file(&identity_path).unwrap();
        let mismatching_key = [83_u8; 32];
        assert_ne!(
            key_id(&SigningKey::from_bytes(&mismatching_key).verifying_key()),
            identity.key_id
        );
        overwrite_managed_test_file(&key_path, &mismatching_key);

        let error = ensure_local_signing_identity(&key_path).unwrap_err();
        assert!(error.to_string().contains("does not exactly match"));
        assert!(error.to_string().contains(&identity.key_id));
        assert!(!identity_path.exists());
        assert_eq!(fs::read(&key_path).unwrap(), mismatching_key);
        assert_eq!(fs::read(&anchor_path).unwrap(), original_anchor);
    }

    #[test]
    fn retained_anchor_without_its_managed_key_never_restores_or_rotates_identity() {
        let temporary = tempfile::tempdir().unwrap();
        let key_path = temporary.path().join("integrity-signing-key");
        let identity = ensure_local_signing_identity(&key_path).unwrap();
        let identity_path = signing_identity_document_path(&key_path);
        let anchor_path = signing_identity_anchor_path(&key_path);
        let original_anchor = fs::read(&anchor_path).unwrap();
        fs::remove_file(&key_path).unwrap();
        fs::remove_file(&identity_path).unwrap();

        let error = ensure_local_signing_identity(&key_path).unwrap_err();
        assert!(error.to_string().contains("private key is missing"));
        assert!(error.to_string().contains(&identity.key_id));
        assert!(!key_path.exists());
        assert!(!identity_path.exists());
        assert_eq!(fs::read(&anchor_path).unwrap(), original_anchor);
        assert!(!signing_rotation_intent_path(&key_path).exists());
    }

    #[test]
    fn managed_key_cannot_be_readopted_after_both_public_sidecars_are_deleted() {
        let temporary = tempfile::tempdir().unwrap();
        let key_path = temporary.path().join("integrity-signing-key");
        ensure_local_signing_identity(&key_path).unwrap();
        let original_key = fs::read(&key_path).unwrap();
        fs::remove_file(signing_identity_document_path(&key_path)).unwrap();
        fs::remove_file(signing_identity_anchor_path(&key_path)).unwrap();

        let error = ensure_local_signing_identity(&key_path).unwrap_err();
        assert!(error.to_string().contains("will not be silently adopted"));
        assert_eq!(fs::read(&key_path).unwrap(), original_key);
        assert!(!signing_identity_document_path(&key_path).exists());
        assert!(!signing_identity_anchor_path(&key_path).exists());
    }

    #[test]
    fn malformed_or_hardlinked_continuity_anchor_is_rejected() {
        let temporary = tempfile::tempdir().unwrap();
        let key_path = temporary.path().join("integrity-signing-key");
        ensure_local_signing_identity(&key_path).unwrap();
        let anchor_path = signing_identity_anchor_path(&key_path);
        let extra_link = temporary.path().join("anchor-extra-link");
        fs::hard_link(&anchor_path, &extra_link).unwrap();
        assert!(ensure_local_signing_identity(&key_path).is_err());
        fs::remove_file(extra_link).unwrap();

        overwrite_managed_test_file(&anchor_path, br#"{"schema_version":"1"}"#);
        assert!(ensure_local_signing_identity(&key_path).is_err());
    }

    #[test]
    fn explicit_rotation_records_the_confirmed_predecessor() {
        let temporary = tempfile::tempdir().unwrap();
        let key_path = temporary.path().join("integrity-signing-key");
        let first = ensure_local_signing_identity(&key_path).unwrap();
        fs::remove_file(&key_path).unwrap();
        let rotated =
            rotate_local_signing_identity_after_confirmed_loss(&key_path, &first.key_id).unwrap();
        assert_ne!(rotated.key_id, first.key_id);
        assert_eq!(
            rotated.previous_key_id.as_deref(),
            Some(first.key_id.as_str())
        );
        assert_eq!(
            rotated.continuity_event,
            SigningIdentityContinuityEvent::RotatedAfterConfirmedKeyLoss
        );
        let document =
            read_identity_document_if_present(&signing_identity_document_path(&key_path))
                .unwrap()
                .unwrap();
        verify_identity_document(&document, 1).unwrap();
        assert!(!signing_rotation_intent_path(&key_path).exists());
        let anchor = read_identity_anchor_if_present(&signing_identity_anchor_path(&key_path))
            .unwrap()
            .unwrap();
        ensure_anchor_matches_identity(&anchor, &document).unwrap();
    }

    #[test]
    fn rotation_never_endorses_an_unbound_mismatching_primary_key() {
        let temporary = tempfile::tempdir().unwrap();
        let key_path = temporary.path().join("integrity-signing-key");
        let first = ensure_local_signing_identity(&key_path).unwrap();
        let original_document =
            read_identity_document_if_present(&signing_identity_document_path(&key_path))
                .unwrap()
                .unwrap();
        fs::remove_file(&key_path).unwrap();
        write_private_new_file(&key_path, &[91_u8; 32]).unwrap();

        let error = rotate_local_signing_identity_after_confirmed_loss(&key_path, &first.key_id)
            .unwrap_err();
        assert!(error.to_string().contains("no rotation intent binds it"));
        assert_eq!(
            read_identity_document_if_present(&signing_identity_document_path(&key_path))
                .unwrap()
                .unwrap(),
            original_document
        );
        assert!(!signing_rotation_intent_path(&key_path).exists());
    }

    #[test]
    fn rotation_intent_mutation_is_rejected_before_any_identity_change() {
        let temporary = tempfile::tempdir().unwrap();
        let key_path = temporary.path().join("integrity-signing-key");
        let first = ensure_local_signing_identity(&key_path).unwrap();
        fs::remove_file(&key_path).unwrap();
        let previous =
            read_identity_document_if_present(&signing_identity_document_path(&key_path))
                .unwrap()
                .unwrap();
        let intent = new_rotation_intent(previous.clone()).unwrap();
        let intent_path = signing_rotation_intent_path(&key_path);
        create_rotation_intent(&intent_path, &intent).unwrap();
        let mut encoded: serde_json::Value =
            serde_json::from_slice(&fs::read(&intent_path).unwrap()).unwrap();
        encoded["candidate_private_key_base64"] =
            serde_json::Value::String(BASE64.encode([123_u8; 32]));
        let mut bytes = serde_json::to_vec_pretty(&encoded).unwrap();
        bytes.push(b'\n');
        overwrite_managed_test_file(&intent_path, &bytes);

        let error = rotate_local_signing_identity_after_confirmed_loss(&key_path, &first.key_id)
            .unwrap_err();
        assert!(
            error
                .to_string()
                .contains("does not match its bound public identity")
        );
        assert!(!key_path.exists());
        assert_eq!(
            read_identity_document_if_present(&signing_identity_document_path(&key_path))
                .unwrap()
                .unwrap(),
            previous
        );
    }

    #[test]
    fn rotation_resumes_only_the_exact_candidate_already_bound_by_intent() {
        let temporary = tempfile::tempdir().unwrap();
        let key_path = temporary.path().join("integrity-signing-key");
        let first = ensure_local_signing_identity(&key_path).unwrap();
        fs::remove_file(&key_path).unwrap();
        let previous =
            read_identity_document_if_present(&signing_identity_document_path(&key_path))
                .unwrap()
                .unwrap();
        let intent = new_rotation_intent(previous).unwrap();
        let expected_candidate_id = intent.candidate_key_id.clone();
        let candidate_key = rotation_intent_signing_key(&intent).unwrap();
        create_rotation_intent(&signing_rotation_intent_path(&key_path), &intent).unwrap();
        let mut secret = candidate_key.to_bytes();
        write_private_new_file(&key_path, &secret).unwrap();
        secret.zeroize();

        let rotated =
            rotate_local_signing_identity_after_confirmed_loss(&key_path, &first.key_id).unwrap();
        assert_eq!(rotated.key_id, expected_candidate_id);
        assert_eq!(
            rotated.previous_key_id.as_deref(),
            Some(first.key_id.as_str())
        );
        assert!(!signing_rotation_intent_path(&key_path).exists());
    }

    #[test]
    fn tampered_public_identity_is_rejected() {
        let temporary = tempfile::tempdir().unwrap();
        let key_path = temporary.path().join("integrity-signing-key");
        ensure_local_signing_identity(&key_path).unwrap();
        let identity_path = signing_identity_document_path(&key_path);
        let mut document = read_identity_document_if_present(&identity_path)
            .unwrap()
            .unwrap();
        document.notice.push_str(" changed");
        let mut bytes = serde_json::to_vec_pretty(&document).unwrap();
        bytes.push(b'\n');
        overwrite_managed_test_file(&identity_path, &bytes);
        let error = ensure_local_signing_identity(&key_path).unwrap_err();
        assert!(error.to_string().contains("unsupported contract"));
    }

    #[cfg(unix)]
    #[test]
    fn symlink_hardlink_and_broad_mode_are_rejected() {
        use std::os::unix::fs::PermissionsExt;
        let temporary = tempfile::tempdir().unwrap();
        let original = temporary.path().join("original");
        fs::write(&original, [9_u8; 32]).unwrap();
        fs::set_permissions(&original, fs::Permissions::from_mode(0o600)).unwrap();

        let symlink = temporary.path().join("symlink");
        std::os::unix::fs::symlink(&original, &symlink).unwrap();
        assert!(ensure_local_signing_identity(&symlink).is_err());

        let hardlink = temporary.path().join("hardlink");
        fs::hard_link(&original, &hardlink).unwrap();
        assert!(ensure_local_signing_identity(&hardlink).is_err());
        fs::remove_file(&hardlink).unwrap();

        fs::set_permissions(&original, fs::Permissions::from_mode(0o644)).unwrap();
        assert!(ensure_local_signing_identity(&original).is_err());
    }

    #[cfg(windows)]
    #[test]
    fn windows_new_identity_files_have_owner_only_protected_dacls() {
        let temporary = tempfile::tempdir().unwrap();
        let key_path = temporary.path().join("integrity-signing-key");
        let identity = ensure_local_signing_identity(&key_path).unwrap();
        let identity_path = signing_identity_document_path(&key_path);
        let anchor_path = signing_identity_anchor_path(&key_path);

        assert_eq!(fs::read(&key_path).unwrap().len(), 32);
        assert_eq!(
            identity.key_id,
            key_id(
                &SigningKey::from_bytes(&fs::read(&key_path).unwrap().try_into().unwrap())
                    .verifying_key()
            )
        );
        verify_windows_current_user_only_file(&File::open(&key_path).unwrap()).unwrap();
        verify_windows_current_user_only_file(&File::open(identity_path).unwrap()).unwrap();
        verify_windows_current_user_only_file(&File::open(anchor_path).unwrap()).unwrap();
        assert!(!signing_rotation_intent_path(&key_path).exists());
    }

    #[cfg(windows)]
    #[test]
    fn windows_exact_legacy_acl_is_hardened_without_changing_key_identity() {
        use windows_sys::Win32::Security::Authorization::{
            TRUSTEE_IS_USER, TRUSTEE_IS_WELL_KNOWN_GROUP,
        };
        use windows_sys::Win32::Security::{WinBuiltinAdministratorsSid, WinLocalSystemSid};
        let temporary = tempfile::tempdir().unwrap();
        let key_path = temporary.path().join("integrity-signing-key");
        let original = [37_u8; 32];
        let expected_key_id = key_id(&SigningKey::from_bytes(&original).verifying_key());
        write_private_new_file(&key_path, &original).unwrap();
        let user = windows_current_user_sid().unwrap();
        let system = windows_well_known_sid(WinLocalSystemSid).unwrap();
        let administrators = windows_well_known_sid(WinBuiltinAdministratorsSid).unwrap();
        windows_test_set_dacl(
            &key_path,
            &[
                (&user, TRUSTEE_IS_USER),
                (&system, TRUSTEE_IS_WELL_KNOWN_GROUP),
                (&administrators, TRUSTEE_IS_WELL_KNOWN_GROUP),
            ],
        );
        assert!(
            verify_windows_current_user_only_file(&File::open(&key_path).unwrap()).is_err(),
            "the predecessor ACL must not already count as the strict owner-only ACL"
        );

        let identity = ensure_local_signing_identity(&key_path).unwrap();
        assert_eq!(
            identity.continuity_event,
            SigningIdentityContinuityEvent::LegacyKeyAdopted
        );
        assert_eq!(identity.key_id, expected_key_id);
        assert_eq!(fs::read(&key_path).unwrap(), original);
        verify_windows_current_user_only_file(&File::open(&key_path).unwrap()).unwrap();
        let anchor = read_identity_anchor_if_present(&signing_identity_anchor_path(&key_path))
            .unwrap()
            .unwrap();
        assert_eq!(anchor.identity.key_id, expected_key_id);
        assert!(!signing_rotation_intent_path(&key_path).exists());
    }

    #[cfg(windows)]
    #[test]
    fn windows_identity_replacement_uses_recoverable_same_directory_move() {
        let temporary = tempfile::tempdir().unwrap();
        let key_path = temporary.path().join("integrity-signing-key");
        ensure_local_signing_identity(&key_path).unwrap();
        let identity_path = signing_identity_document_path(&key_path);
        let replacement_key = SigningKey::from_bytes(&[59_u8; 32]);
        let replacement = signed_identity_document(
            &replacement_key,
            SigningIdentityContinuityEvent::Generated,
            None,
            Utc::now(),
        )
        .unwrap();
        let staging = path_with_suffix(&identity_path, &format!(".next-{}", replacement.key_id));

        replace_identity_document(&identity_path, &replacement).unwrap();
        assert_eq!(
            read_identity_document_if_present(&identity_path)
                .unwrap()
                .unwrap(),
            replacement
        );
        assert!(!staging.exists());
        verify_windows_current_user_only_file(&File::open(identity_path).unwrap()).unwrap();
    }

    #[cfg(windows)]
    #[test]
    fn windows_foreign_ace_is_rejected_instead_of_hardened() {
        use windows_sys::Win32::Security::Authorization::{
            TRUSTEE_IS_USER, TRUSTEE_IS_WELL_KNOWN_GROUP,
        };
        use windows_sys::Win32::Security::{WinLocalSystemSid, WinWorldSid};
        let temporary = tempfile::tempdir().unwrap();
        let key_path = temporary.path().join("integrity-signing-key");
        write_private_new_file(&key_path, &[41_u8; 32]).unwrap();
        let user = windows_current_user_sid().unwrap();
        let system = windows_well_known_sid(WinLocalSystemSid).unwrap();
        let world = windows_well_known_sid(WinWorldSid).unwrap();
        windows_test_set_dacl(
            &key_path,
            &[
                (&user, TRUSTEE_IS_USER),
                (&system, TRUSTEE_IS_WELL_KNOWN_GROUP),
                (&world, TRUSTEE_IS_WELL_KNOWN_GROUP),
            ],
        );

        assert!(ensure_local_signing_identity(&key_path).is_err());
        assert!(!signing_identity_document_path(&key_path).exists());
    }

    #[cfg(windows)]
    #[test]
    fn windows_wrong_owner_descriptor_is_rejected() {
        use windows_sys::Win32::Security::{
            GetLengthSid, SECURITY_DESCRIPTOR_RELATIVE, WinWorldSid,
        };
        let temporary = tempfile::tempdir().unwrap();
        let key_path = temporary.path().join("integrity-signing-key");
        write_private_new_file(&key_path, &[43_u8; 32]).unwrap();
        let file = File::open(&key_path).unwrap();
        let mut descriptor = windows_security_descriptor(&file).unwrap();
        let user = windows_current_user_sid().unwrap();
        let wrong_owner = windows_well_known_sid(WinWorldSid).unwrap();
        // SAFETY: wrong_owner contains a validated Windows SID.
        let owner_length = unsafe { GetLengthSid(wrong_owner.as_ptr()) } as usize;
        let owner_offset = descriptor.len() * std::mem::size_of::<usize>();
        descriptor.resize(
            descriptor.len() + owner_length.div_ceil(std::mem::size_of::<usize>()),
            0,
        );
        // SAFETY: the resized aligned vector has owner_length writable tail bytes.
        unsafe {
            std::ptr::copy_nonoverlapping(
                wrong_owner.as_ptr().cast::<u8>(),
                descriptor.as_mut_ptr().cast::<u8>().add(owner_offset),
                owner_length,
            );
            (*descriptor
                .as_mut_ptr()
                .cast::<SECURITY_DESCRIPTOR_RELATIVE>())
            .Owner = u32::try_from(owner_offset).unwrap();
        }

        let error = verify_windows_current_user_only_descriptor(descriptor, &user).unwrap_err();
        assert!(error.to_string().contains("owner"));
    }

    #[cfg(windows)]
    #[test]
    fn windows_hardlink_and_reparse_file_information_are_rejected() {
        use windows_sys::Win32::Storage::FileSystem::FILE_ATTRIBUTE_REPARSE_POINT;
        let temporary = tempfile::tempdir().unwrap();
        let key_path = temporary.path().join("integrity-signing-key");
        write_private_new_file(&key_path, &[47_u8; 32]).unwrap();
        let extra_link = temporary.path().join("extra-link");
        fs::hard_link(&key_path, &extra_link).unwrap();
        assert!(ensure_local_signing_identity(&key_path).is_err());

        let reparse = WindowsFileInformation {
            volume_serial: 1,
            file_index: 2,
            size: 32,
            links: 1,
            attributes: FILE_ATTRIBUTE_REPARSE_POINT,
        };
        assert!(validate_windows_private_file_information(&reparse, 32).is_err());
        let multiple_links = WindowsFileInformation {
            attributes: 0,
            links: 2,
            ..reparse
        };
        assert!(validate_windows_private_file_information(&multiple_links, 32).is_err());
    }
}
