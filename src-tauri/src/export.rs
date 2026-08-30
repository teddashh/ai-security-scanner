use crate::beginner_report::{
    BEGINNER_MASTER_REPORT_SCHEMA_VERSION, BeginnerMasterReport, TechnicalExecution,
    build_beginner_master_report,
};
use crate::domain::{
    AssessmentCase, CaseExport, DataSource, EngineTaskKind, Finding, RawArtifact, ScanRun,
    ScopeGrant, new_id,
};
use crate::error::{AppError, AppResult};
use crate::export_identity::{
    LOCAL_SIGNING_IDENTITY_SCHEMA_VERSION, LocalSigningIdentityDocument,
    load_or_create_local_signing_identity, verify_identity_document,
};
use crate::exporters::framework_report::MASTER_FRAMEWORK_REPORT_SCHEMA_VERSION;
use crate::exporters::ocsf::OCSF_SCHEMA_VERSION;
use crate::exporters::oscal::OSCAL_VERSION;
use crate::exporters::{
    export_master_framework_report_bytes, export_ocsf_finding_events_bytes,
    export_oscal_assessment_results_bytes,
};
use crate::external_scope::CanonicalTarget;
use base64::Engine as _;
use base64::engine::general_purpose::STANDARD as BASE64;
use chrono::{DateTime, Utc};
use ed25519_dalek::{Signature, Signer, SigningKey, VerifyingKey};
use flate2::read::GzDecoder;
use flate2::{Compression, GzBuilder};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet};
use std::fs::{self, File, OpenOptions};
use std::io::{self, Read, Write};
use std::path::{Component, Path, PathBuf};
use tar::{Builder, EntryType, Header};

pub const BUNDLE_SCHEMA_VERSION: &str = "1";
pub const MANIFEST_PATH: &str = "manifest.json";
pub const SIGNATURE_PATH: &str = "signature.json";
pub const SIGNING_IDENTITY_PATH: &str = "integrity/local-signing-identity.json";
pub const INTEGRITY_ONLY_NOTICE: &str = "The Ed25519 signature establishes integrity of the signed manifest only. It does not prove scanner correctness, completeness, legal authorization, authorship, identity, audit status, or forensic validity.";
pub const PRELIMINARY_EVIDENCE_NOTICE: &str = "This package contains preliminary scanner evidence, not an audit, certification, attestation, compliance determination, or forensic conclusion. Related control references are navigation coordinates only.";

const IO_BUFFER_BYTES: usize = 64 * 1024;
const MAX_ARCHIVE_ENTRIES: usize = 100_000;
const MAX_RESERVED_DOCUMENT_BYTES: u64 = 16 * 1024 * 1024;
const MAX_SIGNING_IDENTITY_DOCUMENT_BYTES: u64 = 64 * 1024;
const MAX_UNCOMPRESSED_BUNDLE_BYTES: u64 = 50 * 1024 * 1024 * 1024;
const MAX_ARCHIVE_PATH_BYTES: usize = 1_024;

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, Default)]
#[serde(rename_all = "snake_case")]
pub enum RedactionProfile {
    None,
    #[default]
    Standard,
}

impl RedactionProfile {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::None => "none",
            Self::Standard => "standard",
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ExportOptions {
    #[serde(default)]
    pub redaction: RedactionProfile,
    /// Raw artifacts are excluded by default because scanner output frequently
    /// contains credentials, internal identifiers, and exploitable details.
    #[serde(default)]
    pub include_raw_artifacts: bool,
}

impl Default for ExportOptions {
    fn default() -> Self {
        Self {
            redaction: RedactionProfile::Standard,
            include_raw_artifacts: false,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct BundleEntry {
    pub path: String,
    pub media_type: String,
    pub sha256: String,
    pub byte_length: u64,
    pub contains_sensitive_data: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct BundleSigningMetadata {
    pub algorithm: String,
    pub key_id: String,
    pub signed_file: String,
    pub integrity_only_notice: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct BundleManifest {
    pub schema_version: String,
    pub product_name: String,
    pub product_version: String,
    pub created_at: DateTime<Utc>,
    pub case_id: String,
    pub run_id: String,
    pub redaction_profile: RedactionProfile,
    pub demo_data: bool,
    pub schemas: BTreeMap<String, String>,
    pub entries: Vec<BundleEntry>,
    pub raw_artifact_count: usize,
    pub raw_artifacts_included: usize,
    pub signing: BundleSigningMetadata,
    pub notices: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct SignatureEnvelope {
    pub algorithm: String,
    pub key_id: String,
    pub public_key_base64: String,
    pub signature_base64: String,
    pub signed_file: String,
    pub integrity_only_notice: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct RawArtifactExportRecord {
    pub id: String,
    pub case_id: String,
    pub run_id: String,
    pub engine_run_id: String,
    pub source_relative_path: String,
    pub media_type: String,
    pub sha256: String,
    pub byte_length: u64,
    pub created_at: DateTime<Utc>,
    pub contains_sensitive_data: bool,
    pub included: bool,
    pub archive_path: Option<String>,
    pub omission_reason: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct BundleVerification {
    pub valid: bool,
    pub archive_sha256: String,
    pub signer_key_id: String,
    pub public_key_base64: String,
    pub entry_count: usize,
    pub raw_artifacts_included: usize,
    pub manifest: BundleManifest,
    pub integrity_only_notice: String,
}

#[derive(Debug, Clone)]
struct ArtifactSource {
    archive_path: String,
    source_path: PathBuf,
    expected_sha256: String,
    expected_byte_length: u64,
    media_type: String,
    contains_sensitive_data: bool,
}

#[derive(Debug, Clone)]
struct PreparedDocument {
    media_type: String,
    bytes: Vec<u8>,
    contains_sensitive_data: bool,
}

type PreparedDocuments = BTreeMap<String, PreparedDocument>;

#[derive(Debug, Clone, PartialEq, Eq)]
struct ObservedEntry {
    sha256: String,
    byte_length: u64,
}

/// Create a portable `.case.tar.gz` package and sign its manifest with a
/// persistent local Ed25519 key.
pub fn create_case_bundle(
    case: &AssessmentCase,
    run_id: &str,
    artifact_root: impl AsRef<Path>,
    destination: impl AsRef<Path>,
    signing_key_path: impl AsRef<Path>,
    options: ExportOptions,
) -> AppResult<CaseExport> {
    create_case_bundle_at(
        case,
        run_id,
        artifact_root,
        destination,
        signing_key_path,
        options,
        Utc::now(),
    )
}

/// Timestamp-injectable bundle creator for repeatable tests and reproducible
/// automation. All tar and gzip timestamps are normalized to zero.
pub fn create_case_bundle_at(
    case: &AssessmentCase,
    run_id: &str,
    artifact_root: impl AsRef<Path>,
    destination: impl AsRef<Path>,
    signing_key_path: impl AsRef<Path>,
    options: ExportOptions,
    created_at: DateTime<Utc>,
) -> AppResult<CaseExport> {
    let run = selected_run(case, run_id)?;
    let destination = destination.as_ref();
    validate_destination(destination)?;

    let parent = destination
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."));
    fs::create_dir_all(parent)?;
    let parent = fs::canonicalize(parent).map_err(|error| {
        AppError::Internal(format!(
            "export destination directory {} could not be resolved: {error}",
            parent.display()
        ))
    })?;
    let file_name = destination.file_name().ok_or_else(|| {
        AppError::InvalidRequest("export destination must include a filename".into())
    })?;
    let destination = parent.join(file_name);
    if fs::symlink_metadata(&destination).is_ok() {
        return Err(AppError::InvalidRequest(format!(
            "export destination already exists: {}",
            destination.display()
        )));
    }

    let identity = load_or_create_local_signing_identity(signing_key_path.as_ref())?;
    let expected_signer_key_id = identity.document.key_id.clone();
    let signing_identity = identity.document;
    let signing_key = identity.signing_key;
    let verifying_key = signing_key.verifying_key();
    let public_key_base64 = BASE64.encode(verifying_key.as_bytes());
    let key_id = sha256_bytes(verifying_key.as_bytes());
    if key_id != expected_signer_key_id {
        return Err(AppError::NotAuthorized(
            "local export-integrity key changed after its public identity was verified".into(),
        ));
    }

    // Derive coverage truth before Standard redaction removes private Naabu
    // work plans and attempt journals. The report is then redacted as a
    // presentation document; execution evidence is never reconstructed from
    // the reduced export case.
    let beginner_report = beginner_report_for_export(case, run_id, options.redaction)?;
    let redacted_case = case_for_export(case, options.redaction);
    let artifact_root = artifact_root.as_ref();
    let (artifact_records, artifact_sources) = prepare_artifacts(
        case,
        artifact_root,
        options.redaction,
        options.include_raw_artifacts,
    )?;
    let mut documents = build_documents(
        &redacted_case,
        run,
        &beginner_report,
        &artifact_records,
        options.redaction,
        options.include_raw_artifacts,
        created_at,
    )?;
    insert_json(
        &mut documents,
        SIGNING_IDENTITY_PATH,
        &signing_identity,
        false,
    )?;

    let temp_path = parent.join(format!(".ai-security-scanner-{}.case.tmp", new_id()));
    let output = create_private_new_file(&temp_path)?;

    let build_result = build_archive(
        output,
        &documents,
        &artifact_sources,
        case,
        run_id,
        options.redaction,
        created_at,
        &signing_key,
        &key_id,
        &public_key_base64,
        artifact_records.len(),
    );

    let (manifest, envelope) = match build_result {
        Ok(result) => result,
        Err(error) => {
            let _ = fs::remove_file(&temp_path);
            return Err(error);
        }
    };

    let archive_sha256 = match sha256_file(&temp_path) {
        Ok(value) => value,
        Err(error) => {
            let _ = fs::remove_file(&temp_path);
            return Err(error);
        }
    };

    if let Err(error) = fs::hard_link(&temp_path, &destination) {
        let _ = fs::remove_file(&temp_path);
        return Err(AppError::Internal(format!(
            "could not publish export {} without overwriting an existing file: {error}",
            destination.display()
        )));
    }
    if let Err(error) = fs::remove_file(&temp_path) {
        let _ = fs::remove_file(&destination);
        return Err(AppError::Internal(format!(
            "could not remove private export staging file: {error}"
        )));
    }

    let destination = fs::canonicalize(&destination)?;
    debug_assert_eq!(manifest.signing.key_id, envelope.key_id);
    Ok(CaseExport {
        id: new_id(),
        case_id: case.id.clone(),
        run_id: run_id.into(),
        created_at,
        format: Some("case_bundle".into()),
        path: destination.display().to_string(),
        sha256: archive_sha256,
        coverage_manifest_path: None,
        coverage_manifest_sha256: None,
        signature: Some(envelope.signature_base64),
        public_key: Some(envelope.public_key_base64),
        redaction_profile: options.redaction.as_str().into(),
        raw_artifacts_included: Some(manifest.raw_artifacts_included),
        raw_artifacts_omitted: Some(
            manifest
                .raw_artifact_count
                .saturating_sub(manifest.raw_artifacts_included),
        ),
        integrity_only_notice: INTEGRITY_ONLY_NOTICE.into(),
    })
}

/// Alias retained for callers that name the operation after the product action.
pub fn export_case_bundle(
    case: &AssessmentCase,
    run_id: &str,
    artifact_root: impl AsRef<Path>,
    destination: impl AsRef<Path>,
    signing_key_path: impl AsRef<Path>,
    options: ExportOptions,
) -> AppResult<CaseExport> {
    create_case_bundle(
        case,
        run_id,
        artifact_root,
        destination,
        signing_key_path,
        options,
    )
}

/// Verify the archive hash, every manifest entry hash, and the embedded Ed25519
/// signature. The returned public key remains self-asserted unless a caller pins
/// it with [`verify_case_bundle_against`].
pub fn verify_case_bundle(path: impl AsRef<Path>) -> AppResult<BundleVerification> {
    verify_case_bundle_against(path, None, None)
}

/// Verify a bundle and optionally pin the expected whole-archive hash and public
/// key from a separately retained `CaseExport` record.
pub fn verify_case_bundle_against(
    path: impl AsRef<Path>,
    expected_archive_sha256: Option<&str>,
    expected_public_key_base64: Option<&str>,
) -> AppResult<BundleVerification> {
    let path = path.as_ref();
    let archive_sha256 = sha256_file(path)?;
    if let Some(expected) = expected_archive_sha256
        && !archive_sha256.eq_ignore_ascii_case(expected)
    {
        return Err(AppError::InvalidRequest(format!(
            "bundle archive hash mismatch: expected {expected}, observed {archive_sha256}"
        )));
    }

    let file = File::open(path)?;
    let decoder = GzDecoder::new(file);
    let mut archive = tar::Archive::new(decoder);
    let mut observed = BTreeMap::<String, ObservedEntry>::new();
    let mut manifest_bytes = None;
    let mut signature_bytes = None;
    let mut signing_identity_bytes = None;
    let mut entry_count = 0_usize;
    let mut total_bytes = 0_u64;

    for entry in archive.entries()? {
        let mut entry = entry?;
        entry_count = entry_count.saturating_add(1);
        if entry_count > MAX_ARCHIVE_ENTRIES {
            return Err(AppError::InvalidRequest(format!(
                "bundle exceeds the entry limit of {MAX_ARCHIVE_ENTRIES}"
            )));
        }

        let entry_type = entry.header().entry_type();
        if entry_type != EntryType::Regular && entry_type != EntryType::Continuous {
            return Err(AppError::InvalidRequest(
                "bundle contains a non-regular archive entry".into(),
            ));
        }
        let archive_path = entry.path()?.into_owned();
        let archive_path = validate_portable_archive_path(&archive_path)?;
        if observed.contains_key(&archive_path)
            || (archive_path == MANIFEST_PATH && manifest_bytes.is_some())
            || (archive_path == SIGNATURE_PATH && signature_bytes.is_some())
        {
            return Err(AppError::InvalidRequest(format!(
                "bundle contains duplicate entry: {archive_path}"
            )));
        }

        let size = entry.size();
        total_bytes = total_bytes
            .checked_add(size)
            .ok_or_else(|| AppError::InvalidRequest("bundle uncompressed size overflow".into()))?;
        if total_bytes > MAX_UNCOMPRESSED_BUNDLE_BYTES {
            return Err(AppError::InvalidRequest(format!(
                "bundle exceeds the uncompressed size limit of {MAX_UNCOMPRESSED_BUNDLE_BYTES} bytes"
            )));
        }

        if archive_path == MANIFEST_PATH || archive_path == SIGNATURE_PATH {
            if size > MAX_RESERVED_DOCUMENT_BYTES {
                return Err(AppError::InvalidRequest(format!(
                    "reserved bundle document is too large: {archive_path}"
                )));
            }
            let bytes = read_exact_entry(&mut entry, size)?;
            if archive_path == MANIFEST_PATH {
                manifest_bytes = Some(bytes);
            } else {
                signature_bytes = Some(bytes);
            }
        } else if archive_path == SIGNING_IDENTITY_PATH {
            if size > MAX_SIGNING_IDENTITY_DOCUMENT_BYTES {
                return Err(AppError::InvalidRequest(
                    "bundle signing identity document is too large".into(),
                ));
            }
            let bytes = read_exact_entry(&mut entry, size)?;
            observed.insert(
                archive_path,
                ObservedEntry {
                    sha256: sha256_bytes(&bytes),
                    byte_length: bytes.len() as u64,
                },
            );
            signing_identity_bytes = Some(bytes);
        } else {
            let (sha256, byte_length) = sha256_reader(&mut entry)?;
            if byte_length != size {
                return Err(AppError::InvalidRequest(format!(
                    "archive entry length mismatch: {archive_path}"
                )));
            }
            observed.insert(
                archive_path,
                ObservedEntry {
                    sha256,
                    byte_length,
                },
            );
        }
    }

    let manifest_bytes = manifest_bytes
        .ok_or_else(|| AppError::InvalidRequest(format!("bundle is missing {MANIFEST_PATH}")))?;
    let signature_bytes = signature_bytes
        .ok_or_else(|| AppError::InvalidRequest(format!("bundle is missing {SIGNATURE_PATH}")))?;
    let manifest: BundleManifest = serde_json::from_slice(&manifest_bytes).map_err(|error| {
        AppError::InvalidRequest(format!("bundle manifest is invalid JSON: {error}"))
    })?;
    let envelope: SignatureEnvelope =
        serde_json::from_slice(&signature_bytes).map_err(|error| {
            AppError::InvalidRequest(format!("bundle signature is invalid JSON: {error}"))
        })?;

    validate_manifest(&manifest, &observed)?;
    verify_signature(&manifest_bytes, &manifest, &envelope)?;
    verify_embedded_signing_identity(&manifest, &envelope, signing_identity_bytes.as_deref())?;

    if let Some(expected_public_key) = expected_public_key_base64
        && expected_public_key != envelope.public_key_base64
    {
        return Err(AppError::InvalidRequest(
            "bundle signing key does not match the expected public key".into(),
        ));
    }

    Ok(BundleVerification {
        valid: true,
        archive_sha256,
        signer_key_id: envelope.key_id,
        public_key_base64: envelope.public_key_base64,
        entry_count: observed.len(),
        raw_artifacts_included: manifest.raw_artifacts_included,
        integrity_only_notice: INTEGRITY_ONLY_NOTICE.into(),
        manifest,
    })
}

#[allow(clippy::too_many_arguments)]
fn build_archive(
    output: File,
    documents: &PreparedDocuments,
    artifact_sources: &BTreeMap<String, ArtifactSource>,
    case: &AssessmentCase,
    run_id: &str,
    redaction_profile: RedactionProfile,
    created_at: DateTime<Utc>,
    signing_key: &SigningKey,
    key_id: &str,
    public_key_base64: &str,
    raw_artifact_count: usize,
) -> AppResult<(BundleManifest, SignatureEnvelope)> {
    let encoder = GzBuilder::new()
        .mtime(0)
        .write(output, Compression::default());
    let mut archive = Builder::new(encoder);
    let mut entries = Vec::<BundleEntry>::new();

    for (path, document) in documents {
        validate_portable_archive_path(Path::new(path))?;
        append_bytes(&mut archive, path, &document.bytes)?;
        entries.push(BundleEntry {
            path: path.clone(),
            media_type: document.media_type.clone(),
            sha256: sha256_bytes(&document.bytes),
            byte_length: document.bytes.len() as u64,
            contains_sensitive_data: document.contains_sensitive_data,
        });
    }

    for source in artifact_sources.values() {
        let entry = append_artifact(&mut archive, source)?;
        entries.push(entry);
    }
    entries.sort_by(|left, right| left.path.cmp(&right.path));

    let raw_artifacts_included = artifact_sources.len();
    let mut schemas = BTreeMap::new();
    schemas.insert("bundle".into(), BUNDLE_SCHEMA_VERSION.into());
    schemas.insert(
        "beginner_master_report".into(),
        BEGINNER_MASTER_REPORT_SCHEMA_VERSION.into(),
    );
    schemas.insert(
        "master_framework_report".into(),
        MASTER_FRAMEWORK_REPORT_SCHEMA_VERSION.into(),
    );
    schemas.insert(
        "local_signing_identity".into(),
        LOCAL_SIGNING_IDENTITY_SCHEMA_VERSION.into(),
    );
    schemas.insert("ocsf".into(), OCSF_SCHEMA_VERSION.into());
    schemas.insert("oscal".into(), OSCAL_VERSION.into());
    let mut notices = vec![
        PRELIMINARY_EVIDENCE_NOTICE.into(),
        INTEGRITY_ONLY_NOTICE.into(),
        "Raw artifact omission is recorded in raw-artifacts.json; omission is not evidence of a clean result.".into(),
        "Finding groups are reversible presentation metadata; canonical findings and evidence remain independent, and create/remove history is retained.".into(),
    ];
    if case.is_demo {
        notices.push(
            "SYNTHETIC DEMO DATA: this package must not be represented as a real scan or engine validation."
                .into(),
        );
    }

    let manifest = BundleManifest {
        schema_version: BUNDLE_SCHEMA_VERSION.into(),
        product_name: "ai-security-scanner".into(),
        product_version: env!("CARGO_PKG_VERSION").into(),
        created_at,
        case_id: case.id.clone(),
        run_id: run_id.into(),
        redaction_profile,
        demo_data: case.is_demo,
        schemas,
        entries,
        raw_artifact_count,
        raw_artifacts_included,
        signing: BundleSigningMetadata {
            algorithm: "Ed25519".into(),
            key_id: key_id.into(),
            signed_file: MANIFEST_PATH.into(),
            integrity_only_notice: INTEGRITY_ONLY_NOTICE.into(),
        },
        notices,
    };
    let manifest_bytes = json_bytes(&manifest)?;
    let signature: Signature = signing_key.sign(&manifest_bytes);
    let envelope = SignatureEnvelope {
        algorithm: "Ed25519".into(),
        key_id: key_id.into(),
        public_key_base64: public_key_base64.into(),
        signature_base64: BASE64.encode(signature.to_bytes()),
        signed_file: MANIFEST_PATH.into(),
        integrity_only_notice: INTEGRITY_ONLY_NOTICE.into(),
    };
    let signature_bytes = json_bytes(&envelope)?;

    append_bytes(&mut archive, MANIFEST_PATH, &manifest_bytes)?;
    append_bytes(&mut archive, SIGNATURE_PATH, &signature_bytes)?;
    archive.finish()?;
    let encoder = archive.into_inner()?;
    let output = encoder.finish()?;
    output.sync_all()?;

    Ok((manifest, envelope))
}

fn append_bytes<W: Write>(archive: &mut Builder<W>, path: &str, bytes: &[u8]) -> AppResult<()> {
    let mut header = normalized_header(bytes.len() as u64);
    archive.append_data(&mut header, path, bytes)?;
    Ok(())
}

fn append_artifact<W: Write>(
    archive: &mut Builder<W>,
    source: &ArtifactSource,
) -> AppResult<BundleEntry> {
    validate_portable_archive_path(Path::new(&source.archive_path))?;
    let metadata = fs::symlink_metadata(&source.source_path)?;
    if metadata.file_type().is_symlink() || !metadata.is_file() {
        return Err(AppError::InvalidRequest(format!(
            "raw artifact must be a regular file and not a symlink: {}",
            source.source_path.display()
        )));
    }

    let file = File::open(&source.source_path)?;
    let actual_size = file.metadata()?.len();
    if actual_size != source.expected_byte_length {
        return Err(AppError::InvalidRequest(format!(
            "raw artifact length changed before export: {}",
            source.source_path.display()
        )));
    }

    let mut hashing_reader = HashingReader::new(file);
    let mut header = normalized_header(actual_size);
    archive.append_data(&mut header, &source.archive_path, &mut hashing_reader)?;
    let (actual_sha256, byte_length) = hashing_reader.finish();
    if byte_length != source.expected_byte_length
        || !actual_sha256.eq_ignore_ascii_case(&source.expected_sha256)
    {
        return Err(AppError::InvalidRequest(format!(
            "raw artifact hash or length changed before export: {}",
            source.source_path.display()
        )));
    }

    Ok(BundleEntry {
        path: source.archive_path.clone(),
        media_type: source.media_type.clone(),
        sha256: actual_sha256,
        byte_length,
        contains_sensitive_data: source.contains_sensitive_data,
    })
}

fn normalized_header(size: u64) -> Header {
    let mut header = Header::new_gnu();
    header.set_size(size);
    header.set_mode(0o600);
    header.set_uid(0);
    header.set_gid(0);
    header.set_mtime(0);
    header.set_entry_type(EntryType::Regular);
    header.set_cksum();
    header
}

fn build_documents(
    case: &AssessmentCase,
    selected_run: &ScanRun,
    beginner_report: &BeginnerMasterReport,
    artifact_records: &[RawArtifactExportRecord],
    redaction: RedactionProfile,
    include_raw_artifacts: bool,
    created_at: DateTime<Utc>,
) -> AppResult<PreparedDocuments> {
    let mut documents = PreparedDocuments::new();
    let run_id = beginner_report.run_id.as_str();
    let case_document = json!({
        "schema_version": BUNDLE_SCHEMA_VERSION,
        "id": case.id,
        "title": case.title,
        "profile": case.profile,
        "status": case.status,
        "created_at": case.created_at,
        "updated_at": case.updated_at,
        "knowledge_cutoff": case.knowledge_cutoff,
        "is_demo": case.is_demo,
        "requested_activities": case.requested_activities,
        "data_sources": case.data_sources,
        "selected_run_id": run_id,
        "exported_at": created_at,
        "counts": {
            "assets": case.assets.len(),
            "scope_grants": case.scope_grants.len(),
            "coverage_entries": case.coverage.len(),
            "scan_runs": case.scan_runs.len(),
            "findings": case.findings.len(),
            "finding_groups": case.finding_groups.len(),
            "finding_group_events": case.finding_group_events.len(),
            "finding_workflow_events": case.finding_workflow_events.len(),
            "observations": case.finding_observations.len(),
            "raw_artifacts": artifact_records.len(),
            "comparisons": case.comparisons.len()
        }
    });
    insert_json(&mut documents, "case.json", &case_document, false)?;
    insert_json(
        &mut documents,
        "assets.json",
        &json!({
            "assets": case.assets,
            "asset_relations": case.asset_relations
        }),
        true,
    )?;
    insert_json(
        &mut documents,
        "scope.json",
        &json!({ "scope_grants": case.scope_grants }),
        true,
    )?;
    insert_json(
        &mut documents,
        "coverage.json",
        &json!({ "coverage": case.coverage }),
        true,
    )?;
    insert_json(
        &mut documents,
        "scan-runs.json",
        &json!({ "scan_runs": case.scan_runs }),
        true,
    )?;
    insert_json(
        &mut documents,
        "findings.json",
        &json!({
            "findings": case.findings,
            "active_groups": case.finding_groups
        }),
        true,
    )?;
    insert_json(
        &mut documents,
        "finding-grouping.json",
        &json!({
            "active_groups": case.finding_groups,
            "finding_group_events": case.finding_group_events,
            "notice": "Finding groups are reversible presentation metadata. Canonical findings, fingerprints, evidence, and raw artifacts remain independent; removal appends an event instead of deleting member records."
        }),
        true,
    )?;
    insert_json(
        &mut documents,
        "finding-workflow.json",
        &json!({ "finding_workflow_events": case.finding_workflow_events }),
        true,
    )?;
    insert_json(
        &mut documents,
        "observations.json",
        &json!({ "finding_observations": case.finding_observations }),
        true,
    )?;
    insert_json(
        &mut documents,
        "comparisons.json",
        &json!({ "verification_comparisons": case.comparisons }),
        true,
    )?;
    insert_json(
        &mut documents,
        "engine-versions.json",
        &json!({ "catalog_engine_runs": engine_version_records(case) }),
        false,
    )?;
    insert_json(
        &mut documents,
        "built-in-tasks.json",
        &json!({ "built_in_tasks": built_in_task_records(case) }),
        false,
    )?;
    insert_json(
        &mut documents,
        "raw-artifacts.json",
        &json!({ "raw_artifacts": artifact_records }),
        true,
    )?;
    insert_json(
        &mut documents,
        "exports/beginner-master-report.json",
        &json!({
            "schema_version": BEGINNER_MASTER_REPORT_SCHEMA_VERSION,
            "product_name": "ai-security-scanner",
            "product_version": env!("CARGO_PKG_VERSION"),
            "export_kind": "beginner_master_report",
            "selected_run_id": beginner_report.run_id.clone(),
            "redaction_profile": redaction.as_str(),
            "raw_artifact_bytes_included": false,
            "notice": beginner_report.framework_notice.non_certification.clone(),
            "report": beginner_report,
        }),
        true,
    )?;
    documents.insert(
        "exports/master-framework-report.json".into(),
        PreparedDocument {
            media_type: "application/json".into(),
            bytes: export_master_framework_report_bytes(case, run_id)?,
            contains_sensitive_data: true,
        },
    );
    documents.insert(
        "exports/ocsf-detection-findings.json".into(),
        PreparedDocument {
            media_type: "application/json".into(),
            bytes: export_ocsf_finding_events_bytes(case, run_id)?,
            contains_sensitive_data: true,
        },
    );
    documents.insert(
        "exports/oscal-assessment-results.json".into(),
        PreparedDocument {
            media_type: "application/oscal+json".into(),
            bytes: export_oscal_assessment_results_bytes(case, run_id)?,
            contains_sensitive_data: true,
        },
    );
    documents.insert(
        "README.txt".into(),
        PreparedDocument {
            media_type: "text/plain; charset=utf-8".into(),
            bytes: readme(
                case,
                selected_run,
                redaction,
                include_raw_artifacts,
                artifact_records,
                created_at,
            )
            .into_bytes(),
            contains_sensitive_data: false,
        },
    );
    Ok(documents)
}

fn insert_json<T: Serialize>(
    documents: &mut PreparedDocuments,
    path: &str,
    value: &T,
    contains_sensitive_data: bool,
) -> AppResult<()> {
    documents.insert(
        path.into(),
        PreparedDocument {
            media_type: "application/json".into(),
            bytes: json_bytes(value)?,
            contains_sensitive_data,
        },
    );
    Ok(())
}

fn json_bytes<T: Serialize>(value: &T) -> AppResult<Vec<u8>> {
    let mut bytes = serde_json::to_vec_pretty(value)?;
    bytes.push(b'\n');
    Ok(bytes)
}

fn readme(
    case: &AssessmentCase,
    selected_run: &ScanRun,
    redaction: RedactionProfile,
    include_raw_artifacts: bool,
    artifacts: &[RawArtifactExportRecord],
    created_at: DateTime<Utc>,
) -> String {
    let included = artifacts
        .iter()
        .filter(|artifact| artifact.included)
        .count();
    let omitted = artifacts.len().saturating_sub(included);
    let demo_notice = if case.is_demo {
        "\nSYNTHETIC DEMO DATA: Do not represent this package as a real scan or engine validation.\n"
    } else {
        ""
    };
    format!(
        "ai-security-scanner portable case\n\n\
         Case ID: {}\n\
         Selected run ID: {}\n\
         Selected run sequence: {}\n\
         Exported at: {}\n\
         Redaction profile: {}\n\
         Raw artifact option selected: {}\n\
         Raw artifacts included: {}\n\
         Raw artifacts omitted: {}\n\
         Active finding groups: {}\n\
         Immutable finding-group events: {}\n\
         {}\n\
         IMPORTANT LIMITATIONS\n\
         {}\n\
         {}\n\
         Start with exports/beginner-master-report.json for what was tested, what was not tested, the problems found, and the next actions.\n\
         Control references in canonical, OCSF, and OSCAL files are related coordinates only.\n\
         Absence of a finding or omitted evidence is not a clean-result assertion.\n\
         Finding groups are reversible presentation metadata; canonical findings and evidence remain independent.\n\
         Review finding-grouping.json for active groups and their append-only create/remove history.\n\
         Review raw-artifacts.json for every included or intentionally omitted raw artifact.\n\
         manifest.json contains the SHA-256 hash and byte length of every payload file.\n\
         signature.json contains the public key and Ed25519 signature over manifest.json.\n",
        case.id,
        selected_run.id,
        selected_run.sequence,
        created_at.to_rfc3339(),
        redaction.as_str(),
        include_raw_artifacts,
        included,
        omitted,
        case.finding_groups.len(),
        case.finding_group_events.len(),
        demo_notice,
        PRELIMINARY_EVIDENCE_NOTICE,
        INTEGRITY_ONLY_NOTICE,
    )
}

fn engine_version_records(case: &AssessmentCase) -> Vec<Value> {
    let mut records = Vec::new();
    for run in &case.scan_runs {
        for engine_run in &run.engine_runs {
            if engine_run.task_kind != EngineTaskKind::CatalogEngine {
                continue;
            }
            records.push(json!({
                "scan_run_id": run.id,
                "scan_run_sequence": run.sequence,
                "knowledge_cutoff": run.knowledge_cutoff,
                "engine_run_id": engine_run.id,
                "engine_id": engine_run.engine_id,
                "status": engine_run.status,
                "engine_version": engine_run.engine_version,
                "image_digest": engine_run.image_digest,
                "rule_version": engine_run.rule_version,
                "adapter_version": engine_run.adapter_version,
                "manifest_schema_version": engine_run.manifest_schema_version,
                "source_revision": engine_run.source_revision,
                "repository_url": engine_run.repository_url,
                "distribution_mode": engine_run.distribution_mode,
                "image_repository": engine_run.image_repository,
                "command_sha256": engine_run.command_sha256,
                "knowledge_input": engine_run.knowledge_input,
                "runtime_provider": engine_run.runtime_provider,
                "runtime_version": engine_run.runtime_version,
                "runtime_security_options": engine_run.runtime_security_options,
                "exit_code": engine_run.exit_code,
                "cleanup_removed": engine_run.cleanup_removed,
                "cleanup_detail": engine_run.cleanup_detail,
                "warnings": engine_run.warnings,
                "error_code": engine_run.error_code,
                "error_message": engine_run.error_message
            }));
        }
    }
    records
}

fn built_in_task_records(case: &AssessmentCase) -> Vec<Value> {
    let mut records = Vec::new();
    for run in &case.scan_runs {
        for engine_run in &run.engine_runs {
            if matches!(engine_run.task_kind, EngineTaskKind::CatalogEngine) {
                continue;
            }
            records.push(json!({
                "scan_run_id": run.id,
                "scan_run_sequence": run.sequence,
                "scan_run_completed_at": run.completed_at,
                "task_run_id": engine_run.id,
                "task_kind": engine_run.task_kind,
                "asset_ids": engine_run.asset_ids,
                "status": engine_run.status,
                "progress_percent": engine_run.progress_percent,
                "phase": engine_run.phase,
                "started_at": engine_run.started_at,
                "finished_at": engine_run.finished_at,
                "localhost_tcp_observation": engine_run.localhost_tcp_observation,
                "error_code": engine_run.error_code,
                "error_message": engine_run.error_message,
                "warnings": engine_run.warnings,
                "notice": "This product-owned task record is not a catalog engine, container execution, vulnerability finding, or security verdict."
            }));
        }
    }
    records
}

fn selected_run<'a>(case: &'a AssessmentCase, run_id: &str) -> AppResult<&'a ScanRun> {
    let run = case
        .scan_runs
        .iter()
        .find(|run| run.id == run_id)
        .ok_or_else(|| AppError::InvalidRequest(format!("scan run not found: {run_id}")))?;
    if run.case_id != case.id {
        return Err(AppError::InvalidRequest(
            "scan run does not belong to the selected case".into(),
        ));
    }
    Ok(run)
}

pub(crate) fn case_for_export(
    case: &AssessmentCase,
    redaction: RedactionProfile,
) -> AssessmentCase {
    let mut exported = case.clone();
    exported.exports.clear();
    sort_case(&mut exported);

    if redaction == RedactionProfile::Standard {
        let sensitive_replacements = standard_redaction_replacements(&exported);
        exported.title = "Redacted assessment case".into();
        exported.profile.organization_name = "[redacted]".into();
        exported.profile.notes = None;
        for (index, source) in exported.data_sources.iter_mut().enumerate() {
            redact_data_source(source, index + 1);
        }
        for (index, asset) in exported.assets.iter_mut().enumerate() {
            asset.name = format!("Asset {}", index + 1);
            asset.provider = None;
            asset.region = None;
            asset.identifiers.clear();
            asset.metadata.clear();
        }
        for grant in &mut exported.scope_grants {
            redact_scope_grant(grant);
        }
        for event in &mut exported.finding_workflow_events {
            event.decided_by = "[redacted]".into();
            event.reason = "[redacted finding workflow reason]".into();
        }
        for group in &mut exported.finding_groups {
            group.title = "[redacted finding group]".into();
            group.rationale = "[redacted grouping rationale]".into();
            group.grouped_by = "[redacted]".into();
        }
        for event in &mut exported.finding_group_events {
            event.title = "[redacted finding group]".into();
            event.rationale = "[redacted grouping rationale]".into();
            event.actor = "[redacted]".into();
        }
        for coverage in &mut exported.coverage {
            coverage.scope_key = "[redacted]".into();
            coverage.label = "[redacted]".into();
            coverage.explanation = "[redacted coverage detail]".into();
        }
        for run in &mut exported.scan_runs {
            for grant in &mut run.scope_grant_snapshots {
                redact_scope_grant(grant);
            }
            for engine_run in &mut run.engine_runs {
                engine_run.resume_token = None;
                // The private work plan contains exact resolved targets and
                // ports. Standard exports retain the ordinary redacted run
                // outcome, but never this execution-only target corpus.
                engine_run.naabu_work_plan = None;
                engine_run.naabu_attempt_requests.clear();
                engine_run.naabu_attempt_results.clear();
                engine_run.error_message = engine_run
                    .error_message
                    .as_ref()
                    .map(|_| "[redacted engine error detail]".into());
                engine_run.cleanup_detail = engine_run
                    .cleanup_detail
                    .as_ref()
                    .map(|_| "[redacted cleanup detail]".into());
                engine_run.warnings = engine_run
                    .warnings
                    .iter()
                    .map(|_| "[redacted engine warning]".into())
                    .collect();
            }
        }
        for finding in &mut exported.findings {
            redact_finding(finding, &sensitive_replacements);
        }
        for observation in &mut exported.finding_observations {
            if let Some(snapshot) = &mut observation.finding_snapshot {
                redact_finding(snapshot, &sensitive_replacements);
            }
        }
        for artifact in &mut exported.raw_artifacts {
            artifact.relative_path = "[redacted]".into();
        }
        for comparison in &mut exported.comparisons {
            for diff in &mut comparison.diffs {
                diff.explanation = "[redacted comparison detail]".into();
                for reason in &mut diff.reasons {
                    reason.detail = "[redacted comparison reason]".into();
                }
            }
            for issue in &mut comparison.completeness_issues {
                issue.detail = "[redacted comparison completeness reason]".into();
            }
        }
    }
    exported
}

/// Builds the authoritative run report from the full durable case before any
/// private execution corpus is removed. Standard redaction changes only
/// presentation text and requested target details; coverage states, counts,
/// gap kinds, run identity, and evidence hashes remain authoritative.
pub(crate) fn beginner_report_for_export(
    case: &AssessmentCase,
    run_id: &str,
    redaction: RedactionProfile,
) -> AppResult<BeginnerMasterReport> {
    let mut report = build_beginner_master_report(case, run_id)
        .map_err(|error| AppError::InvalidRequest(error.to_string()))?;
    if redaction == RedactionProfile::Standard {
        let mut alias_case = case.clone();
        sort_case(&mut alias_case);
        redact_beginner_master_report(&mut report, &alias_case);
    }
    Ok(report)
}

fn redact_beginner_master_report(report: &mut BeginnerMasterReport, case: &AssessmentCase) {
    let replacements = standard_redaction_replacements(case);
    report.project_title = "Redacted assessment case".into();
    redact_known_literals(&mut report.state.explanation, &replacements);

    for target in &mut report.requested.targets {
        target.label = Some(
            case.assets
                .iter()
                .position(|asset| asset.id == target.asset_id)
                .map(|index| format!("Asset {}", index + 1))
                .unwrap_or_else(|| "[redacted target]".into()),
        );
    }
    redact_known_literals(&mut report.requested.stage.explanation, &replacements);
    for limit in &mut report.requested.limits {
        redact_known_literals(&mut limit.name, &replacements);
        match limit.source {
            crate::beginner_report::RequestedLimitSource::FrozenScopeGrant => {
                limit.value = "[redacted scope limit]".into();
            }
            crate::beginner_report::RequestedLimitSource::FrozenTaskContract
                if limit.name.eq_ignore_ascii_case("endpoint") =>
            {
                limit.value = "[redacted endpoint]".into();
            }
            crate::beginner_report::RequestedLimitSource::FrozenTaskContract => {
                redact_known_literals(&mut limit.value, &replacements);
            }
        }
    }
    for reduction in &mut report.requested.automatic_reductions {
        for value in [&mut reduction.dimension, &mut reduction.reason] {
            redact_known_literals(value, &replacements);
        }
        reduction.requested = "[redacted requested scope]".into();
        reduction.executed = "[redacted executed scope]".into();
    }
    for unavailable in &mut report.requested.unavailable_dimensions {
        redact_known_literals(&mut unavailable.dimension, &replacements);
        redact_known_literals(&mut unavailable.explanation, &replacements);
    }

    for check in &mut report.actual.checks {
        for dimension in &mut check.tested_dimensions {
            redact_known_literals(&mut dimension.dimension, &replacements);
            redact_known_literals(&mut dimension.value, &replacements);
            redact_known_literals(&mut dimension.observation, &replacements);
        }
    }
    for unavailable in &mut report.actual.unavailable_dimensions {
        redact_known_literals(&mut unavailable.dimension, &replacements);
        redact_known_literals(&mut unavailable.explanation, &replacements);
    }
    for gap in &mut report.coverage_gaps {
        if gap.kind == crate::beginner_report::CoverageGapKind::Excluded {
            gap.dimension = "Excluded coverage area".into();
            gap.reason = "[redacted coverage detail]".into();
        } else {
            redact_known_literals(&mut gap.dimension, &replacements);
            redact_known_literals(&mut gap.reason, &replacements);
        }
        redact_known_literals(&mut gap.next_action, &replacements);
    }

    for finding in &mut report.findings {
        for value in [
            &mut finding.title,
            &mut finding.plain_language_risk,
            &mut finding.possible_impact,
            &mut finding.next_step,
            &mut finding.recommended_expert_type,
        ] {
            redact_known_literals(value, &replacements);
        }
        for reason in &mut finding.priority_reasons {
            redact_known_literals(reason, &replacements);
        }
        for reference in &mut finding.framework_references {
            for value in [
                &mut reference.title,
                &mut reference.relationship,
                &mut reference.rationale,
            ] {
                redact_known_literals(value, &replacements);
            }
        }
    }
    for step in &mut report.next_steps {
        redact_known_literals(&mut step.action, &replacements);
        redact_known_literals(&mut step.reason, &replacements);
        if let Some(expert) = &mut step.recommended_expert_type {
            redact_known_literals(expert, &replacements);
        }
    }

    for task in &mut report.technical_details.tasks {
        redact_known_literals(&mut task.phase, &replacements);
        for value in [
            &mut task.cleanup_detail,
            &mut task.redacted_scanner_message,
            &mut task.redacted_diagnostic_log,
        ] {
            if let Some(value) = &mut value.value {
                redact_known_literals(value, &replacements);
            }
            redact_known_literals(&mut value.explanation, &replacements);
        }
        match &mut task.execution {
            TechnicalExecution::BuiltInLocalhostTcp { endpoint, .. } => {
                *endpoint = "[redacted endpoint]".into();
            }
            TechnicalExecution::InvalidBuiltInTask { explanation } => {
                redact_known_literals(explanation, &replacements);
            }
            TechnicalExecution::CatalogEngine { .. } => {}
        }
    }
    redact_known_literals(
        &mut report.framework_notice.non_certification,
        &replacements,
    );
    redact_known_literals(
        &mut report.framework_notice.aidefend_mapping_status,
        &replacements,
    );
    for warning in &mut report.data_quality_warnings {
        redact_known_literals(warning, &replacements);
    }
}

fn redact_scope_grant(grant: &mut ScopeGrant) {
    grant.confirmed_by = "[redacted]".into();
    grant.authorization_reference = None;
    grant.notes = None;
    if let Some(external) = &mut grant.external_scope {
        external.target = CanonicalTarget::Hostname("[redacted external target]".into());
        external.ports.clear();
        external.asserted_authority = "[redacted authority assertion]".into();
        external.approved_by = "[redacted]".into();
    }
}

fn redact_data_source(source: &mut DataSource, index: usize) {
    source.label = format!("Source {index}");
    source.metadata.clear();
}

fn redact_finding(finding: &mut Finding, replacements: &[(String, String)]) {
    redact_known_literals(&mut finding.title, replacements);
    redact_known_literals(&mut finding.plain_language_summary, replacements);
    redact_known_literals(&mut finding.possible_impact, replacements);
    redact_known_literals(&mut finding.recommendation, replacements);
    redact_known_literals(&mut finding.verification_guidance, replacements);
    if let Some(rollback) = &mut finding.rollback_considerations {
        redact_known_literals(rollback, replacements);
    }
    for reason in &mut finding.priority_reasons {
        redact_known_literals(reason, replacements);
    }
    for tag in &mut finding.tags {
        redact_known_literals(tag, replacements);
    }
    for reference in &mut finding.official_references {
        redact_known_literals(reference, replacements);
    }
    redact_known_literals(&mut finding.recommended_expert_type, replacements);
    for evidence in &mut finding.evidence {
        evidence.summary = "[redacted evidence summary]".into();
        evidence.pointer = None;
        evidence.redacted = true;
    }
}

fn standard_redaction_replacements(case: &AssessmentCase) -> Vec<(String, String)> {
    let mut replacements = Vec::new();
    add_redaction_replacement(&mut replacements, &case.title, "Redacted assessment case");
    add_redaction_replacement(
        &mut replacements,
        &case.profile.organization_name,
        "Organization",
    );
    for (index, source) in case.data_sources.iter().enumerate() {
        add_redaction_replacement(
            &mut replacements,
            &source.label,
            &format!("Source {}", index + 1),
        );
    }
    for (index, asset) in case.assets.iter().enumerate() {
        let alias = format!("Asset {}", index + 1);
        add_redaction_replacement(&mut replacements, &asset.name, &alias);
        if let Some(provider) = asset.provider.as_deref() {
            add_redaction_replacement(&mut replacements, provider, "[redacted provider]");
        }
        if let Some(region) = asset.region.as_deref() {
            add_redaction_replacement(&mut replacements, region, "[redacted region]");
        }
        for identifier in &asset.identifiers {
            add_redaction_replacement(&mut replacements, &identifier.value, &alias);
        }
    }
    for grant in &case.scope_grants {
        if let Some(external) = grant.external_scope.as_ref() {
            let alias = case
                .assets
                .iter()
                .position(|asset| asset.id == grant.asset_id)
                .map(|index| format!("Asset {}", index + 1))
                .unwrap_or_else(|| "[redacted target]".into());
            add_redaction_replacement(&mut replacements, &external.target.canonical_text(), &alias);
        }
    }
    // A grant can be removed or replaced after a run. The run snapshot still
    // appears in technical export fields and historical finding prose, so it
    // is part of the Standard redaction corpus even when no live grant points
    // to that target anymore.
    for run in &case.scan_runs {
        for grant in &run.scope_grant_snapshots {
            let Some(external) = grant.external_scope.as_ref() else {
                continue;
            };
            let alias = case
                .assets
                .iter()
                .position(|asset| asset.id == grant.asset_id)
                .map(|index| format!("Asset {}", index + 1))
                .unwrap_or_else(|| "[redacted target]".into());
            add_redaction_replacement(&mut replacements, &external.target.canonical_text(), &alias);
        }
    }
    // A frozen Naabu plan may contain DNS answers that never appeared in the
    // asset or grant text. Findings can legitimately quote those observed
    // addresses, so collect the private execution corpus before the plan is
    // removed from a standard export.
    for run in &case.scan_runs {
        for engine_run in &run.engine_runs {
            let Some(plan) = engine_run.naabu_work_plan.as_ref() else {
                continue;
            };
            for frozen_grant in &plan.frozen_grants {
                let alias = case
                    .assets
                    .iter()
                    .position(|asset| asset.id == frozen_grant.asset_id)
                    .map(|index| format!("Asset {}", index + 1))
                    .unwrap_or_else(|| "[redacted target]".into());
                add_redaction_replacement(
                    &mut replacements,
                    &frozen_grant.target.canonical_text(),
                    &alias,
                );
                if let Some(hostname) = frozen_grant.resolved_hostname.as_deref() {
                    add_redaction_replacement(&mut replacements, hostname, &alias);
                }
                for address in &frozen_grant.addresses {
                    add_redaction_replacement(&mut replacements, &address.to_string(), &alias);
                }
            }
        }
    }
    replacements.sort_by(|left, right| {
        right
            .0
            .len()
            .cmp(&left.0.len())
            .then_with(|| left.0.cmp(&right.0))
    });
    replacements
}

fn add_redaction_replacement(
    replacements: &mut Vec<(String, String)>,
    sensitive: &str,
    alias: &str,
) {
    let sensitive = sensitive.trim();
    if sensitive.is_empty()
        || replacements
            .iter()
            .any(|(existing, _)| existing == sensitive)
    {
        return;
    }
    replacements.push((sensitive.to_owned(), alias.to_owned()));
}

fn redact_known_literals(value: &mut String, replacements: &[(String, String)]) {
    for (sensitive, alias) in replacements {
        let exact_match = if sensitive.is_ascii() {
            value.eq_ignore_ascii_case(sensitive)
        } else {
            value == sensitive
        };
        if exact_match {
            *value = alias.clone();
            continue;
        }
        // Avoid corrupting ordinary prose for very short identifiers such as
        // "IP". Exact-field matches above are still redacted at any length.
        if sensitive.chars().count() >= 4 {
            if sensitive.is_ascii() {
                *value = replace_ascii_case_insensitive(value, sensitive, alias);
            } else if value.contains(sensitive) {
                *value = value.replace(sensitive, alias);
            }
        }
    }
}

fn replace_ascii_case_insensitive(value: &str, sensitive: &str, alias: &str) -> String {
    debug_assert!(sensitive.is_ascii());
    let folded_value = value.to_ascii_lowercase();
    let folded_sensitive = sensitive.to_ascii_lowercase();
    let mut output = String::with_capacity(value.len());
    let mut copied_through = 0;
    while let Some(relative_start) = folded_value[copied_through..].find(&folded_sensitive) {
        let start = copied_through + relative_start;
        let end = start + sensitive.len();
        output.push_str(&value[copied_through..start]);
        output.push_str(alias);
        copied_through = end;
    }
    if copied_through == 0 {
        return value.to_owned();
    }
    output.push_str(&value[copied_through..]);
    output
}

fn sort_case(case: &mut AssessmentCase) {
    case.data_sources
        .sort_by(|left, right| left.id.cmp(&right.id));
    case.assets.sort_by(|left, right| left.id.cmp(&right.id));
    for asset in &mut case.assets {
        asset.identifiers.sort_by(|left, right| {
            left.namespace
                .cmp(&right.namespace)
                .then_with(|| left.value.cmp(&right.value))
        });
        asset.discovered_from.sort();
    }
    case.asset_relations
        .sort_by(|left, right| left.id.cmp(&right.id));
    case.scope_grants
        .sort_by(|left, right| left.id.cmp(&right.id));
    case.coverage.sort_by(|left, right| left.id.cmp(&right.id));
    case.scan_runs.sort_by(|left, right| {
        left.sequence
            .cmp(&right.sequence)
            .then_with(|| left.id.cmp(&right.id))
    });
    for run in &mut case.scan_runs {
        run.scope_grant_ids.sort();
        run.engine_runs.sort_by(|left, right| {
            left.engine_id
                .cmp(&right.engine_id)
                .then_with(|| left.id.cmp(&right.id))
        });
        for engine_run in &mut run.engine_runs {
            engine_run.asset_ids.sort();
            engine_run.raw_artifact_ids.sort();
        }
    }
    case.findings.sort_by(|left, right| {
        left.fingerprint
            .cmp(&right.fingerprint)
            .then_with(|| left.id.cmp(&right.id))
    });
    for finding in &mut case.findings {
        finding.asset_ids.sort();
        finding
            .evidence
            .sort_by(|left, right| left.id.cmp(&right.id));
        finding.control_references.sort_by(|left, right| {
            left.framework
                .cmp(&right.framework)
                .then_with(|| left.framework_version.cmp(&right.framework_version))
                .then_with(|| left.control_id.cmp(&right.control_id))
        });
        finding.official_references.sort();
        finding.priority_reasons.sort();
        finding.tags.sort();
    }
    case.finding_groups.sort_by(|left, right| {
        left.created_at
            .cmp(&right.created_at)
            .then_with(|| left.id.cmp(&right.id))
    });
    for group in &mut case.finding_groups {
        group.finding_ids.sort();
    }
    case.finding_group_events.sort_by(|left, right| {
        left.occurred_at
            .cmp(&right.occurred_at)
            .then_with(|| left.id.cmp(&right.id))
    });
    for event in &mut case.finding_group_events {
        event.finding_ids.sort();
    }
    case.finding_workflow_events.sort_by(|left, right| {
        left.decided_at
            .cmp(&right.decided_at)
            .then_with(|| left.id.cmp(&right.id))
    });
    case.finding_observations.sort_by(|left, right| {
        left.run_id
            .cmp(&right.run_id)
            .then_with(|| left.fingerprint.cmp(&right.fingerprint))
            .then_with(|| left.id.cmp(&right.id))
    });
    for observation in &mut case.finding_observations {
        observation.asset_ids.sort();
        observation.engine_ids.sort();
        observation.evidence_hashes.sort();
        if let Some(finding) = &mut observation.finding_snapshot {
            finding.asset_ids.sort();
            finding
                .evidence
                .sort_by(|left, right| left.id.cmp(&right.id));
            finding.control_references.sort_by(|left, right| {
                left.framework
                    .cmp(&right.framework)
                    .then_with(|| left.framework_version.cmp(&right.framework_version))
                    .then_with(|| left.control_id.cmp(&right.control_id))
            });
            finding.official_references.sort();
            finding.priority_reasons.sort();
            finding.tags.sort();
        }
    }
    case.raw_artifacts
        .sort_by(|left, right| left.id.cmp(&right.id));
    case.comparisons.sort_by(|left, right| {
        left.created_at
            .cmp(&right.created_at)
            .then_with(|| left.id.cmp(&right.id))
    });
    for comparison in &mut case.comparisons {
        comparison
            .diffs
            .sort_by(|left, right| left.fingerprint.cmp(&right.fingerprint));
    }
}

fn prepare_artifacts(
    case: &AssessmentCase,
    artifact_root: &Path,
    redaction: RedactionProfile,
    include_raw_artifacts: bool,
) -> AppResult<(
    Vec<RawArtifactExportRecord>,
    BTreeMap<String, ArtifactSource>,
)> {
    let run_ids = case
        .scan_runs
        .iter()
        .map(|run| run.id.as_str())
        .collect::<BTreeSet<_>>();
    let engine_run_ids = case
        .scan_runs
        .iter()
        .flat_map(|run| {
            run.engine_runs
                .iter()
                .map(|engine_run| engine_run.id.as_str())
        })
        .collect::<BTreeSet<_>>();
    validate_evidence_references(case)?;
    let needs_artifact_root = include_raw_artifacts
        && case.raw_artifacts.iter().any(|artifact| {
            redaction != RedactionProfile::Standard || !artifact.contains_sensitive_data
        });
    let root = if needs_artifact_root {
        Some(fs::canonicalize(artifact_root).map_err(|error| {
            AppError::InvalidRequest(format!(
                "artifact root {} could not be resolved: {error}",
                artifact_root.display()
            ))
        })?)
    } else {
        None
    };

    let mut artifacts = case.raw_artifacts.iter().collect::<Vec<_>>();
    artifacts.sort_by(|left, right| left.id.cmp(&right.id));
    let mut records = Vec::with_capacity(artifacts.len());
    let mut sources = BTreeMap::<String, ArtifactSource>::new();
    for artifact in artifacts {
        validate_artifact_references(case, artifact, &run_ids, &engine_run_ids)?;
        let sha256 = normalized_sha256(&artifact.sha256)?;
        let include = include_raw_artifacts
            && !(redaction == RedactionProfile::Standard && artifact.contains_sensitive_data);
        let omission_reason = if include {
            None
        } else if !include_raw_artifacts {
            Some("raw artifacts were not selected for this export".into())
        } else {
            Some("standard redaction excludes artifacts marked sensitive".into())
        };
        let archive_path = include.then(|| format!("artifacts/sha256/{sha256}"));

        if let Some(archive_path) = &archive_path {
            let root = root.as_ref().expect("included artifacts require a root");
            let source_path = resolve_artifact_source(root, &artifact.relative_path)?;
            let new_source = ArtifactSource {
                archive_path: archive_path.clone(),
                source_path,
                expected_sha256: sha256.clone(),
                expected_byte_length: artifact.byte_length,
                media_type: artifact.media_type.clone(),
                contains_sensitive_data: artifact.contains_sensitive_data,
            };
            if let Some(existing) = sources.get(archive_path) {
                if existing.expected_byte_length != new_source.expected_byte_length
                    || existing.expected_sha256 != new_source.expected_sha256
                {
                    return Err(AppError::InvalidRequest(format!(
                        "raw artifacts conflict for content address {archive_path}"
                    )));
                }
            } else {
                sources.insert(archive_path.clone(), new_source);
            }
        }

        records.push(RawArtifactExportRecord {
            id: artifact.id.clone(),
            case_id: artifact.case_id.clone(),
            run_id: artifact.run_id.clone(),
            engine_run_id: artifact.engine_run_id.clone(),
            source_relative_path: if redaction == RedactionProfile::Standard {
                "[redacted]".into()
            } else {
                artifact.relative_path.clone()
            },
            media_type: artifact.media_type.clone(),
            sha256,
            byte_length: artifact.byte_length,
            created_at: artifact.created_at,
            contains_sensitive_data: artifact.contains_sensitive_data,
            included: include,
            archive_path,
            omission_reason,
        });
    }
    Ok((records, sources))
}

fn validate_evidence_references(case: &AssessmentCase) -> AppResult<()> {
    let run_ids = case
        .scan_runs
        .iter()
        .map(|run| run.id.as_str())
        .collect::<BTreeSet<_>>();
    let engine_runs = case
        .scan_runs
        .iter()
        .flat_map(|run| {
            run.engine_runs.iter().map(|engine_run| {
                (
                    engine_run.id.as_str(),
                    (run.id.as_str(), engine_run.engine_id.as_str()),
                )
            })
        })
        .collect::<BTreeMap<_, _>>();
    let artifacts = case
        .raw_artifacts
        .iter()
        .map(|artifact| (artifact.id.as_str(), artifact))
        .collect::<BTreeMap<_, _>>();
    let mut evidence_by_id = BTreeMap::<String, Value>::new();
    let mut validate_finding = |finding: &Finding,
                                expected_run_id: Option<&str>|
     -> AppResult<()> {
        if finding.case_id != case.id {
            return Err(AppError::InvalidRequest(format!(
                "finding {} belongs to another case",
                finding.id
            )));
        }
        if !run_ids.contains(finding.first_seen_run_id.as_str())
            || !run_ids.contains(finding.last_seen_run_id.as_str())
        {
            return Err(AppError::InvalidRequest(format!(
                "finding {} references a missing first or last scan run",
                finding.id
            )));
        }
        if finding.evidence.is_empty() {
            return Err(AppError::InvalidRequest(format!(
                "finding {} has no exact evidence provenance",
                finding.id
            )));
        }
        for evidence in &finding.evidence {
            if expected_run_id.is_some_and(|run_id| evidence.run_id != run_id) {
                return Err(AppError::InvalidRequest(format!(
                    "historical finding snapshot evidence {} belongs to a different run",
                    evidence.id
                )));
            }
            let artifact = artifacts
                .get(evidence.artifact_id.as_str())
                .ok_or_else(|| {
                    AppError::InvalidRequest(format!(
                        "evidence {} references missing raw artifact {}",
                        evidence.id, evidence.artifact_id
                    ))
                })?;
            let (artifact_run_id, artifact_engine_id) = engine_runs
                .get(artifact.engine_run_id.as_str())
                .ok_or_else(|| {
                    AppError::InvalidRequest(format!(
                        "evidence {} resolves to missing engine run {}",
                        evidence.id, artifact.engine_run_id
                    ))
                })?;
            if evidence.finding_id != finding.id
                || evidence.run_id != artifact.run_id
                || evidence.run_id != *artifact_run_id
                || evidence.engine_id != *artifact_engine_id
                || !evidence
                    .artifact_sha256
                    .eq_ignore_ascii_case(&artifact.sha256)
                || evidence
                    .engine_run_id
                    .as_deref()
                    .is_some_and(|engine_run_id| engine_run_id != artifact.engine_run_id)
            {
                return Err(AppError::InvalidRequest(format!(
                    "evidence {} does not match its finding, artifact, scan run, or engine run provenance",
                    evidence.id
                )));
            }
            let encoded = serde_json::to_value(evidence)?;
            if let Some(existing) = evidence_by_id.get(&evidence.id) {
                if existing != &encoded {
                    return Err(AppError::InvalidRequest(format!(
                        "conflicting duplicate evidence identifier in case export: {}",
                        evidence.id
                    )));
                }
            } else {
                evidence_by_id.insert(evidence.id.clone(), encoded);
            }
        }
        Ok(())
    };

    for finding in &case.findings {
        validate_finding(finding, None)?;
    }
    let canonical_findings = case
        .findings
        .iter()
        .map(|finding| (finding.id.as_str(), finding))
        .collect::<BTreeMap<_, _>>();
    if canonical_findings.len() != case.findings.len() {
        return Err(AppError::InvalidRequest(
            "case export contains duplicate canonical finding identifiers".into(),
        ));
    }
    for observation in &case.finding_observations {
        if !run_ids.contains(observation.run_id.as_str()) {
            return Err(AppError::InvalidRequest(format!(
                "observation {} references missing scan run {}",
                observation.id, observation.run_id
            )));
        }
        let canonical = canonical_findings
            .get(observation.finding_id.as_str())
            .copied()
            .ok_or_else(|| {
                AppError::InvalidRequest(format!(
                    "observation {} references missing canonical finding {}",
                    observation.id, observation.finding_id
                ))
            })?;
        let historical = observation.finding_snapshot.as_ref().unwrap_or(canonical);
        if observation.engine_ids.is_empty() || observation.evidence_hashes.is_empty() {
            return Err(AppError::InvalidRequest(format!(
                "historical finding snapshot for observation {} has no exact evidence provenance",
                observation.id
            )));
        }
        let normalize = |values: &[String]| {
            let mut values = values.to_vec();
            values.sort();
            values.dedup();
            values
        };
        let snapshot_assets = normalize(&historical.asset_ids);
        let observation_assets = normalize(&observation.asset_ids);
        let mut snapshot_hashes = historical
            .evidence
            .iter()
            .map(|evidence| evidence.artifact_sha256.to_ascii_lowercase())
            .collect::<Vec<_>>();
        snapshot_hashes.sort();
        snapshot_hashes.dedup();
        let mut observation_hashes = observation
            .evidence_hashes
            .iter()
            .map(|hash| hash.to_ascii_lowercase())
            .collect::<Vec<_>>();
        observation_hashes.sort();
        observation_hashes.dedup();
        let snapshot_engines = normalize(
            &historical
                .evidence
                .iter()
                .map(|evidence| evidence.engine_id.clone())
                .collect::<Vec<_>>(),
        );
        let observation_engines = normalize(&observation.engine_ids);
        if historical.id != observation.finding_id
            || historical.fingerprint != observation.fingerprint
            || historical.last_seen_run_id != observation.run_id
            || snapshot_assets != observation_assets
            || historical.severity != observation.severity
            || historical.confidence != observation.confidence
            || snapshot_hashes != observation_hashes
            || snapshot_engines != observation_engines
        {
            let provenance = if observation.finding_snapshot.is_some() {
                "historical finding snapshot"
            } else {
                "legacy canonical finding provenance"
            };
            return Err(AppError::InvalidRequest(format!(
                "observation {} does not match its {provenance}",
                observation.id
            )));
        }
        validate_finding(historical, Some(&observation.run_id))?;
    }
    Ok(())
}

fn validate_artifact_references(
    case: &AssessmentCase,
    artifact: &RawArtifact,
    run_ids: &BTreeSet<&str>,
    engine_run_ids: &BTreeSet<&str>,
) -> AppResult<()> {
    if artifact.case_id != case.id {
        return Err(AppError::InvalidRequest(format!(
            "raw artifact {} belongs to another case",
            artifact.id
        )));
    }
    if !run_ids.contains(artifact.run_id.as_str()) {
        return Err(AppError::InvalidRequest(format!(
            "raw artifact {} references missing run {}",
            artifact.id, artifact.run_id
        )));
    }
    if !engine_run_ids.contains(artifact.engine_run_id.as_str()) {
        return Err(AppError::InvalidRequest(format!(
            "raw artifact {} references missing engine run {}",
            artifact.id, artifact.engine_run_id
        )));
    }
    Ok(())
}

fn resolve_artifact_source(root: &Path, relative_path: &str) -> AppResult<PathBuf> {
    validate_portable_archive_path(Path::new(relative_path)).map_err(|_| {
        AppError::InvalidRequest(format!(
            "raw artifact has an unsafe relative path: {relative_path}"
        ))
    })?;
    let candidate = root.join(relative_path);
    let metadata = fs::symlink_metadata(&candidate).map_err(|error| {
        AppError::InvalidRequest(format!(
            "raw artifact {} could not be inspected: {error}",
            candidate.display()
        ))
    })?;
    if metadata.file_type().is_symlink() || !metadata.is_file() {
        return Err(AppError::InvalidRequest(format!(
            "raw artifact must be a regular file and not a symlink: {}",
            candidate.display()
        )));
    }
    let canonical = fs::canonicalize(&candidate)?;
    if !canonical.starts_with(root) {
        return Err(AppError::InvalidRequest(format!(
            "raw artifact escaped the artifact root: {}",
            candidate.display()
        )));
    }
    Ok(canonical)
}

fn destination_has_forbidden_prefix(destination: &Path) -> bool {
    destination.components().any(|component| match component {
        Component::Prefix(prefix) => {
            #[cfg(windows)]
            {
                !matches!(
                    prefix.kind(),
                    std::path::Prefix::Disk(_) | std::path::Prefix::UNC(_, _)
                )
            }
            #[cfg(not(windows))]
            {
                let _ = prefix;
                true
            }
        }
        _ => false,
    })
}

fn validate_destination(destination: &Path) -> AppResult<()> {
    let has_parent_traversal = destination
        .components()
        .any(|component| matches!(component, Component::ParentDir));
    let has_drive_relative_prefix = !destination.is_absolute()
        && destination
            .components()
            .any(|component| matches!(component, Component::Prefix(_)));
    if destination.as_os_str().is_empty()
        || has_parent_traversal
        || has_drive_relative_prefix
        || destination_has_forbidden_prefix(destination)
    {
        return Err(AppError::InvalidRequest(
            "case export destination must be an explicit file path without parent traversal".into(),
        ));
    }
    let name = destination
        .file_name()
        .and_then(|name| name.to_str())
        .ok_or_else(|| AppError::InvalidRequest("export destination filename is invalid".into()))?;
    if !name.ends_with(".case.tar.gz") {
        return Err(AppError::InvalidRequest(
            "case export filename must end with .case.tar.gz".into(),
        ));
    }
    Ok(())
}

fn validate_portable_archive_path(path: &Path) -> AppResult<String> {
    let value = path
        .to_str()
        .ok_or_else(|| AppError::InvalidRequest("archive path is not valid UTF-8".into()))?;
    if value.is_empty()
        || value.len() > MAX_ARCHIVE_PATH_BYTES
        || value.starts_with('/')
        || value.ends_with('/')
        || value.contains(['\\', ':', '\0'])
    {
        return Err(AppError::InvalidRequest(format!(
            "unsafe archive path: {value:?}"
        )));
    }
    if value
        .split('/')
        .any(|component| component.is_empty() || component == "." || component == "..")
    {
        return Err(AppError::InvalidRequest(format!(
            "unsafe archive path: {value:?}"
        )));
    }
    if path
        .components()
        .any(|component| !matches!(component, Component::Normal(_)))
    {
        return Err(AppError::InvalidRequest(format!(
            "unsafe archive path: {value:?}"
        )));
    }
    Ok(value.into())
}

fn validate_manifest(
    manifest: &BundleManifest,
    observed: &BTreeMap<String, ObservedEntry>,
) -> AppResult<()> {
    if manifest.schema_version != BUNDLE_SCHEMA_VERSION {
        return Err(AppError::InvalidRequest(format!(
            "unsupported bundle schema version: {}",
            manifest.schema_version
        )));
    }
    if manifest.product_name != "ai-security-scanner" {
        return Err(AppError::InvalidRequest(
            "bundle product name is not ai-security-scanner".into(),
        ));
    }
    if manifest.case_id.trim().is_empty() || manifest.run_id.trim().is_empty() {
        return Err(AppError::InvalidRequest(
            "bundle manifest has an empty case or run identifier".into(),
        ));
    }
    if manifest.signing.algorithm != "Ed25519"
        || manifest.signing.signed_file != MANIFEST_PATH
        || manifest.signing.integrity_only_notice != INTEGRITY_ONLY_NOTICE
    {
        return Err(AppError::InvalidRequest(
            "bundle signing metadata is unsupported or misleading".into(),
        ));
    }

    let mut expected = BTreeMap::<String, ObservedEntry>::new();
    let mut previous_path: Option<&str> = None;
    for entry in &manifest.entries {
        let path = validate_portable_archive_path(Path::new(&entry.path))?;
        if path == MANIFEST_PATH || path == SIGNATURE_PATH {
            return Err(AppError::InvalidRequest(
                "manifest payload list may not contain reserved signature files".into(),
            ));
        }
        if let Some(previous) = previous_path
            && previous >= path.as_str()
        {
            return Err(AppError::InvalidRequest(
                "manifest entries must be uniquely sorted by path".into(),
            ));
        }
        previous_path = Some(&entry.path);
        normalized_sha256(&entry.sha256)?;
        if entry.media_type.trim().is_empty() {
            return Err(AppError::InvalidRequest(format!(
                "manifest entry has no media type: {}",
                entry.path
            )));
        }
        expected.insert(
            path,
            ObservedEntry {
                sha256: entry.sha256.to_ascii_lowercase(),
                byte_length: entry.byte_length,
            },
        );
    }
    if expected != *observed {
        let expected_paths = expected.keys().cloned().collect::<BTreeSet<_>>();
        let observed_paths = observed.keys().cloned().collect::<BTreeSet<_>>();
        let missing = expected_paths
            .difference(&observed_paths)
            .cloned()
            .collect::<Vec<_>>();
        let extra = observed_paths
            .difference(&expected_paths)
            .cloned()
            .collect::<Vec<_>>();
        return Err(AppError::InvalidRequest(format!(
            "bundle payload does not match signed manifest (missing: {missing:?}, extra: {extra:?}, or hash/length mismatch)"
        )));
    }
    if manifest.raw_artifacts_included > manifest.raw_artifact_count {
        return Err(AppError::InvalidRequest(
            "manifest raw artifact counts are inconsistent".into(),
        ));
    }
    Ok(())
}

fn verify_signature(
    manifest_bytes: &[u8],
    manifest: &BundleManifest,
    envelope: &SignatureEnvelope,
) -> AppResult<()> {
    if envelope.algorithm != "Ed25519"
        || envelope.signed_file != MANIFEST_PATH
        || envelope.integrity_only_notice != INTEGRITY_ONLY_NOTICE
        || envelope.key_id != manifest.signing.key_id
    {
        return Err(AppError::InvalidRequest(
            "signature envelope does not match the signed manifest metadata".into(),
        ));
    }
    let public_key = BASE64
        .decode(&envelope.public_key_base64)
        .map_err(|error| {
            AppError::InvalidRequest(format!("invalid signing public key: {error}"))
        })?;
    let public_key: [u8; 32] = public_key
        .try_into()
        .map_err(|_| AppError::InvalidRequest("Ed25519 public key must contain 32 bytes".into()))?;
    let key_id = sha256_bytes(&public_key);
    if key_id != envelope.key_id {
        return Err(AppError::InvalidRequest(
            "signature key identifier does not match its public key".into(),
        ));
    }
    let verifying_key = VerifyingKey::from_bytes(&public_key).map_err(|error| {
        AppError::InvalidRequest(format!("invalid Ed25519 public key: {error}"))
    })?;
    let signature = BASE64.decode(&envelope.signature_base64).map_err(|error| {
        AppError::InvalidRequest(format!("invalid signature encoding: {error}"))
    })?;
    let signature = Signature::try_from(signature.as_slice())
        .map_err(|error| AppError::InvalidRequest(format!("invalid Ed25519 signature: {error}")))?;
    verifying_key
        .verify_strict(manifest_bytes, &signature)
        .map_err(|_| AppError::InvalidRequest("bundle manifest signature is invalid".into()))
}

fn verify_embedded_signing_identity(
    manifest: &BundleManifest,
    envelope: &SignatureEnvelope,
    identity_bytes: Option<&[u8]>,
) -> AppResult<()> {
    let declared_version = manifest
        .schemas
        .get("local_signing_identity")
        .map(String::as_str);
    match (declared_version, identity_bytes) {
        (None, None) => return Ok(()),
        (None, Some(_)) => {
            return Err(AppError::InvalidRequest(
                "bundle contains signing identity metadata without declaring its schema".into(),
            ));
        }
        (Some(_), None) => {
            return Err(AppError::InvalidRequest(format!(
                "bundle declares a signing identity but is missing {SIGNING_IDENTITY_PATH}"
            )));
        }
        (Some(version), Some(_)) if version != LOCAL_SIGNING_IDENTITY_SCHEMA_VERSION => {
            return Err(AppError::InvalidRequest(format!(
                "unsupported bundle signing identity schema version: {version}"
            )));
        }
        (Some(_), Some(_)) => {}
    }
    let identity: LocalSigningIdentityDocument = serde_json::from_slice(
        identity_bytes.expect("matched signing identity bytes"),
    )
    .map_err(|error| {
        AppError::InvalidRequest(format!(
            "bundle signing identity document is invalid JSON: {error}"
        ))
    })?;
    verify_identity_document(&identity, 1)?;
    if identity.key_id != envelope.key_id
        || identity.public_key_base64 != envelope.public_key_base64
    {
        return Err(AppError::InvalidRequest(
            "bundle signing identity does not match the manifest signer".into(),
        ));
    }
    Ok(())
}

#[cfg(unix)]
fn create_private_new_file(path: &Path) -> AppResult<File> {
    use std::os::unix::fs::OpenOptionsExt;
    OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(path)
        .map_err(Into::into)
}

#[cfg(not(unix))]
fn create_private_new_file(path: &Path) -> AppResult<File> {
    OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(path)
        .map_err(Into::into)
}

fn normalized_sha256(value: &str) -> AppResult<String> {
    if value.len() != 64 || !value.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        return Err(AppError::InvalidRequest(format!(
            "invalid SHA-256 value: {value}"
        )));
    }
    Ok(value.to_ascii_lowercase())
}

fn sha256_bytes(bytes: &[u8]) -> String {
    hex::encode(Sha256::digest(bytes))
}

fn sha256_file(path: &Path) -> AppResult<String> {
    let mut file = File::open(path)?;
    let (sha256, _) = sha256_reader(&mut file)?;
    Ok(sha256)
}

fn sha256_reader(reader: &mut impl Read) -> AppResult<(String, u64)> {
    let mut hasher = Sha256::new();
    let mut byte_length = 0_u64;
    let mut buffer = [0_u8; IO_BUFFER_BYTES];
    loop {
        let read = reader.read(&mut buffer)?;
        if read == 0 {
            break;
        }
        hasher.update(&buffer[..read]);
        byte_length = byte_length.checked_add(read as u64).ok_or_else(|| {
            AppError::InvalidRequest("content length overflow while hashing".into())
        })?;
    }
    Ok((hex::encode(hasher.finalize()), byte_length))
}

fn read_exact_entry(reader: &mut impl Read, expected_size: u64) -> AppResult<Vec<u8>> {
    let mut bytes = Vec::with_capacity(expected_size as usize);
    reader.read_to_end(&mut bytes)?;
    if bytes.len() as u64 != expected_size {
        return Err(AppError::InvalidRequest(
            "reserved bundle document was truncated".into(),
        ));
    }
    Ok(bytes)
}

struct HashingReader<R> {
    inner: R,
    hasher: Sha256,
    byte_length: u64,
}

impl<R> HashingReader<R> {
    fn new(inner: R) -> Self {
        Self {
            inner,
            hasher: Sha256::new(),
            byte_length: 0,
        }
    }

    fn finish(self) -> (String, u64) {
        (hex::encode(self.hasher.finalize()), self.byte_length)
    }
}

impl<R: Read> Read for HashingReader<R> {
    fn read(&mut self, buffer: &mut [u8]) -> io::Result<usize> {
        let read = self.inner.read(buffer)?;
        self.hasher.update(&buffer[..read]);
        self.byte_length = self.byte_length.saturating_add(read as u64);
        Ok(read)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::domain::*;
    use crate::execution_coverage::{
        ExecutionCoverageSummary, LAUNCHER_V2_JOURNAL_SCHEMA_VERSION, ValidatedExecutionCoverage,
        WorkUnitCoverage, WorkUnitOutcome,
    };
    use crate::external_scope::{
        ExternalActivity, ExternalScopeGrant, RatePolicy, ResolutionSnapshot, ResolvedExternalPlan,
        TemplatePolicy, TransportProtocol,
    };
    use crate::naabu_work_plan::{NaabuWorkPlanIdentity, build_naabu_work_plan};
    use chrono::TimeZone;
    use std::collections::BTreeMap;
    use tempfile::tempdir;

    fn fixture(artifact_root: &Path, sensitive: bool) -> AssessmentCase {
        let time = Utc.with_ymd_and_hms(2026, 8, 24, 12, 0, 0).unwrap();
        fs::create_dir_all(artifact_root.join("raw")).unwrap();
        let bytes = b"scanner evidence\n";
        fs::write(artifact_root.join("raw/evidence.txt"), bytes).unwrap();

        let mut case = AssessmentCase::new(
            "Export test".into(),
            OrganizationProfile {
                organization_name: "Example".into(),
                employee_range: "1-10".into(),
                data_classes: vec![DataClass::General],
                notes: Some("private note".into()),
            },
        );
        case.id = "case-1".into();
        case.assets.push(Asset {
            id: "asset-1".into(),
            kind: AssetKind::Host,
            name: "private.example.test".into(),
            provider: None,
            region: None,
            identifiers: vec![AssetIdentifier {
                namespace: "dns".into(),
                value: "private.example.test".into(),
            }],
            discovered_from: vec![],
            candidate: false,
            owner_confirmed: true,
            internet_exposed: Some(false),
            contains_sensitive_data: Some(sensitive),
            metadata: BTreeMap::new(),
        });
        case.scan_runs.push(ScanRun {
            id: "run-1".into(),
            case_id: case.id.clone(),
            sequence: 1,
            created_at: time,
            completed_at: Some(time),
            request_outcome: None,
            knowledge_cutoff: time,
            ai_system_applicable: false,
            ai_system_applicability: Default::default(),
            ai_generated_artifact: Default::default(),
            verification_baseline_run_id: None,
            scope_grant_ids: vec![],
            scope_grant_snapshots: vec![],
            engine_admission_issues: Vec::new(),
            engine_runs: vec![EngineRun {
                id: "engine-run-1".into(),
                scan_run_id: "run-1".into(),
                engine_id: "engine-1".into(),
                task_kind: Default::default(),
                localhost_tcp_observation: None,
                asset_ids: vec!["asset-1".into()],
                status: EngineRunStatus::Completed,
                progress_percent: 100,
                phase: "complete".into(),
                started_at: Some(time),
                finished_at: Some(time),
                resume_token: None,
                engine_version: Some("1.2.3".into()),
                image_digest: Some("sha256:abc".into()),
                rule_version: Some("2026.08".into()),
                adapter_version: "1".into(),
                manifest_schema_version: None,
                source_revision: None,
                repository_url: None,
                distribution_mode: None,
                image_repository: None,
                command_sha256: None,
                execution_timeout_seconds: None,
                knowledge_input: None,
                scope_contract_sha256: None,
                naabu_work_plan: None,
                naabu_attempt_requests: Vec::new(),
                naabu_attempt_results: Vec::new(),
                mapping_version: None,
                mapping_provenance: None,
                fingerprint_schema_version: None,
                runtime_provider: None,
                runtime_version: None,
                runtime_security_options: None,
                exit_code: None,
                cleanup_removed: None,
                cleanup_detail: None,
                warnings: vec![],
                raw_artifact_ids: vec!["artifact-1".into()],
                error_code: None,
                error_message: None,
            }],
        });
        case.raw_artifacts.push(RawArtifact {
            id: "artifact-1".into(),
            case_id: case.id.clone(),
            run_id: "run-1".into(),
            engine_run_id: "engine-run-1".into(),
            relative_path: "raw/evidence.txt".into(),
            media_type: "text/plain".into(),
            sha256: sha256_bytes(bytes),
            byte_length: bytes.len() as u64,
            created_at: time,
            contains_sensitive_data: sensitive,
        });
        case
    }

    #[test]
    fn built_in_tasks_are_exported_as_exact_observations_not_engine_provenance() {
        let temp = tempdir().unwrap();
        let artifact_root = temp.path().join("artifacts");
        let mut case = fixture(&artifact_root, false);
        let task = &mut case.scan_runs[0].engine_runs[0];
        task.engine_id = BUILT_IN_LOCALHOST_TCP_ENGINE_ID.into();
        task.task_kind = EngineTaskKind::built_in_localhost_tcp(9_001);
        task.localhost_tcp_observation = Some(LocalhostTcpObservation {
            outcome: LocalhostTcpOutcome::Reachable,
            observed_at: task.finished_at.expect("finished"),
        });

        assert!(engine_version_records(&case).is_empty());
        let records = built_in_task_records(&case);
        assert_eq!(records.len(), 1);
        assert_eq!(
            records[0].pointer("/task_kind/kind"),
            Some(&Value::String("built_in_localhost_tcp".into()))
        );
        assert_eq!(
            records[0].pointer("/task_kind/port"),
            Some(&Value::from(9_001))
        );
        assert_eq!(
            records[0].pointer("/localhost_tcp_observation/outcome"),
            Some(&Value::String("reachable".into()))
        );
        for forbidden in [
            "engine_version",
            "image_digest",
            "adapter_version",
            "runtime_provider",
            "repository_url",
        ] {
            assert!(records[0].get(forbidden).is_none());
        }
    }

    #[test]
    fn case_bundle_destination_rejects_parent_traversal_and_wrong_extension() {
        validate_destination(Path::new("exports/report.case.tar.gz"))
            .expect("ordinary relative bundle path");
        assert!(validate_destination(Path::new("../report.case.tar.gz")).is_err());
        assert!(validate_destination(Path::new("exports/../report.case.tar.gz")).is_err());
        assert!(validate_destination(Path::new("exports/report.tar.gz")).is_err());
    }

    #[cfg(windows)]
    #[test]
    fn windows_case_bundle_destination_accepts_normal_disk_and_unc_only() {
        for allowed in [
            r"C:\Users\example\Downloads\report.case.tar.gz",
            r"\\server\share\report.case.tar.gz",
        ] {
            validate_destination(Path::new(allowed)).unwrap_or_else(|error| {
                panic!("normal Windows destination was rejected: {allowed}: {error}")
            });
        }

        for forbidden in [
            r"C:report.case.tar.gz",
            r"C:\Users\example\..\report.case.tar.gz",
            r"\\server\share\folder\..\report.case.tar.gz",
            r"\\.\PhysicalDrive0\report.case.tar.gz",
            r"\\?\GLOBALROOT\Device\HarddiskVolumeShadowCopy1\report.case.tar.gz",
            r"\\?\Volume{11111111-1111-1111-1111-111111111111}\report.case.tar.gz",
            r"\\?\C:\Users\example\Downloads\report.case.tar.gz",
            r"\\?\UNC\server\share\report.case.tar.gz",
        ] {
            assert!(
                validate_destination(Path::new(forbidden)).is_err(),
                "special, drive-relative, or traversing destination must be rejected: {forbidden}"
            );
        }
    }

    fn add_reversible_grouping(case: &mut AssessmentCase) {
        let time = Utc.with_ymd_and_hms(2026, 8, 24, 12, 30, 0).unwrap();
        let artifact = case.raw_artifacts[0].clone();
        for (id, title) in [
            ("finding-a", "Independent finding A"),
            ("finding-b", "Independent finding B"),
        ] {
            case.findings.push(Finding {
                id: id.into(),
                case_id: case.id.clone(),
                first_seen_run_id: "run-1".into(),
                last_seen_run_id: "run-1".into(),
                fingerprint: format!("engine:{id}"),
                title: title.into(),
                plain_language_summary: "Independent canonical finding".into(),
                possible_impact: "Requires human review".into(),
                severity: Severity::Medium,
                confidence: Confidence::High,
                priority: 50,
                priority_reasons: vec![],
                asset_ids: vec!["asset-1".into()],
                evidence: vec![Evidence {
                    id: format!("evidence-{id}"),
                    finding_id: id.into(),
                    run_id: artifact.run_id.clone(),
                    engine_run_id: Some(artifact.engine_run_id.clone()),
                    kind: EvidenceKind::Observation,
                    engine_id: "engine-1".into(),
                    source_rule: None,
                    result_pointer_sha256: None,
                    observed_at: time,
                    summary: "Independent fixture evidence".into(),
                    artifact_id: artifact.id.clone(),
                    artifact_sha256: artifact.sha256.clone(),
                    pointer: None,
                    redacted: false,
                }],
                control_references: vec![],
                recommendation: "Review without automatic remediation".into(),
                verification_guidance: "Run the responsible engine again".into(),
                rollback_considerations: None,
                official_references: vec![],
                recommended_expert_type: "Security reviewer".into(),
                status: FindingStatus::Unreviewed,
                tags: vec![],
            });
        }

        let finding_ids = vec!["finding-a".into(), "finding-b".into()];
        case.finding_group_events.push(FindingGroupEvent {
            id: "event-old-created".into(),
            case_id: case.id.clone(),
            group_id: "group-old".into(),
            action: FindingGroupAction::Created,
            title: "Private old group title".into(),
            finding_ids: finding_ids.clone(),
            rationale: "Private old grouping rationale".into(),
            actor: "Private old group creator".into(),
            occurred_at: time - chrono::Duration::minutes(2),
        });
        case.finding_group_events.push(FindingGroupEvent {
            id: "event-old-removed".into(),
            case_id: case.id.clone(),
            group_id: "group-old".into(),
            action: FindingGroupAction::Removed,
            title: "Private old group title".into(),
            finding_ids: finding_ids.clone(),
            rationale: "Private old group removal reason".into(),
            actor: "Private old group remover".into(),
            occurred_at: time - chrono::Duration::minutes(1),
        });
        case.finding_groups.push(FindingGroup {
            id: "group-active".into(),
            case_id: case.id.clone(),
            title: "Private active group title".into(),
            finding_ids: finding_ids.clone(),
            rationale: "Private active grouping rationale".into(),
            grouped_by: "Private active group creator".into(),
            created_at: time,
        });
        case.finding_group_events.push(FindingGroupEvent {
            id: "event-active-created".into(),
            case_id: case.id.clone(),
            group_id: "group-active".into(),
            action: FindingGroupAction::Created,
            title: "Private active group title".into(),
            finding_ids,
            rationale: "Private active grouping rationale".into(),
            actor: "Private active group creator".into(),
            occurred_at: time,
        });
    }

    fn archive_entry(path: &Path, requested: &str) -> Vec<u8> {
        let file = File::open(path).unwrap();
        let decoder = GzDecoder::new(file);
        let mut archive = tar::Archive::new(decoder);
        for entry in archive.entries().unwrap() {
            let mut entry = entry.unwrap();
            if entry.path().unwrap() == Path::new(requested) {
                let mut bytes = Vec::new();
                entry.read_to_end(&mut bytes).unwrap();
                return bytes;
            }
        }
        panic!("archive entry not found: {requested}");
    }

    #[test]
    fn creates_repeatable_signed_bundle_and_verifies_every_entry() {
        let temp = tempdir().unwrap();
        let artifact_root = temp.path().join("artifacts");
        let case = fixture(&artifact_root, false);
        let key = temp.path().join("signing.key");
        let first = temp.path().join("first.case.tar.gz");
        let second = temp.path().join("second.case.tar.gz");
        let created_at = Utc.with_ymd_and_hms(2026, 8, 24, 13, 0, 0).unwrap();
        let options = ExportOptions {
            redaction: RedactionProfile::None,
            include_raw_artifacts: true,
        };

        let first_export = create_case_bundle_at(
            &case,
            "run-1",
            &artifact_root,
            &first,
            &key,
            options.clone(),
            created_at,
        )
        .unwrap();
        let second_export = create_case_bundle_at(
            &case,
            "run-1",
            &artifact_root,
            &second,
            &key,
            options.clone(),
            created_at,
        )
        .unwrap();

        assert_eq!(first_export.sha256, second_export.sha256);
        let verified = verify_case_bundle_against(
            &first,
            Some(&first_export.sha256),
            first_export.public_key.as_deref(),
        )
        .unwrap();
        assert!(verified.valid);
        assert_eq!(verified.raw_artifacts_included, 1);
        assert!(
            verified
                .manifest
                .entries
                .iter()
                .any(|entry| entry.path.starts_with("artifacts/sha256/"))
        );
        assert!(verified.manifest.entries.iter().any(|entry| {
            entry.path == "exports/master-framework-report.json"
                && entry.media_type == "application/json"
        }));
        assert!(verified.manifest.entries.iter().any(|entry| {
            entry.path == "exports/beginner-master-report.json"
                && entry.media_type == "application/json"
        }));
        assert_eq!(
            verified
                .manifest
                .schemas
                .get("beginner_master_report")
                .map(String::as_str),
            Some(BEGINNER_MASTER_REPORT_SCHEMA_VERSION)
        );
        assert_eq!(
            verified
                .manifest
                .schemas
                .get("master_framework_report")
                .map(String::as_str),
            Some(MASTER_FRAMEWORK_REPORT_SCHEMA_VERSION)
        );
        let framework_report: Value = serde_json::from_slice(&archive_entry(
            &first,
            "exports/master-framework-report.json",
        ))
        .unwrap();
        assert_eq!(
            framework_report["export_kind"],
            "master_framework_relationship_report"
        );
        assert_eq!(framework_report["frameworks"].as_array().unwrap().len(), 3);
        let beginner_report: Value = serde_json::from_slice(&archive_entry(
            &first,
            "exports/beginner-master-report.json",
        ))
        .unwrap();
        assert_eq!(beginner_report["export_kind"], "beginner_master_report");
        assert_eq!(beginner_report["report"]["run_id"], "run-1");
        let signing_identity: LocalSigningIdentityDocument =
            serde_json::from_slice(&archive_entry(&first, SIGNING_IDENTITY_PATH)).unwrap();
        verify_identity_document(&signing_identity, 1).unwrap();
        assert_eq!(signing_identity.key_id, verified.signer_key_id);
        assert_eq!(
            signing_identity.public_key_base64,
            verified.public_key_base64
        );
        assert_eq!(
            verified
                .manifest
                .schemas
                .get("local_signing_identity")
                .map(String::as_str),
            Some(LOCAL_SIGNING_IDENTITY_SCHEMA_VERSION)
        );
        assert!(crate::export_identity::signing_identity_document_path(&key).is_file());
        assert_eq!(verified.integrity_only_notice, INTEGRITY_ONLY_NOTICE);

        fs::remove_file(&key).unwrap();
        let missing_key_output = temp.path().join("missing-key.case.tar.gz");
        let error = create_case_bundle_at(
            &case,
            "run-1",
            &artifact_root,
            &missing_key_output,
            &key,
            options,
            created_at,
        )
        .unwrap_err();
        assert!(error.to_string().contains(&signing_identity.key_id));
        assert!(!missing_key_output.exists());
    }

    #[test]
    fn bundle_evidence_must_match_the_exact_artifact_and_engine_execution() {
        let temp = tempdir().unwrap();
        let artifact_root = temp.path().join("artifacts");
        let mut case = fixture(&artifact_root, false);
        let artifact = case.raw_artifacts[0].clone();
        let finding_id = "finding-1".to_owned();
        case.findings.push(Finding {
            id: finding_id.clone(),
            case_id: case.id.clone(),
            first_seen_run_id: "run-1".into(),
            last_seen_run_id: "run-1".into(),
            fingerprint: "engine-1:asset-1:rule-1".into(),
            title: "Finding".into(),
            plain_language_summary: "Summary".into(),
            possible_impact: "Impact requires human review".into(),
            severity: Severity::Medium,
            confidence: Confidence::High,
            priority: 50,
            priority_reasons: vec![],
            asset_ids: vec!["asset-1".into()],
            evidence: vec![Evidence {
                id: "evidence-1".into(),
                finding_id,
                run_id: "run-1".into(),
                engine_run_id: Some("engine-run-1".into()),
                kind: EvidenceKind::Observation,
                engine_id: "engine-1".into(),
                source_rule: None,
                result_pointer_sha256: None,
                observed_at: artifact.created_at,
                summary: "Observed".into(),
                artifact_id: artifact.id.clone(),
                artifact_sha256: artifact.sha256.clone(),
                pointer: Some("/result/0".into()),
                redacted: false,
            }],
            control_references: vec![],
            recommendation: "Ask a qualified reviewer".into(),
            verification_guidance: "Repeat the same pinned scan".into(),
            rollback_considerations: None,
            official_references: vec![],
            recommended_expert_type: "Security reviewer".into(),
            status: FindingStatus::Unreviewed,
            tags: vec![],
        });

        validate_evidence_references(&case).unwrap();
        let canonical_evidence = case.findings[0].evidence.clone();
        case.findings[0].evidence.clear();
        assert!(
            validate_evidence_references(&case)
                .unwrap_err()
                .to_string()
                .contains("no exact evidence provenance")
        );
        case.findings[0].evidence = canonical_evidence;
        case.findings[0].evidence[0].engine_run_id = Some("another-engine-run".into());
        assert!(
            validate_evidence_references(&case)
                .unwrap_err()
                .to_string()
                .contains("engine run provenance")
        );

        // Missing engine_run_id is retained only for legacy cases. Validation
        // checks its artifact's exact run without silently backfilling it.
        case.findings[0].evidence[0].engine_run_id = None;
        validate_evidence_references(&case).unwrap();
        case.findings[0].evidence[0].artifact_sha256 = "f".repeat(64);
        assert!(validate_evidence_references(&case).is_err());

        case.findings[0].evidence[0].artifact_sha256 = artifact.sha256.clone();
        let snapshot = case.findings[0].clone();
        case.finding_observations.push(FindingObservation {
            id: "observation-1".into(),
            run_id: "run-1".into(),
            finding_id: snapshot.id.clone(),
            fingerprint: snapshot.fingerprint.clone(),
            asset_ids: snapshot.asset_ids.clone(),
            engine_ids: vec!["engine-1".into()],
            severity: snapshot.severity.clone(),
            confidence: snapshot.confidence.clone(),
            evidence_hashes: vec![artifact.sha256.clone()],
            observed_at: artifact.created_at,
            finding_snapshot: Some(snapshot),
        });
        validate_evidence_references(&case)
            .expect("an identical canonical/snapshot evidence record is deduplicated");
        let snapshot = case.finding_observations[0]
            .finding_snapshot
            .take()
            .expect("snapshot");
        validate_evidence_references(&case)
            .expect("latest exact legacy canonical projection remains exportable");
        case.findings[0].severity = Severity::Low;
        assert!(
            validate_evidence_references(&case)
                .unwrap_err()
                .to_string()
                .contains("legacy canonical finding provenance")
        );
        case.findings[0].severity = Severity::Medium;
        case.finding_observations[0].finding_snapshot = Some(snapshot);
        case.finding_observations[0]
            .finding_snapshot
            .as_mut()
            .unwrap()
            .evidence[0]
            .engine_id = "tampered-engine".into();
        assert!(validate_evidence_references(&case).is_err());
        case.finding_observations[0]
            .finding_snapshot
            .as_mut()
            .unwrap()
            .evidence[0]
            .engine_id = "engine-1".into();
        case.finding_observations[0].severity = Severity::Low;
        assert!(
            validate_evidence_references(&case)
                .unwrap_err()
                .to_string()
                .contains("historical finding snapshot")
        );
        case.finding_observations[0].severity = Severity::Medium;
        case.finding_observations[0]
            .finding_snapshot
            .as_mut()
            .unwrap()
            .evidence
            .clear();
        case.finding_observations[0].evidence_hashes.clear();
        assert!(
            validate_evidence_references(&case)
                .unwrap_err()
                .to_string()
                .contains("historical finding snapshot"),
            "empty snapshot evidence must not bypass observation engine binding"
        );

        let canonical = case.findings[0].clone();
        case.findings.clear();
        assert!(
            validate_evidence_references(&case)
                .unwrap_err()
                .to_string()
                .contains("missing canonical finding")
        );
        case.findings.push(canonical);
        case.finding_observations[0].run_id = "missing-run".into();
        assert!(
            validate_evidence_references(&case)
                .unwrap_err()
                .to_string()
                .contains("missing scan run")
        );
    }

    #[test]
    fn standard_redaction_omits_sensitive_raw_artifacts() {
        let temp = tempdir().unwrap();
        let artifact_root = temp.path().join("artifacts");
        let case = fixture(&artifact_root, true);
        let destination = temp.path().join("redacted.case.tar.gz");
        let export = create_case_bundle_at(
            &case,
            "run-1",
            &artifact_root,
            &destination,
            temp.path().join("key"),
            ExportOptions {
                redaction: RedactionProfile::Standard,
                include_raw_artifacts: true,
            },
            Utc.with_ymd_and_hms(2026, 8, 24, 13, 0, 0).unwrap(),
        )
        .unwrap();

        let verified = verify_case_bundle_against(
            &destination,
            Some(&export.sha256),
            export.public_key.as_deref(),
        )
        .unwrap();
        assert_eq!(verified.raw_artifacts_included, 0);
        assert!(
            !verified
                .manifest
                .entries
                .iter()
                .any(|entry| entry.path.starts_with("artifacts/"))
        );
    }

    #[test]
    fn standard_redaction_keeps_stable_asset_aliases_and_scrubs_known_targets_from_prose() {
        let temp = tempdir().unwrap();
        let artifact_root = temp.path().join("artifacts");
        let mut case = fixture(&artifact_root, true);
        case.assets.push(Asset {
            id: "asset-2".into(),
            kind: AssetKind::Other,
            name: "customer-database.internal".into(),
            provider: None,
            region: None,
            identifiers: vec![AssetIdentifier {
                namespace: "dns".into(),
                value: "customer-database.internal".into(),
            }],
            discovered_from: vec![],
            candidate: false,
            owner_confirmed: true,
            internet_exposed: Some(false),
            contains_sensitive_data: Some(true),
            metadata: BTreeMap::new(),
        });
        case.findings.push(Finding {
            id: "finding-1".into(),
            case_id: case.id.clone(),
            first_seen_run_id: "run-1".into(),
            last_seen_run_id: "run-1".into(),
            fingerprint: "fingerprint-1".into(),
            title: "private.example.test can reach customer-database.internal".into(),
            plain_language_summary:
                "Review traffic from private.example.test to customer-database.internal.".into(),
            possible_impact: "customer-database.internal may be exposed.".into(),
            severity: Severity::Medium,
            confidence: Confidence::High,
            priority: 50,
            priority_reasons: vec!["private.example.test is connected".into()],
            asset_ids: vec!["asset-1".into(), "asset-2".into()],
            evidence: vec![],
            control_references: vec![],
            recommendation: "Review customer-database.internal.".into(),
            verification_guidance: "Retest from private.example.test.".into(),
            rollback_considerations: None,
            official_references: vec![],
            recommended_expert_type: "Network administrator".into(),
            status: FindingStatus::Unreviewed,
            tags: vec![],
        });

        let redacted = case_for_export(&case, RedactionProfile::Standard);
        let encoded = serde_json::to_string(&redacted).unwrap();

        assert_eq!(redacted.assets[0].name, "Asset 1");
        assert_eq!(redacted.assets[1].name, "Asset 2");
        assert!(redacted.findings[0].title.contains("Asset 1"));
        assert!(redacted.findings[0].title.contains("Asset 2"));
        assert!(!encoded.contains("private.example.test"));
        assert!(!encoded.contains("customer-database.internal"));
    }

    #[test]
    fn standard_redaction_never_rewrites_stable_check_identity_on_asset_text_collision() {
        let temp = tempdir().unwrap();
        let artifact_root = temp.path().join("artifacts");
        let mut case = fixture(&artifact_root, false);
        let stable_check_id = case.scan_runs[0].engine_runs[0].engine_id.clone();
        case.assets[0].name = stable_check_id.clone();
        case.assets[0].identifiers[0].value = stable_check_id.clone();

        let report =
            beginner_report_for_export(&case, "run-1", RedactionProfile::Standard).unwrap();
        assert_eq!(
            report.requested.requested_check_ids,
            [stable_check_id.clone()]
        );
        assert_eq!(report.actual.checks[0].check_id, stable_check_id);
        assert!(matches!(
            &report.technical_details.tasks[0].execution,
            TechnicalExecution::CatalogEngine { engine_id, .. }
                if engine_id == &report.actual.checks[0].check_id
        ));
        assert_eq!(
            report.requested.targets[0].label.as_deref(),
            Some("Asset 1")
        );
    }

    #[test]
    fn standard_redaction_removes_sensitive_sentinels_from_every_bundle_document() {
        const SENTINEL: &str = "SENSITIVE_SENTINEL_DO_NOT_EXPORT_8f7c2a";
        const PLAN_HOSTNAME: &str = "work-plan-secret.example.test";
        const PLAN_ADDRESS_ONE: &str = "10.44.55.66";
        const PLAN_ADDRESS_TWO: &str = "10.44.55.67";
        const HISTORICAL_HOSTNAME: &str = "retired-secret.example.test";
        const HISTORICAL_HOSTNAME_RENDERED: &str = "Retired-Secret.Example.Test";
        const PLAN_PORT_ONE: u16 = 49_151;
        const PLAN_PORT_TWO: u16 = 49_152;
        let temp = tempdir().unwrap();
        let artifact_root = temp.path().join("artifacts");
        let mut case = fixture(&artifact_root, true);
        let time = Utc.with_ymd_and_hms(2026, 8, 24, 12, 0, 0).unwrap();
        case.title = SENTINEL.into();
        case.profile.organization_name = SENTINEL.into();
        case.profile.notes = Some(SENTINEL.into());
        case.data_sources.push(DataSource {
            id: "source-1".into(),
            kind: SourceKind::Dns,
            label: SENTINEL.into(),
            status: SourceConnectionStatus::Connected,
            connected_at: Some(time),
            last_discovered_at: Some(time),
            read_only: true,
            metadata: BTreeMap::from([("sensitive".into(), json!(SENTINEL))]),
        });
        case.assets[0].name = SENTINEL.into();
        case.assets[0].provider = Some(SENTINEL.into());
        case.assets[0].region = Some(SENTINEL.into());
        case.assets[0].identifiers[0].value = SENTINEL.into();
        case.assets[0]
            .metadata
            .insert("sensitive".into(), json!(SENTINEL));

        let grant = ScopeGrant {
            id: "grant-1".into(),
            asset_id: "asset-1".into(),
            permission: ScanPermission::ActiveExternalTesting,
            confirmed_by: SENTINEL.into(),
            confirmed_at: time,
            expires_at: Some(time + chrono::Duration::hours(1)),
            authorization_reference: Some(SENTINEL.into()),
            notes: Some(SENTINEL.into()),
            external_scope: Some(ExternalScopeGrant {
                id: "external-1".into(),
                case_id: case.id.clone(),
                asset_id: "asset-1".into(),
                target: CanonicalTarget::Hostname(HISTORICAL_HOSTNAME.into()),
                ports: [8443].into_iter().collect(),
                protocol: TransportProtocol::Https,
                activity: ExternalActivity::ActiveExternal,
                rate_policy: RatePolicy {
                    requests_per_second: 1,
                    concurrency: 1,
                    timeout_seconds: 60,
                },
                template_policy: TemplatePolicy::conservative(
                    "a".repeat(40),
                    vec!["template-1".into()],
                ),
                asserted_authority: SENTINEL.into(),
                approved_by: SENTINEL.into(),
                approved_at: time,
                expires_at: time + chrono::Duration::hours(1),
                allow_sensitive_networks: false,
            }),
        };
        case.scope_grants.push(grant.clone());
        case.scan_runs[0].scope_grant_ids = vec![grant.id.clone()];
        case.scan_runs[0].scope_grant_snapshots = vec![grant];
        case.scope_grants.clear();
        case.scan_runs[0].engine_runs[0].resume_token = Some(SENTINEL.into());
        case.scan_runs[0].engine_runs[0].error_message = Some(SENTINEL.into());
        case.scan_runs[0].engine_runs[0].cleanup_detail = Some(SENTINEL.into());
        case.scan_runs[0].engine_runs[0].warnings = vec![SENTINEL.into()];
        let private_naabu_plan = build_naabu_work_plan(
            NaabuWorkPlanIdentity::new("case-1", "run-1", "engine-run-1", time),
            &[ResolvedExternalPlan {
                grant_id: "work-plan-grant".into(),
                case_id: "case-1".into(),
                asset_id: "asset-1".into(),
                target: CanonicalTarget::Hostname(PLAN_HOSTNAME.into()),
                resolution: ResolutionSnapshot {
                    hostname: Some(PLAN_HOSTNAME.into()),
                    addresses: [
                        PLAN_ADDRESS_ONE.parse().unwrap(),
                        PLAN_ADDRESS_TWO.parse().unwrap(),
                    ]
                    .into_iter()
                    .collect(),
                    resolved_at: time,
                },
                ports: [PLAN_PORT_ONE, PLAN_PORT_TWO].into_iter().collect(),
                protocol: TransportProtocol::Tcp,
                activity: ExternalActivity::LowImpactExternal,
                rate_policy: RatePolicy {
                    requests_per_second: 2,
                    concurrency: 1,
                    timeout_seconds: 3,
                },
                template_policy: TemplatePolicy::conservative("not_applicable", Vec::new()),
                frozen_at: time,
                expires_at: time + chrono::Duration::hours(1),
                allow_sensitive_networks: true,
            }],
            None,
        )
        .unwrap();
        let requested_unit_ids = private_naabu_plan
            .work_units
            .iter()
            .map(|unit| unit.unit_id.clone())
            .collect::<Vec<_>>();
        let requested_units = requested_unit_ids.iter().cloned().collect();
        let private_launcher = private_naabu_plan
            .launcher_plan_v2(1, Some(&requested_units))
            .unwrap();
        case.scan_runs[0].engine_runs[0].naabu_attempt_requests = vec![NaabuAttemptRequest {
            schema_version: NAABU_ATTEMPT_REQUEST_SCHEMA_VERSION,
            execution_attempt: 1,
            requested_unit_ids,
            launcher_plan_sha256: sha256_bytes(&serde_json::to_vec(&private_launcher).unwrap()),
        }];
        let private_attempt_work_units = private_naabu_plan
            .work_units
            .iter()
            .map(|unit| WorkUnitCoverage {
                unit_id: unit.unit_id.clone(),
                scope_sha256: unit.scope_sha256.clone(),
                outcome: WorkUnitOutcome::NotTested,
                attempts: Vec::new(),
            })
            .collect::<Vec<_>>();
        let private_attempt_unit_count = private_attempt_work_units.len();
        case.scan_runs[0].engine_runs[0].naabu_attempt_results = vec![NaabuAttemptResult {
            schema_version: NAABU_ATTEMPT_RESULT_SCHEMA_VERSION,
            execution_attempt: 1,
            journal_raw_artifact_id: case.raw_artifacts[0].id.clone(),
            coverage: ValidatedExecutionCoverage {
                schema_version: LAUNCHER_V2_JOURNAL_SCHEMA_VERSION,
                engine_run_id: private_naabu_plan.identity.engine_run_id.clone(),
                execution_attempt: 1,
                recovered_trailing_record: false,
                validated_artifact_bindings: Vec::new(),
                unreferenced_final_artifacts: Vec::new(),
                work_units: private_attempt_work_units,
                summary: ExecutionCoverageSummary {
                    requested: private_attempt_unit_count,
                    tested_complete: 0,
                    tested_partial: 0,
                    failed: 0,
                    timed_out: 0,
                    cancelled: 0,
                    not_tested: private_attempt_unit_count,
                    partial: true,
                    has_usable_results: false,
                },
            },
            normalization_complete: true,
        }];
        case.scan_runs[0].engine_runs[0].naabu_work_plan = Some(private_naabu_plan);
        case.coverage.push(CoverageEntry {
            id: "coverage-1".into(),
            scope_key: SENTINEL.into(),
            label: SENTINEL.into(),
            source_kind: SourceKind::Dns,
            asset_id: Some("asset-1".into()),
            status: CoverageStatus::AuthorizedScanIncomplete,
            explanation: SENTINEL.into(),
            last_run_id: Some("run-1".into()),
            observed_at: Some(time),
        });
        case.findings.push(Finding {
            id: "finding-1".into(),
            case_id: case.id.clone(),
            first_seen_run_id: "run-1".into(),
            last_seen_run_id: "run-1".into(),
            fingerprint: "fingerprint-1".into(),
            title: format!(
                "{PLAN_HOSTNAME} resolved to {PLAN_ADDRESS_ONE}; earlier target {HISTORICAL_HOSTNAME_RENDERED}"
            ),
            plain_language_summary: format!(
                "The scan observed {PLAN_ADDRESS_ONE} and {PLAN_ADDRESS_TWO}."
            ),
            possible_impact: format!("Traffic may reach {PLAN_ADDRESS_TWO}."),
            severity: Severity::High,
            confidence: Confidence::High,
            priority: 50,
            priority_reasons: vec![format!("Observed at {PLAN_ADDRESS_ONE}")],
            asset_ids: vec!["asset-1".into()],
            evidence: vec![Evidence {
                id: "evidence-1".into(),
                finding_id: "finding-1".into(),
                run_id: "run-1".into(),
                engine_run_id: Some("engine-run-1".into()),
                kind: EvidenceKind::Observation,
                engine_id: "engine-1".into(),
                source_rule: None,
                result_pointer_sha256: None,
                observed_at: time,
                summary: SENTINEL.into(),
                artifact_id: "artifact-1".into(),
                artifact_sha256: case.raw_artifacts[0].sha256.clone(),
                pointer: Some(SENTINEL.into()),
                redacted: false,
            }],
            control_references: vec![],
            recommendation: format!("Review {PLAN_HOSTNAME} and {PLAN_ADDRESS_TWO}."),
            verification_guidance: format!("Repeat against {PLAN_ADDRESS_ONE}."),
            rollback_considerations: None,
            official_references: vec![format!("https://{PLAN_HOSTNAME}/help")],
            recommended_expert_type: format!("Owner of {PLAN_ADDRESS_ONE}"),
            status: FindingStatus::Unreviewed,
            tags: vec![format!("resolved:{PLAN_ADDRESS_TWO}")],
        });
        case.finding_observations.push(FindingObservation {
            id: "observation-1".into(),
            run_id: "run-1".into(),
            finding_id: "finding-1".into(),
            fingerprint: "fingerprint-1".into(),
            asset_ids: vec!["asset-1".into()],
            engine_ids: vec!["engine-1".into()],
            severity: Severity::High,
            confidence: Confidence::High,
            evidence_hashes: vec![case.raw_artifacts[0].sha256.clone()],
            observed_at: time,
            finding_snapshot: None,
        });
        case.comparisons.push(VerificationComparison {
            id: "comparison-1".into(),
            case_id: case.id.clone(),
            baseline_run_id: "run-1".into(),
            current_run_id: "run-1".into(),
            created_at: time,
            diffs: vec![FindingDiff {
                fingerprint: "fingerprint-1".into(),
                baseline_finding_id: Some("finding-1".into()),
                current_finding_id: Some("finding-1".into()),
                status: FindingDiffStatus::Changed,
                explanation: SENTINEL.into(),
                baseline_severity: Some(Severity::High),
                current_severity: Some(Severity::High),
                evidence_changed: true,
                reasons: vec![FindingDiffReason {
                    code: FindingDiffReasonCode::EvidenceChanged,
                    engine_id: Some("engine-1".into()),
                    asset_id: Some("asset-1".into()),
                    detail: SENTINEL.into(),
                }],
            }],
            complete: false,
            completeness_issues: vec![FindingDiffReason {
                code: FindingDiffReasonCode::CoordinateNotCompleted,
                engine_id: Some("engine-1".into()),
                asset_id: Some("asset-1".into()),
                detail: SENTINEL.into(),
            }],
        });
        case.raw_artifacts[0].relative_path = format!("raw/{SENTINEL}.txt");

        let unredacted =
            serde_json::to_string(&case_for_export(&case, RedactionProfile::None)).unwrap();
        assert!(
            unredacted.contains(SENTINEL),
            "the sentinel fixture must be meaningful"
        );
        for private_value in [
            PLAN_HOSTNAME,
            PLAN_ADDRESS_ONE,
            PLAN_ADDRESS_TWO,
            &PLAN_PORT_ONE.to_string(),
            &PLAN_PORT_TWO.to_string(),
        ] {
            assert!(
                unredacted.contains(private_value),
                "the work-plan redaction fixture must contain {private_value}"
            );
        }
        assert!(
            unredacted
                .to_ascii_lowercase()
                .contains(HISTORICAL_HOSTNAME),
            "historical mixed-case target fixture must be meaningful"
        );
        assert!(
            !case.scan_runs[0].engine_runs[0]
                .naabu_attempt_results
                .is_empty(),
            "attempt-result redaction fixture must be meaningful"
        );
        let redacted = case_for_export(&case, RedactionProfile::Standard);
        let redacted_json = serde_json::to_string(&redacted).unwrap();
        assert!(!redacted_json.contains(SENTINEL));
        for private_target in [PLAN_HOSTNAME, PLAN_ADDRESS_ONE, PLAN_ADDRESS_TWO] {
            assert!(
                !redacted_json.contains(private_target),
                "standard-redacted case leaked frozen target {private_target} from finding prose"
            );
        }
        assert!(
            !redacted_json
                .to_ascii_lowercase()
                .contains(HISTORICAL_HOSTNAME),
            "standard-redacted case leaked a historical mixed-case target"
        );
        assert!(
            redacted.scan_runs[0].engine_runs[0]
                .naabu_work_plan
                .is_none()
        );
        assert!(
            redacted.scan_runs[0].engine_runs[0]
                .naabu_attempt_requests
                .is_empty()
        );
        assert!(
            redacted.scan_runs[0].engine_runs[0]
                .naabu_attempt_results
                .is_empty()
        );
        let standard_report =
            beginner_report_for_export(&case, "run-1", RedactionProfile::Standard).unwrap();
        assert_ne!(
            standard_report.state.summary,
            crate::beginner_report::BeginnerReportSummary::Complete
        );
        assert!(standard_report.coverage_gaps.iter().any(|gap| {
            matches!(
                gap.kind,
                crate::beginner_report::CoverageGapKind::NotTested
                    | crate::beginner_report::CoverageGapKind::Unavailable
            )
        }));
        let standard_report_json = serde_json::to_string(&standard_report).unwrap();
        for private_value in [
            SENTINEL,
            PLAN_HOSTNAME,
            PLAN_ADDRESS_ONE,
            PLAN_ADDRESS_TWO,
            HISTORICAL_HOSTNAME,
            &PLAN_PORT_ONE.to_string(),
            &PLAN_PORT_TWO.to_string(),
        ] {
            assert!(
                !standard_report_json
                    .to_ascii_lowercase()
                    .contains(&private_value.to_ascii_lowercase()),
                "standard-redacted beginner report leaked {private_value}"
            );
        }
        let ocsf = String::from_utf8(export_ocsf_finding_events_bytes(&redacted, "run-1").unwrap())
            .unwrap();
        let oscal =
            String::from_utf8(export_oscal_assessment_results_bytes(&redacted, "run-1").unwrap())
                .unwrap();
        for private_value in [SENTINEL, PLAN_HOSTNAME, PLAN_ADDRESS_ONE, PLAN_ADDRESS_TWO] {
            assert!(!ocsf.contains(private_value));
            assert!(!oscal.contains(private_value));
        }
        assert!(!ocsf.to_ascii_lowercase().contains(HISTORICAL_HOSTNAME));
        assert!(!oscal.to_ascii_lowercase().contains(HISTORICAL_HOSTNAME));

        let destination = temp.path().join("sentinel-redacted.case.tar.gz");
        create_case_bundle_at(
            &case,
            "run-1",
            &artifact_root,
            &destination,
            temp.path().join("key"),
            ExportOptions::default(),
            time,
        )
        .unwrap();
        let file = File::open(&destination).unwrap();
        let mut archive = tar::Archive::new(GzDecoder::new(file));
        for entry in archive.entries().unwrap() {
            let mut entry = entry.unwrap();
            let mut bytes = Vec::new();
            entry.read_to_end(&mut bytes).unwrap();
            assert!(
                !bytes
                    .windows(SENTINEL.len())
                    .any(|window| window == SENTINEL.as_bytes()),
                "standard-redacted bundle entry leaked the sentinel"
            );
            for private_value in [
                PLAN_HOSTNAME.to_owned(),
                PLAN_ADDRESS_ONE.to_owned(),
                PLAN_ADDRESS_TWO.to_owned(),
                PLAN_PORT_ONE.to_string(),
                PLAN_PORT_TWO.to_string(),
            ] {
                assert!(
                    !bytes
                        .windows(private_value.len())
                        .any(|window| window == private_value.as_bytes()),
                    "standard-redacted bundle entry leaked private Naabu work-plan data"
                );
            }
            assert!(
                !bytes
                    .to_ascii_lowercase()
                    .windows(HISTORICAL_HOSTNAME.len())
                    .any(|window| window == HISTORICAL_HOSTNAME.as_bytes()),
                "standard-redacted bundle entry leaked a historical mixed-case target"
            );
        }
        drop(archive);
        let bundled_report: Value = serde_json::from_slice(&archive_entry(
            &destination,
            "exports/beginner-master-report.json",
        ))
        .unwrap();
        assert_eq!(
            bundled_report["report"],
            serde_json::to_value(&standard_report).unwrap(),
            "the case bundle must use the same authoritative beginner report as every other export"
        );
    }

    #[test]
    fn bundle_discloses_reversible_groups_and_redacts_their_metadata() {
        let temp = tempdir().unwrap();
        let artifact_root = temp.path().join("artifacts");
        let mut case = fixture(&artifact_root, false);
        add_reversible_grouping(&mut case);
        let destination = temp.path().join("grouped.case.tar.gz");
        create_case_bundle_at(
            &case,
            "run-1",
            &artifact_root,
            &destination,
            temp.path().join("key"),
            ExportOptions::default(),
            Utc.with_ymd_and_hms(2026, 8, 24, 13, 0, 0).unwrap(),
        )
        .unwrap();

        let grouping_bytes = archive_entry(&destination, "finding-grouping.json");
        let grouping_text = String::from_utf8(grouping_bytes.clone()).unwrap();
        for sensitive in [
            "Private old group title",
            "Private old grouping rationale",
            "Private old group removal reason",
            "Private old group creator",
            "Private old group remover",
            "Private active group title",
            "Private active grouping rationale",
            "Private active group creator",
        ] {
            assert!(!grouping_text.contains(sensitive));
        }
        let grouping: Value = serde_json::from_slice(&grouping_bytes).unwrap();
        assert_eq!(grouping["active_groups"].as_array().unwrap().len(), 1);
        assert_eq!(
            grouping["finding_group_events"].as_array().unwrap().len(),
            3
        );
        assert_eq!(
            grouping.pointer("/active_groups/0/title"),
            Some(&Value::String("[redacted finding group]".into()))
        );
        assert_eq!(
            grouping.pointer("/active_groups/0/finding_ids/0"),
            Some(&Value::String("finding-a".into()))
        );

        let findings: Value =
            serde_json::from_slice(&archive_entry(&destination, "findings.json")).unwrap();
        assert_eq!(findings["findings"].as_array().unwrap().len(), 2);
        assert_eq!(findings["active_groups"].as_array().unwrap().len(), 1);

        let readme = String::from_utf8(archive_entry(&destination, "README.txt")).unwrap();
        assert!(readme.contains("Active finding groups: 1"));
        assert!(readme.contains("Immutable finding-group events: 3"));
        assert!(readme.contains("reversible presentation metadata"));
    }

    #[test]
    fn rejects_traversal_in_artifact_and_archive_paths() {
        assert!(validate_portable_archive_path(Path::new("../secret")).is_err());
        assert!(validate_portable_archive_path(Path::new("C:\\secret")).is_err());
        assert!(validate_portable_archive_path(Path::new("/absolute")).is_err());

        let temp = tempdir().unwrap();
        let artifact_root = temp.path().join("artifacts");
        let mut case = fixture(&artifact_root, false);
        case.raw_artifacts[0].relative_path = "../outside".into();
        let result = create_case_bundle_at(
            &case,
            "run-1",
            &artifact_root,
            temp.path().join("bad.case.tar.gz"),
            temp.path().join("key"),
            ExportOptions {
                redaction: RedactionProfile::None,
                include_raw_artifacts: true,
            },
            Utc.with_ymd_and_hms(2026, 8, 24, 13, 0, 0).unwrap(),
        );
        assert!(result.is_err());
    }

    #[test]
    fn detects_corrupted_archive() {
        let temp = tempdir().unwrap();
        let artifact_root = temp.path().join("artifacts");
        let case = fixture(&artifact_root, false);
        let destination = temp.path().join("case.case.tar.gz");
        create_case_bundle_at(
            &case,
            "run-1",
            &artifact_root,
            &destination,
            temp.path().join("key"),
            ExportOptions::default(),
            Utc.with_ymd_and_hms(2026, 8, 24, 13, 0, 0).unwrap(),
        )
        .unwrap();
        let mut bytes = fs::read(&destination).unwrap();
        let middle = bytes.len() / 2;
        bytes[middle] ^= 0x40;
        fs::write(&destination, bytes).unwrap();

        assert!(verify_case_bundle(&destination).is_err());
    }
}
