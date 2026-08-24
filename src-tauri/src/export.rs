use crate::domain::{
    AssessmentCase, CaseExport, DataSource, Finding, RawArtifact, ScanRun, new_id,
};
use crate::error::{AppError, AppResult};
use crate::exporters::ocsf::OCSF_SCHEMA_VERSION;
use crate::exporters::oscal::OSCAL_VERSION;
use crate::exporters::{export_ocsf_finding_events_bytes, export_oscal_assessment_results_bytes};
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
use zeroize::Zeroize;

pub const BUNDLE_SCHEMA_VERSION: &str = "1";
pub const MANIFEST_PATH: &str = "manifest.json";
pub const SIGNATURE_PATH: &str = "signature.json";
pub const INTEGRITY_ONLY_NOTICE: &str = "The Ed25519 signature establishes integrity of the signed manifest only. It does not prove scanner correctness, completeness, legal authorization, authorship, identity, audit status, or forensic validity.";
pub const PRELIMINARY_EVIDENCE_NOTICE: &str = "This package contains preliminary scanner evidence, not an audit, certification, attestation, compliance determination, or forensic conclusion. Related control references are navigation coordinates only.";

const IO_BUFFER_BYTES: usize = 64 * 1024;
const MAX_ARCHIVE_ENTRIES: usize = 100_000;
const MAX_RESERVED_DOCUMENT_BYTES: u64 = 16 * 1024 * 1024;
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

    let signing_key = load_or_create_signing_key(signing_key_path.as_ref())?;
    let verifying_key = signing_key.verifying_key();
    let public_key_base64 = BASE64.encode(verifying_key.as_bytes());
    let key_id = sha256_bytes(verifying_key.as_bytes());

    let redacted_case = case_for_export(case, options.redaction);
    let artifact_root = artifact_root.as_ref();
    let (artifact_records, artifact_sources) = prepare_artifacts(
        case,
        artifact_root,
        options.redaction,
        options.include_raw_artifacts,
    )?;
    let documents = build_documents(
        &redacted_case,
        run,
        run_id,
        &artifact_records,
        options.redaction,
        options.include_raw_artifacts,
        created_at,
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
        path: destination.display().to_string(),
        sha256: archive_sha256,
        signature: Some(envelope.signature_base64),
        public_key: Some(envelope.public_key_base64),
        redaction_profile: options.redaction.as_str().into(),
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
    if let Some(expected) = expected_archive_sha256 {
        if !archive_sha256.eq_ignore_ascii_case(expected) {
            return Err(AppError::InvalidRequest(format!(
                "bundle archive hash mismatch: expected {expected}, observed {archive_sha256}"
            )));
        }
    }

    let file = File::open(path)?;
    let decoder = GzDecoder::new(file);
    let mut archive = tar::Archive::new(decoder);
    let mut observed = BTreeMap::<String, ObservedEntry>::new();
    let mut manifest_bytes = None;
    let mut signature_bytes = None;
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

    if let Some(expected_public_key) = expected_public_key_base64 {
        if expected_public_key != envelope.public_key_base64 {
            return Err(AppError::InvalidRequest(
                "bundle signing key does not match the expected public key".into(),
            ));
        }
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
    schemas.insert("ocsf".into(), OCSF_SCHEMA_VERSION.into());
    schemas.insert("oscal".into(), OSCAL_VERSION.into());
    let mut notices = vec![
        PRELIMINARY_EVIDENCE_NOTICE.into(),
        INTEGRITY_ONLY_NOTICE.into(),
        "Raw artifact omission is recorded in raw-artifacts.json; omission is not evidence of a clean result.".into(),
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
    run_id: &str,
    artifact_records: &[RawArtifactExportRecord],
    redaction: RedactionProfile,
    include_raw_artifacts: bool,
    created_at: DateTime<Utc>,
) -> AppResult<PreparedDocuments> {
    let mut documents = PreparedDocuments::new();
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
        "data_sources": case.data_sources,
        "selected_run_id": run_id,
        "exported_at": created_at,
        "counts": {
            "assets": case.assets.len(),
            "scope_grants": case.scope_grants.len(),
            "coverage_entries": case.coverage.len(),
            "scan_runs": case.scan_runs.len(),
            "findings": case.findings.len(),
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
        &json!({ "findings": case.findings }),
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
        &json!({ "engine_runs": engine_version_records(case) }),
        false,
    )?;
    insert_json(
        &mut documents,
        "raw-artifacts.json",
        &json!({ "raw_artifacts": artifact_records }),
        true,
    )?;
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
         {}\n\
         IMPORTANT LIMITATIONS\n\
         {}\n\
         {}\n\
         Control references in canonical, OCSF, and OSCAL files are related coordinates only.\n\
         Absence of a finding or omitted evidence is not a clean-result assertion.\n\
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
        demo_notice,
        PRELIMINARY_EVIDENCE_NOTICE,
        INTEGRITY_ONLY_NOTICE,
    )
}

fn engine_version_records(case: &AssessmentCase) -> Vec<Value> {
    let mut records = Vec::new();
    for run in &case.scan_runs {
        for engine_run in &run.engine_runs {
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
                "error_code": engine_run.error_code,
                "error_message": engine_run.error_message
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

fn case_for_export(case: &AssessmentCase, redaction: RedactionProfile) -> AssessmentCase {
    let mut exported = case.clone();
    exported.exports.clear();
    sort_case(&mut exported);

    if redaction == RedactionProfile::Standard {
        exported.title = "Redacted assessment case".into();
        exported.profile.organization_name = "[redacted]".into();
        exported.profile.notes = None;
        for source in &mut exported.data_sources {
            redact_data_source(source);
        }
        for asset in &mut exported.assets {
            asset.name = "[redacted asset]".into();
            asset.provider = None;
            asset.region = None;
            asset.identifiers.clear();
            asset.metadata.clear();
        }
        for grant in &mut exported.scope_grants {
            grant.confirmed_by = "[redacted]".into();
            grant.authorization_reference = None;
            grant.notes = None;
        }
        for coverage in &mut exported.coverage {
            coverage.scope_key = "[redacted]".into();
            coverage.label = "[redacted]".into();
            coverage.explanation = "[redacted coverage detail]".into();
        }
        for run in &mut exported.scan_runs {
            for engine_run in &mut run.engine_runs {
                engine_run.error_message = engine_run
                    .error_message
                    .as_ref()
                    .map(|_| "[redacted engine error detail]".into());
            }
        }
        for finding in &mut exported.findings {
            redact_finding(finding);
        }
        for artifact in &mut exported.raw_artifacts {
            artifact.relative_path = "[redacted]".into();
        }
        for comparison in &mut exported.comparisons {
            for diff in &mut comparison.diffs {
                diff.explanation = "[redacted comparison detail]".into();
            }
        }
    }
    exported
}

fn redact_data_source(source: &mut DataSource) {
    source.label = "[redacted source]".into();
    source.metadata.clear();
}

fn redact_finding(finding: &mut Finding) {
    for evidence in &mut finding.evidence {
        evidence.summary = "[redacted evidence summary]".into();
        evidence.pointer = None;
        evidence.redacted = true;
    }
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

fn validate_destination(destination: &Path) -> AppResult<()> {
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
        if let Some(previous) = previous_path {
            if previous >= path.as_str() {
                return Err(AppError::InvalidRequest(
                    "manifest entries must be uniquely sorted by path".into(),
                ));
            }
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

fn load_or_create_signing_key(path: &Path) -> AppResult<SigningKey> {
    if let Some(parent) = path
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
    {
        fs::create_dir_all(parent)?;
    }
    match fs::symlink_metadata(path) {
        Ok(metadata) => {
            if metadata.file_type().is_symlink() || !metadata.is_file() {
                return Err(AppError::InvalidRequest(format!(
                    "signing key must be a regular file and not a symlink: {}",
                    path.display()
                )));
            }
            validate_private_key_permissions(&metadata, path)?;
            let mut bytes = Vec::new();
            File::open(path)?.read_to_end(&mut bytes)?;
            if bytes.len() != 32 {
                bytes.zeroize();
                return Err(AppError::InvalidRequest(format!(
                    "local Ed25519 key must contain exactly 32 bytes: {}",
                    path.display()
                )));
            }
            let mut secret = [0_u8; 32];
            secret.copy_from_slice(&bytes);
            bytes.zeroize();
            let key = SigningKey::from_bytes(&secret);
            secret.zeroize();
            Ok(key)
        }
        Err(error) if error.kind() == io::ErrorKind::NotFound => {
            let mut secret = [0_u8; 32];
            getrandom::fill(&mut secret).map_err(|error| {
                AppError::Internal(format!("could not generate local signing key: {error}"))
            })?;
            let key = SigningKey::from_bytes(&secret);
            let mut file = match create_private_new_file(path) {
                Ok(file) => file,
                Err(AppError::Internal(message))
                    if message.contains("File exists") || message.contains("exists") =>
                {
                    secret.zeroize();
                    return load_or_create_signing_key(path);
                }
                Err(error) => {
                    secret.zeroize();
                    return Err(error);
                }
            };
            file.write_all(&secret)?;
            file.sync_all()?;
            secret.zeroize();
            Ok(key)
        }
        Err(error) => Err(error.into()),
    }
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

#[cfg(unix)]
fn validate_private_key_permissions(metadata: &fs::Metadata, path: &Path) -> AppResult<()> {
    use std::os::unix::fs::PermissionsExt;
    if metadata.permissions().mode() & 0o077 != 0 {
        return Err(AppError::InvalidRequest(format!(
            "local signing key permissions must not allow group or other access: {}",
            path.display()
        )));
    }
    Ok(())
}

#[cfg(not(unix))]
fn validate_private_key_permissions(_metadata: &fs::Metadata, _path: &Path) -> AppResult<()> {
    Ok(())
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
            knowledge_cutoff: time,
            scope_grant_ids: vec![],
            engine_runs: vec![EngineRun {
                id: "engine-run-1".into(),
                scan_run_id: "run-1".into(),
                engine_id: "engine-1".into(),
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
            options,
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
        assert_eq!(verified.integrity_only_notice, INTEGRITY_ONLY_NOTICE);
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
