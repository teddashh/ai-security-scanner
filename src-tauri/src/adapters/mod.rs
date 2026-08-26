//! Bounded, evidence-preserving normalizers for the built-in scanner catalog.
//!
//! Scanner output is untrusted input. These adapters only map explicit tool
//! fields into the case schema; they never execute, render, or follow text from
//! a target or a scanner result.

mod control_mapping;

use crate::adapter::{AdapterInput, AdapterOutput, AdapterRegistry, EngineAdapter};
use crate::domain::{
    Confidence, Evidence, EvidenceKind, Finding, FindingStatus, RawArtifact, Severity,
};
use crate::error::AppResult;
use quick_xml::events::{BytesRef, BytesStart, Event};
use quick_xml::{Reader, XmlVersion};
use serde_json::{Map, Value};
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet};
use std::fs::File;
use std::io::{Read, Take};
use std::path::{Component, Path};
use std::sync::Arc;

pub const ADAPTER_VERSION: &str = "0.1.1";
/// Stable identity for the canonical finding fingerprint algorithm. Changing
/// this value requires an explicit migration before cross-version diffs may be
/// treated as comparable.
pub const FINGERPRINT_SCHEMA_VERSION: &str = "v1";
pub const BUILTIN_ENGINE_IDS: &[&str] = &[
    "cloudquery",
    "steampipe",
    "prowler",
    "scoutsuite",
    "cloudsplaining",
    "scubagear",
    "maester",
    "naabu",
    "httpx",
    "nuclei",
    "greenbone",
    "semgrep",
    "gitleaks",
    "trufflehog",
    "checkov",
    "kics",
    "trivy",
    "grype",
    "syft",
    "kubescape",
    "kube-bench",
];

const MAX_ARTIFACTS: usize = 64;
const MAX_ARTIFACT_BYTES: u64 = 16 * 1024 * 1024;
const MAX_TOTAL_BYTES: u64 = 32 * 1024 * 1024;
const MAX_RECORDS: usize = 10_000;
const MAX_LINE_BYTES: usize = 1024 * 1024;
const MAX_WARNINGS: usize = 256;
const MAX_SHORT_TEXT: usize = 512;
const MAX_LONG_TEXT: usize = 2_048;
const MAX_XML_DEPTH: usize = 64;
const MAX_XML_EVENTS: usize = 200_000;
const MAX_XML_ATTRIBUTES: usize = 256;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Profile {
    CloudQuery,
    Steampipe,
    Prowler,
    ScoutSuite,
    Cloudsplaining,
    ScubaGear,
    Maester,
    Naabu,
    Httpx,
    Nuclei,
    Greenbone,
    Semgrep,
    Gitleaks,
    Trufflehog,
    Checkov,
    Kics,
    Trivy,
    Grype,
    Syft,
    Kubescape,
    KubeBench,
}

#[derive(Debug)]
struct BuiltinAdapter {
    id: &'static str,
    profile: Profile,
    expert_type: &'static str,
}

#[derive(Debug, Clone)]
struct SourceRecord {
    pointer: String,
    rule_id: String,
    title: String,
    severity: Severity,
    source_severity: String,
    location: String,
    asset_hint: Option<String>,
    asset_provider: Option<String>,
    confidence: Confidence,
    evidence_kind: EvidenceKind,
    references: Vec<String>,
    tags: Vec<String>,
}

struct RecordDraft {
    pointer: String,
    rule_id: String,
    title: String,
    source_severity: String,
    location: String,
    asset_hint: Option<String>,
    confidence: Confidence,
    evidence_kind: EvidenceKind,
    references: Vec<String>,
    tags: Vec<String>,
}

macro_rules! record {
    (
        $pointer:expr,
        $rule_id:expr,
        $title:expr,
        $source_severity:expr,
        $location:expr,
        $asset_hint:expr,
        $confidence:expr,
        $evidence_kind:expr,
        $references:expr,
        $tags:expr $(,)?
    ) => {
        record_from_draft(RecordDraft {
            pointer: $pointer,
            rule_id: $rule_id,
            title: $title,
            source_severity: $source_severity,
            location: $location,
            asset_hint: $asset_hint,
            confidence: $confidence,
            evidence_kind: $evidence_kind,
            references: $references,
            tags: $tags,
        })
    };
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum XmlElement {
    Results,
    Result,
    Name,
    Nvt,
    Host,
    Port,
    Severity,
    Threat,
    Qod,
    Value,
    AssetId,
    Family,
    Refs,
    Ref,
    Other,
}

#[derive(Debug, Default)]
struct GreenboneXmlResult {
    pointer: String,
    result_id: Option<String>,
    nvt_oid: Option<String>,
    result_name: Option<String>,
    nvt_name: Option<String>,
    host: Option<String>,
    port: Option<String>,
    severity: Option<String>,
    threat: Option<String>,
    qod: Option<String>,
    asset_id: Option<String>,
    family: Option<String>,
    cves: Vec<String>,
}

#[derive(Debug)]
enum ParsedArtifact {
    Json(Value),
    JsonLines(Vec<(usize, Value)>),
    Xml(Vec<GreenboneXmlResult>),
}

/// Construct the adapter set matching the complete built-in engine catalog.
pub fn builtin_adapter_registry() -> AppResult<AdapterRegistry> {
    control_mapping::validate_catalog(BUILTIN_ENGINE_IDS)?;
    let definitions = [
        ("cloudquery", Profile::CloudQuery, "Cloud security engineer"),
        ("steampipe", Profile::Steampipe, "Cloud security engineer"),
        ("prowler", Profile::Prowler, "Cloud security engineer"),
        ("scoutsuite", Profile::ScoutSuite, "Cloud security engineer"),
        (
            "cloudsplaining",
            Profile::Cloudsplaining,
            "Cloud identity specialist",
        ),
        (
            "scubagear",
            Profile::ScubaGear,
            "Microsoft 365 security administrator",
        ),
        (
            "maester",
            Profile::Maester,
            "Microsoft 365 security administrator",
        ),
        ("naabu", Profile::Naabu, "Network security engineer"),
        ("httpx", Profile::Httpx, "Application security engineer"),
        ("nuclei", Profile::Nuclei, "Application security engineer"),
        ("greenbone", Profile::Greenbone, "Vulnerability manager"),
        ("semgrep", Profile::Semgrep, "Application security engineer"),
        ("gitleaks", Profile::Gitleaks, "Secrets-response specialist"),
        (
            "trufflehog",
            Profile::Trufflehog,
            "Secrets-response specialist",
        ),
        (
            "checkov",
            Profile::Checkov,
            "Infrastructure-as-code engineer",
        ),
        ("kics", Profile::Kics, "Infrastructure-as-code engineer"),
        ("trivy", Profile::Trivy, "Container security engineer"),
        ("grype", Profile::Grype, "Container security engineer"),
        ("syft", Profile::Syft, "Software supply-chain engineer"),
        (
            "kubescape",
            Profile::Kubescape,
            "Kubernetes security engineer",
        ),
        (
            "kube-bench",
            Profile::KubeBench,
            "Kubernetes security engineer",
        ),
    ];

    let mut registry = AdapterRegistry::default();
    for (id, profile, expert_type) in definitions {
        registry.register(Arc::new(BuiltinAdapter {
            id,
            profile,
            expert_type,
        }))?;
    }
    Ok(registry)
}

/// Exact embedded mapping identity frozen into every planned engine run.
pub(crate) fn control_mapping_version() -> AppResult<&'static str> {
    control_mapping::catalog_version()
}

impl EngineAdapter for BuiltinAdapter {
    fn engine_id(&self) -> &str {
        self.id
    }

    fn adapter_version(&self) -> &str {
        ADAPTER_VERSION
    }

    fn normalize(&self, input: &AdapterInput<'_>) -> AppResult<AdapterOutput> {
        normalize_artifacts(self, input)
    }
}

fn normalize_artifacts(
    adapter: &BuiltinAdapter,
    input: &AdapterInput<'_>,
) -> AppResult<AdapterOutput> {
    let mut output = AdapterOutput::default();
    let mut findings: BTreeMap<String, Finding> = BTreeMap::new();
    let mut processed_bytes = 0_u64;
    let mut processed_records = 0_usize;

    let relevant: Vec<&RawArtifact> = input
        .raw_artifacts
        .iter()
        .filter(|artifact| {
            artifact.case_id == input.case_id
                && artifact.run_id == input.scan_run_id
                && artifact.engine_run_id == input.engine_run_id
                && !is_runtime_stream_capture_path(&artifact.relative_path)
        })
        .collect();

    if relevant.is_empty() {
        output.complete = false;
        push_warning(
            &mut output.warnings,
            format!("{} produced no raw artifacts to normalize", adapter.id),
        );
        return Ok(output);
    }

    let relevant_count = relevant.len();
    for artifact in relevant.into_iter().take(MAX_ARTIFACTS) {
        if processed_bytes.saturating_add(artifact.byte_length) > MAX_TOTAL_BYTES {
            output.complete = false;
            push_warning(
                &mut output.warnings,
                "adapter input exceeded the total byte limit; remaining raw artifacts were retained but not normalized",
            );
            break;
        }

        let warnings_before_read = output.warnings.len();
        let bytes = read_bounded_artifact(input.artifact_root, artifact, &mut output.warnings);
        if output.warnings.len() > warnings_before_read {
            output.complete = false;
        }
        let Some(bytes) = bytes else {
            continue;
        };
        processed_bytes += bytes.len() as u64;

        let warnings_before_parse = output.warnings.len();
        let parsed = parse_artifact(&bytes, artifact, &mut output.warnings);
        if output.warnings.len() > warnings_before_parse {
            output.complete = false;
        }
        let Some(parsed) = parsed else {
            continue;
        };
        let warnings_before_extract = output.warnings.len();
        let records = extract_records(adapter.profile, &parsed, &mut output.warnings);
        if output.warnings.len() > warnings_before_extract {
            output.complete = false;
        }
        if records.len() >= MAX_RECORDS {
            output.complete = false;
            push_warning(
                &mut output.warnings,
                "adapter extraction reached the record safety boundary; completeness cannot be established",
            );
        }
        for record in records {
            if processed_records >= MAX_RECORDS {
                output.complete = false;
                push_warning(
                    &mut output.warnings,
                    "adapter record limit reached; remaining raw records were retained but not normalized",
                );
                break;
            }
            processed_records += 1;
            let warnings_before_resolution = output.warnings.len();
            let asset_id = resolve_asset(
                &record,
                input.asset_ids,
                input.asset_identifier_map,
                &mut output.warnings,
            );
            if output.warnings.len() > warnings_before_resolution {
                output.complete = false;
            }
            let Some(asset_id) = asset_id else {
                continue;
            };
            merge_finding(&mut findings, adapter, input, artifact, record, asset_id);
        }
    }

    if relevant_count > MAX_ARTIFACTS {
        output.complete = false;
        push_warning(
            &mut output.warnings,
            "adapter artifact-count limit reached; extra raw artifacts were retained but not normalized",
        );
    }

    if matches!(adapter.profile, Profile::CloudQuery | Profile::Syft) {
        push_warning(
            &mut output.warnings,
            format!(
                "{} output is inventory evidence; no security issue was invented from inventory rows",
                adapter.id
            ),
        );
    }

    output.findings = findings.into_values().collect();
    Ok(output)
}

/// Stdout and stderr are retained as raw evidence, but the released engine
/// contract writes normalizer input below `/output`. Feeding the backend-owned
/// stream captures to JSON/XML adapters would make every otherwise-valid run
/// look malformed (including the normal empty-stream case). Match the complete
/// private run layout so an engine-created `output/raw/stdout.log` remains
/// ordinary untrusted output instead of being silently skipped.
fn is_runtime_stream_capture_path(relative_path: &str) -> bool {
    let mut components = Path::new(relative_path).components().rev();
    let Some(Component::Normal(file_name)) = components.next() else {
        return false;
    };
    let Some(Component::Normal(raw_directory)) = components.next() else {
        return false;
    };
    let Some(Component::Normal(attempt_directory)) = components.next() else {
        return false;
    };
    let Some(attempt_directory) = attempt_directory.to_str() else {
        return false;
    };

    matches!(file_name.to_str(), Some("stdout.log" | "stderr.log"))
        && raw_directory == "raw"
        && attempt_directory
            .strip_prefix("attempt-")
            .is_some_and(|attempt| {
                !attempt.is_empty() && attempt.bytes().all(|byte| byte.is_ascii_digit())
            })
}

fn read_bounded_artifact(
    root: &Path,
    artifact: &RawArtifact,
    warnings: &mut Vec<String>,
) -> Option<Vec<u8>> {
    if artifact.byte_length > MAX_ARTIFACT_BYTES {
        push_warning(
            warnings,
            format!(
                "artifact {} exceeded the per-file byte limit and was not parsed",
                safe_text(&artifact.id, MAX_SHORT_TEXT)
            ),
        );
        return None;
    }

    let relative = Path::new(&artifact.relative_path);
    if relative.is_absolute()
        || relative.components().any(|component| {
            matches!(
                component,
                Component::ParentDir | Component::RootDir | Component::Prefix(_)
            )
        })
    {
        push_warning(
            warnings,
            "an artifact path escaped the case artifact root and was rejected",
        );
        return None;
    }

    let root = match root.canonicalize() {
        Ok(path) => path,
        Err(_) => {
            push_warning(warnings, "the case artifact root could not be opened");
            return None;
        }
    };
    let path = root.join(relative);
    let canonical = match path.canonicalize() {
        Ok(path) if path.starts_with(&root) => path,
        _ => {
            push_warning(
                warnings,
                "an artifact path did not resolve inside the case artifact root",
            );
            return None;
        }
    };
    let file = match File::open(&canonical) {
        Ok(file) => file,
        Err(_) => {
            push_warning(
                warnings,
                format!(
                    "artifact {} could not be read; its metadata remains in the case",
                    safe_text(&artifact.id, MAX_SHORT_TEXT)
                ),
            );
            return None;
        }
    };
    let mut bytes =
        Vec::with_capacity((artifact.byte_length as usize).min(MAX_ARTIFACT_BYTES as usize));
    let mut reader: Take<File> = file.take(MAX_ARTIFACT_BYTES + 1);
    if reader.read_to_end(&mut bytes).is_err() || bytes.len() as u64 > MAX_ARTIFACT_BYTES {
        push_warning(
            warnings,
            "an artifact exceeded the byte limit while being read",
        );
        return None;
    }
    if bytes.len() as u64 != artifact.byte_length {
        push_warning(
            warnings,
            "an artifact length did not match its recorded evidence metadata",
        );
        return None;
    }
    let actual_hash = hex::encode(Sha256::digest(&bytes));
    if !actual_hash.eq_ignore_ascii_case(&artifact.sha256) {
        push_warning(
            warnings,
            "an artifact hash did not match its recorded evidence metadata",
        );
        return None;
    }
    Some(bytes)
}

fn parse_artifact(
    bytes: &[u8],
    artifact: &RawArtifact,
    warnings: &mut Vec<String>,
) -> Option<ParsedArtifact> {
    let first_non_whitespace = bytes
        .iter()
        .copied()
        .find(|byte| !byte.is_ascii_whitespace());
    if first_non_whitespace == Some(b'<') || artifact.media_type.contains("xml") {
        return parse_greenbone_xml(bytes, warnings).map(ParsedArtifact::Xml);
    }

    match serde_json::from_slice::<Value>(bytes) {
        Ok(value) => Some(ParsedArtifact::Json(value)),
        Err(document_error) => {
            let mut rows = Vec::new();
            for (index, line) in bytes.split(|byte| *byte == b'\n').enumerate() {
                let line = trim_ascii(line);
                if line.is_empty() {
                    continue;
                }
                if rows.len() >= MAX_RECORDS {
                    push_warning(
                        warnings,
                        "JSONL record limit reached; later lines remain only as raw evidence",
                    );
                    break;
                }
                if line.len() > MAX_LINE_BYTES {
                    push_warning(
                        warnings,
                        format!(
                            "JSONL line {} exceeded the line limit and was skipped",
                            index + 1
                        ),
                    );
                    continue;
                }
                match serde_json::from_slice::<Value>(line) {
                    Ok(value) => rows.push((index + 1, value)),
                    Err(_) => push_warning(
                        warnings,
                        format!("malformed JSONL line {} was skipped", index + 1),
                    ),
                }
            }
            if rows.is_empty() {
                push_warning(
                    warnings,
                    format!(
                        "artifact {} was neither valid bounded JSON nor JSONL: {}",
                        safe_text(&artifact.id, MAX_SHORT_TEXT),
                        safe_text(&document_error.to_string(), MAX_SHORT_TEXT)
                    ),
                );
                None
            } else {
                Some(ParsedArtifact::JsonLines(rows))
            }
        }
    }
}

fn parse_greenbone_xml(
    bytes: &[u8],
    warnings: &mut Vec<String>,
) -> Option<Vec<GreenboneXmlResult>> {
    let mut reader = Reader::from_reader(bytes);
    reader.config_mut().trim_text(true);
    reader.config_mut().check_end_names = true;
    reader.config_mut().expand_empty_elements = true;

    let mut buffer = Vec::new();
    let mut stack = Vec::new();
    let mut current: Option<GreenboneXmlResult> = None;
    let mut records = Vec::new();
    let mut event_count = 0_usize;
    let mut result_index = 0_usize;

    loop {
        event_count += 1;
        if event_count > MAX_XML_EVENTS {
            push_warning(
                warnings,
                "Greenbone XML event limit reached; later results remain only as raw evidence",
            );
            break;
        }

        match reader.read_event_into(&mut buffer) {
            Ok(Event::Eof) => break,
            Ok(Event::DocType(_)) => {
                push_warning(
                    warnings,
                    "Greenbone XML containing a DTD or custom entity reference was rejected",
                );
                return None;
            }
            Ok(Event::GeneralRef(reference)) => {
                let Some(value) = safe_xml_reference(&reference) else {
                    push_warning(
                        warnings,
                        "Greenbone XML containing a DTD or custom entity reference was rejected",
                    );
                    return None;
                };
                if is_greenbone_field(&stack)
                    && let Some(record) = current.as_mut()
                {
                    let mut encoded = [0_u8; 4];
                    apply_greenbone_text(record, &stack, value.encode_utf8(&mut encoded));
                }
            }
            Ok(Event::Start(start)) => {
                if stack.len() >= MAX_XML_DEPTH {
                    push_warning(
                        warnings,
                        "Greenbone XML nesting limit was exceeded; no XML findings were normalized",
                    );
                    return None;
                }
                let element = xml_element(start.local_name().as_ref());
                if element == XmlElement::Result && stack.last() == Some(&XmlElement::Results) {
                    if current.is_some() {
                        push_warning(warnings, "nested Greenbone result elements were rejected");
                        return None;
                    }
                    if records.len() >= MAX_RECORDS {
                        push_warning(
                            warnings,
                            "Greenbone result limit reached; later results remain only as raw evidence",
                        );
                        break;
                    }
                    result_index += 1;
                    let mut record = GreenboneXmlResult {
                        pointer: format!("/report/results/result[{result_index}]"),
                        ..GreenboneXmlResult::default()
                    };
                    match xml_attribute(&start, reader.decoder(), b"id") {
                        Ok(value) => record.result_id = value,
                        Err(error) => {
                            push_warning(warnings, error);
                            return None;
                        }
                    }
                    current = Some(record);
                } else if element == XmlElement::Nvt && current.is_some() {
                    match xml_attribute(&start, reader.decoder(), b"oid") {
                        Ok(Some(value)) => {
                            if let Some(oid) = normalize_greenbone_oid(&value) {
                                if let Some(record) = current.as_mut() {
                                    record.nvt_oid = Some(oid);
                                }
                            } else {
                                push_warning(warnings, "Greenbone result had an invalid NVT OID");
                            }
                        }
                        Ok(None) => {}
                        Err(error) => {
                            push_warning(warnings, error);
                            return None;
                        }
                    }
                } else if element == XmlElement::Ref
                    && stack.last() == Some(&XmlElement::Refs)
                    && current.is_some()
                {
                    let reference_type = match xml_attribute(&start, reader.decoder(), b"type") {
                        Ok(value) => value,
                        Err(error) => {
                            push_warning(warnings, error);
                            return None;
                        }
                    };
                    let reference_id = match xml_attribute(&start, reader.decoder(), b"id") {
                        Ok(value) => value,
                        Err(error) => {
                            push_warning(warnings, error);
                            return None;
                        }
                    };
                    if reference_type
                        .as_deref()
                        .is_some_and(|value| value.eq_ignore_ascii_case("cve"))
                        && let Some(cve) = reference_id.and_then(|value| normalize_cve(&value))
                        && let Some(record) = current.as_mut()
                        && record.cves.len() < 32
                        && !record.cves.contains(&cve)
                    {
                        record.cves.push(cve);
                    }
                }
                stack.push(element);
            }
            Ok(Event::End(end)) => {
                let element = xml_element(end.local_name().as_ref());
                if element == XmlElement::Result
                    && stack.last() == Some(&XmlElement::Result)
                    && let Some(record) = current.take()
                {
                    records.push(record);
                }
                stack.pop();
            }
            Ok(Event::Text(text)) if current.is_some() && is_greenbone_field(&stack) => {
                let raw_text: &[u8] = text.as_ref();
                if raw_text.len() > MAX_LONG_TEXT * 4 {
                    push_warning(warnings, "an oversized Greenbone XML field was ignored");
                    buffer.clear();
                    continue;
                }
                let decoded = match text.decode() {
                    Ok(value) => value,
                    Err(_) => {
                        push_warning(warnings, "a Greenbone XML text field could not be decoded");
                        buffer.clear();
                        continue;
                    }
                };
                let unescaped = match quick_xml::escape::unescape(&decoded) {
                    Ok(value) => value,
                    Err(_) => {
                        push_warning(
                            warnings,
                            "a Greenbone XML field used an unsupported entity and was ignored",
                        );
                        buffer.clear();
                        continue;
                    }
                };
                apply_greenbone_text(current.as_mut().expect("checked above"), &stack, &unescaped);
            }
            Ok(Event::CData(text)) if current.is_some() && is_greenbone_field(&stack) => {
                let raw_text: &[u8] = text.as_ref();
                if raw_text.len() > MAX_LONG_TEXT * 4 {
                    push_warning(warnings, "an oversized Greenbone XML field was ignored");
                    buffer.clear();
                    continue;
                }
                match text.decode() {
                    Ok(value) => apply_greenbone_text(
                        current.as_mut().expect("checked above"),
                        &stack,
                        &value,
                    ),
                    Err(_) => {
                        push_warning(warnings, "a Greenbone XML CDATA field could not be decoded")
                    }
                }
            }
            Ok(Event::PI(_)) => {
                push_warning(
                    warnings,
                    "a Greenbone XML processing instruction was ignored",
                );
            }
            Ok(_) => {}
            Err(error) => {
                push_warning(
                    warnings,
                    format!(
                        "Greenbone XML parsing stopped at byte {}: {}",
                        reader.error_position(),
                        safe_text(&error.to_string(), 240)
                    ),
                );
                break;
            }
        }
        buffer.clear();
    }

    if current.is_some() {
        push_warning(
            warnings,
            "an incomplete Greenbone result was retained only as raw evidence",
        );
    }
    if records.is_empty() {
        push_warning(
            warnings,
            "Greenbone XML contained no complete bounded result records; no findings were inferred",
        );
    }
    Some(records)
}

fn xml_attribute(
    start: &BytesStart<'_>,
    decoder: quick_xml::encoding::Decoder,
    name: &[u8],
) -> Result<Option<String>, String> {
    let mut matched = None;
    for (index, attribute) in start.attributes().with_checks(true).enumerate() {
        if index >= MAX_XML_ATTRIBUTES {
            return Err("Greenbone XML element exceeded the attribute limit".to_owned());
        }
        let attribute =
            attribute.map_err(|_| "Greenbone XML contained a malformed attribute".to_owned())?;
        if attribute.key.as_ref() == name && matched.is_none() {
            let value = attribute
                .decoded_and_normalized_value(XmlVersion::Implicit1_0, decoder)
                .map_err(|_| "Greenbone XML attribute could not be decoded safely".to_owned())?;
            matched = Some(safe_text(&value, MAX_SHORT_TEXT));
        }
    }
    Ok(matched)
}

fn safe_xml_reference(reference: &BytesRef<'_>) -> Option<char> {
    let reference_bytes: &[u8] = reference.as_ref();
    let value = match reference_bytes {
        b"amp" => '&',
        b"apos" => '\'',
        b"gt" => '>',
        b"lt" => '<',
        b"quot" => '"',
        _ => reference.resolve_char_ref().ok().flatten()?,
    };
    matches!(
        value,
        '\u{9}' | '\u{A}' | '\u{D}'
            | '\u{20}'..='\u{D7FF}'
            | '\u{E000}'..='\u{FFFD}'
            | '\u{10000}'..='\u{10FFFF}'
    )
    .then_some(value)
}

fn xml_element(name: &[u8]) -> XmlElement {
    match name {
        b"results" => XmlElement::Results,
        b"result" => XmlElement::Result,
        b"name" => XmlElement::Name,
        b"nvt" => XmlElement::Nvt,
        b"host" => XmlElement::Host,
        b"port" => XmlElement::Port,
        b"severity" => XmlElement::Severity,
        b"threat" => XmlElement::Threat,
        b"qod" => XmlElement::Qod,
        b"value" => XmlElement::Value,
        b"asset_id" => XmlElement::AssetId,
        b"family" => XmlElement::Family,
        b"refs" => XmlElement::Refs,
        b"ref" => XmlElement::Ref,
        _ => XmlElement::Other,
    }
}

fn is_greenbone_field(stack: &[XmlElement]) -> bool {
    stack.ends_with(&[XmlElement::Result, XmlElement::Name])
        || stack.ends_with(&[XmlElement::Result, XmlElement::Nvt, XmlElement::Name])
        || stack.ends_with(&[XmlElement::Result, XmlElement::Host])
        || stack.ends_with(&[XmlElement::Result, XmlElement::Port])
        || stack.ends_with(&[XmlElement::Result, XmlElement::Severity])
        || stack.ends_with(&[XmlElement::Result, XmlElement::Threat])
        || stack.ends_with(&[XmlElement::Result, XmlElement::Qod, XmlElement::Value])
        || stack.ends_with(&[XmlElement::Result, XmlElement::AssetId])
        || stack.ends_with(&[XmlElement::Result, XmlElement::Nvt, XmlElement::Family])
}

fn apply_greenbone_text(record: &mut GreenboneXmlResult, stack: &[XmlElement], value: &str) {
    let value = value
        .chars()
        .filter(|character| !character.is_control() || matches!(character, '\n' | '\t'))
        .take(MAX_LONG_TEXT)
        .collect::<String>();
    if value.is_empty() {
        return;
    }
    let target = if stack.ends_with(&[XmlElement::Result, XmlElement::Name]) {
        &mut record.result_name
    } else if stack.ends_with(&[XmlElement::Result, XmlElement::Nvt, XmlElement::Name]) {
        &mut record.nvt_name
    } else if stack.ends_with(&[XmlElement::Result, XmlElement::Host]) {
        &mut record.host
    } else if stack.ends_with(&[XmlElement::Result, XmlElement::Port]) {
        &mut record.port
    } else if stack.ends_with(&[XmlElement::Result, XmlElement::Severity]) {
        &mut record.severity
    } else if stack.ends_with(&[XmlElement::Result, XmlElement::Threat]) {
        &mut record.threat
    } else if stack.ends_with(&[XmlElement::Result, XmlElement::Qod, XmlElement::Value]) {
        &mut record.qod
    } else if stack.ends_with(&[XmlElement::Result, XmlElement::AssetId]) {
        &mut record.asset_id
    } else if stack.ends_with(&[XmlElement::Result, XmlElement::Nvt, XmlElement::Family]) {
        &mut record.family
    } else {
        return;
    };
    if let Some(target) = target.as_mut() {
        let remaining = MAX_LONG_TEXT.saturating_sub(target.chars().count());
        target.extend(value.chars().take(remaining));
    } else {
        let value = value.trim().to_owned();
        if !value.is_empty() {
            *target = Some(value);
        }
    }
}

fn normalize_greenbone_oid(value: &str) -> Option<String> {
    let value = value.trim();
    if value.len() < 3
        || value.len() > 128
        || value.starts_with('.')
        || value.ends_with('.')
        || value.split('.').any(|segment| {
            segment.is_empty() || !segment.chars().all(|character| character.is_ascii_digit())
        })
    {
        return None;
    }
    Some(value.to_owned())
}

fn normalize_cve(value: &str) -> Option<String> {
    let value = value.trim().to_ascii_uppercase();
    let mut segments = value.split('-');
    let prefix = segments.next()?;
    let year = segments.next()?;
    let sequence = segments.next()?;
    if segments.next().is_some()
        || prefix != "CVE"
        || year.len() != 4
        || !year.chars().all(|character| character.is_ascii_digit())
        || !(4..=12).contains(&sequence.len())
        || !sequence.chars().all(|character| character.is_ascii_digit())
    {
        return None;
    }
    Some(value)
}

fn extract_records(
    profile: Profile,
    parsed: &ParsedArtifact,
    warnings: &mut Vec<String>,
) -> Vec<SourceRecord> {
    if matches!(profile, Profile::CloudQuery | Profile::Syft) {
        return Vec::new();
    }

    match profile {
        Profile::Prowler => extract_prowler(parsed, warnings),
        Profile::ScoutSuite => extract_scoutsuite(parsed, warnings),
        Profile::Cloudsplaining => extract_cloudsplaining(parsed, warnings),
        Profile::ScubaGear => extract_scubagear(parsed, warnings),
        Profile::Maester => extract_maester(parsed, warnings),
        Profile::Naabu => extract_naabu(parsed, warnings),
        Profile::Httpx => extract_httpx(parsed, warnings),
        Profile::Nuclei => extract_nuclei(parsed, warnings),
        Profile::Greenbone => extract_greenbone(parsed, warnings),
        Profile::Semgrep => extract_semgrep(parsed, warnings),
        Profile::Gitleaks => extract_gitleaks(parsed, warnings),
        Profile::Trufflehog => extract_trufflehog(parsed, warnings),
        Profile::Checkov => extract_checkov(parsed, warnings),
        Profile::Kics => extract_kics(parsed, warnings),
        Profile::Trivy => extract_trivy(parsed, warnings),
        Profile::Grype => extract_grype(parsed, warnings),
        Profile::Kubescape => extract_kubescape(parsed, warnings),
        Profile::KubeBench => extract_kube_bench(parsed, warnings),
        Profile::Steampipe => extract_steampipe(parsed, warnings),
        Profile::CloudQuery | Profile::Syft => Vec::new(),
    }
}

fn json_rows<'a>(
    parsed: &'a ParsedArtifact,
    warnings: &mut Vec<String>,
) -> Vec<(String, &'a Value)> {
    match parsed {
        ParsedArtifact::Json(Value::Array(values)) => {
            if values.len() > MAX_RECORDS {
                push_warning(
                    warnings,
                    "top-level JSON record limit reached; later rows remain only as raw evidence",
                );
            }
            values
                .iter()
                .take(MAX_RECORDS)
                .enumerate()
                .map(|(index, value)| (format!("/{index}"), value))
                .collect()
        }
        ParsedArtifact::Json(value @ Value::Object(_)) => vec![("/".into(), value)],
        ParsedArtifact::Json(_) => {
            push_warning(warnings, "top-level JSON scalar was ignored");
            Vec::new()
        }
        ParsedArtifact::JsonLines(values) => values
            .iter()
            .take(MAX_RECORDS)
            .map(|(line, value)| (format!("line:{line}"), value))
            .collect(),
        ParsedArtifact::Xml(_) => Vec::new(),
    }
}

fn extract_prowler(parsed: &ParsedArtifact, warnings: &mut Vec<String>) -> Vec<SourceRecord> {
    let mut records = Vec::new();
    for (pointer, value) in json_rows(parsed, warnings) {
        let Some(object) = value.as_object() else {
            push_warning(
                warnings,
                format!("non-object Prowler record at {pointer} was skipped"),
            );
            continue;
        };
        // Prowler 5.39 OCSF uses status="New" for finding lifecycle state;
        // PASS/FAIL/MANUAL is carried by the top-level status_code field.
        let status = string_any(object, &["status_code", "StatusCode"])
            .or_else(|| string_any(object, &["Status", "status"]))
            .or_else(|| nested_string(value, &["unmapped", "Status"]))
            .or_else(|| nested_string(value, &["unmapped", "status"]));
        if status
            .as_deref()
            .is_some_and(|status| is_pass(status) || status.eq_ignore_ascii_case("manual"))
        {
            continue;
        }
        if !status.as_deref().is_some_and(is_failure) {
            push_warning(
                warnings,
                format!("Prowler record at {pointer} had no explicit failing status"),
            );
            continue;
        }
        let rule = nested_string(value, &["metadata", "event_code"])
            .or_else(|| nested_string(value, &["finding_info", "analytic", "uid"]))
            .or_else(|| string_any(object, &["CheckID", "check_id"]))
            .or_else(|| nested_string(value, &["unmapped", "CheckID"]))
            .or_else(|| nested_string(value, &["unmapped", "check_id"]));
        let Some(rule_id) = rule else {
            push_warning(
                warnings,
                format!("Prowler failure at {pointer} lacked a check id"),
            );
            continue;
        };
        let title = nested_string(value, &["finding_info", "title"])
            .or_else(|| string_any(object, &["CheckTitle", "check_title"]))
            .unwrap_or_else(|| format!("Prowler check {rule_id}"));
        let severity_text = string_any(object, &["Severity", "severity"])
            .or_else(|| nested_string(value, &["unmapped", "Severity"]))
            .unwrap_or_else(|| "unknown".into());
        let location = first_resource_location(value)
            .or_else(|| nested_string(value, &["unmapped", "ResourceId"]))
            .unwrap_or_else(|| "cloud-resource".into());
        let mut record = record!(
            pointer,
            rule_id,
            title,
            severity_text,
            location,
            nested_string(value, &["cloud", "account", "uid"])
                .or_else(|| nested_string(value, &["unmapped", "provider_uid"]))
                .or_else(|| nested_string(value, &["unmapped", "AccountId"])),
            Confidence::High,
            EvidenceKind::Configuration,
            references_from(value),
            vec!["format:ocsf".into()],
        );
        record.asset_provider = nested_string(value, &["cloud", "provider"])
            .or_else(|| nested_string(value, &["unmapped", "provider"]));
        records.push(record);
    }
    records
}

fn extract_scoutsuite(parsed: &ParsedArtifact, warnings: &mut Vec<String>) -> Vec<SourceRecord> {
    let mut candidates = Vec::new();
    match parsed {
        ParsedArtifact::Json(root) => {
            if let Some(findings) = root.get("findings") {
                collect_named_objects(findings, "/findings", 0, &mut candidates);
            } else if let Some(services) = root.get("services") {
                collect_named_objects(services, "/services", 0, &mut candidates);
            } else {
                candidates.extend(json_rows(parsed, warnings));
            }
        }
        _ => candidates.extend(json_rows(parsed, warnings)),
    }
    candidates
        .into_iter()
        .filter_map(|(pointer, value)| {
            let object = value.as_object()?;
            let flagged = number_any(object, &["flagged_items", "flaggedItems"])
                .is_some_and(|count| count > 0.0);
            let status = string_any(object, &["status", "result"]);
            if !flagged && !status.as_deref().is_some_and(is_failure) {
                return None;
            }
            let rule_id = string_any(object, &["id", "rule_id", "key"])?;
            let title = string_any(object, &["description", "title", "name"])
                .unwrap_or_else(|| format!("ScoutSuite rule {rule_id}"));
            Some(record!(
                pointer,
                rule_id,
                title,
                string_any(object, &["level", "severity"]).unwrap_or_else(|| "medium".into()),
                string_any(object, &["resource", "path", "service"])
                    .unwrap_or_else(|| "cloud-resource".into()),
                string_any(object, &["account_id", "subscription_id", "project_id"]),
                Confidence::High,
                EvidenceKind::Configuration,
                references_from(value),
                vec![],
            ))
        })
        .take(MAX_RECORDS)
        .collect()
}

fn extract_cloudsplaining(
    parsed: &ParsedArtifact,
    warnings: &mut Vec<String>,
) -> Vec<SourceRecord> {
    let mut records = Vec::new();
    for (pointer, value) in json_rows(parsed, warnings) {
        let Some(root) = value.as_object() else {
            continue;
        };
        if let Some(findings) = root.get("findings").and_then(Value::as_array) {
            for (index, finding) in findings.iter().take(MAX_RECORDS).enumerate() {
                if let Some(record) = cloudsplaining_record(
                    finding,
                    format!("{pointer}findings/{index}"),
                    "unspecified-risk",
                ) {
                    records.push(record);
                }
            }
            continue;
        }
        for (risk, entries) in root {
            if !is_cloudsplaining_risk(risk) {
                continue;
            }
            if let Some(values) = entries.as_array() {
                for (index, finding) in values.iter().take(MAX_RECORDS - records.len()).enumerate()
                {
                    if let Some(record) =
                        cloudsplaining_record(finding, format!("{pointer}{risk}/{index}"), risk)
                    {
                        records.push(record);
                    }
                }
            }
        }
    }
    records
}

fn cloudsplaining_record(value: &Value, pointer: String, risk: &str) -> Option<SourceRecord> {
    let object = value.as_object()?;
    let identity = string_any(object, &["arn", "principal", "name", "resource"])?;
    let rule_id = string_any(object, &["finding_id", "rule_id"])
        .unwrap_or_else(|| format!("cloudsplaining:{risk}"));
    Some(record!(
        pointer,
        rule_id,
        format!("IAM privilege risk: {}", humanize_identifier(risk)),
        if risk.contains("admin") || risk.contains("privilege_escalation") {
            "high".into()
        } else {
            "medium".into()
        },
        identity,
        string_any(object, &["account_id", "asset_id"]),
        Confidence::High,
        EvidenceKind::Configuration,
        references_from(value),
        vec![format!("risk:{}", safe_tag(risk))],
    ))
}

fn extract_scubagear(parsed: &ParsedArtifact, warnings: &mut Vec<String>) -> Vec<SourceRecord> {
    extract_m365(
        parsed,
        warnings,
        "ScubaGear",
        &["PolicyId", "ControlId", "id"],
        &["Result", "status"],
    )
}

fn extract_maester(parsed: &ParsedArtifact, warnings: &mut Vec<String>) -> Vec<SourceRecord> {
    extract_m365(
        parsed,
        warnings,
        "Maester",
        &["Id", "TestId", "id"],
        &["Result", "Outcome", "status"],
    )
}

fn extract_m365(
    parsed: &ParsedArtifact,
    warnings: &mut Vec<String>,
    engine: &str,
    rule_keys: &[&str],
    status_keys: &[&str],
) -> Vec<SourceRecord> {
    let mut candidates = Vec::new();
    match parsed {
        ParsedArtifact::Json(root) => collect_named_objects(root, "/", 0, &mut candidates),
        _ => candidates.extend(json_rows(parsed, warnings)),
    }
    let mut seen = BTreeSet::new();
    let mut records = Vec::new();
    for (pointer, value) in candidates {
        let Some(object) = value.as_object() else {
            continue;
        };
        let Some(status) = string_any(object, status_keys) else {
            continue;
        };
        if !is_failure(&status) {
            continue;
        }
        let Some(rule_id) = string_any(object, rule_keys) else {
            push_warning(
                warnings,
                format!("{engine} failed result at {pointer} lacked a rule id"),
            );
            continue;
        };
        let dedup = format!("{rule_id}:{pointer}");
        if !seen.insert(dedup) {
            continue;
        }
        records.push(record!(
            pointer,
            rule_id.clone(),
            string_any(object, &["Name", "Title", "Requirement", "Description"])
                .unwrap_or_else(|| format!("{engine} control {rule_id}")),
            string_any(object, &["Severity", "severity"]).unwrap_or_else(|| "medium".into()),
            string_any(object, &["Service", "Product", "Resource", "TenantId"])
                .unwrap_or_else(|| "microsoft-365-tenant".into()),
            string_any(object, &["asset_id", "AssetId"]),
            Confidence::High,
            EvidenceKind::Configuration,
            references_from(value),
            vec![],
        ));
        if records.len() >= MAX_RECORDS {
            break;
        }
    }
    records
}

fn extract_naabu(parsed: &ParsedArtifact, warnings: &mut Vec<String>) -> Vec<SourceRecord> {
    json_rows(parsed, warnings)
        .into_iter()
        .filter_map(|(pointer, value)| {
            let object = value.as_object()?;
            let host = string_any(object, &["host", "ip"])?;
            let port = scalar_string(object.get("port")?)?;
            let protocol = string_any(object, &["protocol"]).unwrap_or_else(|| "tcp".into());
            Some(record!(
                pointer,
                format!("open-{protocol}-port"),
                "Externally reachable network service".into(),
                "informational".into(),
                format!("{}:{port}", redact_location(&host)),
                string_any(object, &["asset_id"]),
                Confidence::High,
                EvidenceKind::ExternalValidation,
                vec![],
                vec![
                    format!("port:{}", safe_tag(&port)),
                    format!("protocol:{}", safe_tag(&protocol)),
                ],
            ))
        })
        .collect()
}

fn extract_httpx(parsed: &ParsedArtifact, warnings: &mut Vec<String>) -> Vec<SourceRecord> {
    json_rows(parsed, warnings)
        .into_iter()
        .filter_map(|(pointer, value)| {
            let object = value.as_object()?;
            let target = string_any(object, &["url", "input", "host"])?;
            let status = scalar_string(
                object
                    .get("status_code")
                    .or_else(|| object.get("status-code"))?,
            )?;
            Some(record!(
                pointer,
                "http-service-observed".into(),
                "Externally reachable HTTP service".into(),
                "informational".into(),
                redact_location(&target),
                string_any(object, &["asset_id"]),
                Confidence::High,
                EvidenceKind::ExternalValidation,
                vec![],
                vec![format!("http-status:{}", safe_tag(&status))],
            ))
        })
        .collect()
}

fn extract_nuclei(parsed: &ParsedArtifact, warnings: &mut Vec<String>) -> Vec<SourceRecord> {
    json_rows(parsed, warnings)
        .into_iter()
        .filter_map(|(pointer, value)| {
            let object = value.as_object()?;
            let rule_id = string_any(object, &["template-id", "template_id", "templateID"])?;
            let title = nested_string(value, &["info", "name"])
                .unwrap_or_else(|| format!("Nuclei template {rule_id}"));
            let severity = nested_string(value, &["info", "severity"])
                .or_else(|| string_any(object, &["severity"]))
                .unwrap_or_else(|| "unknown".into());
            let target = string_any(object, &["matched-at", "matched_at", "host", "url"])
                .unwrap_or_else(|| "authorized-target".into());
            let mut tags = nested_strings(value, &["info", "tags"])
                .into_iter()
                .map(|tag| format!("template-tag:{}", safe_tag(&tag)))
                .collect::<Vec<_>>();
            if let Some(matcher) = string_any(object, &["matcher-name", "matcher_name"]) {
                tags.push(format!("matcher:{}", safe_tag(&matcher)));
            }
            Some(record!(
                pointer,
                rule_id,
                title,
                severity,
                redact_location(&target),
                string_any(object, &["asset_id"]),
                Confidence::High,
                EvidenceKind::ExternalValidation,
                references_from(value),
                tags,
            ))
        })
        .collect()
}

fn extract_greenbone(parsed: &ParsedArtifact, warnings: &mut Vec<String>) -> Vec<SourceRecord> {
    let ParsedArtifact::Xml(results) = parsed else {
        push_warning(warnings, "Greenbone expected a bounded XML report");
        return Vec::new();
    };

    let mut records = Vec::new();
    for result in results.iter().take(MAX_RECORDS) {
        let numeric_severity = result
            .severity
            .as_deref()
            .and_then(|value| value.parse::<f64>().ok());
        let threat = result.threat.as_deref().unwrap_or("unknown");
        if numeric_severity.is_some_and(|severity| severity <= 0.0)
            || matches!(
                threat.trim().to_ascii_lowercase().as_str(),
                "log" | "false positive"
            )
        {
            continue;
        }
        let source_severity = result
            .severity
            .clone()
            .filter(|_| numeric_severity.is_some_and(|severity| severity > 0.0))
            .or_else(|| result.threat.clone())
            .unwrap_or_else(|| "unknown".into());

        let Some(rule_id) = result
            .nvt_oid
            .clone()
            .or_else(|| result.cves.first().cloned())
        else {
            push_warning(
                warnings,
                format!(
                    "Greenbone result {} lacked a valid NVT OID or CVE and was not normalized",
                    safe_text(result.result_id.as_deref().unwrap_or(&result.pointer), 120)
                ),
            );
            continue;
        };

        let host = result.host.as_deref().unwrap_or("authorized-target");
        let location = result
            .port
            .as_deref()
            .filter(|port| !port.trim().is_empty())
            .map(|port| format!("{host}:{port}"))
            .unwrap_or_else(|| host.to_owned());
        let qod = result
            .qod
            .as_deref()
            .and_then(|value| value.parse::<u8>().ok())
            .filter(|value| *value <= 100);
        let confidence = match qod {
            Some(80..=100) => Confidence::High,
            Some(50..=79) => Confidence::Medium,
            Some(_) => Confidence::Low,
            None => Confidence::Medium,
        };
        let mut references = result
            .cves
            .iter()
            .map(|cve| format!("https://nvd.nist.gov/vuln/detail/{cve}"))
            .collect::<Vec<_>>();
        references.sort();
        references.dedup();
        references.truncate(12);
        let mut tags = result
            .cves
            .iter()
            .take(16)
            .map(|cve| format!("cve:{}", safe_tag(cve)))
            .collect::<Vec<_>>();
        if let Some(family) = &result.family {
            tags.push(format!("nvt-family:{}", safe_tag(family)));
        }
        if let Some(qod) = qod {
            tags.push(format!("quality-of-detection:{qod}"));
        }

        records.push(record!(
            result.pointer.clone(),
            rule_id.clone(),
            result
                .nvt_name
                .clone()
                .or_else(|| result.result_name.clone())
                .unwrap_or_else(|| format!("Greenbone NVT {rule_id}")),
            source_severity,
            location,
            result.asset_id.clone(),
            confidence,
            EvidenceKind::ExternalValidation,
            references,
            tags,
        ));
    }
    records
}

fn extract_semgrep(parsed: &ParsedArtifact, warnings: &mut Vec<String>) -> Vec<SourceRecord> {
    let Some(root) = json_root(parsed) else {
        push_warning(warnings, "Semgrep expected a JSON document");
        return Vec::new();
    };
    let Some(results) = root.get("results").and_then(Value::as_array) else {
        push_warning(warnings, "Semgrep output had no results array");
        return Vec::new();
    };
    results
        .iter()
        .take(MAX_RECORDS)
        .enumerate()
        .filter_map(|(index, value)| {
            let object = value.as_object()?;
            let rule_id = string_any(object, &["check_id"])?;
            let path = string_any(object, &["path"]).unwrap_or_else(|| "source-file".into());
            let line = nested_string(value, &["start", "line"]);
            let pointer = format!("/results/{index}");
            Some(record!(
                pointer,
                rule_id.clone(),
                nested_string(value, &["extra", "metadata", "shortlink"])
                    .map(|_| format!("Semgrep rule {rule_id}"))
                    .unwrap_or_else(|| format!("Semgrep rule {rule_id}")),
                nested_string(value, &["extra", "severity"]).unwrap_or_else(|| "warning".into()),
                path,
                string_any(object, &["asset_id"]),
                Confidence::High,
                EvidenceKind::SourceCode,
                references_from(value),
                line.map(|line| vec![format!("source-line:{}", safe_tag(&line))])
                    .unwrap_or_default(),
            ))
        })
        .collect()
}

fn extract_gitleaks(parsed: &ParsedArtifact, warnings: &mut Vec<String>) -> Vec<SourceRecord> {
    json_rows(parsed, warnings)
        .into_iter()
        .filter_map(|(pointer, value)| {
            let object = value.as_object()?;
            let rule_id = string_any(object, &["RuleID", "rule_id"])?;
            let location = gitleaks_location(object);
            Some(record!(
                pointer,
                rule_id.clone(),
                string_any(object, &["Description", "description"])
                    .unwrap_or_else(|| format!("Potential secret detected by {rule_id}")),
                "high".into(),
                location,
                string_any(object, &["asset_id"]),
                Confidence::High,
                EvidenceKind::SourceCode,
                vec![],
                vec!["secret-value:redacted".into()],
            ))
        })
        .collect()
}

fn gitleaks_location(object: &Map<String, Value>) -> String {
    // Gitleaks' Secret and Match fields must never participate in a durable
    // identity. File coordinates and a validated Git object ID distinguish
    // multiple observations without retaining the detected value.
    let file = string_any(object, &["File", "file"])
        .map(|value| redact_location(&value))
        .filter(|value| !value.is_empty())
        .unwrap_or_else(|| "repository".into());
    let mut location = safe_text(&file, 360);

    if let Some(line) = positive_u32_any(object, &["StartLine", "start_line"]) {
        location.push_str(&format!(":line={line}"));
    }
    if let Some(column) = positive_u32_any(object, &["StartColumn", "start_column"]) {
        location.push_str(&format!(":column={column}"));
    }
    if let Some(commit) =
        string_any(object, &["Commit", "commit"]).and_then(|value| normalized_git_object_id(&value))
    {
        location.push_str(":commit=");
        location.push_str(&commit);
    }

    location
}

fn positive_u32_any(object: &Map<String, Value>, keys: &[&str]) -> Option<u32> {
    keys.iter().find_map(|key| {
        let value = object.get(*key)?;
        let parsed = match value {
            Value::Number(number) => number.as_u64()?,
            Value::String(value) => value.parse::<u64>().ok()?,
            _ => return None,
        };
        u32::try_from(parsed).ok().filter(|value| *value > 0)
    })
}

fn normalized_git_object_id(value: &str) -> Option<String> {
    let value = value.trim();
    if !matches!(value.len(), 40 | 64)
        || !value.bytes().all(|character| character.is_ascii_hexdigit())
    {
        return None;
    }
    Some(value.to_ascii_lowercase())
}

fn extract_trufflehog(parsed: &ParsedArtifact, warnings: &mut Vec<String>) -> Vec<SourceRecord> {
    json_rows(parsed, warnings)
        .into_iter()
        .filter_map(|(pointer, value)| {
            let object = value.as_object()?;
            let detector = string_any(object, &["DetectorName", "DetectorType"])?;
            let verified = object
                .get("Verified")
                .and_then(Value::as_bool)
                .unwrap_or(false);
            let source = nested_string(value, &["SourceMetadata", "Data", "Filesystem", "file"])
                .or_else(|| nested_string(value, &["SourceMetadata", "Data", "Git", "file"]))
                .unwrap_or_else(|| "repository".into());
            Some(record!(
                pointer,
                format!("trufflehog:{detector}"),
                format!("Potential {detector} secret detected"),
                if verified {
                    "critical".into()
                } else {
                    "high".into()
                },
                source,
                string_any(object, &["asset_id"]),
                if verified {
                    Confidence::Confirmed
                } else {
                    Confidence::High
                },
                EvidenceKind::SourceCode,
                vec![],
                vec![
                    format!("verified:{verified}"),
                    "secret-value:redacted".into(),
                ],
            ))
        })
        .collect()
}

fn extract_checkov(parsed: &ParsedArtifact, warnings: &mut Vec<String>) -> Vec<SourceRecord> {
    let Some(root) = json_root(parsed) else {
        push_warning(warnings, "Checkov expected a JSON document");
        return Vec::new();
    };
    let Some(failed) = root
        .pointer("/results/failed_checks")
        .and_then(Value::as_array)
    else {
        return Vec::new();
    };
    failed
        .iter()
        .take(MAX_RECORDS)
        .enumerate()
        .filter_map(|(index, value)| {
            let object = value.as_object()?;
            let rule_id = string_any(object, &["check_id"])?;
            Some(record!(
                format!("/results/failed_checks/{index}"),
                rule_id.clone(),
                string_any(object, &["check_name"])
                    .unwrap_or_else(|| format!("Checkov check {rule_id}")),
                string_any(object, &["severity"]).unwrap_or_else(|| "medium".into()),
                string_any(object, &["file_path", "repo_file_path"])
                    .unwrap_or_else(|| "iac-resource".into()),
                string_any(object, &["asset_id"]),
                Confidence::High,
                EvidenceKind::Configuration,
                references_from(value),
                vec![],
            ))
        })
        .collect()
}

fn extract_kics(parsed: &ParsedArtifact, warnings: &mut Vec<String>) -> Vec<SourceRecord> {
    let Some(root) = json_root(parsed) else {
        push_warning(warnings, "KICS expected a JSON document");
        return Vec::new();
    };
    let Some(queries) = root.get("queries").and_then(Value::as_array) else {
        return Vec::new();
    };
    let mut records = Vec::new();
    for (query_index, query) in queries.iter().enumerate() {
        let Some(query_object) = query.as_object() else {
            continue;
        };
        let Some(rule_id) = string_any(query_object, &["query_id"]) else {
            continue;
        };
        let title = string_any(query_object, &["query_name"])
            .unwrap_or_else(|| format!("KICS query {rule_id}"));
        let severity = string_any(query_object, &["severity"]).unwrap_or_else(|| "medium".into());
        let Some(files) = query_object.get("files").and_then(Value::as_array) else {
            continue;
        };
        for (file_index, file) in files.iter().enumerate() {
            let Some(file_object) = file.as_object() else {
                continue;
            };
            records.push(record!(
                format!("/queries/{query_index}/files/{file_index}"),
                rule_id.clone(),
                title.clone(),
                severity.clone(),
                string_any(file_object, &["file_name"]).unwrap_or_else(|| "iac-resource".into()),
                string_any(file_object, &["asset_id"]),
                Confidence::High,
                EvidenceKind::Configuration,
                references_from(query),
                vec![],
            ));
            if records.len() >= MAX_RECORDS {
                return records;
            }
        }
    }
    records
}

fn extract_trivy(parsed: &ParsedArtifact, warnings: &mut Vec<String>) -> Vec<SourceRecord> {
    let Some(root) = json_root(parsed) else {
        push_warning(warnings, "Trivy expected a JSON document");
        return Vec::new();
    };
    let Some(results) = root
        .get("Results")
        .or_else(|| root.get("results"))
        .and_then(Value::as_array)
    else {
        return Vec::new();
    };
    let mut records = Vec::new();
    for (result_index, result) in results.iter().enumerate() {
        let Some(result_object) = result.as_object() else {
            continue;
        };
        let target = string_any(result_object, &["Target", "target"])
            .unwrap_or_else(|| "container-image".into());
        for (field, prefix, kind) in [
            (
                "Vulnerabilities",
                "vulnerability",
                EvidenceKind::PackageInventory,
            ),
            (
                "Misconfigurations",
                "misconfiguration",
                EvidenceKind::Configuration,
            ),
            ("Secrets", "secret", EvidenceKind::SourceCode),
        ] {
            let Some(items) = result_object.get(field).and_then(Value::as_array) else {
                continue;
            };
            for (item_index, item) in items.iter().enumerate() {
                let Some(object) = item.as_object() else {
                    continue;
                };
                let Some(rule_id) = string_any(object, &["VulnerabilityID", "ID", "RuleID"]) else {
                    continue;
                };
                let title = string_any(object, &["Title", "Message"])
                    .unwrap_or_else(|| format!("Trivy {prefix} {rule_id}"));
                let mut tags = Vec::new();
                if let Some(package) = string_any(object, &["PkgName"]) {
                    tags.push(format!("package:{}", safe_tag(&package)));
                }
                if field == "Secrets" {
                    tags.push("secret-value:redacted".into());
                }
                records.push(record!(
                    format!("/Results/{result_index}/{field}/{item_index}"),
                    rule_id,
                    title,
                    string_any(object, &["Severity"]).unwrap_or_else(|| "unknown".into()),
                    target.clone(),
                    string_any(object, &["asset_id"]),
                    Confidence::High,
                    kind.clone(),
                    references_from(item),
                    tags,
                ));
                if records.len() >= MAX_RECORDS {
                    return records;
                }
            }
        }
    }
    records
}

fn extract_grype(parsed: &ParsedArtifact, warnings: &mut Vec<String>) -> Vec<SourceRecord> {
    let Some(root) = json_root(parsed) else {
        push_warning(warnings, "Grype expected a JSON document");
        return Vec::new();
    };
    let Some(matches) = root.get("matches").and_then(Value::as_array) else {
        return Vec::new();
    };
    matches
        .iter()
        .take(MAX_RECORDS)
        .enumerate()
        .filter_map(|(index, value)| {
            let rule_id = nested_string(value, &["vulnerability", "id"])?;
            let package =
                nested_string(value, &["artifact", "name"]).unwrap_or_else(|| "package".into());
            let location = nested_string(value, &["artifact", "locations", "0", "path"])
                .unwrap_or_else(|| package.clone());
            Some(record!(
                format!("/matches/{index}"),
                rule_id.clone(),
                format!("Vulnerable package {package} ({rule_id})"),
                nested_string(value, &["vulnerability", "severity"])
                    .unwrap_or_else(|| "unknown".into()),
                location,
                value
                    .as_object()
                    .and_then(|object| string_any(object, &["asset_id"])),
                Confidence::High,
                EvidenceKind::PackageInventory,
                references_from(value),
                vec![format!("package:{}", safe_tag(&package))],
            ))
        })
        .collect()
}

fn extract_kubescape(parsed: &ParsedArtifact, warnings: &mut Vec<String>) -> Vec<SourceRecord> {
    let mut candidates = Vec::new();
    match parsed {
        ParsedArtifact::Json(root) => collect_named_objects(root, "/", 0, &mut candidates),
        _ => candidates.extend(json_rows(parsed, warnings)),
    }
    let mut records = Vec::new();
    for (pointer, value) in candidates {
        let Some(object) = value.as_object() else {
            continue;
        };
        let status = string_any(object, &["status", "Status", "result"]);
        if !status.as_deref().is_some_and(is_failure) {
            continue;
        }
        let Some(rule_id) = string_any(object, &["controlID", "control_id", "id", "rule_id"])
        else {
            continue;
        };
        records.push(record!(
            pointer,
            rule_id.clone(),
            string_any(object, &["name", "title", "controlName"])
                .unwrap_or_else(|| format!("Kubescape control {rule_id}")),
            string_any(object, &["severity", "baseScore"]).unwrap_or_else(|| "medium".into()),
            string_any(object, &["resourceID", "resource", "object", "name"])
                .unwrap_or_else(|| "kubernetes-resource".into()),
            string_any(object, &["asset_id"]),
            Confidence::High,
            EvidenceKind::Configuration,
            references_from(value),
            vec![],
        ));
        if records.len() >= MAX_RECORDS {
            break;
        }
    }
    records
}

fn extract_kube_bench(parsed: &ParsedArtifact, warnings: &mut Vec<String>) -> Vec<SourceRecord> {
    let Some(root) = json_root(parsed) else {
        push_warning(warnings, "kube-bench expected a JSON document");
        return Vec::new();
    };
    let controls = root
        .get("Controls")
        .or_else(|| root.get("controls"))
        .and_then(Value::as_array);
    let Some(controls) = controls else {
        return Vec::new();
    };
    let mut records = Vec::new();
    for (control_index, control) in controls.iter().enumerate() {
        let tests = control
            .get("tests")
            .and_then(Value::as_array)
            .into_iter()
            .flatten();
        for (test_index, test) in tests.enumerate() {
            let results = test
                .get("results")
                .and_then(Value::as_array)
                .into_iter()
                .flatten();
            for (result_index, value) in results.enumerate() {
                let Some(object) = value.as_object() else {
                    continue;
                };
                let status = string_any(object, &["status"]).unwrap_or_default();
                if !is_failure(&status) {
                    continue;
                }
                let Some(rule_id) = string_any(object, &["test_number", "id"]) else {
                    continue;
                };
                records.push(record!(
                    format!("/Controls/{control_index}/tests/{test_index}/results/{result_index}"),
                    rule_id.clone(),
                    string_any(object, &["test_desc", "desc"])
                        .unwrap_or_else(|| format!("kube-bench control {rule_id}")),
                    string_any(object, &["severity"]).unwrap_or_else(|| "medium".into()),
                    string_any(object, &["resource", "node_type"])
                        .unwrap_or_else(|| "kubernetes-cluster".into()),
                    string_any(object, &["asset_id"]),
                    Confidence::High,
                    EvidenceKind::Configuration,
                    references_from(value),
                    vec![],
                ));
                if records.len() >= MAX_RECORDS {
                    return records;
                }
            }
        }
    }
    records
}

fn extract_steampipe(parsed: &ParsedArtifact, warnings: &mut Vec<String>) -> Vec<SourceRecord> {
    let mut records = Vec::new();
    for (pointer, value) in json_rows(parsed, warnings) {
        let rows = value.get("rows").and_then(Value::as_array);
        let owned;
        let values: &[Value] = if let Some(rows) = rows {
            rows
        } else {
            owned = vec![value.clone()];
            &owned
        };
        for (index, row) in values.iter().enumerate() {
            let Some(object) = row.as_object() else {
                continue;
            };
            let Some(status) = string_any(object, &["status", "result", "state"]) else {
                continue;
            };
            if !is_failure(&status) {
                continue;
            }
            let Some(rule_id) = string_any(object, &["control_id", "reason", "id"]) else {
                continue;
            };
            records.push(record!(
                format!("{pointer}rows/{index}"),
                rule_id.clone(),
                string_any(object, &["title", "reason"])
                    .unwrap_or_else(|| format!("Steampipe control {rule_id}")),
                string_any(object, &["severity"]).unwrap_or_else(|| "medium".into()),
                string_any(object, &["resource", "resource_id", "title"])
                    .unwrap_or_else(|| "cloud-resource".into()),
                string_any(object, &["asset_id"]),
                Confidence::High,
                EvidenceKind::Configuration,
                references_from(row),
                vec![],
            ));
        }
    }
    records
}

fn merge_finding(
    findings: &mut BTreeMap<String, Finding>,
    adapter: &BuiltinAdapter,
    input: &AdapterInput<'_>,
    artifact: &RawArtifact,
    record: SourceRecord,
    asset_id: String,
) {
    let rule_id = safe_text(&record.rule_id, MAX_SHORT_TEXT);
    let location = redact_location(&record.location);
    let fingerprint = stable_fingerprint(adapter.id, &rule_id, &asset_id, &location);
    let finding_id = format!(
        "finding-{}",
        &fingerprint.rsplit(':').next().unwrap_or(&fingerprint)[..32]
    );
    let evidence_id = stable_evidence_id(
        &fingerprint,
        &artifact.sha256,
        &record.pointer,
        input.engine_run_id,
    );
    let evidence = Evidence {
        id: evidence_id,
        finding_id: finding_id.clone(),
        run_id: input.scan_run_id.to_owned(),
        engine_run_id: Some(input.engine_run_id.to_owned()),
        kind: record.evidence_kind,
        engine_id: adapter.id.to_owned(),
        observed_at: artifact.created_at,
        summary: format!(
            "{} reported rule {} at {}. Raw target text is retained only as untrusted evidence.",
            adapter.id,
            rule_id,
            safe_text(&location, MAX_SHORT_TEXT)
        ),
        artifact_id: artifact.id.clone(),
        artifact_sha256: artifact.sha256.clone(),
        pointer: Some(safe_text(&record.pointer, MAX_SHORT_TEXT)),
        redacted: matches!(adapter.profile, Profile::Gitleaks | Profile::Trufflehog),
    };

    if let Some(existing) = findings.get_mut(&fingerprint) {
        if !existing.evidence.iter().any(|item| item.id == evidence.id) {
            existing.evidence.push(evidence);
        }
        return;
    }

    let mut official_references = vec![input.manifest.repository_url.clone()];
    if let Some(homepage) = &input.manifest.homepage_url {
        official_references.push(homepage.clone());
    }
    official_references.extend(
        record
            .references
            .into_iter()
            .filter_map(safe_https_reference),
    );
    official_references.sort();
    official_references.dedup();
    official_references.truncate(12);

    let severity = record.severity;
    let priority = priority_for(&severity);
    let mut tags = vec![
        format!("engine:{}", adapter.id),
        format!("source-rule:{}", safe_tag(&rule_id)),
        format!("source-severity:{}", safe_tag(&record.source_severity)),
    ];
    tags.extend(
        record
            .tags
            .into_iter()
            .map(|tag| safe_text(&tag, MAX_SHORT_TEXT)),
    );
    tags.sort();
    tags.dedup();
    tags.truncate(32);

    let title = safe_text(&record.title, MAX_SHORT_TEXT);
    let impact = impact_for(adapter.profile, &severity);
    findings.insert(
        fingerprint.clone(),
        Finding {
            id: finding_id,
            case_id: input.case_id.to_owned(),
            first_seen_run_id: input.scan_run_id.to_owned(),
            last_seen_run_id: input.scan_run_id.to_owned(),
            fingerprint,
            title,
            plain_language_summary: format!(
                "{} reported a {}-severity condition on the assessed asset. The attached raw record is evidence, not an instruction.",
                input.manifest.display_name,
                severity_label(&severity)
            ),
            possible_impact: impact,
            severity,
            confidence: record.confidence,
            priority,
            priority_reasons: vec![
                format!("Source severity: {}", safe_text(&record.source_severity, 80)),
                "Direct scanner evidence is attached and still requires human review.".into(),
            ],
            asset_ids: vec![asset_id],
            evidence: vec![evidence],
            control_references: control_mapping::lookup(
                adapter.id,
                &rule_id,
                input.ai_system_applicable,
            ),
            recommendation: format!(
                "Have a {} review the affected asset and the source rule's official guidance, then plan and approve a least-privilege configuration or code change.",
                adapter.expert_type
            ),
            verification_guidance: format!(
                "After an approved manual change, rerun {} with the same authorized scope and confirm that source rule {} is no longer reported.",
                input.manifest.display_name, rule_id
            ),
            rollback_considerations: Some(
                "Before any manual change, preserve the current approved configuration and document a tested restoration path; this product does not execute remediation."
                    .into(),
            ),
            official_references,
            recommended_expert_type: adapter.expert_type.into(),
            status: FindingStatus::Unreviewed,
            tags,
        },
    );
}

fn record_from_draft(draft: RecordDraft) -> SourceRecord {
    SourceRecord {
        pointer: safe_text(&draft.pointer, MAX_SHORT_TEXT),
        rule_id: safe_text(&draft.rule_id, MAX_SHORT_TEXT),
        title: safe_text(&draft.title, MAX_SHORT_TEXT),
        severity: parse_severity(&draft.source_severity),
        source_severity: safe_text(&draft.source_severity, 80),
        location: redact_location(&draft.location),
        asset_hint: draft
            .asset_hint
            .map(|value| safe_text(&value, MAX_SHORT_TEXT)),
        asset_provider: None,
        confidence: draft.confidence,
        evidence_kind: draft.evidence_kind,
        references: draft.references,
        tags: draft.tags,
    }
}

fn resolve_asset(
    record: &SourceRecord,
    allowed_assets: &[String],
    asset_identifier_map: &crate::adapter::AdapterAssetIdentifierMap,
    warnings: &mut Vec<String>,
) -> Option<String> {
    if let Some(hint) = &record.asset_hint {
        if record.asset_provider.is_none() && allowed_assets.iter().any(|asset| asset == hint) {
            return Some(hint.clone());
        }

        if let Some(candidates) =
            asset_identifier_map.candidates(record.asset_provider.as_deref(), hint)
        {
            let authorized = candidates
                .iter()
                .filter(|candidate| allowed_assets.iter().any(|asset| asset == *candidate))
                .collect::<Vec<_>>();
            if authorized.len() == 1 {
                return authorized.first().map(|asset| (*asset).clone());
            }
            if authorized.len() > 1 {
                push_warning(
                    warnings,
                    format!(
                        "record {} matched an ambiguous native asset identifier and was not normalized",
                        safe_text(&record.rule_id, 120)
                    ),
                );
                return None;
            }
        }

        // A provider-qualified OCSF account is authoritative. Falling back to
        // the only selected asset would silently misattribute a provider or
        // account mismatch.
        if record.asset_provider.is_some() {
            push_warning(
                warnings,
                format!(
                    "record {} had no exact authorized provider identifier match and was not normalized",
                    safe_text(&record.rule_id, 120)
                ),
            );
            return None;
        }
    }
    if allowed_assets.len() == 1 {
        return allowed_assets.first().cloned();
    }
    push_warning(
        warnings,
        format!(
            "record {} could not be mapped unambiguously to an authorized asset and was not normalized",
            safe_text(&record.rule_id, 120)
        ),
    );
    None
}

fn stable_fingerprint(engine: &str, rule: &str, asset: &str, location: &str) -> String {
    let mut hasher = Sha256::new();
    for component in [FINGERPRINT_SCHEMA_VERSION, engine, rule, asset, location] {
        hasher.update(component.as_bytes());
        hasher.update([0]);
    }
    format!("{engine}:{}", hex::encode(hasher.finalize()))
}

fn stable_evidence_id(
    fingerprint: &str,
    artifact_hash: &str,
    pointer: &str,
    engine_run_id: &str,
) -> String {
    let mut hasher = Sha256::new();
    for component in [fingerprint, artifact_hash, pointer, engine_run_id] {
        hasher.update(component.as_bytes());
        hasher.update([0]);
    }
    format!("evidence-{}", &hex::encode(hasher.finalize())[..32])
}

fn parse_severity(value: &str) -> Severity {
    let normalized = value.trim().to_ascii_lowercase();
    if let Ok(score) = normalized.parse::<f64>() {
        return if score >= 9.0 {
            Severity::Critical
        } else if score >= 7.0 {
            Severity::High
        } else if score >= 4.0 {
            Severity::Medium
        } else if score > 0.0 {
            Severity::Low
        } else {
            Severity::Informational
        };
    }
    match normalized.as_str() {
        "critical" | "fatal" => Severity::Critical,
        "high" | "error" => Severity::High,
        "medium" | "moderate" | "warning" | "warn" => Severity::Medium,
        "low" | "minor" => Severity::Low,
        _ => Severity::Informational,
    }
}

fn priority_for(severity: &Severity) -> u8 {
    match severity {
        Severity::Critical => 95,
        Severity::High => 80,
        Severity::Medium => 60,
        Severity::Low => 35,
        Severity::Informational => 15,
    }
}

fn severity_label(severity: &Severity) -> &'static str {
    match severity {
        Severity::Critical => "critical",
        Severity::High => "high",
        Severity::Medium => "medium",
        Severity::Low => "low",
        Severity::Informational => "informational",
    }
}

fn impact_for(profile: Profile, severity: &Severity) -> String {
    let consequence = match profile {
        Profile::CloudQuery | Profile::Steampipe | Profile::Prowler | Profile::ScoutSuite => {
            "cloud resources or data may be exposed, changed, or used beyond the organization's intent"
        }
        Profile::Cloudsplaining => {
            "an identity may be able to perform broader actions than its role requires"
        }
        Profile::ScubaGear | Profile::Maester => {
            "Microsoft 365 identities, messages, files, or administrative settings may have weaker protection"
        }
        Profile::Naabu | Profile::Httpx | Profile::Nuclei | Profile::Greenbone => {
            "an internet-reachable service may expose unexpected functionality or a known weakness"
        }
        Profile::Semgrep | Profile::Gitleaks | Profile::Trufflehog => {
            "source code or credentials may permit unauthorized access or unsafe application behavior"
        }
        Profile::Checkov | Profile::Kics => {
            "deployed infrastructure may inherit the reported insecure configuration"
        }
        Profile::Trivy | Profile::Grype | Profile::Syft => {
            "a container or software component may expose the workload to a known weakness"
        }
        Profile::Kubescape | Profile::KubeBench => {
            "the Kubernetes cluster or workload may have reduced isolation or administrative protection"
        }
    };
    format!(
        "If the scanner result is confirmed, {consequence}. The {} source severity is not a product-wide compliance score.",
        severity_label(severity)
    )
}

fn is_failure(value: &str) -> bool {
    matches!(
        value.trim().to_ascii_lowercase().as_str(),
        "fail"
            | "failed"
            | "failure"
            | "error"
            | "alarm"
            | "danger"
            | "noncompliant"
            | "non-compliant"
            | "notpassed"
            | "not_passed"
            | "false"
    )
}

fn is_pass(value: &str) -> bool {
    matches!(
        value.trim().to_ascii_lowercase().as_str(),
        "pass" | "passed" | "ok" | "compliant" | "true"
    )
}

fn is_cloudsplaining_risk(value: &str) -> bool {
    let value = value.to_ascii_lowercase();
    value.contains("privilege")
        || value.contains("admin")
        || value.contains("resource_exposure")
        || value.contains("data_exfiltration")
        || value.contains("credentials_exposure")
}

fn json_root(parsed: &ParsedArtifact) -> Option<&Value> {
    match parsed {
        ParsedArtifact::Json(value) => Some(value),
        _ => None,
    }
}

fn nested_string(value: &Value, path: &[&str]) -> Option<String> {
    let mut current = value;
    for segment in path {
        current = if let Ok(index) = segment.parse::<usize>() {
            current.as_array()?.get(index)?
        } else {
            current.get(*segment)?
        };
    }
    scalar_string(current)
}

fn nested_strings(value: &Value, path: &[&str]) -> Vec<String> {
    let mut current = value;
    for segment in path {
        let Some(next) = current.get(*segment) else {
            return Vec::new();
        };
        current = next;
    }
    match current {
        Value::Array(values) => values.iter().filter_map(scalar_string).take(32).collect(),
        Value::String(value) => value
            .split(',')
            .map(|part| safe_text(part, 80))
            .filter(|part| !part.is_empty())
            .take(32)
            .collect(),
        _ => Vec::new(),
    }
}

fn scalar_string(value: &Value) -> Option<String> {
    match value {
        Value::String(value) => Some(safe_text(value, MAX_LONG_TEXT)),
        Value::Number(value) => Some(value.to_string()),
        Value::Bool(value) => Some(value.to_string()),
        _ => None,
    }
}

fn string_any(object: &Map<String, Value>, keys: &[&str]) -> Option<String> {
    keys.iter()
        .find_map(|key| object.get(*key).and_then(scalar_string))
}

fn number_any(object: &Map<String, Value>, keys: &[&str]) -> Option<f64> {
    keys.iter()
        .find_map(|key| object.get(*key).and_then(Value::as_f64))
}

fn first_resource_location(value: &Value) -> Option<String> {
    let resource = value.get("resources")?.as_array()?.first()?;
    ["uid", "name", "cloud_partition", "type"]
        .iter()
        .find_map(|key| resource.get(*key).and_then(scalar_string))
}

fn references_from(value: &Value) -> Vec<String> {
    const POINTERS: &[&str] = &[
        "/reference",
        "/references",
        "/Reference",
        "/PrimaryURL",
        "/primary_url",
        "/guideline",
        "/help",
        "/HelpUrl",
        "/remediation/references",
        "/unmapped/related_url",
        "/info/reference",
        "/extra/metadata/references",
        "/vulnerability/dataSource",
        "/vulnerability/urls",
    ];
    let mut references = Vec::new();
    for pointer in POINTERS {
        let Some(reference) = value.pointer(pointer) else {
            continue;
        };
        match reference {
            Value::String(url) => references.push(url.clone()),
            Value::Array(urls) => {
                references.extend(urls.iter().filter_map(Value::as_str).map(str::to_owned))
            }
            _ => {}
        }
    }
    references.truncate(32);
    references
}

fn safe_https_reference(value: String) -> Option<String> {
    let value = safe_text(&value, MAX_LONG_TEXT);
    if value.starts_with("https://")
        && !value.chars().any(char::is_whitespace)
        && !value.contains('@')
    {
        Some(value)
    } else {
        None
    }
}

fn collect_named_objects<'a>(
    value: &'a Value,
    pointer: &str,
    depth: usize,
    output: &mut Vec<(String, &'a Value)>,
) {
    if depth > 12 || output.len() >= MAX_RECORDS {
        return;
    }
    match value {
        Value::Object(object) => {
            output.push((pointer.to_owned(), value));
            for (key, child) in object.iter().take(256) {
                let escaped = key.replace('~', "~0").replace('/', "~1");
                collect_named_objects(child, &format!("{pointer}/{escaped}"), depth + 1, output);
                if output.len() >= MAX_RECORDS {
                    break;
                }
            }
        }
        Value::Array(values) => {
            for (index, child) in values.iter().take(MAX_RECORDS - output.len()).enumerate() {
                collect_named_objects(child, &format!("{pointer}/{index}"), depth + 1, output);
                if output.len() >= MAX_RECORDS {
                    break;
                }
            }
        }
        _ => {}
    }
}

fn humanize_identifier(value: &str) -> String {
    safe_text(&value.replace(['_', '-'], " "), 160)
}

fn redact_location(value: &str) -> String {
    let value = value.split(['?', '#']).next().unwrap_or(value);
    let value = value.replace('\\', "/");
    safe_text(&value, MAX_SHORT_TEXT)
}

fn safe_tag(value: &str) -> String {
    let value = safe_text(value, 120).to_ascii_lowercase();
    value
        .chars()
        .map(|character| {
            if character.is_ascii_alphanumeric() || matches!(character, '.' | '_' | '-' | '/') {
                character
            } else {
                '-'
            }
        })
        .collect()
}

fn safe_text(value: &str, max_chars: usize) -> String {
    value
        .chars()
        .filter(|character| !character.is_control() || matches!(character, '\n' | '\t'))
        .take(max_chars)
        .collect::<String>()
        .trim()
        .to_owned()
}

fn trim_ascii(mut value: &[u8]) -> &[u8] {
    while value.first().is_some_and(u8::is_ascii_whitespace) {
        value = &value[1..];
    }
    while value.last().is_some_and(u8::is_ascii_whitespace) {
        value = &value[..value.len() - 1];
    }
    value
}

fn push_warning(warnings: &mut Vec<String>, warning: impl AsRef<str>) {
    if warnings.len() < MAX_WARNINGS {
        warnings.push(safe_text(warning.as_ref(), MAX_SHORT_TEXT));
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fingerprints_are_stable_and_location_queries_are_removed() {
        assert_eq!(
            stable_fingerprint("nuclei", "rule", "asset", "https://example.test/a"),
            stable_fingerprint(
                "nuclei",
                "rule",
                "asset",
                &redact_location("https://example.test/a?token=secret")
            )
        );
    }

    #[test]
    fn evidence_identity_is_distinct_for_each_engine_execution() {
        let first = stable_evidence_id("fingerprint", "artifact", "/result/0", "engine-run-1");
        let second = stable_evidence_id("fingerprint", "artifact", "/result/0", "engine-run-2");
        assert_ne!(first, second);
        assert_eq!(
            first,
            stable_evidence_id("fingerprint", "artifact", "/result/0", "engine-run-1")
        );
    }

    #[test]
    fn secret_fields_are_never_selected_by_helpers() {
        let value: Value = serde_json::json!({
            "Raw": "do-not-copy",
            "Secret": "do-not-copy",
            "DetectorName": "Example"
        });
        assert_eq!(
            nested_string(&value, &["DetectorName"]).as_deref(),
            Some("Example")
        );
        assert!(references_from(&value).is_empty());
    }

    #[test]
    fn only_backend_runtime_stream_capture_paths_are_excluded() {
        assert!(is_runtime_stream_capture_path(
            "case/run/engine/attempt-1/raw/stdout.log"
        ));
        assert!(is_runtime_stream_capture_path(
            "case/run/engine/attempt-42/raw/stderr.log"
        ));
        assert!(!is_runtime_stream_capture_path(
            "case/run/engine/attempt-1/output/raw/stdout.log"
        ));
        assert!(!is_runtime_stream_capture_path(
            "case/run/engine/attempt-one/raw/stdout.log"
        ));
        assert!(!is_runtime_stream_capture_path(
            "case/run/engine/attempt-1/raw/result.json"
        ));
    }

    #[test]
    fn greenbone_attribute_flood_is_bounded_before_normalization() {
        let mut xml = String::from("<results><result id=\"result-1\" ");
        for index in 0..=MAX_XML_ATTRIBUTES {
            xml.push_str(&format!("a{index}=\"x\" "));
        }
        xml.push_str("><name>bounded</name></result></results>");

        let mut warnings = Vec::new();
        assert!(parse_greenbone_xml(xml.as_bytes(), &mut warnings).is_none());
        assert!(
            warnings
                .iter()
                .any(|warning| warning.contains("attribute limit"))
        );
    }
}
