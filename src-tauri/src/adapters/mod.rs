//! Bounded, evidence-preserving normalizers for the built-in scanner catalog.
//!
//! Scanner output is untrusted input. These adapters only map explicit tool
//! fields into the case schema; they never execute, render, or follow text from
//! a target or a scanner result.

use crate::adapter::{AdapterInput, AdapterOutput, AdapterRegistry, EngineAdapter};
use crate::domain::{
    Confidence, Evidence, EvidenceKind, Finding, FindingStatus, RawArtifact, Severity,
};
use crate::error::AppResult;
use serde_json::{Map, Value};
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet};
use std::fs::File;
use std::io::{Read, Take};
use std::path::{Component, Path};
use std::sync::Arc;

pub const ADAPTER_VERSION: &str = "0.1.0";
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
    confidence: Confidence,
    evidence_kind: EvidenceKind,
    references: Vec<String>,
    tags: Vec<String>,
}

#[derive(Debug)]
enum ParsedArtifact {
    Json(Value),
    JsonLines(Vec<(usize, Value)>),
    Xml,
}

/// Construct the adapter set matching the complete built-in engine catalog.
pub fn builtin_adapter_registry() -> AppResult<AdapterRegistry> {
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
        })
        .collect();

    if relevant.is_empty() {
        push_warning(
            &mut output.warnings,
            format!("{} produced no raw artifacts to normalize", adapter.id),
        );
        return Ok(output);
    }

    for artifact in relevant.into_iter().take(MAX_ARTIFACTS) {
        if processed_bytes.saturating_add(artifact.byte_length) > MAX_TOTAL_BYTES {
            push_warning(
                &mut output.warnings,
                "adapter input exceeded the total byte limit; remaining raw artifacts were retained but not normalized",
            );
            break;
        }

        let Some(bytes) =
            read_bounded_artifact(input.artifact_root, artifact, &mut output.warnings)
        else {
            continue;
        };
        processed_bytes += bytes.len() as u64;

        if adapter.profile == Profile::Greenbone {
            push_warning(
                &mut output.warnings,
                "Greenbone XML was retained as hashed raw evidence, but this build has no bounded XML parser; no findings were inferred",
            );
            continue;
        }

        let Some(parsed) = parse_artifact(&bytes, artifact, &mut output.warnings) else {
            continue;
        };
        let records = extract_records(adapter.profile, &parsed, &mut output.warnings);
        for record in records {
            if processed_records >= MAX_RECORDS {
                push_warning(
                    &mut output.warnings,
                    "adapter record limit reached; remaining raw records were retained but not normalized",
                );
                break;
            }
            processed_records += 1;
            let Some(asset_id) = resolve_asset(&record, input.asset_ids, &mut output.warnings)
            else {
                continue;
            };
            merge_finding(&mut findings, adapter, input, artifact, record, asset_id);
        }
    }

    if input.raw_artifacts.len() > MAX_ARTIFACTS {
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
    let trimmed = bytes
        .iter()
        .copied()
        .skip_while(u8::is_ascii_whitespace)
        .collect::<Vec<_>>();
    if trimmed.first() == Some(&b'<') || artifact.media_type.contains("xml") {
        return Some(ParsedArtifact::Xml);
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
                if rows.len() >= MAX_RECORDS {
                    break;
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

fn extract_records(
    profile: Profile,
    parsed: &ParsedArtifact,
    warnings: &mut Vec<String>,
) -> Vec<SourceRecord> {
    if matches!(
        profile,
        Profile::CloudQuery | Profile::Syft | Profile::Greenbone
    ) {
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
        Profile::CloudQuery | Profile::Greenbone | Profile::Syft => Vec::new(),
    }
}

fn json_rows<'a>(
    parsed: &'a ParsedArtifact,
    warnings: &mut Vec<String>,
) -> Vec<(String, &'a Value)> {
    match parsed {
        ParsedArtifact::Json(Value::Array(values)) => values
            .iter()
            .take(MAX_RECORDS)
            .enumerate()
            .map(|(index, value)| (format!("/{index}"), value))
            .collect(),
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
        ParsedArtifact::Xml => Vec::new(),
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
        let status = string_any(object, &["Status", "status"])
            .or_else(|| nested_string(value, &["unmapped", "Status"]))
            .or_else(|| nested_string(value, &["unmapped", "status"]));
        if status.as_deref().is_some_and(is_pass) {
            continue;
        }
        if !status.as_deref().is_some_and(is_failure) {
            push_warning(
                warnings,
                format!("Prowler record at {pointer} had no explicit failing status"),
            );
            continue;
        }
        let rule = string_any(object, &["CheckID", "check_id"])
            .or_else(|| nested_string(value, &["unmapped", "CheckID"]))
            .or_else(|| nested_string(value, &["finding_info", "uid"]));
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
        records.push(record(
            pointer,
            rule_id,
            title,
            severity_text,
            location,
            nested_string(value, &["unmapped", "AccountId"]),
            Confidence::High,
            EvidenceKind::Configuration,
            references_from(value),
            vec!["format:ocsf".into()],
        ));
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
            Some(record(
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
    Some(record(
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
        records.push(record(
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
            Some(record(
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
            Some(record(
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
            Some(record(
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
            Some(record(
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
            let file = string_any(object, &["File", "file"]).unwrap_or_else(|| "repository".into());
            Some(record(
                pointer,
                rule_id.clone(),
                string_any(object, &["Description", "description"])
                    .unwrap_or_else(|| format!("Potential secret detected by {rule_id}")),
                "high".into(),
                file,
                string_any(object, &["asset_id"]),
                Confidence::High,
                EvidenceKind::SourceCode,
                vec![],
                vec!["secret-value:redacted".into()],
            ))
        })
        .collect()
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
            Some(record(
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
            Some(record(
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
            records.push(record(
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
                records.push(record(
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
            Some(record(
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
        records.push(record(
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
                records.push(record(
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
            records.push(record(
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
    let evidence_id = stable_evidence_id(&fingerprint, &artifact.sha256, &record.pointer);
    let evidence = Evidence {
        id: evidence_id,
        finding_id: finding_id.clone(),
        run_id: input.scan_run_id.to_owned(),
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
            control_references: vec![],
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

fn record(
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
) -> SourceRecord {
    SourceRecord {
        pointer: safe_text(&pointer, MAX_SHORT_TEXT),
        rule_id: safe_text(&rule_id, MAX_SHORT_TEXT),
        title: safe_text(&title, MAX_SHORT_TEXT),
        severity: parse_severity(&source_severity),
        source_severity: safe_text(&source_severity, 80),
        location: redact_location(&location),
        asset_hint: asset_hint.map(|value| safe_text(&value, MAX_SHORT_TEXT)),
        confidence,
        evidence_kind,
        references,
        tags,
    }
}

fn resolve_asset(
    record: &SourceRecord,
    allowed_assets: &[String],
    warnings: &mut Vec<String>,
) -> Option<String> {
    if let Some(hint) = &record.asset_hint {
        if allowed_assets.iter().any(|asset| asset == hint) {
            return Some(hint.clone());
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
    for component in ["v1", engine, rule, asset, location] {
        hasher.update(component.as_bytes());
        hasher.update([0]);
    }
    format!("{engine}:{}", hex::encode(hasher.finalize()))
}

fn stable_evidence_id(fingerprint: &str, artifact_hash: &str, pointer: &str) -> String {
    let mut hasher = Sha256::new();
    for component in [fingerprint, artifact_hash, pointer] {
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
}
