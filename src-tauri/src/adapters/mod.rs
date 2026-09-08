//! Bounded, evidence-preserving normalizers for the built-in scanner catalog.
//!
//! Scanner output is untrusted input. These adapters only map explicit tool
//! fields into the case schema; they never execute, render, or follow text from
//! a target or a scanner result.

mod control_mapping;

use crate::adapter::{AdapterInput, AdapterOutput, AdapterRegistry, EngineAdapter};
use crate::domain::{
    Confidence, ConfidenceBasisCode, Evidence, EvidenceKind, Finding, FindingFamily, FindingStatus,
    RawArtifact, ScannerFindingDetails, Severity, SeverityBasisCode,
};
use crate::error::{AppError, AppResult};
use quick_xml::events::{BytesRef, BytesStart, Event};
use quick_xml::{Reader, XmlVersion};
use serde_json::{Map, Value};
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet};
use std::fs::File;
use std::io::{Read, Take};
use std::path::{Component, Path};
use std::sync::Arc;

pub const ADAPTER_VERSION: &str = "0.1.3";
/// Stable identity for the canonical finding fingerprint algorithm. Changing
/// this value requires an explicit migration before cross-version diffs may be
/// treated as comparable.
pub const FINGERPRINT_SCHEMA_VERSION: &str = "v1";
/// Stable identity for the evidence-ID commitment. Version 2 binds the
/// producing engine and normalized source rule in addition to the finding,
/// artifact, result pointer, and exact engine execution.
pub const EVIDENCE_ID_SCHEMA_VERSION: &str = "v2";
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
/// Distinct unresolved provider identifiers tracked per normalization.
const MAX_UNMATCHED_IDENTIFIERS: usize = 32;
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
    /// Bounded display text only. It must never be used as mapping proof
    /// because sanitization can be lossy.
    rule_id: String,
    /// Exact raw scanner rule, present only when it was already bounded,
    /// trimmed, and control-free. Only this value can select catalog entries.
    mapping_source_rule: Option<String>,
    /// Collision-resistant internal identity. Valid rules use their exact
    /// bytes; invalid rules use a domain-separated digest of the raw bytes.
    rule_identity: String,
    title: String,
    severity: Severity,
    source_severity: String,
    /// Present only when the engine reports no severity and this product
    /// derived one. It names what the derivation used, so the user is never
    /// shown a rating the engine did not give.
    severity_basis: Option<SeverityBasisCode>,
    location: String,
    asset_hint: Option<String>,
    asset_provider: Option<String>,
    confidence: Confidence,
    source_confidence: String,
    /// Present only when the engine supplied no confidence and this product
    /// assigned one from the behavior that produced the finding.
    confidence_basis: Option<ConfidenceBasisCode>,
    evidence_kind: EvidenceKind,
    scanner_details: Option<ScannerFindingDetails>,
    references: Vec<String>,
    tags: Vec<String>,
}

/// A severity this product assigned because the engine emits none at all.
///
/// Reading a severity field an engine never populates silently buries its whole
/// output at `Unknown`, which sorts below Low. Inventing a source severity
/// instead is worse: it tells the user the engine rated the finding when it did
/// not. This carries both the level and the basis so the finding can be
/// prioritized honestly and the derivation stays visible.
struct DerivedSeverity {
    severity: Severity,
    /// Which basis. The sentence is derived from this by [`basis_text`] rather
    /// than written beside it, so the code a localized client reads and the
    /// prose an English one reads cannot come to disagree.
    code: SeverityBasisCode,
}

/// A confidence this product assigned because the engine supplied none.
///
/// A source value always wins. This pair exists so downstream readers can
/// distinguish an engine rating from this product's bounded derivation.
struct DerivedConfidence {
    confidence: Confidence,
    code: ConfidenceBasisCode,
}

/// Completes the sentence "severity derived from ...".
fn basis_text(code: SeverityBasisCode) -> &'static str {
    crate::finding_narrative::basis_english(code)
}

fn confidence_basis_text(code: ConfidenceBasisCode) -> &'static str {
    crate::finding_narrative::confidence_basis_english(code)
}

/// Rates only the evidence described by a derived basis; it does not promote
/// the finding because the engine omitted its own confidence field.
fn derived_confidence(code: ConfidenceBasisCode) -> DerivedConfidence {
    let confidence = match code {
        // These extractors admit a record only after the engine returned an
        // explicit failed policy/configuration verdict. The value either met
        // the rule or it did not, so the retained failure is strong evidence.
        ConfidenceBasisCode::DeterministicPolicyEvaluation => Confidence::High,
        // Naabu and httpx records exist because this run received the network
        // response represented by the finding. High describes that observed
        // exposure fact, not whether the exposed service is vulnerable.
        ConfidenceBasisCode::ObservedResponse => Confidence::High,
        // Inventory-to-advisory matching is useful evidence, but version
        // reporting, distribution backports, and advisory applicability still
        // need confirmation on the installed component.
        ConfidenceBasisCode::AdvisoryVersionMatch => Confidence::Medium,
        // A pattern/detector hit was not validated as a live credential or a
        // true defect. Treat it as a lead, not strong evidence of the claim.
        ConfidenceBasisCode::UnverifiedPatternOrDetectorMatch => Confidence::Low,
        // Nuclei templates range from exact banners to heuristic matchers, and
        // this result shape does not say which kind supplied the evidence.
        ConfidenceBasisCode::TemplateMatcher => Confidence::Medium,
        // With no Greenbone QoD value, the NVT result remains useful but cannot
        // inherit the confidence of one of the engine's scored QoD bands.
        ConfidenceBasisCode::MissingDetectionQualityScore => Confidence::Medium,
    };
    DerivedConfidence { confidence, code }
}

struct RecordDraft {
    pointer: String,
    rule_id: String,
    title: String,
    source_severity: String,
    derived_severity: Option<DerivedSeverity>,
    location: String,
    asset_hint: Option<String>,
    source_confidence: String,
    derived_confidence: Option<DerivedConfidence>,
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
        $source_confidence:expr,
        $derived_confidence:expr,
        $evidence_kind:expr,
        $references:expr,
        $tags:expr $(,)?
    ) => {
        record_from_draft(RecordDraft {
            pointer: $pointer,
            rule_id: $rule_id,
            title: $title,
            source_severity: $source_severity,
            derived_severity: None,
            location: $location,
            asset_hint: $asset_hint,
            source_confidence: $source_confidence,
            derived_confidence: $derived_confidence,
            evidence_kind: $evidence_kind,
            references: $references,
            tags: $tags,
        })
    };
}

/// Like [`record!`], for an engine that reports no severity of its own. Takes a
/// [`DerivedSeverity`] where `record!` takes the engine's severity string.
macro_rules! record_with_derived_severity {
    (
        $pointer:expr,
        $rule_id:expr,
        $title:expr,
        $derived:expr,
        $location:expr,
        $asset_hint:expr,
        $source_confidence:expr,
        $derived_confidence:expr,
        $evidence_kind:expr,
        $references:expr,
        $tags:expr $(,)?
    ) => {
        record_from_draft(RecordDraft {
            pointer: $pointer,
            rule_id: $rule_id,
            title: $title,
            source_severity: String::new(),
            derived_severity: Some($derived),
            location: $location,
            asset_hint: $asset_hint,
            source_confidence: $source_confidence,
            derived_confidence: $derived_confidence,
            evidence_kind: $evidence_kind,
            references: $references,
            tags: $tags,
        })
    };
}

/// Like [`record!`], for an engine that has a severity field but leaves it
/// unset for most findings. Takes both the engine's severity — empty when it
/// gave none — and the [`DerivedSeverity`] used only in that case. Whatever the
/// engine did say always wins, so the one rated finding keeps its rating.
macro_rules! record_with_severity_fallback {
    (
        $pointer:expr,
        $rule_id:expr,
        $title:expr,
        $source_severity:expr,
        $derived:expr,
        $location:expr,
        $asset_hint:expr,
        $source_confidence:expr,
        $derived_confidence:expr,
        $evidence_kind:expr,
        $references:expr,
        $tags:expr $(,)?
    ) => {
        record_from_draft(RecordDraft {
            pointer: $pointer,
            rule_id: $rule_id,
            title: $title,
            source_severity: $source_severity,
            derived_severity: Some($derived),
            location: $location,
            asset_hint: $asset_hint,
            source_confidence: $source_confidence,
            derived_confidence: $derived_confidence,
            evidence_kind: $evidence_kind,
            references: $references,
            tags: $tags,
        })
    };
}

/// Like [`record!`], for an engine that supplies no confidence of its own.
macro_rules! record_with_derived_confidence {
    (
        $pointer:expr, $rule_id:expr, $title:expr, $source_severity:expr,
        $location:expr, $asset_hint:expr, $derived_confidence:expr,
        $evidence_kind:expr, $references:expr, $tags:expr $(,)?
    ) => {
        record!(
            $pointer,
            $rule_id,
            $title,
            $source_severity,
            $location,
            $asset_hint,
            String::new(),
            Some($derived_confidence),
            $evidence_kind,
            $references,
            $tags,
        )
    };
}

/// Like [`record!`], when a source confidence may be absent and a derivation
/// is permitted to fill only that gap.
macro_rules! record_with_confidence_fallback {
    (
        $pointer:expr, $rule_id:expr, $title:expr, $source_severity:expr,
        $location:expr, $asset_hint:expr, $source_confidence:expr,
        $derived_confidence:expr, $evidence_kind:expr, $references:expr,
        $tags:expr $(,)?
    ) => {
        record!(
            $pointer,
            $rule_id,
            $title,
            $source_severity,
            $location,
            $asset_hint,
            $source_confidence,
            Some($derived_confidence),
            $evidence_kind,
            $references,
            $tags,
        )
    };
}

/// Both ratings are derived because the engine supplied neither one.
macro_rules! record_with_derived_severity_and_confidence {
    (
        $pointer:expr, $rule_id:expr, $title:expr, $derived_severity:expr,
        $location:expr, $asset_hint:expr, $derived_confidence:expr,
        $evidence_kind:expr, $references:expr, $tags:expr $(,)?
    ) => {
        record_with_derived_severity!(
            $pointer,
            $rule_id,
            $title,
            $derived_severity,
            $location,
            $asset_hint,
            String::new(),
            Some($derived_confidence),
            $evidence_kind,
            $references,
            $tags,
        )
    };
}

/// Severity and confidence each have an independent fallback; the source
/// severity can win while confidence remains explicitly product-derived.
macro_rules! record_with_severity_fallback_and_derived_confidence {
    (
        $pointer:expr, $rule_id:expr, $title:expr, $source_severity:expr,
        $derived_severity:expr, $location:expr, $asset_hint:expr,
        $derived_confidence:expr, $evidence_kind:expr, $references:expr,
        $tags:expr $(,)?
    ) => {
        record_with_severity_fallback!(
            $pointer,
            $rule_id,
            $title,
            $source_severity,
            $derived_severity,
            $location,
            $asset_hint,
            String::new(),
            Some($derived_confidence),
            $evidence_kind,
            $references,
            $tags,
        )
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
    Summary,
    Solution,
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
    summary: Option<String>,
    solution: Option<String>,
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
    if let Err(error) = control_mapping::validate_catalog(BUILTIN_ENGINE_IDS) {
        tracing::warn!(
            error = %error,
            "framework relationships are unavailable; finding normalization remains enabled"
        );
    }
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

/// Canonical catalog identity frozen into each new relationship snapshot.
pub(crate) fn control_mapping_provenance() -> AppResult<crate::domain::ControlMappingProvenance> {
    control_mapping::catalog_provenance()
}

/// Fail-closed proof that a frozen relationship carrying the current catalog
/// identity is an exact reviewed entry for its evidence-producing engine and
/// frozen AI context.
pub(crate) fn validate_current_control_reference(
    reference: &crate::domain::ControlReference,
    evidence_sources: &[(String, String)],
    ai_system_applicable: bool,
    ai_generated_artifact_applicable: bool,
) -> AppResult<()> {
    control_mapping::validate_current_reference(
        reference,
        evidence_sources,
        ai_system_applicable,
        ai_generated_artifact_applicable,
    )
}

/// Return the exact scanner rule only when the current structured evidence ID
/// commits to it and to the rest of the frozen evidence identity. Older
/// records deliberately return `None` and cannot be upgraded from prose or
/// tags into verified-current mapping provenance.
pub(crate) fn validated_evidence_source_rule<'a>(
    evidence: &'a crate::domain::Evidence,
    finding_fingerprint: &str,
) -> AppResult<Option<&'a str>> {
    let Some(source_rule) = evidence.source_rule.as_deref() else {
        return Ok(None);
    };
    if source_rule.is_empty()
        || source_rule.chars().count() > MAX_SHORT_TEXT
        || source_rule.trim() != source_rule
        || source_rule.chars().any(char::is_control)
    {
        return Err(AppError::InvalidRequest(format!(
            "evidence {} has malformed structured source-rule provenance",
            evidence.id
        )));
    }
    let engine_run_id = evidence.engine_run_id.as_deref().ok_or_else(|| {
        AppError::InvalidRequest(format!(
            "evidence {} has a structured source rule but no exact engine run",
            evidence.id
        ))
    })?;
    let pointer_sha256 = evidence.result_pointer_sha256.as_deref().ok_or_else(|| {
        AppError::InvalidRequest(format!(
            "evidence {} has a structured source rule but no result-pointer digest",
            evidence.id
        ))
    })?;
    if pointer_sha256.len() != 64
        || !pointer_sha256
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return Err(AppError::InvalidRequest(format!(
            "evidence {} has a malformed result-pointer digest",
            evidence.id
        )));
    }
    let expected = stable_evidence_id(
        finding_fingerprint,
        &evidence.engine_id,
        source_rule,
        &evidence.artifact_sha256,
        pointer_sha256,
        engine_run_id,
    );
    if evidence.id != expected {
        return Err(AppError::InvalidRequest(format!(
            "evidence {} source rule does not match its structured evidence identity",
            evidence.id
        )));
    }
    Ok(Some(source_rule))
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
    // Provider-qualified identifiers the engine reported on that no authorized
    // asset claims. Counted per identifier rather than per record: the
    // per-record warnings name the rule that was dropped, which is the symptom.
    // The identifier is the cause, it is the same for every dropped record, and
    // it is the one thing the reader can act on.
    let mut unmatched_identifiers: BTreeMap<(String, String), usize> = BTreeMap::new();

    let relevant: Vec<&RawArtifact> = input
        .raw_artifacts
        .iter()
        .filter(|artifact| {
            artifact.case_id == input.case_id
                && artifact.run_id == input.scan_run_id
                && artifact.engine_run_id == input.engine_run_id
                && !is_runtime_stream_capture_path(&artifact.relative_path)
                && !is_preserved_upstream_evidence_path(&artifact.relative_path)
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
        let parsed = if is_complete_empty_json_lines(adapter.profile, artifact, &bytes) {
            Some(ParsedArtifact::JsonLines(Vec::new()))
        } else {
            parse_artifact(&bytes, artifact, &mut output.warnings)
        };
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
        // Deliberately after the window above, so that disclosing a shortfall
        // is not itself read as evidence that failed to normalize. A control
        // the engine passed over by design was normalized correctly and must
        // leave the run complete; only a control it could not evaluate
        // withholds completion, and it says so for itself.
        if let Some(unevaluated) = unevaluated_controls(adapter.profile, &parsed) {
            push_warning(&mut output.warnings, unevaluated.disclosure);
            if unevaluated.withholds_completion {
                output.complete = false;
            }
        }
        // A disputed control was evaluated and still becomes a finding, so this
        // discloses without touching `complete`.
        if let Some(disputed) = tenant_disputed_controls(adapter.profile, &parsed) {
            push_warning(&mut output.warnings, disputed);
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
                &mut unmatched_identifiers,
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

    // The engine ran, produced results, and every one of them was discarded
    // because nothing the person authorized claims the identifier the engine
    // reported on. Said once per identifier, naming the identifier, because
    // adding it to the authorized asset is the whole fix -- and without this
    // the run reads as a clean scan that found nothing.
    //
    // Put in front of the per-record warnings and exempt from MAX_WARNINGS,
    // both deliberately. A real cloud account produces far more records than
    // the cap, so appending this through `push_warning` meant the one sentence
    // worth reading was the one silently dropped, and the surface that renders
    // warnings joins them into a single truncated string, so arriving last is
    // nearly the same as not arriving. Exempting it is safe because the map it
    // comes from is capped at MAX_UNMATCHED_IDENTIFIERS entries.
    let attribution_warnings = unmatched_identifiers
        .iter()
        .map(|((provider, identifier), count)| {
            safe_text(
                &format!(
                    "{} reported {count} result(s) for {provider} identifier {identifier}, but no authorized asset carries that identifier; none of them were attributed. Add {identifier} to the asset you authorized and scan again.",
                    adapter.id
                ),
                MAX_SHORT_TEXT,
            )
        })
        .collect::<Vec<_>>();
    output.warnings.splice(0..0, attribution_warnings);
    output.unattributed = unmatched_identifiers
        .into_iter()
        .map(
            |((provider, identifier), discarded_results)| crate::domain::UnattributedResults {
                provider,
                identifier,
                discarded_results,
            },
        )
        .collect();

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

/// The released Naabu, HTTPx, Nuclei, and TruffleHog contracts are JSON streams
/// containing one object per observation. A clean scan therefore produces a
/// real, hashed output artifact with zero bytes (or only line-ending
/// whitespace). Treat only those exact JSONL contracts as complete zero-record
/// streams; document-shaped adapters keep their schema-specific empty checks.
fn is_complete_empty_json_lines(profile: Profile, artifact: &RawArtifact, bytes: &[u8]) -> bool {
    if !matches!(
        profile,
        Profile::Naabu | Profile::Httpx | Profile::Nuclei | Profile::Trufflehog
    ) || bytes.iter().any(|byte| !byte.is_ascii_whitespace())
    {
        return false;
    }
    let extension_is_json_lines = Path::new(&artifact.relative_path)
        .extension()
        .and_then(|extension| extension.to_str())
        .is_some_and(|extension| {
            matches!(extension.to_ascii_lowercase().as_str(), "jsonl" | "ndjson")
        });
    extension_is_json_lines
        || artifact
            .media_type
            .eq_ignore_ascii_case("application/x-ndjson")
}

/// Mapping catalogs cannot affect a released JSONL engine when its exact
/// adapter input is a verified zero-byte stream: there are no source records
/// from which a finding or control reference could be produced. This is kept
/// deliberately narrower than normal adapter parsing (which also accepts
/// whitespace-only streams) so cross-version resume planning can prove the
/// exception from durable metadata plus the artifact hash alone.
pub(crate) fn is_mapping_independent_empty_json_lines(
    engine_id: &str,
    artifact: &RawArtifact,
) -> bool {
    matches!(engine_id, "naabu" | "httpx" | "nuclei" | "trufflehog")
        && artifact.byte_length == 0
        && (Path::new(&artifact.relative_path)
            .extension()
            .and_then(|extension| extension.to_str())
            .is_some_and(|extension| {
                matches!(extension.to_ascii_lowercase().as_str(), "jsonl" | "ndjson")
            })
            || artifact
                .media_type
                .eq_ignore_ascii_case("application/x-ndjson"))
}

/// Stdout and stderr are retained as raw evidence, but the released engine
/// contract writes normalizer input below `/output`. Feeding the backend-owned
/// stream captures to JSON/XML adapters would make every otherwise-valid run
/// look malformed (including the normal empty-stream case). Match the complete
/// private run layout so an engine-created `output/raw/stdout.log` remains
/// ordinary untrusted output instead of being silently skipped.
pub(crate) fn is_runtime_stream_capture_path(relative_path: &str) -> bool {
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

/// Whether the artifact is a raw vendor report a managed wrapper preserved as
/// evidence rather than the normalized document the wrapper owns.
///
/// The Microsoft 365 wrappers write the untouched upstream report under
/// `output/upstream/` next to their own document (`run-scubagear.ps1` and
/// `run-maester.ps1`). Both are captured, because the raw report is what a
/// reviewer needs in order to check the wrapper against, but only the wrapper's
/// document uses the field names the adapters read. Normalizing the raw report
/// too is not a second opinion, it is a misparse: upstream ScubaGear spells the
/// key `Control ID`, so every raw control is dropped with a "lacked a rule id"
/// warning, and a raw report whose keys happen to match can contribute a second
/// record for a control the wrapper already reported.
pub(crate) fn is_preserved_upstream_evidence_path(relative_path: &str) -> bool {
    let components = Path::new(relative_path)
        .components()
        .filter_map(|component| match component {
            Component::Normal(value) => value.to_str(),
            _ => None,
        })
        .collect::<Vec<_>>();
    components.windows(3).any(|window| {
        window[0].strip_prefix("attempt-").is_some_and(|attempt| {
            !attempt.is_empty() && attempt.bytes().all(|byte| byte.is_ascii_digit())
        }) && window[1] == "output"
            && window[2] == "upstream"
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
        b"summary" => XmlElement::Summary,
        b"solution" => XmlElement::Solution,
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
        || stack.ends_with(&[XmlElement::Result, XmlElement::Summary])
        || stack.ends_with(&[XmlElement::Result, XmlElement::Solution])
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
    } else if stack.ends_with(&[XmlElement::Result, XmlElement::Summary]) {
        &mut record.summary
    } else if stack.ends_with(&[XmlElement::Result, XmlElement::Solution]) {
        &mut record.solution
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

/// Attach only explicitly selected scanner rule/advisory metadata.
///
/// Scanner output remains untrusted data. Every field is bounded and stripped
/// of control characters here, in one place, before it reaches durable
/// evidence. Callers must still allowlist the source paths: secret values, raw
/// matches, response bodies, and target-observed values never belong here.
fn with_scanner_details(
    mut record: SourceRecord,
    description: Option<String>,
    remediation: Option<String>,
    installed_version: Option<String>,
    fixed_version: Option<String>,
) -> SourceRecord {
    let details = ScannerFindingDetails {
        description: bounded_scanner_detail(description, MAX_LONG_TEXT),
        remediation: bounded_scanner_detail(remediation, MAX_LONG_TEXT),
        installed_version: bounded_scanner_detail(installed_version, MAX_SHORT_TEXT),
        fixed_version: bounded_scanner_detail(fixed_version, MAX_SHORT_TEXT),
    };
    if details.description.is_some()
        || details.remediation.is_some()
        || details.installed_version.is_some()
        || details.fixed_version.is_some()
    {
        record.scanner_details = Some(details);
    }
    record
}

fn bounded_scanner_detail(value: Option<String>, max_chars: usize) -> Option<String> {
    let value = value?;
    let cleaned = value
        .chars()
        .map(|character| {
            if character.is_control() {
                ' '
            } else {
                character
            }
        })
        .take(max_chars)
        .collect::<String>();
    let cleaned = cleaned.split_whitespace().collect::<Vec<_>>().join(" ");
    (!cleaned.is_empty()).then_some(cleaned)
}

fn bounded_string_list(value: Option<&Value>, max_items: usize) -> Option<String> {
    let values = value?.as_array()?;
    let joined = values
        .iter()
        .filter_map(Value::as_str)
        .map(|value| safe_text(value, MAX_SHORT_TEXT))
        .filter(|value| !value.is_empty())
        .take(max_items)
        .collect::<Vec<_>>()
        .join(", ");
    (!joined.is_empty()).then_some(joined)
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
        let rule = exact_nested_rule_scalar(value, &["metadata", "event_code"])
            .or_else(|| exact_nested_rule_scalar(value, &["finding_info", "analytic", "uid"]))
            .or_else(|| exact_rule_string_any(object, &["CheckID", "check_id"]))
            .or_else(|| exact_nested_rule_scalar(value, &["unmapped", "CheckID"]))
            .or_else(|| exact_nested_rule_scalar(value, &["unmapped", "check_id"]));
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
        let mut record = record_with_derived_confidence!(
            pointer,
            rule_id,
            title,
            severity_text,
            location,
            nested_string(value, &["cloud", "account", "uid"])
                .or_else(|| nested_string(value, &["unmapped", "provider_uid"]))
                .or_else(|| nested_string(value, &["unmapped", "AccountId"])),
            derived_confidence(ConfidenceBasisCode::DeterministicPolicyEvaluation),
            EvidenceKind::Configuration,
            references_from(value),
            vec!["format:ocsf".into()],
        );
        record.asset_provider = nested_string(value, &["cloud", "provider"])
            .or_else(|| nested_string(value, &["unmapped", "provider"]));
        records.push(with_scanner_details(
            record,
            None,
            nested_string(value, &["remediation", "desc"]),
            None,
            None,
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
            // ScoutSuite writes each rule under
            // `services.<service>.findings.<rule key>` and never repeats that
            // key inside the object (`core/processingengine.py`), so for real
            // output the pointer holds the only copy of the rule identity.
            let rule_id = exact_rule_string_any(object, &["id", "rule_id", "key"])
                .or_else(|| scoutsuite_rule_key(&pointer))?;
            let title = string_any(object, &["description", "title", "name"])
                .unwrap_or_else(|| format!("ScoutSuite rule {rule_id}"));
            Some(with_scanner_details(
                record_with_derived_confidence!(
                    pointer,
                    rule_id,
                    title,
                    string_any(object, &["level", "severity"]).unwrap_or_else(|| "unknown".into()),
                    string_any(object, &["resource", "path", "service"])
                        .unwrap_or_else(|| "cloud-resource".into()),
                    string_any(object, &["account_id", "subscription_id", "project_id"]),
                    derived_confidence(ConfidenceBasisCode::DeterministicPolicyEvaluation),
                    EvidenceKind::Configuration,
                    references_from(value),
                    vec![],
                ),
                string_any(object, &["rationale"]),
                string_any(object, &["remediation"]),
                None,
                None,
            ))
        })
        .take(MAX_RECORDS)
        .collect()
}

/// Recover a ScoutSuite rule key from the pointer of the object it names.
///
/// Scoped to the `findings` container ScoutSuite actually writes rules into, so
/// an unrelated nested object cannot be admitted as a rule just because it sits
/// somewhere under `services`.
fn scoutsuite_rule_key(pointer: &str) -> Option<String> {
    let mut segments = pointer.rsplit('/');
    let leaf = segments.next()?;
    if leaf.is_empty() || segments.next()? != "findings" {
        return None;
    }
    Some(leaf.replace("~1", "/").replace("~0", "~"))
}

/// Where Cloudsplaining files policies in `iam-findings-<account>.json`, paired
/// with the tag that tells a reader whether the account owner can edit the
/// policy at all. An AWS-managed policy is fixed by detaching it, not by
/// rewriting it, so the distinction changes the remediation.
const CLOUDSPLAINING_POLICY_SECTIONS: [(&str, &str); 3] = [
    ("customer_managed_policies", "customer-managed"),
    ("inline_policies", "inline"),
    ("aws_managed_policies", "aws-managed"),
];

/// The risk categories Cloudsplaining writes into every policy object, with the
/// severity upstream assigns each one in `cloudsplaining/shared/constants.py`.
/// Reading the tool's own grading keeps this engine comparable with the others
/// instead of inventing a scale here.
const CLOUDSPLAINING_RISKS: [(&str, &str, &str); 6] = [
    ("PrivilegeEscalation", "high", "Privilege escalation path"),
    ("DataExfiltration", "medium", "Data exfiltration exposure"),
    ("ResourceExposure", "high", "Resource exposure"),
    ("ServiceWildcard", "medium", "Service wildcard permission"),
    ("CredentialsExposure", "high", "Credentials exposure"),
    (
        "InfrastructureModification",
        "low",
        "Infrastructure modification permission",
    ),
];

/// Read Cloudsplaining's IAM findings document.
///
/// The artifact is `authorization_details.results` (`command/scan.py`), keyed by
/// principal and policy collection. Each risk category is an array *inside* a
/// policy object, so nothing recognisable appears at the document root.
fn extract_cloudsplaining(
    parsed: &ParsedArtifact,
    warnings: &mut Vec<String>,
) -> Vec<SourceRecord> {
    let Some(root) = json_root(parsed).and_then(Value::as_object) else {
        warnings.push(
            "Cloudsplaining results were not a single JSON object, so no policy findings could be read."
                .into(),
        );
        return Vec::new();
    };
    let mut records = Vec::new();
    for (section, policy_source) in CLOUDSPLAINING_POLICY_SECTIONS {
        let Some(policies) = root.get(section).and_then(Value::as_object) else {
            continue;
        };
        for (policy_key, policy) in policies {
            let Some(policy) = policy.as_object() else {
                continue;
            };
            // Cloudsplaining already applied the operator's exclusions file;
            // re-reporting what it excluded would overrule the tool's own call.
            if policy.get("is_excluded").and_then(Value::as_bool) == Some(true) {
                continue;
            }
            let policy_name = string_any(policy, &["PolicyName", "PolicyId"])
                .unwrap_or_else(|| policy_key.clone());
            for (risk, severity, label) in CLOUDSPLAINING_RISKS {
                if records.len() >= MAX_RECORDS {
                    return records;
                }
                let Some(entries) = policy.get(risk).and_then(Value::as_array) else {
                    continue;
                };
                if entries.is_empty() {
                    continue;
                }
                let escaped = policy_key.replace('~', "~0").replace('/', "~1");
                records.push(record_with_derived_confidence!(
                    format!("/{section}/{escaped}/{risk}"),
                    risk.to_owned(),
                    format!("{label} in policy {policy_name}"),
                    severity.to_owned(),
                    policy_name.clone(),
                    // The findings document carries no account identifier at
                    // any level, and a policy ARN is not an asset identity —
                    // offering one as a hint would strand these records in a
                    // multi-asset scope instead of resolving them.
                    None,
                    derived_confidence(ConfidenceBasisCode::DeterministicPolicyEvaluation),
                    EvidenceKind::Configuration,
                    vec![],
                    vec![
                        format!("policy-source:{policy_source}"),
                        format!("flagged-permissions:{}", entries.len()),
                    ],
                ));
            }
        }
    }
    records
}

fn extract_scubagear(parsed: &ParsedArtifact, warnings: &mut Vec<String>) -> Vec<SourceRecord> {
    extract_m365(
        parsed,
        warnings,
        "ScubaGear",
        &["PolicyId", "ControlId", "id"],
        &["Result", "status"],
        &["SourceCriticality", "Criticality"],
        "source-criticality",
    )
}

fn extract_maester(parsed: &ParsedArtifact, warnings: &mut Vec<String>) -> Vec<SourceRecord> {
    extract_m365(
        parsed,
        warnings,
        "Maester",
        &["Id", "TestId", "id"],
        &["Result", "Outcome", "status"],
        &["SourceSeverity"],
        "source-rating",
    )
}

/// What a Microsoft 365 run left unevaluated, and whether that shortfall is
/// severe enough that the run must not claim completion.
struct UnevaluatedControls {
    disclosure: String,
    /// True when the engine was asked to check controls and could not, as
    /// opposed to passing over them by design or by tenant configuration. Such
    /// a run produced usable findings but did not establish coverage, which is
    /// exactly what `AdapterOutput::complete` exists to say.
    withholds_completion: bool,
}

/// Controls the Microsoft 365 wrappers counted but did not turn into a
/// normalized result, phrased for the person reading the run.
///
/// Both wrappers drop any control whose upstream status they do not map
/// (`run-scubagear.ps1:126`, `run-maester.ps1:123`), and they record what they
/// dropped in `Diagnostics`. Nothing read it, so a tenant with twenty controls
/// reserved for manual review and five omitted by configuration rendered as an
/// unqualified list of findings.
///
/// The two kinds of shortfall are not equivalent. A control reserved for manual
/// review or omitted in the tenant's own config was passed over deliberately, so
/// the run is still a complete scan of what it set out to check. A control the
/// engine *could not evaluate* means coverage was never established, and
/// upstream is explicit that this is what its error counter means: a missing
/// provider command becomes an error. Only the second withholds completion.
fn unevaluated_controls(profile: Profile, parsed: &ParsedArtifact) -> Option<UnevaluatedControls> {
    // `Diagnostics` counters for controls the wrapper did not represent, paired
    // with how to say each one out loud. `by_design` was a deliberate pass;
    // `unevaluable` means the engine tried and could not.
    let (engine, by_design, unevaluable) = match profile {
        Profile::ScubaGear => (
            "ScubaGear",
            [
                ("manual", "reserved for manual review"),
                ("omitted", "omitted by configuration"),
            ]
            .as_slice(),
            [("errors", "could not be evaluated")].as_slice(),
        ),
        Profile::Maester => (
            "Maester",
            [("skipped", "skipped"), ("not_run", "not run")].as_slice(),
            [("errors", "could not be evaluated")].as_slice(),
        ),
        _ => return None,
    };
    let ParsedArtifact::Json(root) = parsed else {
        return None;
    };
    let diagnostics = root.get("Diagnostics")?.as_object()?;
    let count_of = |group: &[(&str, &str)]| {
        group
            .iter()
            .filter_map(|(key, description)| {
                let count = diagnostics.get(*key)?.as_u64().filter(|count| *count > 0)?;
                Some(format!("{count} {description}"))
            })
            .collect::<Vec<_>>()
    };
    let passed_over = count_of(by_design);
    let could_not_evaluate = count_of(unevaluable);
    let lost = normalization_shortfall(profile, diagnostics);
    if passed_over.is_empty() && could_not_evaluate.is_empty() && lost.is_empty() {
        return None;
    }
    let all = passed_over
        .iter()
        .chain(could_not_evaluate.iter())
        .chain(lost.iter())
        .cloned()
        .collect::<Vec<_>>();
    Some(UnevaluatedControls {
        disclosure: format!(
            "{engine} did not evaluate every control in scope ({}); those controls are absent from findings and this run does not establish their state",
            all.join(", ")
        ),
        // Losing verdicts is not a smaller problem than failing to produce
        // them: either way the run does not establish those controls' state.
        withholds_completion: !could_not_evaluate.is_empty() || !lost.is_empty(),
    })
}

/// How many verdicts the engine reported that the wrapper did not carry across.
///
/// `Diagnostics.normalized_results` is the wrapper's count of the list it just
/// built, so checking it against `Results.len()` is true by construction — it
/// stays true when the wrapper's verdict `switch` matched nothing and silently
/// dropped every control. These counters come from the engine itself, so they
/// are the independent number. Without them, an upstream rename of `Passed` to
/// `Success` produces a clean, confident, completely empty tenant audit.
fn normalization_shortfall(
    profile: Profile,
    diagnostics: &serde_json::Map<String, Value>,
) -> Vec<String> {
    let count = |key: &str| {
        diagnostics
            .get(key)
            .and_then(Value::as_u64)
            .unwrap_or_default()
    };
    // Only the verdicts each wrapper actually converts into a result row. The
    // by-design and unevaluable counters are disclosed separately above.
    //
    // Deliberately a lower bound. A ScubaGear control the tenant disputed is
    // judged on `OriginalResult` and counted in `disputed` rather than
    // `failures`, so it can add a row no verdict counter accounts for -- it can
    // only push `normalized` above this floor, never below it.
    let carried = match profile {
        // `Passed`, `Failed`, and `Investigate` all become rows.
        Profile::Maester => count("passes") + count("failures") + count("investigate"),
        // `Pass`, `Fail`, and `Warning` become rows.
        Profile::ScubaGear => count("passes") + count("failures") + count("warnings"),
        _ => return Vec::new(),
    };
    let mut shortfalls = Vec::new();
    if matches!(profile, Profile::Maester) {
        // Inferred from `run-maester.ps1`: `total` is the upstream test count,
        // while these are every category the wrapper reports. A positive
        // remainder therefore names controls the wrapper accounted for under
        // no category at all. Those controls were in scope but their state is
        // unknown, so, like a verdict lost during normalization, they withhold
        // completion. Saturation matters because upstream counters may overlap;
        // a counter surplus is not evidence that the wrapper dropped controls.
        if let Some(total) = diagnostics.get("total").and_then(Value::as_u64) {
            let accounted = [
                "passes",
                "failures",
                "investigate",
                "errors",
                "skipped",
                "not_run",
            ]
            .into_iter()
            .fold(0_u64, |sum, key| sum.saturating_add(count(key)));
            let uncategorized = total.saturating_sub(accounted);
            if uncategorized > 0 {
                shortfalls.push(format!(
                    "{uncategorized} not accounted for by any reported category"
                ));
            }
        }
    }
    let normalized = diagnostics
        .get("normalized_results")
        .and_then(Value::as_u64);
    if let Some(normalized) = normalized
        && normalized < carried
    {
        let lost = carried - normalized;
        shortfalls.push(format!(
            "{lost} reported by the engine but not carried into results"
        ));
    }
    shortfalls
}

/// Controls whose result the audited tenant's own configuration declares wrong.
///
/// ScubaGear rewrites such a control's `Result` to the sentinel `Incorrect
/// result`, keeps its real determination in `OriginalResult`, and counts it in
/// `IncorrectResults` rather than `Failures` (CreateReport.psm1:331, :342, :348).
/// A tenant could therefore erase a genuine failure from its own audit and leave
/// no finding and no counter behind. The wrapper now judges these on ScubaGear's
/// verdict, so they are not a coverage gap and must not be reported as one — but
/// the dispute is still material to whoever reads the run, so it is said plainly
/// here and marked on each affected finding by `extract_m365`.
fn tenant_disputed_controls(profile: Profile, parsed: &ParsedArtifact) -> Option<String> {
    if !matches!(profile, Profile::ScubaGear) {
        return None;
    }
    let ParsedArtifact::Json(root) = parsed else {
        return None;
    };
    let disputed = root
        .pointer("/Diagnostics/disputed")
        .and_then(Value::as_u64)
        .filter(|count| *count > 0)?;
    let controls = if disputed == 1 { "control" } else { "controls" };
    Some(format!(
        "the tenant's ScubaGear configuration disputes the result of {disputed} {controls}; they are reported on ScubaGear's own determination and tagged tenant-disputed rather than suppressed"
    ))
}

fn extract_m365(
    parsed: &ParsedArtifact,
    warnings: &mut Vec<String>,
    engine: &str,
    rule_keys: &[&str],
    status_keys: &[&str],
    source_rating_keys: &[&str],
    source_rating_tag: &str,
) -> Vec<SourceRecord> {
    let mut candidates = Vec::new();
    // Whether the candidates came from a wrapper's declared `Results` list. Every
    // member of such a list is a control the wrapper says it normalized, so one
    // that cannot become a finding is a loss worth naming. Rows recovered from a
    // tabular artifact carry no such promise and are skipped quietly.
    let mut declared_envelope = false;
    match parsed {
        ParsedArtifact::Json(root) => {
            declared_envelope = true;
            // The wrapper owns this document: it names the engine that wrote it
            // and lists every control it normalized under `Results`. Walking the
            // whole tree instead would let any object that happens to carry a
            // status and a rule id become a finding, including one nested inside
            // provenance or a vendor blob the wrapper merely quoted.
            match root.get("Engine").and_then(Value::as_str) {
                Some(declared) if declared.eq_ignore_ascii_case(engine) => {}
                Some(declared) => {
                    push_warning(
                        warnings,
                        format!(
                            "{engine} adapter was given a document declaring engine {declared}; nothing was normalized from it"
                        ),
                    );
                    return Vec::new();
                }
                // Checking the envelope only when it happens to be present would
                // let a malformed or future-schema document skip every check
                // below and still read as a clean run. Its results are kept,
                // because they are probably real, but the run cannot claim to
                // have accounted for a document it could not identify.
                None => push_warning(
                    warnings,
                    format!(
                        "{engine} document did not name the engine that wrote it; it was normalized but not verified as this engine's own output"
                    ),
                ),
            }
            let Some(results) = root.get("Results").and_then(Value::as_array) else {
                push_warning(
                    warnings,
                    format!("{engine} document declared no Results list and was not normalized"),
                );
                return Vec::new();
            };
            // The wrapper counts what it wrote. A disagreement means results were
            // lost between writing and reading, which no rule-level check sees.
            match root
                .pointer("/Diagnostics/normalized_results")
                .and_then(Value::as_u64)
            {
                Some(declared) if declared == results.len() as u64 => {}
                Some(declared) => push_warning(
                    warnings,
                    format!(
                        "{engine} reported writing {declared} normalized results but its Results list holds {}",
                        results.len()
                    ),
                ),
                None => push_warning(
                    warnings,
                    format!(
                        "{engine} document did not declare how many results it normalized, so nothing can confirm none were lost"
                    ),
                ),
            }
            candidates.extend(
                results
                    .iter()
                    .enumerate()
                    .map(|(index, value)| (format!("/Results/{index}"), value)),
            );
        }
        _ => candidates.extend(json_rows(parsed, warnings)),
    }
    let mut seen = BTreeSet::new();
    let mut records = Vec::new();
    for (pointer, value) in candidates {
        let Some(object) = value.as_object() else {
            if declared_envelope {
                push_warning(
                    warnings,
                    format!(
                        "{engine} listed a result at {pointer} that is not an object; it was not normalized"
                    ),
                );
            }
            continue;
        };
        let Some(status) = string_any(object, status_keys) else {
            if declared_envelope {
                push_warning(
                    warnings,
                    format!(
                        "{engine} result at {pointer} carried no recognizable status; it was not normalized"
                    ),
                );
            }
            continue;
        };
        if !is_failure(&status) {
            continue;
        }
        let Some(rule_id) = exact_rule_string_any(object, rule_keys) else {
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
        let source_rating = string_any(object, source_rating_keys);
        let mut tags = source_rating
            .as_deref()
            .filter(|rating| !rating.is_empty())
            .map(|rating| vec![format!("{source_rating_tag}:{}", safe_tag(rating))])
            .unwrap_or_default();
        // The wrapper leaves the upstream status in `SourceResult` and judges the
        // verdict elsewhere when the tenant disputed the result. Carrying the
        // dispute onto the finding is the difference between reporting it and
        // quietly honouring it; the run-level note alone would not say which
        // control was disputed.
        if string_any(object, &["SourceResult"])
            .is_some_and(|source| source.eq_ignore_ascii_case("incorrect result"))
        {
            tags.push("tenant-disputed".into());
        }
        records.push(record_with_derived_confidence!(
            pointer,
            rule_id.clone(),
            string_any(object, &["Name", "Title", "Requirement", "Description"])
                .unwrap_or_else(|| format!("{engine} control {rule_id}")),
            string_any(object, &["Severity", "severity"]).unwrap_or_else(|| "unknown".into()),
            string_any(object, &["Service", "Product", "Resource", "TenantId"])
                .unwrap_or_else(|| "microsoft-365-tenant".into()),
            string_any(object, &["asset_id", "AssetId"]),
            derived_confidence(ConfidenceBasisCode::DeterministicPolicyEvaluation),
            EvidenceKind::Configuration,
            references_from(value),
            tags,
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
            let Some(object) = value.as_object() else {
                push_warning(
                    warnings,
                    format!("Naabu record at {pointer} was not an object and was not normalized"),
                );
                return None;
            };
            let Some(host) = string_any(object, &["host", "ip"]) else {
                push_warning(
                    warnings,
                    format!("Naabu record at {pointer} had no bounded host and was not normalized"),
                );
                return None;
            };
            let Some(port) = object.get("port").and_then(scalar_string) else {
                push_warning(
                    warnings,
                    format!("Naabu record at {pointer} had no bounded port and was not normalized"),
                );
                return None;
            };
            let protocol = string_any(object, &["protocol"]).unwrap_or_else(|| "tcp".into());
            Some(record_with_derived_severity_and_confidence!(
                pointer,
                format!("open-{protocol}-port"),
                "Externally reachable network service".into(),
                // Naabu is a port scanner and emits no severity; the only
                // `confidence` in its output grades service fingerprinting, not
                // risk. An open port is an exposure fact, so it is recorded
                // rather than rated, and the record says which of the two it is.
                DerivedSeverity {
                    severity: Severity::Informational,
                    code: SeverityBasisCode::OpenPort,
                },
                format!("{}:{port}", redact_location(&host)),
                string_any(object, &["asset_id"]),
                derived_confidence(ConfidenceBasisCode::ObservedResponse),
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
            let Some(object) = value.as_object() else {
                push_warning(
                    warnings,
                    format!("HTTPx record at {pointer} was not an object; retry with the supported pinned JSONL output"),
                );
                return None;
            };
            let Some(target) = string_any(object, &["url", "input", "host"]) else {
                push_warning(
                    warnings,
                    format!("HTTPx record at {pointer} lacked its target; the raw record was retained, and the scan should be retried with the supported pinned JSONL output"),
                );
                return None;
            };
            let Some(status) = object
                .get("status_code")
                .or_else(|| object.get("status-code"))
                .and_then(scalar_string)
            else {
                push_warning(
                    warnings,
                    format!("HTTPx record at {pointer} lacked its HTTP status; the raw record was retained, and the scan should be retried with the supported pinned JSONL output"),
                );
                return None;
            };
            Some(record_with_derived_severity_and_confidence!(
                pointer,
                "http-service-observed".into(),
                "Externally reachable HTTP service".into(),
                // httpx probes reachability and emits no severity on a result.
                // Reaching a service is an exposure fact, so it is recorded
                // rather than rated, and the record says which of the two it is.
                DerivedSeverity {
                    severity: Severity::Informational,
                    code: SeverityBasisCode::ReachableHttpService,
                },
                redact_location(&target),
                string_any(object, &["asset_id"]),
                derived_confidence(ConfidenceBasisCode::ObservedResponse),
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
            let Some(object) = value.as_object() else {
                push_warning(
                    warnings,
                    format!("Nuclei record at {pointer} was not an object; retry with the supported pinned JSONL output"),
                );
                return None;
            };
            let Some(rule_id) =
                exact_rule_string_any(object, &["template-id", "template_id", "templateID"])
            else {
                push_warning(
                    warnings,
                    format!("Nuclei record at {pointer} lacked its template id; the raw record was retained, and the scan should be retried with the supported pinned JSONL output"),
                );
                return None;
            };
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
            Some(with_scanner_details(
                record_with_derived_confidence!(
                    pointer,
                    rule_id,
                    title,
                    severity,
                    redact_location(&target),
                    string_any(object, &["asset_id"]),
                    derived_confidence(ConfidenceBasisCode::TemplateMatcher),
                    EvidenceKind::ExternalValidation,
                    references_from(value),
                    tags,
                ),
                nested_string(value, &["info", "description"]),
                nested_string(value, &["info", "remediation"]),
                None,
                None,
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
        let source_confidence = result.qod.clone().unwrap_or_default();
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

        records.push(with_scanner_details(
            record_with_confidence_fallback!(
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
                source_confidence,
                derived_confidence(ConfidenceBasisCode::MissingDetectionQualityScore),
                EvidenceKind::ExternalValidation,
                references,
                tags,
            ),
            // Only these two result-level fields are copied from the product
            // launcher, which writes them from the pinned feed metadata.
            // `<description>` is the target-observed result message and must
            // remain only in the raw artifact.
            result.summary.clone(),
            result.solution.clone(),
            None,
            None,
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
            let rule_id = exact_rule_string_any(object, &["check_id"])?;
            let path = string_any(object, &["path"]).unwrap_or_else(|| "source-file".into());
            let line = value.pointer("/start/line").and_then(positive_u32_scalar);
            let column = value.pointer("/start/col").and_then(positive_u32_scalar);
            let location = source_coordinate_location(&path, line, column, None);
            let pointer = format!("/results/{index}");
            Some(with_scanner_details(
                record_with_confidence_fallback!(
                    pointer,
                    rule_id.clone(),
                    // Semgrep writes the human-readable explanation here and it is
                    // the only sentence a reader can act on; the rule id alone says
                    // nothing. Falls back to the id when a rule ships no message.
                    nested_string(value, &["extra", "message"])
                        .map(|message| safe_text(&message, MAX_SHORT_TEXT))
                        .filter(|message| !message.is_empty())
                        .unwrap_or_else(|| format!("Semgrep rule {rule_id}")),
                    nested_string(value, &["extra", "severity"])
                        .unwrap_or_else(|| "unknown".into()),
                    location,
                    string_any(object, &["asset_id"]),
                    nested_string(value, &["extra", "metadata", "confidence"]).unwrap_or_default(),
                    derived_confidence(ConfidenceBasisCode::UnverifiedPatternOrDetectorMatch),
                    EvidenceKind::SourceCode,
                    references_from(value),
                    line.map(|line| vec![format!("source-line:{line}")])
                        .unwrap_or_default(),
                ),
                nested_string(value, &["extra", "metadata", "description"]),
                nested_string(value, &["extra", "fix"]),
                None,
                None,
            ))
        })
        .collect()
}

fn extract_gitleaks(parsed: &ParsedArtifact, warnings: &mut Vec<String>) -> Vec<SourceRecord> {
    if !matches!(parsed, ParsedArtifact::Json(Value::Array(_))) {
        push_warning(
            warnings,
            "Gitleaks output was not its supported JSON finding array; the raw artifact was retained, and the scan should be retried with the pinned JSON reporter",
        );
        return Vec::new();
    }
    json_rows(parsed, warnings)
        .into_iter()
        .filter_map(|(pointer, value)| {
            let Some(object) = value.as_object() else {
                push_warning(
                    warnings,
                    format!("Gitleaks finding at {pointer} was not an object; the raw record was retained"),
                );
                return None;
            };
            let Some(rule_id) = exact_rule_string_any(object, &["RuleID", "rule_id"]) else {
                push_warning(
                    warnings,
                    format!("Gitleaks finding at {pointer} lacked its RuleID; the raw record was retained, and the scan should be retried with the pinned JSON reporter"),
                );
                return None;
            };
            let location = gitleaks_location(object);
            Some(record_with_derived_severity_and_confidence!(
                pointer,
                rule_id.clone(),
                string_any(object, &["Description", "description"])
                    .unwrap_or_else(|| format!("Potential secret detected by {rule_id}")),
                // The word "severity" does not occur anywhere in gitleaks'
                // source. Neither `report.Finding` nor the rule config has such
                // a field, and its SARIF writer emits no `level` either. The
                // rating is this product's, from what a match means.
                DerivedSeverity {
                    severity: Severity::High,
                    code: SeverityBasisCode::SecretPatternMatch,
                },
                location,
                string_any(object, &["asset_id"]),
                derived_confidence(ConfidenceBasisCode::UnverifiedPatternOrDetectorMatch),
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
    keys.iter()
        .find_map(|key| object.get(*key).and_then(positive_u32_scalar))
}

fn positive_u32_scalar(value: &Value) -> Option<u32> {
    let parsed = match value {
        Value::Number(number) => number.as_u64()?,
        Value::String(value) => value.parse::<u64>().ok()?,
        _ => return None,
    };
    u32::try_from(parsed).ok().filter(|value| *value > 0)
}

/// Build a stable, secret-free source coordinate from fields the scanner
/// explicitly reports. The fingerprint includes this location, so omitting a
/// line or resource silently merges distinct observations from the same rule
/// and file into one finding.
fn source_coordinate_location(
    path: &str,
    line: Option<u32>,
    column: Option<u32>,
    resource: Option<&str>,
) -> String {
    let mut location = safe_text(&redact_location(path), 360);
    if let Some(line) = line {
        location.push_str(&format!(":line={line}"));
    }
    if let Some(column) = column {
        location.push_str(&format!(":column={column}"));
    }
    if let Some(resource) = resource
        .map(|resource| safe_text(resource, 120))
        .filter(|resource| !resource.is_empty())
    {
        location.push_str(":resource=");
        location.push_str(&resource);
    }
    safe_text(&location, MAX_SHORT_TEXT)
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
            let Some(object) = value.as_object() else {
                push_warning(
                    warnings,
                    format!("TruffleHog record at {pointer} was not an object; retry with the supported pinned JSONL output"),
                );
                return None;
            };
            let Some(detector) = exact_rule_string_any(object, &["DetectorName", "DetectorType"])
            else {
                push_warning(
                    warnings,
                    format!("TruffleHog record at {pointer} lacked its detector identity; the raw record was retained, and the scan should be retried with the supported pinned JSONL output"),
                );
                return None;
            };
            let filesystem = value.pointer("/SourceMetadata/Data/Filesystem");
            let git = value.pointer("/SourceMetadata/Data/Git");
            let source = filesystem
                .and_then(|metadata| nested_string(metadata, &["file"]))
                .or_else(|| git.and_then(|metadata| nested_string(metadata, &["file"])))
                .unwrap_or_else(|| "repository".into());
            let line = filesystem
                .and_then(|metadata| metadata.get("line"))
                .and_then(positive_u32_scalar)
                .or_else(|| {
                    git.and_then(|metadata| metadata.get("line"))
                        .and_then(positive_u32_scalar)
                });
            let location = source_coordinate_location(&source, line, None, None);
            Some(record_with_derived_severity_and_confidence!(
                pointer,
                format!("trufflehog:{detector}"),
                format!("Potential {detector} secret detected"),
                // TruffleHog emits no severity; its JSON printer marshals a
                // fixed struct with no such field. It emits `Verified`, which
                // this product's launcher forces to false by passing
                // `--no-verification`: the engine short-circuits before any
                // detector runs its check. Reading that field would grade every
                // secret on a test that was never performed.
                DerivedSeverity {
                    severity: Severity::High,
                    code: SeverityBasisCode::UnverifiedCredentialDetector,
                },
                location,
                string_any(object, &["asset_id"]),
                derived_confidence(ConfidenceBasisCode::UnverifiedPatternOrDetectorMatch),
                EvidenceKind::SourceCode,
                vec![],
                vec![
                    "verification:not-attempted".into(),
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
    let mut records = Vec::new();
    let mut inspected_rows = 0_usize;

    match root {
        // Checkov serializes a single detected framework as this legacy object
        // shape. Keep its pointers stable for already-saved evidence.
        Value::Object(_) => {
            extract_checkov_framework(root, "", &mut inspected_rows, &mut records, warnings)
        }
        // With `--framework all`, Checkov serializes one report object per
        // detected framework. The record limit applies across the whole
        // document, not once per framework.
        Value::Array(frameworks) => {
            if frameworks.len() > MAX_RECORDS {
                push_warning(
                    warnings,
                    "Checkov framework result limit reached; later framework results remain only as raw evidence",
                );
            }
            for (framework_index, framework) in frameworks.iter().take(MAX_RECORDS).enumerate() {
                if inspected_rows >= MAX_RECORDS {
                    push_warning(
                        warnings,
                        "Checkov failed-check record limit reached; later rows remain only as raw evidence",
                    );
                    break;
                }
                extract_checkov_framework(
                    framework,
                    &format!("/{framework_index}"),
                    &mut inspected_rows,
                    &mut records,
                    warnings,
                );
            }
        }
        _ => push_warning(
            warnings,
            "Checkov expected a JSON object or an array of framework result objects",
        ),
    }

    records
}

fn extract_checkov_framework(
    framework: &Value,
    framework_pointer: &str,
    inspected_rows: &mut usize,
    records: &mut Vec<SourceRecord>,
    warnings: &mut Vec<String>,
) {
    let display_pointer = if framework_pointer.is_empty() {
        "/"
    } else {
        framework_pointer
    };
    let Some(object) = framework.as_object() else {
        push_warning(
            warnings,
            format!("non-object Checkov framework result at {display_pointer} was skipped"),
        );
        return;
    };

    let failed_pointer = format!("{framework_pointer}/results/failed_checks");
    let Some(results) = object.get("results") else {
        // When no runner found an applicable framework, upstream emits its
        // summary object directly rather than a report object. That is a valid
        // zero-finding result and must stay distinct from a malformed report.
        if object.contains_key("checkov_version")
            && object.contains_key("passed")
            && object.contains_key("failed")
            && object.contains_key("skipped")
        {
            return;
        }
        push_warning(
            warnings,
            format!("Checkov framework result at {display_pointer} had no results object"),
        );
        return;
    };
    let Some(results) = results.as_object() else {
        push_warning(
            warnings,
            format!("Checkov results at {display_pointer} were not an object"),
        );
        return;
    };
    let Some(failed) = results.get("failed_checks").and_then(Value::as_array) else {
        push_warning(
            warnings,
            format!("Checkov output at {failed_pointer} was not an array"),
        );
        return;
    };

    for (index, value) in failed.iter().enumerate() {
        if *inspected_rows >= MAX_RECORDS {
            push_warning(
                warnings,
                "Checkov failed-check record limit reached; later rows remain only as raw evidence",
            );
            return;
        }
        *inspected_rows += 1;

        let pointer = format!("{failed_pointer}/{index}");
        let Some(check) = value.as_object() else {
            push_warning(
                warnings,
                format!("non-object Checkov failed check at {pointer} was skipped"),
            );
            continue;
        };
        let Some(rule_id) = exact_rule_string_any(check, &["check_id"]) else {
            push_warning(
                warnings,
                format!("Checkov failed check at {pointer} had no valid check_id and was skipped"),
            );
            continue;
        };
        let path = string_any(check, &["file_path", "repo_file_path"])
            .unwrap_or_else(|| "iac-resource".into());
        let line = check
            .get("file_line_range")
            .and_then(Value::as_array)
            .and_then(|range| range.first())
            .and_then(positive_u32_scalar);
        let resource = string_any(check, &["resource", "resource_address"]);
        records.push(with_scanner_details(
            record_with_severity_fallback_and_derived_confidence!(
                pointer,
                rule_id.clone(),
                string_any(check, &["check_name"])
                    .unwrap_or_else(|| format!("Checkov check {rule_id}")),
                // `Record.severity` is whatever the check object carried, and
                // `BaseCheck` hardcodes `None`. The values that fill it come
                // from downloaded platform metadata, which `--skip-download`
                // switches off entirely. Of the 256 shipped graph-check YAMLs
                // exactly one declares a severity locally, so this is populated
                // for CKV2_AWS_34 and null for every other check.
                string_any(check, &["severity"]).unwrap_or_default(),
                // Rating the rest flat is the most that can be justified: the
                // pack gives no per-check weight offline, and the alternative
                // sinks a whole engine's output below Low as unknown.
                DerivedSeverity {
                    severity: Severity::Medium,
                    code: SeverityBasisCode::IacPolicyCheck,
                },
                source_coordinate_location(&path, line, None, resource.as_deref()),
                string_any(check, &["asset_id"]),
                derived_confidence(ConfidenceBasisCode::DeterministicPolicyEvaluation),
                EvidenceKind::Configuration,
                references_from(value),
                vec![],
            ),
            string_any(check, &["description", "short_description"]),
            None,
            None,
            None,
        ));
    }
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
        let Some(rule_id) = exact_rule_string_any(query_object, &["query_id"]) else {
            continue;
        };
        let title = string_any(query_object, &["query_name"])
            .unwrap_or_else(|| format!("KICS query {rule_id}"));
        let severity = string_any(query_object, &["severity"]).unwrap_or_else(|| "unknown".into());
        let Some(files) = query_object.get("files").and_then(Value::as_array) else {
            continue;
        };
        for (file_index, file) in files.iter().enumerate() {
            let Some(file_object) = file.as_object() else {
                continue;
            };
            let path =
                string_any(file_object, &["file_name"]).unwrap_or_else(|| "iac-resource".into());
            let line = positive_u32_any(file_object, &["line", "search_line"]);
            let resource = [
                string_any(file_object, &["resource_name"])
                    .filter(|value| !value.is_empty())
                    .map(|value| format!("resource:{value}")),
                string_any(file_object, &["similarity_id", "old_similarity_id"])
                    .filter(|value| !value.is_empty())
                    .map(|value| format!("similarity:{value}")),
            ]
            .into_iter()
            .flatten()
            .collect::<Vec<_>>()
            .join(",");
            records.push(with_scanner_details(
                record_with_derived_confidence!(
                    format!("/queries/{query_index}/files/{file_index}"),
                    rule_id.clone(),
                    title.clone(),
                    severity.clone(),
                    source_coordinate_location(
                        &path,
                        line,
                        None,
                        (!resource.is_empty()).then_some(resource.as_str()),
                    ),
                    string_any(file_object, &["asset_id"]),
                    derived_confidence(ConfidenceBasisCode::DeterministicPolicyEvaluation),
                    EvidenceKind::Configuration,
                    references_from(query),
                    vec![],
                ),
                string_any(query_object, &["description"]),
                None,
                None,
                None,
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
        push_warning(
            warnings,
            "Trivy output lacked its Results array; the raw artifact was retained, and the scan should be retried with the pinned JSON reporter",
        );
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
            let confidence_basis = match field {
                "Vulnerabilities" => ConfidenceBasisCode::AdvisoryVersionMatch,
                "Misconfigurations" => ConfidenceBasisCode::DeterministicPolicyEvaluation,
                "Secrets" => ConfidenceBasisCode::UnverifiedPatternOrDetectorMatch,
                _ => unreachable!("closed Trivy result kinds"),
            };
            let Some(items) = result_object.get(field).and_then(Value::as_array) else {
                continue;
            };
            for (item_index, item) in items.iter().enumerate() {
                let Some(object) = item.as_object() else {
                    push_warning(
                        warnings,
                        format!(
                            "Trivy {prefix} at /Results/{result_index}/{field}/{item_index} was not an object and remains only as raw evidence"
                        ),
                    );
                    continue;
                };
                let Some(rule_id) =
                    exact_rule_string_any(object, &["VulnerabilityID", "ID", "RuleID"])
                else {
                    push_warning(
                        warnings,
                        format!(
                            "Trivy {prefix} at /Results/{result_index}/{field}/{item_index} lacked its native rule id; the raw record was retained, and the scan should be retried with the pinned JSON reporter"
                        ),
                    );
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
                let (location, asset_hint) = match field {
                    "Vulnerabilities" => {
                        let package =
                            string_any(object, &["PkgName"]).unwrap_or_else(|| "package".into());
                        let installed = string_any(object, &["InstalledVersion"])
                            .unwrap_or_else(|| "unknown-version".into());
                        let package_path = string_any(object, &["PkgPath", "PkgID"]);
                        let resource = package_path
                            .map(|path| format!("{package}@{installed}:{path}"))
                            .unwrap_or_else(|| format!("{package}@{installed}"));
                        (
                            source_coordinate_location(&target, None, None, Some(&resource)),
                            string_any(object, &["asset_id"]),
                        )
                    }
                    "Secrets" => {
                        let offset = positive_u32_any(object, &["Offset"])
                            .map(|offset| format!("offset:{offset}"));
                        (
                            source_coordinate_location(
                                &target,
                                positive_u32_any(object, &["StartLine"]),
                                None,
                                offset.as_deref(),
                            ),
                            string_any(object, &["asset_id"]),
                        )
                    }
                    "Misconfigurations" => (
                        source_coordinate_location(
                            &target,
                            object
                                .get("CauseMetadata")
                                .and_then(Value::as_object)
                                .and_then(|cause| positive_u32_any(cause, &["StartLine"])),
                            None,
                            object
                                .get("CauseMetadata")
                                .and_then(Value::as_object)
                                .and_then(|cause| string_any(cause, &["Resource"]))
                                .as_deref(),
                        ),
                        string_any(object, &["asset_id"]),
                    ),
                    _ => unreachable!("closed Trivy result kinds"),
                };
                records.push(with_scanner_details(
                    record_with_derived_confidence!(
                        format!("/Results/{result_index}/{field}/{item_index}"),
                        rule_id,
                        title,
                        string_any(object, &["Severity"]).unwrap_or_else(|| "unknown".into()),
                        location,
                        asset_hint,
                        derived_confidence(confidence_basis),
                        kind.clone(),
                        references_from(item),
                        tags,
                    ),
                    string_any(object, &["Description"]),
                    None,
                    string_any(object, &["InstalledVersion"]),
                    string_any(object, &["FixedVersion"]),
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
        push_warning(
            warnings,
            "Grype output lacked its matches array; the raw artifact was retained, and the scan should be retried with the pinned JSON reporter",
        );
        return Vec::new();
    };
    matches
        .iter()
        .take(MAX_RECORDS)
        .enumerate()
        .filter_map(|(index, value)| {
            let rule_id = exact_nested_rule_scalar(value, &["vulnerability", "id"])?;
            let package =
                nested_string(value, &["artifact", "name"]).unwrap_or_else(|| "package".into());
            let location = nested_string(value, &["artifact", "locations", "0", "path"])
                .unwrap_or_else(|| package.clone());
            Some(with_scanner_details(
                record_with_derived_confidence!(
                    format!("/matches/{index}"),
                    rule_id.clone(),
                    format!("Vulnerable package {package} ({rule_id})"),
                    nested_string(value, &["vulnerability", "severity"])
                        .unwrap_or_else(|| "unknown".into()),
                    location,
                    value
                        .as_object()
                        .and_then(|object| string_any(object, &["asset_id"])),
                    derived_confidence(ConfidenceBasisCode::AdvisoryVersionMatch),
                    EvidenceKind::PackageInventory,
                    references_from(value),
                    vec![format!("package:{}", safe_tag(&package))],
                ),
                nested_string(value, &["vulnerability", "description"]),
                None,
                nested_string(value, &["artifact", "version"]),
                bounded_string_list(value.pointer("/vulnerability/fix/versions"), 16),
            ))
        })
        .collect()
}

/// What Kubescape's `summaryDetails.controls` roll-up knows about a control.
struct KubescapeControlSummary {
    name: Option<String>,
    /// Kubescape grades controls 1-10, the same direction and range the shared
    /// numeric severity branch already reads, so the roll-up's score passes
    /// straight through rather than through a second scale invented here.
    score_factor: Option<String>,
}

/// Read Kubescape's v2 posture report.
///
/// `results[].controls[].status` is an object (`{status, subStatus, info}`), so
/// scanning for a string `status` matches only the `summaryDetails.controls`
/// roll-up and silently loses every per-resource result. The roll-up says how
/// bad a control is; `results` says which resource actually failed it, which is
/// the part a reader needs in order to fix anything.
fn extract_kubescape(parsed: &ParsedArtifact, warnings: &mut Vec<String>) -> Vec<SourceRecord> {
    let Some(root) = json_root(parsed).and_then(Value::as_object) else {
        push_warning(warnings, "Kubescape expected a JSON document");
        return Vec::new();
    };

    let summary_controls = root
        .get("summaryDetails")
        .and_then(Value::as_object)
        .and_then(|summary| summary.get("controls"))
        .and_then(Value::as_object);
    let mut summaries: BTreeMap<String, KubescapeControlSummary> = BTreeMap::new();
    for (control_id, control) in summary_controls.into_iter().flatten() {
        let Some(control) = control.as_object() else {
            continue;
        };
        summaries.insert(
            control_id.clone(),
            KubescapeControlSummary {
                name: string_any(control, &["name"]),
                score_factor: control
                    .get("scoreFactor")
                    .and_then(Value::as_f64)
                    .map(|score| score.to_string()),
            },
        );
    }

    let mut records = Vec::new();
    for (index, result) in root
        .get("results")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .enumerate()
    {
        let Some(result) = result.as_object() else {
            continue;
        };
        let location = string_any(result, &["resourceID", "resource"])
            .unwrap_or_else(|| "kubernetes-resource".into());
        for (control_index, control) in result
            .get("controls")
            .and_then(Value::as_array)
            .into_iter()
            .flatten()
            .enumerate()
        {
            if records.len() >= MAX_RECORDS {
                return records;
            }
            let Some(control) = control.as_object() else {
                continue;
            };
            // v2 nests the verdict; older shapes put a plain string here.
            let status = control
                .get("status")
                .and_then(Value::as_object)
                .and_then(|status| string_any(status, &["status"]))
                .or_else(|| string_any(control, &["status"]));
            if !status.as_deref().is_some_and(is_failure) {
                continue;
            }
            let Some(rule_id) = exact_rule_string_any(control, &["controlID"]) else {
                continue;
            };
            let summary = summaries.get(&rule_id);
            records.push(record_with_derived_confidence!(
                format!("/results/{index}/controls/{control_index}"),
                rule_id.clone(),
                string_any(control, &["name"])
                    .or_else(|| summary.and_then(|summary| summary.name.clone()))
                    .unwrap_or_else(|| format!("Kubescape control {rule_id}")),
                summary
                    .and_then(|summary| summary.score_factor.clone())
                    .unwrap_or_else(|| "unknown".into()),
                location.clone(),
                None,
                derived_confidence(ConfidenceBasisCode::DeterministicPolicyEvaluation),
                EvidenceKind::Configuration,
                references_from(control.get("rules").unwrap_or(&Value::Null)),
                vec![],
            ));
        }
    }

    // A report can carry the roll-up without per-resource results. A failing
    // control is still a finding then; it just cannot name a resource.
    if records.is_empty() {
        for (rule_id, control) in summary_controls.into_iter().flatten() {
            if records.len() >= MAX_RECORDS {
                break;
            }
            let Some(object) = control.as_object() else {
                continue;
            };
            if !string_any(object, &["status"])
                .as_deref()
                .is_some_and(is_failure)
            {
                continue;
            }
            let summary = summaries.get(rule_id);
            records.push(record_with_derived_confidence!(
                format!("/summaryDetails/controls/{rule_id}"),
                rule_id.clone(),
                summary
                    .and_then(|summary| summary.name.clone())
                    .unwrap_or_else(|| format!("Kubescape control {rule_id}")),
                summary
                    .and_then(|summary| summary.score_factor.clone())
                    .unwrap_or_else(|| "unknown".into()),
                "kubernetes-cluster".to_owned(),
                None,
                derived_confidence(ConfidenceBasisCode::DeterministicPolicyEvaluation),
                EvidenceKind::Configuration,
                vec![],
                vec![],
            ));
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
        push_warning(
            warnings,
            "kube-bench output lacked its Controls array; the raw artifact was retained, and the scan should be retried with the pinned JSON reporter",
        );
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
                let Some(rule_id) = exact_rule_string_any(object, &["test_number", "id"]) else {
                    continue;
                };
                records.push(with_scanner_details(
                    record_with_derived_severity_and_confidence!(
                        format!(
                            "/Controls/{control_index}/tests/{test_index}/results/{result_index}"
                        ),
                        rule_id.clone(),
                        string_any(object, &["test_desc", "desc"])
                            .unwrap_or_else(|| format!("kube-bench control {rule_id}")),
                        // kube-bench's `Check` struct carries no severity field, so
                        // there is nothing to read here and every finding would
                        // otherwise sort below Low as Unknown. Upstream's own ASFF
                        // exporter reaches the same conclusion and labels every
                        // failed check High for exactly this reason.
                        DerivedSeverity {
                            severity: Severity::High,
                            code: SeverityBasisCode::CisKubernetesBenchmark,
                        },
                        string_any(object, &["resource", "node_type"])
                            .unwrap_or_else(|| "kubernetes-cluster".into()),
                        string_any(object, &["asset_id"]),
                        derived_confidence(ConfidenceBasisCode::DeterministicPolicyEvaluation),
                        EvidenceKind::Configuration,
                        references_from(value),
                        vec![],
                    ),
                    None,
                    string_any(object, &["remediation"]),
                    None,
                    None,
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
            let Some(rule_id) = exact_rule_string_any(object, &["control_id", "reason", "id"])
            else {
                continue;
            };
            records.push(record_with_derived_severity_and_confidence!(
                format!("{pointer}rows/{index}"),
                rule_id.clone(),
                string_any(object, &["title", "reason"])
                    .unwrap_or_else(|| format!("Steampipe control {rule_id}")),
                // The `severity` column exists, and reading it was still a
                // misattribution: Steampipe answers whatever SQL it is given and
                // has no severity of its own, and the value in that column is a
                // literal this product wrote — `'high' as severity` in the fixed
                // query at engines/images/cloud-launcher/main.go. Presenting our
                // own constant back as the engine's rating is circular, so the
                // column is deliberately not read. Removing it from the query
                // needs an engine-image rebuild and is not done here.
                DerivedSeverity {
                    severity: Severity::High,
                    code: SeverityBasisCode::CloudControlQuery,
                },
                string_any(object, &["resource", "resource_id", "title"])
                    .unwrap_or_else(|| "cloud-resource".into()),
                string_any(object, &["asset_id"]),
                derived_confidence(ConfidenceBasisCode::DeterministicPolicyEvaluation),
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
    let rule_id = record.rule_id.clone();
    let location = redact_location(&record.location);
    let fingerprint = stable_fingerprint(adapter.id, &record.rule_identity, &asset_id, &location);
    let finding_id = format!(
        "finding-{}",
        &fingerprint.rsplit(':').next().unwrap_or(&fingerprint)[..32]
    );
    let result_pointer_sha256 = hex::encode(Sha256::digest(record.pointer.as_bytes()));
    let evidence_id = stable_evidence_id(
        &fingerprint,
        adapter.id,
        &record.rule_identity,
        &artifact.sha256,
        &result_pointer_sha256,
        input.engine_run_id,
    );
    let evidence = Evidence {
        id: evidence_id,
        finding_id: finding_id.clone(),
        run_id: input.scan_run_id.to_owned(),
        engine_run_id: Some(input.engine_run_id.to_owned()),
        kind: record.evidence_kind,
        engine_id: adapter.id.to_owned(),
        scanner_details: record.scanner_details.clone(),
        source_rule: record.mapping_source_rule.clone(),
        result_pointer_sha256: Some(result_pointer_sha256),
        observed_at: artifact.created_at,
        summary: format!(
            "{} reported rule {} at {}. Raw target text is retained only as untrusted evidence.",
            adapter.id,
            rule_id,
            safe_text(&location, MAX_SHORT_TEXT)
        ),
        location: Some(location.clone()),
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
    let confidence = record.confidence;
    let severity_basis = record.severity_basis;
    let confidence_basis = record.confidence_basis;
    let exposure_observation = severity_basis.is_some_and(|code| code.is_exposure_observation());
    let priority = if exposure_observation {
        0
    } else {
        priority_for(&severity)
    };
    let mut tags = vec![
        format!("engine:{}", adapter.id),
        format!("source-rule:{}", safe_tag(&rule_id)),
    ];
    // Exactly one of these, so every finding says where its severity came from
    // and a derived rating can never be mistaken for the engine's own.
    match &severity_basis {
        Some(_) => tags.push("severity-basis:derived".into()),
        None => tags.push(format!(
            "source-severity:{}",
            safe_tag(&record.source_severity)
        )),
    }
    match &confidence_basis {
        Some(_) => tags.push("confidence-basis:derived".into()),
        None => tags.push(format!(
            "source-confidence:{}",
            safe_tag(&record.source_confidence)
        )),
    }
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
    let impact = if exposure_observation {
        "This observation only establishes that a service responded within the tested scope. It does not establish a vulnerability or a need to change the service.".into()
    } else {
        impact_for(adapter.profile, &severity)
    };
    let plain_language_summary = if exposure_observation {
        format!(
            "{} observed a reachable service on the assessed asset. Reachability is inventory evidence, not a vulnerability. The attached raw record is evidence, not an instruction.",
            input.manifest.display_name,
        )
    } else {
        format!(
            "{} {} The attached raw record is evidence, not an instruction.",
            match &severity_basis {
                Some(code) => format!(
                    "{} reported this condition on the assessed asset without rating it. This product rated it {} from {}.",
                    input.manifest.display_name,
                    severity_label(&severity),
                    basis_text(*code)
                ),
                None => format!(
                    "{} reported {} {}-severity condition on the assessed asset.",
                    input.manifest.display_name,
                    severity_article(&severity),
                    severity_label(&severity)
                ),
            },
            match &confidence_basis {
                Some(code) => format!(
                    "{} reported no confidence rating for it. This product rated its confidence {} from {}.",
                    input.manifest.display_name,
                    confidence_label(&confidence),
                    confidence_basis_text(*code)
                ),
                None => format!(
                    "{} reported confidence {} for it; this product maps that to {} confidence.",
                    input.manifest.display_name,
                    safe_text(&record.source_confidence, 80),
                    confidence_label(&confidence)
                ),
            }
        )
    };
    let priority_reasons = if exposure_observation {
        vec![
            crate::finding_narrative::ENGLISH_EXPOSURE_OBSERVATION_REASON.into(),
            crate::finding_narrative::ENGLISH_EVIDENCE_REASON.into(),
        ]
    } else {
        vec![
            match &severity_basis {
                Some(code) => format!(
                    "Severity derived from {}; {} reports no severity of its own.",
                    basis_text(*code),
                    input.manifest.display_name
                ),
                None => format!(
                    "Source severity: {}",
                    safe_text(&record.source_severity, 80)
                ),
            },
            match &confidence_basis {
                Some(code) => format!(
                    "Confidence derived from {}; {} reports no confidence of its own.",
                    confidence_basis_text(*code),
                    input.manifest.display_name
                ),
                None => format!(
                    "Source confidence: {}",
                    safe_text(&record.source_confidence, 80)
                ),
            },
            crate::finding_narrative::ENGLISH_EVIDENCE_REASON.into(),
        ]
    };
    let recommendation = if exposure_observation {
        "Confirm that the reachable service is expected. To look for weaknesses, run an applicable security check against that service; do not treat reachability alone as something to fix."
            .into()
    } else {
        format!(
            "Have the recommended specialist ({}) review the affected asset and the source rule's official guidance, then plan and approve {}.",
            adapter.expert_type,
            remedy_for(adapter.profile)
        )
    };
    let verification_guidance = if exposure_observation {
        format!(
            "Repeat {} discovery with the same target and scope if you need to confirm whether the service is still reachable.",
            input.manifest.display_name
        )
    } else {
        format!(
            "After an approved manual change, rerun {} with the same authorized scope and confirm that source rule {} is no longer reported.",
            input.manifest.display_name, rule_id
        )
    };
    findings.insert(
        fingerprint.clone(),
        Finding {
            id: finding_id,
            case_id: input.case_id.to_owned(),
            first_seen_run_id: input.scan_run_id.to_owned(),
            last_seen_run_id: input.scan_run_id.to_owned(),
            fingerprint,
            title,
            plain_language_summary,
            possible_impact: impact,
            severity,
            confidence,
            priority,
            priority_reasons,
            asset_ids: vec![asset_id],
            evidence: vec![evidence],
            control_references: mapping_control_references(
                adapter.id,
                record.mapping_source_rule.as_deref(),
                input.ai_system_applicable,
                input.ai_generated_artifact_applicable,
            ),
            recommendation,
            verification_guidance,
            rollback_considerations: (!exposure_observation)
                .then(|| crate::finding_narrative::ENGLISH_ROLLBACK.into()),
            official_references,
            recommended_expert_type: adapter.expert_type.into(),
            status: FindingStatus::Unreviewed,
            tags,
            // The codes the prose above was composed from, so a client that
            // renders in another language composes its own sentence rather
            // than showing a translated heading over an English paragraph.
            family: Some(family_for(adapter.profile)),
            severity_basis_code: severity_basis,
            confidence_basis_code: confidence_basis,
            context_factors: Vec::new(),
        },
    );
}

fn record_from_draft(draft: RecordDraft) -> SourceRecord {
    let mapping_source_rule = exact_mapping_source_rule(&draft.rule_id);
    let rule_identity = mapping_source_rule.clone().unwrap_or_else(|| {
        let mut hasher = Sha256::new();
        hasher.update(b"ai-security-scanner.unmappable-source-rule");
        hasher.update([0]);
        hasher.update(draft.rule_id.as_bytes());
        format!("unmappable-sha256:{}", hex::encode(hasher.finalize()))
    });
    let reported_severity = safe_text(&draft.source_severity, 80);
    let (severity, source_severity, severity_basis) = match draft.derived_severity {
        // The engine reported nothing, so the source severity stays empty rather
        // than borrowing the derived level. Nothing downstream may present the
        // derived rating as the engine's own.
        Some(derived) if reported_severity.is_empty() => {
            (derived.severity, String::new(), Some(derived.code))
        }
        // A rating the engine did give always wins, including one this product
        // does not recognize: that has to surface as unknown and needing review,
        // not be replaced by a derivation.
        _ => (
            parse_severity(&draft.source_severity),
            reported_severity,
            None,
        ),
    };
    let reported_confidence = safe_text(&draft.source_confidence, 80);
    let (confidence, source_confidence, confidence_basis) = match draft.derived_confidence {
        // The engine reported nothing, so the source confidence stays empty
        // rather than borrowing the derived level. Nothing downstream may
        // present the derived rating as the engine's own.
        Some(derived) if reported_confidence.is_empty() => {
            (derived.confidence, String::new(), Some(derived.code))
        }
        // A value the engine gave always wins. A derivation only fills a gap;
        // even an unfamiliar source value must not be replaced and presented
        // as though it came from this product.
        _ => (
            parse_confidence(&draft.source_confidence),
            reported_confidence,
            None,
        ),
    };
    debug_assert!(
        confidence_basis.is_some() ^ !source_confidence.is_empty(),
        "every confidence must be either a non-empty engine value or a disclosed derivation"
    );
    if let Some(code) = confidence_basis {
        debug_assert!(!confidence_basis_text(code).is_empty());
        debug_assert!(
            crate::finding_narrative::confidence_basis_zh_hant(code)
                .chars()
                .any(|character| ('\u{3400}'..='\u{9fff}').contains(&character)),
            "every derived confidence basis must have a Chinese form"
        );
    }
    SourceRecord {
        pointer: safe_text(&draft.pointer, MAX_SHORT_TEXT),
        rule_id: safe_text(&draft.rule_id, MAX_SHORT_TEXT),
        mapping_source_rule,
        rule_identity,
        title: safe_text(&draft.title, MAX_SHORT_TEXT),
        severity,
        source_severity,
        severity_basis,
        location: redact_location(&draft.location),
        asset_hint: draft
            .asset_hint
            .map(|value| safe_text(&value, MAX_SHORT_TEXT)),
        asset_provider: None,
        confidence,
        source_confidence,
        confidence_basis,
        evidence_kind: draft.evidence_kind,
        scanner_details: None,
        references: draft.references,
        tags: draft.tags,
    }
}

fn exact_mapping_source_rule(value: &str) -> Option<String> {
    if value.is_empty()
        || value.chars().count() > MAX_SHORT_TEXT
        || value.trim() != value
        || value.chars().any(char::is_control)
    {
        None
    } else {
        Some(value.to_owned())
    }
}

fn mapping_control_references(
    engine_id: &str,
    mapping_source_rule: Option<&str>,
    ai_system_applicable: bool,
    ai_generated_artifact_applicable: bool,
) -> Vec<crate::domain::ControlReference> {
    mapping_source_rule
        .map(|source_rule| {
            control_mapping::lookup(
                engine_id,
                source_rule,
                ai_system_applicable,
                ai_generated_artifact_applicable,
            )
        })
        .unwrap_or_default()
}

fn resolve_asset(
    record: &SourceRecord,
    allowed_assets: &[String],
    asset_identifier_map: &crate::adapter::AdapterAssetIdentifierMap,
    warnings: &mut Vec<String>,
    unmatched_identifiers: &mut BTreeMap<(String, String), usize>,
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
        if let Some(provider) = &record.asset_provider {
            push_warning(
                warnings,
                format!(
                    "record {} had no exact authorized provider identifier match and was not normalized",
                    safe_text(&record.rule_id, 120)
                ),
            );
            // Bounded because both halves come from the scanned artifact.
            // Beyond the cap the counts stay accurate for what is already
            // tracked rather than growing without limit on hostile input.
            let key = (
                safe_text(provider, 60).to_ascii_lowercase(),
                safe_text(hint, 120),
            );
            if unmatched_identifiers.len() < MAX_UNMATCHED_IDENTIFIERS
                || unmatched_identifiers.contains_key(&key)
            {
                *unmatched_identifiers.entry(key).or_insert(0) += 1;
            }
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

pub(crate) fn stable_evidence_id(
    fingerprint: &str,
    engine_id: &str,
    source_rule: &str,
    artifact_hash: &str,
    result_pointer_sha256: &str,
    engine_run_id: &str,
) -> String {
    let mut hasher = Sha256::new();
    for component in [
        "ai-security-scanner.evidence-id",
        EVIDENCE_ID_SCHEMA_VERSION,
        fingerprint,
        engine_id,
        source_rule,
        artifact_hash,
        result_pointer_sha256,
        engine_run_id,
    ] {
        hasher.update(component.as_bytes());
        hasher.update([0]);
    }
    format!("evidence-{}", &hex::encode(hasher.finalize())[..32])
}

fn parse_severity(value: &str) -> Severity {
    let normalized = value.trim().to_ascii_lowercase();
    if let Ok(score) = normalized.parse::<f64>() {
        return if !score.is_finite() || !(0.0..=10.0).contains(&score) {
            Severity::Unknown
        } else if score >= 9.0 {
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
        // ScoutSuite grades every rule `danger` or `warning`; 125 of its 197
        // default AWS rules are `danger`, so leaving it unmapped sent the
        // majority of that engine's output to `Unknown`.
        "high" | "error" | "danger" => Severity::High,
        "medium" | "moderate" | "warning" | "warn" => Severity::Medium,
        "low" | "minor" => Severity::Low,
        "informational" | "info" | "log" | "none" | "negligible" => Severity::Informational,
        _ => Severity::Unknown,
    }
}

fn parse_confidence(value: &str) -> Confidence {
    let normalized = value.trim().to_ascii_lowercase();
    if let Ok(score) = normalized.parse::<u8>() {
        return match score {
            80..=100 => Confidence::High,
            50..=79 => Confidence::Medium,
            _ => Confidence::Low,
        };
    }
    match normalized.as_str() {
        "confirmed" => Confidence::Confirmed,
        "high" => Confidence::High,
        "medium" | "moderate" => Confidence::Medium,
        "low" => Confidence::Low,
        // Confidence has no Unknown variant. Preserve the engine's raw word in
        // source_confidence and fail closed at the lowest canonical band.
        _ => Confidence::Low,
    }
}

fn priority_for(severity: &Severity) -> u8 {
    match severity {
        Severity::Critical => 95,
        Severity::High => 80,
        Severity::Medium => 60,
        Severity::Low => 35,
        // Unknown impact stays above a known informational observation so it
        // is not buried as low risk, while never pretending to be Low/Medium.
        Severity::Unknown => 20,
        Severity::Informational => 15,
    }
}

fn severity_label(severity: &Severity) -> &'static str {
    match severity {
        Severity::Critical => "critical",
        Severity::High => "high",
        Severity::Medium => "medium",
        Severity::Low => "low",
        Severity::Unknown => "unknown",
        Severity::Informational => "informational",
    }
}

fn confidence_label(confidence: &Confidence) -> &'static str {
    match confidence {
        Confidence::Low => "low",
        Confidence::Medium => "medium",
        Confidence::High => "high",
        Confidence::Confirmed => "confirmed",
    }
}

/// The English article that precedes a severity label.
///
/// `informational` and `unknown` both open with a vowel sound, so the fixed
/// "a" this sentence used to carry produced "reported a informational-severity
/// condition" — on the first line of the first thing a beginner reads about a
/// finding. Matched on the variant rather than sniffed from the first letter so
/// that adding a severity forces the choice instead of inheriting a wrong one.
fn severity_article(severity: &Severity) -> &'static str {
    match severity {
        Severity::Critical | Severity::High | Severity::Medium | Severity::Low => "a",
        Severity::Informational | Severity::Unknown => "an",
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

/// The family whose sentences this profile's findings are composed from.
///
/// The single grouping [`impact_for`] and [`remedy_for`] both switch on, named
/// once so a localized client can reach the same nine cases without matching on
/// twenty-one engine profiles it has no other reason to know about.
fn family_for(profile: Profile) -> FindingFamily {
    match profile {
        Profile::CloudQuery | Profile::Steampipe | Profile::Prowler | Profile::ScoutSuite => {
            FindingFamily::CloudPosture
        }
        Profile::Cloudsplaining => FindingFamily::CloudIdentity,
        Profile::ScubaGear | Profile::Maester => FindingFamily::Microsoft365,
        Profile::Naabu | Profile::Httpx | Profile::Nuclei | Profile::Greenbone => {
            FindingFamily::NetworkExposure
        }
        Profile::Semgrep => FindingFamily::SourceCode,
        Profile::Gitleaks | Profile::Trufflehog => FindingFamily::Secret,
        Profile::Checkov | Profile::Kics => FindingFamily::InfrastructureAsCode,
        Profile::Trivy | Profile::Grype | Profile::Syft => FindingFamily::VulnerableComponent,
        Profile::Kubescape | Profile::KubeBench => FindingFamily::Kubernetes,
    }
}

/// The kind of change that actually resolves this family of finding.
///
/// This clause completes the one sentence in a finding that tells a reader what
/// to do, so it has to name the right action. It was a fixed "a least-privilege
/// configuration or code change" for all twenty-one engines: correct for a
/// permissive IAM policy, and wrong in a way a beginner cannot detect for the
/// rest. Someone told that a leaked AWS key needs "a least-privilege
/// configuration change" goes looking for a permissions setting instead of
/// revoking the credential, and the key stays valid for however long that
/// takes. Someone told the same about `CVE-2024-2511` in openssl has no reason
/// to think the answer is an upgrade.
///
/// Grouped the way [`impact_for`] groups the same profiles, except that secret
/// scanners split away from Semgrep: the three share a consequence but not a
/// remedy, and the remedy is the half that is urgent.
fn remedy_for(profile: Profile) -> &'static str {
    match profile {
        Profile::CloudQuery | Profile::Steampipe | Profile::Prowler | Profile::ScoutSuite => {
            "a least-privilege change to the affected resource's configuration or policy"
        }
        Profile::Cloudsplaining => {
            "a narrower policy that grants only the actions the identity's role requires"
        }
        Profile::ScubaGear | Profile::Maester => {
            "a change to the Microsoft 365 tenant setting this control checks"
        }
        Profile::Naabu | Profile::Httpx | Profile::Nuclei | Profile::Greenbone => {
            "either a record of why this service is meant to be reachable, or a change that removes or restricts that exposure"
        }
        Profile::Semgrep => "a code change that removes the reported unsafe pattern",
        Profile::Gitleaks | Profile::Trufflehog => {
            "revocation and rotation of the exposed credential first, then its removal from the source and from the history that still carries it"
        }
        Profile::Checkov | Profile::Kics => {
            "a change to the infrastructure-as-code template, so that redeploying does not restore the reported setting"
        }
        Profile::Trivy | Profile::Grype | Profile::Syft => {
            "an upgrade to a fixed version of the affected component, or a recorded reason it cannot be upgraded yet"
        }
        Profile::Kubescape | Profile::KubeBench => {
            "a change to the workload or cluster setting this check names"
        }
    }
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

/// Rule identifiers need their exact scalar bytes until `RecordDraft` decides
/// whether they are eligible to become structured mapping proof. General UI
/// text uses `scalar_string`, which is intentionally lossy and must not be
/// reused for this purpose.
fn exact_nested_rule_scalar(value: &Value, path: &[&str]) -> Option<String> {
    let mut current = value;
    for segment in path {
        current = if let Ok(index) = segment.parse::<usize>() {
            current.as_array()?.get(index)?
        } else {
            current.get(*segment)?
        };
    }
    exact_rule_scalar(current)
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

fn exact_rule_scalar(value: &Value) -> Option<String> {
    match value {
        Value::String(value) => Some(value.clone()),
        Value::Number(value) => Some(value.to_string()),
        Value::Bool(value) => Some(value.to_string()),
        _ => None,
    }
}

fn string_any(object: &Map<String, Value>, keys: &[&str]) -> Option<String> {
    keys.iter()
        .find_map(|key| object.get(*key).and_then(scalar_string))
}

fn exact_rule_string_any(object: &Map<String, Value>, keys: &[&str]) -> Option<String> {
    keys.iter()
        .find_map(|key| object.get(*key).and_then(exact_rule_scalar))
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
        // JSON Pointer is case-sensitive and Trivy emits `References` on every
        // vulnerability. Without this the advisory links a user needs in order
        // to act are dropped while `PrimaryURL` alone survives.
        "/References",
        // KICS names the page documenting the query it just failed.
        "/query_url",
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

/// Where `container_runtime` bind-mounts the directory the user chose. Engines
/// are handed this path as their scan target, so their output names files under
/// it -- a location that does not exist on the user's machine. Imported rather
/// than repeated so the mount and the strip cannot drift apart.
use crate::container_runtime::CONTAINER_WORKSPACE_PATH;

/// Stands in for the scanned directory itself, matching the `"source-file"`
/// placeholder the extractors use when an engine names no path at all.
const SCANNED_DIRECTORY_LOCATION: &str = "scanned-directory";

fn redact_location(value: &str) -> String {
    let value = value.split(['?', '#']).next().unwrap_or(value);
    let normalized = value.replace('\\', "/");
    // Reported relative to the directory the user picked. Showing the mount
    // path instead would hand a beginner a filename they cannot open, and
    // reading it as their own filesystem would be wrong on every platform.
    let relative = match normalized.strip_prefix(CONTAINER_WORKSPACE_PATH) {
        Some("") | Some("/") => SCANNED_DIRECTORY_LOCATION,
        // Only a path *inside* the mount qualifies. `/workspaces/app.js` is an
        // unrelated directory and must not silently lose its first characters.
        Some(rest) if rest.starts_with('/') => rest.trim_start_matches('/'),
        _ => &normalized,
    };
    safe_text(relative, MAX_SHORT_TEXT)
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

    fn draft_with_rule(rule_id: &str) -> RecordDraft {
        RecordDraft {
            pointer: "/results/0".into(),
            rule_id: rule_id.into(),
            title: "Rule finding".into(),
            source_severity: "high".into(),
            derived_severity: None,
            location: "src/example.py".into(),
            asset_hint: Some("asset-1".into()),
            source_confidence: "HIGH".into(),
            derived_confidence: None,
            evidence_kind: EvidenceKind::SourceCode,
            references: vec![],
            tags: vec![],
        }
    }

    #[test]
    fn absent_or_unrecognized_severity_is_unknown_without_erasing_explicit_informational() {
        for value in ["", "unknown", "not-rated", "NaN", "-1", "11"] {
            assert_eq!(parse_severity(value), Severity::Unknown, "{value}");
        }
        for value in ["informational", "INFO", "log", "none", "negligible", "0"] {
            assert_eq!(parse_severity(value), Severity::Informational, "{value}");
        }
        assert_eq!(priority_for(&Severity::Unknown), 20);
        assert!(
            priority_for(&Severity::Unknown) > priority_for(&Severity::Informational),
            "unknown impact must not be buried as a known informational observation"
        );
    }

    #[test]
    fn scanner_details_are_bounded_and_control_clean() {
        let record = record_from_draft(draft_with_rule("example-rule"));
        let details = with_scanner_details(
            record,
            Some(format!(
                "description\0with\ncontrols{}",
                "x".repeat(MAX_LONG_TEXT * 2)
            )),
            Some("  review\tupstream guidance  ".into()),
            Some("1.0\r\n".into()),
            Some("1.1\u{7f}".into()),
        )
        .scanner_details
        .expect("non-empty scanner details");

        for value in [
            details.description.as_deref(),
            details.remediation.as_deref(),
            details.installed_version.as_deref(),
            details.fixed_version.as_deref(),
        ]
        .into_iter()
        .flatten()
        {
            assert!(!value.chars().any(char::is_control), "{value:?}");
        }
        assert!(
            details
                .description
                .as_deref()
                .is_some_and(|value| value.chars().count() <= MAX_LONG_TEXT)
        );
        assert_eq!(
            details.remediation.as_deref(),
            Some("review upstream guidance")
        );
        assert_eq!(details.installed_version.as_deref(), Some("1.0"));
        assert_eq!(details.fixed_version.as_deref(), Some("1.1"));
    }

    #[test]
    fn source_confidence_values_map_to_the_canonical_bands() {
        for (source, expected) in [
            ("HIGH", Confidence::High),
            ("MEDIUM", Confidence::Medium),
            ("LOW", Confidence::Low),
            ("95", Confidence::High),
            ("65", Confidence::Medium),
            ("25", Confidence::Low),
        ] {
            assert_eq!(parse_confidence(source), expected, "{source}");
        }
    }

    #[test]
    fn production_extractors_never_pass_a_bare_confidence_constant() {
        let production = include_str!("mod.rs")
            .split("#[cfg(test)]")
            .next()
            .expect("production module");
        // Any bare band, not just the High this change removed: a later
        // extractor that hardcodes Medium is the same defect wearing a
        // different number.
        for (index, line) in production.lines().enumerate() {
            // A whole line that is only a band and a comma is an argument
            // being passed; a `=>` on the line is a mapping arm, which is
            // where a deliberate band belongs.
            let trimmed = line.trim();
            assert!(
                !(trimmed.starts_with("Confidence::")
                    && trimmed.ends_with(',')
                    && !trimmed.contains("=>")),
                "bare extractor confidence `{trimmed}` at source line {}",
                index + 1
            );
        }
    }

    #[test]
    fn the_container_mount_prefix_is_stripped_without_eating_look_alike_paths() {
        // Engines are handed `/workspace` as their target, so their paths name
        // a directory the user does not have. Reporting the remainder keeps the
        // path true relative to the directory they chose.
        assert_eq!(
            redact_location("/workspace/deploy/.env.production"),
            "deploy/.env.production"
        );
        assert_eq!(redact_location("/workspace//src/app.js"), "src/app.js");
        // The mount root itself is the scanned directory, not an empty path.
        assert_eq!(redact_location("/workspace"), SCANNED_DIRECTORY_LOCATION);
        assert_eq!(redact_location("/workspace/"), SCANNED_DIRECTORY_LOCATION);

        // A prefix match is not a path match. These are unrelated directories
        // and must keep every character; a bare `strip_prefix` would turn the
        // first into `s/app.js` and quietly point at a file that never existed.
        assert_eq!(redact_location("/workspaces/app.js"), "/workspaces/app.js");
        assert_eq!(
            redact_location("/workspace-backup/app.js"),
            "/workspace-backup/app.js"
        );
        // Not anchored at the root, so not the mount.
        assert_eq!(
            redact_location("/srv/workspace/app.js"),
            "/srv/workspace/app.js"
        );
        // Windows separators are normalized first, so the strip still applies.
        assert_eq!(redact_location("\\workspace\\src\\app.js"), "src/app.js");
    }

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
        assert_eq!(EVIDENCE_ID_SCHEMA_VERSION, "v2");
        let first = stable_evidence_id(
            "fingerprint",
            "semgrep",
            "rule-1",
            "artifact",
            &"a".repeat(64),
            "engine-run-1",
        );
        let second = stable_evidence_id(
            "fingerprint",
            "semgrep",
            "rule-1",
            "artifact",
            &"a".repeat(64),
            "engine-run-2",
        );
        assert_ne!(first, second);
        assert_eq!(
            first,
            stable_evidence_id(
                "fingerprint",
                "semgrep",
                "rule-1",
                "artifact",
                &"a".repeat(64),
                "engine-run-1",
            )
        );
    }

    #[test]
    fn lossy_rule_display_text_never_becomes_mapping_proof() {
        const RULE: &str = "ai-security-scanner.python.dynamic-code-execution";
        let valid = record_from_draft(draft_with_rule(RULE));
        assert_eq!(valid.rule_id, RULE);
        assert_eq!(valid.mapping_source_rule.as_deref(), Some(RULE));
        assert!(
            !mapping_control_references(
                "semgrep",
                valid.mapping_source_rule.as_deref(),
                false,
                false,
            )
            .is_empty()
        );

        for raw_rule in [
            "ai-security-\0scanner.python.dynamic-code-execution".to_owned(),
            format!(" {RULE} "),
        ] {
            let invalid = record_from_draft(draft_with_rule(&raw_rule));
            // Both values sanitize to text that looks exactly like a reviewed
            // rule, but their raw bytes are not acceptable mapping evidence.
            assert_eq!(invalid.rule_id, RULE);
            assert!(invalid.mapping_source_rule.is_none());
            assert_ne!(invalid.rule_identity, RULE);
            assert!(
                mapping_control_references(
                    "semgrep",
                    invalid.mapping_source_rule.as_deref(),
                    true,
                    true,
                )
                .is_empty()
            );
        }
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
    fn only_wrapper_preserved_upstream_evidence_is_excluded() {
        assert!(is_preserved_upstream_evidence_path(
            "case/run/engine/attempt-1/output/upstream/scubagear-raw.json"
        ));
        assert!(is_preserved_upstream_evidence_path(
            "case/run/engine/attempt-7/output/upstream/nested/report.json"
        ));
        // The wrapper's own normalized document sits beside `upstream/`, not
        // inside it, and must still be normalized.
        assert!(!is_preserved_upstream_evidence_path(
            "case/run/engine/attempt-1/output/scubagear.json"
        ));
        assert!(!is_preserved_upstream_evidence_path(
            "case/run/engine/attempt-1/output/upstream.json"
        ));
        assert!(!is_preserved_upstream_evidence_path(
            "case/run/engine/attempt-one/output/upstream/report.json"
        ));
    }

    #[test]
    fn upstream_scubagear_control_key_is_not_normalized_beside_the_wrapper_document() {
        // Upstream ScubaGear spells the identifier `Control ID`, which the
        // adapter cannot read, so normalizing the preserved raw report emits a
        // warning per control and contributes nothing. Guard the exclusion with
        // the real upstream shape rather than a synthetic one.
        let upstream = serde_json::json!({
            "Results": [{
                "Control ID": "MS.AAD.1.1v1",
                "Requirement": "Legacy authentication SHALL be blocked.",
                "Result": "Fail",
                "Criticality": "Shall"
            }]
        });
        let mut warnings = Vec::new();
        let parsed = ParsedArtifact::Json(upstream);
        let records = extract_scubagear(&parsed, &mut warnings);
        assert!(
            records.is_empty(),
            "the upstream key must remain unreadable, otherwise this exclusion is unnecessary: {records:?}"
        );
        assert!(
            warnings
                .iter()
                .any(|warning| warning.contains("lacked a rule id")),
            "expected the misparse this exclusion exists to prevent, got: {warnings:?}"
        );
    }

    #[test]
    fn unevaluated_microsoft365_controls_are_disclosed_with_the_wrappers_own_counts() {
        let scubagear = ParsedArtifact::Json(serde_json::json!({
            "Diagnostics": { "passes": 30, "failures": 2, "warnings": 0, "errors": 1,
                             "manual": 20, "omitted": 5, "normalized_results": 32 }
        }));
        let unevaluated = unevaluated_controls(Profile::ScubaGear, &scubagear)
            .expect("a run with manual, omitted and errored controls discloses all three");
        let note = &unevaluated.disclosure;
        assert!(note.contains("20 reserved for manual review"), "{note}");
        assert!(note.contains("5 omitted by configuration"), "{note}");
        assert!(note.contains("1 could not be evaluated"), "{note}");
        // Passing controls are evaluated, so they are not a coverage shortfall.
        assert!(!note.contains("30"), "{note}");

        let maester = ParsedArtifact::Json(serde_json::json!({
            "Diagnostics": { "passes": 8, "failures": 1, "investigate": 0, "errors": 0,
                             "skipped": 3, "not_run": 0, "total": 12, "normalized_results": 9 }
        }));
        let unevaluated = unevaluated_controls(Profile::Maester, &maester)
            .expect("skipped tests are a coverage shortfall");
        let note = &unevaluated.disclosure;
        assert!(note.contains("3 skipped"), "{note}");
        assert!(!note.contains("not run"), "{note}");
    }

    #[test]
    fn only_controls_the_engine_could_not_evaluate_withhold_completion() {
        // Passed over by design or by the tenant's own config: the run is still
        // a complete scan of what it set out to check.
        let by_design = ParsedArtifact::Json(serde_json::json!({
            "Diagnostics": { "passes": 30, "failures": 2, "errors": 0,
                             "manual": 20, "omitted": 5, "normalized_results": 32 }
        }));
        let unevaluated = unevaluated_controls(Profile::ScubaGear, &by_design)
            .expect("a shortfall is still disclosed");
        assert!(
            !unevaluated.withholds_completion,
            "{}",
            unevaluated.disclosure
        );

        // Asked to check and could not: coverage was never established.
        let unevaluable = ParsedArtifact::Json(serde_json::json!({
            "Diagnostics": { "passes": 30, "failures": 2, "errors": 1,
                             "manual": 0, "omitted": 0, "normalized_results": 32 }
        }));
        assert!(
            unevaluated_controls(Profile::ScubaGear, &unevaluable)
                .expect("an unevaluable control is a shortfall")
                .withholds_completion
        );
        let maester_errors = ParsedArtifact::Json(serde_json::json!({
            "Diagnostics": { "passes": 8, "failures": 1, "errors": 2,
                             "skipped": 0, "not_run": 0, "normalized_results": 9 }
        }));
        assert!(
            unevaluated_controls(Profile::Maester, &maester_errors)
                .expect("an errored test is a shortfall")
                .withholds_completion
        );
    }

    #[test]
    fn every_severity_label_is_introduced_by_a_grammatical_article() {
        // Cross-checks two hand-written functions that have to agree. The
        // article match is exhaustive, so a new severity cannot compile without
        // being assigned one -- but nothing stops it being assigned the wrong
        // one, which is exactly how "a informational-severity condition"
        // shipped. Deriving the expectation from the label instead makes the
        // two disagree loudly.
        for severity in [
            Severity::Critical,
            Severity::High,
            Severity::Medium,
            Severity::Low,
            Severity::Informational,
            Severity::Unknown,
        ] {
            let label = severity_label(&severity);
            let expected = if label.starts_with(['a', 'e', 'i', 'o', 'u']) {
                "an"
            } else {
                "a"
            };
            assert_eq!(
                severity_article(&severity),
                expected,
                "\"reported {} {label}-severity condition\" is not English",
                severity_article(&severity)
            );
        }
    }

    #[test]
    fn verdicts_the_wrapper_dropped_are_disclosed_rather_than_read_as_a_clean_tenant() {
        // The scenario: upstream renames a verdict, the wrapper's `switch`
        // matches nothing, and every control is dropped by its `default { $null
        // }`. `normalized_results` still equals `Results.len()` -- the wrapper
        // counts the list it just built -- so the existing integrity check
        // holds. Without the engine's own counters the user is handed a
        // confident, completely empty tenant audit.
        let everything_dropped = ParsedArtifact::Json(serde_json::json!({
            "Diagnostics": { "passes": 300, "failures": 42, "investigate": 0, "errors": 0,
                             "skipped": 0, "not_run": 0, "total": 342, "normalized_results": 0 },
            "Results": []
        }));
        let unevaluated = unevaluated_controls(Profile::Maester, &everything_dropped)
            .expect("342 evaluated tests and no results is not a clean run");
        assert!(
            unevaluated
                .disclosure
                .contains("342 reported by the engine but not carried into results"),
            "{}",
            unevaluated.disclosure
        );
        assert!(
            unevaluated.withholds_completion,
            "a run that lost every verdict cannot be reported as complete"
        );

        // Partial loss counts too: 3 of 33 verdicts never became rows.
        let partially_dropped = ParsedArtifact::Json(serde_json::json!({
            "Diagnostics": { "passes": 30, "failures": 2, "warnings": 1, "errors": 0,
                             "manual": 0, "omitted": 0, "normalized_results": 30 }
        }));
        assert!(
            unevaluated_controls(Profile::ScubaGear, &partially_dropped)
                .expect("three lost verdicts are a shortfall")
                .withholds_completion
        );

        // A disputed control is judged on ScubaGear's own `OriginalResult` and
        // counted in `disputed` rather than `failures`, so it adds a row that
        // no verdict counter accounts for. That is a surplus, not a loss, and
        // must not be reported as one.
        let disputed_surplus = ParsedArtifact::Json(serde_json::json!({
            "Diagnostics": { "passes": 30, "failures": 2, "warnings": 0, "errors": 0,
                             "manual": 0, "omitted": 0, "disputed": 4, "normalized_results": 36 }
        }));
        assert!(
            unevaluated_controls(Profile::ScubaGear, &disputed_surplus).is_none(),
            "a disputed control resolving to a verdict is not a lost one"
        );
    }

    #[test]
    fn maester_total_discloses_controls_missing_from_every_reported_category() {
        let uncategorized = ParsedArtifact::Json(serde_json::json!({
            "Diagnostics": { "passes": 7, "failures": 1, "investigate": 1, "errors": 1,
                             "skipped": 1, "not_run": 1, "total": 15, "normalized_results": 9 }
        }));
        let unevaluated = unevaluated_controls(Profile::Maester, &uncategorized)
            .expect("three controls outside every reported category must be disclosed");
        assert!(
            unevaluated
                .disclosure
                .contains("3 not accounted for by any reported category"),
            "{}",
            unevaluated.disclosure
        );
    }

    #[test]
    fn maester_total_equal_to_all_reported_counters_adds_no_disclosure() {
        let fully_accounted = ParsedArtifact::Json(serde_json::json!({
            "Diagnostics": { "passes": 7, "failures": 1, "investigate": 1, "errors": 1,
                             "skipped": 1, "not_run": 1, "total": 12, "normalized_results": 9 }
        }));
        let unevaluated = unevaluated_controls(Profile::Maester, &fully_accounted)
            .expect("existing error, skipped, and not-run disclosures remain");
        assert!(
            !unevaluated
                .disclosure
                .contains("not accounted for by any reported category"),
            "{}",
            unevaluated.disclosure
        );
    }

    #[test]
    fn maester_without_total_preserves_older_document_behavior_exactly() {
        let older_document = ParsedArtifact::Json(serde_json::json!({
            "Diagnostics": { "passes": 8, "failures": 1, "investigate": 0, "errors": 0,
                             "skipped": 0, "not_run": 0, "normalized_results": 8 }
        }));
        let unevaluated = unevaluated_controls(Profile::Maester, &older_document)
            .expect("the pre-existing normalization shortfall still applies");
        assert_eq!(
            unevaluated.disclosure,
            "Maester did not evaluate every control in scope (1 reported by the engine but not carried into results); those controls are absent from findings and this run does not establish their state"
        );
        assert!(unevaluated.withholds_completion);
    }

    #[test]
    fn maester_counters_exceeding_total_saturate_without_a_false_shortfall() {
        let overlapping_counters = ParsedArtifact::Json(serde_json::json!({
            "Diagnostics": { "passes": 8, "failures": 2, "investigate": 1, "errors": 0,
                             "skipped": 0, "not_run": 0, "total": 10, "normalized_results": 11 }
        }));
        assert!(
            unevaluated_controls(Profile::Maester, &overlapping_counters).is_none(),
            "a counter surplus is not evidence of an uncategorized control"
        );
    }

    #[test]
    fn maester_uncategorized_controls_withhold_completion_because_their_state_is_unknown() {
        let uncategorized = ParsedArtifact::Json(serde_json::json!({
            "Diagnostics": { "passes": 8, "failures": 1, "investigate": 0, "errors": 0,
                             "skipped": 0, "not_run": 0, "total": 10, "normalized_results": 9 }
        }));
        assert!(
            unevaluated_controls(Profile::Maester, &uncategorized)
                .expect("the unaccounted control is a coverage gap")
                .withholds_completion,
            "an in-scope control with no reported category has no established state"
        );
    }

    #[test]
    fn a_microsoft365_run_that_evaluated_everything_is_not_qualified() {
        let complete = ParsedArtifact::Json(serde_json::json!({
            "Diagnostics": { "passes": 30, "failures": 2, "warnings": 0, "errors": 0,
                             "manual": 0, "omitted": 0, "normalized_results": 32 }
        }));
        assert!(unevaluated_controls(Profile::ScubaGear, &complete).is_none());
        // Upstream's own report has no wrapper accounting to read.
        let upstream = ParsedArtifact::Json(serde_json::json!({ "Results": [] }));
        assert!(unevaluated_controls(Profile::ScubaGear, &upstream).is_none());
        // The disclosure is specific to the wrappers that produce these counts.
        assert!(unevaluated_controls(Profile::Semgrep, &complete).is_none());
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
