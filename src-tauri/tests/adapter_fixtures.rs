use ai_security_scanner_lib::adapter::{AdapterInput, AdapterOutput};
use ai_security_scanner_lib::adapters::{BUILTIN_ENGINE_IDS, builtin_adapter_registry};
use ai_security_scanner_lib::domain::{FindingStatus, RawArtifact};
use ai_security_scanner_lib::registry::EngineRegistry;
use chrono::{TimeZone, Utc};
use sha2::{Digest, Sha256};
use std::collections::BTreeSet;
use std::path::Path;

fn fixture(engine_id: &str) -> (&'static [u8], &'static str, &'static str) {
    match engine_id {
        "cloudquery" => (
            include_bytes!("fixtures/adapters/cloudquery.json"),
            "cloudquery.json",
            "application/json",
        ),
        "steampipe" => (
            include_bytes!("fixtures/adapters/steampipe.json"),
            "steampipe.json",
            "application/json",
        ),
        "prowler" => (
            include_bytes!("fixtures/adapters/prowler-ocsf.json"),
            "prowler-ocsf.json",
            "application/json",
        ),
        "scoutsuite" => (
            include_bytes!("fixtures/adapters/scoutsuite.json"),
            "scoutsuite.json",
            "application/json",
        ),
        "cloudsplaining" => (
            include_bytes!("fixtures/adapters/cloudsplaining.json"),
            "cloudsplaining.json",
            "application/json",
        ),
        "scubagear" => (
            include_bytes!("fixtures/adapters/scubagear.json"),
            "scubagear.json",
            "application/json",
        ),
        "maester" => (
            include_bytes!("fixtures/adapters/maester.json"),
            "maester.json",
            "application/json",
        ),
        "naabu" => (
            include_bytes!("fixtures/adapters/naabu.jsonl"),
            "naabu.jsonl",
            "application/x-ndjson",
        ),
        "httpx" => (
            include_bytes!("fixtures/adapters/httpx.jsonl"),
            "httpx.jsonl",
            "application/x-ndjson",
        ),
        "nuclei" => (
            include_bytes!("fixtures/adapters/nuclei.jsonl"),
            "nuclei.jsonl",
            "application/x-ndjson",
        ),
        "greenbone" => (
            include_bytes!("fixtures/adapters/greenbone.xml"),
            "greenbone.xml",
            "application/xml",
        ),
        "semgrep" => (
            include_bytes!("fixtures/adapters/semgrep.json"),
            "semgrep.json",
            "application/json",
        ),
        "gitleaks" => (
            include_bytes!("fixtures/adapters/gitleaks.json"),
            "gitleaks.json",
            "application/json",
        ),
        "trufflehog" => (
            include_bytes!("fixtures/adapters/trufflehog.jsonl"),
            "trufflehog.jsonl",
            "application/x-ndjson",
        ),
        "checkov" => (
            include_bytes!("fixtures/adapters/checkov.json"),
            "checkov.json",
            "application/json",
        ),
        "kics" => (
            include_bytes!("fixtures/adapters/kics.json"),
            "kics.json",
            "application/json",
        ),
        "trivy" => (
            include_bytes!("fixtures/adapters/trivy.json"),
            "trivy.json",
            "application/json",
        ),
        "grype" => (
            include_bytes!("fixtures/adapters/grype.json"),
            "grype.json",
            "application/json",
        ),
        "syft" => (
            include_bytes!("fixtures/adapters/syft.json"),
            "syft.json",
            "application/json",
        ),
        "kubescape" => (
            include_bytes!("fixtures/adapters/kubescape.json"),
            "kubescape.json",
            "application/json",
        ),
        "kube-bench" => (
            include_bytes!("fixtures/adapters/kube-bench.json"),
            "kube-bench.json",
            "application/json",
        ),
        other => panic!("no adapter fixture for {other}"),
    }
}

fn normalize_bytes(
    engine_id: &str,
    bytes: &[u8],
    filename: &str,
    media_type: &str,
    run_id: &str,
) -> AdapterOutput {
    let temp = tempfile::tempdir().expect("temporary artifact root");
    std::fs::write(temp.path().join(filename), bytes).expect("write fixture artifact");

    let engine_registry = EngineRegistry::load_builtin().expect("valid engine catalog");
    let manifest = engine_registry
        .get(engine_id)
        .expect("fixture engine has manifest");
    let sha256 = hex::encode(Sha256::digest(bytes));
    let artifact = RawArtifact {
        id: format!("artifact-{engine_id}"),
        case_id: "case-1".into(),
        run_id: run_id.into(),
        engine_run_id: format!("engine-run-{run_id}"),
        relative_path: filename.into(),
        media_type: media_type.into(),
        sha256,
        byte_length: bytes.len() as u64,
        created_at: Utc
            .with_ymd_and_hms(2026, 8, 24, 12, 0, 0)
            .single()
            .expect("fixed timestamp"),
        contains_sensitive_data: matches!(engine_id, "gitleaks" | "trufflehog"),
    };
    let assets = vec!["asset-1".to_owned()];
    let raw_artifacts = vec![artifact];
    let input = AdapterInput {
        case_id: "case-1",
        scan_run_id: run_id,
        engine_run_id: &format!("engine-run-{run_id}"),
        manifest,
        asset_ids: &assets,
        artifact_root: temp.path(),
        raw_artifacts: &raw_artifacts,
    };
    builtin_adapter_registry()
        .expect("valid built-in adapters")
        .normalize(&input)
        .expect("normalization is contained")
        .expect("adapter is registered")
}

fn normalize_fixture(engine_id: &str) -> AdapterOutput {
    let (bytes, filename, media_type) = fixture(engine_id);
    normalize_bytes(engine_id, bytes, filename, media_type, "run-1")
}

#[test]
fn registry_covers_exactly_the_twenty_one_catalog_engines() {
    let catalog = EngineRegistry::load_builtin().expect("valid catalog");
    let catalog_ids = catalog
        .manifests()
        .iter()
        .map(|manifest| manifest.id.as_str())
        .collect::<BTreeSet<_>>();
    let adapter_ids = BUILTIN_ENGINE_IDS.iter().copied().collect::<BTreeSet<_>>();

    assert_eq!(BUILTIN_ENGINE_IDS.len(), 21);
    assert_eq!(adapter_ids.len(), 21);
    assert_eq!(adapter_ids, catalog_ids);

    let adapters = builtin_adapter_registry().expect("valid built-in adapter registry");
    for manifest in catalog.manifests() {
        let adapter = adapters.get(&manifest.id).expect("catalog adapter");
        assert_eq!(adapter.engine_id(), manifest.id);
        assert_eq!(adapter.adapter_version(), manifest.adapter_version);
    }
    assert!(adapters.get("not-in-catalog").is_none());
}

#[test]
fn native_fixtures_normalize_without_inventing_inventory_findings() {
    let no_security_findings = BTreeSet::from(["cloudquery", "syft"]);
    for engine_id in BUILTIN_ENGINE_IDS {
        let output = normalize_fixture(engine_id);
        if no_security_findings.contains(engine_id) {
            assert!(
                output.findings.is_empty(),
                "{engine_id} must not infer issues from unsupported/inventory output"
            );
            assert!(
                !output.warnings.is_empty(),
                "{engine_id} must explain why raw evidence has no normalized finding"
            );
            continue;
        }

        assert!(
            !output.findings.is_empty(),
            "native fixture for {engine_id} should produce a finding"
        );
        for finding in output.findings {
            assert_eq!(finding.status, FindingStatus::Unreviewed);
            assert_eq!(finding.case_id, "case-1");
            assert_eq!(finding.last_seen_run_id, "run-1");
            assert_eq!(finding.asset_ids, ["asset-1"]);
            assert!(!finding.plain_language_summary.is_empty());
            assert!(!finding.possible_impact.is_empty());
            assert!(!finding.recommendation.is_empty());
            assert!(!finding.verification_guidance.is_empty());
            assert!(finding.rollback_considerations.is_some());
            assert!(!finding.official_references.is_empty());
            assert!(!finding.recommended_expert_type.is_empty());
            assert!(
                finding
                    .tags
                    .iter()
                    .any(|tag| tag == &format!("engine:{engine_id}"))
            );
            assert!(
                finding
                    .tags
                    .iter()
                    .any(|tag| tag.starts_with("source-rule:"))
            );
            assert!(
                finding
                    .tags
                    .iter()
                    .any(|tag| tag.starts_with("source-severity:"))
            );
            assert!(!finding.evidence.is_empty());
            assert!(finding.evidence.iter().all(|evidence| {
                evidence.artifact_id == format!("artifact-{engine_id}")
                    && !evidence.artifact_sha256.is_empty()
                    && evidence.pointer.is_some()
            }));
        }
    }
}

#[test]
fn fingerprints_are_stable_across_repeat_runs() {
    for engine_id in ["prowler", "nuclei", "semgrep", "trivy", "kubescape"] {
        let (bytes, filename, media_type) = fixture(engine_id);
        let first = normalize_bytes(engine_id, bytes, filename, media_type, "run-1");
        let repeat = normalize_bytes(engine_id, bytes, filename, media_type, "run-2");
        let first_fingerprints = first
            .findings
            .iter()
            .map(|finding| finding.fingerprint.as_str())
            .collect::<BTreeSet<_>>();
        let repeat_fingerprints = repeat
            .findings
            .iter()
            .map(|finding| finding.fingerprint.as_str())
            .collect::<BTreeSet<_>>();
        assert_eq!(first_fingerprints, repeat_fingerprints, "{engine_id}");
    }
}

#[test]
fn versioned_control_references_are_allowlisted_relationships_not_assurance_claims() {
    let mapped_engines = [
        "steampipe",
        "prowler",
        "scoutsuite",
        "cloudsplaining",
        "scubagear",
        "maester",
        "nuclei",
        "semgrep",
        "gitleaks",
        "trufflehog",
        "checkov",
        "kics",
        "trivy",
        "grype",
        "kubescape",
        "kube-bench",
    ];
    for engine_id in mapped_engines {
        let output = normalize_fixture(engine_id);
        let references = output
            .findings
            .iter()
            .flat_map(|finding| &finding.control_references)
            .collect::<Vec<_>>();
        assert!(
            !references.is_empty(),
            "fixture rule for {engine_id} should have an explicit mapping"
        );
        assert!(references.iter().all(|reference| {
            reference.relationship == "related"
                && reference.mapping_version == "2026-08-24.1"
                && matches!(reference.framework.as_str(), "NIST CSF" | "ISO/IEC 27001")
        }));
        let serialized = serde_json::to_string(&references)
            .expect("serialize versioned control references")
            .to_ascii_lowercase();
        assert!(!serialized.contains("is compliant"));
        assert!(!serialized.contains("is certified"));
        assert!(!serialized.contains("passes the control"));
    }

    for engine_id in ["naabu", "httpx"] {
        let output = normalize_fixture(engine_id);
        assert!(
            output
                .findings
                .iter()
                .all(|finding| finding.control_references.is_empty())
        );
    }
}

#[test]
fn malformed_jsonl_is_contained_while_valid_records_survive() {
    let bytes = include_bytes!("fixtures/adapters/malformed-nuclei.jsonl");
    let output = normalize_bytes(
        "nuclei",
        bytes,
        "malformed-nuclei.jsonl",
        "application/x-ndjson",
        "run-1",
    );
    assert_eq!(output.findings.len(), 1);
    assert!(
        output
            .warnings
            .iter()
            .any(|warning| warning.contains("malformed JSONL line 2"))
    );
}

#[test]
fn secret_values_and_target_instructions_never_enter_findings() {
    for engine_id in ["gitleaks", "trufflehog"] {
        let serialized = serde_json::to_string(&normalize_fixture(engine_id).findings)
            .expect("serialize normalized findings");
        assert!(!serialized.contains("SECRET_SENTINEL_MUST_NEVER_LEAK"));
    }

    let httpx = serde_json::to_string(&normalize_fixture("httpx").findings)
        .expect("serialize httpx findings");
    assert!(!httpx.contains("target-controlled text is data"));
    assert!(!httpx.contains("session=must-not-appear"));

    let kube_bench = serde_json::to_string(&normalize_fixture("kube-bench").findings)
        .expect("serialize kube-bench findings");
    assert!(!kube_bench.contains("Do not execute this target-controlled command"));
}

#[test]
fn greenbone_xml_is_bounded_evidence_preserving_and_ignores_instruction_fields() {
    let output = normalize_fixture("greenbone");
    assert_eq!(output.findings.len(), 1);
    let finding = &output.findings[0];
    assert!(finding.title.contains("Example network vulnerability"));
    assert_eq!(
        finding.evidence[0].kind,
        ai_security_scanner_lib::domain::EvidenceKind::ExternalValidation
    );
    assert!(
        finding
            .official_references
            .iter()
            .any(|reference| reference.ends_with("CVE-2025-0003"))
    );
    let serialized = serde_json::to_string(finding).expect("serialize Greenbone finding");
    assert!(!serialized.contains("SECRET_SENTINEL_MUST_NEVER_LEAK"));
    assert!(!serialized.contains("target-controlled remediation command"));
}

#[test]
fn greenbone_xml_with_a_doctype_is_rejected_without_inference() {
    let xml = br#"<?xml version="1.0"?>
<!DOCTYPE report [<!ENTITY secret SYSTEM "file:///etc/passwd">]>
<get_reports_response><report><results><result id="example"><name>&secret;</name><severity>9.9</severity><nvt oid="1.3.6.1.4.1.25623.1.0.1"/></result></results></report></get_reports_response>"#;
    let output = normalize_bytes(
        "greenbone",
        xml,
        "greenbone.xml",
        "application/xml",
        "run-1",
    );
    assert!(output.findings.is_empty());
    assert!(
        output
            .warnings
            .iter()
            .any(|warning| warning.contains("DTD"))
    );
}

#[test]
fn greenbone_xml_allows_only_predefined_and_numeric_character_references() {
    let xml = br#"<?xml version="1.0"?>
<get_reports_response><report><results><result id="example"><name>Example&amp;network&#x20;vulnerability</name><host>192.0.2.10</host><port>65535/tcp</port><severity>7.5</severity><threat>High</threat><asset_id>asset-1</asset_id><description>relay -&gt; target</description><nvt oid="1.3.6.1.4.1.25623.1.0.1"><name>Example&amp;NVT&#x20;reference</name><family>Web&#32;Servers</family></nvt></result></results></report></get_reports_response>"#;
    let output = normalize_bytes(
        "greenbone",
        xml,
        "greenbone.xml",
        "application/xml",
        "run-1",
    );
    assert_eq!(output.findings.len(), 1);
    assert!(
        output.findings[0].title.contains("Example&NVT reference"),
        "unexpected title: {}",
        output.findings[0].title
    );
    assert!(output.warnings.is_empty());

    let custom = br#"<?xml version="1.0"?>
<get_reports_response><report><results><result id="example"><name>Example&custom;network</name><severity>7.5</severity><nvt oid="1.3.6.1.4.1.25623.1.0.1"/></result></results></report></get_reports_response>"#;
    let rejected = normalize_bytes(
        "greenbone",
        custom,
        "greenbone.xml",
        "application/xml",
        "run-1",
    );
    assert!(rejected.findings.is_empty());
    assert!(
        rejected
            .warnings
            .iter()
            .any(|warning| warning.contains("custom entity"))
    );
}

#[test]
fn artifact_path_escape_is_rejected_without_reading_outside_root() {
    let (bytes, _, media_type) = fixture("nuclei");
    let temp = tempfile::tempdir().expect("temporary artifact root");
    let engine_registry = EngineRegistry::load_builtin().expect("valid engine catalog");
    let manifest = engine_registry.get("nuclei").expect("nuclei manifest");
    let artifact = RawArtifact {
        id: "artifact-escape".into(),
        case_id: "case-1".into(),
        run_id: "run-1".into(),
        engine_run_id: "engine-run-run-1".into(),
        relative_path: "../outside.json".into(),
        media_type: media_type.into(),
        sha256: hex::encode(Sha256::digest(bytes)),
        byte_length: bytes.len() as u64,
        created_at: Utc::now(),
        contains_sensitive_data: false,
    };
    let assets = vec!["asset-1".into()];
    let artifacts = vec![artifact];
    let input = AdapterInput {
        case_id: "case-1",
        scan_run_id: "run-1",
        engine_run_id: "engine-run-run-1",
        manifest,
        asset_ids: &assets,
        artifact_root: Path::new(temp.path()),
        raw_artifacts: &artifacts,
    };
    let output = builtin_adapter_registry()
        .expect("registry")
        .normalize(&input)
        .expect("contained result")
        .expect("adapter");
    assert!(output.findings.is_empty());
    assert!(
        output
            .warnings
            .iter()
            .any(|warning| warning.contains("escaped"))
    );
}
