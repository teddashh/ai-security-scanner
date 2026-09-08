use ai_security_scanner_lib::adapter::{AdapterAssetIdentifierMap, AdapterInput, AdapterOutput};
use ai_security_scanner_lib::adapters::{BUILTIN_ENGINE_IDS, builtin_adapter_registry};
use ai_security_scanner_lib::correlation::correlation_report;
use ai_security_scanner_lib::domain::{
    AssessmentCase, Asset, AssetIdentifier, AssetKind, Confidence, ConfidenceBasisCode, DataClass,
    Finding, FindingFamily, FindingStatus, InventoryObservationKind, OrganizationProfile,
    RawArtifact, Severity, SeverityBasisCode,
};
use ai_security_scanner_lib::finding_narrative::{
    ENGLISH_EXPOSURE_OBSERVATION_REASON, ENGLISH_ROLLBACK, expert_type_zh_hant,
    priority_reason_zh_hant, rollback_zh_hant, verification_zh_hant,
};
use ai_security_scanner_lib::registry::EngineRegistry;
use chrono::{TimeZone, Utc};
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet};
use std::path::Path;

fn fixture(engine_id: &str) -> (&'static [u8], &'static str, &'static str) {
    match engine_id {
        "cloudquery" => (
            include_bytes!("fixtures/adapters/cloudquery.json"),
            "aws_iam_users.json",
            "application/x-ndjson",
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
    let assets = if matches!(engine_id, "cloudquery" | "prowler") {
        vec![authorized_asset(
            "asset-1",
            AssetKind::CloudAccount,
            Some("aws"),
            &[("aws_account_id", "123456789012")],
        )]
    } else {
        vec![authorized_asset("asset-1", AssetKind::Other, None, &[])]
    };
    normalize_bytes_with_assets(engine_id, bytes, filename, media_type, run_id, &assets)
}

fn normalize_bytes_with_assets(
    engine_id: &str,
    bytes: &[u8],
    filename: &str,
    media_type: &str,
    run_id: &str,
    assets: &[Asset],
) -> AdapterOutput {
    normalize_bytes_with_assets_and_context(
        engine_id,
        media_type,
        bytes,
        filename,
        run_id,
        assets,
        FrameworkApplicability::default(),
    )
}

#[derive(Clone, Copy, Default)]
struct FrameworkApplicability {
    ai_system: bool,
    ai_generated_artifact: bool,
}

fn normalize_bytes_with_assets_and_context(
    engine_id: &str,
    media_type: &str,
    bytes: &[u8],
    filename: &str,
    run_id: &str,
    assets: &[Asset],
    applicability: FrameworkApplicability,
) -> AdapterOutput {
    let temp = tempfile::tempdir().expect("temporary artifact root");
    let artifact_path = temp.path().join(filename);
    // `filename` becomes the artifact's `relative_path`, so a test that cares
    // where inside a run an artifact sits passes a nested path here.
    if let Some(parent) = artifact_path.parent() {
        std::fs::create_dir_all(parent).expect("artifact parent directory");
    }
    std::fs::write(&artifact_path, bytes).expect("write fixture artifact");

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
    let asset_ids = assets
        .iter()
        .map(|asset| asset.id.clone())
        .collect::<Vec<_>>();
    let asset_identifier_map = AdapterAssetIdentifierMap::from_assets(assets);
    let raw_artifacts = vec![artifact];
    let engine_run_id = format!("engine-run-{run_id}");
    let input = AdapterInput {
        case_id: "case-1",
        scan_run_id: run_id,
        engine_run_id: &engine_run_id,
        manifest,
        ai_system_applicable: applicability.ai_system,
        ai_generated_artifact_applicable: applicability.ai_generated_artifact,
        asset_ids: &asset_ids,
        asset_identifier_map: &asset_identifier_map,
        artifact_root: temp.path(),
        raw_artifacts: &raw_artifacts,
    };
    builtin_adapter_registry()
        .expect("valid built-in adapters")
        .normalize(&input)
        .expect("normalization is contained")
        .expect("adapter is registered")
}

fn authorized_asset(
    id: &str,
    kind: AssetKind,
    provider: Option<&str>,
    identifiers: &[(&str, &str)],
) -> Asset {
    Asset {
        id: id.into(),
        kind,
        name: id.into(),
        provider: provider.map(str::to_owned),
        region: None,
        identifiers: identifiers
            .iter()
            .map(|(namespace, value)| AssetIdentifier {
                namespace: (*namespace).into(),
                value: (*value).into(),
            })
            .collect(),
        discovered_from: vec![],
        candidate: false,
        owner_confirmed: true,
        internet_exposed: None,
        contains_sensitive_data: None,
        metadata: BTreeMap::new(),
    }
}

fn normalize_fixture(engine_id: &str) -> AdapterOutput {
    let (bytes, filename, media_type) = fixture(engine_id);
    normalize_bytes(engine_id, bytes, filename, media_type, "run-1")
}

fn normalize_ai_system_fixture(engine_id: &str) -> AdapterOutput {
    let (bytes, filename, media_type) = fixture(engine_id);
    let assets = if engine_id == "prowler" {
        vec![authorized_asset(
            "asset-1",
            AssetKind::CloudAccount,
            Some("aws"),
            &[("aws_account_id", "123456789012")],
        )]
    } else {
        vec![authorized_asset("asset-1", AssetKind::Other, None, &[])]
    };
    normalize_bytes_with_assets_and_context(
        engine_id,
        media_type,
        bytes,
        filename,
        "run-ai-1",
        &assets,
        FrameworkApplicability {
            ai_system: true,
            ai_generated_artifact: false,
        },
    )
}

fn normalize_ai_generated_fixture(engine_id: &str) -> AdapterOutput {
    let (bytes, filename, media_type) = fixture(engine_id);
    let assets = vec![authorized_asset("asset-1", AssetKind::Other, None, &[])];
    normalize_bytes_with_assets_and_context(
        engine_id,
        media_type,
        bytes,
        filename,
        "run-ai-generated-1",
        &assets,
        FrameworkApplicability {
            ai_system: false,
            ai_generated_artifact: true,
        },
    )
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

/// Engines that emit no severity anywhere in their output, with the rating this
/// product derives and the basis it has to disclose.
///
/// Each of these was previously handed a hard-coded severity string, which
/// reached the user as `source-severity:high` or `source-severity:informational`
/// — a rating the engine never gave. Verified against the pinned checkouts: the
/// word "severity" does not appear in gitleaks' Go sources at all;
/// TruffleHog's JSON printer marshals a fixed struct with no such field, and
/// kube-bench's `Check` struct has none. Naabu and HTTPx inventory no longer
/// enters the finding severity pipeline.
const DERIVED_SEVERITY_ENGINES: &[(&str, Severity, &str)] = &[
    (
        "kube-bench",
        Severity::High,
        "a failed CIS Kubernetes Benchmark check",
    ),
    (
        "gitleaks",
        Severity::High,
        "a secret pattern match in scanned source",
    ),
    (
        "trufflehog",
        Severity::High,
        "a credential detector match that this product does not verify",
    ),
    // Steampipe is the odd one: its output does carry a `severity` column, and
    // reading it was still circular, because the value is a literal this
    // product's own fixed query writes. The fixture keeps the column so this
    // proves the adapter ignores it rather than merely never seeing it.
    (
        "steampipe",
        Severity::High,
        "a failed IAM control from this product's own fixed query",
    ),
];

#[test]
fn engines_that_emit_no_severity_disclose_that_the_rating_is_this_products_own() {
    for (engine_id, expected_severity, expected_basis) in DERIVED_SEVERITY_ENGINES {
        let output = normalize_fixture(engine_id);
        assert!(
            !output.findings.is_empty(),
            "{engine_id} fixture produced nothing to check"
        );
        for finding in &output.findings {
            let exposure_observation = finding
                .severity_basis_code
                .is_some_and(|code| code.is_exposure_observation());
            assert_eq!(
                finding.severity, *expected_severity,
                "{engine_id} finding {} was rated {:?}",
                finding.id, finding.severity
            );
            assert!(
                finding
                    .tags
                    .iter()
                    .any(|tag| tag == "severity-basis:derived"),
                "{engine_id} finding {} hides that its rating is derived: {:?}",
                finding.id,
                finding.tags
            );
            assert!(
                !finding
                    .tags
                    .iter()
                    .any(|tag| tag.starts_with("source-severity:")),
                "{engine_id} finding {} claims a source severity the engine never emits: {:?}",
                finding.id,
                finding.tags
            );
            if exposure_observation {
                assert_eq!(finding.priority, 0);
                assert!(
                    finding
                        .priority_reasons
                        .iter()
                        .any(|reason| { reason == ENGLISH_EXPOSURE_OBSERVATION_REASON })
                );
                assert_eq!(
                    finding
                        .severity_basis_code
                        .map(ai_security_scanner_lib::finding_narrative::basis_english),
                    Some(*expected_basis)
                );
                assert!(
                    finding
                        .plain_language_summary
                        .contains("inventory evidence")
                );
                assert!(
                    finding
                        .plain_language_summary
                        .contains("not a vulnerability")
                );
            } else {
                assert!(
                    finding
                        .priority_reasons
                        .iter()
                        .any(|reason| reason.contains(expected_basis)),
                    "{engine_id} finding {} does not name its basis {expected_basis:?}: {:?}",
                    finding.id,
                    finding.priority_reasons
                );
                assert!(
                    finding.plain_language_summary.contains("without rating it"),
                    "{engine_id} finding {} reads as though the engine rated it: {}",
                    finding.id,
                    finding.plain_language_summary
                );
            }
        }
    }
}

/// Engines that report a severity for some findings and none for others, so
/// neither blanket rule applies. Each has its own test; this list exists to keep
/// them out of the two that assert one behaviour for every finding.
const MIXED_SEVERITY_ENGINES: &[&str] = &["checkov"];

/// Every finding-producing fixture whose engine supplies no confidence rating.
/// The code is grounded in the result shape the corresponding extractor reads,
/// not in an inferred upstream field that is absent from the fixture.
const DERIVED_CONFIDENCE_ENGINES: &[(&str, Confidence, ConfidenceBasisCode)] = &[
    (
        "prowler",
        Confidence::High,
        ConfidenceBasisCode::DeterministicPolicyEvaluation,
    ),
    (
        "scoutsuite",
        Confidence::High,
        ConfidenceBasisCode::DeterministicPolicyEvaluation,
    ),
    (
        "cloudsplaining",
        Confidence::High,
        ConfidenceBasisCode::DeterministicPolicyEvaluation,
    ),
    (
        "scubagear",
        Confidence::High,
        ConfidenceBasisCode::DeterministicPolicyEvaluation,
    ),
    (
        "maester",
        Confidence::High,
        ConfidenceBasisCode::DeterministicPolicyEvaluation,
    ),
    (
        "nuclei",
        Confidence::Medium,
        ConfidenceBasisCode::TemplateMatcher,
    ),
    (
        "gitleaks",
        Confidence::Low,
        ConfidenceBasisCode::UnverifiedPatternOrDetectorMatch,
    ),
    (
        "trufflehog",
        Confidence::Low,
        ConfidenceBasisCode::UnverifiedPatternOrDetectorMatch,
    ),
    (
        "checkov",
        Confidence::High,
        ConfidenceBasisCode::DeterministicPolicyEvaluation,
    ),
    (
        "kics",
        Confidence::High,
        ConfidenceBasisCode::DeterministicPolicyEvaluation,
    ),
    (
        "trivy",
        Confidence::Medium,
        ConfidenceBasisCode::AdvisoryVersionMatch,
    ),
    (
        "grype",
        Confidence::Medium,
        ConfidenceBasisCode::AdvisoryVersionMatch,
    ),
    (
        "kubescape",
        Confidence::High,
        ConfidenceBasisCode::DeterministicPolicyEvaluation,
    ),
    (
        "kube-bench",
        Confidence::High,
        ConfidenceBasisCode::DeterministicPolicyEvaluation,
    ),
    (
        "steampipe",
        Confidence::High,
        ConfidenceBasisCode::DeterministicPolicyEvaluation,
    ),
];

#[test]
fn engines_without_confidence_disclose_this_products_basis() {
    for (engine_id, expected_confidence, expected_code) in DERIVED_CONFIDENCE_ENGINES {
        let output = normalize_fixture(engine_id);
        assert!(
            !output.findings.is_empty(),
            "{engine_id} fixture produced nothing to check"
        );
        for finding in &output.findings {
            let exposure_observation = finding
                .severity_basis_code
                .is_some_and(|code| code.is_exposure_observation());
            assert_eq!(&finding.confidence, expected_confidence, "{engine_id}");
            assert_eq!(
                finding.confidence_basis_code,
                Some(*expected_code),
                "{engine_id} finding {}",
                finding.id
            );
            assert!(
                finding
                    .tags
                    .iter()
                    .any(|tag| tag == "confidence-basis:derived"),
                "{engine_id}: {:?}",
                finding.tags
            );
            assert!(
                !finding
                    .tags
                    .iter()
                    .any(|tag| tag.starts_with("source-confidence:")),
                "{engine_id} claims an engine confidence: {:?}",
                finding.tags
            );
            let basis = ai_security_scanner_lib::finding_narrative::confidence_basis_english(
                *expected_code,
            );
            if exposure_observation {
                assert_eq!(finding.priority, 0);
                assert!(
                    finding
                        .plain_language_summary
                        .contains("inventory evidence")
                );
            } else {
                assert!(finding.priority_reasons.iter().any(|reason| {
                    reason
                        == &format!(
                            "Confidence derived from {basis}; {} reports no confidence of its own.",
                            normalize_engine_display_name(engine_id)
                        )
                }));
                assert!(
                    finding
                        .plain_language_summary
                        .contains("reported no confidence rating for it"),
                    "{engine_id}: {}",
                    finding.plain_language_summary
                );
                assert!(
                    finding.plain_language_summary.contains(basis),
                    "{engine_id}: {}",
                    finding.plain_language_summary
                );
            }
        }
    }
}

fn normalize_engine_display_name(engine_id: &str) -> String {
    let registry = EngineRegistry::load_builtin().expect("valid engine catalog");
    registry
        .get(engine_id)
        .expect("fixture engine")
        .display_name
        .clone()
}

#[test]
fn semgrep_reads_the_fixture_confidence_verbatim() {
    let output = normalize_fixture("semgrep");
    assert_eq!(output.findings.len(), 1);
    let finding = &output.findings[0];
    assert_eq!(finding.confidence, Confidence::High);
    assert_eq!(finding.confidence_basis_code, None);
    assert!(
        finding
            .tags
            .iter()
            .any(|tag| tag == "source-confidence:high"),
        "{:?}",
        finding.tags
    );
    assert!(
        finding
            .priority_reasons
            .iter()
            .any(|reason| reason == "Source confidence: HIGH")
    );
    assert!(finding.plain_language_summary.contains("confidence HIGH"));
}

#[test]
fn semgrep_without_a_source_confidence_is_an_unverified_low_confidence_match() {
    let bytes = br#"{
      "results": [{
        "check_id": "example.rule",
        "path": "src/example.py",
        "extra": {"message": "Pattern matched", "severity": "ERROR"},
        "asset_id": "asset-1"
      }]
    }"#;
    let output = normalize_bytes(
        "semgrep",
        bytes,
        "semgrep-no-confidence.json",
        "application/json",
        "run-semgrep-no-confidence",
    );
    assert_eq!(output.findings.len(), 1);
    let finding = &output.findings[0];
    assert_eq!(finding.confidence, Confidence::Low);
    assert_eq!(
        finding.confidence_basis_code,
        Some(ConfidenceBasisCode::UnverifiedPatternOrDetectorMatch)
    );
    assert!(
        !finding
            .tags
            .iter()
            .any(|tag| tag.starts_with("source-confidence:"))
    );
}

#[test]
fn trivy_confidence_follows_each_result_kind_instead_of_one_engine_default() {
    let bytes = br#"{
      "Results": [{
        "Target": "example:latest",
        "Vulnerabilities": [{
          "VulnerabilityID": "CVE-2026-0001",
          "PkgName": "libexample",
          "Severity": "HIGH",
          "Title": "Advisory match"
        }],
        "Misconfigurations": [{
          "ID": "CFG-1",
          "Severity": "HIGH",
          "Title": "Configuration failure"
        }],
        "Secrets": [{
          "RuleID": "SECRET-1",
          "Severity": "HIGH",
          "Title": "Secret pattern"
        }],
        "asset_id": "asset-1"
      }]
    }"#;
    let output = normalize_bytes(
        "trivy",
        bytes,
        "trivy-confidence-kinds.json",
        "application/json",
        "run-trivy-confidence-kinds",
    );
    assert_eq!(output.findings.len(), 3);
    let by_title = output
        .findings
        .iter()
        .map(|finding| (finding.title.as_str(), finding))
        .collect::<BTreeMap<_, _>>();
    for (title, confidence, basis) in [
        (
            "Advisory match",
            Confidence::Medium,
            ConfidenceBasisCode::AdvisoryVersionMatch,
        ),
        (
            "Configuration failure",
            Confidence::High,
            ConfidenceBasisCode::DeterministicPolicyEvaluation,
        ),
        (
            "Secret pattern",
            Confidence::Low,
            ConfidenceBasisCode::UnverifiedPatternOrDetectorMatch,
        ),
    ] {
        let finding = by_title[title];
        assert_eq!(finding.confidence, confidence, "{title}");
        assert_eq!(finding.confidence_basis_code, Some(basis), "{title}");
    }
}

#[test]
fn finding_written_before_confidence_basis_codes_still_loads_without_one() {
    let finding = normalize_fixture("gitleaks")
        .findings
        .into_iter()
        .next()
        .expect("fixture finding");
    let mut encoded = serde_json::to_value(finding).expect("serialize finding");
    encoded
        .as_object_mut()
        .expect("finding object")
        .remove("confidence_basis_code");
    let decoded: Finding = serde_json::from_value(encoded).expect("load legacy finding");
    assert_eq!(decoded.confidence_basis_code, None);
}

#[test]
fn greenbone_qod_bands_are_source_confidence_and_absence_is_derived() {
    let bytes = br#"<?xml version="1.0"?>
<get_reports_response><report><results>
  <result id="high"><name>High QoD</name><host>192.0.2.1</host><severity>5.0</severity><qod><value>95</value></qod><nvt oid="1.3.6.1.4.1.1"><name>High QoD</name></nvt></result>
  <result id="medium"><name>Medium QoD</name><host>192.0.2.2</host><severity>5.0</severity><qod><value>65</value></qod><nvt oid="1.3.6.1.4.1.2"><name>Medium QoD</name></nvt></result>
  <result id="low"><name>Low QoD</name><host>192.0.2.3</host><severity>5.0</severity><qod><value>25</value></qod><nvt oid="1.3.6.1.4.1.3"><name>Low QoD</name></nvt></result>
  <result id="absent"><name>Absent QoD</name><host>192.0.2.4</host><severity>5.0</severity><nvt oid="1.3.6.1.4.1.4"><name>Absent QoD</name></nvt></result>
</results></report></get_reports_response>"#;
    let output = normalize_bytes(
        "greenbone",
        bytes,
        "greenbone-qod.xml",
        "application/xml",
        "run-greenbone-qod",
    );
    assert!(output.complete, "{:?}", output.warnings);
    let by_title = output
        .findings
        .iter()
        .map(|finding| (finding.title.as_str(), finding))
        .collect::<BTreeMap<_, _>>();
    for (title, source, expected) in [
        ("High QoD", "95", Confidence::High),
        ("Medium QoD", "65", Confidence::Medium),
        ("Low QoD", "25", Confidence::Low),
    ] {
        let finding = by_title[title];
        assert_eq!(finding.confidence, expected, "{title}");
        assert_eq!(finding.confidence_basis_code, None, "{title}");
        assert!(
            finding
                .priority_reasons
                .iter()
                .any(|reason| reason == &format!("Source confidence: {source}"))
        );
    }
    let absent = by_title["Absent QoD"];
    assert_eq!(absent.confidence, Confidence::Medium);
    assert_eq!(
        absent.confidence_basis_code,
        Some(ConfidenceBasisCode::MissingDetectionQualityScore)
    );
    assert!(
        absent
            .priority_reasons
            .iter()
            .any(|reason| reason.contains("absence of a detection-quality score"))
    );
}

/// The other side of the same contract. Deriving a severity is only defensible
/// where the engine truly reports none, so an engine that does report one must
/// keep showing what it said.
#[test]
fn engines_that_report_a_severity_still_present_the_engines_own_rating() {
    let exempt = DERIVED_SEVERITY_ENGINES
        .iter()
        .map(|(engine_id, _, _)| *engine_id)
        .chain(MIXED_SEVERITY_ENGINES.iter().copied())
        .collect::<BTreeSet<_>>();
    let mut checked = 0;
    for engine_id in BUILTIN_ENGINE_IDS {
        if exempt.contains(engine_id) {
            continue;
        }
        for finding in normalize_fixture(engine_id).findings {
            assert!(
                !finding
                    .tags
                    .iter()
                    .any(|tag| tag == "severity-basis:derived"),
                "{engine_id} finding {} replaced a reported severity with a derived one: {:?}",
                finding.id,
                finding.tags
            );
            assert!(
                finding.tags.iter().any(|tag| {
                    tag.strip_prefix("source-severity:")
                        .is_some_and(|value| !value.is_empty())
                }),
                "{engine_id} finding {} reports no severity and no basis: {:?}",
                finding.id,
                finding.tags
            );
            checked += 1;
        }
    }
    assert!(
        checked >= 15,
        "expected the reporting engines' findings to be checked, saw {checked}"
    );
}

/// TruffleHog runs with `--no-verification`, and the engine short-circuits
/// before any detector performs its check, so `Verified` is always false. A
/// `verified:false` tag reads as "checked and rejected"; the finding says
/// verification was never attempted instead.
#[test]
fn trufflehog_findings_say_verification_was_not_attempted_rather_than_failed() {
    let output = normalize_fixture("trufflehog");
    assert!(!output.findings.is_empty());
    for finding in &output.findings {
        assert!(
            finding
                .tags
                .iter()
                .any(|tag| tag == "verification:not-attempted"),
            "{:?}",
            finding.tags
        );
        assert!(
            !finding.tags.iter().any(|tag| tag.starts_with("verified:")),
            "a never-performed check is reported as a failed one: {:?}",
            finding.tags
        );
        assert_ne!(
            finding.confidence,
            Confidence::Confirmed,
            "nothing was confirmed; verification did not run"
        );
    }
}

#[test]
fn native_fixtures_normalize_without_inventing_inventory_findings() {
    let inventory_engines = BTreeSet::from(["cloudquery", "syft", "naabu", "httpx"]);
    for engine_id in BUILTIN_ENGINE_IDS {
        let output = normalize_fixture(engine_id);
        assert!(
            output.complete,
            "native fixture for {engine_id} must normalize completely"
        );
        if inventory_engines.contains(engine_id) {
            assert!(
                output.findings.is_empty(),
                "{engine_id} must not put inventory into the finding pipeline"
            );
            assert!(
                !output.observations.is_empty(),
                "{engine_id} must retain its typed upstream inventory"
            );
            continue;
        }

        assert!(output.observations.is_empty(), "{engine_id}");
        assert!(
            !output.findings.is_empty(),
            "native fixture for {engine_id} should produce a finding"
        );
        for finding in output.findings {
            let exposure_observation = finding
                .severity_basis_code
                .is_some_and(|code| code.is_exposure_observation());
            assert_eq!(finding.status, FindingStatus::Unreviewed);
            assert_eq!(finding.case_id, "case-1");
            assert_eq!(finding.last_seen_run_id, "run-1");
            assert_eq!(finding.asset_ids, ["asset-1"]);
            assert!(!finding.plain_language_summary.is_empty());
            // The summary interpolates the severity, so the article in front of
            // it has to be chosen with it. "Nuclei reported a informational-
            // severity condition" was the first sentence a beginner read about
            // every unrated Nuclei result.
            for ungrammatical in [" a informational", " a unknown"] {
                assert!(
                    !finding.plain_language_summary.contains(ungrammatical),
                    "{engine_id} summary is not English: {}",
                    finding.plain_language_summary
                );
            }
            assert!(!finding.possible_impact.is_empty());
            assert!(!finding.recommendation.is_empty());
            if exposure_observation {
                assert_eq!(finding.priority, 0);
                assert!(
                    finding
                        .possible_impact
                        .contains("does not establish a vulnerability")
                );
                assert!(
                    finding
                        .recommendation
                        .starts_with("Confirm that the reachable service")
                );
                assert!(finding.recommendation.contains("applicable security check"));
                assert!(finding.rollback_considerations.is_none());
            } else {
                assert!(
                    finding
                        .recommendation
                        .starts_with("Have the recommended specialist (")
                );
                assert!(
                    finding
                        .recommendation
                        .contains(&format!("({})", finding.recommended_expert_type))
                );
                assert!(!finding.recommendation.contains("Have a Application"));
                assert!(finding.rollback_considerations.is_some());
            }
            assert!(!finding.verification_guidance.is_empty());
            // Deliberately not `!is_empty()`: `merge_finding` seeds this list
            // with the manifest's own repository URL before any engine
            // reference is considered, so an emptiness check here can never
            // fail -- it stays green with every JSON pointer deleted.
            assert!(
                finding
                    .official_references
                    .iter()
                    .all(|reference| reference.starts_with("https://")),
                "{engine_id} kept a reference that is not a plain https URL: {:?}",
                finding.official_references
            );
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
            // Every finding states where its severity came from, and states it
            // once: `source-severity:` when the engine rated it, or
            // `severity-basis:derived` when the engine emits no severity and
            // this product supplied one. Both at once would let a derived
            // rating be read as the engine's own.
            let reported = finding
                .tags
                .iter()
                .filter(|tag| tag.starts_with("source-severity:"))
                .count();
            let derived = finding
                .tags
                .iter()
                .filter(|tag| tag.as_str() == "severity-basis:derived")
                .count();
            assert_eq!(
                reported + derived,
                1,
                "{engine_id} finding {} has {reported} source-severity and {derived} derived tags",
                finding.id
            );
            let reported_confidence = finding
                .tags
                .iter()
                .filter(|tag| tag.starts_with("source-confidence:"))
                .count();
            let derived_confidence = finding
                .tags
                .iter()
                .filter(|tag| tag.as_str() == "confidence-basis:derived")
                .count();
            assert_eq!(
                reported_confidence + derived_confidence,
                1,
                "{engine_id} finding {} has {reported_confidence} source-confidence and {derived_confidence} derived tags",
                finding.id
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
fn inventory_fixtures_preserve_typed_upstream_facts_and_exact_provenance() {
    for engine_id in ["cloudquery", "syft", "naabu", "httpx"] {
        let output = normalize_fixture(engine_id);
        assert!(output.complete, "{engine_id}: {:?}", output.warnings);
        assert!(output.findings.is_empty(), "{engine_id}");
        assert!(!output.observations.is_empty(), "{engine_id}");
        for observation in &output.observations {
            assert_eq!(observation.case_id, "case-1");
            assert_eq!(observation.run_id, "run-1");
            assert_eq!(observation.engine_run_id, "engine-run-run-1");
            assert_eq!(observation.asset_id, "asset-1");
            assert_eq!(observation.engine_id, engine_id);
            assert_eq!(observation.artifact_id, format!("artifact-{engine_id}"));
            assert_eq!(observation.artifact_sha256.len(), 64);
            assert!(!observation.pointer.is_empty());
            assert!(!observation.pointer.chars().any(char::is_control));
            assert_eq!(
                observation.observed_at,
                Utc.with_ymd_and_hms(2026, 8, 24, 12, 0, 0).unwrap()
            );
        }
    }

    let cloudquery = normalize_fixture("cloudquery");
    assert!(matches!(
        &cloudquery.observations[0].kind,
        InventoryObservationKind::CloudResource {
            resource_type,
            native_id: Some(native_id),
            display_name: Some(display_name),
        } if resource_type == "aws_iam_users"
            && native_id == "arn:aws:iam::123456789012:user/example-user"
            && display_name == "example-user"
    ));
    let cloudquery_json = serde_json::to_string(&cloudquery.observations).unwrap();
    assert!(!cloudquery_json.contains("SECRET_SENTINEL_MUST_NEVER_LEAK"));
    assert!(!cloudquery_json.contains("MUST_NOT_BE_USED"));

    let syft = normalize_fixture("syft");
    assert!(matches!(
        &syft.observations[0].kind,
        InventoryObservationKind::SoftwareComponent {
            name,
            version: Some(version),
            package_type: Some(package_type),
            purl: Some(purl),
        } if name == "example-package"
            && version == "1.0"
            && package_type == "deb"
            && purl == "pkg:deb/debian/example-package@1.0"
    ));
    assert!(
        !serde_json::to_string(&syft.observations)
            .unwrap()
            .contains("SECRET_SENTINEL_MUST_NEVER_LEAK")
    );

    let naabu = normalize_fixture("naabu");
    assert_eq!(naabu.observations.len(), 2);
    assert!(naabu.observations.iter().any(|observation| matches!(
        &observation.kind,
        InventoryObservationKind::Service {
            endpoint,
            port: Some(443),
            transport: Some(transport),
            scheme: None,
            http_status: None,
            tls: Some(true),
        } if endpoint == "192.0.2.10" && transport == "tcp"
    )));

    let httpx = normalize_fixture("httpx");
    assert_eq!(httpx.observations.len(), 2);
    assert!(httpx.observations.iter().any(|observation| matches!(
        &observation.kind,
        InventoryObservationKind::Service {
            endpoint,
            port: Some(443),
            transport: Some(transport),
            scheme: Some(scheme),
            http_status: Some(200),
            ..
        } if endpoint == "192.0.2.11" && transport == "tcp" && scheme == "https"
    )));
    let httpx_json = serde_json::to_string(&httpx.observations).unwrap();
    for forbidden in [
        "/login",
        "session=must-not-appear",
        "target-controlled text is data",
        "SECRET_SENTINEL_MUST_NEVER_LEAK",
    ] {
        assert!(!httpx_json.contains(forbidden), "{httpx_json}");
    }
}

#[test]
fn inventory_schema_and_asset_boundaries_fail_closed_but_known_empty_shapes_complete() {
    for (engine_id, bytes, filename, media_type) in [
        (
            "cloudquery",
            br#"{}"#.as_slice(),
            "aws_s3_buckets.json",
            "application/x-ndjson",
        ),
        (
            "cloudquery",
            br#"{}"#.as_slice(),
            "aws_iam_users.json",
            "application/x-ndjson",
        ),
        ("syft", br#"{}"#.as_slice(), "syft.json", "application/json"),
    ] {
        let output = normalize_bytes(engine_id, bytes, filename, media_type, "run-invalid");
        assert!(!output.complete, "{engine_id}");
        assert!(output.findings.is_empty());
        assert!(output.observations.is_empty());
        assert!(!output.warnings.is_empty());
    }

    for (engine_id, bytes, filename, media_type) in [
        (
            "cloudquery",
            b"".as_slice(),
            "aws_iam_users.json",
            "application/x-ndjson",
        ),
        (
            "cloudquery",
            br#"[]"#.as_slice(),
            "aws_iam_users.json",
            "application/x-ndjson",
        ),
        (
            "syft",
            br#"{"artifacts":[]}"#.as_slice(),
            "syft.json",
            "application/json",
        ),
    ] {
        let output = normalize_bytes(engine_id, bytes, filename, media_type, "run-empty");
        assert!(output.complete, "{engine_id}: {:?}", output.warnings);
        assert!(output.findings.is_empty());
        assert!(output.observations.is_empty());
    }

    let assets = vec![
        authorized_asset("asset-1", AssetKind::Repository, None, &[]),
        authorized_asset("asset-2", AssetKind::Repository, None, &[]),
    ];
    let output = normalize_bytes_with_assets(
        "syft",
        br#"{"artifacts":[{"name":"component"}]}"#,
        "syft.json",
        "application/json",
        "run-multi-asset",
        &assets,
    );
    assert!(!output.complete);
    assert!(output.observations.is_empty());
    assert!(
        output
            .warnings
            .iter()
            .any(|warning| warning.contains("multi-asset"))
    );

    let cleaned = normalize_bytes(
        "syft",
        br#"{"artifacts":[{"name":"component\nname","version":"1.0\tdebug"}]}"#,
        "syft.json",
        "application/json",
        "run-control-clean",
    );
    assert!(cleaned.complete, "{:?}", cleaned.warnings);
    assert!(matches!(
        &cleaned.observations[0].kind,
        InventoryObservationKind::SoftwareComponent {
            name,
            version: Some(version),
            ..
        } if name == "component name" && version == "1.0 debug"
    ));
}

#[test]
fn service_inventory_uses_a_path_free_endpoint_that_report_code_can_correlate() {
    let naabu = normalize_bytes(
        "naabu",
        br#"{"host":"service.example.test","port":443,"protocol":"tcp","asset_id":"asset-1"}"#,
        "naabu.jsonl",
        "application/x-ndjson",
        "run-service-correlation",
    );
    let httpx = normalize_bytes(
        "httpx",
        br#"{"url":"https://service.example.test/login?session=SECRET","host":"service.example.test/target-path?raw=SECRET","port":443,"scheme":"https","status_code":200,"title":"SECRET_TITLE","body":"SECRET_BODY","asset_id":"asset-1"}"#,
        "httpx.jsonl",
        "application/x-ndjson",
        "run-service-correlation",
    );
    let coordinate = |kind: &InventoryObservationKind| match kind {
        InventoryObservationKind::Service { endpoint, port, .. } => (endpoint.clone(), *port),
        _ => panic!("expected service observation"),
    };
    assert_eq!(
        coordinate(&naabu.observations[0].kind),
        coordinate(&httpx.observations[0].kind)
    );
    let serialized = serde_json::to_string(&httpx.observations).unwrap();
    for forbidden in [
        "/login",
        "target-path",
        "session=SECRET",
        "raw=SECRET",
        "SECRET_TITLE",
        "SECRET_BODY",
    ] {
        assert!(!serialized.contains(forbidden), "{serialized}");
    }
}

#[test]
fn checkov_all_framework_output_preserves_each_finding_and_its_exact_pointer() {
    let bytes = br#"[
      {
        "check_type": "cloudformation",
        "results": {
          "failed_checks": [
            {
              "check_id": "CKV_AWS_20",
              "check_name": "S3 bucket allows public read",
              "file_path": "/cloudformation/storage.yaml",
              "severity": "HIGH"
            }
          ]
        }
      },
      {
        "check_type": "dockerfile",
        "results": {
          "failed_checks": [
            {
              "check_id": "CKV_DOCKER_3",
              "check_name": "Container runs as root",
              "file_path": "/Dockerfile",
              "severity": null
            }
          ]
        }
      }
    ]"#;

    let output = normalize_bytes(
        "checkov",
        bytes,
        "checkov-all-frameworks.json",
        "application/json",
        "run-checkov-all-frameworks",
    );
    assert!(
        output.complete,
        "unexpected warnings: {:?}",
        output.warnings
    );
    assert_eq!(output.findings.len(), 2);

    let by_title = output
        .findings
        .iter()
        .map(|finding| (finding.title.as_str(), finding))
        .collect::<BTreeMap<_, _>>();
    assert_eq!(
        by_title["S3 bucket allows public read"].evidence[0]
            .pointer
            .as_deref(),
        Some("/0/results/failed_checks/0")
    );
    assert_eq!(
        by_title["Container runs as root"].evidence[0]
            .pointer
            .as_deref(),
        Some("/1/results/failed_checks/0")
    );
    assert_eq!(
        by_title["S3 bucket allows public read"].evidence[0]
            .source_rule
            .as_deref(),
        Some("CKV_AWS_20")
    );
    assert_eq!(
        by_title["Container runs as root"].evidence[0]
            .source_rule
            .as_deref(),
        Some("CKV_DOCKER_3")
    );

    let legacy = normalize_fixture("checkov");
    assert!(legacy.complete, "legacy warnings: {:?}", legacy.warnings);
    assert!(legacy.findings.iter().all(|finding| {
        finding.evidence.iter().all(|evidence| {
            evidence
                .pointer
                .as_deref()
                .is_some_and(|pointer| pointer.starts_with("/results/failed_checks/"))
        })
    }));
}

#[test]
fn checkov_all_framework_output_contains_malformed_rows_without_losing_valid_findings() {
    let bytes = br#"[
      {
        "check_type": "cloudformation",
        "results": {
          "failed_checks": [
            {
              "check_id": "CKV_AWS_20",
              "check_name": "Valid CloudFormation finding",
              "file_path": "/template.yaml"
            },
            null,
            {"check_name": "Missing identifier", "file_path": "/broken.yaml"}
          ]
        }
      },
      "not-a-framework-report",
      {"check_type": "dockerfile", "results": {"failed_checks": {}}},
      {
        "check_type": "dockerfile",
        "results": {
          "failed_checks": [
            {
              "check_id": "CKV_DOCKER_3",
              "check_name": "Valid Dockerfile finding",
              "file_path": "/Dockerfile"
            }
          ]
        }
      }
    ]"#;

    let output = normalize_bytes(
        "checkov",
        bytes,
        "checkov-all-frameworks-malformed.json",
        "application/json",
        "run-checkov-all-frameworks-malformed",
    );
    assert_eq!(output.findings.len(), 2);
    assert!(!output.complete);
    for expected in [
        "non-object Checkov failed check at /0/results/failed_checks/1",
        "Checkov failed check at /0/results/failed_checks/2 had no valid check_id",
        "non-object Checkov framework result at /1",
        "Checkov output at /2/results/failed_checks was not an array",
    ] {
        assert!(
            output
                .warnings
                .iter()
                .any(|warning| warning.contains(expected)),
            "missing warning {expected:?}: {:?}",
            output.warnings
        );
    }
    assert!(output.findings.iter().any(|finding| {
        finding
            .evidence
            .iter()
            .any(|evidence| evidence.pointer.as_deref() == Some("/3/results/failed_checks/0"))
    }));
}

/// Checkov is the one engine that both reports severities and mostly does not.
/// `BaseCheck` hardcodes `severity = None`, and the values that fill it come
/// from platform metadata that `--skip-download` switches off; exactly one of
/// the 256 shipped graph-check YAMLs declares a severity locally. So a rating
/// has to be derived for almost everything, and the exceptions have to survive
/// that — including a rating this product does not recognize, which spec §9.2
/// requires be shown as unknown and needing review rather than replaced.
#[test]
fn checkov_derives_a_rating_only_where_the_check_carries_none() {
    let bytes = br#"{
      "check_type": "terraform",
      "results": {
        "failed_checks": [
          {"check_id":"absent", "check_name":"No rating key", "file_path":"absent.tf"},
          {"check_id":"null", "check_name":"Null rating", "file_path":"null.tf", "severity":null},
          {"check_id":"custom", "check_name":"Custom rating", "file_path":"custom.tf", "severity":"vendor-special"},
          {"check_id":"info", "check_name":"Information only", "file_path":"info.tf", "severity":"informational"}
        ]
      }
    }"#;
    let output = normalize_bytes(
        "checkov",
        bytes,
        "checkov-severity.json",
        "application/json",
        "run-severity",
    );
    assert!(
        output.complete,
        "unexpected warnings: {:?}",
        output.warnings
    );

    let by_title = output
        .findings
        .iter()
        .map(|finding| (finding.title.as_str(), finding))
        .collect::<BTreeMap<_, _>>();

    // An absent key and an explicit null are the same statement: the check
    // carries no rating. Both are derived, and both say so.
    for title in ["No rating key", "Null rating"] {
        let finding = by_title[title];
        assert_eq!(finding.severity, Severity::Medium, "{title}");
        assert!(
            finding
                .tags
                .iter()
                .any(|tag| tag == "severity-basis:derived"),
            "{title}: {:?}",
            finding.tags
        );
        assert!(
            !finding
                .tags
                .iter()
                .any(|tag| tag.starts_with("source-severity:")),
            "{title}: {:?}",
            finding.tags
        );
    }

    // Checkov did rate these, so its words stand — including the one this
    // product cannot map, which must not be quietly upgraded to the derivation.
    assert_eq!(by_title["Custom rating"].severity, Severity::Unknown);
    assert!(
        by_title["Custom rating"]
            .tags
            .iter()
            .any(|tag| tag == "source-severity:vendor-special"),
        "{:?}",
        by_title["Custom rating"].tags
    );
    assert_eq!(
        by_title["Information only"].severity,
        Severity::Informational
    );
    for title in ["Custom rating", "Information only"] {
        assert!(
            !by_title[title]
                .tags
                .iter()
                .any(|tag| tag == "severity-basis:derived"),
            "{title} lost the rating Checkov gave it: {:?}",
            by_title[title].tags
        );
    }
}

/// kube-bench's `Check` struct has no severity field and `check/` overrides no
/// `MarshalJSON`, so nothing this adapter could read would ever be populated.
/// Treating that as "the engine said unknown" sank the whole engine to priority
/// 20, below Low, and read to the user as a rating kube-bench had given.
///
/// The severity is therefore derived, and the finding has to say so: a derived
/// rating that is indistinguishable from a reported one is the failure this
/// replaces, not a fix for it.
#[test]
fn kube_bench_failures_are_rated_from_the_benchmark_and_labelled_as_derived() {
    let output = normalize_fixture("kube-bench");
    assert!(
        output.complete,
        "unexpected warnings: {:?}",
        output.warnings
    );
    assert_eq!(output.findings.len(), 3, "only failing checks are findings");

    // Read the priority an unrated finding actually gets rather than restating
    // the table, so this still fails if the table changes underneath it.
    let unrated_priority = normalize_bytes(
        "checkov",
        br#"{"results":{"failed_checks":[{"check_id":"missing","check_name":"Missing rating","file_path":"missing.tf"}]}}"#,
        "checkov-unrated.json",
        "application/json",
        "run-unrated",
    )
    .findings
    .first()
    .expect("one unrated finding")
    .priority;

    for finding in &output.findings {
        assert_eq!(
            finding.severity,
            Severity::High,
            "{} was not rated",
            finding.title
        );
        assert!(
            finding.priority > unrated_priority,
            "{} sorted at {}, no better than an unrated finding at {unrated_priority}",
            finding.title,
            finding.priority
        );
        assert!(
            finding
                .tags
                .iter()
                .any(|tag| tag == "severity-basis:derived"),
            "{} does not disclose that its severity is derived: {:?}",
            finding.title,
            finding.tags
        );
        assert!(
            !finding
                .tags
                .iter()
                .any(|tag| tag.starts_with("source-severity:")),
            "{} claims a source severity kube-bench never emits: {:?}",
            finding.title,
            finding.tags
        );
        assert!(
            finding.priority_reasons.iter().any(|reason| {
                reason.contains("Severity derived from a failed CIS Kubernetes Benchmark check")
            }),
            "{} does not explain the derivation: {:?}",
            finding.title,
            finding.priority_reasons
        );
        assert!(
            finding.plain_language_summary.contains("without rating it"),
            "{} reads as though kube-bench rated it: {}",
            finding.title,
            finding.plain_language_summary
        );
    }

    let titles = output
        .findings
        .iter()
        .map(|finding| finding.title.as_str())
        .collect::<BTreeSet<_>>();
    assert!(titles.contains("Ensure anonymous authentication is disabled"));
    assert!(titles.contains("Ensure the read-only port is disabled"));
    assert!(titles.contains("Ensure protectKernelDefaults is enabled"));
    assert!(
        !titles.contains("Ensure authorization mode is Webhook"),
        "a passing check became a finding"
    );
}

#[test]
fn m365_missing_and_unrecognized_source_ratings_stay_unknown_and_traceable() {
    let cases: [(&str, &[u8], &str, &str, &str); 2] = [
        (
            "scubagear",
            br#"{
              "Engine": "ScubaGear",
              "Diagnostics": {"normalized_results": 4},
              "Results": [
                {"PolicyId":"missing", "Requirement":"Missing criticality", "Result":"Failed", "Severity":"unknown"},
                {"PolicyId":"custom", "Requirement":"Custom criticality", "Result":"Failed", "Severity":"unknown", "SourceCriticality":"Vendor-Special"},
                {"PolicyId":"lookalike", "Requirement":"Unreviewed Shall suffix", "Result":"Failed", "Severity":"unknown", "SourceCriticality":"Shall/Vendor-Special"},
                {"PolicyId":"shall", "Requirement":"Known criticality", "Result":"Failed", "Severity":"high", "SourceCriticality":"Shall/3rd Party"}
              ]
            }"#,
            "source-criticality:vendor-special",
            "source-criticality:shall/vendor-special",
            "source-criticality:shall/3rd-party",
        ),
        (
            "maester",
            br#"{
              "Engine": "Maester",
              "Diagnostics": {"normalized_results": 4},
              "Results": [
                {"Id":"missing", "Title":"Missing rating", "Result":"Failed", "Severity":"unknown"},
                {"Id":"custom", "Title":"Custom rating", "Result":"Failed", "Severity":"unknown", "SourceSeverity":"Vendor-Special"},
                {"Id":"lookalike", "Title":"Undocumented informational alias", "Result":"Failed", "Severity":"unknown", "SourceSeverity":"Informational"},
                {"Id":"info", "Title":"Known information", "Result":"Failed", "Severity":"informational", "SourceSeverity":"Info"}
              ]
            }"#,
            "source-rating:vendor-special",
            "source-rating:informational",
            "source-rating:info",
        ),
    ];

    for (engine_id, bytes, unknown_tag, lookalike_tag, known_tag) in cases {
        let output = normalize_bytes(
            engine_id,
            bytes,
            &format!("{engine_id}-source-rating.json"),
            "application/json",
            "run-m365-source-rating",
        );
        assert!(
            output.complete,
            "unexpected warnings: {:?}",
            output.warnings
        );
        assert_eq!(output.findings.len(), 4);

        let by_rule = output
            .findings
            .iter()
            .map(|finding| {
                let source_rule = finding
                    .tags
                    .iter()
                    .find_map(|tag| tag.strip_prefix("source-rule:"))
                    .expect("source rule tag");
                (source_rule, finding)
            })
            .collect::<BTreeMap<_, _>>();
        assert_eq!(by_rule["missing"].severity, Severity::Unknown);
        assert_eq!(by_rule["custom"].severity, Severity::Unknown);
        assert_eq!(by_rule["lookalike"].severity, Severity::Unknown);
        assert!(by_rule["custom"].tags.iter().any(|tag| tag == unknown_tag));
        assert!(
            by_rule["lookalike"]
                .tags
                .iter()
                .any(|tag| tag == lookalike_tag)
        );
        assert!(
            output
                .findings
                .iter()
                .any(|finding| finding.tags.iter().any(|tag| tag == known_tag))
        );
        assert!(output.findings.iter().all(|finding| {
            finding
                .evidence
                .iter()
                .all(|evidence| evidence.pointer.is_some())
        }));
    }
}

#[test]
fn prowler_5_39_ocsf_maps_provider_native_accounts_to_canonical_assets() {
    // Shape and field names are reduced from the pinned Prowler 5.39 OCSF
    // serializer/fixtures: status_code, metadata.event_code,
    // finding_info.analytic.uid, and cloud.account.uid/provider.
    let bytes = include_bytes!("fixtures/adapters/prowler-5.39-multi-provider.ocsf.json");
    let assets = vec![
        authorized_asset(
            "canonical-aws",
            AssetKind::CloudAccount,
            Some("aws"),
            &[("aws_account_id", "123456789012")],
        ),
        authorized_asset(
            "canonical-gcp",
            AssetKind::Project,
            Some("gcp"),
            &[("gcp_project_id", "security-prod-123")],
        ),
        authorized_asset(
            "canonical-azure",
            AssetKind::Subscription,
            Some("azure"),
            &[(
                "azure_subscription_id",
                "11111111-2222-3333-4444-555555555555",
            )],
        ),
        // Deliberately collides by value under another provider's native
        // namespace. cloud.provider must keep the GCP record exact.
        authorized_asset(
            "canonical-azure-decoy",
            AssetKind::Subscription,
            Some("azure"),
            &[("azure_subscription_id", "security-prod-123")],
        ),
    ];

    let output = normalize_bytes_with_assets(
        "prowler",
        bytes,
        "prowler-5.39-multi-provider.ocsf.json",
        "application/json",
        "run-1",
        &assets,
    );

    assert!(
        output.complete,
        "unexpected warnings: {:?}",
        output.warnings
    );
    assert!(output.warnings.is_empty());
    assert_eq!(output.findings.len(), 3, "PASS and MANUAL are not failures");

    let by_asset = output
        .findings
        .iter()
        .map(|finding| (finding.asset_ids[0].as_str(), finding))
        .collect::<BTreeMap<_, _>>();
    assert!(
        by_asset["canonical-aws"]
            .tags
            .iter()
            .any(|tag| tag == "source-rule:accessanalyzer_enabled")
    );
    assert!(
        by_asset["canonical-gcp"]
            .tags
            .iter()
            .any(|tag| tag == "source-rule:iam_audit_logs_enabled"),
        "finding_info.analytic.uid must be the fallback rule identity"
    );
    assert!(
        by_asset["canonical-azure"]
            .tags
            .iter()
            .any(|tag| tag == "source-rule:iam_subscription_owner_max_3")
    );
    assert!(!by_asset.contains_key("canonical-azure-decoy"));
    assert!(by_asset.values().all(|finding| {
        finding
            .official_references
            .iter()
            .any(|reference| reference.starts_with("https://"))
    }));

    let serialized = serde_json::to_string(&output.findings).expect("serialize findings");
    assert!(!serialized.contains("finding-instance-not-the-rule-id"));
    assert!(!serialized.contains("ignored_pass"));
    assert!(!serialized.contains("ignored_manual"));
}

#[test]
fn prowler_native_identifier_collisions_fail_closed() {
    let bytes = include_bytes!("fixtures/adapters/prowler-5.39-multi-provider.ocsf.json");
    let assets = vec![
        authorized_asset(
            "canonical-aws",
            AssetKind::CloudAccount,
            Some("aws"),
            &[("aws_account_id", "123456789012")],
        ),
        authorized_asset(
            "canonical-gcp-a",
            AssetKind::Project,
            Some("gcp"),
            &[("gcp_project_id", "security-prod-123")],
        ),
        authorized_asset(
            "canonical-gcp-b",
            AssetKind::Project,
            Some("gcp"),
            &[("gcp_project_id", "security-prod-123")],
        ),
        authorized_asset(
            "canonical-azure",
            AssetKind::Subscription,
            Some("azure"),
            &[(
                "azure_subscription_id",
                "11111111-2222-3333-4444-555555555555",
            )],
        ),
    ];

    let output = normalize_bytes_with_assets(
        "prowler",
        bytes,
        "prowler-5.39-multi-provider.ocsf.json",
        "application/json",
        "run-1",
        &assets,
    );

    assert!(!output.complete);
    assert_eq!(output.findings.len(), 2);
    assert!(
        output
            .warnings
            .iter()
            .any(|warning| { warning.contains("ambiguous native asset identifier") })
    );
    assert!(output.findings.iter().all(|finding| {
        finding.asset_ids == ["canonical-aws"] || finding.asset_ids == ["canonical-azure"]
    }));
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
fn semgrep_lossy_rule_ids_never_gain_mapping_proof() {
    let output = normalize_bytes(
        "semgrep",
        include_bytes!("fixtures/adapters/semgrep-lossy-rule-ids.json"),
        "semgrep-lossy-rule-ids.json",
        "application/json",
        "run-lossy-rule-ids",
    );

    assert!(
        output.complete,
        "unexpected warnings: {:?}",
        output.warnings
    );
    assert_eq!(output.findings.len(), 2);
    assert!(output.findings.iter().all(|finding| {
        finding.control_references.is_empty()
            && finding.evidence.iter().all(|evidence| {
                evidence.source_rule.is_none() && evidence.result_pointer_sha256.is_some()
            })
    }));
}

#[test]
fn wrapper_preserved_upstream_reports_are_not_normalized_a_second_time() {
    let bytes = include_bytes!("fixtures/adapters/scubagear.json");

    let wrapper_document = normalize_bytes(
        "scubagear",
        bytes,
        "attempt-1/output/scubagear.json",
        "application/json",
        "run-m365-upstream-routing",
    );
    assert!(
        wrapper_document.complete,
        "unexpected warnings: {:?}",
        wrapper_document.warnings
    );
    assert!(!wrapper_document.findings.is_empty());

    // Same engine, same run, byte-identical input: only the location differs.
    // The managed wrapper preserves the vendor's own report under
    // `output/upstream/` as evidence, and that copy is not a second opinion to
    // normalize. Reaching into it would misparse it, because upstream spells
    // the rule key differently than the document the wrapper owns.
    let preserved_upstream = normalize_bytes(
        "scubagear",
        bytes,
        "attempt-1/output/upstream/scubagear.json",
        "application/json",
        "run-m365-upstream-routing",
    );
    assert!(preserved_upstream.findings.is_empty());
    assert!(!preserved_upstream.complete);
    assert!(
        preserved_upstream
            .warnings
            .iter()
            .any(|warning| warning.contains("produced no raw artifacts to normalize")),
        "unexpected warnings: {:?}",
        preserved_upstream.warnings
    );
}

fn scubagear_run_with_diagnostics(diagnostics: serde_json::Value) -> AdapterOutput {
    // `Results` carries every control the wrapper normalized, passes included,
    // so it must agree with the `normalized_results` count each caller declares.
    let document = serde_json::json!({
        "Engine": "ScubaGear",
        "Diagnostics": diagnostics,
        "Results": [
            { "PolicyId": "MS.AAD.1.1v1", "Result": "Failed",
              "Criticality": "Shall", "Requirement": "Block legacy authentication." },
            { "PolicyId": "MS.AAD.2.1v1", "Result": "Pass",
              "Criticality": "Shall", "Requirement": "Risky users SHALL be blocked." }
        ]
    });
    let bytes = serde_json::to_vec(&document).expect("serializable document");
    normalize_bytes(
        "scubagear",
        &bytes,
        "attempt-1/output/scubagear.json",
        "application/json",
        "run-m365-coverage",
    )
}

#[test]
fn only_the_wrappers_declared_results_are_normalized() {
    // Every one of these objects carries a status and a rule id, so the
    // recursive walk this replaced would have turned each into a finding. Only
    // the entry the wrapper listed under `Results` is a normalized control; the
    // rest are provenance, a quoted vendor blob, and a nested annotation.
    let document = serde_json::json!({
        "Engine": "ScubaGear",
        "Provenance": {
            "raw_report": { "PolicyId": "MS.AAD.9.9v1", "Result": "Failed",
                            "Requirement": "Provenance is not a control." }
        },
        "Diagnostics": { "passes": 0, "failures": 1, "errors": 0,
                         "manual": 0, "omitted": 0, "normalized_results": 1 },
        "Results": [{ "PolicyId": "MS.AAD.1.1v1", "Result": "Failed",
                      "Criticality": "Shall", "Requirement": "Block legacy authentication.",
                      "Upstream": { "PolicyId": "MS.AAD.8.8v1", "Result": "Failed",
                                    "Requirement": "A nested quote is not a control." } }]
    });
    let bytes = serde_json::to_vec(&document).expect("serializable document");
    let output = normalize_bytes(
        "scubagear",
        &bytes,
        "attempt-1/output/scubagear.json",
        "application/json",
        "run-m365-envelope",
    );
    assert!(
        output.complete,
        "unexpected warnings: {:?}",
        output.warnings
    );
    let rules = output
        .findings
        .iter()
        .flat_map(|finding| &finding.evidence)
        .filter_map(|evidence| evidence.source_rule.as_deref())
        .collect::<Vec<_>>();
    assert_eq!(rules, vec!["MS.AAD.1.1v1"], "{rules:?}");
}

#[test]
fn a_document_another_engine_wrote_is_refused_rather_than_mined_for_findings() {
    let document = serde_json::json!({
        "Engine": "Maester",
        "Results": [{ "PolicyId": "MS.AAD.1.1v1", "Result": "Failed",
                      "Requirement": "Block legacy authentication." }]
    });
    let bytes = serde_json::to_vec(&document).expect("serializable document");
    let output = normalize_bytes(
        "scubagear",
        &bytes,
        "attempt-1/output/scubagear.json",
        "application/json",
        "run-m365-misrouted",
    );
    assert!(output.findings.is_empty());
    assert!(!output.complete);
    assert!(
        output
            .warnings
            .iter()
            .any(|warning| warning.contains("declaring engine Maester")),
        "the mismatch must be named: {:?}",
        output.warnings
    );
}

#[test]
fn results_lost_between_the_wrapper_and_the_adapter_are_reported() {
    // No rule-level check can see this: every result present parses cleanly,
    // and only the wrapper's own count reveals that one went missing.
    let output = scubagear_run_with_diagnostics(serde_json::json!({
        "passes": 1, "failures": 1, "errors": 0,
        "manual": 0, "omitted": 0, "normalized_results": 3
    }));
    assert!(!output.complete);
    assert!(
        output
            .warnings
            .iter()
            .any(|warning| warning.contains("writing 3 normalized results")
                && warning.contains("holds 2")),
        "the shortfall must be quantified: {:?}",
        output.warnings
    );
}

#[test]
fn controls_passed_over_by_design_are_disclosed_without_marking_the_run_incomplete() {
    // Manual and omitted controls were passed over deliberately, so the run is
    // still a complete scan of what it set out to check. If this disclosure
    // ever flips `complete`, every healthy tenant scan stops reaching
    // ExecutionStage::Completed and sits in CapturedAwaitingAdapter instead
    // (orchestrator.rs:881).
    let output = scubagear_run_with_diagnostics(serde_json::json!({
        "passes": 1, "failures": 1, "errors": 0,
        "manual": 20, "omitted": 5, "normalized_results": 2
    }));
    assert!(
        output.complete,
        "a deliberate pass must not read as a normalization failure: {:?}",
        output.warnings
    );
    assert_eq!(output.findings.len(), 1);
    assert!(
        output
            .warnings
            .iter()
            .any(|warning| warning.contains("20 reserved for manual review")),
        "the disclosure must reach the run: {:?}",
        output.warnings
    );
}

#[test]
fn controls_the_engine_could_not_evaluate_keep_their_findings_but_withhold_completion() {
    // Coverage was never established for the errored control, so the run must
    // not claim completion. The findings it did produce are still real and are
    // kept: orchestrator.rs:879 assigns them before consulting `complete`, so
    // this becomes a PartiallyCompleted run with usable findings rather than a
    // failure that discards them.
    let output = scubagear_run_with_diagnostics(serde_json::json!({
        "passes": 1, "failures": 1, "errors": 3,
        "manual": 0, "omitted": 0, "normalized_results": 2
    }));
    assert!(
        !output.complete,
        "an unevaluable control means coverage was not established"
    );
    assert_eq!(
        output.findings.len(),
        1,
        "withholding completion must not discard real findings"
    );
    assert!(
        output
            .warnings
            .iter()
            .any(|warning| warning.contains("3 could not be evaluated")),
        "the reason must be legible: {:?}",
        output.warnings
    );
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
    let ai_system_related_engines = ["semgrep", "checkov", "kics", "trivy", "grype", "kubescape"];
    let ai_generated_related_engines = ["semgrep", "gitleaks", "trufflehog"];
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
                && reference.mapping_version == "2026-09-05.4"
                && matches!(reference.framework.as_str(), "NIST CSF" | "ISO/IEC 27001")
        }));
        assert!(
            references
                .iter()
                .all(|reference| reference.framework != "AIDEFEND")
        );

        let ai_output = normalize_ai_system_fixture(engine_id);
        let ai_references = ai_output
            .findings
            .iter()
            .flat_map(|finding| &finding.control_references)
            .collect::<Vec<_>>();
        assert_eq!(
            ai_references
                .iter()
                .any(|reference| reference.framework == "AIDEFEND"),
            ai_system_related_engines.contains(&engine_id),
            "explicit AI-system applicability for {engine_id} changed"
        );

        let generated_output = normalize_ai_generated_fixture(engine_id);
        let generated_references = generated_output
            .findings
            .iter()
            .flat_map(|finding| &finding.control_references)
            .collect::<Vec<_>>();
        assert_eq!(
            generated_references
                .iter()
                .any(|reference| reference.control_id == "AID-H-031.002"),
            ai_generated_related_engines.contains(&engine_id),
            "explicit AI-generated-artifact applicability for {engine_id} changed"
        );
        let serialized = serde_json::to_string(&references)
            .expect("serialize versioned control references")
            .to_ascii_lowercase();
        assert!(!serialized.contains("is compliant"));
        assert!(!serialized.contains("is certified"));
        assert!(!serialized.contains("passes the control"));
    }

    for engine_id in ["naabu", "httpx"] {
        let output = normalize_fixture(engine_id);
        assert!(output.findings.is_empty());
        assert!(
            output
                .observations
                .iter()
                .all(|observation| observation.engine_id == engine_id)
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
    assert!(!output.complete);
    assert!(
        output
            .warnings
            .iter()
            .any(|warning| warning.contains("malformed JSONL line 2"))
    );
}

#[test]
fn empty_released_jsonl_streams_are_complete_zero_finding_results() {
    for engine_id in ["naabu", "httpx", "nuclei", "trufflehog"] {
        for bytes in [b"".as_slice(), b"\r\n\t".as_slice()] {
            let filename = format!("{engine_id}.jsonl");
            let output = normalize_bytes(
                engine_id,
                bytes,
                &filename,
                "application/x-ndjson",
                "run-empty",
            );
            assert!(
                output.complete,
                "{engine_id} warnings: {:?}",
                output.warnings
            );
            assert!(output.findings.is_empty());
            assert!(output.warnings.is_empty());
        }
    }
}

#[test]
fn empty_json_document_for_other_adapters_remains_incomplete() {
    let output = normalize_bytes(
        "gitleaks",
        b"",
        "gitleaks.json",
        "application/json",
        "run-empty",
    );
    assert!(!output.complete);
    assert!(output.findings.is_empty());
}

#[test]
fn secret_values_and_target_instructions_never_enter_findings() {
    for engine_id in ["gitleaks", "trufflehog"] {
        let serialized = serde_json::to_string(&normalize_fixture(engine_id).findings)
            .expect("serialize normalized findings");
        assert!(!serialized.contains("SECRET_SENTINEL_MUST_NEVER_LEAK"));
    }

    let httpx = serde_json::to_string(&normalize_fixture("httpx").observations)
        .expect("serialize httpx inventory observations");
    assert!(!httpx.contains("target-controlled text is data"));
    assert!(!httpx.contains("session=must-not-appear"));
    assert!(!httpx.contains("SECRET_SENTINEL_MUST_NEVER_LEAK"));

    // kube-bench's `actual_value` is the verbatim contents of a file read off
    // the scanned node, so it is the one field of its output an attacker who
    // controls the node controls too. The shipped snapshot benchmark carries no
    // remediation text, which is why the sentinel lives here.
    let kube_bench = serde_json::to_string(&normalize_fixture("kube-bench").findings)
        .expect("serialize kube-bench findings");
    assert!(!kube_bench.contains("Do not execute this target-controlled command"));
}

#[test]
fn gitleaks_keeps_same_rule_findings_at_distinct_source_coordinates_without_secrets() {
    let bytes = br#"[
      {
        "RuleID": "generic-api-key",
        "Description": "Potential API key",
        "File": "src/generated.ts",
        "StartLine": 12,
        "StartColumn": 7,
        "Commit": "ABCDEF0123456789ABCDEF0123456789ABCDEF01",
        "Secret": "FIRST_SECRET_SENTINEL_MUST_NEVER_LEAK",
        "Match": "token=FIRST_SECRET_SENTINEL_MUST_NEVER_LEAK",
        "asset_id": "asset-1"
      },
      {
        "RuleID": "generic-api-key",
        "Description": "Potential API key",
        "File": "src/generated.ts",
        "StartLine": 29,
        "StartColumn": 11,
        "Commit": "ABCDEF0123456789ABCDEF0123456789ABCDEF01",
        "Secret": "SECOND_SECRET_SENTINEL_MUST_NEVER_LEAK",
        "Match": "token=SECOND_SECRET_SENTINEL_MUST_NEVER_LEAK",
        "asset_id": "asset-1"
      }
    ]"#;

    let output = normalize_bytes(
        "gitleaks",
        bytes,
        "gitleaks-multiple.json",
        "application/json",
        "run-1",
    );
    assert!(
        output.complete,
        "unexpected warnings: {:?}",
        output.warnings
    );
    assert_eq!(output.findings.len(), 2);
    assert_eq!(
        output
            .findings
            .iter()
            .map(|finding| finding.fingerprint.as_str())
            .collect::<BTreeSet<_>>()
            .len(),
        2,
        "source coordinates must keep same-file, same-rule findings distinct"
    );

    let serialized = serde_json::to_string(&output.findings).expect("serialize Gitleaks findings");
    assert!(serialized.contains("src/generated.ts:line=12:column=7"));
    assert!(serialized.contains("abcdef0123456789abcdef0123456789abcdef01"));
    assert!(!serialized.contains("FIRST_SECRET_SENTINEL_MUST_NEVER_LEAK"));
    assert!(!serialized.contains("SECOND_SECRET_SENTINEL_MUST_NEVER_LEAK"));
    assert!(!serialized.contains("token="));
}

#[test]
fn source_coordinates_prevent_distinct_upstream_results_from_being_silently_merged() {
    let cases = [
        (
            "semgrep",
            "semgrep-multiple.json",
            "application/json",
            br#"{
              "results": [
                {
                  "check_id": "python.lang.security.audit.exec-used.exec-used",
                  "path": "src/worker.py",
                  "start": {"line": 12, "col": 3},
                  "extra": {"message": "exec() used", "severity": "ERROR"},
                  "asset_id": "asset-1"
                },
                {
                  "check_id": "python.lang.security.audit.exec-used.exec-used",
                  "path": "src/worker.py",
                  "start": {"line": 29, "col": 7},
                  "extra": {"message": "exec() used", "severity": "ERROR"},
                  "asset_id": "asset-1"
                }
              ]
            }"#
            .as_slice(),
            ["src/worker.py:line=12:column=3", "src/worker.py:line=29:column=7"],
        ),
        (
            "checkov",
            "checkov-multiple.json",
            "application/json",
            br#"{
              "results": {
                "failed_checks": [
                  {
                    "check_id": "CKV_AWS_18",
                    "check_name": "Ensure access logging is enabled",
                    "file_path": "/infra/storage.tf",
                    "file_line_range": [4, 10],
                    "resource": "aws_s3_bucket.logs",
                    "severity": null,
                    "asset_id": "asset-1"
                  },
                  {
                    "check_id": "CKV_AWS_18",
                    "check_name": "Ensure access logging is enabled",
                    "file_path": "/infra/storage.tf",
                    "file_line_range": [18, 24],
                    "resource": "aws_s3_bucket.archive",
                    "severity": null,
                    "asset_id": "asset-1"
                  }
                ]
              }
            }"#
            .as_slice(),
            [
                "/infra/storage.tf:line=4:resource=aws_s3_bucket.logs",
                "/infra/storage.tf:line=18:resource=aws_s3_bucket.archive",
            ],
        ),
        (
            "trufflehog",
            "trufflehog-multiple.jsonl",
            "application/x-ndjson",
            br#"{"SourceMetadata":{"Data":{"Filesystem":{"file":"/workspace/config/.env","line":6}}},"DetectorType":17,"DetectorName":"AWS","Verified":false,"Raw":"FIRST_SECRET_SENTINEL_MUST_NEVER_LEAK","asset_id":"asset-1"}
{"SourceMetadata":{"Data":{"Filesystem":{"file":"/workspace/config/.env","line":21}}},"DetectorType":17,"DetectorName":"AWS","Verified":false,"Raw":"SECOND_SECRET_SENTINEL_MUST_NEVER_LEAK","asset_id":"asset-1"}
"#
            .as_slice(),
            ["config/.env:line=6", "config/.env:line=21"],
        ),
    ];

    for (engine_id, filename, media_type, bytes, expected_locations) in cases {
        let output = normalize_bytes(engine_id, bytes, filename, media_type, "run-coordinates");
        assert!(
            output.complete,
            "{engine_id} unexpectedly incomplete: {:?}",
            output.warnings
        );
        assert_eq!(
            output.findings.len(),
            2,
            "{engine_id} merged two distinct upstream observations"
        );
        assert_eq!(
            output
                .findings
                .iter()
                .map(|finding| finding.fingerprint.as_str())
                .collect::<BTreeSet<_>>()
                .len(),
            2,
            "{engine_id} produced colliding fingerprints for distinct coordinates"
        );
        let serialized = serde_json::to_string(&output.findings).expect("serialize findings");
        for expected in expected_locations {
            assert!(
                serialized.contains(expected),
                "{engine_id} did not preserve source coordinate {expected}: {serialized}"
            );
        }
        assert!(!serialized.contains("SECRET_SENTINEL_MUST_NEVER_LEAK"));
    }
}

#[test]
fn kics_and_trivy_keep_distinct_upstream_resources_and_secret_coordinates() {
    let kics = br#"{
      "queries": [{
        "query_id": "query-1",
        "query_name": "Encryption required",
        "severity": "HIGH",
        "files": [
          {
            "file_name": "infra/storage.tf",
            "line": 4,
            "resource_name": "aws_s3_bucket.logs",
            "similarity_id": "similarity-logs",
            "asset_id": "asset-1"
          },
          {
            "file_name": "infra/storage.tf",
            "line": 18,
            "resource_name": "aws_s3_bucket.archive",
            "similarity_id": "similarity-archive",
            "asset_id": "asset-1"
          }
        ]
      }]
    }"#;
    let kics = normalize_bytes(
        "kics",
        kics,
        "kics-multiple.json",
        "application/json",
        "run-kics-coordinates",
    );
    assert!(kics.complete, "unexpected warnings: {:?}", kics.warnings);
    assert_eq!(kics.findings.len(), 2);
    let kics_serialized = serde_json::to_string(&kics.findings).expect("serialize KICS findings");
    for coordinate in [
        "infra/storage.tf:line=4:resource=resource:aws_s3_bucket.logs,similarity:similarity-logs",
        "infra/storage.tf:line=18:resource=resource:aws_s3_bucket.archive,similarity:similarity-archive",
    ] {
        assert!(kics_serialized.contains(coordinate), "{kics_serialized}");
    }

    let trivy = br#"{
      "SchemaVersion": 2,
      "Results": [{
        "Target": "example:latest",
        "Vulnerabilities": [
          {
            "VulnerabilityID": "CVE-2026-0001",
            "PkgName": "libalpha",
            "InstalledVersion": "1.0",
            "Severity": "HIGH"
          },
          {
            "VulnerabilityID": "CVE-2026-0001",
            "PkgName": "libbeta",
            "InstalledVersion": "2.0",
            "Severity": "HIGH"
          }
        ],
        "Secrets": [
          {
            "RuleID": "generic-api-key",
            "Title": "API key",
            "Severity": "HIGH",
            "StartLine": 7,
            "Offset": 101,
            "Match": "FIRST_SECRET_SENTINEL_MUST_NEVER_LEAK"
          },
          {
            "RuleID": "generic-api-key",
            "Title": "API key",
            "Severity": "HIGH",
            "StartLine": 31,
            "Offset": 202,
            "Match": "SECOND_SECRET_SENTINEL_MUST_NEVER_LEAK"
          }
        ],
        "asset_id": "asset-1"
      }]
    }"#;
    let trivy = normalize_bytes(
        "trivy",
        trivy,
        "trivy-multiple.json",
        "application/json",
        "run-trivy-coordinates",
    );
    assert!(trivy.complete, "unexpected warnings: {:?}", trivy.warnings);
    assert_eq!(
        trivy.findings.len(),
        4,
        "Trivy merged distinct packages or secret locations"
    );
    let trivy_serialized =
        serde_json::to_string(&trivy.findings).expect("serialize Trivy findings");
    for coordinate in [
        "example:latest:resource=libalpha@1.0",
        "example:latest:resource=libbeta@2.0",
        "example:latest:line=7:resource=offset:101",
        "example:latest:line=31:resource=offset:202",
    ] {
        assert!(trivy_serialized.contains(coordinate), "{trivy_serialized}");
    }
    assert!(!trivy_serialized.contains("SECRET_SENTINEL_MUST_NEVER_LEAK"));
}

#[test]
fn missing_primary_result_shapes_are_incomplete_but_known_empty_shapes_are_complete() {
    let malformed = [
        (
            "httpx",
            br#"{}"#.as_slice(),
            "httpx.jsonl",
            "application/x-ndjson",
        ),
        (
            "nuclei",
            br#"{"info":{"name":"missing template id"}}"#.as_slice(),
            "nuclei.jsonl",
            "application/x-ndjson",
        ),
        (
            "gitleaks",
            br#"{}"#.as_slice(),
            "gitleaks.json",
            "application/json",
        ),
        (
            "trufflehog",
            br#"{"SourceMetadata":{}}"#.as_slice(),
            "trufflehog.jsonl",
            "application/x-ndjson",
        ),
        (
            "trivy",
            br#"{}"#.as_slice(),
            "trivy.json",
            "application/json",
        ),
        (
            "grype",
            br#"{}"#.as_slice(),
            "grype.json",
            "application/json",
        ),
        (
            "kube-bench",
            br#"{}"#.as_slice(),
            "kube-bench.json",
            "application/json",
        ),
    ];
    for (engine_id, bytes, filename, media_type) in malformed {
        let output = normalize_bytes(engine_id, bytes, filename, media_type, "run-missing-shape");
        assert!(
            !output.complete,
            "{engine_id} accepted a missing result shape"
        );
        assert!(output.findings.is_empty());
        assert!(
            output
                .warnings
                .iter()
                .any(|warning| { warning.contains("retry") || warning.contains("retried") }),
            "{engine_id} warning was not actionable: {:?}",
            output.warnings
        );
    }

    let empty = [
        (
            "gitleaks",
            br#"[]"#.as_slice(),
            "gitleaks.json",
            "application/json",
        ),
        (
            "trivy",
            br#"{"Results":[]}"#.as_slice(),
            "trivy.json",
            "application/json",
        ),
        (
            "grype",
            br#"{"matches":[]}"#.as_slice(),
            "grype.json",
            "application/json",
        ),
        (
            "kube-bench",
            br#"{"Controls":[]}"#.as_slice(),
            "kube-bench.json",
            "application/json",
        ),
    ];
    for (engine_id, bytes, filename, media_type) in empty {
        let output = normalize_bytes(
            engine_id,
            bytes,
            filename,
            media_type,
            "run-known-empty-shape",
        );
        assert!(
            output.complete,
            "{engine_id} rejected its known empty shape: {:?}",
            output.warnings
        );
        assert!(output.findings.is_empty());
    }
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
    let details = finding.evidence[0]
        .scanner_details
        .as_ref()
        .expect("pinned-feed scanner details");
    assert_eq!(
        details.description.as_deref(),
        Some(
            "The pinned Greenbone feed identifies an outdated service with a known remote weakness."
        )
    );
    assert_eq!(
        details.remediation.as_deref(),
        Some("Install the vendor security update for the affected service.")
    );
    let serialized = serde_json::to_string(finding).expect("serialize Greenbone finding");
    assert!(!serialized.contains("SECRET_SENTINEL_MUST_NEVER_LEAK"));
    assert!(serialized.contains("pinned Greenbone feed identifies an outdated service"));
    assert!(serialized.contains("Install the vendor security update"));
}

#[test]
fn upstream_rule_details_are_retained_as_evidence_without_replacing_product_recommendations() {
    let details = |engine_id: &str| {
        normalize_fixture(engine_id)
            .findings
            .into_iter()
            .flat_map(|finding| finding.evidence)
            .filter_map(|evidence| evidence.scanner_details)
            .collect::<Vec<_>>()
    };

    let prowler = normalize_fixture("prowler");
    assert!(prowler.findings.iter().any(|finding| {
        finding.evidence.iter().any(|evidence| {
            evidence.scanner_details.as_ref().is_some_and(|details| {
                details.remediation.as_deref()
                    == Some("Replace the wildcard action and resource with the specific permissions the role needs.")
            })
        }) && !finding.recommendation.contains("Replace the wildcard action")
    }));

    let scoutsuite = details("scoutsuite");
    assert!(scoutsuite.iter().any(|details| {
        details
            .description
            .as_deref()
            .is_some_and(|text| text.contains("password policy did not require"))
            && details
                .remediation
                .as_deref()
                .is_some_and(|text| text.contains("require at least one uppercase letter"))
    }));

    let nuclei = normalize_fixture("nuclei");
    assert!(nuclei.findings.iter().any(|finding| {
        finding.evidence.iter().any(|evidence| {
            evidence.scanner_details.as_ref().is_some_and(|details| {
                details.description.as_deref()
                    == Some("A phpMyAdmin administration panel was detected.")
                    && details
                        .remediation
                        .as_deref()
                        .is_some_and(|text| text.starts_with("Restrict access"))
            })
        }) && !finding.recommendation.contains("Restrict access")
    }));

    let semgrep = details("semgrep");
    assert!(semgrep.iter().any(|details| {
        details
            .description
            .as_deref()
            .is_some_and(|text| text.contains("untrusted input executable"))
            && details.remediation.as_deref()
                == Some("Call the subprocess without a command shell.")
    }));

    let checkov = details("checkov");
    assert!(checkov.iter().any(|details| {
        details.description.as_deref()
            == Some("The bucket rule requires access logging to be enabled.")
    }));

    let kics = details("kics");
    assert!(kics.iter().any(|details| {
        details.description.as_deref()
            == Some("S3 Bucket Object should have server-side encryption enabled")
    }));

    let trivy = details("trivy");
    assert!(trivy.iter().any(|details| {
        details
            .description
            .as_deref()
            .is_some_and(|text| text.contains("affected by the advisory"))
            && details.installed_version.as_deref() == Some("1.0")
            && details.fixed_version.as_deref() == Some("1.1")
    }));

    let grype = details("grype");
    assert!(grype.iter().any(|details| {
        details
            .description
            .as_deref()
            .is_some_and(|text| text.contains("critical vulnerability"))
            && details.installed_version.as_deref() == Some("1.0")
            && details.fixed_version.as_deref() == Some("1.1, 1.2")
    }));

    let kube_bench = details("kube-bench");
    assert!(kube_bench.iter().any(|details| {
        details.remediation.as_deref()
            == Some("Set anonymous authentication to false in the kubelet configuration.")
    }));
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
    assert!(!output.complete);
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
<get_reports_response><report><results><result id="example"><name>Example&amp;network&#x20;vulnerability</name><host>192.0.2.10</host><port>65535/tcp</port><severity>7.5</severity><threat>High</threat><asset_id>asset-1</asset_id><description>relay -&gt; target</description><nvt oid="1.3.6.1.4.1.25623.1.0.1"><name>Example&amp;NVT&apos;&quot;&lt;&gt;&#x20;reference</name><family>Web&#32;Servers</family></nvt></result></results></report></get_reports_response>"#;
    let output = normalize_bytes(
        "greenbone",
        xml,
        "greenbone.xml",
        "application/xml",
        "run-1",
    );
    assert_eq!(output.findings.len(), 1);
    assert!(
        output.findings[0]
            .title
            .contains("Example&NVT'\"<> reference"),
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
    let asset_identifier_map = AdapterAssetIdentifierMap::default();
    let artifacts = vec![artifact];
    let input = AdapterInput {
        case_id: "case-1",
        scan_run_id: "run-1",
        engine_run_id: "engine-run-run-1",
        manifest,
        ai_system_applicable: false,
        ai_generated_artifact_applicable: false,
        asset_ids: &assets,
        asset_identifier_map: &asset_identifier_map,
        artifact_root: Path::new(temp.path()),
        raw_artifacts: &artifacts,
    };
    let output = builtin_adapter_registry()
        .expect("registry")
        .normalize(&input)
        .expect("contained result")
        .expect("adapter");
    assert!(output.findings.is_empty());
    assert!(!output.complete);
    assert!(
        output
            .warnings
            .iter()
            .any(|warning| warning.contains("escaped"))
    );
}

#[test]
fn a_result_the_tenant_disputes_is_reported_rather_than_quietly_honoured() {
    // What the wrapper writes for a control ScubaGear failed and the tenant's own
    // ScubaGear config marked incorrect. Upstream rewrites such a control's
    // `Result` to a sentinel and counts it in `IncorrectResults` instead of
    // `Failures`, so reading `Result` alone erased a real failure from the audit
    // with neither a finding nor a counter left behind. The wrapper now takes the
    // verdict from ScubaGear's own `OriginalResult` and leaves the sentinel in
    // `SourceResult`, so the dispute travels with the finding.
    let document = serde_json::json!({
        "Engine": "ScubaGear",
        "Diagnostics": { "passes": 0, "failures": 1, "errors": 0, "manual": 0,
                         "omitted": 0, "disputed": 1, "normalized_results": 2 },
        "Results": [
            { "PolicyId": "MS.AAD.1.1v1", "Result": "Failed",
              "SourceResult": "Incorrect result", "Criticality": "Shall",
              "Requirement": "Block legacy authentication." },
            { "PolicyId": "MS.AAD.2.1v1", "Result": "Failed",
              "SourceResult": "Fail", "Criticality": "Shall",
              "Requirement": "Risky users SHALL be blocked." }
        ]
    });
    let bytes = serde_json::to_vec(&document).expect("serializable document");
    let output = normalize_bytes(
        "scubagear",
        &bytes,
        "attempt-1/output/scubagear.json",
        "application/json",
        "run-m365-disputed",
    );

    let tags_of = |rule: &str| {
        output
            .findings
            .iter()
            .find(|finding| {
                finding
                    .evidence
                    .iter()
                    .any(|evidence| evidence.source_rule.as_deref() == Some(rule))
            })
            .unwrap_or_else(|| panic!("the disputed control must still be a finding: {rule}"))
            .tags
            .clone()
    };
    let disputed = tags_of("MS.AAD.1.1v1");
    let undisputed = tags_of("MS.AAD.2.1v1");
    assert!(
        disputed.iter().any(|tag| tag == "tenant-disputed"),
        "the dispute must be visible on the finding: {disputed:?}"
    );
    assert!(
        !undisputed.iter().any(|tag| tag == "tenant-disputed"),
        "an undisputed failure must not be marked: {undisputed:?}"
    );
    // The control was evaluated and became a finding, so this is not a coverage
    // shortfall and must not be reported as one.
    assert!(
        output.complete,
        "a disputed control is evaluated, not unevaluated: {:?}",
        output.warnings
    );
    assert!(
        output
            .warnings
            .iter()
            .any(|warning| warning.contains("disputes the result of 1 control")),
        "the run must say a dispute occurred: {:?}",
        output.warnings
    );
}

#[test]
fn a_document_the_adapter_cannot_fully_account_for_does_not_read_as_a_clean_run() {
    // The envelope checks used to run only when the fields they read happened to
    // be present, and a `Results` member that could not become a finding was
    // dropped without a word. A document like this one therefore produced one
    // finding, no warnings, and a complete run while silently losing two of the
    // three results the wrapper claimed to have normalized.
    let document = serde_json::json!({
        "Results": [
            "a bare string is not a control",
            { "PolicyId": "MS.AAD.3.3v1", "Requirement": "No status field at all." },
            { "PolicyId": "MS.AAD.1.1v1", "Result": "Failed",
              "Criticality": "Shall", "Requirement": "Block legacy authentication." }
        ]
    });
    let bytes = serde_json::to_vec(&document).expect("serializable document");
    let output = normalize_bytes(
        "scubagear",
        &bytes,
        "attempt-1/output/scubagear.json",
        "application/json",
        "run-m365-unaccounted",
    );

    // The result that is a real control still becomes a finding: the point is to
    // stop claiming completeness, not to discard evidence.
    assert_eq!(output.findings.len(), 1, "{:?}", output.findings);
    assert!(
        !output.complete,
        "two of three declared results were lost: {:?}",
        output.warnings
    );
    for expected in [
        "did not name the engine that wrote it",
        "did not declare how many results it normalized",
        "/Results/0 that is not an object",
        "/Results/1 carried no recognizable status",
    ] {
        assert!(
            output
                .warnings
                .iter()
                .any(|warning| warning.contains(expected)),
            "no warning mentioned {expected:?}: {:?}",
            output.warnings
        );
    }
}

/// Return every finding's `source-rule:` tag paired with its severity.
///
/// The rule identity is asserted through the tag rather than a struct field
/// because that tag is what reaches an export and a mapping lookup.
/// Trivy and Grype scanning one image is the ordinary case, and their results
/// overlap heavily. This drives both real adapters and then asks the
/// correlation rule which of the resulting rows describe one issue — the whole
/// chain from engine output to the single list the user reads.
#[test]
fn one_vulnerability_seen_by_trivy_and_grype_is_offered_as_a_single_row() {
    let mut case = AssessmentCase::new(
        "Correlation".into(),
        OrganizationProfile {
            organization_name: "Example".into(),
            employee_range: "2-49".into(),
            data_classes: vec![DataClass::PersonallyIdentifiableInformation],
            notes: None,
        },
    );
    for engine_id in ["trivy", "grype"] {
        let output = normalize_fixture(engine_id);
        assert_eq!(
            output.findings.len(),
            2,
            "{engine_id} fixture carries one shared and one exclusive vulnerability"
        );
        for mut finding in output.findings {
            finding.case_id = case.id.clone();
            case.findings.push(finding);
        }
    }

    let report = correlation_report(&case);

    assert_eq!(
        case.findings.len(),
        4,
        "correlation is a suggestion; it never removes a row"
    );
    assert_eq!(report.suggestions.len(), 1, "{report:?}");
    let suggestion = &report.suggestions[0];
    assert_eq!(suggestion.engine_ids, ["grype", "trivy"]);
    assert!(
        suggestion.comparison_key.contains("CVE-2024-2511")
            && suggestion.comparison_key.contains("openssl"),
        "the shared vulnerability is the one that correlates: {}",
        suggestion.comparison_key
    );

    let members = suggestion
        .finding_ids
        .iter()
        .map(|finding_id| {
            case.findings
                .iter()
                .find(|finding| &finding.id == finding_id)
                .expect("suggested member is a real finding in the case")
        })
        .collect::<Vec<_>>();
    assert_eq!(members.len(), 2);
    // Trivy says MEDIUM, Grype says Medium. Aligning them onto one row is only
    // meaningful if the normalized severity already agrees.
    assert!(
        members
            .iter()
            .all(|finding| finding.severity == Severity::Medium),
        "both engines' severities normalize to the same level: {:?}",
        members
            .iter()
            .map(|finding| finding.severity.clone())
            .collect::<Vec<_>>()
    );
    assert!(
        members.iter().all(|finding| !finding.evidence.is_empty()),
        "each member keeps its own evidence rather than borrowing the other's"
    );

    // The vulnerabilities only one engine saw must stay as their own rows.
    let suggested = suggestion.finding_ids.iter().collect::<BTreeSet<_>>();
    let unsuggested = case
        .findings
        .iter()
        .filter(|finding| !suggested.contains(&finding.id))
        .filter_map(|finding| {
            finding
                .tags
                .iter()
                .find_map(|tag| tag.strip_prefix("source-rule:"))
        })
        .collect::<BTreeSet<_>>();
    assert_eq!(
        unsuggested,
        ["cve-2025-0001", "cve-2025-0002"].into_iter().collect(),
        "an issue only one engine reported is never folded into another row"
    );
    assert!(report.unverifiable.is_empty(), "{report:?}");
}

fn rules_and_severities(output: &AdapterOutput) -> BTreeMap<String, Severity> {
    output
        .findings
        .iter()
        .map(|finding| {
            let rule = finding
                .tags
                .iter()
                .find_map(|tag| tag.strip_prefix("source-rule:"))
                .expect("every finding carries its source rule")
                .to_owned();
            (rule, finding.severity.clone())
        })
        .collect()
}

#[test]
fn scoutsuite_rule_identity_survives_being_stored_only_as_a_parent_key() {
    // ScoutSuite writes `services.<service>.findings.<rule key>` and never
    // repeats the key inside the object, so a parser that only reads fields
    // finds no rule id and silently drops the entire run.
    let output = normalize_fixture("scoutsuite");
    let found = rules_and_severities(&output);

    assert_eq!(
        found.keys().cloned().collect::<Vec<_>>(),
        vec![
            "iam-ec2-role-without-instances".to_owned(),
            "iam-password-policy-no-uppercase-required".to_owned(),
            "s3-bucket-world-policy-star".to_owned(),
        ],
        "each flagged rule keeps the key ScoutSuite filed it under"
    );

    // 125 of ScoutSuite's 197 default AWS rules are graded `danger`; leaving
    // that word unmapped sent the majority of the engine to `Unknown`.
    assert_eq!(
        found["iam-password-policy-no-uppercase-required"],
        Severity::High
    );
    assert_eq!(found["s3-bucket-world-policy-star"], Severity::High);
    assert_eq!(found["iam-ec2-role-without-instances"], Severity::Medium);

    assert!(
        !found.contains_key("iam-password-policy-minimum-length"),
        "a rule with zero flagged items is not a finding"
    );
    // ScoutSuite's other rule type, `filters`, tags resources for the report
    // and shares the findings object shape, flagged counts included. Deriving a
    // rule id from any pointer would turn those into findings.
    assert!(
        !found.contains_key("s3-bucket-website-enabled"),
        "a `filters` entry is not a finding"
    );
    assert!(
        output.complete,
        "unexpected warnings: {:?}",
        output.warnings
    );
}

#[test]
fn cloudsplaining_risks_are_read_from_policies_not_the_document_root() {
    // `iam-findings-<account>.json` is `authorization_details.results`, keyed by
    // principal and policy collection. Every risk array sits inside a policy
    // object, so nothing recognisable appears at the root.
    let output = normalize_fixture("cloudsplaining");
    let found = rules_and_severities(&output);

    // Severities are upstream's own grading (`shared/constants.py`), not a
    // scale invented here, so this engine stays comparable with the others.
    // The tag is lowercased by `safe_tag`; the mapping lookup keeps the exact
    // case, which the control-reference assertion below covers.
    assert_eq!(found["privilegeescalation"], Severity::High);
    assert_eq!(found["credentialsexposure"], Severity::High);
    assert_eq!(found["resourceexposure"], Severity::High);
    assert_eq!(found["dataexfiltration"], Severity::Medium);
    assert_eq!(found["servicewildcard"], Severity::Medium);
    assert_eq!(found["infrastructuremodification"], Severity::Low);

    // The catalog previously mapped `iam-privesc`, a rule Cloudsplaining never
    // emits, so no real run could ever resolve a framework relationship.
    let escalation = output
        .findings
        .iter()
        .find(|finding| {
            finding
                .tags
                .iter()
                .any(|tag| tag == "source-rule:privilegeescalation")
        })
        .expect("a privilege-escalation finding");
    assert!(
        !escalation.control_references.is_empty(),
        "the corrected mapping coordinate resolves for real output"
    );

    let titles = output
        .findings
        .iter()
        .map(|finding| finding.title.as_str())
        .collect::<BTreeSet<_>>();
    assert!(
        titles.contains("Privilege escalation path in policy IAMFullAccess"),
        "a finding names the policy a reader has to change: {titles:?}"
    );
    assert!(
        titles.contains("Resource exposure in policy InsecurePolicy"),
        "customer-managed policies are read too: {titles:?}"
    );
    assert!(
        titles.contains("Data exfiltration exposure in policy InlinePolicyForAdminGroup"),
        "inline policies are read too: {titles:?}"
    );

    assert!(
        !titles
            .iter()
            .any(|title| title.contains("AdministratorAccess")),
        "Cloudsplaining already excluded that policy; re-reporting it overrules the tool: {titles:?}"
    );

    // Whether the account owner can edit the policy changes the remediation,
    // so the distinction has to survive normalization.
    let sources = output
        .findings
        .iter()
        .flat_map(|finding| &finding.tags)
        .filter_map(|tag| tag.strip_prefix("policy-source:"))
        .collect::<BTreeSet<_>>();
    assert_eq!(
        sources,
        BTreeSet::from(["aws-managed", "customer-managed", "inline"]),
        "each policy collection is distinguishable in the findings list"
    );
}

#[test]
fn kubescape_per_resource_results_are_read_not_only_the_summary_rollup() {
    // v2 nests the verdict as `{status, subStatus, info}`. A scan for a string
    // `status` matches only `summaryDetails.controls`, which names the control
    // but not the resource, so every actionable result disappears.
    let output = normalize_fixture("kubescape");
    let found = rules_and_severities(&output);

    assert_eq!(
        found.keys().cloned().collect::<Vec<_>>(),
        vec![
            "c-0002".to_owned(),
            "c-0009".to_owned(),
            "c-0017".to_owned()
        ],
        "a passing control is not a finding, and failing ones survive"
    );

    // Severity comes from the roll-up's 1-10 `scoreFactor`, read through the
    // shared numeric branch rather than a second scale.
    assert_eq!(found["c-0009"], Severity::High, "scoreFactor 7");
    assert_eq!(found["c-0002"], Severity::Medium, "scoreFactor 5");
    assert_eq!(found["c-0017"], Severity::Low, "scoreFactor 3");

    // The whole point of reading `results` is naming what has to change. The
    // roll-up alone would put the control's own name here instead.
    let summaries = output
        .findings
        .iter()
        .flat_map(|finding| &finding.evidence)
        .map(|evidence| evidence.summary.as_str())
        .collect::<Vec<_>>();
    assert!(
        summaries
            .iter()
            .any(|summary| summary.contains("apps/v1/production/Deployment/payments-api")),
        "a finding points at the resource, not the control name: {summaries:?}"
    );
    assert!(
        summaries
            .iter()
            .any(|summary| summary.contains("apps/v1/production/StatefulSet/ledger-db")),
        "each failing resource is reported: {summaries:?}"
    );
    assert!(
        !summaries
            .iter()
            .any(|summary| summary.contains("kubernetes-cluster")),
        "the resource-less roll-up fallback did not run: {summaries:?}"
    );

    assert_eq!(
        output.findings.len(),
        3,
        "the roll-up must not duplicate what `results` already reported"
    );
}

/// Engines whose artifact is JSON Lines, from `engines/catalog.json`.
const JSON_LINES_ENGINES: &[&str] = &["naabu", "httpx", "nuclei", "trufflehog"];

#[test]
fn json_lines_fixtures_carry_more_than_one_record_so_the_line_loop_actually_runs() {
    // `parse_artifact` only reaches its JSON-Lines branch when parsing the
    // whole file as one JSON document fails. `serde_json` tolerates a trailing
    // newline, so a one-record `.jsonl` fixture parses as a plain object and
    // the line loop never executes even once. Every bug that lives past the
    // first record -- a loop that returns early, an index that does not
    // advance, a fingerprint that collides -- would then ship unseen.
    for engine_id in JSON_LINES_ENGINES {
        let (bytes, filename, _) = fixture(engine_id);
        assert!(
            filename.ends_with(".jsonl"),
            "{engine_id} is listed as JSON Lines but its fixture is {filename}"
        );
        let records = bytes
            .split(|byte| *byte == b'\n')
            .filter(|line| !line.iter().all(u8::is_ascii_whitespace))
            .count();
        assert!(
            records >= 2,
            "{engine_id}'s fixture holds {records} record(s); the line loop needs at least two"
        );

        let output = normalize_fixture(engine_id);
        let normalized_count = if matches!(*engine_id, "naabu" | "httpx") {
            output.observations.len()
        } else {
            output.findings.len()
        };
        assert!(
            normalized_count >= 2,
            "{engine_id} produced {normalized_count} normalized record(s) from {records} records; a record was dropped"
        );
        if matches!(*engine_id, "naabu" | "httpx") {
            let ids = output
                .observations
                .iter()
                .map(|observation| observation.id.as_str())
                .collect::<BTreeSet<_>>();
            assert_eq!(ids.len(), output.observations.len(), "{engine_id}");
            continue;
        }
        let fingerprints = output
            .findings
            .iter()
            .map(|finding| finding.fingerprint.as_str())
            .collect::<BTreeSet<_>>();
        assert_eq!(
            fingerprints.len(),
            output.findings.len(),
            "{engine_id} gave two records the same fingerprint, so one would overwrite the other"
        );
    }
}

#[test]
fn the_container_mount_path_never_reaches_the_user() {
    // Engines are handed `/workspace` as their scan target, so their output
    // names files under a directory that does not exist on the user's machine.
    // A beginner shown `/workspace/deploy/.env.production` cannot open it and
    // cannot tell whether it is even their file.
    for engine_id in BUILTIN_ENGINE_IDS {
        let output = normalize_fixture(engine_id);
        for finding in &output.findings {
            let rendered = [
                finding.title.as_str(),
                finding.plain_language_summary.as_str(),
                finding.recommendation.as_str(),
                finding.verification_guidance.as_str(),
            ]
            .join("\n")
                + &finding
                    .evidence
                    .iter()
                    .map(|evidence| evidence.summary.clone())
                    .collect::<Vec<_>>()
                    .join("\n");
            assert!(
                !rendered.contains("/workspace"),
                "{engine_id} shows the container mount path to the user: {rendered}"
            );
        }
    }
}

#[test]
fn trufflehog_reports_paths_relative_to_the_directory_the_user_chose() {
    // Guards the test above against passing for the wrong reason: trufflehog's
    // fixture does carry absolute `/workspace/...` paths, exactly as the real
    // binary emits them when the launcher hands it `/workspace`. If that ever
    // stopped being true, the mount-path test would be vacuous.
    let (bytes, _, _) = fixture("trufflehog");
    let raw = std::str::from_utf8(bytes).expect("fixture is UTF-8");
    assert!(
        raw.contains("\"/workspace/"),
        "the fixture no longer exercises the mount prefix at all"
    );

    let output = normalize_fixture("trufflehog");
    let locations = output
        .findings
        .iter()
        .flat_map(|finding| finding.evidence.iter().map(|e| e.summary.clone()))
        .collect::<Vec<_>>();
    assert!(
        locations
            .iter()
            .any(|summary| summary.contains("deploy/.env.production")),
        "the path lost more than the mount prefix: {locations:?}"
    );
}

#[test]
fn semgrep_findings_carry_the_engines_explanation_not_just_its_rule_id() {
    // Semgrep's `extra.message` is a required field in its output schema and is
    // the only sentence a reader can act on. A title of
    // "Semgrep rule ai-security-scanner.python.shell-true" tells a beginner
    // nothing about what is wrong.
    let output = normalize_fixture("semgrep");
    assert!(!output.findings.is_empty());
    for finding in &output.findings {
        assert!(
            !finding.title.starts_with("Semgrep rule "),
            "the rule id was used as the title while a message was available: {}",
            finding.title
        );
        assert!(
            finding
                .title
                .contains("subprocess launched through a shell"),
            "the engine's own explanation is missing: {}",
            finding.title
        );
        // The rule id is still recorded; it moved, it was not dropped.
        assert!(
            finding
                .tags
                .iter()
                .any(|tag| tag == "source-rule:ai-security-scanner.python.shell-true"),
            "{:?}",
            finding.tags
        );
    }
}

#[test]
fn engine_supplied_advisory_links_survive_and_unsafe_ones_do_not() {
    // `official_references` is seeded with the manifest's own URLs, so the only
    // way to prove an engine's links are read is to name one the manifest does
    // not contain.
    let trivy = normalize_fixture("trivy");
    let trivy_references = trivy
        .findings
        .iter()
        .flat_map(|finding| finding.official_references.clone())
        .collect::<BTreeSet<_>>();
    assert!(
        trivy_references.contains("https://www.openssl.org/news/secadv/20240408.txt"),
        "Trivy's `References` array is dropped; `PrimaryURL` alone is not the advisory: {trivy_references:?}"
    );
    // Trivy passes advisory links through verbatim, including plain http and
    // mailing-list URLs carrying an @. Neither may be offered to the user.
    assert!(
        !trivy_references
            .iter()
            .any(|reference| reference.starts_with("http://")),
        "{trivy_references:?}"
    );
    assert!(
        !trivy_references
            .iter()
            .any(|reference| reference.contains('@')),
        "{trivy_references:?}"
    );

    let kics = normalize_fixture("kics");
    let kics_references = kics
        .findings
        .iter()
        .flat_map(|finding| finding.official_references.clone())
        .collect::<BTreeSet<_>>();
    assert!(
        kics_references
            .iter()
            .any(|reference| reference.starts_with("https://docs.kics.io/")),
        "KICS names the page documenting the query it failed, and it is dropped: {kics_references:?}"
    );
}

/// The one sentence in a finding that says what to do has to say the right
/// thing. It carried a fixed "a least-privilege configuration or code change"
/// for all twenty-one engines, which is the correct instruction for exactly one
/// of the nine families and is wrong, invisibly, for the rest.
#[test]
fn the_action_a_finding_asks_for_matches_the_kind_of_problem_it_reports() {
    let recommendation = |engine_id: &str| {
        normalize_fixture(engine_id)
            .findings
            .first()
            .unwrap_or_else(|| panic!("{engine_id} fixture must produce a finding"))
            .recommendation
            .clone()
    };

    // A leaked credential is valid until it is revoked. Anything that sends the
    // reader to a permissions screen first leaves it valid for that long.
    for engine_id in ["gitleaks", "trufflehog"] {
        let text = recommendation(engine_id);
        assert!(
            text.contains("revocation and rotation"),
            "{engine_id} must say to revoke the credential: {text}"
        );
        assert!(
            !text.contains("least-privilege"),
            "{engine_id} sends the reader to the wrong screen: {text}"
        );
    }

    // A known CVE in a dependency is not fixed by a configuration change.
    for engine_id in ["trivy", "grype"] {
        let text = recommendation(engine_id);
        assert!(
            text.contains("upgrade to a fixed version"),
            "{engine_id} must name the upgrade: {text}"
        );
    }

    // A permissive cloud policy is the one family least-privilege does describe.
    assert!(recommendation("prowler").contains("least-privilege"));

    // Rewriting the running resource leaves the template that redeployed it.
    for engine_id in ["checkov", "kics"] {
        let text = recommendation(engine_id);
        assert!(
            text.contains("infrastructure-as-code template"),
            "{engine_id} must point at the template: {text}"
        );
    }

    // Guards the collapse this test exists to prevent: a later refactor that
    // reintroduces one shared sentence still satisfies every assertion above
    // for the engines it happens to name, so count the distinct advice too.
    let distinct = BUILTIN_ENGINE_IDS
        .iter()
        .filter_map(|engine_id| {
            let finding = normalize_fixture(engine_id).findings.first()?.clone();
            // Strip the specialist, which already varies; what is under test is
            // the action clause that used to be identical everywhere.
            Some(
                finding
                    .recommendation
                    .rsplit_once("then plan and approve ")?
                    .1
                    .to_owned(),
            )
        })
        .collect::<BTreeSet<_>>();
    // One per family that produces findings, which is all nine: CloudQuery and
    // Syft emit no findings but share a family with engines that do. Pinned
    // exactly, so merging two families is a decision someone has to make here
    // rather than a number that quietly drifts down.
    assert_eq!(
        distinct.len(),
        9,
        "one action clause per family, not {}: {distinct:#?}",
        distinct.len()
    );
}

/// The codes exist so a localized client can compose the sentence itself. That
/// only works if the code says the same thing the English sentence says, and
/// nothing about `family: Some(...)` compiling makes it the right family: a
/// copy-paste that files Gitleaks under `VulnerableComponent` still builds,
/// still serializes, and tells a Chinese reader to upgrade a package when a
/// credential is exposed.
#[test]
fn the_codes_a_localized_client_reads_agree_with_the_english_they_replace() {
    let mut action_by_family: BTreeMap<FindingFamily, BTreeSet<String>> = BTreeMap::new();
    let mut seen_basis: BTreeSet<SeverityBasisCode> = BTreeSet::new();

    for engine_id in BUILTIN_ENGINE_IDS {
        for finding in normalize_fixture(engine_id).findings {
            let family = finding
                .family
                .unwrap_or_else(|| panic!("{engine_id} finding carries no family code"));
            let exposure_observation = finding
                .severity_basis_code
                .is_some_and(|code| code.is_exposure_observation());

            // The action clause is composed from the family, so two findings
            // sharing a family must share it and two families must not.
            if !exposure_observation {
                let action = finding
                    .recommendation
                    .rsplit_once("then plan and approve ")
                    .unwrap_or_else(|| panic!("{engine_id}: {}", finding.recommendation))
                    .1
                    .to_owned();
                action_by_family.entry(family).or_default().insert(action);
            }

            // Exactly the findings tagged as derived carry a basis code, so a
            // client can trust one to explain the other.
            let tagged_derived = finding
                .tags
                .iter()
                .any(|tag| tag == "severity-basis:derived");
            assert_eq!(
                finding.severity_basis_code.is_some(),
                tagged_derived,
                "{engine_id} finding {} disagrees with its own severity-basis tag",
                finding.id
            );
            if let Some(code) = finding.severity_basis_code {
                seen_basis.insert(code);
                if code.is_exposure_observation() {
                    assert!(
                        finding
                            .plain_language_summary
                            .contains("inventory evidence")
                    );
                    assert!(
                        finding
                            .plain_language_summary
                            .contains("not a vulnerability")
                    );
                } else {
                    assert!(
                        finding.plain_language_summary.contains("without rating it"),
                        "{engine_id} carries a basis code for a rating the engine gave: {}",
                        finding.plain_language_summary
                    );
                }
            }
        }
    }

    for (family, actions) in &action_by_family {
        assert_eq!(
            actions.len(),
            1,
            "{family:?} composed more than one action clause: {actions:#?}"
        );
    }
    let distinct_actions = action_by_family
        .values()
        .filter_map(|actions| actions.iter().next().cloned())
        .collect::<BTreeSet<_>>();
    assert_eq!(
        distinct_actions.len(),
        action_by_family.len(),
        "two families share an action clause, so the code cannot be recovered \
         from the sentence: {action_by_family:#?}"
    );

    // Every basis this product can derive is reachable from a shipped fixture.
    // A code no fixture produces is a translation nobody has ever seen render.
    assert_eq!(
        seen_basis.len(),
        5,
        "only {} of the five finding severity bases are exercised: {seen_basis:?}",
        seen_basis.len()
    );
}

/// Every specialist an engine recommends can be named in the reader's language.
///
/// `expert_type_zh_hant` answers with a generic title for a name it has never
/// seen. That is right for a finding restored from a build this one does not
/// know, and wrong for a name this build ships: the reader is told to find
/// someone in general when the product knows exactly who to ask.
///
/// No existing test can see that. The two translation tables agree with each
/// other by construction -- `findingNarrativeParity.test.ts` reads both files
/// and compares them -- so a name missing from both is missing consistently,
/// and the unit tests either side assert on the tables' own contents, which
/// cannot know what the adapters emit. This one asks the adapters. Adding a
/// twenty-second engine with a new specialist fails here rather than shipping
/// a Chinese report that shrugs.
#[test]
fn every_specialist_the_engines_recommend_is_named_in_the_readers_language() {
    const GENERIC: &str = "資安或 IT 專業人員";
    let mut named: BTreeMap<String, String> = BTreeMap::new();

    for engine_id in BUILTIN_ENGINE_IDS {
        for finding in normalize_fixture(engine_id).findings {
            let expert = finding.recommended_expert_type.clone();
            let chinese = expert_type_zh_hant(&expert).to_owned();
            assert_ne!(
                chinese, GENERIC,
                "{engine_id} recommends {expert:?}, and no localized surface can name it"
            );
            named.insert(expert, chinese);
        }
    }

    // A distinct English specialist that collapses onto another's Chinese name
    // hands two different problems to the same person on one side of the
    // product and not the other.
    let distinct = named.values().collect::<BTreeSet<_>>();
    assert_eq!(
        distinct.len(),
        named.len(),
        "two specialists share one Chinese name: {named:#?}"
    );
}

/// The safety and verification sentences are the ones the translator knows.
///
/// Both are matched against the English rather than composed from a code:
/// the safety sentence by exact equality, the verification sentence by its
/// shape. That is deliberate -- if the adapter's wording changes, an exact
/// match falls back to English, which is visible, where a code would keep
/// confidently printing the old sentence in Chinese. But it only degrades
/// safely if something checks the two are still in step, and neither the
/// translator's own tests nor the parity test can: one asserts on its own
/// constants, the other compares the two translations to each other.
#[test]
fn the_safety_and_verification_sentences_are_the_ones_the_translator_knows() {
    let mut engines_seen = 0_usize;
    for engine_id in BUILTIN_ENGINE_IDS {
        for finding in normalize_fixture(engine_id).findings {
            engines_seen += 1;

            if finding
                .severity_basis_code
                .is_some_and(|code| code.is_exposure_observation())
            {
                assert!(
                    finding.rollback_considerations.is_none(),
                    "{engine_id} service inventory carried vulnerability-remediation safety prose"
                );
                assert!(
                    finding.verification_guidance.starts_with("Repeat ")
                        && finding.verification_guidance.contains("discovery"),
                    "{engine_id} service inventory did not explain how to repeat discovery: {}",
                    finding.verification_guidance
                );
                continue;
            }

            let safety = finding
                .rollback_considerations
                .as_deref()
                .unwrap_or_else(|| panic!("{engine_id} carries no safety sentence"));
            assert_eq!(
                safety, ENGLISH_ROLLBACK,
                "{engine_id} writes a safety sentence the translator will not recognize"
            );
            assert_ne!(
                rollback_zh_hant(safety),
                safety,
                "{engine_id} safety sentence fell through untranslated"
            );

            // Recognized, and the engine's own name and rule id survive it --
            // they are the engine's strings and must read identically in both
            // languages.
            let english = &finding.verification_guidance;
            let translated = verification_zh_hant(english);
            assert_ne!(
                &translated, english,
                "{engine_id} verification sentence is not the shape the translator parses: {english}"
            );
            let rule_id = english
                .rsplit_once("source rule ")
                .and_then(|(_, tail)| tail.strip_suffix(" is no longer reported."))
                .unwrap_or_else(|| panic!("{engine_id}: {english}"));
            assert!(
                translated.contains(rule_id),
                "{engine_id} lost its rule id {rule_id}: {translated}"
            );
        }
    }
    assert!(engines_seen >= 21, "only {engines_seen} findings exercised");
}

/// Every priority reason the engines actually write is one the reader's
/// language knows.
///
/// `priority_reasons` is a bare `Vec<String>`: no code, no enum, nothing that
/// fails to compile when a producer invents a new sentence. So the census runs
/// against the producer rather than against the translator's own table -- a
/// test comparing the translator to itself proves it is consistent, never that
/// it is complete, and a reason it does not recognise is returned in English
/// with no error anywhere.
#[test]
fn every_priority_reason_the_engines_write_is_one_the_reader_can_read() {
    let mut reasons_seen = 0_usize;
    let mut derived_seen = 0_usize;
    for engine_id in BUILTIN_ENGINE_IDS {
        for finding in normalize_fixture(engine_id).findings {
            assert!(
                !finding.priority_reasons.is_empty(),
                "{engine_id} explains nothing about why it set this priority"
            );
            for reason in &finding.priority_reasons {
                reasons_seen += 1;
                let translated = priority_reason_zh_hant(reason);
                assert_ne!(
                    &translated, reason,
                    "{engine_id} writes a priority reason the translator does not know: {reason}"
                );
                // The derived-severity reason names the engine. That is the
                // engine's own name and has to survive being said in Chinese,
                // for the same reason the summary sentence keeps it.
                if reason.starts_with("Severity derived from ") {
                    derived_seen += 1;
                    let engine_name = reason
                        .rsplit_once("; ")
                        .and_then(|(_, tail)| tail.strip_suffix(" reports no severity of its own."))
                        .unwrap_or_else(|| panic!("{engine_id}: {reason}"));
                    assert!(
                        translated.contains(engine_name),
                        "{engine_id} lost its own name {engine_name}: {translated}"
                    );
                }
            }
        }
    }
    assert!(reasons_seen >= 38, "only {reasons_seen} reasons exercised");
    // The five finding engines that publish no severity of their own. Naabu
    // and HTTPx now emit typed inventory observations instead.
    assert!(
        derived_seen >= 5,
        "only {derived_seen} derived-severity reasons exercised"
    );
}

/// A cloud account added without its native account id.
///
/// `resolve_asset` treats a provider-qualified OCSF account as authoritative
/// and refuses to fall back to the only selected asset. That is right --
/// attributing an AWS finding to the wrong account is worse than not
/// attributing it. But the identifier map is built only from
/// `asset.identifiers` and nothing makes a person supply one, so someone who
/// adds "Production" and authorizes it gets a run that finds everything,
/// resolves nothing, and returns an empty list.
///
/// The per-record warnings name the rule that was dropped, which is the
/// symptom. Every one of them is different and none of them names the account,
/// so the reader is handed N variations of "something went wrong" and no way to
/// act. The cause is one identifier, and it is said once, with the fix in it.
#[test]
fn prowler_names_the_account_it_could_not_attribute_rather_than_each_dropped_rule() {
    let (bytes, filename, media_type) = fixture("prowler");
    let normalize = |assets: &[Asset], run_id: &str| {
        normalize_bytes_with_assets_and_context(
            "prowler",
            media_type,
            bytes,
            filename,
            run_id,
            assets,
            FrameworkApplicability {
                ai_system: false,
                ai_generated_artifact: false,
            },
        )
    };

    // The same artifact against an asset that does carry the account id. The
    // comparison is the point: the engine, the artifact and the authorization
    // are identical, and only the identifier differs.
    let identified = normalize(
        &[authorized_asset(
            "asset-1",
            AssetKind::CloudAccount,
            Some("aws"),
            &[("aws_account_id", "123456789012")],
        )],
        "run-identified",
    );
    assert!(
        !identified.findings.is_empty(),
        "baseline found nothing, so the comparison below proves nothing"
    );
    assert!(identified.complete);

    // Named, authorized, and never fingerprinted.
    let named_only = normalize(
        &[authorized_asset(
            "asset-1",
            AssetKind::CloudAccount,
            Some("aws"),
            &[],
        )],
        "run-unidentified",
    );
    assert!(
        named_only.findings.is_empty(),
        "the drop itself is deliberate; this test is about what the reader is told"
    );
    assert!(
        !named_only.complete,
        "a run that discarded every result must not claim completion"
    );

    let actionable = named_only
        .warnings
        .iter()
        .find(|warning| warning.contains("no authorized asset carries that identifier"))
        .unwrap_or_else(|| {
            panic!(
                "nothing told the reader why the list is empty: {:?}",
                named_only.warnings
            )
        });
    // The account id is the fix. Without it the reader knows only that
    // something did not match, which is what the per-record warnings already
    // failed to make actionable.
    assert!(
        actionable.contains("123456789012"),
        "the warning does not name the identifier to add: {actionable}"
    );
    assert!(
        actionable.contains(&format!("{} result(s)", identified.findings.len())),
        "the warning does not say how much was discarded: {actionable}"
    );
    assert!(
        actionable.contains("aws"),
        "the warning does not name the provider: {actionable}"
    );

    // Said once for the account, not once per dropped rule.
    assert_eq!(
        named_only
            .warnings
            .iter()
            .filter(|warning| warning.contains("no authorized asset carries that identifier"))
            .count(),
        1,
        "one identifier should produce one warning: {:?}",
        named_only.warnings
    );
}

/// A Prowler run the size a real one is.
///
/// The fixture holds three records, so the actionable warning fits easily. A
/// default AWS scan emits hundreds, `push_warning` silently stops accepting at
/// MAX_WARNINGS, and the per-record warnings are pushed inside the loop while
/// the one sentence naming the account is pushed after it. Passing at three
/// records and failing at three hundred is exactly the shape a fixture-sized
/// test cannot see.
#[test]
fn the_account_warning_survives_a_run_with_more_records_than_the_warning_cap() {
    let base: serde_json::Value = serde_json::from_slice(fixture("prowler").0).expect("fixture");
    let template = base
        .as_array()
        .and_then(|records| records.first())
        .expect("fixture record")
        .clone();

    // Comfortably past MAX_WARNINGS, which is what a real account produces.
    let mut records = Vec::new();
    for index in 0..400 {
        let mut record = template.clone();
        let rule = format!("check_{index:04}");
        record["metadata"]["event_code"] = serde_json::json!(rule);
        record["finding_info"]["analytic"]["uid"] = serde_json::json!(rule);
        record["finding_info"]["uid"] = serde_json::json!(format!("instance-{index}"));
        records.push(record);
    }
    let bytes = serde_json::to_vec(&serde_json::Value::Array(records)).expect("artifact");

    let output = normalize_bytes_with_assets_and_context(
        "prowler",
        "application/json",
        &bytes,
        "prowler-ocsf.json",
        "run-large",
        &[authorized_asset(
            "asset-1",
            AssetKind::CloudAccount,
            Some("aws"),
            &[],
        )],
        FrameworkApplicability {
            ai_system: false,
            ai_generated_artifact: false,
        },
    );

    assert!(output.findings.is_empty());
    let position = output
        .warnings
        .iter()
        .position(|warning| warning.contains("no authorized asset carries that identifier"))
        .unwrap_or_else(|| {
            panic!(
                "the one actionable sentence was dropped by the warning cap; {} warnings survived, all of them naming a rule instead of the account",
                output.warnings.len()
            )
        });
    // Reaching the list is not enough. The progress view joins every warning
    // into one string and truncates it, so a sentence sitting behind hundreds
    // of per-record lines is cut off before it is read.
    assert_eq!(
        position, 0,
        "the actionable sentence is buried behind {position} per-record warnings"
    );
}
