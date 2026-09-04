use ai_security_scanner_lib::adapter::{AdapterAssetIdentifierMap, AdapterInput, AdapterOutput};
use ai_security_scanner_lib::adapters::{BUILTIN_ENGINE_IDS, builtin_adapter_registry};
use ai_security_scanner_lib::domain::{
    Asset, AssetIdentifier, AssetKind, FindingStatus, RawArtifact, Severity,
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

#[test]
fn native_fixtures_normalize_without_inventing_inventory_findings() {
    let no_security_findings = BTreeSet::from(["cloudquery", "syft"]);
    for engine_id in BUILTIN_ENGINE_IDS {
        let output = normalize_fixture(engine_id);
        assert!(
            output.complete,
            "native fixture for {engine_id} must normalize completely"
        );
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
fn checkov_missing_and_unrecognized_severity_stays_unknown() {
    let bytes = br#"{
      "results": {
        "failed_checks": [
          {"check_id":"missing", "check_name":"Missing rating", "file_path":"missing.tf"},
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
        .map(|finding| (finding.title.as_str(), &finding.severity))
        .collect::<BTreeMap<_, _>>();
    assert_eq!(by_title["Missing rating"], &Severity::Unknown);
    assert_eq!(by_title["Custom rating"], &Severity::Unknown);
    assert_eq!(by_title["Information only"], &Severity::Informational);
}

#[test]
fn m365_missing_and_unrecognized_source_ratings_stay_unknown_and_traceable() {
    let cases: [(&str, &[u8], &str, &str, &str); 2] = [
        (
            "scubagear",
            br#"{
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
                && reference.mapping_version == "2026-08-28.1"
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

    let httpx = serde_json::to_string(&normalize_fixture("httpx").findings)
        .expect("serialize httpx findings");
    assert!(!httpx.contains("target-controlled text is data"));
    assert!(!httpx.contains("session=must-not-appear"));

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
