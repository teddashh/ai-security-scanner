use ai_security_scanner_lib::adapter::{AdapterAssetIdentifierMap, AdapterInput, AdapterOutput};
use ai_security_scanner_lib::adapters::{BUILTIN_ENGINE_IDS, builtin_adapter_registry};
use ai_security_scanner_lib::correlation::correlation_report;
use ai_security_scanner_lib::domain::{
    AssessmentCase, Asset, AssetIdentifier, AssetKind, Confidence, DataClass, FindingStatus,
    OrganizationProfile, RawArtifact, Severity,
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

/// Engines that emit no severity anywhere in their output, with the rating this
/// product derives and the basis it has to disclose.
///
/// Each of these was previously handed a hard-coded severity string, which
/// reached the user as `source-severity:high` or `source-severity:informational`
/// — a rating the engine never gave. Verified against the pinned checkouts: the
/// word "severity" does not appear in gitleaks' or naabu's Go sources at all;
/// TruffleHog's JSON printer marshals a fixed struct with no such field; httpx's
/// result struct has none; and kube-bench's `Check` struct has none.
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
    (
        "naabu",
        Severity::Informational,
        "an open port observation rather than a defect",
    ),
    (
        "httpx",
        Severity::Informational,
        "a reachable HTTP service observation rather than a defect",
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

/// The other side of the same contract. Deriving a severity is only defensible
/// where the engine truly reports none, so an engine that does report one must
/// keep showing what it said.
#[test]
fn engines_that_report_a_severity_still_present_the_engines_own_rating() {
    let derived = DERIVED_SEVERITY_ENGINES
        .iter()
        .map(|(engine_id, _, _)| *engine_id)
        .collect::<BTreeSet<_>>();
    let mut checked = 0;
    for engine_id in BUILTIN_ENGINE_IDS {
        if derived.contains(engine_id) {
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
