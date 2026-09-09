use ai_security_scanner_lib::adapters::builtin_adapter_registry;
use ai_security_scanner_lib::artifact_store::ArtifactStore;
use ai_security_scanner_lib::beginner_report::{
    BeginnerInventoryItemKind, build_beginner_master_report,
};
use ai_security_scanner_lib::case_service::{
    CaseExportFormat, CaseService, DurableExecutionReport, EngineAssetRoute,
    PlannedEngineExecution, ScanPlanRequest, ScopeApprovalRequest,
};
use ai_security_scanner_lib::container_runtime::{
    CancellationToken, FakeContainerRuntime, FakeRunBehavior, NetworkPolicy, ResourceLimits,
    ScannerCredentialSet,
};
use ai_security_scanner_lib::domain::{
    AiGeneratedArtifactAnswer, AssessmentActivity, AssessmentIntent, Asset, AssetKind, CaseStatus,
    CoverageStatus, CreateCaseRequest, DataClass, DeclaredAssetInput, DeclaredAssetKind,
    DeclaredHostScanInput, DeclaredHostScanProfile, DeclaredNetworkProtocol, EngineRunStatus,
    FindingDiffStatus, InventoryObservationKind, ScanPermission, ScopeGrant,
    UnevaluatedTargetCause,
};
use ai_security_scanner_lib::export::ExportOptions;
use ai_security_scanner_lib::external_scope::{
    ExternalActivity, ExternalScopeRequest, RatePolicy, TemplatePolicy, TransportProtocol,
};
use ai_security_scanner_lib::orchestrator::{
    EngineExecutionRequest, ExecutionReport, ExecutionStage, Orchestrator,
};
use ai_security_scanner_lib::registry::EngineRegistry;
use ai_security_scanner_lib::storage::Storage;
use ai_security_scanner_lib::workspace_snapshot::{
    WorkspaceInputProfile, WorkspaceSnapshotLimits, WorkspaceSnapshotReference,
    create_workspace_snapshot, create_workspace_snapshot_with_profile, resolve_workspace_snapshot,
};
use chrono::{DateTime, Duration, NaiveDate, Utc};
use serde_json::Value;
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::io::Cursor;
use std::path::{Path, PathBuf};

const GITLEAKS_FIXTURE: &[u8] = include_bytes!("fixtures/adapters/gitleaks.json");
const KICS_FIXTURE: &[u8] = include_bytes!("fixtures/adapters/kics.json");
const CHECKOV_FIXTURE: &[u8] = include_bytes!("fixtures/adapters/checkov.json");
const SYFT_FIXTURE: &[u8] = include_bytes!("fixtures/adapters/syft.json");
const TRIVY_FIXTURE: &[u8] = include_bytes!("fixtures/adapters/trivy.json");
const GRYPE_FIXTURE: &[u8] = include_bytes!("fixtures/adapters/grype.json");
const KUBESCAPE_FIXTURE: &[u8] = include_bytes!("fixtures/adapters/kubescape.json");
const KUBE_BENCH_FIXTURE: &[u8] = include_bytes!("fixtures/adapters/kube-bench.json");
const GREENBONE_RESULT_TYPES_FIXTURE: &[u8] =
    include_bytes!("fixtures/adapters/greenbone-result-types.xml");

fn output_filename(engine_id: &str) -> &'static str {
    match engine_id {
        "gitleaks" => "gitleaks.json",
        "kics" => "kics.json",
        "checkov" => "checkov.json",
        "syft" => "syft.json",
        "trivy" => "trivy.json",
        "grype" => "grype.json",
        "kubescape" => "kubescape.json",
        "kube-bench" => "kube-bench.json",
        other => panic!("no lifecycle fixture output for {other}"),
    }
}

fn baseline_output(engine_id: &str) -> &'static [u8] {
    match engine_id {
        "gitleaks" => GITLEAKS_FIXTURE,
        "kics" => KICS_FIXTURE,
        "checkov" => CHECKOV_FIXTURE,
        "syft" => SYFT_FIXTURE,
        "trivy" => TRIVY_FIXTURE,
        "grype" => GRYPE_FIXTURE,
        "kubescape" => KUBESCAPE_FIXTURE,
        "kube-bench" => KUBE_BENCH_FIXTURE,
        other => panic!("no lifecycle fixture bytes for {other}"),
    }
}

/// Findings each lifecycle fixture is expected to yield. Syft emits an
/// inventory rather than findings; the Kubescape fixture carries the authentic
/// v2 shape with three failing controls across two resources; the Trivy and
/// Grype fixtures each carry one exclusive vulnerability plus the one both
/// engines report, which is the ordinary result of scanning one image twice;
/// the kube-bench fixture is a full run of the shipped six-check snapshot
/// benchmark against an unhardened node, three of whose checks fail; and the
/// Checkov fixture carries one check that publishes a severity offline and one
/// that does not, since almost none of them do.
fn expected_finding_count(engine_id: &str) -> usize {
    match engine_id {
        "syft" => 0,
        "kubescape" | "kube-bench" => 3,
        "trivy" | "grype" | "checkov" => 2,
        _ => 1,
    }
}

fn execute_fixture(
    orchestrator: &Orchestrator<'_, FakeContainerRuntime>,
    runtime: &FakeContainerRuntime,
    execution: &PlannedEngineExecution,
    workspace: &Path,
    output: Vec<u8>,
) -> ExecutionReport {
    runtime.set_behavior(FakeRunBehavior {
        exit_code: Some(0),
        stdout: Vec::new(),
        stderr: Vec::new(),
        output_files: BTreeMap::from([(
            output_filename(&execution.manifest.id).to_owned(),
            output,
        )]),
    });
    let network = NetworkPolicy::Disabled;
    let resources = ResourceLimits::default();
    let credentials = ScannerCredentialSet::default();
    let request = EngineExecutionRequest {
        case_id: &execution.case_id,
        scan_run_id: &execution.scan_run_id,
        engine_run_id: &execution.engine_run_id,
        manifest: &execution.manifest,
        ai_system_applicable: execution.ai_system_applicable,
        ai_generated_artifact_applicable: execution.ai_generated_artifact
            == AiGeneratedArtifactAnswer::Yes,
        assets: &execution.assets,
        scope_grants: &execution.scope_grants,
        frozen_destinations: None,
        naabu_launcher_plan: None,
        expected_naabu_launcher_plan_sha256: None,
        workspace: Some(workspace),
        network_policy: &network,
        resource_limits: &resources,
        credentials: &credentials,
        attempt: execution.attempt,
    };

    orchestrator
        .execute(&request, &CancellationToken::default())
        .expect("representative scanner execution")
}

fn assert_report_provenance(
    artifact_root: &Path,
    execution: &PlannedEngineExecution,
    report: &ExecutionReport,
) {
    assert_eq!(report.checkpoint.stage, ExecutionStage::Completed);
    assert!(report.checkpoint.cleanup_completed);
    assert_eq!(report.exit_code, Some(0));
    assert_eq!(report.checkpoint.case_id, execution.case_id);
    assert_eq!(report.checkpoint.scan_run_id, execution.scan_run_id);
    assert_eq!(report.checkpoint.engine_run_id, execution.engine_run_id);
    assert_eq!(report.checkpoint.engine_id, execution.manifest.id);
    assert_eq!(report.raw_artifacts.len(), 3);
    assert_eq!(
        report.findings.len(),
        expected_finding_count(&execution.manifest.id)
    );

    let artifact_ids = report
        .raw_artifacts
        .iter()
        .map(|artifact| artifact.id.as_str())
        .collect::<BTreeSet<_>>();
    for artifact in &report.raw_artifacts {
        assert_eq!(artifact.case_id, execution.case_id);
        assert_eq!(artifact.run_id, execution.scan_run_id);
        assert_eq!(artifact.engine_run_id, execution.engine_run_id);
        let bytes = fs::read(artifact_root.join(&artifact.relative_path))
            .expect("durable raw artifact remains readable");
        assert_eq!(artifact.byte_length, bytes.len() as u64);
        assert_eq!(artifact.sha256, hex::encode(Sha256::digest(&bytes)));
    }

    for finding in &report.findings {
        assert_eq!(finding.case_id, execution.case_id);
        assert_eq!(finding.first_seen_run_id, execution.scan_run_id);
        assert_eq!(finding.last_seen_run_id, execution.scan_run_id);
        assert_eq!(finding.asset_ids, [execution.assets[0].id.clone()]);
        assert!(!finding.evidence.is_empty());
        for evidence in &finding.evidence {
            assert_eq!(evidence.run_id, execution.scan_run_id);
            assert_eq!(evidence.engine_id, execution.manifest.id);
            assert!(artifact_ids.contains(evidence.artifact_id.as_str()));
            let artifact = report
                .raw_artifacts
                .iter()
                .find(|artifact| artifact.id == evidence.artifact_id)
                .expect("evidence artifact is part of the same execution report");
            assert_eq!(evidence.artifact_sha256, artifact.sha256);
        }
        if execution.manifest.id == "gitleaks" {
            assert!(finding.evidence.iter().all(|evidence| evidence.redacted));
            assert!(
                !serde_json::to_string(finding)
                    .expect("finding JSON")
                    .contains("SECRET_SENTINEL_MUST_NEVER_LEAK")
            );
        }
    }
}

fn make_workspace(root: &Path, name: &str, marker: &str) -> PathBuf {
    let workspace = root.join(name);
    fs::create_dir_all(workspace.join("infra")).expect("working tree directories");
    fs::write(
        workspace.join("infra/storage.tf"),
        format!("# {marker}\nresource \"example\" \"{marker}\" {{}}\n"),
    )
    .expect("working tree IaC file");
    fs::write(
        workspace.join("config.example.env"),
        format!("WORKSPACE_MARKER={marker}\n"),
    )
    .expect("working tree source file");
    workspace
}

fn write_oci_layout(root: &Path) {
    let blobs = root.join("blobs/sha256");
    fs::create_dir_all(&blobs).unwrap();
    fs::write(
        root.join("oci-layout"),
        br#"{"imageLayoutVersion":"1.0.0"}"#,
    )
    .unwrap();
    let contents = b"typed lifecycle layer";
    let mut builder = tar::Builder::new(Vec::new());
    let mut header = tar::Header::new_ustar();
    header.set_entry_type(tar::EntryType::Regular);
    header.set_mode(0o644);
    header.set_uid(0);
    header.set_gid(0);
    header.set_mtime(0);
    header.set_size(contents.len() as u64);
    header.set_path("app/fixture.txt").unwrap();
    header.set_cksum();
    builder.append(&header, Cursor::new(contents)).unwrap();
    builder.finish().unwrap();
    let layer = builder.into_inner().unwrap();
    let layer_digest = hex::encode(Sha256::digest(&layer));
    let config = serde_json::to_vec(&serde_json::json!({
        "architecture": "amd64",
        "os": "linux",
        "rootfs": {"type": "layers", "diff_ids": [format!("sha256:{layer_digest}")]},
        "config": {}
    }))
    .unwrap();
    let config_digest = hex::encode(Sha256::digest(&config));
    fs::write(blobs.join(&config_digest), &config).unwrap();
    fs::write(blobs.join(&layer_digest), &layer).unwrap();
    let manifest = serde_json::to_vec(&serde_json::json!({
        "schemaVersion": 2,
        "mediaType": "application/vnd.oci.image.manifest.v1+json",
        "config": {
            "mediaType": "application/vnd.oci.image.config.v1+json",
            "digest": format!("sha256:{config_digest}"),
            "size": config.len()
        },
        "layers": [{
            "mediaType": "application/vnd.oci.image.layer.v1.tar",
            "digest": format!("sha256:{layer_digest}"),
            "size": layer.len()
        }]
    }))
    .unwrap();
    let manifest_digest = hex::encode(Sha256::digest(&manifest));
    fs::write(blobs.join(&manifest_digest), &manifest).unwrap();
    fs::write(
        root.join("index.json"),
        serde_json::to_vec(&serde_json::json!({
            "schemaVersion": 2,
            "mediaType": "application/vnd.oci.image.index.v1+json",
            "manifests": [{
                "mediaType": "application/vnd.oci.image.manifest.v1+json",
                "digest": format!("sha256:{manifest_digest}"),
                "size": manifest.len()
            }]
        }))
        .unwrap(),
    )
    .unwrap();
}

fn write_node_snapshot(root: &Path) {
    let node = root.join("node-snapshot");
    fs::create_dir_all(&node).unwrap();
    let config = b"kind: KubeletConfiguration\n";
    fs::write(node.join("kubelet-config.yaml"), config).unwrap();
    fs::write(
        node.join("profile.json"),
        serde_json::to_vec(&serde_json::json!({
            "schema_version": "1.0.0",
            "profile": "cis-kubernetes-node-config",
            "captured_at": "2026-08-24T12:00:00Z",
            "files": [{
                "path": "kubelet-config.yaml",
                "sha256": format!("sha256:{}", hex::encode(Sha256::digest(config)))
            }]
        }))
        .unwrap(),
    )
    .unwrap();
}

#[test]
fn local_case_lifecycle_preserves_scope_evidence_and_comparison_truth() {
    let temporary = tempfile::tempdir().expect("lifecycle temporary directory");
    let storage = Storage::open(temporary.path().join("casework.db")).expect("private storage");
    let engines = EngineRegistry::load_builtin().expect("supported built-in engine catalog");
    let adapters = builtin_adapter_registry().expect("built-in adapters");
    let artifacts =
        ArtifactStore::open(temporary.path().join("artifacts")).expect("private artifact store");
    let artifact_root = artifacts.root().to_path_buf();
    let service = CaseService::new(
        &storage,
        &engines,
        &adapters,
        &artifact_root,
        temporary.path().join("integrity-signing-key"),
    );

    let case = service
        .create_case(&CreateCaseRequest {
            title: "Local repository assessment".into(),
            organization_name: "Example organization".into(),
            employee_range: "1-10".into(),
            assessment_intent: None,
            ai_generated_artifact: Default::default(),
            data_classes: vec![DataClass::CredentialsAndSecrets],
            requested_activities: vec![],
            source_kinds: vec![],
            not_applicable_source_kinds: vec![],
            declared_assets: vec![],
            notes: Some("Integration lifecycle fixture".into()),
        })
        .expect("case creation");

    let source_root = temporary.path().join("selected-working-trees");
    fs::create_dir(&source_root).expect("selected source root");
    let selected_a = make_workspace(&source_root, "workspace-a", "alpha");
    let selected_b = make_workspace(&source_root, "workspace-b", "bravo");
    let mut references = BTreeMap::<String, WorkspaceSnapshotReference>::new();
    for (source_id, label, selected) in [
        ("workspace-source-a", "Working tree A", selected_a),
        ("workspace-source-b", "Working tree B", selected_b),
    ] {
        let snapshot = create_workspace_snapshot(
            &artifact_root,
            &case.id,
            source_id,
            selected,
            WorkspaceSnapshotLimits::default(),
        )
        .expect("immutable working-tree snapshot");
        references.insert(snapshot.asset.id.clone(), snapshot.reference.clone());
        service
            .attach_workspace_snapshot(&case.id, label, snapshot)
            .expect("source-grounded snapshot attachment");
    }

    let discovered = service.show_case(&case.id).expect("discovered case");
    assert_eq!(discovered.assets.len(), 2);
    let asset_coverage = discovered
        .coverage
        .iter()
        .filter(|entry| entry.asset_id.is_some())
        .collect::<Vec<_>>();
    assert_eq!(asset_coverage.len(), 2);
    assert!(
        asset_coverage
            .iter()
            .all(|entry| entry.status == CoverageStatus::DiscoveredNotAuthorized)
    );
    assert!(
        discovered
            .assets
            .iter()
            .all(|asset| asset.candidate && !asset.owner_confirmed)
    );

    let asset_ids = discovered
        .assets
        .iter()
        .map(|asset| asset.id.clone())
        .collect::<Vec<_>>();
    for asset_id in &asset_ids {
        service
            .approve_scope(
                &case.id,
                ScopeApprovalRequest {
                    asset_id: asset_id.clone(),
                    permissions: vec![ScanPermission::LocalArtifactRead],
                    confirmed_by: "Repository owner".into(),
                    expires_at: None,
                    authorization_reference: None,
                    notes: Some("Read-only immutable working-tree snapshot".into()),
                    external_scope: None,
                },
            )
            .expect("explicit local-artifact scope approval");
    }

    let lifecycle_engine_ids = ["checkov", "gitleaks", "kics", "syft"];
    let plan = service
        .plan_scan(
            &case.id,
            ScanPlanRequest {
                engine_ids: lifecycle_engine_ids
                    .iter()
                    .map(|engine_id| (*engine_id).to_owned())
                    .collect(),
                engine_asset_routes: Vec::new(),
            },
        )
        .expect("fixture-backed local scan plan");
    assert!(plan.not_executed.is_empty());
    assert_eq!(plan.executable.len(), 8);
    let planned_pairs = plan
        .executable
        .iter()
        .map(|execution| {
            assert!(execution.manifest.compatibility.runnable);
            assert_eq!(execution.assets.len(), 1);
            (
                execution.manifest.id.clone(),
                execution.assets[0].id.clone(),
            )
        })
        .collect::<BTreeSet<_>>();
    let expected_pairs = lifecycle_engine_ids
        .into_iter()
        .flat_map(|engine_id| {
            asset_ids
                .iter()
                .cloned()
                .map(move |asset_id| (engine_id.to_owned(), asset_id))
        })
        .collect::<BTreeSet<_>>();
    assert_eq!(planned_pairs, expected_pairs);
    for unavailable in engines
        .manifests()
        .iter()
        .filter(|manifest| manifest.release_blocker().is_some())
    {
        assert!(
            !plan
                .executable
                .iter()
                .any(|execution| execution.manifest.id == unavailable.id)
        );
    }

    let resolved_workspaces = references
        .iter()
        .map(|(asset_id, reference)| {
            let resolved = resolve_workspace_snapshot(&artifact_root, &case.id, reference)
                .expect("backend-derived immutable workspace resolution");
            (asset_id.clone(), resolved.tree_path)
        })
        .collect::<BTreeMap<_, _>>();
    let runtime = FakeContainerRuntime::default();
    let orchestrator = Orchestrator::new(&runtime, &artifacts, &adapters);
    for execution in &plan.executable {
        let workspace = resolved_workspaces
            .get(&execution.assets[0].id)
            .expect("execution has an attached workspace snapshot");
        let report = execute_fixture(
            &orchestrator,
            &runtime,
            execution,
            workspace,
            baseline_output(&execution.manifest.id).to_vec(),
        );
        assert_report_provenance(&artifact_root, execution, &report);
        service
            .apply_execution_report(&case.id, &DurableExecutionReport::from(&report))
            .expect("durable execution reconciliation");
    }

    let baseline = service
        .show_case(&case.id)
        .expect("completed baseline case");
    let baseline_run = baseline
        .scan_runs
        .iter()
        .find(|run| run.id == plan.scan_run.id)
        .expect("baseline run persisted");
    assert!(baseline_run.completed_at.is_some());
    assert!(
        baseline_run
            .engine_runs
            .iter()
            .all(|run| run.status == EngineRunStatus::Completed)
    );
    assert_eq!(baseline.status, CaseStatus::ReadyForHandoff);
    let expected_baseline_findings = plan
        .executable
        .iter()
        .map(|execution| expected_finding_count(&execution.manifest.id))
        .sum::<usize>();
    assert_eq!(baseline.findings.len(), expected_baseline_findings);
    assert_eq!(
        baseline.finding_observations.len(),
        expected_baseline_findings
    );
    assert_eq!(baseline.raw_artifacts.len(), 24);
    assert!(
        baseline
            .coverage
            .iter()
            .filter(|entry| entry.asset_id.is_some())
            .all(|entry| entry.status == CoverageStatus::DiscoveredAuthorizedScanned)
    );
    for observation in &baseline.finding_observations {
        assert_eq!(observation.run_id, plan.scan_run.id);
        assert_eq!(observation.engine_ids.len(), 1);
        assert_eq!(observation.asset_ids.len(), 1);
        assert!(!observation.evidence_hashes.is_empty());
        assert!(
            observation
                .evidence_hashes
                .iter()
                .all(|digest| digest.len() == 64)
        );
    }

    let bundle_path = temporary.path().join("baseline.case.tar.gz");
    let bundle = service
        .export_case(
            &case.id,
            &plan.scan_run.id,
            CaseExportFormat::CaseBundle,
            &bundle_path,
            ExportOptions::default(),
        )
        .expect("explicit case bundle export");
    assert!(bundle.signature.is_some());
    assert!(bundle.public_key.is_some());
    let verified = service
        .verify_stored_export(&case.id, &bundle.id)
        .expect("stored bundle verification");
    assert!(verified.valid);
    let verified_bundle = verified.bundle.expect("signed bundle details");
    assert!(verified_bundle.valid);
    assert_eq!(verified_bundle.manifest.run_id, plan.scan_run.id);
    assert_eq!(verified_bundle.manifest.raw_artifact_count, 24);
    assert_eq!(verified_bundle.manifest.raw_artifacts_included, 0);

    let rescan = service
        .plan_rescan(
            &case.id,
            &plan.scan_run.id,
            ScanPlanRequest {
                engine_ids: vec!["gitleaks".into()],
                engine_asset_routes: Vec::new(),
            },
        )
        .expect("comparable exact-scope rescan");
    assert_eq!(rescan.plan.executable.len(), 2);
    let changed_asset_id = asset_ids[0].clone();
    let changed_output = String::from_utf8(GITLEAKS_FIXTURE.to_vec())
        .expect("UTF-8 fixture")
        .replace("Potential API key", "Potential rotated API key")
        .into_bytes();
    for execution in &rescan.plan.executable {
        let output = if execution.assets[0].id == changed_asset_id {
            changed_output.clone()
        } else {
            b"[]".to_vec()
        };
        let workspace = resolved_workspaces
            .get(&execution.assets[0].id)
            .expect("rescan workspace");
        let report = execute_fixture(&orchestrator, &runtime, execution, workspace, output);
        assert_eq!(report.checkpoint.stage, ExecutionStage::Completed);
        if execution.assets[0].id == changed_asset_id {
            assert_eq!(report.findings.len(), 1);
        } else {
            assert!(report.findings.is_empty());
        }
        service
            .apply_execution_report(&case.id, &DurableExecutionReport::from(&report))
            .expect("rescan execution reconciliation");
    }
    let current = service.show_case(&case.id).expect("completed rescan case");
    let current_run = current
        .scan_runs
        .iter()
        .find(|run| run.id == rescan.plan.scan_run.id)
        .expect("current run persisted");
    assert!(current_run.completed_at.is_some());
    assert!(
        current_run
            .engine_runs
            .iter()
            .all(|run| run.status == EngineRunStatus::Completed)
    );

    let comparison = service
        .compare_and_persist(&case.id, &plan.scan_run.id, &rescan.plan.scan_run.id)
        .expect("coverage-aware comparison");
    let gitleaks_statuses = comparison
        .diffs
        .iter()
        .filter(|diff| diff.fingerprint.starts_with("gitleaks:"))
        .map(|diff| &diff.status)
        .collect::<Vec<_>>();
    assert_eq!(gitleaks_statuses.len(), 2);
    assert!(gitleaks_statuses.contains(&&FindingDiffStatus::Changed));
    assert!(gitleaks_statuses.contains(&&FindingDiffStatus::Resolved));
    let kics_diffs = comparison
        .diffs
        .iter()
        .filter(|diff| diff.fingerprint.starts_with("kics:"))
        .collect::<Vec<_>>();
    assert_eq!(kics_diffs.len(), 2);
    assert!(
        kics_diffs
            .iter()
            .all(|diff| diff.status == FindingDiffStatus::UnableToVerify)
    );
    assert!(
        kics_diffs
            .iter()
            .all(|diff| diff.explanation.contains("engine=kics"))
    );

    // A JSON-only repository asset carries no backend snapshot reference. Even
    // with a forged grant, the public orchestrator boundary refuses to execute
    // a local scanner without an explicitly resolved workspace path.
    let mut json_asset_value = serde_json::to_value(&baseline.assets[0]).expect("asset JSON");
    json_asset_value["id"] = serde_json::Value::String("json-only-repository".into());
    json_asset_value["metadata"] = serde_json::json!({});
    json_asset_value["discovered_from"] = serde_json::json!(["json-only-source"]);
    let json_only_asset: Asset =
        serde_json::from_value(json_asset_value).expect("JSON-only repository asset");
    let forged_grant = ScopeGrant {
        id: "json-only-grant".into(),
        asset_id: json_only_asset.id.clone(),
        permission: ScanPermission::LocalArtifactRead,
        confirmed_by: "Untrusted JSON".into(),
        confirmed_at: Utc::now(),
        expires_at: None,
        authorization_reference: None,
        notes: None,
        external_scope: None,
    };
    let gitleaks = engines.get("gitleaks").expect("Gitleaks manifest");
    let no_workspace_assets = [json_only_asset];
    let no_workspace_grants = [forged_grant];
    let network = NetworkPolicy::Disabled;
    let resources = ResourceLimits::default();
    let credentials = ScannerCredentialSet::default();
    let no_workspace_request = EngineExecutionRequest {
        case_id: &case.id,
        scan_run_id: "json-only-scan",
        engine_run_id: "json-only-engine-run",
        manifest: gitleaks,
        ai_system_applicable: false,
        ai_generated_artifact_applicable: false,
        assets: &no_workspace_assets,
        scope_grants: &no_workspace_grants,
        frozen_destinations: None,
        naabu_launcher_plan: None,
        expected_naabu_launcher_plan_sha256: None,
        workspace: None,
        network_policy: &network,
        resource_limits: &resources,
        credentials: &credentials,
        attempt: 1,
    };
    let denied = orchestrator
        .execute(&no_workspace_request, &CancellationToken::default())
        .expect_err("JSON-only repository must not execute without a snapshot");
    assert!(
        denied
            .to_string()
            .contains("requires an explicitly selected local workspace")
    );

    // An explicitly requested engine that is absent from this exact release
    // remains a durable terminal not-executed record. The assertion must not
    // depend on a currently published catalog engine staying unreleased.
    let unavailable_ids = vec!["fixture-engine-not-in-release".into()];
    let unavailable = service
        .plan_scan(
            &case.id,
            ScanPlanRequest {
                engine_ids: unavailable_ids.clone(),
                engine_asset_routes: Vec::new(),
            },
        )
        .expect("truthful unavailable-engine plan");
    assert!(unavailable.executable.is_empty());
    assert_eq!(unavailable.not_executed.len(), unavailable_ids.len());
    assert!(unavailable.scan_run.completed_at.is_some());
    assert!(
        unavailable
            .scan_run
            .engine_runs
            .iter()
            .all(|run| run.status == EngineRunStatus::NotExecuted)
    );
    assert_eq!(
        unavailable
            .not_executed
            .iter()
            .map(|entry| entry.engine_id.as_str())
            .collect::<BTreeSet<_>>(),
        unavailable_ids.iter().map(String::as_str).collect()
    );
}

#[test]
fn typed_container_and_kubernetes_inputs_complete_the_product_lifecycle() {
    let temporary = tempfile::tempdir().expect("typed lifecycle temporary directory");
    let storage = Storage::open(temporary.path().join("typed-casework.db")).unwrap();
    let engines = EngineRegistry::load_builtin().unwrap();
    let adapters = builtin_adapter_registry().unwrap();
    let artifacts = ArtifactStore::open(temporary.path().join("typed-artifacts")).unwrap();
    let artifact_root = artifacts.root().to_path_buf();
    let service = CaseService::new(
        &storage,
        &engines,
        &adapters,
        &artifact_root,
        temporary.path().join("typed-integrity-key"),
    );
    let case = service
        .create_case(&CreateCaseRequest {
            title: "Typed local inputs".into(),
            organization_name: "Example organization".into(),
            employee_range: "1-10".into(),
            assessment_intent: None,
            ai_generated_artifact: Default::default(),
            data_classes: vec![],
            requested_activities: vec![],
            source_kinds: vec![],
            not_applicable_source_kinds: vec![],
            declared_assets: vec![],
            notes: None,
        })
        .unwrap();

    let selected = temporary.path().join("typed-selected-inputs");
    let oci = selected.join("oci");
    let manifests = selected.join("manifests");
    let node = selected.join("node");
    fs::create_dir_all(&oci).unwrap();
    fs::create_dir_all(&manifests).unwrap();
    fs::create_dir_all(&node).unwrap();
    write_oci_layout(&oci);
    fs::write(
        manifests.join("pod.yaml"),
        b"apiVersion: v1\nkind: Pod\nmetadata:\n  name: fixture\n",
    )
    .unwrap();
    write_node_snapshot(&node);

    let mut references = BTreeMap::<String, WorkspaceSnapshotReference>::new();
    for (source_id, label, path, profile) in [
        (
            "typed-oci-source",
            "OCI image",
            oci,
            WorkspaceInputProfile::ContainerImageOciLayout,
        ),
        (
            "typed-kubernetes-source",
            "Kubernetes manifests",
            manifests,
            WorkspaceInputProfile::KubernetesManifests,
        ),
        (
            "typed-node-source",
            "Kubernetes node",
            node,
            WorkspaceInputProfile::KubernetesNodeSnapshot,
        ),
    ] {
        let snapshot = create_workspace_snapshot_with_profile(
            &artifact_root,
            &case.id,
            source_id,
            path,
            profile,
            WorkspaceSnapshotLimits::default(),
        )
        .unwrap();
        references.insert(snapshot.asset.id.clone(), snapshot.reference.clone());
        service
            .attach_workspace_snapshot(&case.id, label, snapshot)
            .unwrap();
    }

    let attached = service.show_case(&case.id).unwrap();
    assert_eq!(attached.assets.len(), 3);
    assert!(
        attached.data_sources.iter().all(|source| {
            source.kind == ai_security_scanner_lib::domain::SourceKind::FileSystem
        })
    );
    for asset in &attached.assets {
        service
            .approve_scope(
                &case.id,
                ScopeApprovalRequest {
                    asset_id: asset.id.clone(),
                    permissions: vec![ScanPermission::LocalArtifactRead],
                    confirmed_by: "Typed input owner".into(),
                    expires_at: None,
                    authorization_reference: None,
                    notes: None,
                    external_scope: None,
                },
            )
            .unwrap();
    }

    let plan = service
        .plan_scan(
            &case.id,
            ScanPlanRequest {
                engine_ids: ["syft", "trivy", "grype", "kubescape", "kube-bench"]
                    .into_iter()
                    .map(str::to_owned)
                    .collect(),
                engine_asset_routes: Vec::new(),
            },
        )
        .unwrap();
    assert!(plan.not_executed.is_empty());
    assert_eq!(plan.executable.len(), 5);
    assert!(plan.executable.iter().all(|execution| {
        execution.assets.len() == 1
            && execution.manifest.input_contracts.iter().any(|contract| {
                contract.asset_kind == execution.assets[0].kind
                    && contract.input_profile == references[&execution.assets[0].id].input_profile
            })
    }));
    let syft_execution = plan
        .executable
        .iter()
        .find(|execution| execution.manifest.id == "syft")
        .expect("typed OCI input routes to Syft");
    assert_eq!(syft_execution.assets[0].kind, AssetKind::ContainerImage);
    assert_eq!(
        syft_execution
            .manifest
            .command
            .iter()
            .map(String::as_str)
            .collect::<Vec<_>>(),
        [
            "oci-dir:/workspace",
            "-o",
            "syft-json=/output/syft.json",
            "--quiet"
        ]
    );

    let runtime = FakeContainerRuntime::default();
    let orchestrator = Orchestrator::new(&runtime, &artifacts, &adapters);
    for execution in &plan.executable {
        let resolved = resolve_workspace_snapshot(
            &artifact_root,
            &case.id,
            &references[&execution.assets[0].id],
        )
        .unwrap();
        let report = execute_fixture(
            &orchestrator,
            &runtime,
            execution,
            &resolved.tree_path,
            baseline_output(&execution.manifest.id).to_vec(),
        );
        assert_report_provenance(&artifact_root, execution, &report);
        service
            .apply_execution_report(&case.id, &DurableExecutionReport::from(&report))
            .unwrap();
    }

    let completed = service.show_case(&case.id).unwrap();
    let expected_total = plan
        .executable
        .iter()
        .map(|execution| expected_finding_count(&execution.manifest.id))
        .sum::<usize>();
    assert_eq!(completed.findings.len(), expected_total);
    for engine_id in ["trivy", "grype"] {
        assert!(completed.findings.iter().any(|finding| {
            finding
                .evidence
                .iter()
                .any(|evidence| evidence.engine_id == engine_id)
        }));
    }
    assert!(completed.findings.iter().all(|finding| {
        finding
            .evidence
            .iter()
            .all(|evidence| evidence.engine_id != "syft")
    }));
    let oci_asset_id = syft_execution.assets[0].id.as_str();
    let syft_inventory = completed
        .inventory_observations
        .iter()
        .filter(|observation| observation.engine_id == "syft")
        .collect::<Vec<_>>();
    assert_eq!(syft_inventory.len(), 1);
    assert_eq!(syft_inventory[0].asset_id, oci_asset_id);
    assert!(matches!(
        &syft_inventory[0].kind,
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
    let beginner = build_beginner_master_report(&completed, &plan.scan_run.id).unwrap();
    assert_eq!(beginner.inventory.counts.software_components, 1);
    assert!(beginner.inventory.items.iter().any(|item| {
        item.asset_id == oci_asset_id
            && matches!(
                &item.details,
                BeginnerInventoryItemKind::SoftwareComponent {
                    name,
                    version: Some(version),
                    package_type: Some(package_type),
                    purl: Some(purl),
                } if name == "example-package"
                    && version == "1.0"
                    && package_type == "deb"
                    && purl == "pkg:deb/debian/example-package@1.0"
            )
            && item.sources.iter().any(|source| source.engine_id == "syft")
    }));
    assert!(
        completed
            .coverage
            .iter()
            .filter(|entry| entry.asset_id.is_some())
            .all(|entry| entry.status == CoverageStatus::DiscoveredAuthorizedScanned)
    );
}

struct GreenboneFrameworkVertical {
    report: Value,
    finding_ids: BTreeSet<String>,
    evidence_ids: BTreeSet<String>,
    artifact_ids: BTreeSet<String>,
    ledger_status: CoverageStatus,
    ledger_explanation: String,
}

fn execute_greenbone_framework_vertical(ai_system_applicable: bool) -> GreenboneFrameworkVertical {
    let temporary = tempfile::tempdir().expect("Greenbone framework vertical temporary directory");
    let storage = Storage::open(temporary.path().join("casework.db")).expect("private storage");
    let engines = EngineRegistry::load_builtin().expect("supported built-in engine catalog");
    let adapters = builtin_adapter_registry().expect("built-in adapters");
    let artifacts =
        ArtifactStore::open(temporary.path().join("artifacts")).expect("private artifact store");
    let artifact_root = artifacts.root().to_path_buf();
    let service = CaseService::new(
        &storage,
        &engines,
        &adapters,
        &artifact_root,
        temporary.path().join("integrity-signing-key"),
    );
    let case = service
        .create_case(&CreateCaseRequest {
            title: "Fixture-backed internal host vulnerability scan".into(),
            organization_name: "Example organization".into(),
            employee_range: "1-10".into(),
            assessment_intent: Some(if ai_system_applicable {
                AssessmentIntent::AiApplication
            } else {
                AssessmentIntent::InternalItEnvironment
            }),
            ai_generated_artifact: AiGeneratedArtifactAnswer::No,
            data_classes: vec![],
            requested_activities: vec![AssessmentActivity::ActiveExternalVulnerabilityTests],
            source_kinds: vec![],
            not_applicable_source_kinds: vec![],
            declared_assets: vec![DeclaredAssetInput {
                kind: DeclaredAssetKind::ExternalTarget,
                value: "203.0.113.10".into(),
                internet_exposed: Some(false),
                web_service: None,
                network_service: None,
                host_scan: Some(DeclaredHostScanInput {
                    protocol: DeclaredNetworkProtocol::Tcp,
                    ports: vec![443, 8443],
                    profile: DeclaredHostScanProfile::GreenboneRemoteSafeV1,
                }),
            }],
            notes: Some("Checked-in XML and in-process fake runtime only".into()),
        })
        .expect("internal-host case creation");
    let asset_id = case.assets[0].id.clone();
    let greenbone_revision = format!(
        "greenbone-community-feed@{}",
        engines
            .get("greenbone")
            .expect("Greenbone manifest")
            .rule_version
            .as_deref()
            .expect("Greenbone pinned feed revision")
    );
    let plan = service
        .authorize_and_persist_scan_before_execution_preflight(
            &case.id,
            vec![ScopeApprovalRequest {
                asset_id: asset_id.clone(),
                permissions: vec![ScanPermission::ActiveExternalTesting],
                confirmed_by: "Fixture target owner".into(),
                expires_at: Some(Utc::now() + Duration::hours(1)),
                authorization_reference: Some("Approved exact fixture host scan".into()),
                notes: Some("No target contact; FakeContainerRuntime only".into()),
                external_scope: Some(ExternalScopeRequest {
                    target: "203.0.113.10".into(),
                    ports: BTreeSet::from([443, 8443]),
                    protocol: TransportProtocol::Tcp,
                    activity: ExternalActivity::ActiveExternal,
                    rate_policy: RatePolicy {
                        requests_per_second: 2,
                        concurrency: 1,
                        timeout_seconds: 15,
                    },
                    template_policy: TemplatePolicy::conservative_profile(
                        greenbone_revision,
                        "greenbone_remote_safe_v1",
                    ),
                    asserted_authority: "Approved exact fixture host".into(),
                    allow_sensitive_networks: true,
                }),
            }],
            ScanPlanRequest {
                engine_ids: vec![],
                engine_asset_routes: vec![EngineAssetRoute {
                    engine_id: "greenbone".into(),
                    asset_ids: vec![asset_id.clone()],
                }],
            },
        )
        .expect("authorized Greenbone plan");
    assert!(plan.not_executed.is_empty());
    assert_eq!(plan.executable.len(), 1);
    let execution = &plan.executable[0];
    assert_eq!(execution.manifest.id, "greenbone");
    assert_eq!(execution.ai_system_applicable, ai_system_applicable);

    let scope_grant_id = execution.scope_grants[0].id.clone();
    let fixture = String::from_utf8(GREENBONE_RESULT_TYPES_FIXTURE.to_vec())
        .expect("Greenbone XML fixture is UTF-8")
        .replace("asset-1", &asset_id)
        .replace("grant-1", &scope_grant_id)
        .into_bytes();
    let runtime = FakeContainerRuntime::default();
    runtime.set_behavior(FakeRunBehavior {
        exit_code: Some(0),
        stdout: Vec::new(),
        stderr: Vec::new(),
        output_files: BTreeMap::from([("greenbone.xml".into(), fixture)]),
    });
    let network = NetworkPolicy::managed(
        "fixture-greenbone-network",
        "fixture-greenbone-policy",
        vec!["203.0.113.10:443".into(), "203.0.113.10:8443".into()],
        "socks5h://172.29.0.1:1080",
    )
    .expect("fixture-only managed network contract");
    let resources = ResourceLimits {
        memory_mb: execution.manifest.estimated_memory_mb,
        tmpfs_mb: execution.manifest.estimated_disk_mb.clamp(16, 4_096),
        ..ResourceLimits::default()
    };
    let credentials = ScannerCredentialSet::default();
    let orchestrator = Orchestrator::new(&runtime, &artifacts, &adapters);
    let execution_report = orchestrator
        .execute(
            &EngineExecutionRequest {
                case_id: &execution.case_id,
                scan_run_id: &execution.scan_run_id,
                engine_run_id: &execution.engine_run_id,
                manifest: &execution.manifest,
                ai_system_applicable: execution.ai_system_applicable,
                ai_generated_artifact_applicable: execution.ai_generated_artifact
                    == AiGeneratedArtifactAnswer::Yes,
                assets: &execution.assets,
                scope_grants: &execution.scope_grants,
                frozen_destinations: None,
                naabu_launcher_plan: None,
                expected_naabu_launcher_plan_sha256: None,
                workspace: None,
                network_policy: &network,
                resource_limits: &resources,
                credentials: &credentials,
                attempt: execution.attempt,
            },
            &CancellationToken::default(),
        )
        .expect("fixture-backed Greenbone execution");
    assert_eq!(execution_report.checkpoint.stage, ExecutionStage::Completed);
    assert_eq!(execution_report.findings.len(), 2);
    assert_eq!(execution_report.unevaluated_targets.len(), 2);
    assert!(
        execution_report
            .unevaluated_targets
            .iter()
            .all(|target| target.asset_id == asset_id)
    );
    assert!(execution_report.unevaluated_targets.iter().any(|target| {
        target.cause == UnevaluatedTargetCause::TargetDidNotRespond && target.result_count == 1
    }));
    assert!(execution_report.unevaluated_targets.iter().any(|target| {
        target.cause == UnevaluatedTargetCause::ScannerError && target.result_count == 2
    }));
    let finding_ids = execution_report
        .findings
        .iter()
        .map(|finding| finding.id.clone())
        .collect::<BTreeSet<_>>();
    let evidence_ids = execution_report
        .findings
        .iter()
        .flat_map(|finding| finding.evidence.iter().map(|evidence| evidence.id.clone()))
        .collect::<BTreeSet<_>>();
    let artifact_ids = execution_report
        .raw_artifacts
        .iter()
        .map(|artifact| artifact.id.clone())
        .collect::<BTreeSet<_>>();
    let applied = service
        .apply_execution_report(&case.id, &DurableExecutionReport::from(&execution_report))
        .expect("durable Greenbone execution reconciliation");
    let ledger_entry = applied
        .case
        .coverage
        .iter()
        .find(|entry| entry.asset_id.as_deref() == Some(asset_id.as_str()))
        .expect("coverage entry for the authorized host");
    let ledger_status = ledger_entry.status.clone();
    let ledger_explanation = ledger_entry.explanation.clone();

    let destination = temporary.path().join(if ai_system_applicable {
        "ai-framework-report.json"
    } else {
        "non-ai-framework-report.json"
    });
    service
        .export_case(
            &case.id,
            &execution.scan_run_id,
            CaseExportFormat::FrameworkReport,
            &destination,
            ExportOptions::default(),
        )
        .expect("standardized framework report export");
    let bytes = fs::read(destination).expect("exported framework report bytes");
    let report: Value = serde_json::from_slice(&bytes).expect("MasterFrameworkReport JSON");
    let schema: Value = serde_json::from_str(include_str!(
        "../../schemas/master-framework-report.schema.json"
    ))
    .expect("checked-in MasterFrameworkReport schema");
    validate_schema_value(&schema, &schema, &report, "$")
        .expect("exported bytes validate against the MasterFrameworkReport schema");

    GreenboneFrameworkVertical {
        report,
        finding_ids,
        evidence_ids,
        artifact_ids,
        ledger_status,
        ledger_explanation,
    }
}

fn framework<'a>(report: &'a Value, framework_name: &str) -> &'a Value {
    report["frameworks"]
        .as_array()
        .expect("framework report summaries")
        .iter()
        .find(|framework| framework["framework"] == framework_name)
        .unwrap_or_else(|| panic!("missing {framework_name} framework summary"))
}

fn control_relationships<'a>(
    report: &'a Value,
    framework_name: &str,
    framework_version: &str,
    control_id: &str,
) -> Vec<&'a Value> {
    framework(report, framework_name)["controls"]
        .as_array()
        .expect("framework controls")
        .iter()
        .find(|control| {
            control["framework_version"] == framework_version
                && control["control_id"] == control_id
        })
        .unwrap_or_else(|| {
            panic!(
                "missing Greenbone relationship for {framework_name} {framework_version} {control_id}"
            )
        })["relationships"]
        .as_array()
        .expect("control relationships")
        .iter()
        .collect()
}

fn assert_current_greenbone_relationships(
    vertical: &GreenboneFrameworkVertical,
    framework_name: &str,
    framework_version: &str,
    control_id: &str,
) {
    let relationships = control_relationships(
        &vertical.report,
        framework_name,
        framework_version,
        control_id,
    );
    assert!(
        !relationships.is_empty(),
        "missing Greenbone relationship for {framework_name} {framework_version} {control_id}"
    );
    for relationship in relationships {
        assert_eq!(relationship["relationship"], "related");
        assert_eq!(relationship["mapping_version"], "2026-09-09.1");
        assert_eq!(
            relationship["mapping_provenance_state"],
            "verified_current_catalog"
        );
        assert_eq!(relationship["mapping_version_state"], "exact_match");
        assert_eq!(
            relationship["mapping_provenance"]["mapping_version"],
            "2026-09-09.1"
        );
        let finding_id = relationship["finding"]["finding_id"]
            .as_str()
            .expect("relationship finding ID");
        assert!(
            vertical.finding_ids.contains(finding_id),
            "{framework_name} {control_id} does not resolve to a Greenbone fixture finding"
        );
        let bindings = relationship["evidence_bindings"]
            .as_array()
            .expect("relationship evidence bindings");
        assert!(!bindings.is_empty());
        for binding in bindings {
            assert_eq!(binding["engine_id"], "greenbone");
            assert_eq!(binding["engine_mapping_version"], "2026-09-09.1");
            assert_eq!(
                binding["engine_mapping_provenance_state"],
                "verified_current_catalog"
            );
            assert_eq!(binding["mapping_version_state"], "exact_match");
            assert!(
                binding["source_rule"]
                    .as_str()
                    .is_some_and(|rule| rule.starts_with("1.3.6.1.4.1.25623."))
            );
            assert!(
                vertical
                    .evidence_ids
                    .contains(binding["evidence_id"].as_str().expect("bound evidence ID")),
                "{framework_name} {control_id} evidence does not resolve to the fixture finding"
            );
            assert!(
                vertical
                    .artifact_ids
                    .contains(binding["artifact_id"].as_str().expect("bound artifact ID")),
                "{framework_name} {control_id} evidence does not resolve to the fixture artifact"
            );
        }
    }
    let summary = framework(&vertical.report, framework_name);
    assert_eq!(
        summary["observed_mapping_versions"],
        serde_json::json!(["2026-09-09.1"])
    );
    assert_eq!(
        summary["evidence_engine_mapping_versions"],
        serde_json::json!(["2026-09-09.1"])
    );
    assert_eq!(
        summary["mapping_version_state"],
        "all_relationships_exact_match"
    );
    assert_eq!(summary["mismatch_relationship_count"], 0);
    assert_eq!(summary["unavailable_relationship_count"], 0);
}

#[test]
fn greenbone_framework_report_vertical_preserves_relationships_ai_gating_and_incomplete_coverage() {
    let ai = execute_greenbone_framework_vertical(true);
    assert_current_greenbone_relationships(&ai, "NIST CSF", "2.0", "ID.RA-01");
    assert_current_greenbone_relationships(&ai, "ISO/IEC 27001", "2022", "A.8.8");
    assert_current_greenbone_relationships(&ai, "AIDEFEND", "1.20260805", "AID-H-003.010");
    assert_eq!(
        ai.report["declared_ai_context"]["ai_system_applicability"],
        "applicable"
    );
    assert_eq!(
        ai.report["declared_ai_context"]["aidefend_applicability"],
        "applicable"
    );

    let coverage = &ai.report["coverage"];
    assert_eq!(coverage["state"], "incomplete_or_unknown");
    assert_eq!(coverage["selected_run_checks_complete"], true);
    assert_eq!(
        coverage["selected_run_coverage_has_unknown_or_incomplete_entries"],
        true
    );
    // The coverage-ledger defect is fixed: the dead-host cause takes precedence
    // over the scanner-error cause for this asset and keeps the completed task
    // inside the ledger's existing incomplete-explanation frame.
    assert_eq!(ai.ledger_status, CoverageStatus::AuthorizedScanIncomplete);
    assert!(
        ai.ledger_explanation
            .contains("greenbone=target_did_not_respond")
    );
    assert!(!ai.ledger_explanation.contains("greenbone=scanner_error"));

    let coverage_states = coverage["selected_run_coverage_states"]
        .as_object()
        .expect("selected-run coverage states");
    assert!(!coverage_states.is_empty());
    assert_eq!(
        coverage_states.get("authorized_scan_incomplete"),
        Some(&serde_json::json!(1))
    );
    // Greenbone reported this host as dead and errored, so nothing in the
    // standardized export may count it as scanned.
    assert!(
        coverage_states
            .get("discovered_authorized_scanned")
            .is_none(),
        "a host Greenbone never evaluated must not be counted as scanned"
    );
    assert_eq!(coverage["authorized_incomplete_count"], 1);
    assert_eq!(coverage["selected_run_coverage_ledger_available"], true);
    assert_eq!(
        coverage["selected_run_missing_planned_asset_coverage_count"],
        0
    );
    assert_eq!(coverage["selected_run_unmatched_coverage_entry_count"], 0);
    assert!(
        coverage["limitations"]
            .as_array()
            .expect("coverage limitations")
            .iter()
            .any(|limitation| limitation.as_str().is_some_and(|limitation| {
                limitation.contains("authorized area(s) were only partly scanned")
            }))
    );
    assert!(
        coverage["limitations"]
            .as_array()
            .expect("coverage limitations")
            .iter()
            .any(|limitation| limitation.as_str().is_some_and(|limitation| {
                limitation.contains("cannot establish complete scan coverage")
            }))
    );

    let non_ai = execute_greenbone_framework_vertical(false);
    assert_current_greenbone_relationships(&non_ai, "NIST CSF", "2.0", "ID.RA-01");
    assert_current_greenbone_relationships(&non_ai, "ISO/IEC 27001", "2022", "A.8.8");
    let aidefend = framework(&non_ai.report, "AIDEFEND");
    assert_eq!(aidefend["state"], "not_applicable_to_declared_context");
    assert_eq!(aidefend["relationship_count"], 0);
    assert_eq!(aidefend["control_count"], 0);
    assert!(
        aidefend["controls"]
            .as_array()
            .expect("AIDEFEND controls")
            .is_empty(),
        "AID-H-003.010 must be absent when AI-system applicability is not declared"
    );
    assert_eq!(
        non_ai.report["declared_ai_context"]["ai_system_applicability"],
        "not_applicable"
    );
    assert_eq!(
        non_ai.report["declared_ai_context"]["aidefend_applicability"],
        "not_applicable"
    );
}

// Keep integration validation aligned with the exporter's checked-in-schema
// test helper. The crate deliberately has no runtime JSON Schema dependency.
fn validate_schema_value(
    root: &Value,
    schema: &Value,
    value: &Value,
    path: &str,
) -> Result<(), String> {
    if let Some(all_of) = schema.get("allOf").and_then(Value::as_array) {
        for child_schema in all_of {
            validate_schema_value(root, child_schema, value, path)?;
        }
    }
    if let Some(one_of) = schema.get("oneOf").and_then(Value::as_array) {
        let matches = one_of
            .iter()
            .filter(|candidate| validate_schema_value(root, candidate, value, path).is_ok())
            .count();
        if matches != 1 {
            return Err(format!(
                "expected exactly one matching schema at {path}, found {matches}"
            ));
        }
    }
    if let Some(reference) = schema.get("$ref").and_then(Value::as_str) {
        let name = reference
            .strip_prefix("#/$defs/")
            .ok_or_else(|| format!("unsupported schema reference at {path}: {reference}"))?;
        let resolved = root
            .get("$defs")
            .and_then(|defs| defs.get(name))
            .ok_or_else(|| format!("missing schema definition at {path}: {name}"))?;
        return validate_schema_value(root, resolved, value, path);
    }
    if let Some(expected) = schema.get("const")
        && expected != value
    {
        return Err(format!("const mismatch at {path}"));
    }
    if let Some(allowed) = schema.get("enum").and_then(Value::as_array)
        && !allowed.contains(value)
    {
        return Err(format!("enum mismatch at {path}: {value}"));
    }
    if let Some(kind) = schema.get("type").and_then(Value::as_str) {
        match kind {
            "object" => {
                let object = value
                    .as_object()
                    .ok_or_else(|| format!("expected object at {path}"))?;
                let properties = schema
                    .get("properties")
                    .and_then(Value::as_object)
                    .cloned()
                    .unwrap_or_default();
                for required in schema
                    .get("required")
                    .and_then(Value::as_array)
                    .into_iter()
                    .flatten()
                {
                    let required = required
                        .as_str()
                        .ok_or_else(|| format!("non-string required key at {path}"))?;
                    if !object.contains_key(required) {
                        return Err(format!("missing required key at {path}.{required}"));
                    }
                }
                for (key, child) in object {
                    if let Some(child_schema) = properties.get(key) {
                        validate_schema_value(root, child_schema, child, &format!("{path}.{key}"))?;
                    } else {
                        match schema.get("additionalProperties") {
                            Some(Value::Bool(false)) => {
                                return Err(format!("unexpected key at {path}.{key}"));
                            }
                            Some(additional @ Value::Object(_)) => {
                                validate_schema_value(
                                    root,
                                    additional,
                                    child,
                                    &format!("{path}.{key}"),
                                )?;
                            }
                            _ => {}
                        }
                    }
                }
            }
            "array" => {
                let values = value
                    .as_array()
                    .ok_or_else(|| format!("expected array at {path}"))?;
                if let Some(minimum) = schema.get("minItems").and_then(Value::as_u64)
                    && values.len() < minimum as usize
                {
                    return Err(format!("too few array items at {path}"));
                }
                if let Some(maximum) = schema.get("maxItems").and_then(Value::as_u64)
                    && values.len() > maximum as usize
                {
                    return Err(format!("too many array items at {path}"));
                }
                if schema.get("uniqueItems") == Some(&Value::Bool(true)) {
                    let unique = values.iter().map(Value::to_string).collect::<BTreeSet<_>>();
                    if unique.len() != values.len() {
                        return Err(format!("duplicate array item at {path}"));
                    }
                }
                let prefix_items = schema
                    .get("prefixItems")
                    .and_then(Value::as_array)
                    .cloned()
                    .unwrap_or_default();
                for (index, child_schema) in prefix_items.iter().enumerate() {
                    let child = values
                        .get(index)
                        .ok_or_else(|| format!("missing prefix item at {path}[{index}]"))?;
                    validate_schema_value(root, child_schema, child, &format!("{path}[{index}]"))?;
                }
                if schema.get("items") == Some(&Value::Bool(false))
                    && values.len() > prefix_items.len()
                {
                    return Err(format!("unexpected trailing array item at {path}"));
                }
                if let Some(item_schema @ Value::Object(_)) = schema.get("items") {
                    for (index, child) in values.iter().enumerate() {
                        validate_schema_value(
                            root,
                            item_schema,
                            child,
                            &format!("{path}[{index}]"),
                        )?;
                    }
                }
            }
            "string" => {
                let text = value
                    .as_str()
                    .ok_or_else(|| format!("expected string at {path}"))?;
                if let Some(minimum) = schema.get("minLength").and_then(Value::as_u64)
                    && text.chars().count() < minimum as usize
                {
                    return Err(format!("string is too short at {path}"));
                }
                if let Some(maximum) = schema.get("maxLength").and_then(Value::as_u64)
                    && text.chars().count() > maximum as usize
                {
                    return Err(format!("string is too long at {path}"));
                }
                if let Some(pattern) = schema.get("pattern").and_then(Value::as_str) {
                    match pattern {
                        "^[0-9a-f]{64}$"
                            if text.len() != 64
                                || !text.bytes().all(|byte| {
                                    byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte)
                                }) =>
                        {
                            return Err(format!("string does not match SHA-256 pattern at {path}"));
                        }
                        "^[0-9a-f]{64}$" => {}
                        "^[0-9]{4}-[0-9]{2}-[0-9]{2}\\.[1-9][0-9]*$"
                            if mapping_version_date(text).is_err() =>
                        {
                            return Err(format!("string is not a valid mapping version at {path}"));
                        }
                        "^[0-9]{4}-[0-9]{2}-[0-9]{2}\\.[1-9][0-9]*$" => {}
                        "^[0-9]{4}-[0-9]{2}-[0-9]{2}$"
                            if text.len() != 10
                                || NaiveDate::parse_from_str(text, "%Y-%m-%d").is_err() =>
                        {
                            return Err(format!("string is not a valid date at {path}"));
                        }
                        "^[0-9]{4}-[0-9]{2}-[0-9]{2}$" => {}
                        other => {
                            return Err(format!(
                                "unsupported schema string pattern at {path}: {other}"
                            ));
                        }
                    }
                }
                if schema.get("format").and_then(Value::as_str) == Some("date-time") {
                    DateTime::parse_from_rfc3339(text)
                        .map_err(|_| format!("invalid date-time at {path}"))?;
                }
            }
            "integer" => {
                let number = value
                    .as_i64()
                    .ok_or_else(|| format!("expected integer at {path}"))?;
                if let Some(minimum) = schema.get("minimum").and_then(Value::as_i64)
                    && number < minimum
                {
                    return Err(format!("integer is below minimum at {path}"));
                }
            }
            "boolean" => {
                if !value.is_boolean() {
                    return Err(format!("expected boolean at {path}"));
                }
            }
            "null" => {
                if !value.is_null() {
                    return Err(format!("expected null at {path}"));
                }
            }
            other => return Err(format!("unsupported schema type at {path}: {other}")),
        }
    }
    Ok(())
}

fn mapping_version_date(value: &str) -> Result<NaiveDate, String> {
    let Some((date, revision)) = value.split_once('.') else {
        return Err("mapping version must be YYYY-MM-DD.N".into());
    };
    if date.len() != 10
        || date.as_bytes().get(4) != Some(&b'-')
        || date.as_bytes().get(7) != Some(&b'-')
        || revision.starts_with('0')
        || !revision.parse::<u32>().is_ok_and(|value| value > 0)
    {
        return Err("mapping version must be YYYY-MM-DD.N".into());
    }
    NaiveDate::parse_from_str(date, "%Y-%m-%d")
        .map_err(|_| "mapping version contains an invalid calendar date".into())
}
