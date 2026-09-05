use ai_security_scanner_lib::adapters::builtin_adapter_registry;
use ai_security_scanner_lib::artifact_store::ArtifactStore;
use ai_security_scanner_lib::case_service::{
    CaseExportFormat, CaseService, DurableExecutionReport, PlannedEngineExecution, ScanPlanRequest,
    ScopeApprovalRequest,
};
use ai_security_scanner_lib::container_runtime::{
    CancellationToken, FakeContainerRuntime, FakeRunBehavior, NetworkPolicy, ResourceLimits,
    ScannerCredentialSet,
};
use ai_security_scanner_lib::domain::{
    AiGeneratedArtifactAnswer, Asset, CaseStatus, CoverageStatus, CreateCaseRequest, DataClass,
    EngineRunStatus, FindingDiffStatus, ScanPermission, ScopeGrant,
};
use ai_security_scanner_lib::export::ExportOptions;
use ai_security_scanner_lib::orchestrator::{
    EngineExecutionRequest, ExecutionReport, ExecutionStage, Orchestrator,
};
use ai_security_scanner_lib::registry::EngineRegistry;
use ai_security_scanner_lib::storage::Storage;
use ai_security_scanner_lib::workspace_snapshot::{
    WorkspaceInputProfile, WorkspaceSnapshotLimits, WorkspaceSnapshotReference,
    create_workspace_snapshot, create_workspace_snapshot_with_profile, resolve_workspace_snapshot,
};
use chrono::Utc;
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
/// and the kube-bench fixture is a full run of the shipped six-check snapshot
/// benchmark against an unhardened node, three of whose checks fail.
fn expected_finding_count(engine_id: &str) -> usize {
    match engine_id {
        "syft" => 0,
        "kubescape" | "kube-bench" => 3,
        "trivy" | "grype" => 2,
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
    assert_eq!(baseline.findings.len(), 6);
    assert_eq!(baseline.finding_observations.len(), 6);
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
                engine_ids: ["trivy", "grype", "kubescape", "kube-bench"]
                    .into_iter()
                    .map(str::to_owned)
                    .collect(),
            },
        )
        .unwrap();
    assert!(plan.not_executed.is_empty());
    assert_eq!(plan.executable.len(), 4);
    assert!(plan.executable.iter().all(|execution| {
        execution.assets.len() == 1
            && execution.manifest.input_contracts.iter().any(|contract| {
                contract.asset_kind == execution.assets[0].kind
                    && contract.input_profile == references[&execution.assets[0].id].input_profile
            })
    }));

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
    assert!(
        completed
            .coverage
            .iter()
            .filter(|entry| entry.asset_id.is_some())
            .all(|entry| entry.status == CoverageStatus::DiscoveredAuthorizedScanned)
    );
}
