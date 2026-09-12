use ai_security_scanner_lib::adapter::AdapterRegistry;
use ai_security_scanner_lib::adapters::{BUILTIN_ENGINE_IDS, builtin_adapter_registry};
use ai_security_scanner_lib::artifact_store::ArtifactStore;
use ai_security_scanner_lib::beginner_report::{
    BeginnerInventoryItemKind, BeginnerMasterReport, CoverageDimensionStatus,
    build_beginner_master_report,
};
use ai_security_scanner_lib::case_service::{
    CaseExportFormat, CaseService, DurableExecutionReport, EngineAssetRoute,
    PlannedEngineExecution, ScanPlanRequest, ScopeApprovalRequest, SourceMutation,
};
use ai_security_scanner_lib::connectors::{
    LIVE_PROVIDER_ARTIFACT_SET_SCHEMA, LiveProviderArtifactPage, LiveProviderArtifactSet,
    SnapshotConnectorRegistry,
};
use ai_security_scanner_lib::container_runtime::{
    CONTAINER_EXECUTION_TIMEOUT_ERROR, CancellationToken, FakeContainerRuntime, FakeRunBehavior,
    NetworkPolicy, ResourceLimits, ScannerCredentialSet,
};
use ai_security_scanner_lib::discovery::run_connector;
use ai_security_scanner_lib::domain::{
    AiGeneratedArtifactAnswer, AssessmentActivity, AssessmentCase, AssessmentIntent, AssetKind,
    CreateCaseRequest, DataClass, DeclaredAssetInput, DeclaredAssetKind, DeclaredHostScanInput,
    DeclaredHostScanProfile, DeclaredNetworkProtocol, DeclaredWebProtocol, DeclaredWebServiceInput,
    EngineRunStatus, ScanPermission, SourceConnectionStatus, SourceKind,
};
use ai_security_scanner_lib::export::{ExportOptions, RedactionProfile, ReportLocale};
use ai_security_scanner_lib::external_scope::{
    ExternalActivity, ExternalScopeRequest, RatePolicy, TemplatePolicy, TransportProtocol,
};
use ai_security_scanner_lib::managed_network::GatewayDestination;
use ai_security_scanner_lib::orchestrator::{
    EngineExecutionRequest, ExecutionCheckpoint, ExecutionReport, ExecutionStage, Orchestrator,
};
use ai_security_scanner_lib::registry::EngineRegistry;
use ai_security_scanner_lib::source_authorization::PROVIDER_RESOURCE_SCOPE_METADATA_KEY;
use ai_security_scanner_lib::storage::Storage;
use ai_security_scanner_lib::workspace_snapshot::{
    WorkspaceInputProfile, WorkspaceSnapshotLimits, WorkspaceSnapshotReference,
    create_workspace_snapshot_with_profile, resolve_workspace_snapshot,
};
use chrono::{Duration, Utc};
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::io::Cursor;
use std::path::{Path, PathBuf};

fn fixture(engine: &str) -> (&'static [u8], &'static str) {
    match engine {
        "cloudquery" => (
            include_bytes!("fixtures/adapters/cloudquery.json"),
            "aws_iam_users.json",
        ),
        "steampipe" => (
            include_bytes!("fixtures/adapters/steampipe.json"),
            "steampipe.json",
        ),
        "prowler" => (
            include_bytes!("fixtures/adapters/prowler-ocsf.json"),
            "prowler-ocsf.json",
        ),
        "scoutsuite" => (
            include_bytes!("fixtures/adapters/scoutsuite.json"),
            "scoutsuite.json",
        ),
        "cloudsplaining" => (
            include_bytes!("fixtures/adapters/cloudsplaining.json"),
            "cloudsplaining.json",
        ),
        "scubagear" => (
            include_bytes!("fixtures/adapters/scubagear.json"),
            "scubagear.json",
        ),
        "maester" => (
            include_bytes!("fixtures/adapters/maester.json"),
            "maester.json",
        ),
        "naabu" => (
            include_bytes!("fixtures/adapters/naabu.jsonl"),
            "naabu.jsonl",
        ),
        "httpx" => (
            include_bytes!("fixtures/adapters/httpx.jsonl"),
            "httpx.jsonl",
        ),
        "nuclei" => (
            include_bytes!("fixtures/adapters/malformed-nuclei.jsonl"),
            "nuclei.jsonl",
        ),
        "greenbone" => (
            include_bytes!("fixtures/adapters/greenbone-result-types.xml"),
            "greenbone.xml",
        ),
        "semgrep" => (
            include_bytes!("fixtures/adapters/semgrep-empty.json"),
            "semgrep.json",
        ),
        "gitleaks" => (
            include_bytes!("fixtures/adapters/gitleaks.json"),
            "gitleaks.json",
        ),
        "trufflehog" => (
            include_bytes!("fixtures/adapters/trufflehog.jsonl"),
            "trufflehog.jsonl",
        ),
        "checkov" => (
            include_bytes!("fixtures/adapters/checkov.json"),
            "checkov.json",
        ),
        "kics" => (include_bytes!("fixtures/adapters/kics.json"), "kics.json"),
        "trivy" => (include_bytes!("fixtures/adapters/trivy.json"), "trivy.json"),
        "grype" => (include_bytes!("fixtures/adapters/grype.json"), "grype.json"),
        "syft" => (include_bytes!("fixtures/adapters/syft.json"), "syft.json"),
        "kubescape" => (
            include_bytes!("fixtures/adapters/kubescape.json"),
            "kubescape.json",
        ),
        "kube-bench" => (
            include_bytes!("fixtures/adapters/kube-bench.json"),
            "kube-bench.json",
        ),
        other => panic!("missing fixture for {other}"),
    }
}

fn write_oci_layout(root: &Path) {
    let blobs = root.join("blobs/sha256");
    fs::create_dir_all(&blobs).unwrap();
    fs::write(
        root.join("oci-layout"),
        br#"{"imageLayoutVersion":"1.0.0"}"#,
    )
    .unwrap();
    let contents = b"all-engine report audit layer";
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
        "architecture":"amd64", "os":"linux",
        "rootfs":{"type":"layers","diff_ids":[format!("sha256:{layer_digest}")]}, "config":{}
    }))
    .unwrap();
    let config_digest = hex::encode(Sha256::digest(&config));
    fs::write(blobs.join(&config_digest), &config).unwrap();
    fs::write(blobs.join(&layer_digest), &layer).unwrap();
    let manifest = serde_json::to_vec(&serde_json::json!({
        "schemaVersion":2,
        "mediaType":"application/vnd.oci.image.manifest.v1+json",
        "config":{"mediaType":"application/vnd.oci.image.config.v1+json","digest":format!("sha256:{config_digest}"),"size":config.len()},
        "layers":[{"mediaType":"application/vnd.oci.image.layer.v1.tar","digest":format!("sha256:{layer_digest}"),"size":layer.len()}]
    })).unwrap();
    let manifest_digest = hex::encode(Sha256::digest(&manifest));
    fs::write(blobs.join(&manifest_digest), &manifest).unwrap();
    fs::write(root.join("index.json"), serde_json::to_vec(&serde_json::json!({
        "schemaVersion":2,"mediaType":"application/vnd.oci.image.index.v1+json",
        "manifests":[{"mediaType":"application/vnd.oci.image.manifest.v1+json","digest":format!("sha256:{manifest_digest}"),"size":manifest.len()}]
    })).unwrap()).unwrap();
}

fn write_node_snapshot(root: &Path) {
    let node = root.join("node-snapshot");
    fs::create_dir_all(&node).unwrap();
    let config = b"kind: KubeletConfiguration\n";
    fs::write(node.join("kubelet-config.yaml"), config).unwrap();
    fs::write(node.join("profile.json"), serde_json::to_vec(&serde_json::json!({
        "schema_version":"1.0.0", "profile":"cis-kubernetes-node-config",
        "captured_at":"2026-08-24T12:00:00Z",
        "files":[{"path":"kubelet-config.yaml","sha256":format!("sha256:{}", hex::encode(Sha256::digest(config)))}]
    })).unwrap()).unwrap();
}

fn attach_provider_asset(
    service: &CaseService<'_>,
    registry: &SnapshotConnectorRegistry,
    case_id: &str,
    kind: SourceKind,
    profile: &str,
    raw: &[u8],
    expected_kind: AssetKind,
) -> String {
    let source = service
        .upsert_source(
            case_id,
            SourceMutation {
                id: None,
                kind: kind.clone(),
                label: format!("Fixture {kind:?}"),
                status: SourceConnectionStatus::Connected,
                read_only: true,
                metadata: BTreeMap::from([(
                    PROVIDER_RESOURCE_SCOPE_METADATA_KEY.into(),
                    serde_json::Value::String(if kind == SourceKind::AwsOrganization {
                        "aws-account:123456789012".into()
                    } else {
                        "microsoft365-tenant:22222222-2222-4222-8222-222222222222".into()
                    }),
                )]),
            },
        )
        .unwrap();
    let observed_at = Utc::now();
    let artifact = registry
        .ingest_provider_response(&kind, raw, profile, observed_at)
        .unwrap();
    let operation = if kind == SourceKind::AwsOrganization {
        "organizations:ListAccounts"
    } else {
        "microsoft-graph:DirectoryInventory"
    };
    service
        .attach_live_provider_capture(
            case_id,
            &source.id,
            LiveProviderArtifactSet {
                schema_version: LIVE_PROVIDER_ARTIFACT_SET_SCHEMA.into(),
                capture_id: format!("capture-{}", source.id),
                profile: profile.into(),
                operation: operation.into(),
                observed_at,
                complete: true,
                pages: vec![LiveProviderArtifactPage {
                    sequence: 1,
                    operation: operation.into(),
                    http_status: 200,
                    parser_eligible: true,
                    artifact,
                }],
            },
        )
        .unwrap();
    let captured = service
        .show_case(case_id)
        .unwrap()
        .data_sources
        .into_iter()
        .find(|item| item.id == source.id)
        .unwrap();
    let batch = run_connector(&registry.connector_for(&kind), &captured).unwrap();
    service.reconcile_discovery_batch(case_id, &batch).unwrap();
    service
        .show_case(case_id)
        .unwrap()
        .assets
        .into_iter()
        .find(|asset| asset.kind == expected_kind && asset.discovered_from.contains(&source.id))
        .unwrap()
        .id
}

fn substituted_fixture(engine: &str, asset_id: &str, grant_id: &str) -> (&'static str, Vec<u8>) {
    let (bytes, name) = fixture(engine);
    let text = String::from_utf8(bytes.to_vec()).unwrap();
    (
        name,
        text.replace("asset-1", asset_id)
            .replace("grant-1", grant_id)
            .replace("service.example.test", "portal.example.test")
            .replace("example.com", "portal.example.test")
            .into_bytes(),
    )
}

fn execute(
    orchestrator: &Orchestrator<'_, FakeContainerRuntime>,
    runtime: &FakeContainerRuntime,
    execution: &PlannedEngineExecution,
    workspace: Option<&Path>,
    cancellation: &CancellationToken,
) -> ExecutionReport {
    let manifest = execution.manifest.clone();
    let (name, output) = substituted_fixture(
        &execution.manifest.id,
        &execution.assets[0].id,
        &execution.scope_grants[0].id,
    );
    runtime.set_behavior(FakeRunBehavior {
        exit_code: if manifest.id == "checkov" {
            Some(9)
        } else {
            Some(0)
        },
        stdout: vec![],
        stderr: vec![],
        output_files: BTreeMap::from([(name.into(), output)]),
    });
    let destinations = match execution.manifest.id.as_str() {
        "nuclei" | "httpx" => vec!["portal.example.test:443".into()],
        "greenbone" => vec!["203.0.113.10:443".into(), "203.0.113.10:8443".into()],
        "naabu" => vec!["203.0.113.11:443".into(), "203.0.113.11:8443".into()],
        _ => manifest.network_destinations.clone(),
    };
    let network = if destinations.is_empty() {
        NetworkPolicy::Disabled
    } else {
        NetworkPolicy::managed(
            format!("audit-{}-network", execution.manifest.id),
            format!("audit-{}-policy", execution.manifest.id),
            destinations,
            "socks5h://172.29.0.1:1080",
        )
        .unwrap()
    };
    let resources = ResourceLimits {
        memory_mb: execution.manifest.estimated_memory_mb,
        tmpfs_mb: execution.manifest.estimated_disk_mb.clamp(16, 4096),
        ..Default::default()
    };
    let frozen = match execution.manifest.id.as_str() {
        "nuclei" | "httpx" => Some(vec![GatewayDestination {
            hostname: Some("portal.example.test".into()),
            addresses: BTreeSet::from(["203.0.113.20".parse().unwrap()]),
            ports: BTreeSet::from([443]),
            allow_sensitive_networks: false,
        }]),
        "naabu" => Some(vec![GatewayDestination {
            hostname: None,
            addresses: BTreeSet::from(["203.0.113.11".parse().unwrap()]),
            ports: BTreeSet::from([443, 8443]),
            allow_sensitive_networks: true,
        }]),
        _ => None,
    };
    orchestrator
        .execute(
            &EngineExecutionRequest {
                case_id: &execution.case_id,
                scan_run_id: &execution.scan_run_id,
                engine_run_id: &execution.engine_run_id,
                manifest: &manifest,
                ai_system_applicable: execution.ai_system_applicable,
                ai_generated_artifact_applicable: execution.ai_generated_artifact
                    == AiGeneratedArtifactAnswer::Yes,
                assets: &execution.assets,
                scope_grants: &execution.scope_grants,
                frozen_destinations: frozen.as_deref(),
                naabu_launcher_plan: None,
                expected_naabu_launcher_plan_sha256: None,
                workspace,
                network_policy: &network,
                resource_limits: &resources,
                credentials: &ScannerCredentialSet::default(),
                attempt: execution.attempt,
            },
            cancellation,
        )
        .unwrap()
}

/// One finished all-engine run, handed to the audit body by reference so the
/// service and the temporary tree it writes into outlive every check.
struct AllEngineRun<'a> {
    engines: &'a EngineRegistry,
    adapters: &'a AdapterRegistry,
    database: &'a Path,
    artifact_root: &'a Path,
    signing_key: &'a Path,
    case_id: &'a str,
    scan_run_id: &'a str,
    completed: AssessmentCase,
    report: BeginnerMasterReport,
}

/// Runs every integrated engine once against one fixture case and hands the
/// terminal report to `audit`.
///
/// The two case answers are parameters because they are the only inputs that
/// decide which framework families a report may reference: AIDEFEND
/// coordinates are withheld unless the case declares an AI system, and its
/// static-admission coordinate unless the case also declares an AI-generated
/// artifact. Everything else -- assets, grants, routes, fixture bytes and the
/// per-engine outcomes -- is identical between runs, so a difference between
/// two reports is a difference the answers caused.
fn all_engines_in_one_report<T>(
    intent: AssessmentIntent,
    ai_generated: AiGeneratedArtifactAnswer,
    audit: impl FnOnce(&AllEngineRun<'_>) -> T,
) -> T {
    let temp = tempfile::tempdir().unwrap();
    let database = temp.path().join("casework.db");
    let artifact_root = temp.path().join("artifacts");
    let signing_key = temp.path().join("integrity-key");
    let storage = Storage::open(&database).unwrap();
    let engines = EngineRegistry::load_builtin().unwrap();
    let adapters = builtin_adapter_registry().unwrap();
    let artifacts = ArtifactStore::open(&artifact_root).unwrap();
    let service = CaseService::new(&storage, &engines, &adapters, &artifact_root, &signing_key);
    let case = service
        .create_case(&CreateCaseRequest {
            title: format!("All 21 engines, one report ({intent:?})"),
            organization_name: "Fixture organization".into(),
            employee_range: "1-10".into(),
            assessment_intent: Some(intent),
            ai_generated_artifact: ai_generated,
            data_classes: vec![DataClass::CredentialsAndSecrets],
            requested_activities: vec![AssessmentActivity::ActiveExternalVulnerabilityTests],
            source_kinds: vec![],
            not_applicable_source_kinds: vec![],
            notes: Some("FakeContainerRuntime only; no network target contact".into()),
            declared_assets: vec![
                DeclaredAssetInput {
                    kind: DeclaredAssetKind::ExternalTarget,
                    value: "portal.example.test".into(),
                    internet_exposed: Some(true),
                    web_service: Some(DeclaredWebServiceInput {
                        protocol: DeclaredWebProtocol::Https,
                        port: 443,
                        path: "/".into(),
                        scan_profile: None,
                    }),
                    network_service: None,
                    host_scan: None,
                },
                DeclaredAssetInput {
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
                },
                DeclaredAssetInput {
                    kind: DeclaredAssetKind::ExternalTarget,
                    value: "203.0.113.11".into(),
                    internet_exposed: Some(false),
                    web_service: None,
                    network_service: None,
                    host_scan: None,
                },
            ],
        })
        .unwrap();
    let website = case
        .assets
        .iter()
        .find(|a| a.kind == AssetKind::WebService)
        .unwrap()
        .id
        .clone();
    let host = case
        .assets
        .iter()
        .find(|a| a.kind == AssetKind::Host)
        .unwrap()
        .id
        .clone();
    let naabu_host = case
        .assets
        .iter()
        .find(|asset| {
            asset
                .identifiers
                .iter()
                .any(|identifier| identifier.value == "203.0.113.11")
        })
        .unwrap()
        .id
        .clone();

    let selected = temp.path().join("selected");
    let inputs = [
        (
            "repo",
            "Repository",
            WorkspaceInputProfile::RepositoryWorkingTree,
        ),
        (
            "oci",
            "OCI image",
            WorkspaceInputProfile::ContainerImageOciLayout,
        ),
        (
            "manifests",
            "Kubernetes manifests",
            WorkspaceInputProfile::KubernetesManifests,
        ),
        (
            "node",
            "Kubernetes node",
            WorkspaceInputProfile::KubernetesNodeSnapshot,
        ),
    ];
    fs::create_dir_all(selected.join("repo")).unwrap();
    fs::write(
        selected.join("repo/main.tf"),
        b"resource \"fixture\" \"audit\" {}\n",
    )
    .unwrap();
    write_oci_layout(&selected.join("oci"));
    fs::create_dir_all(selected.join("manifests")).unwrap();
    fs::write(
        selected.join("manifests/pod.yaml"),
        b"apiVersion: v1\nkind: Pod\nmetadata:\n  name: audit\n",
    )
    .unwrap();
    fs::create_dir_all(selected.join("node")).unwrap();
    write_node_snapshot(&selected.join("node"));
    let mut local_assets = BTreeMap::<String, (String, WorkspaceSnapshotReference)>::new();
    for (source_id, label, profile) in inputs {
        let snapshot = create_workspace_snapshot_with_profile(
            &artifact_root,
            &case.id,
            source_id,
            selected.join(source_id),
            profile,
            WorkspaceSnapshotLimits::default(),
        )
        .unwrap();
        local_assets.insert(
            source_id.into(),
            (snapshot.asset.id.clone(), snapshot.reference.clone()),
        );
        service
            .attach_workspace_snapshot(&case.id, label, snapshot)
            .unwrap();
    }
    let connector_root = temp.path().join("connector-artifacts");
    fs::create_dir(&connector_root).unwrap();
    let connectors = SnapshotConnectorRegistry::new(&connector_root).unwrap();
    let aws = attach_provider_asset(
        &service,
        &connectors,
        &case.id,
        SourceKind::AwsOrganization,
        "aws-organizations-list-accounts",
        br#"<ListAccountsResponse><Accounts><member><Id>123456789012</Id><Arn>arn:aws:organizations::123456789012:account/o-fixture/123456789012</Arn><Name>Audit account</Name><Email>audit@example.test</Email><Status>ACTIVE</Status></member></Accounts></ListAccountsResponse>"#,
        AssetKind::CloudAccount,
    );
    let m365 = attach_provider_asset(&service, &connectors, &case.id, SourceKind::Microsoft365Tenant, "microsoft-graph-directory-inventory", br#"{"value":[{"id":"22222222-2222-4222-8222-222222222222","displayName":"Audit tenant"}]}"#, AssetKind::Tenant);

    let repo = &local_assets["repo"].0;
    let oci = &local_assets["oci"].0;
    let manifests = &local_assets["manifests"].0;
    let node = &local_assets["node"].0;
    for (asset_id, permissions, external_scope) in [
        (repo, vec![ScanPermission::LocalArtifactRead], None),
        (oci, vec![ScanPermission::LocalArtifactRead], None),
        (manifests, vec![ScanPermission::LocalArtifactRead], None),
        (node, vec![ScanPermission::LocalArtifactRead], None),
        (
            &aws,
            vec![
                ScanPermission::InventoryRead,
                ScanPermission::ConfigurationRead,
            ],
            None,
        ),
        (
            &m365,
            vec![
                ScanPermission::InventoryRead,
                ScanPermission::ConfigurationRead,
            ],
            None,
        ),
    ] {
        service
            .approve_scope(
                &case.id,
                ScopeApprovalRequest {
                    asset_id: asset_id.clone(),
                    permissions,
                    confirmed_by: "Fixture asset owner".into(),
                    expires_at: None,
                    authorization_reference: None,
                    notes: Some("Fixture-only execution".into()),
                    external_scope,
                },
            )
            .unwrap();
    }
    let expires = Utc::now() + Duration::hours(1);
    for (asset_id, target, ports, protocol, permission, activity, templates) in [
        (
            &website,
            "portal.example.test",
            BTreeSet::from([443]),
            TransportProtocol::Https,
            ScanPermission::LowImpactExternalConnection,
            ExternalActivity::LowImpactExternal,
            TemplatePolicy::conservative("not_applicable", vec![]),
        ),
        (
            &website,
            "portal.example.test",
            BTreeSet::from([443]),
            TransportProtocol::Https,
            ScanPermission::ActiveExternalTesting,
            ExternalActivity::ActiveExternal,
            TemplatePolicy::conservative_profile(
                format!(
                    "nuclei-templates@{}",
                    engines
                        .get("nuclei")
                        .unwrap()
                        .rule_version
                        .as_deref()
                        .unwrap()
                ),
                "nuclei_web_safe_v1",
            ),
        ),
        (
            &naabu_host,
            "203.0.113.11",
            BTreeSet::from([443, 8443]),
            TransportProtocol::Tcp,
            ScanPermission::LowImpactExternalConnection,
            ExternalActivity::LowImpactExternal,
            TemplatePolicy::conservative("not_applicable", vec![]),
        ),
        (
            &host,
            "203.0.113.10",
            BTreeSet::from([443, 8443]),
            TransportProtocol::Tcp,
            ScanPermission::ActiveExternalTesting,
            ExternalActivity::ActiveExternal,
            TemplatePolicy::conservative_profile(
                format!(
                    "greenbone-community-feed@{}",
                    engines
                        .get("greenbone")
                        .unwrap()
                        .rule_version
                        .as_deref()
                        .unwrap()
                ),
                "greenbone_remote_safe_v1",
            ),
        ),
    ] {
        service
            .approve_scope(
                &case.id,
                ScopeApprovalRequest {
                    asset_id: asset_id.clone(),
                    permissions: vec![permission],
                    confirmed_by: "Fixture target owner".into(),
                    expires_at: Some(expires),
                    authorization_reference: Some("Exact fixture target".into()),
                    notes: Some("Fake runtime only".into()),
                    external_scope: Some(ExternalScopeRequest {
                        target: target.into(),
                        ports,
                        protocol,
                        activity,
                        rate_policy: RatePolicy {
                            requests_per_second: if target == "portal.example.test" {
                                10
                            } else {
                                2
                            },
                            concurrency: if target == "portal.example.test" {
                                5
                            } else {
                                1
                            },
                            timeout_seconds: if target == "portal.example.test" {
                                10
                            } else {
                                15
                            },
                        },
                        template_policy: templates,
                        asserted_authority: "Exact fixture target approved".into(),
                        allow_sensitive_networks: target != "portal.example.test",
                    }),
                },
            )
            .unwrap();
    }

    let routes = [
        ("nuclei", &website),
        ("httpx", &website),
        ("greenbone", &host),
        ("naabu", &naabu_host),
        ("gitleaks", repo),
        ("trufflehog", repo),
        ("semgrep", repo),
        ("checkov", repo),
        ("kics", repo),
        ("kubescape", manifests),
        ("kube-bench", node),
        ("cloudquery", &aws),
        ("steampipe", &aws),
        ("prowler", &aws),
        ("scoutsuite", &aws),
        ("cloudsplaining", &aws),
        ("scubagear", &m365),
        ("maester", &m365),
    ]
    .into_iter()
    .map(|(engine_id, asset_id)| EngineAssetRoute {
        engine_id: engine_id.into(),
        asset_ids: vec![asset_id.clone()],
    })
    .chain(
        ["trivy", "grype", "syft"]
            .into_iter()
            .map(|engine_id| EngineAssetRoute {
                engine_id: engine_id.into(),
                asset_ids: vec![repo.clone(), oci.clone()],
            }),
    )
    .collect();
    let plan = service
        .plan_scan(
            &case.id,
            ScanPlanRequest {
                engine_ids: vec![],
                engine_asset_routes: routes,
            },
        )
        .unwrap();
    assert!(
        plan.not_executed.is_empty(),
        "unroutable engines: {:?}",
        plan.not_executed
    );
    assert_eq!(plan.executable.len(), 24);
    assert!(
        plan.executable
            .iter()
            .all(|execution| execution.assets.len() == 1)
    );

    let runtime = FakeContainerRuntime::default();
    let orchestrator = Orchestrator::new(&runtime, &artifacts, &adapters);
    // Outcome carriers: nuclei=partial; semgrep=complete-empty; checkov=failed;
    // kics=timed out on the host deadline; trufflehog=cancelled;
    // greenbone=unevaluated/dead host.
    // Syft, CloudQuery, Steampipe, Naabu and HTTPX are observation/inventory only.
    for execution in &plan.executable {
        let workspace = local_assets
            .values()
            .find(|(id, _)| id == &execution.assets[0].id)
            .map(|(_, reference)| {
                resolve_workspace_snapshot(&artifact_root, &case.id, reference)
                    .unwrap()
                    .tree_path
            });
        let mut report = match execution.manifest.id.as_str() {
            "naabu" => ExecutionReport {
                checkpoint: ExecutionCheckpoint {
                    case_id: execution.case_id.clone(),
                    scan_run_id: execution.scan_run_id.clone(),
                    engine_run_id: execution.engine_run_id.clone(),
                    engine_id: execution.manifest.id.clone(),
                    attempt: execution.attempt,
                    stage: ExecutionStage::Cancelled,
                    container_name: None,
                    scope_sha256: None,
                    launcher_plan_sha256: None,
                    artifact_ids: vec![],
                    cleanup_completed: true,
                    last_error: None,
                    runtime_command_provenance: None,
                    runtime_provider: None,
                    managed_network: None,
                },
                runtime_preflight: None,
                cleanup: None,
                exit_code: None,
                raw_artifacts: vec![],
                findings: vec![],
                observations: vec![],
                warnings: vec![],
                unattributed: vec![],
                unevaluated_targets: vec![],
                security_template_executions: vec![],
                manual_review_controls: vec![],
                artifact_root: artifact_root.clone(),
                output_directory: artifact_root.join("naabu-cancelled"),
            },
            "checkov" => execute(
                &orchestrator,
                &runtime,
                execution,
                workspace.as_deref(),
                &CancellationToken::default(),
            ),
            "trufflehog" => {
                let token = CancellationToken::default();
                token.cancel();
                execute(
                    &orchestrator,
                    &runtime,
                    execution,
                    workspace.as_deref(),
                    &token,
                )
            }
            _ => execute(
                &orchestrator,
                &runtime,
                execution,
                workspace.as_deref(),
                &CancellationToken::default(),
            ),
        };
        if execution.manifest.id == "kics" {
            // The product's own host deadline, recorded the way the runtime
            // records it. An invented marker here would have exercised a
            // shape no run produces and left the timed-out row untested.
            report.checkpoint.stage = ExecutionStage::Failed;
            report.checkpoint.last_error = Some(CONTAINER_EXECUTION_TIMEOUT_ERROR.into());
            report.exit_code = None;
            report.findings.clear();
        }
        service
            .apply_execution_report(&case.id, &DurableExecutionReport::from(&report))
            .unwrap();
    }

    let completed = service.show_case(&case.id).unwrap();
    let report = build_beginner_master_report(&completed, &plan.scan_run.id).unwrap();
    audit(&AllEngineRun {
        engines: &engines,
        adapters: &adapters,
        database: &database,
        artifact_root: &artifact_root,
        signing_key: &signing_key,
        case_id: &case.id,
        scan_run_id: &plan.scan_run.id,
        completed,
        report,
    })
}

/// Every paragraph in one export closes before a block element opens.
///
/// Forty-five cards shipped `<p>...<h4>...</h4><p>...</p></p>`: a heading
/// nested in a paragraph, which every parser recovers from by closing the
/// paragraph early, plus a stray end tag after it. No reader saw an error and
/// no assertion about the report's words could see it either.
fn assert_paragraphs_are_well_formed(html: &str, label: &str) {
    assert_eq!(
        html.matches("<p>").count(),
        html.matches("</p>").count(),
        "{label} does not close every paragraph"
    );
    let mut cursor = 0usize;
    while let Some(at) = html[cursor..].find("<p>") {
        let start = cursor + at + "<p>".len();
        let end = html[start..]
            .find("</p>")
            .map_or(html.len(), |offset| start + offset);
        for block in [
            "<p>", "<h1", "<h2", "<h3", "<h4", "<ul", "<ol", "<table", "<section", "<article",
            "<details",
        ] {
            assert!(
                !html[start..end].contains(block),
                "{label} opens {block} inside a paragraph: {}",
                &html[start..end.min(start + 200)]
            );
        }
        cursor = end;
    }
}

#[test]
fn every_integrated_engine_lands_in_one_terminal_report() {
    all_engines_in_one_report(
        AssessmentIntent::InternalItEnvironment,
        AiGeneratedArtifactAnswer::No,
        |subject| {
            let &AllEngineRun {
                engines,
                adapters,
                database,
                artifact_root,
                signing_key,
                case_id,
                scan_run_id,
                ..
            } = subject;
            let (completed, report) = (&subject.completed, &subject.report);
            assert_eq!(
                report
                    .actual
                    .checks
                    .iter()
                    .map(|check| check.check_id.as_str())
                    .collect::<BTreeSet<_>>(),
                BUILTIN_ENGINE_IDS.iter().copied().collect()
            );
            assert_eq!(
                report
                    .requested
                    .targets
                    .iter()
                    .map(|target| &target.asset_id)
                    .collect::<BTreeSet<_>>()
                    .len(),
                completed.assets.len()
            );
            for (engine, status) in [
                ("nuclei", CoverageDimensionStatus::TestedPartial),
                ("semgrep", CoverageDimensionStatus::TestedComplete),
                ("checkov", CoverageDimensionStatus::Failed),
                ("kics", CoverageDimensionStatus::TimedOut),
                ("trufflehog", CoverageDimensionStatus::Cancelled),
            ] {
                assert_eq!(
                    report
                        .actual
                        .checks
                        .iter()
                        .find(|check| check.check_id == engine)
                        .unwrap()
                        .status,
                    status
                );
            }
            let inventory = ["syft", "cloudquery", "steampipe", "naabu", "httpx"];
            assert!(
                completed
                    .findings
                    .iter()
                    .flat_map(|finding| &finding.evidence)
                    .all(|evidence| !inventory.contains(&evidence.engine_id.as_str()))
            );
            assert!(report.inventory.items.iter().any(|item| matches!(
                item.details,
                BeginnerInventoryItemKind::SoftwareComponent { .. }
            )));
            assert!(
                report
                    .actual
                    .checks
                    .iter()
                    .any(|check| check.check_id == "gitleaks"
                        && check.status == CoverageDimensionStatus::TestedComplete)
            );
            assert!(
                report
                    .actual
                    .checks
                    .iter()
                    .any(|check| check.check_id == "trivy"
                        && check.status == CoverageDimensionStatus::TestedComplete)
            );
            assert!(
                completed
                    .scan_runs
                    .iter()
                    .find(|run| run.id == scan_run_id)
                    .unwrap()
                    .engine_runs
                    .iter()
                    .any(|run| run.status == EngineRunStatus::Completed)
            );

            // One instruction is listed once, however many findings name it. Every
            // finding still reaches the reader through exactly one step: nothing is
            // dropped by the merge, and nothing is counted twice.
            let mut step_findings = report
                .next_steps
                .iter()
                .filter_map(|step| step.finding_id.clone().map(|lead| (lead, step)))
                .flat_map(|(lead, step)| {
                    std::iter::once(lead).chain(step.also_resolves.iter().cloned())
                })
                .collect::<Vec<_>>();
            let listed = step_findings.len();
            step_findings.sort();
            step_findings.dedup();
            assert_eq!(
                listed,
                step_findings.len(),
                "a finding must be named by exactly one next step"
            );
            let mut actionable = report
                .findings
                .iter()
                .filter(|finding| {
                    !finding
                        .severity_basis_code
                        .is_some_and(|code| code.is_exposure_observation())
                })
                .map(|finding| finding.finding_id.clone())
                .collect::<Vec<_>>();
            actionable.sort();
            assert_eq!(
                step_findings, actionable,
                "every actionable finding reaches the reader through a next step"
            );
            let repeated = report
                .next_steps
                .iter()
                .filter(|step| !step.also_resolves.is_empty())
                .count();
            assert!(
                repeated > 0,
                "this run has findings that share a fix; the merge must be exercised"
            );
            assert!(
                report.next_steps.len() < actionable.len(),
                "{} steps for {} findings is the findings list printed twice",
                report.next_steps.len(),
                actionable.len()
            );

            // Two findings whose stored instruction is the same string are still two
            // instructions when the reader is sent to a different specialist, and a
            // Cloudsplaining step is composed from its typed policy record rather than
            // from that string at all. Merging on the stored text alone would collapse
            // both of these into one wrong sentence.
            let same_text_different_expert = report
            .next_steps
            .iter()
            .filter(|step| {
                step.action
                    == "Document why this service must remain reachable, or remove or restrict the exposure."
            })
            .map(|step| step.recommended_expert_type.clone())
            .collect::<Vec<_>>();
            assert_eq!(
                same_text_different_expert,
                [
                    Some("Vulnerability manager".to_string()),
                    Some("Application security engineer".to_string()),
                ],
                "one stored sentence, two experts, two steps"
            );
            let iam_policies = [
                "IAMFullAccess",
                "InlinePolicyForAdminGroup",
                "InsecurePolicy",
            ];
            for policy in iam_policies {
                let named = report
                    .next_steps
                    .iter()
                    .filter(|step| step.action.contains(policy))
                    .collect::<Vec<_>>();
                assert_eq!(
                    named.len(),
                    1,
                    "one step per IAM policy the reader has to change; {policy} has {}",
                    named.len()
                );
                assert!(
                    !named[0].also_resolves.is_empty(),
                    "{policy} is named by more than one finding"
                );
            }

            // CloudQuery is the one engine in the catalog whose declared knowledge
            // support ended before this run. Planning already writes that as an
            // engine-run warning, but the warning is a Progress surface: without a
            // coverage row the reader receives a report in which a scanner running on
            // knowledge three years past support is indistinguishable from a current
            // one.
            let stale = report
                .coverage_gaps
                .iter()
                .filter(|gap| gap.dimension.ends_with(": expired detection knowledge"))
                .collect::<Vec<_>>();
            assert_eq!(
                stale.len(),
                1,
                "exactly the engines whose support ended: {:#?}",
                stale
            );
            assert_eq!(
                stale[0].dimension,
                "cloudquery: expired detection knowledge"
            );
            assert!(
                stale[0].reason.ends_with(" Support ended: 2023-04-10."),
                "{}",
                stale[0].reason
            );
            // The check still ran and its inventory is still reported. The row
            // qualifies the result; it does not withdraw it.
            assert_eq!(
                report
                    .actual
                    .checks
                    .iter()
                    .find(|check| check.check_id == "cloudquery")
                    .unwrap()
                    .status,
                CoverageDimensionStatus::TestedComplete
            );

            let reopened_storage = Storage::open(database).unwrap();
            let reopened = reopened_storage.get_case(case_id).unwrap();
            assert_eq!(
                &build_beginner_master_report(&reopened, scan_run_id).unwrap(),
                report
            );
            let reopened_service = CaseService::new(
                &reopened_storage,
                engines,
                adapters,
                artifact_root,
                signing_key,
            );
            // Two vulnerability scanners cover the same repository and the same
            // image, so this run is the shape cross-engine correlation exists for:
            // Trivy and Grype both name CVE-2024-2511 on openssl. The suggestion is
            // the product's offer to combine them; nothing is merged without the
            // reader accepting it, and an unfired suggestion here would mean the
            // reader is never offered the choice on a run that plainly needs it.
            let correlations = ai_security_scanner_lib::correlation::correlation_report(completed);
            let openssl = correlations
                .suggestions
                .iter()
                .filter(|suggestion| suggestion.vulnerability_id == "CVE-2024-2511")
                .collect::<Vec<_>>();
            assert_eq!(
                openssl.len(),
                2,
                "one suggestion per asset the two scanners agree on: {:#?}",
                correlations
            );
            for suggestion in openssl {
                assert_eq!(suggestion.package, "openssl");
                assert_eq!(suggestion.engine_ids, ["grype", "trivy"]);
                assert_eq!(suggestion.finding_ids.len(), 2);
            }
            assert_eq!(correlations.truncated_suggestions, 0);

            // The heading promises the assets that need attention, so the list is
            // read as an order. Before it was one, this run put the asset carrying a
            // single problem first, the asset carrying twenty-two third, and the host
            // whose check failed in the middle of the healthy ones.
            let ordered_html = artifact_root.join("asset-order.html");
            reopened_service
                .export_case(
                    case_id,
                    scan_run_id,
                    CaseExportFormat::Html,
                    ordered_html.clone(),
                    ExportOptions {
                        redaction: RedactionProfile::None,
                        include_raw_artifacts: false,
                        locale: ReportLocale::En,
                    },
                )
                .unwrap();
            let ordered_html = fs::read_to_string(&ordered_html).unwrap();
            assert_paragraphs_are_well_formed(&ordered_html, "the English report");
            // The inventory sample prints addresses, not quantities. Digit
            // grouping turned this run's 8080 into "8,080", which is not a
            // port anyone can paste back into a tool.
            assert!(ordered_html.contains("port 8080"));
            assert!(!ordered_html.contains("port 8,080"));
            let asset_board = &ordered_html[ordered_html
                .find("Which assets need attention")
                .expect("asset board")..];
            let asset_board = &asset_board[..asset_board.find("</section>").expect("board end")];
            let leading_finding = &report.findings[0];
            let leading_asset = report
                .requested
                .targets
                .iter()
                .find(|target| leading_finding.target_asset_ids.contains(&target.asset_id))
                .and_then(|target| target.label.clone())
                .expect("the report's first problem is on a requested asset");
            let first_row = asset_board
                .find("<li class=\"asset-result")
                .expect("at least one asset row");
            assert!(
            asset_board[first_row..].starts_with(&format!(
                "<li class=\"asset-result asset-result--problems-found\"><div class=\"asset-result__identity\"><strong>{leading_asset}</strong>"
            )),
            "the asset carrying the report's first problem leads the board"
        );
            let last_problem = asset_board
                .rfind("asset-result--problems-found")
                .expect("a problems row");
            let first_incomplete = asset_board
                .find("asset-result--incomplete-failed")
                .expect("an incomplete row");
            assert!(
                last_problem < first_incomplete,
                "every asset with a found problem is read before the ones with none"
            );

            // What this product retained about how it knows is kept, and kept out of
            // the way. On this run those two blocks were 57% of everything printed
            // under "Problems found" -- artifact and engine-run identifiers, capture
            // hashes, and the same catalog rationale repeated once per reference --
            // read before the reader reached the next problem.
            let problems = &ordered_html[ordered_html
                .find(">Problems found</h2>")
                .expect("problems section")..];
            // Bounded before the run-level technical section, whose task records are
            // articles too.
            let problems = &problems[..problems
                .find("<details class=\"technical\">")
                .expect("technical details follow the problems")];
            let cards = problems.match_indices("<article>").count();
            assert_eq!(cards, report.findings.len(), "one card per finding");
            assert_eq!(
                problems
                    .match_indices("<details class=\"technical finding-technical\">")
                    .count(),
                cards,
                "every card keeps its evidence and framework provenance collapsed"
            );
            // The report cites twenty-one third-party projects by name. Humanizing
            // their identifiers named five of them something their own documentation
            // does not use, and split one on its hyphen.
            let tested = &ordered_html[ordered_html
                .find(">What was actually tested</h2>")
                .expect("tested section")..];
            let tested = &tested[..tested
                .find(">What needs attention</h2>")
                .expect("gaps follow")];
            for wrong in [
                "Httpx",
                "Kics",
                "Kube Bench",
                "Scoutsuite",
                "Scubagear",
                "Trufflehog",
                "Cloudquery",
                "Completed check To Target",
            ] {
                assert!(
                    !tested.contains(wrong),
                    "the report printed a humanized identifier: {wrong}"
                );
            }
            for right in [
                "httpx",
                "KICS",
                "kube-bench",
                "ScoutSuite",
                "ScubaGear",
                "TruffleHog",
                "CloudQuery",
            ] {
                assert!(tested.contains(right), "the report lost a name: {right}");
            }

            // A completed check's coarse coordinate restated its own header line and
            // added a sentence about this product's record keeping. Eighteen of them
            // were a third of this section.
            for restated in [
                "check-to-target coordinate",
                "The durable task reached completed state for this target binding.",
            ] {
                assert!(
                    !tested.contains(restated),
                    "a completed check restates its header: {restated}"
                );
            }
            // The header still carries every completed check, its window, and its
            // target, and Nuclei's partial run still shows the dimensions it proved.
            assert!(tested.contains("<strong>Syft</strong> — Completed"));

            // The same rule, in the one other place the report composes a name
            // around an identifier. This list named six scanners differently
            // from the "Requested checks" list two headings above it, and
            // title-cased the reader's own target into "Https://...".
            let limits = &ordered_html[ordered_html.find(">Limits</h3>").expect("limits")..];
            let limits = &limits[..limits.find("</ul>").expect("limits end")];
            for wrong in [
                "Httpx",
                "Kics",
                "Kube Bench",
                "Scoutsuite",
                "Scubagear",
                "Trufflehog",
                "Cloudquery",
                "Https://",
            ] {
                assert!(
                    !limits.contains(wrong),
                    "the limits list humanized an identifier: {wrong}"
                );
            }
            for right in [
                "httpx execution timeout",
                "KICS execution timeout",
                "kube-bench execution timeout",
                "ScoutSuite execution timeout",
                "ScubaGear execution timeout",
                "TruffleHog execution timeout",
                "CloudQuery execution timeout",
                "Greenbone Community Edition execution timeout",
                "https://portal.example.test:443 approved ports",
            ] {
                assert!(limits.contains(right), "the limits list lost: {right}");
            }

            // Every remediable finding carries the same product-authored safety
            // sentence, so the report printed the same 115 characters forty-five
            // times. It is advice about making any change, not about one finding.
            assert_eq!(ordered_html.matches("Before changing anything").count(), 1);

            // The coverage rows and the action list sit next to each other, and
            // every gap-derived step used to restate its row's own sentence --
            // a quarter of the section, and five of the nine said "this check"
            // without saying which. Each now names the coverage it closes.
            let steps = &ordered_html[ordered_html
                .find(">What to do next</h2>")
                .expect("next-step section")..];
            let steps = &steps[..steps.find(">Problems found</h2>").expect("problems follow")];
            for restated in [
                "This check stopped before it could establish completed coverage.",
                "Host response unavailable. Vulnerability checks: not run.",
                "The bounded check reached its time limit, so it cannot be treated as tested complete.",
                "This check was cancelled before completed coverage was recorded.",
                "This check produced some durable work but did not complete every planned dimension.",
                "This check ran on detection knowledge whose declared support had already ended",
                "This run did not retain an exact reduction record.",
                "Maester evaluated this control but did not return a pass or fail verdict.",
            ] {
                assert!(
                    !steps.contains(restated),
                    "a step restates the coverage row above it: {restated}"
                );
            }
            for named in [
                "Retry this check.</strong> — Checkov: failed check dimension",
                "Confirm the host is powered on and reachable from this computer on the approved ports, then run this check again.</strong> — Greenbone Community Edition: target response",
                "Confirm reachability in Scan setup, then retry the timed-out work.</strong> — KICS: timed-out check dimension",
                "Retry this check to complete the unfinished dimensions.</strong> — Nuclei: remaining requested dimensions",
                "Treat these results as evidence from expired knowledge, not as current coverage.</strong> — CloudQuery: expired detection knowledge",
                // One step closes two rows, and says so rather than showing one
                // of the two reasons and dropping the other.
                "Retry this check to complete the missing coverage.</strong> — Naabu: cancelled check dimension; TruffleHog: cancelled check dimension",
                "Open the saved scope details.</strong> — Automatic scope reductions or truncations; Requested scan stage",
            ] {
                assert!(
                    steps.contains(named),
                    "a step lost its coverage name: {named}"
                );
            }
            assert!(
                ordered_html.find("Before changing anything")
                    < ordered_html.find(">Problems found</h2>")
            );

            // One attached principal is the ordinary shape of a customer-managed
            // policy, and the sentence had been written only for a list.
            assert!(steps.contains(
                "Narrow customer-managed policy InsecurePolicy and verify that user ExampleUser retains only the permissions they need."
            ));

            // The Chinese report composes its coverage names from the engine's
            // id, so the same scanner was "Checkov" in the tested-checks list
            // and "checkov" in the limits, coverage rows and next steps two
            // sections below. A reader cannot tell whether that is one tool.
            let zh_path = artifact_root.join("asset-order-zh.html");
            reopened_service
                .export_case(
                    case_id,
                    scan_run_id,
                    CaseExportFormat::Html,
                    zh_path.clone(),
                    ExportOptions {
                        redaction: RedactionProfile::None,
                        include_raw_artifacts: false,
                        locale: ReportLocale::ZhHant,
                    },
                )
                .unwrap();
            let zh_html = fs::read_to_string(&zh_path).unwrap();
            assert_paragraphs_are_well_formed(&zh_html, "the Chinese report");
            for named in [
                "檢查逾時限制（Checkov）",
                "檢查逾時限制（CloudQuery）",
                "檢查逾時限制（Greenbone Community Edition）",
                "檢查逾時限制（KICS）",
                "檢查逾時限制（ScoutSuite）",
                "檢查逾時限制（TruffleHog）",
                "Checkov 的失敗的檢查項目",
                "Greenbone Community Edition 的目標回應",
                "KICS 的逾時的檢查項目",
                "Naabu 的已取消的檢查項目",
                "TruffleHog 的已取消的檢查項目",
                "CloudQuery 的已過期的偵測知識",
                "Nuclei 的尚未完成的要求項目",
                "Maester：未回傳判定的控制項 MT.1003",
            ] {
                assert!(
                    zh_html.contains(named),
                    "the Chinese report lost a scanner's name: {named}"
                );
            }
            // The deepest technical block is the report's provenance, not a
            // dumping ground: its headings were translated while the values
            // under them stayed in English. A Chinese reader saw "證據類型:
            // Configuration", "散布方式 Pull Pinned Image", a partly finished
            // run labelled "Partially Completed" beside "已完成" siblings, and
            // one English sentence between two translated ones.
            for translated in [
                "設定",
                "套件盤點",
                "外部驗證",
                "原始碼",
                "拉取已釘選映像",
                "部分完成",
                "本輪的診斷紀錄無法取得；已遮蔽的診斷匯出為獨立檔案。",
            ] {
                assert!(
                    zh_html.contains(translated),
                    "the Chinese report lost a technical value: {translated}"
                );
            }
            for stored_english in [
                "Configuration<",
                "Package Inventory",
                "External Validation",
                "Pull Pinned Image",
                "Partially Completed",
                "Run-bound diagnostic log",
            ] {
                assert!(
                    !zh_html.contains(stored_english),
                    "the Chinese report printed a technical value in English: {stored_english}"
                );
            }
            // The same values stay in English where English is the report.
            for kept in [
                "Package Inventory",
                "Pull Pinned Image",
                "Partially Completed",
                "Run-bound diagnostic log: unavailable. Redacted diagnostic export: separate.",
            ] {
                assert!(
                    ordered_html.contains(kept),
                    "the English report lost: {kept}"
                );
            }

            for spelled_two_ways in [
                "（checkov）",
                "（cloudquery）",
                "（greenbone）",
                "（kics）",
                "（scoutsuite）",
                "（trufflehog）",
                "checkov 的",
                "greenbone 的",
                "kics 的",
                "naabu 的",
                "trufflehog 的",
                "cloudquery 的",
                "nuclei 的",
                "maester：",
            ] {
                assert!(
                    !zh_html.contains(spelled_two_ways),
                    "the Chinese report named a scanner by its id: {spelled_two_ways}"
                );
            }

            // The redacted export is the copy that leaves this machine. Every
            // value it removes has to say it was removed: a cloud resource
            // whose native ID was dropped to nothing printed one line reading
            // "Resource type aws_iam_users", which a recipient reads as an
            // observation that recorded nothing else.
            let redacted_path = artifact_root.join("asset-order-redacted.html");
            reopened_service
                .export_case(
                    case_id,
                    scan_run_id,
                    CaseExportFormat::Html,
                    redacted_path.clone(),
                    ExportOptions {
                        redaction: RedactionProfile::Standard,
                        include_raw_artifacts: false,
                        locale: ReportLocale::En,
                    },
                )
                .unwrap();
            let redacted_html = fs::read_to_string(&redacted_path).unwrap();
            for removed in [
                "192.0.2.11",
                "arn:aws:iam::123456789012:user/alice",
                "pkg:deb/debian/example-package@1.0",
                "example-user",
            ] {
                assert!(
                    ordered_html.contains(removed),
                    "the run no longer carries {removed}; this gate proves nothing"
                );
                assert!(
                    !redacted_html.contains(removed),
                    "the redacted report kept {removed}"
                );
            }
            for marker in [
                "[redacted service endpoint]",
                "[redacted software component]",
                "[redacted version]",
                "[redacted purl]",
                "[redacted native ID]",
                "[redacted display name]",
                "[redacted inventory pointer]",
            ] {
                assert!(
                    redacted_html.contains(marker),
                    "the redacted report dropped a value silently: {marker}"
                );
                assert!(
                    !ordered_html.contains(marker),
                    "the unredacted report marked a value redacted: {marker}"
                );
            }

            // Two scanners find the same CVE on the repository and on the image built
            // from it. The cards are titled identically by upstream, so with the asset
            // four items into the identifier line the reader sees the same heading
            // twice in a row and reads it as the report duplicating one problem.
            let headings = problems
                .match_indices("<h3>")
                .map(|(at, _)| {
                    let rest = &problems[at + "<h3>".len()..];
                    rest[..rest.find("</h3>").expect("heading end")].to_owned()
                })
                .collect::<Vec<_>>();
            assert_eq!(headings.len(), cards);
            let mut unique = headings.clone();
            unique.sort();
            unique.dedup();
            assert_eq!(
                unique.len(),
                headings.len(),
                "no two problems are titled the same: {headings:#?}"
            );
            for (heading, finding) in headings.iter().zip(&report.findings) {
                assert!(
                    heading.contains("<span class=\"finding-asset\">"),
                    "every heading names the asset it is on: {heading}"
                );
                let (title, asset) = heading
                    .split_once(" <span class=\"finding-asset\">")
                    .expect("heading end");
                assert_eq!(
                    title
                        .replace("&amp;", "&")
                        .replace("&lt;", "<")
                        .replace("&gt;", ">")
                        .replace("&quot;", "\"")
                        .replace("&#39;", "'"),
                    finding.title,
                    "the upstream title still leads, unchanged"
                );
                assert!(asset.starts_with("— "), "{asset}");
            }

            let first_card = &problems[problems.find("<article>").expect("a card")..];
            let first_card = &first_card[..first_card.find("</article>").expect("card end")];
            let collapsed_at = first_card
                .find("<details class=\"technical finding-technical\">")
                .expect("collapsed block");
            for open_text in [
                "Grype reported a critical-severity condition on the assessed asset.",
                "Upgrade the affected component to a fixed version",
                "Container security engineer",
                "https://nvd.nist.gov/vuln/detail/CVE-2025-0002",
            ] {
                let at = first_card
                    .find(open_text)
                    .unwrap_or_else(|| panic!("card omitted {open_text}"));
                assert!(at < collapsed_at, "{open_text} must stay in the open");
            }
            for retained in [
                "Evidence SHA-256",
                "Related framework coordinates",
                "Mapping version",
                "ISO/IEC 27001",
            ] {
                let at = first_card
                    .find(retained)
                    .unwrap_or_else(|| panic!("card dropped {retained}"));
                assert!(
                    at > collapsed_at,
                    "{retained} must stay available, collapsed"
                );
            }

            if let Some(dump) = std::env::var_os("AI_SCANNER_REPORT_DUMP_DIR").map(PathBuf::from) {
                fs::create_dir_all(&dump).unwrap();
                for (name, format, locale, redaction) in [
                    (
                        "report-en.html",
                        CaseExportFormat::Html,
                        ReportLocale::En,
                        RedactionProfile::None,
                    ),
                    (
                        "report-zh.html",
                        CaseExportFormat::Html,
                        ReportLocale::ZhHant,
                        RedactionProfile::None,
                    ),
                    (
                        "report-standard-redacted.html",
                        CaseExportFormat::Html,
                        ReportLocale::En,
                        RedactionProfile::Standard,
                    ),
                    (
                        "report.json",
                        CaseExportFormat::CanonicalJson,
                        ReportLocale::En,
                        RedactionProfile::None,
                    ),
                    (
                        "framework.json",
                        CaseExportFormat::FrameworkReport,
                        ReportLocale::En,
                        RedactionProfile::None,
                    ),
                ] {
                    reopened_service
                        .export_case(
                            case_id,
                            scan_run_id,
                            format,
                            dump.join(name),
                            ExportOptions {
                                redaction,
                                include_raw_artifacts: false,
                                locale,
                            },
                        )
                        .unwrap();
                }
                fs::write(
                    dump.join("beginner-report.json"),
                    serde_json::to_string_pretty(&report).unwrap(),
                )
                .unwrap();
            }
        },
    );
}

/// What one set of case answers leaves in the AIDEFEND half of a finished
/// report.
struct AidefendView {
    state: String,
    /// Coordinate to the engines whose evidence carried it.
    reached: BTreeMap<String, BTreeSet<String>>,
    finding_titles: Vec<String>,
    html: String,
    zh_html: String,
    /// The framework export's own account of how much of the run it placed.
    mapped: usize,
    unmapped: usize,
    limitations: Vec<String>,
    mapping_states: BTreeMap<String, usize>,
}

/// Runs the whole 21-engine batch under one set of case answers and reads back
/// what AIDEFEND received.
///
/// Running the whole batch is the point. A coordinate that only a hand-built
/// single-engine case can reach is not a coordinate a reader will ever see,
/// and the reach depends on the run: a check that failed, timed out or was
/// cancelled carries no evidence, so its coordinates stay out no matter what
/// the catalog says.
fn aidefend_view(
    intent: AssessmentIntent,
    ai_generated: AiGeneratedArtifactAnswer,
) -> AidefendView {
    all_engines_in_one_report(intent, ai_generated, |subject| {
        let storage = Storage::open(subject.database).unwrap();
        let service = CaseService::new(
            &storage,
            subject.engines,
            subject.adapters,
            subject.artifact_root,
            subject.signing_key,
        );
        let export = |format, name: &str, locale| {
            let path = subject.artifact_root.join(name);
            service
                .export_case(
                    subject.case_id,
                    subject.scan_run_id,
                    format,
                    path.clone(),
                    ExportOptions {
                        redaction: RedactionProfile::None,
                        include_raw_artifacts: false,
                        locale,
                    },
                )
                .unwrap();
            fs::read(&path).unwrap()
        };
        let framework: serde_json::Value = serde_json::from_slice(&export(
            CaseExportFormat::FrameworkReport,
            "aidefend-framework.json",
            ReportLocale::En,
        ))
        .unwrap();
        assert!(
            framework["unrecognized_relationships"]
                .as_array()
                .unwrap()
                .is_empty(),
            "a relationship the catalog cannot explain must never reach a reader"
        );
        let family = framework["frameworks"]
            .as_array()
            .unwrap()
            .iter()
            .find(|entry| entry["framework"] == "AIDEFEND")
            .expect("AIDEFEND is one of the declared families")
            .clone();
        let mut reached = BTreeMap::<String, BTreeSet<String>>::new();
        for control in family["controls"].as_array().unwrap() {
            for relationship in control["relationships"].as_array().unwrap() {
                // A drifted mapping version is a different claim than one the
                // current catalog still states, and the reader cannot tell
                // them apart from the coordinate alone.
                assert_eq!(relationship["mapping_version_state"], "exact_match");
                assert_eq!(
                    relationship["mapping_provenance_state"],
                    "verified_current_catalog"
                );
                let engines = reached
                    .entry(control["control_id"].as_str().unwrap().to_owned())
                    .or_default();
                for engine in relationship["finding"]["engine_ids"].as_array().unwrap() {
                    engines.insert(engine.as_str().unwrap().to_owned());
                }
            }
        }
        let mut mapping_states = BTreeMap::<String, usize>::new();
        for entry in framework["observation_provenance"].as_array().unwrap() {
            *mapping_states
                .entry(
                    entry["framework_mapping_state"]
                        .as_str()
                        .unwrap()
                        .to_owned(),
                )
                .or_default() += 1;
        }
        let html = String::from_utf8(export(
            CaseExportFormat::Html,
            "aidefend-report.html",
            ReportLocale::En,
        ))
        .unwrap();
        let zh_html = String::from_utf8(export(
            CaseExportFormat::Html,
            "aidefend-report-zh.html",
            ReportLocale::ZhHant,
        ))
        .unwrap();
        assert_paragraphs_are_well_formed(&html, "the English report");
        assert_paragraphs_are_well_formed(&zh_html, "the Chinese report");
        AidefendView {
            state: family["state"].as_str().unwrap().to_owned(),
            mapped: framework["coverage"]["selected_run_findings_with_framework_relationship"]
                .as_u64()
                .unwrap() as usize,
            unmapped: framework["coverage"]["selected_run_findings_without_framework_relationship"]
                .as_u64()
                .unwrap() as usize,
            limitations: framework["coverage"]["limitations"]
                .as_array()
                .unwrap()
                .iter()
                .map(|limitation| limitation.as_str().unwrap().to_owned())
                .collect(),
            mapping_states,
            reached,
            finding_titles: subject
                .report
                .findings
                .iter()
                .map(|finding| finding.title.clone())
                .collect(),
            html,
            zh_html,
        }
    })
}

/// AIDEFEND is a third of the framework structure this product maps to, and
/// the audit above cannot reach any of it: coordinates are withheld from a
/// case that declares a non-AI assessment, which is exactly what the
/// IT-environment run declares. So the AI half of the mapping is exercised
/// here -- catalog, adapter, report layer and export -- on the same 21 checks.
#[test]
fn the_ai_framework_follows_the_case_answers_and_nothing_else() {
    let withheld = aidefend_view(
        AssessmentIntent::InternalItEnvironment,
        AiGeneratedArtifactAnswer::No,
    );
    assert_eq!(withheld.state, "not_applicable_to_declared_context");
    assert!(
        withheld.reached.is_empty(),
        "a non-AI assessment infers no AI coordinate: {:?}",
        withheld.reached
    );
    assert!(
        !withheld.html.contains("AIDEFEND 1.20260805 /"),
        "no AIDEFEND coordinate reaches the reader of a non-AI run"
    );

    let declared = aidefend_view(
        AssessmentIntent::AiApplication,
        AiGeneratedArtifactAnswer::Yes,
    );
    assert_eq!(declared.state, "related_coordinates_observed");
    // Coordinate by coordinate, with the engine that earned it. The catalog
    // also carries IaC-scanning and static-analysis coordinates; Checkov
    // failed, KICS timed out and Semgrep completed empty on this run, so
    // those three carry no evidence and correctly stay out.
    assert_eq!(
        declared
            .reached
            .iter()
            .map(|(control, engines)| (
                control.as_str(),
                engines.iter().map(String::as_str).collect::<Vec<_>>()
            ))
            .collect::<Vec<_>>(),
        vec![
            ("AID-H-003.001", vec!["grype", "trivy"]),
            ("AID-H-003.010", vec!["greenbone", "grype", "trivy"]),
            ("AID-H-031.002", vec!["gitleaks"]),
            ("AID-I-001.001", vec!["kubescape"]),
        ]
    );
    assert!(
        declared.html.contains(
            "<strong>AIDEFEND 1.20260805 / AID-H-003.001</strong> \
             — Software Dependency &amp; Package Security"
        ),
        "the coordinate has to reach the report, not only the export"
    );

    // The artifact answer moves one coordinate and nothing else: the
    // static-admission gate is about artifacts an AI wrote, so a declared AI
    // system that wrote none of its own code does not acquire it.
    let no_artifact = aidefend_view(
        AssessmentIntent::AiApplication,
        AiGeneratedArtifactAnswer::No,
    );
    assert_eq!(no_artifact.state, "related_coordinates_observed");
    assert_eq!(
        no_artifact.reached.keys().collect::<Vec<_>>(),
        ["AID-H-003.001", "AID-H-003.010", "AID-I-001.001"]
    );

    // What the catalog could not place, said out loud. One finding in this run
    // comes from the deliberately malformed Nuclei fixture, whose template id
    // exists only in that fixture, so no reviewed relationship can be written
    // for it -- and an absent coordinate has to read as unknown, not as "no
    // control relates to this".
    for view in [&withheld, &declared, &no_artifact] {
        assert_eq!(view.mapped + view.unmapped, 45);
        assert_eq!(
            view.mapping_states.get("no_packaged_catalog_relationship"),
            Some(&view.unmapped),
            "every unplaced finding says so in the provenance ledger"
        );
        // And the reader is told on the card, in either language, instead of
        // reading the absence as "no control relates to this".
        assert_eq!(
            view.html
                .matches("The packaged mapping catalog has no entry for this finding's rule, so its framework position is unknown, not absent.")
                .count(),
            view.unmapped
        );
        assert_eq!(
            view.zh_html
                .matches("內建的對照目錄沒有此問題規則的項目，因此其框架位置為未知，而非不存在。")
                .count(),
            view.unmapped
        );
        assert!(
            !view
                .html
                .contains("No selected-run framework coordinate was retained.")
        );
        assert!(!view.zh_html.contains("未保留本輪的框架座標。"));
        assert!(
            view.limitations.iter().any(|limitation| limitation
                == "1 of 45 selected-run findings has no relationship in the packaged mapping catalog. Its framework position is unknown, not absent."),
            "{:#?}",
            view.limitations
        );
    }
    // Declaring an AI system adds coordinates to findings the catalog had
    // already placed, so it moves no finding across the line.
    assert_eq!((withheld.mapped, withheld.unmapped), (44, 1));
    assert_eq!((declared.mapped, declared.unmapped), (44, 1));

    // None of this is detection. The same 21 checks found the same problems
    // in all three runs; only the coordinates the report may name changed.
    assert_eq!(withheld.finding_titles.len(), 45);
    assert_eq!(declared.finding_titles, withheld.finding_titles);
    assert_eq!(no_artifact.finding_titles, withheld.finding_titles);
}
