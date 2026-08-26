use ai_security_scanner_lib::connectors::{
    LIVE_PROVIDER_ARTIFACT_SET_SCHEMA, LiveProviderArtifactPage, LiveProviderArtifactSet,
    MAX_SNAPSHOT_BYTES, SNAPSHOT_ARTIFACT_METADATA_KEY, SnapshotArtifactReference,
    SnapshotConnectorRegistry, preflight_snapshot_artifact,
};
use ai_security_scanner_lib::discovery::{
    DiscoveryBatch, DiscoveryConnector, DiscoveryError, reconcile_discovery, run_connector,
};
use ai_security_scanner_lib::domain::{
    AssessmentCase, DataClass, DataSource, OrganizationProfile, SourceConnectionStatus, SourceKind,
};
use ai_security_scanner_lib::storage::Storage;
use chrono::{DateTime, Utc};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::path::{Path, PathBuf};

#[cfg(unix)]
use std::os::unix::fs::{PermissionsExt, symlink};

const OBSERVED_AT: &str = "2026-08-24T12:00:00Z";

fn observed_at() -> DateTime<Utc> {
    DateTime::parse_from_rfc3339(OBSERVED_AT)
        .expect("valid fixture timestamp")
        .with_timezone(&Utc)
}

fn empty_case() -> AssessmentCase {
    AssessmentCase::new(
        "Connector fixtures".into(),
        OrganizationProfile {
            organization_name: "Example".into(),
            employee_range: "1-10".into(),
            data_classes: vec![DataClass::General],
            notes: None,
        },
    )
}

fn source(id: &str, kind: SourceKind) -> DataSource {
    DataSource {
        id: id.into(),
        kind,
        label: id.into(),
        status: SourceConnectionStatus::Connected,
        connected_at: Some(observed_at()),
        last_discovered_at: None,
        read_only: true,
        metadata: BTreeMap::new(),
    }
}

fn fixture(name: &str) -> &'static [u8] {
    match name {
        "aws-cloudquery.json" => include_bytes!("connectors/fixtures/aws-cloudquery.json"),
        "aws-prowler.json" => include_bytes!("connectors/fixtures/aws-prowler.json"),
        "azure-steampipe.json" => include_bytes!("connectors/fixtures/azure-steampipe.json"),
        "gcp-prowler.json" => include_bytes!("connectors/fixtures/gcp-prowler.json"),
        "m365-scubagear.json" => include_bytes!("connectors/fixtures/m365-scubagear.json"),
        "m365-maester.json" => include_bytes!("connectors/fixtures/m365-maester.json"),
        "dns-response.json" => include_bytes!("connectors/fixtures/dns-response.json"),
        "ct-response.json" => include_bytes!("connectors/fixtures/ct-response.json"),
        "billing-export.json" => include_bytes!("connectors/fixtures/billing-export.json"),
        "git-manifest.json" => include_bytes!("connectors/fixtures/git-manifest.json"),
        "terraform-state.json" => include_bytes!("connectors/fixtures/terraform-state.json"),
        "kubernetes-manifest.json" => {
            include_bytes!("connectors/fixtures/kubernetes-manifest.json")
        }
        "container-registry-manifest.json" => {
            include_bytes!("connectors/fixtures/container-registry-manifest.json")
        }
        "filesystem-manifest.json" => {
            include_bytes!("connectors/fixtures/filesystem-manifest.json")
        }
        "user-declared-manifest.json" => {
            include_bytes!("connectors/fixtures/user-declared-manifest.json")
        }
        "empty-cloudquery.json" => include_bytes!("connectors/fixtures/empty-cloudquery.json"),
        "malformed-cloudquery.json" => {
            include_bytes!("connectors/fixtures/malformed-cloudquery.json")
        }
        _ => panic!("unknown connector fixture {name}"),
    }
}

fn write_selected(directory: &Path, name: &str, bytes: &[u8]) -> PathBuf {
    let path = directory.join(name);
    fs::write(&path, bytes).expect("write selected fixture");
    path
}

#[test]
fn preserved_live_pages_survive_restart_without_persisting_authorization() {
    let temp = tempfile::tempdir().unwrap();
    let artifact_root = temp.path().join("artifacts");
    fs::create_dir(&artifact_root).unwrap();
    let registry = SnapshotConnectorRegistry::new(&artifact_root).unwrap();
    let raw = br#"{"projects":[{"name":"projects/987654321","parent":"organizations/123456789012","projectId":"restart-project-123","displayName":"Restart proof","state":"ACTIVE"}]}"#;
    let reference = registry
        .ingest_provider_response(
            &SourceKind::GcpOrganization,
            raw,
            "gcp-resource-manager-projects",
            observed_at(),
        )
        .unwrap();
    let artifacts = LiveProviderArtifactSet {
        schema_version: LIVE_PROVIDER_ARTIFACT_SET_SCHEMA.into(),
        capture_id: "restart-capture".into(),
        profile: "gcp-resource-manager-projects".into(),
        operation: "cloud-resource-manager:ListProjects".into(),
        observed_at: observed_at(),
        complete: true,
        pages: vec![LiveProviderArtifactPage {
            sequence: 1,
            operation: "cloud-resource-manager:ListProjects".into(),
            http_status: 200,
            parser_eligible: true,
            artifact: reference,
        }],
    };
    let mut case = empty_case();
    let mut live_source = source("source-restart", SourceKind::GcpOrganization);
    artifacts.insert_into(&mut live_source).unwrap();
    case.data_sources.push(live_source);
    let database = temp.path().join("casework.db");
    {
        let storage = Storage::open(&database).unwrap();
        storage
            .save_case(&mut case, "fixture.live_capture_saved")
            .unwrap();
    }
    let storage = Storage::open(&database).unwrap();
    let reopened = storage.get_case(&case.id).unwrap();
    let source = &reopened.data_sources[0];
    let batch = run_connector(&registry.connector_for(&source.kind), source).unwrap();
    assert!(batch.assets.iter().any(|asset| {
        asset.stable_identifier.namespace == "gcp_project_id"
            && asset.stable_identifier.value == "restart-project-123"
    }));
    // No token/capability is serialized into the case; reauthorization is a
    // separate in-memory concern handled by the desktop command.
    let encoded = serde_json::to_string(&reopened).unwrap();
    assert!(!encoded.contains("access_token"));
    assert!(!encoded.contains("fixture-secret"));
}

fn ingest_source(
    registry: &SnapshotConnectorRegistry,
    selected_directory: &Path,
    source_id: &str,
    kind: SourceKind,
    profile: &str,
    fixture_name: &str,
) -> (DataSource, SnapshotArtifactReference) {
    let selected = write_selected(
        selected_directory,
        &format!("{source_id}-{fixture_name}"),
        fixture(fixture_name),
    );
    let reference = registry
        .ingest_selected_snapshot(&kind, selected, profile, observed_at())
        .expect("fixture ingests");
    let mut source = source(source_id, kind);
    reference
        .clone()
        .insert_into(&mut source)
        .expect("reference enters source metadata");
    (source, reference)
}

fn batch_for(
    registry: &SnapshotConnectorRegistry,
    selected_directory: &Path,
    source_id: &str,
    kind: SourceKind,
    profile: &str,
    fixture_name: &str,
) -> (DataSource, SnapshotArtifactReference, DiscoveryBatch) {
    let (source, reference) = ingest_source(
        registry,
        selected_directory,
        source_id,
        kind,
        profile,
        fixture_name,
    );
    let connector = registry.connector_for(&source.kind);
    let batch = run_connector(&connector, &source).expect("connector parses fixture");
    (source, reference, batch)
}

#[test]
fn registry_selects_every_source_kind_and_only_provider_sources_support_live_capture() {
    let temp = tempfile::tempdir().unwrap();
    let artifact_root = temp.path().join("artifacts");
    fs::create_dir(&artifact_root).unwrap();
    let registry = SnapshotConnectorRegistry::new(&artifact_root).unwrap();
    let descriptors = registry.descriptors();

    assert_eq!(descriptors.len(), 13);
    assert!(
        descriptors
            .iter()
            .all(|descriptor| descriptor.connector_id.ends_with("-snapshot-v1"))
    );
    let live_kinds = descriptors
        .iter()
        .filter(|descriptor| descriptor.live_discovery)
        .map(|descriptor| descriptor.source_kind.clone())
        .collect::<Vec<_>>();
    assert_eq!(
        live_kinds,
        vec![
            SourceKind::AwsOrganization,
            SourceKind::AzureTenant,
            SourceKind::GcpOrganization,
            SourceKind::Microsoft365Tenant,
        ]
    );
    assert_eq!(
        descriptors
            .iter()
            .map(|descriptor| descriptor.connector_id)
            .collect::<BTreeSet<_>>()
            .len(),
        descriptors.len()
    );
    assert!(descriptors.iter().all(|descriptor| {
        registry
            .connector_for(&descriptor.source_kind)
            .connector_id()
            == descriptor.connector_id
    }));
}

#[test]
fn all_source_kinds_parse_only_their_bounded_snapshot_profiles() {
    struct FixtureCase {
        kind: SourceKind,
        profile: &'static str,
        fixture: &'static str,
        minimum_assets: usize,
        minimum_relations: usize,
    }
    let fixtures = [
        FixtureCase {
            kind: SourceKind::AwsOrganization,
            profile: "cloudquery",
            fixture: "aws-cloudquery.json",
            minimum_assets: 3,
            minimum_relations: 2,
        },
        FixtureCase {
            kind: SourceKind::AzureTenant,
            profile: "steampipe",
            fixture: "azure-steampipe.json",
            minimum_assets: 3,
            minimum_relations: 2,
        },
        FixtureCase {
            kind: SourceKind::GcpOrganization,
            profile: "prowler",
            fixture: "gcp-prowler.json",
            minimum_assets: 3,
            minimum_relations: 2,
        },
        FixtureCase {
            kind: SourceKind::Microsoft365Tenant,
            profile: "scubagear",
            fixture: "m365-scubagear.json",
            minimum_assets: 1,
            minimum_relations: 0,
        },
        FixtureCase {
            kind: SourceKind::Dns,
            profile: "dns-response",
            fixture: "dns-response.json",
            minimum_assets: 3,
            minimum_relations: 2,
        },
        FixtureCase {
            kind: SourceKind::CertificateTransparency,
            profile: "certificate-transparency-response",
            fixture: "ct-response.json",
            minimum_assets: 3,
            minimum_relations: 2,
        },
        FixtureCase {
            kind: SourceKind::Billing,
            profile: "billing-export",
            fixture: "billing-export.json",
            minimum_assets: 6,
            minimum_relations: 3,
        },
        FixtureCase {
            kind: SourceKind::GitRepository,
            profile: "git-manifest",
            fixture: "git-manifest.json",
            minimum_assets: 1,
            minimum_relations: 0,
        },
        FixtureCase {
            kind: SourceKind::TerraformState,
            profile: "terraform-state",
            fixture: "terraform-state.json",
            minimum_assets: 2,
            minimum_relations: 1,
        },
        FixtureCase {
            kind: SourceKind::KubernetesCluster,
            profile: "kubernetes-manifest",
            fixture: "kubernetes-manifest.json",
            minimum_assets: 2,
            minimum_relations: 1,
        },
        FixtureCase {
            kind: SourceKind::ContainerRegistry,
            profile: "container-registry-manifest",
            fixture: "container-registry-manifest.json",
            minimum_assets: 2,
            minimum_relations: 1,
        },
        FixtureCase {
            kind: SourceKind::FileSystem,
            profile: "filesystem-manifest",
            fixture: "filesystem-manifest.json",
            minimum_assets: 1,
            minimum_relations: 0,
        },
        FixtureCase {
            kind: SourceKind::UserDeclared,
            profile: "user-declared-manifest",
            fixture: "user-declared-manifest.json",
            minimum_assets: 2,
            minimum_relations: 1,
        },
    ];

    let temp = tempfile::tempdir().unwrap();
    let artifact_root = temp.path().join("artifacts");
    let selected_root = temp.path().join("selected");
    fs::create_dir(&artifact_root).unwrap();
    fs::create_dir(&selected_root).unwrap();
    let registry = SnapshotConnectorRegistry::new(&artifact_root).unwrap();

    for (index, fixture_case) in fixtures.into_iter().enumerate() {
        let source_id = format!("fixture-source-{index}");
        let (source, reference, batch) = batch_for(
            &registry,
            &selected_root,
            &source_id,
            fixture_case.kind,
            fixture_case.profile,
            fixture_case.fixture,
        );
        assert!(
            batch.assets.len() >= fixture_case.minimum_assets,
            "{} produced {} assets",
            fixture_case.fixture,
            batch.assets.len()
        );
        assert!(
            batch.relations.len() >= fixture_case.minimum_relations,
            "{} produced {} relations",
            fixture_case.fixture,
            batch.relations.len()
        );
        assert!(batch.notices.iter().any(|notice| {
            notice.contains("consumes preserved provider output")
                && notice.contains("did not perform live discovery")
        }));
        assert!(
            batch
                .relations
                .iter()
                .all(|relation| { relation.evidence_ids == [reference.artifact_id.clone()] })
        );

        let mut case = empty_case();
        case.data_sources.push(source);
        let report = reconcile_discovery(&mut case, &batch).expect("fixture batch reconciles");
        assert_eq!(report.created_asset_ids.len(), batch.assets.len());
        assert!(case.assets.iter().all(|asset| asset.candidate));
        assert!(case.assets.iter().all(|asset| !asset.owner_confirmed));
        assert!(case.scope_grants.is_empty());
    }
}

#[test]
fn maester_and_prowler_shapes_do_not_turn_check_titles_into_assets() {
    let temp = tempfile::tempdir().unwrap();
    let artifact_root = temp.path().join("artifacts");
    let selected_root = temp.path().join("selected");
    fs::create_dir(&artifact_root).unwrap();
    fs::create_dir(&selected_root).unwrap();
    let registry = SnapshotConnectorRegistry::new(&artifact_root).unwrap();

    let (_, _, maester) = batch_for(
        &registry,
        &selected_root,
        "maester",
        SourceKind::Microsoft365Tenant,
        "maester",
        "m365-maester.json",
    );
    assert_eq!(
        maester.assets.len(),
        1,
        "only the explicit tenant is inventory"
    );
    assert!(
        maester
            .assets
            .iter()
            .all(|asset| !asset.name.contains("phishing-resistant"))
    );

    let (_, _, prowler) = batch_for(
        &registry,
        &selected_root,
        "prowler",
        SourceKind::AwsOrganization,
        "prowler",
        "aws-prowler.json",
    );
    assert_eq!(prowler.assets.len(), 2);
    assert!(prowler.assets.iter().any(|asset| {
        asset.stable_identifier.namespace == "aws_arn"
            && asset.stable_identifier.value == "arn:aws:s3:::example-evidence-bucket"
    }));
}

#[test]
fn connected_but_empty_is_preserved_as_empty_and_never_rendered_as_successful_coverage() {
    let temp = tempfile::tempdir().unwrap();
    let artifact_root = temp.path().join("artifacts");
    let selected_root = temp.path().join("selected");
    fs::create_dir(&artifact_root).unwrap();
    fs::create_dir(&selected_root).unwrap();
    let registry = SnapshotConnectorRegistry::new(&artifact_root).unwrap();
    let (source, _, batch) = batch_for(
        &registry,
        &selected_root,
        "empty",
        SourceKind::AwsOrganization,
        "cloudquery",
        "empty-cloudquery.json",
    );

    assert!(batch.assets.is_empty());
    assert!(batch.relations.is_empty());
    assert!(
        batch.notices.iter().any(|notice| {
            notice.contains("connected source is recorded as connected but empty")
        })
    );
    let mut case = empty_case();
    case.data_sources.push(source);
    let report = reconcile_discovery(&mut case, &batch).unwrap();
    assert!(report.created_asset_ids.is_empty());
    assert!(case.assets.is_empty());
    assert_eq!(case.data_sources[0].last_discovered_at, Some(observed_at()));
}

#[test]
fn malformed_documents_are_contained_and_valid_siblings_survive() {
    let temp = tempfile::tempdir().unwrap();
    let artifact_root = temp.path().join("artifacts");
    let selected_root = temp.path().join("selected");
    fs::create_dir(&artifact_root).unwrap();
    fs::create_dir(&selected_root).unwrap();
    let registry = SnapshotConnectorRegistry::new(&artifact_root).unwrap();

    let (source, _) = ingest_source(
        &registry,
        &selected_root,
        "malformed",
        SourceKind::AwsOrganization,
        "cloudquery",
        "malformed-cloudquery.json",
    );
    let connector = registry.connector_for(&source.kind);
    assert!(matches!(
        run_connector(&connector, &source),
        Err(DiscoveryError::Connector(message)) if message.contains("malformed")
    ));

    let (_, _, git) = batch_for(
        &registry,
        &selected_root,
        "partial-git",
        SourceKind::GitRepository,
        "git-manifest",
        "git-manifest.json",
    );
    assert_eq!(git.assets.len(), 1);
    assert!(
        git.notices
            .iter()
            .any(|notice| { notice.contains("without a provider-native repository identifier") })
    );
}

#[test]
fn multi_source_stable_identity_merges_and_relations_retain_each_artifact() {
    let temp = tempfile::tempdir().unwrap();
    let artifact_root = temp.path().join("artifacts");
    let selected_root = temp.path().join("selected");
    fs::create_dir(&artifact_root).unwrap();
    fs::create_dir(&selected_root).unwrap();
    let registry = SnapshotConnectorRegistry::new(&artifact_root).unwrap();
    let (cloudquery_source, cloudquery_ref, cloudquery) = batch_for(
        &registry,
        &selected_root,
        "aws-cloudquery",
        SourceKind::AwsOrganization,
        "cloudquery",
        "aws-cloudquery.json",
    );
    let (prowler_source, prowler_ref, prowler) = batch_for(
        &registry,
        &selected_root,
        "aws-prowler",
        SourceKind::AwsOrganization,
        "prowler",
        "aws-prowler.json",
    );
    let mut case = empty_case();
    case.data_sources.push(cloudquery_source);
    case.data_sources.push(prowler_source);
    reconcile_discovery(&mut case, &cloudquery).unwrap();
    reconcile_discovery(&mut case, &prowler).unwrap();

    let bucket = case
        .assets
        .iter()
        .find(|asset| {
            asset.identifiers.iter().any(|identifier| {
                identifier.namespace == "aws_arn"
                    && identifier.value == "arn:aws:s3:::example-evidence-bucket"
            })
        })
        .expect("bucket identity merges");
    assert!(bucket.discovered_from.contains(&"aws-cloudquery".into()));
    assert!(bucket.discovered_from.contains(&"aws-prowler".into()));
    let relation = case
        .asset_relations
        .iter()
        .find(|relation| relation.to_asset_id == bucket.id)
        .expect("account/bucket relation retained");
    assert!(relation.evidence_ids.contains(&cloudquery_ref.artifact_id));
    assert!(relation.evidence_ids.contains(&prowler_ref.artifact_id));

    let (dns_source, _, dns) = batch_for(
        &registry,
        &selected_root,
        "dns",
        SourceKind::Dns,
        "dns-response",
        "dns-response.json",
    );
    let (ct_source, _, ct) = batch_for(
        &registry,
        &selected_root,
        "ct",
        SourceKind::CertificateTransparency,
        "certificate-transparency-response",
        "ct-response.json",
    );
    case.data_sources.push(dns_source);
    case.data_sources.push(ct_source);
    reconcile_discovery(&mut case, &dns).unwrap();
    reconcile_discovery(&mut case, &ct).unwrap();
    let app_domains = case
        .assets
        .iter()
        .filter(|asset| {
            asset.identifiers.iter().any(|identifier| {
                identifier.namespace == "dns_name" && identifier.value == "app.example.com"
            })
        })
        .collect::<Vec<_>>();
    assert_eq!(app_domains.len(), 1, "DNS and CT share the domain identity");
    assert!(app_domains[0].discovered_from.contains(&"dns".into()));
    assert!(app_domains[0].discovered_from.contains(&"ct".into()));
}

#[test]
fn canonical_output_never_copies_secret_fields_or_values() {
    let temp = tempfile::tempdir().unwrap();
    let artifact_root = temp.path().join("artifacts");
    let selected_root = temp.path().join("selected");
    fs::create_dir(&artifact_root).unwrap();
    fs::create_dir(&selected_root).unwrap();
    let registry = SnapshotConnectorRegistry::new(&artifact_root).unwrap();
    for (index, (kind, profile, fixture_name)) in [
        (
            SourceKind::AwsOrganization,
            "cloudquery",
            "aws-cloudquery.json",
        ),
        (
            SourceKind::GitRepository,
            "git-manifest",
            "git-manifest.json",
        ),
        (
            SourceKind::UserDeclared,
            "user-declared-manifest",
            "user-declared-manifest.json",
        ),
    ]
    .into_iter()
    .enumerate()
    {
        let (_, _, batch) = batch_for(
            &registry,
            &selected_root,
            &format!("no-secret-{index}"),
            kind,
            profile,
            fixture_name,
        );
        let serialized = serde_json::to_string(&batch).unwrap();
        assert!(!serialized.contains("must-never-enter-canonical-metadata"));
        assert!(!serialized.contains("raw-only"));
        for asset in batch.assets {
            assert!(asset.metadata.keys().all(|key| {
                let key = key.to_ascii_lowercase();
                !key.contains("password")
                    && !key.contains("secret")
                    && !key.contains("token")
                    && !key.contains("credential")
            }));
            assert!(asset.stable_identifier.namespace != "api_key");
            assert!(
                asset
                    .additional_identifiers
                    .iter()
                    .all(|identifier| identifier.namespace != "api_key")
            );
        }
    }

    let (mut unsafe_source, _) = ingest_source(
        &registry,
        &selected_root,
        "unsafe-source",
        SourceKind::GitRepository,
        "git-manifest",
        "git-manifest.json",
    );
    unsafe_source
        .metadata
        .insert("client_secret".into(), json!("do-not-store"));
    let connector = registry.connector_for(&unsafe_source.kind);
    assert!(matches!(
        run_connector(&connector, &unsafe_source),
        Err(DiscoveryError::Connector(message)) if message.contains("forbidden secret-like field")
    ));
}

#[test]
fn connector_reads_only_the_backend_canonical_reference_and_rejects_escape_or_tamper() {
    let temp = tempfile::tempdir().unwrap();
    let artifact_root = temp.path().join("artifacts");
    let selected_root = temp.path().join("selected");
    fs::create_dir(&artifact_root).unwrap();
    fs::create_dir(&selected_root).unwrap();
    let registry = SnapshotConnectorRegistry::new(&artifact_root).unwrap();
    let selected = write_selected(&selected_root, "outside.json", fixture("git-manifest.json"));

    let mut unreferenced = source("unreferenced", SourceKind::GitRepository);
    unreferenced
        .metadata
        .insert("snapshot_path".into(), json!(selected));
    let connector = registry.connector_for(&unreferenced.kind);
    assert!(matches!(
        run_connector(&connector, &unreferenced),
        Err(DiscoveryError::Connector(message)) if message.contains("no backend-created canonical")
    ));

    let mut traversal = source("traversal", SourceKind::GitRepository);
    SnapshotArtifactReference::new(
        "../selected/outside.json",
        "artifact-traversal",
        "git-manifest",
        observed_at(),
        None,
    )
    .insert_into(&mut traversal)
    .unwrap();
    assert!(matches!(
        run_connector(&connector, &traversal),
        Err(DiscoveryError::Connector(message)) if message.contains("normalized relative path")
    ));

    let (tampered_source, tampered_reference) = ingest_source(
        &registry,
        &selected_root,
        "tampered",
        SourceKind::GitRepository,
        "git-manifest",
        "git-manifest.json",
    );
    fs::write(
        artifact_root.join(&tampered_reference.canonical_relative_path),
        b"{}",
    )
    .unwrap();
    assert!(matches!(
        run_connector(&connector, &tampered_source),
        Err(DiscoveryError::Connector(message)) if message.contains("integrity check")
    ));
}

#[test]
fn passive_snapshot_preflight_rejects_missing_tampered_and_mismatched_artifacts() {
    let temp = tempfile::tempdir().unwrap();
    let artifact_root = temp.path().join("artifacts");
    let selected_root = temp.path().join("selected");
    fs::create_dir(&artifact_root).unwrap();
    fs::create_dir(&selected_root).unwrap();
    let registry = SnapshotConnectorRegistry::new(&artifact_root).unwrap();
    let (_source, reference) = ingest_source(
        &registry,
        &selected_root,
        "preflight",
        SourceKind::GitRepository,
        "git-manifest",
        "git-manifest.json",
    );

    preflight_snapshot_artifact(&artifact_root, &SourceKind::GitRepository, &reference)
        .expect("valid passive snapshot is ready");

    let profile_error =
        preflight_snapshot_artifact(&artifact_root, &SourceKind::TerraformState, &reference)
            .expect_err("source kind must bind the parser profile");
    assert!(matches!(
        profile_error,
        DiscoveryError::Connector(message) if message.contains("not allowed for this source kind")
    ));

    let artifact_path = artifact_root.join(&reference.canonical_relative_path);
    fs::write(&artifact_path, b"{}").unwrap();
    let tamper_error =
        preflight_snapshot_artifact(&artifact_root, &SourceKind::GitRepository, &reference)
            .expect_err("tampering must fail before persistence");
    assert!(matches!(
        tamper_error,
        DiscoveryError::Connector(message) if message.contains("integrity check")
    ));

    fs::remove_file(&artifact_path).unwrap();
    let missing_error =
        preflight_snapshot_artifact(&artifact_root, &SourceKind::GitRepository, &reference)
            .expect_err("missing snapshot must fail before persistence");
    assert!(matches!(
        missing_error,
        DiscoveryError::Connector(message) if message.contains("could not be inspected")
    ));

    let missing_root = temp.path().join("missing-artifact-root");
    let missing_root_error =
        preflight_snapshot_artifact(&missing_root, &SourceKind::GitRepository, &reference)
            .expect_err("preflight must not create a missing root");
    assert!(matches!(
        missing_root_error,
        DiscoveryError::Connector(message) if message.contains("root could not be inspected")
    ));
    assert!(!missing_root.exists());
}

#[test]
fn passive_snapshot_preflight_is_read_only() {
    let temp = tempfile::tempdir().unwrap();
    let artifact_root = temp.path().join("artifacts");
    let selected_root = temp.path().join("selected");
    fs::create_dir(&artifact_root).unwrap();
    fs::create_dir(&selected_root).unwrap();
    let registry = SnapshotConnectorRegistry::new(&artifact_root).unwrap();
    let (_source, reference) = ingest_source(
        &registry,
        &selected_root,
        "read-only-preflight",
        SourceKind::GitRepository,
        "git-manifest",
        "git-manifest.json",
    );
    let artifact_path = artifact_root.join(&reference.canonical_relative_path);
    let before_bytes = fs::read(&artifact_path).unwrap();
    let before_entries = fs::read_dir(&artifact_root).unwrap().count();

    #[cfg(unix)]
    {
        fs::set_permissions(&artifact_root, fs::Permissions::from_mode(0o755)).unwrap();
        fs::set_permissions(&artifact_path, fs::Permissions::from_mode(0o644)).unwrap();
    }

    preflight_snapshot_artifact(&artifact_root, &SourceKind::GitRepository, &reference)
        .expect("read-only preflight succeeds");

    assert_eq!(fs::read(&artifact_path).unwrap(), before_bytes);
    assert_eq!(
        fs::read_dir(&artifact_root).unwrap().count(),
        before_entries
    );
    #[cfg(unix)]
    {
        assert_eq!(
            fs::metadata(&artifact_root).unwrap().permissions().mode() & 0o777,
            0o755,
            "preflight must not chmod the artifact root"
        );
        assert_eq!(
            fs::metadata(&artifact_path).unwrap().permissions().mode() & 0o777,
            0o644,
            "preflight must not chmod the artifact"
        );
    }
}

#[cfg(unix)]
#[test]
fn connector_artifact_and_selected_source_symlinks_are_rejected() {
    let temp = tempfile::tempdir().unwrap();
    let artifact_root = temp.path().join("artifacts");
    let selected_root = temp.path().join("selected");
    fs::create_dir(&artifact_root).unwrap();
    fs::create_dir(&selected_root).unwrap();
    let registry = SnapshotConnectorRegistry::new(&artifact_root).unwrap();
    let selected = write_selected(&selected_root, "real.json", fixture("git-manifest.json"));
    let selected_link = selected_root.join("selected-link.json");
    symlink(&selected, &selected_link).unwrap();
    assert!(matches!(
        registry.ingest_selected_snapshot(
            &SourceKind::GitRepository,
            &selected_link,
            "git-manifest",
            observed_at(),
        ),
        Err(DiscoveryError::Connector(message)) if message.contains("symlink")
    ));

    let artifact_link = artifact_root.join("artifact-link.json");
    symlink(&selected, &artifact_link).unwrap();
    let mut linked_source = source("linked", SourceKind::GitRepository);
    SnapshotArtifactReference::new(
        "artifact-link.json",
        "artifact-link",
        "git-manifest",
        observed_at(),
        None,
    )
    .insert_into(&mut linked_source)
    .unwrap();
    let connector = registry.connector_for(&linked_source.kind);
    assert!(matches!(
        run_connector(&connector, &linked_source),
        Err(DiscoveryError::Connector(message)) if message.contains("symlink")
    ));
}

#[test]
fn ingestion_generates_private_non_overwriting_paths_and_cleans_failures() {
    let temp = tempfile::tempdir().unwrap();
    let artifact_root = temp.path().join("artifacts");
    let selected_root = temp.path().join("selected");
    fs::create_dir(&artifact_root).unwrap();
    fs::create_dir(&selected_root).unwrap();
    let registry = SnapshotConnectorRegistry::new(&artifact_root).unwrap();
    let selected = write_selected(&selected_root, "git.json", fixture("git-manifest.json"));
    let first = registry
        .ingest_selected_snapshot(
            &SourceKind::GitRepository,
            &selected,
            "git-manifest",
            observed_at(),
        )
        .unwrap();
    let second = registry
        .ingest_selected_snapshot(
            &SourceKind::GitRepository,
            &selected,
            "git-manifest",
            observed_at(),
        )
        .unwrap();
    assert_ne!(first.artifact_id, second.artifact_id);
    assert_ne!(
        first.canonical_relative_path,
        second.canonical_relative_path
    );
    assert_eq!(
        first.sha256,
        Some(hex::encode(Sha256::digest(fixture("git-manifest.json"))))
    );
    assert_eq!(
        fs::read(artifact_root.join(&first.canonical_relative_path)).unwrap(),
        fixture("git-manifest.json")
    );
    assert!(fs::read_dir(&artifact_root).unwrap().all(|entry| {
        !entry
            .unwrap()
            .file_name()
            .to_string_lossy()
            .contains("staging")
    }));
    #[cfg(unix)]
    assert_eq!(
        fs::metadata(artifact_root.join(&first.canonical_relative_path))
            .unwrap()
            .permissions()
            .mode()
            & 0o777,
        0o600
    );

    let before = fs::read_dir(&artifact_root).unwrap().count();
    assert!(matches!(
        registry.ingest_selected_snapshot(
            &SourceKind::GitRepository,
            &selected,
            "terraform-state",
            observed_at(),
        ),
        Err(DiscoveryError::Connector(message)) if message.contains("not allowed")
    ));
    assert_eq!(fs::read_dir(&artifact_root).unwrap().count(), before);

    let oversized = selected_root.join("oversized.json");
    let file = fs::File::create(&oversized).unwrap();
    file.set_len(MAX_SNAPSHOT_BYTES + 1).unwrap();
    assert!(matches!(
        registry.ingest_selected_snapshot(
            &SourceKind::GitRepository,
            &oversized,
            "git-manifest",
            observed_at(),
        ),
        Err(DiscoveryError::Connector(message)) if message.contains("exceeds")
    ));
    assert_eq!(fs::read_dir(&artifact_root).unwrap().count(), before);
}

#[test]
fn ingestion_rejects_relative_and_lexically_traversing_source_paths() {
    let temp = tempfile::tempdir().unwrap();
    let artifact_root = temp.path().join("artifacts");
    let selected_root = temp.path().join("selected");
    fs::create_dir(&artifact_root).unwrap();
    fs::create_dir(&selected_root).unwrap();
    let registry = SnapshotConnectorRegistry::new(&artifact_root).unwrap();
    write_selected(&selected_root, "source.json", fixture("git-manifest.json"));

    assert!(matches!(
        registry.ingest_selected_snapshot(
            &SourceKind::GitRepository,
            Path::new("relative.json"),
            "git-manifest",
            observed_at(),
        ),
        Err(DiscoveryError::Connector(message)) if message.contains("absolute path")
    ));
    let traversing = selected_root.join("child").join("..").join("source.json");
    assert!(matches!(
        registry.ingest_selected_snapshot(
            &SourceKind::GitRepository,
            traversing,
            "git-manifest",
            observed_at(),
        ),
        Err(DiscoveryError::Connector(message)) if message.contains("traversal")
    ));
    assert_eq!(fs::read_dir(&artifact_root).unwrap().count(), 0);
}

#[test]
fn canonical_reference_rejects_unknown_fields_including_secret_injection() {
    let temp = tempfile::tempdir().unwrap();
    let artifact_root = temp.path().join("artifacts");
    fs::create_dir(&artifact_root).unwrap();
    let registry = SnapshotConnectorRegistry::new(&artifact_root).unwrap();
    fs::write(
        artifact_root.join("snapshot.json"),
        fixture("git-manifest.json"),
    )
    .unwrap();
    let mut source = source("secret-ref", SourceKind::GitRepository);
    source.metadata.insert(
        SNAPSHOT_ARTIFACT_METADATA_KEY.into(),
        json!({
            "schema_version": "ai-security-scanner.connector-artifact/v1",
            "canonical_relative_path": "snapshot.json",
            "artifact_id": "artifact-one",
            "profile": "git-manifest",
            "observed_at": OBSERVED_AT,
            "sha256": Value::Null,
            "client_secret": "forbidden"
        }),
    );
    let connector = registry.connector_for(&source.kind);
    assert!(matches!(
        run_connector(&connector, &source),
        Err(DiscoveryError::Connector(message)) if message.contains("forbidden secret-like field")
    ));
}
