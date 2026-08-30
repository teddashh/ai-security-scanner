use crate::coverage::NOT_APPLICABLE_REASON_METADATA;
use crate::domain::*;
use chrono::{Duration, Utc};
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;

fn artifact_hash(content: &str) -> String {
    hex::encode(Sha256::digest(content.as_bytes()))
}

pub fn build_demo_case() -> AssessmentCase {
    let now = Utc::now();
    let mut case = AssessmentCase::new(
        "展示案件：Northstar 線上服務".into(),
        OrganizationProfile {
            organization_name: "Northstar Demo Co.".into(),
            employee_range: "11-50".into(),
            data_classes: vec![
                DataClass::PersonallyIdentifiableInformation,
                DataClass::CredentialsAndSecrets,
            ],
            notes: Some("這是合成展示資料，不代表真實掃描結果。".into()),
        },
    );
    case.is_demo = true;
    case.status = CaseStatus::ReadyForHandoff;
    case.knowledge_cutoff = Some(now - Duration::days(2));
    case.requested_activities = vec![
        AssessmentActivity::ConfigurationAssessment,
        AssessmentActivity::LocalArtifactAnalysis,
        AssessmentActivity::LowImpactExternalChecks,
    ];

    let aws_source_id = new_id();
    let dns_source_id = new_id();
    let azure_source_id = new_id();
    let gcp_source_id = new_id();
    case.data_sources = vec![
        DataSource {
            id: aws_source_id.clone(),
            kind: SourceKind::AwsOrganization,
            label: "AWS Organization（唯讀展示）".into(),
            status: SourceConnectionStatus::Connected,
            connected_at: Some(now - Duration::days(3)),
            last_discovered_at: Some(now - Duration::days(2)),
            read_only: true,
            metadata: BTreeMap::new(),
        },
        DataSource {
            id: dns_source_id.clone(),
            kind: SourceKind::Dns,
            label: "northstar.example DNS".into(),
            status: SourceConnectionStatus::Connected,
            connected_at: Some(now - Duration::days(3)),
            last_discovered_at: Some(now - Duration::days(2)),
            read_only: true,
            metadata: BTreeMap::new(),
        },
        DataSource {
            id: azure_source_id,
            kind: SourceKind::AzureTenant,
            label: "Azure Tenant".into(),
            status: SourceConnectionStatus::NotApplicable,
            connected_at: None,
            last_discovered_at: None,
            read_only: true,
            metadata: BTreeMap::from([(
                NOT_APPLICABLE_REASON_METADATA.into(),
                serde_json::Value::String(
                    "The synthetic questionnaire states that Azure is not used in this case."
                        .into(),
                ),
            )]),
        },
        DataSource {
            id: gcp_source_id,
            kind: SourceKind::GcpOrganization,
            label: "Google Cloud Organization".into(),
            status: SourceConnectionStatus::NotConnected,
            connected_at: None,
            last_discovered_at: None,
            read_only: true,
            metadata: BTreeMap::new(),
        },
    ];

    let account_id = new_id();
    let bucket_id = new_id();
    let domain_id = new_id();
    let unknown_host_id = new_id();
    case.assets = vec![
        Asset {
            id: account_id.clone(),
            kind: AssetKind::CloudAccount,
            name: "northstar-production".into(),
            provider: Some("aws".into()),
            region: Some("us-east-1".into()),
            identifiers: vec![AssetIdentifier {
                namespace: "aws_account_id".into(),
                value: "111122223333".into(),
            }],
            discovered_from: vec![aws_source_id.clone()],
            candidate: false,
            owner_confirmed: true,
            internet_exposed: Some(false),
            contains_sensitive_data: Some(true),
            metadata: BTreeMap::new(),
        },
        Asset {
            id: bucket_id.clone(),
            kind: AssetKind::CloudResource,
            name: "northstar-customer-exports".into(),
            provider: Some("aws".into()),
            region: Some("us-east-1".into()),
            identifiers: vec![AssetIdentifier {
                namespace: "aws_arn".into(),
                value: "arn:aws:s3:::northstar-customer-exports".into(),
            }],
            discovered_from: vec![aws_source_id.clone()],
            candidate: false,
            owner_confirmed: true,
            internet_exposed: Some(true),
            contains_sensitive_data: Some(true),
            metadata: BTreeMap::new(),
        },
        Asset {
            id: domain_id.clone(),
            kind: AssetKind::Domain,
            name: "portal.northstar.example".into(),
            provider: None,
            region: None,
            identifiers: vec![AssetIdentifier {
                namespace: "dns_name".into(),
                value: "portal.northstar.example".into(),
            }],
            discovered_from: vec![dns_source_id],
            candidate: false,
            owner_confirmed: true,
            internet_exposed: Some(true),
            contains_sensitive_data: None,
            metadata: BTreeMap::new(),
        },
        Asset {
            id: unknown_host_id.clone(),
            kind: AssetKind::IpAddress,
            name: "198.51.100.24（候選）".into(),
            provider: None,
            region: None,
            identifiers: vec![AssetIdentifier {
                namespace: "ip".into(),
                value: "198.51.100.24".into(),
            }],
            discovered_from: vec![aws_source_id.clone()],
            candidate: true,
            owner_confirmed: false,
            internet_exposed: Some(true),
            contains_sensitive_data: None,
            metadata: BTreeMap::new(),
        },
    ];

    case.asset_relations.push(AssetRelation {
        id: new_id(),
        from_asset_id: account_id.clone(),
        to_asset_id: bucket_id.clone(),
        kind: RelationKind::Contains,
        evidence_ids: Vec::new(),
    });

    let scope_id = new_id();
    case.scope_grants = vec![ScopeGrant {
        id: scope_id.clone(),
        asset_id: account_id.clone(),
        permission: ScanPermission::ConfigurationRead,
        confirmed_by: "Demo operator".into(),
        confirmed_at: now - Duration::days(2),
        expires_at: Some(now + Duration::hours(1)),
        authorization_reference: Some("SYNTHETIC-DEMO".into()),
        notes: Some("Synthetic demonstration only".into()),
        external_scope: None,
    }];

    let run_id = new_id();
    let prowler_run_id = new_id();
    let httpx_run_id = new_id();
    case.scan_runs.push(ScanRun {
        id: run_id.clone(),
        case_id: case.id.clone(),
        sequence: 1,
        created_at: now - Duration::days(2),
        completed_at: Some(now - Duration::days(2) + Duration::minutes(18)),
        request_outcome: None,
        knowledge_cutoff: now - Duration::days(2),
        ai_system_applicable: false,
        ai_system_applicability: AiSystemApplicabilityAnswer::NotApplicable,
        ai_generated_artifact: Default::default(),
        verification_baseline_run_id: None,
        scope_grant_ids: vec![scope_id],
        scope_grant_snapshots: case.scope_grants.clone(),
        engine_admission_issues: Vec::new(),
        engine_runs: vec![
            EngineRun {
                id: prowler_run_id.clone(),
                scan_run_id: run_id.clone(),
                engine_id: "prowler".into(),
                task_kind: Default::default(),
                localhost_tcp_observation: None,
                asset_ids: vec![account_id.clone(), bucket_id.clone()],
                status: EngineRunStatus::Completed,
                progress_percent: 100,
                phase: "完成正規化".into(),
                started_at: Some(now - Duration::days(2)),
                finished_at: Some(now - Duration::days(2) + Duration::minutes(14)),
                resume_token: None,
                engine_version: Some("synthetic-demo".into()),
                image_digest: Some("sha256:synthetic-demo-not-an-image".into()),
                rule_version: Some("synthetic-demo".into()),
                adapter_version: "0.1.2-demo".into(),
                manifest_schema_version: Some("synthetic-demo".into()),
                source_revision: Some("synthetic-demo".into()),
                repository_url: None,
                distribution_mode: None,
                image_repository: None,
                command_sha256: None,
                execution_timeout_seconds: None,
                knowledge_input: None,
                scope_contract_sha256: None,
                naabu_work_plan: None,
                naabu_attempt_requests: Vec::new(),
                mapping_version: None,
                mapping_provenance: None,
                fingerprint_schema_version: None,
                runtime_provider: None,
                runtime_version: None,
                runtime_security_options: None,
                exit_code: Some(0),
                cleanup_removed: Some(true),
                cleanup_detail: Some("Synthetic demonstration only".into()),
                warnings: vec!["Synthetic demonstration data; no scanner was executed.".into()],
                raw_artifact_ids: Vec::new(),
                error_code: None,
                error_message: None,
            },
            EngineRun {
                id: httpx_run_id.clone(),
                scan_run_id: run_id.clone(),
                engine_id: "httpx".into(),
                task_kind: Default::default(),
                localhost_tcp_observation: None,
                asset_ids: vec![domain_id.clone()],
                status: EngineRunStatus::PartiallyCompleted,
                progress_percent: 72,
                phase: "部分目標逾時".into(),
                started_at: Some(now - Duration::days(2) + Duration::minutes(3)),
                finished_at: Some(now - Duration::days(2) + Duration::minutes(18)),
                resume_token: Some("synthetic-resume-token".into()),
                engine_version: Some("synthetic-demo".into()),
                image_digest: None,
                rule_version: None,
                adapter_version: "0.1.2-demo".into(),
                manifest_schema_version: Some("synthetic-demo".into()),
                source_revision: Some("synthetic-demo".into()),
                repository_url: None,
                distribution_mode: None,
                image_repository: None,
                command_sha256: None,
                execution_timeout_seconds: None,
                knowledge_input: None,
                scope_contract_sha256: None,
                naabu_work_plan: None,
                naabu_attempt_requests: Vec::new(),
                mapping_version: None,
                mapping_provenance: None,
                fingerprint_schema_version: None,
                runtime_provider: None,
                runtime_version: None,
                runtime_security_options: None,
                exit_code: Some(2),
                cleanup_removed: Some(true),
                cleanup_detail: Some("Synthetic demonstration only".into()),
                warnings: vec!["Synthetic demonstration data; no scanner was executed.".into()],
                raw_artifact_ids: Vec::new(),
                error_code: Some("TARGET_TIMEOUT".into()),
                error_message: Some("One synthetic target timed out.".into()),
            },
        ],
    });

    case.coverage = vec![
        CoverageEntry {
            id: new_id(),
            scope_key: "aws:111122223333".into(),
            label: "AWS production account".into(),
            source_kind: SourceKind::AwsOrganization,
            asset_id: Some(account_id.clone()),
            status: CoverageStatus::DiscoveredAuthorizedScanned,
            explanation: "已由合成 Prowler 展示資料完成設定檢查。".into(),
            last_run_id: Some(run_id.clone()),
            observed_at: Some(now - Duration::days(2)),
        },
        CoverageEntry {
            id: new_id(),
            scope_key: "ip:198.51.100.24".into(),
            label: "候選外部 IP".into(),
            source_kind: SourceKind::AwsOrganization,
            asset_id: Some(unknown_host_id),
            status: CoverageStatus::DiscoveredNotAuthorized,
            explanation: "已發現，但尚未確認資產所有權，未啟動外部掃描。".into(),
            last_run_id: None,
            observed_at: Some(now - Duration::days(2)),
        },
        CoverageEntry {
            id: new_id(),
            scope_key: "dns:portal.northstar.example".into(),
            label: "公開入口網站".into(),
            source_kind: SourceKind::Dns,
            asset_id: Some(domain_id.clone()),
            status: CoverageStatus::AuthorizedScanIncomplete,
            explanation: "已授權低干擾連線，但部分探測逾時。".into(),
            last_run_id: Some(run_id.clone()),
            observed_at: Some(now - Duration::days(2)),
        },
        CoverageEntry {
            id: new_id(),
            scope_key: "azure:tenant".into(),
            label: "Azure Tenant".into(),
            source_kind: SourceKind::AzureTenant,
            asset_id: None,
            status: CoverageStatus::NotApplicable,
            explanation: "合成問卷明確記錄此案件不使用 Azure；這是適用性聲明，不是掃描成功。"
                .into(),
            last_run_id: None,
            observed_at: None,
        },
        CoverageEntry {
            id: new_id(),
            scope_key: "gcp:organization".into(),
            label: "Google Cloud Organization".into(),
            source_kind: SourceKind::GcpOrganization,
            asset_id: None,
            status: CoverageStatus::SourceNotConnectedUnknown,
            explanation: "未連接任何 GCP 盤點來源；不能推論不存在 GCP 資產。".into(),
            last_run_id: None,
            observed_at: None,
        },
    ];

    let raw_content = r#"{"demo":true,"check":"s3_public_access","status":"FAIL"}"#;
    let artifact_id = new_id();
    let finding_id = new_id();
    case.raw_artifacts.push(RawArtifact {
        id: artifact_id.clone(),
        case_id: case.id.clone(),
        run_id: run_id.clone(),
        engine_run_id: prowler_run_id.clone(),
        relative_path: "raw/prowler/synthetic-demo.json".into(),
        media_type: "application/json".into(),
        sha256: artifact_hash(raw_content),
        byte_length: raw_content.len() as u64,
        created_at: now - Duration::days(2),
        contains_sensitive_data: true,
    });
    case.findings.push(Finding {
        id: finding_id.clone(),
        case_id: case.id.clone(),
        first_seen_run_id: run_id.clone(),
        last_seen_run_id: run_id.clone(),
        fingerprint: "demo:aws:s3:public-customer-export".into(),
        title: "客戶匯出資料儲存空間可能允許公開存取".into(),
        plain_language_summary: "合成展示證據指出，一個可能存放客戶匯出資料的儲存空間未完整阻擋公開存取。".into(),
        possible_impact: "若經人工確認，未授權者可能讀取或列舉敏感資料。".into(),
        severity: Severity::Critical,
        confidence: Confidence::High,
        priority: 96,
        priority_reasons: vec!["資產可能對外".into(), "標記為包含個人資料".into()],
        asset_ids: vec![bucket_id.clone()],
        evidence: vec![Evidence {
            id: new_id(),
            finding_id: finding_id.clone(),
            run_id: run_id.clone(),
            engine_run_id: Some(prowler_run_id.clone()),
            kind: EvidenceKind::Configuration,
            engine_id: "prowler".into(),
            source_rule: None,
            result_pointer_sha256: None,
            observed_at: now - Duration::days(2),
            summary: "Synthetic policy observation for interface demonstration.".into(),
            artifact_id: artifact_id.clone(),
            artifact_sha256: artifact_hash(raw_content),
            pointer: Some("/check".into()),
            redacted: true,
        }],
        control_references: vec![
            ControlReference {
                framework: "NIST CSF".into(),
                framework_version: "2.0".into(),
                control_id: "PR.DS-01".into(),
                title: "Data-at-rest protection".into(),
                relationship: "related".into(),
                rationale: "This finding may relate to protection of stored data; it is not an audit conclusion.".into(),
                mapping_version: "demo-0.1".into(),
                mapping_provenance: None,
            },
            ControlReference {
                framework: "ISO/IEC 27001".into(),
                framework_version: "2022".into(),
                control_id: "A.8.3".into(),
                title: "Information access restriction".into(),
                relationship: "related".into(),
                rationale: "Coordinate only; no compliance determination is made.".into(),
                mapping_version: "demo-0.1".into(),
                mapping_provenance: None,
            },
        ],
        recommendation: "請由 AWS 雲端安全專家確認 bucket policy、Block Public Access 與實際業務依賴。不要直接套用自動修復。".into(),
        verification_guidance: "專家調整後，使用同一案件與範圍重新執行設定檢查。".into(),
        rollback_considerations: Some("變更公開存取可能中斷既有資料交換；先確認使用者與服務。".into()),
        official_references: vec!["https://docs.aws.amazon.com/AmazonS3/latest/userguide/access-control-block-public-access.html".into()],
        recommended_expert_type: "AWS 雲端安全／IAM 專家".into(),
        status: FindingStatus::ExpertReviewRequested,
        tags: vec!["synthetic-demo".into(), "data-exposure".into()],
    });

    let timeout_content =
        r#"{"demo":true,"check":"hsts","status":"INCOMPLETE","reason":"TARGET_TIMEOUT"}"#;
    let timeout_artifact_id = new_id();
    case.raw_artifacts.push(RawArtifact {
        id: timeout_artifact_id.clone(),
        case_id: case.id.clone(),
        run_id: run_id.clone(),
        engine_run_id: httpx_run_id.clone(),
        relative_path: "raw/httpx/synthetic-timeout.json".into(),
        media_type: "application/json".into(),
        sha256: artifact_hash(timeout_content),
        byte_length: timeout_content.len() as u64,
        created_at: now - Duration::days(2),
        contains_sensitive_data: false,
    });
    case.scan_runs[0].engine_runs[0]
        .raw_artifact_ids
        .push(artifact_id);
    case.scan_runs[0].engine_runs[1]
        .raw_artifact_ids
        .push(timeout_artifact_id.clone());

    let second_finding_id = new_id();
    case.findings.push(Finding {
        id: second_finding_id.clone(),
        case_id: case.id.clone(),
        first_seen_run_id: run_id.clone(),
        last_seen_run_id: run_id.clone(),
        fingerprint: "demo:web:missing-hsts".into(),
        title: "公開網站的 HSTS 狀態尚未完成確認".into(),
        plain_language_summary: "合成展示掃描因部分目標逾時，尚無法確認瀏覽器強制使用 HTTPS 的 HSTS 狀態。".into(),
        possible_impact: "目前證據不足以判定風險；若後續確認未啟用 HSTS，首次連線在特定情境下可能被降級或攔截。".into(),
        severity: Severity::Informational,
        confidence: Confidence::Medium,
        priority: 58,
        priority_reasons: vec!["公開服務".into(), "掃描僅部分完成".into()],
        asset_ids: vec![domain_id],
        evidence: vec![Evidence {
            id: new_id(),
            finding_id: second_finding_id.clone(),
            run_id: run_id.clone(),
            engine_run_id: Some(httpx_run_id),
            kind: EvidenceKind::Observation,
            engine_id: "httpx".into(),
            source_rule: None,
            result_pointer_sha256: None,
            observed_at: now - Duration::days(2),
            summary: "Synthetic timeout record proving the check was incomplete, not that HSTS was absent.".into(),
            artifact_id: timeout_artifact_id,
            artifact_sha256: artifact_hash(timeout_content),
            pointer: Some("/status".into()),
            redacted: false,
        }],
        control_references: vec![ControlReference {
            framework: "NIST CSF".into(),
            framework_version: "2.0".into(),
            control_id: "PR.DS-02".into(),
            title: "Data-in-transit protection".into(),
            relationship: "related".into(),
            rationale: "Coordinate only; no compliance determination is made.".into(),
            mapping_version: "demo-0.1".into(),
            mapping_provenance: None,
        }],
        recommendation: "請網站或平台工程師確認反向代理與 CDN 的 TLS/HSTS 設定。".into(),
        verification_guidance: "調整後重新執行低干擾 HTTP 標頭檢查。".into(),
        rollback_considerations: None,
        official_references: vec![
            "https://developer.mozilla.org/docs/Web/HTTP/Headers/Strict-Transport-Security".into(),
        ],
        recommended_expert_type: "Web 平台／TLS 專家".into(),
        status: FindingStatus::Unreviewed,
        tags: vec!["synthetic-demo".into(), "tls".into()],
    });

    let group_id = new_id();
    let group_title = "對外資料傳輸面向需要一起檢視".to_owned();
    let group_rationale = "兩項合成觀察都涉及公開服務與資料保護；群組只供人工交接，不會合併 finding、fingerprint 或證據。".to_owned();
    let group_actor = "Synthetic demo builder".to_owned();
    let group_created_at = now - Duration::days(1);
    let grouped_finding_ids = vec![finding_id.clone(), second_finding_id.clone()];
    case.finding_groups.push(FindingGroup {
        id: group_id.clone(),
        case_id: case.id.clone(),
        title: group_title.clone(),
        finding_ids: grouped_finding_ids.clone(),
        rationale: group_rationale.clone(),
        grouped_by: group_actor.clone(),
        created_at: group_created_at,
    });
    case.finding_group_events.push(FindingGroupEvent {
        id: new_id(),
        case_id: case.id.clone(),
        group_id,
        action: FindingGroupAction::Created,
        title: group_title,
        finding_ids: grouped_finding_ids,
        rationale: group_rationale,
        actor: group_actor,
        occurred_at: group_created_at,
    });

    case.finding_observations = case
        .findings
        .iter()
        .map(|finding| FindingObservation {
            id: new_id(),
            run_id: run_id.clone(),
            finding_id: finding.id.clone(),
            fingerprint: finding.fingerprint.clone(),
            asset_ids: finding.asset_ids.clone(),
            engine_ids: finding
                .evidence
                .iter()
                .map(|evidence| evidence.engine_id.clone())
                .collect(),
            severity: finding.severity.clone(),
            confidence: finding.confidence.clone(),
            evidence_hashes: finding
                .evidence
                .iter()
                .map(|evidence| evidence.artifact_sha256.clone())
                .collect(),
            observed_at: now - Duration::days(2),
            finding_snapshot: Some(finding.clone()),
        })
        .collect();

    case.touch();
    case
}
