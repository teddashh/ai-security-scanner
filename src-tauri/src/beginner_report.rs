//! Beginner-facing, run-specific report projection.
//!
//! This module deliberately derives one report from durable case state. It is
//! not another persisted lifecycle or coverage state machine. When an older
//! run did not freeze a requested or executed dimension, the report says so
//! instead of reconstructing it from mutable case state.

use crate::domain::{
    AssessmentCase, AssetKind, Confidence, ControlMappingProvenance, DistributionMode, EngineRun,
    EngineRunStatus, EngineTaskKind, Finding, FindingObservation, Id, LocalhostTcpObservation,
    LocalhostTcpOutcome, ScanRequestOutcome, ScanRequestOutcomeCode, ScanRun, Severity,
};
use crate::execution_coverage::{
    CumulativeNaabuCoverage, WorkUnitOutcome, reduce_naabu_attempt_coverage,
};
use crate::naabu_work_plan::{NAABU_ENGINE_ID, NaabuWorkStage};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};
use std::fmt;
use std::net::IpAddr;

pub const BEGINNER_MASTER_REPORT_SCHEMA_VERSION: &str = "1.1.0";

pub const FRAMEWORK_NON_CERTIFICATION_NOTICE: &str = "These references do not establish certification, compliance, control implementation, control effectiveness, endorsement, or a pass/fail result.";

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct BeginnerMasterReport {
    pub schema_version: String,
    pub case_id: Id,
    pub run_id: Id,
    pub project_title: String,
    pub state: BeginnerReportState,
    pub requested: RequestedCoverage,
    pub actual: ActualCoverage,
    pub coverage_gaps: Vec<CoverageGap>,
    pub coverage_counts: CoverageCounts,
    pub findings: Vec<BeginnerFinding>,
    #[serde(default)]
    pub finding_groups: Vec<BeginnerFindingGroup>,
    pub next_steps: Vec<BeginnerNextStep>,
    pub technical_details: TechnicalDetails,
    pub framework_notice: FrameworkNotice,
    pub data_quality_warnings: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct BeginnerFindingGroup {
    pub group_id: Id,
    pub presentation_scope: FindingGroupPresentationScope,
    pub title: String,
    pub rationale: String,
    pub actor: String,
    pub created_at: DateTime<Utc>,
    pub members: Vec<BeginnerFindingGroupMember>,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum FindingGroupPresentationScope {
    CurrentCasePresentation,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct BeginnerFindingGroupMember {
    pub finding_id: Id,
    pub observed_in_selected_run: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct BeginnerReportState {
    pub summary: BeginnerReportSummary,
    pub lifecycle: ReportLifecycle,
    pub last_durable_update: DateTime<Utc>,
    pub explanation: String,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum BeginnerReportSummary {
    Complete,
    Partial,
    NoChecksCompleted,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum ReportLifecycle {
    Live,
    Final,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct RequestedCoverage {
    pub targets: Vec<RequestedTarget>,
    pub stage: RecordedStage,
    pub limits: Vec<RequestedLimit>,
    pub requested_check_ids: Vec<String>,
    pub request_outcome_code: Option<ScanRequestOutcomeCode>,
    pub automatic_reductions: Vec<CoverageReduction>,
    pub reductions_availability: DataAvailability,
    pub unavailable_dimensions: Vec<UnavailableDimension>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct CoverageReduction {
    pub dimension: String,
    pub requested: String,
    pub executed: String,
    pub reason: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct RequestedTarget {
    pub asset_id: Id,
    pub label: Option<String>,
    pub asset_kind: Option<AssetKind>,
    pub label_availability: DataAvailability,
    pub asset_kind_availability: DataAvailability,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct RecordedStage {
    pub value: Option<ReportScanStage>,
    pub availability: DataAvailability,
    pub explanation: String,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum ReportScanStage {
    QuickDiscovery,
    Inventory,
    Deep,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum DataAvailability {
    Recorded,
    CurrentCaseFallback,
    Unavailable,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct RequestedLimit {
    pub name: String,
    pub value: String,
    pub source: RequestedLimitSource,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum RequestedLimitSource {
    FrozenTaskContract,
    FrozenScopeGrant,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct UnavailableDimension {
    pub dimension: String,
    pub explanation: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ActualCoverage {
    pub observed_from: Option<DateTime<Utc>>,
    pub observed_until: Option<DateTime<Utc>>,
    pub checks: Vec<ActualCheck>,
    /// Exact, run-frozen network rectangles and their validated outcome. This
    /// keeps a beginner report honest about which addresses and ports were or
    /// were not tested instead of reducing scope truth to only "N of total".
    #[serde(default)]
    pub network_scopes: Vec<NetworkScopeCoverage>,
    pub unavailable_dimensions: Vec<UnavailableDimension>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct NetworkScopeCoverage {
    pub task_id: Id,
    pub check_id: String,
    pub work_unit_id: String,
    pub target_asset_id: Id,
    pub target: String,
    pub address_ranges: Vec<String>,
    pub port_ranges: Vec<String>,
    pub transport: String,
    pub stage: ReportScanStage,
    pub outcome: WorkUnitOutcome,
    pub observed_at: Option<DateTime<Utc>>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ActualCheck {
    pub task_id: Id,
    pub check_id: String,
    pub target_asset_ids: Vec<Id>,
    pub status: CoverageDimensionStatus,
    pub started_at: Option<DateTime<Utc>>,
    pub finished_at: Option<DateTime<Utc>>,
    pub tested_dimensions: Vec<TestedDimension>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct TestedDimension {
    pub dimension: String,
    pub value: String,
    pub observation: String,
    pub observed_at: Option<DateTime<Utc>>,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum CoverageDimensionStatus {
    TestedComplete,
    TestedPartial,
    Failed,
    TimedOut,
    Cancelled,
    NotTested,
    InProgress,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct CoverageGap {
    pub kind: CoverageGapKind,
    pub task_id: Option<Id>,
    pub target_asset_ids: Vec<Id>,
    pub dimension: String,
    pub reason: String,
    pub next_action_code: NextActionCode,
    pub next_action: String,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum CoverageGapKind {
    NotTested,
    Failed,
    TimedOut,
    Cancelled,
    Excluded,
    Truncated,
    Unavailable,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct CoverageCounts {
    pub tested_complete: usize,
    pub tested_partial: usize,
    pub failed: usize,
    pub timed_out: usize,
    pub cancelled: usize,
    pub not_tested: usize,
    pub excluded: usize,
    pub truncated: usize,
    pub unavailable: usize,
}

/// Stable UI/export semantic. English prose beside this value is display
/// copy, never the only meaning a localized client has to parse.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
#[serde(rename_all = "snake_case")]
pub enum NextActionCode {
    ReviewFinding,
    RetryCheck,
    ReviewScopeAndRetry,
    ChooseCompatibleCheck,
    WaitOrCancel,
    StartExpectedServiceAndRetry,
    ReviewCoverage,
    PreserveVisibleLimitation,
    NoActionUnlessScopeChanges,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct BeginnerFinding {
    pub finding_id: Id,
    pub fingerprint: String,
    pub snapshot_source: FindingSnapshotSource,
    pub title: String,
    pub plain_language_risk: String,
    pub possible_impact: String,
    pub severity: Severity,
    pub confidence: Confidence,
    pub priority: Option<u8>,
    pub priority_reasons: Vec<String>,
    pub target_asset_ids: Vec<Id>,
    pub next_step: String,
    pub recommended_expert_type: String,
    pub evidence_references: Vec<FindingEvidenceReference>,
    pub framework_references: Vec<FrameworkReference>,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum FindingSnapshotSource {
    FrozenSelectedRun,
    CurrentCanonicalLegacyFallback,
    ObservationOnly,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct FindingEvidenceReference {
    pub evidence_id: Id,
    pub engine_id: String,
    pub artifact_sha256: String,
    pub observed_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct FrameworkReference {
    pub framework: String,
    pub framework_version: String,
    pub control_id: String,
    pub title: String,
    pub relationship: String,
    pub rationale: String,
    pub mapping_version: String,
    pub mapping_provenance: Option<ControlMappingProvenance>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct FrameworkNotice {
    pub non_certification: String,
    pub aidefend_mapping_status: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct BeginnerNextStep {
    pub priority: u16,
    pub code: NextActionCode,
    pub action: String,
    pub reason: String,
    pub finding_id: Option<Id>,
    pub task_id: Option<Id>,
    pub recommended_expert_type: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct TechnicalDetails {
    pub collapsed_by_default: bool,
    pub tasks: Vec<TechnicalTaskDetails>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct TechnicalTaskDetails {
    pub task_id: Id,
    pub target_asset_ids: Vec<Id>,
    pub status: EngineRunStatus,
    pub phase: String,
    pub progress_percent: u8,
    pub started_at: Option<DateTime<Utc>>,
    pub finished_at: Option<DateTime<Utc>>,
    pub exit_code: Option<i32>,
    pub cleanup_removed: Option<bool>,
    pub cleanup_detail: UnavailableTechnicalValue,
    pub error_code: Option<String>,
    pub redacted_scanner_message: UnavailableTechnicalValue,
    pub redacted_diagnostic_log: UnavailableTechnicalValue,
    pub evidence_sha256: Vec<String>,
    pub execution: TechnicalExecution,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum TechnicalExecution {
    CatalogEngine {
        engine_id: String,
        engine_version: Option<String>,
        image_digest: Option<String>,
        command_sha256: Option<String>,
        runtime_provider: Option<String>,
        runtime_version: Option<String>,
        runtime_security_options: Option<String>,
        distribution_mode: Option<DistributionMode>,
        image_repository: Option<String>,
        adapter_version: String,
        rule_version: Option<String>,
    },
    BuiltInLocalhostTcp {
        endpoint: String,
        timeout_ms: u64,
        payload_bytes: u64,
        observation: Option<LocalhostTcpObservation>,
        contract: String,
    },
    InvalidBuiltInTask {
        explanation: String,
    },
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct UnavailableTechnicalValue {
    pub availability: DataAvailability,
    pub value: Option<String>,
    pub explanation: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BeginnerReportError {
    RunNotFound { run_id: Id },
}

impl fmt::Display for BeginnerReportError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::RunNotFound { run_id } => {
                write!(formatter, "scan run {run_id} was not found in this project")
            }
        }
    }
}

impl std::error::Error for BeginnerReportError {}

/// Build the single beginner report for a selected durable scan run.
///
/// The builder performs no I/O, loads no mapping catalog, and never mutates the
/// case. Consequently a missing or damaged mapping source cannot suppress a
/// finding or prevent report construction.
pub fn build_beginner_master_report(
    case: &AssessmentCase,
    run_id: &str,
) -> Result<BeginnerMasterReport, BeginnerReportError> {
    let run = case
        .scan_runs
        .iter()
        .find(|run| run.id == run_id)
        .ok_or_else(|| BeginnerReportError::RunNotFound {
            run_id: run_id.to_owned(),
        })?;

    let contradictory_request_outcome =
        run.request_outcome.is_some() && !run.is_terminal_no_checks();
    let mut data_quality_warnings = Vec::new();
    if contradictory_request_outcome {
        data_quality_warnings.push(
            "This run contains a request-level outcome beside non-terminal or planned check data. The report ignored that outcome and did not treat it as ‘no checks completed’."
                .into(),
        );
    }
    if run.case_id != case.id {
        data_quality_warnings.push(
            "The selected run's stored project identifier does not match this project. The report remains limited to the selected in-project record."
                .into(),
        );
    }
    if run.completed_at.is_some() && run.engine_runs.iter().any(task_is_active) {
        data_quality_warnings.push(
            "This run has a saved completion time while at least one check is still active. The report follows the check state and remains live instead of presenting a final result."
                .into(),
        );
    }

    let requested = project_requested_coverage(case, run, !contradictory_request_outcome);
    let actual_projection = project_actual_coverage(run);
    let actual = actual_projection.actual;
    let mut coverage_gaps = actual_projection.gaps;
    data_quality_warnings.extend(actual_projection.data_quality_warnings);
    append_request_outcome_gaps(run, !contradictory_request_outcome, &mut coverage_gaps);
    append_engine_admission_gaps(run, &mut coverage_gaps);
    append_case_exclusions(case, run, &mut coverage_gaps);

    for unavailable in requested
        .unavailable_dimensions
        .iter()
        .chain(actual.unavailable_dimensions.iter())
    {
        coverage_gaps.push(CoverageGap {
            kind: CoverageGapKind::Unavailable,
            task_id: None,
            target_asset_ids: requested
                .targets
                .iter()
                .map(|target| target.asset_id.clone())
                .collect(),
            dimension: unavailable.dimension.clone(),
            reason: unavailable.explanation.clone(),
            next_action_code: NextActionCode::PreserveVisibleLimitation,
            next_action: "Keep this limitation visible; do not interpret missing historical detail as completed coverage."
                .into(),
        });
    }
    if contradictory_request_outcome {
        coverage_gaps.push(CoverageGap {
            kind: CoverageGapKind::Unavailable,
            task_id: None,
            target_asset_ids: requested
                .targets
                .iter()
                .map(|target| target.asset_id.clone())
                .collect(),
            dimension: "request outcome integrity".into(),
            reason: "The request-level outcome contradicts the run's durable task state and was ignored."
                .into(),
            next_action_code: NextActionCode::RetryCheck,
            next_action: "Keep the saved results, then retry this scan if you need an internally consistent coverage record."
                .into(),
        });
    }

    let (findings, finding_warnings) = project_findings(case, run);
    let finding_groups = project_finding_groups(case, &findings);
    data_quality_warnings.extend(finding_warnings);
    if findings
        .iter()
        .any(|finding| finding.snapshot_source != FindingSnapshotSource::FrozenSelectedRun)
    {
        coverage_gaps.push(CoverageGap {
            kind: CoverageGapKind::Unavailable,
            task_id: None,
            target_asset_ids: Vec::new(),
            dimension: "selected-run finding presentation snapshot".into(),
            reason: "At least one legacy finding observation did not retain its full run-specific presentation snapshot."
                .into(),
            next_action_code: NextActionCode::PreserveVisibleLimitation,
            next_action: "Use the retained severity, confidence, and evidence for review; rerun to create a fully frozen report."
                .into(),
        });
    }

    coverage_gaps.sort_by(|left, right| {
        gap_rank(left.kind)
            .cmp(&gap_rank(right.kind))
            .then_with(|| left.task_id.cmp(&right.task_id))
            .then_with(|| left.dimension.cmp(&right.dimension))
    });
    coverage_gaps.dedup();

    let lifecycle = if run_is_authoritatively_final(run) {
        ReportLifecycle::Final
    } else {
        ReportLifecycle::Live
    };
    let has_useful_tested_outcome =
        !findings.is_empty() || !actual_projection.useful_task_ids.is_empty();
    let summary = if lifecycle == ReportLifecycle::Final
        && ((run.is_terminal_no_checks() && !contradictory_request_outcome)
            || !has_useful_tested_outcome)
    {
        BeginnerReportSummary::NoChecksCompleted
    } else if lifecycle == ReportLifecycle::Final
        && !run.engine_runs.is_empty()
        && run
            .engine_runs
            .iter()
            .all(|task| actual_projection.exact_complete_task_ids.contains(&task.id))
        && coverage_gaps.is_empty()
    {
        BeginnerReportSummary::Complete
    } else {
        BeginnerReportSummary::Partial
    };
    let state = BeginnerReportState {
        summary,
        lifecycle,
        last_durable_update: selected_run_last_durable_update(case, run),
        explanation: state_explanation(summary, lifecycle).into(),
    };
    let next_steps = project_next_steps(&state, &findings, &coverage_gaps, &actual);
    let technical_details = project_technical_details(case, run);
    let coverage_counts = coverage_counts(&actual, &coverage_gaps);

    Ok(BeginnerMasterReport {
        schema_version: BEGINNER_MASTER_REPORT_SCHEMA_VERSION.into(),
        case_id: case.id.clone(),
        run_id: run.id.clone(),
        project_title: case.title.clone(),
        state,
        requested,
        actual,
        coverage_gaps,
        coverage_counts,
        findings,
        finding_groups,
        next_steps,
        technical_details,
        framework_notice: FrameworkNotice {
            non_certification: FRAMEWORK_NON_CERTIFICATION_NOTICE.into(),
            aidefend_mapping_status: "AIDEFEND references are an independent, unofficial mapping unless the framework owner states otherwise."
                .into(),
        },
        data_quality_warnings,
    })
}

fn project_requested_coverage(
    case: &AssessmentCase,
    run: &ScanRun,
    use_request_outcome: bool,
) -> RequestedCoverage {
    let mut target_ids = BTreeSet::new();
    let mut requested_check_ids = BTreeSet::new();
    let mut request_outcome_code = None;

    if use_request_outcome && run.is_terminal_no_checks() {
        if let Some(ScanRequestOutcome::NoChecksCompleted {
            code,
            requested_asset_ids,
            requested_engine_ids,
            ..
        }) = run.request_outcome.as_ref()
        {
            request_outcome_code = Some(*code);
            target_ids.extend(requested_asset_ids.iter().cloned());
            requested_check_ids.extend(requested_engine_ids.iter().cloned());
        }
    } else {
        target_ids.extend(
            run.scope_grant_snapshots
                .iter()
                .map(|grant| grant.asset_id.clone()),
        );
        for task in &run.engine_runs {
            target_ids.extend(task.asset_ids.iter().cloned());
            requested_check_ids.insert(check_id(task));
        }
    }

    let targets = target_ids
        .into_iter()
        .map(|asset_id| project_requested_target(case, run, asset_id))
        .collect::<Vec<_>>();

    let exact_localhost_only = !run.engine_runs.is_empty()
        && run.engine_runs.iter().all(|task| {
            matches!(task.task_kind, EngineTaskKind::BuiltInLocalhostTcp { .. })
                && task.task_kind.is_exact_built_in_localhost_tcp_contract()
        });
    let naabu_tasks = run
        .engine_runs
        .iter()
        .filter(|task| {
            task.engine_id == NAABU_ENGINE_ID
                && matches!(task.task_kind, EngineTaskKind::CatalogEngine)
        })
        .collect::<Vec<_>>();
    let valid_naabu_plans = naabu_tasks
        .iter()
        .filter_map(|task| task.naabu_work_plan.as_ref())
        .filter(|plan| plan.validate().is_ok())
        .collect::<Vec<_>>();
    let all_naabu_plans_valid =
        !naabu_tasks.is_empty() && valid_naabu_plans.len() == naabu_tasks.len();
    let stage = if exact_localhost_only {
        RecordedStage {
            value: Some(ReportScanStage::QuickDiscovery),
            availability: DataAvailability::Recorded,
            explanation:
                "The frozen native localhost task is a quick reachability discovery check.".into(),
        }
    } else if !valid_naabu_plans.is_empty() {
        let includes_inventory = valid_naabu_plans
            .iter()
            .flat_map(|plan| &plan.work_units)
            .any(|unit| unit.stage == NaabuWorkStage::FullInventory);
        RecordedStage {
            value: Some(if includes_inventory {
                ReportScanStage::Inventory
            } else {
                ReportScanStage::QuickDiscovery
            }),
            availability: if all_naabu_plans_valid {
                DataAvailability::Recorded
            } else {
                DataAvailability::Unavailable
            },
            explanation: if !all_naabu_plans_valid {
                if includes_inventory {
                    "At least one readable frozen network plan includes full inventory, but another network check has no valid saved plan. Inventory is the highest known stage, not a complete run-wide record."
                        .into()
                } else {
                    "Readable frozen network plans contain quick discovery only, but another network check has no valid saved plan. Quick discovery is the highest known stage, not a complete run-wide record."
                        .into()
                }
            } else if includes_inventory {
                "The frozen network plan includes quick discovery followed by the full approved port inventory."
                    .into()
            } else {
                "The frozen network plan contains quick discovery work only.".into()
            },
        }
    } else {
        RecordedStage {
            value: None,
            availability: DataAvailability::Unavailable,
            explanation: "This run did not freeze a quick-discovery, inventory, or deep-stage selection. The report does not infer one from engine names or current project settings."
                .into(),
        }
    };

    let mut limits = Vec::new();
    for task in &run.engine_runs {
        match task.task_kind {
            EngineTaskKind::BuiltInLocalhostTcp {
                port,
                timeout_ms,
                payload_bytes,
            } if task.task_kind.is_exact_built_in_localhost_tcp_contract() => {
                limits.push(RequestedLimit {
                    name: "endpoint".into(),
                    value: format!("127.0.0.1:{port}"),
                    source: RequestedLimitSource::FrozenTaskContract,
                });
                limits.push(RequestedLimit {
                    name: "connection timeout".into(),
                    value: format!("{timeout_ms} ms"),
                    source: RequestedLimitSource::FrozenTaskContract,
                });
                limits.push(RequestedLimit {
                    name: "application payload".into(),
                    value: format!("{payload_bytes} bytes"),
                    source: RequestedLimitSource::FrozenTaskContract,
                });
            }
            EngineTaskKind::CatalogEngine => {
                if let Some(seconds) = task.execution_timeout_seconds {
                    limits.push(RequestedLimit {
                        name: format!("{} execution timeout", task.engine_id),
                        value: format!("{seconds} seconds"),
                        source: RequestedLimitSource::FrozenTaskContract,
                    });
                }
            }
            EngineTaskKind::BuiltInLocalhostTcp { .. } => {}
        }
    }
    for grant in &run.scope_grant_snapshots {
        let Some(external) = grant.external_scope.as_ref() else {
            continue;
        };
        limits.extend([
            RequestedLimit {
                name: format!("{} authorized network target", grant.asset_id),
                value: external.target.canonical_text(),
                source: RequestedLimitSource::FrozenScopeGrant,
            },
            RequestedLimit {
                name: format!("{} approved ports", grant.asset_id),
                value: external
                    .ports
                    .iter()
                    .map(u16::to_string)
                    .collect::<Vec<_>>()
                    .join(","),
                source: RequestedLimitSource::FrozenScopeGrant,
            },
            RequestedLimit {
                name: format!("{} request rate", grant.asset_id),
                value: format!(
                    "{} per second, concurrency {}",
                    external.rate_policy.requests_per_second, external.rate_policy.concurrency
                ),
                source: RequestedLimitSource::FrozenScopeGrant,
            },
            RequestedLimit {
                name: format!("{} network timeout", grant.asset_id),
                value: format!("{} seconds", external.rate_policy.timeout_seconds),
                source: RequestedLimitSource::FrozenScopeGrant,
            },
        ]);
    }
    limits.sort_by(|left, right| {
        left.name
            .cmp(&right.name)
            .then_with(|| left.value.cmp(&right.value))
    });
    limits.dedup();

    let mut unavailable_dimensions = Vec::new();
    if stage.availability == DataAvailability::Unavailable {
        unavailable_dimensions.push(UnavailableDimension {
            dimension: "requested scan stage".into(),
            explanation: stage.explanation.clone(),
        });
    }
    if limits.is_empty() && !run.is_terminal_no_checks() {
        unavailable_dimensions.push(UnavailableDimension {
            dimension: "requested limits".into(),
            explanation: "No exact per-run limits were retained. Current project settings are not substituted for historical requested limits."
                .into(),
        });
    }
    let reductions_availability = if exact_localhost_only || all_naabu_plans_valid {
        DataAvailability::Recorded
    } else {
        unavailable_dimensions.push(UnavailableDimension {
            dimension: "automatic scope reductions or truncations".into(),
            explanation: "This run did not retain an exact reduction record. An empty list therefore cannot be interpreted as proof that no requested dimension was reduced."
                .into(),
        });
        DataAvailability::Unavailable
    };
    if targets.iter().any(|target| {
        target.label_availability != DataAvailability::Recorded
            || target.asset_kind_availability != DataAvailability::Recorded
    }) {
        unavailable_dimensions.push(UnavailableDimension {
            dimension: "run-frozen target label or type".into(),
            explanation: "At least one target identifier is frozen with the run, but its displayed label or type comes from current project data or is unavailable. The report labels that provenance and does not call it historical fact."
                .into(),
        });
    }

    RequestedCoverage {
        targets,
        stage,
        limits,
        requested_check_ids: requested_check_ids.into_iter().collect(),
        request_outcome_code,
        automatic_reductions: Vec::new(),
        reductions_availability,
        unavailable_dimensions,
    }
}

fn project_requested_target(case: &AssessmentCase, run: &ScanRun, asset_id: Id) -> RequestedTarget {
    if let Some(port) = run
        .engine_runs
        .iter()
        .find_map(|task| match task.task_kind {
            EngineTaskKind::BuiltInLocalhostTcp { port, .. }
                if task.task_kind.is_exact_built_in_localhost_tcp_contract()
                    && task.asset_ids.len() == 1
                    && task.asset_ids[0] == asset_id =>
            {
                Some(port)
            }
            _ => None,
        })
    {
        return RequestedTarget {
            asset_id,
            label: Some(format!("127.0.0.1:{port}")),
            asset_kind: Some(AssetKind::WebService),
            label_availability: DataAvailability::Recorded,
            asset_kind_availability: DataAvailability::Recorded,
        };
    }

    if let Some(external) = run
        .scope_grant_snapshots
        .iter()
        .find(|grant| grant.asset_id == asset_id)
        .and_then(|grant| grant.external_scope.as_ref())
    {
        let frozen_kind = match &external.target {
            crate::external_scope::CanonicalTarget::Hostname(_) => AssetKind::Domain,
            crate::external_scope::CanonicalTarget::Address(_)
            | crate::external_scope::CanonicalTarget::Network(_) => AssetKind::IpAddress,
        };
        return RequestedTarget {
            asset_id,
            label: Some(external.target.canonical_text()),
            asset_kind: Some(frozen_kind),
            label_availability: DataAvailability::Recorded,
            asset_kind_availability: DataAvailability::Recorded,
        };
    }

    let current_asset = case.assets.iter().find(|asset| asset.id == asset_id);
    RequestedTarget {
        asset_id,
        label: current_asset.map(|asset| asset.name.clone()),
        asset_kind: current_asset.map(|asset| asset.kind.clone()),
        label_availability: if current_asset.is_some() {
            DataAvailability::CurrentCaseFallback
        } else {
            DataAvailability::Unavailable
        },
        asset_kind_availability: if current_asset.is_some() {
            DataAvailability::CurrentCaseFallback
        } else {
            DataAvailability::Unavailable
        },
    }
}

struct ActualCoverageProjection {
    actual: ActualCoverage,
    gaps: Vec<CoverageGap>,
    data_quality_warnings: Vec<String>,
    useful_task_ids: BTreeSet<Id>,
    exact_complete_task_ids: BTreeSet<Id>,
}

fn project_actual_coverage(run: &ScanRun) -> ActualCoverageProjection {
    let mut checks = Vec::new();
    let mut network_scopes = Vec::new();
    let mut gaps = Vec::new();
    let mut unavailable_dimensions = Vec::new();
    let mut observed_times = Vec::new();
    let mut data_quality_warnings = Vec::new();
    let mut useful_task_ids = BTreeSet::new();
    let mut exact_complete_task_ids = BTreeSet::new();

    for task in &run.engine_runs {
        observed_times.extend(task.started_at);
        observed_times.extend(task.finished_at);
        if let Some(observation) = task.localhost_tcp_observation.as_ref() {
            observed_times.push(observation.observed_at);
        }

        let mut tested_dimensions = Vec::new();
        let mut status = actual_status(task);
        let mut task_gap_already_projected = false;
        let mut exact_complete = false;
        let mut useful_result = false;
        match task.task_kind {
            EngineTaskKind::BuiltInLocalhostTcp {
                port,
                timeout_ms,
                payload_bytes,
            } if task.task_kind.is_exact_built_in_localhost_tcp_contract() => {
                if let Some(observation) = task.localhost_tcp_observation.as_ref() {
                    tested_dimensions.push(TestedDimension {
                        dimension: "TCP reachability".into(),
                        value: format!("127.0.0.1:{port}"),
                        observation: localhost_observation_text(&observation.outcome).into(),
                        observed_at: Some(observation.observed_at),
                    });
                    tested_dimensions.push(TestedDimension {
                        dimension: "bounded connection contract".into(),
                        value: format!(
                            "one connection attempt; {timeout_ms} ms timeout; {payload_bytes} application-payload bytes"
                        ),
                        observation: "The native task only observed whether the endpoint accepted, refused, or timed out during the bounded connection attempt. It did not perform a vulnerability test."
                            .into(),
                        observed_at: Some(observation.observed_at),
                    });
                    useful_result = true;
                }
                exact_complete = exactly_completed_without_known_gap(task);
            }
            EngineTaskKind::CatalogEngine
                if task.engine_id == NAABU_ENGINE_ID
                    && (task.naabu_work_plan.is_some()
                        || !task.naabu_attempt_requests.is_empty()
                        || !task.naabu_attempt_results.is_empty()) =>
            {
                let reduced = task.naabu_work_plan.as_ref().map_or_else(
                    || Err("saved work plan is missing"),
                    |plan| {
                        reduce_naabu_attempt_coverage(
                            plan,
                            &task.naabu_attempt_requests,
                            &task.naabu_attempt_results,
                        )
                        .map_err(|_| "saved work-unit history is inconsistent")
                    },
                );
                match reduced {
                    Ok(coverage) => {
                        status = naabu_coverage_status(task, &coverage);
                        append_naabu_tested_dimensions(task, &coverage, &mut tested_dimensions);
                        append_naabu_coverage_gaps(task, &coverage, &mut gaps);
                        network_scopes.extend(project_naabu_network_scopes(task, &coverage));
                        useful_result = coverage.summary.has_usable_results;
                        exact_complete =
                            task.status == EngineRunStatus::Completed && coverage.fully_complete;
                        task_gap_already_projected = true;
                    }
                    Err(_) => {
                        status = untrusted_naabu_history_status(task);
                        let explanation = "The saved work-unit coverage for this check is internally inconsistent. The report did not guess which planned units were tested.";
                        gaps.push(CoverageGap {
                            kind: CoverageGapKind::Unavailable,
                            task_id: Some(task.id.clone()),
                            target_asset_ids: task.asset_ids.clone(),
                            dimension: format!("{} saved work-unit coverage", check_id(task)),
                            reason: explanation.into(),
                            next_action_code: NextActionCode::RetryCheck,
                            next_action: "Keep the saved evidence and other results. Retry this check to create a new consistent coverage record."
                                .into(),
                        });
                        data_quality_warnings.push(
                            "One check's saved coverage history could not be reconciled. Retained findings and evidence remain available, but that check is not counted complete."
                                .into(),
                        );
                        task_gap_already_projected = true;
                    }
                }
            }
            EngineTaskKind::CatalogEngine if task.status == EngineRunStatus::Completed => {
                for asset_id in &task.asset_ids {
                    tested_dimensions.push(TestedDimension {
                        dimension: "completed check-to-target coordinate".into(),
                        value: format!("{} on asset {asset_id}", task.engine_id),
                        observation: "The durable task reached completed state for this target binding. More granular executed dimensions were not frozen in this case record."
                            .into(),
                        observed_at: task.finished_at,
                    });
                }
                unavailable_dimensions.push(UnavailableDimension {
                    dimension: format!("{} granular executed scope", task.engine_id),
                    explanation: "The run records the completed engine/asset coordinate but not exact observed hosts, services, ports, paths, files, branches, accounts, or resources."
                        .into(),
                });
                useful_result = !tested_dimensions.is_empty();
                exact_complete = exactly_completed_without_known_gap(task);
            }
            EngineTaskKind::CatalogEngine => {
                // Older adapters did not freeze granular executed dimensions.
                // Their durable PartiallyCompleted state remains the only
                // available coarse proof that some usable result arrived.
                useful_result = status == CoverageDimensionStatus::TestedPartial;
            }
            EngineTaskKind::BuiltInLocalhostTcp { .. } => {}
        }

        if status == CoverageDimensionStatus::TestedComplete && tested_dimensions.is_empty() {
            status = CoverageDimensionStatus::NotTested;
        }
        if status == CoverageDimensionStatus::TestedComplete
            && task.finished_at.is_none()
            && task.localhost_tcp_observation.is_none()
        {
            unavailable_dimensions.push(UnavailableDimension {
                dimension: format!("{} completed-check time", check_id(task)),
                explanation: "The task says completed but has neither a finish time nor a bounded native observation time. The report does not invent when it was tested."
                    .into(),
            });
        }

        if !task_gap_already_projected {
            append_task_gap(task, status, &mut gaps);
        }
        if useful_result {
            useful_task_ids.insert(task.id.clone());
        }
        if exact_complete {
            exact_complete_task_ids.insert(task.id.clone());
        }
        checks.push(ActualCheck {
            task_id: task.id.clone(),
            check_id: check_id(task),
            target_asset_ids: task.asset_ids.clone(),
            status,
            started_at: task.started_at,
            finished_at: task.finished_at,
            tested_dimensions,
        });
    }

    checks.sort_by(|left, right| left.task_id.cmp(&right.task_id));
    network_scopes.sort_by(|left, right| {
        left.task_id
            .cmp(&right.task_id)
            .then_with(|| left.work_unit_id.cmp(&right.work_unit_id))
    });
    unavailable_dimensions.sort_by(|left, right| left.dimension.cmp(&right.dimension));
    unavailable_dimensions.dedup();
    observed_times.sort();
    let observed_from = observed_times.first().copied();
    let observed_until = observed_times.last().copied();
    ActualCoverageProjection {
        actual: ActualCoverage {
            observed_from,
            observed_until,
            checks,
            network_scopes,
            unavailable_dimensions,
        },
        gaps,
        data_quality_warnings,
        useful_task_ids,
        exact_complete_task_ids,
    }
}

fn naabu_coverage_status(
    task: &EngineRun,
    coverage: &CumulativeNaabuCoverage,
) -> CoverageDimensionStatus {
    if task.status == EngineRunStatus::Completed && coverage.fully_complete {
        return CoverageDimensionStatus::TestedComplete;
    }
    if coverage.summary.has_usable_results {
        return CoverageDimensionStatus::TestedPartial;
    }
    if task_is_active(task) {
        return CoverageDimensionStatus::InProgress;
    }
    if coverage.summary.failed > 0 || task.status == EngineRunStatus::Failed {
        return CoverageDimensionStatus::Failed;
    }
    if coverage.summary.timed_out > 0 || stable_timeout_marker(task) {
        return CoverageDimensionStatus::TimedOut;
    }
    if coverage.summary.cancelled > 0 || task.status == EngineRunStatus::Cancelled {
        return CoverageDimensionStatus::Cancelled;
    }
    CoverageDimensionStatus::NotTested
}

fn untrusted_naabu_history_status(task: &EngineRun) -> CoverageDimensionStatus {
    if task_is_active(task) {
        return CoverageDimensionStatus::InProgress;
    }
    if stable_timeout_marker(task) {
        return CoverageDimensionStatus::TimedOut;
    }
    match task.status {
        EngineRunStatus::Failed => CoverageDimensionStatus::Failed,
        EngineRunStatus::Cancelled => CoverageDimensionStatus::Cancelled,
        EngineRunStatus::NotExecuted
        | EngineRunStatus::Completed
        | EngineRunStatus::PartiallyCompleted => CoverageDimensionStatus::NotTested,
        EngineRunStatus::Queued
        | EngineRunStatus::Preparing
        | EngineRunStatus::Running
        | EngineRunStatus::Paused => CoverageDimensionStatus::InProgress,
    }
}

fn append_naabu_tested_dimensions(
    task: &EngineRun,
    coverage: &CumulativeNaabuCoverage,
    tested_dimensions: &mut Vec<TestedDimension>,
) {
    let total = coverage.summary.requested;
    if coverage.summary.tested_complete > 0 {
        tested_dimensions.push(TestedDimension {
            dimension: "completed planned work units".into(),
            value: format!("{} of {total}", coverage.summary.tested_complete),
            observation: "These exact frozen work units have validated completed outcomes across all saved attempts. A completed network check reports reachability; it is not a security pass."
                .into(),
            observed_at: task.finished_at,
        });
    }
    if coverage.summary.tested_partial > 0 {
        tested_dimensions.push(TestedDimension {
            dimension: "partly completed planned work units".into(),
            value: format!("{} of {total}", coverage.summary.tested_partial),
            observation: "These work units produced usable saved results but did not finish every planned operation."
                .into(),
            observed_at: task.finished_at,
        });
    }
}

fn project_naabu_network_scopes(
    task: &EngineRun,
    coverage: &CumulativeNaabuCoverage,
) -> Vec<NetworkScopeCoverage> {
    let Some(plan) = task.naabu_work_plan.as_ref() else {
        return Vec::new();
    };
    coverage
        .work_units
        .iter()
        .filter_map(|covered| {
            let unit = plan
                .work_units
                .iter()
                .find(|unit| unit.unit_id == covered.unit_id)?;
            let grant = plan
                .frozen_grants
                .get(usize::try_from(unit.grant_index).ok()?)?;
            let address_start = usize::try_from(unit.address_start).ok()?;
            let address_end = address_start.checked_add(usize::try_from(unit.address_len).ok()?)?;
            let port_start = usize::try_from(unit.port_start).ok()?;
            let port_end = port_start.checked_add(usize::try_from(unit.port_len).ok()?)?;
            let addresses = grant.addresses.get(address_start..address_end)?;
            let ports = grant.ports.get(port_start..port_end)?;
            Some(NetworkScopeCoverage {
                task_id: task.id.clone(),
                check_id: check_id(task),
                work_unit_id: unit.unit_id.clone(),
                target_asset_id: grant.asset_id.clone(),
                target: grant.target.canonical_text(),
                address_ranges: compact_ip_ranges(addresses),
                port_ranges: compact_port_ranges(ports),
                transport: "tcp".into(),
                stage: match unit.stage {
                    NaabuWorkStage::QuickDiscovery => ReportScanStage::QuickDiscovery,
                    NaabuWorkStage::FullInventory => ReportScanStage::Inventory,
                },
                outcome: covered.outcome,
                observed_at: covered.outcome_execution_attempt.and(task.finished_at),
            })
        })
        .collect()
}

fn compact_ip_ranges(addresses: &[IpAddr]) -> Vec<String> {
    let Some(first) = addresses.first().copied() else {
        return Vec::new();
    };
    let mut ranges = Vec::new();
    let mut start = first;
    let mut previous = first;
    for address in addresses.iter().copied().skip(1) {
        if ip_addresses_are_adjacent(previous, address) {
            previous = address;
            continue;
        }
        ranges.push(format_ip_range(start, previous));
        start = address;
        previous = address;
    }
    ranges.push(format_ip_range(start, previous));
    ranges
}

fn ip_addresses_are_adjacent(left: IpAddr, right: IpAddr) -> bool {
    match (left, right) {
        (IpAddr::V4(left), IpAddr::V4(right)) => {
            u32::from(left).checked_add(1) == Some(u32::from(right))
        }
        (IpAddr::V6(left), IpAddr::V6(right)) => {
            u128::from(left).checked_add(1) == Some(u128::from(right))
        }
        _ => false,
    }
}

fn format_ip_range(start: IpAddr, end: IpAddr) -> String {
    if start == end {
        start.to_string()
    } else {
        format!("{start}-{end}")
    }
}

fn compact_port_ranges(ports: &[u16]) -> Vec<String> {
    let Some(first) = ports.first().copied() else {
        return Vec::new();
    };
    let mut ranges = Vec::new();
    let mut start = first;
    let mut previous = first;
    for port in ports.iter().copied().skip(1) {
        if previous.checked_add(1) == Some(port) {
            previous = port;
            continue;
        }
        ranges.push(format_port_range(start, previous));
        start = port;
        previous = port;
    }
    ranges.push(format_port_range(start, previous));
    ranges
}

fn format_port_range(start: u16, end: u16) -> String {
    if start == end {
        start.to_string()
    } else {
        format!("{start}-{end}")
    }
}

fn append_naabu_coverage_gaps(
    task: &EngineRun,
    coverage: &CumulativeNaabuCoverage,
    gaps: &mut Vec<CoverageGap>,
) {
    let summary = &coverage.summary;
    let task_id = Some(task.id.clone());
    let targets = task.asset_ids.clone();
    let mut push = |kind: CoverageGapKind,
                    dimension: String,
                    reason: String,
                    next_action_code: NextActionCode,
                    next_action: &str| {
        gaps.push(CoverageGap {
            kind,
            task_id: task_id.clone(),
            target_asset_ids: targets.clone(),
            dimension,
            reason,
            next_action_code,
            next_action: next_action.into(),
        });
    };

    if summary.tested_partial > 0 {
        push(
            CoverageGapKind::NotTested,
            format!(
                "{} partly completed work units ({})",
                check_id(task),
                summary.tested_partial
            ),
            "Usable results were saved for these work units, but their remaining planned operations were not tested complete."
                .into(),
            NextActionCode::RetryCheck,
            "Keep the saved results and retry only the unfinished work.",
        );
    }
    if summary.failed > 0 {
        push(
            CoverageGapKind::Failed,
            format!("{} failed work units ({})", check_id(task), summary.failed),
            "These planned work units stopped before establishing completed coverage.".into(),
            NextActionCode::RetryCheck,
            "Keep other saved results and retry only the failed work.",
        );
    }
    if summary.timed_out > 0 {
        push(
            CoverageGapKind::TimedOut,
            format!(
                "{} timed-out work units ({})",
                check_id(task),
                summary.timed_out
            ),
            "These planned work units reached their bounded time limit before completed coverage was recorded."
                .into(),
            NextActionCode::RetryCheck,
            "Keep other saved results and retry only the timed-out work.",
        );
    }
    if summary.cancelled > 0 {
        push(
            CoverageGapKind::Cancelled,
            format!(
                "{} cancelled work units ({})",
                check_id(task),
                summary.cancelled
            ),
            "These planned work units were cancelled before completed coverage was recorded."
                .into(),
            NextActionCode::RetryCheck,
            "Start only the cancelled work again when you want to finish it.",
        );
    }
    if summary.not_tested > 0 {
        push(
            CoverageGapKind::NotTested,
            format!(
                "{} not-tested work units ({})",
                check_id(task),
                summary.not_tested
            ),
            "These frozen work units have no validated tested outcome in any saved attempt.".into(),
            if task_is_active(task) {
                NextActionCode::WaitOrCancel
            } else {
                NextActionCode::RetryCheck
            },
            if task_is_active(task) {
                "Let the current check continue or cancel it; saved partial results remain available."
            } else {
                "Retry only the work that has not yet produced a tested outcome."
            },
        );
    }
    if !coverage.all_validated_final_artifacts_normalized {
        push(
            CoverageGapKind::Unavailable,
            format!("{} saved result processing", check_id(task)),
            "At least one validated scanner result has not been fully processed into findings. Tested coverage remains saved, but the finding list may be incomplete."
                .into(),
            NextActionCode::PreserveVisibleLimitation,
            "Keep the saved results. The app should retry result processing automatically; keep this limitation visible until it succeeds.",
        );
    }

    if coverage.fully_complete && task.status != EngineRunStatus::Completed {
        let (kind, code, action) = if stable_timeout_marker(task) {
            (
                CoverageGapKind::TimedOut,
                NextActionCode::RetryCheck,
                "Keep the completed results. The app should reconcile the timed-out check before treating the run as final.",
            )
        } else if task.status == EngineRunStatus::Failed {
            (
                CoverageGapKind::Failed,
                NextActionCode::RetryCheck,
                "Keep the completed results. The app should reconcile the stopped check before treating the run as final.",
            )
        } else if task.status == EngineRunStatus::Cancelled {
            (
                CoverageGapKind::Cancelled,
                NextActionCode::RetryCheck,
                "Keep the completed results. The app should reconcile the cancelled check before treating the run as final.",
            )
        } else {
            (
                CoverageGapKind::Unavailable,
                if task_is_active(task) {
                    NextActionCode::WaitOrCancel
                } else {
                    NextActionCode::PreserveVisibleLimitation
                },
                "Keep the completed results while the app reconciles the check's final state.",
            )
        };
        push(
            kind,
            format!("{} final-state reconciliation", check_id(task)),
            "Every planned work unit has completed evidence, but the check itself has not recorded a completed final state."
                .into(),
            code,
            action,
        );
    }

    // Usable unit evidence never erases the task's terminal outcome. Avoid a
    // duplicate when the cumulative unit projection already carries the same
    // failure category.
    if !coverage.fully_complete {
        if stable_timeout_marker(task) && summary.timed_out == 0 {
            push(
                CoverageGapKind::TimedOut,
                format!("{} ended after its time limit", check_id(task)),
                if summary.has_usable_results {
                    "The check reached its time limit after saving some usable results."
                } else {
                    "The check reached its time limit before saving a tested outcome."
                }
                .into(),
                NextActionCode::RetryCheck,
                "Keep saved results and retry only the unfinished work.",
            );
        } else if task.status == EngineRunStatus::Failed && summary.failed == 0 {
            push(
                CoverageGapKind::Failed,
                format!("{} stopped before finishing", check_id(task)),
                if summary.has_usable_results {
                    "The check stopped after saving some usable results."
                } else {
                    "The check stopped before saving a tested outcome."
                }
                .into(),
                NextActionCode::RetryCheck,
                "Keep saved results and retry only the unfinished work.",
            );
        } else if task.status == EngineRunStatus::Cancelled && summary.cancelled == 0 {
            push(
                CoverageGapKind::Cancelled,
                format!("{} was cancelled before finishing", check_id(task)),
                if summary.has_usable_results {
                    "The check was cancelled after saving some usable results."
                } else {
                    "The check was cancelled before saving a tested outcome."
                }
                .into(),
                NextActionCode::RetryCheck,
                "Keep saved results and start only the unfinished work again when you are ready.",
            );
        }
    }
}

fn append_task_gap(task: &EngineRun, status: CoverageDimensionStatus, gaps: &mut Vec<CoverageGap>) {
    let (kind, dimension, reason, next_action_code, next_action) = match status {
        CoverageDimensionStatus::TestedComplete => return,
        CoverageDimensionStatus::TestedPartial => (
            CoverageGapKind::NotTested,
            "remaining requested dimensions",
            "This check produced some durable work but did not complete every planned dimension.",
            NextActionCode::RetryCheck,
            "Review the saved results, then retry this check to cover the unfinished dimensions.",
        ),
        CoverageDimensionStatus::TimedOut => (
            CoverageGapKind::TimedOut,
            "timed-out check dimension",
            "The bounded check reached its time limit, so it cannot be treated as tested complete.",
            NextActionCode::RetryCheck,
            "Retry once; if it times out again, review reachability or ask a network specialist.",
        ),
        CoverageDimensionStatus::Failed => (
            CoverageGapKind::Failed,
            "failed check dimension",
            "This check stopped before it could establish completed coverage.",
            NextActionCode::RetryCheck,
            "Keep the saved results from other checks and retry this check.",
        ),
        CoverageDimensionStatus::Cancelled => (
            CoverageGapKind::Cancelled,
            "cancelled check dimension",
            "This check was cancelled before completed coverage was recorded.",
            NextActionCode::RetryCheck,
            "Start this check again when you want to finish the missing coverage.",
        ),
        CoverageDimensionStatus::NotTested => (
            CoverageGapKind::NotTested,
            "not-tested check dimension",
            "This check did not start, so it is not a pass.",
            NextActionCode::ReviewScopeAndRetry,
            "Review the target and try this check again.",
        ),
        CoverageDimensionStatus::InProgress => (
            CoverageGapKind::NotTested,
            "unfinished check dimension",
            "This check is still changing and has not recorded a complete result.",
            NextActionCode::WaitOrCancel,
            "Let it continue or cancel it; the partial report remains available.",
        ),
    };
    gaps.push(CoverageGap {
        kind,
        task_id: Some(task.id.clone()),
        target_asset_ids: task.asset_ids.clone(),
        dimension: format!("{}: {dimension}", check_id(task)),
        reason: stable_task_reason(task, reason),
        next_action_code,
        next_action: next_action.into(),
    });
}

fn append_request_outcome_gaps(
    run: &ScanRun,
    use_request_outcome: bool,
    gaps: &mut Vec<CoverageGap>,
) {
    if !use_request_outcome || !run.is_terminal_no_checks() {
        return;
    }
    let Some(ScanRequestOutcome::NoChecksCompleted {
        code,
        requested_asset_ids,
        requested_engine_ids,
        explanation,
    }) = run.request_outcome.as_ref()
    else {
        return;
    };
    let (next_action_code, next_action) = match code {
        ScanRequestOutcomeCode::EffectiveScopeRequired => (
            NextActionCode::ReviewScopeAndRetry,
            "Review the exact target and permission, then start the scan again.",
        ),
        ScanRequestOutcomeCode::OwnershipConfirmationRequired => (
            NextActionCode::ReviewScopeAndRetry,
            "Choose a target you control, then start the scan again.",
        ),
        ScanRequestOutcomeCode::NoApplicableChecks => (
            NextActionCode::ChooseCompatibleCheck,
            "Choose another available check or add a compatible target source.",
        ),
    };
    if requested_engine_ids.is_empty() {
        gaps.push(CoverageGap {
            kind: CoverageGapKind::NotTested,
            task_id: None,
            target_asset_ids: requested_asset_ids.clone(),
            dimension: "requested checks".into(),
            reason: explanation.clone(),
            next_action_code,
            next_action: next_action.into(),
        });
    } else {
        for engine_id in requested_engine_ids {
            gaps.push(CoverageGap {
                kind: CoverageGapKind::NotTested,
                task_id: None,
                target_asset_ids: requested_asset_ids.clone(),
                dimension: format!("requested check {engine_id}"),
                reason: explanation.clone(),
                next_action_code,
                next_action: next_action.into(),
            });
        }
    }
}

fn append_engine_admission_gaps(run: &ScanRun, gaps: &mut Vec<CoverageGap>) {
    if run.engine_admission_issues.is_empty() {
        return;
    }
    let catalog_list_unavailable = run
        .engine_admission_issues
        .iter()
        .any(|issue| issue.code == "catalog_container_invalid");
    let count = run.engine_admission_issues.len();
    gaps.push(CoverageGap {
        kind: CoverageGapKind::NotTested,
        task_id: None,
        // Catalog admission failed before applicability could be trusted, so
        // this gap must not fabricate either a scanner or target binding.
        target_asset_ids: Vec::new(),
        dimension: "additional packaged checks".into(),
        reason: if catalog_list_unavailable {
            "The packaged check list could not be loaded. Available checks may still run, but checks from that list are not tested."
                .into()
        } else if count == 1 {
            "One additional packaged check was unavailable before planning. Whether it applied to the selected target is unknown, so it is not tested."
                .into()
        } else {
            format!(
                "{count} additional packaged checks were unavailable before planning. Whether they applied to the selected target is unknown, so they are not tested."
            )
        },
        next_action_code: NextActionCode::PreserveVisibleLimitation,
        next_action: "Keep the available results. The app can include these checks in a later run after their packaged scanner information is restored."
            .into(),
    });
}

fn append_case_exclusions(case: &AssessmentCase, run: &ScanRun, gaps: &mut Vec<CoverageGap>) {
    for entry in case.coverage.iter().filter(|entry| {
        entry.last_run_id.as_deref() == Some(run.id.as_str())
            && matches!(entry.status, crate::domain::CoverageStatus::NotApplicable)
    }) {
        gaps.push(CoverageGap {
            kind: CoverageGapKind::Excluded,
            task_id: None,
            target_asset_ids: entry.asset_id.iter().cloned().collect(),
            dimension: entry.label.clone(),
            reason: entry.explanation.clone(),
            next_action_code: NextActionCode::NoActionUnlessScopeChanges,
            next_action:
                "No action is needed unless this area should be included in a future scan.".into(),
        });
    }
}

fn project_findings(case: &AssessmentCase, run: &ScanRun) -> (Vec<BeginnerFinding>, Vec<String>) {
    let mut selected = BTreeMap::<Id, &FindingObservation>::new();
    for observation in case
        .finding_observations
        .iter()
        .filter(|observation| observation.run_id == run.id)
    {
        selected
            .entry(observation.finding_id.clone())
            .and_modify(|current| {
                if observation.observed_at > current.observed_at {
                    *current = observation;
                }
            })
            .or_insert(observation);
    }

    let canonical = case
        .findings
        .iter()
        .map(|finding| (finding.id.as_str(), finding))
        .collect::<BTreeMap<_, _>>();
    let mut warnings = Vec::new();
    let mut findings = selected
        .values()
        .map(|observation| {
            let (source, details) = if let Some(snapshot) = observation.finding_snapshot.as_ref() {
                (FindingSnapshotSource::FrozenSelectedRun, Some(snapshot))
            } else if let Some(current) = canonical.get(observation.finding_id.as_str()) {
                warnings.push(format!(
                    "Finding {} has no selected-run presentation snapshot; current canonical wording is labeled as a legacy fallback.",
                    observation.finding_id
                ));
                (
                    FindingSnapshotSource::CurrentCanonicalLegacyFallback,
                    Some(*current),
                )
            } else {
                warnings.push(format!(
                    "Finding {} has only its retained run observation; presentation detail is unavailable.",
                    observation.finding_id
                ));
                (FindingSnapshotSource::ObservationOnly, None)
            };
            project_finding(observation, source, details, run)
        })
        .collect::<Vec<_>>();

    findings.sort_by(|left, right| {
        right
            .priority
            .unwrap_or(0)
            .cmp(&left.priority.unwrap_or(0))
            .then_with(|| severity_rank(&right.severity).cmp(&severity_rank(&left.severity)))
            .then_with(|| {
                confidence_rank(&right.confidence).cmp(&confidence_rank(&left.confidence))
            })
            .then_with(|| left.finding_id.cmp(&right.finding_id))
    });
    (findings, warnings)
}

fn project_finding_groups(
    case: &AssessmentCase,
    findings: &[BeginnerFinding],
) -> Vec<BeginnerFindingGroup> {
    let observed_finding_ids = findings
        .iter()
        .map(|finding| finding.finding_id.as_str())
        .collect::<BTreeSet<_>>();

    case.finding_groups
        .iter()
        .filter(|group| {
            group
                .finding_ids
                .iter()
                .any(|finding_id| observed_finding_ids.contains(finding_id.as_str()))
        })
        .map(|group| BeginnerFindingGroup {
            group_id: group.id.clone(),
            presentation_scope: FindingGroupPresentationScope::CurrentCasePresentation,
            title: group.title.clone(),
            rationale: group.rationale.clone(),
            actor: group.grouped_by.clone(),
            created_at: group.created_at,
            members: group
                .finding_ids
                .iter()
                .map(|finding_id| BeginnerFindingGroupMember {
                    finding_id: finding_id.clone(),
                    observed_in_selected_run: observed_finding_ids.contains(finding_id.as_str()),
                })
                .collect(),
        })
        .collect()
}

fn project_finding(
    observation: &FindingObservation,
    snapshot_source: FindingSnapshotSource,
    details: Option<&Finding>,
    run: &ScanRun,
) -> BeginnerFinding {
    let evidence_references = details
        .map(|finding| {
            finding
                .evidence
                .iter()
                .filter(|evidence| evidence.run_id == run.id)
                .map(|evidence| FindingEvidenceReference {
                    evidence_id: evidence.id.clone(),
                    engine_id: evidence.engine_id.clone(),
                    artifact_sha256: evidence.artifact_sha256.clone(),
                    observed_at: evidence.observed_at,
                })
                .collect()
        })
        .unwrap_or_default();
    let framework_references = if snapshot_source == FindingSnapshotSource::FrozenSelectedRun {
        details
            .map(|finding| {
                finding
                    .control_references
                    .iter()
                    .map(|reference| FrameworkReference {
                        framework: reference.framework.clone(),
                        framework_version: reference.framework_version.clone(),
                        control_id: reference.control_id.clone(),
                        title: reference.title.clone(),
                        relationship: reference.relationship.clone(),
                        rationale: reference.rationale.clone(),
                        mapping_version: reference.mapping_version.clone(),
                        mapping_provenance: reference.mapping_provenance.clone(),
                    })
                    .collect()
            })
            .unwrap_or_default()
    } else {
        Vec::new()
    };

    BeginnerFinding {
        finding_id: observation.finding_id.clone(),
        fingerprint: observation.fingerprint.clone(),
        snapshot_source,
        title: details
            .map(|finding| finding.title.clone())
            .unwrap_or_else(|| "Finding details unavailable for this legacy run".into()),
        plain_language_risk: details
            .map(|finding| finding.plain_language_summary.clone())
            .unwrap_or_else(|| {
                "A retained observation exists, but this older run did not save its full plain-language description."
                    .into()
            }),
        possible_impact: details
            .map(|finding| finding.possible_impact.clone())
            .unwrap_or_else(|| "The historical impact description is unavailable.".into()),
        severity: observation.severity.clone(),
        confidence: observation.confidence.clone(),
        priority: details.map(|finding| finding.priority),
        priority_reasons: details
            .map(|finding| finding.priority_reasons.clone())
            .unwrap_or_default(),
        target_asset_ids: observation.asset_ids.clone(),
        next_step: details
            .map(|finding| finding.recommendation.clone())
            .unwrap_or_else(|| {
                "Ask a security professional to review the retained observation and evidence."
                    .into()
            }),
        recommended_expert_type: details
            .map(|finding| finding.recommended_expert_type.clone())
            .unwrap_or_else(|| "Security professional".into()),
        evidence_references,
        framework_references,
    }
}

fn project_next_steps(
    state: &BeginnerReportState,
    findings: &[BeginnerFinding],
    gaps: &[CoverageGap],
    actual: &ActualCoverage,
) -> Vec<BeginnerNextStep> {
    let mut steps = findings
        .iter()
        .enumerate()
        .map(|(index, finding)| BeginnerNextStep {
            priority: index as u16,
            code: NextActionCode::ReviewFinding,
            action: finding.next_step.clone(),
            reason: format!(
                "{} — {:?} severity, {:?} confidence",
                finding.title, finding.severity, finding.confidence
            ),
            finding_id: Some(finding.finding_id.clone()),
            task_id: None,
            recommended_expert_type: Some(finding.recommended_expert_type.clone()),
        })
        .collect::<Vec<_>>();

    let mut seen_gap_actions = BTreeSet::new();
    for gap in gaps {
        if seen_gap_actions.insert(gap.next_action.clone()) {
            steps.push(BeginnerNextStep {
                priority: 100 + gap_rank(gap.kind) as u16,
                code: gap.next_action_code,
                action: gap.next_action.clone(),
                reason: gap.reason.clone(),
                finding_id: None,
                task_id: gap.task_id.clone(),
                recommended_expert_type: if gap.kind == CoverageGapKind::TimedOut {
                    Some("Network or system administrator".into())
                } else {
                    None
                },
            });
        }
    }

    if steps.is_empty() {
        let (code, action, reason) = if state.lifecycle == ReportLifecycle::Live {
            (
                NextActionCode::WaitOrCancel,
                "Let the scan continue or cancel it if you need to stop.",
                "This report is still changing and keeps the durable work already saved.",
            )
        } else if actual.checks.iter().any(is_closed_localhost_check) {
            (
                NextActionCode::StartExpectedServiceAndRetry,
                "If you expected an app on this port, start it and run the check again.",
                "The port refused the bounded TCP connection at the recorded time; this is not a security pass or failure.",
            )
        } else {
            (
                NextActionCode::ReviewCoverage,
                "Review what was tested before deciding whether you need a broader scan.",
                "No actionable finding was recorded, but a no-findings result is only as broad as the displayed coverage.",
            )
        };
        steps.push(BeginnerNextStep {
            priority: 0,
            code,
            action: action.into(),
            reason: reason.into(),
            finding_id: None,
            task_id: None,
            recommended_expert_type: None,
        });
    }
    steps.sort_by(|left, right| {
        left.priority
            .cmp(&right.priority)
            .then_with(|| left.action.cmp(&right.action))
    });
    steps
}

fn project_technical_details(case: &AssessmentCase, run: &ScanRun) -> TechnicalDetails {
    let mut tasks = run
        .engine_runs
        .iter()
        .map(|task| {
            let mut evidence_sha256 = case
                .raw_artifacts
                .iter()
                .filter(|artifact| artifact.run_id == run.id && artifact.engine_run_id == task.id)
                .map(|artifact| artifact.sha256.clone())
                .collect::<Vec<_>>();
            evidence_sha256.sort();
            evidence_sha256.dedup();
            let execution = match task.task_kind {
                EngineTaskKind::CatalogEngine => TechnicalExecution::CatalogEngine {
                    engine_id: task.engine_id.clone(),
                    engine_version: task.engine_version.clone(),
                    image_digest: task.image_digest.clone(),
                    command_sha256: task.command_sha256.clone(),
                    runtime_provider: task.runtime_provider.clone(),
                    runtime_version: task.runtime_version.clone(),
                    runtime_security_options: task.runtime_security_options.clone(),
                    distribution_mode: task.distribution_mode.clone(),
                    image_repository: task.image_repository.clone(),
                    adapter_version: task.adapter_version.clone(),
                    rule_version: task.rule_version.clone(),
                },
                EngineTaskKind::BuiltInLocalhostTcp {
                    port,
                    timeout_ms,
                    payload_bytes,
                } if task.task_kind.is_exact_built_in_localhost_tcp_contract() => {
                    TechnicalExecution::BuiltInLocalhostTcp {
                        endpoint: format!("127.0.0.1:{port}"),
                        timeout_ms,
                        payload_bytes,
                        observation: task.localhost_tcp_observation.clone(),
                        contract: "One desktop-host TCP connection attempt; no application payload; reachability observation only."
                            .into(),
                    }
                }
                EngineTaskKind::BuiltInLocalhostTcp { .. } => {
                    TechnicalExecution::InvalidBuiltInTask {
                        explanation: "The stored native task does not match the supported bounded localhost contract, so the report does not claim an endpoint observation contract."
                            .into(),
                    }
                }
            };
            TechnicalTaskDetails {
                task_id: task.id.clone(),
                target_asset_ids: task.asset_ids.clone(),
                status: task.status.clone(),
                phase: task.phase.clone(),
                progress_percent: task.progress_percent,
                started_at: task.started_at,
                finished_at: task.finished_at,
                exit_code: task.exit_code,
                cleanup_removed: task.cleanup_removed,
                cleanup_detail: UnavailableTechnicalValue {
                    availability: DataAvailability::Unavailable,
                    value: None,
                    explanation: "The stored cleanup detail is not proven redacted; only the structured cleanup outcome is shown here."
                        .into(),
                },
                error_code: task.error_code.clone(),
                redacted_scanner_message: UnavailableTechnicalValue {
                    availability: DataAvailability::Unavailable,
                    value: None,
                    explanation: "The case does not prove that its stored scanner message is redacted, so this beginner projection does not expose it. Use the separately redacted diagnostic export for scanner text."
                        .into(),
                },
                redacted_diagnostic_log: UnavailableTechnicalValue {
                    availability: DataAvailability::Unavailable,
                    value: None,
                    explanation: "No run-bound redacted diagnostic log is retained in the case model. Use the separately generated redacted diagnostic export when available."
                        .into(),
                },
                evidence_sha256,
                execution,
            }
        })
        .collect::<Vec<_>>();
    tasks.sort_by(|left, right| left.task_id.cmp(&right.task_id));
    TechnicalDetails {
        collapsed_by_default: true,
        tasks,
    }
}

fn coverage_counts(actual: &ActualCoverage, gaps: &[CoverageGap]) -> CoverageCounts {
    let mut counts = CoverageCounts::default();
    for check in &actual.checks {
        match check.status {
            CoverageDimensionStatus::TestedComplete => counts.tested_complete += 1,
            CoverageDimensionStatus::TestedPartial => counts.tested_partial += 1,
            CoverageDimensionStatus::Failed => counts.failed += 1,
            CoverageDimensionStatus::TimedOut => counts.timed_out += 1,
            CoverageDimensionStatus::Cancelled => counts.cancelled += 1,
            CoverageDimensionStatus::NotTested => counts.not_tested += 1,
            CoverageDimensionStatus::InProgress => counts.not_tested += 1,
        }
    }
    for gap in gaps {
        let task_state_already_counted = gap.task_id.as_ref().is_some_and(|task_id| {
            actual.checks.iter().any(|check| {
                check.task_id.as_str() == task_id.as_str()
                    && matches!(
                        (gap.kind, check.status),
                        (CoverageGapKind::Failed, CoverageDimensionStatus::Failed)
                            | (CoverageGapKind::TimedOut, CoverageDimensionStatus::TimedOut)
                            | (
                                CoverageGapKind::Cancelled,
                                CoverageDimensionStatus::Cancelled
                            )
                            | (
                                CoverageGapKind::NotTested,
                                CoverageDimensionStatus::NotTested
                                    | CoverageDimensionStatus::InProgress
                            )
                    )
            })
        });
        match gap.kind {
            // A task-level state was already counted above. Gap-only records
            // (request outcomes/exclusions/unavailable dimensions) add counts.
            CoverageGapKind::Failed if task_state_already_counted => {}
            CoverageGapKind::TimedOut if task_state_already_counted => {}
            CoverageGapKind::Cancelled if task_state_already_counted => {}
            CoverageGapKind::NotTested if task_state_already_counted => {}
            CoverageGapKind::Failed => counts.failed += 1,
            CoverageGapKind::TimedOut => counts.timed_out += 1,
            CoverageGapKind::Cancelled => counts.cancelled += 1,
            CoverageGapKind::NotTested => counts.not_tested += 1,
            CoverageGapKind::Excluded => counts.excluded += 1,
            CoverageGapKind::Truncated => counts.truncated += 1,
            CoverageGapKind::Unavailable => counts.unavailable += 1,
        }
    }
    counts
}

fn actual_status(task: &EngineRun) -> CoverageDimensionStatus {
    if matches!(
        task.localhost_tcp_observation,
        Some(LocalhostTcpObservation {
            outcome: LocalhostTcpOutcome::TimedOut,
            ..
        })
    ) || stable_timeout_marker(task)
    {
        return CoverageDimensionStatus::TimedOut;
    }
    match task.status {
        EngineRunStatus::Completed => CoverageDimensionStatus::TestedComplete,
        EngineRunStatus::PartiallyCompleted => CoverageDimensionStatus::TestedPartial,
        EngineRunStatus::Failed => CoverageDimensionStatus::Failed,
        EngineRunStatus::Cancelled => CoverageDimensionStatus::Cancelled,
        EngineRunStatus::NotExecuted => CoverageDimensionStatus::NotTested,
        EngineRunStatus::Queued
        | EngineRunStatus::Preparing
        | EngineRunStatus::Running
        | EngineRunStatus::Paused => CoverageDimensionStatus::InProgress,
    }
}

fn task_is_active(task: &EngineRun) -> bool {
    matches!(
        task.status,
        EngineRunStatus::Queued
            | EngineRunStatus::Preparing
            | EngineRunStatus::Running
            | EngineRunStatus::Paused
    )
}

fn run_is_authoritatively_final(run: &ScanRun) -> bool {
    if run.is_terminal_no_checks() {
        return true;
    }
    if run.engine_runs.is_empty() {
        return run.completed_at.is_some();
    }
    run.engine_runs.iter().all(|task| !task_is_active(task))
}

fn exactly_completed_without_known_gap(task: &EngineRun) -> bool {
    if task.engine_id == NAABU_ENGINE_ID
        && matches!(task.task_kind, EngineTaskKind::CatalogEngine)
        && let Some(plan) = task.naabu_work_plan.as_ref()
    {
        return task.status == EngineRunStatus::Completed
            && reduce_naabu_attempt_coverage(
                plan,
                &task.naabu_attempt_requests,
                &task.naabu_attempt_results,
            )
            .is_ok_and(|coverage| coverage.fully_complete);
    }
    if task.status != EngineRunStatus::Completed {
        return false;
    }
    match task.task_kind {
        EngineTaskKind::BuiltInLocalhostTcp { .. } => {
            task.task_kind.is_exact_built_in_localhost_tcp_contract()
                && matches!(
                    task.localhost_tcp_observation,
                    Some(LocalhostTcpObservation {
                        outcome: LocalhostTcpOutcome::Reachable | LocalhostTcpOutcome::Closed,
                        ..
                    })
                )
        }
        EngineTaskKind::CatalogEngine => true,
    }
}

fn stable_timeout_marker(task: &EngineRun) -> bool {
    task.error_code.as_deref().is_some_and(|value| {
        let value = value.to_ascii_lowercase();
        value.contains("timed_out") || value.contains("timeout")
    }) || {
        let phase = task.phase.to_ascii_lowercase();
        phase == "timed_out" || phase == "timeout"
    }
}

fn check_id(task: &EngineRun) -> String {
    match task.task_kind {
        EngineTaskKind::BuiltInLocalhostTcp { port, .. } => {
            format!("native localhost TCP check on 127.0.0.1:{port}")
        }
        EngineTaskKind::CatalogEngine => task.engine_id.clone(),
    }
}

fn stable_task_reason(task: &EngineRun, fallback: &str) -> String {
    task.error_code
        .as_ref()
        .map(|code| format!("{fallback} Diagnostic code: {code}."))
        .unwrap_or_else(|| fallback.into())
}

fn localhost_observation_text(outcome: &LocalhostTcpOutcome) -> &'static str {
    match outcome {
        LocalhostTcpOutcome::Reachable => "The port accepted the bounded TCP connection.",
        LocalhostTcpOutcome::Closed => "The port refused the bounded TCP connection.",
        LocalhostTcpOutcome::TimedOut => {
            "The bounded TCP connection attempt timed out; reachability was not established."
        }
    }
}

fn selected_run_last_durable_update(case: &AssessmentCase, run: &ScanRun) -> DateTime<Utc> {
    let mut times = vec![run.created_at];
    times.extend(run.completed_at);
    for task in &run.engine_runs {
        times.extend(task.started_at);
        times.extend(task.finished_at);
        if let Some(observation) = task.localhost_tcp_observation.as_ref() {
            times.push(observation.observed_at);
        }
    }
    times.extend(
        case.finding_observations
            .iter()
            .filter(|observation| observation.run_id == run.id)
            .map(|observation| observation.observed_at),
    );
    times.extend(
        case.raw_artifacts
            .iter()
            .filter(|artifact| artifact.run_id == run.id)
            .map(|artifact| artifact.created_at),
    );
    times.into_iter().max().unwrap_or(run.created_at)
}

fn state_explanation(summary: BeginnerReportSummary, lifecycle: ReportLifecycle) -> &'static str {
    match (summary, lifecycle) {
        (BeginnerReportSummary::Complete, ReportLifecycle::Final) => {
            "Every exact requested dimension retained by this run has a completed durable outcome. Review the displayed coverage before deciding whether to scan more."
        }
        (BeginnerReportSummary::NoChecksCompleted, _) => {
            "The request finished without any check contacting a target. Nothing untested is presented as passed."
        }
        (BeginnerReportSummary::Partial, ReportLifecycle::Live) => {
            "This report is still changing. Durable work already saved is available now, and unfinished coverage remains explicit."
        }
        (BeginnerReportSummary::Partial, ReportLifecycle::Final) => {
            "Useful saved results are available, but one or more requested or historical coverage dimensions are incomplete or unavailable."
        }
        (BeginnerReportSummary::Complete, ReportLifecycle::Live) => {
            "The report is still changing and is therefore not treated as final coverage."
        }
    }
}

fn is_closed_localhost_check(check: &ActualCheck) -> bool {
    check
        .tested_dimensions
        .iter()
        .any(|dimension| dimension.observation == "The port refused the bounded TCP connection.")
}

fn gap_rank(kind: CoverageGapKind) -> u8 {
    match kind {
        CoverageGapKind::Failed => 0,
        CoverageGapKind::TimedOut => 1,
        CoverageGapKind::Cancelled => 2,
        CoverageGapKind::NotTested => 3,
        CoverageGapKind::Truncated => 4,
        CoverageGapKind::Unavailable => 5,
        CoverageGapKind::Excluded => 6,
    }
}

fn severity_rank(severity: &Severity) -> u8 {
    match severity {
        Severity::Informational => 0,
        Severity::Unknown => 1,
        Severity::Low => 2,
        Severity::Medium => 3,
        Severity::High => 4,
        Severity::Critical => 5,
    }
}

fn confidence_rank(confidence: &Confidence) -> u8 {
    match confidence {
        Confidence::Low => 0,
        Confidence::Medium => 1,
        Confidence::High => 2,
        Confidence::Confirmed => 3,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::domain::{
        Asset, AssetIdentifier, BUILT_IN_LOCALHOST_TCP_ASSET_IDENTIFIER_NAMESPACE,
        BUILT_IN_LOCALHOST_TCP_AUTHORIZATION_REFERENCE, BUILT_IN_LOCALHOST_TCP_ENGINE_ID,
        CaseStatus, ControlReference, CoverageEntry, CoverageStatus, DataClass, EngineRun,
        Evidence, EvidenceKind, FindingGroup, FindingStatus, NAABU_ATTEMPT_REQUEST_SCHEMA_VERSION,
        NAABU_ATTEMPT_RESULT_SCHEMA_VERSION, NaabuAttemptRequest, NaabuAttemptResult,
        OrganizationProfile, RawArtifact, ScopeGrant, SourceKind, new_id,
    };
    use crate::execution_coverage::{
        ExecutionCoverageSummary, FinalArtifactIdentity, LAUNCHER_V2_JOURNAL_SCHEMA_VERSION,
        ValidatedArtifactBinding, ValidatedExecutionCoverage, WorkUnitAttempt, WorkUnitCoverage,
    };
    use crate::external_scope::{
        CanonicalTarget, ExternalActivity, RatePolicy, ResolutionSnapshot, ResolvedExternalPlan,
        TemplatePolicy, TransportProtocol,
    };
    use crate::naabu_work_plan::{NaabuWorkPlanIdentity, build_naabu_work_plan};
    use chrono::{Duration, TimeZone};
    use sha2::{Digest, Sha256};
    use std::collections::{BTreeMap, BTreeSet};

    #[test]
    fn unknown_severity_sorts_after_known_low_but_before_informational() {
        assert!(severity_rank(&Severity::Low) > severity_rank(&Severity::Unknown));
        assert!(severity_rank(&Severity::Unknown) > severity_rank(&Severity::Informational));
    }

    fn instant(seconds: i64) -> DateTime<Utc> {
        Utc.timestamp_opt(1_788_000_000 + seconds, 0).unwrap()
    }

    fn empty_case() -> AssessmentCase {
        let mut case = AssessmentCase::new(
            "Beginner report test".into(),
            OrganizationProfile {
                organization_name: "Home lab".into(),
                employee_range: "1".into(),
                data_classes: vec![DataClass::General],
                notes: None,
            },
        );
        case.id = "case-1".into();
        case.status = CaseStatus::Scanning;
        case.created_at = instant(0);
        case.updated_at = instant(100);
        case
    }

    fn localhost_case(
        outcome: LocalhostTcpOutcome,
        status: EngineRunStatus,
        terminal: bool,
    ) -> AssessmentCase {
        let mut case = empty_case();
        case.assets.push(Asset {
            id: "localhost-asset".into(),
            kind: AssetKind::WebService,
            name: "127.0.0.1:9001".into(),
            provider: None,
            region: None,
            identifiers: vec![AssetIdentifier {
                namespace: BUILT_IN_LOCALHOST_TCP_ASSET_IDENTIFIER_NAMESPACE.into(),
                value: "127.0.0.1:9001".into(),
            }],
            discovered_from: vec!["source-1".into()],
            candidate: false,
            owner_confirmed: true,
            internet_exposed: Some(false),
            contains_sensitive_data: Some(false),
            metadata: BTreeMap::new(),
        });
        let run_id = "run-1".to_string();
        case.scan_runs.push(ScanRun {
            id: run_id.clone(),
            case_id: case.id.clone(),
            sequence: 1,
            created_at: instant(10),
            completed_at: terminal.then(|| instant(20)),
            request_outcome: None,
            knowledge_cutoff: instant(10),
            ai_system_applicable: false,
            ai_system_applicability: Default::default(),
            ai_generated_artifact: Default::default(),
            verification_baseline_run_id: None,
            scope_grant_ids: vec!["grant-1".into()],
            scope_grant_snapshots: vec![ScopeGrant {
                id: "grant-1".into(),
                asset_id: "localhost-asset".into(),
                permission: crate::domain::ScanPermission::LowImpactExternalConnection,
                confirmed_by: "local user".into(),
                confirmed_at: instant(9),
                expires_at: None,
                authorization_reference: Some(
                    BUILT_IN_LOCALHOST_TCP_AUTHORIZATION_REFERENCE.into(),
                ),
                notes: None,
                external_scope: None,
            }],
            engine_admission_issues: Vec::new(),
            engine_runs: vec![EngineRun {
                id: "task-1".into(),
                scan_run_id: run_id,
                engine_id: BUILT_IN_LOCALHOST_TCP_ENGINE_ID.into(),
                task_kind: EngineTaskKind::built_in_localhost_tcp(9_001),
                localhost_tcp_observation: Some(LocalhostTcpObservation {
                    outcome,
                    observed_at: instant(16),
                }),
                asset_ids: vec!["localhost-asset".into()],
                status,
                progress_percent: 100,
                phase: "completed".into(),
                started_at: Some(instant(15)),
                finished_at: terminal.then(|| instant(16)),
                resume_token: None,
                last_execution_report_sha256: None,
                engine_version: None,
                image_digest: None,
                rule_version: None,
                adapter_version: "native".into(),
                manifest_schema_version: None,
                source_revision: None,
                repository_url: None,
                distribution_mode: None,
                image_repository: None,
                command_sha256: None,
                execution_timeout_seconds: None,
                knowledge_input: None,
                scope_contract_sha256: None,
                naabu_work_plan: None,
                naabu_attempt_requests: Vec::new(),
                naabu_attempt_results: Vec::new(),
                mapping_version: None,
                mapping_provenance: None,
                fingerprint_schema_version: None,
                runtime_provider: None,
                runtime_version: None,
                runtime_security_options: None,
                exit_code: None,
                cleanup_removed: Some(true),
                cleanup_detail: Some("No disposable runtime was created.".into()),
                warnings: vec![],
                raw_artifact_ids: vec![],
                error_code: None,
                error_message: None,
            }],
        });
        case
    }

    fn catalog_task(id: &str, status: EngineRunStatus) -> EngineRun {
        EngineRun {
            id: id.into(),
            scan_run_id: "run-1".into(),
            engine_id: format!("engine-{id}"),
            task_kind: EngineTaskKind::CatalogEngine,
            localhost_tcp_observation: None,
            asset_ids: vec!["asset-1".into()],
            status,
            progress_percent: 25,
            phase: "test".into(),
            started_at: Some(instant(12)),
            finished_at: Some(instant(14)),
            resume_token: None,
            last_execution_report_sha256: None,
            engine_version: Some("1.0.0".into()),
            image_digest: Some("sha256:test".into()),
            rule_version: Some("rules-1".into()),
            adapter_version: "adapter-1".into(),
            manifest_schema_version: Some("2.0.0".into()),
            source_revision: Some("revision".into()),
            repository_url: Some("https://example.invalid/engine".into()),
            distribution_mode: Some(DistributionMode::PullPinnedImage),
            image_repository: Some("example.invalid/engine".into()),
            command_sha256: Some("command".into()),
            execution_timeout_seconds: Some(60),
            knowledge_input: None,
            scope_contract_sha256: Some("scope".into()),
            naabu_work_plan: None,
            naabu_attempt_requests: Vec::new(),
            naabu_attempt_results: Vec::new(),
            mapping_version: None,
            mapping_provenance: None,
            fingerprint_schema_version: Some("finding-v2".into()),
            runtime_provider: Some("managed_local".into()),
            runtime_version: Some("1".into()),
            runtime_security_options: Some("read_only".into()),
            exit_code: Some(1),
            cleanup_removed: Some(true),
            cleanup_detail: Some("done".into()),
            warnings: vec![],
            raw_artifact_ids: vec![],
            error_code: None,
            error_message: Some("untrusted target text must not be exposed".into()),
        }
    }

    fn case_with_catalog_tasks(tasks: Vec<EngineRun>, terminal: bool) -> AssessmentCase {
        let mut case = empty_case();
        case.assets.push(Asset {
            id: "asset-1".into(),
            kind: AssetKind::Repository,
            name: "sample repository".into(),
            provider: None,
            region: None,
            identifiers: vec![],
            discovered_from: vec![],
            candidate: false,
            owner_confirmed: true,
            internet_exposed: None,
            contains_sensitive_data: None,
            metadata: BTreeMap::new(),
        });
        case.scan_runs.push(ScanRun {
            id: "run-1".into(),
            case_id: case.id.clone(),
            sequence: 1,
            created_at: instant(10),
            completed_at: terminal.then(|| instant(20)),
            request_outcome: None,
            knowledge_cutoff: instant(10),
            ai_system_applicable: false,
            ai_system_applicability: Default::default(),
            ai_generated_artifact: Default::default(),
            verification_baseline_run_id: None,
            scope_grant_ids: vec![],
            scope_grant_snapshots: vec![],
            engine_admission_issues: Vec::new(),
            engine_runs: tasks,
        });
        case
    }

    #[test]
    fn reachable_localhost_is_exact_complete_and_never_engine_provenance() {
        let case = localhost_case(
            LocalhostTcpOutcome::Reachable,
            EngineRunStatus::Completed,
            true,
        );
        let report = build_beginner_master_report(&case, "run-1").unwrap();

        assert_eq!(report.state.summary, BeginnerReportSummary::Complete);
        assert_eq!(report.state.lifecycle, ReportLifecycle::Final);
        assert_eq!(
            report.requested.stage.value,
            Some(ReportScanStage::QuickDiscovery)
        );
        assert_eq!(
            report.requested.targets[0].label_availability,
            DataAvailability::Recorded
        );
        assert_eq!(
            report.requested.reductions_availability,
            DataAvailability::Recorded
        );
        assert!(report.coverage_gaps.is_empty());
        assert_eq!(report.coverage_counts.tested_complete, 1);
        assert_eq!(
            report.actual.checks[0].status,
            CoverageDimensionStatus::TestedComplete
        );
        assert_eq!(
            report.actual.checks[0].tested_dimensions[0].value,
            "127.0.0.1:9001"
        );
        assert!(matches!(
            report.technical_details.tasks[0].execution,
            TechnicalExecution::BuiltInLocalhostTcp {
                timeout_ms: 3_000,
                payload_bytes: 0,
                ..
            }
        ));
        let encoded = serde_json::to_value(&report.technical_details.tasks[0].execution).unwrap();
        assert_eq!(encoded["kind"], "built_in_localhost_tcp");
        assert!(encoded.get("engine_version").is_none());
        assert!(encoded.get("image_digest").is_none());
        assert!(encoded.get("runtime_provider").is_none());
    }

    #[test]
    fn refused_localhost_connection_is_a_completed_observation_not_a_security_verdict() {
        let case = localhost_case(
            LocalhostTcpOutcome::Closed,
            EngineRunStatus::Completed,
            true,
        );
        let report = build_beginner_master_report(&case, "run-1").unwrap();

        assert_eq!(report.state.summary, BeginnerReportSummary::Complete);
        assert!(
            report.actual.checks[0].tested_dimensions[0]
                .observation
                .contains("refused")
        );
        assert!(report.next_steps[0].action.contains("expected an app"));
        assert!(
            serde_json::to_string(&report)
                .unwrap()
                .contains("not a security pass or failure")
        );
    }

    #[test]
    fn timed_out_localhost_is_partial_with_an_explicit_gap() {
        let case = localhost_case(
            LocalhostTcpOutcome::TimedOut,
            EngineRunStatus::PartiallyCompleted,
            true,
        );
        let report = build_beginner_master_report(&case, "run-1").unwrap();

        assert_eq!(report.state.summary, BeginnerReportSummary::Partial);
        assert_eq!(
            report.actual.checks[0].status,
            CoverageDimensionStatus::TimedOut
        );
        assert_eq!(report.coverage_counts.timed_out, 1);
        assert!(
            report
                .coverage_gaps
                .iter()
                .any(|gap| gap.kind == CoverageGapKind::TimedOut)
        );
    }

    #[test]
    fn completed_native_state_without_observation_is_no_checks_completed_not_green() {
        let mut case = localhost_case(
            LocalhostTcpOutcome::Reachable,
            EngineRunStatus::Completed,
            true,
        );
        case.scan_runs[0].engine_runs[0].localhost_tcp_observation = None;
        let report = build_beginner_master_report(&case, "run-1").unwrap();

        assert_eq!(
            report.state.summary,
            BeginnerReportSummary::NoChecksCompleted
        );
        assert_eq!(
            report.actual.checks[0].status,
            CoverageDimensionStatus::NotTested
        );
        assert!(
            report
                .coverage_gaps
                .iter()
                .any(|gap| gap.kind == CoverageGapKind::NotTested)
        );
    }

    #[test]
    fn partial_task_counts_both_saved_partial_work_and_remaining_gap() {
        let case = case_with_catalog_tasks(
            vec![catalog_task("partial", EngineRunStatus::PartiallyCompleted)],
            true,
        );
        let report = build_beginner_master_report(&case, "run-1").unwrap();

        assert_eq!(report.state.summary, BeginnerReportSummary::Partial);
        assert_eq!(report.coverage_counts.tested_partial, 1);
        assert_eq!(report.coverage_counts.not_tested, 1);
    }

    #[test]
    fn network_master_report_names_the_exact_tested_and_untested_ports() {
        let frozen_at = instant(10);
        let address = "192.168.50.10".parse().expect("fixture address");
        let resolved = ResolvedExternalPlan {
            grant_id: "grant-1".into(),
            case_id: "case-1".into(),
            asset_id: "asset-1".into(),
            target: CanonicalTarget::Address(address),
            resolution: ResolutionSnapshot {
                hostname: None,
                addresses: BTreeSet::from([address]),
                resolved_at: frozen_at,
            },
            ports: BTreeSet::from([80, 443]),
            protocol: TransportProtocol::Tcp,
            activity: ExternalActivity::LowImpactExternal,
            rate_policy: RatePolicy {
                requests_per_second: 25,
                concurrency: 10,
                timeout_seconds: 3,
            },
            template_policy: TemplatePolicy::conservative("not_applicable", Vec::new()),
            frozen_at,
            expires_at: frozen_at + Duration::hours(1),
            allow_sensitive_networks: true,
        };
        let plan = build_naabu_work_plan(
            NaabuWorkPlanIdentity::new("case-1", "run-1", "task-network", frozen_at),
            &[resolved],
            None,
        )
        .expect("exact two-port plan");
        assert_eq!(
            plan.work_units.len(),
            2,
            "fixture requires one unit per port"
        );

        let requested_unit_ids = plan
            .work_units
            .iter()
            .map(|unit| unit.unit_id.clone())
            .collect::<Vec<_>>();
        let selected = requested_unit_ids.iter().cloned().collect::<BTreeSet<_>>();
        let launcher = plan
            .launcher_plan_v3(1, Some(&selected))
            .expect("current compact launcher plan");
        let request = NaabuAttemptRequest {
            schema_version: NAABU_ATTEMPT_REQUEST_SCHEMA_VERSION,
            execution_attempt: 1,
            requested_unit_ids,
            launcher_plan_sha256: hex::encode(Sha256::digest(
                serde_json::to_vec(&launcher).expect("launcher JSON"),
            )),
        };

        let mut tested_complete = 0;
        let mut not_tested = 0;
        let mut work_units = Vec::new();
        let mut bindings = Vec::new();
        for unit in &plan.work_units {
            let grant = &plan.frozen_grants[usize::try_from(unit.grant_index).unwrap()];
            let port = grant.ports[usize::try_from(unit.port_start).unwrap()];
            let (outcome, final_artifact) = if port == 80 {
                tested_complete += 1;
                let identity = FinalArtifactIdentity {
                    engine_run_id: plan.identity.engine_run_id.clone(),
                    unit_id: unit.unit_id.clone(),
                    scope_sha256: unit.scope_sha256.clone(),
                    attempt: 1,
                    relative_path: format!("attempt-1/{}.jsonl", unit.unit_id),
                    sha256: "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
                        .into(),
                    byte_length: 0,
                };
                bindings.push(ValidatedArtifactBinding {
                    raw_artifact_id: "raw-port-80".into(),
                    identity: identity.clone(),
                });
                (WorkUnitOutcome::TestedComplete, Some(identity))
            } else {
                not_tested += 1;
                (WorkUnitOutcome::NotTested, None)
            };
            work_units.push(WorkUnitCoverage {
                unit_id: unit.unit_id.clone(),
                scope_sha256: unit.scope_sha256.clone(),
                outcome,
                attempts: vec![WorkUnitAttempt {
                    attempt: 1,
                    outcome,
                    incomplete_reason: None,
                    final_artifact,
                }],
            });
        }
        assert_eq!((tested_complete, not_tested), (1, 1));
        let result = NaabuAttemptResult {
            schema_version: NAABU_ATTEMPT_RESULT_SCHEMA_VERSION,
            execution_attempt: 1,
            journal_raw_artifact_id: "raw-journal-1".into(),
            coverage: ValidatedExecutionCoverage {
                schema_version: LAUNCHER_V2_JOURNAL_SCHEMA_VERSION,
                engine_run_id: plan.identity.engine_run_id.clone(),
                execution_attempt: 1,
                recovered_trailing_record: false,
                validated_artifact_bindings: bindings,
                unreferenced_final_artifacts: Vec::new(),
                work_units,
                summary: ExecutionCoverageSummary {
                    requested: 2,
                    tested_complete: 1,
                    tested_partial: 0,
                    failed: 0,
                    timed_out: 0,
                    cancelled: 0,
                    not_tested: 1,
                    partial: true,
                    has_usable_results: true,
                },
            },
            normalization_complete: true,
        };

        let mut task = catalog_task("network", EngineRunStatus::PartiallyCompleted);
        task.id = "task-network".into();
        task.engine_id = NAABU_ENGINE_ID.into();
        task.progress_percent = 50;
        task.error_message = None;
        task.naabu_work_plan = Some(plan);
        task.naabu_attempt_requests = vec![request];
        task.naabu_attempt_results = vec![result];
        let mut case = case_with_catalog_tasks(vec![task], true);
        case.assets[0].kind = AssetKind::IpAddress;
        case.assets[0].name = address.to_string();

        let report = build_beginner_master_report(&case, "run-1").expect("beginner report");
        let port_80 = report
            .actual
            .network_scopes
            .iter()
            .find(|scope| scope.port_ranges == ["80"])
            .expect("port 80 scope");
        let port_443 = report
            .actual
            .network_scopes
            .iter()
            .find(|scope| scope.port_ranges == ["443"])
            .expect("port 443 scope");
        assert_eq!(port_80.address_ranges, [address.to_string()]);
        assert_eq!(port_80.target, address.to_string());
        assert_eq!(port_80.outcome, WorkUnitOutcome::TestedComplete);
        assert_eq!(port_443.address_ranges, [address.to_string()]);
        assert_eq!(port_443.outcome, WorkUnitOutcome::NotTested);
        assert_eq!(report.state.summary, BeginnerReportSummary::Partial);
        assert_eq!(report.coverage_counts.tested_partial, 1);
        assert_eq!(report.coverage_counts.not_tested, 1);
    }

    #[test]
    fn failed_and_cancelled_tasks_are_no_checks_completed_with_separate_gaps() {
        let mut failed = catalog_task("failed", EngineRunStatus::Failed);
        failed.error_code = Some("execution_failed".into());
        let cancelled = catalog_task("cancelled", EngineRunStatus::Cancelled);
        let case = case_with_catalog_tasks(vec![failed, cancelled], true);
        let report = build_beginner_master_report(&case, "run-1").unwrap();

        assert_eq!(
            report.state.summary,
            BeginnerReportSummary::NoChecksCompleted
        );
        assert!(
            report
                .coverage_gaps
                .iter()
                .any(|gap| gap.kind == CoverageGapKind::Failed)
        );
        assert!(
            report
                .coverage_gaps
                .iter()
                .any(|gap| gap.kind == CoverageGapKind::Cancelled)
        );
        let encoded = serde_json::to_string(&report).unwrap();
        assert!(!encoded.contains("untrusted target text"));
    }

    #[test]
    fn valid_terminal_no_check_outcome_is_not_failure_or_success() {
        let mut case = empty_case();
        case.assets.push(Asset {
            id: "asset-1".into(),
            kind: AssetKind::Domain,
            name: "example.invalid".into(),
            provider: None,
            region: None,
            identifiers: vec![],
            discovered_from: vec![],
            candidate: false,
            owner_confirmed: true,
            internet_exposed: Some(true),
            contains_sensitive_data: None,
            metadata: BTreeMap::new(),
        });
        case.scan_runs.push(ScanRun {
            id: "run-1".into(),
            case_id: case.id.clone(),
            sequence: 1,
            created_at: instant(10),
            completed_at: Some(instant(11)),
            request_outcome: Some(
                ScanRequestOutcome::no_checks_completed(
                    ScanRequestOutcomeCode::NoApplicableChecks,
                    vec!["asset-1".into()],
                    vec!["missing-check".into()],
                    "No available check supports the requested target.",
                )
                .unwrap(),
            ),
            knowledge_cutoff: instant(10),
            ai_system_applicable: false,
            ai_system_applicability: Default::default(),
            ai_generated_artifact: Default::default(),
            verification_baseline_run_id: None,
            scope_grant_ids: vec![],
            scope_grant_snapshots: vec![],
            engine_admission_issues: Vec::new(),
            engine_runs: vec![],
        });

        let report = build_beginner_master_report(&case, "run-1").unwrap();
        assert_eq!(
            report.state.summary,
            BeginnerReportSummary::NoChecksCompleted
        );
        assert_eq!(
            report.requested.request_outcome_code,
            Some(ScanRequestOutcomeCode::NoApplicableChecks)
        );
        assert_eq!(report.state.lifecycle, ReportLifecycle::Final);
        assert!(report.actual.checks.is_empty());
        assert_eq!(report.requested.targets[0].asset_id, "asset-1");
        assert_eq!(report.requested.requested_check_ids, vec!["missing-check"]);
        assert!(
            report
                .coverage_gaps
                .iter()
                .any(|gap| gap.kind == CoverageGapKind::NotTested)
        );
    }

    #[test]
    fn active_run_is_live_partial_and_uses_selected_run_durable_time() {
        let mut task = catalog_task("active", EngineRunStatus::Running);
        task.finished_at = None;
        task.started_at = Some(instant(30));
        let case = case_with_catalog_tasks(vec![task], false);
        let report = build_beginner_master_report(&case, "run-1").unwrap();

        assert_eq!(report.state.summary, BeginnerReportSummary::Partial);
        assert_eq!(report.state.lifecycle, ReportLifecycle::Live);
        assert_eq!(report.state.last_durable_update, instant(30));
        assert_eq!(
            report.actual.checks[0].status,
            CoverageDimensionStatus::InProgress
        );
        assert_eq!(
            report.requested.targets[0].label_availability,
            DataAvailability::CurrentCaseFallback
        );
        assert!(
            report
                .coverage_gaps
                .iter()
                .any(|gap| gap.dimension == "run-frozen target label or type")
        );
    }

    #[test]
    fn stale_completion_time_cannot_turn_an_active_check_into_a_final_report() {
        let mut task = catalog_task("active", EngineRunStatus::Running);
        task.finished_at = None;
        task.started_at = Some(instant(30));
        let case = case_with_catalog_tasks(vec![task], true);
        let report = build_beginner_master_report(&case, "run-1").unwrap();

        assert_eq!(report.state.summary, BeginnerReportSummary::Partial);
        assert_eq!(report.state.lifecycle, ReportLifecycle::Live);
        assert_eq!(
            report.actual.checks[0].status,
            CoverageDimensionStatus::InProgress
        );
        assert!(report.data_quality_warnings.iter().any(|warning| {
            warning.contains("saved completion time") && warning.contains("remains live")
        }));
    }

    #[test]
    fn terminal_check_states_survive_a_missing_run_completion_event() {
        let case = case_with_catalog_tasks(
            vec![catalog_task("completed", EngineRunStatus::Completed)],
            false,
        );
        let report = build_beginner_master_report(&case, "run-1").unwrap();

        assert_eq!(report.state.summary, BeginnerReportSummary::Partial);
        assert_eq!(report.state.lifecycle, ReportLifecycle::Final);
    }

    #[test]
    fn packaged_scanner_limitation_prevents_a_complete_claim_without_exposing_internals() {
        let mut case = localhost_case(
            LocalhostTcpOutcome::Reachable,
            EngineRunStatus::Completed,
            true,
        );
        case.scan_runs[0]
            .engine_admission_issues
            .push(crate::domain::EngineAdmissionIssue {
                engine_id: Some("gitleaks".into()),
                code: "engine_contract_invalid".into(),
                detail: "technical fixture detail".into(),
            });
        let report = build_beginner_master_report(&case, "run-1").unwrap();

        assert_eq!(report.state.summary, BeginnerReportSummary::Partial);
        let gap = report
            .coverage_gaps
            .iter()
            .find(|gap| gap.dimension == "additional packaged checks")
            .expect("catalog limitation gap");
        assert_eq!(gap.kind, CoverageGapKind::NotTested);
        assert!(gap.target_asset_ids.is_empty());
        assert!(!gap.reason.contains("gitleaks"));
        assert!(!gap.reason.contains("engine_contract_invalid"));
        assert_eq!(report.coverage_counts.not_tested, 1);
    }

    #[test]
    fn unreadable_packaged_check_list_never_invents_a_check_count() {
        let mut case = localhost_case(
            LocalhostTcpOutcome::Reachable,
            EngineRunStatus::Completed,
            true,
        );
        case.scan_runs[0]
            .engine_admission_issues
            .push(crate::domain::EngineAdmissionIssue {
                engine_id: None,
                code: "catalog_container_invalid".into(),
                detail: "test-only root detail".into(),
            });
        let report = build_beginner_master_report(&case, "run-1").unwrap();
        let gap = report
            .coverage_gaps
            .iter()
            .find(|gap| gap.dimension == "additional packaged checks")
            .expect("catalog-list limitation gap");

        assert_eq!(
            gap.reason,
            "The packaged check list could not be loaded. Available checks may still run, but checks from that list are not tested."
        );
        assert!(!gap.reason.chars().any(|character| character.is_numeric()));
        assert!(!gap.reason.contains("One additional"));
    }

    #[test]
    fn contradictory_request_outcome_is_ignored_and_forces_honest_partial_report() {
        let mut case = localhost_case(
            LocalhostTcpOutcome::Reachable,
            EngineRunStatus::Completed,
            true,
        );
        case.scan_runs[0].request_outcome = Some(
            ScanRequestOutcome::no_checks_completed(
                ScanRequestOutcomeCode::NoApplicableChecks,
                vec!["different-asset".into()],
                vec!["different-check".into()],
                "Contradictory old state.",
            )
            .unwrap(),
        );

        let report = build_beginner_master_report(&case, "run-1").unwrap();
        assert_eq!(report.state.summary, BeginnerReportSummary::Partial);
        assert_ne!(
            report.state.summary,
            BeginnerReportSummary::NoChecksCompleted
        );
        assert_eq!(report.requested.targets[0].asset_id, "localhost-asset");
        assert!(
            !report
                .requested
                .requested_check_ids
                .contains(&"different-check".into())
        );
        assert!(
            report
                .coverage_gaps
                .iter()
                .any(|gap| gap.dimension == "request outcome integrity")
        );
    }

    #[test]
    fn selected_run_snapshot_drives_priority_and_frameworks_without_catalog_lookup() {
        let mut case = localhost_case(
            LocalhostTcpOutcome::Reachable,
            EngineRunStatus::Completed,
            true,
        );
        let low = frozen_finding(&case, "finding-low", 10, Severity::Low);
        let high = frozen_finding(&case, "finding-high", 90, Severity::High);
        case.findings = vec![low.clone(), high.clone()];
        case.finding_observations = vec![
            observation(&low, "run-1", instant(17)),
            observation(&high, "run-1", instant(18)),
        ];
        // Mutable canonical wording changes after the selected run. The report
        // must keep the frozen snapshot.
        case.findings[1].title = "Later mutable title".into();

        let report = build_beginner_master_report(&case, "run-1").unwrap();
        assert_eq!(report.findings[0].finding_id, "finding-high");
        assert_eq!(report.findings[0].title, "Frozen finding-high");
        assert_eq!(
            report.findings[0].snapshot_source,
            FindingSnapshotSource::FrozenSelectedRun
        );
        assert_eq!(report.findings[0].framework_references.len(), 1);
        assert_eq!(
            report.framework_notice.non_certification,
            FRAMEWORK_NON_CERTIFICATION_NOTICE
        );
    }

    #[test]
    fn active_groups_project_selected_and_historical_members_without_changing_run_results() {
        let mut case = localhost_case(
            LocalhostTcpOutcome::Reachable,
            EngineRunStatus::Completed,
            true,
        );
        let selected = frozen_finding(&case, "finding-selected", 90, Severity::High);
        let historical = frozen_finding(&case, "finding-historical", 40, Severity::Medium);
        let other_historical = frozen_finding(&case, "finding-other-historical", 10, Severity::Low);
        case.findings = vec![
            selected.clone(),
            historical.clone(),
            other_historical.clone(),
        ];
        case.finding_observations = vec![observation(&selected, "run-1", instant(18))];

        let without_groups = build_beginner_master_report(&case, "run-1").unwrap();
        case.finding_groups = vec![
            FindingGroup {
                id: "group-mixed".into(),
                case_id: case.id.clone(),
                title: "Related observations".into(),
                finding_ids: vec![selected.id.clone(), historical.id.clone()],
                rationale: "Review the shared path together.".into(),
                grouped_by: "Human reviewer".into(),
                created_at: instant(19),
            },
            FindingGroup {
                id: "group-history-only".into(),
                case_id: case.id.clone(),
                title: "Historical observations".into(),
                finding_ids: vec![historical.id.clone(), other_historical.id.clone()],
                rationale: "This group has no selected-run observation.".into(),
                grouped_by: "Human reviewer".into(),
                created_at: instant(20),
            },
        ];

        let report = build_beginner_master_report(&case, "run-1").unwrap();
        assert_eq!(report.schema_version, "1.1.0");
        assert_eq!(report.finding_groups.len(), 1);
        let group = &report.finding_groups[0];
        assert_eq!(group.group_id, "group-mixed");
        assert_eq!(
            group.presentation_scope,
            FindingGroupPresentationScope::CurrentCasePresentation
        );
        assert_eq!(group.title, "Related observations");
        assert_eq!(group.rationale, "Review the shared path together.");
        assert_eq!(group.actor, "Human reviewer");
        assert_eq!(group.created_at, instant(19));
        assert_eq!(
            group.members,
            vec![
                BeginnerFindingGroupMember {
                    finding_id: "finding-selected".into(),
                    observed_in_selected_run: true,
                },
                BeginnerFindingGroupMember {
                    finding_id: "finding-historical".into(),
                    observed_in_selected_run: false,
                },
            ]
        );
        let report_json = serde_json::to_value(&report).unwrap();
        assert_eq!(
            report_json.pointer("/finding_groups/0/presentation_scope"),
            Some(&serde_json::json!("current_case_presentation"))
        );

        assert_eq!(report.findings, without_groups.findings);
        assert_eq!(report.requested, without_groups.requested);
        assert_eq!(report.actual, without_groups.actual);
        assert_eq!(report.coverage_gaps, without_groups.coverage_gaps);
        assert_eq!(report.coverage_counts, without_groups.coverage_counts);
        assert_eq!(report.next_steps, without_groups.next_steps);
    }

    #[test]
    fn legacy_report_without_group_projection_deserializes_with_an_empty_projection() {
        let case = localhost_case(
            LocalhostTcpOutcome::Reachable,
            EngineRunStatus::Completed,
            true,
        );
        let report = build_beginner_master_report(&case, "run-1").unwrap();
        let mut legacy = serde_json::to_value(report).unwrap();
        let legacy = legacy.as_object_mut().unwrap();
        legacy.insert("schema_version".into(), serde_json::json!("1.0.0"));
        legacy.remove("finding_groups");

        let decoded: BeginnerMasterReport =
            serde_json::from_value(serde_json::Value::Object(legacy.clone())).unwrap();
        assert_eq!(decoded.schema_version, "1.0.0");
        assert!(decoded.finding_groups.is_empty());
    }

    fn frozen_finding(
        case: &AssessmentCase,
        id: &str,
        priority: u8,
        severity: Severity,
    ) -> Finding {
        Finding {
            id: id.into(),
            case_id: case.id.clone(),
            first_seen_run_id: "run-1".into(),
            last_seen_run_id: "run-1".into(),
            fingerprint: format!("fingerprint-{id}"),
            title: format!("Frozen {id}"),
            plain_language_summary: "Plain-language risk".into(),
            possible_impact: "Possible impact".into(),
            severity,
            confidence: Confidence::High,
            priority,
            priority_reasons: vec!["exposed".into()],
            asset_ids: vec!["localhost-asset".into()],
            evidence: vec![Evidence {
                id: format!("evidence-{id}"),
                finding_id: id.into(),
                run_id: "run-1".into(),
                engine_run_id: Some("task-1".into()),
                kind: EvidenceKind::Observation,
                engine_id: BUILT_IN_LOCALHOST_TCP_ENGINE_ID.into(),
                source_rule: None,
                result_pointer_sha256: None,
                observed_at: instant(17),
                summary: "Evidence".into(),
                artifact_id: format!("artifact-{id}"),
                artifact_sha256: format!("hash-{id}"),
                pointer: None,
                redacted: true,
            }],
            control_references: vec![ControlReference {
                framework: "NIST CSF".into(),
                framework_version: "2.0".into(),
                control_id: "ID.AM-01".into(),
                title: "Assets inventoried".into(),
                relationship: "related".into(),
                rationale: "Navigation only".into(),
                mapping_version: "test-map".into(),
                mapping_provenance: None,
            }],
            recommendation: "Review this finding.".into(),
            verification_guidance: "Scan again after review.".into(),
            rollback_considerations: None,
            official_references: vec![],
            recommended_expert_type: "Security engineer".into(),
            status: FindingStatus::Unreviewed,
            tags: vec![],
        }
    }

    fn observation(
        finding: &Finding,
        run_id: &str,
        observed_at: DateTime<Utc>,
    ) -> FindingObservation {
        FindingObservation {
            id: new_id(),
            run_id: run_id.into(),
            finding_id: finding.id.clone(),
            fingerprint: finding.fingerprint.clone(),
            asset_ids: finding.asset_ids.clone(),
            engine_ids: vec![BUILT_IN_LOCALHOST_TCP_ENGINE_ID.into()],
            severity: finding.severity.clone(),
            confidence: finding.confidence.clone(),
            evidence_hashes: finding
                .evidence
                .iter()
                .map(|evidence| evidence.artifact_sha256.clone())
                .collect(),
            observed_at,
            finding_snapshot: Some(finding.clone()),
        }
    }

    #[test]
    fn run_not_found_is_the_only_construction_error() {
        let case = empty_case();
        assert_eq!(
            build_beginner_master_report(&case, "missing").unwrap_err(),
            BeginnerReportError::RunNotFound {
                run_id: "missing".into()
            }
        );
    }

    #[test]
    fn exclusions_are_explicit_and_do_not_disappear() {
        let mut case = localhost_case(
            LocalhostTcpOutcome::Reachable,
            EngineRunStatus::Completed,
            true,
        );
        case.coverage.push(CoverageEntry {
            id: "coverage-1".into(),
            scope_key: "optional-cloud".into(),
            label: "Optional cloud account".into(),
            source_kind: SourceKind::AwsOrganization,
            asset_id: None,
            status: CoverageStatus::NotApplicable,
            explanation: "The user deliberately excluded this source area.".into(),
            last_run_id: Some("run-1".into()),
            observed_at: Some(instant(15)),
        });
        let report = build_beginner_master_report(&case, "run-1").unwrap();
        assert_eq!(report.state.summary, BeginnerReportSummary::Partial);
        assert!(
            report
                .coverage_gaps
                .iter()
                .any(|gap| gap.kind == CoverageGapKind::Excluded)
        );
    }

    #[test]
    fn selected_run_time_ignores_later_unrelated_case_update() {
        let mut case = localhost_case(
            LocalhostTcpOutcome::Reachable,
            EngineRunStatus::Completed,
            true,
        );
        case.updated_at = instant(10_000);
        case.raw_artifacts.push(RawArtifact {
            id: "artifact".into(),
            case_id: case.id.clone(),
            run_id: "run-1".into(),
            engine_run_id: "task-1".into(),
            relative_path: "raw/test.json".into(),
            media_type: "application/json".into(),
            sha256: "hash".into(),
            byte_length: 1,
            created_at: instant(19),
            contains_sensitive_data: false,
        });
        let report = build_beginner_master_report(&case, "run-1").unwrap();
        assert_eq!(report.state.last_durable_update, instant(20));
        assert_eq!(
            report.technical_details.tasks[0].evidence_sha256,
            vec!["hash"]
        );
    }
}
