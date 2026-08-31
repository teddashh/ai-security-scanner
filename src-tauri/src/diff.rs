use crate::domain::{
    AssessmentCase, Confidence, EngineRun, EngineRunStatus, FindingDiff, FindingDiffReason,
    FindingDiffReasonCode, FindingDiffStatus, FindingObservation, Id, KnowledgeInputKind,
    KnowledgePinState, ScanRun, Severity, VerificationComparison, new_id,
};
use crate::error::{AppError, AppResult};
use chrono::{DateTime, Utc};
use std::collections::{BTreeMap, BTreeSet};

/// Compare the observations from two runs in the same case.
///
/// A missing observation is only called resolved/new when the other run completed
/// the same engine-and-asset coordinates. Partial, failed, cancelled, and absent
/// engine runs are deliberately treated as unavailable evidence.
pub fn compare_case_runs(
    case: &AssessmentCase,
    baseline_run_id: &str,
    current_run_id: &str,
) -> AppResult<VerificationComparison> {
    compare_case_runs_at(case, baseline_run_id, current_run_id, Utc::now())
}

/// Timestamp-injectable variant used by deterministic callers and tests.
pub fn compare_case_runs_at(
    case: &AssessmentCase,
    baseline_run_id: &str,
    current_run_id: &str,
    created_at: DateTime<Utc>,
) -> AppResult<VerificationComparison> {
    if baseline_run_id == current_run_id {
        return Err(AppError::InvalidRequest(
            "baseline and current run must be different".into(),
        ));
    }

    let baseline_run = case
        .scan_runs
        .iter()
        .find(|run| run.id == baseline_run_id)
        .ok_or_else(|| {
            AppError::InvalidRequest(format!("baseline run not found: {baseline_run_id}"))
        })?;
    let current_run = case
        .scan_runs
        .iter()
        .find(|run| run.id == current_run_id)
        .ok_or_else(|| {
            AppError::InvalidRequest(format!("current run not found: {current_run_id}"))
        })?;

    if baseline_run.case_id != case.id || current_run.case_id != case.id {
        return Err(AppError::InvalidRequest(
            "both runs must belong to the selected case".into(),
        ));
    }

    let baseline = aggregate_observations(
        case.finding_observations
            .iter()
            .filter(|observation| observation.run_id == baseline_run_id),
    );
    let current = aggregate_observations(
        case.finding_observations
            .iter()
            .filter(|observation| observation.run_id == current_run_id),
    );

    let fingerprints = baseline
        .keys()
        .chain(current.keys())
        .cloned()
        .collect::<BTreeSet<_>>();

    let diffs = fingerprints
        .into_iter()
        .map(|fingerprint| {
            compare_fingerprint(
                &fingerprint,
                baseline.get(&fingerprint),
                current.get(&fingerprint),
                baseline_run,
                current_run,
            )
        })
        .collect::<Vec<_>>();

    let mut completeness_issues = run_completeness_issues(baseline_run, current_run);
    for diff in &diffs {
        if diff.status != FindingDiffStatus::UnableToVerify {
            continue;
        }
        if diff.reasons.is_empty() {
            push_unique_reason(
                &mut completeness_issues,
                reason(
                    FindingDiffReasonCode::ComparisonIdentityMissing,
                    None,
                    None,
                    format!(
                        "finding fingerprint {} could not be compared",
                        diff.fingerprint
                    ),
                ),
            );
        } else {
            for issue in &diff.reasons {
                push_unique_reason(&mut completeness_issues, issue.clone());
            }
        }
    }
    Ok(VerificationComparison {
        id: new_id(),
        case_id: case.id.clone(),
        baseline_run_id: baseline_run_id.into(),
        current_run_id: current_run_id.into(),
        created_at,
        diffs,
        complete: completeness_issues.is_empty(),
        completeness_issues,
    })
}

fn run_completeness_issues(
    baseline_run: &ScanRun,
    current_run: &ScanRun,
) -> Vec<FindingDiffReason> {
    let coordinates = |run: &ScanRun| {
        run.engine_runs
            .iter()
            .flat_map(|engine_run| {
                if engine_run.asset_ids.is_empty() {
                    vec![(engine_run.engine_id.clone(), None)]
                } else {
                    engine_run
                        .asset_ids
                        .iter()
                        .cloned()
                        .map(|asset_id| (engine_run.engine_id.clone(), Some(asset_id)))
                        .collect()
                }
            })
            .collect::<BTreeSet<_>>()
    };
    let baseline_coordinates = coordinates(baseline_run);
    let current_coordinates = coordinates(current_run);
    if baseline_coordinates.is_empty() && current_coordinates.is_empty() {
        return vec![reason(
            FindingDiffReasonCode::ComparisonIdentityMissing,
            None,
            None,
            "both runs lack planned engine/asset coordinates".into(),
        )];
    }

    let mut issues = Vec::new();
    for (engine_id, asset_id) in &baseline_coordinates {
        for issue in compare_coordinate(baseline_run, current_run, engine_id, asset_id.as_deref()) {
            push_unique_reason(&mut issues, issue);
        }
    }
    for (engine_id, asset_id) in &current_coordinates {
        for issue in compare_coordinate(current_run, baseline_run, engine_id, asset_id.as_deref()) {
            push_unique_reason(&mut issues, issue);
        }
    }
    issues
}

#[derive(Debug, Clone)]
struct AggregatedObservation {
    finding_id: Id,
    asset_ids: BTreeSet<Id>,
    engine_ids: BTreeSet<String>,
    severity: Severity,
    confidence: Confidence,
    evidence_hashes: BTreeSet<String>,
}

fn aggregate_observations<'a>(
    observations: impl Iterator<Item = &'a FindingObservation>,
) -> BTreeMap<String, AggregatedObservation> {
    let mut by_fingerprint = BTreeMap::<String, AggregatedObservation>::new();

    for observation in observations {
        by_fingerprint
            .entry(observation.fingerprint.clone())
            .and_modify(|aggregate| {
                if observation.finding_id < aggregate.finding_id {
                    aggregate.finding_id = observation.finding_id.clone();
                }
                aggregate
                    .asset_ids
                    .extend(observation.asset_ids.iter().cloned());
                aggregate
                    .engine_ids
                    .extend(observation.engine_ids.iter().cloned());
                aggregate
                    .evidence_hashes
                    .extend(observation.evidence_hashes.iter().cloned());
                if observation.severity > aggregate.severity {
                    aggregate.severity = observation.severity.clone();
                }
                if observation.confidence > aggregate.confidence {
                    aggregate.confidence = observation.confidence.clone();
                }
            })
            .or_insert_with(|| AggregatedObservation {
                finding_id: observation.finding_id.clone(),
                asset_ids: observation.asset_ids.iter().cloned().collect(),
                engine_ids: observation.engine_ids.iter().cloned().collect(),
                severity: observation.severity.clone(),
                confidence: observation.confidence.clone(),
                evidence_hashes: observation.evidence_hashes.iter().cloned().collect(),
            });
    }

    by_fingerprint
}

fn compare_fingerprint(
    fingerprint: &str,
    baseline: Option<&AggregatedObservation>,
    current: Option<&AggregatedObservation>,
    baseline_run: &ScanRun,
    current_run: &ScanRun,
) -> FindingDiff {
    let (status, explanation, reasons) = match (baseline, current) {
        (Some(baseline), Some(current)) => {
            let mut comparability_issues = coordinate_comparability_issues(
                baseline_run,
                current_run,
                &baseline.engine_ids,
                &baseline.asset_ids,
            );
            for reason in coordinate_comparability_issues(
                current_run,
                baseline_run,
                &current.engine_ids,
                &current.asset_ids,
            ) {
                push_unique_reason(&mut comparability_issues, reason);
            }
            if !comparability_issues.is_empty() {
                (
                    FindingDiffStatus::UnableToVerify,
                    format!(
                        "The finding was observed in both runs, but its coordinates are not comparable: {}.",
                        reason_details(&comparability_issues)
                    ),
                    comparability_issues,
                )
            } else {
                let mut changes = Vec::<FindingDiffReason>::new();
                if baseline.severity != current.severity {
                    changes.push(reason(
                        FindingDiffReasonCode::SeverityChanged,
                        None,
                        None,
                        format!(
                            "severity changed from {} to {}",
                            severity_name(&baseline.severity),
                            severity_name(&current.severity)
                        ),
                    ));
                }
                if baseline.evidence_hashes != current.evidence_hashes {
                    changes.push(reason(
                        FindingDiffReasonCode::EvidenceChanged,
                        None,
                        None,
                        "evidence hashes changed".into(),
                    ));
                }
                if baseline.confidence != current.confidence {
                    changes.push(reason(
                        FindingDiffReasonCode::ConfidenceChanged,
                        None,
                        None,
                        format!(
                            "confidence changed from {} to {}",
                            confidence_name(&baseline.confidence),
                            confidence_name(&current.confidence)
                        ),
                    ));
                }
                if baseline.asset_ids != current.asset_ids {
                    changes.push(reason(
                        FindingDiffReasonCode::AffectedAssetsChanged,
                        None,
                        None,
                        "affected assets changed".into(),
                    ));
                }
                if baseline.engine_ids != current.engine_ids {
                    changes.push(reason(
                        FindingDiffReasonCode::ObservingEnginesChanged,
                        None,
                        None,
                        "observing engines changed".into(),
                    ));
                }

                if changes.is_empty() {
                    (
                        FindingDiffStatus::StillPresent,
                        "The same fingerprint, severity, confidence, assets, engines, and evidence were observed again.".into(),
                        changes,
                    )
                } else {
                    (
                        FindingDiffStatus::Changed,
                        format!(
                            "The finding remains observable, but {}.",
                            reason_details(&changes)
                        ),
                        changes,
                    )
                }
            }
        }
        (Some(baseline), None) => {
            let issues = coordinate_comparability_issues(
                baseline_run,
                current_run,
                &baseline.engine_ids,
                &baseline.asset_ids,
            );
            if issues.is_empty() {
                (
                    FindingDiffStatus::Resolved,
                    "The current run completed an exactly comparable release, knowledge, mapping, scope, and target contract for the original coordinates and did not reproduce the fingerprint.".into(),
                    issues,
                )
            } else {
                (
                    FindingDiffStatus::UnableToVerify,
                    format!(
                        "The fingerprint was not observed, but resolution cannot be claimed because the current-run coordinates are not comparable: {}.",
                        reason_details(&issues)
                    ),
                    issues,
                )
            }
        }
        (None, Some(current)) => {
            let issues = coordinate_comparability_issues(
                current_run,
                baseline_run,
                &current.engine_ids,
                &current.asset_ids,
            );
            if issues.is_empty() {
                (
                    FindingDiffStatus::NewlyObserved,
                    "The baseline completed an exactly comparable release, knowledge, mapping, scope, and target contract without this fingerprint; the current run observed it.".into(),
                    issues,
                )
            } else {
                (
                    FindingDiffStatus::UnableToVerify,
                    format!(
                        "The fingerprint appears in the current run, but it cannot be called new because the baseline coordinates are not comparable: {}.",
                        reason_details(&issues)
                    ),
                    issues,
                )
            }
        }
        (None, None) => unreachable!("fingerprints are taken from the union of both maps"),
    };

    FindingDiff {
        fingerprint: fingerprint.into(),
        baseline_finding_id: baseline.map(|observation| observation.finding_id.clone()),
        current_finding_id: current.map(|observation| observation.finding_id.clone()),
        status,
        explanation,
        baseline_severity: baseline.map(|observation| observation.severity.clone()),
        current_severity: current.map(|observation| observation.severity.clone()),
        evidence_changed: baseline
            .zip(current)
            .is_some_and(|(baseline, current)| baseline.evidence_hashes != current.evidence_hashes),
        reasons,
    }
}

/// Adapter/fingerprint changes are deliberately incomparable unless a future
/// release adds an explicit, reviewed migration tuple here. An empty table is
/// safer than inferring compatibility from a shared fingerprint string.
const APPROVED_FINGERPRINT_MIGRATIONS: &[(&str, &str, &str, &str, &str)] = &[];

fn coordinate_comparability_issues(
    reference_run: &ScanRun,
    candidate_run: &ScanRun,
    engine_ids: &BTreeSet<String>,
    asset_ids: &BTreeSet<Id>,
) -> Vec<FindingDiffReason> {
    if engine_ids.is_empty() {
        return vec![reason(
            FindingDiffReasonCode::ComparisonIdentityMissing,
            None,
            None,
            "observation has no originating engine".into(),
        )];
    }

    let mut issues = Vec::new();
    if asset_ids.is_empty() {
        for engine_id in engine_ids {
            for issue in compare_coordinate(reference_run, candidate_run, engine_id, None) {
                push_unique_reason(&mut issues, issue);
            }
        }
        return issues;
    }

    for engine_id in engine_ids {
        for asset_id in asset_ids {
            for issue in compare_coordinate(
                reference_run,
                candidate_run,
                engine_id,
                Some(asset_id.as_str()),
            ) {
                push_unique_reason(&mut issues, issue);
            }
        }
    }
    issues
}

fn compare_coordinate(
    reference_run: &ScanRun,
    candidate_run: &ScanRun,
    engine_id: &str,
    asset_id: Option<&str>,
) -> Vec<FindingDiffReason> {
    let coordinate = asset_id.unwrap_or("<global>");
    let reference = completed_coordinate_runs(reference_run, engine_id, asset_id);
    if reference.is_empty() {
        return vec![reason(
            FindingDiffReasonCode::CoordinateNotCompleted,
            Some(engine_id),
            asset_id,
            format!("reference engine={engine_id}, asset={coordinate} did not complete"),
        )];
    }
    let candidate = completed_coordinate_runs(candidate_run, engine_id, asset_id);
    if candidate.is_empty() {
        return vec![reason(
            FindingDiffReasonCode::CoordinateNotCompleted,
            Some(engine_id),
            asset_id,
            format!("candidate engine={engine_id}, asset={coordinate} did not complete"),
        )];
    }

    let mut run_history_issues = Vec::new();
    if let Some(issue) = scope_history_issue(reference_run, "reference", engine_id, asset_id) {
        run_history_issues.push(issue);
    }
    if let Some(issue) = scope_history_issue(candidate_run, "candidate", engine_id, asset_id) {
        push_unique_reason(&mut run_history_issues, issue);
    }
    if !run_history_issues.is_empty() {
        return run_history_issues;
    }

    let mut closest_issues: Option<Vec<FindingDiffReason>> = None;
    for reference_engine in &reference {
        for candidate_engine in &candidate {
            let pair_issues =
                engine_identity_issues(reference_engine, candidate_engine, engine_id, asset_id);
            if pair_issues.is_empty() {
                return Vec::new();
            }
            if closest_issues
                .as_ref()
                .is_none_or(|closest| pair_issues.len() < closest.len())
            {
                closest_issues = Some(pair_issues);
            }
        }
    }
    closest_issues.unwrap_or_else(|| {
        vec![reason(
            FindingDiffReasonCode::ComparisonIdentityMissing,
            Some(engine_id),
            asset_id,
            format!("engine={engine_id}, asset={coordinate} has no comparable execution identity"),
        )]
    })
}

fn completed_coordinate_runs<'a>(
    run: &'a ScanRun,
    engine_id: &str,
    asset_id: Option<&str>,
) -> Vec<&'a EngineRun> {
    let mut matching = run
        .engine_runs
        .iter()
        .filter(|engine_run| {
            engine_run.engine_id == engine_id
                && asset_id.is_none_or(|asset_id| {
                    engine_run
                        .asset_ids
                        .iter()
                        .any(|candidate| candidate == asset_id)
                })
                && engine_run.status == EngineRunStatus::Completed
        })
        .collect::<Vec<_>>();
    matching.sort_by(|left, right| left.id.cmp(&right.id));
    matching
}

fn scope_history_issue(
    run: &ScanRun,
    side: &str,
    engine_id: &str,
    asset_id: Option<&str>,
) -> Option<FindingDiffReason> {
    let frozen_ids = run
        .scope_grant_snapshots
        .iter()
        .map(|grant| grant.id.as_str())
        .collect::<BTreeSet<_>>();
    let referenced_ids = run
        .scope_grant_ids
        .iter()
        .map(String::as_str)
        .collect::<BTreeSet<_>>();
    if referenced_ids.is_empty()
        || frozen_ids.is_empty()
        || frozen_ids.len() != run.scope_grant_snapshots.len()
        || referenced_ids.len() != run.scope_grant_ids.len()
        || frozen_ids != referenced_ids
    {
        return Some(reason(
            FindingDiffReasonCode::ComparisonIdentityMissing,
            Some(engine_id),
            asset_id,
            format!(
                "{side} run lacks a complete immutable scope-grant snapshot for engine={engine_id}, asset={}",
                asset_id.unwrap_or("<global>")
            ),
        ));
    }
    None
}

fn engine_identity_issues(
    baseline: &EngineRun,
    current: &EngineRun,
    engine_id: &str,
    asset_id: Option<&str>,
) -> Vec<FindingDiffReason> {
    let mut issues = Vec::new();
    let baseline_missing = missing_identity_fields(baseline);
    let current_missing = missing_identity_fields(current);
    if !baseline_missing.is_empty() || !current_missing.is_empty() {
        let mut details = Vec::new();
        if !baseline_missing.is_empty() {
            details.push(format!("reference missing {}", baseline_missing.join(", ")));
        }
        if !current_missing.is_empty() {
            details.push(format!("candidate missing {}", current_missing.join(", ")));
        }
        issues.push(reason(
            FindingDiffReasonCode::ComparisonIdentityMissing,
            Some(engine_id),
            asset_id,
            details.join("; "),
        ));
        return issues;
    }

    compare_identity_field(
        &mut issues,
        baseline.scope_contract_sha256.as_ref(),
        current.scope_contract_sha256.as_ref(),
        FindingDiffReasonCode::ScopeContractChanged,
        engine_id,
        asset_id,
        "scope, permission, or target contract changed",
    );
    compare_identity_field(
        &mut issues,
        baseline.manifest_schema_version.as_ref(),
        current.manifest_schema_version.as_ref(),
        FindingDiffReasonCode::ManifestSchemaChanged,
        engine_id,
        asset_id,
        "manifest schema changed",
    );
    compare_identity_field(
        &mut issues,
        baseline.engine_version.as_ref(),
        current.engine_version.as_ref(),
        FindingDiffReasonCode::EngineVersionChanged,
        engine_id,
        asset_id,
        "engine version changed",
    );
    if baseline.image_digest != current.image_digest
        || baseline.image_repository != current.image_repository
    {
        issues.push(reason(
            FindingDiffReasonCode::ImageChanged,
            Some(engine_id),
            asset_id,
            "image repository or immutable digest changed".into(),
        ));
    }
    if baseline.rule_version != current.rule_version {
        issues.push(reason(
            FindingDiffReasonCode::RuleVersionChanged,
            Some(engine_id),
            asset_id,
            "rule or template version changed".into(),
        ));
    }
    if baseline.knowledge_input != current.knowledge_input {
        issues.push(reason(
            FindingDiffReasonCode::KnowledgeInputChanged,
            Some(engine_id),
            asset_id,
            "database, feed, live source, or knowledge window changed".into(),
        ));
    }

    let adapter_migrated = approved_fingerprint_migration(baseline, current);
    if baseline.adapter_version != current.adapter_version && !adapter_migrated {
        issues.push(reason(
            FindingDiffReasonCode::AdapterVersionChanged,
            Some(engine_id),
            asset_id,
            "adapter version changed without an explicit fingerprint migration".into(),
        ));
    }
    compare_identity_field(
        &mut issues,
        baseline.source_revision.as_ref(),
        current.source_revision.as_ref(),
        FindingDiffReasonCode::SourceRevisionChanged,
        engine_id,
        asset_id,
        "source revision changed",
    );
    compare_identity_field(
        &mut issues,
        baseline.repository_url.as_ref(),
        current.repository_url.as_ref(),
        FindingDiffReasonCode::RepositoryChanged,
        engine_id,
        asset_id,
        "source repository changed",
    );
    if baseline.distribution_mode != current.distribution_mode {
        issues.push(reason(
            FindingDiffReasonCode::DistributionModeChanged,
            Some(engine_id),
            asset_id,
            "distribution mode changed".into(),
        ));
    }
    compare_identity_field(
        &mut issues,
        baseline.command_sha256.as_ref(),
        current.command_sha256.as_ref(),
        FindingDiffReasonCode::CommandChanged,
        engine_id,
        asset_id,
        "engine command contract changed",
    );
    if baseline.mapping_version != current.mapping_version
        || baseline.mapping_provenance != current.mapping_provenance
    {
        issues.push(reason(
            FindingDiffReasonCode::MappingVersionChanged,
            Some(engine_id),
            asset_id,
            "control-mapping catalog version or canonical provenance changed".into(),
        ));
    }
    if baseline.fingerprint_schema_version != current.fingerprint_schema_version
        && !adapter_migrated
    {
        issues.push(reason(
            FindingDiffReasonCode::FingerprintSchemaChanged,
            Some(engine_id),
            asset_id,
            "fingerprint schema changed without an explicit migration".into(),
        ));
    }
    issues
}

fn missing_identity_fields(engine_run: &EngineRun) -> Vec<&'static str> {
    let mut missing = Vec::new();
    let present = |value: Option<&str>| value.is_some_and(|value| !value.trim().is_empty());
    if !present(engine_run.manifest_schema_version.as_deref()) {
        missing.push("manifest_schema_version");
    }
    if !present(engine_run.engine_version.as_deref()) {
        missing.push("engine_version");
    }
    if !engine_run
        .image_digest
        .as_deref()
        .is_some_and(valid_sha256_digest)
    {
        missing.push("image_digest");
    }
    if !present(engine_run.image_repository.as_deref()) {
        missing.push("image_repository");
    }
    if !present(engine_run.source_revision.as_deref()) {
        missing.push("source_revision");
    }
    if !present(engine_run.repository_url.as_deref()) {
        missing.push("repository_url");
    }
    if engine_run.distribution_mode.is_none() {
        missing.push("distribution_mode");
    }
    if !engine_run
        .command_sha256
        .as_deref()
        .is_some_and(valid_sha256_hex)
    {
        missing.push("command_sha256");
    }
    if !engine_run
        .knowledge_input
        .as_ref()
        .is_some_and(knowledge_identity_complete)
    {
        missing.push("knowledge_input");
    }
    if !engine_run
        .scope_contract_sha256
        .as_deref()
        .is_some_and(valid_sha256_hex)
    {
        missing.push("scope_contract_sha256");
    }
    if !present(engine_run.mapping_version.as_deref()) {
        missing.push("mapping_version");
    }
    if engine_run.mapping_provenance.is_none() {
        missing.push("mapping_provenance");
    }
    if !present(engine_run.fingerprint_schema_version.as_deref()) {
        missing.push("fingerprint_schema_version");
    }
    if engine_run.adapter_version.trim().is_empty() {
        missing.push("adapter_version");
    }
    missing
}

fn knowledge_identity_complete(input: &crate::domain::EngineKnowledgeInput) -> bool {
    let version_present = input
        .version
        .as_deref()
        .is_some_and(|version| !version.trim().is_empty());
    let pin_is_complete = match input.kind {
        KnowledgeInputKind::ExternalPinned | KnowledgeInputKind::ExternalPinRequired => {
            input.pin_state == KnowledgePinState::PinnedOrNotApplicable && version_present
        }
        KnowledgeInputKind::RuntimeBound => {
            input.pin_state == KnowledgePinState::RuntimeBound && version_present
        }
        KnowledgeInputKind::RuntimeLive => input.pin_state == KnowledgePinState::RuntimeLive,
        KnowledgeInputKind::Embedded | KnowledgeInputKind::NotApplicable => {
            input.pin_state == KnowledgePinState::PinnedOrNotApplicable
        }
    };
    !input.identifier.trim().is_empty()
        && input
            .knowledge_date
            .as_deref()
            .is_some_and(|date| !date.trim().is_empty())
        && input
            .support_until
            .as_deref()
            .is_some_and(|date| !date.trim().is_empty())
        && pin_is_complete
}

fn compare_identity_field<T: PartialEq>(
    issues: &mut Vec<FindingDiffReason>,
    baseline: Option<&T>,
    current: Option<&T>,
    code: FindingDiffReasonCode,
    engine_id: &str,
    asset_id: Option<&str>,
    detail: &str,
) {
    if baseline != current {
        issues.push(reason(code, Some(engine_id), asset_id, detail.to_owned()));
    }
}

fn approved_fingerprint_migration(baseline: &EngineRun, current: &EngineRun) -> bool {
    APPROVED_FINGERPRINT_MIGRATIONS.iter().any(
        |(engine, from_adapter, from_schema, to_adapter, to_schema)| {
            *engine == baseline.engine_id
                && baseline.engine_id == current.engine_id
                && *from_adapter == baseline.adapter_version
                && baseline.fingerprint_schema_version.as_deref() == Some(*from_schema)
                && *to_adapter == current.adapter_version
                && current.fingerprint_schema_version.as_deref() == Some(*to_schema)
        },
    )
}

fn reason(
    code: FindingDiffReasonCode,
    engine_id: Option<&str>,
    asset_id: Option<&str>,
    detail: String,
) -> FindingDiffReason {
    FindingDiffReason {
        code,
        engine_id: engine_id.map(str::to_owned),
        asset_id: asset_id.map(str::to_owned),
        detail,
    }
}

fn push_unique_reason(reasons: &mut Vec<FindingDiffReason>, reason: FindingDiffReason) {
    if !reasons.contains(&reason) {
        reasons.push(reason);
    }
}

fn reason_details(reasons: &[FindingDiffReason]) -> String {
    reasons
        .iter()
        .map(|reason| reason.detail.as_str())
        .collect::<Vec<_>>()
        .join("; ")
}

fn valid_sha256_hex(value: &str) -> bool {
    value.len() == 64 && value.chars().all(|character| character.is_ascii_hexdigit())
}

fn valid_sha256_digest(value: &str) -> bool {
    value.strip_prefix("sha256:").is_some_and(valid_sha256_hex)
}

fn severity_name(severity: &Severity) -> &'static str {
    match severity {
        Severity::Unknown => "unknown",
        Severity::Informational => "informational",
        Severity::Low => "low",
        Severity::Medium => "medium",
        Severity::High => "high",
        Severity::Critical => "critical",
    }
}

fn confidence_name(confidence: &Confidence) -> &'static str {
    match confidence {
        Confidence::Low => "low",
        Confidence::Medium => "medium",
        Confidence::High => "high",
        Confidence::Confirmed => "confirmed",
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::domain::{
        DataClass, DistributionMode, EngineKnowledgeInput, EngineRun, FindingObservation,
        KnowledgeInputKind, KnowledgePinState, OrganizationProfile, ScanPermission, ScanRun,
        ScopeGrant,
    };
    use chrono::TimeZone;

    #[test]
    fn comparison_preserves_unknown_severity_name() {
        assert_eq!(severity_name(&Severity::Unknown), "unknown");
    }

    fn fixture() -> AssessmentCase {
        let mut case = AssessmentCase::new(
            "Comparison".into(),
            OrganizationProfile {
                organization_name: "Example".into(),
                employee_range: "1-10".into(),
                data_classes: vec![DataClass::General],
                notes: None,
            },
        );
        case.id = "case-1".into();
        case.scan_runs = vec![run("baseline"), run("current")];
        case
    }

    fn run(id: &str) -> ScanRun {
        let time = Utc.with_ymd_and_hms(2026, 8, 24, 12, 0, 0).unwrap();
        ScanRun {
            id: id.into(),
            case_id: "case-1".into(),
            sequence: if id == "baseline" { 1 } else { 2 },
            created_at: time,
            completed_at: Some(time),
            request_outcome: None,
            knowledge_cutoff: time,
            ai_system_applicable: false,
            ai_system_applicability: Default::default(),
            ai_generated_artifact: Default::default(),
            verification_baseline_run_id: None,
            scope_grant_ids: vec!["grant-a".into()],
            scope_grant_snapshots: vec![ScopeGrant {
                id: "grant-a".into(),
                asset_id: "asset-a".into(),
                permission: ScanPermission::ConfigurationRead,
                confirmed_by: "test operator".into(),
                confirmed_at: time,
                expires_at: None,
                authorization_reference: None,
                notes: None,
                external_scope: None,
            }],
            engine_admission_issues: Vec::new(),
            engine_runs: vec![engine_run(id, EngineRunStatus::Completed)],
        }
    }

    fn engine_run(run_id: &str, status: EngineRunStatus) -> EngineRun {
        EngineRun {
            id: format!("engine-run-{run_id}"),
            scan_run_id: run_id.into(),
            engine_id: "engine-a".into(),
            task_kind: Default::default(),
            localhost_tcp_observation: None,
            asset_ids: vec!["asset-a".into()],
            status,
            progress_percent: 100,
            phase: "complete".into(),
            started_at: None,
            finished_at: None,
            resume_token: None,
            last_execution_report_sha256: None,
            engine_version: Some("1.0.0".into()),
            image_digest: Some(format!("sha256:{}", "a".repeat(64))),
            rule_version: Some("2026.08".into()),
            adapter_version: "1".into(),
            manifest_schema_version: Some("1".into()),
            source_revision: Some("b".repeat(40)),
            repository_url: Some("https://example.test/engine".into()),
            distribution_mode: Some(DistributionMode::PullPinnedImage),
            image_repository: Some("ghcr.io/example/engine".into()),
            command_sha256: Some("c".repeat(64)),
            execution_timeout_seconds: None,
            knowledge_input: Some(EngineKnowledgeInput {
                kind: KnowledgeInputKind::Embedded,
                identifier: "embedded checks".into(),
                version: Some("2026.08".into()),
                acquisition_source: Some("https://example.test/engine".into()),
                pin_state: KnowledgePinState::PinnedOrNotApplicable,
                knowledge_date: Some("2026-08-24".into()),
                support_until: Some("2026-11-22".into()),
            }),
            scope_contract_sha256: Some("d".repeat(64)),
            naabu_work_plan: None,
            naabu_attempt_requests: Vec::new(),
            naabu_attempt_results: Vec::new(),
            mapping_version: Some("2026-08-24.1".into()),
            mapping_provenance: Some(crate::domain::ControlMappingProvenance {
                mapping_version: "2026-08-24.1".into(),
                reviewed_at: "2026-08-24".into(),
                review_process: "source_coordinate_and_rationale_review_v1".into(),
                catalog_sha256: "e".repeat(64),
            }),
            fingerprint_schema_version: Some("v1".into()),
            runtime_provider: None,
            runtime_version: None,
            runtime_security_options: None,
            exit_code: None,
            cleanup_removed: None,
            cleanup_detail: None,
            warnings: vec![],
            raw_artifact_ids: vec![],
            error_code: None,
            error_message: None,
        }
    }

    fn observation(
        run_id: &str,
        fingerprint: &str,
        severity: Severity,
        hash: &str,
    ) -> FindingObservation {
        FindingObservation {
            id: format!("observation-{run_id}-{fingerprint}"),
            run_id: run_id.into(),
            finding_id: format!("finding-{fingerprint}"),
            fingerprint: fingerprint.into(),
            asset_ids: vec!["asset-a".into()],
            engine_ids: vec!["engine-a".into()],
            severity,
            confidence: crate::domain::Confidence::High,
            evidence_hashes: vec![hash.into()],
            observed_at: Utc.with_ymd_and_hms(2026, 8, 24, 12, 0, 0).unwrap(),
            finding_snapshot: None,
        }
    }

    #[test]
    fn stable_identity_distinguishes_resolved_present_new_and_changed() {
        let mut case = fixture();
        case.finding_observations = vec![
            observation("baseline", "resolved", Severity::High, "a"),
            observation("baseline", "present", Severity::Medium, "b"),
            observation("current", "present", Severity::Medium, "b"),
            observation("baseline", "changed", Severity::Low, "c"),
            observation("current", "changed", Severity::High, "d"),
            observation("current", "new", Severity::Low, "e"),
        ];

        let comparison = compare_case_runs_at(
            &case,
            "baseline",
            "current",
            Utc.with_ymd_and_hms(2026, 8, 24, 13, 0, 0).unwrap(),
        )
        .unwrap();
        let statuses = comparison
            .diffs
            .iter()
            .map(|diff| (diff.fingerprint.as_str(), diff.status.clone()))
            .collect::<BTreeMap<_, _>>();

        assert_eq!(statuses["resolved"], FindingDiffStatus::Resolved);
        assert_eq!(statuses["present"], FindingDiffStatus::StillPresent);
        assert_eq!(statuses["changed"], FindingDiffStatus::Changed);
        assert_eq!(statuses["new"], FindingDiffStatus::NewlyObserved);

        let changed = comparison
            .diffs
            .iter()
            .find(|diff| diff.fingerprint == "changed")
            .unwrap();
        assert_eq!(changed.baseline_severity, Some(Severity::Low));
        assert_eq!(changed.current_severity, Some(Severity::High));
        assert!(changed.evidence_changed);
        assert!(
            changed
                .reasons
                .iter()
                .any(|reason| reason.code == FindingDiffReasonCode::SeverityChanged)
        );
    }

    #[test]
    fn incomplete_current_coordinate_is_unable_to_verify_not_resolved() {
        let mut case = fixture();
        case.scan_runs[1].engine_runs[0].status = EngineRunStatus::PartiallyCompleted;
        case.finding_observations = vec![observation(
            "baseline",
            "not-reproduced",
            Severity::High,
            "a",
        )];

        let comparison = compare_case_runs(&case, "baseline", "current").unwrap();
        assert_eq!(
            comparison.diffs[0].status,
            FindingDiffStatus::UnableToVerify
        );
        assert!(comparison.diffs[0].explanation.contains("engine=engine-a"));
        assert!(!comparison.complete);
        assert!(!comparison.completeness_issues.is_empty());
    }

    #[test]
    fn an_unidentifiable_legacy_observation_prevents_handoff_even_when_runs_completed() {
        let mut case = fixture();
        let mut legacy = observation("baseline", "legacy", Severity::High, "a");
        legacy.engine_ids.clear();
        case.finding_observations = vec![legacy];

        let comparison = compare_case_runs(&case, "baseline", "current").unwrap();

        assert_eq!(
            comparison.diffs[0].status,
            FindingDiffStatus::UnableToVerify
        );
        assert!(!comparison.complete);
        assert!(comparison.completeness_issues.iter().any(|issue| {
            issue.code == FindingDiffReasonCode::ComparisonIdentityMissing
                && issue.detail.contains("no originating engine")
        }));
    }

    #[test]
    fn zero_finding_runs_are_complete_only_when_all_coordinates_are_comparable() {
        let complete = fixture();
        let comparison = compare_case_runs(&complete, "baseline", "current").unwrap();
        assert!(comparison.diffs.is_empty());
        assert!(comparison.complete);
        assert!(comparison.completeness_issues.is_empty());

        for status in [
            EngineRunStatus::Failed,
            EngineRunStatus::NotExecuted,
            EngineRunStatus::PartiallyCompleted,
        ] {
            let mut incomplete = fixture();
            incomplete.scan_runs[1].engine_runs[0].status = status.clone();
            let comparison = compare_case_runs(&incomplete, "baseline", "current").unwrap();
            assert!(comparison.diffs.is_empty());
            assert!(!comparison.complete, "{status:?} must be incomplete");
            assert!(comparison.completeness_issues.iter().any(|issue| {
                issue.code == FindingDiffReasonCode::CoordinateNotCompleted
                    && issue.engine_id.as_deref() == Some("engine-a")
                    && issue.asset_id.as_deref() == Some("asset-a")
            }));
        }
    }

    #[test]
    fn repeated_observation_is_unavailable_when_original_coordinate_did_not_complete() {
        let mut case = fixture();
        case.scan_runs[1].engine_runs[0].status = EngineRunStatus::Failed;
        case.finding_observations = vec![
            observation("baseline", "same", Severity::High, "a"),
            observation("current", "same", Severity::High, "a"),
        ];

        let comparison = compare_case_runs(&case, "baseline", "current").unwrap();
        assert_eq!(
            comparison.diffs[0].status,
            FindingDiffStatus::UnableToVerify
        );
    }

    #[test]
    fn changed_does_not_imply_that_evidence_changed() {
        let mut case = fixture();
        case.finding_observations = vec![
            observation("baseline", "same", Severity::Medium, "same-hash"),
            observation("current", "same", Severity::High, "same-hash"),
        ];

        let comparison = compare_case_runs(&case, "baseline", "current").unwrap();
        let diff = &comparison.diffs[0];
        assert_eq!(diff.status, FindingDiffStatus::Changed);
        assert!(!diff.evidence_changed);
        assert_eq!(diff.baseline_severity, Some(Severity::Medium));
        assert_eq!(diff.current_severity, Some(Severity::High));
        assert_eq!(
            diff.reasons
                .iter()
                .map(|reason| reason.code.clone())
                .collect::<Vec<_>>(),
            vec![FindingDiffReasonCode::SeverityChanged]
        );
    }

    #[test]
    fn rule_change_is_unverifiable_not_resolved() {
        let mut case = fixture();
        case.scan_runs[1].engine_runs[0].rule_version = Some("2026.09".into());
        case.finding_observations = vec![observation(
            "baseline",
            "not-reproduced",
            Severity::High,
            "a",
        )];

        let comparison = compare_case_runs(&case, "baseline", "current").unwrap();
        let diff = &comparison.diffs[0];
        assert_eq!(diff.status, FindingDiffStatus::UnableToVerify);
        assert!(
            diff.reasons
                .iter()
                .any(|reason| reason.code == FindingDiffReasonCode::RuleVersionChanged)
        );
    }

    #[test]
    fn adapter_change_without_explicit_migration_is_unverifiable() {
        let mut case = fixture();
        case.scan_runs[1].engine_runs[0].adapter_version = "2".into();
        case.finding_observations = vec![
            observation("baseline", "same", Severity::High, "a"),
            observation("current", "same", Severity::High, "a"),
        ];

        let comparison = compare_case_runs(&case, "baseline", "current").unwrap();
        let diff = &comparison.diffs[0];
        assert_eq!(diff.status, FindingDiffStatus::UnableToVerify);
        assert!(diff.reasons.iter().any(|reason| {
            reason.code == FindingDiffReasonCode::AdapterVersionChanged
                && reason
                    .detail
                    .contains("without an explicit fingerprint migration")
        }));
    }

    #[test]
    fn database_or_feed_identity_change_is_unverifiable() {
        let mut case = fixture();
        case.scan_runs[1].engine_runs[0]
            .knowledge_input
            .as_mut()
            .unwrap()
            .version = Some("2026.09".into());
        case.finding_observations = vec![observation(
            "baseline",
            "not-reproduced",
            Severity::High,
            "a",
        )];

        let comparison = compare_case_runs(&case, "baseline", "current").unwrap();
        let diff = &comparison.diffs[0];
        assert_eq!(diff.status, FindingDiffStatus::UnableToVerify);
        assert!(
            diff.reasons
                .iter()
                .any(|reason| reason.code == FindingDiffReasonCode::KnowledgeInputChanged)
        );
    }

    #[test]
    fn mapping_and_fingerprint_schema_drift_are_unverifiable() {
        for (mapping, fingerprint, expected) in [
            (
                Some("2026-08-25.1"),
                Some("v1"),
                FindingDiffReasonCode::MappingVersionChanged,
            ),
            (
                Some("2026-08-24.1"),
                Some("v2"),
                FindingDiffReasonCode::FingerprintSchemaChanged,
            ),
        ] {
            let mut case = fixture();
            case.scan_runs[1].engine_runs[0].mapping_version = mapping.map(str::to_owned);
            case.scan_runs[1].engine_runs[0].fingerprint_schema_version =
                fingerprint.map(str::to_owned);
            case.finding_observations = vec![observation(
                "baseline",
                "not-reproduced",
                Severity::High,
                "a",
            )];

            let comparison = compare_case_runs(&case, "baseline", "current").unwrap();
            let diff = &comparison.diffs[0];
            assert_eq!(diff.status, FindingDiffStatus::UnableToVerify);
            assert!(diff.reasons.iter().any(|reason| reason.code == expected));
        }
    }

    #[test]
    fn legacy_missing_identity_is_unverifiable() {
        let mut case = fixture();
        case.scan_runs[0].engine_runs[0].scope_contract_sha256 = None;
        case.finding_observations = vec![observation(
            "baseline",
            "not-reproduced",
            Severity::High,
            "a",
        )];

        let comparison = compare_case_runs(&case, "baseline", "current").unwrap();
        let diff = &comparison.diffs[0];
        assert_eq!(diff.status, FindingDiffStatus::UnableToVerify);
        assert!(diff.reasons.iter().any(|reason| {
            reason.code == FindingDiffReasonCode::ComparisonIdentityMissing
                && reason.detail.contains("scope_contract_sha256")
        }));
    }

    #[test]
    fn changed_scope_contract_is_unverifiable_not_new_or_resolved() {
        let mut case = fixture();
        case.scan_runs[1].engine_runs[0].scope_contract_sha256 = Some("e".repeat(64));
        case.finding_observations = vec![observation(
            "baseline",
            "not-reproduced",
            Severity::High,
            "a",
        )];

        let comparison = compare_case_runs(&case, "baseline", "current").unwrap();
        let diff = &comparison.diffs[0];
        assert_eq!(diff.status, FindingDiffStatus::UnableToVerify);
        assert!(
            diff.reasons
                .iter()
                .any(|reason| reason.code == FindingDiffReasonCode::ScopeContractChanged)
        );
    }
}
