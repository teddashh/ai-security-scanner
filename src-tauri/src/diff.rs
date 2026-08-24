use crate::domain::{
    AssessmentCase, EngineRunStatus, FindingDiff, FindingDiffStatus, FindingObservation, Id,
    ScanRun, Severity, VerificationComparison, new_id,
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
        .collect();

    Ok(VerificationComparison {
        id: new_id(),
        case_id: case.id.clone(),
        baseline_run_id: baseline_run_id.into(),
        current_run_id: current_run_id.into(),
        created_at,
        diffs,
    })
}

#[derive(Debug, Clone)]
struct AggregatedObservation {
    finding_id: Id,
    asset_ids: BTreeSet<Id>,
    engine_ids: BTreeSet<String>,
    severity: Severity,
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
            })
            .or_insert_with(|| AggregatedObservation {
                finding_id: observation.finding_id.clone(),
                asset_ids: observation.asset_ids.iter().cloned().collect(),
                engine_ids: observation.engine_ids.iter().cloned().collect(),
                severity: observation.severity.clone(),
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
    let (status, explanation) = match (baseline, current) {
        (Some(baseline), Some(current)) => {
            let gaps = coverage_gaps(current_run, &baseline.engine_ids, &baseline.asset_ids);
            if !gaps.is_empty() {
                (
                    FindingDiffStatus::UnableToVerify,
                    format!(
                        "The finding was observed again, but the baseline coordinates were not fully reverified: {}.",
                        gaps.join(", ")
                    ),
                )
            } else {
                let mut changes = Vec::new();
                if baseline.severity != current.severity {
                    changes.push(format!(
                        "severity changed from {} to {}",
                        severity_name(&baseline.severity),
                        severity_name(&current.severity)
                    ));
                }
                if baseline.evidence_hashes != current.evidence_hashes {
                    changes.push("evidence changed".into());
                }
                if baseline.asset_ids != current.asset_ids {
                    changes.push("affected assets changed".into());
                }
                if baseline.engine_ids != current.engine_ids {
                    changes.push("observing engines changed".into());
                }

                if changes.is_empty() {
                    (
                        FindingDiffStatus::StillPresent,
                        "The same fingerprint, severity, assets, engines, and evidence were observed again.".into(),
                    )
                } else {
                    (
                        FindingDiffStatus::Changed,
                        format!(
                            "The finding remains observable, but {}.",
                            changes.join("; ")
                        ),
                    )
                }
            }
        }
        (Some(baseline), None) => {
            let gaps = coverage_gaps(current_run, &baseline.engine_ids, &baseline.asset_ids);
            if gaps.is_empty() {
                (
                    FindingDiffStatus::Resolved,
                    "The current run completed the original engine-and-asset coordinates and did not reproduce the fingerprint.".into(),
                )
            } else {
                (
                    FindingDiffStatus::UnableToVerify,
                    format!(
                        "The fingerprint was not observed, but resolution cannot be claimed because these current-run coordinates were unavailable: {}.",
                        gaps.join(", ")
                    ),
                )
            }
        }
        (None, Some(current)) => {
            let gaps = coverage_gaps(baseline_run, &current.engine_ids, &current.asset_ids);
            if gaps.is_empty() {
                (
                    FindingDiffStatus::NewlyObserved,
                    "The baseline completed the same engine-and-asset coordinates without this fingerprint; the current run observed it.".into(),
                )
            } else {
                (
                    FindingDiffStatus::UnableToVerify,
                    format!(
                        "The fingerprint appears in the current run, but it cannot be called new because these baseline coordinates were unavailable: {}.",
                        gaps.join(", ")
                    ),
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
    }
}

fn coverage_gaps(
    run: &ScanRun,
    engine_ids: &BTreeSet<String>,
    asset_ids: &BTreeSet<Id>,
) -> Vec<String> {
    if engine_ids.is_empty() {
        return vec!["observation has no originating engine".into()];
    }

    let mut gaps = Vec::new();
    if asset_ids.is_empty() {
        for engine_id in engine_ids {
            let completed = run.engine_runs.iter().any(|engine_run| {
                engine_run.engine_id == *engine_id
                    && engine_run.status == EngineRunStatus::Completed
            });
            if !completed {
                gaps.push(format!("engine={engine_id}, asset=<global>"));
            }
        }
        return gaps;
    }

    for engine_id in engine_ids {
        for asset_id in asset_ids {
            let completed = run.engine_runs.iter().any(|engine_run| {
                engine_run.engine_id == *engine_id
                    && engine_run.status == EngineRunStatus::Completed
                    && engine_run.asset_ids.iter().any(|id| id == asset_id)
            });
            if !completed {
                gaps.push(format!("engine={engine_id}, asset={asset_id}"));
            }
        }
    }
    gaps
}

fn severity_name(severity: &Severity) -> &'static str {
    match severity {
        Severity::Informational => "informational",
        Severity::Low => "low",
        Severity::Medium => "medium",
        Severity::High => "high",
        Severity::Critical => "critical",
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::domain::{DataClass, EngineRun, FindingObservation, OrganizationProfile, ScanRun};
    use chrono::TimeZone;

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
            knowledge_cutoff: time,
            scope_grant_ids: vec![],
            engine_runs: vec![engine_run(id, EngineRunStatus::Completed)],
        }
    }

    fn engine_run(run_id: &str, status: EngineRunStatus) -> EngineRun {
        EngineRun {
            id: format!("engine-run-{run_id}"),
            scan_run_id: run_id.into(),
            engine_id: "engine-a".into(),
            asset_ids: vec!["asset-a".into()],
            status,
            progress_percent: 100,
            phase: "complete".into(),
            started_at: None,
            finished_at: None,
            resume_token: None,
            engine_version: Some("1.0.0".into()),
            image_digest: None,
            rule_version: Some("2026.08".into()),
            adapter_version: "1".into(),
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
        }
    }

    #[test]
    fn distinguishes_resolved_present_new_and_changed() {
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
}
