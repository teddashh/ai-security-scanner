//! Versioned, bounded coverage evidence for future multi-work-unit launchers.
//!
//! This module is deliberately inert: it does not run an engine, adapt an
//! artifact, schedule a retry, or change an [`crate::domain::EngineRun`]. It
//! only validates an append-only launcher-v2 journal against artifact metadata
//! already captured by the host. That separation lets a later orchestration
//! change retain completed work without treating stdout, an empty file, or a
//! process exit code as proof that a work unit was tested.

use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};
use thiserror::Error;

pub const LAUNCHER_V2_JOURNAL_SCHEMA_VERSION: u32 = 2;
pub const MAX_JOURNAL_BYTES: usize = 4 * 1024 * 1024;
pub const MAX_JOURNAL_LINE_BYTES: usize = 1024 * 1024;
pub const MAX_REQUESTED_WORK_UNITS: usize = 512;
pub const MAX_ATTEMPTS_PER_WORK_UNIT: u32 = 4;
/// One header plus one terminal outcome for every allowed attempt.
pub const MAX_JOURNAL_RECORDS: usize =
    1 + MAX_REQUESTED_WORK_UNITS * (MAX_ATTEMPTS_PER_WORK_UNIT as usize);
pub const MAX_CAPTURED_FINAL_ARTIFACTS: usize = MAX_REQUESTED_WORK_UNITS;
pub const MAX_OPAQUE_ID_BYTES: usize = 128;
pub const MAX_RELATIVE_ARTIFACT_PATH_BYTES: usize = 512;
pub const MAX_FINAL_ARTIFACT_BYTES: u64 = 64 * 1024 * 1024 * 1024;

const EMPTY_SHA256: &str = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";

#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum ExecutionCoverageError {
    #[error("launcher-v2 journal is empty")]
    Empty,
    #[error("launcher-v2 journal exceeds its {MAX_JOURNAL_BYTES}-byte limit")]
    JournalTooLarge,
    #[error("launcher-v2 journal is not a complete UTF-8 JSONL document")]
    InvalidEncoding,
    #[error("launcher-v2 journal record {record} exceeds its line-size limit")]
    LineTooLarge { record: usize },
    #[error("launcher-v2 journal exceeds its record-count limit")]
    TooManyRecords,
    #[error("launcher-v2 expected execution identity is invalid: {0}")]
    InvalidExpectedIdentity(String),
    #[error("launcher-v2 journal record {record} is invalid: {reason}")]
    InvalidRecord { record: usize, reason: String },
    #[error("launcher-v2 captured-artifact inventory is invalid: {0}")]
    InvalidCapturedArtifact(String),
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct RequestedWorkUnit {
    /// Opaque stable identity. Target names and addresses do not belong here.
    pub unit_id: String,
    /// Hash of the exact non-secret scope contract for this unit.
    pub scope_sha256: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
#[serde(deny_unknown_fields)]
pub struct FinalArtifactIdentity {
    pub engine_run_id: String,
    pub unit_id: String,
    pub scope_sha256: String,
    pub attempt: u32,
    pub relative_path: String,
    pub sha256: String,
    pub byte_length: u64,
}

/// Terminal truth for one attempt. These values describe coverage only; none
/// of them assert a finding or a security verdict.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum WorkUnitOutcome {
    TestedComplete,
    Failed,
    TimedOut,
    Cancelled,
    /// The attempt closed before the unit performed its test (for example, a
    /// unit-local prerequisite was unavailable). This explicit terminal value
    /// permits a later retry without mislabeling the attempt as a test failure.
    NotTested,
}

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct WorkUnitAttempt {
    pub attempt: u32,
    pub outcome: WorkUnitOutcome,
    pub final_artifact: Option<FinalArtifactIdentity>,
}

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct WorkUnitCoverage {
    pub unit_id: String,
    pub scope_sha256: String,
    pub outcome: WorkUnitOutcome,
    pub attempts: Vec<WorkUnitAttempt>,
}

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct ExecutionCoverageSummary {
    pub requested: usize,
    pub tested_complete: usize,
    pub failed: usize,
    pub timed_out: usize,
    pub cancelled: usize,
    pub not_tested: usize,
    /// True unless every requested work unit has exact completed evidence.
    pub partial: bool,
    /// True when at least one work unit produced usable completed evidence.
    pub has_usable_results: bool,
}

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct ValidatedExecutionCoverage {
    pub schema_version: u32,
    pub engine_run_id: String,
    pub work_units: Vec<WorkUnitCoverage>,
    pub summary: ExecutionCoverageSummary,
}

#[derive(Debug, Deserialize)]
#[serde(tag = "record_type", rename_all = "snake_case")]
enum JournalRecord {
    Header(HeaderRecord),
    AttemptFinished(AttemptFinishedRecord),
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct HeaderRecord {
    schema_version: u32,
    engine_run_id: String,
    requested_work_units: Vec<RequestedWorkUnit>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct AttemptFinishedRecord {
    unit_id: String,
    scope_sha256: String,
    attempt: u32,
    outcome: WorkUnitOutcome,
    #[serde(default)]
    final_artifact: Option<FinalArtifactIdentity>,
}

#[derive(Debug)]
struct WorkUnitState {
    requested: RequestedWorkUnit,
    attempts: Vec<WorkUnitAttempt>,
}

/// Parse and validate a complete launcher-v2 JSONL journal.
///
/// `expected_requested_work_units` is the authoritative host-frozen plan. The
/// launcher header must match it exactly, so a compromised or interrupted
/// launcher cannot omit work and make incomplete coverage look complete.
///
/// `captured_final_artifacts` must be the host-observed inventory intended for
/// this journal, not every runtime stream artifact. Every entry must match one
/// and only one `tested_complete` terminal record, and every such record must
/// have a matching captured entry. This makes an empty result file useful
/// evidence only when its empty-file hash, size, portable relative path, scope,
/// run, unit, and attempt all match a durable completion record.
pub fn parse_launcher_v2_journal(
    bytes: &[u8],
    expected_engine_run_id: &str,
    expected_requested_work_units: &[RequestedWorkUnit],
    captured_final_artifacts: &[FinalArtifactIdentity],
) -> Result<ValidatedExecutionCoverage, ExecutionCoverageError> {
    validate_journal_bytes(bytes)?;
    validate_opaque_id(expected_engine_run_id, "expected engine run ID")
        .map_err(ExecutionCoverageError::InvalidExpectedIdentity)?;
    validate_expected_work_units(expected_requested_work_units)?;
    let captured = validate_captured_artifacts(captured_final_artifacts)?;

    let text = std::str::from_utf8(bytes).map_err(|_| ExecutionCoverageError::InvalidEncoding)?;
    let mut records = Vec::new();
    for (index, line_with_newline) in text.split_inclusive('\n').enumerate() {
        let record_number = index + 1;
        let line = line_with_newline
            .strip_suffix('\n')
            .expect("complete journal lines end in a newline");
        if line.as_bytes().len() > MAX_JOURNAL_LINE_BYTES {
            return Err(ExecutionCoverageError::LineTooLarge {
                record: record_number,
            });
        }
        if line.is_empty() || line.contains('\r') {
            return Err(invalid_record(
                record_number,
                "blank or carriage-return records are not allowed",
            ));
        }
        if records.len() == MAX_JOURNAL_RECORDS {
            return Err(ExecutionCoverageError::TooManyRecords);
        }
        let record = serde_json::from_str::<JournalRecord>(line)
            .map_err(|_| invalid_record(record_number, "record is not strict launcher-v2 JSON"))?;
        records.push(record);
    }

    let header = match records.remove(0) {
        JournalRecord::Header(header) => header,
        _ => return Err(invalid_record(1, "the first record must be the header")),
    };
    validate_header(
        &header,
        expected_engine_run_id,
        expected_requested_work_units,
    )?;

    let mut order = Vec::with_capacity(header.requested_work_units.len());
    let mut states = BTreeMap::<String, WorkUnitState>::new();
    for requested in &header.requested_work_units {
        validate_requested_work_unit(requested).map_err(|reason| invalid_record(1, reason))?;
        if states.contains_key(&requested.unit_id) {
            return Err(invalid_record(1, "requested work-unit IDs must be unique"));
        }
        order.push(requested.unit_id.clone());
        states.insert(
            requested.unit_id.clone(),
            WorkUnitState {
                requested: requested.clone(),
                attempts: Vec::new(),
            },
        );
    }

    let mut referenced_paths = BTreeSet::new();
    for (index, record) in records.into_iter().enumerate() {
        let record_number = index + 2;
        match record {
            JournalRecord::Header(_) => {
                return Err(invalid_record(record_number, "header may appear only once"));
            }
            JournalRecord::AttemptFinished(finished) => validate_attempt_finished(
                record_number,
                finished,
                &header.engine_run_id,
                &mut states,
                &captured,
                &mut referenced_paths,
            )?,
        }
    }

    if referenced_paths.len() != captured.len() {
        return Err(ExecutionCoverageError::InvalidCapturedArtifact(
            "captured final-artifact inventory contains an orphan entry".into(),
        ));
    }

    let mut work_units = Vec::with_capacity(order.len());
    let mut summary = ExecutionCoverageSummary {
        requested: order.len(),
        tested_complete: 0,
        failed: 0,
        timed_out: 0,
        cancelled: 0,
        not_tested: 0,
        partial: true,
        has_usable_results: false,
    };
    for unit_id in order {
        let state = states
            .remove(&unit_id)
            .expect("requested work-unit state remains available");
        let outcome = state
            .attempts
            .last()
            .map(|attempt| attempt.outcome)
            .unwrap_or(WorkUnitOutcome::NotTested);
        match outcome {
            WorkUnitOutcome::TestedComplete => summary.tested_complete += 1,
            WorkUnitOutcome::Failed => summary.failed += 1,
            WorkUnitOutcome::TimedOut => summary.timed_out += 1,
            WorkUnitOutcome::Cancelled => summary.cancelled += 1,
            WorkUnitOutcome::NotTested => summary.not_tested += 1,
        }
        work_units.push(WorkUnitCoverage {
            unit_id: state.requested.unit_id,
            scope_sha256: state.requested.scope_sha256,
            outcome,
            attempts: state.attempts,
        });
    }
    summary.partial = summary.tested_complete != summary.requested;
    summary.has_usable_results = summary.tested_complete > 0;

    Ok(ValidatedExecutionCoverage {
        schema_version: header.schema_version,
        engine_run_id: header.engine_run_id.clone(),
        work_units,
        summary,
    })
}

fn validate_journal_bytes(bytes: &[u8]) -> Result<(), ExecutionCoverageError> {
    if bytes.is_empty() {
        return Err(ExecutionCoverageError::Empty);
    }
    if bytes.len() > MAX_JOURNAL_BYTES {
        return Err(ExecutionCoverageError::JournalTooLarge);
    }
    if !bytes.ends_with(b"\n") {
        return Err(ExecutionCoverageError::InvalidEncoding);
    }
    Ok(())
}

fn validate_header(
    header: &HeaderRecord,
    expected_engine_run_id: &str,
    expected_requested_work_units: &[RequestedWorkUnit],
) -> Result<(), ExecutionCoverageError> {
    if header.schema_version != LAUNCHER_V2_JOURNAL_SCHEMA_VERSION {
        return Err(invalid_record(1, "unsupported journal schema version"));
    }
    validate_opaque_id(&header.engine_run_id, "engine run ID")
        .map_err(|reason| invalid_record(1, reason))?;
    if header.engine_run_id != expected_engine_run_id {
        return Err(invalid_record(
            1,
            "journal engine-run identity does not match the expected run",
        ));
    }
    if header.requested_work_units.is_empty() {
        return Err(invalid_record(
            1,
            "journal must request at least one work unit",
        ));
    }
    if header.requested_work_units.len() > MAX_REQUESTED_WORK_UNITS {
        return Err(invalid_record(1, "journal requests too many work units"));
    }
    if header.requested_work_units != expected_requested_work_units {
        return Err(invalid_record(
            1,
            "journal requested work units do not exactly match the host-frozen execution plan",
        ));
    }
    Ok(())
}

fn validate_expected_work_units(
    expected: &[RequestedWorkUnit],
) -> Result<(), ExecutionCoverageError> {
    if expected.is_empty() {
        return Err(ExecutionCoverageError::InvalidExpectedIdentity(
            "expected work-unit set is empty".into(),
        ));
    }
    if expected.len() > MAX_REQUESTED_WORK_UNITS {
        return Err(ExecutionCoverageError::InvalidExpectedIdentity(
            "expected work-unit set exceeds its entry limit".into(),
        ));
    }
    let mut seen = BTreeSet::new();
    for requested in expected {
        validate_requested_work_unit(requested)
            .map_err(ExecutionCoverageError::InvalidExpectedIdentity)?;
        if !seen.insert(requested.unit_id.as_str()) {
            return Err(ExecutionCoverageError::InvalidExpectedIdentity(
                "expected work-unit IDs must be unique".into(),
            ));
        }
    }
    Ok(())
}

fn validate_requested_work_unit(requested: &RequestedWorkUnit) -> Result<(), String> {
    validate_opaque_id(&requested.unit_id, "work-unit ID")?;
    validate_sha256(&requested.scope_sha256, "work-unit scope digest")
}

fn validate_attempt_finished(
    record_number: usize,
    finished: AttemptFinishedRecord,
    expected_engine_run_id: &str,
    states: &mut BTreeMap<String, WorkUnitState>,
    captured: &BTreeMap<String, FinalArtifactIdentity>,
    referenced_paths: &mut BTreeSet<String>,
) -> Result<(), ExecutionCoverageError> {
    validate_opaque_id(&finished.unit_id, "work-unit ID")
        .map_err(|reason| invalid_record(record_number, reason))?;
    validate_sha256(&finished.scope_sha256, "work-unit scope digest")
        .map_err(|reason| invalid_record(record_number, reason))?;
    let state = states
        .get_mut(&finished.unit_id)
        .ok_or_else(|| invalid_record(record_number, "outcome refers to an unknown work unit"))?;
    if finished.scope_sha256 != state.requested.scope_sha256 {
        return Err(invalid_record(
            record_number,
            "outcome scope does not match the requested work unit",
        ));
    }
    if state
        .attempts
        .iter()
        .any(|attempt| attempt.attempt == finished.attempt)
    {
        return Err(invalid_record(
            record_number,
            "an attempt has more than one terminal outcome",
        ));
    }
    if state
        .attempts
        .last()
        .is_some_and(|attempt| attempt.outcome == WorkUnitOutcome::TestedComplete)
    {
        return Err(invalid_record(
            record_number,
            "a completed work unit cannot record another attempt",
        ));
    }
    let expected_attempt = u32::try_from(state.attempts.len())
        .ok()
        .and_then(|count| count.checked_add(1))
        .ok_or_else(|| invalid_record(record_number, "attempt sequence overflowed"))?;
    if finished.attempt != expected_attempt
        || !(1..=MAX_ATTEMPTS_PER_WORK_UNIT).contains(&finished.attempt)
    {
        return Err(invalid_record(
            record_number,
            "attempt outcomes must be consecutive, start at one, and remain bounded",
        ));
    }

    match finished.outcome {
        WorkUnitOutcome::TestedComplete => {
            let artifact = finished.final_artifact.as_ref().ok_or_else(|| {
                invalid_record(
                    record_number,
                    "tested_complete requires one exact final artifact",
                )
            })?;
            validate_final_artifact(artifact)
                .map_err(|reason| invalid_record(record_number, reason))?;
            if artifact.engine_run_id != expected_engine_run_id
                || artifact.unit_id != finished.unit_id
                || artifact.scope_sha256 != finished.scope_sha256
                || artifact.attempt != finished.attempt
            {
                return Err(invalid_record(
                    record_number,
                    "final artifact identity does not match its run, unit, scope, and attempt",
                ));
            }
            let observed = captured.get(&artifact.relative_path).ok_or_else(|| {
                invalid_record(
                    record_number,
                    "final artifact is missing from the captured inventory",
                )
            })?;
            if observed != artifact {
                return Err(invalid_record(
                    record_number,
                    "final artifact does not exactly match captured path, hash, size, run, scope, unit, and attempt",
                ));
            }
            if !referenced_paths.insert(artifact.relative_path.clone()) {
                return Err(invalid_record(
                    record_number,
                    "a final artifact is referenced more than once",
                ));
            }
        }
        WorkUnitOutcome::Failed
        | WorkUnitOutcome::TimedOut
        | WorkUnitOutcome::Cancelled
        | WorkUnitOutcome::NotTested => {
            if finished.final_artifact.is_some() {
                return Err(invalid_record(
                    record_number,
                    "only tested_complete may bind a final artifact",
                ));
            }
        }
    }

    state.attempts.push(WorkUnitAttempt {
        attempt: finished.attempt,
        outcome: finished.outcome,
        final_artifact: finished.final_artifact,
    });
    Ok(())
}

fn validate_captured_artifacts(
    artifacts: &[FinalArtifactIdentity],
) -> Result<BTreeMap<String, FinalArtifactIdentity>, ExecutionCoverageError> {
    if artifacts.len() > MAX_CAPTURED_FINAL_ARTIFACTS {
        return Err(ExecutionCoverageError::InvalidCapturedArtifact(
            "captured final-artifact inventory exceeds its entry limit".into(),
        ));
    }
    let mut by_path = BTreeMap::new();
    let mut attempts = BTreeSet::new();
    for artifact in artifacts {
        validate_final_artifact(artifact)
            .map_err(ExecutionCoverageError::InvalidCapturedArtifact)?;
        if by_path
            .insert(artifact.relative_path.clone(), artifact.clone())
            .is_some()
        {
            return Err(ExecutionCoverageError::InvalidCapturedArtifact(
                "captured final-artifact paths must be unique".into(),
            ));
        }
        if !attempts.insert((
            artifact.unit_id.clone(),
            artifact.scope_sha256.clone(),
            artifact.attempt,
        )) {
            return Err(ExecutionCoverageError::InvalidCapturedArtifact(
                "one work-unit attempt cannot have multiple final artifacts".into(),
            ));
        }
    }
    Ok(by_path)
}

fn validate_final_artifact(artifact: &FinalArtifactIdentity) -> Result<(), String> {
    validate_opaque_id(&artifact.engine_run_id, "artifact engine-run ID")?;
    validate_opaque_id(&artifact.unit_id, "artifact work-unit ID")?;
    validate_sha256(&artifact.scope_sha256, "artifact scope digest")?;
    if !(1..=MAX_ATTEMPTS_PER_WORK_UNIT).contains(&artifact.attempt) {
        return Err("artifact attempt is outside the supported range".into());
    }
    validate_relative_artifact_path(&artifact.relative_path)?;
    validate_sha256(&artifact.sha256, "artifact digest")?;
    if artifact.byte_length > MAX_FINAL_ARTIFACT_BYTES {
        return Err("final artifact exceeds its supported size".into());
    }
    if artifact.byte_length == 0 && artifact.sha256 != EMPTY_SHA256 {
        return Err("zero-byte final artifact does not have the empty-file digest".into());
    }
    Ok(())
}

fn validate_opaque_id(value: &str, label: &str) -> Result<(), String> {
    if value.is_empty()
        || value.as_bytes().len() > MAX_OPAQUE_ID_BYTES
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.' | b':'))
    {
        return Err(format!("{label} must be a bounded opaque ASCII identifier"));
    }
    Ok(())
}

fn validate_sha256(value: &str, label: &str) -> Result<(), String> {
    if value.len() != 64
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return Err(format!("{label} must be one lowercase SHA-256 digest"));
    }
    Ok(())
}

fn validate_relative_artifact_path(path: &str) -> Result<(), String> {
    if path.is_empty()
        || path.as_bytes().len() > MAX_RELATIVE_ARTIFACT_PATH_BYTES
        || path.starts_with('/')
        || path.ends_with('/')
        || path.contains('\\')
        || path.contains(':')
        || path.bytes().any(|byte| {
            !(byte.is_ascii_alphanumeric() || matches!(byte, b'/' | b'-' | b'_' | b'.'))
        })
        || path
            .split('/')
            .any(|component| component.is_empty() || matches!(component, "." | ".."))
    {
        return Err("final artifact path must be a bounded portable relative path".into());
    }
    Ok(())
}

fn invalid_record(record: usize, reason: impl Into<String>) -> ExecutionCoverageError {
    ExecutionCoverageError::InvalidRecord {
        record,
        reason: reason.into(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    const SCOPE_A: &str = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
    const SCOPE_B: &str = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";
    const NONEMPTY_SHA: &str = "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc";

    fn record(value: serde_json::Value) -> String {
        format!("{}\n", serde_json::to_string(&value).unwrap())
    }

    fn header(units: serde_json::Value) -> String {
        record(json!({
            "record_type": "header",
            "schema_version": 2,
            "engine_run_id": "run-opaque",
            "requested_work_units": units,
        }))
    }

    fn finished(
        unit: &str,
        scope: &str,
        attempt: u32,
        outcome: &str,
        artifact: Option<&FinalArtifactIdentity>,
    ) -> String {
        let mut value = json!({
            "record_type": "attempt_finished",
            "unit_id": unit,
            "scope_sha256": scope,
            "attempt": attempt,
            "outcome": outcome,
        });
        if let Some(artifact) = artifact {
            value["final_artifact"] = serde_json::to_value(artifact).unwrap();
        }
        record(value)
    }

    fn artifact(
        unit: &str,
        scope: &str,
        attempt: u32,
        path: &str,
        sha256: &str,
        byte_length: u64,
    ) -> FinalArtifactIdentity {
        FinalArtifactIdentity {
            engine_run_id: "run-opaque".into(),
            unit_id: unit.into(),
            scope_sha256: scope.into(),
            attempt,
            relative_path: path.into(),
            sha256: sha256.into(),
            byte_length,
        }
    }

    fn parse_with_expected(
        bytes: &[u8],
        units: &[(&str, &str)],
        artifacts: &[FinalArtifactIdentity],
    ) -> Result<ValidatedExecutionCoverage, ExecutionCoverageError> {
        let expected = units
            .iter()
            .map(|(unit_id, scope_sha256)| RequestedWorkUnit {
                unit_id: (*unit_id).into(),
                scope_sha256: (*scope_sha256).into(),
            })
            .collect::<Vec<_>>();
        parse_launcher_v2_journal(bytes, "run-opaque", &expected, artifacts)
    }

    fn two_unit_header() -> String {
        header(json!([
            {"unit_id": "unit-a", "scope_sha256": SCOPE_A},
            {"unit_id": "unit-b", "scope_sha256": SCOPE_B}
        ]))
    }

    #[test]
    fn derives_partial_truth_and_accepts_exact_completed_empty_artifact() {
        let empty = artifact("unit-a", SCOPE_A, 1, "unit-a/result.jsonl", EMPTY_SHA256, 0);
        let journal = format!(
            "{}{}{}",
            two_unit_header(),
            finished("unit-a", SCOPE_A, 1, "tested_complete", Some(&empty)),
            finished("unit-b", SCOPE_B, 1, "failed", None),
        );

        let coverage = parse_with_expected(
            journal.as_bytes(),
            &[("unit-a", SCOPE_A), ("unit-b", SCOPE_B)],
            &[empty],
        )
        .unwrap();

        assert_eq!(coverage.summary.requested, 2);
        assert_eq!(coverage.summary.tested_complete, 1);
        assert_eq!(coverage.summary.failed, 1);
        assert_eq!(coverage.summary.timed_out, 0);
        assert_eq!(coverage.summary.cancelled, 0);
        assert_eq!(coverage.summary.not_tested, 0);
        assert!(coverage.summary.partial);
        assert!(coverage.summary.has_usable_results);
        assert_eq!(
            coverage.work_units[0].outcome,
            WorkUnitOutcome::TestedComplete
        );
        assert_eq!(coverage.work_units[1].outcome, WorkUnitOutcome::Failed);
    }

    #[test]
    fn units_without_a_terminal_outcome_are_not_invented_as_failures_or_successes() {
        let journal = two_unit_header();
        let coverage = parse_with_expected(
            journal.as_bytes(),
            &[("unit-a", SCOPE_A), ("unit-b", SCOPE_B)],
            &[],
        )
        .unwrap();

        assert_eq!(coverage.summary.not_tested, 2);
        assert_eq!(coverage.summary.tested_complete, 0);
        assert_eq!(coverage.summary.failed, 0);
        assert!(!coverage.summary.has_usable_results);
    }

    #[test]
    fn keeps_all_five_terminal_coverage_outcomes_distinct() {
        let complete = artifact(
            "complete",
            SCOPE_A,
            1,
            "complete/result.jsonl",
            EMPTY_SHA256,
            0,
        );
        let units = ["complete", "failed", "timeout", "cancelled", "not-tested"];
        let mut journal = header(json!(
            units
                .iter()
                .map(|unit| json!({"unit_id": unit, "scope_sha256": SCOPE_A}))
                .collect::<Vec<_>>()
        ));
        for (unit, outcome) in [
            ("complete", "tested_complete"),
            ("failed", "failed"),
            ("timeout", "timed_out"),
            ("cancelled", "cancelled"),
            ("not-tested", "not_tested"),
        ] {
            journal.push_str(&finished(
                unit,
                SCOPE_A,
                1,
                outcome,
                (unit == "complete").then_some(&complete),
            ));
        }

        let coverage = parse_with_expected(
            journal.as_bytes(),
            &[
                ("complete", SCOPE_A),
                ("failed", SCOPE_A),
                ("timeout", SCOPE_A),
                ("cancelled", SCOPE_A),
                ("not-tested", SCOPE_A),
            ],
            &[complete],
        )
        .unwrap();
        assert_eq!(coverage.summary.tested_complete, 1);
        assert_eq!(coverage.summary.failed, 1);
        assert_eq!(coverage.summary.timed_out, 1);
        assert_eq!(coverage.summary.cancelled, 1);
        assert_eq!(coverage.summary.not_tested, 1);
        assert!(coverage.summary.partial);
    }

    #[test]
    fn retries_are_consecutive_and_latest_terminal_outcome_is_reported() {
        let final_artifact = artifact(
            "unit-a",
            SCOPE_A,
            2,
            "unit-a/result.jsonl",
            NONEMPTY_SHA,
            12,
        );
        let journal = format!(
            "{}{}{}",
            header(json!([{"unit_id": "unit-a", "scope_sha256": SCOPE_A}])),
            finished("unit-a", SCOPE_A, 1, "timed_out", None),
            finished(
                "unit-a",
                SCOPE_A,
                2,
                "tested_complete",
                Some(&final_artifact),
            ),
        );
        let coverage = parse_with_expected(
            journal.as_bytes(),
            &[("unit-a", SCOPE_A)],
            &[final_artifact],
        )
        .unwrap();

        assert_eq!(coverage.work_units[0].attempts.len(), 2);
        assert_eq!(coverage.summary.tested_complete, 1);
        assert!(!coverage.summary.partial);
    }

    #[test]
    fn rejects_duplicate_and_unknown_work_unit_identities() {
        let duplicate = header(json!([
            {"unit_id": "same", "scope_sha256": SCOPE_A},
            {"unit_id": "same", "scope_sha256": SCOPE_A}
        ]));
        assert!(matches!(
            parse_with_expected(duplicate.as_bytes(), &[("same", SCOPE_A)], &[]),
            Err(ExecutionCoverageError::InvalidRecord { record: 1, .. })
        ));

        let unknown = format!(
            "{}{}",
            header(json!([{"unit_id": "unit-a", "scope_sha256": SCOPE_A}])),
            finished("unit-b", SCOPE_B, 1, "failed", None),
        );
        assert!(matches!(
            parse_with_expected(unknown.as_bytes(), &[("unit-a", SCOPE_A)], &[]),
            Err(ExecutionCoverageError::InvalidRecord { record: 2, .. })
        ));
    }

    #[test]
    fn journal_cannot_silently_remove_a_host_requested_work_unit() {
        let declared = header(json!([{"unit_id": "unit-a", "scope_sha256": SCOPE_A}]));
        assert!(matches!(
            parse_with_expected(
                declared.as_bytes(),
                &[("unit-a", SCOPE_A), ("unit-b", SCOPE_B)],
                &[],
            ),
            Err(ExecutionCoverageError::InvalidRecord { record: 1, .. })
        ));
    }

    #[test]
    fn rejects_invalid_attempt_order_and_duplicate_terminal_outcomes() {
        let header = header(json!([{"unit_id": "unit-a", "scope_sha256": SCOPE_A}]));
        let skipped = format!(
            "{}{}",
            header,
            finished("unit-a", SCOPE_A, 2, "failed", None),
        );
        assert!(parse_with_expected(skipped.as_bytes(), &[("unit-a", SCOPE_A)], &[]).is_err());

        let duplicate_terminal = format!(
            "{}{}{}",
            header,
            finished("unit-a", SCOPE_A, 1, "failed", None),
            finished("unit-a", SCOPE_A, 1, "cancelled", None),
        );
        assert!(matches!(
            parse_with_expected(duplicate_terminal.as_bytes(), &[("unit-a", SCOPE_A)], &[],),
            Err(ExecutionCoverageError::InvalidRecord { record: 3, .. })
        ));
    }

    #[test]
    fn only_tested_complete_can_bind_a_final_artifact() {
        let final_artifact = artifact("unit-a", SCOPE_A, 1, "unit-a/result.jsonl", NONEMPTY_SHA, 4);
        let failed_with_artifact = format!(
            "{}{}",
            header(json!([{"unit_id": "unit-a", "scope_sha256": SCOPE_A}])),
            finished("unit-a", SCOPE_A, 1, "failed", Some(&final_artifact),),
        );
        assert!(
            parse_with_expected(
                failed_with_artifact.as_bytes(),
                &[("unit-a", SCOPE_A)],
                &[final_artifact],
            )
            .is_err()
        );
    }

    #[test]
    fn rejects_path_traversal_and_absolute_or_windows_paths() {
        for path in [
            "../result.jsonl",
            "/tmp/result.jsonl",
            "C:\\tmp\\result.jsonl",
        ] {
            let bad = artifact("unit-a", SCOPE_A, 1, path, EMPTY_SHA256, 0);
            assert!(matches!(
                parse_with_expected(
                    header(json!([{"unit_id": "unit-a", "scope_sha256": SCOPE_A}])).as_bytes(),
                    &[("unit-a", SCOPE_A)],
                    &[bad],
                ),
                Err(ExecutionCoverageError::InvalidCapturedArtifact(_))
            ));
        }
    }

    #[test]
    fn rejects_orphan_and_mismatched_artifact_identity() {
        let observed = artifact("unit-a", SCOPE_A, 1, "unit-a/result.jsonl", NONEMPTY_SHA, 9);
        let mut claimed = observed.clone();
        claimed.byte_length = 8;
        let journal = format!(
            "{}{}",
            header(json!([{"unit_id": "unit-a", "scope_sha256": SCOPE_A}])),
            finished("unit-a", SCOPE_A, 1, "tested_complete", Some(&claimed),),
        );
        assert!(
            parse_with_expected(journal.as_bytes(), &[("unit-a", SCOPE_A)], &[observed]).is_err()
        );

        let orphan = artifact("unit-a", SCOPE_A, 1, "unit-a/orphan.jsonl", NONEMPTY_SHA, 9);
        assert!(matches!(
            parse_with_expected(
                header(json!([{"unit_id": "unit-a", "scope_sha256": SCOPE_A}])).as_bytes(),
                &[("unit-a", SCOPE_A)],
                &[orphan],
            ),
            Err(ExecutionCoverageError::InvalidCapturedArtifact(_))
        ));
    }

    #[test]
    fn final_artifact_cannot_be_borrowed_from_another_engine_run() {
        let mut other_run = artifact("unit-a", SCOPE_A, 1, "unit-a/result.jsonl", NONEMPTY_SHA, 9);
        other_run.engine_run_id = "different-run".into();
        let journal = format!(
            "{}{}",
            header(json!([{"unit_id": "unit-a", "scope_sha256": SCOPE_A}])),
            finished("unit-a", SCOPE_A, 1, "tested_complete", Some(&other_run),),
        );

        assert!(
            parse_with_expected(journal.as_bytes(), &[("unit-a", SCOPE_A)], &[other_run]).is_err()
        );
    }

    #[test]
    fn zero_byte_artifacts_require_empty_digest_and_completed_terminal_record() {
        let bad_hash = artifact("unit-a", SCOPE_A, 1, "result.jsonl", NONEMPTY_SHA, 0);
        assert!(matches!(
            parse_with_expected(
                header(json!([{"unit_id": "unit-a", "scope_sha256": SCOPE_A}])).as_bytes(),
                &[("unit-a", SCOPE_A)],
                &[bad_hash],
            ),
            Err(ExecutionCoverageError::InvalidCapturedArtifact(_))
        ));

        let empty = artifact("unit-a", SCOPE_A, 1, "result.jsonl", EMPTY_SHA256, 0);
        assert!(matches!(
            parse_with_expected(
                header(json!([{"unit_id": "unit-a", "scope_sha256": SCOPE_A}])).as_bytes(),
                &[("unit-a", SCOPE_A)],
                &[empty],
            ),
            Err(ExecutionCoverageError::InvalidCapturedArtifact(_))
        ));
    }

    #[test]
    fn rejects_torn_unknown_and_oversized_inputs() {
        let torn = header(json!([{"unit_id": "unit-a", "scope_sha256": SCOPE_A}]))
            .trim_end()
            .as_bytes()
            .to_vec();
        assert_eq!(
            parse_with_expected(&torn, &[("unit-a", SCOPE_A)], &[]),
            Err(ExecutionCoverageError::InvalidEncoding)
        );

        let unknown = record(json!({
            "record_type": "header",
            "schema_version": 2,
            "engine_run_id": "run-opaque",
            "requested_work_units": [{"unit_id": "unit-a", "scope_sha256": SCOPE_A}],
            "unexpected": true,
        }));
        assert!(parse_with_expected(unknown.as_bytes(), &[("unit-a", SCOPE_A)], &[]).is_err());

        let oversized = vec![b' '; MAX_JOURNAL_BYTES + 1];
        assert_eq!(
            parse_with_expected(&oversized, &[("unit-a", SCOPE_A)], &[]),
            Err(ExecutionCoverageError::JournalTooLarge)
        );
    }

    #[test]
    fn existing_legacy_engine_run_shape_deserializes_unchanged() {
        let legacy: crate::domain::EngineRun = serde_json::from_value(json!({
            "id": "legacy-engine-run",
            "scan_run_id": "legacy-scan-run",
            "engine_id": "legacy-engine",
            "asset_ids": ["opaque-asset"],
            "status": "failed",
            "progress_percent": 25,
            "phase": "legacy_phase",
            "started_at": null,
            "finished_at": null,
            "resume_token": null,
            "engine_version": null,
            "image_digest": null,
            "rule_version": null,
            "adapter_version": "legacy-adapter",
            "raw_artifact_ids": [],
            "error_code": "legacy_error",
            "error_message": null
        }))
        .unwrap();

        assert_eq!(legacy.id, "legacy-engine-run");
        assert_eq!(
            legacy.task_kind,
            crate::domain::EngineTaskKind::CatalogEngine
        );
        assert_eq!(legacy.status, crate::domain::EngineRunStatus::Failed);
        assert!(legacy.warnings.is_empty());
    }
}
