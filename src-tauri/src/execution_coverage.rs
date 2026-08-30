//! Versioned, bounded coverage evidence for one future multi-work-unit launcher
//! invocation.
//!
//! This module is deliberately inert: it does not run an engine, adapt an
//! artifact, schedule a retry, or change an [`crate::domain::EngineRun`]. It
//! only validates an append-only launcher-v2 journal against the exact
//! host-frozen invocation and artifact metadata already captured by the host.
//! A retry gets a new journal with a new host attempt number and only the work
//! units selected for that retry; the host, not the launcher, later merges
//! stable unit identities across attempts. That separation lets a later
//! orchestration change retain completed work without treating stdout, an
//! empty file, or a process exit code as proof that a work unit was tested.

use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};
use thiserror::Error;

pub const LAUNCHER_V2_JOURNAL_SCHEMA_VERSION: u32 = 2;
pub const MAX_JOURNAL_BYTES: usize = 4 * 1024 * 1024;
pub const MAX_JOURNAL_LINE_BYTES: usize = 1024 * 1024;
pub const MAX_REQUESTED_WORK_UNITS: usize = 512;
/// One header plus at most one terminal outcome for every unit in this exact
/// host invocation. Retries are separate invocations and separate journals.
pub const MAX_JOURNAL_RECORDS: usize = 1 + MAX_REQUESTED_WORK_UNITS;
pub const MAX_CAPTURED_FINAL_ARTIFACTS: usize = MAX_REQUESTED_WORK_UNITS;
pub const MAX_OPAQUE_ID_BYTES: usize = 128;
pub const MAX_RELATIVE_ARTIFACT_PATH_BYTES: usize = 512;
pub const WORK_UNIT_ID_PREFIX: &str = "wu_";
pub const WORK_UNIT_ID_HEX_CHARACTERS: usize = 32;
/// The launcher-v2 output mount has one fixed 512 MiB budget. The journal
/// reserves 4 MiB, leaving at most 508 MiB shared by final and quarantined
/// payloads. The host receives only final artifacts here, so their aggregate
/// can never honestly exceed this remainder.
pub const MAX_LAUNCHER_V2_OUTPUT_BYTES: u64 = 512 * 1024 * 1024;
pub const MAX_CAPTURED_FINAL_ARTIFACT_BYTES: u64 =
    MAX_LAUNCHER_V2_OUTPUT_BYTES - MAX_JOURNAL_BYTES as u64;

const EMPTY_SHA256: &str = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";

#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum ExecutionCoverageError {
    #[error("launcher-v2 journal is empty")]
    Empty,
    #[error("launcher-v2 journal exceeds its {MAX_JOURNAL_BYTES}-byte limit")]
    JournalTooLarge,
    #[error("launcher-v2 journal has no valid complete UTF-8 JSONL prefix")]
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

/// The host's no-follow observation of one file beneath the exact invocation
/// output root. The launcher never chooses or learns the durable raw-artifact
/// ID; keeping it beside (not inside) the claimed identity gives later adapter
/// selection one unambiguous host-owned coordinate.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct HostObservedFinalArtifact {
    pub raw_artifact_id: String,
    pub relative_path: String,
    pub sha256: String,
    pub byte_length: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ValidatedArtifactBinding {
    pub raw_artifact_id: String,
    pub identity: FinalArtifactIdentity,
}

/// Terminal truth for one attempt. These values describe coverage only; none
/// of them assert a finding or a security verdict.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum WorkUnitOutcome {
    TestedComplete,
    /// Some validated observations are usable, but this invocation did not
    /// complete the work unit. This is evidence, never a green verdict.
    TestedPartial,
    Failed,
    TimedOut,
    Cancelled,
    /// The attempt closed before the unit performed its test (for example, a
    /// unit-local prerequisite was unavailable). This explicit terminal value
    /// permits a later retry without mislabeling the attempt as a test failure.
    NotTested,
}

/// Why an invocation that produced usable evidence nevertheless stopped
/// before completing the work unit. Raw scanner text does not belong in the
/// coverage journal.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum IncompleteReason {
    Failed,
    TimedOut,
    Cancelled,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct WorkUnitAttempt {
    pub attempt: u32,
    pub outcome: WorkUnitOutcome,
    pub incomplete_reason: Option<IncompleteReason>,
    pub final_artifact: Option<FinalArtifactIdentity>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct WorkUnitCoverage {
    pub unit_id: String,
    pub scope_sha256: String,
    pub outcome: WorkUnitOutcome,
    pub attempts: Vec<WorkUnitAttempt>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ExecutionCoverageSummary {
    pub requested: usize,
    pub tested_complete: usize,
    pub tested_partial: usize,
    pub failed: usize,
    pub timed_out: usize,
    pub cancelled: usize,
    pub not_tested: usize,
    /// True unless every requested work unit has exact completed evidence.
    pub partial: bool,
    /// True when at least one work unit produced usable complete or partial
    /// evidence.
    pub has_usable_results: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ValidatedExecutionCoverage {
    pub schema_version: u32,
    pub engine_run_id: String,
    pub execution_attempt: u32,
    /// A crash may leave an unsynced final JSON fragment after the last synced
    /// newline. The validator ignores only that suffix and reports recovery;
    /// every unit without a durable terminal record remains `not_tested`.
    pub recovered_trailing_record: bool,
    /// Exact host-owned raw artifacts that a validated terminal record may
    /// pass to the result adapter.
    pub validated_artifact_bindings: Vec<ValidatedArtifactBinding>,
    /// Files atomically published before a crash but not followed by a synced
    /// terminal record. They remain retained raw evidence and are never fed to
    /// an adapter or counted as tested coverage.
    pub unreferenced_final_artifacts: Vec<HostObservedFinalArtifact>,
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
    execution_attempt: u32,
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
    incomplete_reason: Option<IncompleteReason>,
    #[serde(default)]
    final_artifact: Option<FinalArtifactIdentity>,
}

#[derive(Debug)]
struct WorkUnitState {
    requested: RequestedWorkUnit,
    attempts: Vec<WorkUnitAttempt>,
}

/// Parse and validate a launcher-v2 JSONL journal or its longest complete,
/// newline-terminated crash-recovery prefix.
///
/// `expected_requested_work_units` is the authoritative host-frozen plan. The
/// launcher header must match it exactly, so a compromised or interrupted
/// launcher cannot omit work and make incomplete coverage look complete.
///
/// `captured_final_artifacts` must be the host-observed inventory intended for
/// this journal, not every runtime stream, journal, or quarantine artifact.
/// Every terminal record that claims tested coverage must have one exact
/// matching captured entry. An extra captured final file is retained as
/// unreferenced evidence: a crash can occur after atomic publish but before its
/// terminal record is synced, so it must never be promoted to coverage or
/// invalidate earlier durable siblings. This makes an empty result file useful
/// evidence only when its empty-file hash, size, portable relative path, scope,
/// run, unit, and attempt all match a durable terminal record.
pub fn parse_launcher_v2_journal(
    bytes: &[u8],
    expected_engine_run_id: &str,
    expected_execution_attempt: u32,
    expected_requested_work_units: &[RequestedWorkUnit],
    captured_final_artifacts: &[HostObservedFinalArtifact],
) -> Result<ValidatedExecutionCoverage, ExecutionCoverageError> {
    let (complete_bytes, recovered_trailing_record) = complete_journal_prefix(bytes)?;
    validate_opaque_id(expected_engine_run_id, "expected engine run ID")
        .map_err(ExecutionCoverageError::InvalidExpectedIdentity)?;
    if expected_execution_attempt == 0 {
        return Err(ExecutionCoverageError::InvalidExpectedIdentity(
            "expected execution attempt must be nonzero".into(),
        ));
    }
    validate_expected_work_units(expected_requested_work_units)?;
    let captured = validate_captured_artifacts(captured_final_artifacts)?;

    let text =
        std::str::from_utf8(complete_bytes).map_err(|_| ExecutionCoverageError::InvalidEncoding)?;
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
        expected_execution_attempt,
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

    let mut referenced_artifacts = BTreeMap::new();
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
                header.execution_attempt,
                &mut states,
                &captured,
                &mut referenced_artifacts,
            )?,
        }
    }

    let validated_artifact_bindings = referenced_artifacts
        .iter()
        .map(|(path, identity)| {
            let observed = captured
                .get(path)
                .expect("every referenced artifact was validated as captured");
            ValidatedArtifactBinding {
                raw_artifact_id: observed.raw_artifact_id.clone(),
                identity: identity.clone(),
            }
        })
        .collect::<Vec<_>>();
    let unreferenced_final_artifacts = captured
        .iter()
        .filter(|(path, _)| !referenced_artifacts.contains_key(*path))
        .map(|(_, artifact)| artifact.clone())
        .collect::<Vec<_>>();

    let mut work_units = Vec::with_capacity(order.len());
    let mut summary = ExecutionCoverageSummary {
        requested: order.len(),
        tested_complete: 0,
        tested_partial: 0,
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
            WorkUnitOutcome::TestedPartial => summary.tested_partial += 1,
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
    summary.has_usable_results = summary.tested_complete + summary.tested_partial > 0;

    Ok(ValidatedExecutionCoverage {
        schema_version: header.schema_version,
        engine_run_id: header.engine_run_id.clone(),
        execution_attempt: header.execution_attempt,
        recovered_trailing_record,
        validated_artifact_bindings,
        unreferenced_final_artifacts,
        work_units,
        summary,
    })
}

fn complete_journal_prefix(bytes: &[u8]) -> Result<(&[u8], bool), ExecutionCoverageError> {
    if bytes.is_empty() {
        return Err(ExecutionCoverageError::Empty);
    }
    if bytes.len() > MAX_JOURNAL_BYTES {
        return Err(ExecutionCoverageError::JournalTooLarge);
    }
    let final_newline = bytes
        .iter()
        .rposition(|byte| *byte == b'\n')
        .ok_or(ExecutionCoverageError::InvalidEncoding)?;
    let complete_length = final_newline + 1;
    Ok((&bytes[..complete_length], complete_length != bytes.len()))
}

fn validate_header(
    header: &HeaderRecord,
    expected_engine_run_id: &str,
    expected_execution_attempt: u32,
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
    if header.execution_attempt == 0 || header.execution_attempt != expected_execution_attempt {
        return Err(invalid_record(
            1,
            "journal execution attempt does not match the expected host invocation",
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
    validate_work_unit_id(&requested.unit_id)?;
    validate_sha256(&requested.scope_sha256, "work-unit scope digest")
}

fn validate_attempt_finished(
    record_number: usize,
    finished: AttemptFinishedRecord,
    expected_engine_run_id: &str,
    expected_execution_attempt: u32,
    states: &mut BTreeMap<String, WorkUnitState>,
    captured: &BTreeMap<String, HostObservedFinalArtifact>,
    referenced_artifacts: &mut BTreeMap<String, FinalArtifactIdentity>,
) -> Result<(), ExecutionCoverageError> {
    validate_work_unit_id(&finished.unit_id)
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
    if !state.attempts.is_empty() {
        return Err(invalid_record(
            record_number,
            "one invocation may record only one terminal outcome per work unit",
        ));
    }
    if finished.attempt != expected_execution_attempt {
        return Err(invalid_record(
            record_number,
            "terminal outcome does not match the host invocation attempt",
        ));
    }

    match finished.outcome {
        WorkUnitOutcome::TestedComplete | WorkUnitOutcome::TestedPartial => {
            let artifact = finished.final_artifact.as_ref().ok_or_else(|| {
                invalid_record(
                    record_number,
                    "tested coverage requires one exact final artifact",
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
            if finished.outcome == WorkUnitOutcome::TestedPartial && artifact.byte_length == 0 {
                return Err(invalid_record(
                    record_number,
                    "tested_partial requires at least one validated observation",
                ));
            }
            match (finished.outcome, finished.incomplete_reason) {
                (WorkUnitOutcome::TestedComplete, None)
                | (WorkUnitOutcome::TestedPartial, Some(_)) => {}
                (WorkUnitOutcome::TestedComplete, Some(_)) => {
                    return Err(invalid_record(
                        record_number,
                        "tested_complete cannot claim an incomplete reason",
                    ));
                }
                (WorkUnitOutcome::TestedPartial, None) => {
                    return Err(invalid_record(
                        record_number,
                        "tested_partial requires one bounded incomplete reason",
                    ));
                }
                _ => unreachable!("tested outcome match is exhaustive"),
            }
            let observed = captured.get(&artifact.relative_path).ok_or_else(|| {
                invalid_record(
                    record_number,
                    "final artifact is missing from the captured inventory",
                )
            })?;
            if observed.relative_path != artifact.relative_path
                || observed.sha256 != artifact.sha256
                || observed.byte_length != artifact.byte_length
            {
                return Err(invalid_record(
                    record_number,
                    "final artifact does not exactly match captured path, hash, size, run, scope, unit, and attempt",
                ));
            }
            if referenced_artifacts
                .insert(artifact.relative_path.clone(), artifact.clone())
                .is_some()
            {
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
            if finished.final_artifact.is_some() || finished.incomplete_reason.is_some() {
                return Err(invalid_record(
                    record_number,
                    "non-tested outcomes cannot bind an artifact or incomplete reason",
                ));
            }
        }
    }

    state.attempts.push(WorkUnitAttempt {
        attempt: finished.attempt,
        outcome: finished.outcome,
        incomplete_reason: finished.incomplete_reason,
        final_artifact: finished.final_artifact,
    });
    Ok(())
}

fn validate_captured_artifacts(
    artifacts: &[HostObservedFinalArtifact],
) -> Result<BTreeMap<String, HostObservedFinalArtifact>, ExecutionCoverageError> {
    if artifacts.len() > MAX_CAPTURED_FINAL_ARTIFACTS {
        return Err(ExecutionCoverageError::InvalidCapturedArtifact(
            "captured final-artifact inventory exceeds its entry limit".into(),
        ));
    }
    let mut by_path = BTreeMap::new();
    let mut raw_artifact_ids = BTreeSet::new();
    let mut aggregate_bytes = 0_u64;
    for artifact in artifacts {
        validate_opaque_id(&artifact.raw_artifact_id, "durable raw-artifact ID")
            .map_err(ExecutionCoverageError::InvalidCapturedArtifact)?;
        if !raw_artifact_ids.insert(artifact.raw_artifact_id.as_str()) {
            return Err(ExecutionCoverageError::InvalidCapturedArtifact(
                "captured durable raw-artifact IDs must be unique".into(),
            ));
        }
        validate_observed_artifact(artifact)
            .map_err(ExecutionCoverageError::InvalidCapturedArtifact)?;
        aggregate_bytes = aggregate_bytes
            .checked_add(artifact.byte_length)
            .ok_or_else(|| {
                ExecutionCoverageError::InvalidCapturedArtifact(
                    "captured final-artifact sizes overflow their aggregate bound".into(),
                )
            })?;
        if aggregate_bytes > MAX_CAPTURED_FINAL_ARTIFACT_BYTES {
            return Err(ExecutionCoverageError::InvalidCapturedArtifact(
                "captured final artifacts exceed the launcher-v2 aggregate payload budget".into(),
            ));
        }
        if by_path
            .insert(artifact.relative_path.clone(), artifact.clone())
            .is_some()
        {
            return Err(ExecutionCoverageError::InvalidCapturedArtifact(
                "captured final-artifact paths must be unique".into(),
            ));
        }
    }
    Ok(by_path)
}

fn validate_observed_artifact(artifact: &HostObservedFinalArtifact) -> Result<(), String> {
    validate_relative_artifact_path(&artifact.relative_path)?;
    validate_sha256(&artifact.sha256, "captured artifact digest")?;
    if artifact.byte_length > MAX_CAPTURED_FINAL_ARTIFACT_BYTES {
        return Err("captured artifact exceeds its supported size".into());
    }
    if artifact.byte_length == 0 && artifact.sha256 != EMPTY_SHA256 {
        return Err("zero-byte captured artifact does not have the empty-file digest".into());
    }
    Ok(())
}

fn validate_final_artifact(artifact: &FinalArtifactIdentity) -> Result<(), String> {
    validate_opaque_id(&artifact.engine_run_id, "artifact engine-run ID")?;
    validate_work_unit_id(&artifact.unit_id)?;
    validate_sha256(&artifact.scope_sha256, "artifact scope digest")?;
    if artifact.attempt == 0 {
        return Err("artifact attempt must be nonzero".into());
    }
    validate_relative_artifact_path(&artifact.relative_path)?;
    validate_sha256(&artifact.sha256, "artifact digest")?;
    if artifact.byte_length > MAX_CAPTURED_FINAL_ARTIFACT_BYTES {
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

/// Host-frozen work-unit IDs are random 128-bit lowercase hexadecimal values
/// in a fixed namespace. This makes literal IP addresses and domains invalid
/// journal identities instead of relying on callers to remember a privacy
/// convention.
fn validate_work_unit_id(value: &str) -> Result<(), String> {
    let suffix = value
        .strip_prefix(WORK_UNIT_ID_PREFIX)
        .ok_or_else(|| "work-unit ID must use the generated-ID namespace".to_string())?;
    if suffix.len() != WORK_UNIT_ID_HEX_CHARACTERS
        || !suffix
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return Err("work-unit ID must contain one generated 128-bit lowercase value".into());
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

    fn test_unit_id(alias: &str) -> String {
        let suffix = match alias {
            "unit-a" => "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            "unit-b" => "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
            "complete" => "cccccccccccccccccccccccccccccccc",
            "partial" => "dddddddddddddddddddddddddddddddd",
            "failed" => "eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee",
            "timeout" => "ffffffffffffffffffffffffffffffff",
            "cancelled" => "00000000000000000000000000000000",
            "not-tested" => "11111111111111111111111111111111",
            "same" => "22222222222222222222222222222222",
            other => panic!("missing generated test work-unit ID for {other}"),
        };
        format!("{WORK_UNIT_ID_PREFIX}{suffix}")
    }

    fn record(value: serde_json::Value) -> String {
        format!("{}\n", serde_json::to_string(&value).unwrap())
    }

    fn header_with_attempt(mut units: serde_json::Value, execution_attempt: u32) -> String {
        for unit in units
            .as_array_mut()
            .expect("test journal work units are an array")
        {
            let alias = unit["unit_id"]
                .as_str()
                .expect("test work-unit alias is a string")
                .to_string();
            unit["unit_id"] = json!(test_unit_id(&alias));
        }
        record(json!({
            "record_type": "header",
            "schema_version": 2,
            "engine_run_id": "run-opaque",
            "execution_attempt": execution_attempt,
            "requested_work_units": units,
        }))
    }

    fn header(units: serde_json::Value) -> String {
        header_with_attempt(units, 1)
    }

    fn finished(
        unit: &str,
        scope: &str,
        attempt: u32,
        outcome: &str,
        artifact: Option<&FinalArtifactIdentity>,
    ) -> String {
        finished_with_reason(unit, scope, attempt, outcome, None, artifact)
    }

    fn finished_with_reason(
        unit: &str,
        scope: &str,
        attempt: u32,
        outcome: &str,
        incomplete_reason: Option<&str>,
        artifact: Option<&FinalArtifactIdentity>,
    ) -> String {
        let mut value = json!({
            "record_type": "attempt_finished",
            "unit_id": test_unit_id(unit),
            "scope_sha256": scope,
            "attempt": attempt,
            "outcome": outcome,
        });
        if let Some(artifact) = artifact {
            value["final_artifact"] = serde_json::to_value(artifact).unwrap();
        }
        if let Some(incomplete_reason) = incomplete_reason {
            value["incomplete_reason"] = json!(incomplete_reason);
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
            unit_id: test_unit_id(unit),
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
        parse_with_attempt(bytes, 1, units, artifacts)
    }

    fn parse_with_attempt(
        bytes: &[u8],
        execution_attempt: u32,
        units: &[(&str, &str)],
        artifacts: &[FinalArtifactIdentity],
    ) -> Result<ValidatedExecutionCoverage, ExecutionCoverageError> {
        let expected = units
            .iter()
            .map(|(unit_id, scope_sha256)| RequestedWorkUnit {
                unit_id: test_unit_id(unit_id),
                scope_sha256: (*scope_sha256).into(),
            })
            .collect::<Vec<_>>();
        let observed = artifacts
            .iter()
            .enumerate()
            .map(|(index, identity)| HostObservedFinalArtifact {
                raw_artifact_id: format!("raw-{index}"),
                relative_path: identity.relative_path.clone(),
                sha256: identity.sha256.clone(),
                byte_length: identity.byte_length,
            })
            .collect::<Vec<_>>();
        parse_launcher_v2_journal(bytes, "run-opaque", execution_attempt, &expected, &observed)
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
        assert_eq!(coverage.summary.tested_partial, 0);
        assert_eq!(coverage.summary.failed, 1);
        assert_eq!(coverage.summary.timed_out, 0);
        assert_eq!(coverage.summary.cancelled, 0);
        assert_eq!(coverage.summary.not_tested, 0);
        assert!(coverage.summary.partial);
        assert!(coverage.summary.has_usable_results);
        assert_eq!(coverage.execution_attempt, 1);
        assert!(!coverage.recovered_trailing_record);
        assert_eq!(coverage.validated_artifact_bindings.len(), 1);
        assert_eq!(
            coverage.validated_artifact_bindings[0].raw_artifact_id,
            "raw-0"
        );
        assert_eq!(
            coverage.work_units[0].outcome,
            WorkUnitOutcome::TestedComplete
        );
        assert_eq!(coverage.work_units[1].outcome, WorkUnitOutcome::Failed);
    }

    #[test]
    fn accepts_the_exact_go_emitted_golden_journal_contract() {
        // The Go test file is already copied into every launcher image build,
        // so it can be the single golden source without widening Dockerfile or
        // catalog inputs. Its Go test asserts the emitter produces these exact
        // bytes; this test asserts the Rust validator consumes those same bytes.
        let go_test_source = include_str!("../../engines/images/external-launcher/main_test.go");
        let marked = go_test_source
            .split_once("// LAUNCHER_V2_RUST_GOLDEN_START")
            .expect("Go launcher golden start marker exists")
            .1
            .split_once("// LAUNCHER_V2_RUST_GOLDEN_END")
            .expect("Go launcher golden end marker exists")
            .0;
        let journal = marked
            .split_once('`')
            .expect("Go launcher golden opens one raw string")
            .1
            .rsplit_once('`')
            .expect("Go launcher golden closes one raw string")
            .0;
        let expected = [RequestedWorkUnit {
            unit_id: test_unit_id("unit-a"),
            scope_sha256: SCOPE_A.into(),
        }];
        let observed = [HostObservedFinalArtifact {
            raw_artifact_id: "raw-golden".into(),
            relative_path: "launcher-v2/units/unit-000000/attempt-7.jsonl".into(),
            sha256: NONEMPTY_SHA.into(),
            byte_length: 12,
        }];

        let coverage =
            parse_launcher_v2_journal(journal.as_bytes(), "run-opaque", 7, &expected, &observed)
                .unwrap();
        assert_eq!(coverage.summary.tested_partial, 1);
        assert_eq!(coverage.summary.tested_complete, 0);
        assert_eq!(coverage.execution_attempt, 7);
        assert_eq!(coverage.validated_artifact_bindings.len(), 1);
        assert_eq!(
            coverage.validated_artifact_bindings[0].raw_artifact_id,
            "raw-golden"
        );
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
        assert_eq!(coverage.summary.tested_partial, 0);
        assert_eq!(coverage.summary.failed, 0);
        assert!(!coverage.summary.has_usable_results);
    }

    #[test]
    fn keeps_all_six_terminal_coverage_outcomes_distinct() {
        let complete = artifact(
            "complete",
            SCOPE_A,
            1,
            "complete/result.jsonl",
            EMPTY_SHA256,
            0,
        );
        let partial = artifact(
            "partial",
            SCOPE_A,
            1,
            "partial/result.jsonl",
            NONEMPTY_SHA,
            12,
        );
        let units = [
            "complete",
            "partial",
            "failed",
            "timeout",
            "cancelled",
            "not-tested",
        ];
        let mut journal = header(json!(
            units
                .iter()
                .map(|unit| json!({"unit_id": unit, "scope_sha256": SCOPE_A}))
                .collect::<Vec<_>>()
        ));
        for (unit, outcome) in [
            ("complete", "tested_complete"),
            ("partial", "tested_partial"),
            ("failed", "failed"),
            ("timeout", "timed_out"),
            ("cancelled", "cancelled"),
            ("not-tested", "not_tested"),
        ] {
            journal.push_str(&finished_with_reason(
                unit,
                SCOPE_A,
                1,
                outcome,
                (unit == "partial").then_some("failed"),
                match unit {
                    "complete" => Some(&complete),
                    "partial" => Some(&partial),
                    _ => None,
                },
            ));
        }

        let coverage = parse_with_expected(
            journal.as_bytes(),
            &[
                ("complete", SCOPE_A),
                ("partial", SCOPE_A),
                ("failed", SCOPE_A),
                ("timeout", SCOPE_A),
                ("cancelled", SCOPE_A),
                ("not-tested", SCOPE_A),
            ],
            &[complete, partial],
        )
        .unwrap();
        assert_eq!(coverage.summary.tested_complete, 1);
        assert_eq!(coverage.summary.tested_partial, 1);
        assert_eq!(coverage.summary.failed, 1);
        assert_eq!(coverage.summary.timed_out, 1);
        assert_eq!(coverage.summary.cancelled, 1);
        assert_eq!(coverage.summary.not_tested, 1);
        assert!(coverage.summary.partial);
    }

    #[test]
    fn a_retry_is_a_fresh_host_invocation_with_its_exact_attempt_and_subset() {
        let final_artifact = artifact(
            "unit-a",
            SCOPE_A,
            37,
            "unit-a/attempt-37.jsonl",
            NONEMPTY_SHA,
            12,
        );
        let journal = format!(
            "{}{}",
            header_with_attempt(json!([{"unit_id": "unit-a", "scope_sha256": SCOPE_A}]), 37,),
            finished(
                "unit-a",
                SCOPE_A,
                37,
                "tested_complete",
                Some(&final_artifact),
            ),
        );
        let coverage = parse_with_attempt(
            journal.as_bytes(),
            37,
            &[("unit-a", SCOPE_A)],
            &[final_artifact],
        )
        .unwrap();

        assert_eq!(coverage.work_units[0].attempts.len(), 1);
        assert_eq!(coverage.execution_attempt, 37);
        assert_eq!(coverage.summary.tested_complete, 1);
        assert!(!coverage.summary.partial);
    }

    #[test]
    fn rejects_duplicate_and_unknown_work_unit_identities() {
        assert!(validate_work_unit_id(&test_unit_id("unit-a")).is_ok());
        for target_shaped in ["192.0.2.10", "a.example.test", "wu_a.example.test"] {
            assert!(validate_work_unit_id(target_shaped).is_err());
        }

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
    fn rejects_attempt_mismatch_and_duplicate_terminal_outcomes() {
        let header = header(json!([{"unit_id": "unit-a", "scope_sha256": SCOPE_A}]));
        let mismatched = format!(
            "{}{}",
            header,
            finished("unit-a", SCOPE_A, 2, "failed", None),
        );
        assert!(parse_with_expected(mismatched.as_bytes(), &[("unit-a", SCOPE_A)], &[]).is_err());

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
    fn only_tested_complete_or_partial_can_bind_a_final_artifact() {
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
                std::slice::from_ref(&final_artifact),
            )
            .is_err()
        );

        let partial = format!(
            "{}{}",
            header(json!([{"unit_id": "unit-a", "scope_sha256": SCOPE_A}])),
            finished_with_reason(
                "unit-a",
                SCOPE_A,
                1,
                "tested_partial",
                Some("timed_out"),
                Some(&final_artifact),
            ),
        );
        let coverage = parse_with_expected(
            partial.as_bytes(),
            &[("unit-a", SCOPE_A)],
            std::slice::from_ref(&final_artifact),
        )
        .unwrap();
        assert_eq!(coverage.summary.tested_partial, 1);
        assert!(coverage.summary.has_usable_results);
        assert_eq!(
            coverage.work_units[0].attempts[0].incomplete_reason,
            Some(IncompleteReason::TimedOut)
        );

        let missing_reason = format!(
            "{}{}",
            header(json!([{"unit_id": "unit-a", "scope_sha256": SCOPE_A}])),
            finished(
                "unit-a",
                SCOPE_A,
                1,
                "tested_partial",
                Some(&final_artifact),
            ),
        );
        assert!(
            parse_with_expected(
                missing_reason.as_bytes(),
                &[("unit-a", SCOPE_A)],
                std::slice::from_ref(&final_artifact),
            )
            .is_err()
        );

        let empty_partial = artifact("unit-a", SCOPE_A, 1, "unit-a/empty.jsonl", EMPTY_SHA256, 0);
        let empty_partial_journal = format!(
            "{}{}",
            header(json!([{"unit_id": "unit-a", "scope_sha256": SCOPE_A}])),
            finished_with_reason(
                "unit-a",
                SCOPE_A,
                1,
                "tested_partial",
                Some("failed"),
                Some(&empty_partial),
            ),
        );
        assert!(
            parse_with_expected(
                empty_partial_journal.as_bytes(),
                &[("unit-a", SCOPE_A)],
                &[empty_partial],
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
    fn rejects_mismatched_claims_but_retains_unreferenced_published_artifacts() {
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
        let coverage = parse_with_expected(
            header(json!([{"unit_id": "unit-a", "scope_sha256": SCOPE_A}])).as_bytes(),
            &[("unit-a", SCOPE_A)],
            std::slice::from_ref(&orphan),
        )
        .unwrap();
        assert_eq!(coverage.summary.not_tested, 1);
        assert_eq!(coverage.unreferenced_final_artifacts.len(), 1);
        assert_eq!(
            coverage.unreferenced_final_artifacts[0].relative_path,
            orphan.relative_path
        );
        assert_eq!(
            coverage.unreferenced_final_artifacts[0].sha256,
            orphan.sha256
        );
        assert_eq!(
            coverage.unreferenced_final_artifacts[0].byte_length,
            orphan.byte_length
        );
        assert_eq!(
            coverage.unreferenced_final_artifacts[0].raw_artifact_id,
            "raw-0"
        );
        assert!(!coverage.summary.has_usable_results);
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
    fn zero_byte_artifacts_require_empty_digest_and_a_terminal_to_count_as_coverage() {
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
        let coverage = parse_with_expected(
            header(json!([{"unit_id": "unit-a", "scope_sha256": SCOPE_A}])).as_bytes(),
            &[("unit-a", SCOPE_A)],
            std::slice::from_ref(&empty),
        )
        .unwrap();
        assert_eq!(coverage.summary.not_tested, 1);
        assert_eq!(coverage.unreferenced_final_artifacts.len(), 1);
        assert_eq!(
            coverage.unreferenced_final_artifacts[0].relative_path,
            empty.relative_path
        );
    }

    #[test]
    fn recovers_a_torn_final_record_but_rejects_torn_header_unknown_and_oversized_inputs() {
        let torn_header = header(json!([{"unit_id": "unit-a", "scope_sha256": SCOPE_A}]))
            .trim_end()
            .as_bytes()
            .to_vec();
        assert_eq!(
            parse_with_expected(&torn_header, &[("unit-a", SCOPE_A)], &[]),
            Err(ExecutionCoverageError::InvalidEncoding)
        );

        let complete = artifact("unit-a", SCOPE_A, 1, "unit-a/result.jsonl", EMPTY_SHA256, 0);
        let mut torn_tail = format!(
            "{}{}",
            two_unit_header(),
            finished("unit-a", SCOPE_A, 1, "tested_complete", Some(&complete)),
        )
        .into_bytes();
        torn_tail.extend_from_slice(b"{\"record_type\":\"attempt_fin");
        let recovered = parse_with_expected(
            &torn_tail,
            &[("unit-a", SCOPE_A), ("unit-b", SCOPE_B)],
            &[complete],
        )
        .unwrap();
        assert!(recovered.recovered_trailing_record);
        assert_eq!(recovered.summary.tested_complete, 1);
        assert_eq!(recovered.summary.not_tested, 1);

        let unknown = record(json!({
            "record_type": "header",
            "schema_version": 2,
            "engine_run_id": "run-opaque",
            "execution_attempt": 1,
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
    fn captured_final_artifacts_share_the_launchers_exact_payload_budget() {
        let expected = [RequestedWorkUnit {
            unit_id: test_unit_id("unit-a"),
            scope_sha256: SCOPE_A.into(),
        }];
        let first = HostObservedFinalArtifact {
            raw_artifact_id: "raw-a".into(),
            relative_path: "unit-a/first.jsonl".into(),
            sha256: NONEMPTY_SHA.into(),
            byte_length: MAX_CAPTURED_FINAL_ARTIFACT_BYTES / 2 + 1,
        };
        let second = HostObservedFinalArtifact {
            raw_artifact_id: "raw-b".into(),
            relative_path: "unit-a/second.jsonl".into(),
            sha256: NONEMPTY_SHA.into(),
            byte_length: MAX_CAPTURED_FINAL_ARTIFACT_BYTES / 2,
        };

        assert!(matches!(
            parse_launcher_v2_journal(
                header(json!([{"unit_id": "unit-a", "scope_sha256": SCOPE_A}]))
                    .as_bytes(),
                "run-opaque",
                1,
                &expected,
                &[first, second],
            ),
            Err(ExecutionCoverageError::InvalidCapturedArtifact(reason))
                if reason.contains("aggregate payload budget")
        ));
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
