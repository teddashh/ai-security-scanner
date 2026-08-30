//! Deterministic coverage ledger computation.
//!
//! Coverage is derived from source connectivity, discovered assets, explicit
//! effective grants, compatible planned engine runs, and their execution
//! status. Findings are deliberately not an input: zero findings is never
//! evidence that a scan ran or that an area was covered.

use crate::domain::{
    AssessmentCase, Asset, AssetKind, BUILT_IN_LOCALHOST_TCP_ASSET_IDENTIFIER_NAMESPACE,
    BUILT_IN_LOCALHOST_TCP_AUTHORIZATION_REFERENCE, BUILT_IN_LOCALHOST_TCP_ENGINE_ID,
    CoverageEntry, CoverageStatus, DataSource, EngineManifest, EngineRun, EngineRunStatus,
    EngineTaskKind, Id, LocalhostTcpOutcome, ScanPermission, ScanRun, ScopeGrant,
    SourceConnectionStatus, SourceKind,
};
use chrono::{DateTime, NaiveDate, Utc};
use serde::Serialize;
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet};

const SOURCE_OBSERVATIONS_METADATA: &str = "ai_security_scanner.source_observations";
pub const NOT_APPLICABLE_REASON_METADATA: &str = "ai_security_scanner.not_applicable_reason";

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AssetCoverageAssessment {
    pub status: CoverageStatus,
    pub explanation: String,
    pub last_run_id: Option<Id>,
    pub observed_at: Option<DateTime<Utc>>,
}

/// The single coverage state that may be rendered as scanned/green.
pub fn coverage_status_is_green(status: &CoverageStatus) -> bool {
    matches!(status, CoverageStatus::DiscoveredAuthorizedScanned)
}

/// Recomputes the current coverage snapshot in a stable order.
///
/// The result contains a source-area row when a source is not connected or
/// when a connected source has discovered no attributable assets, plus one
/// row for every known asset. Connected sources with discovered assets are
/// represented by their asset rows rather than an ambiguous aggregate.
pub fn compute_coverage_ledger(
    case: &AssessmentCase,
    manifests: &[EngineManifest],
    as_of: DateTime<Utc>,
) -> Vec<CoverageEntry> {
    let mut entries = Vec::new();
    let mut sources = case.data_sources.iter().collect::<Vec<_>>();
    sources.sort_by(|left, right| left.id.cmp(&right.id));

    for source in sources {
        let (retained_asset_count, latest_asset_count) = source_asset_counts(case, source);
        match source.status {
            SourceConnectionStatus::NotApplicable => {
                let reason = source
                    .metadata
                    .get(NOT_APPLICABLE_REASON_METADATA)
                    .and_then(serde_json::Value::as_str)
                    .filter(|value| {
                        !value.trim().is_empty()
                            && value.chars().count() <= 1_000
                            && !value.chars().any(char::is_control)
                    })
                    .unwrap_or("The source was marked not applicable, but this legacy record has no retained reason.");
                entries.push(source_entry(
                    source,
                    CoverageStatus::NotApplicable,
                    &format!(
                        "The source area is explicitly outside this case: {reason} This is a scoped applicability statement, not a successful scan result."
                    ),
                ));
            }
            SourceConnectionStatus::Connected if latest_asset_count == 0 => {
                let mut explanation = if source.last_discovered_at.is_some() {
                    format!(
                        "The source is connected and the latest attributable discovery returned no assets. This is not a successful scan result; {retained_asset_count} prior asset observation(s) remain retained."
                    )
                } else {
                    "The source is connected, but no attributable discovery has completed and no assets are known. Coverage is not established.".into()
                };
                append_live_discovery_detail(source, &mut explanation);
                entries.push(source_entry(
                    source,
                    CoverageStatus::SourceConnectedNothingDiscovered,
                    &explanation,
                ));
            }
            SourceConnectionStatus::Connected => {}
            _ => {
                let mut explanation = format!(
                    "The source is not currently connected (status: {}). Its present coverage is unknown; {} previously attributed asset(s) are retained but do not make the source green.",
                    enum_key(&source.status),
                    retained_asset_count
                );
                append_live_discovery_detail(source, &mut explanation);
                entries.push(source_entry(
                    source,
                    CoverageStatus::SourceNotConnectedUnknown,
                    &explanation,
                ));
            }
        }
    }

    let sources_by_id = case
        .data_sources
        .iter()
        .map(|source| (source.id.as_str(), source))
        .collect::<BTreeMap<_, _>>();
    let mut assets = case.assets.iter().collect::<Vec<_>>();
    assets.sort_by(|left, right| left.id.cmp(&right.id));
    for asset in assets {
        let assessment = assess_asset_coverage(case, asset, manifests, as_of);
        let source_kind = representative_source_kind(asset, &sources_by_id);
        entries.push(CoverageEntry {
            id: stable_coverage_id(&format!("asset:{}", asset.id)),
            scope_key: format!("asset:{}", asset.id),
            label: asset.name.clone(),
            source_kind,
            asset_id: Some(asset.id.clone()),
            status: assessment.status,
            explanation: assessment.explanation,
            last_run_id: assessment.last_run_id,
            observed_at: assessment
                .observed_at
                .or_else(|| asset_last_discovered_at(asset, &sources_by_id)),
        });
    }

    entries.sort_by(|left, right| left.scope_key.cmp(&right.scope_key));
    entries
}

fn append_live_discovery_detail(source: &DataSource, explanation: &mut String) {
    let Some(outcome) = source
        .metadata
        .get("ai_security_scanner.live_discovery_outcome")
        .and_then(|value| value.as_object())
    else {
        return;
    };
    let code = outcome
        .get("code")
        .and_then(|value| value.as_str())
        .unwrap_or_default();
    let message = outcome
        .get("message")
        .and_then(|value| value.as_str())
        .unwrap_or_default();
    if code.is_empty()
        || code.len() > 128
        || message.is_empty()
        || message.len() > 1_024
        || code.chars().any(char::is_control)
        || message.chars().any(char::is_control)
    {
        return;
    }
    explanation.push_str(&format!(" Latest provider discovery: {code}: {message}"));
}

/// Replaces the case's current coverage snapshot with a deterministic ledger.
/// Callers should persist an explicit coverage event after this operation.
pub fn refresh_coverage_ledger(
    case: &mut AssessmentCase,
    manifests: &[EngineManifest],
    as_of: DateTime<Utc>,
) {
    case.coverage = compute_coverage_ledger(case, manifests, as_of);
}

/// Computes coverage for one asset. Only `Completed` is a green run state;
/// partial, failed, cancelled, not-executed, and every non-terminal state are
/// incomplete. The findings collection is intentionally never consulted.
pub fn assess_asset_coverage(
    case: &AssessmentCase,
    asset: &Asset,
    manifests: &[EngineManifest],
    as_of: DateTime<Utc>,
) -> AssetCoverageAssessment {
    let effective_grants = case
        .scope_grants
        .iter()
        .filter(|grant| grant.asset_id == asset.id && effective_grant(grant, as_of))
        .collect::<Vec<_>>();

    if asset.candidate || !asset.owner_confirmed || effective_grants.is_empty() {
        let reason = if asset.candidate || !asset.owner_confirmed {
            "The discovered candidate has not had ownership and scope explicitly confirmed."
        } else {
            "The asset has no unexpired, valid scope grant."
        };
        return AssetCoverageAssessment {
            status: CoverageStatus::DiscoveredNotAuthorized,
            explanation: format!("{reason} Discovery never authorizes a target automatically."),
            last_run_id: None,
            observed_at: None,
        };
    }

    let effective_grant_ids = effective_grants
        .iter()
        .map(|grant| grant.id.as_str())
        .collect::<BTreeSet<_>>();
    let latest_run = case
        .scan_runs
        .iter()
        .filter(|run| {
            run.scope_grant_ids
                .iter()
                .any(|id| effective_grant_ids.contains(id.as_str()))
        })
        .max_by(|left, right| {
            (left.sequence, left.created_at, left.id.as_str()).cmp(&(
                right.sequence,
                right.created_at,
                right.id.as_str(),
            ))
        });

    let Some(run) = latest_run else {
        return incomplete(
            None,
            None,
            "The asset is authorized, but no scan plan is tied to its current effective grants.",
        );
    };

    let relevant_grant_ids = run
        .scope_grant_ids
        .iter()
        .filter(|id| effective_grant_ids.contains(id.as_str()))
        .map(String::as_str)
        .collect::<BTreeSet<_>>();
    if run.scope_grant_snapshots.is_empty() {
        return incomplete(
            Some(run.id.clone()),
            run_observed_at(run),
            "The scan predates frozen scope-grant snapshots, so its historical authorization and permission coverage are unknown. Live grants are never substituted for missing run evidence.",
        );
    }

    let mut run_grants = Vec::new();
    let mut snapshot_errors = Vec::new();
    for grant_id in &relevant_grant_ids {
        let matches = run
            .scope_grant_snapshots
            .iter()
            .filter(|snapshot| {
                snapshot.id == *grant_id
                    && snapshot.asset_id == asset.id
                    && run.scope_grant_ids.contains(&snapshot.id)
            })
            .collect::<Vec<_>>();
        match matches.as_slice() {
            [snapshot] if effective_grant(snapshot, run.created_at) => {
                run_grants.push(*snapshot);
            }
            [snapshot] => snapshot_errors.push(format!(
                "{}=historical_scope_not_effective_at_run({})",
                grant_id,
                enum_key(&snapshot.permission)
            )),
            [] => snapshot_errors.push(format!("{}=historical_scope_snapshot_missing", grant_id)),
            _ => snapshot_errors.push(format!("{}=historical_scope_snapshot_ambiguous", grant_id)),
        }
    }
    if relevant_grant_ids.is_empty() || !snapshot_errors.is_empty() {
        snapshot_errors.sort();
        let detail = if snapshot_errors.is_empty() {
            "no current effective grant is represented by the selected run".into()
        } else {
            snapshot_errors.join(", ")
        };
        return incomplete(
            Some(run.id.clone()),
            run_observed_at(run),
            &format!(
                "The scan's frozen authorization evidence is incomplete: {detail}. Live grants are never used to reconstruct historical scan permission."
            ),
        );
    }
    let planned_runs = run
        .engine_runs
        .iter()
        .filter(|engine_run| engine_run.asset_ids.contains(&asset.id))
        .collect::<Vec<_>>();
    let observed_at = run_observed_at(run);

    if planned_runs.is_empty() {
        return incomplete(
            Some(run.id.clone()),
            observed_at,
            "The asset is authorized, but the latest applicable scan plan contains no engine run for it.",
        );
    }

    let manifests_by_id = manifest_index(manifests);
    let mut incomplete_reasons = Vec::new();
    let mut stale_knowledge = Vec::new();
    let mut completed_localhost_attempts = Vec::new();
    for engine_run in &planned_runs {
        if matches!(
            &engine_run.task_kind,
            EngineTaskKind::BuiltInLocalhostTcp { .. }
        ) {
            match assess_built_in_localhost_tcp_binding(run, engine_run, asset, &run_grants) {
                Ok(completed_attempt) => completed_localhost_attempts.push(completed_attempt),
                Err(reason) => incomplete_reasons.push(reason),
            }
            continue;
        }

        let manifest_matches = manifests_by_id.get(engine_run.engine_id.as_str());
        let manifest = match manifest_matches {
            None => {
                incomplete_reasons.push(format!("{}=manifest_missing", engine_run.engine_id));
                continue;
            }
            Some(matches) if matches.len() != 1 => {
                incomplete_reasons.push(format!("{}=manifest_ambiguous", engine_run.engine_id));
                continue;
            }
            Some(matches) => matches[0],
        };

        if !manifest.supported_asset_kinds.contains(&asset.kind) {
            incomplete_reasons.push(format!("{}=asset_kind_incompatible", engine_run.engine_id));
            continue;
        }
        if !manifest.supports_provider(asset.provider.as_deref()) {
            incomplete_reasons.push(format!("{}=provider_incompatible", engine_run.engine_id));
            continue;
        }
        if !manifest.provider_execution_contracts.is_empty()
            && manifest
                .provider_execution_contract(asset.provider.as_deref(), &asset.kind)
                .is_none()
        {
            incomplete_reasons.push(format!(
                "{}=provider_execution_contract_incompatible",
                engine_run.engine_id
            ));
            continue;
        }
        if !permissions_cover_manifest(&run_grants, manifest) {
            incomplete_reasons.push(format!("{}=scope_incompatible", engine_run.engine_id));
            continue;
        }
        if engine_run.status != EngineRunStatus::Completed {
            incomplete_reasons.push(format!(
                "{}={}",
                engine_run.engine_id,
                enum_key(&engine_run.status)
            ));
        } else if let Some(input) = engine_run.knowledge_input.as_ref()
            && let (Some(knowledge_date), Some(support_until)) = (
                input.knowledge_date.as_deref(),
                input.support_until.as_deref(),
            )
            && NaiveDate::parse_from_str(support_until, "%Y-%m-%d")
                .ok()
                .is_some_and(|date| date < as_of.date_naive())
        {
            stale_knowledge.push(format!(
                "{} knowledge {} (support ended {})",
                engine_run.engine_id, knowledge_date, support_until
            ));
        }
    }

    if incomplete_reasons.is_empty() {
        stale_knowledge.sort();
        let freshness_notice = if stale_knowledge.is_empty() {
            String::new()
        } else {
            format!(
                " Explicit stale-knowledge warning: {}. Completion proves execution, not current knowledge.",
                stale_knowledge.join(", ")
            )
        };
        let localhost_notice = if completed_localhost_attempts.is_empty() {
            String::new()
        } else {
            completed_localhost_attempts.sort();
            format!(
                " Exact built-in localhost TCP attempt(s): {}. This records only those connection attempts; it does not establish that the service or computer is secure, and it does not cover other ports or hosts.",
                completed_localhost_attempts.join(", ")
            )
        };
        let completion_summary = if completed_localhost_attempts.is_empty() {
            format!(
                "All {} compatible engine run(s) planned for this asset completed.",
                planned_runs.len()
            )
        } else {
            format!(
                "All {} planned task(s) for this asset completed their exact declared dimensions.",
                planned_runs.len()
            )
        };
        AssetCoverageAssessment {
            status: CoverageStatus::DiscoveredAuthorizedScanned,
            explanation: format!(
                "{completion_summary} This state is independent of how many findings were reported.{}{}",
                localhost_notice, freshness_notice
            ),
            last_run_id: Some(run.id.clone()),
            observed_at,
        }
    } else {
        incomplete_reasons.sort();
        incomplete(
            Some(run.id.clone()),
            observed_at,
            &format!(
                "The authorized scan is incomplete: {}. Only completed compatible catalog-engine runs or exact completed built-in tasks can produce scanned coverage.",
                incomplete_reasons.join(", ")
            ),
        )
    }
}

fn assess_built_in_localhost_tcp_binding(
    run: &ScanRun,
    engine_run: &EngineRun,
    asset: &Asset,
    run_grants: &[&ScopeGrant],
) -> Result<String, String> {
    let EngineTaskKind::BuiltInLocalhostTcp { port, .. } = &engine_run.task_kind else {
        return Err("built_in_localhost_tcp=task_kind_mismatch".into());
    };
    let endpoint = format!("127.0.0.1:{port}");
    if engine_run.engine_id != BUILT_IN_LOCALHOST_TCP_ENGINE_ID {
        return Err("built_in_localhost_tcp=engine_identity_mismatch".into());
    }
    if run.request_outcome.is_some() || run.engine_runs.len() != 1 {
        return Err("built_in_localhost_tcp=run_contract_expanded".into());
    }
    if engine_run.asset_ids.as_slice() != [asset.id.as_str()] {
        return Err("built_in_localhost_tcp=asset_binding_mismatch".into());
    }
    if asset.kind != AssetKind::WebService
        || asset.candidate
        || !asset.owner_confirmed
        || asset.internet_exposed != Some(false)
        || asset.name != endpoint
        || asset.identifiers.len() != 1
        || asset.identifiers[0].namespace != BUILT_IN_LOCALHOST_TCP_ASSET_IDENTIFIER_NAMESPACE
        || asset.identifiers[0].value != endpoint
    {
        return Err("built_in_localhost_tcp=loopback_asset_contract_mismatch".into());
    }
    if run.scope_grant_ids.len() != 1
        || run.scope_grant_snapshots.len() != 1
        || run_grants.len() != 1
    {
        return Err("built_in_localhost_tcp=scope_contract_expanded".into());
    }
    let grant = run_grants[0];
    if grant.id != run.scope_grant_ids[0]
        || grant.asset_id != asset.id
        || grant.permission != ScanPermission::LowImpactExternalConnection
        || grant.authorization_reference.as_deref()
            != Some(BUILT_IN_LOCALHOST_TCP_AUTHORIZATION_REFERENCE)
        || grant.external_scope.is_some()
    {
        return Err("built_in_localhost_tcp=scope_binding_mismatch".into());
    }
    if engine_run.progress_percent != 100 {
        return Err("built_in_localhost_tcp=terminal_progress_mismatch".into());
    }
    let observation = engine_run
        .localhost_tcp_observation
        .as_ref()
        .ok_or_else(|| {
            format!(
                "built_in_localhost_tcp:{endpoint}=observation_missing({})",
                enum_key(&engine_run.status)
            )
        })?;
    if engine_run
        .started_at
        .is_none_or(|started_at| observation.observed_at < started_at)
        || engine_run
            .finished_at
            .is_none_or(|finished_at| observation.observed_at > finished_at)
        || observation.observed_at < run.created_at
    {
        return Err("built_in_localhost_tcp=observation_time_mismatch".into());
    }
    assess_built_in_localhost_tcp_task(engine_run)
}

fn assess_built_in_localhost_tcp_task(engine_run: &EngineRun) -> Result<String, String> {
    let EngineTaskKind::BuiltInLocalhostTcp {
        port,
        timeout_ms,
        payload_bytes,
    } = &engine_run.task_kind
    else {
        return Err("built_in_localhost_tcp=task_kind_mismatch".into());
    };
    let task_label = format!("127.0.0.1:{port}");

    if !engine_run
        .task_kind
        .is_exact_built_in_localhost_tcp_contract()
    {
        return Err(format!(
            "built_in_localhost_tcp:{task_label}=invalid_contract(port={port},timeout_ms={timeout_ms},payload_bytes={payload_bytes})"
        ));
    }

    let Some(observation) = engine_run.localhost_tcp_observation.as_ref() else {
        return Err(format!(
            "built_in_localhost_tcp:{task_label}=observation_missing({})",
            enum_key(&engine_run.status)
        ));
    };

    match observation.outcome {
        LocalhostTcpOutcome::TimedOut => {
            Err(format!("built_in_localhost_tcp:{task_label}=timed_out"))
        }
        LocalhostTcpOutcome::Reachable | LocalhostTcpOutcome::Closed
            if engine_run.status != EngineRunStatus::Completed =>
        {
            Err(format!(
                "built_in_localhost_tcp:{task_label}=observation_not_completed({})",
                enum_key(&engine_run.status)
            ))
        }
        LocalhostTcpOutcome::Reachable | LocalhostTcpOutcome::Closed => {
            Ok(format!("{task_label}={}", enum_key(&observation.outcome)))
        }
    }
}

fn incomplete(
    last_run_id: Option<Id>,
    observed_at: Option<DateTime<Utc>>,
    explanation: &str,
) -> AssetCoverageAssessment {
    AssetCoverageAssessment {
        status: CoverageStatus::AuthorizedScanIncomplete,
        explanation: explanation.into(),
        last_run_id,
        observed_at,
    }
}

fn effective_grant(grant: &ScopeGrant, as_of: DateTime<Utc>) -> bool {
    let not_expired = grant.expires_at.is_none_or(|expires_at| expires_at > as_of);
    let already_confirmed = grant.confirmed_at <= as_of;
    let named_confirmer = !grant.confirmed_by.trim().is_empty();
    let external_authorization_present = match grant.permission {
        ScanPermission::LowImpactExternalConnection | ScanPermission::ActiveExternalTesting => {
            grant
                .authorization_reference
                .as_deref()
                .is_some_and(|reference| !reference.trim().is_empty())
        }
        _ => true,
    };
    already_confirmed && not_expired && named_confirmer && external_authorization_present
}

fn permissions_cover_manifest(grants: &[&ScopeGrant], manifest: &EngineManifest) -> bool {
    manifest.required_permissions_satisfied_by(grants.iter().map(|grant| &grant.permission))
}

fn manifest_index(manifests: &[EngineManifest]) -> BTreeMap<&str, Vec<&EngineManifest>> {
    let mut by_id = BTreeMap::<&str, Vec<&EngineManifest>>::new();
    for manifest in manifests {
        by_id
            .entry(manifest.id.as_str())
            .or_default()
            .push(manifest);
    }
    by_id
}

fn run_observed_at(run: &ScanRun) -> Option<DateTime<Utc>> {
    run.completed_at
        .or_else(|| {
            run.engine_runs
                .iter()
                .flat_map(|engine_run| {
                    [
                        engine_run.finished_at,
                        engine_run
                            .localhost_tcp_observation
                            .as_ref()
                            .map(|observation| observation.observed_at),
                    ]
                })
                .flatten()
                .max()
        })
        .or(Some(run.created_at))
}

fn source_entry(source: &DataSource, status: CoverageStatus, explanation: &str) -> CoverageEntry {
    let scope_key = format!("source:{}", source.id);
    CoverageEntry {
        id: stable_coverage_id(&scope_key),
        scope_key,
        label: source.label.clone(),
        source_kind: source.kind.clone(),
        asset_id: None,
        status,
        explanation: explanation.into(),
        last_run_id: None,
        observed_at: source.last_discovered_at,
    }
}

fn source_asset_counts(case: &AssessmentCase, source: &DataSource) -> (usize, usize) {
    let attributed = case
        .assets
        .iter()
        .filter(|asset| asset.discovered_from.contains(&source.id))
        .collect::<Vec<_>>();
    let retained_count = attributed.len();
    let Some(latest_discovery) = source.last_discovered_at else {
        // Legacy/user-declared records have no per-source observation stamp.
        return (retained_count, retained_count);
    };

    let has_source_stamps = attributed.iter().any(|asset| {
        asset
            .metadata
            .get(SOURCE_OBSERVATIONS_METADATA)
            .and_then(|value| value.as_object())
            .is_some_and(|observations| observations.contains_key(&source.id))
    });
    if !has_source_stamps {
        // Preserve compatibility for assets created before source-specific
        // discovery stamps were introduced.
        return (retained_count, retained_count);
    }

    let latest_count = attributed
        .iter()
        .filter(|asset| {
            asset
                .metadata
                .get(SOURCE_OBSERVATIONS_METADATA)
                .and_then(|value| value.as_object())
                .and_then(|observations| observations.get(&source.id))
                .and_then(|value| value.as_str())
                .and_then(|value| DateTime::parse_from_rfc3339(value).ok())
                .is_some_and(|observed_at| observed_at.with_timezone(&Utc) == latest_discovery)
        })
        .count();
    (retained_count, latest_count)
}

fn representative_source_kind(asset: &Asset, sources: &BTreeMap<&str, &DataSource>) -> SourceKind {
    let mut connected = asset
        .discovered_from
        .iter()
        .filter_map(|id| sources.get(id.as_str()).copied())
        .filter(|source| source.status == SourceConnectionStatus::Connected)
        .collect::<Vec<_>>();
    connected.sort_by(|left, right| left.id.cmp(&right.id));
    if let Some(source) = connected.first() {
        return source.kind.clone();
    }

    let mut known = asset
        .discovered_from
        .iter()
        .filter_map(|id| sources.get(id.as_str()).copied())
        .collect::<Vec<_>>();
    known.sort_by(|left, right| left.id.cmp(&right.id));
    known
        .first()
        .map(|source| source.kind.clone())
        .unwrap_or(SourceKind::UserDeclared)
}

fn asset_last_discovered_at(
    asset: &Asset,
    sources: &BTreeMap<&str, &DataSource>,
) -> Option<DateTime<Utc>> {
    asset
        .discovered_from
        .iter()
        .filter_map(|id| {
            sources
                .get(id.as_str())
                .and_then(|source| source.last_discovered_at)
        })
        .max()
}

fn stable_coverage_id(scope_key: &str) -> Id {
    let digest = hex::encode(Sha256::digest(
        format!("coverage/v1\u{0}{scope_key}").as_bytes(),
    ));
    format!("coverage-{}", &digest[..32])
}

fn enum_key<T: Serialize>(value: &T) -> String {
    serde_json::to_value(value)
        .ok()
        .and_then(|value| value.as_str().map(str::to_owned))
        .unwrap_or_else(|| "unknown".into())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::domain::{BUILT_IN_LOCALHOST_TCP_TIMEOUT_MS, LocalhostTcpObservation};

    fn built_in_localhost_run(
        status: EngineRunStatus,
        outcome: Option<LocalhostTcpOutcome>,
    ) -> EngineRun {
        let observed_at = Utc::now();
        EngineRun {
            id: "localhost-run".into(),
            scan_run_id: "scan-run".into(),
            engine_id: "built-in-localhost-tcp".into(),
            task_kind: EngineTaskKind::built_in_localhost_tcp(9_001),
            localhost_tcp_observation: outcome.map(|outcome| LocalhostTcpObservation {
                outcome,
                observed_at,
            }),
            asset_ids: vec!["localhost-asset".into()],
            status,
            progress_percent: 100,
            phase: "terminal".into(),
            started_at: Some(observed_at),
            finished_at: Some(observed_at),
            resume_token: None,
            engine_version: None,
            image_digest: None,
            rule_version: None,
            adapter_version: "built-in".into(),
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
            mapping_version: None,
            mapping_provenance: None,
            fingerprint_schema_version: None,
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

    #[test]
    fn every_non_completed_status_is_non_green() {
        for status in [
            EngineRunStatus::NotExecuted,
            EngineRunStatus::Queued,
            EngineRunStatus::Preparing,
            EngineRunStatus::Running,
            EngineRunStatus::Paused,
            EngineRunStatus::PartiallyCompleted,
            EngineRunStatus::Failed,
            EngineRunStatus::Cancelled,
        ] {
            assert_ne!(status, EngineRunStatus::Completed);
        }
    }

    #[test]
    fn source_empty_and_source_unknown_are_never_green() {
        assert!(!coverage_status_is_green(
            &CoverageStatus::SourceConnectedNothingDiscovered
        ));
        assert!(!coverage_status_is_green(
            &CoverageStatus::SourceNotConnectedUnknown
        ));
        assert!(coverage_status_is_green(
            &CoverageStatus::DiscoveredAuthorizedScanned
        ));
    }

    #[test]
    fn completed_reachable_and_closed_localhost_attempts_are_exact_completed_dimensions() {
        for outcome in [LocalhostTcpOutcome::Reachable, LocalhostTcpOutcome::Closed] {
            let completed = assess_built_in_localhost_tcp_task(&built_in_localhost_run(
                EngineRunStatus::Completed,
                Some(outcome.clone()),
            ))
            .unwrap();
            assert!(completed.contains("127.0.0.1:9001"));
            assert!(completed.contains(&enum_key(&outcome)));
        }
    }

    #[test]
    fn localhost_timeout_failure_and_missing_observation_remain_incomplete() {
        let timed_out = assess_built_in_localhost_tcp_task(&built_in_localhost_run(
            EngineRunStatus::PartiallyCompleted,
            Some(LocalhostTcpOutcome::TimedOut),
        ))
        .unwrap_err();
        assert!(timed_out.contains("timed_out"));

        let failed = assess_built_in_localhost_tcp_task(&built_in_localhost_run(
            EngineRunStatus::Failed,
            Some(LocalhostTcpOutcome::Reachable),
        ))
        .unwrap_err();
        assert!(failed.contains("observation_not_completed(failed)"));

        let missing = assess_built_in_localhost_tcp_task(&built_in_localhost_run(
            EngineRunStatus::Failed,
            None,
        ))
        .unwrap_err();
        assert!(missing.contains("observation_missing(failed)"));
    }

    #[test]
    fn localhost_task_rejects_scope_expansion_in_its_persisted_contract() {
        let mut expanded = built_in_localhost_run(
            EngineRunStatus::Completed,
            Some(LocalhostTcpOutcome::Reachable),
        );
        expanded.task_kind = EngineTaskKind::BuiltInLocalhostTcp {
            port: 9_001,
            timeout_ms: BUILT_IN_LOCALHOST_TCP_TIMEOUT_MS + 1,
            payload_bytes: 1,
        };

        let reason = assess_built_in_localhost_tcp_task(&expanded).unwrap_err();
        assert!(reason.contains("invalid_contract"));
    }
}
