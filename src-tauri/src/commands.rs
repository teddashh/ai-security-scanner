use crate::demo::build_demo_case;
use crate::domain::*;
use crate::error::{AppError, AppResult};
use crate::runtime::detect_runtime;
use crate::state::AppState;
use chrono::{Duration, Utc};
use tauri::State;

#[tauri::command]
pub async fn get_app_snapshot(state: State<'_, AppState>) -> AppResult<AppSnapshot> {
    let cases = state.storage.list_cases()?;
    let selected_case = match state.storage.selected_case_id()? {
        Some(id) => state.storage.get_case(&id).ok(),
        None => cases
            .first()
            .and_then(|summary| state.storage.get_case(&summary.id).ok()),
    };

    Ok(AppSnapshot {
        product_name: "ai-security-scanner".into(),
        product_version: env!("CARGO_PKG_VERSION").into(),
        storage_path: state.storage.path().display().to_string(),
        cases,
        selected_case,
        runtime: detect_runtime().await,
        engine_count: state.engines.manifests().len(),
    })
}

#[tauri::command]
pub fn create_case(
    request: CreateCaseRequest,
    state: State<'_, AppState>,
) -> AppResult<AssessmentCase> {
    let title = request.title.trim();
    let organization_name = request.organization_name.trim();
    if title.is_empty() {
        return Err(AppError::InvalidRequest("case title is required".into()));
    }
    if organization_name.is_empty() {
        return Err(AppError::InvalidRequest(
            "organization name is required".into(),
        ));
    }

    let case = AssessmentCase::new(
        title.into(),
        OrganizationProfile {
            organization_name: organization_name.into(),
            employee_range: request.employee_range,
            data_classes: request.data_classes,
            notes: request.notes,
        },
    );
    state.storage.save_case(&case, "case.created")?;
    state.storage.set_selected_case(Some(&case.id))?;
    Ok(case)
}

#[tauri::command]
pub fn select_case(case_id: String, state: State<'_, AppState>) -> AppResult<AssessmentCase> {
    let case = state.storage.get_case(&case_id)?;
    state.storage.set_selected_case(Some(&case.id))?;
    Ok(case)
}

#[tauri::command]
pub fn seed_demo_case(state: State<'_, AppState>) -> AppResult<AssessmentCase> {
    if let Some(summary) = state
        .storage
        .list_cases()?
        .into_iter()
        .find(|summary| summary.is_demo)
    {
        let case = state.storage.get_case(&summary.id)?;
        state.storage.set_selected_case(Some(&case.id))?;
        return Ok(case);
    }

    let case = build_demo_case();
    state.storage.save_case(&case, "case.demo_seeded")?;
    state.storage.set_selected_case(Some(&case.id))?;
    Ok(case)
}

#[tauri::command]
pub fn list_engine_manifests(state: State<'_, AppState>) -> Vec<EngineManifest> {
    state.engines.manifests().to_vec()
}

#[tauri::command]
pub fn start_discovery(case_id: String, state: State<'_, AppState>) -> AppResult<AssessmentCase> {
    let mut case = state.storage.get_case(&case_id)?;
    case.status = CaseStatus::Discovering;
    case.touch();
    state.storage.save_case(&case, "discovery.requested")?;
    Ok(case)
}

#[tauri::command]
pub fn approve_scope(
    case_id: String,
    decisions: Vec<ScopeDecision>,
    state: State<'_, AppState>,
) -> AppResult<AssessmentCase> {
    let mut case = state.storage.get_case(&case_id)?;
    for decision in decisions {
        let asset = case
            .assets
            .iter_mut()
            .find(|asset| asset.id == decision.asset_id)
            .ok_or_else(|| {
                AppError::InvalidRequest(format!("unknown asset: {}", decision.asset_id))
            })?;
        asset.owner_confirmed = true;
        asset.candidate = false;

        for permission in decision.permissions {
            if matches!(
                permission,
                ScanPermission::LowImpactExternalConnection | ScanPermission::ActiveExternalTesting
            ) && decision
                .authorization_reference
                .as_deref()
                .unwrap_or("")
                .trim()
                .is_empty()
            {
                return Err(AppError::NotAuthorized(format!(
                    "external scan authorization reference is required for asset {}",
                    asset.id
                )));
            }

            case.scope_grants.push(ScopeGrant {
                id: new_id(),
                asset_id: asset.id.clone(),
                permission,
                confirmed_by: decision.confirmed_by.clone(),
                confirmed_at: Utc::now(),
                expires_at: Some(Utc::now() + Duration::days(30)),
                authorization_reference: decision.authorization_reference.clone(),
                notes: decision.notes.clone(),
            });
        }
    }

    case.status = CaseStatus::Ready;
    case.touch();
    state.storage.save_case(&case, "scope.approved")?;
    Ok(case)
}

#[tauri::command]
pub fn start_scan(case_id: String, state: State<'_, AppState>) -> AppResult<AssessmentCase> {
    let mut case = state.storage.get_case(&case_id)?;
    if case.scope_grants.is_empty() {
        return Err(AppError::NotAuthorized(
            "at least one explicit scope grant is required before scanning".into(),
        ));
    }

    let run_id = new_id();
    let mut engine_runs = Vec::new();
    for manifest in state.engines.manifests() {
        let asset_ids: Vec<Id> = case
            .assets
            .iter()
            .filter(|asset| manifest.supported_asset_kinds.contains(&asset.kind))
            .filter(|asset| {
                manifest.required_permissions.iter().all(|required| {
                    case.scope_grants
                        .iter()
                        .any(|grant| grant.asset_id == asset.id && grant.permission == *required)
                })
            })
            .map(|asset| asset.id.clone())
            .collect();

        if !asset_ids.is_empty() {
            engine_runs.push(EngineRun {
                id: new_id(),
                scan_run_id: run_id.clone(),
                engine_id: manifest.id.clone(),
                asset_ids,
                status: EngineRunStatus::Queued,
                progress_percent: 0,
                phase: "queued".into(),
                started_at: None,
                finished_at: None,
                resume_token: None,
                engine_version: manifest.engine_version.clone(),
                image_digest: manifest
                    .image
                    .as_ref()
                    .and_then(|image| image.digest.clone()),
                rule_version: manifest.rule_version.clone(),
                adapter_version: manifest.adapter_version.clone(),
                raw_artifact_ids: Vec::new(),
                error_code: None,
                error_message: None,
            });
        }
    }

    if engine_runs.is_empty() {
        return Err(AppError::InvalidRequest(
            "no engine is compatible with the approved assets and permissions".into(),
        ));
    }

    let sequence = case.scan_runs.len() as u32 + 1;
    case.scan_runs.push(ScanRun {
        id: run_id,
        case_id: case.id.clone(),
        sequence,
        created_at: Utc::now(),
        completed_at: None,
        knowledge_cutoff: Utc::now(),
        scope_grant_ids: case
            .scope_grants
            .iter()
            .map(|grant| grant.id.clone())
            .collect(),
        engine_runs,
    });
    case.status = CaseStatus::Scanning;
    case.touch();
    state.storage.save_case(&case, "scan.planned")?;
    Ok(case)
}

fn mutate_latest_run(
    case_id: &str,
    state: &State<'_, AppState>,
    status: EngineRunStatus,
    event_type: &str,
) -> AppResult<AssessmentCase> {
    let mut case = state.storage.get_case(case_id)?;
    let run = case
        .scan_runs
        .last_mut()
        .ok_or_else(|| AppError::InvalidRequest("case has no scan run".into()))?;
    for engine_run in &mut run.engine_runs {
        if matches!(
            engine_run.status,
            EngineRunStatus::Queued
                | EngineRunStatus::Preparing
                | EngineRunStatus::Running
                | EngineRunStatus::Paused
        ) {
            engine_run.status = status.clone();
            engine_run.phase = format!("{status:?}").to_lowercase();
        }
    }
    case.touch();
    state.storage.save_case(&case, event_type)?;
    Ok(case)
}

#[tauri::command]
pub fn pause_scan(case_id: String, state: State<'_, AppState>) -> AppResult<AssessmentCase> {
    mutate_latest_run(&case_id, &state, EngineRunStatus::Paused, "scan.paused")
}

#[tauri::command]
pub fn resume_scan(case_id: String, state: State<'_, AppState>) -> AppResult<AssessmentCase> {
    mutate_latest_run(&case_id, &state, EngineRunStatus::Queued, "scan.resumed")
}

#[tauri::command]
pub fn cancel_scan(case_id: String, state: State<'_, AppState>) -> AppResult<AssessmentCase> {
    let mut case = mutate_latest_run(
        &case_id,
        &state,
        EngineRunStatus::Cancelled,
        "scan.cancelled",
    )?;
    case.status = CaseStatus::NeedsAttention;
    case.touch();
    state.storage.save_case(&case, "case.needs_attention")?;
    Ok(case)
}
