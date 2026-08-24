use crate::domain::{
    AssessmentCase, Asset, Confidence, Evidence, Finding, FindingObservation, FindingStatus,
    Severity,
};
use crate::error::{AppError, AppResult};
use serde_json::{Map, Value, json};
use std::collections::BTreeMap;

pub const OCSF_SCHEMA_VERSION: &str = "1.10.0-dev";
pub const OCSF_EXPORT_NOTICE: &str = "Preliminary scanner observations only. Related control references are navigation coordinates, not compliance results. This export is not an audit or forensic conclusion.";

/// Convert canonical observations for one run into OCSF Detection Finding events.
///
/// Detection Finding (class UID 2004) is used because the canonical model can
/// represent several scanner families and does not always contain the fields
/// required by the narrower Vulnerability or Compliance Finding classes.
pub fn export_ocsf_finding_events(case: &AssessmentCase, run_id: &str) -> AppResult<Vec<Value>> {
    let run = case
        .scan_runs
        .iter()
        .find(|run| run.id == run_id)
        .ok_or_else(|| AppError::InvalidRequest(format!("scan run not found: {run_id}")))?;
    if run.case_id != case.id {
        return Err(AppError::InvalidRequest(
            "scan run does not belong to the selected case".into(),
        ));
    }

    let findings = case
        .findings
        .iter()
        .map(|finding| (finding.id.as_str(), finding))
        .collect::<BTreeMap<_, _>>();
    let assets = case
        .assets
        .iter()
        .map(|asset| (asset.id.as_str(), asset))
        .collect::<BTreeMap<_, _>>();

    let mut observations = case
        .finding_observations
        .iter()
        .filter(|observation| observation.run_id == run_id)
        .collect::<Vec<_>>();
    observations.sort_by(|left, right| {
        left.fingerprint
            .cmp(&right.fingerprint)
            .then_with(|| left.id.cmp(&right.id))
    });

    observations
        .into_iter()
        .map(|observation| {
            let finding = findings
                .get(observation.finding_id.as_str())
                .ok_or_else(|| {
                    AppError::InvalidRequest(format!(
                        "observation {} references missing finding {}",
                        observation.id, observation.finding_id
                    ))
                })?;
            Ok(to_event(case, run_id, finding, observation, &assets))
        })
        .collect()
}

pub fn export_ocsf_finding_events_bytes(case: &AssessmentCase, run_id: &str) -> AppResult<Vec<u8>> {
    Ok(serde_json::to_vec_pretty(&export_ocsf_finding_events(
        case, run_id,
    )?)?)
}

fn to_event(
    case: &AssessmentCase,
    run_id: &str,
    finding: &Finding,
    observation: &FindingObservation,
    assets: &BTreeMap<&str, &Asset>,
) -> Value {
    let activity_id = if finding.first_seen_run_id == run_id {
        1
    } else {
        2
    };
    let activity_name = if activity_id == 1 { "Create" } else { "Update" };
    let (severity_id, severity) = ocsf_severity(&observation.severity);
    let (confidence_id, confidence) = ocsf_confidence(&observation.confidence);
    let (status_id, status) = ocsf_status(&finding.status);

    let first_seen_time = case
        .scan_runs
        .iter()
        .find(|run| run.id == finding.first_seen_run_id)
        .map(|run| run.created_at.timestamp_millis())
        .unwrap_or_else(|| observation.observed_at.timestamp_millis());

    let mut asset_ids = observation.asset_ids.clone();
    asset_ids.sort();
    asset_ids.dedup();
    let resources = asset_ids
        .iter()
        .map(|asset_id| match assets.get(asset_id.as_str()) {
            Some(asset) => resource_value(asset),
            None => json!({
                "uid": asset_id,
                "name": "Unknown canonical asset",
                "role_id": 3,
                "role": "Affected"
            }),
        })
        .collect::<Vec<_>>();

    let mut evidence = finding
        .evidence
        .iter()
        .filter(|evidence| evidence.run_id == run_id)
        .collect::<Vec<_>>();
    evidence.sort_by(|left, right| left.id.cmp(&right.id));
    let evidences = if evidence.is_empty() {
        let mut hashes = observation.evidence_hashes.clone();
        hashes.sort();
        hashes.dedup();
        hashes
            .into_iter()
            .map(|sha256| {
                json!({
                    "name": "Canonical evidence hash",
                    "data": { "sha256": sha256 }
                })
            })
            .collect::<Vec<_>>()
    } else {
        evidence.into_iter().map(evidence_value).collect()
    };

    let control_coordinates = finding
        .control_references
        .iter()
        .map(|reference| {
            json!({
                "framework": reference.framework,
                "framework_version": reference.framework_version,
                "control_id": reference.control_id,
                "title": reference.title,
                "relationship": reference.relationship,
                "rationale": reference.rationale,
                "mapping_version": reference.mapping_version,
                "assertion": "related_coordinate_only"
            })
        })
        .collect::<Vec<_>>();

    let mut engines = observation.engine_ids.clone();
    engines.sort();
    engines.dedup();

    json!({
        "activity_id": activity_id,
        "activity_name": activity_name,
        "category_uid": 2,
        "category_name": "Findings",
        "class_uid": 2004,
        "class_name": "Detection Finding",
        "type_uid": 200400 + activity_id,
        "type_name": format!("Detection Finding: {activity_name}"),
        "time": observation.observed_at.timestamp_millis(),
        "severity_id": severity_id,
        "severity": severity,
        "confidence_id": confidence_id,
        "confidence": confidence,
        "status_id": status_id,
        "status": status,
        "message": finding.plain_language_summary,
        "metadata": {
            "uid": observation.id,
            "original_event_uid": observation.id,
            "correlation_uid": case.id,
            "version": OCSF_SCHEMA_VERSION,
            "product": {
                "name": "ai-security-scanner",
                "vendor_name": "ai-security-scanner",
                "version": env!("CARGO_PKG_VERSION")
            },
            "source": "Canonical scanner observation"
        },
        "finding_info": {
            "uid": finding.id,
            "uid_alt": finding.fingerprint,
            "title": finding.title,
            "desc": finding.plain_language_summary,
            "created_time": first_seen_time,
            "first_seen_time": first_seen_time,
            "last_seen_time": observation.observed_at.timestamp_millis(),
            "types": ["Preliminary scanner observation"],
            "tags": finding.tags
        },
        "resources": resources,
        "evidences": evidences,
        "unmapped": {
            "ai_security_scanner": {
                "canonical_fingerprint": observation.fingerprint,
                "canonical_confidence": confidence_name(&observation.confidence),
                "priority": finding.priority,
                "priority_reasons": finding.priority_reasons,
                "possible_impact": finding.possible_impact,
                "recommendation": finding.recommendation,
                "verification_guidance": finding.verification_guidance,
                "rollback_considerations": finding.rollback_considerations,
                "official_references": finding.official_references,
                "recommended_expert_type": finding.recommended_expert_type,
                "engine_ids": engines,
                "run_id": run_id,
                "related_control_coordinates": control_coordinates,
                "control_mapping_notice": "References are navigation coordinates only; no control pass, failure, compliance, or audit conclusion is asserted.",
                "export_notice": OCSF_EXPORT_NOTICE,
                "omitted_canonical_areas": [
                    "case scope grants",
                    "coverage ledger",
                    "asset relationships",
                    "workflow history"
                ]
            }
        }
    })
}

fn resource_value(asset: &Asset) -> Value {
    let mut resource = Map::new();
    resource.insert("uid".into(), json!(asset.id));
    resource.insert("name".into(), json!(asset.name));
    resource.insert("type".into(), json!(asset_kind_name(asset)));
    resource.insert("role_id".into(), json!(3));
    resource.insert("role".into(), json!("Affected"));
    if let Some(provider) = &asset.provider {
        resource.insert("provider".into(), json!(provider));
    }
    if let Some(region) = &asset.region {
        resource.insert("region".into(), json!(region));
    }
    Value::Object(resource)
}

fn asset_kind_name(asset: &Asset) -> String {
    serde_json::to_value(&asset.kind)
        .ok()
        .and_then(|value| value.as_str().map(str::to_owned))
        .unwrap_or_else(|| "other".into())
}

fn evidence_value(evidence: &Evidence) -> Value {
    json!({
        "uid": evidence.id,
        "name": format!("{:?}", evidence.kind),
        "data": {
            "summary": evidence.summary,
            "engine_id": evidence.engine_id,
            "artifact_uid": evidence.artifact_id,
            "artifact_sha256": evidence.artifact_sha256,
            "pointer": evidence.pointer,
            "redacted": evidence.redacted,
            "observed_time": evidence.observed_at.timestamp_millis()
        }
    })
}

fn ocsf_severity(severity: &Severity) -> (u8, &'static str) {
    match severity {
        Severity::Informational => (1, "Informational"),
        Severity::Low => (2, "Low"),
        Severity::Medium => (3, "Medium"),
        Severity::High => (4, "High"),
        Severity::Critical => (5, "Critical"),
    }
}

fn ocsf_confidence(confidence: &Confidence) -> (u8, &'static str) {
    match confidence {
        Confidence::Low => (1, "Low"),
        Confidence::Medium => (2, "Medium"),
        Confidence::High | Confidence::Confirmed => (3, "High"),
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

fn ocsf_status(status: &FindingStatus) -> (u8, &'static str) {
    match status {
        FindingStatus::Unreviewed => (1, "New"),
        FindingStatus::SentForReview
        | FindingStatus::Confirmed
        | FindingStatus::RemediationPlanned
        | FindingStatus::RemediatedPendingVerification => (2, "In Progress"),
        FindingStatus::FalsePositive => (3, "Suppressed"),
        FindingStatus::Closed => (4, "Resolved"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::domain::*;
    use chrono::{TimeZone, Utc};
    use std::collections::BTreeMap;

    fn fixture() -> AssessmentCase {
        let time = Utc.with_ymd_and_hms(2026, 8, 24, 12, 0, 0).unwrap();
        let mut case = AssessmentCase::new(
            "Export".into(),
            OrganizationProfile {
                organization_name: "Example".into(),
                employee_range: "1-10".into(),
                data_classes: vec![DataClass::General],
                notes: None,
            },
        );
        case.id = "case-1".into();
        case.assets.push(Asset {
            id: "asset-1".into(),
            kind: AssetKind::CloudAccount,
            name: "Account".into(),
            provider: Some("AWS".into()),
            region: Some("us-east-1".into()),
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
            created_at: time,
            completed_at: Some(time),
            knowledge_cutoff: time,
            scope_grant_ids: vec![],
            engine_runs: vec![],
        });
        case.findings.push(Finding {
            id: "finding-1".into(),
            case_id: case.id.clone(),
            first_seen_run_id: "run-1".into(),
            last_seen_run_id: "run-1".into(),
            fingerprint: "fp-1".into(),
            title: "Public bucket".into(),
            plain_language_summary: "A bucket may be public.".into(),
            possible_impact: "Data exposure".into(),
            severity: Severity::High,
            confidence: Confidence::High,
            priority: 90,
            priority_reasons: vec!["Internet exposed".into()],
            asset_ids: vec!["asset-1".into()],
            evidence: vec![],
            control_references: vec![ControlReference {
                framework: "NIST CSF".into(),
                framework_version: "2.0".into(),
                control_id: "PR.DS-01".into(),
                title: "Data-at-rest protection".into(),
                relationship: "related".into(),
                rationale: "Possible relationship".into(),
                mapping_version: "1".into(),
            }],
            recommendation: "Ask the cloud owner to review access.".into(),
            verification_guidance: "Re-run the read-only check.".into(),
            rollback_considerations: None,
            official_references: vec![],
            recommended_expert_type: "Cloud security engineer".into(),
            status: FindingStatus::Unreviewed,
            tags: vec!["cloud".into()],
        });
        case.finding_observations.push(FindingObservation {
            id: "observation-1".into(),
            run_id: "run-1".into(),
            finding_id: "finding-1".into(),
            fingerprint: "fp-1".into(),
            asset_ids: vec!["asset-1".into()],
            engine_ids: vec!["prowler".into()],
            severity: Severity::High,
            confidence: Confidence::Confirmed,
            evidence_hashes: vec!["abc".into()],
            observed_at: time,
        });
        case
    }

    #[test]
    fn maps_to_detection_finding_without_compliance_assertions() {
        let events = export_ocsf_finding_events(&fixture(), "run-1").unwrap();
        assert_eq!(events.len(), 1);
        let event = &events[0];
        assert_eq!(event["class_uid"], 2004);
        assert_eq!(event["type_uid"], 200401);
        assert_eq!(event["severity_id"], 4);
        assert_eq!(event["confidence_id"], 3);
        assert_eq!(event["resources"][0]["uid"], "asset-1");
        assert_eq!(event["finding_info"]["uid"], "finding-1");
        assert!(event.get("compliance").is_none());
        let coordinates = &event["unmapped"]["ai_security_scanner"]["related_control_coordinates"];
        assert_eq!(coordinates[0]["assertion"], "related_coordinate_only");
    }
}
