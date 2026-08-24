use crate::domain::{AssessmentCase, Confidence, Evidence, Finding, FindingObservation, Severity};
use crate::error::{AppError, AppResult};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;
use uuid::Uuid;

pub const OSCAL_VERSION: &str = "1.2.3";
pub const OSCAL_PROPERTY_NAMESPACE: &str = "urn:ai-security-scanner:oscal:props";
pub const OSCAL_EXPORT_NOTICE: &str = "This document contains preliminary scanner observations. It is not a formal assessment, audit, certification, attestation, or forensic conclusion. Related control references are navigation coordinates only and do not state that a control passed, failed, was assessed, or is compliant.";

/// Convert canonical observations for a run to an OSCAL Assessment Results JSON model.
///
/// OSCAL requires an assessment-plan import and reviewed-controls structure. Because
/// the product does not perform a formal control assessment, the exporter points to
/// an explicit placeholder plan and selects its empty control set. Canonical control
/// mappings appear only as namespaced observation properties.
pub fn export_oscal_assessment_results(case: &AssessmentCase, run_id: &str) -> AppResult<Value> {
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
    let mut canonical_observations = case
        .finding_observations
        .iter()
        .filter(|observation| observation.run_id == run_id)
        .collect::<Vec<_>>();
    canonical_observations.sort_by(|left, right| {
        left.fingerprint
            .cmp(&right.fingerprint)
            .then_with(|| left.id.cmp(&right.id))
    });

    let observations = canonical_observations
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
            Ok(oscal_observation(finding, observation))
        })
        .collect::<AppResult<Vec<_>>>()?;

    let end = run.completed_at.unwrap_or(run.created_at);
    Ok(json!({
        "assessment-results": {
            "uuid": stable_uuid(&format!("assessment-results:{}:{}", case.id, run_id)),
            "metadata": {
                "title": format!("{} — preliminary scanner observations", case.title),
                "last-modified": end.to_rfc3339(),
                "version": env!("CARGO_PKG_VERSION"),
                "oscal-version": OSCAL_VERSION,
                "remarks": OSCAL_EXPORT_NOTICE
            },
            "import-ap": {
                "href": "urn:ai-security-scanner:placeholder:non-formal-assessment-plan",
                "remarks": "Structural placeholder required by the OSCAL Assessment Results model. No formal assessment plan was executed or imported."
            },
            "results": [{
                "uuid": stable_uuid(&format!("assessment-result:{}:{}", case.id, run_id)),
                "title": format!("Scanner run {} observations", run.sequence),
                "description": "Read-only and explicitly authorized scanner observations normalized by ai-security-scanner.",
                "start": run.created_at.to_rfc3339(),
                "end": end.to_rfc3339(),
                "props": [
                    property("canonical-case-id", &case.id),
                    property("canonical-run-id", run_id),
                    property("export-kind", "preliminary-scanner-observations")
                ],
                "reviewed-controls": {
                    "description": "No formal controls were reviewed. This required OSCAL structure selects the empty set from the explicit placeholder assessment plan; related coordinates appear only on observations.",
                    "control-selections": [{
                        "description": "Empty structural selection; it makes no control assessment claim.",
                        "include-all": {}
                    }]
                },
                "observations": observations,
                "remarks": OSCAL_EXPORT_NOTICE
            }]
        }
    }))
}

pub fn export_oscal_assessment_results_bytes(
    case: &AssessmentCase,
    run_id: &str,
) -> AppResult<Vec<u8>> {
    Ok(serde_json::to_vec_pretty(
        &export_oscal_assessment_results(case, run_id)?,
    )?)
}

fn oscal_observation(finding: &Finding, observation: &FindingObservation) -> Value {
    let mut props = vec![
        property("canonical-finding-id", &finding.id),
        property("canonical-fingerprint", &observation.fingerprint),
        property("canonical-severity", severity_name(&observation.severity)),
        property(
            "canonical-confidence",
            confidence_name(&observation.confidence),
        ),
    ];

    let mut asset_ids = observation.asset_ids.clone();
    asset_ids.sort();
    asset_ids.dedup();
    for asset_id in asset_ids {
        props.push(property("canonical-asset-id", &asset_id));
    }

    let mut engine_ids = observation.engine_ids.clone();
    engine_ids.sort();
    engine_ids.dedup();
    for engine_id in engine_ids {
        props.push(property("source-engine-id", &engine_id));
    }

    for reference in &finding.control_references {
        props.push(json!({
            "name": "related-control-coordinate",
            "ns": OSCAL_PROPERTY_NAMESPACE,
            "value": format!(
                "{}@{}:{}",
                reference.framework, reference.framework_version, reference.control_id
            ),
            "remarks": format!(
                "Coordinate only; no assessment result. Title: {}. Relationship: {}. Rationale: {}. Mapping version: {}.",
                reference.title,
                reference.relationship,
                reference.rationale,
                reference.mapping_version
            )
        }));
    }

    let mut evidence = finding
        .evidence
        .iter()
        .filter(|evidence| evidence.run_id == observation.run_id)
        .collect::<Vec<_>>();
    evidence.sort_by(|left, right| left.id.cmp(&right.id));
    let relevant_evidence: Vec<Value> = if evidence.is_empty() {
        let mut hashes = observation.evidence_hashes.clone();
        hashes.sort();
        hashes.dedup();
        hashes
            .into_iter()
            .map(|hash| {
                json!({
                    "description": "Canonical evidence content hash; raw evidence may be omitted from this schema export.",
                    "props": [property("sha-256", &hash)]
                })
            })
            .collect()
    } else {
        evidence.into_iter().map(oscal_evidence).collect()
    };

    json!({
        "uuid": stable_uuid(&format!(
            "observation:{}:{}:{}",
            observation.run_id, observation.id, observation.fingerprint
        )),
        "title": finding.title,
        "description": format!(
            "{} Possible impact: {}",
            finding.plain_language_summary, finding.possible_impact
        ),
        "props": props,
        "methods": ["EXAMINE"],
        "types": ["discovery"],
        "relevant-evidence": relevant_evidence,
        "collected": observation.observed_at.to_rfc3339(),
        "remarks": format!(
            "Preliminary observation. Suggested next step: {} Verification guidance: {}",
            finding.recommendation, finding.verification_guidance
        )
    })
}

fn oscal_evidence(evidence: &Evidence) -> Value {
    let mut props = vec![
        property("canonical-evidence-id", &evidence.id),
        property("source-engine-id", &evidence.engine_id),
        property("canonical-scan-run-id", &evidence.run_id),
        property("raw-artifact-id", &evidence.artifact_id),
        property("sha-256", &evidence.artifact_sha256),
        property("redacted", if evidence.redacted { "true" } else { "false" }),
    ];
    if let Some(engine_run_id) = &evidence.engine_run_id {
        props.push(property("canonical-engine-run-id", engine_run_id));
    } else {
        props.push(property(
            "canonical-engine-run-id-state",
            "legacy-not-recorded",
        ));
    }
    json!({
        "description": evidence.summary,
        "props": props
    })
}

fn property(name: &str, value: &str) -> Value {
    json!({
        "name": name,
        "ns": OSCAL_PROPERTY_NAMESPACE,
        "value": value
    })
}

fn stable_uuid(seed: &str) -> String {
    let digest = Sha256::digest(seed.as_bytes());
    let mut bytes = [0_u8; 16];
    bytes.copy_from_slice(&digest[..16]);
    bytes[6] = (bytes[6] & 0x0f) | 0x50;
    bytes[8] = (bytes[8] & 0x3f) | 0x80;
    Uuid::from_bytes(bytes).to_string()
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
    use crate::domain::*;
    use chrono::{TimeZone, Utc};

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
        case.scan_runs.push(ScanRun {
            id: "run-1".into(),
            case_id: case.id.clone(),
            sequence: 1,
            created_at: time,
            completed_at: Some(time),
            knowledge_cutoff: time,
            verification_baseline_run_id: None,
            scope_grant_ids: vec![],
            scope_grant_snapshots: vec![],
            engine_runs: vec![],
        });
        case.findings.push(Finding {
            id: "finding-1".into(),
            case_id: case.id.clone(),
            first_seen_run_id: "run-1".into(),
            last_seen_run_id: "run-1".into(),
            fingerprint: "fp-1".into(),
            title: "Potential issue".into(),
            plain_language_summary: "A setting needs review.".into(),
            possible_impact: "Unexpected access".into(),
            severity: Severity::Medium,
            confidence: Confidence::High,
            priority: 60,
            priority_reasons: vec![],
            asset_ids: vec!["asset-1".into()],
            evidence: vec![],
            control_references: vec![ControlReference {
                framework: "ISO/IEC 27001".into(),
                framework_version: "2022".into(),
                control_id: "A.8.3".into(),
                title: "Information access restriction".into(),
                relationship: "related".into(),
                rationale: "Possible relationship".into(),
                mapping_version: "1".into(),
            }],
            recommendation: "Have the system owner review it.".into(),
            verification_guidance: "Repeat the read-only inspection.".into(),
            rollback_considerations: None,
            official_references: vec![],
            recommended_expert_type: "Security engineer".into(),
            status: FindingStatus::Unreviewed,
            tags: vec![],
        });
        case.finding_observations.push(FindingObservation {
            id: "observation-1".into(),
            run_id: "run-1".into(),
            finding_id: "finding-1".into(),
            fingerprint: "fp-1".into(),
            asset_ids: vec!["asset-1".into()],
            engine_ids: vec!["engine-1".into()],
            severity: Severity::Medium,
            confidence: Confidence::High,
            evidence_hashes: vec!["abc".into()],
            observed_at: time,
        });
        case
    }

    #[test]
    fn emits_observations_and_coordinate_only_control_properties() {
        let value = export_oscal_assessment_results(&fixture(), "run-1").unwrap();
        let root = &value["assessment-results"];
        assert_eq!(root["metadata"]["oscal-version"], OSCAL_VERSION);
        let result = &root["results"][0];
        assert!(result.get("findings").is_none());
        assert!(result.get("risks").is_none());
        assert!(result.get("attestations").is_none());
        assert!(
            result["reviewed-controls"]["control-selections"][0]
                .get("include-controls")
                .is_none()
        );
        let props = result["observations"][0]["props"].as_array().unwrap();
        let coordinate = props
            .iter()
            .find(|prop| prop["name"] == "related-control-coordinate")
            .unwrap();
        assert_eq!(coordinate["value"], "ISO/IEC 27001@2022:A.8.3");
        assert!(
            coordinate["remarks"]
                .as_str()
                .unwrap()
                .contains("no assessment result")
        );
    }

    #[test]
    fn stable_uuid_is_repeatable_and_well_formed() {
        let first = stable_uuid("same input");
        assert_eq!(first, stable_uuid("same input"));
        assert!(Uuid::parse_str(&first).is_ok());
    }
}
