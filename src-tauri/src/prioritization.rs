//! Conservative case-context enrichment for canonical findings.
//!
//! Scanner severity remains intact. This layer records why an already-observed
//! issue may deserve earlier human attention in this exact case. Questionnaire
//! data never invents a finding and only affects wording when an affected asset
//! independently carries the matching sensitivity or exposure attribute.

use crate::domain::{AssessmentCase, DataClass, Finding};
use std::collections::BTreeSet;

const CONTEXT_VERSION_TAG: &str = "context-priority:v1";
const INTERNET_REASON: &str =
    "An affected asset is explicitly marked internet-exposed in the case inventory.";
const SENSITIVE_REASON: &str = "An affected asset is explicitly marked sensitive and matches data context retained by the case questionnaire.";
const INTERNET_IMPACT: &str = " The affected asset is marked internet-exposed in the case inventory, which may increase the reachable attack surface; that inventory attribute still requires human confirmation.";
const SENSITIVE_IMPACT: &str = " The affected asset is marked as containing sensitive data and the case questionnaire records a relevant data context, so a confirmed exposure may have greater impact; neither entry is itself proof of data exposure.";

/// Adds bounded, explainable case-context factors without changing severity,
/// confidence, fingerprints, evidence, workflow status, or any authorization.
pub fn apply_case_context(case: &AssessmentCase, finding: &mut Finding) {
    let affected = case
        .assets
        .iter()
        .filter(|asset| finding.asset_ids.contains(&asset.id))
        .collect::<Vec<_>>();
    let internet_exposed = affected
        .iter()
        .any(|asset| asset.internet_exposed == Some(true));
    let sensitive_asset = affected
        .iter()
        .any(|asset| asset.contains_sensitive_data == Some(true));
    let sensitive_context = case
        .profile
        .data_classes
        .iter()
        .any(|data_class| !matches!(data_class, DataClass::General));

    let mut adjustment = 0_u8;
    if internet_exposed {
        if push_once(&mut finding.priority_reasons, INTERNET_REASON) {
            adjustment = adjustment.saturating_add(5);
        }
        append_once(&mut finding.possible_impact, INTERNET_IMPACT);
    }
    if sensitive_asset && sensitive_context {
        if push_once(&mut finding.priority_reasons, SENSITIVE_REASON) {
            adjustment = adjustment.saturating_add(5);
        }
        append_once(&mut finding.possible_impact, SENSITIVE_IMPACT);
    }
    if adjustment > 0 {
        finding.priority = finding.priority.saturating_add(adjustment).min(100);
        push_once(&mut finding.tags, CONTEXT_VERSION_TAG);
    }

    deduplicate(&mut finding.priority_reasons);
    deduplicate(&mut finding.tags);
}

fn append_once(value: &mut String, suffix: &str) {
    if !value.contains(suffix.trim()) {
        value.push_str(suffix);
    }
}

fn push_once(values: &mut Vec<String>, value: &str) -> bool {
    if !values.iter().any(|candidate| candidate == value) {
        values.push(value.into());
        return true;
    }
    false
}

fn deduplicate(values: &mut Vec<String>) {
    let mut observed = BTreeSet::new();
    values.retain(|value| observed.insert(value.clone()));
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::domain::{
        Asset, AssetIdentifier, AssetKind, Confidence, FindingStatus, OrganizationProfile, Severity,
    };
    use std::collections::BTreeMap;

    fn finding(case: &AssessmentCase) -> Finding {
        Finding {
            id: "finding".into(),
            case_id: case.id.clone(),
            first_seen_run_id: "run".into(),
            last_seen_run_id: "run".into(),
            fingerprint: "engine:rule:asset".into(),
            title: "Observed issue".into(),
            plain_language_summary: "Scanner observation".into(),
            possible_impact: "Possible impact requires review.".into(),
            severity: Severity::High,
            confidence: Confidence::High,
            priority: 80,
            priority_reasons: vec!["Source severity: high".into()],
            asset_ids: vec!["asset".into()],
            evidence: vec![],
            control_references: vec![],
            recommendation: "Ask a qualified reviewer.".into(),
            verification_guidance: "Rerun after an approved change.".into(),
            rollback_considerations: None,
            official_references: vec![],
            recommended_expert_type: "Security reviewer".into(),
            status: FindingStatus::Unreviewed,
            tags: vec![],
        }
    }

    fn contextual_case() -> AssessmentCase {
        let mut case = AssessmentCase::new(
            "Context".into(),
            OrganizationProfile {
                organization_name: "Example".into(),
                employee_range: "2-49".into(),
                data_classes: vec![DataClass::PersonallyIdentifiableInformation],
                notes: None,
            },
        );
        case.assets.push(Asset {
            id: "asset".into(),
            kind: AssetKind::CloudResource,
            name: "customer data store".into(),
            provider: Some("aws".into()),
            region: Some("us-east-1".into()),
            identifiers: vec![AssetIdentifier {
                namespace: "test".into(),
                value: "asset".into(),
            }],
            discovered_from: vec!["source".into()],
            candidate: false,
            owner_confirmed: true,
            internet_exposed: Some(true),
            contains_sensitive_data: Some(true),
            metadata: BTreeMap::new(),
        });
        case
    }

    #[test]
    fn evidenced_case_context_changes_priority_and_wording_without_changing_severity() {
        let case = contextual_case();
        let mut finding = finding(&case);
        apply_case_context(&case, &mut finding);

        assert_eq!(finding.priority, 90);
        assert_eq!(finding.severity, Severity::High);
        assert!(finding.priority_reasons.contains(&INTERNET_REASON.into()));
        assert!(finding.priority_reasons.contains(&SENSITIVE_REASON.into()));
        assert!(
            finding
                .possible_impact
                .contains("neither entry is itself proof")
        );
        assert!(finding.tags.contains(&CONTEXT_VERSION_TAG.into()));

        let once = finding.clone();
        apply_case_context(&case, &mut finding);
        assert_eq!(finding.priority, once.priority);
        assert_eq!(finding.priority_reasons, once.priority_reasons);
        assert_eq!(finding.possible_impact, once.possible_impact);
    }

    #[test]
    fn questionnaire_context_alone_never_invents_asset_sensitivity() {
        let mut case = contextual_case();
        case.assets[0].internet_exposed = None;
        case.assets[0].contains_sensitive_data = None;
        let mut finding = finding(&case);
        apply_case_context(&case, &mut finding);

        assert_eq!(finding.priority, 80);
        assert_eq!(finding.possible_impact, "Possible impact requires review.");
        assert!(!finding.tags.contains(&CONTEXT_VERSION_TAG.into()));
    }

    #[test]
    fn unrelated_asset_attributes_cannot_change_a_finding() {
        let mut case = contextual_case();
        case.assets[0].id = "different-asset".into();
        let mut finding = finding(&case);
        apply_case_context(&case, &mut finding);

        assert_eq!(finding.priority, 80);
        assert_eq!(finding.possible_impact, "Possible impact requires review.");
        assert!(!finding.tags.contains(&CONTEXT_VERSION_TAG.into()));
    }

    #[test]
    fn generic_questionnaire_data_does_not_assert_sensitive_impact() {
        let mut case = contextual_case();
        case.profile.data_classes = vec![DataClass::General];
        case.assets[0].internet_exposed = Some(false);
        let mut finding = finding(&case);
        apply_case_context(&case, &mut finding);

        assert_eq!(finding.priority, 80);
        assert!(!finding.possible_impact.contains("sensitive data"));
        assert!(!finding.tags.contains(&CONTEXT_VERSION_TAG.into()));
    }
}
