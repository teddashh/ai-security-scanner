//! Conservative case-context enrichment for canonical findings.
//!
//! Scanner severity remains intact. This layer records why an already-observed
//! issue may deserve earlier human attention in this exact case. Questionnaire
//! data never invents a finding and only affects wording when an affected asset
//! independently carries the matching sensitivity or exposure attribute.

use crate::domain::{AssessmentCase, Asset, DataClass, Finding, SourceKind};
use std::collections::BTreeSet;

const CONTEXT_VERSION_TAG: &str = "context-priority:v1";
const INTERNET_REASON: &str = "An affected asset is marked internet-exposed, and all retained source attribution for that asset is non-questionnaire.";
const SENSITIVE_REASON: &str = "An affected asset is marked sensitive, all retained source attribution for that asset is non-questionnaire, and the case questionnaire separately records sensitive-data context.";
const INTERNET_IMPACT: &str = " The affected asset is marked internet-exposed and has only retained non-questionnaire source attribution, which may increase the reachable attack surface; field-level provenance for that attribute is not retained, so it still requires human confirmation.";
const SENSITIVE_IMPACT: &str = " The affected asset is marked as containing sensitive data and has only retained non-questionnaire source attribution, while the case questionnaire separately records sensitive-data context. This may increase the impact of a confirmed exposure, but field-level data-class provenance is not retained and neither entry is itself proof of data exposure.";

/// Adds bounded, explainable case-context factors without changing severity,
/// confidence, fingerprints, evidence, workflow status, or any authorization.
pub fn apply_case_context(case: &AssessmentCase, finding: &mut Finding) {
    let affected = case
        .assets
        .iter()
        .filter(|asset| finding.asset_ids.contains(&asset.id))
        .collect::<Vec<_>>();
    let internet_exposed = affected.iter().any(|asset| {
        asset.internet_exposed == Some(true)
            && has_only_retained_non_questionnaire_sources(case, asset)
    });
    let sensitive_asset = affected.iter().any(|asset| {
        asset.contains_sensitive_data == Some(true)
            && has_only_retained_non_questionnaire_sources(case, asset)
    });
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

fn has_only_retained_non_questionnaire_sources(case: &AssessmentCase, asset: &Asset) -> bool {
    !asset.discovered_from.is_empty()
        && asset.discovered_from.iter().all(|source_id| {
            case.data_sources
                .iter()
                .find(|source| source.id == *source_id)
                .is_some_and(|source| source.kind != SourceKind::UserDeclared)
        })
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
        Asset, AssetIdentifier, AssetKind, Confidence, DataSource, FindingStatus,
        OrganizationProfile, Severity, SourceConnectionStatus,
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
        case.data_sources.push(DataSource {
            id: "source".into(),
            kind: SourceKind::AwsOrganization,
            label: "Retained AWS inventory".into(),
            status: SourceConnectionStatus::Connected,
            connected_at: None,
            last_discovered_at: None,
            read_only: true,
            metadata: BTreeMap::new(),
        });
        case
    }

    #[test]
    fn evidenced_case_context_changes_priority_and_wording_without_changing_severity() {
        let case = contextual_case();
        let mut finding = finding(&case);
        let original_confidence = finding.confidence.clone();
        let original_evidence = serde_json::to_value(&finding.evidence).unwrap();
        let original_scope = serde_json::to_value(&case.scope_grants).unwrap();
        apply_case_context(&case, &mut finding);

        assert_eq!(finding.priority, 90);
        assert_eq!(finding.severity, Severity::High);
        assert_eq!(finding.confidence, original_confidence);
        assert_eq!(
            serde_json::to_value(&finding.evidence).unwrap(),
            original_evidence
        );
        assert_eq!(
            serde_json::to_value(&case.scope_grants).unwrap(),
            original_scope
        );
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
    fn questionnaire_declared_exposure_alone_never_changes_priority() {
        let mut case = contextual_case();
        case.profile.data_classes = vec![DataClass::General];
        case.assets[0].contains_sensitive_data = None;
        case.data_sources[0].kind = SourceKind::UserDeclared;
        let mut finding = finding(&case);
        let original = finding.clone();

        apply_case_context(&case, &mut finding);

        assert_eq!(finding.priority, original.priority);
        assert_eq!(finding.severity, original.severity);
        assert_eq!(finding.confidence, original.confidence);
        assert_eq!(
            serde_json::to_value(&finding.evidence).unwrap(),
            serde_json::to_value(&original.evidence).unwrap()
        );
        assert_eq!(finding.possible_impact, original.possible_impact);
        assert!(!finding.priority_reasons.contains(&INTERNET_REASON.into()));
        assert!(!finding.tags.contains(&CONTEXT_VERSION_TAG.into()));
    }

    #[test]
    fn retained_non_questionnaire_source_can_support_internet_priority() {
        let mut case = contextual_case();
        case.profile.data_classes = vec![DataClass::General];
        case.assets[0].contains_sensitive_data = None;
        let mut finding = finding(&case);
        let original_severity = finding.severity.clone();
        let original_confidence = finding.confidence.clone();

        apply_case_context(&case, &mut finding);

        assert_eq!(finding.priority, 85);
        assert_eq!(finding.severity, original_severity);
        assert_eq!(finding.confidence, original_confidence);
        assert!(finding.priority_reasons.contains(&INTERNET_REASON.into()));
        assert!(finding.possible_impact.contains("field-level provenance"));
        assert!(finding.tags.contains(&CONTEXT_VERSION_TAG.into()));
    }

    #[test]
    fn retained_non_questionnaire_source_can_support_sensitive_priority() {
        let mut case = contextual_case();
        case.assets[0].internet_exposed = Some(false);
        let mut finding = finding(&case);
        let original_severity = finding.severity.clone();
        let original_confidence = finding.confidence.clone();

        apply_case_context(&case, &mut finding);

        assert_eq!(finding.priority, 85);
        assert_eq!(finding.severity, original_severity);
        assert_eq!(finding.confidence, original_confidence);
        assert!(finding.priority_reasons.contains(&SENSITIVE_REASON.into()));
        assert!(
            finding
                .possible_impact
                .contains("field-level data-class provenance")
        );
        assert!(finding.tags.contains(&CONTEXT_VERSION_TAG.into()));
    }

    #[test]
    fn sensitive_context_fails_closed_for_questionnaire_mixed_and_unresolved_provenance() {
        let mut questionnaire_only = contextual_case();
        questionnaire_only.assets[0].internet_exposed = Some(false);
        questionnaire_only.data_sources[0].kind = SourceKind::UserDeclared;

        let mut mixed = contextual_case();
        mixed.assets[0].internet_exposed = Some(false);
        mixed.assets[0]
            .discovered_from
            .push("questionnaire-source".into());
        mixed.data_sources.push(DataSource {
            id: "questionnaire-source".into(),
            kind: SourceKind::UserDeclared,
            label: "Questionnaire entry".into(),
            status: SourceConnectionStatus::Connected,
            connected_at: None,
            last_discovered_at: None,
            read_only: true,
            metadata: BTreeMap::new(),
        });

        let mut unresolved = contextual_case();
        unresolved.assets[0].internet_exposed = Some(false);
        unresolved.assets[0]
            .discovered_from
            .push("missing-source".into());

        for (label, case) in [
            ("questionnaire-only", questionnaire_only),
            ("mixed", mixed),
            ("unresolved", unresolved),
        ] {
            let mut finding = finding(&case);
            let original = finding.clone();

            apply_case_context(&case, &mut finding);

            assert_eq!(finding.priority, original.priority, "{label}");
            assert_eq!(finding.severity, original.severity, "{label}");
            assert_eq!(finding.confidence, original.confidence, "{label}");
            assert_eq!(finding.possible_impact, original.possible_impact, "{label}");
            assert!(
                !finding.priority_reasons.contains(&SENSITIVE_REASON.into()),
                "{label}"
            );
            assert!(
                !finding.tags.contains(&CONTEXT_VERSION_TAG.into()),
                "{label}"
            );
        }
    }

    #[test]
    fn mixed_questionnaire_and_observed_source_provenance_never_changes_priority() {
        let mut case = contextual_case();
        case.profile.data_classes = vec![DataClass::General];
        case.assets[0].contains_sensitive_data = None;
        case.assets[0]
            .discovered_from
            .push("questionnaire-source".into());
        case.data_sources.push(DataSource {
            id: "questionnaire-source".into(),
            kind: SourceKind::UserDeclared,
            label: "Questionnaire entry".into(),
            status: SourceConnectionStatus::Connected,
            connected_at: None,
            last_discovered_at: None,
            read_only: true,
            metadata: BTreeMap::new(),
        });
        let mut finding = finding(&case);
        let original = finding.clone();

        apply_case_context(&case, &mut finding);

        assert_eq!(finding.priority, original.priority);
        assert_eq!(finding.severity, original.severity);
        assert_eq!(finding.confidence, original.confidence);
        assert_eq!(finding.possible_impact, original.possible_impact);
        assert!(!finding.priority_reasons.contains(&INTERNET_REASON.into()));
        assert!(!finding.tags.contains(&CONTEXT_VERSION_TAG.into()));
    }

    #[test]
    fn unresolved_source_provenance_never_changes_priority() {
        let mut case = contextual_case();
        case.profile.data_classes = vec![DataClass::General];
        case.assets[0].contains_sensitive_data = None;
        case.assets[0].discovered_from.push("missing-source".into());
        let mut finding = finding(&case);
        let original = finding.clone();

        apply_case_context(&case, &mut finding);

        assert_eq!(finding.priority, original.priority);
        assert_eq!(finding.possible_impact, original.possible_impact);
        assert!(!finding.priority_reasons.contains(&INTERNET_REASON.into()));
        assert!(!finding.tags.contains(&CONTEXT_VERSION_TAG.into()));
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
