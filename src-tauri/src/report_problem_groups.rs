//! Owner-reviewed presentation groups for related AWS checks. Findings and
//! correlation decisions remain unchanged; every member stays in the report.

use crate::beginner_report::{BeginnerFinding, FindingSnapshotSource, severity_rank};
use crate::domain::{AwsIamPolicySource, Id, ScanRun};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet};

const RULE_VERSION: &str = "aws-related-checks-1";

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ReportProblemKind {
    IamPasswordPolicy,
    RootAccountUsage,
    IamPolicyPermissions,
}

/// How many members of a problem group this product ordered lower than their
/// scanner severity suggests.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum LowerPriorityMembers {
    Partial,
    All,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ReportProblemGroup {
    pub group_id: Id,
    pub rule_version: String,
    pub kind: ReportProblemKind,
    pub title: String,
    pub target_asset_id: Id,
    pub representative_finding_id: Id,
    pub finding_ids: Vec<Id>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub policy_name: Option<String>,
    /// Present when at least one member carries a product order lower than its
    /// scanner severity. Omitted from the group id: it is presentation only.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub lower_priority_members: Option<LowerPriorityMembers>,
}

impl ReportProblemGroup {
    pub fn next_step_english(&self) -> Option<&'static str> {
        match self.kind {
            ReportProblemKind::IamPasswordPolicy => match self.lower_priority_members {
                Some(LowerPriorityMembers::Partial) => Some(
                    "Review the account's IAM password policy. Fix the failed length or reuse settings first; change the character-mix or expiry settings only if an audit you must pass still requires them.",
                ),
                Some(LowerPriorityMembers::All) => Some(
                    "Change these IAM password policy settings only if an audit you must pass still requires them; NIST SP 800-63B-4 says not to require character mixes or scheduled expiry.",
                ),
                None => Some(
                    "Review the account's IAM password policy and address each failed setting.",
                ),
            },
            ReportProblemKind::RootAccountUsage => Some(
                "Review each scanner's root-usage window and use an IAM role for routine work.",
            ),
            ReportProblemKind::IamPolicyPermissions => None,
        }
    }

    pub fn next_step_zh_hant(&self) -> Option<&'static str> {
        match self.kind {
            ReportProblemKind::IamPasswordPolicy => match self.lower_priority_members {
                Some(LowerPriorityMembers::Partial) => Some(
                    "檢查帳號的 IAM 密碼政策：先調整未通過的長度或重複使用設定；字元組成或到期設定，只有在必須通過的稽核仍要求時才需要變更。",
                ),
                Some(LowerPriorityMembers::All) => Some(
                    "只有在必須通過的稽核仍要求時，才需要變更這些 IAM 密碼政策設定；NIST SP 800-63B-4 要求不要強制混合字元類型或定期到期。",
                ),
                None => Some("檢查帳號的 IAM 密碼政策，並調整每項未通過的設定。"),
            },
            ReportProblemKind::RootAccountUsage => {
                Some("檢查各掃描工具記錄的 root 使用時間範圍，日常工作改用 IAM role。")
            }
            ReportProblemKind::IamPolicyPermissions => None,
        }
    }

    pub fn impact_english(&self) -> Option<&'static str> {
        match self.kind {
            ReportProblemKind::IamPasswordPolicy => match self.lower_priority_members {
                Some(LowerPriorityMembers::All) => Some(
                    "CIS AWS Foundations Benchmark v1.2.0 lists these settings; current guidance does not treat their absence as a weakness.",
                ),
                Some(LowerPriorityMembers::Partial) | None => Some(
                    "Weak password settings increase the risk of unauthorized access to IAM users.",
                ),
            },
            ReportProblemKind::RootAccountUsage => Some(
                "Root-account activity uses permissions with broad control of this AWS account.",
            ),
            ReportProblemKind::IamPolicyPermissions => None,
        }
    }

    pub fn impact_zh_hant(&self) -> Option<&'static str> {
        match self.kind {
            ReportProblemKind::IamPasswordPolicy => match self.lower_priority_members {
                Some(LowerPriorityMembers::All) => Some(
                    "CIS AWS Foundations Benchmark v1.2.0 列出這些設定；現行指引不把缺少這些設定視為弱點。",
                ),
                Some(LowerPriorityMembers::Partial) | None => {
                    Some("較弱的密碼設定會增加 IAM 使用者遭未授權存取的風險。")
                }
            },
            ReportProblemKind::RootAccountUsage => {
                Some("root 帳號的活動會使用可廣泛控制此 AWS 帳號的權限。")
            }
            ReportProblemKind::IamPolicyPermissions => None,
        }
    }

    pub fn title_english(&self) -> String {
        match self.kind {
            ReportProblemKind::IamPasswordPolicy => "IAM password policy needs attention".into(),
            ReportProblemKind::RootAccountUsage => "Root account used recently".into(),
            ReportProblemKind::IamPolicyPermissions => format!(
                "Review IAM policy permissions: {}",
                self.policy_name.as_deref().unwrap_or("IAM policy")
            ),
        }
    }

    pub fn title_zh_hant(&self) -> String {
        match self.kind {
            ReportProblemKind::IamPasswordPolicy => "IAM 密碼政策需要調整".into(),
            ReportProblemKind::RootAccountUsage => "最近使用過 root 帳號".into(),
            ReportProblemKind::IamPolicyPermissions => format!(
                "檢查 IAM policy 的權限：{}",
                self.policy_name.as_deref().unwrap_or("IAM policy")
            ),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
struct Subject {
    kind: ReportProblemKind,
    asset_id: Id,
    resource: String,
}

const PROWLER_PASSWORD_RULES: &[&str] = &[
    "iam_password_policy_lowercase",
    "iam_password_policy_uppercase",
    "iam_password_policy_number",
    "iam_password_policy_symbol",
    "iam_password_policy_minimum_length_14",
    "iam_password_policy_reuse_24",
    "iam_password_policy_expires_passwords_within_90_days_or_less",
];
const SCOUT_PASSWORD_RULES: &[&str] = &[
    "iam-password-policy-minimum-length",
    "iam-password-policy-reuse-enabled",
    "iam-password-policy-no-expiration",
    "iam-password-policy-expiration-threshold",
];

fn subject(finding: &BeginnerFinding, run: &ScanRun) -> Option<(Subject, Option<String>)> {
    if run.completed_at.is_none()
        || finding.snapshot_source != FindingSnapshotSource::FrozenSelectedRun
        || finding.target_asset_ids.len() != 1
        || finding.evidence_references.is_empty()
        || finding
            .severity_basis_code
            .is_some_and(|code| code.is_exposure_observation())
    {
        return None;
    }
    let asset_id = &finding.target_asset_ids[0];
    let asset = &run
        .report_asset_snapshots
        .iter()
        .find(|snapshot| {
            &snapshot.asset.id == asset_id
                && snapshot.asset.provider.as_deref() == Some("aws")
                && snapshot.asset.kind == crate::domain::AssetKind::CloudAccount
                && snapshot.disposition == crate::domain::ReportAssetDisposition::RequestedForScan
        })?
        .asset;
    let account_ids = asset
        .identifiers
        .iter()
        .filter(|identifier| identifier.namespace == "aws_account_id")
        .map(|identifier| identifier.value.as_str())
        .collect::<BTreeSet<_>>();
    if account_ids.len() != 1 {
        return None;
    }
    let account_id = account_ids.into_iter().next()?;
    if account_id.len() != 12 || !account_id.bytes().all(|byte| byte.is_ascii_digit()) {
        return None;
    }
    let mut subjects = BTreeSet::new();
    let mut policy_name = None;
    for evidence in &finding.evidence_references {
        if !evidence.details_frozen {
            return None;
        }
        let task_id = evidence.engine_run_id.as_ref()?;
        let task = run.engine_runs.iter().find(|task| {
            &task.id == task_id
                && task.scan_run_id == run.id
                && task.engine_id == evidence.engine_id
                && task.asset_ids.len() == 1
                && task.asset_ids[0] == *asset_id
        })?;
        let artifact_id = evidence.artifact_id.as_ref()?;
        if !task.raw_artifact_ids.contains(artifact_id) || evidence.artifact_sha256.is_empty() {
            return None;
        }
        let rule = evidence.source_rule.as_deref()?;
        if evidence.engine_id == "prowler" {
            if PROWLER_PASSWORD_RULES.contains(&rule)
                && !evidence.location.as_deref().is_some_and(|location| {
                    location.ends_with(&format!(":{account_id}:password-policy"))
                })
            {
                return None;
            }
            if rule == "iam_avoid_root_usage"
                && evidence.location.as_deref()
                    != Some(format!("arn:aws:iam::{account_id}:root").as_str())
            {
                return None;
            }
        }
        let (kind, resource) = match evidence.engine_id.as_str() {
            "prowler" if PROWLER_PASSWORD_RULES.contains(&rule) => (
                ReportProblemKind::IamPasswordPolicy,
                "account-password-policy".into(),
            ),
            "scoutsuite" if SCOUT_PASSWORD_RULES.contains(&rule) => (
                ReportProblemKind::IamPasswordPolicy,
                "account-password-policy".into(),
            ),
            "prowler" if rule == "iam_avoid_root_usage" => {
                (ReportProblemKind::RootAccountUsage, "account-root".into())
            }
            "scoutsuite" if rule == "iam-root-account-used-recently" => {
                (ReportProblemKind::RootAccountUsage, "account-root".into())
            }
            "cloudsplaining"
                if matches!(rule, "ResourceExposure" | "InfrastructureModification") =>
            {
                let policy = evidence.scanner_details.as_ref()?.aws_iam_policy.as_ref()?;
                let location = evidence.location.as_deref()?;
                let (identity, _) = location.split_once(" :: ")?;
                // Only complete ARN/hash coordinates can establish the same
                // policy. Display names and legacy sanitized locations cannot.
                let source = match policy.policy_source {
                    AwsIamPolicySource::AwsManaged
                        if identity.starts_with("arn:aws:iam::aws:policy/")
                            && identity.len() > "arn:aws:iam::aws:policy/".len()
                            && !identity.chars().any(char::is_whitespace) =>
                    {
                        "aws"
                    }
                    AwsIamPolicySource::CustomerManaged
                        if policy_arn(identity)
                            && identity
                                .starts_with(&format!("arn:aws:iam::{account_id}:policy/")) =>
                    {
                        "customer"
                    }
                    AwsIamPolicySource::Inline
                        if identity.len() == 64
                            && identity.bytes().all(|byte| byte.is_ascii_hexdigit()) =>
                    {
                        "inline"
                    }
                    _ => return None,
                };
                policy_name = Some(policy.policy_name.clone());
                (
                    ReportProblemKind::IamPolicyPermissions,
                    format!("{source}:{identity}"),
                )
            }
            _ => return None,
        };
        subjects.insert(Subject {
            kind,
            asset_id: asset_id.clone(),
            resource,
        });
    }
    (subjects.len() == 1).then(|| (subjects.into_iter().next().unwrap(), policy_name))
}

fn policy_arn(identity: &str) -> bool {
    let parts = identity.split(':').collect::<Vec<_>>();
    matches!(parts.as_slice(), ["arn", "aws", "iam", "", account, resource]
        if account.len() == 12 && account.bytes().all(|byte| byte.is_ascii_digit())
        && resource.starts_with("policy/") && resource.len() > 7)
        && !identity.chars().any(char::is_whitespace)
}
pub(crate) fn build_problem_groups(
    findings: &[BeginnerFinding],
    run: &ScanRun,
) -> Vec<ReportProblemGroup> {
    let mut candidates = BTreeMap::<Subject, (Vec<&BeginnerFinding>, Option<String>)>::new();
    for finding in findings {
        if let Some((subject, name)) = subject(finding, run) {
            let entry = candidates.entry(subject).or_default();
            entry.0.push(finding);
            if entry.1.is_none() {
                entry.1 = name;
            }
        }
    }
    candidates
        .into_iter()
        .filter_map(|(subject, (members, policy_name))| {
            if members.len() < 2 {
                return None;
            }
            let representative = members.iter().min_by_key(|finding| {
                (
                    std::cmp::Reverse(severity_rank(&finding.severity)),
                    std::cmp::Reverse(finding.priority.unwrap_or(0)),
                    &finding.finding_id,
                )
            })?;
            let mut digest = Sha256::new();
            for component in [
                RULE_VERSION,
                &run.id,
                &subject.asset_id,
                &format!("{:?}", subject.kind),
                &subject.resource,
            ] {
                digest.update(component.as_bytes());
                digest.update([0]);
            }
            let guided = members
                .iter()
                .filter(|finding| {
                    crate::priority_guidance::PriorityGuidance::from_priority_reasons(
                        &finding.priority_reasons,
                    )
                    .is_some()
                })
                .count();
            let lower_priority_members = if guided == 0 {
                None
            } else if guided == members.len() {
                Some(LowerPriorityMembers::All)
            } else {
                Some(LowerPriorityMembers::Partial)
            };
            let mut group = ReportProblemGroup {
                group_id: format!("report-problem:{}", hex::encode(digest.finalize())),
                rule_version: RULE_VERSION.into(),
                kind: subject.kind,
                title: String::new(),
                target_asset_id: subject.asset_id,
                representative_finding_id: representative.finding_id.clone(),
                finding_ids: members
                    .iter()
                    .map(|finding| finding.finding_id.clone())
                    .collect(),
                policy_name,
                lower_priority_members,
            };
            group.title = group.title_english();
            Some(group)
        })
        .collect()
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use crate::beginner_report::{
        build_beginner_master_report,
        tests::{aws_grouping_case, frozen_finding, observation},
    };
    use crate::domain::{AssessmentCase, Severity};
    use chrono::Utc;

    fn add(
        case: &mut AssessmentCase,
        engine: &str,
        rule: &str,
        location: &str,
        policy: Option<(AwsIamPolicySource, &str)>,
        severity: Severity,
    ) {
        let id = format!("finding-{}", case.findings.len());
        let mut finding = frozen_finding(case, &id, 50, severity);
        finding.title = format!("{engine}: {rule} / {id}");
        let evidence = &mut finding.evidence[0];
        evidence.engine_id = engine.into();
        evidence.engine_run_id = Some(engine.into());
        evidence.source_rule = Some(rule.into());
        evidence.location = Some(location.into());
        if let Some((source, name)) = policy {
            evidence.scanner_details = Some(serde_json::from_value(serde_json::json!({
                "aws_iam_policy": {
                    "policy_source": source, "policy_name": name, "finding_identity": rule,
                    "actions": [format!("service:Action{}",case.findings.len())], "actions_complete": true,
                    "attached_to": {"roles":[], "groups":[], "users":[], "complete":true}
                }
            })).unwrap());
        }
        case.scan_runs[0]
            .engine_runs
            .iter_mut()
            .find(|task| task.engine_id == engine)
            .unwrap()
            .raw_artifact_ids
            .push(evidence.artifact_id.clone());
        let mut retained = observation(&finding, "run-1", Utc::now());
        retained.engine_ids = vec![engine.into()];
        case.finding_observations.push(retained);
        case.findings.push(finding);
    }

    pub(crate) fn approved_case() -> AssessmentCase {
        let mut case = aws_grouping_case();
        for rule in PROWLER_PASSWORD_RULES {
            add(
                &mut case,
                "prowler",
                rule,
                "arn:aws:iam::123456789012:password-policy",
                None,
                Severity::Low,
            );
        }
        for rule in SCOUT_PASSWORD_RULES {
            add(
                &mut case,
                "scoutsuite",
                rule,
                "iam.password_policy",
                None,
                Severity::High,
            );
        }
        add(
            &mut case,
            "prowler",
            "iam_avoid_root_usage",
            "arn:aws:iam::123456789012:root",
            None,
            Severity::Medium,
        );
        add(
            &mut case,
            "scoutsuite",
            "iam-root-account-used-recently",
            "iam.credential_report.root",
            None,
            Severity::High,
        );
        for (source, identity, name, total) in [
            (
                AwsIamPolicySource::AwsManaged,
                "arn:aws:iam::aws:policy/SecurityAudit",
                "SecurityAudit",
                6,
            ),
            (
                AwsIamPolicySource::CustomerManaged,
                "arn:aws:iam::123456789012:policy/private-one",
                "PrivatePolicy",
                2,
            ),
            (
                AwsIamPolicySource::CustomerManaged,
                "arn:aws:iam::123456789012:policy/private-two",
                "PrivatePolicy",
                2,
            ),
            (
                AwsIamPolicySource::Inline,
                "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
                "InlinePolicy",
                1,
            ),
        ] {
            for index in 0..total {
                add(
                    &mut case,
                    "cloudsplaining",
                    if index % 2 == 0 {
                        "ResourceExposure"
                    } else {
                        "InfrastructureModification"
                    },
                    &format!("{identity} :: service:Action{index}"),
                    Some((source, name)),
                    if index % 2 == 0 {
                        Severity::High
                    } else {
                        Severity::Low
                    },
                );
            }
        }
        for rule in [
            "iam_root_credentials_management",
            "iam_user_mfa_enabled",
            "iam_user_accesskey_unused",
            "iam_role_unused_permissions",
            "other-1",
            "other-2",
            "other-3",
        ] {
            add(
                &mut case,
                "prowler",
                rule,
                "arn:aws:iam::123456789012:role/example",
                None,
                Severity::Medium,
            );
        }
        case
    }

    #[test]
    fn approved_groups_reduce_31_rows_to_13_without_changing_any_original_or_workflow() {
        let case = approved_case();
        let before = serde_json::to_value(&case).unwrap();
        let report = build_beginner_master_report(&case, "run-1").unwrap();
        assert_eq!(report.findings.len(), 31);
        assert_eq!(report.problem_findings().len(), 13);
        let mut sizes = report
            .problem_groups
            .iter()
            .map(|group| group.finding_ids.len())
            .collect::<Vec<_>>();
        sizes.sort();
        assert_eq!(sizes, [2, 2, 2, 6, 11]);
        assert!(
            report
                .problem_groups
                .iter()
                .all(|group| group.rule_version == RULE_VERSION)
        );
        assert!(report.problem_groups.iter().all(|group| {
            report
                .findings
                .iter()
                .find(|finding| finding.finding_id == group.representative_finding_id)
                .unwrap()
                .severity
                == Severity::High
        }));
        assert_eq!(serde_json::to_value(&case).unwrap(), before);
        for original in &case.findings {
            let member = report
                .findings
                .iter()
                .find(|finding| finding.finding_id == original.id)
                .unwrap();
            assert_eq!(member.title, original.title);
            assert_eq!(member.fingerprint, original.fingerprint);
            assert_eq!(member.severity, original.severity);
            assert_eq!(
                member.evidence_references[0].source_rule,
                original.evidence[0].source_rule
            );
            assert_eq!(
                member.evidence_references[0].location,
                original.evidence[0].location
            );
        }
        let serialized = serde_json::to_string(&report).unwrap();
        assert!(!serialized.contains("customer:arn:"));
    }

    #[test]
    fn grouping_requires_frozen_selected_run_asset_task_and_full_resource_identity() {
        let case = approved_case();
        let report = build_beginner_master_report(&case, "run-1").unwrap();
        let run = &case.scan_runs[0];
        for mutate in 0..7 {
            let mut findings = report.findings.clone();
            for finding in &mut findings {
                match mutate {
                    0 => {
                        finding.snapshot_source =
                            FindingSnapshotSource::CurrentCanonicalLegacyFallback
                    }
                    1 => finding.evidence_references[0].details_frozen = false,
                    2 => {
                        finding.evidence_references[0].engine_run_id = Some("other-run-task".into())
                    }
                    3 => finding.target_asset_ids.push("other-asset".into()),
                    4 => finding.evidence_references[0].artifact_id = Some("other-artifact".into()),
                    5 => {
                        finding.evidence_references[0].source_rule = Some("unapproved-rule".into())
                    }
                    _ => finding.evidence_references[0].artifact_sha256.clear(),
                }
            }
            assert!(
                build_problem_groups(&findings, run).is_empty(),
                "guard {mutate}"
            );
        }
        let mut wrong_run = run.clone();
        wrong_run.report_asset_snapshots[0].asset.identifiers[0].value = "999999999999".into();
        let groups = build_problem_groups(&report.findings, &wrong_run);
        assert!(
            groups
                .iter()
                .all(|group| group.finding_ids.iter().all(|id| report
                    .findings
                    .iter()
                    .find(|finding| &finding.finding_id == id)
                    .unwrap()
                    .evidence_references[0]
                    .engine_id
                    != "prowler"))
        );
        wrong_run.report_asset_snapshots.clear();
        assert!(build_problem_groups(&report.findings, &wrong_run).is_empty());
        let mut findings = report.findings.clone();
        for finding in &mut findings {
            if finding.evidence_references[0].engine_id == "cloudsplaining" {
                finding.evidence_references[0].location =
                    Some("PrivatePolicy :: service:Action".into());
            }
        }
        assert!(
            build_problem_groups(&findings, run)
                .iter()
                .all(|group| group.kind != ReportProblemKind::IamPolicyPermissions)
        );
    }

    #[test]
    fn grouping_uses_selected_observations_and_is_backward_compatible() {
        let mut case = approved_case();
        let historical = build_beginner_master_report(&case, "run-1").unwrap();
        for finding in &mut case.findings {
            finding.title = "Changed in a later run".into();
            finding.last_seen_run_id = "run-2".into();
            finding.evidence.clear();
        }
        let retained = build_beginner_master_report(&case, "run-1").unwrap();
        assert_eq!(retained.problem_groups, historical.problem_groups);
        assert_eq!(retained.findings, historical.findings);
        let mut wire = serde_json::to_value(retained).unwrap();
        wire.as_object_mut().unwrap().remove("problem_groups");
        let old: crate::beginner_report::BeginnerMasterReport =
            serde_json::from_value(wire).unwrap();
        assert!(old.problem_groups.is_empty());
        assert_eq!(old.problem_findings().len(), 31);
    }

    #[test]
    fn standard_export_redacts_policy_labels_without_losing_group_membership() {
        let case = approved_case();
        let raw = build_beginner_master_report(&case, "run-1").unwrap();
        let redacted = crate::export::beginner_report_for_export(
            &case,
            "run-1",
            crate::export::RedactionProfile::Standard,
        )
        .unwrap();
        assert_eq!(redacted.findings.len(), 31);
        assert_eq!(redacted.problem_findings().len(), 13);
        for (before, after) in raw.problem_groups.iter().zip(&redacted.problem_groups) {
            assert_eq!(before.group_id, after.group_id);
            assert_eq!(before.finding_ids, after.finding_ids);
            assert_eq!(
                before.representative_finding_id,
                after.representative_finding_id
            );
        }
        let wire = serde_json::to_string(&redacted).unwrap();
        assert!(!wire.contains("PrivatePolicy"));
        assert!(!wire.contains("123456789012"));
        assert!(!wire.contains("private-one"));
        assert!(!wire.contains("private-two"));
    }

    #[test]
    fn password_policy_group_says_when_members_are_ordered_lower() {
        use crate::finding_narrative::{
            PASSWORD_COMPOSITION_ORDER_REASON, PASSWORD_EXPIRY_ORDER_REASON,
        };

        let case = approved_case();
        let report = build_beginner_master_report(&case, "run-1").unwrap();
        let run = &case.scan_runs[0];
        let original = report
            .problem_groups
            .iter()
            .find(|group| group.kind == ReportProblemKind::IamPasswordPolicy)
            .unwrap();
        assert_eq!(original.lower_priority_members, None);
        assert_eq!(
            original.next_step_english(),
            Some("Review the account's IAM password policy and address each failed setting.")
        );
        assert_eq!(
            original.next_step_zh_hant(),
            Some("檢查帳號的 IAM 密碼政策，並調整每項未通過的設定。")
        );
        assert_eq!(
            original.impact_english(),
            Some("Weak password settings increase the risk of unauthorized access to IAM users.")
        );
        assert_eq!(
            original.impact_zh_hant(),
            Some("較弱的密碼設定會增加 IAM 使用者遭未授權存取的風險。")
        );
        let group_id = original.group_id.clone();
        let representative = original.representative_finding_id.clone();
        let password_ids = original
            .finding_ids
            .iter()
            .cloned()
            .collect::<BTreeSet<_>>();

        let mut partial_findings = report.findings.clone();
        for finding in &mut partial_findings {
            if !password_ids.contains(&finding.finding_id) {
                continue;
            }
            let evidence = &finding.evidence_references[0];
            let reason = match (evidence.engine_id.as_str(), evidence.source_rule.as_deref()) {
                (
                    "prowler",
                    Some(
                        "iam_password_policy_uppercase"
                        | "iam_password_policy_lowercase"
                        | "iam_password_policy_number"
                        | "iam_password_policy_symbol",
                    ),
                ) => Some(PASSWORD_COMPOSITION_ORDER_REASON),
                (
                    "prowler",
                    Some("iam_password_policy_expires_passwords_within_90_days_or_less"),
                ) => Some(PASSWORD_EXPIRY_ORDER_REASON),
                (
                    "scoutsuite",
                    Some(
                        "iam-password-policy-no-expiration"
                        | "iam-password-policy-expiration-threshold",
                    ),
                ) => Some(PASSWORD_EXPIRY_ORDER_REASON),
                _ => None,
            };
            if let Some(reason) = reason {
                finding.priority_reasons.push(reason.to_owned());
            }
        }
        let partial = build_problem_groups(&partial_findings, run)
            .into_iter()
            .find(|group| group.kind == ReportProblemKind::IamPasswordPolicy)
            .unwrap();
        assert_eq!(
            partial.lower_priority_members,
            Some(LowerPriorityMembers::Partial)
        );
        assert_eq!(partial.group_id, group_id);
        assert_eq!(partial.representative_finding_id, representative);
        assert_eq!(
            partial.next_step_english(),
            Some(
                "Review the account's IAM password policy. Fix the failed length or reuse settings first; change the character-mix or expiry settings only if an audit you must pass still requires them."
            )
        );
        assert_eq!(
            partial.next_step_zh_hant(),
            Some(
                "檢查帳號的 IAM 密碼政策：先調整未通過的長度或重複使用設定；字元組成或到期設定，只有在必須通過的稽核仍要求時才需要變更。"
            )
        );
        assert_eq!(partial.impact_english(), original.impact_english());
        assert_eq!(partial.impact_zh_hant(), original.impact_zh_hant());
        let partial_wire = serde_json::to_value(&partial).unwrap();
        assert_eq!(partial_wire["lower_priority_members"], "partial");
        let mut without = partial_wire.clone();
        without
            .as_object_mut()
            .unwrap()
            .remove("lower_priority_members");
        let decoded: ReportProblemGroup = serde_json::from_value(without).unwrap();
        assert_eq!(decoded.lower_priority_members, None);

        let mut all_findings = report.findings.clone();
        for finding in &mut all_findings {
            if password_ids.contains(&finding.finding_id) {
                finding
                    .priority_reasons
                    .push(PASSWORD_COMPOSITION_ORDER_REASON.to_owned());
            }
        }
        let groups = build_problem_groups(&all_findings, run);
        let all = groups
            .iter()
            .find(|group| group.kind == ReportProblemKind::IamPasswordPolicy)
            .unwrap();
        assert_eq!(all.lower_priority_members, Some(LowerPriorityMembers::All));
        assert_eq!(all.group_id, group_id);
        assert_eq!(all.representative_finding_id, representative);
        assert_eq!(
            all.next_step_english(),
            Some(
                "Change these IAM password policy settings only if an audit you must pass still requires them; NIST SP 800-63B-4 says not to require character mixes or scheduled expiry."
            )
        );
        assert_eq!(
            all.next_step_zh_hant(),
            Some(
                "只有在必須通過的稽核仍要求時，才需要變更這些 IAM 密碼政策設定；NIST SP 800-63B-4 要求不要強制混合字元類型或定期到期。"
            )
        );
        assert_eq!(
            all.impact_english(),
            Some(
                "CIS AWS Foundations Benchmark v1.2.0 lists these settings; current guidance does not treat their absence as a weakness."
            )
        );
        assert_eq!(
            all.impact_zh_hant(),
            Some(
                "CIS AWS Foundations Benchmark v1.2.0 列出這些設定；現行指引不把缺少這些設定視為弱點。"
            )
        );
        assert!(groups.iter().all(|group| {
            group.kind == ReportProblemKind::IamPasswordPolicy
                || group.lower_priority_members.is_none()
        }));
        assert!(
            serde_json::to_value(original)
                .unwrap()
                .get("lower_priority_members")
                .is_none()
        );
        assert_eq!(
            serde_json::to_value(all).unwrap()["lower_priority_members"],
            "all"
        );
    }
}
