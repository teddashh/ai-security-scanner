//! Product-owned review order for scanner checks whose benchmark item current
//! guidance advises against.
//!
//! The scanner's severity, evidence, and remediation stay exactly as reported.
//! NIST SP 800-63B-4 section 3.1.1.2 says verifiers shall not impose other
//! composition rules, such as mixtures of character types, and shall force a
//! password change only when there is evidence the authenticator was
//! compromised. Among CIS AWS Foundations Benchmark versions, AWS Security Hub
//! maps IAM.11, IAM.12, IAM.13, IAM.14, and IAM.17 only to v1.2.0; it also
//! maps IAM.11, IAM.12, and IAM.14 to PCI DSS v4.0.1, which is why the reason
//! keeps "only if an audit you must pass still requires it". Prowler's CIS AWS
//! compliance files for versions 1.4, 1.5, 2.0, 3.0, 4.0, and 5.0 include only
//! the minimum-length and reuse password checks.

use crate::finding_narrative::{PASSWORD_COMPOSITION_ORDER_REASON, PASSWORD_EXPIRY_ORDER_REASON};

/// A scanner check whose benchmark item current guidance advises against.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PriorityGuidance {
    PasswordCompositionRule,
    PasswordScheduledExpiry,
}

/// The Low tier of `priority_for`. A guided check is not ordered above Low.
pub const GUIDED_PRIORITY_CEILING: u8 = 35;

/// The product order for one scanner rule, when this product places it lower
/// than the scanner's severity suggests.
pub fn guidance_for_rule(engine_id: &str, source_rule: &str) -> Option<PriorityGuidance> {
    match (engine_id, source_rule) {
        (
            "prowler",
            "iam_password_policy_uppercase"
            | "iam_password_policy_lowercase"
            | "iam_password_policy_number"
            | "iam_password_policy_symbol",
        )
        | (
            "scoutsuite",
            "iam-password-policy-no-uppercase-required"
            | "iam-password-policy-no-lowercase-required"
            | "iam-password-policy-no-number-required"
            | "iam-password-policy-no-symbol-required",
        ) => Some(PriorityGuidance::PasswordCompositionRule),
        ("prowler", "iam_password_policy_expires_passwords_within_90_days_or_less")
        | (
            "scoutsuite",
            "iam-password-policy-no-expiration" | "iam-password-policy-expiration-threshold",
        ) => Some(PriorityGuidance::PasswordScheduledExpiry),
        _ => None,
    }
}

/// One shared order for every evidence rule, or nothing.
///
/// `Some` only when there is at least one item and every item's source rule
/// maps to that same guidance. A missing rule, an unlisted rule, or two
/// different guidances leave the scanner's order unchanged.
pub fn guidance_for_rules<'a>(
    rules: impl IntoIterator<Item = (&'a str, Option<&'a str>)>,
) -> Option<PriorityGuidance> {
    let mut guidance = None;
    let mut seen = false;
    for (engine_id, source_rule) in rules {
        seen = true;
        let source_rule = source_rule?;
        let next = guidance_for_rule(engine_id, source_rule)?;
        match guidance {
            None => guidance = Some(next),
            Some(current) if current == next => {}
            Some(_) => return None,
        }
    }
    seen.then_some(guidance).flatten()
}

impl PriorityGuidance {
    /// The English reason stored on the finding. The report translates it.
    pub fn reason_english(self) -> &'static str {
        match self {
            Self::PasswordCompositionRule => PASSWORD_COMPOSITION_ORDER_REASON,
            Self::PasswordScheduledExpiry => PASSWORD_EXPIRY_ORDER_REASON,
        }
    }

    /// The first stored reason that is one of the two order sentences.
    pub fn from_priority_reasons(reasons: &[String]) -> Option<Self> {
        reasons.iter().find_map(|reason| {
            let trimmed = reason.trim();
            if trimmed == PASSWORD_COMPOSITION_ORDER_REASON {
                Some(Self::PasswordCompositionRule)
            } else if trimmed == PASSWORD_EXPIRY_ORDER_REASON {
                Some(Self::PasswordScheduledExpiry)
            } else {
                None
            }
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn listed_password_rules_map_and_length_or_reuse_do_not() {
        for rule in [
            "iam_password_policy_uppercase",
            "iam_password_policy_lowercase",
            "iam_password_policy_number",
            "iam_password_policy_symbol",
        ] {
            assert_eq!(
                guidance_for_rule("prowler", rule),
                Some(PriorityGuidance::PasswordCompositionRule),
                "{rule}"
            );
        }
        assert_eq!(
            guidance_for_rule(
                "prowler",
                "iam_password_policy_expires_passwords_within_90_days_or_less"
            ),
            Some(PriorityGuidance::PasswordScheduledExpiry)
        );
        for rule in [
            "iam-password-policy-no-uppercase-required",
            "iam-password-policy-no-lowercase-required",
            "iam-password-policy-no-number-required",
            "iam-password-policy-no-symbol-required",
        ] {
            assert_eq!(
                guidance_for_rule("scoutsuite", rule),
                Some(PriorityGuidance::PasswordCompositionRule),
                "{rule}"
            );
        }
        for rule in [
            "iam-password-policy-no-expiration",
            "iam-password-policy-expiration-threshold",
        ] {
            assert_eq!(
                guidance_for_rule("scoutsuite", rule),
                Some(PriorityGuidance::PasswordScheduledExpiry),
                "{rule}"
            );
        }
        for (engine, rule) in [
            ("prowler", "iam_password_policy_minimum_length_14"),
            ("prowler", "iam_password_policy_reuse_24"),
            ("scoutsuite", "iam-password-policy-minimum-length"),
            ("scoutsuite", "iam-password-policy-reuse-enabled"),
            ("scoutsuite", "iam_password_policy_uppercase"),
            ("prowler", "iam-password-policy-no-uppercase-required"),
            ("nuclei", "iam_password_policy_uppercase"),
        ] {
            assert_eq!(guidance_for_rule(engine, rule), None, "{engine} {rule}");
        }
    }

    #[test]
    fn guidance_for_rules_requires_every_item_to_share_one_order() {
        let none: [(&str, Option<&str>); 0] = [];
        assert_eq!(guidance_for_rules(none), None);
        assert_eq!(
            guidance_for_rules([("prowler", Some("iam_password_policy_uppercase"))]),
            Some(PriorityGuidance::PasswordCompositionRule)
        );
        assert_eq!(
            guidance_for_rules([
                ("scoutsuite", Some("iam-password-policy-no-expiration")),
                (
                    "prowler",
                    Some("iam_password_policy_expires_passwords_within_90_days_or_less"),
                ),
            ]),
            Some(PriorityGuidance::PasswordScheduledExpiry)
        );
        assert_eq!(
            guidance_for_rules([
                ("prowler", Some("iam_password_policy_uppercase")),
                (
                    "prowler",
                    Some("iam_password_policy_expires_passwords_within_90_days_or_less")
                ),
            ]),
            None
        );
        assert_eq!(
            guidance_for_rules([
                ("prowler", Some("iam_password_policy_symbol")),
                ("prowler", Some("iam_password_policy_minimum_length_14")),
            ]),
            None
        );
        assert_eq!(
            guidance_for_rules([
                ("scoutsuite", Some("iam-password-policy-no-symbol-required")),
                ("scoutsuite", None),
            ]),
            None
        );
    }

    #[test]
    fn from_priority_reasons_reads_the_two_sentences_and_ignores_the_rest() {
        assert_eq!(PriorityGuidance::from_priority_reasons(&[]), None);
        assert_eq!(
            PriorityGuidance::from_priority_reasons(&["Source severity: high".into()]),
            None
        );
        assert_eq!(
            PriorityGuidance::from_priority_reasons(&[format!(
                "  {PASSWORD_COMPOSITION_ORDER_REASON}\n"
            )]),
            Some(PriorityGuidance::PasswordCompositionRule)
        );
        assert_eq!(
            PriorityGuidance::from_priority_reasons(&[
                "The affected asset is internet-accessible.".into(),
                format!("\t{PASSWORD_EXPIRY_ORDER_REASON}  "),
            ]),
            Some(PriorityGuidance::PasswordScheduledExpiry)
        );
        assert_eq!(
            PriorityGuidance::PasswordCompositionRule.reason_english(),
            PASSWORD_COMPOSITION_ORDER_REASON
        );
        assert_eq!(
            PriorityGuidance::PasswordScheduledExpiry.reason_english(),
            PASSWORD_EXPIRY_ORDER_REASON
        );
    }
}
