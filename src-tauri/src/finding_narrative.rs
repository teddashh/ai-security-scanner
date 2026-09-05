//! Writes the sentences this product says about a finding, in the reader's
//! language, for the shared HTML report.
//!
//! The findings pane composes these in TypeScript (`src/findingNarrative.ts`).
//! The report is written here because it is produced as a file, not rendered,
//! so the same sentences exist twice. That is deliberate and guarded: the
//! Chinese in the two files is pinned against each other by
//! `tests/frontend/findingNarrativeParity.test.ts`, which reads both and fails
//! on any wording that appears in one and not the other. Two readers being told
//! different things about the same finding is the failure that matters, and
//! only a test that reads both sides can see it.
//!
//! Rules match the TypeScript exactly:
//!
//!  - English returns the stored prose untouched. It is the canonical wording.
//!  - A finding with no code keeps that prose. Untranslated beats blank.
//!  - The engine's own title is never restated in another language.

use crate::domain::{FindingFamily, SeverityBasisCode};

/// The clause completing "If the scanner result is confirmed, ...".
fn consequence(family: FindingFamily) -> &'static str {
    match family {
        FindingFamily::CloudPosture => "雲端資源或資料可能遭到未預期的存取、變更或使用",
        FindingFamily::CloudIdentity => "某個身分可能擁有超出其角色所需的操作權限",
        FindingFamily::Microsoft365 => "Microsoft 365 的身分、郵件、檔案或管理設定的保護可能不足",
        FindingFamily::NetworkExposure => "可從網際網路連線的服務可能暴露非預期的功能或已知弱點",
        FindingFamily::SourceCode | FindingFamily::Secret => {
            "原始碼或憑證可能導致未授權存取或不安全的程式行為"
        }
        FindingFamily::InfrastructureAsCode => "之後部署出來的基礎架構會沿用這個不安全的設定",
        FindingFamily::VulnerableComponent => "容器或軟體元件可能讓工作負載暴露於已知弱點",
        FindingFamily::Kubernetes => "Kubernetes 叢集或工作負載的隔離或管理保護可能不足",
    }
}

/// The clause completing "...then plan and approve ...".
///
/// `Secret` departs from `SourceCode` even though they share a consequence. A
/// leaked credential stays valid until it is revoked, so sending the reader to
/// a permissions screen first leaves it valid for exactly that long.
fn remedy(family: FindingFamily) -> &'static str {
    match family {
        FindingFamily::CloudPosture => "將受影響資源的設定或政策改為最小權限",
        FindingFamily::CloudIdentity => "改用只授予該身分角色所需操作的較小範圍政策",
        FindingFamily::Microsoft365 => "調整這項控制項所檢查的 Microsoft 365 租用戶設定",
        FindingFamily::NetworkExposure => {
            "記錄這項服務為何需要對外開放，或調整設定以移除、限制這個對外暴露"
        }
        FindingFamily::SourceCode => "修改程式碼以移除回報的不安全寫法",
        FindingFamily::Secret => {
            "先撤銷並輪替這組已外洩的憑證，再從原始碼以及仍保留它的歷史紀錄中移除"
        }
        FindingFamily::InfrastructureAsCode => {
            "修改基礎架構即程式碼的範本，讓重新部署不會再還原這個設定"
        }
        FindingFamily::VulnerableComponent => {
            "將受影響的元件升級到已修正的版本，或記錄目前無法升級的原因"
        }
        FindingFamily::Kubernetes => "調整這項檢查所指出的工作負載或叢集設定",
    }
}

/// The clause completing "This product rated it {severity} from ...".
fn basis(code: SeverityBasisCode) -> &'static str {
    match code {
        SeverityBasisCode::OpenPort => "開放連接埠的觀察結果，而非缺陷",
        SeverityBasisCode::ReachableHttpService => "可連線 HTTP 服務的觀察結果，而非缺陷",
        SeverityBasisCode::SecretPatternMatch => "掃描到的原始碼中符合機密資料的樣式",
        SeverityBasisCode::UnverifiedCredentialDetector => {
            "憑證偵測器的比對結果，本產品並未加以驗證"
        }
        SeverityBasisCode::IacPolicyCheck => {
            "一項未通過的基礎架構即程式碼政策檢查；因為 Checkov 離線執行時不提供各別檢查的嚴重程度，所以一律採用相同等級"
        }
        SeverityBasisCode::CisKubernetesBenchmark => "一項未通過的 CIS Kubernetes Benchmark 檢查",
        SeverityBasisCode::CloudControlQuery => "本產品自有固定查詢中一項未通過的 IAM 控制項",
    }
}

/// The specialists the adapters recommend, matched on the whole name.
///
/// Not substring-matched: "security" and "vulnerability" both contain "it", and
/// a rule asking that question sent Kubernetes, container, Microsoft 365 and
/// vulnerability findings all to an IT administrator.
pub fn expert_type_zh_hant(expert: &str) -> &str {
    match expert.trim() {
        "Cloud security engineer" => "雲端安全工程師",
        "Cloud identity specialist" => "雲端身分權限專家",
        "Microsoft 365 security administrator" => "Microsoft 365 安全管理員",
        "Network security engineer" => "網路安全工程師",
        "Application security engineer" => "應用程式安全工程師",
        "Vulnerability manager" => "弱點管理負責人",
        "Secrets-response specialist" => "機密外洩應變專家",
        "Infrastructure-as-code engineer" => "基礎架構即程式碼工程師",
        "Container security engineer" => "容器安全工程師",
        "Software supply-chain engineer" => "軟體供應鏈工程師",
        "Kubernetes security engineer" => "Kubernetes 安全工程師",
        // Not from an adapter. A check that timed out is a network or system
        // problem, and the report says so on purpose; letting it fall through
        // would send the reader to a security specialist for a connectivity
        // fault, which is the same misdirection the substring rule used to
        // cause. The generic name is what a finding with no details gets.
        "Network or system administrator" => "網路或系統管理員",
        "Security professional" => "資安專業人員",
        // A name from a build this one has never seen still has to say
        // something, and a general answer beats a confidently wrong one.
        _ => "資安或 IT 專業人員",
    }
}

/// The engine's display name, read back off the sentence the product wrote, so
/// the translated sentence names it exactly as the English does. `None` for any
/// sentence that is not the shape this product writes.
fn engine_name_from(english_summary: &str) -> Option<&str> {
    let (name, _) = english_summary.split_once(" reported ")?;
    if name.is_empty() || name.contains('.') {
        return None;
    }
    Some(name)
}

/// "{engine} reported a {severity}-severity condition on the assessed asset."
pub fn summary_zh_hant(
    english: &str,
    severity_label: &str,
    severity_basis_code: Option<SeverityBasisCode>,
) -> String {
    let Some(engine) = engine_name_from(english) else {
        return english.to_owned();
    };
    const EVIDENCE: &str = "附帶的原始記錄是證據，不是指示。";
    match severity_basis_code {
        None => {
            format!("{engine} 在受評估的資產上回報了一項{severity_label}等級的狀況。{EVIDENCE}")
        }
        Some(code) => format!(
            "{engine} 在受評估的資產上回報了這項狀況，但未評定嚴重程度。本產品依據{}，將它評為{severity_label}。{EVIDENCE}",
            basis(code)
        ),
    }
}

/// "If the scanner result is confirmed, {consequence}."
pub fn impact_zh_hant(
    english: &str,
    severity_label: &str,
    family: Option<FindingFamily>,
) -> String {
    let Some(family) = family else {
        return english.to_owned();
    };
    format!(
        "若掃描結果經人工確認，{}。{severity_label}這個等級來自來源工具，不代表整體合規分數。",
        consequence(family)
    )
}

/// "Have the recommended specialist (...) review ... then plan and approve ..."
pub fn action_zh_hant(english: &str, expert_type: &str, family: Option<FindingFamily>) -> String {
    let Some(family) = family else {
        return english.to_owned();
    };
    format!(
        "請由建議的專業人員（{}）檢視受影響的資產與來源規則的官方說明，再規劃並核准{}。",
        expert_type_zh_hant(expert_type),
        remedy(family)
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    const ENGLISH_SUMMARY: &str = "Trivy reported a medium-severity condition on the assessed asset. The attached raw record is evidence, not an instruction.";

    #[test]
    fn a_finding_with_no_code_keeps_the_english_rather_than_losing_the_sentence() {
        // Legacy runs stored prose and no code. Untranslated beats blank.
        assert_eq!(
            impact_zh_hant("English impact.", "中", None),
            "English impact."
        );
        assert_eq!(
            action_zh_hant("English action.", "Container security engineer", None),
            "English action."
        );
        // A sentence this product did not write is not taken apart for a name.
        assert_eq!(
            summary_zh_hant("Some other text.", "高", None),
            "Some other text."
        );
    }

    #[test]
    fn the_engines_own_display_name_survives_verbatim() {
        for engine in ["httpx", "kube-bench", "Greenbone Community Edition"] {
            let english = format!(
                "{engine} reported a high-severity condition on the assessed asset. The attached raw record is evidence, not an instruction."
            );
            assert!(
                summary_zh_hant(&english, "高", None).starts_with(&format!("{engine} ")),
                "{engine} lost its name"
            );
        }
    }

    #[test]
    fn every_family_and_basis_composes_a_distinct_chinese_sentence() {
        let families = [
            FindingFamily::CloudPosture,
            FindingFamily::CloudIdentity,
            FindingFamily::Microsoft365,
            FindingFamily::NetworkExposure,
            FindingFamily::SourceCode,
            FindingFamily::Secret,
            FindingFamily::InfrastructureAsCode,
            FindingFamily::VulnerableComponent,
            FindingFamily::Kubernetes,
        ];
        // Every family must resolve to its own action, or two different problems
        // are given the same instruction in the shared report.
        let actions = families
            .iter()
            .map(|family| action_zh_hant("English.", "Secrets-response specialist", Some(*family)))
            .collect::<std::collections::BTreeSet<_>>();
        assert_eq!(actions.len(), families.len());

        let bases = [
            SeverityBasisCode::OpenPort,
            SeverityBasisCode::ReachableHttpService,
            SeverityBasisCode::SecretPatternMatch,
            SeverityBasisCode::UnverifiedCredentialDetector,
            SeverityBasisCode::IacPolicyCheck,
            SeverityBasisCode::CisKubernetesBenchmark,
            SeverityBasisCode::CloudControlQuery,
        ];
        let summaries = bases
            .iter()
            .map(|code| summary_zh_hant(ENGLISH_SUMMARY, "高", Some(*code)))
            .collect::<std::collections::BTreeSet<_>>();
        assert_eq!(summaries.len(), bases.len());
        for summary in &summaries {
            assert!(summary.contains("未評定嚴重程度"), "{summary}");
        }
    }

    #[test]
    fn each_recommended_specialist_is_named_rather_than_sorted_by_a_substring() {
        let experts = [
            "Cloud security engineer",
            "Cloud identity specialist",
            "Microsoft 365 security administrator",
            "Network security engineer",
            "Application security engineer",
            "Vulnerability manager",
            "Secrets-response specialist",
            "Infrastructure-as-code engineer",
            "Container security engineer",
            "Software supply-chain engineer",
            "Kubernetes security engineer",
        ];
        let named = experts
            .iter()
            .map(|expert| expert_type_zh_hant(expert))
            .collect::<std::collections::BTreeSet<_>>();
        assert_eq!(
            named.len(),
            experts.len(),
            "distinct specialists collapsed together: {named:?}"
        );
        assert!(!named.contains(&"資安或 IT 專業人員"));
    }
}
