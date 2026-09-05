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

use crate::domain::{ContextFactor, FindingFamily, SeverityBasisCode};

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
/// The English clause completing "This product rated it {severity} from ...".
///
/// Lives here rather than in the adapter that prints it because two sentences
/// are built from it -- the summary and the priority reason -- and the reader's
/// language is derived by recognising this exact text. A second copy in the
/// adapter would be a second thing to keep in step, and drift would show up as
/// a silently untranslated reason rather than as a failure.
pub fn basis_english(code: SeverityBasisCode) -> &'static str {
    match code {
        SeverityBasisCode::OpenPort => "an open port observation rather than a defect",
        SeverityBasisCode::ReachableHttpService => {
            "a reachable HTTP service observation rather than a defect"
        }
        SeverityBasisCode::SecretPatternMatch => "a secret pattern match in scanned source",
        SeverityBasisCode::UnverifiedCredentialDetector => {
            "a credential detector match that this product does not verify"
        }
        SeverityBasisCode::IacPolicyCheck => {
            "a failed infrastructure-as-code policy check, rated flat because \
             Checkov publishes no per-check severity offline"
        }
        SeverityBasisCode::CisKubernetesBenchmark => "a failed CIS Kubernetes Benchmark check",
        SeverityBasisCode::CloudControlQuery => {
            "a failed IAM control from this product's own fixed query"
        }
    }
}

/// Every basis code, so a new one cannot be added without being translated.
pub const ALL_SEVERITY_BASIS_CODES: [SeverityBasisCode; 7] = [
    SeverityBasisCode::OpenPort,
    SeverityBasisCode::ReachableHttpService,
    SeverityBasisCode::SecretPatternMatch,
    SeverityBasisCode::UnverifiedCredentialDetector,
    SeverityBasisCode::IacPolicyCheck,
    SeverityBasisCode::CisKubernetesBenchmark,
    SeverityBasisCode::CloudControlQuery,
];

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

/// The case-specific clauses `apply_case_context` appends to `possible_impact`.
///
/// These are appended to the English rather than composed into it, so a
/// surface that rewrites the impact sentence replaces the string they live in
/// and drops them unless it puts them back. That is not a missing translation
/// but a missing fact: the same case raised this finding's priority by up to
/// ten points, and the reasons are the only thing that says why.
fn context_clause(factor: ContextFactor) -> &'static str {
    match factor {
        ContextFactor::InternetExposedAsset => {
            "受影響的資產被標記為可從網際網路存取，且其保留的來源歸屬皆非問卷填答，這可能擴大可被觸及的攻擊面；該屬性的欄位層級來源並未保留，因此仍需人工確認。"
        }
        ContextFactor::SensitiveDataAsset => {
            "受影響的資產被標記為含有敏感資料，且其保留的來源歸屬皆非問卷填答，同時案件問卷另有記錄敏感資料情境。這可能提高確認暴露後的影響程度，但資料類別的欄位層級來源並未保留，且兩項記錄本身都不構成資料外洩的證明。"
        }
    }
}

/// "If the scanner result is confirmed, {consequence}."
pub fn impact_zh_hant(
    english: &str,
    severity_label: &str,
    family: Option<FindingFamily>,
    context_factors: &[ContextFactor],
) -> String {
    let Some(family) = family else {
        return english.to_owned();
    };
    let mut composed = format!(
        "若掃描結果經人工確認，{}。{severity_label}這個等級來自來源工具，不代表整體合規分數。",
        consequence(family)
    );
    for factor in context_factors {
        composed.push_str(context_clause(*factor));
    }
    composed
}

/// The one sentence every adapter finding carries before any change is made.
///
/// Matched exactly rather than inferred from a code. If the adapter's wording
/// ever changes, an exact match falls back to the English -- visible and
/// honest -- where a code would keep confidently printing the old sentence in
/// Chinese. `the_safety_sentence_this_module_translates_is_the_one_adapters_write`
/// in tests/adapter_fixtures.rs pins the two together.
pub const ENGLISH_ROLLBACK: &str = "Before any manual change, preserve the current approved configuration and document a tested restoration path; this product does not execute remediation.";

/// "Before any manual change, preserve ... this product does not execute
/// remediation."
pub fn rollback_zh_hant(english: &str) -> String {
    if english.trim() == ENGLISH_ROLLBACK {
        return "進行任何人工變更前，請先保留目前已核准的設定，並記錄一條經過測試的還原路徑；本產品不會代為執行修復。".to_owned();
    }
    english.to_owned()
}

/// "After an approved manual change, rerun {engine} ... source rule {rule}
/// is no longer reported."
///
/// Read back off the sentence for the same reason `engine_name_from` is: the
/// engine's display name and the source rule id are the engine's own strings
/// and have to appear in the Chinese exactly as they do in the English.
/// Returns the English unchanged for any sentence not in this shape.
/// The one priority reason every adapter finding carries.
pub const ENGLISH_EVIDENCE_REASON: &str =
    "Direct scanner evidence is attached and still requires human review.";

/// "Why this priority", in the reader's language.
///
/// `priority_reasons` is a bare `Vec<String>` with no per-entry code, so each
/// entry is recognised by its shape rather than looked up. There are four
/// producers and they are all closed:
///
///  - the derived-severity reason, built from a basis code and an engine name
///  - `Source severity: {value}`, whose value is the engine's own raw word
///  - the evidence constant above
///  - the two case-context reasons `apply_case_context` pushes
///
/// Anything else is returned unchanged. A reason is the product's account of
/// why it moved a finding up the list; printing a confident Chinese sentence
/// for text this build cannot identify would be inventing that account.
/// The two sentences of an unattributed-results coverage gap.
///
/// Composed from the structured payload rather than translated from the
/// English, for the same reason every other pair here is: the identifier and
/// the provider are the engine's own strings and have to read identically in
/// both languages, and the reader has to copy the identifier onto their asset.
pub fn unattributed_gap_zh_hant(
    engine_id: &str,
    unattributed: &crate::domain::UnattributedResults,
) -> (String, String, String) {
    let crate::domain::UnattributedResults {
        provider,
        identifier,
        discarded_results,
    } = unattributed;
    (
        format!("{engine_id}：針對 {provider} {identifier} 的結果"),
        format!(
            "{engine_id} 回報了 {discarded_results} 筆針對 {provider} 識別碼 {identifier} 的結果。你已授權的資產都沒有登記這個識別碼，因此這些結果都沒有被歸屬，也不會出現在這份報告中。"
        ),
        format!("請在你已授權的資產上，新增 {provider} 識別碼 {identifier}，然後重新掃描。"),
    )
}

/// The names a coverage row is speaking about, in Traditional Chinese.
///
/// Most of these are composed at runtime around an identifier -- a check id, an
/// engine id, or the label a person wrote on an exclusion -- and the identifier
/// is the only part telling one row from the next. So the kind is translated
/// and the identifier is carried through untouched, rather than the whole
/// phrase being replaced by a fixed label.
///
/// An unrecognized name keeps its original text behind a marker. Untranslated
/// detail is worth more than fluent erasure: a person can search for
/// "cloudquery" in their scanner's own output, and cannot search for a label
/// this product invented.
pub fn coverage_dimension_zh_hant(dimension: &str) -> String {
    let lower = dimension.to_lowercase();

    // Fixed names, in the order the more specific one has to be tried first:
    // "completed planned work units" is a substring of the partly-completed one.
    for (needle, label) in [
        ("tcp reachability", "TCP 連線狀態"),
        ("bounded connection contract", "受限的連線檢查"),
        ("completed check-to-target coordinate", "完成的目標檢查"),
        ("requested scan stage", "要求的掃描深度"),
        ("requested limits", "要求的掃描限制"),
        ("scope reduction", "自動縮減的範圍"),
        ("truncation", "自動縮減的範圍"),
        ("target label", "目標的歷史顯示資料"),
        ("target type", "目標的歷史顯示資料"),
        ("finding presentation", "本輪問題顯示資料"),
        ("request outcome", "掃描結果資料一致性"),
        (
            "partly completed planned work units",
            "部分完成的計畫工作單元",
        ),
        ("completed planned work units", "已完成的計畫工作單元"),
        ("additional packaged checks", "額外的內建檢查項目"),
        ("requested checks", "要求的檢查項目"),
    ] {
        if lower.contains(needle) {
            return label.to_owned();
        }
    }

    // "{check id} {kind} work units ({count})". The count is what makes the row
    // worth reading, so it survives beside the id.
    if let Some((head, count)) = dimension
        .strip_suffix(')')
        .and_then(|rest| rest.rsplit_once(" ("))
        .filter(|(_, count)| !count.is_empty() && count.chars().all(|c| c.is_ascii_digit()))
    {
        for (suffix, label) in [
            (" partly completed work units", "部分完成的工作單元"),
            (" failed work units", "失敗的工作單元"),
            (" timed-out work units", "逾時的工作單元"),
            (" cancelled work units", "已取消的工作單元"),
            (" not-tested work units", "未檢測的工作單元"),
        ] {
            if let Some(check) = head.strip_suffix(suffix) {
                return with_check(check, &format!("{label}（{count}）"));
            }
        }
    }

    // "{check id} {kind}".
    for (suffix, label) in [
        (" granular executed scope", "細部執行範圍"),
        (" completed-check time", "檢查完成時間"),
        (" saved work-unit coverage", "已儲存的工作單元涵蓋記錄"),
        (" saved result processing", "已儲存結果的處理"),
        (" final-state reconciliation", "最終狀態核對"),
        (" ended after its time limit", "因逾時而結束"),
        (" stopped before finishing", "未完成就停止"),
        (" was cancelled before finishing", "未完成就被取消"),
    ] {
        if let Some(check) = dimension.strip_suffix(suffix) {
            return with_check(check, label);
        }
    }

    // "{check id}: {kind}".
    if let Some((check, rest)) = dimension.split_once(": ") {
        for (fragment, label) in [
            ("remaining requested dimensions", "尚未完成的要求項目"),
            ("timed-out check dimension", "逾時的檢查項目"),
            ("failed check dimension", "失敗的檢查項目"),
            ("cancelled check dimension", "已取消的檢查項目"),
            ("not-tested check dimension", "未檢測的檢查項目"),
            ("unfinished check dimension", "未完成的檢查項目"),
        ] {
            if rest == fragment {
                return with_check(check, label);
            }
        }
    }

    // "requested check {engine id}", singular: the plural rule above is a
    // different row, about the whole requested list rather than one scanner.
    if let Some(engine) = dimension
        .strip_prefix("requested check ")
        .filter(|engine| !engine.is_empty())
    {
        return format!("要求的檢查項目：{engine}");
    }

    format!("涵蓋範圍細節：{dimension}")
}

/// Names the check a composed dimension belongs to, or just the kind when the
/// producer had no id to interpolate.
fn with_check(check: &str, label: &str) -> String {
    let check = check.trim();
    if check.is_empty() {
        return label.to_owned();
    }
    format!("{check} 的{label}")
}

pub fn priority_reason_zh_hant(english: &str) -> String {
    let trimmed = english.trim();
    if trimmed == ENGLISH_EVIDENCE_REASON {
        return "已附上掃描工具的直接證據，仍需人工檢視。".to_owned();
    }
    if trimmed == crate::prioritization::INTERNET_REASON {
        return "受影響的資產被標記為可從網際網路存取，且其保留的來源歸屬皆非問卷填答。".to_owned();
    }
    if trimmed == crate::prioritization::SENSITIVE_REASON {
        return "受影響的資產被標記為含有敏感資料，其保留的來源歸屬皆非問卷填答，且案件問卷另有記錄敏感資料情境。".to_owned();
    }
    // The engine's own raw severity word, kept verbatim. Restating "high" as
    // 高 would stop it matching what the reader sees in the engine's own output.
    if let Some(value) = trimmed
        .strip_prefix("Source severity: ")
        .filter(|value| !value.is_empty())
    {
        return format!("來源工具評定的嚴重程度：{value}");
    }
    const DERIVED: &str = "Severity derived from ";
    const TAIL: &str = " reports no severity of its own.";
    let Some(rest) = trimmed.strip_prefix(DERIVED) else {
        return english.to_owned();
    };
    let Some(rest) = rest.strip_suffix(TAIL) else {
        return english.to_owned();
    };
    // No basis text contains "; ", so the last one separates basis from engine.
    let Some((basis_text, engine)) = rest.rsplit_once("; ") else {
        return english.to_owned();
    };
    let Some(code) = ALL_SEVERITY_BASIS_CODES
        .into_iter()
        .find(|code| basis_english(*code) == basis_text)
    else {
        return english.to_owned();
    };
    if engine.is_empty() {
        return english.to_owned();
    }
    format!(
        "嚴重程度是由{}推導而來；{engine} 本身不提供嚴重程度。",
        basis(code)
    )
}

pub fn verification_zh_hant(english: &str) -> String {
    const RERUN: &str = "After an approved manual change, rerun ";
    const SCOPE: &str = " with the same authorized scope and confirm that source rule ";
    const TAIL: &str = " is no longer reported.";
    let Some(rest) = english.trim().strip_prefix(RERUN) else {
        return english.to_owned();
    };
    let Some(rest) = rest.strip_suffix(TAIL) else {
        return english.to_owned();
    };
    let Some((engine, rule)) = rest.split_once(SCOPE) else {
        return english.to_owned();
    };
    if engine.is_empty() || rule.is_empty() {
        return english.to_owned();
    }
    format!(
        "在核准的人工變更完成後，請以相同的授權範圍重新執行 {engine}，並確認來源規則 {rule} 不再被回報。"
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

    /// One assertion per shape the beginner report composes.
    ///
    /// The TypeScript twin is held to the same outputs by
    /// `tests/frontend/coverageDimensionPresentation.test.ts`, which censuses
    /// the producer rather than this list. This one exists so that a rule
    /// reordered here -- the fixed-name loop runs first and matches on
    /// substrings, so it can swallow a composed name -- fails in Rust too.
    #[test]
    fn a_coverage_name_is_translated_around_the_identifier_it_carries() {
        for (dimension, expected) in [
            // Fixed names.
            ("requested scan stage", "要求的掃描深度"),
            ("requested checks", "要求的檢查項目"),
            (
                "partly completed planned work units",
                "部分完成的計畫工作單元",
            ),
            ("completed planned work units", "已完成的計畫工作單元"),
            // Composed around a check or engine id.
            (
                "cloudquery granular executed scope",
                "cloudquery 的細部執行範圍",
            ),
            (
                "naabu-tcp saved work-unit coverage",
                "naabu-tcp 的已儲存的工作單元涵蓋記錄",
            ),
            (
                "naabu-tcp failed work units (3)",
                "naabu-tcp 的失敗的工作單元（3）",
            ),
            (
                "naabu-tcp partly completed work units (12)",
                "naabu-tcp 的部分完成的工作單元（12）",
            ),
            ("trivy: failed check dimension", "trivy 的失敗的檢查項目"),
            (
                "trivy: remaining requested dimensions",
                "trivy 的尚未完成的要求項目",
            ),
            ("requested check prowler", "要求的檢查項目：prowler"),
        ] {
            assert_eq!(
                coverage_dimension_zh_hant(dimension),
                expected,
                "{dimension}"
            );
        }
    }

    #[test]
    fn a_name_this_product_did_not_author_keeps_its_own_text() {
        // A case exclusion's dimension is the label a person typed. There is
        // nothing to translate and no shape to match, so it survives whole
        // rather than being replaced by a label this product invented.
        assert_eq!(
            coverage_dimension_zh_hant("S3 buckets in the archive account"),
            "涵蓋範圍細節：S3 buckets in the archive account"
        );
        // The singular row names one scanner; the plural row is the whole
        // requested list. Collapsing them would lose which is which.
        assert_ne!(
            coverage_dimension_zh_hant("requested check prowler"),
            coverage_dimension_zh_hant("requested checks")
        );
    }

    #[test]
    fn a_finding_with_no_code_keeps_the_english_rather_than_losing_the_sentence() {
        // Legacy runs stored prose and no code. Untranslated beats blank.
        assert_eq!(
            impact_zh_hant("English impact.", "中", None, &[]),
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

    /// The case context this product added must survive being said in Chinese.
    ///
    /// `apply_case_context` appends its sentences to the English
    /// `possible_impact` and raises the priority by up to ten points. Composing
    /// a fresh Chinese sentence replaces the string those appendices live in,
    /// so without this the zh-Hant reader saw a finding promoted above the
    /// scanner's own rating with the explanation removed -- while the English
    /// reader, reading the same finding, was told exactly why.
    #[test]
    fn case_context_that_raised_the_priority_is_not_lost_in_translation() {
        let english = "If the scanner result is confirmed, something may happen.";
        let plain = impact_zh_hant(english, "高", Some(FindingFamily::CloudPosture), &[]);
        assert!(!plain.contains("受影響的資產被標記"), "{plain}");

        for (factor, expected) in [
            (ContextFactor::InternetExposedAsset, "可從網際網路存取"),
            (ContextFactor::SensitiveDataAsset, "含有敏感資料"),
        ] {
            let composed =
                impact_zh_hant(english, "高", Some(FindingFamily::CloudPosture), &[factor]);
            assert!(composed.contains(expected), "{factor:?} lost: {composed}");
            assert!(
                composed.starts_with(&plain),
                "{factor:?} rewrote the base sentence"
            );
        }

        // Both at once, in the order the backend recorded them, and neither
        // swallowing the other.
        let both = impact_zh_hant(
            english,
            "高",
            Some(FindingFamily::CloudPosture),
            &[
                ContextFactor::InternetExposedAsset,
                ContextFactor::SensitiveDataAsset,
            ],
        );
        let internet = both
            .find("可從網際網路存取")
            .expect("internet clause missing");
        let sensitive = both.find("含有敏感資料").expect("sensitive clause missing");
        assert!(internet < sensitive, "{both}");
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
