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

use crate::domain::{
    AwsIamPolicyFindingDetails, AwsIamPolicySource, ConfidenceBasisCode, ContextFactor,
    FindingFamily, Severity, SeverityBasisCode,
};

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

/// The English clause retained for historical findings whose product-derived
/// severity was frozen before missing scanner ratings began staying Unknown.
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
        SeverityBasisCode::CloudsplainingIamPolicyFinding => {
            "an IAM policy finding Cloudsplaining did not rate"
        }
        SeverityBasisCode::UnratedVulnerabilityTestAlarm => {
            "a Greenbone vulnerability-test alarm whose pinned feed entry carries no parseable severity vector"
        }
    }
}

/// Every basis code, so a new one cannot be added without being translated.
pub const ALL_SEVERITY_BASIS_CODES: [SeverityBasisCode; 9] = [
    SeverityBasisCode::OpenPort,
    SeverityBasisCode::ReachableHttpService,
    SeverityBasisCode::SecretPatternMatch,
    SeverityBasisCode::UnverifiedCredentialDetector,
    SeverityBasisCode::IacPolicyCheck,
    SeverityBasisCode::CisKubernetesBenchmark,
    SeverityBasisCode::CloudControlQuery,
    SeverityBasisCode::CloudsplainingIamPolicyFinding,
    SeverityBasisCode::UnratedVulnerabilityTestAlarm,
];

/// The canonical English clause explaining why this product assigned a
/// confidence when the engine did not provide one.
pub fn confidence_basis_english(code: ConfidenceBasisCode) -> &'static str {
    match code {
        ConfidenceBasisCode::DeterministicPolicyEvaluation => {
            "a deterministic policy or configuration evaluation"
        }
        ConfidenceBasisCode::AdvisoryVersionMatch => {
            "an installed-version match against a published advisory range"
        }
        ConfidenceBasisCode::UnverifiedPatternOrDetectorMatch => {
            "an unverified pattern or detector match"
        }
        ConfidenceBasisCode::ObservedResponse => "a response this product observed directly",
        ConfidenceBasisCode::TemplateMatcher => "a template matcher firing on the assessed target",
        ConfidenceBasisCode::MissingDetectionQualityScore => {
            "the absence of a detection-quality score in the engine result"
        }
    }
}

/// The Traditional Chinese form of [`confidence_basis_english`].
pub fn confidence_basis_zh_hant(code: ConfidenceBasisCode) -> &'static str {
    match code {
        ConfidenceBasisCode::DeterministicPolicyEvaluation => "確定性的政策或設定評估結果",
        ConfidenceBasisCode::AdvisoryVersionMatch => "已安裝版本符合已發布公告的受影響範圍",
        ConfidenceBasisCode::UnverifiedPatternOrDetectorMatch => "尚未驗證的樣式或偵測器比對結果",
        ConfidenceBasisCode::ObservedResponse => "本產品直接觀察到的回應",
        ConfidenceBasisCode::TemplateMatcher => "範本比對器在受評估目標上觸發",
        ConfidenceBasisCode::MissingDetectionQualityScore => "引擎結果中未提供偵測品質分數",
    }
}

/// Every confidence basis code, so a new one cannot be added without both
/// reader-facing forms.
pub const ALL_CONFIDENCE_BASIS_CODES: [ConfidenceBasisCode; 6] = [
    ConfidenceBasisCode::DeterministicPolicyEvaluation,
    ConfidenceBasisCode::AdvisoryVersionMatch,
    ConfidenceBasisCode::UnverifiedPatternOrDetectorMatch,
    ConfidenceBasisCode::ObservedResponse,
    ConfidenceBasisCode::TemplateMatcher,
    ConfidenceBasisCode::MissingDetectionQualityScore,
];

fn source_confidence(priority_reasons: &[String]) -> Option<&str> {
    priority_reasons
        .iter()
        .find_map(|reason| reason.trim().strip_prefix("Source confidence: "))
        .filter(|source| !source.is_empty())
}

pub fn confidence_presentation_english(
    confidence_label: &str,
    confidence_basis_code: Option<ConfidenceBasisCode>,
    priority_reasons: &[String],
) -> String {
    if let Some(code) = confidence_basis_code {
        return format!(
            "{confidence_label} — this product's rating from {}",
            confidence_basis_english(code)
        );
    }
    source_confidence(priority_reasons).map_or_else(
        || confidence_label.to_owned(),
        |source| format!("{confidence_label} — engine rating: {source}"),
    )
}

pub fn confidence_presentation_zh_hant(
    confidence_label: &str,
    confidence_basis_code: Option<ConfidenceBasisCode>,
    priority_reasons: &[String],
) -> String {
    if let Some(code) = confidence_basis_code {
        return format!(
            "{confidence_label} — 本產品依據{}評定",
            confidence_basis_zh_hant(code)
        );
    }
    source_confidence(priority_reasons).map_or_else(
        || confidence_label.to_owned(),
        |source| format!("{confidence_label} — 來源工具評定：{source}"),
    )
}

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
        SeverityBasisCode::CloudsplainingIamPolicyFinding => {
            "Cloudsplaining 未評定嚴重程度的 IAM 政策問題"
        }
        SeverityBasisCode::UnratedVulnerabilityTestAlarm => {
            "Greenbone 弱點測試發出的警示，但固定版本 feed 條目沒有可解析的嚴重程度向量"
        }
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
    severity: &Severity,
    severity_label: &str,
    severity_basis_code: Option<SeverityBasisCode>,
    confidence_label: &str,
    confidence_basis_code: Option<ConfidenceBasisCode>,
    priority_reasons: &[String],
) -> String {
    let Some(engine) = engine_name_from(english) else {
        return english.to_owned();
    };
    const EVIDENCE: &str = "附帶的原始記錄是證據，不是指示。";
    let mut summary = match (severity_basis_code, severity) {
        (Some(_), Severity::Unknown) => {
            format!("{engine} 回報了這項狀況，但未評定嚴重程度，因此維持為未知，需由人工確認。")
        }
        (None, _) => format!("{engine} 在受評估的資產上回報了一項{severity_label}等級的狀況。"),
        (Some(code), _) => format!(
            "{engine} 在受評估的資產上回報了這項狀況，但未評定嚴重程度。本產品依據{}，將它評為{severity_label}。",
            basis(code)
        ),
    };
    if let Some(code) = confidence_basis_code {
        summary.push_str(&format!(
            "{engine} 本身不提供信心評定。本產品依據{}，將信心評為{confidence_label}。",
            confidence_basis_zh_hant(code)
        ));
    } else if let Some(source) = source_confidence(priority_reasons) {
        summary.push_str(&format!(
            "{engine} 對這項問題的信心評定為 {source}；本產品將它對應為{confidence_label}信心。"
        ));
    }
    summary.push_str(EVIDENCE);
    summary
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
    severity: &Severity,
    severity_label: &str,
    severity_basis_code: Option<SeverityBasisCode>,
    family: Option<FindingFamily>,
    context_factors: &[ContextFactor],
) -> String {
    let Some(family) = family else {
        return english.to_owned();
    };
    let rating_context = match (severity, severity_basis_code) {
        (Severity::Unknown, Some(_)) => {
            "掃描工具未評定嚴重程度，因此維持為未知，需由人工確認。".to_owned()
        }
        (_, Some(_)) => {
            format!("掃描工具未評定嚴重程度；顯示的{severity_label}等級由本產品提供。")
        }
        (_, None) => format!("掃描工具評定的嚴重程度為{severity_label}。"),
    };
    let mut composed = format!(
        "若掃描結果經人工確認，{}。{rating_context}",
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
pub const ENGLISH_EXPOSURE_OBSERVATION_REASON: &str =
    "Classified as a reachable-service inventory observation, not a vulnerability.";

/// Report-layer wording for Naabu/httpx reachability records. Older cases may
/// contain the vulnerability-oriented impact and remediation prose used before
/// reachability was separated from findings. Export projections replace those
/// stale fields with these inventory semantics while retaining the original
/// evidence and the machine-readable severity basis code.
pub const EXPOSURE_OBSERVATION_RISK: &str = "A service responded within the tested scope. Reachability is inventory evidence, not a vulnerability.";
pub const EXPOSURE_OBSERVATION_IMPACT: &str =
    "Reachability alone does not establish a security weakness or a need to change the service.";
pub const EXPOSURE_OBSERVATION_NEXT_STEP: &str = "Confirm that the service is expected. To look for weaknesses, run an applicable security check against it.";
pub const EXPOSURE_OBSERVATION_VERIFICATION: &str = "Repeat the same bounded discovery if you need to confirm whether the service is still reachable.";
pub const EXPOSURE_OBSERVATION_OWNER: &str = "System or service owner";

/// "Why this priority", in the reader's language.
///
/// `priority_reasons` is a bare `Vec<String>` with no per-entry code, so each
/// entry is recognised by its shape rather than looked up. The producers are
/// closed and listed below:
///
///  - the derived-severity reason, built from a basis code and an engine name
///  - `Source severity: {value}`, whose value is the engine's own raw word
///  - the evidence constant above
///  - the reachable-service inventory constant above
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
    recognized_coverage_dimension_zh_hant(dimension)
        .unwrap_or_else(|| format!("涵蓋範圍細節：{dimension}"))
}

/// `None` for a name this build does not author. `beginner_report.rs` asserts
/// on it in debug builds for every tested dimension it writes, so the whole
/// Rust suite is the census of that vocabulary.
pub(crate) fn recognized_coverage_dimension_zh_hant(dimension: &str) -> Option<String> {
    let lower = dimension.to_lowercase();

    if let Some((check, control)) = dimension.split_once(": manual review for ")
        && !check.is_empty()
        && !control.is_empty()
    {
        return Some(format!("{check}：需人工檢視的控制項 {control}"));
    }

    // Fixed names, in the order the more specific one has to be tried first:
    // "completed planned work units" is a substring of the partly-completed one.
    for (needle, label) in [
        ("tcp reachability", "TCP 連線狀態"),
        ("bounded connection contract", "受限的連線檢查"),
        (
            "internal-device tls vulnerability checks",
            "內部設備 TLS 弱點檢查",
        ),
        (
            "internal-device scan-profile coverage",
            "內部設備掃描設定檔涵蓋記錄",
        ),
        (
            "greenbone remote vulnerability scan",
            "Greenbone 遠端弱點掃描",
        ),
        ("nuclei upstream website scan", "Nuclei 上游網站掃描"),
        ("ssh service vulnerability checks", "SSH 服務弱點檢查"),
        (
            "ssh endpoint scan-profile coverage",
            "SSH 端點掃描設定檔涵蓋記錄",
        ),
        ("rdp transport security checks", "RDP 傳輸安全性檢查"),
        (
            "rdp transport endpoint scan-profile coverage",
            "RDP 傳輸端點掃描設定檔涵蓋記錄",
        ),
        (
            "rdp implementation, authentication/nla, and endpoint host coverage",
            "RDP 實作、驗證／NLA 與端點主機涵蓋範圍",
        ),
        ("vnc transport security check", "VNC 傳輸安全性檢查"),
        (
            "vnc transport endpoint scan-profile coverage",
            "VNC 傳輸端點掃描設定檔涵蓋記錄",
        ),
        (
            "vnc implementation, authentication, and endpoint host coverage",
            "VNC 實作、驗證與端點主機涵蓋範圍",
        ),
        (
            "smtp cleartext-login and tls security checks",
            "SMTP 明文登入與 TLS 安全性檢查",
        ),
        (
            "smtp fixed security profile attempt",
            "SMTP 固定安全設定檔嘗試",
        ),
        (
            "smtp tls checks with selected-run evidence",
            "具有所選本輪證據的 SMTP TLS 檢查",
        ),
        (
            "smtp tls negotiation-dependent coverage",
            "需成功協商 TLS 的 SMTP 涵蓋範圍",
        ),
        (
            "smtp endpoint scan-profile coverage",
            "SMTP 端點掃描設定檔涵蓋記錄",
        ),
        (
            "smtp server behavior, implementation, and endpoint host coverage",
            "SMTP 伺服器行為、實作與端點主機涵蓋範圍",
        ),
        (
            "telnet cleartext-login security check",
            "Telnet 明文登入安全性檢查",
        ),
        (
            "telnet endpoint scan-profile coverage",
            "Telnet 端點掃描設定檔涵蓋記錄",
        ),
        (
            "telnet authentication, implementation, and endpoint host coverage",
            "Telnet 驗證、實作與端點主機涵蓋範圍",
        ),
        (
            "endpoint operating-system, package, application, and local-configuration coverage",
            "端點作業系統、套件、應用程式與本機設定涵蓋範圍",
        ),
        ("supported vulnerability profile", "可用的弱點掃描設定"),
        (
            "device product and firmware vulnerability coverage",
            "設備產品與韌體弱點涵蓋範圍",
        ),
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
            return Some(label.to_owned());
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
                return Some(with_check(check, &format!("{label}（{count}）")));
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
            return Some(with_check(check, label));
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
            ("vulnerability profile evidence", "弱點掃描設定檔證據"),
            ("website execution evidence", "網站執行證據"),
            ("target response", "目標回應"),
            ("scanner errors", "掃描器錯誤"),
        ] {
            if rest == fragment {
                return Some(with_check(check, label));
            }
        }
    }

    // "requested check {engine id}", singular: the plural rule above is a
    // different row, about the whole requested list rather than one scanner.
    if let Some(engine) = dimension
        .strip_prefix("requested check ")
        .filter(|engine| !engine.is_empty())
    {
        return Some(format!("要求的檢查項目：{engine}"));
    }

    None
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

/// Names one limit the run was executed under, in Traditional Chinese.
///
/// The backend composes most of these as "<engine or asset id> <limit kind>",
/// so translating the kind alone erases the only part saying which scanner or
/// which authorized target the limit applied to. A case with three scope
/// grants would otherwise show three rows all reading "approved ports" with no
/// way to attribute them, so the identifier survives in parentheses.
///
/// An unrecognized name keeps its text behind a marker, for the same reason a
/// coverage name does: a limit written by another build still says something.
pub fn requested_limit_name_zh_hant(name: &str) -> String {
    recognized_requested_limit_name_zh_hant(name)
        .unwrap_or_else(|| format!("本輪使用的限制：{name}"))
}

/// `None` for a limit name this build does not author. `beginner_report.rs`
/// asserts on it in debug builds for every limit it writes.
pub(crate) fn recognized_requested_limit_name_zh_hant(name: &str) -> Option<String> {
    // Three names are fixed strings rather than composed ones, so they reach
    // neither the suffix rules nor the fallback.
    match name {
        "endpoint" => return Some("連線端點".to_owned()),
        "connection timeout" => return Some("連線逾時限制".to_owned()),
        "application payload" => return Some("應用資料量".to_owned()),
        _ => {}
    }
    for (suffix, label) in [
        ("approved ports", "允許檢查的連接埠"),
        ("request rate", "請求速率"),
        ("network timeout", "網路逾時限制"),
        ("authorized network target", "已確認的網路目標"),
        ("execution timeout", "檢查逾時限制"),
    ] {
        if let Some(identifier) = name.strip_suffix(suffix) {
            return Some(with_identifier(label, identifier));
        }
    }
    None
}

const REQUESTED_LIMIT_VALUE_UNITS: &[(&str, &str)] =
    &[(" ms", " 毫秒"), (" bytes", " 位元組"), (" seconds", " 秒")];

const REQUEST_RATE_MIDDLE: (&str, &str) = (" per second, concurrency ", " 次，並行 ");

/// One stored requested-limit value in Traditional Chinese.
///
/// Only unit shapes this build authors are changed. Endpoints, targets, port
/// lists, and values written by another build remain byte-for-byte searchable.
pub fn requested_limit_value_zh_hant(name: &str, value: &str) -> String {
    recognized_requested_limit_value_zh_hant(name, value).unwrap_or_else(|| value.to_owned())
}

/// `None` means neither a known unit shape nor a known identifier-bearing
/// limit. The producer assertion uses this distinction to catch a new English
/// unit while the public presentation function safely preserves unknown data.
pub(crate) fn recognized_requested_limit_value_zh_hant(name: &str, value: &str) -> Option<String> {
    for (english_unit, chinese_unit) in REQUESTED_LIMIT_VALUE_UNITS {
        if let Some(number) = value.strip_suffix(english_unit)
            && is_ascii_number(number)
        {
            return Some(format!("{number}{chinese_unit}"));
        }
    }

    if let Some((requests, concurrency)) = value.split_once(REQUEST_RATE_MIDDLE.0)
        && is_ascii_number(requests)
        && is_ascii_number(concurrency)
    {
        return Some(format!(
            "每秒 {requests}{}{concurrency}",
            REQUEST_RATE_MIDDLE.1
        ));
    }

    if name == "endpoint"
        || name.ends_with(" authorized network target")
        || name.ends_with(" approved ports")
    {
        return Some(value.to_owned());
    }
    None
}

fn is_ascii_number(value: &str) -> bool {
    !value.is_empty() && value.bytes().all(|byte| byte.is_ascii_digit())
}

/// Appends the identifier a composed name carries, when it has one.
///
/// `format!("{} approved ports", grant.asset_id)` degrades to a bare suffix if
/// the grant carries no asset id; without this guard the label would end in a
/// pair of empty parentheses.
fn with_identifier(label: &str, identifier: &str) -> String {
    let identifier = identifier.trim();
    if identifier.is_empty() {
        return label.to_owned();
    }
    format!("{label}（{identifier}）")
}

/// The fixed observations attached to tested dimensions, paired with their
/// Traditional Chinese.
///
/// The backend writes these in English before any locale is known and freezes
/// them into the case, so the whole stored observation is the lookup key.
/// `None` means this build did not author the sentence; callers preserve that
/// stored English rather than claiming to understand prose from another build.
const TESTED_OBSERVATION_PROSE: &[(&str, &str)] = &[
    (
        "Nuclei completed the pinned upstream automatic web profile on the displayed origin. Upstream technology detection selected applicable read-only templates; completion does not prove that every eligible template executed.",
        "Nuclei 已對畫面所列網站來源範圍完成固定版本的上游自動網站設定。上游技術偵測會選擇適用的唯讀模板；完成不代表每個合格模板都實際執行。",
    ),
    (
        "The port accepted the bounded TCP connection.",
        "這個連接埠接受了受限的 TCP 連線。",
    ),
    (
        "The port refused the bounded TCP connection.",
        "這個連接埠拒絕了受限的 TCP 連線。",
    ),
    (
        "The bounded TCP connection attempt timed out; reachability was not established.",
        "受限的 TCP 連線嘗試逾時；無法確認連線可達。",
    ),
    (
        "The native task only observed whether the endpoint accepted, refused, or timed out during the bounded connection attempt. It did not perform a vulnerability test.",
        "這項內建工作只觀察端點在受限的連線嘗試期間，是接受連線、拒絕連線，還是逾時。它沒有執行弱點檢測。",
    ),
    (
        "The durable task reached completed state for this target binding. More granular executed dimensions were not frozen in this case record.",
        "這項已保存的工作已針對這個目標完成。這份案件記錄沒有凍結更細部的執行範圍。",
    ),
    (
        "The completed Greenbone task retained a frozen allowlist containing the profile's TLS protocol, cipher, and certificate vulnerability checks.",
        "已完成的 Greenbone 工作保留了凍結的允許清單，其中包含此設定檔的 TLS 協定、加密套件與憑證弱點檢查。",
    ),
    (
        "Greenbone completed the frozen remote-safe profile on the displayed host and ports. Its upstream service and product prerequisites decided which feed checks applied; the result API does not prove that every scheduled VT executed.",
        "Greenbone 已對畫面所列主機與連接埠完成凍結的遠端安全掃描設定。哪些 feed 檢查適用，由上游的服務與產品先決條件決定；結果 API 不能證明每個排程的 VT 都實際執行。",
    ),
    (
        "The completed Greenbone task retained the exact reviewed SSH profile for deprecated protocol, known or static host key, and weak MAC, encryption, host-key, key-size, or key-exchange choices.",
        "已完成的 Greenbone 工作保留了精確且經過檢視的 SSH 設定檔，用來檢查淘汰的協定、已知或固定的 host key，以及較弱的 MAC、加密、host-key、key size 或 key-exchange 選項。",
    ),
    (
        "The completed Greenbone task retained the exact reviewed RDP transport profile: ten TLS protocol, cipher, and certificate checks plus one check for the legacy fixed private key used by RDP 5.2 or earlier.",
        "已完成的 Greenbone 工作保留了精確且經過檢視的 RDP 傳輸設定檔：十項 TLS 協定、加密套件與憑證檢查，加上一項針對 RDP 5.2 或更早版本所使用之舊式固定私密金鑰的檢查。",
    ),
    (
        "The completed Greenbone task retained the exact reviewed VNC transport profile containing one check for an unencrypted VNC connection.",
        "已完成的 Greenbone 工作保留了精確且經過檢視的 VNC 傳輸設定檔，其中包含一項未加密 VNC 連線檢查。",
    ),
    (
        "The completed Greenbone task retained the exact reviewed SMTP profile: one banner, EHLO, STARTTLS, and advertised-AUTH check for an unencrypted cleartext login risk, plus ten TLS checks that apply when TLS can be negotiated. No credentials or mail were sent.",
        "已完成的 Greenbone 工作保留了精確且經過檢視的 SMTP 設定檔：一項透過 banner、EHLO、STARTTLS 與服務宣告 AUTH 檢查未加密明文登入風險的檢查，加上十項在可協商 TLS 時適用的 TLS 檢查。本輪未送出帳號或密碼，也沒有寄信。",
    ),
    (
        "The completed Greenbone task retained and attempted the exact SMTP profile: one check reads the banner, sends EHLO, tries STARTTLS when offered, and reviews advertised AUTH for cleartext-login risk; ten more checks depend on TLS being available. Task completion alone does not prove those TLS checks ran. No credentials or mail were sent.",
        "已完成的 Greenbone 工作保留並嘗試執行精確的 SMTP 設定檔：其中一項檢查會讀取 banner、送出 EHLO、在服務提供時嘗試 STARTTLS，並檢視服務宣告的 AUTH 是否有明文登入風險；另有十項檢查必須在 TLS 可用時才能執行。工作完成本身不能證明這些 TLS 檢查實際執行。本輪未送出帳號或密碼，也沒有寄信。",
    ),
    (
        "Only the exact TLS source OIDs present in this selected run's finding evidence are counted here. A finding for one OID does not prove that another TLS check ran.",
        "此處只計入所選本輪 finding 證據中明確記載的 TLS 來源 OID。某一個 OID 有 finding，不能證明另一項 TLS 檢查也已執行。",
    ),
    (
        "The completed Greenbone task retained the exact reviewed Telnet profile, which observes whether a login or password prompt is offered without TLS. No username or password was sent and no login was attempted.",
        "已完成的 Greenbone 工作保留了精確且經過檢視的 Telnet 設定檔，用來觀察服務是否在沒有 TLS 的情況下提供登入或密碼提示。本輪未送出帳號或密碼，也沒有嘗試登入。",
    ),
    (
        "These exact frozen work units have validated completed outcomes across all saved attempts. A completed network check reports reachability; it is not a security pass.",
        "這些已凍結的特定工作單元，在所有已儲存的嘗試中都有通過驗證的完成結果。完成的網路檢查只回報連線是否可達；不代表安全性檢查通過。",
    ),
    (
        "These work units produced usable saved results but did not finish every planned operation.",
        "這些工作單元產生了已儲存的可用結果，但沒有完成每一項計畫中的操作。",
    ),
];

/// A tested-dimension observation in Traditional Chinese, or `None` when this
/// build did not author the stored sentence.
pub fn tested_observation_zh_hant(english: &str) -> Option<String> {
    let trimmed = english.trim();
    TESTED_OBSERVATION_PROSE
        .iter()
        .find(|(candidate, _)| *candidate == trimmed)
        .map(|(_, chinese)| (*chinese).to_owned())
}

/// Reviewed catalog rationales presented in Traditional Chinese. The English
/// catalog remains the canonical source, and an unknown sentence from another
/// build deliberately has no translation here.
const CONTROL_MAPPING_RATIONALE_PROSE: &[(&str, &str)] = &[
    (
        "Evidence that an identity has no registered multi-factor device is related to authenticating users and safeguarding authentication information.",
        "某個身分未登記多重要素驗證裝置的證據，與驗證使用者及保護驗證資訊有關。",
    ),
    (
        "Evidence that an attached identity policy grants unrestricted administrative permissions is related to least privilege, entitlement review, and privileged access safeguards.",
        "附加的身分政策授予不受限制之管理權限的證據，與最小權限、權限審查及特權存取保護有關。",
    ),
    (
        "Evidence that an object-storage resource permits public access is related to access policy, authorization review, and cloud service protection.",
        "物件儲存資源允許公開存取的證據，與存取政策、授權審查及雲端服務保護有關。",
    ),
    (
        "Evidence of an identity privilege-escalation path is related to least privilege, entitlement review, and privileged access safeguards.",
        "身分權限提升路徑的證據，與最小權限、權限審查及特權存取保護有關。",
    ),
    (
        "Evidence that legacy authentication is not blocked is related to enforcing appropriate authentication and protecting authentication information.",
        "未封鎖舊式驗證的證據，與強制使用適當的驗證方式及保護驗證資訊有關。",
    ),
    (
        "Evidence that privileged identities lack phishing-resistant authentication is related to authentication enforcement and authentication information safeguards.",
        "特權身分缺少抗網路釣魚驗證的證據，與強制驗證及驗證資訊保護有關。",
    ),
    (
        "Evidence of an exposed database administration interface is related to identifying, validating, recording, and handling technical vulnerabilities.",
        "資料庫管理介面對外暴露的證據，與識別、確認、記錄及處理技術弱點有關。",
    ),
    (
        "Static-analysis evidence of dynamic code execution is related to secure development and pre-execution dangerous-construct checks. AIDEFEND's AI-generated-artifact coordinate applies when the selected code was generated or materially changed by AI.",
        "動態程式碼執行的靜態分析證據，與安全開發及執行前的危險程式結構檢查有關。當所選程式碼由 AI 產生或經 AI 實質修改時，AIDEFEND 的 AI 產生構件座標才適用。",
    ),
    (
        "Static-analysis evidence that Python code invokes an operating-system shell is related to secure development and pre-execution dangerous-construct checks. AIDEFEND's AI-generated-artifact coordinate applies when the selected code was generated or materially changed by AI.",
        "Python 程式碼呼叫作業系統 shell 的靜態分析證據，與安全開發及執行前的危險程式結構檢查有關。當所選程式碼由 AI 產生或經 AI 實質修改時，AIDEFEND 的 AI 產生構件座標才適用。",
    ),
    (
        "Static-analysis evidence that JavaScript or TypeScript code invokes a command through a shell is related to secure development and pre-execution dangerous-construct checks. AIDEFEND's AI-generated-artifact coordinate applies when the selected code was generated or materially changed by AI.",
        "JavaScript 或 TypeScript 程式碼透過 shell 呼叫命令的靜態分析證據，與安全開發及執行前的危險程式結構檢查有關。當所選程式碼由 AI 產生或經 AI 實質修改時，AIDEFEND 的 AI 產生構件座標才適用。",
    ),
    (
        "Static-analysis evidence of private-key material in current project files is related to managing credentials and protecting authentication information. AIDEFEND's static-admission coordinate applies when the selected artifact was generated or materially changed by AI.",
        "目前專案檔案含有私密金鑰資料的靜態分析證據，與管理憑證及保護驗證資訊有關。當所選構件由 AI 產生或經 AI 實質修改時，AIDEFEND 的靜態准入座標才適用。",
    ),
    (
        "Evidence of a credential embedded in current project files is related to managing credentials and protecting authentication information. AIDEFEND's static-admission coordinate applies when the selected artifact was generated or materially changed by AI.",
        "目前專案檔案內嵌憑證的證據，與管理憑證及保護驗證資訊有關。當所選構件由 AI 產生或經 AI 實質修改時，AIDEFEND 的靜態准入座標才適用。",
    ),
    (
        "Every TruffleHog result is a detected credential, so this reference covers the engine's whole detector surface rather than one detector. Evidence of a credential in source material is related to managing credentials and protecting authentication information. AIDEFEND's static-admission coordinate applies when the selected artifact was generated or materially changed by AI.",
        "每一筆 TruffleHog 結果都是偵測到的憑證，因此這項參照涵蓋該掃描工具的完整偵測範圍，而不是單一偵測器。原始資料中含有憑證的證據，與管理憑證及保護驗證資訊有關。當所選構件由 AI 產生或經 AI 實質修改時，AIDEFEND 的靜態准入座標才適用。",
    ),
    (
        "Infrastructure-as-code evidence that access logging is disabled is related to security-relevant audit records. AIDEFEND's IaC-scanning coordinate applies when the selected configuration provisions an AI system.",
        "基礎架構即程式碼顯示存取記錄已停用的證據，與安全性相關的稽核記錄有關。當所選設定用來佈建 AI 系統時，AIDEFEND 的 IaC 掃描座標才適用。",
    ),
    (
        "Infrastructure-as-code evidence that server-side encryption is absent is related to protecting data at rest and using cryptographic safeguards. AIDEFEND's IaC-scanning coordinate applies when the selected configuration provisions an AI system.",
        "基礎架構即程式碼顯示未使用伺服器端加密的證據，與保護靜態資料及使用密碼學保護措施有關。當所選設定用來佈建 AI 系統時，AIDEFEND 的 IaC 掃描座標才適用。",
    ),
    (
        "Evidence that an installed component is affected by a CVE is related to vulnerability handling. For an AI system, AIDEFEND separates build or deployment admission from the deployed-software remediation lifecycle; this reference does not decide which lifecycle state applies.",
        "已安裝元件受某項 CVE 影響的證據，與弱點處理有關。對 AI 系統而言，AIDEFEND 將建置或部署准入與已部署軟體的修復生命週期分開；這項參照不會判定適用哪一個生命週期階段。",
    ),
    (
        "Evidence that subjects can run commands inside running containers is related to least-privilege authorization, privileged access safeguards, and container isolation. AIDEFEND's container-isolation coordinate applies when the workload is part of an AI system.",
        "主體可以在執行中的容器內執行命令的證據，與最小權限授權、特權存取保護及容器隔離有關。當工作負載屬於 AI 系統的一部分時，AIDEFEND 的容器隔離座標才適用。",
    ),
    (
        "Evidence that the kubelet accepts anonymous authentication is related to authentication enforcement and authentication information safeguards. This is the node check the shipped snapshot benchmark runs; the control-plane equivalent is not in scope for this product.",
        "kubelet 接受匿名驗證的證據，與強制驗證及驗證資訊保護有關。這是隨附的快照基準所執行的節點檢查；對應的控制平面檢查不在本產品範圍內。",
    ),
    (
        "A Greenbone vulnerability-test alarm on an authorized host is evidence related to technical vulnerability handling. For an AI system, AIDEFEND separates build-time dependency admission from the deployed-software remediation lifecycle; this reference points at the deployed lifecycle and does not decide remediation state.",
        "Greenbone 對已授權主機發出的弱點測試警示，是與技術性弱點處理相關的證據。對 AI 系統而言，AIDEFEND 將建置階段的相依套件准入與已部署軟體的修復生命週期分開；這項參照指向已部署的生命週期，並不判定修復狀態。",
    ),
];

pub fn control_mapping_rationale_zh_hant(english: &str) -> Option<String> {
    CONTROL_MAPPING_RATIONALE_PROSE
        .iter()
        .find(|(candidate, _)| *candidate == english)
        .map(|(_, chinese)| (*chinese).to_owned())
}

/// Fixed coverage-ledger explanations shared by the screen and the exported
/// case record. Explanations with retained values are matched by shape below.
const COVERAGE_RECORD_DETAIL_PROSE: &[(&str, &str)] = &[
    (
        "The source is connected, but no attributable discovery has completed and no assets are known. Coverage is not established.",
        "來源已連線，但尚未完成可歸屬的探索，也沒有已知資產。尚未建立涵蓋。",
    ),
    (
        "The discovered candidate has not had ownership and scope explicitly confirmed. Discovery never authorizes a target automatically.",
        "探索到的候選資產尚未明確確認所有權與範圍。探索本身絕不會自動授權目標。",
    ),
    (
        "The asset has no unexpired, valid scope grant. Discovery never authorizes a target automatically.",
        "此資產沒有尚未到期的有效範圍授權。探索本身絕不會自動授權目標。",
    ),
    (
        "The asset is authorized, but no scan plan is tied to its current effective grants.",
        "此資產已獲授權，但沒有任何掃描計畫連結到目前有效的授權。",
    ),
    (
        "The scan predates frozen scope-grant snapshots, so its historical authorization and permission coverage are unknown. Live grants are never substituted for missing run evidence.",
        "這次掃描早於凍結範圍授權快照的機制，因此無法得知當時的授權與權限涵蓋。絕不會用現行授權補上缺少的執行記錄。",
    ),
    (
        "The asset is authorized, but the latest applicable scan plan contains no engine run for it.",
        "此資產已獲授權，但最近適用的掃描計畫沒有包含它的掃描工具工作。",
    ),
];

const COVERAGE_STATE_APPEND: (&str, &str) = (
    " This state is independent of how many findings were reported.",
    " 此狀態與回報了多少個問題無關。",
);
const PROVIDER_DISCOVERY_APPEND: (&str, &str) =
    (" Latest provider discovery: ", " 最近一次供應商探索：");
const STALE_KNOWLEDGE_APPEND: (&str, &str) = (
    " Explicit stale-knowledge warning: ",
    " 明確的過時知識警告：",
);
const STALE_KNOWLEDGE_SUFFIX: (&str, &str) = (
    ". Completion proves execution, not current knowledge.",
    "。完成只證明已執行，不代表知識仍為最新。",
);
const LOCALHOST_ATTEMPT_APPEND: (&str, &str) = (
    " Exact built-in localhost TCP attempt(s): ",
    " 精確的內建 localhost TCP 嘗試：",
);
const LOCALHOST_ATTEMPT_SUFFIX: (&str, &str) = (
    ". This records only those connection attempts; it does not establish that the service or computer is secure, and it does not cover other ports or hosts.",
    "。這只記錄這些連線嘗試；無法證明服務或電腦安全，也不涵蓋其他連接埠或主機。",
);

/// A coverage-ledger explanation in Traditional Chinese, or `None` when this
/// build did not author the stored sentence. Values retained inside a known
/// frame -- including a person's applicability reason -- remain verbatim.
pub fn coverage_record_detail_zh_hant(english: &str) -> Option<String> {
    if let Some((_, chinese)) = COVERAGE_RECORD_DETAIL_PROSE
        .iter()
        .find(|(candidate, _)| *candidate == english)
    {
        return Some((*chinese).to_owned());
    }

    if let Some(translated) =
        translate_trailing_coverage_frame(english, STALE_KNOWLEDGE_APPEND, STALE_KNOWLEDGE_SUFFIX)
    {
        return Some(translated);
    }
    if let Some(translated) = translate_trailing_coverage_frame(
        english,
        LOCALHOST_ATTEMPT_APPEND,
        LOCALHOST_ATTEMPT_SUFFIX,
    ) {
        return Some(translated);
    }
    if let Some(translated) =
        translate_trailing_coverage_frame(english, PROVIDER_DISCOVERY_APPEND, ("", ""))
    {
        return Some(translated);
    }
    if let Some(summary) = english.strip_suffix(COVERAGE_STATE_APPEND.0)
        && let Some(summary) = coverage_record_detail_zh_hant(summary)
    {
        return Some(format!("{summary}{}", COVERAGE_STATE_APPEND.1));
    }

    if let Some(reason) = strip_frame(
        english,
        "The source area is explicitly outside this case: ",
        " This is a scoped applicability statement, not a successful scan result.",
    ) {
        return Some(format!(
            "此來源範圍明確不在本案件內：{reason} 這是範圍適用性的說明，不是掃描成功的結果。"
        ));
    }
    if let Some(count) = strip_frame(
        english,
        "The source is connected and the latest attributable discovery returned no assets. This is not a successful scan result; ",
        " prior asset observation(s) remain retained.",
    ) && is_ascii_number(count)
    {
        return Some(format!(
            "來源已連線，且最近一次可歸屬的探索未傳回任何資產。這不是掃描成功的結果；仍保留 {count} 筆先前的資產觀察結果。"
        ));
    }
    if let Some(rest) = english.strip_prefix("The source is not currently connected (status: ")
        && let Some((status, rest)) = rest.split_once("). Its present coverage is unknown; ")
        && let Some(count) = rest.strip_suffix(
            " previously attributed asset(s) are retained but do not make the source green.",
        )
        && !status.is_empty()
        && is_ascii_number(count)
    {
        return Some(format!(
            "來源目前未連線（狀態：{status}）。目前的涵蓋未知；仍保留 {count} 筆先前歸屬的資產，但這不會讓來源顯示為綠色。"
        ));
    }
    if let Some(detail) = strip_frame(
        english,
        "The scan's frozen authorization evidence is incomplete: ",
        ". Live grants are never used to reconstruct historical scan permission.",
    ) {
        return Some(format!(
            "掃描中凍結的授權證據不完整：{detail}。絕不會用現行授權重建過去的掃描權限。"
        ));
    }
    if let Some(count) = strip_frame(
        english,
        "All ",
        " compatible engine run(s) planned for this asset completed.",
    ) && is_ascii_number(count)
    {
        return Some(format!(
            "為此資產規劃的 {count} 項相容掃描工具工作皆已完成。"
        ));
    }
    if let Some(count) = strip_frame(
        english,
        "All ",
        " planned task(s) for this asset completed their exact declared dimensions.",
    ) && is_ascii_number(count)
    {
        return Some(format!(
            "為此資產規劃的 {count} 項工作，皆已完成各自明確宣告的檢查範圍。"
        ));
    }
    if let Some(reasons) = strip_frame(
        english,
        "The authorized scan is incomplete: ",
        ". Only completed compatible catalog-engine runs or exact completed built-in tasks can produce scanned coverage.",
    ) {
        return Some(format!(
            "已授權的掃描未完成：{reasons}。只有已完成且相容的目錄掃描工具工作，或精確完成的內建工作，才能產生已掃描涵蓋。"
        ));
    }
    None
}

/// A data-quality warning written into the beginner report, in Traditional
/// Chinese. Unknown text is deliberately not translated: case bundles can
/// outlive the build that authored them.
pub fn data_quality_warning_zh_hant(english: &str) -> Option<String> {
    let fixed = [
        (
            "This run contains a request-level outcome beside non-terminal or planned check data. The report ignored that outcome and did not treat it as ‘no checks completed’.",
            "本輪在尚未結束或仍有已規劃檢查資料的同時，含有請求層級的結果。報告已忽略該結果，且未將其視為「未完成任何檢查」。",
        ),
        (
            "The selected run's stored project identifier does not match this project. The report remains limited to the selected in-project record.",
            "所選掃描輪次儲存的專案識別碼與此專案不符。報告仍只限於專案內所選的記錄。",
        ),
        (
            "This run has a saved completion time while at least one check is still active. The report follows the check state and remains live instead of presenting a final result.",
            "本輪已儲存完成時間，但至少一項檢查仍在進行。報告依循檢查狀態，維持進行中，而不會呈現為最終結果。",
        ),
        (
            "One check's saved coverage history could not be reconciled. Retained findings and evidence remain available, but that check is not counted complete.",
            "有一項檢查已儲存的涵蓋歷程無法核對。保留的問題與證據仍可使用，但該檢查不會計為完成。",
        ),
    ];
    if let Some((_, chinese)) = fixed.iter().find(|(candidate, _)| *candidate == english) {
        return Some((*chinese).to_owned());
    }
    if let Some(finding_id) = strip_frame(
        english,
        "Finding ",
        " has no selected-run presentation snapshot; current canonical wording is labeled as a legacy fallback.",
    ) && !finding_id.is_empty()
    {
        return Some(format!(
            "問題 {finding_id} 沒有所選輪次的呈現快照；目前的正式措辭已標示為舊版備援。"
        ));
    }
    if let Some(finding_id) = strip_frame(
        english,
        "Finding ",
        " has only its retained run observation; presentation detail is unavailable.",
    ) && !finding_id.is_empty()
    {
        return Some(format!(
            "問題 {finding_id} 只有保留的輪次觀察記錄；無法取得呈現細節。"
        ));
    }
    None
}

fn translate_trailing_coverage_frame(
    english: &str,
    middle: (&str, &str),
    suffix: (&str, &str),
) -> Option<String> {
    let (base, retained_with_suffix) = english.rsplit_once(middle.0)?;
    let retained = retained_with_suffix.strip_suffix(suffix.0)?;
    if retained.is_empty() {
        return None;
    }
    let translated_base = if base.is_empty() {
        String::new()
    } else {
        coverage_record_detail_zh_hant(base)?
    };
    Some(format!(
        "{translated_base}{}{retained}{}",
        middle.1, suffix.1
    ))
}

fn strip_frame<'a>(value: &'a str, prefix: &str, suffix: &str) -> Option<&'a str> {
    value.strip_prefix(prefix)?.strip_suffix(suffix)
}

/// The sentences a coverage row says, paired with their Traditional Chinese.
///
/// The backend writes these in English before any locale is known and freezes
/// them into the case, so the English is canonical and this is a lookup rather
/// than a second source of truth. `None` means the sentence is not one this
/// product authored -- a case exclusion carries the words a person typed -- and
/// the caller prints the stored text rather than inventing a label for it.
///
/// Completeness is not enforced by reading this file. `beginner_report.rs`
/// asserts in debug builds that every gap it writes is found here, so the whole
/// Rust suite is the census, and a new sentence added there fails the test that
/// exercises its path rather than passing silently in English.
const COVERAGE_GAP_PROSE: &[(&str, &str)] = &[
    // Why the coverage is missing.
    (
        "Maester evaluated this control but did not return a pass or fail verdict. It requires manual review and is not a vulnerability finding.",
        "Maester 已評估這項控制措施，但未回傳通過或失敗的判定。這項控制措施需要人工檢視，且不是漏洞問題。",
    ),
    (
        "No completed upstream security-template execution record was retained for this website, so the scan cannot be shown as tested. The site may not have responded, or upstream technology detection may not have selected an applicable template.",
        "這個網站沒有保留任何已完成的上游安全模板執行記錄，因此無法將這次掃描顯示為已檢測。網站可能沒有回應，或上游技術偵測可能沒有選出任何適用的模板。",
    ),
    (
        "Greenbone reported that this host did not respond during the scan, so none of its vulnerability checks ran. This is not a clean result.",
        "Greenbone 回報這台主機在掃描期間沒有回應，因此它的弱點檢查一項都沒有執行。這不是乾淨的結果。",
    ),
    (
        "Greenbone reported one or more scanner errors for this host, so some of its checks did not finish. Findings and checks that did complete remain valid.",
        "Greenbone 回報這台主機發生一項或多項掃描器錯誤，因此部分檢查沒有完成。已完成的檢查與問題仍然有效。",
    ),
    (
        "The request-level outcome contradicts the run's durable task state and was ignored.",
        "這次請求層級的結果與本輪儲存的檢查狀態互相矛盾，因此未被採用。",
    ),
    (
        "At least one legacy finding observation did not retain its full run-specific presentation snapshot.",
        "至少有一筆舊版的問題觀察結果，沒有保留該輪完整的顯示資料。",
    ),
    (
        "The saved work-unit coverage for this check is internally inconsistent. The report did not guess which planned units were tested.",
        "這項檢查儲存的工作單元涵蓋記錄本身互相矛盾。報告不會臆測哪些計畫中的單元已經被檢測。",
    ),
    (
        "Usable results were saved for these work units, but their remaining planned operations were not tested complete.",
        "這些工作單元已儲存可用的結果，但其餘計畫中的操作並未完成檢測。",
    ),
    (
        "These planned work units stopped before establishing completed coverage.",
        "這些計畫中的工作單元在建立完整涵蓋之前就停止了。",
    ),
    (
        "These planned work units reached their bounded time limit before completed coverage was recorded.",
        "這些計畫中的工作單元在記錄完整涵蓋之前就達到時間上限。",
    ),
    (
        "These planned work units were cancelled before completed coverage was recorded.",
        "這些計畫中的工作單元在記錄完整涵蓋之前就被取消。",
    ),
    (
        "These frozen work units have no validated tested outcome in any saved attempt.",
        "這些已凍結的工作單元，在任何一次已儲存的嘗試中都沒有通過驗證的檢測結果。",
    ),
    (
        "At least one validated scanner result has not been fully processed into findings. Tested coverage remains saved, but the finding list may be incomplete.",
        "至少有一筆通過驗證的掃描結果尚未完全轉換成問題項目。已檢測的涵蓋範圍仍然保留，但問題清單可能不完整。",
    ),
    (
        "Every planned work unit has completed evidence, but the check itself has not recorded a completed final state.",
        "每個計畫中的工作單元都有完成的證據，但這項檢查本身尚未記錄完成的最終狀態。",
    ),
    (
        "The check reached its time limit after saving some usable results.",
        "這項檢查在儲存了一部分可用結果之後達到時間上限。",
    ),
    (
        "The check reached its time limit before saving a tested outcome.",
        "這項檢查在儲存任何檢測結果之前就達到時間上限。",
    ),
    (
        "The check stopped after saving some usable results.",
        "這項檢查在儲存了一部分可用結果之後停止。",
    ),
    (
        "The check stopped before saving a tested outcome.",
        "這項檢查在儲存任何檢測結果之前就停止。",
    ),
    (
        "The check was cancelled after saving some usable results.",
        "這項檢查在儲存了一部分可用結果之後被取消。",
    ),
    (
        "The check was cancelled before saving a tested outcome.",
        "這項檢查在儲存任何檢測結果之前就被取消。",
    ),
    (
        "This check produced some durable work but did not complete every planned dimension.",
        "這項檢查產生了一部分已保存的成果，但沒有完成每一個計畫中的項目。",
    ),
    (
        "The bounded check reached its time limit, so it cannot be treated as tested complete.",
        "這項受限的檢查達到時間上限，因此不能視為已完整檢測。",
    ),
    (
        "This check stopped before it could establish completed coverage.",
        "這項檢查在建立完整涵蓋之前就停止了。",
    ),
    (
        "This check was cancelled before completed coverage was recorded.",
        "這項檢查在記錄完整涵蓋之前就被取消。",
    ),
    (
        "This check did not start, so it is not a pass.",
        "這項檢查沒有啟動，因此不代表通過。",
    ),
    (
        "This check is still changing and has not recorded a complete result.",
        "這項檢查仍在變動中，尚未記錄完整的結果。",
    ),
    (
        "The packaged check list could not be loaded. Available checks may still run, but checks from that list are not tested.",
        "無法載入內建的檢查清單。可用的檢查仍然可以執行，但該清單上的檢查未被檢測。",
    ),
    (
        "One additional packaged check was unavailable before planning. Whether it applied to the selected target is unknown, so it is not tested.",
        "有一項額外的內建檢查在規劃前無法使用。無法得知它是否適用於所選目標，因此未被檢測。",
    ),
    (
        "At least one target identifier is frozen with the run, but its displayed label or type comes from current project data or is unavailable. The report labels that provenance and does not call it historical fact.",
        "至少有一個目標的識別資料是與本輪一起凍結的，但畫面上顯示的名稱或類型來自目前的專案資料，或是無法取得。報告會標示這項來源，不會把它當成歷史事實。",
    ),
    (
        "This run did not retain an exact reduction record. An empty list therefore cannot be interpreted as proof that no requested dimension was reduced.",
        "本輪沒有保留精確的縮減記錄。因此清單為空，並不能證明沒有任何要求的項目被縮減。",
    ),
    (
        "No exact per-run limits were retained. Current project settings are not substituted for historical requested limits.",
        "沒有保留本輪的精確限制。目前的專案設定不會拿來代替當時要求的限制。",
    ),
    (
        "This run did not freeze a quick-discovery, inventory, or deep-stage selection. The report does not infer one from engine names or current project settings.",
        "本輪沒有凍結快速探索、清點或深度掃描的階段選擇。報告不會從掃描工具名稱或目前的專案設定推測階段。",
    ),
    (
        "At least one readable frozen network plan includes full inventory, but another network check has no valid saved plan. Inventory is the highest known stage, not a complete run-wide record.",
        "至少有一份可讀取的凍結網路計畫包含完整清點，但另一項網路檢查沒有有效的已儲存計畫。清點是目前已知的最高階段，不代表整輪的完整記錄。",
    ),
    (
        "Readable frozen network plans contain quick discovery only, but another network check has no valid saved plan. Quick discovery is the highest known stage, not a complete run-wide record.",
        "可讀取的凍結網路計畫只包含快速探索，但另一項網路檢查沒有有效的已儲存計畫。快速探索是目前已知的最高階段，不代表整輪的完整記錄。",
    ),
    (
        "The run records the completed engine/asset coordinate but not exact observed hosts, services, ports, paths, files, branches, accounts, or resources.",
        "本輪記錄了完成的掃描工具與資產對應關係，但沒有記錄實際觀察到的主機、服務、連接埠、路徑、檔案、分支、帳號或資源。",
    ),
    (
        "This HTTPS management-service profile contains no device product or firmware vulnerability checks. TLS protocol, cipher, and certificate checks are reported separately.",
        "此 HTTPS 管理服務設定檔不包含設備產品或韌體弱點檢查；TLS 協定、加密套件與憑證檢查會另行回報。",
    ),
    (
        "This run does not retain one exact frozen HTTPS management-service profile for this asset. Current project metadata is not used to claim historical TLS coverage.",
        "本輪沒有為此資產保留一份精確凍結的 HTTPS 管理服務設定檔。目前的專案資料不會用來宣稱當時已涵蓋 TLS。",
    ),
    (
        "This run does not retain the exact fixed SSH profile for this asset. Current project metadata is not used to claim historical SSH vulnerability coverage.",
        "本輪沒有為此資產保留精確固定的 SSH 設定檔。目前的專案資料不會用來宣稱當時已完成 SSH 弱點涵蓋。",
    ),
    (
        "The unauthenticated SSH service profile does not inspect operating-system patch level, installed packages or applications, or local host configuration.",
        "這項不需登入的 SSH 服務設定檔，不會檢查作業系統修補層級、已安裝的套件或應用程式，也不會檢查主機本機設定。",
    ),
    (
        "This run does not retain the exact fixed RDP transport profile for this asset. Current project metadata is not used to claim historical RDP transport security coverage.",
        "本輪沒有為此資產保留精確固定的 RDP 傳輸設定檔。目前的專案資料不會用來宣稱當時已完成 RDP 傳輸安全性涵蓋。",
    ),
    (
        "The unauthenticated RDP transport profile checks one legacy RDP 5.2-or-earlier fixed-private-key issue, but does not inspect broader or current RDP implementation CVEs, authentication or Network Level Authentication (NLA), Windows patch level, installed packages or applications, or local host configuration.",
        "這項不需登入的 RDP 傳輸設定檔會檢查一項 RDP 5.2 或更早版本的舊式固定私密金鑰問題，但不會檢查更廣泛或現行的 RDP 實作 CVE、驗證或網路層級驗證（NLA）、Windows 修補層級、已安裝的套件或應用程式，也不會檢查主機本機設定。",
    ),
    (
        "This run does not retain the exact fixed VNC transport profile for this asset. Current project metadata is not used to claim historical VNC transport security coverage.",
        "本輪沒有為此資產保留精確固定的 VNC 傳輸設定檔。目前的專案資料不會用來宣稱當時已完成 VNC 傳輸安全性涵蓋。",
    ),
    (
        "The unauthenticated VNC transport profile checks whether the VNC connection is encrypted. It does not inspect VNC implementation CVEs, authentication strength, operating-system patch level, installed packages or applications, or local host configuration. No login or desktop session was attempted.",
        "這項不需登入的 VNC 傳輸設定檔會檢查 VNC 連線是否加密，但不會檢查 VNC 實作 CVE、驗證強度、作業系統修補層級、已安裝的套件或應用程式，也不會檢查主機本機設定；本輪未嘗試登入或建立桌面工作階段。",
    ),
    (
        "This run does not retain the exact fixed SMTP profile for this asset. Current project metadata is not used to claim historical SMTP security coverage.",
        "本輪沒有為此資產保留精確固定的 SMTP 設定檔。目前的專案資料不會用來宣稱當時已完成 SMTP 安全性涵蓋。",
    ),
    (
        "This run does not retain selected-run finding evidence for every SMTP TLS check. Task completion shows that the fixed profile was attempted, but it does not prove that TLS was available or that every TLS check ran; one finding proves only its own source OID.",
        "本輪沒有為每一項 SMTP TLS 檢查保留所選本輪的 finding 證據。工作完成只表示已嘗試固定設定檔，不能證明 TLS 可用，也不能證明每一項 TLS 檢查都已執行；一筆 finding 只能證明它自己的來源 OID。",
    ),
    (
        "The unauthenticated SMTP profile reads the banner, issues EHLO, negotiates STARTTLS when offered, and checks advertised AUTH for an unencrypted cleartext-login risk. Its TLS checks apply only when TLS can be negotiated. It does not send credentials or mail, test relay or delivery, authentication enforcement or bypass, anti-spam behavior, general mail-server implementation CVEs, operating-system patches, installed software, or local configuration.",
        "這項不需登入的 SMTP 設定檔會讀取 banner、送出 EHLO、在服務提供時協商 STARTTLS，並檢查服務宣告的 AUTH 是否存在未加密的明文登入風險。只有在能協商 TLS 時才會執行 TLS 檢查。它不會送出帳號或密碼、寄信，也不會測試 relay 或投遞、驗證強制或繞過、anti-spam 行為、一般郵件伺服器實作 CVE、作業系統修補、已安裝軟體或本機設定。",
    ),
    (
        "This run does not retain the exact fixed Telnet profile for this asset. Current project metadata is not used to claim historical Telnet security coverage.",
        "本輪沒有為此資產保留精確固定的 Telnet 設定檔。目前的專案資料不會用來宣稱當時已完成 Telnet 安全性涵蓋。",
    ),
    (
        "The unauthenticated Telnet profile observes whether a login or password prompt is offered without TLS. It sends no username or password and does not log in; it does not test default credentials, authentication bypass, Telnet implementation CVEs, operating-system patches, installed software, or local configuration.",
        "這項不需登入的 Telnet 設定檔會觀察服務是否在沒有 TLS 的情況下提供登入或密碼提示。它不會送出帳號或密碼，也不會登入；不會測試預設帳密、驗證繞過、Telnet 實作 CVE、作業系統修補、已安裝軟體或本機設定。",
    ),
    (
        "The Greenbone process completed, but this run does not retain one exact reviewed vulnerability profile for every bound asset. Process completion is not counted as a vulnerability result.",
        "Greenbone 程序雖已完成，但本輪沒有為每個綁定資產保留一份精確且經審查的弱點掃描設定檔。因此程序完成不會被算成弱點掃描結果。",
    ),
    (
        "This asset was added to the IT environment, but this run had no supported service-specific vulnerability profile for it. It was not contacted or tested.",
        "此資產已加入 IT 環境，但本輪沒有適用的服務專屬弱點掃描設定，因此沒有連線，也沒有進行測試。",
    ),
    (
        "The task says completed but has neither a finish time nor a bounded native observation time. The report does not invent when it was tested.",
        "這項工作標示為已完成，卻既沒有結束時間，也沒有內建檢查的觀察時間。報告不會臆造檢測的時間。",
    ),
    // The one step a report with nothing else to say still offers.
    ("Scan continues automatically.", "掃描會自動繼續。"),
    ("Current checks are in progress.", "目前的檢查正在進行中。"),
    (
        "If you expected an app on this port, start it and run the check again.",
        "如果你預期這個連接埠上有服務在執行，請先啟動它，再重新執行檢查。",
    ),
    (
        "The port refused the bounded TCP connection at the recorded time; this is not a security pass or failure.",
        "在記錄的時間點，這個連接埠拒絕了受限的 TCP 連線；這不代表安全性通過或失敗。",
    ),
    (
        "Review what was tested before deciding whether you need a broader scan.",
        "請先檢視已檢測的內容，再決定是否需要更大範圍的掃描。",
    ),
    (
        "No actionable finding was recorded, but a no-findings result is only as broad as the displayed coverage.",
        "沒有記錄到需要處理的問題，但「沒有發現問題」的結論，只在畫面上顯示的涵蓋範圍內成立。",
    ),
    // The three explanations this build stores on a request that contacted
    // nothing. The field is durable free text, so an unrecognized one falls
    // back to the stored English rather than failing.
    (
        "No checks ran because this scan has no active permission for a selected target.",
        "沒有執行任何檢查，因為這次掃描對所選目標沒有有效的授權。",
    ),
    (
        "No checks ran because none of the selected targets is confirmed as yours to scan.",
        "沒有執行任何檢查，因為所選目標都尚未確認是你有權掃描的對象。",
    ),
    (
        "No installed check applies to the selected target and permission. Nothing contacted the target.",
        "沒有任何已安裝的檢查適用於所選的目標與授權範圍。沒有任何連線接觸過該目標。",
    ),
    (
        "Review the exact target and permission, then start the scan again.",
        "請確認目標與授權範圍，然後重新開始掃描。",
    ),
    (
        "Choose a target you control, then start the scan again.",
        "請選擇一個你有掌控權的目標，然後重新開始掃描。",
    ),
    (
        "Choose another available check or add a compatible target source.",
        "請改選其他可用的檢查，或新增相容的目標來源。",
    ),
    // What to do about it.
    (
        "Keep this limitation visible; do not interpret missing historical detail as completed coverage.",
        "請保留這項限制的說明；不要把缺少的歷史細節解讀為已完成的涵蓋。",
    ),
    (
        "Keep this limitation visible; do not interpret a completed process as completed SSH vulnerability coverage.",
        "請保留這項限制；不要把程序完成解讀為已完成 SSH 弱點涵蓋。",
    ),
    (
        "Keep this limitation visible; do not interpret a completed process as completed RDP transport security coverage.",
        "請保留這項限制；不要把程序完成解讀為已完成 RDP 傳輸安全性涵蓋。",
    ),
    (
        "Keep this limitation visible; do not interpret a completed process as completed VNC transport security coverage.",
        "請保留這項限制；不要把程序完成解讀為已完成 VNC 傳輸安全性涵蓋。",
    ),
    (
        "Keep this limitation visible; do not interpret a completed process as completed SMTP security coverage.",
        "請保留這項限制；不要把程序完成解讀為已完成 SMTP 安全性涵蓋。",
    ),
    (
        "Keep this limitation visible; do not interpret a completed process as completed Telnet security coverage.",
        "請保留這項限制；不要把程序完成解讀為已完成 Telnet 安全性涵蓋。",
    ),
    (
        "Keep this limitation visible; use an approved endpoint inventory or local snapshot when those host-level checks are needed.",
        "請保留這項限制；需要主機層級檢查時，請使用已核准的端點盤點資料或本機快照。",
    ),
    (
        "Keep this limitation visible; choose a separately approved host or RDP-authentication assessment when those checks are needed.",
        "請保留這項限制；需要這些檢查時，請另外選擇經核准的主機或 RDP 驗證評估。",
    ),
    (
        "Keep this limitation visible; use an approved endpoint inventory or a separate authorized VNC assessment when those checks are needed.",
        "請保留這項限制；需要這些檢查時，請使用已核准的端點盤點資料，或另行進行已授權的 VNC 評估。",
    ),
    (
        "Keep this limitation visible; use a separately approved mail-server assessment or endpoint inventory when those checks are needed.",
        "請保留這項限制；需要這些檢查時，請另行進行已核准的郵件伺服器評估，或使用已核准的端點盤點資料。",
    ),
    (
        "Keep this limitation visible; use a separately approved TLS assessment when complete SMTP TLS coverage is needed.",
        "請保留這項限制；若需要完整的 SMTP TLS 涵蓋，請另行進行已核准的 TLS 評估。",
    ),
    (
        "Keep this limitation visible; use a separately approved authentication assessment or endpoint inventory when those checks are needed.",
        "請保留這項限制；需要這些檢查時，請另行進行已核准的驗證評估，或使用已核准的端點盤點資料。",
    ),
    (
        "Choose a supported exact asset profile and run it when vulnerability coverage is needed.",
        "需要弱點涵蓋時，請為資產選擇支援的精確掃描設定檔並執行。",
    ),
    (
        "Add a supported exact service profile when you want this asset vulnerability-tested.",
        "需要檢測此資產弱點時，請加入支援的精確服務設定。",
    ),
    (
        "Keep the saved results, then retry this scan if you need an internally consistent coverage record.",
        "請保留已儲存的結果；如果你需要前後一致的涵蓋記錄，再重新執行這次掃描。",
    ),
    (
        "Use the retained severity, confidence, and evidence for review; rerun to create a fully frozen report.",
        "請以保留下來的嚴重程度、把握度與證據進行檢視；若要產生完全凍結的報告，請重新掃描。",
    ),
    (
        "Keep the saved evidence and other results. Retry this check to create a new consistent coverage record.",
        "請保留已儲存的證據與其他結果。重新執行這項檢查，以建立新的一致涵蓋記錄。",
    ),
    (
        "Keep the saved results and retry only the unfinished work.",
        "請保留已儲存的結果，只重新執行尚未完成的部分。",
    ),
    (
        "Keep other saved results and retry only the failed work.",
        "請保留其他已儲存的結果，只重新執行失敗的部分。",
    ),
    (
        "Keep other saved results and retry only the timed-out work.",
        "請保留其他已儲存的結果，只重新執行逾時的部分。",
    ),
    (
        "Start only the cancelled work again when you want to finish it.",
        "想要完成時，只需重新啟動被取消的那部分工作。",
    ),
    (
        "Let the current check continue or cancel it; saved partial results remain available.",
        "可以讓目前的檢查繼續，或是取消它；已儲存的部分結果仍然可以使用。",
    ),
    (
        "Retry only the work that has not yet produced a tested outcome.",
        "只需重新執行尚未產生檢測結果的那部分工作。",
    ),
    (
        "Keep the saved results. The app should retry result processing automatically; keep this limitation visible until it succeeds.",
        "請保留已儲存的結果。本程式應該會自動重試結果處理；在成功之前，請保留這項限制的說明。",
    ),
    (
        "Keep the completed results. The app should reconcile the timed-out check before treating the run as final.",
        "請保留已完成的結果。本程式應該先核對這項逾時的檢查，才能把本輪視為最終結果。",
    ),
    (
        "Keep the completed results. The app should reconcile the stopped check before treating the run as final.",
        "請保留已完成的結果。本程式應該先核對這項中止的檢查，才能把本輪視為最終結果。",
    ),
    (
        "Keep the completed results. The app should reconcile the cancelled check before treating the run as final.",
        "請保留已完成的結果。本程式應該先核對這項被取消的檢查，才能把本輪視為最終結果。",
    ),
    (
        "Keep the completed results while the app reconciles the check's final state.",
        "在本程式核對這項檢查的最終狀態期間，請保留已完成的結果。",
    ),
    (
        "Confirm the host is powered on and reachable from this computer on the approved ports, then run this check again.",
        "請確認這台主機已開機，且本機能連到已核准的連接埠，然後再執行一次這項檢查。",
    ),
    (
        "Keep the saved results and run this check again to cover the checks that did not finish.",
        "保留已儲存的結果，再執行一次這項檢查以涵蓋沒有完成的項目。",
    ),
    (
        "Keep saved results and retry only the unfinished work.",
        "請保留已儲存的結果，只重新執行尚未完成的部分。",
    ),
    (
        "Keep saved results and start only the unfinished work again when you are ready.",
        "請保留已儲存的結果；準備好之後，只需重新啟動尚未完成的部分。",
    ),
    (
        "Review the saved results, then retry this check to cover the unfinished dimensions.",
        "請先檢視已儲存的結果，再重新執行這項檢查，以涵蓋尚未完成的項目。",
    ),
    (
        "Retry once; if it times out again, review reachability or ask a network specialist.",
        "請重試一次；如果再次逾時，請檢查連線是否可達，或詢問網路專業人員。",
    ),
    (
        "Keep the saved results from other checks and retry this check.",
        "請保留其他檢查已儲存的結果，並重新執行這項檢查。",
    ),
    (
        "Start this check again when you want to finish the missing coverage.",
        "想要補齊缺少的涵蓋範圍時，請重新執行這項檢查。",
    ),
    (
        "Review the target and try this check again.",
        "請檢視目標設定，然後重新執行這項檢查。",
    ),
    (
        "Let it continue or cancel it; the partial report remains available.",
        "可以讓它繼續，或是取消它；這份部分完成的報告仍然可以使用。",
    ),
    (
        "Keep the available results. The app can include these checks in a later run after their packaged scanner information is restored.",
        "請保留目前可用的結果。等這些檢查的內建掃描工具資訊恢復之後，本程式可以在之後的掃描中納入它們。",
    ),
    (
        "Review the upstream detail and record a human decision for this control.",
        "請檢視上游詳細資料，並為這項控制措施記錄人工判定。",
    ),
    (
        "No action is needed unless this area should be included in a future scan.",
        "除非之後的掃描要納入這個範圍，否則不需要採取任何行動。",
    ),
];

/// One sentence of a coverage row, in Traditional Chinese, or `None` when this
/// product did not author it.
pub fn coverage_gap_prose_zh_hant(english: &str) -> Option<String> {
    let trimmed = english.trim();
    const REVIEW_BASE: &str = "Maester evaluated this control but did not return a pass or fail verdict. It requires manual review and is not a vulnerability finding.";
    if let Some(detail) = trimmed.strip_prefix(&format!("{REVIEW_BASE} Upstream detail: "))
        && !detail.is_empty()
    {
        let base = lookup(REVIEW_BASE)?;
        return Some(format!("{base} 上游詳細資料：{detail}"));
    }
    // Six reasons gain a diagnostic code when the task recorded one. It is the
    // scanner's own code and stays verbatim; only the sentence around it moves.
    if let Some((head, code)) = trimmed
        .strip_suffix('.')
        .and_then(|rest| rest.rsplit_once(" Diagnostic code: "))
    {
        // `stable_task_reason` appends to a sentence that already ends in a
        // period, so the head is a complete key on its own.
        let base = lookup(head)?;
        return Some(format!("{base}診斷代碼：{code}。"));
    }
    lookup(trimmed)
}

fn lookup(english: &str) -> Option<String> {
    COVERAGE_GAP_PROSE
        .iter()
        .find(|(candidate, _)| *candidate == english)
        .map(|(_, chinese)| (*chinese).to_owned())
}

pub fn priority_reason_zh_hant(english: &str) -> String {
    let trimmed = english.trim();
    if trimmed == ENGLISH_EVIDENCE_REASON {
        return "已附上掃描工具的直接證據，仍需人工檢視。".to_owned();
    }
    if trimmed == ENGLISH_EXPOSURE_OBSERVATION_REASON {
        return "這是可連線服務的盤點觀察，不是漏洞。".to_owned();
    }
    if trimmed == crate::prioritization::INTERNET_REASON {
        return "受影響的資產被標記為可從網際網路存取，且其保留的來源歸屬皆非問卷填答。".to_owned();
    }
    if trimmed == crate::prioritization::SENSITIVE_REASON {
        return "受影響的資產被標記為含有敏感資料，其保留的來源歸屬皆非問卷填答，且案件問卷另有記錄敏感資料情境。".to_owned();
    }
    const UNRATED_PREFIX: &str = "Severity remains Unknown because ";
    const UNRATED_TAIL: &str = " did not assign one; human review is required.";
    if let Some(engine) = trimmed
        .strip_prefix(UNRATED_PREFIX)
        .and_then(|rest| rest.strip_suffix(UNRATED_TAIL))
        .filter(|engine| !engine.is_empty())
    {
        return format!("嚴重程度維持為未知，因為 {engine} 未提供評級；需由人工確認。");
    }
    // The engine's own raw severity word, kept verbatim. Restating "high" as
    // 高 would stop it matching what the reader sees in the engine's own output.
    if let Some(value) = trimmed
        .strip_prefix("Source severity: ")
        .filter(|value| !value.is_empty())
    {
        return format!("來源工具評定的嚴重程度：{value}");
    }
    if let Some(value) = trimmed
        .strip_prefix("Source confidence: ")
        .filter(|value| !value.is_empty())
    {
        return format!("來源工具評定的信心：{value}");
    }
    const CONFIDENCE_DERIVED: &str = "Confidence derived from ";
    const CONFIDENCE_TAIL: &str = " reports no confidence of its own.";
    if let Some(rest) = trimmed
        .strip_prefix(CONFIDENCE_DERIVED)
        .and_then(|rest| rest.strip_suffix(CONFIDENCE_TAIL))
    {
        let Some((basis_text, engine)) = rest.rsplit_once("; ") else {
            return english.to_owned();
        };
        let Some(code) = ALL_CONFIDENCE_BASIS_CODES
            .into_iter()
            .find(|code| confidence_basis_english(*code) == basis_text)
        else {
            return english.to_owned();
        };
        if engine.is_empty() {
            return english.to_owned();
        }
        return format!(
            "信心是由{}推導而來；{engine} 本身不提供信心評定。",
            confidence_basis_zh_hant(code)
        );
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
const IAM_PRINCIPAL_PREVIEW_LIMIT: usize = 6;

pub fn aws_iam_policy_source_label_english(source: AwsIamPolicySource) -> &'static str {
    match source {
        AwsIamPolicySource::AwsManaged => "AWS-managed",
        AwsIamPolicySource::CustomerManaged => "Customer-managed",
        AwsIamPolicySource::Inline => "Inline",
    }
}

pub fn aws_iam_policy_source_label_zh_hant(source: AwsIamPolicySource) -> &'static str {
    match source {
        AwsIamPolicySource::AwsManaged => "AWS 受管",
        AwsIamPolicySource::CustomerManaged => "客戶受管",
        AwsIamPolicySource::Inline => "內嵌",
    }
}

fn iam_principal_labels(details: &AwsIamPolicyFindingDetails, locale: &str) -> Vec<String> {
    let labels = if locale == "zh-Hant" {
        ("角色", "群組", "使用者")
    } else {
        ("role", "group", "user")
    };
    details
        .attached_to
        .roles
        .iter()
        .map(|name| format!("{} {name}", labels.0))
        .chain(
            details
                .attached_to
                .groups
                .iter()
                .map(|name| format!("{} {name}", labels.1)),
        )
        .chain(
            details
                .attached_to
                .users
                .iter()
                .map(|name| format!("{} {name}", labels.2)),
        )
        .collect()
}

fn iam_principal_summary(details: &AwsIamPolicyFindingDetails, locale: &str) -> Option<String> {
    let labels = iam_principal_labels(details, locale);
    if labels.is_empty() {
        return None;
    }
    let retained = labels
        .iter()
        .take(IAM_PRINCIPAL_PREVIEW_LIMIT)
        .cloned()
        .collect::<Vec<_>>()
        .join(if locale == "zh-Hant" { "、" } else { ", " });
    let omitted = labels.len().saturating_sub(IAM_PRINCIPAL_PREVIEW_LIMIT);
    if omitted == 0 {
        Some(retained)
    } else if locale == "zh-Hant" {
        Some(format!("{retained}，以及另外 {omitted} 個主體"))
    } else {
        Some(format!("{retained}, and {omitted} more principal(s)"))
    }
}

/// Product-owned English next action for bounded Cloudsplaining evidence.
/// The source engine still owns the finding, rating, and attached-principal
/// facts; this function only tells a beginner what kind of manual change fits
/// the policy source.
pub fn aws_iam_policy_action_english(
    expert_type: &str,
    details: &AwsIamPolicyFindingDetails,
) -> String {
    let principals = iam_principal_summary(details, "en");
    let action = match (
        details.policy_source,
        principals.as_deref(),
        details.attached_to.complete,
    ) {
        (AwsIamPolicySource::AwsManaged, Some(principals), _) => format!(
            "replace AWS-managed policy {} with a narrower policy on {principals}, or detach it where it is not needed; AWS-managed policies cannot be edited by this account",
            details.policy_name
        ),
        (AwsIamPolicySource::AwsManaged, None, true) => format!(
            "confirm that AWS-managed policy {} remains detached and choose a narrower policy before attaching it; AWS-managed policies cannot be edited by this account",
            details.policy_name
        ),
        (AwsIamPolicySource::AwsManaged, None, false) => format!(
            "identify the current roles, groups, and users attached to AWS-managed policy {}, then replace it with a narrower policy or detach it where it is not needed; AWS-managed policies cannot be edited by this account",
            details.policy_name
        ),
        (AwsIamPolicySource::CustomerManaged, Some(principals), _) => format!(
            "narrow customer-managed policy {} and verify that {principals} retain only the permissions they need",
            details.policy_name
        ),
        (AwsIamPolicySource::CustomerManaged, None, true) => format!(
            "narrow customer-managed policy {} before it is attached or reused",
            details.policy_name
        ),
        (AwsIamPolicySource::CustomerManaged, None, false) => format!(
            "identify the current attachments to customer-managed policy {}, then narrow it and verify that each principal retains only the permissions it needs",
            details.policy_name
        ),
        (AwsIamPolicySource::Inline, Some(principals), _) => format!(
            "narrow inline policy {} directly on {principals}",
            details.policy_name
        ),
        (AwsIamPolicySource::Inline, None, _) => format!(
            "review where inline policy {} is owned and narrow it there before reuse",
            details.policy_name
        ),
    };
    let incomplete = (!details.attached_to.complete).then_some(
        " The retained attachment list is incomplete; confirm the current IAM attachments before changing the policy.",
    );
    format!(
        "Have the recommended specialist ({expert_type}) review the affected policy and source evidence, then plan and approve this action: {action}.{}",
        incomplete.unwrap_or_default()
    )
}

fn aws_iam_policy_action_zh_hant(
    expert_type: &str,
    details: &AwsIamPolicyFindingDetails,
) -> String {
    let principals = iam_principal_summary(details, "zh-Hant");
    let action = match (
        details.policy_source,
        principals.as_deref(),
        details.attached_to.complete,
    ) {
        (AwsIamPolicySource::AwsManaged, Some(principals), _) => format!(
            "在{principals}上將 AWS 受管政策 {} 改為權限較小的政策；若不需要則解除附加。AWS 受管政策無法由此帳戶直接編輯",
            details.policy_name
        ),
        (AwsIamPolicySource::AwsManaged, None, true) => format!(
            "確認 AWS 受管政策 {} 維持未附加狀態；之後如有需要，應選用權限較小的政策。AWS 受管政策無法由此帳戶直接編輯",
            details.policy_name
        ),
        (AwsIamPolicySource::AwsManaged, None, false) => format!(
            "先確認目前有哪些角色、群組與使用者附加了 AWS 受管政策 {}，再改用權限較小的政策；若不需要則解除附加。AWS 受管政策無法由此帳戶直接編輯",
            details.policy_name
        ),
        (AwsIamPolicySource::CustomerManaged, Some(principals), _) => format!(
            "縮小客戶受管政策 {} 的權限，並確認{principals}只保留工作所需權限",
            details.policy_name
        ),
        (AwsIamPolicySource::CustomerManaged, None, true) => format!(
            "在客戶受管政策 {} 再次附加或使用前縮小其權限",
            details.policy_name
        ),
        (AwsIamPolicySource::CustomerManaged, None, false) => format!(
            "先確認客戶受管政策 {} 目前附加到哪些 IAM 主體，再縮小政策權限，並確認每個主體只保留工作所需權限",
            details.policy_name
        ),
        (AwsIamPolicySource::Inline, Some(principals), _) => format!(
            "直接在{principals}上縮小內嵌政策 {} 的權限",
            details.policy_name
        ),
        (AwsIamPolicySource::Inline, None, _) => format!(
            "確認內嵌政策 {} 所屬的 IAM 主體，並在再次使用前於該處縮小權限",
            details.policy_name
        ),
    };
    let incomplete = (!details.attached_to.complete)
        .then_some("保留的附加清單不完整；變更政策前請先核對目前的 IAM 附加關係。");
    format!(
        "請由建議的專業人員（{}）檢視受影響的政策與來源證據，再規劃並核准以下處理：{}。{}",
        expert_type_zh_hant(expert_type),
        action,
        incomplete.unwrap_or_default()
    )
}

pub fn action_zh_hant(
    english: &str,
    expert_type: &str,
    family: Option<FindingFamily>,
    aws_iam_policy: Option<&AwsIamPolicyFindingDetails>,
) -> String {
    if let Some(details) = aws_iam_policy {
        return aws_iam_policy_action_zh_hant(expert_type, details);
    }
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

    #[test]
    fn control_mapping_rationale_lookup_translates_only_reviewed_catalog_prose() {
        let known = "Evidence that an identity has no registered multi-factor device is related to authenticating users and safeguarding authentication information.";
        assert_eq!(
            control_mapping_rationale_zh_hant(known),
            Some("某個身分未登記多重要素驗證裝置的證據，與驗證使用者及保護驗證資訊有關。".into())
        );
        assert_eq!(
            control_mapping_rationale_zh_hant("A rationale from another build."),
            None
        );
    }

    #[test]
    fn data_quality_warning_lookup_translates_fixed_and_framed_prose_only() {
        assert_eq!(
            data_quality_warning_zh_hant(
                "The selected run's stored project identifier does not match this project. The report remains limited to the selected in-project record."
            ),
            Some("所選掃描輪次儲存的專案識別碼與此專案不符。報告仍只限於專案內所選的記錄。".into())
        );
        assert_eq!(
            data_quality_warning_zh_hant(
                "Finding finding-user-value has only its retained run observation; presentation detail is unavailable."
            ),
            Some("問題 finding-user-value 只有保留的輪次觀察記錄；無法取得呈現細節。".into())
        );
        assert_eq!(
            data_quality_warning_zh_hant("[redacted data-quality warning]"),
            None
        );
        assert_eq!(
            data_quality_warning_zh_hant("A warning from a later build."),
            None
        );
    }

    #[test]
    fn requested_limit_values_translate_known_units_and_preserve_identifiers() {
        for (name, value, expected) in [
            ("connection timeout", "250 ms", "250 毫秒"),
            ("application payload", "64 bytes", "64 位元組"),
            ("gitleaks execution timeout", "600 seconds", "600 秒"),
            (
                "asset-primary request rate",
                "5 per second, concurrency 2",
                "每秒 5 次，並行 2",
            ),
            ("endpoint", "127.0.0.1:443", "127.0.0.1:443"),
        ] {
            assert_eq!(requested_limit_value_zh_hant(name, value), expected);
        }
        assert_eq!(
            requested_limit_value_zh_hant("future limit", "value from another build"),
            "value from another build"
        );
    }

    #[test]
    fn coverage_record_detail_shapes_translate_without_changing_retained_values() {
        for (english, expected) in [
            (
                "The source area is explicitly outside this case: Legacy lab stays excluded. This is a scoped applicability statement, not a successful scan result.",
                "此來源範圍明確不在本案件內：Legacy lab stays excluded. 這是範圍適用性的說明，不是掃描成功的結果。",
            ),
            (
                "The source is connected and the latest attributable discovery returned no assets. This is not a successful scan result; 17 prior asset observation(s) remain retained. Latest provider discovery: provider_timeout: Provider response was late.",
                "來源已連線，且最近一次可歸屬的探索未傳回任何資產。這不是掃描成功的結果；仍保留 17 筆先前的資產觀察結果。 最近一次供應商探索：provider_timeout: Provider response was late.",
            ),
            (
                "The source is not currently connected (status: credentials_expired). Its present coverage is unknown; 17 previously attributed asset(s) are retained but do not make the source green.",
                "來源目前未連線（狀態：credentials_expired）。目前的涵蓋未知；仍保留 17 筆先前歸屬的資產，但這不會讓來源顯示為綠色。",
            ),
            (
                "The scan's frozen authorization evidence is incomplete: grant-1=historical_scope_snapshot_missing. Live grants are never used to reconstruct historical scan permission.",
                "掃描中凍結的授權證據不完整：grant-1=historical_scope_snapshot_missing。絕不會用現行授權重建過去的掃描權限。",
            ),
            (
                "All 2 compatible engine run(s) planned for this asset completed. This state is independent of how many findings were reported. Explicit stale-knowledge warning: scanner knowledge 2026-01-01 (support ended 2026-06-01). Completion proves execution, not current knowledge.",
                "為此資產規劃的 2 項相容掃描工具工作皆已完成。 此狀態與回報了多少個問題無關。 明確的過時知識警告：scanner knowledge 2026-01-01 (support ended 2026-06-01)。完成只證明已執行，不代表知識仍為最新。",
            ),
            (
                "All 1 planned task(s) for this asset completed their exact declared dimensions. This state is independent of how many findings were reported. Exact built-in localhost TCP attempt(s): 127.0.0.1:443=reachable. This records only those connection attempts; it does not establish that the service or computer is secure, and it does not cover other ports or hosts.",
                "為此資產規劃的 1 項工作，皆已完成各自明確宣告的檢查範圍。 此狀態與回報了多少個問題無關。 精確的內建 localhost TCP 嘗試：127.0.0.1:443=reachable。這只記錄這些連線嘗試；無法證明服務或電腦安全，也不涵蓋其他連接埠或主機。",
            ),
            (
                "The authorized scan is incomplete: scanner=failed. Only completed compatible catalog-engine runs or exact completed built-in tasks can produce scanned coverage.",
                "已授權的掃描未完成：scanner=failed。只有已完成且相容的目錄掃描工具工作，或精確完成的內建工作，才能產生已掃描涵蓋。",
            ),
        ] {
            assert_eq!(
                coverage_record_detail_zh_hant(english),
                Some(expected.to_owned())
            );
        }
        assert!(
            coverage_record_detail_zh_hant(
                "A later build records a different coverage explanation."
            )
            .is_none()
        );
    }

    #[test]
    fn tested_observation_lookup_translates_only_prose_this_build_authored() {
        assert_eq!(
            tested_observation_zh_hant("The port accepted the bounded TCP connection."),
            Some("這個連接埠接受了受限的 TCP 連線。".to_owned())
        );
        assert_eq!(
            tested_observation_zh_hant(
                "The completed Greenbone task retained the exact reviewed RDP transport profile: ten TLS protocol, cipher, and certificate checks plus one check for the legacy fixed private key used by RDP 5.2 or earlier."
            ),
            Some("已完成的 Greenbone 工作保留了精確且經過檢視的 RDP 傳輸設定檔：十項 TLS 協定、加密套件與憑證檢查，加上一項針對 RDP 5.2 或更早版本所使用之舊式固定私密金鑰的檢查。".to_owned())
        );
        assert_eq!(
            tested_observation_zh_hant(
                "The completed Greenbone task retained the exact reviewed VNC transport profile containing one check for an unencrypted VNC connection."
            ),
            Some("已完成的 Greenbone 工作保留了精確且經過檢視的 VNC 傳輸設定檔，其中包含一項未加密 VNC 連線檢查。".to_owned())
        );
        assert_eq!(
            tested_observation_zh_hant("A later build recorded a different observation."),
            None
        );
    }

    #[test]
    fn rdp_and_vnc_limit_prose_is_available_in_traditional_chinese() {
        assert_eq!(
            coverage_gap_prose_zh_hant(
                "The unauthenticated RDP transport profile checks one legacy RDP 5.2-or-earlier fixed-private-key issue, but does not inspect broader or current RDP implementation CVEs, authentication or Network Level Authentication (NLA), Windows patch level, installed packages or applications, or local host configuration."
            ),
            Some("這項不需登入的 RDP 傳輸設定檔會檢查一項 RDP 5.2 或更早版本的舊式固定私密金鑰問題，但不會檢查更廣泛或現行的 RDP 實作 CVE、驗證或網路層級驗證（NLA）、Windows 修補層級、已安裝的套件或應用程式，也不會檢查主機本機設定。".to_owned())
        );
        assert_eq!(
            coverage_gap_prose_zh_hant(
                "Keep this limitation visible; choose a separately approved host or RDP-authentication assessment when those checks are needed."
            ),
            Some(
                "請保留這項限制；需要這些檢查時，請另外選擇經核准的主機或 RDP 驗證評估。"
                    .to_owned()
            )
        );
        assert_eq!(
            coverage_gap_prose_zh_hant(
                "The unauthenticated VNC transport profile checks whether the VNC connection is encrypted. It does not inspect VNC implementation CVEs, authentication strength, operating-system patch level, installed packages or applications, or local host configuration. No login or desktop session was attempted."
            ),
            Some("這項不需登入的 VNC 傳輸設定檔會檢查 VNC 連線是否加密，但不會檢查 VNC 實作 CVE、驗證強度、作業系統修補層級、已安裝的套件或應用程式，也不會檢查主機本機設定；本輪未嘗試登入或建立桌面工作階段。".to_owned())
        );
    }

    /// The TypeScript twin is held to the same outputs by
    /// `tests/frontend/coverageDimensionPresentation.test.ts`, which also
    /// censuses the producer. This one exists so the Rust side fails on its own.
    #[test]
    fn a_limit_name_is_translated_around_the_identifier_it_carries() {
        // Fixed names.
        assert_eq!(requested_limit_name_zh_hant("endpoint"), "連線端點");
        assert_eq!(
            requested_limit_name_zh_hant("connection timeout"),
            "連線逾時限制"
        );
        assert_eq!(
            requested_limit_name_zh_hant("application payload"),
            "應用資料量"
        );
        // Composed around an engine or asset id, which is what tells three
        // grants' rows apart.
        let labels = [
            "asset-primary approved ports",
            "asset-secondary approved ports",
            "asset-lab approved ports",
        ]
        .map(requested_limit_name_zh_hant);
        assert_eq!(labels[0], "允許檢查的連接埠（asset-primary）");
        assert_eq!(labels[1], "允許檢查的連接埠（asset-secondary）");
        assert_eq!(labels[2], "允許檢查的連接埠（asset-lab）");
        assert_eq!(
            requested_limit_name_zh_hant("gitleaks execution timeout"),
            "檢查逾時限制（gitleaks）"
        );
        // An empty identifier gains no empty parentheses.
        assert_eq!(
            requested_limit_name_zh_hant("approved ports"),
            "允許檢查的連接埠"
        );
        assert_eq!(
            requested_limit_name_zh_hant(" execution timeout"),
            "檢查逾時限制"
        );
        // An unrecognized name keeps its text.
        assert_eq!(
            requested_limit_name_zh_hant("prowler concurrency ceiling"),
            "本輪使用的限制：prowler concurrency ceiling"
        );
        assert!(recognized_requested_limit_name_zh_hant("prowler concurrency ceiling").is_none());
    }

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
            ("RDP transport security checks", "RDP 傳輸安全性檢查"),
            (
                "RDP transport endpoint scan-profile coverage",
                "RDP 傳輸端點掃描設定檔涵蓋記錄",
            ),
            (
                "RDP implementation, authentication/NLA, and endpoint host coverage",
                "RDP 實作、驗證／NLA 與端點主機涵蓋範圍",
            ),
            ("VNC transport security check", "VNC 傳輸安全性檢查"),
            (
                "VNC transport endpoint scan-profile coverage",
                "VNC 傳輸端點掃描設定檔涵蓋記錄",
            ),
            (
                "VNC implementation, authentication, and endpoint host coverage",
                "VNC 實作、驗證與端點主機涵蓋範圍",
            ),
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

    /// The other direction from the producer census in `beginner_report.rs`:
    /// that one fails when a sentence has no entry, this one fails when an
    /// entry has no sentence. A key with a typo in it is invisible to the
    /// census unless the suite happens to exercise the path that writes it.
    #[test]
    fn every_key_is_a_sentence_some_producer_actually_writes() {
        let producers = [
            include_str!("beginner_report.rs"),
            include_str!("case_service.rs"),
        ];
        // Rust continues a long literal with a backslash before the newline and
        // swallows the indentation that follows it.
        let joined = producers
            .iter()
            .map(|source| {
                source
                    .split('\\')
                    .map(|part| part.trim_start_matches(['\n', ' ']))
                    .collect::<String>()
            })
            .collect::<Vec<_>>();
        let orphans = COVERAGE_GAP_PROSE
            .iter()
            .map(|(english, _)| *english)
            .filter(|english| !joined.iter().any(|source| source.contains(english)))
            .collect::<Vec<_>>();
        assert_eq!(orphans, Vec::<&str>::new(), "no producer writes these");
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
            impact_zh_hant("English impact.", &Severity::Unknown, "中", None, None, &[],),
            "English impact."
        );
        assert_eq!(
            action_zh_hant("English action.", "Container security engineer", None, None,),
            "English action."
        );
        // A sentence this product did not write is not taken apart for a name.
        assert_eq!(
            summary_zh_hant(
                "Some other text.",
                &Severity::High,
                "高",
                None,
                "高",
                None,
                &[],
            ),
            "Some other text."
        );
    }

    #[test]
    fn aws_iam_policy_actions_follow_the_upstream_policy_source_and_attachments() {
        let details = AwsIamPolicyFindingDetails {
            policy_source: AwsIamPolicySource::AwsManaged,
            policy_name: "IAMFullAccess".into(),
            finding_identity: "CreateAccessKey".into(),
            actions: vec!["iam:createaccesskey".into()],
            actions_complete: true,
            attached_to: crate::domain::AwsIamAttachedTo {
                roles: vec!["BuildRole".into()],
                groups: vec![],
                users: vec!["Operator".into()],
                complete: false,
            },
        };

        let english = aws_iam_policy_action_english("Cloud security engineer", &details);
        assert!(english.contains("replace AWS-managed policy IAMFullAccess"));
        assert!(english.contains("role BuildRole"));
        assert!(english.contains("user Operator"));
        assert!(english.contains("cannot be edited by this account"));
        assert!(english.contains("attachment list is incomplete"));

        let chinese = action_zh_hant(
            "unused English fallback",
            "Cloud security engineer",
            Some(FindingFamily::CloudIdentity),
            Some(&details),
        );
        assert!(chinese.contains("AWS 受管政策 IAMFullAccess"));
        assert!(chinese.contains("角色 BuildRole"));
        assert!(chinese.contains("使用者 Operator"));
        assert!(chinese.contains("無法由此帳戶直接編輯"));
        assert!(chinese.contains("附加清單不完整"));

        let mut unknown_attachments = details.clone();
        unknown_attachments.attached_to.roles.clear();
        unknown_attachments.attached_to.users.clear();
        let unknown_action =
            aws_iam_policy_action_english("Cloud security engineer", &unknown_attachments);
        assert!(unknown_action.contains("identify the current roles, groups, and users"));
        assert!(!unknown_action.contains("remains detached"));

        let mut customer_managed = details.clone();
        customer_managed.policy_source = AwsIamPolicySource::CustomerManaged;
        let customer_action =
            aws_iam_policy_action_english("Cloud security engineer", &customer_managed);
        assert!(customer_action.contains("narrow customer-managed policy IAMFullAccess"));
        assert!(!customer_action.contains("cannot be edited by this account"));

        let mut inline = details;
        inline.policy_source = AwsIamPolicySource::Inline;
        let inline_action = aws_iam_policy_action_english("Cloud security engineer", &inline);
        assert!(inline_action.contains("narrow inline policy IAMFullAccess directly on"));
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
        let plain = impact_zh_hant(
            english,
            &Severity::High,
            "高",
            None,
            Some(FindingFamily::CloudPosture),
            &[],
        );
        assert!(!plain.contains("受影響的資產被標記"), "{plain}");

        for (factor, expected) in [
            (ContextFactor::InternetExposedAsset, "可從網際網路存取"),
            (ContextFactor::SensitiveDataAsset, "含有敏感資料"),
        ] {
            let composed = impact_zh_hant(
                english,
                &Severity::High,
                "高",
                None,
                Some(FindingFamily::CloudPosture),
                &[factor],
            );
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
            &Severity::High,
            "高",
            None,
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
                summary_zh_hant(&english, &Severity::High, "高", None, "高", None, &[],)
                    .starts_with(&format!("{engine} ")),
                "{engine} lost its name"
            );
        }
    }

    #[test]
    fn an_unrated_unknown_says_the_scanner_did_not_rate_it_and_requests_review() {
        let english_summary = "Gitleaks reported this condition but did not assign a severity. Severity remains Unknown and requires human review. The attached raw record is evidence, not an instruction.";
        let summary = summary_zh_hant(
            english_summary,
            &Severity::Unknown,
            "未知",
            Some(SeverityBasisCode::SecretPatternMatch),
            "高",
            None,
            &[],
        );
        assert!(summary.contains("Gitleaks"), "{summary}");
        assert!(summary.contains("未評定嚴重程度"), "{summary}");
        assert!(summary.contains("維持為未知"), "{summary}");
        assert!(summary.contains("人工確認"), "{summary}");
        assert!(!summary.contains("本產品依據"), "{summary}");
        assert!(!summary.contains("將它評為未知"), "{summary}");

        let impact = impact_zh_hant(
            "If the scanner result is confirmed, a secret may permit unauthorized access. The scanner did not assign a severity; it remains Unknown for human review.",
            &Severity::Unknown,
            "未知",
            Some(SeverityBasisCode::SecretPatternMatch),
            Some(FindingFamily::Secret),
            &[],
        );
        assert!(impact.contains("未評定嚴重程度"), "{impact}");
        assert!(impact.contains("維持為未知"), "{impact}");
        assert!(impact.contains("人工確認"), "{impact}");
        assert!(!impact.contains("由本產品提供"), "{impact}");

        let reason = priority_reason_zh_hant(
            "Severity remains Unknown because Gitleaks did not assign one; human review is required.",
        );
        assert!(reason.contains("Gitleaks"), "{reason}");
        assert!(reason.contains("維持為未知"), "{reason}");
        assert!(reason.contains("人工確認"), "{reason}");
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
            .map(|family| {
                action_zh_hant(
                    "English.",
                    "Secrets-response specialist",
                    Some(*family),
                    None,
                )
            })
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
            SeverityBasisCode::CloudsplainingIamPolicyFinding,
            SeverityBasisCode::UnratedVulnerabilityTestAlarm,
        ];
        let summaries = bases
            .iter()
            .map(|code| {
                summary_zh_hant(
                    ENGLISH_SUMMARY,
                    &Severity::High,
                    "高",
                    Some(*code),
                    "高",
                    None,
                    &[],
                )
            })
            .collect::<std::collections::BTreeSet<_>>();
        assert_eq!(summaries.len(), bases.len());
        for summary in &summaries {
            assert!(summary.contains("未評定嚴重程度"), "{summary}");
        }
    }

    #[test]
    fn every_confidence_basis_composes_chinese_and_names_this_product() {
        let summaries = ALL_CONFIDENCE_BASIS_CODES
            .into_iter()
            .map(|code| {
                summary_zh_hant(
                    ENGLISH_SUMMARY,
                    &Severity::High,
                    "高",
                    None,
                    "高",
                    Some(code),
                    &[],
                )
            })
            .collect::<std::collections::BTreeSet<_>>();
        assert_eq!(summaries.len(), ALL_CONFIDENCE_BASIS_CODES.len());
        for summary in summaries {
            assert!(summary.contains("本產品依據"), "{summary}");
            assert!(summary.contains("信心評為高"), "{summary}");
        }
        assert_eq!(
            confidence_presentation_zh_hant("高", None, &["Source confidence: HIGH".into()]),
            "高 — 來源工具評定：HIGH"
        );
        assert_eq!(confidence_presentation_zh_hant("高", None, &[]), "高");
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
