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
        "The task says completed but has neither a finish time nor a bounded native observation time. The report does not invent when it was tested.",
        "這項工作標示為已完成，卻既沒有結束時間，也沒有內建檢查的觀察時間。報告不會臆造檢測的時間。",
    ),
    // The one step a report with nothing else to say still offers.
    (
        "Let the scan continue or cancel it if you need to stop.",
        "可以讓掃描繼續，或是在你需要停止時取消它。",
    ),
    (
        "This report is still changing and keeps the durable work already saved.",
        "這份報告仍在變動中，並保留已經儲存下來的成果。",
    ),
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
        "No action is needed unless this area should be included in a future scan.",
        "除非之後的掃描要納入這個範圍，否則不需要採取任何行動。",
    ),
];

/// One sentence of a coverage row, in Traditional Chinese, or `None` when this
/// product did not author it.
pub fn coverage_gap_prose_zh_hant(english: &str) -> Option<String> {
    let trimmed = english.trim();
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
