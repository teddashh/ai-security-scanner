# 產品編輯策劃方案：ai-security-scanner

本策劃案為產品負責人量身編製，旨在將「ai-security-scanner」的技術成果轉譯為清楚、真誠且嚴謹的產品語言。目標受眾涵蓋商業決策者、專案管理者、人文社科背景工作者，以及一般 IT 人員。文案徹底去除公關修辭與資安黑話，回歸產品「解決什麼問題、為何重要、下一步該做什麼、有哪些明確極限」的本質。

---

## 1. 繁體中文 README (README.zh-TW.md)

```markdown
# ai-security-scanner

[專案網站](https://teddashh.github.io/ai-security-scanner/?lang=zh-TW) · [English](README.md) · [說明文件](docs/README.zh-TW.md) · [版本下載](https://github.com/teddashh/ai-security-scanner/releases)

多數團隊在評估數位專案時，往往需要同時面對程式碼、相依套件、對外網站與內部伺服器。過去這意味著必須在十幾個命令列工具之間切換，並手動比對成百上千條格式各異的警告。

ai-security-scanner 採取更直接的方式：你只需要選定要檢查的項目並確認授權，應用程式會自動挑選適用的開源掃描工具，完成後整合出一份依資產分類、排定優先順序的標準化報告。報告會直接告訴你哪裡有風險、為什麼要修正，以及如何著手處理。

---

## 第一次掃描

所有掃描均在你的本機電腦上執行。掃描的啟動、暫停與繼續，均必須在**桌面應用程式視窗**中操作。

### 1. 下載與安裝 (v0.4.0 穩定版)

| 作業系統 | 安裝檔案 | 首次開啟步驟 |
| :--- | :--- | :--- |
| **macOS** (Apple Silicon / Intel) | [ai-security-scanner_0.4.0_universal.dmg](https://github.com/teddashh/ai-security-scanner/releases/download/v0.4.0/ai-security-scanner_0.4.0_universal.dmg) | 拖移至「應用程式」目錄。本版本未向 Apple 申請公證，首次開啟前請在終端機執行一次：<br>`xattr -dr com.apple.quarantine /Applications/ai-security-scanner.app` |
| **Windows** (x86-64) | [Setup .exe](https://github.com/teddashh/ai-security-scanner/releases/download/v0.4.0/ai-security-scanner_0.4.0_x64-setup.exe) 或 [MSI 安裝檔](https://github.com/teddashh/ai-security-scanner/releases/download/v0.4.0/ai-security-scanner_0.4.0_x64_en-US.msi) | 安裝檔未含商業數位簽章。若出現 SmartScreen 提示，點選**「其他資訊」→「仍要執行」**。若系統提示更新 WSL，請允許安裝。 |
| **Debian / Ubuntu** (x86-64) | [ai-security-scanner_0.4.0_amd64.deb](https://github.com/teddashh/ai-security-scanner/releases/download/v0.4.0/ai-security-scanner_0.4.0_amd64.deb) | 於終端機執行安裝：<br>`sudo apt install ./ai-security-scanner_0.4.0_amd64.deb` |

*註：應用程式在首次檢查時會於背景自行準備執行環境，無需安裝 Docker。*

### 2. 選擇檢查路徑

開啟應用程式後，你會看到三個核心檢查選項：

*   **檢查程式碼或 AI 專案 (Check code or an AI project)**：掃描本機專案資料夾。應用程式會建立隔離的唯讀複本，檢查內嵌的金鑰密碼、已知套件弱點、危險程式碼模式與模型組態。
*   **檢查網站 (Check a website)**：針對單一授權網址進行唯讀 HTTP 安全性檢驗。
*   **掃描 IT 環境 (Scan my environment)**：將多個專案資料夾、對外網站與已獲授權的內部主機整合在同一輪掃描中。

*(進階選項：提供雲端與 Microsoft 365 檢查，請見下方說明。)*

### 3. 開始與儲存

點選 **「開始新掃描 (New scan)」→ 確認目標與授權範圍 (Review and start) → 在視窗中點擊「開始 (Start)」**。
掃描完成後，依序點選 **「保存或分享報告 (Save or share report)」→「儲存 HTML 報告 (Save HTML report)」**。你也可以隨時從主畫面的「我的掃描 (My scans)」重新檢視過往紀錄。

---

## 可以檢查什麼，以及檢查的極限

我們堅持工具的功能邊界必須清晰透明：

1.  **三個核心檢查路徑**：
    *   **本機專案**：使用靜態分析比對常見編程弱點、讀取宣告檔檢查已知漏洞套件，並離線辨識是否遺留 API Token 或憑證。
    *   **網站檢驗**：以唯讀方式發送預設的無害 HTTP 請求，驗證伺服器回應標頭與公開設定是否符合基本安全防護。
    *   **IT 環境整合**：測試指定內部主機的特定連接埠是否可連通，並盤點基礎資產。
2.  **進階雲端檢查的真實範圍**：
    *   目前的 AWS、Azure 與 GCP 模組**僅限於身分與存取管理 (IAM) 的靜態設定檢視**，例如檢查過度寬鬆的權限政策。
    *   **這不是全盤性的雲端安全稽核**，無法檢測執行階段流量、未授權入侵或複雜的雲端架構拓撲。
3.  **盤點資訊不是漏洞**：
    *   軟體物料清單 (SBOM)、主機清單，以及開放的網路通訊埠（Port），屬於客觀的「資產現況盤點」，並不等於安全漏洞。報告會將兩者嚴格分開列示。
4.  **未發現問題不等於絕對安全**：
    *   「零發現」僅代表在本次執行的特定規則下未觸發警報，絕不能視為系統無懈可擊的保證。
5.  **絕不擅自修改任何系統**：
    *   應用程式提供診斷與步驟指引，**不會自動執行修復腳本**，亦不會擅自變更你的程式碼或主機配置。

---

## 如何解讀報告

每次掃描後產生的單一報告，會依你選取的資產逐一分組：

*   **最優先處理事項**：將風險最高、最明確的問題排在最前面，說明潛在衝擊。
*   **最小可行處置動作**：提供工程師或管理者能立即著手的具體修改建議，以及事後如何驗證修正。
*   **未完成與未測試項目**：明確列出哪些檢查因超時、權限不足或未勾選而跳過，避免造成「已經全部檢查完畢」的錯覺。
*   **完整技術佐證**：每筆發現均保留上游工具的原始編號（Rule ID）、嚴重度評級、原始輸出與程式碼行號，供技術人員比對確認。

---

## 隱私與安全邊界

*   **專案程式碼絕不上傳**：本機專案檢查完全在本機建立暫存的唯讀複本進行掃描，不會執行專案程式碼，亦不會將專案上傳至任何雲端伺服器。
*   **網路連線嚴格受限**：網路掃描模組僅會對你在畫面上明確核准的網址與連接埠發出連線請求。
*   **報告預設保留於本機**：所有掃描結果均儲存在你自己的裝置上，除非你手動匯出或分享 HTML 檔案。
*   **雲端存取權限說明**：若你曾設定雲端 IAM 讀取權限，現行的設定腳本會保留該授權以便重複檢驗；**本工具目前不會在掃描後自動撤銷該權限**，若不再使用請至雲端後台手動移除。
*   **歷史檔案留存**：本工具不會自動抹除所有過往的掃描紀錄與暫存快照，以利歷史比對；使用者可在需要時手動清理。

---

## 配合 Claude Code 或 Codex 使用

你可以使用 AI 輔助程式來協助準備環境與檢視報告。

**重要限制**：為了確保執行安全，AI Agent（包括 CLI 工具）**無法獨立啟動、暫停或恢復掃描**。掃描的執行開關唯一存在於桌面應用程式視窗中。

AI Agent 可以協助你完成以下工作：
1. 檢查你的作業系統是否符合掃描相容性。
2. 協助下載並正確安裝桌面應用程式。
3. 在終端機中引導你選擇適當的檢查資產。
4. 掃描完成後，解讀本機報告並將其另存為 HTML。

兩款工具均支援本專案的專屬 Skill：
*   Claude Code Skill：`.claude/skills/ai-security-scanner/SKILL.md`
*   Codex Skill：`.codex/skills/ai-security-scanner/SKILL.md`

---

## 深入了解技術細節

*   [快速入門指南 (Getting Started)](docs/getting-started.zh-TW.md)
*   [掃描範圍與設定界限 (Scanning Scope)](docs/scanning-scope.zh-TW.md)
*   [整合工具型錄與固定版本 (Engine Catalog)](docs/engine-catalog.md)
*   [範例報告展示 (Sample Reports)](docs/samples/v0.4.0/README.zh-TW.md)
*   [發布說明 (Release Notes)](docs/release/v0.4.0.zh-TW.md)
```

---

## 2. 英文 README (README.md)

```markdown
# ai-security-scanner

[Project Website](https://teddashh.github.io/ai-security-scanner/) · [繁體中文](README.zh-TW.md) · [Documentation](docs/README.md) · [Releases](https://github.com/teddashh/ai-security-scanner/releases)

Assessing the security of modern software typically involves running multiple specialized tools across code repositories, external endpoints, and internal infrastructure. Stitching disparate command-line utilities together often leaves teams with duplicate alerts, conflicting severity ratings, and confusion over what to fix first.

ai-security-scanner simplifies this process. You choose the assets to evaluate and confirm network permissions. The application selects the appropriate open-source inspection tools, executes them locally, and normalizes the results into one structured report grouped by asset. You get clear priorities, explanations of why an issue matters, and practical remediation steps.

---

## Getting Started

All scans execute on your local machine. **Starting, pausing, and resuming a scan requires pressing the controls in the desktop application window.**

### 1. Download and Install (v0.4.0 Stable)

| Operating System | Installer | First Launch Note |
| :--- | :--- | :--- |
| **macOS** (Apple silicon / Intel) | [ai-security-scanner_0.4.0_universal.dmg](https://github.com/teddashh/ai-security-scanner/releases/download/v0.4.0/ai-security-scanner_0.4.0_universal.dmg) | Drag the app to `/Applications`. This build is not notarized by Apple. Run this command once in Terminal before opening:<br>`xattr -dr com.apple.quarantine /Applications/ai-security-scanner.app` |
| **Windows** (x86-64) | [Setup .exe](https://github.com/teddashh/ai-security-scanner/releases/download/v0.4.0/ai-security-scanner_0.4.0_x64-setup.exe) or [MSI](https://github.com/teddashh/ai-security-scanner/releases/download/v0.4.0/ai-security-scanner_0.4.0_x64_en-US.msi) | Unsigned installer. If Windows SmartScreen prompts, select **More info → Run anyway**. Allow WSL installation if prompted. |
| **Debian / Ubuntu** (x86-64) | [ai-security-scanner_0.4.0_amd64.deb](https://github.com/teddashh/ai-security-scanner/releases/download/v0.4.0/ai-security-scanner_0.4.0_amd64.deb) | Install via terminal:<br>`sudo apt install ./ai-security-scanner_0.4.0_amd64.deb` |

*Note: The desktop app configures its own runtime environment before the first run; Docker is not required.*

### 2. Choose Your Scan Path

Open the app and select one of three primary paths:

*   **Check code or an AI project**: Evaluates a local folder using an isolated read-only copy. Checks for exposed secrets, outdated dependencies, insecure code patterns, and configuration issues.
*   **Check a website**: Performs bounded, read-only HTTP health and security configuration checks against a single approved origin.
*   **Scan my environment**: Combines local repositories, websites, and approved internal hosts in a single batch.

*(Advanced cloud and workspace checks are also available; see details below.)*

### 3. Review, Start, and Save

Navigate through **New scan → Review and start → Click "Start" in the application window**.
When finished, select **Save or share report → Save HTML report**. You can reopen prior runs at any time under **My scans**.

---

## What It Checks — and Real Limits

We believe in stating operational boundaries upfront:

1.  **Three Primary Paths**:
    *   **Local Projects**: Scans code for known vulnerability patterns, inspects package manifests against vulnerability registries, and checks for accidentally committed credentials.
    *   **Websites**: Sends controlled, non-destructive HTTP requests to evaluate transport security headers and misconfigurations.
    *   **IT Environments**: Verifies TCP port connectivity and basic service discovery on approved target hosts.
2.  **Scope of Cloud Checks (Advanced)**:
    *   Cloud checks for AWS, Azure, and GCP are **strictly limited to static identity and access management (IAM) configuration reviews** (e.g., detecting overly permissive policies).
    *   **This is not a comprehensive cloud audit.** It does not inspect runtime network traffic, monitor active workloads, or evaluate overall cloud infrastructure health.
3.  **Inventory Is Not a Vulnerability**:
    *   Software Bills of Materials (SBOMs), host inventories, and open network ports are objective observations, not security defects. The report catalogs them separately from actionable findings.
4.  **No Findings Is Not a Guarantee**:
    *   A scan reporting zero findings means only that the selected tools detected no matching patterns under their specific rules. It does not certify that an asset is inherently invulnerable.
5.  **No Automatic Remediation**:
    *   The app diagnoses risks and suggests concrete next actions. It **never modifies source code, cloud permissions, or system configurations automatically**.

---

## Understanding the Report

Your final report groups all results under their respective assets:

*   **Top Priorities First**: High-impact issues are elevated, with clear explanations of potential consequences.
*   **Actionable Next Steps**: Practical, human-executable recommendations for fixing each issue, along with simple steps to verify the resolution.
*   **Visible Coverage Gaps**: Incomplete or skipped checks are displayed explicitly, ensuring you always know what was evaluated and what was not.
*   **Preserved Evidence**: Upstream rule IDs, severities, exact lines of code, and tool outputs remain intact for verification by engineering teams.

---

## Privacy and Data Handling

*   **Local Processing**: Repository scans operate on an isolated local read-only snapshot. Your source code is never executed and never uploaded to remote servers.
*   **Controlled Network Traffic**: Network scanners contact only the hostnames, IPs, and ports you explicitly review and approve.
*   **Local Report Storage**: Scan findings, logs, and evidence remain on your computer unless you explicitly export or share them.
*   **Cloud Credential Persistence**: Cloud assessment setup scripts establish access for ongoing evaluations. **The application does not automatically revoke these permissions after a run.** Revoke them manually in your cloud console when finished.
*   **Artifact Retention**: Historical scan records and temp snapshots are preserved locally for comparison; automatic background cleanup of every past artifact is not guaranteed.

---

## Integration with Claude Code and Codex

You can pair the scanner with AI developer tools like Claude Code or Codex.

**Important Operational Constraint**: AI Agents and CLI commands **cannot independently start, pause, or resume scans**. The execution control exists exclusively as a button inside the desktop application interface.

An AI Agent running on your machine can:
1. Verify system prerequisites and environment readiness.
2. Help you download and install the desktop application.
3. Guide you through selecting your assets before you start the scan in the app.
4. Explain the findings and export the HTML report once the scan finishes.

Supported skills:
*   Claude Code Skill: `.claude/skills/ai-security-scanner/SKILL.md`
*   Codex Skill: `.codex/skills/ai-security-scanner/SKILL.md`

---

## Further Documentation

*   [Getting Started Guide](docs/getting-started.md)
*   [Scanning Scope and Rules](docs/scanning-scope.md)
*   [Engine Catalog and Pinned Versions](docs/engine-catalog.md)
*   [Sample Reports (v0.4.0)](docs/samples/v0.4.0/README.md)
*   [Release Notes](docs/release/v0.4.0.md)
```

---

## 3. 網站文案 (Website Copy)

### 繁體中文版

```markdown
<!-- HERO SECTION -->
# 多種安全工具，一份清楚報告。

選擇你的專案資料夾、網站或內部主機，在桌面應用程式上一鍵啟動。
ai-security-scanner 自動執行適用的開源掃描工具，將繁雜的偵測結果整理成一份依資產分組、指出處理順序與具體作法的標準化報告。

[ 下載 v0.4.0 正式版 ]  [ 閱讀使用指南 → ]

> 適用於 macOS、Windows 與 Linux。本機優先、預設唯讀，無需安裝 Docker。
> 支援搭配 Claude Code 與 Codex 進行環境準備、問題解讀與報告匯出。

---

<!-- THREE STEPS SECTION -->
## 只要三步，掌握真實安全現況

### 1. 選定目標並確認範圍
選取本機程式碼資料夾、網站網址或內部主機。在開始前，完整檢視所有將接觸的目標與網路通訊埠，確保一切皆在授權範圍內。

### 2. 在桌面程式一鍵啟動
點擊桌面視窗中的「開始」按鈕。系統會根據資產類型自動配置最合適的檢測工具，透過唯讀方式進行檢查，既不中斷既有服務，也不會擅自改動任何檔案。

### 3. 閱讀優先排序報告
掃描結束後，獲得一份結構清晰的報告。高風險問題置於頂部，附帶白話影響評估、建議處置步驟與驗證方法；未測試的項目同樣清清楚楚。

---

## 核心能力與明確邊界

我們提供精確的診斷，並且從不誇大功能極限：

*   **本機專案與 AI 工作流程**
    *   **檢查內容**：靜態程式碼安全分析、依賴套件弱點比對、不慎洩漏的 API 金鑰與 Token，以及新興 AI 框架（LangGraph、CrewAI、n8n 等）的架構組態。
    *   **運作保證**：全程使用隔離的唯讀複本，不執行你的專案，不改動你的程式碼，也絕不上傳原始碼。
*   **授權網站檢驗**
    *   **檢查內容**：透過預設的安全規則庫檢查對外 HTTP 回應標頭、常見伺服器設定疏漏。
    *   **運作保證**：僅限於使用者授權的單一來源網址，不發動破壞性攻擊請求。
*   **內部 IT 環境與基礎設施**
    *   **檢查內容**：已核准主機的通訊埠可連通性、軟體物料清單（SBOM）產生。
    *   **重要觀念**：開放的通訊埠與系統軟體清單屬於客觀的「資產盤點」，並非安全漏洞；報告會將兩者清楚拆分。
*   **雲端 IAM 身分與權限檢查（進階功能）**
    *   **檢查內容**：針對 AWS、Azure 與 GCP 檢驗身分與存取管理（IAM）是否出現過度寬鬆的政策指派。
    *   **明確邊界**：這**不是全盤性的雲端安全稽核**。檢查設定腳本所建立的唯讀金鑰需由管理者手動維護或刪除，本程式不會自動撤銷雲端存取權。

---

<!-- REPORT PREVIEW SECTION -->
## 真正的報告，長這個樣子

不賣弄難懂的資安術語，直接回答經營者與工程團隊最關心的三個問題：
**發生了什麼？這有多要緊？下一步該做什麼？**

```
┌────────────────────────────────────────────────────────────────────────┐
│  資產：api-service (本機程式碼專案)                                       │
│                                                                        │
│  [嚴重] 原始碼內發現疑似外洩之雲端存取憑證 (AWS Access Key)              │
│  影響：任何能存取該儲存庫的人員皆可能取得相應雲端環境之讀寫權限。          │
│  下一步：                                                              │
│  1. 立即至 AWS IAM 控制台停用該憑證 ID (AKIA...)。                      │
│  2. 將金鑰移出程式碼，改以環境變數或秘密管理服務注入。                  │
│  3. 執行檢驗：重新掃描本專案，確認該金鑰模式不再出現。                 │
│  技術依據：Gitleaks (Rule: aws-access-token) · src/config.ts:42        │
└────────────────────────────────────────────────────────────────────────┘
```

> **真實範例提供**：我們提供以真實工具格式產生的模擬展示報告，供你在安裝前直接預覽。
> [ 查看遮蔽版 HTML 報告 → ]   [ 查看完整資訊版 HTML 報告 → ]

---

<!-- AI ASSISTANT HELP SECTION -->
## 搭配 Claude Code 與 Codex：分工明確的安全助理

你可以將本專案的專屬 Skill 載入 Claude Code 或 Codex。AI 可以在你的本機環境中：
*   驗證作業系統環境是否具備執行條件。
*   協助下載並安裝 v0.4.0 穩定版桌面應用程式。
*   依照你的需求指引你挑選資產範圍。
*   掃描完成後，協助你閱讀報告中的技術細節並匯出 HTML。

> **安全機制提醒**：AI 助手與命令列**無法自行在背景啟動或暫停掃描**。為了確保操作完全受控，實際掃描的啟動按鈕固定存在於桌面應用程式介面中。

---

<!-- CTA SECTION -->
## 立即掌握你的專案安全現況

無訂閱套牢、無雲端上傳疑慮。下載安裝即可在本機開始第一次檢查。

[ 下載 v0.4.0 穩定版 (macOS / Windows / Linux) ]
[ 探索 GitHub 開源儲存庫 ↗ ] · [ 查看 25 個整合工具與引擎版本型錄 ↗ ]
```

---

### English Version

```markdown
<!-- HERO SECTION -->
# Many security tools. One clear report.

Select your project repositories, websites, or internal hosts, then start an evaluation in our desktop application.
ai-security-scanner coordinates established open-source security tools, normalizes their output, and gives you one consolidated report organized by asset—with clear priorities, practical context, and concrete next actions.

[ Download v0.4.0 Stable ]  [ Read Getting Started → ]

> Available for macOS, Windows, and Linux. Local-first, read-only by default, no Docker required.
> Compatible with Claude Code and Codex for guided environment preparation and report export.

---

<!-- THREE STEPS SECTION -->
## Three Steps to Security Clarity

### 1. Select Targets and Review Scope
Choose local code folders, website URLs, or internal hosts. Review the exact list of targets and network ports before anything runs, ensuring all checks remain within authorized boundaries.

### 2. Start Once from the Desktop App
Click "Start" directly inside the desktop application window. The app selects the appropriate inspection tools for each asset type and runs them in a bounded, read-only manner without touching live services.

### 3. Read Your Prioritized Report
Review a unified, structured summary once the run completes. Severe issues appear at the top with plain-language explanations of impact, suggested next steps, and verification instructions.

---

## Built for Precision, Honest About Limits

We provide direct technical evidence without marketing hype or inflated claims:

*   **Local Code and AI Frameworks**
    *   **What it does**: Identifies exposed credentials, scans package manifests for known CVEs, highlights high-risk code patterns, and parses configurations of popular agentic frameworks (LangGraph, CrewAI, n8n, etc.).
    *   **Guarantees**: Scans run against isolated, local read-only snapshots. Your code is never executed, modified, or uploaded.
*   **Authorized Website Checks**
    *   **What it does**: Inspects HTTP response headers, transport security flags, and public configuration flaws using reviewed, non-destructive check templates.
    *   **Guarantees**: Restricted exclusively to your approved origin; never sends intrusive attack payloads.
*   **Internal IT Infrastructure**
    *   **What it does**: Verifies TCP port accessibility and generates Software Bills of Materials (SBOMs).
    *   **Distinction**: Open ports and component lists are recorded as *inventory observations*, not vulnerabilities.
*   **Cloud IAM Configuration (Advanced)**
    *   **What it does**: Evaluates identity and access management policies in AWS, Azure, and GCP for common excessive permissions.
    *   **Boundaries**: This is **strictly a configuration review, not a comprehensive cloud audit**. Setup scripts establish read-only credentials that persist until you manually remove them; the app does not automatically revoke access.

---

<!-- REPORT PREVIEW SECTION -->
## What You Actually Receive

No obscure security acronyms. The report directly answers:
**What happened? Why does it matter? What is the next step?**

```
┌────────────────────────────────────────────────────────────────────────┐
│  Asset: api-service (Local Repository)                                 │
│                                                                        │
│  [CRITICAL] Hardcoded Cloud Credential Pattern (AWS Access Key)         │
│  Impact: Anyone with repository access could obtain cloud environment   │
│          read/write permissions.                                       │
│  Next Action:                                                          │
│  1. Immediately deactivate this credential ID in AWS IAM Console.      │
│  2. Remove key from source code and load via environment secrets.       │
│  3. Verify: Re-run scan to confirm the secret is no longer detected.   │
│  Evidence: Gitleaks (Rule: aws-access-token) · src/config.ts:42        │
└────────────────────────────────────────────────────────────────────────┘
```

> **Review Sample Reports**: Explore simulated reports produced by our real production pipeline.
> [ View Redacted HTML Sample → ]   [ View Full Disclosure HTML Sample → ]

---

<!-- AI ASSISTANT HELP SECTION -->
## Working with Claude Code and Codex

Use our dedicated Agent Skills to streamline your workflow. An agent running locally can:
*   Confirm that your operating system satisfies scanning prerequisites.
*   Guide you through downloading and installing the v0.4.0 desktop app.
*   Help you configure your scan targets before you begin.
*   Explain technical findings and export the final HTML report.

> **Operational Safeguard**: AI agents and command-line interfaces **cannot start, pause, or resume scans independently**. To guarantee human oversight, scan execution controls remain strictly inside the desktop application interface.

---

<!-- CTA SECTION -->
## Know Where Your Security Stands Today

No subscriptions, no external data sharing. Install locally and run your first assessment.

[ Download v0.4.0 (macOS / Windows / Linux) ]
[ View on GitHub ↗ ] · [ Explore the 25 Integrated Engines Catalog ↗ ]
```

---

## 4. 報告文案標準庫 (Standard Report Copy)

本節提供報告各個區塊的中英文標準範本，確保產出之報告語氣冷靜、嚴謹且兼具實用性。

### 4.1 已完成檢查且發現問題 (Completed with Findings)

#### 繁體中文
> **狀態：已完成檢查 · 發現需要處理的項目**
> 
> 本輪掃描已針對指定資產完成適用工具的檢測，並確認存在若干安全性問題。
> 
> **優先處理項目**
> *   **影響資產**：`{asset_name}`（類型：`{asset_type}`）
> *   **問題概述**：`{finding_title}`
> *   **嚴重程度**：`{Critical / High / Medium / Low}`
> *   **潛在影響**：`{impact_explanation}`（說明未修復時可能造成的業務或技術後果）
> *   **建議下一步**：
>     1. `{step_1}`（具體可行的最小改善動作）
>     2. `{step_2}`
> *   **驗證方式**：完成修改後，請對該資產重新執行檢查，確認此項目不再出現於問題列表中。
> *   **技術證據**：由 `{upstream_scanner}` 檢測提供（規則識別碼：`{rule_id}`），位置：`{file_path_or_endpoint}:{line_number}`。詳細原始輸出請參閱下方「技術細節」展開欄。

#### English
> **Status: Completed with Actionable Findings**
> 
> The scan completed applicable checks for the selected asset and identified security issues that require attention.
> 
> **Highest Priority Item**
> *   **Affected Asset**: `{asset_name}` (Type: `{asset_type}`)
> *   **Issue**: `{finding_title}`
> *   **Severity**: `{Critical / High / Medium / Low}`
> *   **Potential Impact**: `{impact_explanation}` (Explains the practical operational or security risk if left unaddressed)
> *   **Recommended Next Steps**:
>     1. `{step_1}` (The smallest practical corrective action)
>     2. `{step_2}`
> *   **Verification**: After implementing the fix, re-scan this asset to verify that the finding is resolved.
> *   **Technical Evidence**: Reported by `{upstream_scanner}` (Rule ID: `{rule_id}`) at `{file_path_or_endpoint}:{line_number}`. Raw engine output is preserved in the Technical Details section below.

---

### 4.2 已完成檢查且未發現問題 (No Findings in Completed Checks)

#### 繁體中文
> **狀態：已完成檢查 · 未觸發已知警報**
> 
> 在本次所選定的工具與規則範圍內，未發現符合已知特徵的安全問題。
> 
> **重要說明與邊界提醒**：
> 本結果**僅代表已完成的特定檢查項目未回報異常，絕非系統絕對安全的保證**。未在此次檢驗範圍內的架構邏輯、未公開之零日漏洞（Zero-day）、非預設組態，以及未經勾選的深度檢測模組，均不在本結論涵蓋之內。請定期維持相依套件更新並檢視存取權限。

#### English
> **Status: Completed Checks Found No Issues**
> 
> All applicable checks executed to completion without triggering alerts under their current pinned rulesets.
> 
> **Important Scope Limitation**:
> This result indicates **only that no problems were detected by the specific tools and rules executed during this run. It is not a guarantee of absolute security.** Undetected flaws, custom business logic risks, zero-day vulnerabilities, and checks outside the chosen scope are not covered by this outcome. Maintain regular dependency updates and access reviews.

---

### 4.3 部分完成／涵蓋缺口 (Partial Completion / Coverage Gaps)

#### 繁體中文
> **狀態：部分完成 · 存在未竟之涵蓋缺口**
> 
> 本輪掃描中部分獨立工具未能順利完成檢測（原因可能為網路連線超時、本機權限不足或目標服務拒絕連線）。
> 
> **已完成與保留之結果**：
> 凡已執行完畢的工具結果與佐證資料，均已妥善保留於下方報告中，不受失敗項目影響。
> 
> **未完成項目說明**：
> *   **資產**：`{asset_name}`
> *   **中斷工具**：`{failed_engine_name}`
> *   **回報原因**：`{failure_reason_or_timeout}`
> *   **建議處置**：檢查目標主機連線狀況、驗證本機防毒或防火牆規則未阻擋該工具執行後，於桌面應用程式中針對該項目重新發起檢查。

#### English
> **Status: Partially Complete · Coverage Gaps Observed**
> 
> One or more independent inspection tools did not complete successfully (e.g., target timeout, insufficient local privileges, or connection refusal).
> 
> **Preservation of Completed Results**:
> All findings from tools that finished successfully are preserved below and remain fully valid.
> 
> **Unfinished Checks Detail**:
> *   **Asset**: `{asset_name}`
> *   **Affected Tool**: `{failed_engine_name}`
> *   **Reported Reason**: `{failure_reason_or_timeout}`
> *   **Recommended Action**: Verify host reachability and local execution permissions, then re-run the check for this asset from the desktop app.

---

### 4.4 資產涵蓋範圍總覽 (Asset Coverage Summary)

#### 繁體中文
> ### 資產檢驗涵蓋範圍 (Coverage Summary)
> 
> 每項資產的安全性必須建立在清楚的檢驗邊界上。以下為本次評估之完整執行狀態：
> 
> | 選定資產 | 資產類型 | 已完成檢查項目 | 存在問題項目 | 執行中斷／失敗 | 未納入測試項目 |
> | :--- | :--- | :--- | :--- | :--- | :--- |
> | `web-portal` | 網站 (HTTPS) | 2 項 (Nuclei, ZAP) | 1 個高風險 | 0 | 伺服器內部組態 (未授權) |
> | `core-api` | 本機儲存庫 | 3 項 (Semgrep, Gitleaks, Grype) | 1 個嚴重 (金鑰) | 0 | 執行階段記憶體分析 (不支援) |
> | `db-host-01` | 內部主機 | 1 項 (Naabu) | 0 | 1 項 (OpenVAS 超時) | 帳號弱密碼爆破 (已停用) |
> 
> *註：軟體元件盤點（SBOM）與開放通訊埠屬於系統現況盤點，已獨立列於「盤點觀察清單」，不計入上方「存在問題項目」數字。*

#### English
> ### Asset Coverage Summary
> 
> Reliable security assessments require knowing exactly what was examined and what was omitted. Current run status:
> 
> | Asset Name | Asset Type | Completed Checks | Issues Detected | Incomplete / Failed | Omitted from Scope |
> | :--- | :--- | :--- | :--- | :--- | :--- |
> | `web-portal` | Website (HTTPS) | 2 (Nuclei, ZAP) | 1 High | 0 | Internal Host Config (Unauthorized) |
> | `core-api` | Local Repo | 3 (Semgrep, Gitleaks, Grype) | 1 Critical (Secret) | 0 | Dynamic Runtime Analysis (Unsupported) |
> | `db-host-01` | Internal Host | 1 (Naabu) | 0 | 1 (OpenVAS Timeout) | Credential Brute-Force (Disabled) |
> 
> *Note: Software inventory lists (SBOM) and open port observations reflect objective system state and are cataloged under "Inventory Observations," separate from vulnerability counts.*

---

### 4.5 下一步處置與修正指引 (Next Steps & Practical Remediation)

#### 繁體中文
> ### 後續處置指引
> 
> 1.  **人工審閱與確認**：
>     請技術團隊依據問題清單中的程式碼行號與原始證據進行複查。本工具不會自動修改原始碼或套用設定，所有變更均需經過人工評估。
> 2.  **優先處理關鍵憑證**：
>     若報告中出現「嚴重（Critical）」等級的金鑰外洩警報，首要之務為前往發證服務商後台將該金鑰立即**撤銷或輪替（Rotate）**，單純從 Git 歷史刪除並不足以消除外洩風險。
> 3.  **相依套件升級**：
>     針對含有已知漏洞的第三方程式庫，請參考建議版本於套件管理清單（如 `package.json`、`go.mod`、`requirements.txt`）中進行版本升級，並於本地通過自動化測試後再行部署。
> 4.  **修正後複驗**：
>     完成處置後，請開啟應用程式並利用「重新檢查（Re-scan）」功能進行驗證，確認修正後的專案已不再觸發該警報。

#### English
> ### Next Steps and Remediation Guidance
> 
> 1.  **Human Review Required**:
>     Engineering teams should review the flagged code locations and raw evidence. The scanner does not modify code, deploy patches, or change configuration files automatically.
> 2.  **Prioritize Exposed Credentials**:
>     If a "Critical" exposed secret is identified, immediately **revoke or rotate the token in the provider console**. Removing the secret from the git commit history does not invalidate an already exposed credential.
> 3.  **Update Vulnerable Dependencies**:
>     For libraries with known CVEs, reference the suggested target versions in your package manifest (`package.json`, `go.mod`, `requirements.txt`). Run test suites before deploying the upgrade.
> 4.  **Verify Resolution**:
>     After implementing changes, open the desktop application and trigger a re-scan of the affected asset to verify that the issue is fully cleared.

---

### 4.6 技術細節展開區塊 (Technical Details Accordion)

#### 繁體中文
> <details>
> <summary>點擊展開技術細節與原始偵測輸出 (Technical Details & Raw Evidence)</summary>
> 
> *   **偵測引擎**：`Gitleaks v8.18.4` (固定修訂版)
> *   **規則識別碼**：`aws-access-token`
> *   **比對目標**：`/local/snapshots/api-service/src/config.ts` (行號: 42)
> *   **原始比對字串**：`AKIA****************` (敏感數值於報告中自動遮蔽)
> *   **上游建議處置**：Revoke the AWS access key immediately and replace with environment variable injection.
> *   **執行指標**：耗時 142ms · 檔案系統比對規則數 184 · 唯讀沙箱模式
> </details>

#### English
> <details>
> <summary>Click to view Technical Details & Raw Output</summary>
> 
> *   **Engine**: `Gitleaks v8.18.4` (Pinned upstream revision)
> *   **Rule ID**: `aws-access-token`
> *   **Match Location**: `/local/snapshots/api-service/src/config.ts` (Line 42)
> *   **Matched Value**: `AKIA****************` (Sensitive characters redacted by report pipeline)
> *   **Upstream Remediation**: Revoke the AWS access key immediately and replace with environment variable injection.
> *   **Execution Metrics**: Elapsed: 142ms · Evaluated rules: 184 · Mode: Read-only local snapshot
> </details>

---

### 4.7 正式報告頁尾與法律責任免責聲明 (Formal Footer & Notice)

#### 繁體中文
> ---
> **報告正式聲明**
> 
> *   **產製時間**：`2026-10-04 15:56:00 UTC` · **執行工具版本**：`ai-security-scanner v0.4.0`
> *   **資料處理界限**：本報告之評估數據完全於本機端產製並保存。原始程式碼使用唯讀複本進行靜態比對，絕無外傳或遠端執行。網路檢驗僅接觸本次掃描前於畫面確認核准之目標主機與通訊埠。
> *   **檢查能力範圍免責聲明**：本報告所列之一切結果，僅反映所載整合工具（固定版本）在特定規則庫下之偵測成果。鑑於資安威脅之動態性，本工具不對系統是否存在未檢出之安全漏洞、未公開缺陷（0-day）或惡意行為承擔保證責任。本報告不構成對任何資訊系統之適法性或絕對安全背書。

#### English
> ---
> **Formal Report Notice**
> 
> *   **Generated**: `2026-10-04 15:56:00 UTC` · **Engine Release**: `ai-security-scanner v0.4.0`
> *   **Data Boundaries**: This report was processed and generated locally. Source code repositories were analyzed via isolated, read-only snapshots and were neither executed nor uploaded to any external server. Network communications were confined strictly to the user-confirmed targets and ports.
> *   **Scope Disclaimer**: The findings and observations in this document reflect only the detection capabilities of the integrated upstream scanning engines and their pinned rulesets at the time of execution. Due to the evolving nature of digital security threats, this report does not warrant that the inspected assets are completely secure or free from unlisted, novel, or zero-day vulnerabilities. This document does not constitute a formal legal or regulatory certification.

---

## 5. 編輯策劃理念與原文待澄清事項 (Editorial Rationale & Clarifications)

### 5.1 編輯策劃理念 (Editorial Rationale)

在重構本專案的中英文產品文案與 README 時，我們確立了以下編輯準則：

1.  **徹底降解資安行話，強化因果關係**：
    受眾包含商業管理、人文社科背景的使用者。過去資安工具充斥著「SAST/DAST」、「CVE 評分矩陣」、「態勢感知（Posture）」等抽象術語。新版文案將每一項技術行為還原為日常語言：
    *   靜態分析（SAST）＝「在不執行程式的前提下，檢查程式碼內是否存在危險的撰寫習慣」。
    *   秘密偵測（Secret Scanning）＝「檢查檔案裡是否遺留了忘記拔除的金鑰或密碼」。
    *   SBOM 盤點＝「列出專案使用了哪些第三方積木，如同食品包裝上的成分表」。
2.  **誠實呈現極限，建立長期信任**：
    如同最優秀的產品展示，真正的說服力源自「對產品能做什麼無比自信，對不能做什麼坦誠交代」：
    *   不承諾「一鍵讓系統安全無虞」。
    *   明確區分「盤點現況（如開了哪些 Port、裝了哪些套件）」與「安全漏洞（如已證實可被利用的弱點）」。
    *   堅守「零發現（No findings）絕不等於安全保證」。
3.  **操作動線絕對真實，杜絕流程誤導**：
    明確指出 CLI 與 AI Agent 僅能做「輔助、引導與匯出」，而核心動作「啟動掃描」必須由人在桌面 App 視窗中按下按鈕，確保符合產品底層架構事實。

---

### 5.2 原文待澄清聲明清單 (Source Claims to Clarify)

經比對專案技術現況與底層架構約束，原文字材料中存在數處容易使使用者產生誤解或過度期待的敘述，建議在後續官方文件修訂時正式釐清：

| 原始文案說法 | 存在的問題／易生誤解之處 | 編輯建議之精準表述 |
| :--- | :--- | :--- |
| **「透過桌面應用程式，或 Claude Code／Codex 的 Agent Skill，檢查程式碼專案...啟動一次掃描」** | 語法結構讓讀者誤以為可以在 Claude Code 或 Codex 終端機中「直接發起或排程掃描」，忽略了底層限制。 | **明確區分角色**：「掃描的啟動、暫停與繼續必須在桌面應用程式視窗內操作；Agent Skill 僅能協助環境檢查、操作指引與結果解讀，無法獨立發起掃描。」 |
| **「雲端與 Microsoft 365 檢查」**（提及 Prowler、ScoutSuite、Cloudsplaining 等工具並列） | 讀者容易將其理解為「全方位的雲端安全架構稽核」，期待能偵測執行時期異常、跨 VPC 網路攻擊等。 | **嚴格限縮範圍**：「目前對 AWS、Azure 與 GCP 的支援僅限於身分與存取管理（IAM）的特定配置檢查，絕非全盤性的雲端安全稽核。」 |
| **「開放連接埠」與「SBOM 清單」列在掃描發現中** | 一般使用者若在報告中看見開放 Port 80/443 或裝了 50 個 npm 套件，常會恐慌以為全部都是資安弱點。 | **強制概念解耦**：在 UI 與報告中設立專屬的「資產現況盤點（Inventory）」區塊，嚴格禁止將開放連接埠或套件清單標示為 Vulnerability / Issue。 |
| **自動清理歷史紀錄之模糊性** | 原文提及唯讀副本與暫存機制，可能讓使用者誤以為應用程式在關閉後會自動抹除所有歷史快照與日誌。 | **如實說明留存機制**：「本機資料夾會複製至唯讀暫存副本以供檢查，但工具目前不會保證自動清理所有過往產生的暫存與報告歷史，使用者可在需要時手動清理。」 |
| **雲端授權腳本之權限撤銷** | 原文提及雲端連線過期後可重連，未明確警告現有 setup 腳本所產生的雲端憑證具備持久性。 | **明確安全警示**：「現行輔助腳本所設定之雲端 IAM 讀取權限具有持續性，本工具不會在掃描完成後自動撤銷該存取權；若不再評估，管理者必須主動至雲端主控台移除該憑證。」 |
| **「自動修復（Auto-remediation）」的過度想像** | 部分使用者看見「建議下一步」時，常期待會有「一鍵自動修復」按鈕。 | **明確宣告產品邊界**：「ai-security-scanner 僅提供靜態診斷與人工處置建議，產品永遠不會擅自修改任何原始碼、伺服器組態或雲端政策。」 |
