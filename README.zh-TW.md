# ai-security-scanner

[專案網站](https://teddashh.github.io/ai-security-scanner/?lang=zh-TW) · [English](README.md) · [文件](docs/README.zh-TW.md) · [下載](https://github.com/teddashh/ai-security-scanner/releases)

透過桌面應用程式，或 Claude Code／Codex 的 Agent Skill，檢查程式碼專案、網站與內部系統。選定目標、確認網路檢查授權後，啟動一次掃描。偵測由既有上游掃描器負責，薄層轉接器與輸出轉換器將結果整理成一份標準化、依優先順序排列的報告。

## 開始使用

下載適合你電腦的 **v0.3.1 正式版**：

| 電腦 | 安裝檔 | 第一次開啟前 |
| --- | --- | --- |
| macOS（Apple 晶片或 Intel） | [ai-security-scanner_0.3.1_universal.dmg](https://github.com/teddashh/ai-security-scanner/releases/download/v0.3.1/ai-security-scanner_0.3.1_universal.dmg) | 把應用程式拖進**應用程式**資料夾。此版本未經 Apple 公證，開啟前先在「終端機」執行一次 `xattr -dr com.apple.quarantine /Applications/ai-security-scanner.app`。 |
| Windows x86-64 | [ai-security-scanner_0.3.1_x64-setup.exe](https://github.com/teddashh/ai-security-scanner/releases/download/v0.3.1/ai-security-scanner_0.3.1_x64-setup.exe) 或 [MSI](https://github.com/teddashh/ai-security-scanner/releases/download/v0.3.1/ai-security-scanner_0.3.1_x64_en-US.msi) | 安裝檔未簽章。SmartScreen 警告時，選**其他資訊 → 仍要執行**。Windows 要求安裝或更新 WSL 時請允許。 |
| Debian 或 Ubuntu x86-64 | [ai-security-scanner_0.3.1_amd64.deb](https://github.com/teddashh/ai-security-scanner/releases/download/v0.3.1/ai-security-scanner_0.3.1_amd64.deb) | 以 `sudo apt install ./ai-security-scanner_0.3.1_amd64.deb` 安裝。 |

第一次需要掃描時，應用程式會自行準備掃描環境，不需要另外安裝 Docker。檢查碼與此版本的驗證範圍請見 [v0.3.1 發布頁](https://github.com/teddashh/ai-security-scanner/releases/tag/v0.3.1)。

開啟應用程式並選擇一條路徑：

- **掃描公司環境**：在同一輪加入多個專案資料夾、網站與已獲准的內部系統。
- **檢查網站**：使用經過審查的 Nuclei 設定檢查一個精確網站來源範圍。
- **檢查程式碼或 AI 專案**：掃描本機唯讀副本中的秘密、弱點相依套件、危險程式碼與設定問題。

依**開始新掃描 → 確認後開始 → 掃描進度 → 掃描結果**前進。在掃描結果按**保存或分享報告**進入**分享結果**，再按**儲存「HTML 報告」**。詳見[取得 HTML 報告的逐步操作](docs/getting-started.zh-TW.md#從開始新掃描到-html-報告)，也包含如何從**我的掃描**回到原本的專案。

## 透過 Claude Code 或 Codex 使用

掃描在你自己電腦上的桌面應用程式中執行，**開始**是應用程式視窗裡的按鈕。在同一台電腦上的 Agent 可以從上方表格安裝應用程式、確認這台電腦能否掃描、引導你操作應用程式、解讀結果，並保存 HTML 報告，不需要建置本儲存庫。兩者共用同一份 Skill：

| Agent | 儲存庫內的 Skill |
| --- | --- |
| Claude Code | [ai-security-scanner](.claude/skills/ai-security-scanner/SKILL.md) |
| Codex | [ai-security-scanner](.codex/skills/ai-security-scanner/SKILL.md) |

在任一 Agent 開啟本儲存庫後，可以這樣要求：

> 使用 ai-security-scanner skill 在這台電腦安裝應用程式、確認可以掃描、引導我完成一次掃描，並保存最終 HTML 報告。

Agent 的沙箱擋住下載或應用程式時，它會請你允許那一個指令。雲端 Agent 無法在你的電腦上安裝任何東西，會改為提供安裝檔連結。範圍由你決定，產品選擇適用的上游檢查。詳見 [Agent 需要的環境](docs/getting-started.zh-TW.md#透過-agent-skill-使用)。

## 所有資產集中在一份報告

報告首先呈現：

- 已確認有問題的資產；
- 優先處理的問題及其影響；
- 最小可行的處理動作與修正驗證方式；
- 每個資產已完成及尚未執行的檢查；
- 技術細節中的原始掃描器識別碼、嚴重度、證據與修正建議。

個別檢查失敗時，其他已完成結果仍會保留。報告可重新開啟、與後續掃描比較，並匯出成好讀的 HTML 或結構化資料。

## v0.4.0 準備中的更新

- **ZAP：**對一個核准來源進行可選的被動網站檢查。
- **Agentic Radar：**選擇五種框架之一，離線盤點工作流程。
- **Garak：**54 個固定原生模型探針，需精確 HTTPS／模型確認、一次性本機金鑰，以及明確請求限制與服務商費用。
- 改善涵蓋範圍判定、精確授權的 Greenbone 復原、HTML 平板版面、M365 平台辨識，並提供可重現的引擎建置更新筆記。

詳見 [v0.4.0 準備紀錄](docs/release/v0.4.0.zh-TW.md)。新版安裝包發布驗證完成前，上方下載仍為 v0.3.1。

## v0.3.1 更新內容

- 雲端結果說明實際失敗原因；需要相同修正的 AWS 發現合併呈現，保留原始證據。
- 唯讀連線過期後，可直接重新連接再掃描。
- Semgrep 提供 1,493 條固定的舊版上游規則與四條產品規則。
- kube-bench 人工檢查與 KICS 執行失敗會標示涵蓋範圍未完成。

安裝檔實際驗證與待擁有者操作的 Microsoft 365 複驗，請見[發布紀錄](docs/release/v0.3.1.zh-TW.md)。

## 串接的工具

main 目前可執行的引擎集合整合了 25 個上游專案。準備中的 v0.4.0 新增可選的 ZAP 被動網站檢查、Agentic Radar 離線工作流程盤點，以及受限的 Garak 模型檢查；已發布的 v0.3.1 安裝包仍維持固定的 22 個工具。Garak 需要精確 HTTPS 端點與模型、新的本機金鑰，以及 54 個固定原生提示和服務商費用的明確核准。研究用候選不是目前的掃描能力。詳見[開發狀態](docs/development-status.zh-TW.md)。產品只會針對每個選定資產執行適用工具，保留原始識別碼、嚴重度、證據與修正建議，再把所有已完成結果整理到同一份報告。

**選定資產與授權 → 薄層轉接器 → 上游掃描器 → 輸出轉換器 → 一份依資產整理的標準化報告**

偵測規則沿用上游；產品的排序、去重與白話說明集中在共用報告層。

### 程式碼專案、相依套件與基礎設施即程式碼

| 工具 | ai-security-scanner 的使用方式 |
| --- | --- |
| [Semgrep](https://github.com/semgrep/semgrep) | 使用固定的 1,493 條舊版上游規則與四條產品規則，進行危險程式碼模式的靜態分析。 |
| [Gitleaks](https://github.com/gitleaks/gitleaks) | 離線偵測秘密模式；一般證據會遮蔽秘密值。 |
| [TruffleHog](https://github.com/trufflesecurity/trufflehog) | 離線檔案系統秘密偵測；停用網路驗證。 |
| [Trivy](https://github.com/aquasecurity/trivy) | 使用固定離線資料，檢查支援的專案 manifest 與單一映像 OCI layout 中的弱點套件。 |
| [Grype](https://github.com/anchore/grype) | 使用固定離線資料，檢查專案副本與單一映像 OCI layout 中的弱點套件。 |
| [Checkov](https://github.com/bridgecrewio/checkov) | 針對選定的唯讀副本執行適用的基礎設施與設定檢查。 |
| [KICS](https://github.com/Checkmarx/kics) | 使用上游 query pack 檢查基礎設施即程式碼的錯誤設定。 |
| [Syft](https://github.com/anchore/syft) | 建立軟體元件盤點與可保存的 SBOM；盤點本身不是弱點結果。 |

本版目錄將 Grype 映像固定為 **`0.117.0-4`**，digest 為 `sha256:56b0d675…`，可檢查本機專案相依套件的已知弱點；受控專案掃描曾記錄 **81 筆 Grype 問題**。這是測試專案的實測結果，各專案筆數會不同。詳見[完整釘選與實測紀錄](docs/engine-catalog.md#grype-repository-support)。

### 網站與內部系統

| 工具 | ai-security-scanner 的使用方式 |
| --- | --- |
| [Nuclei](https://github.com/projectdiscovery/nuclei) | 從固定的 [Nuclei Templates](https://github.com/projectdiscovery/nuclei-templates) 快照，執行會辨識技術、範圍受限的唯讀 HTTP 安全檢查。 |
| [ZAP](https://github.com/zaproxy/zaproxy) | 對一個核准來源爬取頁面並執行上游被動回應檢查；已在 main 接通，預計納入 v0.4.0，未包含於固定的 v0.3.1 安裝包。 |
| [Greenbone OpenVAS Scanner](https://github.com/greenbone/openvas-scanner) | 針對精確獲准的主機與連接埠，從固定 Community Feed 執行會辨識服務的遠端檢查。 |
| [Naabu](https://github.com/projectdiscovery/naabu) | 探索選定 TCP 連接埠的可達性與曝露；開放連接埠不等於弱點。 |
| [httpx](https://github.com/projectdiscovery/httpx) | 取得範圍受限的 HTTP 可達性與狀態資訊；它不是弱點掃描器。 |

### 雲端與 Microsoft 365

| 工具 | ai-security-scanner 的使用方式 |
| --- | --- |
| [Prowler](https://github.com/prowler-cloud/prowler) | 針對 AWS、Azure 與 GCP 精確資產的限縮 IAM 設定檢查。 |
| [ScoutSuite](https://github.com/nccgroup/ScoutSuite) | 限縮的 AWS IAM 評估，並非完整 ScoutSuite 涵蓋範圍。 |
| [Cloudsplaining](https://github.com/salesforce/cloudsplaining) | 分析有界 AWS IAM 證據中的過度權限。 |
| [CloudQuery](https://github.com/cloudquery/cloudquery) | 固定的 AWS IAM 盤點；回傳資料維持盤點資訊，不會轉成安全問題。 |
| [Steampipe](https://github.com/turbot/steampipe) | AWS IAM 使用者盤點；盤點欄位不會轉成安全問題。 |
| [ScubaGear](https://github.com/cisagov/ScubaGear) | 固定的 Microsoft 365 安全基準設定檢查。 |
| [Maester](https://github.com/maester365/maester) | 固定的 Microsoft 365 安全設定測試。 |

### Kubernetes

| 工具 | ai-security-scanner 的使用方式 |
| --- | --- |
| [Kubescape](https://github.com/kubescape/kubescape) | 離線檢查使用者明確選定的本機 Kubernetes manifests。 |
| [kube-bench](https://github.com/aquasecurity/kube-bench) | 檢查不可變的節點設定副本是否符合 CIS，不使用具特權的即時主機掛載。 |

### AI 工作流程與 MCP 設定

| 工具 | ai-security-scanner 的使用方式 |
| --- | --- |
| [Agentic Radar](https://github.com/splx-ai/agentic-radar) | 可選的離線工作流程盤點，支援一份已核准儲存庫快照中的 LangGraph、CrewAI、n8n、OpenAI Agents 與 AutoGen；不執行工作流程，也不連線模型。目前已在 main 上提供，將納入 v0.4.0。 |
| [Garak](https://github.com/NVIDIA/garak) | 對一個核准 HTTPS 聊天 API／模型進行可選行為檢查：54 個原生 DAN／ANSI 提示、一次性本機金鑰，以及明確推論限制與服務商費用。 |
| [MCP Armor](https://github.com/aira-security/mcp-armor) | 靜態檢查一份已核准的 MCP 設定快照中的硬編碼憑證與過度工具權限，不啟動或連線 MCP 伺服器，也不載入模型。 |

探索、盤點、SBOM 與 localhost TCP 連線工具會和弱點問題清楚分開。完整固定版本、授權、設定與執行界線記錄在[引擎目錄](docs/engine-catalog.md)。

完整掃描界線與設定行為請參閱[掃描範圍](docs/scanning-scope.zh-TW.md)。

## 資料與授權

案件、問題與證據會保留在裝置上，直到使用者連接外部來源或匯出報告。本機資料夾會複製成有界的唯讀副本；網路掃描器只會接觸確認頁面列出的目標與連接埠。

網路掃描只適用於自行擁有或已獲准評估的資產。應用程式不會自動套用修正。

## 文件

- [開始使用](docs/getting-started.zh-TW.md)
- [掃描範圍](docs/scanning-scope.zh-TW.md)
- [結果與匯出](docs/results-and-exports.zh-TW.md)
- [文件索引](docs/README.zh-TW.md)
- [目前開發狀態](docs/development-status.zh-TW.md)
- [參與開發](CONTRIBUTING.md)
- [貢獻者](CONTRIBUTORS.md)
- [安全政策](SECURITY.md)

## 開發

開發環境需要 Node.js 24 或更新版本、Rust 1.98，以及 Tauri 對應平台的相依套件。

```sh
npm ci
npm run typecheck
npm run test:frontend
npm run test:component
npm run build
cargo test --locked --workspace --no-default-features --features cli
npm run tauri dev
```

`npm run dev` 會開啟使用範例資料的瀏覽器預覽。桌面掃描由 Tauri 應用程式執行。

`npm run upstream:refresh -- --engine <id>` 會產生離線的 adapter 更新提案套件，再用 `npm run upstream:propose -- --bundle <path>` 重新驗證。預設走確定性的 `mechanical` 路徑；若要使用 AI，需明確指定 `--provider cli --ai-cli <executable>`。`--open-pr` 或 `--no-open-pr` 記錄變更是否應送回本儲存庫。這些指令只會印出供人執行的命令，本身不會執行。完整流程見[引擎維護](docs/engine-maintenance.md)。

## 授權

本專案自行撰寫的原始碼採用 [Apache-2.0](LICENSE) 授權。第三方引擎與資料保留各自的授權，詳見 [THIRD_PARTY.md](THIRD_PARTY.md)。
