# ai-security-scanner

[專案網站](https://teddashh.github.io/ai-security-scanner/?lang=zh-TW) · [English](README.md) · [使用說明](docs/README.zh-TW.md) · [下載](https://github.com/teddashh/ai-security-scanner/releases)

檢查你的程式碼、網站與公司系統，把需要注意的安全問題整理成一份報告。你會知道哪裡有問題、為什麼重要，以及接下來可以怎麼做。

在桌面應用程式裡選好要檢查的項目，程式就會選用適合的安全工具，整理檢查結果。可以先從一個資料夾或網站開始，也可以一次檢查公司環境中的多個系統。

## 完成第一次掃描

1. [下載 v0.4.0](https://github.com/teddashh/ai-security-scanner/releases/tag/v0.4.0)，依你的 Windows、macOS 或 Linux 電腦[完成安裝](docs/getting-started.zh-TW.md#安裝)。程式會準備掃描工具，不需要另外安裝 Docker。
2. 開啟程式，選擇**掃描公司環境**、**檢查網站**或**檢查程式碼或 AI 專案**，加入想檢查的資料夾、網址或內部系統。
3. 確認畫面列出的目標與檢查內容。網站及內部系統必須是你有權檢查的對象，再從應用程式視窗開始掃描。
4. 掃描結束後，打開**掃描結果**。按**保存或分享報告**，再儲存 **HTML 報告**，就能用瀏覽器閱讀。

第一次可能需要等候工具下載，之後可以重複使用。每個畫面的操作方式都在[開始使用](docs/getting-started.zh-TW.md#從開始新掃描到-html-報告)。

## 可以檢查什麼？

| 你想檢查的東西 | 可以了解的問題 |
| --- | --- |
| 程式碼資料夾，包括 AI 專案 | 支援的檔案中，是否留下密碼或金鑰、使用有已知漏洞的套件，或有危險寫法與不安全設定。程式會複製檔案來檢查，不會執行或修改你的專案。 |
| 網站與 API | 核准範圍內的網站是否有已知漏洞，或暴露了不該公開的資訊。開始前會列出檢查的網址範圍與限制。 |
| 公司內部系統 | 指定主機與連接埠提供哪些服務，以及適用的安全檢查發現了什麼。連接埠開著，本身不代表有漏洞。 |
| 雲端帳號與 Microsoft 365 | 支援的帳號與權限檢查發現了什麼。目前 AWS、Azure、GCP 只檢查部分身分與權限設定，還不能代表整個雲端環境的安全狀況。 |
| 部署設定、容器與 Kubernetes | 支援的設定檔或容器內容，是否使用有已知漏洞的套件，或有不安全設定。可執行的檢查會依提供的資料而定。 |

進階 AI 選項可以整理支援的工作流程、檢查 MCP 設定，或測試一個你核准的模型服務。模型測試會送出 54 個固定提示，可能產生服務商費用；開始前會讓你確認。詳細內容見[掃描範圍](docs/scanning-scope.zh-TW.md)。

## 看完報告，知道下一步

先看需要優先處理的問題。每一項都會說明影響哪個系統或檔案、為什麼值得注意，以及可以先做什麼。負責調查或修正的人，也能展開技術細節，查看掃描工具原本的證據、評級與建議。

報告同時列出已檢查與未檢查的項目。某項檢查失敗，其他結果仍會保留。「沒有發現問題」只代表完成的檢查沒有找到問題，不代表所有風險都已排除。程式會提供修正建議，不會自行更改你的系統。

報告可以重新開啟、比較相容的前後兩次掃描，也能存成英文或繁體中文 HTML 分享。未遮蔽的匯出可在報告最後附上原始掃描報告 ZIP。詳見[閱讀與分享結果](docs/results-and-exports.zh-TW.md)。

### 先看看報告長什麼樣

[打開範例報告](https://teddashh.github.io/ai-security-scanner/samples/v0.4.0/sample-report-redacted-zh-TW.html)，或[選擇其他語言與顯示方式](https://teddashh.github.io/ai-security-scanner/sample-reports.html?lang=zh-TW)。

範例使用模擬資料，包含 25 個工具的 62 筆發現與 42 筆盤點紀錄。它用來展示報告，不代表任何真實公司的安全狀況。盤點紀錄會另外列出，不算成安全問題。[範例製作方式](docs/samples/v0.4.0/README.zh-TW.md)。

## 請 Claude Code 或 Codex 幫忙

在同一台電腦上的 AI 助手，可以協助安裝、確認設定、解讀結果與儲存報告。你負責選好目標，並在桌面應用程式裡開始、暫停或繼續掃描。

在 AI 助手中開啟這個專案，告訴它：

> 使用 ai-security-scanner skill，幫我安裝程式、引導我完成第一次掃描，並存下最後的 HTML 報告。

這裡有 [Claude Code 指引](.claude/skills/ai-security-scanner/SKILL.md)與 [Codex 指引](.codex/skills/ai-security-scanner/SKILL.md)。如果助手在另一台機器上，它可以提供操作說明與下載連結，無法直接替你的電腦安裝。[查看使用方式](docs/getting-started.zh-TW.md#透過-agent-skill-使用)。

## 資料放在哪裡？權限會留下嗎？

專案、檢查結果與證據存放在你的電腦。本機程式碼檢查不會上傳或執行專案；網站與雲端檢查會連到你核准的服務。儲存 HTML 報告只會建立本機檔案，是否分享由你決定。

雲端登入與雲端權限是兩件事。登入可能已經過期，但設定時建立的權限仍然存在。Microsoft 365 有可選用的[清理 script](cloud-setup/README.md)：等指定掃描結束、存下報告，再撤除紀錄中的設定變更。AWS 也新增了[掃描專用存取與清理](cloud-setup/README.md#aws-專用存取與清理)。執行時須保持清理視窗開啟；管理員登入過期時可能需要重新登入。這些還不是桌面程式的預設動作，也不會一併撤除缺少建立紀錄的舊 AWS 或 Azure 權限。

## 報告背後有哪些工具？

程式整合了 25 個開源工具。各工具負責原本的安全檢查，程式再整理結果、說明處理順序。想了解用途、限制與版本，可以閱讀[工具指南](https://teddashh.github.io/ai-security-scanner/scanner-guide.html?lang=zh-TW)。

<details>
<summary>展開各工具的技術資料</summary>

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
| [ZAP](https://github.com/zaproxy/zaproxy) | 對一個核准來源爬取頁面並執行上游被動回應檢查。 |
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
| [Agentic Radar](https://github.com/splx-ai/agentic-radar) | 可選的離線工作流程盤點，支援一份已核准儲存庫快照中的 LangGraph、CrewAI、n8n、OpenAI Agents 與 AutoGen；不執行工作流程，也不連線模型。 |
| [Garak](https://github.com/NVIDIA/garak) | 對一個核准 HTTPS 聊天 API／模型進行可選行為檢查：54 個原生 DAN／ANSI 提示、一次性本機金鑰，以及明確推論限制與服務商費用。 |
| [MCP Armor](https://github.com/aira-security/mcp-armor) | 靜態檢查一份已核准的 MCP 設定快照中的硬編碼憑證與過度工具權限，不啟動或連線 MCP 伺服器，也不載入模型。 |

探索、盤點、SBOM 與 localhost TCP 連線工具會和弱點問題清楚分開。完整固定版本、授權、設定與執行界線記錄在[引擎目錄](docs/engine-catalog.md)。

完整掃描界線與設定行為請參閱[掃描範圍](docs/scanning-scope.zh-TW.md)。

仍在評估中的工具另行記錄，還不能用來掃描。


</details>

## 更多說明

- [開始使用](docs/getting-started.zh-TW.md)
- [掃描範圍](docs/scanning-scope.zh-TW.md)
- [閱讀與分享結果](docs/results-and-exports.zh-TW.md)
- [目前開發狀態](docs/development-status.zh-TW.md)
- [v0.4.0 更新](docs/release/v0.4.0.zh-TW.md) · [v0.3.1 更新](docs/release/v0.3.1.md)
- [參與開發](CONTRIBUTING.md) · [貢獻者](CONTRIBUTORS.md) · [安全政策](SECURITY.md)

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
