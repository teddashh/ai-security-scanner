# Codex 文案版本

以下是本次套用在工作目錄的版本。README 保留完整文字；網站依區塊列出中英對照，導覽和重複按鈕不再逐一重印。

## 繁體中文 README

```markdown
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

報告可以重新開啟、比較相容的前後兩次掃描，也能存成 HTML 分享。詳見[閱讀與分享結果](docs/results-and-exports.zh-TW.md)。

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

雲端登入與雲端權限是兩件事。登入可能已經過期，但設定時建立的權限仍然存在。目前的設定 script 不會在掃描後自動移除那些權限。

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
```

## English README

```markdown
# ai-security-scanner

[Project website](https://teddashh.github.io/ai-security-scanner/) · [繁體中文](README.zh-TW.md) · [Documentation](docs/README.md) · [Downloads](https://github.com/teddashh/ai-security-scanner/releases)

Find security problems in your code, websites and company systems. Get one report that explains what needs attention, why it matters and what to do next.

Choose what to check in the desktop app. It selects suitable security tools and brings their results together. You can start with one folder or website, or check several parts of your IT environment at once.

## Run your first scan

1. [Download v0.4.0](https://github.com/teddashh/ai-security-scanner/releases/tag/v0.4.0) for Windows, macOS or Linux and [follow the install steps](docs/getting-started.md#install). The app prepares its scanning tools; you do not need to install Docker.
2. Open the app and choose **Scan my environment**, **Check a website**, or **Check code or an AI project**. Add the folders, URLs or internal systems you want to check.
3. Review the listed targets and checks. Confirm that you may scan any network targets, then start the scan in the app window.
4. When the scan ends, open **Results**. Choose **Save or share report**, then **Save HTML report** to save a report you can open in a browser.

The first scan may take longer while tools download. Later scans can use those tools again. The [walkthrough](docs/getting-started.md#from-new-scan-to-an-html-report) shows each screen.

## What can it check?

| What you choose | What you learn |
| --- | --- |
| Project folders, including AI projects | Whether supported files contain exposed passwords or keys, risky code, vulnerable software packages or unsafe settings. Your project is copied for inspection, not run or changed. |
| Websites and APIs | Whether the approved website has known vulnerabilities or exposed information. Checks stay within the address and limits shown before you start. |
| Internal systems | Which services are available on the approved hosts and ports, and which security problems the applicable checks find. An open port alone is not a vulnerability. |
| Cloud accounts and Microsoft 365 | What the supported account and access checks find. AWS, Azure and GCP currently cover selected identity and permission settings; they do not provide a complete cloud audit. |
| Deployment files, containers and Kubernetes | Whether supported files or container contents have known package vulnerabilities or unsafe settings. Available checks depend on the input you provide. |

Optional AI checks can map supported workflows, inspect MCP configuration, or test one approved model endpoint. The model test sends 54 fixed prompts and may incur provider charges; you review those limits before starting. See [what each scan covers](docs/scanning-scope.md).

## A report you can act on

Start with the problems that need attention first. Each includes the affected system or file, why the problem matters and a practical next step. Technical details retain the scanner's original evidence, rating and recommendation for whoever will investigate or make the fix.

The report also tells you what was checked and what was not. If one check fails, completed results remain available. “No problems found” applies to the completed checks, not every possible risk. The app suggests fixes; it does not make them for you.

You can reopen reports, compare compatible scans and share an HTML copy. See [how to read and share results](docs/results-and-exports.md).

### See an example

[Open the example report](https://teddashh.github.io/ai-security-scanner/samples/v0.4.0/sample-report-redacted-en.html), or [choose another language or disclosure level](https://teddashh.github.io/ai-security-scanner/sample-reports.html).

These examples use simulated data: 62 findings and 42 inventory observations across all 25 tools. They show the report format, not the security of a real company. Inventory is listed separately from security problems. [How the examples were made](docs/samples/v0.4.0/README.md).

## Get help from Claude Code or Codex

An assistant running on your computer can help install the app, check setup, explain findings and save the report. You select the targets and start, pause or resume scans in the desktop app.

Open this repository in your assistant and ask:

> Use the ai-security-scanner skill to install the app, guide me through my first scan and save the final HTML report.

Use the [Claude Code skill](.claude/skills/ai-security-scanner/SKILL.md) or the [Codex skill](.codex/skills/ai-security-scanner/SKILL.md). An assistant running elsewhere can provide instructions and download links. It cannot install the app on your computer. [Assistant setup](docs/getting-started.md#use-with-an-agent-skill).

## Your data and access

Projects, findings and evidence are stored on your computer. Local code checks do not upload or execute your project. Website and cloud checks contact the services you approve. Saving an HTML report creates a local file; you decide whether to share it.

Cloud sign-in and cloud permissions are separate. A login can expire while the permissions created during setup remain. The current setup scripts do not automatically remove those permissions after a scan.

## The tools behind the report

The app brings together 25 open-source tools. Each keeps its own detection rules; the app organizes their results and explains what to do next. [Read the tool guide](https://teddashh.github.io/ai-security-scanner/scanner-guide.html) for uses, limits and versions.

<details>
<summary>Tool-by-tool technical reference</summary>

### Repositories, dependencies, and infrastructure as code

| Tool | What ai-security-scanner uses it for |
| --- | --- |
| [Semgrep](https://github.com/semgrep/semgrep) | Static analysis for risky code patterns using 1,493 pinned legacy upstream rules plus four product rules. |
| [Gitleaks](https://github.com/gitleaks/gitleaks) | Offline secret-pattern scanning with secret values redacted from normal evidence. |
| [TruffleHog](https://github.com/trufflesecurity/trufflehog) | Offline filesystem secret detection; network verification is disabled. |
| [Trivy](https://github.com/aquasecurity/trivy) | Vulnerable packages in recognized repository manifests and single-image OCI layouts using pinned offline data. |
| [Grype](https://github.com/anchore/grype) | Vulnerable packages in repository snapshots and single-image OCI layouts using pinned offline data. |
| [Checkov](https://github.com/bridgecrewio/checkov) | Applicable infrastructure and configuration checks across the selected read-only snapshot. |
| [KICS](https://github.com/Checkmarx/kics) | Infrastructure-as-code misconfiguration checks from the upstream query pack. |
| [Syft](https://github.com/anchore/syft) | Software component inventory and preserved SBOM output; inventory is not a vulnerability result. |

The released catalog pins the Grype image to **`0.117.0-4`**, digest `sha256:56b0d675…`. It can scan local repository dependencies for known vulnerabilities; a controlled repository scan recorded **81 Grype findings**. That is a fixture result, not an expected count for every project. See the [exact pin and recorded result](docs/engine-catalog.md#grype-repository-support).

### Websites and internal systems

| Tool | What ai-security-scanner uses it for |
| --- | --- |
| [Nuclei](https://github.com/projectdiscovery/nuclei) | Technology-aware, bounded read-only HTTP security checks from a pinned [Nuclei Templates](https://github.com/projectdiscovery/nuclei-templates) snapshot. |
| [ZAP](https://github.com/zaproxy/zaproxy) | Optional page-crawling and upstream passive response checks for one approved origin. |
| [Greenbone OpenVAS Scanner](https://github.com/greenbone/openvas-scanner) | Service-aware remote checks from a pinned Community Feed for exact approved hosts and ports. |
| [Naabu](https://github.com/projectdiscovery/naabu) | Selected TCP-port reachability and exposure discovery; an open port is not a vulnerability finding. |
| [httpx](https://github.com/projectdiscovery/httpx) | Bounded HTTP reachability and status metadata; it is not a vulnerability scanner. |

### Cloud and Microsoft 365

| Tool | What ai-security-scanner uses it for |
| --- | --- |
| [Prowler](https://github.com/prowler-cloud/prowler) | Narrow, exact-asset IAM configuration profiles for AWS, Azure, and GCP. |
| [ScoutSuite](https://github.com/nccgroup/ScoutSuite) | A reduced AWS IAM assessment rather than full ScoutSuite coverage. |
| [Cloudsplaining](https://github.com/salesforce/cloudsplaining) | Excessive-permission analysis over bounded AWS IAM evidence. |
| [CloudQuery](https://github.com/cloudquery/cloudquery) | A fixed AWS IAM inventory; returned rows remain inventory rather than security findings. |
| [Steampipe](https://github.com/turbot/steampipe) | AWS IAM user inventory; inventory fields do not become findings. |
| [ScubaGear](https://github.com/cisagov/ScubaGear) | A fixed Microsoft 365 security-baseline configuration profile. |
| [Maester](https://github.com/maester365/maester) | A fixed Microsoft 365 security-configuration test profile. |

### Kubernetes

| Tool | What ai-security-scanner uses it for |
| --- | --- |
| [Kubescape](https://github.com/kubescape/kubescape) | Offline configuration checks over explicitly selected local Kubernetes manifests. |
| [kube-bench](https://github.com/aquasecurity/kube-bench) | CIS checks over an immutable node-configuration snapshot, without a privileged live-host mount. |

### AI workflows and MCP configuration

| Tool | What ai-security-scanner uses it for |
| --- | --- |
| [Agentic Radar](https://github.com/splx-ai/agentic-radar) | Optional offline workflow inventory for LangGraph, CrewAI, n8n, OpenAI Agents, and AutoGen in one approved repository snapshot. It does not execute the workflow or contact a model. |
| [Garak](https://github.com/NVIDIA/garak) | Optional model behavior checks against one approved HTTPS chat API/model with 54 native DAN/ANSI prompts, one-shot local keys and explicit inference limits/provider charges. |
| [MCP Armor](https://github.com/aira-security/mcp-armor) | Static checks over one approved MCP configuration snapshot for hardcoded credentials and excessive tool permissions, without starting or contacting an MCP server or loading a model. |

Discovery, inventory, SBOM generation, and the localhost TCP utility remain clearly separated from vulnerability findings. The complete pinned versions, licenses, profiles, and execution boundaries are recorded in the [engine catalog](docs/engine-catalog.md).

Exact scan boundaries and profile behavior are documented in [Scanning scope](docs/scanning-scope.md).


</details>

## More information

- [Getting started](docs/getting-started.md)
- [Scan coverage](docs/scanning-scope.md)
- [Reading and sharing results](docs/results-and-exports.md)
- [Current development status](docs/development-status.md)
- [Changes in v0.4.0](docs/release/v0.4.0.md) · [Earlier changes in v0.3.1](docs/release/v0.3.1.md)
- [Contributing](CONTRIBUTING.md) · [Contributors](CONTRIBUTORS.md) · [Security policy](SECURITY.md)

## Development

Development requires Node.js 24 or newer, Rust 1.98, and the platform dependencies required by Tauri.

```sh
npm ci
npm run typecheck
npm run test:frontend
npm run test:component
npm run build
cargo test --locked --workspace --no-default-features --features cli
npm run tauri dev
```

`npm run dev` opens a browser preview with sample data. Desktop scanning runs through the Tauri application.

`npm run upstream:refresh -- --engine <id>` produces an offline adapter refresh proposal bundle, and `npm run upstream:propose -- --bundle <path>` re-validates it. `mechanical` is the default deterministic path; the optional AI path is selected explicitly with `--provider cli --ai-cli <executable>`. `--open-pr` or `--no-open-pr` records whether the change should be sent back to this repository. These commands print commands for a human to run and never execute them. The full procedure is in [Engine maintenance](docs/engine-maintenance.md).

## License

Project-owned source is licensed under [Apache-2.0](LICENSE). Third-party engines and data retain their own licenses; see [THIRD_PARTY.md](THIRD_PARTY.md).
```

## 網站主要文字

找出問題，知道怎麼做。

Find risks. Act on them.

在一個桌面程式裡，檢查你的程式碼、網站與公司系統。看一份報告，了解哪裡需要注意、為什麼重要，以及接下來可以怎麼做。

Check your code, websites and company systems from one desktop app. Get one report that explains what needs attention, why it matters and what you can do next.

由你決定檢查範圍 網路檢查只會連到你核准的目標與連接埠。

You choose what to check Network checks contact only the targets and ports you approve.

保留專案原貌 程式會複製本機專案來檢查，不會改動檔案或自行套用修正。

Your project stays as it is The app checks a copy of your local project. It does not change your files or apply fixes.

每個問題都有依據可查 展開細節，就能查看原始檢查結果、嚴重程度與修正建議。

The evidence is there Open the details to see the original finding, its rating and the recommended fix.

從第一次掃描，到知道怎麼處理。 可以先檢查一個資料夾或網站，也可以把多個公司系統放在同一次掃描。程式會選用適合的檢查。

From your first scan to your next step. Start with one folder or website, or bring several company systems into the same scan. The app selects the checks that fit.

選好要檢查的東西 加入專案資料夾、網站網址或內部系統。確認清單，並確認你有權對這些網路目標進行檢查。

Choose what to check Add project folders, website addresses or internal systems. Review the list and confirm that you may scan the network targets.

在程式裡開始掃描 程式會執行適合的安全工具，讓你看到目前進度。需要時，可以從視窗暫停或停止掃描。

Start the scan in the app The app runs suitable security tools and shows their progress. You can pause or stop from the app window.

先看最需要處理的問題 掃描結束後，報告會說明發現的問題、可能的影響與下一步，也會列出未完成的檢查。某項檢查失敗，其他結果仍然保留。

See what to do first When the scan ends, the report explains the problems, their impact and the next steps. It also lists unfinished checks. A failed check does not erase other results.

讓 AI 助手陪你完成第一次掃描。 同一台電腦上的 Claude Code 或 Codex，可以協助安裝、確認設定、解讀結果與儲存報告。你選好目標，再從桌面程式開始掃描。

An AI assistant can help you get started. Claude Code or Codex on your computer can help install the app, check setup, explain the results and save your report. You choose the targets and start the scan in the desktop app.

### 各工具用途

| 工具 | 繁體中文 | English |
| --- | --- | --- |
| Semgrep | 依照本版提供的規則，找出程式碼中可能不安全的寫法。 | Finds risky patterns in code, using the rule set included with this version. |
| Gitleaks | 找出專案檔案裡可能留下的密碼與金鑰，報告會隱藏它們的內容。 | Looks for passwords and keys left in project files. Values are hidden in the report. |
| TruffleHog | 在本機檔案裡找出可能外洩的密碼與金鑰，不會拿它們登入服務。 | Looks for exposed secrets in local files. It does not try the credentials against a live service. |
| Trivy | 用內附的漏洞資料庫，檢查支援的專案與容器套件。 | Checks supported project and container packages against the included vulnerability database. |
| Grype | 使用內附資料庫，找出支援的專案與容器套件是否有已知漏洞。 | Finds known vulnerabilities in supported project and container packages using the included database. |
| Checkov | 檢查支援的部署與基礎設施設定檔，找出不安全的設定。 | Checks supported deployment and infrastructure files for unsafe settings. |
| KICS | 檢查用來部署系統的設定檔，找出可能造成風險的設定。 | Looks for unsafe settings in files that describe how your systems are deployed. |
| Syft | 列出專案或容器裡的軟體元件，幫你掌握用了哪些東西；清單本身不是漏洞報告。 | Lists the software components in your project or container. The list helps you track what is installed. |
| Nuclei | 先辨識網站使用的技術，再於核准的網址與限制內執行適用的唯讀檢查。 | Identifies website technologies, then runs suitable read-only checks within the approved address and limits. |
| ZAP | 瀏覽一個核准網站的頁面並檢查回應，不會送出表單或攻擊內容。 | Visits pages on one approved website and checks the responses. It does not submit forms or send attack payloads. |
| Greenbone OpenVAS | 辨識核准主機與連接埠上的服務，再執行適合的安全檢查。 | Identifies services on approved hosts and ports, then runs the security checks that apply. |
| Naabu | 查看核准的連接埠是否接受連線。連接埠開著值得了解，但不代表有漏洞。 | Shows which approved ports accept connections. An open port is information to investigate, not proof of a vulnerability. |
| httpx | 確認選定的網站服務是否回應，並記錄基本資訊；這不是漏洞檢查。 | Checks whether a selected web service responds and records basic response information. It does not assess vulnerabilities. |
| Prowler | 檢查核准的 AWS 帳號、Azure 訂用帳戶或 GCP 專案中的部分身分與權限設定。 | Checks selected identity and permission settings in an approved AWS account, Azure subscription or GCP project. |
| ScoutSuite | 檢查部分 AWS 身分與存取設定。本程式使用的是 ScoutSuite 的部分功能。 | Checks selected AWS identity and access settings. This app uses a limited part of ScoutSuite. |
| Cloudsplaining | 分析收集到的 AWS 權限政策，找出可能給得太多的權限。 | Reviews collected AWS permission policies for access that may be broader than needed. |
| CloudQuery | 整理部分 AWS 身分與權限政策，作為盤點資料，和安全問題分開列出。 | Lists selected AWS identities and permission policies. This inventory is kept separate from security findings. |
| Steampipe | 列出 AWS 使用者與部分帳號設定，方便了解哪些人可以存取。 | Lists AWS users and selected account settings so you can review who has access. |
| ScubaGear | 依照美國 CISA 的安全建議，檢查支援的 Microsoft 365 設定。 | Compares supported Microsoft 365 settings with CISA security guidance. |
| Maester | 檢查支援的 Microsoft 365 安全設定，列出需要注意的項目。 | Tests supported Microsoft 365 security settings and explains which checks need attention. |
| Kubescape | 檢查你選好的 Kubernetes 設定檔，不會連到正在運作的叢集。 | Checks the Kubernetes configuration files you select, without connecting to a running cluster. |
| kube-bench | 依照 CIS 建議檢查節點設定的副本，不會取得管理員權限來檢查運作中的主機。 | Checks a saved copy of node settings against CIS guidance. It does not inspect a live host with administrator access. |
| Agentic Radar | 離線盤點保存專案中的 Agent、工具與工作流程連接。 | Offline inventory of agents, tools, and workflow connections in a saved project. |
| Garak | 對一個核准 HTTPS 聊天 API 與模型送出 54 個原生 DAN／ANSI 提示。明確列出推論限制與服務商費用，使用一次性本機金鑰；失敗次數保留上游判定。 | 54 native DAN/ANSI prompts for one approved HTTPS chat API and model. Explicit inference limits, provider charges and a one-shot local key; detector failure counts remain upstream-owned. |
| MCP Armor | 檢查選定的 MCP 設定是否留下金鑰，或給了工具過大的權限；不會啟動或連線 MCP 伺服器。 | Checks a selected MCP configuration for exposed keys and overly broad tool permissions. It does not start or contact MCP servers. |


## 報告說明 繁體中文

# 閱讀與分享檢查結果

[English](results-and-exports.md) · [使用說明](README.zh-TW.md)

掃描結束或停止後，打開**掃描結果**。先看摘要：哪些系統或檔案需要注意、哪個問題該先處理，以及下一步可以怎麼做。掃描還在進行時，請在**掃描進度**查看。

## 看懂每一種結果

| 報告顯示的結果 | 代表什麼 |
| --- | --- |
| 發現問題 | 安全檢查找到至少一個影響這個項目的問題。打開後可以查看證據與建議做法。 |
| 已完成的檢查沒有發現問題 | 完成的檢查在本次範圍內沒有找到問題，不代表所有風險都已排除。 |
| 未完成或失敗 | 有些檢查沒有完成，其他已完成的結果仍然保留。 |
| 未測試 | 這個項目還沒有完成任何適用的安全檢查。 |

報告也可能列出服務、開放的連接埠或已安裝的軟體，幫你了解系統現況。這些是盤點資料，不會算成漏洞。

## 決定先處理什麼

先看排在前面的重要問題。每一項都會說明影響對象、為什麼值得注意，以及可以先做什麼。有適用資訊時，也會提供確認修正是否有效、或還原變更的方法。

要交給其他人調查時，可以展開技術細節。裡面保留原始掃描工具、規則編號、證據、嚴重程度與修正建議。「未知」表示工具沒有提供嚴重程度評級，不代表問題不重要。

程式會提供建議，不會自行修改你的系統。

## 確認還有哪些沒查到

查看**實際測試的內容**與**未測試的內容**。即使部分工作沒完成，報告裡的其他發現仍然有用。連線成功，或列出了系統清單，都不等於做過安全檢查。

尚未完成的檢查，請依照程式顯示的下一步處理。有些項目需要重新登入，或補齊資料，才能繼續。

## 之後回來看，也能比較前後結果

從**我的掃描**開啟專案，就能找到原本的目標、問題、證據與報告紀錄。閱讀或匯出前，先選好要看的那一次掃描。

兩次掃描可以比較時，程式會列出新增、仍存在與已解決的問題。無法比較的項目會另外標示，避免把「這次沒查到」誤認成「已經修好了」。

## 存一份報告分享

在**掃描結果**按**保存或分享報告**，選擇 **HTML 報告（建議）**。除非收件人需要辨識系統名稱等資訊，否則保留遮蔽敏感資訊的設定。儲存後，用瀏覽器開啟檢查，再決定是否分享。

報告會使用程式目前的語言，支援英文與繁體中文，閱讀順序也和畫面相同。技術證據可以展開查看，正式條款放在最後。儲存報告只會建立本機檔案，不會替你寄送給任何人。

<details>
<summary>提供給技術團隊的其他格式</summary>

- JSON：保留程式使用的結構化報告資料。
- OCSF：把檢查發現整理成通用的安全資料格式。
- OSCAL 與框架報告：有適用對照時，附上經過檢視的控制項參考。
- 案件資料包：依匯出選項，包含指定的專案資料與證據。

各種格式都來自同一次已結束或停止的掃描。SHA-256 校驗值可用來辨識匯出的檔案。命令列匯出的 HTML 預設使用英文；加上 `--locale zh-Hant` 即為繁體中文，檢查事實不會改變。

</details>


## Report guide English

# Read and share your results

[繁體中文](results-and-exports.zh-TW.md) · [Documentation](README.md)

When a scan finishes or stops, open **Results**. Start with the summary: which systems or files need attention, what matters first and what to do next. While a scan is running, follow it in **Scan progress**.

## Understand each result

| What the report says | What it means |
| --- | --- |
| Problems found | A security check found at least one issue affecting this item. Open it to see the evidence and suggested next step. |
| No problems in completed checks | The checks that finished found no problems within their stated scope. This does not rule out every possible risk. |
| Incomplete or failed | Some requested checks did not finish. Results from completed checks are still available. |
| Not tested | No applicable security check finished for this item. |

The report may also list services, open ports or installed software. These help describe what you have; they are not counted as vulnerabilities.

## Decide what to do first

Read the highest-priority problems first. For each one, the report explains what is affected, why it matters and a practical next step. When available, it also explains how to verify a fix or undo a change.

If someone else will investigate, expand the technical details. They contain the original scanner, rule number, evidence, severity rating and recommendation. “Unknown” means the tool did not provide a severity rating; it does not mean the problem is minor.

The app provides guidance. It does not apply fixes to your systems.

## Check what is still missing

Look at **What was actually tested** and **What was not tested**. A report can contain useful findings even when some work is unfinished. A successful connection or a list of systems does not mean a security check ran.

For unfinished checks, follow the next step shown in the app. Some need a new sign-in or different input before they can run.

## Return later and compare

Open **My scans** to return to a project. Its targets, findings, evidence and report history stay available. Select the scan you want before reading or exporting the report.

When two scans can be compared, the app shows which problems are new, still present or resolved. It marks results that cannot be compared, so missing coverage is not mistaken for a fix.

## Save a report to share

From **Results**, choose **Save or share report**, then **HTML report (recommended)**. Keep sensitive identifiers hidden unless the recipient needs them. Save the file and open it in a browser to check it before sharing.

The report uses the app language, English or Traditional Chinese. It follows the same order as the screen. Technical evidence is available in expandable sections, with formal terms at the end. Saving the report creates a local file; it does not send it to anyone.

<details>
<summary>Formats for technical teams</summary>

- JSON keeps the product's structured report data.
- OCSF provides findings in a common security-data format.
- OSCAL and framework reports include reviewed control references where a mapping exists.
- A case bundle contains the selected project data and evidence allowed by its export options.

All formats use the same finished or stopped scan. SHA-256 hashes identify the exported files. CLI HTML exports use English by default; choose `--locale zh-Hant` for Traditional Chinese. The scan facts remain the same.

</details>


## 報告摘要與狀態

| 情況 | 繁體中文 | English |
| --- | --- | --- |
| 部分未完成 | 部分檢查未完成 | Some checks are incomplete |
| 完成但沒有發現 | 已完成的檢查沒有發現問題。 | The checks that completed reported no problems. |
| 只有部分有結果 | 目前完成的部分沒有發現問題，其餘仍未完成。 | The partly completed checks reported no problems. |
| 還需要處理的檢查 | 未完成的檢查與待判讀結果 | Unfinished checks and results to review |
| 需要優先查看 | 發現 {總數} 個問題，其中 {數量} 個被評為「嚴重」或「高」等級，請先查看這些項目。 | {Total} problems were found, {count} of them Critical or High severity. |

括號欄位由真實結果填入，這裡沒有杜撰掃描結果。原始偵測規則、證據、評級與修正建議沒有改寫。
