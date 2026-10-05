# ai-security-scanner 編輯提案：README、網站文案與報告用語

**Editorial proposal: README, website copy and report wording**

提案範圍：重寫面向一般讀者的文字。內容依據你提供的原始 README（中英）、網站文字與事實限制。版本、安裝檔、套件格式和下載連結維持原樣。文中沒有任何掃描結果。報告範例只呈現版面，或連到原本就標明為「模擬資料」的範例報告。

> 複製時請注意：本提案的標題都降了一級，貼回 README 時把 `##` 改回 `#`，以此類推。`{大括號}` 是要由程式填入的欄位。

---

# 1. README（繁體中文）

## ai-security-scanner

[專案網站](https://teddashh.github.io/ai-security-scanner/?lang=zh-TW) · [English](README.md) · [文件](docs/README.zh-TW.md) · [下載](https://github.com/teddashh/ai-security-scanner/releases)

ai-security-scanner 是一個在你自己電腦上使用的桌面應用程式。你先選好要檢查什麼，可以是公司內部系統、一個網站，或電腦裡的一個專案資料夾。接著它會挑出適用的開源安全工具來檢查，最後整理成一份報告：

- 哪裡有問題
- 為什麼值得處理
- 下一步可以怎麼做
- 這次有哪些項目沒有檢查到

它不會幫你修改任何東西。「這次沒發現問題」也不代表「一定安全」。

### 第一次掃描

**1. 下載並安裝 v0.4.0 正式版**

| 電腦 | 安裝檔 | 第一次開啟前 |
| --- | --- | --- |
| macOS（Apple 晶片或 Intel） | [ai-security-scanner_0.4.0_universal.dmg](https://github.com/teddashh/ai-security-scanner/releases/download/v0.4.0/ai-security-scanner_0.4.0_universal.dmg) | 把應用程式拖進「應用程式」資料夾。此版本未經 Apple 公證，第一次開啟前請在「終端機」執行一次 `xattr -dr com.apple.quarantine /Applications/ai-security-scanner.app`。 |
| Windows x86-64 | [ai-security-scanner_0.4.0_x64-setup.exe](https://github.com/teddashh/ai-security-scanner/releases/download/v0.4.0/ai-security-scanner_0.4.0_x64-setup.exe) 或 [MSI](https://github.com/teddashh/ai-security-scanner/releases/download/v0.4.0/ai-security-scanner_0.4.0_x64_en-US.msi) | 安裝檔未簽章。SmartScreen 跳出警告時，選**其他資訊 → 仍要執行**。Windows 要求安裝或更新 WSL 時請允許。 |
| Debian 或 Ubuntu x86-64 | [ai-security-scanner_0.4.0_amd64.deb](https://github.com/teddashh/ai-security-scanner/releases/download/v0.4.0/ai-security-scanner_0.4.0_amd64.deb) | 執行 `sudo apt install ./ai-security-scanner_0.4.0_amd64.deb` 安裝。 |

第一次掃描時，應用程式會自己準備掃描環境，不需要另外安裝 Docker。檢查碼和本版的驗證範圍請見 [v0.4.0 發布頁](https://github.com/teddashh/ai-security-scanner/releases/tag/v0.4.0)。

**2. 選一條路徑**

- **掃描公司環境**：把多個專案資料夾、網站和已獲准的內部系統放進同一輪檢查。
- **檢查網站**：檢查一個網站，例如 `https://www.example.com`，範圍不會超出這個網站。
- **檢查程式碼或 AI 專案**：檢查電腦裡的一個專案資料夾。

**3. 確認範圍，然後開始**

操作順序是**開始新掃描 → 確認後開始 → 掃描進度 → 掃描結果**。

確認頁會列出這次會連到的每個目標和連接埠。連接埠就是一台主機對外提供服務的入口。只有你在應用程式裡按下**開始**，掃描才會啟動。掃描途中可以暫停，之後再繼續。

**4. 保存報告**

在**掃描結果**按**保存或分享報告**，進入**分享結果**，再按**儲存「HTML 報告」**。之後可以從**我的掃描**重新開啟這次的結果。詳見[取得 HTML 報告的逐步操作](docs/getting-started.zh-TW.md#從開始新掃描到-html-報告)。

### 可以檢查什麼

| 你選的 | 它會看 | 範圍界線 |
| --- | --- | --- |
| 公司 IT 環境 | 你核准的內部主機與連接埠上有哪些服務在運作，以及這些服務的已知漏洞和設定問題 | 只連到確認頁列出的主機與連接埠 |
| 網站 | 網站的安全設定與已知問題。進階選項可以多加一項頁面檢查：只讀取頁面回應，不送出表單 | 只送出讀取用的請求，不登入，不送攻擊內容 |
| 本機專案 | 寫在檔案裡的密碼和金鑰、有已知漏洞的第三方套件、有風險的程式寫法、不安全的設定。AI 專案還會檢查工作流程與 MCP 設定 | 先複製成唯讀副本再檢查，不執行專案，也不上傳專案 |

**進階選項（需要時再開啟）**

- **雲端（AWS、Azure、GCP）**：目前只檢查身分與存取權限的設定，例如某個帳號的權限是否過大。**這不是完整的雲端安全稽核。**
- **Microsoft 365**：檢查一組固定的安全基準設定。
- **Kubernetes**：檢查你選定的設定檔，以及節點設定的副本。
- **AI 模型行為**：對你指定的一個 HTTPS 聊天 API 送出 54 個固定提示。這會用到你的服務商額度，可能產生費用，送出前需要你明確同意。

> **盤點不是漏洞。** 有些工具只負責列出「有什麼」，例如軟體元件清單、雲端帳號清單、哪些連接埠是開的。報告會把這些列為「觀察」，不算成問題。開著的連接埠本身不是漏洞。

### 怎麼讀報告

一次掃描只產生一份報告，依你選的資產分組。每個資產會標示四種狀態之一：

- **發現問題**
- **已完成的檢查未發現問題**
- **未完成**：有檢查開始了，但沒有跑完
- **未測試**：這次沒有執行的檢查

每個問題依序說明三件事：先處理什麼、為什麼重要、建議的下一步，以及修好之後怎麼確認。原始工具名稱、規則編號、嚴重度和證據都收在「技術細節」裡，需要時再展開。

某一項檢查失敗時，其他已完成的結果仍會保留。報告可以重新開啟、和之後的掃描比較，也能匯出成 HTML 或結構化資料。

> **「未發現問題」只代表已完成的檢查沒有回報問題。** 它不能保證資產安全，也不涵蓋未完成或未測試的項目。

想先看看報告長什麼樣子？以下範例使用**模擬資料**，透過正式報告流程產生：

- [遮蔽版 HTML](https://teddashh.github.io/ai-security-scanner/samples/v0.4.0/sample-report-redacted-zh-TW.html) · [完整揭露版 HTML](https://teddashh.github.io/ai-security-scanner/samples/v0.4.0/sample-report-full-zh-TW.html)
- [四份中英文範例與產製方式](docs/samples/v0.4.0/README.zh-TW.md)

### 隱私與資料

- **報告留在你的電腦上。** 除非你自己匯出或分享，報告不會離開這台電腦。
- **本機專案只看副本。** 專案會先複製成唯讀副本再檢查，不會執行，也不會上傳。
- **掃描會連到你核准的地方。** 網路檢查會連到你核准的目標；雲端檢查會連到雲端服務商；模型檢查會把提示送到你指定的 API。
- **只掃描你擁有、或已獲授權檢查的資產。**
- **不會自動修正。** 所有修改都由你或你的團隊決定、執行。
- **雲端存取權限需要你自己移除。** 如果你用設定腳本讓應用程式讀取雲端帳號，這個權限會一直存在，直到你在雲端主控台移除。目前請不要預期應用程式會自動撤銷。
- **舊的掃描檔案不一定會自動清除。** 目前不保證過去每次掃描留下的副本和檔案都會自動刪除。需要清除時，請參考[結果與匯出](docs/results-and-exports.zh-TW.md)。

### 搭配 Claude Code、Codex 或命令列

**開始**、**暫停**和**繼續**都只能在桌面應用程式裡操作。AI 助理（Agent Skill）和命令列工具（CLI）可以幫你準備、查看和匯出，但無法自己啟動掃描。

在同一台電腦上，Claude Code 或 Codex 可以：

- 安裝應用程式
- 確認這台電腦能否掃描
- 帶你走過操作步驟
- 解讀結果
- 保存 HTML 報告

兩者共用同一份 Skill：[Claude Code](.claude/skills/ai-security-scanner/SKILL.md) · [Codex](.codex/skills/ai-security-scanner/SKILL.md)。

在任一 Agent 開啟本儲存庫後，可以這樣說：

> 使用 ai-security-scanner skill 在這台電腦安裝應用程式、確認可以掃描、引導我完成一次掃描，並保存最終 HTML 報告。

Agent 的沙箱擋住下載或應用程式時，它會請你允許那一個指令。雲端上的 Agent 無法在你的電腦安裝東西，會改給你安裝檔連結。詳見 [Agent 需要的環境](docs/getting-started.zh-TW.md#透過-agent-skill-使用)。

### 深入文件

- [開始使用](docs/getting-started.zh-TW.md)
- [掃描範圍](docs/scanning-scope.zh-TW.md)：每種檢查會做什麼、不做什麼
- [結果與匯出](docs/results-and-exports.zh-TW.md)
- [25 個掃描工具指南](https://teddashh.github.io/ai-security-scanner/scanner-guide.html?lang=zh-TW)（[GitHub 版](docs/scanner-guide.zh-TW.md)）
- [引擎目錄](docs/engine-catalog.md)：固定版本、授權與執行界線
- [目前開發狀態](docs/development-status.zh-TW.md) · [v0.4.0 發布紀錄](docs/release/v0.4.0.zh-TW.md)
- [文件索引](docs/README.zh-TW.md) · [參與開發](CONTRIBUTING.md) · [貢獻者](CONTRIBUTORS.md) · [安全政策](SECURITY.md)

<details>
<summary><strong>技術細節：串接的 25 個開源工具</strong></summary>

偵測工作由既有的開源工具負責。本產品用薄層轉接器把選定的輸入交給這些工具，再用輸出轉換器把結果整理進同一份報告。偵測規則沿用上游；排序、去重和白話說明由共用報告層處理。原始識別碼、嚴重度、證據和修正建議都會保留。

- **程式碼、套件與基礎設施設定**：Semgrep、Gitleaks、TruffleHog、Trivy、Grype、Checkov、KICS、Syft（只做盤點）
- **網站與內部系統**：Nuclei、ZAP（選用，被動檢查）、Greenbone OpenVAS Scanner、Naabu（只做觀察）、httpx（只做觀察）
- **雲端與 Microsoft 365**：Prowler、ScoutSuite（限縮範圍）、Cloudsplaining、CloudQuery（只做盤點）、Steampipe（只做盤點）、ScubaGear、Maester
- **Kubernetes**：Kubescape、kube-bench
- **AI 工作流程、模型與 MCP**：Agentic Radar（選用，離線盤點）、Garak（選用，會產生服務商費用）、MCP Armor

各工具的精確版本、設定與界線，以[引擎目錄](docs/engine-catalog.md)和[掃描範圍](docs/scanning-scope.zh-TW.md)為準。研究中的候選工具不屬於目前的掃描能力。

</details>

<details>
<summary><strong>開發</strong></summary>

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

`npm run dev` 會開啟使用範例資料的瀏覽器預覽。實際掃描只在 Tauri 桌面應用程式中執行。上游引擎更新流程見[引擎維護](docs/engine-maintenance.md)。

</details>

### 授權

本專案自行撰寫的原始碼採用 [Apache-2.0](LICENSE) 授權。第三方工具與資料保留各自的授權，詳見 [THIRD_PARTY.md](THIRD_PARTY.md)。

---

# 2. README (English)

## ai-security-scanner

[Project website](https://teddashh.github.io/ai-security-scanner/) · [繁體中文](README.zh-TW.md) · [Documentation](docs/README.md) · [Releases](https://github.com/teddashh/ai-security-scanner/releases)

ai-security-scanner is a desktop app that runs on your own computer. First you choose what to check: your internal IT systems, a website, or a project folder on your computer. The app picks the open-source security tools that fit and runs them. Then it gives you one report:

- what needs attention
- why it matters
- what to do next
- what this scan did not check

It never changes anything for you. "No problems found" never means "secure."

### Your first scan

**1. Download and install the v0.4.0 stable release**

| Computer | Installer | Before first launch |
| --- | --- | --- |
| macOS, Apple silicon or Intel | [ai-security-scanner_0.4.0_universal.dmg](https://github.com/teddashh/ai-security-scanner/releases/download/v0.4.0/ai-security-scanner_0.4.0_universal.dmg) | Drag the app into **Applications**. It is not notarized, so run `xattr -dr com.apple.quarantine /Applications/ai-security-scanner.app` once in Terminal before opening it. |
| Windows x86-64 | [ai-security-scanner_0.4.0_x64-setup.exe](https://github.com/teddashh/ai-security-scanner/releases/download/v0.4.0/ai-security-scanner_0.4.0_x64-setup.exe) or the [MSI](https://github.com/teddashh/ai-security-scanner/releases/download/v0.4.0/ai-security-scanner_0.4.0_x64_en-US.msi) | The installer is unsigned. If SmartScreen warns, select **More info → Run anyway**. If Windows asks to install or update WSL, allow it. |
| Debian or Ubuntu x86-64 | [ai-security-scanner_0.4.0_amd64.deb](https://github.com/teddashh/ai-security-scanner/releases/download/v0.4.0/ai-security-scanner_0.4.0_amd64.deb) | Install with `sudo apt install ./ai-security-scanner_0.4.0_amd64.deb`. |

The first time a scan needs it, the app sets up its own scanning environment. You don't need Docker. Checksums and the tested limits of this release are on the [v0.4.0 release page](https://github.com/teddashh/ai-security-scanner/releases/tag/v0.4.0).

**2. Choose a path**

- **Scan my environment**: check several project folders, websites and approved internal systems in one run.
- **Check a website**: check one website, such as `https://www.example.com`, without going beyond that site.
- **Check code or an AI project**: check one project folder on your computer.

**3. Confirm the scope, then start**

The steps are **New scan → Review and start → Scan progress → Results**.

The Review screen lists every target and port the scan will contact. A port is the entry point a computer uses to offer a service. Nothing happens until you select **Start** in the app. You can pause a scan and resume it later.

**4. Save the report**

From **Results**, select **Save or share report**, then **Save HTML report**. You can reopen the scan later from **My scans**. See the [step-by-step path to an HTML report](docs/getting-started.md#from-new-scan-to-an-html-report).

### What it can check

| You choose | It looks at | Where it stops |
| --- | --- | --- |
| Your IT environment | Which services are running on the hosts and ports you approve, plus known vulnerabilities and configuration problems in those services | Contacts only the hosts and ports listed on Review |
| A website | The site's security settings and known issues. An advanced option adds a page check that only reads responses and never submits forms | Sends read-only requests. No logins, no attack content |
| A local project | Passwords and keys left in files, third-party packages with known vulnerabilities, risky code patterns, unsafe configuration. In AI projects, workflows and MCP configuration too | Works on a read-only copy. It never runs or uploads your project |

**Advanced options (turn them on only when you need them)**

- **Cloud (AWS, Azure, GCP):** for now, only identity and access settings, such as whether an account has more permissions than it needs. **This is not a full cloud security audit.**
- **Microsoft 365:** a fixed set of security baseline settings.
- **Kubernetes:** configuration files you select, and a copy of node settings.
- **AI model behavior:** sends 54 fixed prompts to one HTTPS chat API you name. This uses your provider quota and may cost money. The app asks for your explicit approval first.

> **Inventory is not a vulnerability.** Some tools only list what exists, such as software components, cloud accounts or open ports. The report shows these as observations, not problems. An open port is not a vulnerability by itself.

### Reading the report

Each scan produces one report, grouped by the assets you selected. Every asset gets one of four statuses:

- **Problems found**
- **No problems in completed checks**
- **Incomplete:** a check started but did not finish
- **Not tested:** a check that did not run this time

For each problem, the report covers three things in order: what to fix first, why it matters, and the smallest practical next step, plus how to confirm the fix worked. The original tool, rule ID, severity and evidence sit in **Technical details**, ready when you need them.

If one check fails, the other completed results stay in the report. You can reopen reports, compare them with later scans, and export them as HTML or structured data.

> **"No problems found" covers only the checks that completed.** It is not a security guarantee. It says nothing about incomplete or untested checks.

Want to see a report first? These examples use **simulated data** run through the production report pipeline:

- [Redacted HTML](https://teddashh.github.io/ai-security-scanner/samples/v0.4.0/sample-report-redacted-en.html) · [Fully disclosed HTML](https://teddashh.github.io/ai-security-scanner/samples/v0.4.0/sample-report-full-en.html)
- [All four bilingual examples and how they were made](docs/samples/v0.4.0/README.md)

### Privacy and your data

- **Reports stay on your computer.** They leave only when you export or share them.
- **Local projects are copied, not touched.** The app checks a read-only copy and never runs or uploads your project.
- **Scans contact only what you approve.** Network checks reach the targets you approve. Cloud checks reach the cloud provider. Model checks send prompts to the API you name.
- **Scan only what you own or are authorized to assess.**
- **Nothing is fixed automatically.** You and your team decide what to change.
- **You need to remove cloud access yourself.** If you used a setup script to give the app read access to a cloud account, that access stays until you remove it in your cloud console. Don't count on the app to revoke it for you.
- **Old scan files may remain.** The app does not currently guarantee that copies and files from every earlier scan are deleted automatically. If you need them gone, see [Results and exports](docs/results-and-exports.md).

### Using Claude Code, Codex or the command line

You can only **Start**, **Pause** and **Resume** a scan in the desktop app. AI assistants (Agent Skills) and the command-line tool (CLI) can help you prepare, review and export, but they cannot start a scan on their own.

On the same computer, Claude Code or Codex can:

- install the app
- check that the computer is ready to scan
- walk you through the steps
- explain the results
- save the HTML report

Both use the same skill: [Claude Code](.claude/skills/ai-security-scanner/SKILL.md) · [Codex](.codex/skills/ai-security-scanner/SKILL.md).

Open this repository in either agent and say:

> Use the ai-security-scanner skill to install the app on this computer, check that it can scan, guide me through a scan, and save the final HTML report.

If the agent's sandbox blocks a download or the app, it will ask you to allow that one command. A cloud-hosted agent can't install anything on your computer, so it gives you the installer link instead. See [what the agent needs](docs/getting-started.md#use-with-an-agent-skill).

### Go deeper

- [Getting started](docs/getting-started.md)
- [Scanning scope](docs/scanning-scope.md): what each check does and doesn't do
- [Results and exports](docs/results-and-exports.md)
- [Guide to the 25 scanners](https://teddashh.github.io/ai-security-scanner/scanner-guide.html) ([GitHub edition](docs/scanner-guide.md))
- [Engine catalog](docs/engine-catalog.md): pinned versions, licenses and limits
- [Development status](docs/development-status.md) · [v0.4.0 release record](docs/release/v0.4.0.md)
- [Documentation index](docs/README.md) · [Contributing](CONTRIBUTING.md) · [Contributors](CONTRIBUTORS.md) · [Security policy](SECURITY.md)

<details>
<summary><strong>Technical details: the 25 open-source tools</strong></summary>

Detection comes from established open-source tools. Thin adapters pass your selected inputs to them, and output converters bring the results into one report. Detection rules stay upstream. Ordering, deduplication and plain-language guidance live in the shared report layer. Original identifiers, severity, evidence and remediation are kept.

- **Code, packages and infrastructure settings:** Semgrep, Gitleaks, TruffleHog, Trivy, Grype, Checkov, KICS, Syft (inventory only)
- **Websites and internal systems:** Nuclei, ZAP (optional, passive), Greenbone OpenVAS Scanner, Naabu (observation only), httpx (observation only)
- **Cloud and Microsoft 365:** Prowler, ScoutSuite (reduced scope), Cloudsplaining, CloudQuery (inventory only), Steampipe (inventory only), ScubaGear, Maester
- **Kubernetes:** Kubescape, kube-bench
- **AI workflows, models and MCP:** Agentic Radar (optional, offline inventory), Garak (optional, provider charges apply), MCP Armor

The [engine catalog](docs/engine-catalog.md) and [Scanning scope](docs/scanning-scope.md) are the source of truth for exact versions, profiles and boundaries. Research-only candidates are not current scan capabilities.

</details>

<details>
<summary><strong>Development</strong></summary>

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

`npm run dev` opens a browser preview with sample data. Real scans run only in the Tauri desktop app. For updating upstream engines, see [Engine maintenance](docs/engine-maintenance.md).

</details>

### License

Project-owned source is licensed under [Apache-2.0](LICENSE). Third-party tools and data keep their own licenses; see [THIRD_PARTY.md](THIRD_PARTY.md).

---

# 3. 網站文案 / Website copy

## 3.1 Hero

| | 繁體中文 | English |
| --- | --- | --- |
| 眉標 / Eyebrow | 開源 · 桌面應用程式 · 資料留在你的電腦 | Open source · Desktop app · Your data stays on your computer |
| 標題 / Headline | 選好要檢查的，拿到一份看得懂的報告。 | Choose what to check. Get one report you can act on. |
| 副標 / Subhead | 選擇公司系統、網站或專案資料夾，確認範圍後在桌面應用程式按下開始。它會用適合的開源安全工具檢查，再告訴你哪裡要處理、為什麼重要、下一步怎麼做，以及哪些還沒檢查到。 | Choose your internal systems, a website or a project folder. Confirm the scope and select Start in the desktop app. It runs the open-source security tools that fit, then tells you what needs attention, why, what to do next, and what wasn't checked. |
| 主要按鈕 / Primary CTA | 下載 v0.4.0 正式版 | Download v0.4.0 stable release |
| 次要按鈕 / Secondary CTA | 閱讀開始使用 | Read getting started |
| 小字 / Fine print | Windows（.exe／MSI，未簽章，SmartScreen 可能警告）、macOS Universal .dmg（未經 Apple 公證，第一次開啟前需執行一行 `xattr` 指令）、Debian／Ubuntu .deb。不需要 Docker。[安裝步驟](docs/getting-started.zh-TW.md) · [發布說明](https://github.com/teddashh/ai-security-scanner/releases/tag/v0.4.0) | Windows (.exe/MSI, unsigned; SmartScreen may warn), macOS Universal .dmg (not notarized; run one `xattr` command before first launch), Debian/Ubuntu .deb. No Docker needed. [Install steps](docs/getting-started.md) · [Release notes](https://github.com/teddashh/ai-security-scanner/releases/tag/v0.4.0) |

**Hero 下方三點保證 / Three plain commitments under the hero**

| 繁體中文 | English |
| --- | --- |
| **只碰你核准的範圍。** 網路檢查只連到確認頁列出的目標與連接埠。 | **Only what you approve.** Network checks reach only the targets and ports listed on Review. |
| **你的專案不會被執行或上傳。** 本機專案以唯讀副本檢查。 | **Your project is never run or uploaded.** Local projects are checked from a read-only copy. |
| **不替你修改任何東西。** 報告給建議，決定權在你。 | **Nothing changes without you.** The report suggests; you decide. |

## 3.2 三個步驟 / Three steps

**區塊標題**：選擇、確認、閱讀。
**Section title**: Choose. Confirm. Read.

| # | 繁體中文 | English |
| --- | --- | --- |
| 01 | **選擇要檢查的東西**<br>本機資料夾、完整網站網址，或明確的內部主機。你選的是要檢查的東西，不用自己設定掃描工具。 | **Choose what to check**<br>A local folder, a full website address, or specific internal hosts. You pick what to check; you never configure scanner settings. |
| 02 | **確認範圍，按下開始**<br>確認頁列出每個會連到的目標。你確認授權後，在應用程式按下開始。可以暫停，也可以稍後繼續。 | **Confirm the scope and start**<br>Review lists every target the scan will contact. Confirm you're authorized, then select Start in the app. You can pause and resume. |
| 03 | **閱讀一份報告**<br>依資產整理：先處理什麼、為什麼、下一步，以及沒有檢查到的部分。某項檢查失敗時，其他結果仍會保留。 | **Read one report**<br>Organized by asset: what comes first, why, the next step, and what wasn't checked. If one check fails, the rest of the results stay. |

## 3.3 能力 / Capabilities

**區塊標題**：三種常用檢查，需要時再開進階選項。
**Section title**: Three everyday checks. Advanced options when you need them.

| | 繁體中文 | English |
| --- | --- | --- |
| IT 環境 / IT environment | 檢查你核准的內部主機上有哪些服務在運作，以及已知的服務漏洞和設定問題。 | Finds the services running on internal hosts you approve, and checks them for known vulnerabilities and configuration problems. |
| 網站 / Website | 檢查一個網站的安全設定和已知問題。只送出讀取用的請求。 | Checks one website's security settings and known issues, using read-only requests. |
| 本機專案 / Local project | 找出留在檔案裡的密碼和金鑰、有已知漏洞的套件、有風險的程式寫法和設定。AI 專案還會檢查工作流程和 MCP 設定。 | Finds passwords and keys left in files, packages with known vulnerabilities, and risky code and configuration. In AI projects, it also checks workflows and MCP configuration. |

**進階（選用）/ Advanced (optional)**

| 繁體中文 | English |
| --- | --- |
| **雲端：** AWS、Azure、GCP 的身分與存取權限設定。目前範圍有限，不是完整的雲端稽核。 | **Cloud:** identity and access settings in AWS, Azure and GCP. The scope is limited for now; this is not a full cloud audit. |
| **Microsoft 365：** 一組固定的安全基準設定。 | **Microsoft 365:** a fixed set of security baseline settings. |
| **Kubernetes：** 你選定的設定檔和節點設定副本。 | **Kubernetes:** configuration files you select and a copy of node settings. |
| **AI 模型行為：** 對你指定的聊天 API 送出 54 個固定提示。可能產生服務商費用，送出前需要你同意。 | **AI model behavior:** 54 fixed prompts sent to a chat API you name. Provider charges may apply, and the app asks before sending. |

**界線說明（建議放在能力區塊下方，不要藏進頁尾）/ Limits (place directly below capabilities, not in the footer)**

| 繁體中文 | English |
| --- | --- |
| 有些工具只列出「有什麼」，例如軟體清單、帳號清單、開放的連接埠。這些是觀察，不是漏洞。 | Some tools only list what exists, such as software, accounts or open ports. Those are observations, not vulnerabilities. |
| 「未發現問題」只代表已完成的檢查沒有回報問題，不代表一定安全。 | "No problems found" means the completed checks reported nothing. It does not mean secure. |
| 應用程式不會自動修正任何東西。 | The app does not fix anything automatically. |
| 如果你用設定腳本開放雲端存取，這個權限需要你自己移除。 | If you used a setup script to grant cloud access, you need to remove that access yourself. |

## 3.4 報告範例 / Report example

**區塊標題**：先看看你會拿到什麼。
**Section title**: See what you'll get.

**說明文字 / Intro**

| 繁體中文 | English |
| --- | --- |
| 以下是報告的版面結構，不是真實掃描結果。要看完整內容，請打開模擬資料範例報告。 | Below is the layout of a report, not a real scan result. To see full content, open the simulated sample reports. |

**版面示意（顯示時請加上「版面示意」標籤）/ Layout illustration (label it "Layout only")**

```
┌ 需要優先處理 / What needs attention ─────────────────────
│  {資產 / asset}        {問題標題 / finding title}     {優先度 / priority}
│    為什麼重要 / Why it matters: {一句話 / one sentence}
│    下一步 / Next step: {最小可行動作 / smallest practical action}
│    如何確認 / How to confirm: {驗證方式 / verification}
├ 資產涵蓋 / Asset coverage ───────────────────────────────
│  {資產}  發現問題 / Problems found
│  {資產}  已完成的檢查未發現問題 / No problems in completed checks
│  {資產}  未完成 / Incomplete — {原因 / reason}
│  {資產}  未測試 / Not tested — {項目 / checks}
├ 觀察與盤點（不是漏洞）/ Observations and inventory (not vulnerabilities)
└ ▸ 技術細節 / Technical details（展開 / expand）
```

**範例連結 / Sample links**

| 繁體中文 | English |
| --- | --- |
| **遮蔽版報告**：保留問題與下一步，隱藏可辨識的資產資訊。[閱讀](https://teddashh.github.io/ai-security-scanner/samples/v0.4.0/sample-report-redacted-zh-TW.html) | **Redacted report**: findings and next steps, with identifying asset details hidden. [Read](https://teddashh.github.io/ai-security-scanner/samples/v0.4.0/sample-report-redacted-en.html) |
| **完整揭露版報告**：顯示虛構的名稱、端點與帳號背景。兩版的機密值都會遮住。[閱讀](https://teddashh.github.io/ai-security-scanner/samples/v0.4.0/sample-report-full-zh-TW.html) | **Fully disclosed report**: fictional names, endpoints and account context. Secret values stay masked in both. [Read](https://teddashh.github.io/ai-security-scanner/samples/v0.4.0/sample-report-full-en.html) |
| 兩份範例使用相同的模擬資料，涵蓋全部 25 個工具的輸出格式：62 筆原始發現、42 筆盤點觀察（盤點不算漏洞）。[產製方式](docs/samples/v0.4.0/README.zh-TW.md) | Both use the same simulated data in the output formats of all 25 tools: 62 original findings and 42 inventory observations (inventory is not counted as vulnerabilities). [How they were made](docs/samples/v0.4.0/README.md) |

## 3.5 AI 助理能幫什麼 / AI assistant help

**區塊標題**：讓 Claude Code 或 Codex 幫你準備和解讀。開始仍由你按下。
**Section title**: Let Claude Code or Codex help you prepare and understand. You still select Start.

| 繁體中文 | English |
| --- | --- |
| 在同一台電腦上，AI 助理可以安裝應用程式、確認電腦能否掃描、帶你走過步驟、解讀結果，並保存 HTML 報告。命令列工具也能協助準備、查看和匯出。 | On the same computer, an AI assistant can install the app, check that the computer is ready, walk you through the steps, explain the results and save the HTML report. The command-line tool can also help you prepare, review and export. |
| **它們做不到的事：** 自己啟動、暫停或繼續掃描。這些只能在桌面應用程式裡做。 | **What they can't do:** start, pause or resume a scan. Only the desktop app can. |
| 沙箱擋住某個指令時，Agent 會請你允許那一個指令。雲端上的 Agent 無法在你的電腦安裝東西，會改給你安裝檔連結。 | If a sandbox blocks a command, the agent asks you to allow that one command. A cloud-hosted agent can't install anything on your computer, so it gives you the installer link instead. |
| 按鈕：[Claude Code Skill](.claude/skills/ai-security-scanner/SKILL.md) · [Codex Skill](.codex/skills/ai-security-scanner/SKILL.md) | Buttons: [Claude Code Skill](.claude/skills/ai-security-scanner/SKILL.md) · [Codex Skill](.codex/skills/ai-security-scanner/SKILL.md) |

## 3.6 行動呼籲 / Call to action

| | 繁體中文 | English |
| --- | --- | --- |
| 標題 / Title | 從你要檢查的東西開始。 | Start with what you want to check. |
| 內文 / Body | 下載正式版，選好範圍，確認後按下開始。讀完報告，你會知道先處理什麼，也會知道還有什麼沒檢查到。 | Download the stable release, choose your scope and select Start. When you finish the report, you'll know what to handle first and what hasn't been checked yet. |
| 按鈕 / Buttons | 下載 v0.4.0 正式版 · 閱讀開始使用 | Download v0.4.0 stable release · Read getting started |
| 頁尾 / Footer | 專案原始碼採 Apache-2.0 · 第三方工具保留各自授權 · [引擎目錄](docs/engine-catalog.md) · [安全政策](SECURITY.md) | Apache-2.0 project source · Third-party tools keep their own licenses · [Engine catalog](docs/engine-catalog.md) · [Security policy](SECURITY.md) |

> 工具卡片牆（25 張卡片與星星數）建議移到獨立的「工具」頁或[掃描器指南](https://teddashh.github.io/ai-security-scanner/scanner-guide.html)，首頁只留一句話和連結。理由見第 5 節。

---

# 4. 報告用語 / Report wording

## 4.1 完成，有發現 / Completed with findings

| 繁體中文 | English |
| --- | --- |
| **掃描完成。{n_assets} 個資產中，有 {n_affected} 個需要處理。** | **Scan complete. {n_affected} of {n_assets} assets need attention.** |
| 下面先列出最需要處理的 {n_priority} 項。每一項都附上原因、建議的下一步，以及修好之後如何確認。 | The {n_priority} most important items are listed first. Each one includes why it matters, a suggested next step and how to confirm the fix. |
| 這份報告只反映已完成的檢查。未完成和未測試的項目列在「涵蓋範圍」。 | This report reflects only the checks that completed. Incomplete and untested checks are listed under Coverage. |

**單一問題 / Single finding**

| 繁體中文 | English |
| --- | --- |
| **{問題標題}** · {資產} · 優先度：{priority} | **{finding title}** · {asset} · Priority: {priority} |
| **為什麼重要：** {一句白話說明} | **Why it matters:** {one plain sentence} |
| **建議下一步：** {最小可行動作} | **Suggested next step:** {smallest practical action} |
| **如何確認已修正：** {驗證方式} | **How to confirm the fix:** {verification} |
| 來源：{工具名稱} · ▸ 技術細節 | Source: {tool name} · ▸ Technical details |

## 4.2 完成，未發現問題 / No findings

| 繁體中文 | English |
| --- | --- |
| **掃描完成。已完成的檢查沒有回報問題。** | **Scan complete. The completed checks reported no problems.** |
| 這代表這次執行的 {n_checks} 項檢查，在選定範圍內沒有回報問題。它不保證這些資產安全，也不涵蓋這次未執行的檢查。 | This means the {n_checks} checks that ran found nothing within the selected scope. It is not a guarantee that these assets are secure, and it doesn't cover checks that did not run. |
| {若有未測試項目}：這次有 {n_untested} 項檢查未執行，詳見「涵蓋範圍」。 | {If any untested}: {n_untested} checks did not run this time. See Coverage. |
| {若有觀察}：另有 {n_observations} 筆觀察，例如開放的連接埠或軟體清單。這些不是漏洞。 | {If observations exist}: There are also {n_observations} observations, such as open ports or software inventory. These are not vulnerabilities. |

## 4.3 部分完成 / Partial completion

| 繁體中文 | English |
| --- | --- |
| **掃描部分完成。{n_done} 項檢查已完成，{n_incomplete} 項沒有完成。** | **Scan partly complete. {n_done} checks finished; {n_incomplete} did not.** |
| 已完成的結果都保留在下方。沒有完成的部分無法判斷，請不要把它當成「沒有問題」。 | Results from the finished checks are kept below. Unfinished checks tell you nothing, so don't read them as "no problems." |
| **未完成：** {檢查名稱} · {資產} · 原因：{reason} | **Incomplete:** {check} · {asset} · Reason: {reason} |
| {連線過期時}：唯讀連線已過期。重新連線後可以再掃描一次。[重新連線並掃描] | {When a connection expired}: The read-only connection has expired. Reconnect to scan again. [Reconnect and rescan] |
| {使用者暫停時}：掃描已暫停。在應用程式裡按「繼續」完成剩下的檢查。 | {When paused}: The scan is paused. Select Resume in the app to finish the remaining checks. |

## 4.4 涵蓋範圍 / Coverage

| 繁體中文 | English |
| --- | --- |
| **涵蓋範圍**：每個資產這次檢查了什麼、沒檢查什麼。 | **Coverage**: what was and wasn't checked for each asset. |
| **發現問題**：至少一項已完成的檢查回報了問題。 | **Problems found**: at least one completed check reported a problem. |
| **已完成的檢查未發現問題**：已執行的檢查都沒有回報問題。 | **No problems in completed checks**: every check that ran reported nothing. |
| **未完成**：檢查已開始，但沒有跑完。結果未知。 | **Incomplete**: the check started but did not finish. The result is unknown. |
| **未測試**：這次沒有執行，可能是不適用、沒有選擇，或需要人工確認。 | **Not tested**: this check didn't run. It may not apply, may not have been selected, or may need a manual review. |
| **觀察與盤點**：列出有什麼，例如開放的連接埠、軟體元件、雲端帳號。不是漏洞，也不會計入問題數。 | **Observations and inventory**: lists of what exists, such as open ports, software components or cloud accounts. These are not vulnerabilities and are not counted as problems. |
| {雲端資產}：雲端檢查目前只涵蓋身分與存取權限設定，不是完整的雲端稽核。 | {Cloud assets}: Cloud checks currently cover identity and access settings only. This is not a full cloud audit. |

## 4.5 下一步 / Next steps

| 繁體中文 | English |
| --- | --- |
| **接下來可以做的事** | **What to do next** |
| 1. 先處理「需要優先處理」裡的項目。把報告交給負責那個資產的人。 | 1. Start with the items under "What needs attention." Share the report with whoever owns each asset. |
| 2. 修正後再掃描一次相同範圍，確認問題已經消失。 | 2. After making fixes, scan the same scope again to confirm the problems are gone. |
| 3. 檢視「未完成」和「未測試」的項目，決定是否需要補做。 | 3. Review incomplete and untested checks and decide whether to run them. |
| 4. {若使用過雲端設定腳本}：不再需要時，請到雲端主控台移除這次授予的存取權限。應用程式不會自動移除。 | 4. {If a cloud setup script was used}: When you no longer need it, remove the access you granted in your cloud console. The app does not remove it for you. |
| 應用程式沒有修改任何資產。所有修正都由你決定。 | The app made no changes to any asset. Every fix is your decision. |

## 4.6 技術細節 / Technical details

| 繁體中文 | English |
| --- | --- |
| ▸ **技術細節**（展開） | ▸ **Technical details** (expand) |
| 以下保留原始掃描工具的輸出，供技術人員查核。 | Original output from the scanning tools, kept for technical review. |
| 工具：{engine} {version} · 規則：{rule_id} · 原始嚴重度：{severity} | Tool: {engine} {version} · Rule: {rule_id} · Original severity: {severity} |
| 證據：{evidence}（機密值已遮蔽） | Evidence: {evidence} (secret values masked) |
| 工具建議的修正：{remediation} | Tool's suggested remediation: {remediation} |
| 執行結果：{completed / failed / skipped} · 開始 {start} · 結束 {end} | Execution: {completed / failed / skipped} · Started {start} · Ended {end} |
| 「原始嚴重度」由上游工具判定；報告上方的「優先度」由本產品綜合排序，兩者可能不同。 | "Original severity" comes from the upstream tool. The "priority" at the top of the report is this product's overall ordering. The two may differ. |

## 4.7 正式頁尾 / Formal footer

**繁體中文**

> 本報告由 ai-security-scanner {app_version} 於 {scan_date} 產生，依據使用者選定並確認授權的範圍。內容僅反映已完成的檢查；未完成與未測試的項目列於「涵蓋範圍」。本報告不是安全認證，也不保證受檢資產沒有其他問題。掃描過程中未對任何資產套用修正。偵測結果來自所列的開源工具，原始識別碼、嚴重度與證據保留於技術細節。本報告產生後儲存在執行掃描的電腦上；{若為匯出版本：本份由使用者於 {export_date} 匯出。}{若產品支援揭露層級：揭露層級：{遮蔽版／完整揭露版}。}

**English**

> This report was generated by ai-security-scanner {app_version} on {scan_date} for the scope the user selected and confirmed as authorized. It reflects only checks that completed; incomplete and untested checks are listed under Coverage. This report is not a security certification and does not guarantee that the assessed assets have no other problems. No changes were applied to any asset during the scan. Findings come from the listed open-source tools; original identifiers, severity and evidence are preserved in Technical details. The report is stored on the computer that ran the scan. {If exported: This copy was exported by the user on {export_date}.} {If disclosure levels are supported: Disclosure level: {Redacted / Fully disclosed}.}

---

# 5. 編輯理由與需要釐清的原始說法 / Editorial rationale and source claims to clarify

## 5.1 編輯理由 / Rationale

1. **從讀者的任務開始寫，不從架構開始。** 原文第一段就出現 thin adapters、output converters、upstream scanners。這些對管理、人文和一般 IT 讀者沒有幫助，所以新版先說它做什麼、你會拿到什麼、它不做什麼。架構說明移進可展開的技術細節。
2. **界線要放在讀者看得到的地方。** 「未發現問題不等於安全」「盤點不是漏洞」「不會自動修正」「雲端範圍有限」都放在正文和報告主體裡，不放在頁尾小字。對這群讀者，說清楚界線就是建立信任的方式。
3. **誰能按開始，要講清楚。** 原網站的 hero 寫「透過桌面程式或 Agent Skills 執行……掃描器」，容易讓人以為 AI 助理可以自己掃描。新版統一說法：開始、暫停、繼續只在桌面應用程式；Agent Skills 和 CLI 負責準備、查看和匯出。
4. **新增兩個原文沒有說的限制。** 一是雲端存取權限會一直存在，需要使用者自己移除；二是舊的掃描檔案不保證自動清除。兩者都依事實限制寫成提醒，沒有承諾任何自動功能。
5. **拿掉數字型行銷。** 首頁的「25／3／1」、星星數、「81 筆 Grype 問題」對一般讀者沒有判斷價值，還可能被誤讀成產品成效。數字留給掃描器指南和引擎目錄。
6. **報告範例不放假結果。** 原網站預覽寫著「Exposed credential pattern · Critical」，看起來像真實掃描結果。新版只呈現版面，並連到已標明「模擬資料」的範例。
7. **用語選擇。** 中文用一般讀者較熟悉的「漏洞」，不用「弱點」；「secrets」寫成「密碼和金鑰」；「origin」寫成「一個網站」；「dependencies」寫成「第三方套件」。英文避免 posture、exposure、IAM 這類術語，必要時放在技術細節。
8. **版本與安裝內容原封不動。** v0.4.0、檔名、未簽章與未公證的說明、`xattr` 指令、WSL 提示、Docker 說明都沒有改。

## 5.2 需要釐清的原始說法 / Source claims to clarify

| # | 原始說法 / Source claim | 問題 / Concern | 建議 / Suggestion |
| --- | --- | --- | --- |
| 1 | 網站 hero：「Use the desktop app or Claude Code and Codex Agent Skills to run applicable upstream scanners」 | 暗示 Agent Skills 能執行掃描，和事實不符 | 改成「在桌面應用程式啟動；Agent Skills 協助準備與解讀」 |
| 2 | 「Data stays on the device until an external source is connected or a report is exported」 | 「external source」意思不清。掃描本來就會連到網路目標、雲端服務商和模型 API | 分開寫：報告留在本機；掃描會連到哪些地方 |
| 3 | 「Read-only by default」（網站） | 只對本機副本成立。網路檢查會送出請求；Garak 會送出提示並產生費用 | 限定為「本機專案以唯讀副本檢查」 |
| 4 | 「Network scanners contact only the targets and ports confirmed on Review」 | 沒提到雲端檢查會連到雲端服務商，模型檢查會連到外部 API | 補一句說明雲端與模型檢查的連線對象 |
| 5 | 首頁流程圖：「Repositories · websites · endpoints · cloud · containers · Kubernetes」 | 把雲端和其他核心選項並列，容易讓人以為是完整的雲端檢查 | 標示雲端為進階，並寫明只做身分與存取設定檢查 |
| 6 | 「Scan my environment」對應「掃描公司環境」，事實限制稱為「IT environment」 | 三種說法不一致，個人使用者也可能不覺得自己有「公司」 | 確認 UI 正式名稱，中英文統一 |
| 7 | 原文完全沒提到設定腳本建立的雲端存取權限 | 使用者可能以為掃描結束後權限會自動收回 | 在 README、隱私段落和報告下一步加入「需自行移除」 |
| 8 | 原文沒提到 CLI 的角色，也沒提到暫停與繼續 | 讀者不知道 CLI 能做什麼，也不知道掃描可以暫停 | 在文件中寫明 CLI 支援的準備、查看、匯出指令（本提案沒有自行編造指令） |
| 9 | 「Reports can be ... compared with later runs」 | 不清楚比較是在應用程式內進行，還是要靠匯出資料 | 確認後在結果文件中具體說明 |
| 10 | 範例報告有「遮蔽版」和「完整揭露版」 | 不清楚一般使用者匯出時是否能選揭露層級，還是這只是範例的產製方式 | 確認後決定頁尾是否保留揭露層級那一行 |
| 11 | 「Every byte a model wrote is attributed…」等引擎維護說明出現在首頁 | 這是給開發者的內容，一般讀者看不懂，也容易把它和「AI 會改你的系統」混在一起 | 移到引擎維護文件 |
| 12 | 星星數與「81 Grype findings」 | 可能被讀成品質背書或預期結果 | 移出首頁和 README 正文，保留在掃描器指南和引擎目錄 |
| 13 | 「Check a website scans one exact web origin with a reviewed Nuclei profile」 | 「origin」「profile」是術語，而且沒說是否會跟著連結跳到其他網域 | 用白話說「一個網站，不會超出這個網站」，細節放掃描範圍文件 |
| 14 | 舊掃描副本與紀錄的保存方式 | 原文沒有說，但讀者會想知道資料什麼時候會刪除 | 在結果與匯出文件中如實說明目前的狀況，以及手動清除的方式 |
