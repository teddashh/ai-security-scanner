# Editorial proposal: reader-facing copy for ai-security-scanner

Proposed copy for review. Installers, version, and packaging stay on the published v0.4.0 facts. Sample numbers below are the published simulated report, not a scan of a real environment. Button names already in the app are quoted. No new scan results are introduced.

---

## 1. README（繁體中文）

# ai-security-scanner

[專案網站](https://teddashh.github.io/ai-security-scanner/?lang=zh-TW) · [English](README.md) · [文件](docs/README.zh-TW.md) · [下載 v0.4.0](https://github.com/teddashh/ai-security-scanner/releases/tag/v0.4.0)

### 這份工具做什麼

ai-security-scanner 是裝在你自己電腦上的桌面應用程式。你選定專案、網站或內部系統，它執行適用的檢查，再把結果收成一份報告。

報告依你選的對象排列。每個對象都會看到優先順序、原因、下一步，以及還沒有檢查的項目。原始掃描器的名稱、規則識別碼、嚴重度與證據收在可展開的技術細節裡。

掃描的開始、暫停與繼續都在桌面應用程式裡。命令列工具，以及 Claude Code、Codex 的 Agent Skill，可以幫忙準備這台電腦、查看已完成的掃描、匯出報告。它們不能自己啟動掃描。

偵測規則來自既有的上游工具。這個產品負責選定適用的檢查，並把已完成的結果整理成同一份報告。v0.4.0 串接 25 個上游工具。完整名單、版本與執行界線在[引擎目錄](docs/engine-catalog.md)，一般讀者可先看[掃描器指南](https://teddashh.github.io/ai-security-scanner/scanner-guide.html?lang=zh-TW)。

### 第一次掃描

下載適合這台電腦的 **v0.4.0 正式版**：

| 電腦 | 安裝檔 | 第一次開啟 |
| --- | --- | --- |
| macOS（Apple 晶片或 Intel） | [ai-security-scanner_0.4.0_universal.dmg](https://github.com/teddashh/ai-security-scanner/releases/download/v0.4.0/ai-security-scanner_0.4.0_universal.dmg) | 把應用程式拖進「應用程式」。此版本未經 Apple 公證。開啟前先在「終端機」執行一次 `xattr -dr com.apple.quarantine /Applications/ai-security-scanner.app`。 |
| Windows x86-64 | [ai-security-scanner_0.4.0_x64-setup.exe](https://github.com/teddashh/ai-security-scanner/releases/download/v0.4.0/ai-security-scanner_0.4.0_x64-setup.exe) 或 [MSI](https://github.com/teddashh/ai-security-scanner/releases/download/v0.4.0/ai-security-scanner_0.4.0_x64_en-US.msi) | 安裝檔未簽章。SmartScreen 出現時，選「其他資訊 → 仍要執行」。若 Windows 要求安裝或更新 WSL，請允許。WSL 是這支應用程式在 Windows 上可能用到的系統元件。不需要另外安裝 Docker。 |
| Debian 或 Ubuntu x86-64 | [ai-security-scanner_0.4.0_amd64.deb](https://github.com/teddashh/ai-security-scanner/releases/download/v0.4.0/ai-security-scanner_0.4.0_amd64.deb) | 執行 `sudo apt install ./ai-security-scanner_0.4.0_amd64.deb`。 |

第一次需要掃描時，應用程式會自己準備掃描環境。檢查碼與這個版本的驗證範圍寫在 [v0.4.0 發布頁](https://github.com/teddashh/ai-security-scanner/releases/tag/v0.4.0)。

打開應用程式，走這條路徑：**開始新掃描 → 確認後開始 → 掃描進度 → 掃描結果**。開始、暫停與繼續都在這個視窗裡。掃描結果可以從**我的掃描**再打開，也可以和之後的掃描比較。

要留下一份可傳送的檔案時，在掃描結果按**保存或分享報告**，進入**分享結果**，再按**儲存「HTML 報告」**。逐步畫面見[從開始新掃描到 HTML 報告](docs/getting-started.zh-TW.md#從開始新掃描到-html-報告)。

同一台電腦上的 Claude Code 或 Codex 可以幫忙安裝、確認電腦是否就緒、沿畫面引導，以及在掃描結束後幫忙閱讀並儲存 HTML。開始掃描的那一下仍由你在應用程式裡按下。可以這樣要求：

> 使用 ai-security-scanner skill，在這台電腦安裝應用程式、確認它可以掃描，並引導我操作桌面應用程式。掃描由我在應用程式裡開始。完成後協助我閱讀結果，並儲存 HTML 報告。

Skill 檔案：Claude Code 用 [.claude/skills/ai-security-scanner/SKILL.md](.claude/skills/ai-security-scanner/SKILL.md)，Codex 用 [.codex/skills/ai-security-scanner/SKILL.md](.codex/skills/ai-security-scanner/SKILL.md)。代理的隔離環境若擋住下載或應用程式，它會請你允許那一個指令。雲端上的代理碰不到你的電腦，只會把安裝檔連結給你。

### 可以檢查什麼

三條基本路徑：

- **資訊環境。** 畫面上的名稱是「掃描公司環境」。同一輪可以加入多個專案資料夾、網站，以及你有權檢查的內部系統。
- **網站。** 畫面上的名稱是「檢查網站」。檢查一個精確的網站來源，使用已經審過的網站檢查設定。
- **本機專案。** 畫面上的名稱是「檢查程式碼或 AI 專案」。應用程式複製一份有範圍的唯讀複本，在複本上查看秘密、已知有漏洞的相依套件、有風險的程式碼與不安全的設定。它不執行這個專案，也不把專案上傳出去。

雲端是進階選項，不是第四條對等的基本路徑。目前對 AWS、Azure、GCP 的安全檢查，只涵蓋你指定帳號的身分與存取設定，不是一次完整的雲端稽核。Azure 與 GCP 走的是這組有限的身分與存取檢查。AWS 另外有幾項同樣限於身分與存取的檢查，也有只產生身分清單的工具。Microsoft 365 是對照一份固定的安全設定基準。

依對象不同，適用的檢查大致是這些：

- **本機專案。** 程式碼模式、離線的秘密比對、以固定離線資料比對的已知套件漏洞、基礎設施與設定檔。軟體組成清單會另存，清單本身不是漏洞。你若選了 Kubernetes 設定檔，可以離線檢查那些檔案；節點設定則對照一份不可變的設定複本，不會對正在運行的主機做高權限掛載。做不完的項目會標成未完成。
- **網站與內部系統。** 對準已核准的網站來源做有範圍的網頁檢查。內部系統只連線你在確認頁核准的主機與連接埠。開放的連接埠、網站是否回應，都是觀察，不是漏洞。可另外打開一項被動網站檢查：只爬一個核准來源，不送出表單，也不送出攻擊內容。
- **AI 相關的可選檢查。** 工作流程盤點只讀一份已核准的專案複本，支援 LangGraph、CrewAI、n8n、OpenAI Agents、AutoGen；不執行該工作流程，也不連線模型。MCP 設定只做靜態檢查，查看寫死的憑證與過寬的工具權限，不啟動伺服器，也不載入模型。模型行為檢查是另一個選項：對一個你核准的 HTTPS 聊天位址與模型送出 54 個固定提示、四組探針。開始前會確認位址、模型、一把僅供此次使用的本機金鑰、請求上限，以及服務商可能向你收費。
- **還沒有放進產品的研究項目，不是現在能掃的項目。**

程式碼模式檢查使用固定的 1,493 條上游規則，加上 4 條由這個產品維護的規則。各工具的用途、版本與界線見[引擎目錄](docs/engine-catalog.md)與[掃描範圍](docs/scanning-scope.zh-TW.md)。

只檢查你擁有，或已經獲准評估的對象。應用程式不會自動修改程式碼、設定或雲端權限。

### 怎麼讀報告

讀的順序是：哪些對象有問題、優先處理哪一項、可能的影響、一個實際的下一步、做完如何確認。接著看每個對象已完成什麼、還沒做什麼。

沒有出現問題，只表示已完成的那些檢查沒有回報問題。這不是安全保證。清單、軟體組成、開放連接埠，都不算漏洞，也不算「檢查通過」。

某一項檢查失敗或沒做完時，其他已經完成的結果仍留在報告裡。未完成的項目保持可見。

技術細節展開後，可以看到原始掃描器、規則識別碼、嚴重度、證據與上游的修復說明。一般證據裡的秘密值會遮蔽。

v0.4.0 在 2026-10-04 用全部 25 個轉接器的真實支援格式，走正式報告流程，做了一份**模擬**評估，供你先看版面與用語。其中有 62 筆原始問題、42 筆盤點觀察。盤點不算漏洞。遮蔽版與完整揭露版使用同一份模擬資料。完整揭露版保留虛構的對象與帳號背景。兩版都隱藏秘密值。

- [遮蔽版 HTML](https://teddashh.github.io/ai-security-scanner/samples/v0.4.0/sample-report-redacted-zh-TW.html) · [GitHub 直接下載](https://raw.githubusercontent.com/teddashh/ai-security-scanner/main/docs/samples/v0.4.0/sample-report-redacted-zh-TW.html)
- [完整揭露版 HTML](https://teddashh.github.io/ai-security-scanner/samples/v0.4.0/sample-report-full-zh-TW.html) · [GitHub 直接下載](https://raw.githubusercontent.com/teddashh/ai-security-scanner/main/docs/samples/v0.4.0/sample-report-full-zh-TW.html)
- [四份中英文範例與產製方式](docs/samples/v0.4.0/README.zh-TW.md) · [網站下載頁](https://teddashh.github.io/ai-security-scanner/sample-reports.html?lang=zh-TW)

這份範例不是你的環境的掃描結果。

### 資料留在哪裡

案件、問題與證據存在這台電腦上。你匯出或分享報告之後，那一份檔案才會離開原本的位置。儲存 HTML，就是產生一份你之後可以自行傳送的檔案。

本機資料夾會先複製成有範圍的唯讀複本。本機專案掃描不執行專案，也不上傳專案。

網站、內部系統與雲端掃描，會連線你在確認頁核准的目標，或連線雲端供應商。模型行為檢查會把那 54 個固定提示送到你核准的服務。

連接雲端的既有設定腳本會留下持續有效的存取。這一版不會自動收回那種存取。要取消時，請到雲端供應商那邊處理。過去掃描留下的每一個檔案或憑證，也還沒有一個已確認的「全部自動清除」功能。需要清掉時，請自行核對這台電腦與雲端帳號。

### 想看更完整的說明

- [開始使用](docs/getting-started.zh-TW.md)
- [掃描範圍](docs/scanning-scope.zh-TW.md)
- [結果與匯出](docs/results-and-exports.zh-TW.md)
- [文件索引](docs/README.zh-TW.md)
- [25 個掃描器指南](https://teddashh.github.io/ai-security-scanner/scanner-guide.html?lang=zh-TW)（[GitHub 版](docs/scanner-guide.zh-TW.md)）
- [引擎目錄](docs/engine-catalog.md)：固定版本、授權、設定與執行界線
- [v0.4.0 發布紀錄](docs/release/v0.4.0.zh-TW.md)
- [目前開發狀態](docs/development-status.zh-TW.md)
- [參與開發](CONTRIBUTING.md)
- [安全政策](SECURITY.md)

本專案自行撰寫的原始碼採 [Apache-2.0](LICENSE)。第三方引擎與資料沿用各自的授權，見 [THIRD_PARTY.md](THIRD_PARTY.md)。

---

## 2. README (English)

# ai-security-scanner

[Project website](https://teddashh.github.io/ai-security-scanner/) · [繁體中文](README.zh-TW.md) · [Documentation](docs/README.md) · [Download v0.4.0](https://github.com/teddashh/ai-security-scanner/releases/tag/v0.4.0)

### What it does

ai-security-scanner is a desktop app on your own computer. You choose projects, websites, or internal systems. It runs the checks that fit those choices and gathers the results into one report.

The report is grouped by the assets you selected. Each asset shows priority, the reason an item is there, a next action, and the checks that did not run. The original scanner name, rule identifier, severity, and evidence stay in technical details you can expand.

You start, pause, and resume a scan in the desktop app. The command-line tool, and the Agent Skill for Claude Code and Codex, can help you prepare the computer, inspect a finished scan, and export the report. They cannot start a scan on their own.

Detection rules stay with the upstream tools. This product chooses the checks that apply and puts completed results into the same report. v0.4.0 connects 25 upstream tools. The full list, versions, and execution boundaries are in the [engine catalog](docs/engine-catalog.md). For a guided overview, start with the [scanner guide](https://teddashh.github.io/ai-security-scanner/scanner-guide.html).

### The first scan

Download the **v0.4.0 stable release** for this computer:

| Computer | Installer | First launch |
| --- | --- | --- |
| macOS, Apple silicon or Intel | [ai-security-scanner_0.4.0_universal.dmg](https://github.com/teddashh/ai-security-scanner/releases/download/v0.4.0/ai-security-scanner_0.4.0_universal.dmg) | Drag the app into **Applications**. It is not notarized. Before opening it, run `xattr -dr com.apple.quarantine /Applications/ai-security-scanner.app` once in Terminal. |
| Windows x86-64 | [ai-security-scanner_0.4.0_x64-setup.exe](https://github.com/teddashh/ai-security-scanner/releases/download/v0.4.0/ai-security-scanner_0.4.0_x64-setup.exe) or the [MSI](https://github.com/teddashh/ai-security-scanner/releases/download/v0.4.0/ai-security-scanner_0.4.0_x64_en-US.msi) | The installer is unsigned. If SmartScreen warns, select **More info → Run anyway**. If Windows asks to install or update WSL, allow it. WSL is a Windows component the app may need. Docker is not required. |
| Debian or Ubuntu x86-64 | [ai-security-scanner_0.4.0_amd64.deb](https://github.com/teddashh/ai-security-scanner/releases/download/v0.4.0/ai-security-scanner_0.4.0_amd64.deb) | Install with `sudo apt install ./ai-security-scanner_0.4.0_amd64.deb`. |

The first time a scan needs it, the app prepares its own scanning runtime. Checksums and the tested limits of this release are on the [v0.4.0 release page](https://github.com/teddashh/ai-security-scanner/releases/tag/v0.4.0).

Open the app and follow **New scan → Review and start → Scan progress → Results**. Start, pause, and resume happen in this window. You can reopen a run from **My scans** and compare it with a later run.

To keep a file you can send to someone, open Results, select **Save or share report**, go to **Share results**, and select **Save HTML report**. The screens are written out in [From New scan to an HTML report](docs/getting-started.md#from-new-scan-to-an-html-report).

On the same computer, Claude Code or Codex can install the app, check that the computer is ready, walk you through the screens, and after the scan, help you read the results and save the HTML report. You press Start in the app. You can ask:

> Use the ai-security-scanner skill to install the app on this computer, check that it can scan, and guide me through the desktop app. I will start the scan in the app. When it finishes, help me read the results and save the HTML report.

Skill files: [Claude Code](.claude/skills/ai-security-scanner/SKILL.md) and [Codex](.codex/skills/ai-security-scanner/SKILL.md). If the agent's sandbox blocks a download or the app, it asks you to allow that one command. A cloud agent cannot install anything on your computer. It gives you the installer link.

### What you can check

Three starting paths:

- **IT environment.** The button label is **Scan my environment**. One run can include several project folders, websites, and internal systems you are allowed to assess.
- **Website.** The button label is **Check a website**. It checks one exact web origin with a reviewed set of website checks.
- **Local project.** The button label is **Check code or an AI project**. The app copies a bounded, read-only snapshot and looks for secrets, known vulnerable dependencies, risky code, and unsafe configuration. It does not execute the project or upload it.

Cloud is an advanced choice, not a fourth path beside these three. Current security checks for AWS, Azure, and GCP cover identity and access configuration for the account you select. They are not a full audit of that cloud. Azure and GCP use that limited identity-and-access set. AWS adds further checks that stay inside identity and access, plus tools that only list identities. Microsoft 365 checks compare configuration with a fixed baseline.

What runs depends on the asset:

- **Local project.** Code patterns, offline secret matching, known package vulnerabilities matched against pinned offline data, and infrastructure or configuration files. A list of software components can be saved with the report. That list is not a vulnerability result. If you select Kubernetes manifests, those files can be checked offline. Node configuration is checked from an immutable copy, without mounting the live machine with elevated rights. Work that cannot be finished is marked incomplete.
- **Website and internal systems.** Website checks stay on the approved origin and within a bounded read-only set. Internal systems are contacted only at the hosts and ports you confirm. An open port, and the fact that a site responds, are observations. They are not vulnerabilities. An optional passive website check can be turned on for one approved origin. It crawls pages on that origin. It does not submit forms or send attack payloads.
- **Optional checks around AI.** Workflow inventory reads one approved project snapshot. It understands LangGraph, CrewAI, n8n, OpenAI Agents, and AutoGen. It does not run the workflow or contact a model. An MCP configuration check reads one approved snapshot for hardcoded credentials and tool permissions that are broader than they need to be. It does not start a server or load a model. Model-behavior checks are a separate option: 54 fixed prompts, in four probes, sent to one HTTPS chat address and model you approve. Before they run, you confirm the address, the model, a one-time local key, the request limits, and that the provider may charge you.
- **Research candidates that are not in the product are not things this release can scan.**

Code-pattern checks use a pinned upstream set of 1,493 rules, plus four rules maintained with this product. Purpose, version, and boundary for each tool are in the [engine catalog](docs/engine-catalog.md) and [Scanning scope](docs/scanning-scope.md).

Use network and cloud checks only on assets you own or are authorized to assess. The app does not change your code, configuration, or cloud permissions for you.

### Reading the report

Read in this order: which assets have problems, what to handle first, why it matters, one practical next action, and how to tell whether that action worked. Then see what finished and what was not tested for each asset.

A result with nothing to report covers the checks that finished. It is not a statement that the asset is secure. Inventory, a software-component list, and open ports are not vulnerabilities, and they are not a pass.

When one check fails or stops, finished results from the others stay in the report. Unfinished checks stay visible.

Expand technical details for the original scanner, rule identifier, severity, evidence, and the upstream remediation note. Secret values are masked in ordinary evidence.

On 2026-10-04, v0.4.0 published a **simulated** assessment. It uses the real supported formats of all 25 adapters and the production report pipeline, so you can see the layout and the wording. It contains 62 original findings and 42 inventory observations. Inventory is not counted as vulnerabilities. The redacted and fully disclosed editions use the same simulated facts. Full disclosure keeps fictional asset and account context. Secret values stay masked in both.

- [Redacted HTML](https://teddashh.github.io/ai-security-scanner/samples/v0.4.0/sample-report-redacted-en.html) · [Direct GitHub download](https://raw.githubusercontent.com/teddashh/ai-security-scanner/main/docs/samples/v0.4.0/sample-report-redacted-en.html)
- [Fully disclosed HTML](https://teddashh.github.io/ai-security-scanner/samples/v0.4.0/sample-report-full-en.html) · [Direct GitHub download](https://raw.githubusercontent.com/teddashh/ai-security-scanner/main/docs/samples/v0.4.0/sample-report-full-en.html)
- [All four bilingual examples and the generation method](docs/samples/v0.4.0/README.md) · [Website downloads](https://teddashh.github.io/ai-security-scanner/sample-reports.html)

That sample is not a scan of your environment.

### Where the data stays

Cases, findings, and evidence stay on this computer. A report leaves that place when you export or share it. Saving HTML creates a file you can send yourself.

Local folders are copied into bounded read-only snapshots. A local project scan does not execute the project or upload it.

A website, internal-system, or cloud scan contacts the targets you approved on the review screen, or the cloud provider. A model-behavior check sends those 54 fixed prompts to the service you approved.

The existing scripts that connect a cloud account leave access in place. This release does not revoke that access automatically. To remove it, act at the cloud provider. Automatic removal of every file or credential left by earlier runs is not an established feature. If you need that cleaned up, check this computer and the cloud account yourself.

### Deeper documentation

- [Getting started](docs/getting-started.md)
- [Scanning scope](docs/scanning-scope.md)
- [Results and exports](docs/results-and-exports.md)
- [Documentation index](docs/README.md)
- [Guide to all 25 scanners](https://teddashh.github.io/ai-security-scanner/scanner-guide.html) ([GitHub edition](docs/scanner-guide.md))
- [Engine catalog](docs/engine-catalog.md): pinned versions, licenses, profiles, and execution boundaries
- [v0.4.0 release record](docs/release/v0.4.0.md)
- [Development status](docs/development-status.md)
- [Contributing](CONTRIBUTING.md)
- [Security policy](SECURITY.md)

Project-owned source is licensed under [Apache-2.0](LICENSE). Third-party engines and data keep their own licenses. See [THIRD_PARTY.md](THIRD_PARTY.md).

---

## 3. Website copy

### 繁體中文

#### 首屏

眉題：開源桌面應用程式 · 正式版 0.4.0

標題：檢查你指定的範圍，報告留在這台電腦上。

說明：選擇資訊環境、一個網站，或一個本機專案。在桌面應用程式裡開始掃描。報告會告訴你先處理什麼、為什麼、下一步，以及哪些項目沒有檢查。

主要按鈕：下載 v0.4.0 正式版

次要按鈕：看助理能幫什麼

首屏附註：

- 開始、暫停與繼續都在桌面應用程式裡。
- 本機專案使用唯讀複本。應用程式不執行專案，也不上傳專案。
- 已完成的檢查沒有問題，只說明那些檢查。這不是安全保證。

安裝一行：v0.4.0 提供 Windows 的 .exe 與 MSI（未簽章，SmartScreen 可能警告）、macOS Universal .dmg（未經 Apple 公證，第一次開啟前執行一行 `xattr`）、Debian／Ubuntu 的 .deb。應用程式會自己準備掃描環境，不需要另外安裝 Docker。Windows 若要求安裝或更新 WSL，那是應用程式可能用到的系統元件。

連結：[安裝步驟](docs/getting-started.zh-TW.md) · [發布說明](docs/release/v0.4.0.zh-TW.md)

這一版新增的具名能力：可選的被動網站檢查（ZAP）、離線的 AI 工作流程盤點（Agentic Radar）、以及有上限的模型行為檢查（Garak）。其餘變更見發布說明。

#### 三個步驟

小標：你選定對象。應用程式執行適用的檢查。你讀一份報告。

01 選定範圍並確認連線
選擇本機資料夾、一個完整的網站網址，或精確的內部主機。雲端帳號是進階選項。在**確認後開始**核對每一個允許連線的目標與連接埠。只放入你擁有或已獲准評估的對象。

02 在桌面應用程式裡執行
按下開始之後，應用程式只跑適用於這些對象的檢查。暫停與繼續也在同一個視窗。命令列與 Agent Skill 可以準備環境、查看結果、匯出報告。它們不能自己啟動掃描。某一項檢查停住時，已經完成的結果仍保留。

03 讀報告，再決定要不要帶出門
報告依檢查對象排列：優先順序、原因、下一步、尚未檢查的項目。技術細節可以展開。要帶走時，走**保存或分享報告 → 分享結果 → 儲存「HTML 報告」**。在你匯出或分享之前，報告留在這台電腦。

#### 做得到的事

小標：三條基本路徑，加上一組進階的雲端檢查。

資訊環境
畫面上寫「掃描公司環境」。同一輪納入多個專案、網站與已核准的內部系統。內部系統只連線確認頁上的主機與連接埠。

網站
畫面上寫「檢查網站」。一個精確來源，一組已審過、範圍有限的網頁檢查。可另外打開被動檢查：爬取該來源的頁面，不送出表單，也不送出攻擊內容。

本機專案
畫面上寫「檢查程式碼或 AI 專案」。在唯讀複本上查看秘密、已知有漏洞的套件、有風險的程式碼與設定。不執行專案，不上傳專案。軟體組成清單可以保存，清單不是漏洞。

進階：雲端與 Microsoft 365
AWS、Azure、GCP 目前只檢查你指定帳號的身分與存取設定。這不是完整的雲端稽核。Azure 與 GCP 使用這組有限檢查。AWS 另有幾項仍限於身分與存取的檢查；其中一部分只列出身分，那些列出來的資料是盤點，不是漏洞。Microsoft 365 對照一份固定的安全設定基準。

連接雲端的設定腳本會留下持續有效的存取。這一版不會自動收回。過去每一次留下的檔案，也沒有已確認的全部自動清除。

可另外打開的檢查
AI 工作流程盤點只讀專案複本，不執行流程，也不連線模型。MCP 設定只做靜態檢查，不啟動伺服器，也不載入模型。模型行為檢查會對你核准的一個 HTTPS 模型位址送出 54 個固定提示。開始前你要確認位址、模型、一次性本機金鑰、請求上限，以及服務商可能收費。

觀察，不是漏洞
開放的連接埠、網站是否回應、軟體組成、雲端身分清單，都跟漏洞分開列出。

v0.4.0 共 25 個上游工具。這裡不逐項展開。名稱、版本、實際啟用的功能與界線見 [25 個掃描器指南](https://teddashh.github.io/ai-security-scanner/scanner-guide.html?lang=zh-TW) 與 [引擎目錄](docs/engine-catalog.md)。

#### 報告長什麼樣子

小標：先看一份模擬報告，再掃描你自己的範圍。

v0.4.0 · 2026-10-04。25 個轉接器的真實格式，經正式報告流程產生的模擬評估。62 筆原始問題，42 筆盤點觀察。盤點不算漏洞。這不是某個真實環境的掃描結果。

遮蔽版保留問題與下一步，拿掉可識別對象與背景。完整揭露版看得到虛構名稱、端點與帳號背景。兩版的秘密值都保持隱藏。

- [閱讀遮蔽版](https://teddashh.github.io/ai-security-scanner/samples/v0.4.0/sample-report-redacted-zh-TW.html) · [下載 HTML](https://raw.githubusercontent.com/teddashh/ai-security-scanner/main/docs/samples/v0.4.0/sample-report-redacted-zh-TW.html)
- [閱讀完整揭露版](https://teddashh.github.io/ai-security-scanner/samples/v0.4.0/sample-report-full-zh-TW.html) · [下載 HTML](https://raw.githubusercontent.com/teddashh/ai-security-scanner/main/docs/samples/v0.4.0/sample-report-full-zh-TW.html)
- [四份範例與產製方式](https://teddashh.github.io/ai-security-scanner/sample-reports.html?lang=zh-TW)

你自己的報告會依這份結構書寫：先是要處理的問題，再是已完成卻沒有問題的檢查，再是沒有做完或沒有做的項目。原始證據在技術細節裡。

#### 人工智慧助理能幫什麼

小標：同一台電腦上的 Claude Code 或 Codex，可以當嚮導。掃描仍由你開始。

助理用同一份 ai-security-scanner skill，幫忙安裝 v0.4.0、確認這台電腦能否掃描、沿桌面應用程式的畫面引導、解釋結果、儲存 HTML 報告。

開始、暫停與繼續在應用程式裡，由你操作。隔離環境擋住某一個指令時，助理會請你允許那一次。雲端助理無法在你的電腦安裝軟體，只會給你安裝檔連結。

- [Claude Code Skill](.claude/skills/ai-security-scanner/SKILL.md)
- [Codex Skill](.codex/skills/ai-security-scanner/SKILL.md)
- [助理需要的環境](docs/getting-started.zh-TW.md#透過-agent-skill-使用)

#### 下一步

標題：先下載應用程式，再在確認頁看清楚這一次會連線什麼。

說明：Linux、macOS、Windows 都是 v0.4.0 正式版。安裝之後打開應用程式，核對範圍，由你按下開始。

主要按鈕：下載 v0.4.0 正式版

次要連結：閱讀開始使用

頁尾：專案原始碼採 Apache-2.0。第三方工具保留各自授權。

### English

#### Hero

Eyebrow: Open source desktop app · stable release 0.4.0

Title: Check the scope you name. Keep the report on this computer.

Deck: Choose an IT environment, one website, or a local project. Start the scan in the desktop app. The report tells you what to handle first, why it is there, what to do next, and what was not tested.

Primary button: Download the v0.4.0 stable release

Secondary button: See what an assistant can do

Notes under the title:

- You start, pause, and resume in the desktop app.
- A local project is scanned from a read-only copy. The app does not execute the project or upload it.
- Nothing to report means those finished checks had nothing to report. It is not a security guarantee.

Install line: v0.4.0 ships a Windows .exe and MSI (unsigned; SmartScreen may warn), a macOS Universal .dmg (not notarized; run one `xattr` command before the first launch), and a Debian/Ubuntu .deb. The app prepares its own scanning runtime. Docker is not required. If Windows asks to install or update WSL, that is a system component the app may need.

Links: [Install steps](docs/getting-started.md) · [Release notes](docs/release/v0.4.0.md)

Named additions in this release: optional passive website checks (ZAP), offline AI-workflow inventory (Agentic Radar), and bounded model-behavior checks (Garak). Other changes are in the release notes.

#### Three steps

Label: You name the assets. The app runs the checks that fit. You read one report.

01 Choose the scope and confirm who may be contacted
Pick local folders, one full website URL, or exact internal hosts. A cloud account is an advanced choice. On **Review and start**, check every target and port the scan is allowed to contact. Include only assets you own or are authorized to assess.

02 Run it in the desktop app
After you press Start, the app runs the checks that apply to those assets. Pause and resume stay in the same window. The command-line tool and the Agent Skill can prepare the computer, inspect results, and export the report. They cannot start the scan. If one check stops, finished results stay.

03 Read the report, then decide whether it leaves the computer
The report is grouped by asset: priority, reason, next action, and checks that did not run. Technical details expand. To take a copy with you, use **Save or share report → Share results → Save HTML report**. Until you export or share it, the report stays on this computer.

#### Capabilities

Label: Three starting paths, plus an advanced set of cloud checks.

IT environment
The button reads **Scan my environment**. One run can hold several projects, websites, and approved internal systems. Internal systems are contacted only at the hosts and ports on the review screen.

Website
The button reads **Check a website**. One exact origin, one reviewed and bounded set of web checks. An optional passive check crawls pages on that origin. It does not submit forms or send attack payloads.

Local project
The button reads **Check code or an AI project**. On a read-only copy, it looks for secrets, known vulnerable packages, risky code, and unsafe configuration. It does not execute the project or upload it. A software-component list can be kept. The list is not a vulnerability result.

Advanced: cloud and Microsoft 365
Current AWS, Azure, and GCP security checks look at identity and access configuration for the account you select. They are not a full audit of that cloud. Azure and GCP use this limited set. AWS adds further checks that remain inside identity and access. Some of those AWS tools only list identities. Those lists are inventory, not vulnerabilities. Microsoft 365 checks compare configuration with a fixed baseline.

Scripts that connect a cloud account leave access in place. This release does not revoke that access automatically. Automatic removal of every file left by earlier runs is not an established feature.

Checks you turn on separately
AI workflow inventory reads a project copy. It does not run the workflow or contact a model. An MCP configuration check is static. It does not start a server or load a model. Model-behavior checks send 54 fixed prompts to one HTTPS model address you approve. Before they run, you confirm the address, the model, a one-time local key, the request limits, and that the provider may charge you.

Observations are not vulnerabilities
Open ports, whether a site responds, software-component lists, and cloud identity lists are kept apart from vulnerabilities.

v0.4.0 connects 25 upstream tools. They are not listed one by one here. Names, versions, enabled features, and boundaries are in the [scanner guide](https://teddashh.github.io/ai-security-scanner/scanner-guide.html) and the [engine catalog](docs/engine-catalog.md).

#### Report example

Label: Read a simulated report before you scan your own scope.

v0.4.0 · 2026-10-04. A simulated assessment in the real formats of all 25 adapters, processed through the production report pipeline. 62 original findings and 42 inventory observations. Inventory is not counted as vulnerabilities. This is not a scan of a real environment.

The redacted edition keeps findings and next actions, and removes identifying asset and context fields. The fully disclosed edition shows fictional names, endpoints, and account context. Secret values stay masked in both.

- [Read the redacted report](https://teddashh.github.io/ai-security-scanner/samples/v0.4.0/sample-report-redacted-en.html) · [Download HTML](https://raw.githubusercontent.com/teddashh/ai-security-scanner/main/docs/samples/v0.4.0/sample-report-redacted-en.html)
- [Read the fully disclosed report](https://teddashh.github.io/ai-security-scanner/samples/v0.4.0/sample-report-full-en.html) · [Download HTML](https://raw.githubusercontent.com/teddashh/ai-security-scanner/main/docs/samples/v0.4.0/sample-report-full-en.html)
- [All four examples and how they were generated](https://teddashh.github.io/ai-security-scanner/sample-reports.html)

A report from your own scan follows the same structure: problems to handle, finished checks with nothing to report, then work that did not finish or did not run. Original evidence is in technical details.

#### What an AI assistant can do

Label: Claude Code or Codex on this computer can guide you. You still start the scan.

The assistant uses the same ai-security-scanner skill to install v0.4.0, check that this computer can scan, walk you through the desktop app, explain the results, and save the HTML report.

You start, pause, and resume in the app. If a sandbox blocks one command, the assistant asks you to allow that command. A cloud assistant cannot install software on your computer. It gives you the installer link.

- [Claude Code Skill](.claude/skills/ai-security-scanner/SKILL.md)
- [Codex Skill](.codex/skills/ai-security-scanner/SKILL.md)
- [What the agent needs](docs/getting-started.md#use-with-an-agent-skill)

#### Call to action

Title: Download the app, then read the review screen before anything is contacted.

Deck: The Linux, macOS, and Windows builds are the v0.4.0 stable release. After installation, open the app, check the scope, and press Start yourself.

Primary button: Download the v0.4.0 stable release

Secondary link: Read getting started

Footer: Project source is Apache-2.0. Third-party tools keep their own licenses.

---

## 4. Report wording

These are proposed strings for the product report. Brackets are structural labels, not text a reader sees. No sample finding is invented here.

### 繁體中文

**已完成，且有問題**

標題：這次掃描已完成，已完成的檢查裡有需要處理的問題

內文：問題依你選取的對象排列，優先順序高的在前面。每一項寫出原因、一個實際的下一步，以及做完後如何確認。原始掃描器的名稱、規則識別碼、嚴重度與證據在技術細節中。清單、軟體組成與開放連接埠另列，不算漏洞。沒有執行的檢查列在涵蓋範圍。

**已完成，沒有問題**

標題：已完成的檢查沒有回報問題

內文：這句話只涵蓋已經跑完的檢查。它不是安全保證，也不是評估通過。請一併閱讀涵蓋範圍。若其中有盤點、軟體組成或開放連接埠，那些是觀察，不是「沒有漏洞」。

**只完成一部分**

標題：這次掃描只完成一部分

內文：已經完成的結果都保留在這份報告裡。沒有完成的檢查仍列出來，知道原因時一併寫出原因。未完成不是通過。

**涵蓋範圍**

標題：涵蓋範圍

內文：每個對象分開標示三件事：已完成且有問題、已完成且沒有問題、尚未檢查。只做清單或只確認連得上的項目，標成觀察。觀察包含軟體組成、開放的連接埠、網站是否回應，以及雲端身分清單。若這次包含雲端檢查，範圍是你選取帳號的身分與存取設定，不是整個雲端環境的稽核。

狀態用詞：

- 已完成的檢查發現問題
- 已完成的檢查沒有發現問題
- 只完成一部分
- 尚未檢查
- 觀察，不是漏洞

**下一步**

標題：下一步

內文：這是針對這個問題、可以實際去做的動作，加上做完後的確認方式。動作由你自己執行。應用程式不會修改程式碼、設定或雲端權限。上游掃描器的原始修復說明放在技術細節，供你對照。

**技術細節**

標題：技術細節

內文：這裡保留原始掃描器、規則識別碼、原始嚴重度、證據，以及上游的修復說明。一般證據中的秘密值會遮蔽。展開這些細節是為了核對，上方的白話說明仍然是閱讀報告的起點。

**正式頁尾**

ai-security-scanner 0.4.0 在這台電腦上產生本報告。報告存放於本機；唯有在你匯出或分享之後，該份檔案才離開這個位置。已完成的檢查不是完整的安全評估。沒有回報問題，只表示那些已完成的檢查沒有回報問題。網路與雲端檢查只連線本次已核准的目標或雲端供應商。連接雲端時，設定腳本會留下持續有效的存取；此版本不會自動收回該存取。此版本也沒有已確認的功能，可自動清除過去每次執行留下的全部檔案與憑證。請只將你擁有或已獲授權評估的對象納入掃描。本報告中的下一步不會被自動執行。

### English

**Completed, with findings**

Heading: This scan finished. The completed checks reported problems that need a decision.

Body: Problems are grouped by the assets you selected, with the highest priority first. Each one gives a reason, one practical next action, and a way to check whether that action worked. The original scanner name, rule identifier, severity, and evidence are in technical details. Inventory, software-component lists, and open ports are listed apart from vulnerabilities. Checks that did not run are listed under coverage.

**Completed, with nothing to report**

Heading: The completed checks reported no problems.

Body: This sentence covers only the checks that finished. It is not a security guarantee, and it is not a passed assessment. Read the coverage section with it. Inventory, a software-component list, or an open port is an observation. It does not mean there is no vulnerability.

**Partial completion**

Heading: This scan finished only in part.

Body: Results from checks that finished are kept in this report. Checks that did not finish stay listed, with the reason when the reason is known. Unfinished work is not a pass.

**Coverage**

Heading: Coverage

Body: Each asset is marked in three ways: completed with problems, completed with nothing to report, or not tested. Work that only builds a list, or only checks that something can be reached, is marked as an observation. Observations include software components, open ports, whether a site responds, and cloud identity lists. When this run included cloud checks, the scope is identity and access configuration for the account you selected. It is not an audit of the whole cloud environment.

Status labels:

- Problems in completed checks
- No problems in completed checks
- Finished only in part
- Not tested
- Observation, not a vulnerability

**Next steps**

Heading: Next step

Body: This is a practical action for this problem, plus a way to check the result after you do it. You carry out the action. The app does not change code, configuration, or cloud permissions. The upstream scanner’s original remediation note is in technical details, for comparison.

**Technical details**

Heading: Technical details

Body: This section keeps the original scanner, rule identifier, original severity, evidence, and the upstream remediation note. Secret values are masked in ordinary evidence. Open this section to verify the result. The plain-language section above remains the place to start reading.

**Formal footer**

ai-security-scanner 0.4.0 produced this report on this computer. The report is stored locally. A copy leaves this computer only when you export or share it. Completed checks are not a full security assessment. A report of no problems means those completed checks reported none. Network and cloud checks contacted only the targets approved for this run, or the cloud provider. Cloud setup leaves lasting access in place. This release does not revoke that access automatically. This release also has no established feature that automatically removes every file and credential left by earlier runs. Include only assets you own or are authorized to assess. Next steps in this report are not carried out automatically.

---

## 5. Editorial rationale

The current pages already contain the right raw facts: version 0.4.0, the installer warnings, the 25 tools, the local report, the simulated sample of 62 findings and 42 inventory observations, and a careful split between vulnerabilities and inventory. A reader in management, the humanities, or general IT still has to assemble the decision from scanner names.

This draft leads with the decision. What will be read, what may be contacted, what stays on the computer, and what the quiet result does not mean. Scanner names remain available, one layer down, because the evidence has to stay checkable. The engine matrix, star counts, digests, and the Grype fixture count of 81 move behind the scanner guide and the engine catalog. Star counts dated 2026-10-04 are real and easy to misread as a rating.

Three published impressions needed a direct correction. The hero can be read as if an Agent Skill runs the scan. Cloud sits in the same visual row as a normal environment, wider than the identity-and-access checks this release actually runs. A chip that only says “Checked” is softer than the sentence “no problems in completed checks.” The draft states the positive behavior, then the limit, in words a non-specialist can repeat to a colleague.

I did not add a customer story, a duration, a coverage percentage, or a promise that the next action will fix the issue. Installer names, the unsigned and notarization status, the WSL prompt, and “Docker is not required” are unchanged. WSL is explained in one line so it does not contradict the Docker sentence. Pause and resume are described without invented button labels. Developer build commands are left to the existing docs; if the README must still carry them, keep the current block as published.

The cloud-access sentences are the most deliberate addition. The source describes reconnecting an expired read-only connection. It does not say the access is removed. Setup that leaves persistent access, and the absence of a proven full cleanup, are now visible at the moment a person decides to connect a cloud account.

### Source claims to clarify

1. Several pages say the desktop app **or** Claude Code and Codex Agent Skills run the scanners. Confirm the public rule: only the desktop app can start, pause, and resume. The CLI and skills prepare, inspect, and export.
2. The English button **Scan my environment** and the Chinese button **掃描公司環境** do not say the same thing. “Company” excludes a lab, a school, and a personal project. Preferred explanatory name in this draft: IT environment / 資訊環境. Confirm the label to ship.
3. The pipeline line lists cloud beside repositories, websites, endpoints, containers, and Kubernetes. Confirm that AWS, Azure, and GCP remain limited identity-and-access configuration checks, and that the page must not be read as a cloud audit.
4. Prowler is the only listed security check that names Azure and GCP. ScoutSuite, Cloudsplaining, CloudQuery, and Steampipe are described as AWS. Confirm the reader-facing split: Azure and GCP get the narrow profile only; extra AWS tools are still identity-and-access or inventory.
5. CloudQuery and Steampipe return inventory. Confirm report templates never promote those rows into findings.
6. “Expired read-only connections offer reconnect-and-rescan” does not say access is revoked. Existing setup scripts create persistent access. Confirm there is no automatic cloud permission revocation in 0.4.0, and name what a person must delete at the provider.
7. Automatic cleanup of every historical artifact is not established. Confirm what earlier runs leave behind: snapshots, runtime files, keys, cloud roles, or report exports.
8. The v0.3.1 record still mentions a Microsoft 365 rerun waiting on the owner. Confirm whether that rerun happened before 0.4.0. Until it has, avoid copy that sounds as if the M365 profile was fully re-verified.
9. “More reliable coverage” and “exact-grant Greenbone recovery” are not yet sentences a reader can test. Confirm the observable behavior before they appear outside the release record.
10. The website preview chips (“Checked”, the example assets, “2 priority actions”, “1 coverage gap”) can be read as a real result. The dated sample is a different thing: simulated, 62 findings, 42 inventory observations. Confirm the preview is labeled as layout only.
11. The controlled repository scan recorded 81 Grype findings for pin `0.117.0-4`. Confirm this stays in the engine catalog, with the fixture label, and does not appear as an expected count.
12. GitHub star counts were checked on 2026-10-04 (UTC). Confirm they stay off the primary page for this audience. They are not a security rating.
13. Semgrep’s “1,493 pinned legacy upstream rules” needs a plain meaning. Does legacy mean a deliberately pinned older pack that is still the supported set, or a pack the project expects to replace?
14. TruffleHog: the README says network verification is disabled. The website says credential verification and engine networking are disabled. Confirm these are the same boundary.
15. ZAP is described as passive, one approved origin, no form submission and no attack payloads. Confirm that sentence is still exactly true for the shipped profile.
16. Garak sends 54 fixed prompts in four probes to an approved HTTPS model, with a one-time local key, request limits, and provider charges. Confirm the request contains only those fixed prompts and the approved address, and that a local project is not uploaded as part of this check.
17. Agentic Radar’s short website line (“agents, tools, and workflow connections”) is narrower than the README list: LangGraph, CrewAI, n8n, OpenAI Agents, AutoGen, offline, no execution, no model contact. Confirm the five-framework list is the one to publish.
18. kube-bench uses an immutable node-configuration snapshot and can leave manual checks incomplete. Kubescape reads selected local manifests. Confirm nobody can read this as a live review of a running cluster.
19. “Save or share report” can sound like an upload. Confirm the shipped action only writes a local HTML file, unless some other share path exists.
20. The app “prepares its own scanning runtime.” Confirm whether that first preparation downloads components, so privacy copy can say so if it does. This draft does not claim a download that the source does not name.
21. “Legacy” packaging claims to leave untouched: 0.4.0 is the stable version; macOS is not notarized; Windows installers are unsigned; Docker is not required; WSL may be requested on Windows.
22. Research-only candidates are not current capabilities. Confirm the public tool count remains 25, with no candidate shown as available.
