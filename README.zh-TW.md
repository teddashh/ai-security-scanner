# ai-security-scanner

[English README](README.md)

`ai-security-scanner` 是一套「資料優先留在本機」的桌面應用程式，把一次資安檢查整理成可重複、可交接、可複驗的案件。你只要先說想檢查什麼，再確認精確範圍；產品會在本機隔離環境執行適用的開源引擎，以人話呈現問題與證據，匯出可交接的案件包，並在修復後比較前後差異。

它**不會**保證組織絕對安全、不會取代合格的資安專業人員，也不會產生 ISO 27001 或 NIST 認證分數。框架對照只是方便討論問題的座標，不是合規結論。「沒有發現問題」也不等於「所有地方都檢查過」。

> **目前狀態：**`v0.2.0` 原始碼候選版本已完成跨平台自動建置與全新主機資格驗證；規格要求的 IAM 新手真人首次使用研究，以及研究之後的正式品質檢查與程式碼審查尚未完成。因此目前尚無公開的 `v0.2.0` 標籤或 GitHub Release。原始碼文字、截圖、展示資料與自動測試都不能冒充真人研究證據。

## 先從你想檢查的東西開始

不需要先挑掃描器名稱。選一個最像你情況的入口即可：

| 使用情境 | 你需要準備什麼 | 產品會做什麼，以及不會做什麼 |
| --- | --- | --- |
| 已經架好的網站或 API | 精確網址、你可以測試它的證明，以及允許的掃描強度 | 只對核准服務執行有限目標與速度的連線及弱點檢查；不測商業邏輯，也不能取代人工滲透測試。 |
| 外部 IP 或網域 | 精確公開 IP／網域、所有權或授權證明、排除項目 | 只檢查核准目標；不自行擴張到相鄰 IP，也不把無法連線說成安全。 |
| 公司內部 IT 環境 | 精確內部目標或設定快照、可連到目標的位置、掃描限制與 IT 負責人同意 | 對已核准系統做有限檢查，或在本機分析附加證據；不掃一個模糊的整段私有網路、不裝 agent、不改設備。 |
| 寫好的程式碼 | 本機唯讀專案或程式碼儲存庫快照 | 在本機找高風險寫法與秘密模式；不上傳程式碼、不推送修改，也不拿找到的秘密登入線上服務。 |
| 基礎設施程式碼（IaC） | Terraform、CloudFormation、Kubernetes YAML 或其他本機 IaC 專案 | 檢查選定檔案裡的危險預設值與設定錯誤；不部署、不改檔案。 |
| AWS、Azure、GCP 或 Microsoft 365 | 一個精確帳號、訂閱、專案或租用戶，以及檢查許可 | 透過雲端服務商官方的短效唯讀登入路徑檢查；不把管理員權限交給掃描器，也不修改雲端設定。 |
| 容器映像 | 一個帶有唯一內容摘要的本機映像匯出檔 | 用固定離線資料找已知弱點套件並產生軟體內容清單（SBOM）；不執行映像、不登入映像倉庫，也不掃意義不明的 `latest`。 |
| Kubernetes 設定 | 選定的 YAML 設定檔，或經核准且不可變更的節點設定快照 | 檢查工作負載安全設定與有限範圍的節點 CIS 安全基準；不要求叢集管理員權限、不掛載線上主機，也不是持續監控。 |

選擇使用情境只會準備下一個設定畫面，並不等於授權掃描。真正接觸任何系統前，應用程式仍會要求精確目標、所有權、允許的活動與限制。同一案件之後仍可加入其他檢查，所以簡化入口不會縮減產品範圍。

## 一個完整案件會怎麼進行

1. 選擇想檢查的東西並建立案件。
2. 加入精確的本機檔案、目標清單或雲端服務商資料來源。
3. 逐項確認所有權，以及每個目標允許哪種接觸方式。
4. 讓應用程式只選擇符合資產與權限的引擎。
5. 把原始證據與整理後的問題一起保留在本機案件。
6. 先看緊急問題，但不隱藏完整問題清單。
7. 清楚區分已掃描、未完成、未授權、不適用與未知範圍。
8. 匯出本機案件包，交給獨立資安專業人員。
9. 修復後重新執行同一案件，比較已解決、仍存在、新增、改變與無法複驗的結果。

「已檢查資料來源，但裡面沒有資產」與「根本沒連資料來源」是兩件事。掃描範圍紀錄會保留這個差別，絕不把未知範圍塗成綠色。

## 隱私、憑證與掃描授權

- 案件資料與原始證據留在工作站；只有使用者主動匯出時才會離開。
- 掃描引擎不會收到管理員憑證。
- 雲端存取優先採服務商官方短效唯讀授權。若需要建立暫時權限，會由獨立的一次性授權程序處理，不會交給掃描器。
- 公開及內部目標都需要可追溯、逐項的授權紀錄。發現一個目標不代表自動取得主動測試許可。
- 引擎以不具管理員權限的隔離容器執行，輸入唯讀，不能控制 Docker、不能讀取主機根目錄，並限制資源與可連線目的地。
- 產品提供說明與複驗建議，不提供一鍵修復。
- AI 整合可以解釋狀態，或使用受限的本機 CLI；不能擴大掃描範圍、接收秘密、替使用者授權目標，或繞過相同產品控制。

在敏感環境使用前，請閱讀[威脅模型](docs/threat-model.md)、[雲端服務商授權契約](docs/provider-authorization.md)與[安全政策](SECURITY.md)。安全漏洞請依 `SECURITY.md` 回報，不要開公開議題。

## 產品管理的本機隔離環境

安裝版桌面應用程式會攜帶固定版本的 Podman machine client 與各平台 helper。使用者不用另外安裝 Docker、Podman、Python、PowerShell module、弱點資料庫或個別引擎 CLI。

首次設定會先驗證隨附執行環境與主機必要條件，確認後才下載以校驗碼鎖定的機器映像，再初始化不具管理員權限的私有隔離環境，並逐步顯示狀態。下載可取消及續傳。應用程式不會修改系統 `PATH`、執行套件管理器、啟用作業系統功能，或為此執行環境要求管理員權限。

在 Windows 上，如果 WSL 檢查失敗，設定卡片只會顯示一個人話下一步：安裝 WSL、開啟必要元件、更新 WSL、重新啟動 Windows，或重新檢查。畫面可複製適用的 Microsoft 指令，例如 `wsl --install --no-distribution` 或 `wsl --update`，並連到 Microsoft 說明；應用程式本身不會執行這些需要系統權限的變更。因此 WSL 尚未就緒時，設定會在約 257 MB 的機器映像開始下載前停止。

| 桌面系統 | 產品管理的執行環境 | 主機必要條件 |
| --- | --- | --- |
| Linux x86-64 | 不具管理員權限的 Podman 機器與隨附 QEMU | 無；能用 KVM 時會使用，否則改用較慢的 QEMU 軟體模擬。 |
| macOS Intel 或 Apple silicon | 不具管理員權限的 Podman 機器與 Apple 虛擬化 | 支援 Apple 虛擬化的 macOS 版本。 |
| Windows x86-64 | 不具管理員權限的 Podman 機器與 WSL | WSL 2；如果尚未可用，設定會在映像下載前停止並顯示精確 Windows 下一步，應用程式不會自行啟用選用功能。 |

Docker 或使用者已安裝的 Podman 只能作為明確標示的相容執行環境；它們不是必要條件，也不會偷偷與產品管理的執行環境混用。完整生命週期、恢復、驗證與精確清理規則請看[產品管理執行環境契約](docs/managed-runtime.md)。

## 已納入的檢查類型

`v0.2.0` 必要清單涵蓋下列端到端引擎家族：

- 雲端資產盤點：CloudQuery、Steampipe；
- 雲端設定與身分權限：Prowler、ScoutSuite、Cloudsplaining；
- Microsoft 365：ScubaGear、Maester；
- 外部攻擊面與網路弱點：Naabu、httpx、Nuclei、Greenbone；
- 程式碼與秘密：Semgrep、Gitleaks、TruffleHog；
- 基礎設施程式碼：Checkov、KICS；
- 容器套件與軟體內容清單（SBOM）：Trivy、Grype、Syft；
- Kubernetes 安全設定：Kubescape、kube-bench。

每個引擎都是獨立授權的程序或容器，並具有固定檔案、規則與資料來源紀錄、權限設定、結果解析器、證據路徑、掃描範圍行為、匯出對照與複驗路徑。機器可讀的 [`engines/catalog.json`](engines/catalog.json) 才是引擎是否已整合、可執行、適用某雲端服務商、仍在知識期限內，以及可採何種散布方式的權威來源。只有程式碼儲存庫網址或友善說明，不能把被阻擋的項目升級成可用。

詳情請看[引擎清單指南](docs/engine-catalog.md)與[第三方清單](THIRD_PARTY.md)。第三方程式碼、映像、範本、規則、資料來源與弱點資料庫保留原授權，不會被本專案重新授權。

## 展示模式

用瀏覽器執行 Vite 介面時會顯示清楚標記的合成展示資料。它不會啟動掃描器，也不代表真實評估。原生桌面版本才會使用 Rust 本機案件服務與產品管理的執行環境。

## 本機開發

原始碼 checkout 的必要條件：

- Node.js 24 以上；
- Rust 1.98，與 release/CI toolchain 相同；
- 編譯桌面 shell 時所需的 Tauri 平台 build dependencies。

安裝 dependencies 並驗證 web 介面：

```sh
npm ci
npm run test:frontend
npm run typecheck
npm run build
```

不依賴桌面系統 library，執行 Rust core 與 CLI 測試：

```sh
cargo test --workspace --no-default-features --features cli
```

啟動瀏覽器 demo：

```sh
npm run dev
```

安裝 Tauri 平台套件後，啟動 native desktop 開發版本：

```sh
npm run tauri dev
```

## 本機 CLI

每個桌面安裝程式都會把 `ai-security-scanner-cli` 放在應用程式執行檔旁，但不會加入 `PATH`。即時掃描控制保留在桌面程序，避免第二個程序取得不同的授權能力與工作狀態。CLI 負責本機規劃、狀態檢查、匯出、複驗紀錄、產品管理執行環境的生命週期與精確清理。

從原始碼 checkout 檢查必要條件：

```sh
cargo run --package ai-security-scanner \
  --no-default-features --features cli \
  --bin ai-security-scanner-cli -- doctor
```

未封裝的 CLI 必須先準備符合目標平台的精確執行環境，並明確傳入：

```sh
node runtime/vendor-managed-runtime.mjs \
  --target x86_64-unknown-linux-gnu \
  --output runtime/staged/managed-runtime

cargo run --package ai-security-scanner \
  --no-default-features --features cli \
  --bin ai-security-scanner-cli -- \
  --managed-runtime-bundle runtime/staged/managed-runtime \
  runtime managed install
```

受限操作流程請看 [CLI 與代理程式操作指南](.codex/skills/ai-security-scanner/SKILL.md)。該指南不能處理憑證、核准或擴大掃描範圍、接觸未核准目標，或執行修復。

## Repository 結構

```text
src/                         React 桌面介面
src-tauri/                   Rust/Tauri 本機案件服務與 CLI
engines/catalog.json         權威、版本化的引擎清單
mappings/                    版本化的控制項與匯出對照
bootstrap/                   固定的雲端唯讀權限建立定義
docs/product-spec.md         最終需求與完成標準
docs/architecture.md         程序邊界、領域模型、IPC 與執行環境設計
docs/threat-model.md         憑證、scanner、證據、export 與 AI boundary
docs/usability/              真人研究流程與 evidence schema
.upstreams/                  本機 shallow research clones；Git 忽略
```

## Release 與證據狀態

發布工作流程會建置 Linux、通用 macOS 與 Windows 原生安裝程式，在各平台觀察安裝後的桌面程式啟動，再從全新主機驗證產品管理執行環境的完整生命週期與固定隔離容器。定稿候選版本也包含校驗碼、CycloneDX／SPDX 軟體物料清單、第三方聲明、更新簽章、平台資格紀錄與 GitHub 建置來源證明。

從 `main` 手動執行工作流程只會產生發布前檢查，無權建立版本標籤或公開 GitHub Release。只有精確的穩定版本標籤且所有發布檢查成功才可發布。Apple Developer ID／公證與 Windows Authenticode 尚未設定，因此作業系統仍可能顯示「無法識別的開發者」警告；Tauri 更新簽章是另一項完整性控制，不代表作業系統發布者身分。

發布 `v0.2.0` 前仍需要：

1. 一位符合條件、對 IAM 不熟悉的成人受試者，在乾淨的支援桌面安裝與 disposable cloud account 上進行真實、受觀察的首次使用研究；
2. 通過 validator、已 redacted 且綁定精確 candidate commit 的證據；
3. 完成產品研究後，再進行正式 QC 與 code review。

自動測試、貢獻者 walkthrough 與生成式證據不能替代真人。詳見[研究流程](docs/usability/iam-naive-first-run.md)與 [release pipeline](docs/release/README.md)。

## 文件

- [產品規格](docs/product-spec.md)
- [架構](docs/architecture.md)
- [威脅模型](docs/threat-model.md)
- [雲端服務商授權](docs/provider-authorization.md)
- [引擎清單](docs/engine-catalog.md)
- [產品管理的本機執行環境](docs/managed-runtime.md)
- [Release 與 signed updater](docs/release/README.md)
- [IAM 新手首次使用研究](docs/usability/iam-naive-first-run.md)
- [第三方清單](THIRD_PARTY.md)
- [貢獻指南](CONTRIBUTING.md)

## 貢獻與授權

請閱讀 [CONTRIBUTING.md](CONTRIBUTING.md)，並遵守程式碼儲存庫對掃描範圍、證據、測試資料、授權條款與安全邊界的要求。專案自行開發的原始碼採 [Apache-2.0](LICENSE) 授權；第三方元件保留各自授權。
