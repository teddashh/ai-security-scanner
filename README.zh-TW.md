# ai-security-scanner

[專案網站](https://teddashh.github.io/ai-security-scanner/?lang=zh-TW) · [English](README.md) · [文件](docs/README.zh-TW.md) · [下載](https://github.com/teddashh/ai-security-scanner/releases)

一個桌面應用程式，同時檢查程式碼專案、網站與內部系統。選好資產後只需啟動一次掃描，即可取得一份依優先順序整理的報告，直接列出問題、受影響資產、證據與下一步。

## 開始使用

從 [GitHub Releases](https://github.com/teddashh/ai-security-scanner/releases) 下載適用的安裝程式：

| 平台 | 安裝程式 |
| --- | --- |
| Windows x86-64 | NSIS `.exe` 或 `.msi` |
| macOS | Universal `.dmg` |
| Linux x86-64 | Debian `.deb` |

開啟應用程式並選擇一條路徑：

- **掃描我的 IT 環境**：在同一輪加入多個專案資料夾、網站與已獲准的內部系統。
- **檢查網站**：使用經過審查的 Nuclei 設定檢查一個精確網站來源範圍。
- **檢查專案資料夾**：掃描本機唯讀副本中的秘密、弱點相依套件、危險程式碼與設定問題。

確認精確資產與網路範圍後，選擇**開始掃描**。掃描結束後會直接開啟結果。

## 所有資產集中在一份報告

報告首先呈現：

- 已確認有問題的資產；
- 優先處理的問題及其影響；
- 最小可行的處理動作與修正驗證方式；
- 每個資產已完成及尚未執行的檢查；
- 技術細節中的原始掃描器識別碼、嚴重度、證據與修正建議。

個別檢查失敗時，其他已完成結果仍會保留。報告可重新開啟、與後續掃描比較，並匯出成好讀的 HTML 或結構化資料。

## 串接的工具

目前的引擎目錄整合了 21 個上游專案。產品只會針對每個選定資產執行適用工具，保留原始識別碼、嚴重度、證據與修正建議，再把所有已完成結果整理到同一份報告。

**選定資產 → 適用的上游工具 → 薄層轉接器 → 一份依資產整理、排好優先順序的報告**

### 程式碼專案、相依套件與基礎設施即程式碼

| 工具 | ai-security-scanner 的使用方式 |
| --- | --- |
| [Semgrep](https://github.com/semgrep/semgrep) | 使用固定的上游安全規則快照，進行危險程式碼模式的靜態分析。 |
| [Gitleaks](https://github.com/gitleaks/gitleaks) | 離線偵測秘密模式；一般證據會遮蔽秘密值。 |
| [TruffleHog](https://github.com/trufflesecurity/trufflehog) | 離線檔案系統秘密偵測；停用網路驗證。 |
| [Trivy](https://github.com/aquasecurity/trivy) | 使用固定離線資料，檢查支援的專案 manifest 與單一映像 OCI layout 中的弱點套件。 |
| [Grype](https://github.com/anchore/grype) | 使用固定離線資料，檢查專案副本與單一映像 OCI layout 中的弱點套件。 |
| [Checkov](https://github.com/bridgecrewio/checkov) | 針對選定的唯讀副本執行適用的基礎設施與設定檢查。 |
| [KICS](https://github.com/Checkmarx/kics) | 使用上游 query pack 檢查基礎設施即程式碼的錯誤設定。 |
| [Syft](https://github.com/anchore/syft) | 建立軟體元件盤點與可保存的 SBOM；盤點本身不是弱點結果。 |

### 網站與內部系統

| 工具 | ai-security-scanner 的使用方式 |
| --- | --- |
| [Nuclei](https://github.com/projectdiscovery/nuclei) | 從固定的 [Nuclei Templates](https://github.com/projectdiscovery/nuclei-templates) 快照，執行會辨識技術、範圍受限的唯讀 HTTP 安全檢查。 |
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
- [參與開發](CONTRIBUTING.md)
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

## 授權

本專案自行撰寫的原始碼採用 [Apache-2.0](LICENSE) 授權。第三方引擎與資料保留各自的授權，詳見 [THIRD_PARTY.md](THIRD_PARTY.md)。
