# ai-security-scanner

[English](README.md) · [文件](docs/README.zh-TW.md) · [下載](https://github.com/teddashh/ai-security-scanner/releases)

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

## 執行的安全檢查

| 選定資產 | 安全檢查 |
| --- | --- |
| 專案資料夾 | Gitleaks、TruffleHog、Semgrep、Trivy、Grype、Checkov 與 KICS 會依適用情況檢查隔離的唯讀副本。 |
| 網站或 API | Nuclei 先辨識網站技術，再從固定的上游模板快照選擇相符的唯讀檢查。 |
| 內部系統 | Greenbone 在獲准主機與連接埠辨識服務，再從固定的 Community Feed 執行相符的遠端檢查。 |
| 基礎設施、雲端、容器或 Kubernetes 來源 | 適用的上游設定會針對精確選定的來源與範圍執行。 |

資產盤點與 localhost TCP 工具是輔助功能，只說明資產或連線狀態；安全問題來自適用的安全檢查。

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
