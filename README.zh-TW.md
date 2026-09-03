# ai-security-scanner

[English](README.md)

## 找出真正該處理的問題，也看得懂下一步

`ai-security-scanner` 是為不想先學會一整套資安工具的人設計的桌面安全掃描器。

你只要選擇想保護的東西。應用程式會準備適合的檢查，先給你快速且有用的結果，再整理成一份報告，清楚回答：

- 你原本要求掃描什麼；
- 實際測試了什麼；
- 哪些部分沒有測到；
- 發現了什麼；以及
- 接下來可以怎麼做。

如果其中一項檢查跑不起來，其他檢查仍會繼續。報告會誠實標示缺口，不會把有用的結果一起丟掉，也不會把沒測到的部分假裝成安全。

## 可以檢查什麼？

- **這台電腦上的服務**：從 `127.0.0.1:9001` 這類明確位址開始。
- **網站或 API**：檢查指定的線上網址是否有常見曝露與已知弱點。
- **外部 IP 或網域**：了解你指定的服務有哪些可以從網際網路連到。
- **家裡或辦公室的網路**：檢查你獲准管理的內部主機或 `/24` 網段。
- **程式碼或 GitHub 程式庫**：在不修改專案的前提下，找出危險程式碼、外洩秘密、有弱點的相依套件與設定錯誤。
- **AI 應用程式**：檢查選定的程式碼、相依套件、秘密、提示詞與部署檔案，同時清楚說明哪些模型行為沒有測試。
- **進階來源**：需要時再連接雲端帳號，或檢查基礎設施程式碼、匯出的容器映像與 Kubernetes 設定。

## 一條簡單的流程

1. **選擇想保護的東西。** 挑最接近你情境的使用方式。
2. **確認後開始。** 用一般人看得懂的方式查看目標與限制，確認一次就開始。
3. **照報告處理。** 先修最重要的問題、分享容易閱讀的報告，再重新掃描比較差異。

第一批結果應該很快出現；更完整的清查與深度檢查可以在背景繼續。你可以取消掃描、重新開啟專案，已經保存的結果不會因後續失敗而消失。

## 不假裝完整的結果

報告可能是完整、部分完成，或沒有任何檢查完成。產品絕不把「未測試」、「無法連線」或掃描工具失敗說成安全。

NIST CSF、ISO/IEC 27001 與 AIDEFEND 關聯只是幫助你理解發現項目與框架的關係；它們不代表產品替組織完成認證，也不代表已證明合規。

## 目前可以怎麼試？

想直接試真正的 Windows App？請到 [GitHub Releases 頁面](https://github.com/teddashh/ai-security-scanner/releases)下載 **v0.1.8 公開測試預發布版**。這是讓大家實機測試的版本，目前還不是穩定版或新手正式推薦版。

目前 `main` 原始碼已領先這批預發布 binary。開發接手請看
[v0.1.8 foreground QC 交接索引](docs/release/v0.1.8-foreground-qc/README.zh-TW.md)，
其中有精確 source、驗證與未完成項目；不要把舊的可下載 installer 當成目前
`main` 的 build。

安裝前先知道三件事：

- Authenticode 簽章尚未完成驗證，因此 Windows 可能顯示「未知的發行者」；
- 這個精確版本的完整首次設定到 localhost 報告流程仍在實機測試；
- Release 頁面會清楚列出已測與未測內容。卡住時請回報畫面與步驟。

如果只想先看介面，可以使用下方瀏覽器展示版；它不會執行真正的安全掃描。

### 預覽瀏覽器展示版

瀏覽器展示版使用清楚標示的範例資料，不會啟動掃描器，也不會連線到任何掃描目標。

請先準備 Node.js 24 或更新版本：

```sh
npm ci
npm run dev
```

再開啟 Vite 顯示的本機網址。

## 你的資料與掃描範圍

專案、發現項目與證據會留在你的裝置上，除非你主動連接資料來源或匯出。產品不會修改掃描的原始程式碼，也不會自動套用修復。

只能掃描你擁有或確定獲准評估的系統。應用程式會記錄明確選定的範圍、使用保守預設值，並且必須揭露沒有涵蓋的主機、連接埠、路徑、檔案、帳號、階段或檢查。

## 開發者與技術資訊

[正式產品規格](docs/product-spec.md) 是預期產品行為唯一的真相來源；[產品審計](docs/product-audit.md) 是綁定特定 commit 的基準審計與實作順序，不是第二份規格，也不是即時狀態面板。其他技術文件都是下位的實作參考資料。

### 本機開發

從原始碼執行需要：

- Node.js 24 或更新版本；
- Rust 1.98；以及
- 建置原生桌面應用程式時所需的 Tauri 平台相依套件。

執行低成本的網頁端檢查：

```sh
npm ci
npm run typecheck
npm run test:frontend
npm run build
```

在不需要桌面系統程式庫的情況下執行 Rust 核心與命令列介面測試：

```sh
cargo test --workspace --no-default-features --features cli
```

安裝 Tauri 平台相依套件後啟動原生開發版本：

```sh
npm run tauri dev
```

這些原始碼開發指令不能證明 Windows 安裝程式的新手流程已通過。

### 文件

- [正式產品規格](docs/product-spec.md)
- [全程式庫產品審計](docs/product-audit.md)
- [架構](docs/architecture.md)
- [威脅模型](docs/threat-model.md)
- [受管理執行環境實作參考](docs/managed-runtime.md)
- [資料來源授權實作參考](docs/provider-authorization.md)
- [掃描引擎目錄](docs/engine-catalog.md)
- [發行、驗證與發布政策](docs/release/README.md)
- [目前 v0.1.8 foreground QC 交接與測試證據](docs/release/v0.1.8-foreground-qc/README.zh-TW.md)
- [安全政策](SECURITY.md)
- [第三方元件清單](THIRD_PARTY.md)
- [貢獻指南](CONTRIBUTING.md)

### 程式庫結構

```text
src/                         React 桌面介面
src-tauri/                   Rust/Tauri 本機案件服務與命令列介面
engines/catalog.json         有版本的掃描引擎登錄表
mappings/                    有版本的框架對照資料
docs/product-spec.md         正式產品行為規格
docs/product-audit.md        基準審計與實作順序
```

### 授權

本專案自行撰寫的原始碼以 [Apache-2.0](LICENSE) 授權。第三方工具與資料保留各自的授權，詳見 [THIRD_PARTY.md](THIRD_PARTY.md)。
