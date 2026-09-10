# 發布流程

[English](releasing.md) · [文件](README.zh-TW.md)

產品負責人選擇版本、channel、source commit、支援的安裝檔與發布時間。自動化流程會針對同一個決定完成建置、平台驗證、凍結、重新驗證、attestation 與發布。

## 版本身分

`package.json`、`package-lock.json`、`src-tauri/tauri.conf.json`、Rust package 與 release-owned runtime manifests 使用同一個 numeric SemVer。每個公開版本使用新的 immutable `vX.Y.Z` tag。

`package.json` 另外記錄：

- `release.channel`：`prerelease` 或 `stable`；
- `release.target`：下一個開發目標版本。

## 準備 main

1. 完成 release notes 與現行文件。
2. 執行變更範圍要求的 repository validation、frontend、component、Rust、build、release-policy 與 release-evidence suites。
3. Commit 一致的版本與 channel 更新。
4. 把精確 candidate commit 推到 protected `main`。

## 建置與 platform qualification

從 `main` 執行 **Release desktop installers**：

- `public_release_candidate: true`；
- 需要驗證 Windows N-1 upgrade 與 ambiguous-runtime recovery 時，設定 `windows_data_preservation: true`。

Workflow 會在全新的 runner 安裝並驗證四個 artifact：

| Qualification | Runner | 安裝檔 |
| --- | --- | --- |
| Linux x86-64 | Ubuntu 24.04 | Debian package |
| macOS Universal | macOS 15 Intel | DMG application |
| Windows x86-64 | Windows Server 2025 | MSI |
| Windows x86-64 | Windows Server 2025 | NSIS installer |

每條 lane 會驗證安裝後的 application 與 companion layout、啟動桌面程式、執行該平台支援的 managed-runtime operations、檢查 runtime 與 container evidence、移除測試安裝狀態，並產生綁定 version、tag、commit 與 artifact digest 的 JSON qualification record。

Finalized candidate 只收錄 qualification evidence、checksums、runtime manifests、notices 與 SBOM 完整相符的支援 artifact。Workflow summary 會列出 candidate run ID、run attempt、artifact ID、artifact digest 與 source commit。

## 發布 frozen artifacts

從 `main` 執行 **Promote frozen desktop release candidate**，填入 candidate workflow 產生的五個值：

- candidate run ID；
- candidate run attempt；
- candidate artifact ID；
- candidate artifact SHA-256；
- exact source commit。

使用 Windows external-evidence bundle 時，四個 evidence 欄位必須一起填寫；不使用時全部留空。

Promotion workflow 會重新驗證 candidate lock 與 checksums，在不重新建置的情況下組合公開檔案，建立 build-provenance attestations，並進入 `release-publication` environment 等待核准。核准後會把同一批檔案發布到 immutable version tag。Stable channel 會成為 latest release；prerelease channel 會標示為 prerelease。

## 確認發布內容

GitHub Release 應包含選定的安裝檔、`SHA256SUMS.txt`、release index、runtime manifests、SBOMs、notices、release notes 與 platform qualification records。Published tag 與 source commit 必須和 frozen candidate summary 完全一致。

安裝版產品驗收依[開始使用](getting-started.zh-TW.md)完成新手路徑。
