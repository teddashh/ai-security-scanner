# 發布流程

[English](releasing.md) · [文件](README.zh-TW.md)

產品負責人選擇版本、channel、source commit、支援的安裝檔與發布時間。自動化流程會針對同一個決定完成建置、平台驗證、凍結、重新驗證、attestation 與發布。

## 目前發布版本

[v0.3.0](https://github.com/teddashh/ai-security-scanner/releases/tag/v0.3.0) 是目前已發布的桌面版本，涵蓋 **Linux、macOS、Windows**。[Actions run 36884417623](https://github.com/teddashh/ai-security-scanner/actions/runs/36884417623) 以 public candidate 建置並驗證精確來源 `dddd491b87f90c9cebc5f946d9e2070f36742f21`；[promotion run 36890665121](https://github.com/teddashh/ai-security-scanner/actions/runs/36890665121) 在 `release-publication` environment 核准後，不重新建置即發布同一批凍結檔案。發布頁包含安裝檔、`SHA256SUMS.txt`、runtime manifests、SBOM、notices 與 qualification 紀錄。

2026-10-03 核對時，GitHub 將 v0.3.0 標為 latest，且 `prerelease: false`。凍結的 `release-metadata.json` 仍記錄 `releaseChannel: prerelease`，發布說明也保留原始測試揭露。公開的 `latest.json` 有 macOS 與 Windows NSIS 更新目標；Linux Debian 與 Windows MSI 沒有對應的套件更新。GitHub 標籤不會改變原始驗證紀錄，也不代表已達 GA。`package.json` 仍保留 `release.target: 1.0.0`；下一版的版本與渠道由負責人決定。

| 平台 | 安裝檔 | 揭露事項 |
| --- | --- | --- |
| Windows x86-64 | MSI 與 NSIS | **未簽章**，SmartScreen 可能顯示警告。技術 qualification 通過；未觀察 Windows lifecycle 與資料保留驗證。 |
| macOS Universal | `.dmg` | **未經 Apple 公證**，未設定 OS 簽章。安裝檔 qualification 通過；qualification 主機上未觀察 managed runtime 執行。 |
| Linux x86-64 | Debian `.deb` | 技術 qualification 通過。AppImage 與 `.rpm` 因未觀察技術 qualification 而**未提供**。 |

兩種 Windows 安裝檔均保留 `windows-lifecycle-not-observed` 與 `windows-data-preservation-not-observed`；安裝檔 qualification 通過不代表已驗證這些 lifecycle 行為。每個安裝檔的 exact-candidate 新手真人操作路徑均為 `not-observed`。部分套件具有 updater 簽章，但不代表具備 OS 簽章或 Apple 公證。以上是揭露事項，並非發布門檻。

最新進度見 [2026-10-03 桌面發布準備紀錄](release/desktop-readiness-2026-10-03.md)，區分已完成的 main 修正與候選安裝包待辦。

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

## 建置與 platform qualification，不執行公開發布

產品負責人要求 QC 建置時，**Release desktop installers** 使用：

- `public_release_candidate: false`：只完成 commit-bound QC artifacts，不發布任何內容；
- 僅在負責人要求 Windows N-1 upgrade 與 ambiguous-runtime recovery fixtures 時使用選用的 `windows_data_preservation` 輸入。v0.3.0 紀錄仍標示未觀察這些項目。

Workflow 定義以下四條 qualification 路徑，各路徑最終可記為 `not-offered`。實際提供哪些安裝檔，應以該次 run 的 metadata 判定，不可只看路徑清單。

| Qualification | Runner | 安裝檔 |
| --- | --- | --- |
| Linux x86-64 | Ubuntu 24.04 | Debian package |
| macOS Universal | macOS 15 Intel | DMG application |
| Windows x86-64 | Windows Server 2025 | MSI |
| Windows x86-64 | Windows Server 2025 | NSIS installer |

各 lane 如實記錄觀察到的安裝、application 與 companion layout、桌面啟動、支援的 managed-runtime operations、runtime／container evidence，以及測試狀態移除。JSON qualification record 將這些觀察綁定 version、source commit 與 artifact digest。安裝檔檢查通過不代表已觀察 runtime 執行或 Windows lifecycle；本次 macOS／Windows 限制已列於上方。

Finalized QC 集合記錄所提供的 artifacts 及其 qualification evidence、checksums、runtime manifests、notices、SBOM 與限制。Workflow summary 識別 run、artifact 與 source commit；finalization 不會發布任何內容。

## 發布 public candidate

公開發布由產品負責人另外決定。負責人授權後，從 `main` 以 `public_release_candidate: true` 執行 **Release desktop installers**；**Promote frozen desktop release candidate** 再使用該 run summary 中的五個值：

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
