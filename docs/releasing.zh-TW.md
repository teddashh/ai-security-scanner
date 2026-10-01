# 發布流程

[English](releasing.md) · [文件](README.zh-TW.md)

產品負責人選擇版本、channel、source commit、支援的安裝檔與發布時間。自動化流程會針對同一個決定完成建置、平台驗證、凍結、重新驗證、attestation 與發布。

## 目前候選版本與公開發布暫停狀態

目前候選版本涵蓋 **Linux、macOS、Windows 三平台**。[Actions run 35513091476](https://github.com/teddashh/ai-security-scanner/actions/runs/35513091476) 已將來源 `56d3b3f469b9fd9bb090f404b0230e7667d5d884` 以 `publicationMode: commit-bound-qc` 完成 finalization。該 run 的 `release-finalized` artifact 內含權威的 `release-metadata.json`、安裝檔、checksums 與揭露紀錄。這份紀錄只適用於該 commit，不會自動涵蓋後續原始碼變更。

**公開發布維持 HOLD（暫停）。** 保持 `public_release_candidate: false`；HOLD 期間不得執行 promotion、建立 tag 或 GitHub Release。已完成的 QC artifacts 可供審閱，並非已公開的 Release 下載或 GA 宣告。正式發布必須涵蓋三種作業系統。

| 平台 | 本次 QC 提供的安裝檔 | 揭露事項 |
| --- | --- | --- |
| Windows x86-64 | MSI 與 NSIS | **未簽章**，SmartScreen 可能顯示警告。技術 qualification 通過；未觀察 Windows lifecycle 與資料保留驗證。 |
| macOS Universal | `.dmg` | **未經 Apple 公證**，未設定 OS 簽章。安裝檔 qualification 通過；qualification 主機上未觀察 managed runtime 執行。 |
| Linux x86-64 | Debian `.deb` | 技術 qualification 通過。AppImage 與 `.rpm` 因未觀察技術 qualification 而**未提供**。 |

兩種 Windows 安裝檔均保留 `windows-lifecycle-not-observed` 與 `windows-data-preservation-not-observed`；安裝檔 qualification 通過不代表已驗證這些 lifecycle 行為。每個安裝檔的 exact-candidate 新手真人操作路徑均為 `not-observed`。部分套件具有 updater 簽章，但不代表具備 OS 簽章或 Apple 公證。此 commit-bound QC 集合尚未建立公開 provenance。以上是既有紀錄的揭露，並非新增發布門檻。

最新**已發布**版本 [v0.2.0](https://github.com/teddashh/ai-security-scanner/releases/tag/v0.2.0) 仍是較早的版本，**僅提供 Linux x86-64 Debian `.deb`**；該歷史版本未提供 Windows／macOS 安裝檔。不可用它的供應狀態概括目前三平台候選版本，也不可為尚未發布的候選檔案編造公開下載網址。

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

- `public_release_candidate: false`，公開發布 HOLD 期間維持 commit-bound QC；
- 僅在負責人要求 Windows N-1 upgrade 與 ambiguous-runtime recovery fixtures 時使用選用的 `windows_data_preservation` 輸入。目前 QC 紀錄仍標示未觀察這些項目。

Workflow 定義以下四條 qualification 路徑，各路徑最終可記為 `not-offered`。實際提供哪些安裝檔，應以該次 run 的 metadata 判定，不可只看路徑清單。

| Qualification | Runner | 安裝檔 |
| --- | --- | --- |
| Linux x86-64 | Ubuntu 24.04 | Debian package |
| macOS Universal | macOS 15 Intel | DMG application |
| Windows x86-64 | Windows Server 2025 | MSI |
| Windows x86-64 | Windows Server 2025 | NSIS installer |

各 lane 如實記錄觀察到的安裝、application 與 companion layout、桌面啟動、支援的 managed-runtime operations、runtime／container evidence，以及測試狀態移除。JSON qualification record 將這些觀察綁定 version、source commit 與 artifact digest。安裝檔檢查通過不代表已觀察 runtime 執行或 Windows lifecycle；本次 macOS／Windows 限制已列於上方。

Finalized QC 集合記錄所提供的 artifacts 及其 qualification evidence、checksums、runtime manifests、notices、SBOM 與限制。Workflow summary 識別 run、artifact 與 source commit；finalization 不會解除 HOLD。

## 未來 promotion 參考：HOLD 期間不執行

公開發布仍由產品負責人另外決定。負責人解除 HOLD 並授權建立 public candidate 後，**Promote frozen desktop release candidate** 才會使用該次準備流程產生的五個值：

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
