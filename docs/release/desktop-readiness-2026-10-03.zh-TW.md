# 桌面交付紀錄 — 2026-10-03

[English](desktop-readiness-2026-10-03.md) · [本版發布紀錄](v0.3.1.zh-TW.md)

負責人已核准 v0.3.1 正式版、安裝包建置驗證與發布，以及中英文行銷文件和網站更新。三點交付均已完成：[v0.3.1](https://github.com/teddashh/ai-security-scanner/releases/tag/v0.3.1) 已發布為 stable／latest，凍結來源為 `6b61e9ef72f90174ef7310f80e766aba61c9428d`。

## 已完成的三點交付

1. **版本與渠道：** 應用程式、lockfiles、Tauri bundle、Rust package 與 gateway 的產品身分一致為 0.3.1 stable，`release.target` 亦為 0.3.1。同一來源的 [CI 37148020161](https://github.com/teddashh/ai-security-scanner/actions/runs/37148020161) 與 [CodeQL 37148020167](https://github.com/teddashh/ai-security-scanner/actions/runs/37148020167) 通過。
2. **安裝包與實際執行：** [候選 run 37148617398](https://github.com/teddashh/ai-security-scanner/actions/runs/37148617398)，attempt 1，四條獨立安裝檔 qualification 均通過；下載後的 immutable candidate、索引、檢查碼及 updater 簽章亦通過。本機另以精確 Debian 包解開後的安裝布局及獨立資料測試，從真正桌面程式執行 Gitleaks／Semgrep，兩項均 exit 0，保留四筆發現及六份原始產物。中英文遮蔽 HTML 均從桌面保存，重新開啟後識別碼與 fingerprint 不變。新 runner 另完成真正 Debian 套件安裝；本機自動化操作不等於新手真人研究。
3. **發布凍結檔案：** [Promotion 37153378798](https://github.com/teddashh/ai-security-scanner/actions/runs/37153378798)，attempt 1，經 `release-publication` environment 正常核准後通過，於 2026-10-03 21:05:59 UTC 不重新建置即發布。公開 tag、來源及 stable／latest 身分正確，49 個公開檔案均經匿名下載核對，長度及 SHA-256 與凍結內容一致。

精確 artifact ID、digest、四個安裝檔的檢查碼、updater 目標與平台限制，都在[中英文發布紀錄](v0.3.1.zh-TW.md)。現行產品 README、文件／引擎／發布介紹、開始使用與網站已更新中英文內容；網站兩語系在 390、768、1440px 均無橫向溢出，語言切換、metadata 與文件目的地亦已檢查。

## 包含的產品更新

- Prowler 標題使用實際失敗原因；核准的 AWS 分組將 31 筆原始發現整理為 13 個修正卡片，原始識別碼、嚴重度、證據與建議均保留。
- 唯讀連線過期後直接提供重新連接再掃描；受阻的繼續操作與 Markdown 顯示修正已包含在本版。
- Semgrep `1.174.0-4` 已發布並固定 digest，包含 1,493 條舊版上游規則與四條產品規則；[規則、授權與發布證據](../engines/semgrep-publication-2026-10-03.md)保留原始事實。
- kube-bench 真實 CIS 1.11 fixture 為 15 PASS、6 FAIL、5 WARN；五項 WARN 揭露為自動檢查未完成，六項失敗及其上游證據保留。KICS 的正值或格式錯誤失敗 counter 也不會被誤報為完整掃描。
- 共用 adapter contract 為 `0.2.3`，來源綁定 coverage 實作 `f0126c0791337d258f10b0d68367b78a3660e0fa`；沒有因此重建映像檔或修改偵測規則。
- M365 已包含四項核准的 PIM 讀取權限、ScubaGear `1.8.0-8` 與 Maester `2.0.0-9`。
- [映像檔建置與更新筆記](../engines/image-build-index.md)涵蓋全部 25 個引擎紀錄及 gateway，保留來源、規則／資料準備、連動修改與注意事項。

Gateway 映像檔沿用 `0.3.0-1` 的固定 digest 與來源；桌面產品版本與映像檔發布版本分別驗證。下一次 gateway 發布需同步更新 manifest、Rust runtime pin 與 JavaScript qualification pin。

## 已記錄的來源驗證

10 月 3 日通過 2,072 項 Rust、798 項前端（六項明確 skip）、515 項 component、89 項 CI 合約及 202 項發布合約。Formatting、Clippy、production build、引擎 catalog／input hash、release policy、完整打包自測及三項 gateway 身分／安全測試均通過。這些是來源驗證，不代替安裝或真人操作證據。

前版 v0.3.0 的 tag 與檔案保留不變。其凍結 metadata 記錄原始 prerelease channel，即使 GitHub 後來曾標示 stable／latest，也不會重寫歷史測試揭露或改變檔案內容。

## 獨立後續事項

- **Microsoft 365 新的 live 複驗：** 仍待擁有者執行更新的 Windows setup、登入並從 app 開始驗證；開發不代為登入或讀取私人憑證，本版不宣稱這條新的 live 路徑已通過。
- **HTML 平板布局：** 768px 有橫向捲動，390 與 1440px 符合視窗寬度，內容仍可讀；已列為後續改善。
- **原有平台揭露：** Windows 未簽章，macOS 未公證；部分 runtime／lifecycle／資料保留觀察與各安裝檔的新手真人路徑仍缺，詳見[本版紀錄](v0.3.1.zh-TW.md)。

Garak、Agentic Radar、ZAP 仍不可執行。啟用新引擎、其他映像檔後續重建、OS 簽章／公證及新的 lifecycle 研究，不會自行加進本次發布範圍。
