# Windows operator 作業紀錄（2026-09-07）

本檔只保存當時的產品變更、實際觀察與未執行項目。產品方向以[產品規格](../../product-spec.md)為準；版本與發布尺度由產品 owner 決定。

## 產品與開發結果

- 修正 target validation、行動版 scroll lock、locale preservation、case deletion 與並行 selection races。
- 修正 shared-corpus CI routing，以及 evidence timestamp 的 UTC、日曆有效性與奈秒排序。
- 改善網站輸入、AI onboarding、partial-result disclosure、master-report export 與 two-step deletion 的介面行為。
- 建立固定 loopback fixture 與隔離資料目錄，供連線與 lifecycle plumbing 測試使用；這些工具不是安全掃描能力。

Source checkpoints：主要實作 `bd47e26b6c8024eb3461176637d7fce3e8370561`；最終程式 `3b3591ad72e35735b71e17a3d30c1bb8546e0d5c`。

## 實際觀察

- 已安裝 App 可啟動；CLI doctor 回報 21/21 manifests、0 invalid checkpoints、0 cleanup obligations，managed-local Podman 5.8.2 可用且執行中。
- 隔離 CLI 測試完成 case 建立、讀取、精確確認刪除、HTML／JSON／case bundle 匯出、重複目的地拒絕與原檔不覆寫。
- Browser 開發畫面實際檢查中英文導覽、URL 驗證、AI onboarding、部分結果揭露、報告匯出與兩階段刪除。
- `127.0.0.1:9001` 當時由既有 BAT SSH tunnel 使用，因此未接觸、停止或重設該服務。

## 測試結果

- Frontend `486/486`、component `145/145`、usability `5/5`。
- Rust 1.98 all-targets `1478/1478`；Clippy `-D warnings`、rustfmt、TypeScript typecheck 與 production frontend build 通過。
- Focused lifecycle `27/27`、evidence regression `142/142`、CI boundary／drift regression `31/31`。
- Build 保留主 JS chunk 超過 500 kB 的警告；Linux desktop dependency graph 仍包含受既有 moderate alert 影響的 `glib 0.18.5`。

## 未執行

- 沒有新的原生 Start → Progress → report → reopen → export 掃描旅程。
- 沒有新手參與者觀察；新掃描數為 0。
- 沒有 clean install、UAC、update、uninstall 或 destructive cleanup 測試。
- 當時的 browser walkthrough 與隔離 CLI 測試不能代表真正目標已接受安全掃描。
