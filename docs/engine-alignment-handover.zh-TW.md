# 引擎接線與結果對齊 — 歷史摘要

狀態：`f21e6fc..0392aea` 與其後相關修正的歷史工程紀錄（2026-09-05 至 2026-09-06）

目前產品方向以[產品規格](product-spec.md)為準，現況與後續工作以[產品檢視](product-audit.md)為準。本文不決定 roadmap，也不建立版本、發布、簽署、qualification 或合規工作。

## 這段工作留下的價值

真正的「接上 scanner」不是 adapter 存在或程序以 0 結束，而是上游真實輸出能完整成為可追溯、可理解的 finding。這段工作修正了幾個重複出現的問題：

- ScoutSuite、Cloudsplaining、Kubescape、kube-bench、Checkov 等輸出形狀或欄位解析不完整，可能讓真實結果消失。
- 產品替 Gitleaks、TruffleHog、Naabu、httpx 等引擎寫入它們沒有提供的 severity，卻讓讀者以為是上游判定。
- M365 wrapper 的 unknown、details 或 dropped records 沒有完整傳到結果層，可能讀成乾淨結果。
- 缺少資產識別座標的 findings 會被丟棄，且相關警告可能被大量逐筆訊息淹沒。
- 不同引擎指出同一 CVE 時，需要共用報告層分組呈現，但不得假裝成獨立雙重確認。
- finding、coverage gap 與 HTML 報告的產品散文需要雙語；引擎名稱、rule ID、原始 severity 與證據則保留原樣。

詳細 commit、原始輸出與舊狀態仍可從 Git 歷史查閱，不在這份現行摘要重複維護。

## 現行整合原則

1. 優先使用上游支援的 CLI、API、規則、severity、identifier 與 remediation。
2. Adapter 只處理已授權輸入、執行安全與資源界線、取消、輸出擷取和結構轉換。
3. 不在 wrapper 內重寫偵測邏輯或各自創作使用者敘事。
4. 共用報告層負責一致術語、優先順序、去重、在地化與下一步，同時保留所有上游 provenance。
5. Unknown、dropped、truncated、not tested 與 unavailable 都要保持原意，不能變成 pass 或零問題。

目前各引擎的真實能力與限制，請直接看[引擎目錄](engine-catalog.md)與[引擎維護方式](engine-maintenance.md)。

## 驗證方式

以風險相稱的方式驗證受影響路徑：使用代表性的上游輸出、執行 adapter、檢查 normalized record，再渲染使用者看到的報告。若變更影響主要掃描路徑，應盡可能走過目標選擇、實際 scanner、Results 與保存後重開；source regex 與固定 test count 不能取代這條路徑。

## 使用界線

這是歷史技術教訓，不是下一輪工作清單。任何引擎更新應從目前上游、目前 adapter 與目前產品路徑重新判斷；版本、發布、映像 publication、簽署與合規工作只有在產品負責人明確要求時才開始。
