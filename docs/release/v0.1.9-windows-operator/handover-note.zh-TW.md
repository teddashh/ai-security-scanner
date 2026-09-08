# Windows operator 歷史摘要（2026-09-07）

本檔把當時的交接內容收斂為可查核事實。產品方向以[產品規格](../../product-spec.md)為準；版本與發布尺度由產品 owner 決定。

## 當時完成

- 產品修正：target validation、mobile scroll lock、locale preservation、case deletion、selection/loading races、timestamp 處理與 shared-corpus CI routing。
- UI／UX 修正：網站輸入、AI onboarding、部分結果、報告匯出與刪除流程。
- 自動測試：frontend `486/486`、component `145/145`、Rust `1478/1478`、focused lifecycle `27/27`、evidence regression `142/142`、CI guards `31/31`。
- 最終程式 checkpoint：`3b3591ad72e35735b71e17a3d30c1bb8546e0d5c`。

## 當時未完成

- 沒有 fresh native Start → Progress → report → reopen → export。
- 沒有真正目標掃描或新手參與者觀察；scan count 為 0。
- `127.0.0.1:9001` 由 BAT SSH tunnel 使用，未被接觸或停止。
- 沒有 clean install、UAC、update、uninstall 或 destructive cleanup 測試。

細節見[作業紀錄](operation-report.zh-TW.md)與[測試紀錄](test-report.zh-TW.md)。
