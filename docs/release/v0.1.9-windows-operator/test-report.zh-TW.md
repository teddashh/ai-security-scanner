# Windows operator 測試紀錄（2026-09-07）

本檔是當時測試結果的簡要歷史紀錄，不是目前產品標準或後續工作清單。版本與發布尺度由產品 owner 決定。

## 自動測試

| 測試 | 結果 |
| --- | ---: |
| Frontend | `486/486` |
| Component | `145/145` |
| Usability | `5/5` |
| Rust 1.98 all-targets | `1478/1478` |
| Focused lifecycle | `27/27` |
| Evidence regression | `142/142` |
| CI boundary／drift regression | `31/31` |
| TypeScript、Clippy、rustfmt、frontend build | PASS |

Production build 有既有的大型 JS chunk 警告。Dependency reachability 檢查顯示 Windows target 未連入 `glib`；Linux desktop dependency graph 當時仍連入 `glib 0.18.5`。

## 實際功能測試

- CLI doctor：21/21 manifests、0 invalid checkpoints、0 cleanup obligations；managed-local Podman 5.8.2 available／running。
- 隔離 CLI：case seed／list／show、錯誤確認不刪除、精確確認只刪除指定 case、HTML／JSON／case bundle 匯出、重複目的地拒絕均符合預期。
- 匯出檔：HTML 15,992 bytes；canonical JSON 22,339 bytes；standard-redaction case bundle 16,873 bytes。
- Browser UI：中英文導覽、use-case disclosure、URL scheme／credential validation、AI onboarding、partial-result disclosure、報告匯出與 two-step deletion已操作。

## 發現並修正

- 修正 target validation、mobile scroll lock、locale preservation、case deletion 與非同步 selection/loading races。
- 修正 Windows path portability、固定 loopback fixture、shared-corpus CI routing，以及 timestamp 的 UTC／真實日曆／奈秒排序。
- 修正八項 UI／UX 誤導或錯誤恢復問題，並補上對應回歸測試。

## 未執行

- `127.0.0.1:9001` 由無關 BAT SSH tunnel 使用，因此沒有 probe、掃描、停止或重設它。
- 沒有 fresh native scan、真正目標的安全結果、完整 installed lifecycle 或新手使用者觀察。
- 沒有 clean install、UAC、update、uninstall 或 destructive cleanup。
- Browser、fixture、CLI 與 process completion 只證明各自範圍，不代表未執行的安全檢查。
