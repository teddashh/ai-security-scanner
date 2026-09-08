# v0.1.8 Foreground 工作歷史摘要

日期：2026-09-02

這是已結束工作線的簡短事實摘要，不提供接手命令、優先級或後續決策。產品方向以 [`docs/product-spec.md`](../../product-spec.md) 為準。

## 原始碼節點

- 基底：`fa1fa9d401995de45080fbfaffc6b39d99955387`
- 功能整合：`503542271ff8b2178ed2d334fd47d76c494d1c75`
- Provider、bundle、Settings 強化：`a538778a34cd7db72b28256591575aee77937ab8`
- 整合到 `main`：`1d4054e18b5b8a4014ffd2634ac507fa569e72a7`
- 跨平台回歸紀錄：`31f137d03997c221e7c81ba8fc5ae579348b0c14`
- CodeQL 原始碼修正：`8ba72315b6d136bdaf89617d95aa06aea0c72e8c`
- Linux 平台 scope 修正：`09ff38e2d7ba8d9b3ca1fcc63faa73d41092dcef`

## 做了什麼

- 改善 managed runtime 隔離、資料 root、lease、workspace snapshot 與 uninstall staging。
- 強化 provider artifact 的 identity、permission、durability 與 bounded recovery。
- 將結果、報告、匯出與驗證呈現綁定明確 case/run/locale。
- 改善 partial、no-check、取消和重試狀態，並補上雙語 Settings 與行動版導覽。
- 將 Linux interface enumeration 改為 `nix` safe API，並修正三個測試輸出路徑。
- 當時的 localhost TCP-connect 功能只提供連線資訊，不是漏洞掃描。

## 看到了什麼

- Windows desktop 1,347/1,347、CLI 1,340/1,340、Castle Linux CLI 1,307/1,307 通過。
- Frontend 364/364、evidence 53/53、usability schema 5/5、Prowler 8/8 通過。
- Linux Clippy 曾找出錯誤的平台 scope；`09ff38e` 修正後相關測試通過。
- CodeQL 的四條回報路徑經修正後，在 GitHub API 中標示為 fixed。
- Linux desktop graph 當時仍有 `glib 0.18.5` advisory；Vite 仍有大型 chunk warning。

## 當時沒做什麼

- 沒有安裝或操作 Windows App，也沒有真人走過新手掃描流程。
- 沒有執行任何真實目標掃描。
- 沒有執行 installer upgrade、restart、uninstall 或 standard-user journey。
- 沒有簽署或發布新的 installer、updater 或 Nuclei production image。
- 本機 unsigned installer 只做過 build metadata/hash 檢查，且早於後續原始碼修正。

以上未執行事項不形成後續待辦。
