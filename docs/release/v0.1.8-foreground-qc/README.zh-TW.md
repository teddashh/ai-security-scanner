# v0.1.8 Foreground 工程歷史紀錄

這個目錄保存 2026-09-02 前後一輪產品與工程工作的歷史事實。內容只描述當時做過、觀察到與未執行的事項，不是目前產品方向、工作清單或決策依據。目前產品方向以 [`docs/product-spec.md`](../../product-spec.md) 為準。

## 紀錄範圍

- 基底：`fa1fa9d401995de45080fbfaffc6b39d99955387`
- 原始功能整合：`503542271ff8b2178ed2d334fd47d76c494d1c75`
- Provider、case bundle 與 Settings 強化：`a538778a34cd7db72b28256591575aee77937ab8`
- 工作線整合點：`1d4054e18b5b8a4014ffd2634ac507fa569e72a7`
- 跨平台回歸紀錄：`31f137d03997c221e7c81ba8fc5ae579348b0c14`
- CodeQL 回報修正：`8ba72315b6d136bdaf89617d95aa06aea0c72e8c`
- Linux Clippy 後續修正：`09ff38e2d7ba8d9b3ca1fcc63faa73d41092dcef`

## 當時完成的工作

- 改善 Windows managed runtime 隔離、provider artifact 回復、workspace snapshot、uninstall staging 與資料保護。
- 讓 findings、preview、export 與驗證畫面明確綁定 case、run 和 locale。
- 改善 partial result、取消與重試狀態，避免把未執行的檢查呈現為成功。
- 加入雙語 Settings、行動版導覽、case/run 識別與漸進式揭露。
- 將 Linux interface enumeration 從 raw pointer traversal 改為 `nix` safe API。
- 修正測試中的三條動態資料輸出路徑。
- 當時加入的 localhost TCP 功能只建立連線，不是漏洞掃描；它不代表目前的主要新手流程。

## 當時觀察到的結果

- Windows desktop 1,347/1,347、Windows CLI 1,340/1,340、Castle Linux CLI 1,307/1,307 通過。
- Frontend 364/364、evidence tests 53/53、usability schema 5/5、Prowler 8/8 通過。
- TypeScript、Vite build、Rustfmt、Clippy 與相關引擎檢查通過。
- CodeQL 回報的四條路徑經原始碼修正後，由後續分析標示為 fixed。
- Linux desktop dependency graph 當時仍包含 `glib 0.18.5` advisory。

## 當時未執行

- 沒有安裝或啟動 Windows App，也沒有執行真人的新手掃描流程。
- 沒有執行 installer upgrade、restart、uninstall 或 standard-user 操作。
- 沒有簽署或發布新的 installer、updater 或 Nuclei production image。
- 本機曾產生的 unsigned installer 早於後續原始碼修正；紀錄只包含其檔案 metadata 與 hash。

## 文件

- [作業紀錄](operation-report.zh-TW.md)
- [測試紀錄](test-report.zh-TW.md)
- [工作摘要](handover-note.zh-TW.md)
- [English summary](../v0.1.8-foreground-qc-handover.md)
