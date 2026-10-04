# 開發狀態

[English](development-status.md) · [文件](README.zh-TW.md)

更新：2026-10-04。[產品規格](product-spec.md)定義現行產品行為；本頁記錄工程現況與已觀察的限制。

## 現況

- [v0.3.1 正式版](release/v0.3.1.zh-TW.md)提供 Linux、macOS 與 Windows 安裝檔；實際提供的套件、更新目標及平台限制以該版紀錄為準。
- 本版包含 Prowler 實際失敗標題、核准的 AWS 發現合併、重新連接再掃描、受阻的繼續操作修正、Semgrep `1.174.0-4` 合併規則包，以及 kube-bench／KICS 的未完成涵蓋範圍揭露。
- 引擎目錄共 25 個紀錄，25 個均可執行；Agentic Radar 提供離線工作流程盤點，Garak 則以精確端點／模型、明確授權與一次性本機金鑰進行可選檢查。
- 主要路徑可合併專案資料夾、網站及已獲准內部系統；另有單一網站與單一專案捷徑。結果依資產整理，個別工具失敗不會抹除其他已完成發現。
- Main 的共用 HTML 匯出已將寬表格限制在自己的捲動區域，平板尺寸採單欄，長技術識別字串可換行。這項原始碼修正尚未包含在已發布的 v0.3.1 安裝包；原始交付觀察仍保留在該版紀錄中。
- Main 也已修正 Microsoft 365 身分資產的平台標記，辨識後端的 `microsoft365` 值，避免誤列為公開網站與 IP 位址；尚未包含於 v0.3.1 安裝包。
- Microsoft 365 已更新 setup、四項 PIM 讀取權限與固定的 ScubaGear／Maester 映像檔；仍待擁有者登入後重新實測。
- MCP Armor 可執行已核准 MCP 設定快照的靜態檢查，預設不啟用；不啟動 MCP 伺服器、不載入模型。
- Augustus 仍是研究用資料契約，沒有 production 引擎、派送或授權路徑。研究期間沒有連線任何模型端點。

擁有者指定先完成結果完整性、引擎建置／修補維護與實驗功能整合，再製作 **v0.4.0 正式版**。目前開發中的修正會將 Greenbone 按確切授權分成獨立工作，保存重試所需的授權成員；Kubescape 的缺漏或未評估資料會揭露涵蓋缺口；大型報告則在 512 MiB 證據限制內串流處理。這些改動不在固定的 v0.3.1 安裝包內。Gitleaks 新映像與所有建置／修補輸入稽核已完成。ZAP 已接通進階網站選項、確切授權派送、每秒 5 次的上游請求限速與計畫保存；Agentic Radar 已完成五種框架、空專案與 `.env` 隔離的原生靜態盤點測試；CrewAI 的五項診斷保留為未完成盤點。框架選擇、雙平台公開映像與來源簽章已驗證，並以公開 amd64 映像複驗全部七個案例；Garak 已完成精確 HTTPS／模型輸入、一次性本機金鑰、固定原生探針與六種受控 TLS 測試，公開雙平台位元組、來源簽章與 SBOM 已獨立驗證，六種 TLS 案例亦以公開 amd64 digest 複驗通過；v0.4.0 尚未打包或發布。

## 已記錄的驗證

10 月 4 日 Garak admission 與 v0.4.0 來源檢查：2,114 項 Rust、527 項 component、91 項 CI 合約、203 項發布合約通過；25 個工具均進入同一份最終報告，精確模型資訊及原生次數可保存、重開與中英文匯出。前端先通過 799 項，再修正星星快照的過期斷言，相關三項網站測試均通過。公開雙平台位元組、來源／SBOM 簽章、六種 amd64 原生 TLS 案例、Formatting、Clippy 與 production build 亦已驗證；安裝包交付另行記錄。

10 月 4 日 ZAP 整合：2,092 項 Rust、798 項前端（六項明確 skip）、518 項 component、Formatting、Clippy 與 production build 通過。受控的原生 amd64 掃描驗證固定主機名稱解析、來源邊界、持續連線下的請求限速與取消；報告測試保留所有原生警示實例。這是現行原始碼與受控資料的驗證，v0.4.0 安裝包仍待完成。

10 月 3 日來源準備檢查：2,072 項 Rust、798 項前端（六項明確 skip）、515 項 component、89 項 CI 合約與 202 項發布合約通過。Formatting、Clippy、production build、引擎 admission 與 release identity 亦通過。v0.3.1 準備另通過完整打包自測及三項 gateway 身分／安全測試。

以上是來源測試；安裝、實際掃描、保存與重新開啟的觀察，請見[本版交付紀錄](release/v0.3.1.zh-TW.md)。歷史測試數量保存在[英文工程紀錄](development-status.md#recorded-verification-baseline)，不會當作本版新測試宣稱。

## 維護入口

- [引擎參考](engines/README.zh-TW.md)與[全部映像檔建置更新筆記](engines/image-build-index.md)
- [發布流程](releasing.zh-TW.md)與[本版發布紀錄](release/v0.3.1.zh-TW.md)
- [現行產品檢視](product-audit.md)與[掃描範圍](scanning-scope.zh-TW.md)

掃描只使用明確授權範圍；憑證不透過聊天或指令參數傳遞。版本、發布、簽章與包裝由產品負責人決定。

CI 文件與合約測試：91 項，新增既有映像與新建置候選分開記錄，以及禁止把可執行輸入藏在發布歷史中的檢查。引擎維護已補齊原先缺漏的實際檔案雜湊、六類下游修改的例外紀錄，並驗證全新 Gitleaks amd64 建置與遮蔽秘密值的合成掃描；新版 Gitleaks `8.30.1-2` 已發布，雙架構來源／SBOM 證據與匿名下載驗證通過，catalog 已固定使用新映像。
