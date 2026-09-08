# v0.1.8 Foreground 作業歷史紀錄

日期：2026-09-02

這份文件記錄一輪已結束的工程工作，不指定後續工作，也不代表目前產品狀態。當時的原始碼範圍從 `fa1fa9d` 延伸至 `09ff38e`。

## 完成的產品與工程工作

### Managed runtime 與資料保護

- 全新 Windows managed runtime 從隔離的 generation 1 開始；已被精確辨識的既有 generation 0 仍可重用。
- 加強 product-data root、process lifetime lease、workspace snapshot 與 uninstall staging。
- packaged runtime component 不可用時，錯誤被限制在相關工作；既有 case 與 report 仍可存取。
- provider artifact 寫入中斷後可以在四個固定 recovery slots 內重試；既有 collision 不會被刪除或覆寫。
- Windows canonical root 的 DACL 修補發生在內容、identity 與 durability 確認之後；custom root 維持 verify-only。
- Unix artifact 流程加入 file 與 parent-directory sync、identity 與 mode 重驗。

### 結果與報告

- findings、preview、export 與 verification presentation 綁定明確的 case、run 與 locale。
- HTML 報告加入實際掃描的 address/port 範圍與結果，同時保留 redaction。
- signed case bundle 被實作為 case-wide records 加上 run-bound reports；selected run 的 observation/evidence 另行綁定。
- Browser demo export 只輸出已實作的 selected-run JSON，不再顯示未實作格式。
- partial、no-check、取消、重試與新 attempt 狀態有各自的持久化結果，不再以單一成功狀態涵蓋。

### 介面

- 加入雙語 Settings、行動版導覽、case/run identity 與 progressive disclosure。
- Settings 區分「尚未檢查」和「已確認不可用」。
- 當時加入 localhost TCP-connect 功能與 deadline；這只能說明連線結果，不會找出漏洞。

### 原始碼安全修正

- Linux interface enumeration 從 raw `getifaddrs` pointer traversal 改為 Linux-only `nix 0.30.1` safe API。
- 三個測試路徑不再把動態 fixture 資料帶入 panic/assert output。
- 後續 Linux Clippy 找到 macOS-only helper 在 Linux 成為 dead code，`09ff38e` 將它限制到正確平台。

## 整合與觀察

- 原始功能位於 `5035422`；provider、bundle、Settings 增量位於 `a538778`。
- 工作線在 `1d4054e` 整合到 `main`，後續 dependency 與 CI fixture 修正形成 `31f137d`。
- CodeQL 回報修正在 `8ba7231`，平台 scope 修正在 `09ff38e`。
- 當時 Windows、GitHub 與 Castle checkout 曾對齊 `09ff38e`。
- GitHub CI 曾發現 minimal-feature dependency、Windows fixture ownership 與 Linux dead-code 問題；每一項都以原始碼修正後重跑相關測試。
- GitHub API 當時顯示 CodeQL #2、#4、#5、#7 已由新分析標示為 fixed，沒有使用 dismissal。
- Linux desktop dependency graph 仍包含 `glib 0.18.5` 的 moderate advisory；Windows 與 Linux CLI-only graph 不包含該 dependency path。

## 當時未執行的操作

- 沒有使用 BAT，沒有安裝、啟動或操作 App。
- 沒有真人從輸入目標、執行有意義掃描到理解結果的流程紀錄。
- 沒有操作 installer 的安裝、upgrade、restart 或 uninstall。
- 沒有簽署或發布新的 installer、updater artifact 或 Nuclei production image。
- Nuclei 只在真實 pinned template tree 上執行 targeted test 1/1。
- 本機 unsigned installer 產生於 `a538778` 之前；只記錄檔案大小、時間與 SHA-256，沒有執行它。

這些未執行事項只界定本紀錄涵蓋的事實，不構成後續待辦。
