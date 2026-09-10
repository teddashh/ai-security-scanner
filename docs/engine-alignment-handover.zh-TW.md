# 引擎與報告層交接紀錄

狀態日期：2026-09-10

目前產品行為：[產品規格](product-spec.md)

目前能力與工作：[產品檢視](product-audit.md)

這份文件保存 2026-09-10 的工程交接事實。完整變更與驗證紀錄位於 Git history。

## 已成立的共同架構

主要 IT 環境路徑可在同一個專案加入：

- 多個 repository 資料夾；
- 多個完整網站或 API URL；
- 多個以精確 hostname 或 IP 表示的內部系統。

執行計畫把每個資產綁定到適用引擎；引擎不會把一個資產的授權擴大到其他資產。個別引擎失敗不會刪除其他已完成結果。所有終態結果使用同一個 report model，並維持保存、重開、複驗與 HTML 匯出的語意一致。

Adapter 負責 typed input、scope、資源限制、執行、取消與正規化。Detector 行為、rule ID、severity、證據與 remediation 保留上游定義。優先排序、去重、跨引擎關聯、白話解釋與報告呈現位於共用報告層。

## Repository 路徑

Repository 先建立有界、私密、唯讀副本，再依適用情況執行：

- Gitleaks、TruffleHog：秘密；
- Semgrep：危險程式碼模式；
- Trivy、Grype：弱點相依套件；
- Checkov、KICS：基礎設施設定；
- Syft：元件清單。

Ignore 規則會排除相依、建置、快取與 VCS 目錄；`.env`、私鑰、registry/auth 設定與 `*.tfvars` 等常見秘密來源檔案仍會交給秘密掃描器。原始專案不會被執行或修改。

Trivy 的下一個建置來源已加入 checksum-pinned Java index，可透過上游標準資料庫辨識 JAR 套件並比對弱點。現行 catalog 仍指向已發布的 `0.74.0-3`；新來源需要新的 immutable image 座標才會進入實際掃描。

## Website 路徑

Nuclei automatic scan 先做上游技術辨識，再從固定唯讀模板快照選擇適用檢查。每個網站各自產生 engine run。

Launcher 使用 StandardWriter JSONL 與 matcher status，讓 adapter 能分辨：

- security template 命中；
- security template 已完成但未命中；
- scanner error；
- 沒有形成執行證據的空輸出。

只有命中會形成 finding；無錯誤的 security-template non-match 可形成 completed-check evidence。Finding 保留 template ID、severity、evidence 與 remediation。

## Internal-system 路徑

Greenbone 使用精確已確認的 host 與 ports。Launcher 從固定 Community Feed 機械式選取目前有效、未淘汰、不需登入的 remote `gather_info` VTs，並保留 Greenbone 的 service detection、dependency 與 required-key/port 決策。

結果語意：

- `alarm`：vulnerability finding；
- 無可解析 feed severity 的 `alarm`：finding，severity 為 **Unknown**；
- `error`、`dead_host`：該資產的 incomplete coverage；
- `log`：技術證據，不是 finding；
- 無 `result_type` 的舊輸出：只接受明確正分 finding，模糊紀錄不形成 clean outcome。

新版 launcher source 已完成這套 typed output。現行 immutable Greenbone image 仍包含舊 launcher；必須發布並選取新 image 座標才會讓真實掃描使用新版輸出。

## Advanced 路徑

- kube-bench 下一個建置來源使用未修改的上游 CIS 1.11 node profile，共 26 個 upstream checks；現行 catalog 仍為 `0.16.0-3`。
- Maester 下一個 wrapper 會把 upstream `Investigate` 保存為 no-verdict control；現行 published image 仍是舊 wrapper。
- GCP Prowler 維持已審查的四項檢查、權限與 endpoint closure。擴大範圍時，checks、permissions、assets、endpoints 與 report wording 必須一起更新。
- CloudQuery、Steampipe 與 Syft 產生 inventory evidence；它們不被列為 vulnerability detector。

## 報告契約

進行中的工作只顯示在 Progress。Results 與 Export 只使用終態輪次。

每個選定資產會得到一個狀態：發現問題、已完成檢查未發現問題、未完成或失敗、尚未測試。Observed services 與 connectivity 分開呈現，不進 problem count。

Finding 第一層直接列出結果、影響、下一步與驗證方式。Unknown severity 保持 Unknown。上游證據與技術工作紀錄放在展開細節；正式條款放在報告最後。舊案件在建立權威報告時會正規化為同一套呈現。

## 發布交接

目前主線包含 `v0.1.9` 之後的產品變更，因此下一個公開版本使用新的 immutable version。候選版完成文件、版本身分、release evidence 與平台 qualification 後，以同一批 frozen artifacts 發布。

Installed-product acceptance 使用公開安裝檔完成 repository、website、internal host 的 mixed flow，涵蓋 Setup、Review、Progress、Results、重新開啟與 HTML 匯出，並記錄第一個有用安全結果的時間。

## 完成判準

```text
使用者選定資產
  → 適用的上游 scanner 真正執行
  → finding、inventory、no-verdict 與 incomplete outcome 保留原意
  → sibling 結果不因單點失敗消失
  → 共用報告按資產列出結果與下一步
  → 保存、重開與匯出維持相同語意
```
