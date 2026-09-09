# ai-security-scanner 開發交接

狀態日期：2026-09-09

最後完成的產品程式 checkpoint：`9823a68546b9e05e00a93bb14e444b22f57b639a`

這份文件是目前唯一的開發交接摘要，已直接取代舊的歷史版。產品決策以[產品規格](product-spec.md)為準，能力現況以[產品檢視](product-audit.md)為準。

## 產品目標

讓一位 IT 使用者在同一條簡短流程加入多個 repository、內部設備或 endpoint，以及網站，快速完成真正有意義的安全掃描，然後在一份報告中看懂：掃了什麼、發現什麼、先處理什麼、原因、下一步，以及哪些項目沒有測到。

Scanner 應盡量保留上游行為、規則、識別碼、severity、證據與 remediation。產品 adapter 只負責型別轉換、授權範圍、資源限制、執行與正規化；跨引擎整理、去重、解釋、排序與報告呈現放在共用報告層。SonicWall、WatchGuard 只是內部資產例子，不應建立品牌專用的偵測替身。

版本、發布時機、打包、簽署與合規尺度由產品負責人決定，不是這份交接的待辦。

## 接手時的 Git 狀態

- `9823a68546b9e05e00a93bb14e444b22f57b639a` 已推到 `origin/main`，包含最近完成的 Cloudsplaining、Syft 與共用報告語意修正，可直接依賴。這份交接文件可能位於其後的純文件 commit。
- 本機工作樹刻意保留四個尚未提交的產品程式檔案；請先閱讀 diff，不要用 `git reset --hard` 或 `git checkout --` 丟掉：
  - `engines/images/greenbone-launcher/main.go`
  - `engines/images/greenbone-launcher/main_test.go`
  - `engines/images/maester/run-maester.ps1`
  - `engines/images/maester/run-maester.Tests.ps1`

接手先執行：

```bash
git status --short --branch
git diff --check
git diff -- engines/images/greenbone-launcher engines/images/maester
```

## 已在 main 上成立的產品能力

- 「IT environment」主路徑可在同一個 project 中接受多個 repository、完整網站 URL 與精確內部 host，按資產型別只執行適用的 scanner。
- Repository 路徑已接上 Gitleaks、TruffleHog、Semgrep、Trivy、Grype、Checkov 與 KICS 等上游安全檢查。
- 網站路徑以 Nuclei 上游 automatic scan 與固定的安全模板池執行；每個網站是獨立 engine run，單一網站失敗不應抹掉其他網站結果。
- 內部資產路徑使用 Greenbone Community Feed 與通用的上游檢查，不包含 SonicWall、WatchGuard 或其他廠牌的自製規則。
- 混合掃描結果會進入同一份報告，依資產呈現 finding、已完成檢查、未完成範圍與上游 provenance；一個 scanner 失敗不會刪除已完成的 sibling 結果。
- Cloudsplaining finding 已保留 policy source、policy name、finding、actions、action completeness 與 attached principals，並在共用報告中產生與實際 policy 來源相符的下一步。
- Inventory、service discovery 與 connectivity 仍可作為證據，但不會被宣稱為 vulnerability finding 或成功的安全掃描。

Scanner 出現在目錄中不代表每個引擎的完整使用者路徑都已完成；應以實際上游執行、normalized result 與最終報告三層皆可驗證為準。

## 尚未提交的工作

### Greenbone：先完成這條主路徑

Launcher 的進度已在上述兩個 Go 檔案中：

- 保留上游 `<result_type>`：`alarm`、`log`、`error`、`dead_host`。
- OID-less `error` 與 `dead_host` 會保留，因為它們代表目標未被完整評估。
- OID-less lifecycle／一般 log noise 仍會丟棄，避免把程序訊息當成 finding。
- 無法從 feed vector 評級的 `alarm` 保持 `Unknown`，不再降成 benign `Log`。
- OID-less 狀態不會虛構 NVT identity。

Go 測試與 `gofmt` 已通過；本機沒有 Go，因此上次使用固定 digest 的 Go container 並關閉網路執行：

```bash
docker run --rm --network none \
  -v "$PWD/engines/images/greenbone-launcher:/src:ro" \
  -w /tmp/work \
  golang:1.26.0-alpine@sha256:d4c030d2e2a1d35965dc3e55a874fc4c97fd9528f33f2c9da7527a237e172490 \
  sh -c 'cp -R /src/. . && test -z "$(gofmt -d main.go main_test.go)" && go test ./...'
```

剩餘工作是把這個語意接到 Rust adapter 與共用報告：

1. 只有 `alarm` 產生 vulnerability finding。
2. `error`／`dead_host` 形成該資產的 incomplete coverage 與可行下一步，同時保留其他資產或引擎的結果。
3. `log` 不產生 finding；legacy XML 沒有 `result_type` 時採保守判斷，不能把模糊的零分紀錄當成 clean proof。
4. 未評級 alarm 使用誠實的 `Unknown` severity 與相應 basis；補齊英文、繁中、native DTO 和報告測試。
5. 完成 focused Rust、frontend 與 rendered report 驗證後，將 Greenbone 這一組獨立 commit／push。

### Maester：wrapper 已修，報告層尚未接完

PowerShell wrapper 已把上游 `Investigate` 與 `Failed` 分開，並保留經清理、限制長度的 `ResultDetail.TestResult` 為 `ReviewDetail`。Pester 上次結果為 51/51。

不要把 `Investigate` 當成 vulnerability failure，也不要當成 pass。下一步應在 host adapter／共用報告中把它呈現為「需要人工確認」的 coverage item，附上上游 detail；完成端到端測試後再與 wrapper 一起提交。

## 已確認的最高優先缺陷：Nuclei 空輸出可能顯示假乾淨

目前 Nuclei automatic scan 可能在 technology detection、tag 選擇或 applicable template 載入失敗時以 exit code 0 結束，但沒有產生 JSONL。現行 launcher 對缺少 temporary output 直接接受，Rust adapter 又允許 Nuclei 的空 JSONL 成為 complete；最後 UI 可能顯示「已完成、未發現問題」。這會直接誤導新手，優先度高於介面微調。

相關位置：

- `.upstreams/projectdiscovery/nuclei/pkg/protocols/common/automaticscan/automaticscan.go`
- `engines/images/external-launcher/main.go` 的 Nuclei invocation、`runCommand` 與 `normalizeEvidence`
- `src-tauri/src/adapters/mod.rs` 的 complete-empty JSONL 判斷
- `src-tauri/tests/adapter_fixtures.rs` 的 empty released JSONL 測試
- `src-tauri/src/orchestrator.rs` 的 adapter completion 狀態
- `src-tauri/src/beginner_report.rs` 的 Nuclei tested dimension
- `src/pages/FindingsPage.tsx` 的逐資產狀態判斷

建議分兩步修：

1. 立即停止假乾淨：Nuclei temporary output 缺少或為空時標成 incomplete，從可證明 complete 的 empty-stream 例外與相應測試中移除 Nuclei；報告說明缺少執行證據。
2. 再以真實上游 outcome record 建立「確實執行但零 finding」的完成證據。`-matcher-status -jsonl` 可作為待實測候選；先用固定 fixture 驗證 automatic mode 的實際輸出，不能只根據 exit code 推定完成。不要直接依賴 `-stats-json`，automatic scan 的最後階段使用 mock progress client，未證明能提供所需的逐次完成證據。

## 後續順序

1. 接完 Greenbone launcher → Rust adapter → 共用報告，驗證 alarm、unrated alarm、error、dead host、log 與 mixed sibling preservation。
2. 修正 Nuclei 空／缺失輸出的假乾淨路徑，再補上可證明 genuine zero-finding completion 的上游證據。
3. 把 Maester `Investigate` 接成 manual-review coverage item。
4. 移除進階 cloud／Kubernetes 路徑中產品自訂的窄 subsets，改由上游 profile 與使用者選定資產驅動。
5. 補齊 Trivy JAR 掃描所需的固定 Java vulnerability DB。
6. 用受控自有 fixture 走一次完整 mixed IT flow，量測從加入資產到第一個有用結果所需時間，優先修掉阻礙新手的步驟。

## 交接判準

每個 scanner 的工作只有在以下鏈路都成立時才算完成：

```text
使用者選定資產
  → 適用的上游 scanner 真正執行
  → finding／inventory／incomplete outcome 保留原意
  → sibling 結果不因單點失敗消失
  → 共用報告按資產說明結果、限制與下一步
  → 保存後重開及匯出仍維持相同語意
```

本輪開發沒有接觸任何外部或未授權目標，也沒有更動發布、版本、installer、簽署或合規設定。
