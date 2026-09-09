# ai-security-scanner 開發交接

狀態日期：2026-09-09

最後完成的產品程式 checkpoint：`879394d`

這份文件是目前唯一的開發交接摘要，已直接取代舊的歷史版。產品決策以[產品規格](product-spec.md)為準，能力現況以[產品檢視](product-audit.md)為準。

## 產品目標

讓一位 IT 使用者在同一條簡短流程加入多個 repository、內部設備或 endpoint，以及網站，快速完成真正有意義的安全掃描，然後在一份報告中看懂：掃了什麼、發現什麼、先處理什麼、原因、下一步，以及哪些項目沒有測到。

Scanner 應盡量保留上游行為、規則、識別碼、severity、證據與 remediation。產品 adapter 只負責型別轉換、授權範圍、資源限制、執行與正規化；跨引擎整理、去重、解釋、排序與報告呈現放在共用報告層。SonicWall、WatchGuard 只是內部資產例子，不應建立品牌專用的偵測替身。

版本、發布時機、打包、簽署與合規尺度由產品負責人決定，不是這份交接的待辦。

## 接手時的 Git 狀態

- `369a6b97273c11bc2d770fa8d73de84ea4cefb20` 已推到 `origin/main`，把 Greenbone launcher 的結果語意（`alarm`、unrated alarm、`error`、`dead_host`、`log`）接到 Rust adapter 與共用報告，並包含先前完成的 Cloudsplaining、Syft 與共用報告語意修正，可直接依賴。這份交接文件位於其後的純文件 commit。
- `15b27e5bdce659a9cb1429ce980c14b727530423` 修正了讓 `main` 的 CI 在最近幾次 push 都失敗的三個非產品問題：README 契約測試仍檢查 `ef1c653` 之前的固定 13 檢查／19 次 GET 描述、CI classifier 沒有把 `engines/images/greenbone-launcher/main.go` 排入讀取它的 frontend lane，以及 clippy 1.98 的七個既有 lint。之後的 CI 應以綠燈為基準；再變紅時先看新變更。
- `d90c264` 把 `engines/images/greenbone/plan.json` 的 `wrapper.launcher_sha256` 綁到目前的 launcher 原始碼，這是 engine admission 契約要求、每次 launcher 變更都要跟著做的一行更新，不涉及版本或發布。
- `3fae8cd` 補上 Greenbone 在 `mappings/control-mappings.json` 的兩筆已審查 bounded prefix（NVT OID arc `1.3.6.1.4.1.25623.` 與無 OID 時的 `CVE-` fallback），對應 NIST CSF 2.0 `ID.RA-01`、ISO/IEC 27001 2022 `A.8.8`，以及僅在宣告 AI system applicability 時才附加的 AIDEFEND `AID-H-003.010`。在此之前整條內部主機弱點路徑進到 master framework report 時完全沒有任何 framework 關聯，而既有的 census 測試只讀「已存在的 entry」，看不到「完全沒有 entry 的引擎」。同一個 commit 從 producer 端補上 `every_finding_producing_engine_has_at_least_one_mapping_entry`，只用名單豁免五個 inventory-only 引擎（cloudquery、steampipe、syft、naabu、httpx）。catalog identity 為 `2026-09-09.1`。
- `837ad7f` 修好自 `d8fe70b` 起就無法編譯的 desktop 建置。`d8fe70b` 為 `ExecutionReport` 與 `DurableExecutionReport` 加了 `observations`，但沒有一併更新 `commands.rs`；該檔在 `#[cfg(feature = "desktop")]` 之下，本機所有 gate 與多數 CI 走的 `cli` lane 都不會編譯它，因此三處 initializer 一直缺欄位，`cargo check --features desktop` 以 E0063 失敗。真正該攔下它的 CI 執行，都被同一個 ref 上較晚的 push 在 Desktop lane 跑完前取消掉了。本機沒有 GTK／webkit，無法在本地驗證 desktop feature，只能靠 CI 的 Desktop Linux lane；`837ad7f` 的該 lane 已綠。
- `879394d` 補上第一個從真實 scanner 輸出一路走到 `MasterFrameworkReport` 的整合測試。在此之前 exporter 的每一個測試都是在 `framework_report.rs` 內手工組 `AssessmentCase`，mapping catalog、adapter 與 exporter 各自有覆蓋，中間那條路徑沒有。新測試以 checked-in 的 Greenbone result-types XML 經 `FakeContainerRuntime` → `apply_execution_report` → `export_case(FrameworkReport)`，驗證三個座標、每條關聯都回得到 fixture finding 與其 evidence／artifact、mapping identity 是現行 catalog 而非未驗證的歷史版本，且匯出位元組通過 checked-in schema。AI 適用性以同一條路徑跑兩次驗證。沒有接觸任何目標：`FakeContainerRuntime` 只有記憶體狀態，fixture 位址是 RFC 5737 文件用範圍。
- push 後，`Publish managed Greenbone engine image` workflow 在 publication guard 停止：不可變的 managed image 版本標籤 `23.50.21-feed202608240615-1` 已綁定到較早的 source commit，`ef1c653` 之後每次改到 launcher 的 push 都同樣停在這裡。是否提高 managed image 版本並發布新 launcher 是產品負責人的發布決策，本輪沒有更動。在新 image 發布前，實際掃描仍使用舊 launcher 的輸出（沒有 `<result_type>`），Rust adapter 會走 legacy 保守路徑，行為與本輪之前相同；新語意目前只在 fixture 與測試中被執行。
- `0937fb3` 修好 coverage ledger 把未評估主機記成「已完成」的缺陷。`assess_asset_coverage` 現在會讀 `unevaluated_targets`：completed run 只要指名該資產，就在既有 explanation 框架內加一條 `{engine_id}={cause}` incomplete reason，不再產生 scanned 狀態。cause 排序用 exhaustive `match`，日後新增 cause 會編譯失敗而不是無聲退回 scanned。
- `3aa018e` 修好標準化報告永遠丟失整份 coverage ledger 的缺陷。Standard redaction 會把每筆 coverage 的 `scope_key` 改成 `[redacted]`，而 framework exporter 只在 `scope_key == "asset:{asset_id}"` 時才把 coverage entry 對上 planned asset；`ExportOptions::default()` 就是 Standard，因此每一份預設 framework report 的 `selected_run_coverage_ledger_available` 恆為 false、coverage state map 恆為空、`authorized_incomplete_count` 恆為 0，「authorized area(s) were only partly scanned」那句限制也永遠不會出現。現在只在 `scope_key` 恰好能由同一筆保留下來的 `asset_id` 還原時才保留該欄位，其餘（source-scoped、demo 形狀、對不上的 id）仍然遮蔽，`label` 與 `explanation` 不變。exporter 的比對條件沒有放寬。這同時解答了 `879394d` 當時未查明的 unmatched coverage entry 異常：那不是 planned-asset 計算錯誤，就是這條遮蔽。
- `4309127` 修好 Nuclei 假乾淨（見下節）。
- 本機工作樹刻意保留兩個尚未提交的 Maester 程式檔案；請先閱讀 diff，不要用 `git reset --hard` 或 `git checkout --` 丟掉：
  - `engines/images/maester/run-maester.ps1`
  - `engines/images/maester/run-maester.Tests.ps1`

接手先執行：

```bash
git status --short --branch
git diff --check
git diff -- engines/images/maester
```

## 已在 main 上成立的產品能力

- 「IT environment」主路徑可在同一個 project 中接受多個 repository、完整網站 URL 與精確內部 host，按資產型別只執行適用的 scanner。
- Repository 路徑已接上 Gitleaks、TruffleHog、Semgrep、Trivy、Grype、Checkov 與 KICS 等上游安全檢查。
- 網站路徑以 Nuclei 上游 automatic scan 與固定的安全模板池執行；每個網站是獨立 engine run，單一網站失敗不應抹掉其他網站結果。
- 內部資產路徑使用 Greenbone Community Feed 與通用的上游檢查，不包含 SonicWall、WatchGuard 或其他廠牌的自製規則。
- Greenbone 結果語意已接通 launcher → Rust adapter → 共用報告：只有 `alarm` 產生 vulnerability finding；feed vector 無法評級的 alarm 保持 `Unknown` severity（basis `unrated_vulnerability_test_alarm`）並走既有的「未評定、需人工確認」呈現；`error` 與 `dead_host` 以結構化的 `unevaluated_targets` 保存，在報告中成為該資產的 incomplete coverage 並附下一步（dead host 為 failed、tested dimensions 清空；scanner error 為 partial、已完成項目保留）；`log` 不產生 finding；沒有 `result_type` 的 legacy XML 只接受正分 finding，模糊的零分紀錄讓該輪標成 incomplete 而不是 clean；未支援的 result type 或未指向已授權資產的紀錄同樣標成 incomplete。保存、重開與英文／繁中 HTML 匯出維持相同語意。
- 混合掃描結果會進入同一份報告，依資產呈現 finding、已完成檢查、未完成範圍與上游 provenance；一個 scanner 失敗不會刪除已完成的 sibling 結果。
- Cloudsplaining finding 已保留 policy source、policy name、finding、actions、action completeness 與 attached principals，並在共用報告中產生與實際 policy 來源相符的下一步。
- Inventory、service discovery 與 connectivity 仍可作為證據，但不會被宣稱為 vulnerability finding 或成功的安全掃描。
- 21 個引擎在 `engines/catalog.json` 與 `BUILTIN_ENGINE_IDS` 兩邊完全對齊，沒有任何一邊多出或少掉的引擎；每個引擎都有 adapter fixture 與使用者可讀的中英文說明文案。三個匯出器（`framework_report`、`oscal`、`ocsf`）都只讀 `finding.control_references`，沒有任何 per-engine 分支，所以引擎一旦有映射就會同時進入三種匯出。

控制項映射的實際涵蓋範圍要據實理解：catalog 目前是 20 筆 entry、23 個控制項定義，且刻意採用 allowlist。只有 Trivy、Grype 與 Greenbone 透過 `CVE-`／OID prefix 做到廣泛映射，其餘引擎各只映射一條代表性規則。真實掃描中多數 finding 不會帶 framework reference，這是「絕不從標題或 severity 猜測控制項」的設計結果，UI 也逐筆明說「這筆問題沒有控制項映射」。但目前沒有任何一處把「本輪 M 筆 finding 中有 N 筆沒有映射」彙總出來，讀者必須自行以 framework summary 的 `finding_count` 對照 coverage 的 `selected_run_finding_count` 相減。若要提高涵蓋率或加上彙總說明，都屬產品負責人的決定。

Scanner 出現在目錄中不代表每個引擎的完整使用者路徑都已完成；應以實際上游執行、normalized result 與最終報告三層皆可驗證為準。Greenbone 的新語意目前以 launcher Go 測試、adapter fixture、報告單元測試、HTML 匯出測試與 component render 測試驗證；本輪沒有對任何真實主機執行 Greenbone，第一次真實執行留給後續的 mixed IT flow 走查。

## 尚未提交的工作

### Maester：wrapper 已修，報告層尚未接完

PowerShell wrapper 已把上游 `Investigate` 與 `Failed` 分開，並保留經清理、限制長度的 `ResultDetail.TestResult` 為 `ReviewDetail`。Pester 上次結果為 51/51。

不要把 `Investigate` 當成 vulnerability failure，也不要當成 pass。下一步應在 host adapter／共用報告中把它呈現為「需要人工確認」的 coverage item，附上上游 detail；完成端到端測試後再與 wrapper 一起提交。

## Nuclei 假乾淨：step 1 已修（`4309127`），step 2 未做

上游的實際行為比先前記錄的更嚴重，已在 pinned 副本逐行確認：

`.upstreams/projectdiscovery/nuclei/pkg/protocols/common/automaticscan/automaticscan.go`
有三條路徑會放棄該目標並且**不回傳錯誤**——第 173 行 `len(finalTags) == 0`
（technology detection 沒找到 tag，等於一個 template 都沒跑）、第 182 行
`LoadTemplatesWithTags` 失敗、以及 `getTagsUsingWappalyzer` 在 HTTP 請求失敗時回
`nil` 而落入第一條。三條都以 exit code 0 結束。

同時 `pkg/output/file_output_writer.go:19` 以 `os.O_APPEND|os.O_CREATE|os.O_WRONLY`
開檔，而 `internal/runner/runner.go:288` 在 `New()` 建構這個 writer，遠早於第 706
行的 template 載入。**所以輸出檔會被提早建立**：檔案存在且為空，和真正乾淨的掃描
完全一樣。連不上的網站與確實乾淨的網站產生逐位元組相同的產品輸出。

`4309127` 完成 step 1：

- Nuclei 從 `is_complete_empty_json_lines` 與 `is_mapping_independent_empty_json_lines`
  兩個名單移除，空 artifact 因此讓 normalization 變成 incomplete。
- 單靠 adapter 層無法處理多資產 run，所以 completed Nuclei task 另外要求**逐資產**
  有一筆 normalized record，且其 observation、finding snapshot 與 evidence 全部綁到
  這次 run、這個 engine run 與該資產（`coverage::selected_run_has_nuclei_record`）。
  沒有證據的資產失去 tested dimension 並得到 `Unavailable` coverage gap；同一個 run
  中有證據的 sibling 資產保留 tested 狀態。
- `case_service.rs` 中「verified zero-byte JSONL」的 resume 訊息改成不再宣稱空串流
  等於完整結果。副作用：release identity 有漂移時，zero-byte Nuclei 串流不再能繞過
  release 相容性做 adapter-only resume，會被擋成 `resume_release_incompatible`。

**這一步刻意保守，代價要講清楚**：在有上游執行證據之前，真正乾淨的網站也會顯示為
「無法確認已檢測」，因為零 finding 無法區分兩者。這是有意識的取捨，不是遺漏。

step 2 仍未做：需要真正的上游 outcome record 才能證明「確實執行但零 finding」。
不能只把 `-matcher-status` 打開就算數——`adapters/mod.rs` 的 `extract_nuclei` 只看
`template-id` 是否存在，不看 match status，因此未命中的執行紀錄會直接變成 finding。
step 2 必須同時改 extractor，並先用固定 fixture 驗證 automatic mode 的實際輸出。
不要依賴 `-stats-json`，automatic scan 最後階段使用 mock progress client。

## coverage ledger 與標準化報告：兩個缺陷都已修（`0937fb3`、`3aa018e`）

原本 `assess_asset_coverage` 只看 engine run 狀態、manifest 相容性與凍結授權，整個
檔案對 `unevaluated_targets` 只有一處測試 fixture 的欄位初始化，判斷邏輯完全沒讀它。
因此 Greenbone 在 `dead_host` 或 `error` 下仍以 `Completed` 結束時，該資產的 ledger
會是 `DiscoveredAuthorizedScanned` 與「All 1 compatible engine run(s) ... completed」，
`CoveragePage.tsx` 照抄成「已完成／Finished」。beginner master report 本身一直是對的
（`beginner_report.rs` 約 1627–1690 行），缺的是 ledger 這一層。`0937fb3` 依 beginner
report 的界定方式修好：只採計 `asset_id` 落在該 engine run 綁定資產內的紀錄，同一資產
`TargetDidNotRespond` 優先於 `ScannerError`，並沿用既有的

```text
The authorized scan is incomplete: {reasons}. Only completed compatible catalog-engine runs or exact completed built-in tasks can produce scanned coverage.
```

框架與 `{engine_id}={cause}` token 形狀。`finding_narrative.rs` 的
`coverage_record_detail_zh_hant` 會原樣帶過 token，所以留在框架內就不需要新增中英對照。

`879394d` 當時記為「尚未查明」的第二個問題——單一資產案件卻出現
`selected_run_matched_coverage_entry_count: 0`、`selected_run_unmatched_coverage_entry_count: 1`、
`selected_run_coverage_ledger_available: false`——已查明並修好。原因不在 planned asset
計算，而是 Standard redaction 把 `scope_key` 改成 `[redacted]`，而 exporter 用
`asset:{asset_id}` 比對。詳見 `3aa018e`。

這裡有一個值得記住的教訓：`879394d` 當時釘住「沒有任何 coverage state 把這台主機算成
scanned」的斷言，其實是**空洞通過**的——因為整個 map 是空的，它對一份什麼都沒說的報告
一樣會通過。修好 redaction 後才補上「map 非空且含 `authorized_scan_incomplete`」。
與 desktop build 在 `cfg` 之下壞掉數個 commit 沒被發現是同一種形狀：看起來像證據，
其實沒有執行到。

## 驗證方式

Rust gate 使用 CI 的 `--no-default-features --features cli` lane；預設的 `desktop` feature 需要本機沒有的 GTK／webkit 開發函式庫：

```bash
cargo fmt --all -- --check
cargo clippy --locked --workspace --no-default-features --features cli --all-targets -- -D warnings
cargo test --locked --workspace --no-default-features --features cli
npm run typecheck && npm run test:frontend && npm run test:component
node --test tests/ci/*.test.mjs
```

本機沒有 Go；Greenbone launcher 的 `gofmt` 與測試用 `engines/images/greenbone/Dockerfile` 固定的 Go image 離線執行：

```bash
docker run --rm --network none \
  -v "$PWD/engines/images/greenbone-launcher:/src:ro" \
  -w /tmp/work \
  golang:1.26.0-alpine@sha256:d4c4845f5d60c6a974c6000ce58ae079328d03ab7f721a0734277e69905473e5 \
  sh -c 'cp -R /src/. . && test -z "$(gofmt -d main.go main_test.go)" && go test ./...'
```

## 後續順序

1. Nuclei step 2：以真正的上游 outcome record 證明「確實執行但零 finding」，同時修
   `extract_nuclei` 讓未命中的執行紀錄不會變成 finding。在此之前乾淨網站會顯示為
   無法確認已檢測。
2. 把 Maester `Investigate` 接成 manual-review coverage item，與 wrapper 一起提交。
3. 移除進階 cloud／Kubernetes 路徑中產品自訂的窄 subsets，改由上游 profile 與使用者
   選定資產驅動。
4. 補齊 Trivy JAR 掃描所需的固定 Java vulnerability DB。
5. 用受控自有 fixture 走一次完整 mixed IT flow，包含第一次以新語意真實執行 Greenbone，
   量測從加入資產到第一個有用結果所需時間，優先修掉阻礙新手的步驟。

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
