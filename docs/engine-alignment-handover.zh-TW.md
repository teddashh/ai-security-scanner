# ai-security-scanner 開發交接

狀態日期：2026-09-09

最後完成的產品程式 checkpoint：`601da4b`

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
- `4932ea7` 更正 Nuclei step 2 的輸出機制說明：`-matcher-status`
  的 non-match 記錄只進入 `-o` 背後的 StandardWriter，不會進入現行
  `-jsonl-export` 的 reporting exporter，所以 step 2 不能只加一個旗標。
- `59c97bf` 先在 adapter 端釘住 `matcher-status: false` 一定不會變成 finding。
  這對目前部署的 `-jsonl-export` 輸出是 no-op，但避免 step 2 切換輸出
  通道時把「已執行但未命中」的 template 誤報為漏洞。
- `63097f3` 完成 Maester `Investigate` 的端到端 manual-review 路徑（見下節）。
  原本未提交的兩個 PowerShell wrapper 檔案已連同 adapter、保存、報告、
  Standard redaction、中英文呈現與測試一起提交，不再是工作樹中的草稿。
- `601da4b` 完成 Nuclei step 2：launcher 直接擷取上游 StandardWriter 的
  `-jsonl -matcher-status` stdout，adapter 將 error-free non-match 保存成逐資產的
  typed execution evidence；零 finding 現在可以誠實成為 tested，而 silent skip、
  scanner error、舊版 match-only 輸出仍 fail closed。細節與部署邊界見下節。

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

## Maester `Investigate`：manual-review 路徑已完成（`63097f3`）

- PowerShell wrapper 保留上游 `Investigate` verdict，不再改寫成 `Failed`，並將
  `ResultDetail.TestResult` 清理、限制為 4096 個字元後放入 `ReviewDetail`。
  `Failed` 仍是 finding，`Passed` 仍是 pass；其他非終局狀態沒有被偽造成結果。
- Rust adapter 將每一筆 `Investigate` 建立為有界、綁定已授權資產的
  `ManualReviewControl`，獨立傳過 execution report、durable report 與 `EngineRun`。
  它不進 finding，不宣稱 pass，也不把已完成的 Maester run 改成 incomplete。
- beginner report 每個 control 顯示一筆「需人工檢視」項目、上游 detail 與明確的
  人工判定下一步；asset coverage ledger 仍是
  `DiscoveredAuthorizedScanned`。UI 與 HTML 會將這區標為「需要留意的內容」，
  不再把它誤稱「未測試」。
- 無遮蔽報告保留上游 detail；Standard 匯出保留 manual-review 項目的存在，
  但遮蔽 rule id、title 與 detail。舊 case／report 缺少新欄位時會安全地解讀為空。
- wrapper Pester 為 51/51；Rust 完整 suite、frontend 568 項、component 237 項、
  TypeScript、clippy、engine admission 與 CI contract 都通過。曾故意關閉
  adapter 的 `Investigate` 路徑做 non-vacuity 檢查，新測試如預期失敗，復原後通過。

部署邊界仍需據實說明：目前 catalog 固定的 Maester image
`2.0.0-6@sha256:60913086…e3c0b` 是舊 wrapper，仍會在容器內把 `Investigate`
寫成 `Failed`；host 端無法從這種已改寫的輸出還原原意。`63097f3` 只更新建置來源
的 checksum，沒有變更 image tag、digest 或發布狀態。何時提高不可變版本並發布
新 image，仍是產品負責人的發布決定；在那之前，真實 Maester 掃描不會獲得新語意。

## Nuclei 假乾淨：step 1 與 step 2 都已完成（`4309127`、`601da4b`）

根因沒有改變：pinned Nuclei 的 automatic scan 會在 technology detection 沒找到 tag、
Wappalyzer HTTP 請求失敗，或 `LoadTemplatesWithTags` 失敗時，以 exit code 0 放棄目標，
沒有任何 security template 執行。原本的 `-jsonl-export` 只保存 match，真正零 finding
與這些 silent skip 都留下相同的空串流。

`4309127` 先採 fail-closed 的 step 1：空 artifact 不再代表 clean，且 finding 暫時被當成
逐資產執行證據。`59c97bf` 又先釘住 `matcher-status: false` 絕不會變成 finding。
`601da4b` 現已完成真正的 step 2，並刪除 finding-as-completion 例外：

- launcher 改用 `-jsonl -matcher-status`，並把 Nuclei StandardWriter 的 stdout 直接寫進
  exclusive `0600` 暫存 evidence file。沒有採用 `-o`：pinned StandardWriter 對 stdout
  逐筆補 newline，但 `-o` 的 JSON file writer 不補，會把多筆 JSON 黏在一起。
  launcher 同時移除環境中的 `DISABLE_STDOUT`，其他環境值不變；既有的
  `validateEvidenceObject`、逐 grant target/template allowlist 與 `normalizeEvidence`
  仍在 stdout 之後驗證每筆紀錄並注入確切 `asset_id`。
- automatic technology-detection phase 呼叫 `ExecuteWithResults`，不會走
  `StandardWriter.WriteFailure`；只有最後的 applicable security-template phase 才會產生
  `matcher-status:false`。因此一筆有界、已對上授權資產、且 `error` 為空的 non-match
  可以證明至少一個適用 security template 已完成。帶 scanner error 的 false record
  不算證據；match 仍完整保存為 finding，但單靠 match 也不再當完成證據，因為它可能
  來自 detection phase。
- adapter 將 qualifying non-match 依資產彙總成
  `EngineRun.security_template_executions`；它是 positive typed coverage evidence，不是
  finding。沒有這種證據的每個資產都得到
  `UnevaluatedTargetCause::NoSecurityTemplateExecutionEvidence`。這兩條資料會經過
  `ExecutionReport`、`DurableExecutionReport` 保存，重開後仍維持相同語意。
- coverage ledger 與 beginner report 現在只讀 typed positive evidence。零 finding 加上
  qualifying non-match 會顯示 tested；無 tag、載入失敗、連線失敗、空串流、舊版
  match-only case，以及只有 finding 而沒有 execution evidence 的 case，都保留 finding
  但不會被宣稱 tested。多資產 run 逐資產判斷，已證明的 sibling 不受另一資產缺口影響。
- 舊 case／report 缺少新欄位時 serde 會安全讀成空值，因此不會因為更新 reader 就把
  歷史資料升格為 clean。Nuclei 仍不在 mapping-independent zero-byte adapter-resume
  例外內，因為空串流現在會產生一個有語意的 typed coverage outcome。

這個證據刻意只做足以支持結論的保守推論：若最後階段所有適用 template 都命中、因而
沒有任何 false record，finding 仍保留，但 coverage 會維持「無法證明已檢測」。這比把
technology-detection match 誤當成 security-template completion 安全。

容量也已離線核對，沒有接觸目標：將 pinned HTTP tree 全部 11,240 個 template 的 metadata
模擬成 non-match JSON 約 10.89 MiB；實際安全 profile 是 4,674 個 template，低於 adapter
的 16 MiB artifact 與 10,000-record 邊界。

部署邊界仍需明說：catalog 目前仍固定舊的 Nuclei image
`3.11.1-5@sha256:2bd1e15a…7488`，其 launcher 仍使用 `-jsonl-export`，不會產生新的
non-match evidence。`601da4b` 只更新 httpx、naabu、nuclei 三份共用 launcher build-plan
checksum，沒有變更 image tag、digest 或發布狀態。在產品負責人決定提高不可變版本並發布
新 image 前，實際 Nuclei 掃描會保留 finding，但所有網站都會因沒有 typed execution
evidence 而顯示無法證明 tested；host adapter 無法從舊 image 的 match-only 輸出補造證據。

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

## kube-bench 產品自訂 subset 已從建置來源移除（`f6b6171`）

原本 kube-bench image 不包含上游 benchmark，而是產品自行撰寫的六個 check。它不只縮小
coverage，還改寫了上游 ID 的意義：例如產品的 `4.2.6` 檢查
`protectKernelDefaults`，但 pinned upstream CIS 1.11 的同一 ID 實際檢查
`makeIPTablesUtilChains`；產品的 `4.2.11` 也不是上游的 server-certificate feature-gate
check。這已越過 thin adapter 邊界，等於在 wrapper 內重做 detection logic。

`f6b6171` 已把這個自訂 `node.yaml` 從建置來源刪除，改為：

- 從同一個 checksum-pinned kube-bench source archive 複製上游原始
  `cfg/cis-1.11/node.yaml` 與 `config.yaml`；Docker build 另核對兩個檔案各自的 SHA-256，
  launcher 固定執行 `--benchmark cis-1.11 --targets node`，不再帶產品 check allowlist。
- 新的 `kubernetes_node_snapshot` schema 2.0.0 必須帶完整五個有界檔案、每個檔案的原始
  path／mode／owner／group／digest，以及 kubelet 與 kube-proxy 的單行 process arguments。
  backend 在建立 case snapshot 前會核對 exact inventory、digest 與有界字元；未知欄位、
  未列檔案、未知 process、symlink 或被修改的內容都 fail closed。
- image 內的 `ps`／`stat` 是同一個無 shell launcher 的有界模式，只接受 pinned upstream
  node profile 實際發出的三種 `ps` 形狀與兩種 `stat` format。它只把已驗證的 snapshot
  facts 寫到 stdout；captured command 永遠不執行，原 host path 只機械式映射到已核對的
  snapshot copy。kubelet／proxy YAML 才交給上游 parser；kubeconfig、certificate 與 service
  file 可用不含秘密的 placeholder 保存 metadata，文件明確禁止 token、private key 與真實
  certificate。
- 真實建置後以 `--network none`、read-only rootfs、drop-all capabilities、non-root user 與
  read-only fixture mount 執行成功。輸出是上游 `cis-1.11` 的完整 26 checks：15 PASS、6 FAIL、
  5 WARN；三個 upstream groups 分別是 10、15、1 checks。這份真實 artifact 已取代手寫的
  adapter fixture，mapping guard 也直接核對 26 個可達 ID。
- host reader 暫時同時接受現行 schema 1 與新 schema 2。schema 1 是 catalog 目前發布 image
  的相容邊界；schema 2 走完整新驗證。這不是把舊資料升格成 26-check coverage。

部署邊界必須據實保留：catalog 現在仍固定舊 image
`0.16.0-3@sha256:d748f983…c563`，所以實際安裝產品仍執行舊的六個產品自訂 checks。
`f6b6171` 只準備新建置來源並更新共用 launcher 與 kube-bench Dockerfile 的 plan checksum，
沒有改 image tag、digest、發布狀態、UI 的現行 schema 說明或 released-scope 文件。何時提高
不可變版本並發布／切換 image 是產品負責人的決定；在那之前不得宣稱 26-check runtime 已部署。

同輪也核對了 cloud 路徑，但沒有擴權：AWS 與 Azure Prowler 已使用上游 `iam` service；GCP
仍固定四個 checks。pinned upstream GCP IAM service 有 13 checks，會新增 Access Approval、
Cloud Asset、Service Usage、Monitoring、IAM 與 Essential Contacts 等 API 行為；現有 downstream
patch 的安全說明又明定只適用四-check profile。直接把 `--checks` 換成 `--service iam` 會在沒有
新 grant、endpoint closure 與 exact-project 行為審查時靜默擴大授權，因此本輪沒有這樣做。
ScoutSuite、CloudQuery 與 Steampipe 的進階固定 subsets 也仍是後續 cloud 工作，不因 Kubernetes
修正而被宣稱完成。

## 驗證方式

Rust gate 使用 CI 的 `--no-default-features --features cli` lane；預設的 `desktop` feature 需要本機沒有的 GTK／webkit 開發函式庫：

```bash
cargo fmt --all -- --check
cargo clippy --locked --workspace --no-default-features --features cli --all-targets -- -D warnings
cargo test --locked --workspace --no-default-features --features cli
npm run typecheck && npm run test:frontend && npm run test:component
node --test tests/ci/*.test.mjs
```

本機沒有 Go；launcher 的 `gofmt` 與測試用固定的 Go image 離線執行。Nuclei step 2 使用：

```bash
docker run --rm --network none \
  -v "$PWD/engines/images/external-launcher:/src:ro" \
  -w /tmp/work \
  golang:1.26.0-alpine@sha256:d4c4845f5d60c6a974c6000ce58ae079328d03ab7f721a0734277e69905473e5 \
  sh -c 'cp -R /src/. . && test -z "$(gofmt -d main.go main_test.go)" && go test ./...'
```

`f6b6171` 的 Rust 1,584 項、frontend 568 項、component 237 項、CI contract 32 項與
engine contract 8 項全部通過；TypeScript、clippy、format、diff check、launcher Go 測試
與真實 kube-bench image build／offline execution 也通過。scanner execution 沒有接觸任何
外部或未授權目標；建置只取得 checksum-pinned upstream source 與 Go modules。

## 後續順序

1. 繼續移除進階 cloud 路徑中的產品固定 subsets。任何較廣 upstream service/profile 都必須
   先取得產品負責人對新資產／權限／endpoint closure 的明確決定，不得以 refactor 名義擴權。
   kube-bench 的 source replacement 已完成；何時發布與切換 image 另由產品負責人決定。
2. 補齊 Trivy JAR 掃描所需的固定 Java vulnerability DB。
3. 用受控自有 fixture 走一次完整 mixed IT flow，包含第一次以新語意真實執行 Greenbone，
   量測從加入資產到第一個有用結果所需時間，優先修掉阻礙新手的步驟。

## 交接判準

每個 scanner 的工作只有在以下鏈路都成立時才算完成：

```text
使用者選定資產
  → 適用的上游 scanner 真正執行
  → finding／inventory／manual-review／incomplete outcome 保留原意
  → sibling 結果不因單點失敗消失
  → 共用報告按資產說明結果、限制與下一步
  → 保存後重開及匯出仍維持相同語意
```

本輪開發沒有接觸任何外部或未授權目標，也沒有更動發布、版本、installer、簽署或合規設定。
