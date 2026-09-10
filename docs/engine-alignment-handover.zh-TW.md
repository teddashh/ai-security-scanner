# ai-security-scanner 開發交接

狀態日期：2026-09-10

最後完成的產品程式 checkpoint：`1da9bd5`

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
- `63097f3` 完成 Maester `Investigate` 的端到端 no-verdict 路徑（見下節）。
  原本未提交的兩個 PowerShell wrapper 檔案已連同 adapter、保存、報告、
  Standard redaction、中英文呈現與測試一起提交，不再是工作樹中的草稿。
- `601da4b` 完成 Nuclei step 2：launcher 直接擷取上游 StandardWriter 的
  `-jsonl -matcher-status` stdout，adapter 將 error-free non-match 保存成逐資產的
  typed execution evidence；零 finding 現在可以誠實成為 tested，而 silent skip、
  scanner error、舊版 match-only 輸出仍 fail closed。細節與部署邊界見下節。
- `f6b6171` 以 pinned upstream CIS 1.11 node profile 取代建置來源中的六筆產品自寫
  kube-bench checks；`796d80b` 記錄其 26-check 真實離線執行與尚未發布的部署邊界。
- `686e427` 補齊 checksum-pinned Trivy Java index DB，並以兩個不重疊的上游 profile
  分別處理 working-tree lockfiles 與 individual packages；真實 no-network smoke 已證明
  unidentified JAR 可經 Java index 對上套件，再由標準 vulnerability DB 產生 CVE finding。
  詳細來源、驗證與尚未發布的邊界見下節。
- `b8bf318` 完成最終報告的直接敘述契約：掃描進行中只留在 Progress；terminal report
  直接呈現結果、影響、動作、還原與驗證；專家類型獨立作為交接欄位；掃描器未評等時
  直接顯示 Unknown；有未完成涵蓋的終止輪次標為「已完成，但有涵蓋缺口」。正式條款與
  技術工作紀錄只在報告末端出現一次，HTML 匯出同序；舊案件進入權威報告模型時也會
  正規化掉舊式人工審查、規劃核准、證據但書與責任轉移文字。
- `cbd6481` 把相同規則延伸到支援的 CLI。`doctor`、來源探索、scope、finding 群組、
  scan plan／status、engine retrieval、case deletion 與 runtime cleanup 直接回傳結構化狀態，
  不再附加重複解釋、未執行聲明或責任轉移 notice；既有 `live_discovery` 欄位仍保留。
- `502b70a` 把直接敘述契約套用到執行中的主要產品路徑。Progress、runtime setup、provider
  authorization、coverage 輸入、scan lifecycle 與應用程式動作只呈現當前結果和下一個有效
  動作；移除重複的未發生事件、保存狀態安撫、實作術語與責任轉移文字。必要的授權與精確
  scope 邊界仍以簡短明確的文字保留。
- `acac84a` 把 Rust 與 TypeScript report lifecycle 收斂為只表示終態；active work 只存在於
  Progress，report builder、snapshot 與所有 exporter 都拒絕 queued、preparing、running 或
  paused 工作。
- `5dbdeff` 完成其餘可見文案清理。App shell、更新、專案、雲端權限、Progress、Results、
  Verification 與 Export 的失敗狀態都直接給結果與下一步；移除第一人稱解釋、等待語句、
  未發生事件的安撫與首層簽章但書。正式條款維持在報告末端，必要授權邊界保持不變。
- `6247c25` 把相同契約落到 backend producer、保存結果與 recovery 狀態。20 種 typed preflight
  blocker 都限制為 160 字元內的精確狀態與下一步；runtime、cloud、workspace、network、component、
  evidence 與 cleanup 失敗不再附加重試安撫、未發生事件或實作解釋。typed code、授權邊界與
  durable outcome 語意不變。
- `8b6024b` 完成 lifecycle acknowledgement、terminal coverage gap、cleanup reconciliation、
  case deletion、export failure、platform setup 與 adapter warning 的直接化。Nuclei、Greenbone、
  packaged check、unsupported profile 與零 finding 的舊保存句子會在顯示及匯出前正規化；英／繁中
  保持同一結果，產品撰寫的中文不再使用 AI 第一人稱。掃描、授權、清理與 durable state 語意不變。
- `1da9bd5` 移除取消、案件刪除 blocker 與 Windows setup 中剩餘的等待後重做、保留安撫及程序
  自述。雲端 IT request 改為中性句子；請求與 device code 複製在 Clipboard API 失敗時會自動走
  有界的 document-copy fallback，兩條路徑都失敗時只呈現精確結果，不把 workaround 丟給新手。

## 已在 main 上成立的產品能力

- 「IT environment」主路徑可在同一個 project 中接受多個 repository、完整網站 URL 與精確內部 host，按資產型別只執行適用的 scanner。
- Repository 路徑已接上 Gitleaks、TruffleHog、Semgrep、Trivy、Grype、Checkov 與 KICS 等上游安全檢查。
- 網站路徑以 Nuclei 上游 automatic scan 與固定的安全模板池執行；每個網站是獨立 engine run，單一網站失敗不應抹掉其他網站結果。
- 內部資產路徑使用 Greenbone Community Feed 與通用的上游檢查，不包含 SonicWall、WatchGuard 或其他廠牌的自製規則。
- Greenbone 結果語意已接通 launcher → Rust adapter → 共用報告：只有 `alarm` 產生 vulnerability finding；feed vector 無法評級的 alarm 保持 `Unknown` severity（basis `unrated_vulnerability_test_alarm`），並直接說明上游未提供評等；`error` 與 `dead_host` 以結構化的 `unevaluated_targets` 保存，在報告中成為該資產的 incomplete coverage 並附下一步（dead host 為 failed、tested dimensions 清空；scanner error 為 partial、已完成項目保留）；`log` 不產生 finding；沒有 `result_type` 的 legacy XML 只接受正分 finding，模糊的零分紀錄讓該輪標成 incomplete 而不是 clean；未支援的 result type 或未指向已授權資產的紀錄同樣標成 incomplete。保存、重開與英文／繁中 HTML 匯出維持相同語意。
- 混合掃描結果會進入同一份報告，依資產呈現 finding、已完成檢查、未完成範圍與上游 provenance；一個 scanner 失敗不會刪除已完成的 sibling 結果。
- Cloudsplaining finding 已保留 policy source、policy name、finding、actions、action completeness 與 attached principals，並在共用報告中產生與實際 policy 來源相符的下一步。
- Inventory、service discovery 與 connectivity 仍可作為證據，但不會被宣稱為 vulnerability finding 或成功的安全掃描。
- 21 個引擎在 `engines/catalog.json` 與 `BUILTIN_ENGINE_IDS` 兩邊完全對齊，沒有任何一邊多出或少掉的引擎；每個引擎都有 adapter fixture 與使用者可讀的中英文說明文案。三個匯出器（`framework_report`、`oscal`、`ocsf`）都只讀 `finding.control_references`，沒有任何 per-engine 分支，所以引擎一旦有映射就會同時進入三種匯出。

控制項映射的實際涵蓋範圍要據實理解：catalog 目前是 20 筆 entry、23 個控制項定義，且刻意採用 allowlist。只有 Trivy、Grype 與 Greenbone 透過 `CVE-`／OID prefix 做到廣泛映射，其餘引擎各只映射一條代表性規則。真實掃描中多數 finding 不會帶 framework reference，這是「絕不從標題或 severity 猜測控制項」的設計結果，UI 也逐筆明說「這筆問題沒有控制項映射」。但目前沒有任何一處把「本輪 M 筆 finding 中有 N 筆沒有映射」彙總出來，讀者必須自行以 framework summary 的 `finding_count` 對照 coverage 的 `selected_run_finding_count` 相減。若要提高涵蓋率或加上彙總說明，都屬產品負責人的決定。

Scanner 出現在目錄中不代表每個引擎的完整使用者路徑都已完成；應以實際上游執行、normalized result 與最終報告三層皆可驗證為準。Greenbone 的新語意目前以 launcher Go 測試、adapter fixture、報告單元測試、HTML 匯出測試與 component render 測試驗證；本輪沒有對任何真實主機執行 Greenbone，第一次真實執行留給後續的 mixed IT flow 走查。

## Maester `Investigate`：no-verdict 路徑已完成（`63097f3`、`b8bf318`）

- PowerShell wrapper 保留上游 `Investigate` verdict，不再改寫成 `Failed`，並將
  `ResultDetail.TestResult` 清理、限制為 4096 個字元後放入 `ReviewDetail`。
  `Failed` 仍是 finding，`Passed` 仍是 pass；其他非終局狀態沒有被偽造成結果。
- Rust adapter 將每一筆 `Investigate` 建立為有界、綁定已授權資產的
  `ManualReviewControl`，獨立傳過 execution report、durable report 與 `EngineRun`。
  它不進 finding，不宣稱 pass，也不把已完成的 Maester run 改成 incomplete。
- beginner report 每個 control 顯示一筆「未回傳自動判定」項目、上游 detail 與「開啟
  上游詳細資料並設定狀態」的直接下一步；asset coverage ledger 仍是
  `DiscoveredAuthorizedScanned`。UI 與 HTML 會將這區標為「需要留意的內容」，
  不再把它誤稱「未測試」。
- 無遮蔽報告保留上游 detail；Standard 匯出保留 no-verdict 項目的存在，
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

後續逐一核對其餘 cloud launcher 後，沒有找到另一個可像 kube-bench 一樣直接移除的產品偵測
subset：ScoutSuite 已以 `aws --services iam` 交給上游完整 IAM service，產品 patch 只移除
HTML／SQLite 報告依賴並保留 JSON；CloudQuery 的七張 table 與 Steampipe 的單一 SQL 都明確是
inventory evidence，不是 security detector 或成功掃描。擴充它們會改變收集資料、權限或
endpoint closure，不能以「補齊 detector」名義進行。GCP Prowler 的四-check 邊界仍需產品
負責人先決定新增資產、權限與 endpoint；在此之前 cloud subset 稽核沒有安全的程式變更。

## Trivy Java index 與 JAR working-tree 路徑已在建置來源完成（`686e427`）

原本 managed Trivy image 只有標準 vulnerability DB。Repository／IaC 的 `filesystem` profile
能讀 lockfile 與 `pom.xml`，但 pinned Trivy 上游會在這個 mode 明確停用
`TypeIndividualPkgs`，所以只存在於 JAR 內容中的套件不會被分析。直接改成 `rootfs` 也不對：
上游 `rootfs` 恰好會停用 lockfile analyzers，會讓現有 manifest coverage 消失。

`686e427` 保留兩組上游 detector family，而沒有在 wrapper 重寫判斷：

- `prepare-offline-engine-data.mjs` 以 anonymous pull 取得並驗證 Java DB schema 1 的 immutable
  manifest `sha256:0a859620…8829`、單一 layer `sha256:90775452…de4`、media type、title 與
  963,142,179-byte 大小；Docker build 再核對 archive、`trivy-java.db` 與 `metadata.json`
  SHA-256，並把 DB 設為唯讀。標準 vulnerability DB 的既有 pin 不變。
- Repository 與 IaC 先跑上游 `filesystem --pkg-types library` 保存 lockfile 結果，再跑上游
  `rootfs --pkg-types library` 保存 individual package archive／binary 結果到獨立 JSON。
  兩次都固定 `--scanners vuln`、memory cache、所有 DB／VEX／version／telemetry update 關閉，
  讀同一份已授權的唯讀 snapshot，沒有 shell 或動態 scanner argument。OCI profile 仍只有
  一次 `image --pkg-types os`，不會加入 working-tree pass 或 OCI language-package coverage。
- Launcher 在 repository／IaC 執行前核對標準 DB 與 Java DB 的實際檔案 hash；兩個 output
  path 都必須事先不存在，且每份 evidence 都要通過 bounded JSON 驗證。Rust adapter 原本就
  能處理同一次 engine run 的多個 raw artifacts；新增的 non-vacuity 測試同時餵入 lockfile
  與 individual-package JSON，確認兩筆 finding 保留各自 artifact provenance。
- 真實 image build 以 workflow 同等的 read-only rootfs、non-root user、drop-all capabilities、
  `--network none` 走過三條路徑：`lodash` 4.17.20 lockfile finding；沒有可用 package metadata、
  只能靠 SHA-1 查 Java index 的 upstream JAR fixture，解析成
  `org.apache.tomcat.embed:tomcat-embed-websocket` 9.0.65 並回報 `CVE-2024-23672`；以及原本的
  single-image OCI OS-only profile，確認沒有 `lang-pkgs` 與第二份 working-tree output。

部署邊界仍與其他 source-prepared engine 相同：catalog 目前固定的 Trivy image 是
`0.74.0-3@sha256:6b19f889…dfe4`，它沒有 Java DB，也只會產生舊的單一 filesystem output；
`engines/catalog.json` 與使用者文件因此仍據實排除 JAR-only repository discovery。
`686e427` 沒有提高 tag、改 digest、發布 image 或切換 runtime。何時建立新的 immutable image
coordinate 並啟用它，是產品負責人的發布決定；在那之前不得宣稱 JAR coverage 已部署。

## mixed IT 共用報告 lifecycle 已有不接觸目標的整合證據（`2e8c3aa`）

新增的 `local_case_lifecycle` 整合測試把一份 immutable repository snapshot、一個
`.example.test` HTTPS origin 與一個 TEST-NET internal host 放進同一個
`InternalItEnvironment` case。一次 atomic Start 同時保存三份 exact grant 與 disjoint route：
Gitleaks 只讀 repository、Nuclei 只收 website、Greenbone 只收 host 的 443／8443。測試再以
checked-in upstream-shaped outputs 與 in-process `FakeContainerRuntime` 走過真正的 orchestrator、
adapter、durable reconciliation 與 beginner report；Nuclei 的 frozen hostname／address snapshot
也必須通過 managed-network scope contract。

這條 vertical 刻意讓 Greenbone 回報 `dead_host`／scanner error，同時保留已完成的 Greenbone
alarms。最後一份共用報告必須把 host 顯示成 failed coverage，但不能抹掉 repository、website
或 host 已保存的 findings；三個資產與三個 checks 都必須留在 run-frozen report。資料庫重開後
重建的 report 必須逐欄相同，HTML export 也必須可驗證、含三個資產與主要結果，而且不能洩漏
secret／target-controlled fixture 欄位。這補上了先前「前端 route 測試」與「各自 backend
vertical」之間缺少的一條完整 shared-report lifecycle。

這仍不是 installed-desktop 或真實 scanner 證據。本機 read-only preflight 顯示 Docker
compatibility service 可用，但 release-managed runtime payload 尚未安裝；Linux host 也缺少
desktop feature 所需的 GTK／WebKit system libraries。CLI 的 scan start 本來就拒絕執行，因為
scan control 只屬於 desktop process。本輪沒有安裝 runtime／system packages、建立真實 target
授權或接觸任何 target。若要完成 installed walkthrough，需要使用者先明確授權所需安裝，並為
一個確切自有 website 與 internal host 提供當輪 scope confirmation；不能把測試 fixture 的 grant
當成操作授權。

## mixed IT setup 不再建立沒有可執行檢查的專案（`d2599a1`）

先前 combined environment 表單把僅供盤點的 CIDR 當成「至少一項環境資產」，因此新手可以只加入
一個明確標示不會掃描的網段、建立專案，然後才在下一頁發現沒有 scan-ready asset。現在至少要有
一個 repository folder、website／API origin 或 exact internal host；inventory-only range 仍可與其中
任一可掃描資產一起保存，也仍會在共同報告中標示為 not tested。

這個邊界沒有犧牲具體輸入回饋：若 inventory-only CIDR 本身格式錯誤，表單會先打開原本收合的欄位、
顯示該 CIDR 的精確錯誤並把焦點放回該欄位；格式有效但沒有可掃描資產時，才顯示 bilingual
scan-ready 說明並把焦點移到第一個 exact-host 欄位。unit test 同時鎖住「單獨 inventory 不成立」與
「搭配 repository snapshot 時仍完整保存」，rendered component test 則鎖住錯誤文案、未建立 case
與 focus 行為。本輪只調整 setup validation／presentation，沒有執行 scanner 或接觸 target。

## 選填的 organization size 不再暗中猜成 2–49 人（`77c54fc`）

`Optional project details` 預設是收合的，但先前表單 state 仍預選 `small`，所以完全沒打開這一區的
新手也會被保存成 2–49 人。現在 frontend model 有明確的 `unknown`；新建 case 預設保存既有 schema
可接受的 `Not provided`，native snapshot 重開後也還原為 `unknown`。使用者主動選取的 solo、small、
medium、large band 與舊 case 都不變，scanner routing／finding priority 也沒有因此改寫。

rendered website setup test 確認收合區內的預設值與送出的 case 都是 unknown；native serialization
test 確認 wire value 是 `Not provided`；adapter test 確認重開不會再把它投影成 small。這只移除
product-owned metadata guess，沒有增加問題、權限、目標或 scanner 執行。

## Home、Review、Progress 共用精簡時間目標（`cd0adda`）

Home 的 company IT environment、website 與 code／AI project 三個主要選項現在先說結果與動作，
不再把 scanner 名稱、inventory 條款或各路徑的延長因素塞進首層。三張卡、focused Review 與 active
Progress 都從 `primaryScanTiming` 取得同一句：「工具就緒後幾分鐘內提供有用結果」。私密副本建立中
也只說系統正在自動準備，不再要求使用者自行等待或切換頁面。

Nuclei／Greenbone、exact origin／host、rate、concurrency、timeout、read-only snapshot 與 inventory
邊界仍在會改變 Start 決定的 review／scope detail 中。advanced path 與 localhost connection utility
沒有這項 security-result timing。rendered tests 鎖住兩種語言的 Home 三張卡、三種 Review、active
Progress 與自動建立私密副本的狀態。

## Progress 會指出目前 check 綁定的資產（`00dc9a1`）

Progress 的 activity first layer 先前只顯示 current／next scan tool，沒有滿足 product spec 所寫的
「which asset is being checked」。現在 active、paused 或 queued run 會列出 current／next engine
run 綁定且有可讀名稱的資產。若 live／frozen beginner report 已保存 target label，畫面優先採用該
run-bound label；否則才使用目前 workspace 的 saved asset name。正在執行的 engine 存在時，不會把
pending sibling 的資產混成目前工作；多 engine 共用的資產名稱也只顯示一次。

這個 presentation 不會把 raw scanner message、warning 或 technical asset ID 當成資產名稱。無法在
report 或 workspace 解出名稱的 ID 會留在 technical／durable record，而不洩漏到 first layer。
rendered component test 同時鎖住 run-bound label 優先順序、兩個 active assets、pending sibling 與
unknown ID 的排除，以及 Traditional Chinese label。shareable diagnostic 仍不包含 target name、path
或 asset ID。

## Progress first layer 分開完成、剩餘與需要處理的工作（`083040c`）

先前 run overview 只有「已完整檢查 X／Y 個目標」，而完整 scanner-state ledger 收在 technical
details；新手無法直接看出還有多少工作或多少項已停止。現在 overview 以兩行 compact bilingual
summary 分開顯示 assets 的 fully checked／remaining／need attention，以及 checks 的
completed／remaining／need attention。check counts 直接使用 durable `EngineRun.status`；asset 完成數
保留 backend `coveredAssetCount`，部分、失敗、未執行或取消的 engine 所綁定資產會計入 attention。

active／queued／paused run 中其餘未涵蓋資產才算 remaining。run 一旦 terminal，所有未完整涵蓋資產
都轉成 attention，即使舊資料沒有留下可對應的 engine asset ID，也不會繼續顯示成正在執行。
exact localhost connection utility 不套用這個 security-scan summary，仍使用自己的 connection
outcome presentation。rendered tests 鎖住一個 completed、一個 active、一個 failed 的 mixed run，
以及 terminal cancellation 含一個無法歸因 asset 的 conservative count；static localization test
同時鎖住兩種語言與 asset／check 用詞。

## active scan 固定留在 Progress（`137db23`）

執行中的 selected run 只顯示 Progress：durable finding count、check outcome、asset/check
completed／remaining／attention 數量與目前資產會持續更新，但不開啟 Results，也不建立任何格式的
preview、document 或 case bundle。直接呼叫 beginner、OCSF、OSCAL 或 framework exporter 時也套用
相同 terminal gate，避免繞過 UI；被拒絕的 bundle 不會建立目錄、key、temporary archive 或目的檔案。

Results 與 Export 的 active deep link 都只顯示簡短的 Scan in progress 動作並返回 Progress。terminal
run 才顯示 per-asset result、finding、coverage gap 與儲存選項。HTML 首層移除 lifecycle、報告變動與
防禦性說明段落，只留下結果摘要、最後保存時間與可執行內容；正式條款維持在報告末端，machine-facing
evidence 維持 collapsed technical detail。這項產品規則已同步寫入 `docs/product-spec.md`、AGENTS、
CLAUDE、CONTRIBUTING，以及 Codex／Claude 的 ai-security-scanner skill。

## 報告資料模型只保留終態（`acac84a`）

Rust 與 TypeScript 的 beginner report lifecycle 現在都只能表示 `final`。report builder 遇到
queued、preparing、running 或 paused 工作會回傳 `RunInProgress`；desktop snapshot 只投影終態
run；HTML、JSON、framework、OCSF、OSCAL 與 case bundle 共用相同 terminal gate。進行中的工作
只能從 Progress 查看，不會產生可預覽、可保存或可匯出的報告。

Results、Coverage、Verification、Export、runtime setup、provider authorization、demo 與 scan
lifecycle 文案已統一成「目前結果＋下一個動作」。缺少報告、結果處理、runtime ownership、catalog
差異及 historical coverage 都直接顯示狀態與 recovery action；舊 case 中的防禦性句子會先正規化，
不會再送到畫面或新匯出檔。正式條款仍只出現在報告末端，技術證據仍留在收合細節。

## 可見產品文案直接化（`5dbdeff`）

剩餘的 saved-data、update、setup、project、preview、verification、export 與 correlation 文案已
移除「我們無法」、稍後重試、未建立檔案／未更動資料等防禦性敘述，改成精確結果與單一步驟。
Export 首層只列完整性狀態；完整條款留在報告末端。產品指引改用程式、掃描或所選狀態為主詞，
不再以 AI 第一人稱介入操作流程。真正的限時雲端存取、破壞性刪除警告及目標授權仍保留原意。

## 前置檢查與保存結果直接化（`6247c25`）

直接敘述契約已從畫面延伸到 Rust producer。20 種 `ScanReadinessBlocker` 各自回傳精確狀態與
下一步，不再共用模糊的 scope 說明；單元測試逐一鎖住非空、160 字元上限及禁用句型。
Greenbone partial coverage、無適用檢查、localhost connection、managed runtime、bootstrap、
egress 與 cleanup/recovery 紀錄同步採用直接結果。英／繁中共用敘述表與畫面文字已一起更新。

## 生命週期與舊案件結果直接化（`8b6024b`）

取消／繼續回應、rate limit、localhost 終態、managed runtime、cleanup reconciliation、case
deletion、export、platform 與 adapter warning 已統一為「精確狀態＋下一步」。報告中的 Nuclei
證據缺口、Greenbone dead host／scanner error、packaged scanner 資訊缺口、unsupported profile
與 completed checks 零 finding 都直接標明結果。舊案件中的原句會在 Rust 與 TypeScript
presentation layer 正規化後再顯示或匯出；英／繁中對應由 parity 與 presentation tests 鎖定。
掃描範圍、target binding、認證、清理判定與 durable outcome 沒有改變。

## 取消、setup 與雲端交接收斂（`1da9bd5`）

取消中的 result state、active scan／provider discovery 案件刪除 blocker、managed runtime
cancellation、Windows WSL servicing timeout／cooldown 及 managed-egress cleanup 都改成單一目前
狀態，不再要求等待後重按，也不再解釋保留資料或程式接下來會做什麼。雲端交接請求不使用
`me`／`our`；Clipboard API 失敗時由程式執行第二條 copy path，完成後移除輔助 DOM 並恢復原焦點。

## Setup 終態與失敗文案收斂（`0396db3`）

進階本機工具取消狀態已在 assistant、sidebar 與應用程式通知統一為「已取消／尚未就緒」；停止
操作不再承諾保留下載，也不再以暫停、等待或稍後再試解釋目前狀態。真正可用的「繼續設定」仍
保留為操作。專案建立失敗、桌面服務不可用、技術錯誤 fallback 與 adapter conversion 進度也改成
精確結果或正在執行的工作；英／繁中及 rendered component 契約同步鎖定。

## 引擎警告顯示層直接化（`048df2c`）

Progress 的引擎技術警告統一經過英／繁中產品顯示層。Adapter 仍保存精確診斷與證據語意；畫面只
說明哪些記錄被排除、哪些結果不完整、哪些參照不可用，以及真正可執行的下一步。不再顯示 raw
artifact／valid findings 已保留、未臆造 finding、使用者停止掃描等辯護句，也不把 adapter、pinned
reporter 或 result reader 等實作細節當成使用者操作。Producer census 逐條驗證目前所有警告形狀。

## Setup、shell 與 localhost 狀態收斂（`6d545d9`）

Settings 不再解釋重試沿用進度、暫停保留下載或繼續後恢復下載；只說明 setup 會下載工具，以及真正
需要 Windows restart 時會顯示下一步。Shell refresh、localhost quick start、unsupported pause、
cancelling 與 setup finished-but-not-ready 都直接顯示目前狀態與可用操作。Capture stage 只說正在記錄
掃描器輸出，不把保存中的資料描述成報告，也不加入未發生事項或之後再試的說明。

## 佇列、執行與待驗證狀態直接化（`b691aaf`）

Pending engine 與 queued run 統一顯示 `Queued／已排入佇列`；Progress activity 直接顯示
`Next check queued` 或 `Scan tool running`，不再說正在等待工具回報。Paused check 的下一步直接是
`Continue scan／繼續掃描`。續跑通知、重新啟動接續點、cleanup checkpoint，以及 finding／case 的
fix verification 狀態也改用 queued 或 pending 語意。Core presentation、shared locale 與 rendered
Progress tests 同時鎖住英／繁中結果及禁用的等待式舊文案。

## Setup 必要條件與缺少資料狀態直接化（`ed5c831`）

內部網站與主動測試的授權邊界維持不變，但畫面改由產品直接陳述 Start 的必要確認與授權欄位，不再
寫成「你必須」。未連接來源直接顯示 `no connected source`；Coverage 與 Results 統一顯示缺少資料
的來源數。Cloud cleanup 直接顯示需要處理的清理紀錄與 `temporary access expiry pending`，不再要求
等待或把 setup 狀態寫成可能需要使用者注意。重新啟動接續點只陳述已記錄的 checkpoint，不再加入
不會自動重連的實作說明。

## Start 與雲端連線邊界直接化（`0a9e96a`）

Start 頁面直接要求先選一項，其他檢查從「掃描設定」加入；網路掃描以精確目標、檢查類型與限制作為
開始條件，不再解釋選項只是讓下一頁變短，也不以「由你掌控」作防禦性保證。雲端連線直接列出組織
app／role 的必要條件、官方頁面的管理員核准，以及唯讀存取與自動到期邊界；移除未提供 shared
OAuth、表單不會收到密碼、檔案之後丟棄等機制辯護。Windows restart 則直接列出重啟、重開專案、
繼續設定、確認目標與 Start 的順序。

## Runtime 階段與 cleanup 結果精確化（`cb60dbe`）

Managed runtime 的啟動、驗證、失敗與授權需求改成精確狀態，不再顯示第一次可能需要一點時間、快準備
好了或需要注意等模糊文字。暫時雲端 cleanup 直接顯示 required action，不再要求在關閉程式前處理；
案件證據目錄不存在時只顯示 backend 已確認的結果，不再解釋沒有送出刪除命令。

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

`686e427` 的 pinned Go launcher test、完整 Rust CLI suite（含 92 項 adapter fixtures）、
clippy、format、engine admission、line-ending、fixture reproduction 與 32 項 CI contract 均通過；
Trivy 離線資料 materialization、image build、embedded label／notice 核對，以及上述三條真實
no-network smoke 也通過。執行只讀 repository／JAR／OCI fixtures，沒有接觸任何掃描目標。

`2e8c3aa` 新增後，完整 Rust CLI suite、`clippy -D warnings`、format／diff check 與
`coverageConciseBoundaries` 18 項 component tests 都通過。新增 vertical 本身以 temporary
case database、private artifact directory、checked-in outputs 與 `FakeContainerRuntime` 執行，
沒有 DNS lookup、socket、container runtime 或 target contact。

`d2599a1` 新增後，frontend 568 項、component 238 項、TypeScript typecheck 與 production frontend
build 全部通過。production build 只有既有的大型 chunk 提示，沒有 build failure。

`77c54fc` 新增後，相同的 frontend 568 項、component 238 項、TypeScript typecheck 與 production
frontend build 再次全部通過；build 仍只有既有的大型 chunk 提示。

`a94131a` 新增後，frontend 568 項、component 238 項、TypeScript typecheck 與 production frontend
build 全部通過；build 只有既有的大型 chunk 提示。

`282d3fb` 新增後，相同的 frontend 568 項、component 238 項、TypeScript typecheck 與 production
frontend build 再次全部通過；build 仍只有既有的大型 chunk 提示。

`4ad0759` 新增後，frontend 568 項、component 242 項、TypeScript typecheck 與 production frontend
build 全部通過；build 仍只有既有的大型 chunk 提示。本輪沒有執行 scanner 或接觸 target。

`00dc9a1` 新增後，frontend 568 項、component 243 項、TypeScript typecheck 與 production frontend
build 全部通過；build 仍只有既有的大型 chunk 提示。本輪沒有執行 scanner 或接觸 target。

`083040c` 新增後，frontend 568 項、component 245 項、TypeScript typecheck 與 production frontend
build 全部通過；build 仍只有既有的大型 chunk 提示。本輪沒有執行 scanner 或接觸 target。

`137db23` 新增後，完整 Rust CLI suite 1,588 項、frontend 569 項、component 252 項、CI contract
32 項、TypeScript typecheck、clippy、format、diff check 與 production frontend build 全部通過；
build 只有既有的大型 chunk 提示。本輪沒有執行 scanner 或接觸 target。

`cd0adda` 新增後，frontend 569 項、component 252 項、CI contract 32 項、TypeScript typecheck、
diff check 與 production frontend build 全部通過；build 只有既有的大型 chunk 提示。本輪沒有執行
scanner 或接觸 target。

`b8bf318` 新增後，完整 Rust CLI suite 1,588 項、frontend 569 項、component 252 項、CI contract
32 項、TypeScript typecheck、production frontend build、clippy、format 與 diff check 全部通過；
build 只有既有的大型 chunk 提示。本輪只處理本機程式碼與 checked-in fixtures，沒有執行 scanner
或接觸 target。

`cbd6481` 新增後，完整 Rust CLI suite 1,588 項、CLI binary 35 項、clippy、format 與 diff check
全部通過；重建後的實際 `doctor --json` 輸出已確認沒有頂層 defensive notice。本輪沒有執行
scanner 或接觸 target。

`502b70a` 新增後，frontend 569 項、component 252 項、CI contract 32 項、TypeScript typecheck、
production frontend build、完整 Rust CLI suite、`clippy -D warnings`、format 與 diff check 全部
通過；build 只有既有的大型 chunk 提示。

`acac84a` 新增後，完整 Rust CLI workspace 1,588 項、frontend 569 項、component 252 項、CI
contract 32 項、TypeScript typecheck、production frontend build、`clippy -D warnings`、format
與 diff check 全部通過；build 只有既有的大型 chunk 提示。本輪沒有執行 scanner、刪除 RAM disk
資料或接觸任何 target。

`5dbdeff` 新增後，frontend 569 項、component 252 項、CI contract 32 項、TypeScript typecheck、
production frontend build 與 diff check 全部通過；build 只有既有的大型 chunk 提示。本輪沒有
執行 scanner、刪除 RAM disk 資料或接觸任何 target。

`6247c25` 新增後，完整 Rust CLI workspace 1,589 項、frontend 569 項、component 252 項、CI
contract 32 項、TypeScript typecheck、production frontend build、`clippy -D warnings`、format
與 diff check 全部通過；build 只有既有的大型 chunk 提示。本輪沒有執行 scanner、刪除 RAM
disk 資料或接觸任何 target。

`8b6024b` 新增後，完整 Rust CLI workspace 1,590 項、frontend 571 項、component 252 項、CI
contract 32 項、TypeScript typecheck、production frontend build、`clippy -D warnings`、format
與 diff check 全部通過；build 只有既有的大型 chunk 提示。本輪沒有執行 scanner、刪除 RAM
disk 資料或接觸任何 target。

`1da9bd5` 新增後，完整 Rust CLI workspace 1,590 項、frontend 572 項、component 253 項、CI
contract 32 項、TypeScript typecheck、production frontend build、`clippy -D warnings`、format
與 diff check 全部通過；build 只有既有的大型 chunk 提示。本輪沒有執行 scanner、刪除 RAM
disk 資料或接觸任何 target。

`0396db3` 新增後，frontend 573 項、component 253 項、CI contract 32 項、TypeScript typecheck、
production frontend build 與 diff check 全部通過；build 只有既有的大型 chunk 提示。Rust 程式碼
未變更，沿用上一個已通過的 1,590 項完整 Rust CLI workspace 基線。本輪沒有執行 scanner、刪除
RAM disk 資料或接觸任何 target。

`048df2c` 新增後，frontend 573 項、component 253 項、TypeScript typecheck、production frontend
build 與 diff check 全部通過；producer census 涵蓋目前 70 種以上的 product-authored engine-warning
形狀，Progress rendered case 也通過。Rust 程式碼未變更，本輪沒有執行 scanner、刪除 RAM disk
資料或接觸任何 target。

`6d545d9` 新增後，frontend 573 項、component 253 項、TypeScript typecheck、production frontend
build 與 diff check 全部通過；相關 setup、shell、capture 與 localhost 舊文案搜尋結果為零。

`b691aaf` 新增後，frontend 574 項、component 254 項、TypeScript typecheck、production frontend
build 與 diff check 全部通過；rendered Progress test 驗證 queued 與 running 畫面，shared locale、
per-check next step 及 resume lifecycle tests 驗證英／繁中直接狀態。Rust 程式碼未變更，沿用已通過的
1,590 項完整 Rust CLI workspace 基線。本輪沒有執行 scanner、刪除 RAM disk 資料或接觸任何
target。

`ed5c831` 新增後，frontend 575 項、component 254 項、TypeScript typecheck、production frontend
build 與 diff check 全部通過；Cases、Coverage 與 provider cleanup 的 rendered tests，以及跨頁面
direct-copy contract 均通過。Rust 程式碼未變更，本輪沒有執行 scanner、刪除 RAM disk 資料或接觸
任何 target。

`0a9e96a` 新增後，frontend 575 項、component 254 項、TypeScript typecheck、production frontend
build 與 diff check 全部通過；Start 與 provider setup 的 unit／rendered contracts 及 runtime-deferred
scan tests 均通過。Rust 程式碼未變更，本輪沒有執行 scanner、刪除 RAM disk 資料或接觸任何 target。

`cb60dbe` 新增後，frontend 575 項、component 254 項、TypeScript typecheck、production frontend
build 與 diff check 全部通過；shared i18n contract、Cases 與 Coverage rendered tests 均通過。Rust
程式碼未變更，本輪沒有執行 scanner、刪除 RAM disk 資料或接觸任何 target。

## 後續順序

1. 在使用者明確允許安裝缺少的 managed runtime／desktop dependencies，並對確切自有 target
   提供當輪 authorization 後，用 installed desktop 走一次真實 mixed IT flow，涵蓋 repository、
   內部 host 與 website 的 setup、progress、共同報告、保存重開與 readable export。量測從加入
   資產到第一個有用結果的時間，優先修掉阻礙新手的步驟。`2e8c3aa` 已證明不接觸目標的結構
   lifecycle，但不能代替真實 scanner 或 installed UI 證據；若要驗證新 Greenbone result-type
   語意，還需要產品負責人先決定對應 immutable image 切換。
2. Cloud 稽核目前唯一確定仍窄於 upstream service 的 GCP Prowler profile 會改變權限與 endpoint
   closure。只有在產品負責人明確決定新資產／權限／endpoint 後才繼續；ScoutSuite 已是完整
   upstream IAM service，CloudQuery 與 Steampipe 是 inventory，不列為 detector subset 待辦。

## 交接判準

每個 scanner 的工作只有在以下鏈路都成立時才算完成：

```text
使用者選定資產
  → 適用的上游 scanner 真正執行
  → finding／inventory／no-verdict／incomplete outcome 保留原意
  → sibling 結果不因單點失敗消失
  → 共用報告按資產說明結果、限制與下一步
  → 保存後重開及匯出仍維持相同語意
```

本輪開發沒有接觸任何外部或未授權目標，也沒有更動發布、版本、installer、簽署或合規設定。
