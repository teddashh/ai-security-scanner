# 引擎接線與結果對齊 — 交接文件

日期：2026-09-05

主線分支：`main`（無其他分支或 worktree）

涵蓋範圍：`f21e6fc..0392aea`（29 個 commit）

最後驗證檢查點：`0392aea`，12 道本機閘門全綠，工作目錄乾淨。

前一份交接是 `docs/honesty-audit-handover.md`（範圍 `122a5fd..c5c9a41`，使用者面向誠實性稽核）。
那是另一條工作線，本文件接在它後面，不取代它。

## 這條工作線要解決什麼

指令是三件事，而且有順序：

1. **把每一個套件都趕快接起來**
2. **讓它們的掃描結果全部對齊到同一張清單**
3. **讓新手好用**

這三件事其實是同一個失敗模式的三個切面。一個引擎跑完、輸出被讀進來、
但欄位對不上，結果就是「掃描成功、零個問題」——這比掃描失敗更糟，因為
使用者沒有任何線索知道自己被騙了。同理，二十一個引擎各自用自己的字彙講
嚴重度，那張清單就不是一張清單，是二十一張疊在一起的清單。而只要有一句
話是英文，中文使用者讀到的就是一個他無法處理的洞。

本區間找到的主要缺陷類別是：**產品自己編造了引擎沒有說過的話**——編造嚴重度、
把自己的字面值當成引擎的評分讀回來、用一個籠統的原因取代後端實際記錄的原因。

## 完成了什麼

| | |
|---|---|
| Commit 數 | 29（18 `fix`、9 `feat`、1 `test`、1 `security`） |
| Diff | 62 個檔案，+8,917 / −451 |
| Rust 測試（`cargo test`） | 1,391 通過（本區間 `#[test]` 宣告數 1,158 → 1,202，靜態計數） |
| 前端測試（`node --test`） | 404 → 438 |
| 元件測試（vitest + jsdom） | 95 → 117 |
| CI lane 測試 | 29（本區間未新增） |
| 新增測試檔 | 7 |

新增的測試檔：

- `tests/frontend/findingNarrative.test.ts`
- `tests/frontend/findingNarrativeParity.test.ts`
- `tests/frontend/correlationService.test.ts`
- `tests/frontend/correlationWireContract.test.ts`
- `tests/frontend/nativeCommandRegistry.test.ts`
- `tests/component/findingCorrelations.test.tsx`
- `tests/component/findingNarrativeLocalization.test.tsx`

---

## 第一條：把套件真的接起來

「接起來」的判準不是「adapter 存在」，而是「餵真實輸出進去會出來正確的
finding」。二十一個 adapter fixture 全部重新對照上游 pin 住的原始碼稽核過一遍。

1. **ScoutSuite 與 Cloudsplaining 讀不到任何東西** — `da6729a`
   兩個 adapter 都在解析上游根本不會產生的形狀。真實輸出進去是零筆。
2. **Kubescape 只讀 roll-up，不讀 per-resource** — `696183c`
   每個 control 只拿到一個彙總判定，個別資源的失敗全部消失。
3. **control mapping 掛在引擎不可能發出的 rule id 上** — `a5e76de`
   對照表的 key 是人寫出來的規則名，不是引擎實際輸出的識別碼，所以整段
   mapping 從來沒有命中過。
4. **kube-bench 的 finding 全部埋在 unknown** — `1da78c3`
5. **四個引擎被安上它們沒有發出的嚴重度** — `b8b989a`
   gitleaks、TruffleHog、naabu、httpx 各被寫死一個 severity 字串，然後以
   `source-severity:high` 的形式送到使用者面前——那個 tag 的全部意義就是
   「這是引擎說的」，而它們四個都沒說。逐一對照 pin 住的上游原始碼確認：
   gitleaks 的 Go 原始碼裡根本沒有 `severity` 這個字；TruffleHog 的 `--json`
   序列化的結構沒有這個欄位；naabu 發出的 `confidence` 是在評服務指紋的把握度，
   不是風險；httpx 的 result struct 上沒有。四者改走
   `record_with_derived_severity!`，帶 `severity-basis:derived`、不帶
   `source-severity:`，並在摘要裡明說引擎沒有評分。**等級沒有改，改的是歸屬。**
   另外 TruffleHog 有一條建立在從未執行過的檢查上的評分：launcher 傳
   `--no-verification`，`Engine.shouldVerifyChunk` 在任何 detector 的 verify
   路徑之前就回 false，所以 `Verified` 恆為 false，`critical` 那條分支不可能
   到達，已移除；`verified:false`（讀起來像「驗過了、是假的」）改成
   `verification:not-attempted`。
6. **Checkov 沒帶嚴重度的 finding 被丟掉** — `b42ad87`
   改成替沒有嚴重度的評分、保留有嚴重度的原值。
7. **把產品自己的字面值當成 Steampipe 的評分讀回來** — `df632f3`
8. **四個引擎實際說了什麼在中途被丟掉** — `a60d38a`
9. **M365 wrapper 丟掉的判定被讀成「租戶很乾淨」** — `ac892da`
   wrapper 沒有回報的判定，adapter 讀起來跟「檢查通過」無法區分。

> 相關的既有記憶：`one-asset-per-engine-run`（規劃永遠不會把多個資產放進
> 同一次引擎執行，所以多資產的 adapter 測試會「找到」七個假 bug）。

## 第二條：讓結果對齊到同一張清單

對齊有兩個層次：**同一個尺規**，以及**同一個問題只出現一次**。

**尺規**由上面第 5–8 項處理：嚴重度現在要嘛是引擎自己說的（原字保留，
連 `High` 這個字都不翻譯，否則使用者拿去跟引擎自己的輸出對照時會對不起來），
要嘛明確標成本產品自行推導的（`severity-basis:derived`），沒有第三種。

**去重**是新的跨引擎關聯功能：

- `e1aebdc` — 後端 `src-tauri/src/correlation.rs`，建議哪些不同引擎的
  finding 其實是同一件事。
- `98bf44a` — 前端終於把它畫出來。後端從模組落地起就一直在算，但**沒有任何
  地方在讀**：兩個引擎報同一個套件的同一個 CVE，使用者看到的是兩列不相干的
  資料。同時：
  - 依 spec 9.3，兩個引擎有共識**不得**呈現成獨立佐證，所以每一條建議都帶著
    這個但書，而不是暗示已經雙重確認。
  - 共用識別碼但缺少可比較座標的 finding 會被列成「無法驗證」，而不是消失。
  - 建議清單有上限，被丟掉幾筆會明說。
  - `FindingCorrelationSuggestion` 新增 `vulnerability_id` 與 `package`：
    原本只能靠解析英文 `title` 取得，等於強迫中文讀者收到英文散文。
- `d86bef5` — 把工作計畫 port 的測試從「檢查有沒有出現」改成「檢查有沒有洩漏」。

這個功能跨越前後端邊界，所以順手補了三道合約防護（見下方「結構性防護」）。

## 第三條：讓新手好用

新手介面的核心問題是：**產品自己寫的句子只有英文版**。中文使用者看到的是
中文標題底下一串英文。本區間把三大塊使用者可讀的散文改成雙語，方式一致：

> **後端發出結構化的代碼／標準英文散文；每一個閱讀面自己組句子。英文一律
> 原封不動回傳後端的標準散文。引擎自己的字串（引擎名、rule id、原始嚴重度
> 用字、雲端識別碼）一律逐字保留。**

- `3498393` — finding 的散文改帶組成它的代碼，中文才有東西可組。
- `799ba1d` — finding 的摘要、影響、下一步以讀者的語言書寫。
- `2724d38` — 分享報告（HTML）的 finding 散文同樣依讀者語言組成。
- `2a60b13` — demo 的散文若不是從 family 組出來的，就不要宣稱它有 family。
- `38077c8` — 補上只有英文側知道的兩個專有名詞。
- `a480bbc` — 修正組合後的中文句子漏掉英文原句資訊的問題。
- `75af582` — findings 列上標明是哪個引擎找到的，以及哪些評分是本產品自己的。
- `de5663b` — 安全性與驗證這兩句一併帶過去並在地化。
- `6132ee2` — 「為什麼是這個優先度」原本是中文標題配英文清單，兩處（findings
  抽屜與 HTML 報告）皆是。`priority_reasons` 是沒有 per-entry code 的
  `Vec<String>`，所以改用形狀辨識；四個生產者全部封閉，其他一律原樣回傳——
  對這個 build 認不出來的文字印出一句自信的中文，那不是翻譯，是捏造。
- `5465394` — 依讀者實際看到的嚴重度選對冠詞。
- `7e257a2` — 告訴讀者能解決他這個 finding 的動作，而不是一句通用的。

### Prowler 歸屬缺口（一條線，四個 commit）

這條值得單獨看，因為它示範了「adapter 層測試通過」與「使用者看得到」之間的距離。

- `165ef62` — 用一般人實際的方式加入一個雲端帳號（取名字、授權、但從未
  填入指紋），Prowler 會回傳空的 finding 清單。`resolve_asset` 把
  provider-qualified 的 OCSF 帳號視為權威、不會回退到唯一選取的資產——這是
  對的，把 AWS finding 歸給錯的帳號比不歸屬更糟。但識別碼對照表完全來自
  `asset.identifiers`，而沒有任何地方要求必須填。於是引擎找到了一切、解析出
  零筆，整次執行讀起來像一次乾淨的掃描。改成**每個識別碼講一次**：講 provider、
  講識別碼、講丟掉幾筆、講怎麼修。per-record 的警告留著當稽核軌跡。
- `200c81a` — 那句話**從來沒有到達過真實執行**。它是在 record 迴圈之後透過
  `push_warning` 附加的，而 `push_warning` 在警告數達到 `MAX_WARNINGS`（256）
  後會靜默 no-op，一次預設 AWS 掃描的 record 數遠超過這個值。256 個名額被
  per-record 雜訊填滿，唯一值得讀的那句被丟掉。fixture 只有三筆，所以測試通過。
  現在它排在 per-record 警告之前，並且豁免上限。測試用 400 筆的 artifact，
  不是重用三筆的 fixture——**三筆會過、三百筆會爆，正好是 fixture 尺寸的測試
  看不見的東西**；而且斷言它排第一，不只是存在，因為「有但被埋掉」對讀者是
  同一個結果。
- `20409d6` — 讓識別碼以**資料**的形式旅行：`UnattributedResults`
  （provider、identifier、丟棄筆數）從 adapter → execution report → engine run
  → 一個同時帶著英文散文與 payload 的 coverage gap。把它加進
  `data_quality_warnings` 當一個裸字串會複製剛修掉的缺陷：那個欄位沒有代碼，
  只能是英文。它被算成獨立的 coverage 狀態，而不是折進既有的：檢查有跑，
  所以「未檢測」低估了發生的事；結果存在，所以「無法使用」描述的是別的東西。
- `d377f2d` — **安全性**：那個識別碼直接讀自被掃描的 artifact，且未登記在任何
  資產上，所以會改寫已知識別碼的 `redact_known_literals` 碰不到它。一份宣稱
  不含此類資料的標準遮蔽匯出，實際上夾帶了一個真實的雲端帳號 id。三個散文
  欄位與兩個 payload（`beginner_report_for_export` 與 `case_for_export`）都
  已處理：gap 保留計數、失去識別碼，`engine_run.unattributed` 跟著旁邊的
  warnings 一起清掉。未遮蔽的匯出仍然有它，遮蔽後的 gap 會告訴讀者去哪裡找。

### 涵蓋清單的在地化（本區間最後兩個 commit）

- `1c05a3f` — **dimension（這個缺口是關於什麼）**。
  `localizedCoverageDimension` 對照了 13 個固定名稱，其餘全部落到
  `涵蓋範圍細節：<英文原文>`。它的測試普查的是 `dimension: "..."` 這個形狀，
  而所有約 16 個組合而成的名稱都不是這個形狀——於是測試回報「完整覆蓋」，
  而每一個組合名稱送到中文讀者面前都是英文。其中
  `{engine} granular executed scope` 對每一個完成的目錄檢查都會觸發，
  **所以每一次正常執行都踩到**。HTML 報告則根本沒有在地化 dimension。
  另外 `readable_identifier` 會把組合出來的中文名稱弄壞（會把
  `naabu-tcp 的…` 改成 `Naabu TCP 的…`，破壞讀者要拿去跟自己掃描器輸出
  對照的引擎 id），現在只在非中文路徑套用。
- `0392aea` — **reason（為什麼缺）**。findings 面板**在兩個語言下**都是從
  `gap.kind` 組句子、丟掉 `gap.reason`。`not_tested` 一個 kind 涵蓋三種狀況，
  所以「每個 kind 一句話」對三列中的兩列是假的，而且會跟旁邊的 dimension
  互相矛盾。HTML 報告則逐字印出儲存的英文。現在兩者都讀後端實際記錄的句子。
  `COVERAGE_GAP_PROSE` 有 69 組對照，TypeScript 側由 Rust 表生成。

---

## 建立的結構性防護

這些比任何單一修正重要，因為它們改變了「下一次退化」的代價。

### 1. 生產者處普查，而不是對生產者做正則普查

`beginner_report.rs` 用四種不同方式寫出使用者可見的句子：struct 欄位、
傳給本地 `push` closure 的位置參數、`append_task_gap` 的 match arm tuple、
以及從上游 struct 複製過來的文字。**一個 grep `reason: "..."` 的普查只找到
約 45 句中的 7 句，然後回報成功。**

可靠的做法是在生產者處斷言：

```rust
coverage_gaps.dedup();
debug_assert_coverage_prose_is_translatable(&coverage_gaps);
```

放在集合定案的地方。這樣**整個 Rust 測試套件就是普查**——每一個建報告的
既有測試都會跑到它，而一句新的散文會讓走它自己那條路徑的測試失敗。

例外：本產品沒有寫的文字要豁免。`ScanRequestOutcome.explanation` 是只驗長度
與控制字元的持久性自由文字，對它斷言會在合法紀錄上 panic，所以
`requested check*` 開頭的 dimension 被豁免。

### 2. 雙生檔不變式

`src-tauri/src/finding_narrative.rs` 與 `src/findingNarrative.ts` 持有同一批
句子。`tests/frontend/findingNarrativeParity.test.ts` 讀兩個檔案，比對
中文字面（插值塌縮成 `⟦⟧`）、英文 match key，**以及英文 key 與中文句子的
配對**。最後這項是必要的：因為英文現在是比對用的 key，一旦飄移，翻譯會
**靜默失效**——不會 crash、不會有斷言失敗，只會出現一個中文項目配兩個英文項目。
它已經抓到一次真實的不一致（Rust 側 `" failed work units "` vs TS 側
`" failed work units"`）。

注意 rustfmt 會把長的配對折成三行，所以比對前兩側都要把空白壓平。

### 3. 跨邊界合約防護（隨關聯功能一起加）

- `correlationWireContract` — 兩側的 JSON 欄位名必須相同。改一個 Rust 欄位名
  在各處都能編譯，然後靜靜地送 `undefined` 給頁面。
- `nativeCommandRegistry` — 前端能呼叫的每一個 command 字串都必須真的註冊在
  Tauri 上。這裡打錯字會出貨，然後只在使用者打開那一頁時才失敗。
- `correlationService` — **執行**服務而不是讀它的原始碼，證明 demo 路徑帶著
  notice、原生失敗會 reject 而不是解析成一份空報告。

`src-tauri/src/correlation.rs` 已加入 `FRONTEND_PATHS`，讓純後端 commit 也會
跑到這些測試所在的 lane（見記憶 `render-test-hazards`：跨邊界測試需要
classifier 條目，否則它在最可能弄壞它的那個 commit 上不會執行）。

---

## 驗證方法

每一項修正都經過：找到矛盾的程式碼 → 修 → 寫測試 → **對測試做突變驗證**。

1. 還原修正（或關掉渲染）。
2. 重跑，**以子行程 exit code 確認失敗**（Rust 101 / vitest、node --test 1）。
   管線化的 exit code 會說謊。
3. 區分斷言失敗與編譯錯誤（`^error\[E|could not compile`）——編譯不過不算殺死。
4. **從 `/tmp` 備份 `cp` 回去還原，絕不用 `git checkout --`**（先前有一次
   session 因此弄丟未提交的工作），然後以 sha256 確認位元組相同。
5. **突變存活 = 測試有缺陷。修測試，不要修量測。**

本區間有兩次存活，每一次都揭露真實的缺口：

- **遮蔽測試存活**：第一版只驗了 `beginner_report_for_export`，`case_for_export`
  那條路徑沒碰到。補上後才殺死。
- **報告接線的突變存活**：把整個 `(ZhHant, None)` match arm 拿掉，**整個 Rust
  套件依然全綠**。用暫時的 `panic!("GAPDIMS>>>{:?}<<<")` 探針找出 fixture 實際
  的 gap dimension，補上中文正／負面斷言後才殺死。

## 本機閘門（12 道）

見記憶 `local-verification-recipe`。`cargo` 不在 PATH 上：

```
PATH="$HOME/.cargo/bin:$PATH"
cargo fmt --all -- --check
cargo clippy --locked --workspace --no-default-features --features cli --all-targets -- -D warnings
cargo test  --locked --workspace --no-default-features --features cli
npm run typecheck
npm run test:frontend
npm run test:component
npm run test:release-evidence
node --test tests/ci/*.test.mjs
npm run validate:engines
npm run release:self-test
npm run validate:usability-evidence
node scripts/release/validate-windows-nsis-template.mjs
```

注意 `node --test tests/ci/`（目錄形式）會噴一個看起來像測試壞掉的模組錯誤，
要用 glob。`src/` 中前端測試會走到的檔案，**value import 必須寫出 `.ts` 副檔名**
（`import type` 會被抹除，不需要）。

---

## 還沒做的

### 需要 Ted 授權（對外操作）

GHCR 發布是對外行為，**每一次都需要明確授權；上一個版本的同意不延伸到下一個**。

- **#10 — 移除 Steampipe 查詢中捏造的嚴重度欄位。**
  `engines/images/cloud-launcher/main.go:1222` 有一行 `'high' as severity`，
  是產品自己寫進 SQL 的常數，然後被當成 Steampipe 的評分讀回來（`df632f3`
  修的是讀取側；產生側還在）。卡住的原因：`scripts/engine-image-evidence.mjs:366`
  會把 `engines/images/cloud-launcher/` 底下的任何變更擴張成**五個引擎的
  GHCR 發布**。
- ~~**Maester `run-maester.ps1` 的 `dropped` 計數器**~~ —— **這一項不需要授權，
  原本的分類是錯的**，已在 Rust 側修掉（見文末 `dropped` 那段）。wrapper 早就
  寫出 `Diagnostics.total`（`run-maester.ps1:175`），只是 Rust 從來沒讀。
  剩下**該映像內的一份 Pester spec** 仍需重建並發布 M365 引擎映像。
- **#10 的補充判讀**：讀取側（`adapters/mod.rs:2905` 起）已經刻意不讀那個
  欄位並以 `CloudControlQuery` 揭露評分是本產品的，**使用者看到的已經誠實**；
  產生側剩一行沒人讀的 SQL 死碼。不值得為它觸發五個引擎的發布——等下次有
  實質理由重建 cloud-launcher 時順手清掉。

> 供應鏈 digest pin **不得**為了讓 CI 變綠而重新 pin。只有在被審查的內容
> 真的改變時，重新 pin 才是正當的。另見記憶 `pinned-digests-need-eol-lf`
> （Windows CRLF checkout 會破壞位元組精確的 SHA-256 pin，該修 `.gitattributes`）
> 與 `m365-publication-mechanics`（失敗的發布不會燒掉版本 tag，任何步驟都能
> 在本機重播，不必重新 dispatch）。

### 需要 schema／spec 決定，不是清理

- **`CoverageGapKind::Truncated` 與 `CoverageReduction`。**
  `Truncated` 被宣告、序列化、由 `coverage_counts` 計數、由 `gap_rank` 排序、
  由 `case_service.rs` 渲染——但**沒有任何地方建構它**，所以
  `CoverageCounts.truncated` 恆為 0。它讀起來完全像可以刪的死碼。**它不是。**
  這是刻意保留的合約欄位，預期的建構者是「要求涵蓋範圍投影」（一旦凍結的
  計畫能夠陳述要求範圍 X 對執行子集 Y 以及原因），也就是 `CoverageReduction`。
  taxonomy 在 `docs/product-spec.md` 有承諾。刪掉對目前的執行是安全的，但**不是
  合約中性的**：它會改變序列化 schema 並牴觸已發布的承諾。詳見記憶
  `truncated-is-a-spec-promise`。

### 同一個缺陷類別、還沒修的位置

`1c05a3f` / `0392aea` 修的是 coverage gap 那幾列。本文件寫成後，同一份 HTML
報告裡的另外三處已在 `9b57e39` 修掉（詳見文末「交接後續」）：`limit.name`、
已檢測維度的 `dimension.dimension`、以及由 finding 推導出來的下一步 reason
（原本用 `Debug` 印列舉）。

同一份報告、同一個類別，後續又修掉的（詳見文末「交接後續」）：已檢測維度的
`observation` 句（`6ba6909`）、`limit.value` 的單位字與 CoveragePage 的 record
detail（`0d8f447`）、VerificationPage 的 diff 說明與 AppShell 的佔位標題
（`e15f2ff`）、ProgressPage 的引擎警告與 beginner report 的 data-quality 警告
（`15e7fa0`）、框架對照的 `rationale` 與 `relationship`（`5e468a9`）、
demo 案件的全部儲存字串（`9e9d863`）。

**這一類別目前沒有已知的剩餘位置。**下一個人要找新的，最快的方法是照
`15e7fa0` 的做法：找出寫出那些句子的生產者，在那裡做普查，而不是對原始碼
掃正則——後者只會找到其中一部分。

### 其他仍是英文／無代碼的使用者可見文字

**這一節列的四項已全部做完**（`6f9d778`、`15e7fa0`、`5e468a9`、`9e9d863`，詳見
文末「交接後續」）。原本判定它們「需要 schema 或資料決定」是對的——但決定的
內容不是「改 schema」，而是**不改 schema**：三項都改用呈現層翻譯加生產者普查，
儲存的英文維持正典，簽章過的 case bundle 與釘住的目錄一個位元組都沒動。

留下原本的判讀，因為推翻它的理由本身值得記住：

- **引擎警告**（原判：得先分開「本產品說的」與「引擎說的」）。實際查核後，
  **沒有任何引擎的 stderr 會變成警告**——72 種句型全部是本產品自己寫的，
  所以根本不需要分。
- **`data_quality_warnings`**（原判：需要代碼、要改 beginner report schema）。
  它被序列化進簽章的 case bundle（`export.rs:1029`、`1060`），為了措辭問題改
  形狀會弄壞既有的每一個 case 檔。改用整句查表＋`build_beginner_master_report`
  裡的 debug 普查。
- **框架 `rationale`**（原判：等於改 catalog、重算 pin、更新審閱記錄）。這點
  完全正確，所以 catalog **沒有動**：19 條經審閱的英文仍是正典，中文只是呈現，
  兩邊的普查都直接讀目錄本身。
- **`demo.rs` 的硬寫中文**（原判：先決定 demo 去留，再決定語言）。這個排序不
  成立——不論 demo 最後去留，它今天存的就是錯的語言，而且它的 coverage
  explanation 繞過 ledger 普查，兩種語言的讀者都會看到中文。語言先修，去留
  仍是未決的問題（見下方 3.3／3.5）。

### 對齊清單本身還有的缺口

- ~~**2.1 — `Confidence::High` 對 21 個引擎中的 20 個是常數欄。**~~
  已修（`6f9d778`）。它有意義：每個 extractor 的等級都從引擎實際做了什麼重新
  論證，引擎自己報的值一律優先，本產品推導的一律帶 basis code。
- **2.2 — control filter 只觸及約 19 條對照規則，5 個引擎一條都沒有。**
- **2.4 — 列上沒有 location。**
- **1.4 — 對照表飄移時，control reference 是整批清空的。**
- 3.3 / 3.5 及 `seedDemoCase` 的死接線。

### 誠實的限制（延續自前一份交接，仍然成立）

- **兩個 M365 引擎從未對真實租戶執行過。** 只做過發布與 launcher 驗證。
- **Windows 安裝後的生命週期從未執行過**（NSIS 快取植入、損毀套件復原、
  複製舊 uninstaller 的路徑）。只有靜態驗證。
- Dependabot moderate：`rust/glib 0.18.5` `VariantStrIter` unsoundness，
  0.20.0 已修，經由 Tauri 的 Linux GTK 堆疊間接引入。Linux 是發行目標。

---

## 目前位置

| 階段 | 狀態 |
|---|---|
| 1. 每個引擎餵真實輸出都出得來 finding | 21 個 adapter fixture 全部對照上游稽核完畢；產生側還剩 #10（卡授權） |
| 2. 嚴重度可跨引擎比較 | 完成——不是引擎說的就標成本產品推導的，沒有第三種 |
| 3. 同一個問題只出現一次 | 後端關聯 + 前端呈現 + spec 9.3 但書，完成 |
| 4. 新手可讀的雙語散文 | 報告與畫面上所有由本產品撰寫、有固定句型的文字都已在地化（見「交接後續」六個 commit）；剩下的四項各自卡在 schema 或資料決定 |
| 5. 對齊清單的欄位品質 | 未開始（2.1 / 2.2 / 2.4 / 1.4） |
| 6. 授權與 schema 決定 | 等 Ted |

**建議的下一步**：第 4 項能不經決定就做的部分已經做完。接下來每一條都要
Ted 先拍板：（a）引擎警告與 `data_quality_warnings` 要不要改成帶代碼的結構
（schema 變更，兩者可以共用同一個 `{code, text}` 形狀）；（b）第 5 項
`Confidence::High` 是常數欄，那個欄位到底代表什麼；（c）control-mapping catalog
的 rationale 要不要有第二語言版本以及 provenance 怎麼記；（d）demo 案件去留。
其中（a）與（b）是清單品質上最大的兩塊。

---

## 交接後續（06b7035 之後）

### `9b57e39` — 要求限制、已檢測維度、finding 推導的下一步，改用讀者的語言

同一份 HTML 報告、同一個 bug class 的三處，依本文件建議的順序做完：

- **`limit.name`**：報告端只跑 `readable_identifier`，中文報告印出
  「Gitleaks Execution Timeout」。前端早有 `localizedRequestedLimitName`，
  報告從未呼叫。現在 Rust 也寫同一組標籤，識別碼保留在括號內：
  `檢查逾時限制（gitleaks）`。在地化函式從 `coverageDimensionPresentation.ts`
  搬進 `findingNarrative.ts`（原處 re-export），因為那是 parity 測試對照
  `finding_narrative.rs` 的檔案。
- **`dimension.dimension`**：名稱全在既有的 coverage 詞彙表裡，報告端只是沒接。
- **finding 推導的 next step reason**：英文改為明確的窮舉 `match`，不再
  `{:?}`；中文不是從儲存的英文句子反解析，而是從 step 指向的 finding 重新組句
  （`{title} — 嚴重程度：高；信心程度：已確認`），標籤與 finding 本身那一節相同。
  順手補了 `identifier` 表缺的 `"unknown" => "未知"`，之前中文報告會在一排中文
  評等旁邊印 "Unknown"。

**普查在 producer 端**：`coverage_dimension_zh_hant` 拆成回傳 `Option` 的核心
＋帶 fallback 的外殼，`beginner_report.rs` 對每個 limit 名稱與每個已檢測維度
做 `debug_assert`。把某個 producer 的 `"endpoint"` 改成別的字，第一個建報告的
Rust 測試就會炸。前端的 census 也改成從 Rust 原始碼讀出八個 limit producer。

**突變驗證**：三處報告接線各自拔掉，zh 報告測試都在自己那一行失敗；改掉一個
limit 名稱，普查即攔下。

**一個要記得的坑**：parity 測試的字面值擷取器會掃 `///` 文件註解裡帶引號的中文。
我在 `with_identifier` 的說明裡寫了 `"允許檢查的連接埠（）"` 當例子，parity 就
判定「報告有、畫面沒有」。文件註解裡不要用引號包中文例句。

實跑數字（`9b57e39`）：Rust 1,393（＋2）、前端 439（＋1）、元件 117、CI lane 29；
`cargo fmt --check`、clippy `-D warnings`、typecheck、release-evidence、
validate:engines、release:self-test、validate:usability-evidence、NSIS 範本
驗證全部通過。

### `6ba6909`、`0d8f447`、`e15f2ff` — 由 Codex 撰寫、本文作者指揮與審查

Ted 指定寫程式的部分交給 Codex CLI（`gpt-5.6-sol`），我當 orchestrator：寫簡報、
審 diff、自己重跑全部 gate 後才提交。三個 commit 的簡報都放在 `/tmp/codex-brief-N.md`
（未入庫；簡報的要點都在各 commit message 裡）。

- **`6ba6909`** 已檢測維度的 `observation` 句：7 句固定句子，雙生檔案整句查表；
  畫面原本完全不印這句，現在也印，所以「完成的網路檢查不代表安全性檢查通過」
  這句誠實話第一次到達畫面。
- **`0d8f447`** `limit.value` 的單位字（4 個句型，數字原樣）＋ CoveragePage 的
  record detail（`coverage.rs` 6 句固定＋12 個帶洞句型；狀態字、計數、grant id、
  使用者自己打的排除理由全部原樣）。表放在雙生檔案是因為 case bundle 也序列化
  這個欄位，且只有放在 Rust 端才能做 producer 的 debug 普查。`coverage.rs` 加進
  CI classifier 的跨邊界清單。
- **`e15f2ff`** VerificationPage 的 diff 說明：不解析英文成品，改從結構組句——
  五向 status 決定框架（adapter 原本把它壓成四種畫面狀態，現在保留原值）、
  20 個 reason code 各有標籤、27 個 detail 句型、engine／asset／指紋／版本值
  全部原樣。AppShell 的「Saved project」只在 `selected_case_missing` 時換成
  i18n 佔位，真實案件名稱原樣。`diff.rs`、`domain.rs` 加進 classifier。

**與 Codex 合作的觀察**：它的報告與我實跑的數字每次都一致；它在 sandbox 內跑
Rust 全套會撞到兩個 managed-runtime 清理測試的 `Operation not permitted`，
它會自己在 sandbox 外重跑，我的重跑沒有這個問題。它兩次主動發現 CI classifier
少了跨邊界檔案而補上。我改過它的一處：普查用精確計數 `=== 7`，改成下限。

實跑數字（`e15f2ff`）：Rust 1,396、前端 457、元件 122、CI lane 29，
fmt／clippy／typecheck 全綠。

### `6f9d778`、`15e7fa0`、`5e468a9`、`9e9d863` — 同樣由 Codex 撰寫、本文作者審查

這四項就是上面「其他仍是英文／無代碼」那一節列的全部內容。流程與前一輪相同：
我寫簡報、審 diff、自己重跑全部 gate 後才提交。

- **`6f9d778` 信心度。** `Confidence` 原本 19 個 extractor 都寫死 `High`，而
  Semgrep 的 `extra.metadata.confidence`、Greenbone 缺 QoD 的那條分支都被丟掉。
  照嚴重程度那套鏡像：`ConfidenceBasisCode` 六個代碼、`SourceRecord` 存引擎
  原話、`record_from_draft` 用同一條規則解析（引擎給的一律勝出，推導只補洞），
  並在該處放 debug 斷言讓整套 Rust 測試變成普查。每個等級都重新論證：確定性
  政策失敗與本產品直接觀察到的回應維持 High；公告版本比對與 Nuclei 範本比對
  降為 Medium；未驗證的樣式比對（Gitleaks、TruffleHog、Trivy secrets、缺
  confidence 的 Semgrep）降為 Low。**沒有任何 basis 配得上 Confirmed。**
  優先權重完全沒動——`prioritization.rs` 從來沒讀過 confidence，它只影響同等
  嚴重程度之間的排序，那本來就該是它的作用。
- **`15e7fa0` 警告。** ProgressPage 的技術警告（72 種句型）與 beginner report
  的 data-quality 警告（6 種）。兩者都不改形狀。`data_quality_warnings` 兩個
  介面都會顯示，所以表放在受 parity 保護的雙生檔；引擎警告只有 ProgressPage
  會顯示，所以放在畫面專用模組。**審查時抓到三個 Codex 漏掉的真缺陷**：
  M365「未評估所有控制措施」句子括號裡的清單被當成引擎的值原樣保留，但那是
  本產品自己寫的英文片語；兩種認證封套警告（當機遺留 vs 單純殘留）被併成同
  一句中文；普查的解析器碰到讀不出字面值的呼叫點會靜默跳過——現在那份清單
  被釘住，新的間接產生點會讓測試失敗。
- **`5e468a9` 框架對照 rationale。** catalog 逐位元組不變，pin 未動。19 條
  rationale 整句查表，兩邊普查都直接讀目錄（Rust 讀內嵌 JSON、前端讀磁碟上的
  檔案），都不釘筆數——筆數本來就由 hash pin 守著。`relationship` 只出現在
  報告裡，所以留在 `case_service.rs`，不放進雙生檔（放進去會逼出一個前端沒有
  呼叫者的匯出）。框架名稱、control id、官方控制措施名稱兩種語言都原樣。
- **`9e9d863` demo 案件。** 32 處硬寫中文改成英文，並改走真實路徑：coverage
  explanation 重用 ledger 的真句子、phase 用結構化 key、finding 用有翻譯的
  family。回歸測試序列化整個 case，任何儲存字串出現漢字就失敗。**合成的 HSTS
  finding 拿掉了框架關聯**——釘住的目錄沒有 httpx 條目，真實的 HSTS 觀察不會
  帶任何關聯，硬留一條就得為那張「其餘每句都是經審閱目錄條目」的表憑空造一句。
  `src/data/demo.ts` 沒動：它是有測試保護的語系切換 fixture，不是同一個缺陷。

**與 Codex 合作的補充觀察**：這一輪四項它都交出可用的實作，但**四項裡有三項
我在審查時改了它的東西**，而且改的都是同一類問題——它會把「本產品寫的句子」
誤當成「要原樣保留的值」，也會寫出看起來像普查、實際上是白名單的測試。它的
gate 數字仍然每次都與我實跑一致。另外：`codex exec` 沒有 `--approve-for-me`
（那是互動版的旗標），要寫 `-s workspace-write`，而且**一定要把 stdin 導掉**
（`< /dev/null`），否則它會停在 "Reading additional input from stdin..." 不動。

實跑數字（`9e9d863`）：Rust 1,412、前端 467、元件 126、CI lane 29，
fmt／clippy／typecheck／validate:engines 全綠。

### Maester 被吞掉的控制措施：用 wrapper 已經給的 `total` 在 Rust 側算出來

`run-maester.ps1:126-130` 的 `switch` 只認 Passed／Failed／Investigate，其餘
`default { $null }` 直接 `continue`——控制措施從 `Results` 消失且沒有任何計數器
記得它。`normalization_shortfall` 本來就是為了抓這種事寫的，但它的 Maester 底線
是 `passes + failures + investigate`，上游用別的類別回報的判定對它是隱形的：
租戶看到一份乾淨的稽核。

wrapper 早就寫出關掉這個洞的數字：`total = $report.TotalCount`（`:175`），
fixture 裡也有（`"total": 342`）。現在 `total` 減掉六類已交代的計數
（passes／failures／investigate／errors／skipped／not_run），正餘數以
「N not accounted for by any reported category」揭露，並**扣住完成**——在範圍內
但狀態未知的控制措施，跟正規化時遺失的判定一樣，都不能讓這輪算完整。飽和在零：
上游計數器可能重疊，計數超過 total 不是被吞的證據。沒有 `total` 的文件（ScubaGear、
舊版 wrapper、舊 case 檔）行為與之前逐字相同。`engines/` 底下一個檔案都沒動，
不需要重建映像、不需要發布。

由 Codex 撰寫；它的 session 在跑 gate 時被切斷，且它在 sandbox 裡跑了
`npm install`、esbuild 的 postinstall 撞 EPERM，把 `node_modules` 掏空只剩懸空的
`.bin` symlink（lockfile 沒動，`npm ci` 即還原）。我補了兩處：前端普查對
`normalization_shortfall` 的擷取原本綁死 `{lost}` 這個洞名，新句子的洞叫
`{uncategorized}` 就漏了，改成任意洞名；以及一個 clippy `collapsible_if`。
