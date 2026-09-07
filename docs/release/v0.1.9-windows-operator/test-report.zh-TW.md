# AI Security Scanner v0.1.9 Windows Operator 測試報告

日期：2026-09-07
凍結 source／本輪起始 `main` checkpoint：`5c95572f54220adbd170d9bfb5af3159c56708ef`
Windows：Windows 11 Pro `10.0.26200.9168`，x64
Rust：`1.98`
Post-release final code checkpoint：`3b3591ad72e35735b71e17a3d30c1bb8546e0d5c`
（canonical timestamps；WL-13／case race：`8d138a13d736259d2626eed0ef12324cb327fdc4`；CI behavior：
`f04567cf09635b24062219684dc8325b3e44f61a`；UI／service：
`d28f287d78a079828af45f1ee3bbca165ae091ea`；主要實作：
`bd47e26b6c8024eb3461176637d7fce3e8370561`）

> **總結：automated source suites 通過、unsigned 狀態得到嚴格驗證，但原生 Windows
> operator journey 被安全地阻擋。** 本報告沒有 passing BEGINNER、lifecycle、
> Authenticode、stable 或 signed 結論。Browser CUA 是開發預覽的人工 regression，不能
> 替代 installed candidate evidence。

## 判讀規則

本報告把證據分成三層，禁止互相代換：

1. **Frozen published candidate**：只包含精確 `v0.1.9` installer／installed bytes 與對它們
   實際做過的 observation。
2. **Source support evidence**：對 `5c95572f54220adbd170d9bfb5af3159c56708ef` 或本輪明確
   checkpoint 執行的 automated tests；不等於 installed Windows journey。
3. **Post-release fixes**：browser review 後新增的修正與 portability tests；沒有新 build
   前，對 published `v0.1.9` bytes 的產品變化為零。

GitHub 目前的 mutable listing 是 owner 刻意設定的 non-prerelease **Latest**，但 candidate
lock／package／published machine-readable metadata 仍是 `prerelease`。Release body 與 textual
assets 也仍是 stale；listing 或舊文字都不能覆寫 frozen identity 與本報告的 gate 結果。

## 結果總表

| 範圍 | 結果 | 證據邊界 |
| --- | --- | --- |
| Candidate filename／size／SHA-256 | PASS | 精確 frozen NSIS identity 相符 |
| Candidate version | PASS | file／product version `0.1.9` |
| Candidate Authenticode | OBSERVED：`NotSigned` | 預期 unsigned；不是 PASS |
| Strict unsigned JSON | PASS validator | outcome `not-configured`；不是 accepted signing evidence |
| Installed App identity | PASS | version、size、SHA-256 相符 |
| Installed runtime manifest | PASS | `3,724` bytes，SHA-256 exact |
| Installed CLI version | PASS | `ai-security-scanner 0.1.9` |
| Installed CLI doctor | PASS for reported checks | `21/21` manifests，invalid／cleanup `0` |
| Isolated installed-CLI probe | PASS for scoped regression | 無既有 App data／無 network；private、non-importable |
| Native GUI control | NOT OBSERVED | Codex CUA 回報 `apps:[]` |
| Localhost Start／scan | BLOCKED，未執行 | port `9001` 屬 BAT SSH tunnel |
| Lifecycle rows | NOT OBSERVED | 非 disposable lab；沒有 canonical row |
| BEGINNER | NOT OBSERVED | 沒有 qualifying beginner session |
| Browser dev preview | SUPPORTING MANUAL REGRESSION | `390–433px`；不是 installed candidate |
| Source automated suites | PASS at recorded checkpoints | 不能替代 human／native／lifecycle evidence |
| Post-release release evidence | `142/142` PASS | 尚未進入新 installer |
| CI boundary／drift guards | `31/31` PASS | classifier coverage，不是產品功能測試 |

## Frozen candidate 與 installed identity

### NSIS candidate

| 欄位 | 實際值 |
| --- | --- |
| Filename | `ai-security-scanner_0.1.9_x64-setup.exe`；本機下載路徑不公開 |
| Size | `40,186,968` bytes |
| SHA-256 | `f7b5374fff07fca98af06931b2dc0ebc52abc2b3ac5a70a6602001d03a1a065e` |
| File／product version | `0.1.9` |
| `Get-AuthenticodeSignature` | `NotSigned` |

### Installed App

| 欄位 | 實際值 |
| --- | --- |
| Installed path | `<user-profile>\AppData\Local\ai-security-scanner\ai-security-scanner.exe` |
| Version | `0.1.9` |
| Size | `30,512,128` bytes |
| SHA-256 | `3e876497e7cb47881ec12e96ce2976b7f5e6ea5ab71da41c1f1a7357587c8c8a` |

Installed managed-runtime manifest：

| 欄位 | 實際值 |
| --- | --- |
| Installed path | `<user-profile>\AppData\Local\ai-security-scanner\managed-runtime\manifest.json` |
| Size | `3,724` bytes |
| SHA-256 | `a8112473e5d87655e6145ea5f6cff569c872329d2ec14bfb9463078abcb60e3a` |
| Expected comparison | byte-exact match |

## SIGNING-VERIFY 詳細結果

`Get-AuthenticodeSignature` 對 candidate 回報 `NotSigned`。嚴格 redacted observation：

- Canonical filename：`unsigned-os-signing-observation-windows-x86_64-nsis.json`
- `815` bytes
- SHA-256 `d42f13ab731c3b8f1f8bd89d267ffa07d2bd86b7aaf9f14d87ba4b1688342d43`
- strict validator：PASS
- outcome：`not-configured`

判定是「預期的 unsigned 狀態已如實記錄」，不是「SIGNING-VERIFY passed」。未配置
accepted publisher／producer policy，也沒有 passing OS-signing evidence，因此不能稱為
signed、stable 或 recommended。

## Installed CLI doctor

`ai-security-scanner-cli.exe --version` 回報 `ai-security-scanner 0.1.9`。JSON doctor 回報：

| Check | 結果 |
| --- | --- |
| Manifests | `21/21` release-approved |
| Invalid checkpoints | `0` |
| Cleanup obligations | `0` |
| Compatibility runtime | absent |
| Managed-local Podman | `5.8.2`，available、running |
| Provider | WSL |
| Preferred provider | `managed_local` |
| Legacy CLI data | preserved |

Doctor 的 `provider: WSL` 與 OS optional feature disabled 是兩個分開觀察的欄位；本報告不從
前者推論 WSL feature 已啟用，也不從後者推論 doctor 的字串有誤。

Doctor 沒有啟動 scan，也不驗證 desktop UI、case journey、report export 或 lifecycle。

## 隔離 installed-CLI export／deletion regression

Probe 使用已安裝的 `0.1.9` CLI，但把 data directory 隔離在一次性 private location。沒有
載入既有 App data，也沒有 network contact；本機 path、內容與 raw logs 不納入 repository。

### Case 與 deletion semantics

| Step | 結果 |
| --- | --- |
| `--version` | `0.1.9` |
| `seed-demo`／list／selected／show | PASS |
| Exact delete plan | 已觀察 |
| Wrong `--confirm-case-id` | exit `1`；case preserved |
| Exact confirmation | 只刪除 case DB／event rows；case count `0` |
| Artifact plan | `exists = false` |
| External export files | case deletion 後仍存在 |

這證明隔離 CLI probe 的兩步確認與外部輸出保留行為，不證明 browser delete defect 已修復，
也不等於 installed GUI lifecycle row。

### Export／verification

| Artifact | Size | SHA-256 | Verification |
| --- | ---: | --- | --- |
| Standard-redaction HTML | `15,992` bytes | `98fcc7d7aec6b027b78adfc46e03d785379bdf6b3d88f0922692523f19409f81` | local valid |
| Canonical beginner/master JSON | `22,339` bytes | `6c283ad82496060210c427ebe930f2f0ac975f293b61d1e9eb8d8578fc760b2d` | local valid |
| Standard-redaction case bundle | `16,873` bytes | `767ae0cf9304a88612b8c78f1f187df4f1039aea95aad55061ebb3106e19eecc` | local valid；DB deletion 後 detached valid |

Case bundle inventory 是 `19` entries、`rawArtifactsIncluded = 0`，並含 truthful
integrity-only notice；不宣稱 signer identity、Authenticode 或完整 scan。Duplicate-destination
export 正確 exit `1`，既有 HTML SHA-256 保持不變。

這些檔案只允許留在 `private-diagnostic`，不可上傳、不可放進 external-evidence import root。
本輪沒有打開 report 內容或 raw evidence，只讀取必要 metadata／manifest inventory。
`beginner/master` 是 export 的產品類型，不是 qualifying BEGINNER session 或 evidence。

## Automated source／build 結果

| Suite | 結果 | 限制 |
| --- | ---: | --- |
| Frontend | `486/486` PASS | source-level |
| Component | `145/145` PASS | component runner；不是真人 UI |
| Usability evidence | `5/5` PASS | schema／fixture，不是 BEGINNER observation |
| Engine validation | PASS | `168` byte-stable inputs、`21` records、Prowler `8/8` |
| AIDEFEND snapshot | PASS | `6` records |
| Release validate | PASS | policy／artifact metadata checks |
| Release self-test | PASS | synthetic release paths |
| Frontend build | PASS | build success，不是 installed runtime |
| Desktop check | PASS | packaging/source check，不是 GUI journey |
| TypeScript typecheck | PASS | source-level |
| Rust 1.98 all-targets | `1478/1478` PASS | 該 command 的 suite total |
| Clippy all-targets | PASS | `-D warnings` |
| Rustfmt all | PASS | `--check`；同步後的 exact source tree |
| Release evidence | `142/142` PASS | post-release commit/source result |
| CI boundary／drift guards | `31/31` PASS | shared corpus 同時觸發 frontend 與 rust_core；不觸發 desktop |

上述 suites 可能測到重疊邏輯，所以不相加成單一測試總數。尤其 `5/5` usability evidence
只表示 evidence contract 測試通過，不能寫成「5 位使用者通過」。

第一次 release self-test 與 desktop check 使用 ambient default Rust `1.97`，因專案要求的
工具鏈不符而失敗；設定 `RUSTUP_TOOLCHAIN=1.98.0` 後兩項均完整通過。Self-test 列出的
tamper、錯誤 signature 與缺少 evidence 是預期被拒絕的負向 fixtures。Production build
成功，但 Vite 對 `985.21 kB`（gzip `300.50 kB`）的主 JS chunk 發出超過 `500 kB` 的
非阻擋 warning；這是 code-splitting 技術債，不是 installer 或 runtime 測試通過的證據。

### Dependency reachability observation

GitHub push 回報 medium open alert
[`GHSA-wrw7-89jp-8q8g`](https://github.com/advisories/GHSA-wrw7-89jp-8q8g)／
`RUSTSEC-2024-0429`：鎖定的
`glib 0.18.5` 位於 `>=0.15,<0.20`，首個修正版為 `0.20.0`。Target-specific inverse trees 顯示：

- `x86_64-pc-windows-msvc`：`glib` 無輸出，不會連入 Windows installer binary；
- `x86_64-unknown-linux-gnu`：`tauri 2.11.5 -> gtk 0.18.2 / webkit2gtk 2.0.2 -> glib 0.18.5`。

Repository／GUI-stack source search 沒找到受影響 `VariantStrIter` API 的直接使用，但不能因此
把依賴告警視為不存在。精確 `glib 0.20.0` dry-run 因 `gtk` 的 `^0.18` constraint 失敗，
Tauri dry-run 也沒有可用的 Rust `1.98` 相容更新；因此狀態是 **Windows not reachable／Linux
residual risk open**，不是 FIXED，也沒有 dismiss。

## Browser CUA 手動 regression

以 `390–433px` viewport 在 browser 開發預覽手動檢查：

- 中英文 navigation；
- use-case disclosure；
- website URL 驗證拒絕 `ftp` 與 credentials，接受精確 localhost URL且未 contact；
- AI onboarding；
- partial-results disclosure；
- master-report export UX；
- two-step deletion semantics。

Console 沒有 warning／error。Browser review 與 final diff audit 共揭露八個具體 issue，
歸為下列四個 defect families：

| Defect | 觀察 | 本報告狀態 |
| --- | --- | --- |
| Runtime locale | 切換語言後，內建 demo record 仍顯示中文 | FIXED；自動測試加 browser 人工切換通過，使用者文字維持原文 |
| Mobile modal scroll | 導覽 drawer 開啟時背景仍可捲動 | FIXED；scroll lock／style restoration／page transition 自動測試與 browser 人工檢查通過 |
| Browser demo deletion | user-created demo case 無法刪除；刪除背景 case 會讓目前選取跳回 built-in demo；刪除期間連續切換 case 有 stale-selection／loading race | FIXED；exact-name／built-in protection／no-artifact／latest-selection supersession／stale-loading guard 自動測試通過；收尾未實際刪除本機 UI test data |
| Target validation parity | public／internal line 接受 malformed URL／port／space；deployed URL 衍生 host、明確 port `0`、percent-expanded path 可繞過 native 邊界 | FIXED；field-specific alert／focus 人工通過，valid FQDN／IP／CIDR 也通過；host／port／path parity 自動測試通過 |

這四個 families 只證明 browser preview／source audit 中存在問題；因 native GUI 沒有被控制，本輪不宣稱已在安裝版
重現，也不宣稱 post-release 修正已進入 `v0.1.9`。

Qualification plan／tooling 另完成 `AUTO-OPERATOR` track、exact loopback fixture、固定 Windows
Node runtime、fixture digest 與 WL-13 `reachable` 雙向 schema／validator binding；fixture
runtime、path、digest 三個座標也只允許 WL-13 使用。這使 Codex 在
擁有人明確授權後可自行按固定 localhost Start 並連續跑安全 rows；沒有 raw HTML reader 時只把
readability check 記為 `not-observed`，把已嘗試的 lifecycle row 記為 `inconclusive`、
`reasonCode: required-observation-unavailable`，不會停掉其他測試，也不會把 agent output 冒充
beginner evidence。

Evidence timestamp validation 另由寬鬆的 `Date.parse` 收斂成 shared canonical UTC parser：只接受
真實 calendar date、`Z`／`+00:00` UTC offset 與最多九位 fractional seconds；排序保留
nanosecond 精度。Schema 同步約束 UTC、月份邊界與閏年，focused artifact／lifecycle suite
`27/27`、完整 release-evidence suite `142/142` PASS。

同步時另找到一個 CI routing issue：shared external-target corpus 同時被 frontend 與 Rust parity
tests 讀取，但 corpus-only change 原本不會排程這兩條 lane。Classifier 已修成
`frontend:true`、`rust_core:true`、`desktop:false`，直接 regression 與整套 CI boundary／drift
guards `31/31` PASS。這是額外的 release-engineering 修正，不增加上面八個 UI／UX issue 的計數。

## Native Windows 路徑：阻擋而非失敗後重試

### 控制面限制

已安裝 App 在執行，但 current Codex CUA 回報 `apps:[]`。因此本輪沒有 click、keyboard、
Start、report、reopen 或 export 的原生 GUI evidence，也沒有用 PowerShell UI automation
代替 computer-use observation。

### Port ownership

Private read-only preflight 確認 `127.0.0.1:9001` 由現有 BAT SSH tunnel 使用，而不是 exact
reviewed qualification fixture。公開測試報告不保存本機 PID、command line、遠端 endpoint 或
其他 network topology。

此 owner 不是 exact reviewed qualification fixture。實際 Start 會掃描 BAT，屬明確禁止的
contact。結果是 **BLOCKED／NOT RUN**：scan 次數 `0`，tunnel stop 次數 `0`。新納入版本
控制的 localhost fixture harness 正確 fail closed；production invocation 回報
`EADDRINUSE`。不能把 `EADDRINUSE` 寫成 scan PASS。

完整 structured blocker note 只留在 private diagnostics，不上傳、不匯入，也不複製進公開
報告。

## Windows qualification 缺口

- 主機是 filtered non-elevated admin，且不是 clean、resettable disposable lab。
- `HypervisorPresent` 為 true、VirtualMachinePlatform enabled，但 WSL optional feature
  disabled；這些 capability facts 不等於準備好一個 qualification snapshot。
- 沒有 canonical installed lifecycle row。
- 沒有 BEGINNER participant 或 observe-only session。
- 沒有原生 combined Start、master report、reopen、readable export journey。
- 隔離 CLI 雖驗證 export／delete 行為，仍不是上述原生 GUI journey。
- 沒有 passing Authenticode evidence；outcome 是 `not-configured`。
- 所以沒有 stable、signed、recommended、beginner-ready qualification。

## Process deviation

一個 delegated read-only audit 在 reminder 前使用 authenticated `gh api` 做了 `18` 次 GET；
沒有 download、write、dispatch 或 remote mutation。狀態其後從 public surface 重驗，owner
之後也授權 GitHub access。此事不影響 artifact hash，但屬過程偏差，保留在測試紀錄中，
不得描述成從一開始就有授權。

## 最終驗證

所有 PASS 都是 post-release source／tooling 結果；published `v0.1.9` bytes 維持不變。

| 項目 | Final commit／result |
| --- | --- |
| Exact post-release final code checkpoint | `3b3591ad72e35735b71e17a3d30c1bb8546e0d5c`（canonical timestamps；WL-13／case race：`8d138a13d736259d2626eed0ef12324cb327fdc4`；CI behavior：`f04567cf09635b24062219684dc8325b3e44f61a`；UI／service：`d28f287d78a079828af45f1ee3bbca165ae091ea`；主要實作：`bd47e26b6c8024eb3461176637d7fce3e8370561`） |
| GitHub checks for code checkpoint | [CI `34128123284`](https://github.com/teddashh/ai-security-scanner/actions/runs/34128123284) 9/9 jobs PASS；[CodeQL `34128074242`](https://github.com/teddashh/ai-security-scanner/actions/runs/34128074242) Rust／JavaScript-TypeScript 均 PASS |
| Frontend | `486/486` PASS |
| Component | `145/145` PASS |
| Usability evidence | `5/5` PASS |
| Engine／Prowler／AIDEFEND | `168` byte-stable inputs／`21` records／`8/8`／`6` records，PASS |
| Release validate／self-test | PASS／PASS（Rust 1.98） |
| Release evidence | `142/142` PASS |
| CI boundary／drift guards | `31/31` PASS |
| Typecheck／build／desktop check | PASS／PASS（chunk warning）／PASS |
| Rust 1.98 all-targets | `1478/1478` PASS |
| Clippy all-targets `-D warnings` | PASS |
| Rustfmt all `--check` | PASS |
| Dependency reachability | Windows target 無 `glib`；Linux target 可達 `glib 0.18.5`，medium `GHSA-wrw7-89jp-8q8g` 仍 open |
| Locale／modal／delete／target-validation families | FIXED；targeted tests、完整 frontend/component 與最小 browser recheck 通過 |
| Published `v0.1.9` installer | **UNCHANGED；new installer NOT BUILT** |
