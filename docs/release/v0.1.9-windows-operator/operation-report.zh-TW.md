# AI Security Scanner v0.1.9 Windows Operator 作業報告

日期：2026-09-07
Repository：`teddashh/ai-security-scanner`
凍結 source／本輪起始 `main` checkpoint：`5c95572f54220adbd170d9bfb5af3159c56708ef`
平台：Windows 11 Pro `10.0.26200.9168`，x64

> **結論先講：部分觀察完成，但沒有完成 Windows qualification。** 本輪確認了公開
> `v0.1.9` NSIS candidate、已安裝程式與 managed-runtime manifest 的 identity，並產生及
> 驗證一份嚴格的 unsigned observation；另以隔離 data directory 完成一條不接觸網路的
> installed-CLI regression。原生桌面 GUI 功能路徑沒有執行：Codex 當時無法控制
> 原生視窗，而且 `127.0.0.1:9001` 由 Better Agent Terminal（BAT）使用的 SSH tunnel
> 持有；按 Start 會接觸未獲准的 BAT 服務。因此沒有 scan、沒有 lifecycle row、沒有
> BEGINNER session，也沒有 signed、stable、recommended 或 beginner-ready qualification。

本報告只記錄本輪實際觀察。它不改寫已發布的 `v0.1.9` bytes，也不把 source test、
browser 開發預覽或安裝於日常電腦上的 regression observation 冒充 exact-candidate
clean-lab evidence。正式操作規則見
[Windows 外部 qualification 計畫](../windows-external-qualification-plan.zh-TW.md)。

## 發行狀態與證據分層

### 已發布的 `v0.1.9` candidate

- Public candidate：`ai-security-scanner_0.1.9_x64-setup.exe`
- Size：`40,186,968` bytes
- SHA-256：`f7b5374fff07fca98af06931b2dc0ebc52abc2b3ac5a70a6602001d03a1a065e`
- `Get-AuthenticodeSignature`：`NotSigned`
- Candidate／package 的 immutable metadata 仍是 `prerelease`。
- Repository owner 後來刻意把 GitHub 的可變 release listing 改成 non-prerelease
  **Latest**。這只改變 listing；不改變 installer bytes、candidate channel、evidence、
  Authenticode 或 qualification 結果。
- Release body 與 textual assets 仍是 stale 發行文字，不能拿來覆蓋 machine-readable
  identity 或本報告的實測缺口。

已發布的 `v0.1.9` bytes 本輪沒有替換、重建或修改。發行後的 source 修正即使測試通過，
在產生並重新 qualification 新 bytes 前，都不屬於上述 installer。

### 發行後 `main` 工作

本輪主要實作 commit 是 `bd47e26b6c8024eb3461176637d7fce3e8370561`；website-service
邊界修正 checkpoint 是 `d28f287d78a079828af45f1ee3bbca165ae091ea`；補齊 shared-corpus
CI routing 的 behavior checkpoint 是 `f04567cf09635b24062219684dc8325b3e44f61a`；同步 rustfmt
checkpoint 是 `31e4506b464716798f6134476c64353a02c674ff`；WL-13 identity exclusivity
與 case-selection race checkpoint 是 `8d138a13d736259d2626eed0ef12324cb327fdc4`；canonical UTC
evidence timestamp 收尾後的 final code checkpoint 是
`3b3591ad72e35735b71e17a3d30c1bb8546e0d5c`。它們都是
`v0.1.9` 發布後的 source commit，不是已發布 installer 的 source identity。

Browser 預覽與最終 diff audit 共揭露八個具體缺陷，歸在四個 defect families：

1. runtime 切換語言後，內建 demo record 現在會同步翻譯；使用者輸入仍保留原文；
2. mobile navigation modal 現在鎖住背景 scroll，並在 close／unmount／breakpoint 後精確還原；
3. browser demo 建立的 case 現在可經 exact-name two-step flow 刪除，且不暗示有 evidence files；
   刪除背景 case 時也會保留目前選取的其他 case；若刪除期間連續切換 case，post-delete reload
   會跟隨最新已完成的選取，過時 selection 不會卡住流程或清掉較新 selection 的 loading state；
4. public／internal target 輸入列現在於建立前拒絕 malformed URL、port、wildcard、含空白假主機
   與錯誤 CIDR；deployed-website URL 衍生出的 host 也會經過同一驗證與 canonicalization，
   明確 port `0` 與 percent-encoding 後超過 `2,048` 字元的 path 也會在表單內被拒絕，
   native path 仍是最終權威。

Qualification tooling 也有實質推進：計畫新增擁有人明確授權的 `AUTO-OPERATOR` track，
Codex 可自行對唯一固定的 `127.0.0.1:9001` 執行 safe Start，不需另外等真人按鍵；無人可做
raw HTML readability observation 時，readability check 誠實留為 `not-observed`，已嘗試的
lifecycle row 記為 `inconclusive`、`reasonCode: required-observation-unavailable`，其他安全 rows 繼續。
Lifecycle validator／schema 綁定 exact fixture path、script digest、Windows Node runtime identity，
並雙向限制只有 WL-13 可以回報 `reachable`；WL-13 的 fixture runtime、path 與 digest 三個座標
也全部保留給 WL-13，其他 row 不得借用其中任何一項。新 fixture 固定綁在 loopback、拒絕
override／覆寫 receipt，且 port 被其他 owner 佔用時 fail closed。

Evidence timestamp validator 也由寬鬆的 `Date.parse` 改為共用 canonical UTC parser：只接受真實
calendar date、`Z`／`+00:00` UTC offset 與最多九位 fractional seconds，並用 nanosecond
order key 比較先後；JSON schema 同步約束 UTC、月份邊界與閏年。這是 fail-closed evidence
hardening，不會改變 candidate bytes。

這些是有價值的 defect discovery，但當時不是已發布 candidate 的原生 GUI 重現證據；
修正也不是 `v0.1.9` 已發布 bytes 的一部分。Release-evidence 與 Windows portability／fixture
修正最終為 `142/142`，同樣只算 post-release source advancement，直到新 build 才可能成為產品 bytes。

同步到 Castle 後另發現一個 release-engineering 缺口：新增的 shared external-target corpus 同時被
frontend 與 Rust parity tests 讀取，但 corpus-only change 原本不會排程這兩條 CI lane。Classifier
現在精確排程 `frontend:true`、`rust_core:true`、`desktop:false`，新增 regression 後 CI boundary
suite 為 `31/31` PASS。這是第九個具體修正，但不列入上面的八個 UI／UX issue。

## 操作環境

| 項目 | 實際觀察 |
| --- | --- |
| Windows | Windows 11 Pro `10.0.26200.9168`，x64 |
| 帳號／權限 | filtered、non-elevated administrator token |
| Virtualization | `HypervisorPresent = true` |
| WSL optional feature | disabled |
| VirtualMachinePlatform | enabled |
| Lab 性質 | 日常主機；沒有 disposable snapshot，也不是 clean lab |
| 原生 App | 已安裝且已在執行，但 Codex CUA 回報 `apps:[]`，無法控制視窗 |

因為沒有 resettable disposable snapshot，這台機器即使完成某些 regression 也不能產生可
import 的 canonical lifecycle 或 BEGINNER qualification evidence。

## Candidate、安裝與 runtime identity

下載的 candidate filename 為 `ai-security-scanner_0.1.9_x64-setup.exe`；實際 size、version、
SHA-256 與 frozen handoff 相符，Authenticode 為 `NotSigned`。本機下載路徑不納入公開報告。

已安裝程式：

- Installed path：`<user-profile>\AppData\Local\ai-security-scanner\ai-security-scanner.exe`
- File／product version：`0.1.9`
- Size：`30,512,128` bytes
- SHA-256：`3e876497e7cb47881ec12e96ce2976b7f5e6ea5ab71da41c1f1a7357587c8c8a`

已安裝 managed-runtime manifest：

- Installed path：`<user-profile>\AppData\Local\ai-security-scanner\managed-runtime\manifest.json`
- Size：`3,724` bytes
- SHA-256：`a8112473e5d87655e6145ea5f6cff569c872329d2ec14bfb9463078abcb60e3a`
- 結果：與 frozen expected manifest byte-exact 相符。

## Installed CLI 與 doctor

已安裝 CLI 的 `--version` 回報 `ai-security-scanner 0.1.9`。JSON doctor 的實際摘要為：

- `21/21` manifests 為 release-approved；
- invalid checkpoints：`0`；
- cleanup obligations：`0`；
- compatibility runtime：absent；
- managed-local Podman `5.8.2`：available、running；
- provider：WSL；preferred provider：`managed_local`；
- legacy CLI data：preserved。

Doctor 的 `provider: WSL` 是產品當下回報的 runtime/provider 欄位，不會推翻 OS optional
feature 為 disabled 的獨立觀察，也不代表 clean-lab WSL lifecycle 已驗證。

這只證明該 installed CLI 的診斷狀態；它不證明桌面 Start、scan、report、reopen、export、
repair、upgrade 或 uninstall lifecycle 已通過。

## 隔離的 installed-candidate CLI regression

另以一次性、隔離的 private data directory 操作已安裝的 `0.1.9` CLI。該目錄不使用既有
App data，整條 probe 沒有 network contact；本機 path、內容與 raw logs 不納入 repository：

- `--version` 回報 `0.1.9`；
- `seed-demo`、case list、selected-case 與 show 都成功；
- 先觀察 exact delete plan；提供錯誤的 `--confirm-case-id` 時 exit `1`，case 被保留；
- 提供精確 confirmation 後，只刪除該 case 的 DB／event rows，case count 成為 `0`；artifact
  plan 的 `exists` 為 `false`，先前輸出的 external files 仍保留；
- standard-redaction HTML export：`15,992` bytes，SHA-256
  `98fcc7d7aec6b027b78adfc46e03d785379bdf6b3d88f0922692523f19409f81`；local verification valid；
- canonical beginner/master JSON export：`22,339` bytes，SHA-256
  `6c283ad82496060210c427ebe930f2f0ac975f293b61d1e9eb8d8578fc760b2d`；local verification valid；
- 對已存在的 destination 重複 export 時 exit `1`，原 HTML hash 不變，沒有覆寫；
- standard-redaction case bundle：`16,873` bytes，SHA-256
  `767ae0cf9304a88612b8c78f1f187df4f1039aea95aad55061ebb3106e19eecc`；local verify valid；刪除
  DB case 後 detached verify 仍 valid；bundle 有 `19` entries、`rawArtifactsIncluded = 0`，並使用
  truthful integrity-only notice。

所有檔案只留在 private diagnostics，**不可上傳或匯入**。本輪沒有開啟 report
內容或 raw evidence，只檢查必要 metadata 與 manifest inventory。檔名中的
`beginner/master` 描述 export 類型，不是 BEGINNER human evidence；整條 probe 是 installed
CLI regression，不是 native GUI、lifecycle 或 stable qualification。

## SIGNING-VERIFY

嚴格 unsigned observation：

- Canonical filename：`unsigned-os-signing-observation-windows-x86_64-nsis.json`
- Size：`815` bytes
- SHA-256：`d42f13ab731c3b8f1f8bd89d267ffa07d2bd86b7aaf9f14d87ba4b1688342d43`
- Validator：PASS
- Outcome：`not-configured`
- Signature status：`NotSigned`

這是「已確認沒有配置受接受的 OS signing」的有效紀錄，不是 passing Authenticode
evidence。沒有建立或冒充保留給通過簽章結果的 evidence 檔。

## Browser CUA 預覽

在 `433px` 寬度的人工作業中，以 browser 開發預覽檢查：

- Traditional Chinese／English navigation；
- use-case disclosure；
- website URL 輸入：拒絕 `ftp` 與含 credentials URL，接受精確 localhost URL，且未接觸目標；
- AI onboarding；
- partial-results disclosure；
- master-report export UX；
- two-step deletion semantics。

該路徑沒有觀察到 console warning 或 error，並找到四個初始 issue；final diff audit 再找到
同屬 deletion 與 target-validation families 的四個 edge issue。修正後再驗證顯示：
內建案例可隨語系切換、使用者文字維持原文、modal background scroll 被鎖住並還原、無效
external targets 被 field-specific alert 擋下且 focus 正確，合法 FQDN／IPv4／IPv6／CIDR 通過。
Browser-only deletion 的實際刪除動作未在收尾時重跑，避免未經 action-time confirmation 改動
本機 UI 資料；其 exact-name／built-in 保護／no-artifact／background-selection 行為，以及刪除
期間連續 selection 的 supersession／loading-state race，均由 frontend 與 component tests 覆蓋。
這是 current source 的
browser preview，不是 installed candidate、Tauri webview、clean Windows、BEGINNER 或
lifecycle evidence；「沒有 console error」也不代表沒有產品缺陷。

## 原生 GUI 與 localhost fail-closed

Codex 的 current CUA surface 回報 `apps:[]`，所以無法操作已在執行的原生 App。本輪沒有
用 PowerShell、Win32 automation 或其他旁路假裝完成 GUI 操作。

Private port-owner observation 確認 `127.0.0.1:9001` 由現有 BAT SSH tunnel 使用，而不是
reviewed qualification fixture。公開報告不保存本機 PID、command line、遠端 endpoint 或
其他 network topology。

因此按下產品的 localhost Start 會掃描 BAT 所使用的遠端 tunnel，而不是 reviewed
qualification fixture；這超出授權範圍，必須 fail closed。本輪沒有接觸該 port、沒有執行
scan、沒有停止或重新設定 tunnel，也沒有終止 BAT。

新納入版本控制的 localhost fixture harness 採 fail-closed 行為；在目前 production port
狀態執行時回報 `EADDRINUSE`。這個結果證明 blocker 被拒絕，不證明 scan path 通過。

完整 port-owner structured note 只保存在 private diagnostics，不上傳、不匯入，也不複製進
公開報告。

## Automated support evidence

在本輪紀錄的 source checkpoints，已觀察到下列 automated 結果：

- frontend：`486/486`；
- component：`145/145`；
- usability evidence：`5/5`；
- engine validation：`168` 個 byte-stable inputs、`21` records、Prowler `8/8`；
- AIDEFEND：`6` records；
- release validate、release self-test、frontend build、desktop check：PASS；
- TypeScript typecheck：PASS；
- Rust `1.98` all-targets：`1478/1478`；
- Clippy all-targets `-D warnings`：PASS；
- Rustfmt all `--check`：PASS；
- post-release release evidence：`142/142`。
- CI boundary／drift guards：`31/31`。

第一次執行 release self-test 與 desktop check 時，ambient default Rust `1.97` 不符合專案的
`1.98` 工具鏈而失敗；明確設定 `RUSTUP_TOOLCHAIN=1.98.0` 後，兩項均完整通過。Self-test
輸出的 tamper／bad-signature／missing-evidence 錯誤是預期的負向 fixtures。Production frontend
build 另有一項非阻擋提醒：主 JS chunk `985.21 kB`（gzip `300.50 kB`）高於 Vite 的
`500 kB` warning threshold，應列為後續 code-splitting 技術債。

### GitHub dependency residual risk

Push 後 GitHub 回報一項仍開啟的 medium Dependabot alert：
[`GHSA-wrw7-89jp-8q8g`](https://github.com/advisories/GHSA-wrw7-89jp-8q8g)／
`RUSTSEC-2024-0429`，
`Cargo.lock` 中 `glib 0.18.5` 落在 `>=0.15,<0.20`，首個修正版為 `0.20.0`。
`cargo tree --locked --offline --target x86_64-pc-windows-msvc -i glib` 沒有輸出，表示這個
crate 不會連入本輪 Windows NSIS／MSI binary；Linux target 則可沿
`tauri 2.11.5 -> gtk 0.18.2 / webkit2gtk 2.0.2 -> glib 0.18.5` 到達。Source audit
沒有找到產品或這條 GUI stack 使用受影響 `VariantStrIter` API，但這只降低實際可達性，不能
消除依賴風險。

`cargo update -p glib --precise 0.20.0 --dry-run` 被 `gtk` 的 `glib = ^0.18` 約束拒絕；
`cargo update -p tauri --dry-run` 在 Rust `1.98` 下沒有可更新套件。因此本輪沒有用不受控 fork、
雙版本或大型 Tauri／GTK migration 冒充小修，也沒有 dismiss alert。它不阻擋本輪 Windows
結果，但仍是 Linux desktop 發行前必須明示接受、暫緩該 artifact，或另案升級並重新 qualification
的 residual risk。

不同 runner／suite 可能重疊，不把數字相加成虛假的「獨立測試總數」。這些結果支持 source
品質；它們不能替代 exact installed candidate 的真人、原生 GUI、lifecycle 或 signing gate。

## 實質推進與沒有推進的部分

| 項目 | 本輪實質變化 | 不可外推的宣稱 |
| --- | --- | --- |
| Published installer | `0` bytes 改寫；filename／size／SHA-256 維持 frozen identity | 沒有把 post-release fix 送進 `v0.1.9` |
| Signing observation | 新增 `1` 份、`815` bytes 的嚴格 validated unsigned record | `not-configured` 不是 signing PASS |
| Installed identity | `1` 個 App executable 與 `1` 個 runtime manifest 完成 exact check | 不等於 lifecycle 或 clean-install PASS |
| CLI health | version `0.1.9`；doctor `21/21`，invalid／cleanup 均 `0` | 不等於桌面 first-value journey |
| Installed CLI regression | `1` 個隔離、無網路 probe；列明的 HTML／JSON／bundle 有固定 hash；delete／no-overwrite／detached verify 成立 | private、non-importable；不是 GUI／lifecycle／BEGINNER |
| Browser review | `7` 類 UX／disclosure path 被人工檢查；browser 加 final audit 找到四個 defect families／八個具體 issue | dev preview 不是 installed-candidate evidence |
| Native scan | `0` 次；port-owner check 正確阻擋接觸 BAT | 沒有 report、reopen 或 export lifecycle evidence |
| BEGINNER | `0` qualifying sessions | beginner-ready gate 完全未通過 |
| Post-release tests | release evidence `142/142`，frontend `486/486`，component `145/145`，Rust `1478/1478`，CI boundary `31/31`，其餘列明的 final gates 通過 | 在新 installer 前，對 published bytes 的改善為 `0` |

**水分判讀：**自動測試數字彼此有覆蓋，不能相加成一個誇張總數；browser preview 也不能
冒充 installed Windows app。真正可交付的推進是主要 implementation commit 的 `2,400` 行新增／
`153` 行刪除，加上 website-service follow-up 的 `37` 行新增／`2` 行刪除、CI follow-up 的
`21` 行新增、rustfmt convergence 的 `4` 行新增／`1` 行刪除，以及 final WL-13／case-selection
race follow-up 的 `194` 行新增／`13` 行刪除，再加 canonical timestamp hardening 的 `125` 行
新增／`9` 行刪除；交付涵蓋八個 UI／UX issue（含 deletion family 的並行 race 收尾）、一個 CI
routing issue、exact Windows fixture／evidence contract、canonical UTC evidence timestamps，
以及三份可追溯文件。
對已發布 `v0.1.9` installer 的程式碼推進是 **0 bytes**，原生 localhost scan 是 **0 次**，
Windows qualification 仍是 **未完成**。這兩面都必須同時保留，不能只報漂亮數字。

## 過程偏差

一個 delegated read-only audit 在收到 reminder 前，以已登入的 `gh api` 執行 `18` 次 GET。
沒有下載 artifact、沒有 write、沒有 workflow dispatch，也沒有改 GitHub state。相關狀態其後以
publicly accessible 資料重新驗證；repository owner 之後也明確授權 GitHub access。後續授權
不抹去先前的 process deviation，因此在此保留紀錄；它沒有被拿來當作下載或 mutation 授權。

## 收尾狀態

- 未建立 BEGINNER evidence。
- 未建立 canonical lifecycle evidence。
- 未執行任何 scan，未接觸 `127.0.0.1:9001` 上的服務。
- Installed CLI regression 只使用隔離 private-diagnostic data directory，沒有讀取既有 App data
  或接觸網路；其輸出不可上傳。
- 未停止 tunnel、BAT 或已安裝 App。
- 未刪除使用者資料，未執行 all-data uninstall。
- 未替換 tag、release asset 或 `v0.1.9` installer。
- 最終 disposition：**partial／blocked；可保留 unsigned observation，不可宣稱 Windows
  qualification、stable、signed、recommended 或 beginner-ready。**

## 最終驗證

以下結果都綁定 post-release implementation commit；它們不會回溯修改已發布的
`v0.1.9` bytes 或 candidate qualification。

| 欄位 | 最終值 |
| --- | --- |
| Post-release final code checkpoint | `3b3591ad72e35735b71e17a3d30c1bb8546e0d5c`（canonical timestamps；WL-13／case race：`8d138a13d736259d2626eed0ef12324cb327fdc4`；CI behavior：`f04567cf09635b24062219684dc8325b3e44f61a`；UI／service：`d28f287d78a079828af45f1ee3bbca165ae091ea`；主要實作：`bd47e26b6c8024eb3461176637d7fce3e8370561`） |
| Branch／remote alignment | `main`；交付時以 remote ref 與 Castle clean fast-forward 驗證本機／GitHub／Castle exact HEAD 對齊 |
| GitHub checks for code checkpoint | [CI `34128123284`](https://github.com/teddashh/ai-security-scanner/actions/runs/34128123284) 9/9 jobs PASS；[CodeQL `34128074242`](https://github.com/teddashh/ai-security-scanner/actions/runs/34128074242) Rust／JavaScript-TypeScript 均 PASS |
| Frontend final | `486/486` PASS |
| Component final | `145/145` PASS |
| Release evidence final | `142/142` PASS |
| CI boundary／drift guards | `31/31` PASS |
| Usability evidence final | `5/5` PASS |
| Rust 1.98 all-targets final | `1478/1478` PASS |
| Clippy／Rustfmt final | `-D warnings` PASS／all `--check` PASS |
| Typecheck／build／desktop check | PASS／PASS（chunk-size warning）／PASS |
| Release validate／self-test | PASS／PASS（Rust 1.98；負向 fixtures 如預期） |
| Dependabot | `1` medium open：`GHSA-wrw7-89jp-8q8g`；Windows target 不可達，Linux desktop residual risk 未 dismiss |
| 四個 defect families／八個具體 issues | FIXED；targeted tests、全套 frontend／component 與最小 browser recheck 通過 |
| New installer | **NOT BUILT**；只有 production frontend bundle 與 desktop source/sidecar check，不存在可發布的新 installer identity |
