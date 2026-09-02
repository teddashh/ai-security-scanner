# AI Security Scanner v0.1.8 Foreground QC 測試報告

日期：2026-09-02
原始功能整合 commit：`503542271ff8b2178ed2d334fd47d76c494d1c75`
本輪主要強化 commit：`a538778a34cd7db72b28256591575aee77937ab8`
最終已驗證程式 checkpoint：`0077b2c5a6df8c758afbb44be5a1c6a9b2202a64`
平台：Windows 11 Professional／Castle Linux
Rust：兩端 rustc/cargo 1.98.0
Node：v24.16.0
npm：11.13.0

## 測試範圍與限制

本報告涵蓋 source、unit/integration、fixture、typecheck、lint、frontend build、release evidence、engine metadata validation 與 unsigned installer build。

本輪沒有安裝、啟動或操作 App，沒有 BAT，沒有 clean VM／human session／real engine scan。因此「PASS」只代表對應 automated command 或 artifact check 成功，不能外推成 production qualification。

0.1.8 後續增量程式已 commit／push，Windows 與 Castle 都在同一個 `0077b2c` code checkpoint 完成完整重跑。文件本身會形成其後的文件 commit；仍不可把不同 feature/platform 的重疊測試相加成一個行銷總數。

## 最終測試矩陣

| 類別 | 命令／證據 | 最終結果 | 說明 |
|---|---|---:|---|
| Rust format | `cargo fmt --all -- --check` | PASS | 最終 source format clean |
| Desktop Rust | `cargo test --locked --package ai-security-scanner --features desktop` | PASS | 詳細 binary/suite 如下 |
| CLI/workspace Rust | `cargo test --locked --workspace --no-default-features --features cli` | PASS | 與 desktop 有重疊，不合併灌總數 |
| Castle Linux CLI workspace | 同一 locked CLI workspace | 1,307/1,307 PASS | 0 failed／ignored／measured／filtered |
| Castle provider artifact | targeted module | 14/14 PASS | 包含 Unix hardlink、permission、file/parent durability regressions |
| Clippy | desktop、all targets、`-D warnings`，且 `RUSTFLAGS=-D warnings` | PASS | 最終 0 warning/error |
| Castle Linux Clippy | CLI workspace、all targets、`-D warnings` | PASS | 首輪 8 findings 修正後重跑 |
| TypeScript | `npm.cmd run typecheck` | PASS | TypeScript typecheck 通過 |
| Frontend tests（最新增量） | `npm.cmd run test:frontend` | 364/364 PASS | 包含 Settings state 與 case bundle disclosure regression |
| Frontend build | `npm.cmd run build` | PASS | Vite 8.2.2，93 modules |
| Release evidence | release evidence tests | 53/53 PASS | fixture/evidence regression |
| CI classification | classification tests | 22/22 PASS | change routing regression |
| Engine validation | catalog／line endings／Prowler | PASS | 167 inputs、21 records、19 runnable、Prowler 8/8 |
| Release policy | policy validator | PASS | automated policy checks |
| AIDEFEND | snapshot validator | PASS | 6 records；captured snapshot ref `e10c…` |
| Usability evidence | evidence schema tests | 5/5 PASS | 明確沒有 human session |
| Provider artifact desktop module | targeted desktop module | 19/19 PASS | 固定 4 recovery slots、matching reuse、durability、security fail-closed |
| Provider artifact CLI module | targeted CLI module | 19/19 PASS | 與 desktop run 重疊，不相加成獨立 38 tests |
| Signed case bundle | targeted Rust regression | 1/1 PASS | case-wide records、selected-run observations/evidence 與 current-projection caveat皆有 sentinel 驗證 |
| Nuclei real template tree | Castle；pinned Go 1.26.0 container；`nuclei-templates@24858b4…` | 1/1 PASS | 真實 tree targeted test；不是 image publication |
| Nuclei production image gate | 新 immutable recipe／tag／attestation | NOT IMPLEMENTED／NOT RUN | `3.11.1-5` 是舊 recipe；本輪拒絕冒用其 digest／evidence |
| Previous Windows bundle | unsigned NSIS build（pre-`a538778`） | HISTORICAL PASS；latest rebuild NOT RUN | 舊 candidate未安裝／未啟動，不能代表最新 source |
| Historical original staged diff | `git diff --cached --check`（`5035422` commit 前） | PASS | 74 檔只屬原始功能整合，不是 `0077b2c` 最終 diff |
| Cross-machine integrity | Windows／GitHub／Castle SHA | PASS | 驗證 code HEAD 都是 `0077b2c5…`，Castle clean |

## Desktop Rust 詳細結果

`cargo test --locked --package ai-security-scanner --features desktop`：

- library：892 passed
- adapter fixtures：18 passed
- connector fixtures：14 passed
- discovery coverage：11 passed
- engine execution：354 passed
- job manager：21 passed
- local lifecycle：2 passed
- source authorization：14 passed
- workspace snapshot：18 passed
- doctests：3 passed

合計：1,347 passed，0 failed／ignored／measured／filtered。

這些是不同 test binary／suite 的個別結果。報告不把它們與 CLI build 重疊測試相加成單一行銷數字。

## CLI／workspace 詳細結果

`cargo test --locked --workspace --no-default-features --features cli`：

- library：852 passed
- CLI binary：33 passed
- adapter fixtures：18 passed
- connector fixtures：14 passed
- discovery coverage：11 passed
- engine execution：354 passed
- job manager：21 passed
- local lifecycle：2 passed
- source authorization：14 passed
- workspace snapshot：18 passed
- doctests：3 passed

合計：1,340 passed，0 failed／ignored／measured／filtered。

Desktop 與 CLI feature set 會重編並重跑部分共同邏輯，所以「1,347 + 1,340」不是獨立測試總數。

### Castle Linux CLI／Unix 結果

在 `/home/ted-h/projects/ai-security-scanner`、Rust 1.98、commit `0077b2c5a6df8c758afbb44be5a1c6a9b2202a64`：

- 完整 CLI workspace：821 library + 35 CLI + 18 adapter + 15 connector + 11 discovery + 343 engine execution + 21 job manager + 2 lifecycle + 14 authorization + 24 workspace snapshot + 3 doctests = 1,307 passed，0 failed／ignored／measured／filtered。
- Provider artifact targeted module：14/14 PASS（807 library tests filtered）；包含 Unix collision、hardlink、permission hardening、file sync、parent-directory sync 與 retry/no-slot-advance regressions。
- `cargo clippy --locked --workspace --no-default-features --features cli --all-targets -- -D warnings`：PASS。
- `cargo fmt --all -- --check`：PASS；worktree clean。

這個 1,307 是該 Linux command 的 suite total，不與 Windows suites相加成單一獨立測試數。

## Frontend 與 build 詳細結果

- Typecheck：PASS。
- Frontend tests：最新增量 364/364 PASS；先前完整 checkpoint 是 358/358。
- Vite：8.2.2，93 modules。
- CSS：約 107.60 kB，gzip 約 19.69 kB。
- Main JS：877.98 kB，gzip 265.59 kB。
- Vite 仍顯示 >500 kB chunk warning；非本輪 blocking gate，但要在量測 startup 後安排 code splitting。

Frontend tests 包含 presentation helper、case/run identity、demo export projection、navigation、locale、runtime truth reconciliation、primary path source regression 等。後者是 source-level regression，不是 browser human journey。

Castle 以 Node 24.15.0／npm 11.12.1 在 `0077b2c` 重跑：typecheck、364/364 frontend、93-module Vite build、53/53 release evidence、5/5 usability schema、167 engine inputs／21 records／19 runnable／Prowler 8/8、AIDEFEND 6 records與 release validation，全數 PASS。Linux build main JS 同為 877.98／265.59 gzip kB。歷史 `npm ci` audit 曾對該 lockfile 安裝圖回報 36 packages／0 vulnerabilities，但不抵銷 GitHub default branch 顯示的 1 個 moderate vulnerability。

### 0.1.8 後續增量結果

- Frontend：364/364 PASS。
- Release evidence：53/53 PASS。
- Usability schema：5/5 PASS；仍明確不是 human session。
- Prowler：8/8 PASS。
- Typecheck、Vite build、engine validation、AIDEFEND validation：PASS。
- Provider artifact targeted module：Windows desktop 19/19、CLI 19/19、Castle/Linux 14/14 PASS；feature/platform runs 有重疊，不合併灌總數。
- Nuclei real template tree：Castle targeted test 1/1 PASS；production gate NOT IMPLEMENTED，image build／新 tag／publication NOT RUN。

## 安全與資料完整性重點回歸

### Managed runtime generations

- fresh Windows runtime 會選 generation 1。
- 已精確證明的 deployed generation 0 可重用。
- clean gen1 不會虛構 collision name。
- interrupted init／retry 的 generation advancement 有 regression coverage。

### Provider artifact recovery

- canonical collision mismatch 會保留原檔。
- recovery 使用固定 4 個 deterministic slots；相同內容會重用既有 slot，不新增重複 artifact。
- 不同內容只會依序使用下一格，保留每個 collision 的 byte-exact 證據；4 格耗盡時回傳錯誤且不新增檔案。
- hardlink、custom/noncanonical authority 的不安全 Windows DACL、identity 或其他非內容型安全失敗立即 fail closed，不會跳到下一格、修補或改寫既有 artifact。
- Windows custom root 的 DACL policy 永遠 verify-only；matching reuse 仍以同一 write-capable pinned handle 執行 durability sync，但不要求 `WRITE_DAC`。Canonical root 只有在內容/identity與 sync 成功後才做 bounded DACL repair，sync failure 會在 repair 前停止。
- Unix fresh canonical/recovery：file sync → identity/mode proof → pinned parent-directory sync → 再 proof。Matching reuse：content/identity proof → file sync → parent sync → `chmod(0600)` → 第二次 file sync → final proof。Parent sync failure 不 chmod、不成功、不前進 slot，retry 重用同一 object。
- desktop targeted module 19/19、CLI 19/19、Castle/Linux 14/14 PASS；三組有重疊，不相加。
- 非阻擋殘餘風險：部分 Unix namespace 操作仍是 pathname-relative，same-user mutation 可發生在循序 checks 之間及 final proof／authority pin 釋放之後。Identity rechecks 可偵測已觀察到的置換，但無法讓 namespace proof 原子化；完全消除需 dirfd-relative 操作或保留 handle到 consumption。
- 沒有以路徑名稱粗暴刪除未知 artifact。

### Signed case bundle scope

- Bundle contract 明確是 **case-wide records + run-bound reports**，不是整包 run-only。
- Signed manifest 的 notice、`case.json` scope fields、README 與 Export UI 使用同步 disclosure。
- Case-wide records 涵蓋 assets、grants、coverage、history、findings、workflow、comparisons 與 source files；reports 選取 selected run 的 observations/evidence。Legacy observation 缺 frozen presentation snapshot 時可使用 current canonical finding，workflow status 與 asset display 也可能反映 current case projection；manifest／README／UI 明確揭露。
- Targeted fixture 證明 distinct run 的 finding/observation 不進入四種 reports，卻仍留在 case-wide findings；current projection sentinel 只出現在 exporter 真正會使用它的欄位。
- Automated disclosure regression 已通過；真實簽章 bundle 的 installed／human journey 仍未執行。

### Settings runtime presentation

- `undefined`／unknown 顯示為「尚未檢查」狀態，和已確認 unavailable 的 warning 分離。
- `demo`、`ready`、`unavailable`、`unchecked` 由 pure presentation helper 統一產生。
- 新增的 Settings presentation tests 已包含在最新 364/364 frontend PASS。

### Nuclei pinned-template-tree 驗證與 image 邊界

- Castle checkout 的 template repository HEAD 精確為 `24858b4bfabfa86f0bcfd36aea24fb535152b012`，工作樹乾淨。
- 使用 `golang:1.26.0-alpine@sha256:d4c4845f5d60c6a974c6000ce58ae079328d03ab7f721a0734277e69905473e5` container，設定真實 `NUCLEI_TEMPLATE_ROOT` 後，`TestPinnedNucleiTemplateTreeWhenProvided` 1/1 PASS（0.42s）。
- Review 發現 production Dockerfile／plan 仍綁定已發布 `3.11.1-5@sha256:2bd1e15a0ffdf450cdf85acd75bca2fb7f3cf4f9bc1d1fce80d5f8a659bc7488` 及 publication source revision `7514fd0642b28fe73ebdd2d48f0149b40f6eec17`；直接更改 recipe 卻沿用舊 tag 會讓 provenance guard 失敗，也會讓文件假稱舊 image 跑過新 gate。
- 因此本輪撤回 Dockerfile／plan recipe 改動，只保留真實 targeted test 證據。新的 production gate 必須使用新 immutable tag、新 digest／attestation 與只處理實際變更 engine 的 publication path；production gate NOT IMPLEMENTED，image build／publication NOT RUN。

### Report/redaction

- HTML 輸出 exact address／port rectangles、stage、target、transport、outcome、observed time。
- HTML escaping 有 coverage。
- standard redaction 以 `[redacted address set 1]`、`[redacted port set 1]` 取代原值。

### Demo export honesty

- selected-run JSON only。
- raw evidence 固定 false。
- redaction claim 固定 false。
- 不宣稱 HTML／OCSF／OSCAL serializer、coverage companion 或 signature。
- UI 禁用 demo 不支援的選項並解釋限制。

### Lease 與同步

- CLI managed status 在隱性 managed-runtime mutation 前取得 data-directory lease。
- localhost polling tests 使用 2 秒 deadline 與 `recv_timeout`，避免主要 regression 無限等待。

## Installer 驗證

檔案：`C:\Users\tedjc\Documents\Codex\2026-08-27\t\outputs\ai-security-scanner_0.1.8_x64-setup-foreground-qc-unsigned.exe`

| 欄位 | 值 |
|---|---|
| Size | 39,985,091 bytes |
| LastWriteTimeUtc | `2026-09-02T09:24:15.3379353Z` |
| SHA-256 | `15A74C9EAA9BA0864B03524D7F2B40B1B2C854D6DEA5E8079C81B1C96AAD56B9` |
| Authenticode | `NotSigned` |
| FileVersion | `0.1.8` |
| ProductVersion | `0.1.8` |

確認範圍只有檔案 metadata、hash 與 bundle build。沒有執行 installer、沒有 launch App、沒有檢查 installed files、upgrade、restart、uninstall 或 human UX。

這個 unsigned installer 建於已提交的 provider／case bundle／Settings 增量修正之前；尚未重建，因此不能把它當成 `a538778`／`0077b2c` 或最終 branch HEAD 的 binary candidate。

## 過程失敗紀錄

### 命令／測試選擇錯誤

- `npm.cmd test -- --run`：FAIL，因為 package 沒有 `test` script。改跑 `test:frontend` 後取得有效結果。
- desktop 曾用錯 feature 而得到 0-test：此結果作廢；改用 `--features desktop` 後完整測試。
- locale 測試曾顯示 0 filtered target：此結果作廢；修正 selector 後才接受。

### Source regression 修復

- demo export 變更後首次完整 frontend run 有 3 個舊 source-regex assertion 失敗。確認是 expectation 已過時後更新測試；targeted 25/25、full 358/358 PASS。
- HTML 變更曾出現 Rust `E0435`；修正 compile-time/資料綁定後重跑。
- Clippy 最初 10 項，再剩 2 項；全部清除後才以 warnings-as-errors 接受。
- lowercase assertion 曾讓 library 停於 837/838；修正後完整 882/882。
- managed-runtime bootstrap transient access denied 曾讓 library 停於 879/880；修正後先精準回歸，再完整通過。
- ACL startup denial 曾暴露 admission/bootstrap 次序問題；修正後重跑。
- 兩個 ACL propagation 方案因會過度擴大權限而被否決；沒有以放寬安全界線換取綠燈。
- Castle 首輪 Linux Clippy 報 8 項：2 `drop_non_drop`、4 platform-only `unused_mut`、2 Windows-test helper `dead_code`。以 lexical scope／精確 `cfg(windows)` 修正於 `20cf935`，完整 Linux tests、8 個 Unix filters與 Clippy重跑 PASS。
- 本輪第一次非互動 Castle Rust 指令因 PATH 找不到 `cargo`，測試未啟動；確認既有 stable toolchain 是 Rust/Cargo 1.98 後，以既有 `/home/ted-h/.cargo/bin` 重跑。
- Unix refactor 後共用 open-file verifier 只在 Windows 使用，Castle ordinary build先揭露 1 個 `dead_code` warning。以精確 `#[cfg(windows)]` 修正並提交 `0077b2c`，再跑 Windows modules、Castle 14/14 與 Linux Clippy後全綠。

### Delivery／metadata 修復

- 首次 commit 因 repo 未設定 author identity 被 Git 拒絕；只用既有作者設定 repo-local identity，重試成功。
- clone 原 fetch refspec 只追蹤 tag；加入精確 branch refspec 後 upstream 正常。
- 本機 default stable 是 1.97，但 repo 的 `rust-version = "1.98"`；第一次命令在測試開始前被 Cargo 拒絕。改用已安裝的 `cargo +1.98.0` 後完整 Windows suite與 Clippy PASS。先前將文件改成 1.97 是錯誤，現已恢復 1.98。
- Castle 驗證有數次 SSH connect timeout，皆發生在遠端命令開始前；每次都重連、核對 SHA／clean worktree後才執行，不納入測試通過數。

## 未執行測試

- App install／launch／interactive UI。
- Clean Windows VM、standard user、N-1 upgrade、reboot、enterprise ACL。
- 真實 WSL／Podman machine provisioning。
- 真實 localhost target 與真實 engine scan。
- Nuclei 新 immutable image recipe／tag／publication；真實 template-tree test 已 PASS，但 production gate NOT IMPLEMENTED，image build／publication NOT RUN。
- 真實 partial result、cancel、retry、export、signed bundle、recovery、uninstall human journey。
- Screen reader、keyboard-only、mobile viewport 與十分鐘 first-value human study。
- Authenticode signing、updater、GitHub Release download/install path。

## 最終判定

**Automated source/build checkpoint：PASS（限定 automated source/build 範圍）。** Windows desktop 1,347/1,347、CLI 1,340/1,340、Castle CLI 1,307/1,307、兩端 frontend 364/364、release 53/53、usability 5/5、Prowler 8/8、provider Windows desktop／CLI 各 19/19與 Castle 14/14，以及 typecheck、Windows／Castle Vite build、engine、AIDEFEND、Rustfmt、Clippy 均 PASS。整體產品仍是 PARTIAL：新 Nuclei immutable image recipe／publication、installer rebuild、installed/human qualification與 P0 A19 都未完成。

**Installed Windows qualification：NOT RUN。** 不可從本報告推論安裝成功。

**Human UX qualification：NOT RUN。** Source tests 與 demo tests 不等於真人證據。

**Release/signing qualification：NOT READY。** Installer unsigned且早於最新 source；P0 A19 完整 same-version repair 仍未完成。Case bundle scope 已定義為 case-wide records + run-bound reports（含 current case projection caveat），但真實簽章／installed end-to-end qualification未做，也沒有 PR／tag／Release。
