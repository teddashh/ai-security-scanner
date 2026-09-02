# AI Security Scanner v0.1.8 前景 QC 作業報告

日期：2026-09-02
Repository：`teddashh/ai-security-scanner`
分支：`codex/v0.1.8-foreground-qc`
基底：`fa1fa9d401995de45080fbfaffc6b39d99955387`（`v0.1.8`）
原始功能整合提交：`503542271ff8b2178ed2d334fd47d76c494d1c75`
Provider／case bundle／Settings 強化提交：`a538778a34cd7db72b28256591575aee77937ab8`
最終已驗證程式 checkpoint：`0077b2c5a6df8c758afbb44be5a1c6a9b2202a64`

- 分支：https://github.com/teddashh/ai-security-scanner/tree/codex/v0.1.8-foreground-qc
- 原始功能整合：https://github.com/teddashh/ai-security-scanner/commit/503542271ff8b2178ed2d334fd47d76c494d1c75
- 本輪主要強化：https://github.com/teddashh/ai-security-scanner/commit/a538778a34cd7db72b28256591575aee77937ab8
- Linux warning 修正：https://github.com/teddashh/ai-security-scanner/commit/0077b2c5a6df8c758afbb44be5a1c6a9b2202a64

## 結論先講

這一輪完成的是「原始碼整合、風險修正、automated regression、unsigned Windows installer build、commit 與 GitHub branch push」。不是正式 release qualification，也不是已安裝的人機驗收。

我沒有安裝、啟動或操作 App，沒有使用 BAT，沒有建立 tag、PR、GitHub Release、updater artifact，也沒有簽章。使用者後來要求先停止操作 App，因此本輪所有 UI/UX 結論都來自程式碼、結構化 fixture、automated tests 與 build，不冒充真人操作證據。

本輪增量程式已 commit、push，並 fast-forward 到 Castle；Windows、GitHub、Castle 的已驗證 code checkpoint 都是 `0077b2c5a6df8c758afbb44be5a1c6a9b2202a64`。現有 unsigned installer 沒有重建，且早於本輪程式 checkpoint，不能代表最新 source。

## 實際交付

原始 `5035422` 功能提交包含 74 個檔案、11,778 additions、1,423 deletions；本輪 `a538778` 另有 8 個檔案、1,642 additions、125 deletions，`0077b2c` 是 1 行平台條件修正。這些數字只描述變更規模，不等於價值；實質推進如下。

### 1. Managed runtime 與資料安全

- 全新 Windows managed runtime 不再預設占用固定 generation 0，而是從隔離的 generation 1 開始配置。
- 已有且能精確證明的 generation 0 部署仍可重用；沒有把舊環境粗暴搬移、刪除或重建。
- ambiguous／legacy WSL runtime 採 append-only generation 選擇，保留不明狀態並建立產品隔離 runtime。
- 加強 product-data root、process lifetime lease、Windows DACL admission、workspace snapshot 與 uninstall staging。
- CLI managed-runtime status 在建立 DB、artifact 或 signing key 等隱性 mutation 前取得 data-directory lease。
- packaged runtime component 不可用時採 task-scoped degradation，避免整個產品永久失效，且仍讓既有 case/report 可讀。
- hard-block 的方向維持在不可逆、非產品資料的危險操作；沒有把一般可恢復情況變成多餘 gate。

### 2. Artifact、evidence 與 report 正確性

- Provider response 的 deterministic canonical artifact 若遭中斷或碰撞，不再永久毒化後續重試。
- 原碰撞檔會保留；recovery 改成固定最多 4 個 deterministic slots，內容完全相符時重用既有 slot，內容不符時才前進到下一格。
- hardlink、custom/noncanonical authority 的不安全 DACL、identity 或其他非內容型安全失敗會立即 fail closed，不會嘗試下一格、修補或覆寫；4 格用盡也只回傳錯誤並保留所有既有 bytes。
- Windows custom root 的 DACL policy 永遠 verify-only；matching reuse 仍以同一 write-capable pinned handle 執行 durability sync，但不要求 `WRITE_DAC`。Canonical product root 也只有在內容、identity 與 sync 都證明後才做 bounded DACL repair，sync 失敗會在修補前停止。
- Unix fresh path 會先 file sync，再驗證 identity/mode、sync pinned parent directory 並重驗；matching reuse 則在 parent sync 後才 `chmod(0600)`，再做第二次 file sync 與最終 proof。Parent sync 失敗不會 chmod、回成功或前進 recovery slot。
- Findings、preview、export 與 verification 改以明確 case/run/locale coordinates 綁定；stale coordinate fail closed。
- HTML report 增加精確 network scope：address、port、stage、target、transport、outcome、observed time。
- standard redaction 會把 address 與 port 替換成對應的 redacted set，不把原始目標漏進報告。
- Browser demo export 改成誠實的 selected-run JSON only：不再宣稱輸出未實作的 HTML／OCSF／OSCAL serializer，不宣稱 raw evidence、redaction 或 signature。
- Signed case bundle 的產品契約是「case-wide records + run-bound reports」；reports 選所選 run 的 observations/evidence，但 legacy observation 缺 frozen presentation snapshot 時可用目前 canonical finding，workflow status 與 asset display 也可能來自 current case projection。signed manifest notice、`case.json`、README 與 Export UI 使用同一份 disclosure，不再暗示整包或全部 report 欄位都是單一 run 的 frozen snapshot。

### 3. First value、partial truth 與 UI/UX

- 補強 bounded localhost first-value path、partial/no-check truth、cancel race、retry/new-attempt 與 beginner master report。
- partial result 不會被假裝成完整成功；沒有 silent scope reduction。
- 加入 bilingual Settings route/page/navigation、mobile navigation、case/run identity presentation、report locale 與 beginner-first progressive disclosure。
- Settings、Cases、Findings、Progress、Export、Start、Verification 與 AppShell 的資料流與顯示狀態同步更新。
- Settings runtime presentation 現在把 unknown／尚未檢查與已確認 unavailable 分成不同狀態、圖示與說明，不再混為同一警告。
- localhost 同步測試改成有 deadline 與 `recv_timeout`，避免 regression 讓 CI 無限掛住。

### 4. Release／CI 證據

- 更新 release self-test、release validator、publication artifact 與 Windows fixture evidence。
- 更新 CI change classification，讓新增 release／runtime 路徑不會被漏分類。
- 驗證 engine catalog、line-ending fixtures、release policy、AIDEFEND snapshot 與 usability evidence schema。
- Castle 已用 digest-pinned Go 1.26.0 container 對精確 pinned template tree 執行 targeted Go test，測試本身 PASS。曾評估把它直接加進 production Dockerfile，但該檔仍綁定既有 immutable `3.11.1-5` digest／attestation；為避免偽造 provenance，這個 recipe 改動已撤回。新 gate 必須配合新 immutable tag 與新 publication evidence 才能交付。
- 成功建立 unsigned NSIS installer，並複製到使用者輸出目錄；未安裝、未啟動。

### 5. Castle 跨機器驗證

- GitHub branch 已在 Castle 的 `/home/ted-h/projects/ai-security-scanner` checkout，沒有依賴此筆電的 `outputs` 或 BAT archive。
- Castle Linux Rust 1.98：完整 CLI workspace 1,307/1,307、provider artifact module 14/14（包含 Unix hardlink/permission/durability regressions）、all-targets Clippy `-D warnings`、Rustfmt與 diff check 全 PASS。
- Castle Node 24.15.0／npm 11.12.1：typecheck、364/364 frontend、93-module Vite build、53/53 release evidence、5/5 usability schema、engine validation 167 inputs／21 records／19 runnable、Prowler 8/8、AIDEFEND 6 records、release validation 全 PASS。一次 build 與一次 final status query 在命令啟動前遇到 SSH timeout；重連後相同 validation command PASS，不算測試 failure。
- Castle `npm ci` audit 36 packages，0 vulnerabilities；這只代表該 lockfile 安裝圖，不抵銷 GitHub 對 default branch 顯示的另一項 moderate vulnerability。
- Windows 端以明確 Rust 1.98 完整重跑 desktop 1,347/1,347（library 892）與 CLI 1,340/1,340（library 852），desktop／CLI all-targets Clippy `-D warnings`、Rustfmt均 PASS。

### 6. 0.1.8 後續增量修正與驗證

- Provider artifact recovery 的 Windows desktop module 19/19、CLI module 19/19，Castle/Linux module 14/14 PASS；不同 feature/platform 的重疊測試不相加成獨立總數。
- Frontend 364/364、release evidence 53/53、usability schema 5/5、Prowler 8/8 PASS。
- Typecheck、Vite build、engine validation 與 AIDEFEND validation PASS。
- Case bundle disclosure 與 Settings unknown／unavailable presentation 已有對應 automated coverage。
- Signed case-bundle targeted regression 1/1 PASS；證明另一 run 的 finding/observation 不進入四種 reports，而 legacy/current projection caveat 與 case-wide records 如實出現。
- Castle Nuclei 真實 template-tree targeted test 1/1 PASS；production gate NOT IMPLEMENTED，image build／publication NOT RUN，三者不混為一談。

## Git 與 GitHub 結果

- 原始功能 commit：`503542271ff8b2178ed2d334fd47d76c494d1c75`
- 本輪主要程式 commit：`a538778a34cd7db72b28256591575aee77937ab8`
- Linux warning 修正 commit：`0077b2c5a6df8c758afbb44be5a1c6a9b2202a64`
- 遠端：`origin/codex/v0.1.8-foreground-qc`
- 程式驗證時 Windows、GitHub 與 Castle code HEAD 都是 `0077b2c5a6df8c758afbb44be5a1c6a9b2202a64`；後續文件 commit 請以 GitHub branch HEAD 為準。
- upstream 已設定為 `origin/codex/v0.1.8-foreground-qc`
- 程式變更已 commit／push；文件 commit 前只有本目錄報告待提交。
- Castle checkout：`/home/ted-h/projects/ai-security-scanner`，同一 branch；程式 checkpoint 驗證時 clean。
- 沒有建立 PR、tag 或 Release，避免把 foreground QC 分支包裝成正式發布。
- GitHub push 回應指出 default branch 現有 1 個 moderate vulnerability；本輪沒有取得其細節、沒有評估是否影響這個分支，也沒有宣稱修復。

## Installer 與供應鏈輸出

輸出檔：`C:\Users\tedjc\Documents\Codex\2026-08-27\t\outputs\ai-security-scanner_0.1.8_x64-setup-foreground-qc-unsigned.exe`

- Size：39,985,091 bytes
- Last write UTC：`2026-09-02T09:24:15.3379353Z`
- SHA-256：`15A74C9EAA9BA0864B03524D7F2B40B1B2C854D6DEA5E8079C81B1C96AAD56B9`
- Authenticode：`NotSigned`
- File version／Product version：`0.1.8`

Packaged managed-runtime evidence：

- `bin/gvproxy.exe`：12,954,624 bytes，SHA-256 `8803CAF895325DC2EA52337FA2C7C835C1F7F115B0BDE71FDB1479D1B3710526`
- `bin/podman.exe`：45,106,176 bytes，SHA-256 `8A956D9BAFB253AF9932FFA1ACF17477235E043131A5D73D963830398C33D837`
- `bin/win-sshproxy.exe`：4,826,112 bytes，SHA-256 `AFA4C0D97787F2A4E6509CFE472E9D2CEB5FCFD41A870E66687AA314909B4D10`
- `manifest.json`：3,724 bytes，SHA-256 `A8112473E5D87655E6145EA5F6CFF569C872329D2EC14BFB9463078ABCB60E3A`
- CycloneDX：`32D2590F4097063A1667F0AC961079785677B8B6038CF4DD14C38B5AA653096B`
- NOTICES：`3F7DB58C47CF777755C9E21F01A2F96F8B4440FAF21E67C19EB92A57DB1FF4B6`
- SPDX：`AAE562377FCE9CC56C5BFE44950571CE39E06228E18FCF202BB5CF532869F467`

## 過程中失敗、修正、再驗證

這些失敗沒有藏掉，也沒有把第一次失敗當成最終結果：

- 一開始誤跑 `npm.cmd test -- --run`，package 沒有 `test` script；改用實際存在的 `test:frontend`。
- demo export 修正後，第一次完整 frontend run 有 3 個舊的 source-regex assertions 失敗；同步更新已過時的期望後，targeted 25/25 與完整 358/358 通過。
- 曾遇到 ACL startup denial；修正 admission／bootstrap 順序後再跑精準與完整套件。
- 曾否決兩個會過度傳播 ACL 的設計，沒有為了讓測試變綠而放寬安全邊界。
- HTML report 變更曾出現 Rust `E0435`；改成正確資料綁定後重跑。
- locale 測試曾出現 0 filter，表示當時沒有真的測到目標；修正 test selection 後才接受結果。
- 曾用錯 desktop feature 造成 0-test；改成 `--features desktop` 並重跑完整 desktop suite。
- Clippy 曾先報 10 項、再剩 2 項；逐項清掉後才以 `-D warnings` 通過。
- library suite 曾在 lowercase assertion 停於 837/838；修正後完整通過。
- managed-runtime bootstrap 曾因 transient access denied 停於 879/880；修正後先跑精準測試，再跑完整 882/882。
- 第一次 commit 因 checkout 沒有 author identity 被 Git 拒絕；只在 repo-local 設定既有作者身份後重試，沒有改 global config。
- push 後此 clone 的 fetch refspec 原本只追蹤 `v0.1.8` tag；加入這一個 branch 的精確 refspec 後 upstream 可正常解析。
- 本機 default stable 一度仍是 Rust 1.97；Cargo 因 `rust-version = "1.98"` 在測試開始前正確拒絕。改用已安裝的 `cargo +1.98.0` 後重跑成功。先前把 handover 改成 1.97 是判讀錯誤，本次已恢復正確需求並留下紀錄。
- Castle 第一次 Linux Clippy 找到 8 個跨平台 lint（2 `drop_non_drop`、4 `unused_mut`、2 `dead_code`）；以 lexical guard lifetime 與精確 `cfg(windows)` 修正，提交為 `20cf935`，重跑 tests／Clippy 後全綠。
- 本輪第一次非互動 Castle Rust 命令因 PATH 找不到 `cargo`，尚未啟動測試；確認既有 stable toolchain 是 Rust/Cargo 1.98 後，以 `/home/ted-h/.cargo/bin` 的既有工具重跑。
- 新的 Unix implementation 讓共用 `verify_provider_artifact_open_file` 只在 Windows 使用；Castle targeted test 先以 ordinary warnings 揭露 `dead_code`。加上精確 `#[cfg(windows)]` 並提交為 `0077b2c` 後，Windows 19/19、Castle 14/14 與 Linux all-targets Clippy 全綠。
- Castle 驗證期間有 SSH connect timeout；都發生在遠端命令啟動前，重連並核對 HEAD/clean worktree 後才重跑，不算測試 PASS 或 FAIL。

## 「水分」稽核

### 有實質證據的部分

- Rust desktop、CLI、integration、frontend、release evidence、CI classification、typecheck、Clippy、Vite build 與 unsigned NSIS build 都有實際成功結果。
- 後續增量有 Windows desktop 1,347/1,347、CLI 1,340/1,340、Castle CLI 1,307/1,307、frontend 364/364、release evidence 53/53、usability schema 5/5、Prowler 8/8，以及 provider Windows desktop／CLI 各 19/19、Castle module 14/14 的實際結果；feature/platform 重疊不相加。
- GitHub remote SHA 可由 `git ls-remote` 對上本地 SHA。
- Installer 的 size、hash、version、signature status 已直接讀取。
- 安全與資料保留方向有 code path、fixture 與 regression tests，不只改文案。

### 不能拿來灌水的部分

- 11,778 additions 不代表 11,778 行價值；其中含測試、fixtures、CSS、型別、文件與既有邏輯重整。
- Rust 測試數來自多個 feature/build target，彼此有重疊，不能把所有數字相加宣稱成一個巨大「總測試數」。
- source-regex UX tests 只證明必要字串／結構仍存在，不代表真人能在十分鐘完成流程。
- demo mode 的通過不證明 native provider、WSL 或真實 engine 能在一台乾淨 Windows 機器完成掃描。
- 先前 unsigned NSIS candidate 的 historical build 成功，不等於最新 source 已重建，也不等於 installer 已安裝、啟動、升級、重啟或解除安裝成功。
- usability evidence validator 的 5/5 是 schema/fixture 驗證；validator 明確說沒有 human session，不能當人機研究。
- unsigned installer 不是可推薦給一般使用者的正式 release。

### 實際完成度判斷

- 原始碼與 automated regression：本輪目標已實質推進並達到乾淨 checkpoint。
- P0/P1 產品方向：大部分核心切片已落地，但 **A19 是 P0，完整 A19 仍未完成**，因此不能說 canonical P0 或 canonical spec 全部完成。
- installed Windows qualification：0 次；沒有操作 App。
- human UX qualification：0 個 session。
- signing／publication qualification：未開始。

## 仍未完成與已知風險

1. **P0 A19 同版本 packaged-component 自動修復仍開放。** Running app 沒有獨立、authenticated 的同版本 installer／payload cache；不能從可能已損壞的 resource tree 自我修復。現況是安全降級與誠實 recovery 指引，不能把局部保護描述成完整 A19。
2. **Signed case bundle scope 契約已定義，但尚未做人機／installed qualification。** Bundle 是 case-wide records + run-bound reports；reports 的 observations/evidence 綁 selected run，但 legacy presentation、workflow status與 asset display 有已揭露的 current case projection caveat。signed manifest、`case.json`、README 與 UI 已同步，但仍沒有真實簽章 bundle 的端到端 human path。
3. Provider recovery 已限制為 4 格且安全失敗 fail closed；4 格皆被不同內容占用時會回傳錯誤。後續若要 GC，仍需不破壞 chain-of-custody 的 retention 規則。
4. Nuclei 真實 pinned-template-tree test 已在 Castle PASS，但 production `3.11.1-5` 仍是舊 immutable recipe。下一版需新 tag、新 attestation／digest 與單 engine publication 路徑後才能把 gate 納入；不可覆寫或冒用 `-5` evidence。
5. CLI canonical data-root 首次建立／ACL admission 仍發生在主要 lease 前，存在小型 concurrency surface；後續 runtime mutation 已有 lease。
6. 新 localhost polling wait 有 2 秒 deadline，但既有測試仍有少數無 timeout 的 `Barrier::wait()`；屬測試韌性風險，不是 runtime 產品路徑。
7. Vite main JS 877.98 kB minified／265.59 kB gzip，仍有 >500 kB 非阻擋 warning。
8. Unix provider artifact module 已在 Castle 執行；但部分 namespace 操作仍是 pathname-relative，same-user mutation 可發生在循序 checks 之間及 final proof／pin 釋放之後。Identity rechecks 可偵測已觀察到的置換，但無法讓 namespace proof 原子化；完全消除需 dirfd-relative 操作或把 handle 保留到 consumption。這是目前 trust boundary 下的非阻擋殘餘風險。
9. Administrators-owned、conditional/object ACE、foreign inheritable-write 的 legacy roots 目前故意 fail closed；尚未做 enterprise policy qualification。
10. 沒有 clean VM、standard-user、N-1 upgrade、restart、WSL、real localhost、real engine、export、uninstall 或 accessibility/mobile human path。
11. Installer 未簽章，未發布為 GitHub Release／updater artifact；現有 installer早於 `a538778`／`0077b2c`，不能代表最新 source。

## 建議下一步

1. 先從最終 branch HEAD 重建新的 unsigned candidate；再於明確非 production 的乾淨 Windows VM 做完整 human path，逐步記錄新 SHA-256、畫面、時間、資料保留與 recovery 結果。不可用本報告列出的舊 installer 驗證最新 source。
2. P0 A19 必須設計獨立 authenticated same-version repair source、out-of-process exit/repair/relaunch 與 locked/interrupted repair qualification；不要降低 manifest 或 ACL 驗證來假裝修復。
3. 以已定義的 case-wide records + run-bound reports（含 current case projection caveat）契約做真實簽章 bundle、manifest 驗證、README／UI disclosure 與 installed human-path acceptance。
4. 為下一個 Nuclei image 設計新 immutable tag 與單 engine publication evidence，再把已通過的真實 template-tree test 納入新 build recipe 並實際建置。
5. 另行檢視 GitHub 提示的 moderate vulnerability；先確認 dependency、影響分支與 exploitability，再決定修補。
6. 量測 startup 後再做 frontend code splitting，不把目前 chunk warning臨時升格成與產品價值無關的 gate。
