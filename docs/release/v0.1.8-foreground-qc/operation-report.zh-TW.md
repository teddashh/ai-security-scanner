# AI Security Scanner v0.1.8 前景 QC 作業報告

日期：2026-09-02  
Repository：`teddashh/ai-security-scanner`  
分支：`codex/v0.1.8-foreground-qc`  
基底：`fa1fa9d401995de45080fbfaffc6b39d99955387`（`v0.1.8`）  
功能提交：`503542271ff8b2178ed2d334fd47d76c494d1c75`  
最終分支 HEAD：`e0b21e66883fe214f108834a692d3eb8156be4c2`

- 分支：https://github.com/teddashh/ai-security-scanner/tree/codex/v0.1.8-foreground-qc
- 功能提交：https://github.com/teddashh/ai-security-scanner/commit/503542271ff8b2178ed2d334fd47d76c494d1c75
- 文件更正提交：https://github.com/teddashh/ai-security-scanner/commit/e0b21e66883fe214f108834a692d3eb8156be4c2

## 結論先講

這一輪完成的是「原始碼整合、風險修正、automated regression、unsigned Windows installer build、commit 與 GitHub branch push」。不是正式 release qualification，也不是已安裝的人機驗收。

我沒有安裝、啟動或操作 App，沒有使用 BAT，沒有建立 tag、PR、GitHub Release、updater artifact，也沒有簽章。使用者後來要求先停止操作 App，因此本輪所有 UI/UX 結論都來自程式碼、結構化 fixture、automated tests 與 build，不冒充真人操作證據。

## 實際交付

功能提交包含 74 個檔案，11,778 additions、1,423 deletions。這個數字只描述變更規模，不等於價值；實質推進如下。

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
- 原碰撞檔會保留，新的資料發布到私有 `recovered-<uuid>` artifact；沒有用路徑式粗暴刪除未知內容。
- Findings、preview、export 與 verification 改以明確 case/run/locale coordinates 綁定；stale coordinate fail closed。
- HTML report 增加精確 network scope：address、port、stage、target、transport、outcome、observed time。
- standard redaction 會把 address 與 port 替換成對應的 redacted set，不把原始目標漏進報告。
- Browser demo export 改成誠實的 selected-run JSON only：不再宣稱輸出未實作的 HTML／OCSF／OSCAL serializer，不宣稱 raw evidence、redaction 或 signature。

### 3. First value、partial truth 與 UI/UX

- 補強 bounded localhost first-value path、partial/no-check truth、cancel race、retry/new-attempt 與 beginner master report。
- partial result 不會被假裝成完整成功；沒有 silent scope reduction。
- 加入 bilingual Settings route/page/navigation、mobile navigation、case/run identity presentation、report locale 與 beginner-first progressive disclosure。
- Settings、Cases、Findings、Progress、Export、Start、Verification 與 AppShell 的資料流與顯示狀態同步更新。
- localhost 同步測試改成有 deadline 與 `recv_timeout`，避免 regression 讓 CI 無限掛住。

### 4. Release／CI 證據

- 更新 release self-test、release validator、publication artifact 與 Windows fixture evidence。
- 更新 CI change classification，讓新增 release／runtime 路徑不會被漏分類。
- 驗證 engine catalog、line-ending fixtures、release policy、AIDEFEND snapshot 與 usability evidence schema。
- 成功建立 unsigned NSIS installer，並複製到使用者輸出目錄；未安裝、未啟動。

## Git 與 GitHub 結果

- 功能 commit：`503542271ff8b2178ed2d334fd47d76c494d1c75`
- 文件準確性更正 commit：`e0b21e66883fe214f108834a692d3eb8156be4c2`
- 遠端：`origin/codex/v0.1.8-foreground-qc`
- 本地 HEAD 與 `git ls-remote` 遠端 HEAD 都是 `e0b21e66883fe214f108834a692d3eb8156be4c2`
- upstream 已設定為 `origin/codex/v0.1.8-foreground-qc`
- push 後工作樹乾淨。
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
- repo handover 原寫 Rust 1.98.0，但最終可重現輸出是 rustc/cargo 1.97.0；另做純文件 commit 更正，沒有掩蓋差異。

## 「水分」稽核

### 有實質證據的部分

- Rust desktop、CLI、integration、frontend、release evidence、CI classification、typecheck、Clippy、Vite build 與 unsigned NSIS build 都有實際成功結果。
- GitHub remote SHA 可由 `git ls-remote` 對上本地 SHA。
- Installer 的 size、hash、version、signature status 已直接讀取。
- 安全與資料保留方向有 code path、fixture 與 regression tests，不只改文案。

### 不能拿來灌水的部分

- 11,778 additions 不代表 11,778 行價值；其中含測試、fixtures、CSS、型別、文件與既有邏輯重整。
- Rust 測試數來自多個 feature/build target，彼此有重疊，不能把所有數字相加宣稱成一個巨大「總測試數」。
- source-regex UX tests 只證明必要字串／結構仍存在，不代表真人能在十分鐘完成流程。
- demo mode 的通過不證明 native provider、WSL 或真實 engine 能在一台乾淨 Windows 機器完成掃描。
- build 成功不等於 installer 已安裝、啟動、升級、重啟或解除安裝成功。
- usability evidence validator 的 5/5 是 schema/fixture 驗證；validator 明確說沒有 human session，不能當人機研究。
- unsigned installer 不是可推薦給一般使用者的正式 release。

### 實際完成度判斷

- 原始碼與 automated regression：本輪目標已實質推進並達到乾淨 checkpoint。
- P0/P1 產品方向：大部分核心切片已落地，但 A19 尚未完成，因此不能說 canonical spec 全部完成。
- installed Windows qualification：0 次；沒有操作 App。
- human UX qualification：0 個 session。
- signing／publication qualification：未開始。

## 仍未完成與已知風險

1. **A19 同版本 packaged-component 自動修復仍開放。** Running app 沒有獨立、authenticated 的同版本 installer／payload cache；不能從可能已損壞的 resource tree 自我修復。現況是安全降級與誠實 recovery 指引。
2. **Signed case bundle 還不是完全 run-only。** selected-run readable report 已綁定 run，但 bundle 仍可含 case-wide records；不能宣稱整包都是單一 run。
3. Canonical provider artifact 若永久損壞，相同 response 的重試可能累積 recovery artifact；後續需要安全 orphan retention／GC 規則。
4. CLI canonical data-root 首次建立／ACL admission 仍發生在主要 lease 前，存在小型 concurrency surface；後續 runtime mutation 已有 lease。
5. Settings 目前把 `runtimeAvailable === undefined` 與已知 unavailable 顯示得太相近，可再區分「尚未檢查」與「確認不可用」。
6. 新 localhost polling wait 有 2 秒 deadline，但既有測試仍有少數無 timeout 的 `Barrier::wait()`；屬測試韌性風險，不是 runtime 產品路徑。
7. Vite main JS 約 876 kB minified／265 kB gzip，仍有 >500 kB 非阻擋 warning。
8. Unix-only connector regressions 沒在此 Windows host 執行；privilege-dependent Windows symlink branches 可能被 OS skip。
9. Administrators-owned、conditional/object ACE、foreign inheritable-write 的 legacy roots 目前故意 fail closed；尚未做 enterprise policy qualification。
10. 沒有 clean VM、standard-user、N-1 upgrade、restart、WSL、real localhost、real engine、export、uninstall 或 accessibility/mobile human path。
11. Installer 未簽章，未發布為 GitHub Release／updater artifact。

## 建議下一步

1. 在明確非 production 的乾淨 Windows VM，以本報告 SHA-256 對應的 unsigned candidate 做完整 human path，逐步記錄畫面、時間、資料保留與 recovery 結果。
2. A19 必須設計獨立 authenticated same-version repair source、out-of-process exit/repair/relaunch 與 locked/interrupted repair qualification；不要降低 manifest 或 ACL 驗證來假裝修復。
3. 決定 signed case bundle 的產品契約：嚴格 run-scoped，或明確定義為 case-wide bundle 內含 run-scoped report。
4. 另行檢視 GitHub 提示的 moderate vulnerability；先確認 dependency、影響分支與 exploitability，再決定修補。
5. 量測 startup 後再做 frontend code splitting，不把目前 chunk warning臨時升格成與產品價值無關的 gate。

