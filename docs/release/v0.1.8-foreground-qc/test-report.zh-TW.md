# AI Security Scanner v0.1.8 Foreground QC 測試報告

日期：2026-09-02  
測試對象功能 commit：`503542271ff8b2178ed2d334fd47d76c494d1c75`  
最終 branch HEAD：`e0b21e66883fe214f108834a692d3eb8156be4c2`  
平台：Windows 11 Professional，x86_64-pc-windows-msvc  
Rust：rustc/cargo 1.97.0  
Node：v24.16.0  
npm：11.13.0

## 測試範圍與限制

本報告涵蓋 source、unit/integration、fixture、typecheck、lint、frontend build、release evidence、engine metadata validation 與 unsigned installer build。

本輪沒有安裝、啟動或操作 App，沒有 BAT，沒有 clean VM／human session／real engine scan。因此「PASS」只代表對應 automated command 或 artifact check 成功，不能外推成 production qualification。

## 最終測試矩陣

| 類別 | 命令／證據 | 最終結果 | 說明 |
|---|---|---:|---|
| Rust format | `cargo fmt --all -- --check` | PASS | 最終 source format clean |
| Desktop Rust | `cargo test --locked --package ai-security-scanner --features desktop` | PASS | 詳細 binary/suite 如下 |
| CLI/workspace Rust | `cargo test --locked --workspace --no-default-features --features cli` | PASS | 與 desktop 有重疊，不合併灌總數 |
| Clippy | desktop、all targets、`-D warnings`，且 `RUSTFLAGS=-D warnings` | PASS | 最終 0 warning/error |
| TypeScript | `npm.cmd run typecheck` | PASS | TypeScript typecheck 通過 |
| Frontend tests | `npm.cmd run test:frontend` | 358/358 PASS | 修正 3 個過時 assertion 後完整通過 |
| Frontend build | `npm.cmd run build` | PASS | Vite 8.2.2，92 modules |
| Release evidence | release evidence tests | 53/53 PASS | fixture/evidence regression |
| CI classification | classification tests | 22/22 PASS | change routing regression |
| Engine validation | catalog／line endings／Prowler | PASS | 167 inputs、21 records、19 runnable、8 Prowler tests |
| Release policy | policy validator | PASS | automated policy checks |
| AIDEFEND | snapshot validator | PASS | 6 records；captured snapshot ref `e10c…` |
| Usability evidence | evidence schema tests | 5/5 PASS | 明確沒有 human session |
| Windows bundle | unsigned NSIS build | PASS | Build only；未安裝／未啟動 |
| Staged diff | `git diff --cached --check`（commit 前） | PASS | 74 檔，無 whitespace blocker |
| Remote integrity | local SHA vs `git ls-remote` | PASS | final HEAD 都是 `e0b21e6…` |

## Desktop Rust 詳細結果

`cargo test --locked --package ai-security-scanner --features desktop`：

- library：882 passed
- adapter fixtures：18 passed
- connector fixtures：14 passed
- discovery coverage：11 passed
- engine execution：354 passed
- job manager：21 passed
- local lifecycle：2 passed
- source authorization：14 passed
- workspace snapshot：18 passed
- doctests：3 passed

這些是不同 test binary／suite 的個別結果。報告不把它們與 CLI build 重疊測試相加成單一行銷數字。

## CLI／workspace 詳細結果

`cargo test --locked --workspace --no-default-features --features cli`：

- library：842 passed
- CLI binary：33 passed
- 共用 integration suites 與 doctests：PASS

Desktop 與 CLI feature set 會重編並重跑部分共同邏輯，所以「882 + 842」不是獨立測試總數。

## Frontend 與 build 詳細結果

- Typecheck：PASS。
- Frontend tests：358/358 PASS。
- Vite：8.2.2，92 modules。
- CSS：約 107.60 kB，gzip 約 19.69 kB。
- Main JS：約 876.24–876.26 kB，gzip 約 264.96–264.97 kB。
- Vite 仍顯示 >500 kB chunk warning；非本輪 blocking gate，但要在量測 startup 後安排 code splitting。

Frontend tests 包含 presentation helper、case/run identity、demo export projection、navigation、locale、runtime truth reconciliation、primary path source regression 等。後者是 source-level regression，不是 browser human journey。

## 安全與資料完整性重點回歸

### Managed runtime generations

- fresh Windows runtime 會選 generation 1。
- 已精確證明的 deployed generation 0 可重用。
- clean gen1 不會虛構 collision name。
- interrupted init／retry 的 generation advancement 有 regression coverage。

### Provider artifact recovery

- canonical collision mismatch 會保留原檔。
- 新資料發布為 private recovered artifact。
- Windows DACL 與跨平台行為有 regression coverage。
- 沒有以路徑名稱粗暴刪除未知 artifact。

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

### Delivery／metadata 修復

- 首次 commit 因 repo 未設定 author identity 被 Git 拒絕；只用既有作者設定 repo-local identity，重試成功。
- clone 原 fetch refspec 只追蹤 tag；加入精確 branch refspec 後 upstream 正常。
- handover 誤記 Rust 1.98.0；實際 `rustc -Vv`／`cargo -Vv` 是 1.97.0，已以 `e0b21e6` 修正。

## 未執行測試

- App install／launch／interactive UI。
- Clean Windows VM、standard user、N-1 upgrade、reboot、enterprise ACL。
- 真實 WSL／Podman machine provisioning。
- 真實 localhost target 與真實 engine scan。
- 真實 partial result、cancel、retry、export、signed bundle、recovery、uninstall human journey。
- Screen reader、keyboard-only、mobile viewport 與十分鐘 first-value human study。
- Unix-only connector regressions。
- Authenticode signing、updater、GitHub Release download/install path。

## 最終判定

**Automated source/build checkpoint：PASS。** 目前分支適合 foreground review 與下一階段 installed qualification。

**Installed Windows qualification：NOT RUN。** 不可從本報告推論安裝成功。

**Human UX qualification：NOT RUN。** Source tests 與 demo tests 不等於真人證據。

**Release/signing qualification：NOT READY。** Installer unsigned，A19 與 signed bundle scope 尚開放，也沒有 PR／tag／Release。

