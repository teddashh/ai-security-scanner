# AI Security Scanner v0.1.8 Foreground QC Handover Note

日期：2026-09-02

## 接手位置

- Repo：`https://github.com/teddashh/ai-security-scanner`
- Canonical branch：`main`
- Base：`fa1fa9d401995de45080fbfaffc6b39d99955387`（tag `v0.1.8`）
- 原始功能整合 commit：`503542271ff8b2178ed2d334fd47d76c494d1c75`
- Provider／case bundle／Settings 強化 commit：`a538778a34cd7db72b28256591575aee77937ab8`
- Foreground QC fast-forward point：`1d4054e18b5b8a4014ffd2634ac507fa569e72a7`
- 合併後 CI 修正 code checkpoint：`31f137d03997c221e7c81ba8fc5ae579348b0c14`
- Upstream：`origin/main`
- 狀態：文件提交前的 code checkpoint `31f137d` 曾確認 Windows HEAD、GitHub `origin/main` 與 Castle HEAD一致；文件 commit 之後請以 GitHub `main` HEAD 為準。

GitHub main：https://github.com/teddashh/ai-security-scanner/tree/main

主要產品整合在 `5035422`；provider durability、case-bundle scope、Settings runtime truth 在 `a538778`，Castle 揭露的 Unix unused helper 則以精確 `cfg(windows)` 修正在 `0077b2c`。完整 foreground line 已在 `1d4054e` fast-forward 進 `main`。合併後由 GitHub CI 找到並修正 minimal-feature dependency 與 Windows hosted-runner fixture ownership 問題；gateway publication 也改成手動觸發，保留 immutable-tag guard。產品 metadata 明確仍是 0.1.8，不是 0.1.9／0.1.9.8，也沒有新 tag／Release。

Gateway 邊界要分開看：immutable tag `0.1.8-1` 已由 run `33243068682` 綁定 source `59e34af14f4aa829419ae8cafa9fa352e2e450c2` 與 index digest `sha256:9f0575f58a6329740eca6a042f8c9d44a3af25144fc80946956823924c445725`。`main@1d4054e` 的 run `33695158567` 嘗試同 tag時，guard正確拒絕覆寫，build／publish／evidence／promote均 skipped，既有 tag未被更動。之後 workflow 改成 manual-only；Windows sidecar build/stage PASS 不等於 OCI image publication或qualification。舊 `0.1.8-1` evidence只適用 `59e34af…`，不適用 `1d4054e…`、`31f137d…` 或其後 source。

這批增量程式已 commit、push 並同步到 Castle。GitHub CI 對 `31f137d` 的 ephemeral NSIS compile已 PASS，但 workflow沒有上傳或保存該檔，也未做 hash／sign／publish／install；本機現有 unsigned installer仍早於 `a538778`／`0077b2c`，不可當成最新 source 的 candidate。

Castle checkout：`/home/ted-h/projects/ai-security-scanner`，branch `main`、upstream `origin/main`。直接 `git pull --ff-only` 即可接續，不需要 BAT 或此筆電的檔案。

## 本輪邊界

- 沒有使用 BAT。
- 沒有安裝、啟動或操作 App。
- 沒有改使用者 Windows／WSL、部署、cookie、credential 或 session settings。
- 已依使用者授權把完整 foreground line fast-forward 到 `main`；沒有 PR，也沒有新的 Git tag／GitHub Release、gateway OCI tag/image、stable-channel publication、code signing 或 updater artifact。
- 只保存一個 historical、pre-`a538778` 的 unsigned NSIS candidate；它不是目前 `main` 的 build。

## 核心設計不變量

後續修改請保留以下方向：

- beginner outcome first；localhost first value 的目標仍是十分鐘內得到有用且誠實的結果。
- ambiguous／legacy runtime 要保留；建立隔離 product runtime，不可默默接管或刪除未知 WSL 狀態。
- hard-block 僅用於不可逆、非產品資料的危險操作；可恢復情況應提供 recovery，不應堆 qualification loop。
- partial result 必須有用且如實，不可假裝 complete，不可 silent scope reduction。
- isolation、retention、recovery、disclosure 要同時成立。
- 一個 beginner master report；NIST／ISO／AIDEFEND mapping 不可宣稱 certification。
- report/export 必須以 case/run/locale coordinate 決定資料；stale coordinate fail closed。

## 重要程式區域

### Managed runtime／product data

- `src-tauri/src/managed_runtime.rs`
  - fresh Windows generation 從 1 開始。
  - exact proven deployed generation 0 可重用。
  - ambiguous runtime 保留並隔離。
  - component admission、task-scoped degradation、state journal 與 generation allocation。
- `src-tauri/src/process_lease.rs`
  - product-data lease、lifetime coordination、平台 ACL/mode 行為。
- `src-tauri/src/product_uninstall.rs`
  - staged uninstall、retention 與安全刪除邊界。
- `src-tauri/src/bin/cli.rs`
  - managed status 在隱性 state mutation 前取得 data-directory lease。

### Artifact／report／export

- `src-tauri/src/connectors/artifact.rs`
  - deterministic canonical collision 不刪原檔；使用固定 4 個 recovery slots，matching content 重用同一格，內容不符才依序前進。
  - hardlink、custom/noncanonical authority 的不安全 DACL、identity 等非內容型安全錯誤立即 fail closed；不前進、不覆寫、不嘗試修補。4 格耗盡時回錯且完整保留既有內容。
  - Windows 只在 canonical product root、內容與 pinned handle durability 已證明後做 bounded DACL repair；custom root 的 DACL policy 永遠 verify-only，matching reuse仍使用 write-capable pinned handle 完成 durability sync，但不要求 `WRITE_DAC`。
  - Unix success path包含 file sync、pinned parent-directory sync、identity/mode proof；matching reuse 在 `chmod(0600)` 後再做第二次 file sync。Parent sync 失敗不會 chmod、回成功或前進 recovery slot。
- `src-tauri/src/case_service.rs`
  - case/run report、exact network rectangles、standard redaction。
- `src-tauri/src/export.rs`、`src/demoExportProjection.ts`、`src/services/scanner.ts`、`src/pages/ExportPage.tsx`
  - browser demo 僅能誠實輸出 selected-run JSON，不得宣稱 raw/redaction/signature/其他 serializer。
  - signed case bundle 是 case-wide records 加 run-bound reports；reports 選取所選 run 的 observations/evidence，但 legacy observation 缺 frozen presentation snapshot 時，文案可用目前 canonical finding，workflow status 與 asset display 也可能來自 current case projection。manifest、`case.json`、README 與 UI 皆揭露此限制。
- `src/exportRunSelection.ts`、`src/reportLocale.ts`、`src/caseScopedUiState.ts`
  - run/locale/case coordinate selection。

### Primary UX

- `src/App.tsx`、`src/components/AppShell.tsx`
  - route、navigation、mobile behavior。
- `src/pages/SettingsPage.tsx`、`src/settingsRuntimePresentation.ts`、`src/settings-page.css`
  - bilingual Settings；unknown／尚未檢查與 confirmed unavailable 使用不同 presentation，不再共用同一警告語意。
- `src/pages/CasesPage.tsx`、`FindingsPage.tsx`、`ProgressPage.tsx`、`VerificationPage.tsx`
  - explicit case/run identity、partial truth 與 primary path。
- `src/localhostQuickScan.ts`、`src-tauri/src/localhost_quick_scan.rs`
  - bounded first-value behavior 與有 timeout 的 regression synchronization。

## 已知未完成事項

### P0：A19 same-version component repair

目前 running app 沒有獨立 authenticated 同版本來源。Private installed copy 可以從 verified packaged tree 修復，但 packaged tree 自身若損壞，就沒有可信來源。不要做以下假修復：

- 不要降低 hash／manifest 驗證。
- 不要把同一個可能損壞的 resource tree 當 recovery source。
- 不要自動下載未驗簽 binary。
- 不要為通過測試而刪除 ambiguous WSL 或 case data。

正確方向至少需要：

1. exact same-version signed installer 或 digest-anchored payload，且位於 `$INSTDIR` 之外；
2. Authenticode／publisher／digest verification；
3. App exit 後的 out-of-process repair；
4. repair/relaunch 與 NSIS coordination；
5. 缺檔、tamper、locked file、interrupted repair、standard user、restart 與資料保留的 Windows qualification。

### Case bundle scope 已定義，端到端 qualification 未完成

產品契約已選定為 **case-wide records + run-bound reports**：

- case-wide：assets、grants、coverage、history、findings、workflow、comparisons 與 source files；
- run-bound reports：只選所選 run 的 observations/evidence；legacy 缺 frozen snapshot 的 presentation、workflow status 與 asset display 可能使用 current case projection；
- signed manifest notice、`case.json` 的 scope fields、README 與 Export UI 使用一致 disclosure。

仍未執行真實簽章 bundle 的 installed／human end-to-end path，所以只能說 scope 契約與 automated disclosure 已落地；不可宣稱 signing qualification 完成，也不可寫「整個 bundle 只含所選 run」。

### 其他非阻擋風險

- Provider recovery 已固定最多 4 格並重用 matching slot；4 格被不同內容占滿時會 fail closed。任何後續 GC 仍需保留 chain-of-custody，不能用 GC 當成覆寫安全邊界。
- CLI canonical root 首次建立／ACL admission 仍在主要 lease 之前，有小型 concurrency surface。
- Castle 已用 digest-pinned Go 1.26.0 container 對精確 `nuclei-templates@24858b4…` 執行真實 template-tree targeted test 1/1 PASS；production gate **NOT IMPLEMENTED**，image build／publication **NOT RUN**。下一個 image recipe 必須使用新 immutable tag、獨立 publication evidence，且只發布真正改動的 engine；不得拿既有 `3.11.1-5` digest／attestation 代替新 recipe。
- 少數舊測試 `Barrier::wait()` 沒有 deadline。
- Vite main chunk 877.98 kB minified／265.59 kB gzip。
- Castle provider artifact module 14/14 PASS（含 Unix hardlink、permission 與 durability regressions）；其他 privilege-dependent、installed-runtime paths 仍需各自環境 qualification。
- Unix authority/artifact proof 仍是循序 pathname checks；same-user mutation 可發生在各次依序檢查之間，也可在最後驗證後或 pin 釋放後改變 namespace。Pinned directory fd 只保證 sync 的是已證明目錄，不讓 pathname 操作變成 atomic。完全消除需 dirfd-relative 操作或將 handle 保留到 consumption；在目前 current-user trust boundary 下列為非阻擋殘餘風險。
- Enterprise ACL policy 尚未 qualification；目前對不明 ACE fail closed。
- GitHub Dependabot alert #1 仍開放：Linux desktop graph 的 `glib 0.18.5` 受 `GHSA-wrw7-89jp-8q8g`／`RUSTSEC-2024-0429`（Moderate 6.9）影響。Windows 與 Linux CLI-only graph 不含 `glib`。`gtk 0.18.2` 要求 `glib ^0.18`，因此不能用 lockfile 單獨升到第一個 patched `0.20.0`；短期若要真正 backport，需使用經稽核且固定 revision 的 fork/vendor，長期需 GTK4/Tauri migration。此風險未修復，不以 `npm audit` 結果抵銷。

## 建置與驗證命令

已驗證工具版本：

- Windows：`rustc/cargo 1.98.0`、Node `v24.16.0`、npm `11.13.0`
- Castle Linux：`rustc/cargo 1.98.0`、Node `v24.15.0`、npm `11.12.1`

主要命令：

```powershell
cargo +1.98.0 fmt --all -- --check
cargo +1.98.0 test --locked --package ai-security-scanner --features desktop
cargo +1.98.0 test --locked --workspace --no-default-features --features cli
$env:RUSTFLAGS='-D warnings'
cargo +1.98.0 clippy --locked --package ai-security-scanner --features desktop --all-targets -- -D warnings
cargo +1.98.0 clippy --locked --workspace --no-default-features --features cli --all-targets -- -D warnings
npm.cmd run typecheck
npm.cmd run test:frontend
npm.cmd run build
```

完整跨平台基線：Windows desktop 1,347/1,347、CLI 1,340/1,340；provider artifact desktop／CLI 各 19/19；兩種 all-targets Clippy、Rustfmt 全 PASS。Castle Linux CLI 1,307/1,307、provider artifact 14/14、all-targets Clippy 與 Rustfmt PASS。Windows 與 Castle frontend 都是 364/364，release evidence 53/53、usability schema 5/5、Prowler 8/8；typecheck、Vite build、engine、AIDEFEND、release validation 也 PASS。合併後另在 Windows 重跑 desktop 1,347/1,347、CLI 1,340/1,340、managed-runtime 141/141、frontend 364/364、release self-test、sidecar builds 與 CI contract 23/23。Nuclei 真實 template-tree targeted test 1/1 PASS；production gate NOT IMPLEMENTED，image build／publication NOT RUN。詳細結果見 test report；不同 feature/platform 的重疊 suites 不相加成虛假的獨立總數。

`main@31f137d` 的 GitHub affected-lane CI run [`33697821312`](https://github.com/teddashh/ai-security-scanner/actions/runs/33697821312) 與 CodeQL run [`33697821316`](https://github.com/teddashh/ai-security-scanner/actions/runs/33697821316) 均 SUCCESS。CI 所有 scheduled jobs成功；不相關的 frontend／engine／framework lanes由 classifier明確skipped。CodeQL的 Rust與JavaScript/TypeScript jobs都完成；這不等於聲稱零finding。

## Installer candidate

路徑：`C:\Users\tedjc\Documents\Codex\2026-08-27\t\outputs\ai-security-scanner_0.1.8_x64-setup-foreground-qc-unsigned.exe`

- SHA-256：`15A74C9EAA9BA0864B03524D7F2B40B1B2C854D6DEA5E8079C81B1C96AAD56B9`
- Size：39,985,091 bytes
- Version：0.1.8
- Signature：NotSigned

此候選只證明先前 bundle build，沒有 installed qualification，而且早於 `main` 的最新 source。下一位接手者不可用它驗證最新 source；必須先由最終 `main` HEAD 重建，再核對新 SHA-256，且只能在明確非 production 的 Windows test environment 使用。

## 建議接手順序

1. 先閱讀 `docs/product-spec.md`、`docs/product-audit.md` 與 `docs/release/v0.1.8-foreground-qc-handover.md`。
2. 在乾淨 clone checkout `main`，跑上述 automated baseline。
3. 從最終 `main` HEAD 重建新 installer，再建立 clean Windows VM human-path matrix；保持畫面、時間、hash、standard-user 與 reboot 證據。
4. 優先處理 P0 A19；完整 same-version repair 尚未完成，不要先做 P2 美化掩蓋 recovery 缺口。
5. 依既定 case-wide records + run-bound reports（含 current case projection caveat）契約增加真實簽章 bundle 的端到端 acceptance test。
6. 為下一個 Nuclei image 建立新 immutable tag 與獨立 publication evidence 路徑，再把已在 Castle 實證通過的 template-tree test 放進新 recipe；不可改寫或沿用 `3.11.1-5` 的既有證據。
7. 對 `glib 0.18.5` advisory 決定 audited backport 或 GTK4 migration，不可只改版本字串或忽略 Linux desktop graph。
8. 只有安裝、人機、簽章與發行條件都成立後，才建立 release candidate；不要把目前 `main` 直接稱為 production-ready。
