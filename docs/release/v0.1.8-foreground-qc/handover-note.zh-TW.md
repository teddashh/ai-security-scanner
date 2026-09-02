# AI Security Scanner v0.1.8 Foreground QC Handover Note

日期：2026-09-02

## 接手位置

- Repo：`https://github.com/teddashh/ai-security-scanner`
- Branch：`codex/v0.1.8-foreground-qc`
- Base：`fa1fa9d401995de45080fbfaffc6b39d99955387`（tag `v0.1.8`）
- 功能 commit：`503542271ff8b2178ed2d334fd47d76c494d1c75`
- 跨平台已驗證程式 commit：`20cf93516e9d45b83af15222db782c2d22c0c162`
- Upstream：`origin/codex/v0.1.8-foreground-qc`
- 驗證當時狀態：Windows、GitHub、Castle code SHA 一致，兩個 working tree clean；文件更新後請以 GitHub branch HEAD 為準。

GitHub branch：https://github.com/teddashh/ai-security-scanner/tree/codex/v0.1.8-foreground-qc

主要產品整合在 `5035422`；Castle Linux 發現並驗證的跨平台 lint 修正在 `20cf935`。產品 metadata 仍是 0.1.8，沒有新 tag／Release。

Castle checkout：`/home/ted-h/projects/ai-security-scanner`，branch `codex/v0.1.8-foreground-qc`。直接 `git pull --ff-only` 即可接續，不需要 BAT 或此筆電的檔案。

## 本輪邊界

- 沒有使用 BAT。
- 沒有安裝、啟動或操作 App。
- 沒有改使用者 Windows／WSL、部署、cookie、credential 或 session settings。
- 沒有 PR、merge、tag、GitHub Release、stable-channel publication、code signing 或 updater artifact。
- 只建立並保存 unsigned NSIS candidate。

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
  - deterministic canonical collision 不刪原檔；改發布 private recovered artifact。
- `src-tauri/src/case_service.rs`
  - case/run report、exact network rectangles、standard redaction。
- `src/demoExportProjection.ts`、`src/services/scanner.ts`、`src/pages/ExportPage.tsx`
  - browser demo 僅能誠實輸出 selected-run JSON，不得宣稱 raw/redaction/signature/其他 serializer。
- `src/exportRunSelection.ts`、`src/reportLocale.ts`、`src/caseScopedUiState.ts`
  - run/locale/case coordinate selection。

### Primary UX

- `src/App.tsx`、`src/components/AppShell.tsx`
  - route、navigation、mobile behavior。
- `src/pages/SettingsPage.tsx`、`src/settings-page.css`
  - bilingual Settings。
- `src/pages/CasesPage.tsx`、`FindingsPage.tsx`、`ProgressPage.tsx`、`VerificationPage.tsx`
  - explicit case/run identity、partial truth 與 primary path。
- `src/localhostQuickScan.ts`、`src-tauri/src/localhost_quick_scan.rs`
  - bounded first-value behavior 與有 timeout 的 regression synchronization。

## 已知未完成事項

### P1：A19 same-version component repair

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

### Signed case bundle scope

Readable report 已 selected-run scoped，但 bundle 仍可包含 case-wide records。產品必須二選一：

- 讓 bundle 每一項都嚴格 run-only；或
- 明確稱它為 case-wide bundle，內含 selected-run report。

在完成前，不可寫「整個 signed bundle 只含所選 run」。

### 其他非阻擋風險

- 永久損壞的 canonical provider artifact 可能讓相同 response 每次重試都新增 recovery artifact；需要不破壞 chain-of-custody 的 retention／orphan GC。
- CLI canonical root 首次建立／ACL admission 仍在主要 lease 之前，有小型 concurrency surface。
- Settings 對 unknown runtime 與 known unavailable 的顯示仍可更清楚。
- 少數舊測試 `Barrier::wait()` 沒有 deadline。
- Vite main chunk 約 876 kB minified／265 kB gzip。
- 八個 Unix-only artifact／lease／uninstall symlink/hard-link guards 已在 Castle Linux 通過；其他 privilege-dependent、installed-runtime paths 仍需各自環境 qualification。
- Enterprise ACL policy 尚未 qualification；目前對不明 ACE fail closed。
- GitHub push 提示 default branch 有 1 個 moderate vulnerability；尚未評估。

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
npm.cmd run typecheck
npm.cmd run test:frontend
npm.cmd run build
```

Release evidence、classification、engine validation、policy、AIDEFEND、usability schema 與 NSIS bundle 的詳細結果見同目錄的 test report。不要把 desktop 與 CLI 的重疊 Rust suites 相加成虛假的單一總數。

## Installer candidate

路徑：`C:\Users\tedjc\Documents\Codex\2026-08-27\t\outputs\ai-security-scanner_0.1.8_x64-setup-foreground-qc-unsigned.exe`

- SHA-256：`15A74C9EAA9BA0864B03524D7F2B40B1B2C854D6DEA5E8079C81B1C96AAD56B9`
- Size：39,985,091 bytes
- Version：0.1.8
- Signature：NotSigned

此候選只證明 bundle build，沒有 installed qualification。下一位接手者在任何測試前都應先重新核對 SHA-256，而且只能在明確非 production 的 Windows test environment 使用。

## 建議接手順序

1. 先閱讀 `docs/product-spec.md`、`docs/product-audit.md` 與 `docs/release/v0.1.8-foreground-qc-handover.md`。
2. 在乾淨 clone checkout 此 branch，跑上述 automated baseline。
3. 建立 clean Windows VM human-path matrix；保持畫面、時間、hash、standard-user 與 reboot 證據。
4. 優先處理 A19，不要先做 P2 美化掩蓋 recovery 缺口。
5. 決定 signed bundle scope 契約並增加端到端 acceptance test。
6. 另行 triage GitHub moderate vulnerability。
7. 只有安裝、人機、簽章與發行條件都成立後，才建立 PR／release candidate；不要把此 branch 直接稱為 production-ready。
