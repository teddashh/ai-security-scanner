# AI Security Scanner v0.1.9 Windows Operator 交接註記

日期：2026-09-07
Canonical repository：`teddashh/ai-security-scanner`
凍結 source／本輪起始 `main` checkpoint：`5c95572f54220adbd170d9bfb5af3159c56708ef`
Post-release final code checkpoint：`d28f287d78a079828af45f1ee3bbca165ae091ea`
（主要實作：`bd47e26b6c8024eb3461176637d7fce3e8370561`）

## 接手結論

目前已完成「精確 identity 核對、installed CLI doctor、隔離 installed-CLI regression、
一份嚴格 validated unsigned observation、四個 defect families／八個具體 issue 的 source 修正，
以及 Windows qualification tooling／AUTO-OPERATOR contract 強化」。Windows 原生
operator journey 沒有完成：CUA 回報 `apps:[]`，而 `127.0.0.1:9001` 是 BAT 使用中的
SSH tunnel，禁止接觸。沒有 scan、canonical lifecycle row 或 BEGINNER evidence。

`SIGNING-VERIFY` 的 disposition 是 `not-configured`／`NotSigned`，不是 PASS。不得稱
`v0.1.9` 為 stable、signed、recommended 或 beginner-ready。

詳細記錄：

- [作業報告](operation-report.zh-TW.md)
- [測試報告](test-report.zh-TW.md)
- [Windows 外部 qualification 計畫](../windows-external-qualification-plan.zh-TW.md)

## 不可變 candidate identity

| 欄位 | 值 |
| --- | --- |
| Source commit | `5c95572f54220adbd170d9bfb5af3159c56708ef` |
| Installer | `ai-security-scanner_0.1.9_x64-setup.exe` |
| Size | `40,186,968` bytes |
| SHA-256 | `f7b5374fff07fca98af06931b2dc0ebc52abc2b3ac5a70a6602001d03a1a065e` |
| Authenticode | `NotSigned` |
| Immutable release channel | `prerelease` |

Owner 已刻意把 GitHub 的可變 listing 改為 non-prerelease **Latest**。Candidate lock、package
metadata 與發布的 machine-readable metadata 仍是 `prerelease`；release body／textual assets
仍 stale。後續接手者必須把這兩層分開，不可因 Latest badge 或舊文字就宣稱 bytes、channel、
evidence 或 stable eligibility 已改變。

不得移動 tag、覆寫 release asset，或把修正後 source 重建成同一個 `v0.1.9` identity。
Browser 發現的修正要進入新 build／新版本，並以新的 filename、size、SHA-256 與 qualification
重新開始。

## 已保存的安全證據

嚴格 unsigned observation：

- Canonical filename：`unsigned-os-signing-observation-windows-x86_64-nsis.json`
- Size：`815` bytes
- SHA-256：`d42f13ab731c3b8f1f8bd89d267ffa07d2bd86b7aaf9f14d87ba4b1688342d43`
- Validator：PASS
- Outcome：`not-configured`；signature status `NotSigned`

只保留這份 redacted/importable 檔案的 identity；不要把 raw diagnostics、Technical details、
credentials、screenshots 或任意 logs 放入 import root，也不要把檔名改成 passing signing
evidence。

## Installed state checkpoint

### App executable

- Installed executable：`<user-profile>\AppData\Local\ai-security-scanner\ai-security-scanner.exe`
- Version `0.1.9`
- `30,512,128` bytes
- SHA-256 `3e876497e7cb47881ec12e96ce2976b7f5e6ea5ab71da41c1f1a7357587c8c8a`

### Managed-runtime manifest

- Installed manifest：`<user-profile>\AppData\Local\ai-security-scanner\managed-runtime\manifest.json`
- `3,724` bytes
- SHA-256 `a8112473e5d87655e6145ea5f6cff569c872329d2ec14bfb9463078abcb60e3a`
- Frozen expected manifest：exact match

### CLI doctor

- CLI version：`0.1.9`
- manifests：`21/21` release-approved
- invalid checkpoints：`0`
- cleanup obligations：`0`
- compatibility runtime：absent
- managed-local Podman `5.8.2`：available、running
- provider：WSL；preferred：`managed_local`
- legacy CLI data：preserved

`provider: WSL` 是 doctor 的產品欄位，OS optional feature disabled 是另一個環境觀察；不要
把兩者任意改寫成「WSL 已啟用」或「doctor 失敗」。

這是已安裝日常主機的 regression checkpoint，不是 clean-install／lifecycle evidence。

### 隔離 installed-CLI regression

Private probe 使用一次性、隔離的 data directory，沒有碰既有 App data 或 network；其本機
path、內容與 raw logs 未納入 repository。

- `seed-demo`、list、selected、show 成功；
- exact delete plan 已觀察；wrong confirmation exit `1` 且保留 case；exact confirmation 只刪除
  DB／event rows，case count 成為 `0`；artifact plan `exists = false`，external exports 保留；
- HTML：`15,992` bytes，SHA-256
  `98fcc7d7aec6b027b78adfc46e03d785379bdf6b3d88f0922692523f19409f81`，local verify valid；
- canonical beginner/master JSON：`22,339` bytes，SHA-256
  `6c283ad82496060210c427ebe930f2f0ac975f293b61d1e9eb8d8578fc760b2d`，local verify valid；
- duplicate destination exit `1`，HTML hash 未變；
- standard-redaction case bundle：`16,873` bytes，SHA-256
  `767ae0cf9304a88612b8c78f1f187df4f1039aea95aad55061ebb3106e19eecc`，local 與 DB deletion 後
  detached verify 均 valid；`19` entries、`rawArtifactsIncluded = 0`、truthful integrity-only notice。

所有 probe files 都是 private／non-importable，**不可上傳**。沒有開啟 report content 或 raw
evidence，只檢查 metadata／manifest inventory。這是 CLI regression，不是 GUI、lifecycle 或
BEGINNER evidence；`beginner/master` 只是 export 類型名稱。

## 環境與硬 blocker

- Windows 11 Pro `10.0.26200.9168`，x64。
- filtered non-elevated administrator token。
- `HypervisorPresent = true`。
- WSL optional feature disabled；VirtualMachinePlatform enabled。
- 沒有 disposable snapshot／clean lab。
- 已安裝 App 正在執行，但 current Codex CUA 回報 `apps:[]`；沒有改用 PowerShell UI
  automation 冒充原生操作。

Port ownership 的 private observation 確認 `127.0.0.1:9001` 由現有 BAT SSH tunnel 使用，
不是本次 reviewed qualification fixture。公開交接不保存本機 PID、command line、遠端 endpoint
或其他 network topology。

所以 actual Start 會掃描 BAT，明確禁止。不要按 Start、不要 probe port、不要停止 tunnel，
也不要關閉 BAT 來製造可測條件。本輪 scan `0` 次、tunnel stop `0` 次。新納入版本控制的
localhost fixture harness 應維持 fail-closed；在此 production state 的預期實測結果是
`EADDRINUSE`，不是 PASS scan。

完整 port-owner observation 只留在 private diagnostics，不上傳、不匯入，也不複製進公開報告。

## Browser review 與已完成修正

Browser CUA 在 `433px` 已人工檢查中英文 navigation、use-case disclosure、website URL
reject／accept 行為、AI onboarding、partial-results disclosure、master-report export UX 與
two-step deletion semantics；沒有 console warning／error。這只是 dev preview。

Browser review 與 final diff audit 共找到八個具體 issue，歸為四個 families，並已在
post-release source 修正：

1. runtime language switch 現在同步翻譯內建 demo record，同時保留使用者輸入原文；
2. mobile navigation modal 現在鎖住背景 scroll，並在 close／unmount／breakpoint 後精確還原；
3. user-created browser demo case 現在支援 exact-name two-step deletion，且不虛構 evidence folder；
   刪除背景 case 時也保留目前選取的其他 case；
4. public／internal target line 現在於建立前拒絕 URL／port／wildcard／空白假主機／錯誤 CIDR，
   deployed-website URL 衍生的 host 也走同一驗證與 canonicalization，並保留 native
   `CanonicalTarget` 作為最終權威；明確 port `0` 與 percent-encoding 後超過 `2,048` 字元的
   path 也會在表單內得到 field-specific 拒絕。

修正後 automated regression 與最小人工 browser recheck 均已通過；browser-only deletion 的
實際刪除動作未在收尾時重跑，避免未經 action-time confirmation 改動本機 UI 資料，該行為由
frontend／component regression 覆蓋。若要聲稱 installed behavior，仍須新 build 上的原生 App
recheck。

Qualification plan 現已包含擁有人明確授權的 `AUTO-OPERATOR` track：Codex 可自行核對並按下
唯一固定 `127.0.0.1:9001` 的 safe Start，不需再等另一位真人操作。沒有 raw HTML reader 時，
readability check 留為 `not-observed`，已嘗試的 lifecycle row 必須是 `inconclusive` 且使用
`required-observation-unavailable`，其餘安全、獨立的 rows 照常繼續。UAC／secure desktop、
credentials 與 WL-12c 即時 all-data cleanup confirmation 仍不在此授權內。

新 localhost fixture 與 lifecycle validator／schema 綁定 exact script path／digest、固定 Windows
Node runtime identity、loopback endpoint 與 non-overwriting receipt；只有 WL-13 可回報
`reachable`，其他 row 反向禁止。Port owner 不符時 fixture 會 fail closed。

## 已有 automated baseline

- frontend `485/485`；component `145/145`；usability `5/5`；
- engine：`168` byte-stable inputs、`21` records、Prowler `8/8`；
- AIDEFEND `6` records；
- release validate、release self-test、build、desktop check PASS；
- TypeScript typecheck PASS；Rust 1.98 all-targets `1478/1478`；Clippy all-targets `-D warnings` PASS；
- post-release release-evidence `137/137` PASS。

數字不可相加成虛假的獨立測試總數。`137/137` 與四個 defect families 的 fixes 屬 post-release source；
已發布 `v0.1.9` bytes 的改進仍是 `0`，直到新版本 build 並重新 qualification。

第一次 release self-test／desktop check 使用 ambient Rust `1.97` 而失敗；明確設定
`RUSTUP_TOOLCHAIN=1.98.0` 後均 PASS。Self-test 的 tamper／bad-signature／missing-evidence 訊息
是預期負向 fixtures。Production build PASS，但主 JS chunk `984.66 kB`（gzip `300.24 kB`）
超過 Vite `500 kB` warning threshold，留下 code-splitting 技術債。沒有建立新的 installer。

## Process deviation

Delegated read-only audit 在 reminder 前透過 authenticated `gh api` 執行 `18` 次 GET；沒有
downloads、writes、workflow dispatch 或 GitHub mutation。狀態後來以 public surface 重驗，
owner 其後也授權 GitHub access。這項後續授權不回溯消除偏差；請在任何最終總結保留一句
truthful disclosure，不要誇大成 security incident，也不要省略。

## 建議接手順序

1. 從 GitHub `main` 的 final code checkpoint
   `d28f287d78a079828af45f1ee3bbca165ae091ea` 或其後續報告 commit 繼續；不要回到本輪起始
   `5c95572f...`。
2. 若要交付修正，使用新版本與新 immutable identity。不得覆寫 `v0.1.9`。
3. 在 named、resettable disposable Windows lab 執行新 artifact 的 read-only preflight；先證明
   port 未綁定或由 exact reviewed fixture 持有。
4. 依更新後 `AUTO-OPERATOR` contract 連續執行 safe operator lifecycle；沒有 readability reader
   時記錄 row inconclusive，不要停掉其他 safe rows。
5. 分別執行 SIGNING-VERIFY 與 qualifying BEGINNER lane。BEGINNER 開始後
   facilitator 必須 observe-only；operator／agent 操作永遠不能冒充 beginner。
6. 只有 exact installed artifact 的必要 gates 都實際通過，才評估 stable／signed／recommended
   claim。未配置 Authenticode 時，這些 claim 仍被阻擋。

## 不可採取的捷徑

- 不可掃描、probe、停止或重設目前 BAT tunnel。
- 不可用 PowerShell UI automation 補寫不存在的 CUA observation。
- 不可把 browser dev preview 當 Tauri／installed candidate evidence。
- 不可把 doctor `21/21` 當 complete scan 或 lifecycle PASS。
- 不可把 isolated CLI export／delete probe 或 `beginner/master` export 名稱當 BEGINNER evidence。
- 不可上傳 `private-diagnostic` 下的 CLI probe 或 port-owner note。
- 不可把 unsigned `not-configured` observation 改稱 signing PASS。
- 不可把 owner 的 Latest listing 當成 immutable candidate 已變 stable。
- 不可把 source fix 或 `137/137` release-evidence result 歸入未變更的 `v0.1.9` installer。
- 不可建立 BEGINNER passing record；本輪根本沒有 beginner session。

## 最終驗證

| 欄位 | 最終交接值 |
| --- | --- |
| Post-release final code checkpoint | `d28f287d78a079828af45f1ee3bbca165ae091ea`（主要實作：`bd47e26b6c8024eb3461176637d7fce3e8370561`） |
| Branch／remote／clean status | `main`；報告 commit push 後另以 remote ref 與 Castle clean fast-forward 驗證 |
| Frontend／component | `485/485`／`145/145` PASS |
| Release evidence／usability | `137/137`／`5/5` PASS |
| Engine／Prowler／AIDEFEND | `168` byte-stable inputs、`21` records／`8/8`／`6` records，PASS |
| Release validate／self-test／build／desktop check | 全部 PASS（Rust 1.98；build 有 chunk-size warning） |
| Rust 1.98 all-targets／Clippy | `1478/1478` PASS／PASS |
| 四個 defect families／八個具體 issues | FIXED；targeted tests、完整 frontend/component 與最小 browser recheck 通過 |
| New build identity | **NOT BUILT**；沒有新 installer／release asset |
| Windows qualification | **預設仍 NOT QUALIFIED，除非另有 exact-artifact clean-lab evidence** |
