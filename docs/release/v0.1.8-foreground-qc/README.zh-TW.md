# v0.1.8 Foreground QC 跨機器交接索引

這個目錄是 GitHub `main` 的跨機器交接入口。原本的
`codex/v0.1.8-foreground-qc` 已在 `1d4054e18b5b8a4014ffd2634ac507fa569e72a7`
完整 fast-forward 進 `main`；分支仍保留作歷史稽核，不再是接手入口。

- `v0.1.8` release-line 基底：`fa1fa9d401995de45080fbfaffc6b39d99955387`
- 原始功能整合：`503542271ff8b2178ed2d334fd47d76c494d1c75`
- Provider／case bundle／Settings 強化：`a538778a34cd7db72b28256591575aee77937ab8`
- Foreground QC 文件 checkpoint／fast-forward point：`1d4054e18b5b8a4014ffd2634ac507fa569e72a7`
- 歷史完整 GitHub affected-lane baseline：`31f137d03997c221e7c81ba8fc5ae579348b0c14`
- CodeQL source remediation：`8ba72315b6d136bdaf89617d95aa06aea0c72e8c`
- Linux Clippy follow-up／目前 source checkpoint：`09ff38e2d7ba8d9b3ca1fcc63faa73d41092dcef`
- Canonical source：<https://github.com/teddashh/ai-security-scanner/tree/main>

## 文件

- [完整作業報告](operation-report.zh-TW.md)
- [接手說明](handover-note.zh-TW.md)
- [完整測試報告](test-report.zh-TW.md)
- [Repo 內精簡英文 handover](../v0.1.8-foreground-qc-handover.md)

## 在另一台電腦接手

```bash
git clone https://github.com/teddashh/ai-security-scanner.git
cd ai-security-scanner
git switch main
git pull --ff-only
git rev-parse HEAD
```

請以 GitHub `main` HEAD 為準；不要以本機 `outputs`、BAT archive 或舊
foreground branch HEAD 當交接來源。

Castle 已有 checkout：

```bash
ssh castleridge-ai1
cd /home/ted-h/projects/ai-security-scanner
git switch main
git pull --ff-only
```

`31f137d` 以前的跨平台完整回歸曾在 Rust 1.98 完成：Windows desktop
1,347/1,347、CLI 1,340/1,340，Castle Linux CLI workspace 1,307/1,307；frontend
364/364、release evidence 53/53，並有兩平台的 lint、build 與精準安全回歸。

之後 `8ba7231` 修補四個 CodeQL-reported high alerts：Linux production
`rust/access-invalid-pointer` 一項，以及 test code 的 `rust/cleartext-logging` 三項。
Linux interface enumeration 改用 target-specific `nix 0.30.1` safe API；Windows
local CLI 1,340/1,340 PASS。`8ba7231` 的 GitHub CI run `33700815872` 隨即在 Linux
Clippy `-D warnings` 找到 `ipv4_from_network_order` 已成 dead code，該 job FAIL 且
CLI test step skipped；`09ff38e` 已把 helper 精確限於 macOS。

Castle 已在 `09ff38e` 完成 target-candidate 10/10、完整 CLI 1,307/1,307、Clippy、
Rustfmt 與 locked Cargo metadata/tree PASS，checkout clean 且與 Windows／GitHub SHA
對齊。GitHub [CI `33701122412`](https://github.com/teddashh/ai-security-scanner/actions/runs/33701122412)
已 terminal SUCCESS：受影響的 Rust core/CLI 與 Tauri Linux compile jobs 均 PASS，
不相關 lanes 依 classifier 預期 skipped，aggregate job也PASS。
[CodeQL `33701122410`](https://github.com/teddashh/ai-security-scanner/actions/runs/33701122410)
也已對 Rust 與 JavaScript/TypeScript terminal SUCCESS。`8ba7231` 的 [CodeQL `33700815840`](https://github.com/teddashh/ai-security-scanner/actions/runs/33700815840)
則已完成 Rust與JavaScript/TypeScript analysis並SUCCESS；GitHub API目前是0個open
code-scanning alerts，#2／#4／#5／#7均由新分析在`2026-09-03T00:54:32Z`
判定fixed，沒有人工dismissal。精確範圍、失敗修正與不可相加的重疊測試見測試報告。
`31f137d` 仍是完整 GitHub affected-lane 歷史基線；`09ff38e` 是範圍較窄的安全修正
affected-lane follow-up。

產品 metadata 仍明確是 `0.1.8`，不是 `0.1.9` 或 `0.1.9.8`。`v0.1.8`
tag 與既有 prerelease artifacts 沒有移動或重建，因此 GitHub `main` 的新 source
不等於已發布一套新 installer。

邊界：P0 A19 same-version repair 仍未完成；現有 unsigned installer 早於最新
source；installed／human／signing qualification 均未執行。Nuclei 只有真實
template-tree targeted test 1/1 PASS，新 production image recipe／publication
未執行。`glib 0.18.5` 的 moderate advisory 仍是 Linux desktop 的已知開放風險，
不能被 `npm audit` 的 0 vulnerabilities 抵銷；新增的 Linux-only `nix 0.30.1`
只取代 unsafe interface traversal，並沒有修補或取代 `glib`。

Signed case bundle 是 case-wide records + run-bound reports；reports 選
selected-run observations/evidence，但 legacy presentation、workflow status 與
asset display 有已揭露的 current case projection caveat。
