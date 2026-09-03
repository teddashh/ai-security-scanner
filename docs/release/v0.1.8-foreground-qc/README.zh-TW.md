# v0.1.8 Foreground QC 跨機器交接索引

這個目錄是 GitHub `main` 的跨機器交接入口。原本的
`codex/v0.1.8-foreground-qc` 已在 `1d4054e18b5b8a4014ffd2634ac507fa569e72a7`
完整 fast-forward 進 `main`；分支仍保留作歷史稽核，不再是接手入口。

- `v0.1.8` release-line 基底：`fa1fa9d401995de45080fbfaffc6b39d99955387`
- 原始功能整合：`503542271ff8b2178ed2d334fd47d76c494d1c75`
- Provider／case bundle／Settings 強化：`a538778a34cd7db72b28256591575aee77937ab8`
- Foreground QC 文件 checkpoint／fast-forward point：`1d4054e18b5b8a4014ffd2634ac507fa569e72a7`
- 合併後 CI 修正 code checkpoint：`31f137d03997c221e7c81ba8fc5ae579348b0c14`
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

跨平台完整回歸曾在 Rust 1.98 完成：Windows desktop 1,347/1,347、CLI
1,340/1,340，Castle Linux CLI workspace 1,307/1,307；frontend 364/364，
release evidence 53/53，並有兩平台的 lint、build 與精準安全回歸。合併後另有
GitHub Actions 與最小 feature build 驗證；精確範圍、失敗修正與不可相加的重疊
測試見測試報告。

產品 metadata 仍明確是 `0.1.8`，不是 `0.1.9` 或 `0.1.9.8`。`v0.1.8`
tag 與既有 prerelease artifacts 沒有移動或重建，因此 GitHub `main` 的新 source
不等於已發布一套新 installer。

邊界：P0 A19 same-version repair 仍未完成；現有 unsigned installer 早於最新
source；installed／human／signing qualification 均未執行。Nuclei 只有真實
template-tree targeted test 1/1 PASS，新 production image recipe／publication
未執行。`glib 0.18.5` 的 moderate advisory 仍是 Linux desktop 的已知開放風險，
不能被 `npm audit` 的 0 vulnerabilities 抵銷。

Signed case bundle 是 case-wide records + run-bound reports；reports 選
selected-run observations/evidence，但 legacy presentation、workflow status 與
asset display 有已揭露的 current case projection caveat。
