# v0.1.8 Foreground QC 跨機器交接索引

這個目錄是 branch `codex/v0.1.8-foreground-qc` 的跨機器交接入口。

- 原始功能整合提交：`503542271ff8b2178ed2d334fd47d76c494d1c75`
- Provider／case bundle／Settings 強化提交：`a538778a34cd7db72b28256591575aee77937ab8`
- 最終已驗證程式 checkpoint：`0077b2c5a6df8c758afbb44be5a1c6a9b2202a64`
- GitHub branch：<https://github.com/teddashh/ai-security-scanner/tree/codex/v0.1.8-foreground-qc>

## 文件

- [完整作業報告](operation-report.zh-TW.md)
- [接手說明](handover-note.zh-TW.md)
- [完整測試報告](test-report.zh-TW.md)
- [Repo 內精簡英文 handover](../v0.1.8-foreground-qc-handover.md)

## 在另一台電腦接手

```bash
git clone --branch codex/v0.1.8-foreground-qc --single-branch \
  https://github.com/teddashh/ai-security-scanner.git
cd ai-security-scanner
git rev-parse HEAD
```

請以 GitHub branch HEAD 為準；不要以本機 `outputs` 目錄或 BAT archive 當交接來源。

Castle 已有 checkout：

```bash
ssh castleridge-ai1
cd /home/ted-h/projects/ai-security-scanner
git switch codex/v0.1.8-foreground-qc
git pull --ff-only
```

跨平台驗證在 Rust 1.98 完成：Windows desktop 1,347/1,347、CLI 1,340/1,340 與兩種 all-targets Clippy 全部 PASS；Castle Linux CLI workspace 1,307/1,307、provider artifact module 14/14、Linux all-targets Clippy、frontend 364/364 與 release validators 全部 PASS。

上述 SHA 是程式驗證 checkpoint；本目錄文件本身會形成其後的文件 commit，接手時仍應以 GitHub branch HEAD 為準。

本分支的產品 metadata 仍是 `0.1.8`。它不是 `0.1.9`，也尚未建立新的 tag 或 GitHub Release。

邊界：P0 A19 same-version repair仍未完成；現有 unsigned installer早於最新 source，必須重建；installed／human／signing qualification 均 NOT RUN；Nuclei 只有真實 template-tree targeted test 1/1 PASS，production gate NOT IMPLEMENTED，image build／publication NOT RUN。

Signed case bundle 是 case-wide records + run-bound reports；reports 選 selected-run observations/evidence，但 legacy presentation、workflow status 與 asset display 有已揭露的 current case projection caveat。
