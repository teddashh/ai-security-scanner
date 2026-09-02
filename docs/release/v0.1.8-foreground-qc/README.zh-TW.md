# v0.1.8 Foreground QC 跨機器交接索引

這個目錄是 branch `codex/v0.1.8-foreground-qc` 的跨機器交接入口。

- 功能提交：`503542271ff8b2178ed2d334fd47d76c494d1c75`
- 跨平台已驗證程式提交：`20cf93516e9d45b83af15222db782c2d22c0c162`
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

跨平台驗證在 Rust 1.98 完成：Windows desktop 及 Clippy PASS；Castle Linux CLI workspace 1,298 passed、8/8 Unix-only filters與 Linux Clippy PASS。Castle frontend/release validators 也全部 PASS。

本分支的產品 metadata 仍是 `0.1.8`。它不是 `0.1.9`，也尚未建立新的 tag 或 GitHub Release。
