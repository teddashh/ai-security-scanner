# 確認修復：一次真實的修復前後掃描 · 2026-10-06

[English](README.md) · [在網站閱讀](https://teddashh.github.io/ai-security-scanner/check-fixes-demo.html?lang=zh-TW)

我們用桌面程式掃描一個小型示範專案，修正後再檢查一次。和 [v0.4.0 範例報告](../../samples/v0.4.0/README.zh-TW.md) 不同，這兩次都是真實掃描：八個工具在程式的本機掃描環境中實際檢查了這個資料夾。

| 掃描 | 問題數 | 繁體中文 | English |
| --- | --- | --- | --- |
| 第 1 次掃描（修正前） | 26 | [scan1-before-fix-zh-TW.html](scan1-before-fix-zh-TW.html) | [scan1-before-fix-en.html](scan1-before-fix-en.html) |
| 第 2 次掃描（修正後） | 16 | [scan2-after-fix-zh-TW.html](scan2-after-fix-zh-TW.html) | [scan2-after-fix-en.html](scan2-after-fix-en.html) |

確認修復比較兩次掃描：11 個這次沒有再看到、15 個仍然存在（其中 5 個只是從第 19 行移到第 21 行）、1 個新出現、0 個驗證未完成。

## 製作方式

- **程式：** Linux 上的桌面程式開發版本，以 v0.4.1 之後的 commit [`054e716`](https://github.com/teddashh/ai-security-scanner/commit/054e716) 建置；掃描器映像與 v0.4.1 固定的版本相同。兩次掃描都從程式視窗啟動。
- **工具：** Checkov 3.3.13、Gitleaks 8.30.1、Grype 0.117.0、KICS 2.1.20、Semgrep 1.174.0、Syft 1.51.0、Trivy 0.74.0、TruffleHog 3.97.0。Syft 負責列出軟體套件，不回報問題。兩次掃描中八個工具都已完成。
- **掃描時間：** 2026 年 10 月 6 日，第 1 次 14:40:26 至 14:53:15 UTC，第 2 次 14:55:02 至 15:07:20 UTC。
- **專案：** 為這次示範寫的小型 Flask 服務，刻意放入五種問題。修正的 commit 刪除部署金鑰、改用 `yaml.safe_load`、把 PyYAML 從 5.3.1 升級到 6.0.2、讓容器以非 root 使用者執行，並刻意開啟 Flask 除錯模式。專案本身不公開，因為裡面有刻意放入的私鑰；這把金鑰為示範而產生，從未在任何地方使用。
- **報告：** 用程式的 HTML 匯出功能與 `standard` 遮蔽設定（**遮罩敏感識別資訊**）儲存。第 2 次掃描的報告以 commit [`f02a30d`](https://github.com/teddashh/ai-security-scanner/commit/f02a30d) 重新儲存，這個版本會在報告開頭加上與第 1 次掃描的比較；除了這一段，內容與先前的匯出逐位元組相同，第 1 次掃描的報告用兩個版本匯出也完全相同。檔案未經修改；雜湊值列在 [SHA256SUMS.txt](SHA256SUMS.txt)。
- **截圖：** 從程式視窗擷取，只做裁切並轉成 WebP，沒有其他編輯。

## 沒有涵蓋的部分

- 刪除的金鑰仍留在專案的 git 歷史中；真實的金鑰必須撤銷或更換。
- 這次只檢查原始碼資料夾：沒有執行服務、沒有建置容器映像，也沒有測試網站。
- v0.4.1 沒有「確認修復前重新選擇修正後的資料夾」這一步；v0.4.1 的確認修復掃描的是第一次選擇資料夾時保存的副本。
- v0.4.1 的報告不包含與先前掃描的比較。
