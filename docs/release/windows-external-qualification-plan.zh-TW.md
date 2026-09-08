# 歷史 Windows 證據術語

本文件只解釋舊 Windows 紀錄中可能出現的詞彙，不是目前測試計畫或工作清單。目前產品行為以[產品規格](../product-spec.md)為準。

舊證據系統曾把單一 Windows installer 的自動檢查、operator 觀察與無協助新手觀察分開。`REHEARSAL`、`AUTO-OPERATOR`、`LIFECYCLE`、`BEGINNER`、`SIGNING-VERIFY` 等名稱只描述那些歷史紀錄。

當時把連線到 `127.0.0.1:9001` 當成新手結果，是錯誤的產品決策。它只能表示一個 port 接受、拒絕或逾時，沒有執行任何安全檢查。這項功能只能作為名稱清楚的連線工具，不能放在主要掃描路徑。

舊紀錄中仍有用的安全事實：

- 只能使用使用者明確授權的目標與活動；
- 不停止或重新設定占用 port 的無關程序；
- credentials 不得進入聊天、arguments、logs 或 evidence；
- 分清 operator 協助與新手自行完成的行為；
- 不把 source tests 或 process completion 當成 scanner results；
- destructive cleanup 前重新取得明確確認。

舊紀錄只說明當時實際觀察到的內容。新的產品工作應從目前新手流程、上游 scanner 行為與專業報告開始。
