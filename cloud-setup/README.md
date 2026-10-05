# 掃描結束後，收回 Microsoft 365／AWS 存取權限

可以先啟動清理 script，讓它等指定掃描結束、存下 HTML 報告，再收回這次設定增加的存取權限。報告和案件證據會留下。

以下先說明 Windows 的 Microsoft 365 流程；AWS 請看下方的 [AWS 專用存取與清理](#aws-專用存取與清理)。

這是 PowerShell 輔助流程，尚未接成桌面程式的預設收尾動作。請將本目錄的兩個 Microsoft 365 script 放在一起，並在執行掃描的電腦上使用。script 保持 PowerShell 5.1 相容寫法；本次自動測試使用 PowerShell 7，Windows 5.1 仍需實機驗證。清理時會在 Microsoft 的頁面登入管理員，不會把管理員登入資料交給掃描器。

## 第一次設定

若 Windows 阻擋 script，可以先開啟一個僅本次允許執行 script 的 PowerShell，再執行下面的指令；不需要修改整台電腦的執行原則：

```powershell
powershell -NoProfile -ExecutionPolicy Bypass
```

建議為這次掃描建立專用應用程式：

```powershell
.\cloud-setup\microsoft365-read-only.ps1 -Temporary
```

將畫面上的租用戶 ID 與應用程式 ID 填入桌面程式，或匯入產生的 `ai-security-scanner-microsoft365-setup.json`。另外保存畫面列出的 `ai-security-scanner-microsoft365-cleanup-<識別碼>.json`；它記錄本次新增的項目，沒有密碼或權杖。

不加 `-Temporary` 時，仍會沿用原本的 `ai-security-scanner` 應用程式，並記錄本次增加的設定。如果這次什麼都沒新增，新紀錄也不會撤掉先前的存取；要使用原本建立權限時留下的紀錄。不要讓不同掃描同時共用一份即將撤除的授權。

## 讓它等掃描結束後自動收尾

先在桌面程式開始掃描。用隨桌面程式安裝的 CLI 查出同一資料目錄中的案件與掃描 ID：

```powershell
ai-security-scanner-cli --data-dir "C:\掃描資料" --json case list
ai-security-scanner-cli --data-dir "C:\掃描資料" --json case show CASE_ID
```

將以下值換成剛才的紀錄、案件和掃描。報告路徑請選一個尚未使用的檔名：

```powershell
$cleanup = @{
    ReceiptPath = '.\ai-security-scanner-microsoft365-cleanup-識別碼.json'
    WaitForRun  = $true
    CaseId      = 'CASE_ID'
    RunId       = 'RUN_ID'
    DataDir     = 'C:\掃描資料'
    ReportPath  = 'C:\報告\這次掃描.html'
    CliPath     = 'C:\程式所在目錄\ai-security-scanner-cli.exe'
}
.\cloud-setup\microsoft365-cleanup.ps1 @cleanup
```

登入後保持這個 PowerShell 視窗開啟。等待期間若存取權杖過期，script 會嘗試更新登入；裝置代碼登入所需的更新權杖只保留在這個程序的記憶體裡，清理結束或離開時丟棄，不寫入檔案或交給掃描器。這個等待模式會請求 `offline_access`，更新僅限本次等待期限加上 15 分鐘收尾時間。[Microsoft 裝置代碼登入說明](https://learn.microsoft.com/en-us/entra/identity-platform/v2-oauth2-device-code)。

預設最多等待兩小時，可用 `-WaitMinutes` 調整。完成、失敗或取消的掃描都會收尾；仍在執行、暫停或等待繼續的掃描不會被當成結束。script 會核對指定掃描、匯出結果與報告檔案的雜湊，再撤除權限。若 HTML 匯出失敗，案件中已保存的結果仍會保留，權限仍會撤除，最後明確回報報告尚未匯出。

若 Microsoft 拒絕更新登入、要求重新驗證、網路中斷或程式被關閉，清理可能尚未完成。保留紀錄，重新執行同一指令；必要時重新登入。它會接續處理，並重新確認該次掃描已結束。這不是電腦關機後仍會執行的背景服務。

## Microsoft Graph PowerShell 自己的管理授權

設定時用到的 Graph PowerShell 也可能留下管理授權。`Disconnect-MgGraph` 只結束本機登入，不能當成雲端授權已撤除。

先查看它的授權：

```powershell
.\cloud-setup\microsoft365-cleanup.ps1 -ReceiptPath '.\清理紀錄.json' -ListGraphPowerShellGrants
```

確認要收回的 `GrantId`，再把它加入前面的自動清理指令：

```powershell
$cleanup.GraphPowerShellGrantId = '剛才確認的 GrantId'
.\cloud-setup\microsoft365-cleanup.ps1 @cleanup
```

這會在最後移除該筆授權中的 `Application.ReadWrite.All` 和 `DelegatedPermissionGrant.ReadWrite.All`，保留其他權限；若整筆授權已沒有其他權限，會刪除那筆授權，但不刪除 Microsoft Graph 或 Graph PowerShell 本身。`AppliesTo: Principal` 只代表列出的使用者；`AllPrincipals` 是全租用戶授權，撤除其中的權限會影響其他管理員使用這筆授權的操作。

必須指定確切的 GrantId，因為第一次登入同意授權發生在 script 能讀取既有設定之前，無法可靠分辨哪些 Graph PowerShell 權限早已存在。未指定時會保留並提醒，不會宣稱這部分已清除。已選定的 ID 與授權對象會留在清理紀錄中，供失敗後重試。若 Microsoft 重新建立了不同 ID 的授權，script 會要求核對新 ID，不會直接把它當成原本那筆。其他尚有管理權限的授權也會列出並記錄，保留不等於已撤除。

## 預覽、立即清理與留下的檔案

在指令加上 `-WhatIf` 可先查看撤除計畫；預覽只查一次掃描狀態，不會等到掃描結束。不加 `-WaitForRun` 的新紀錄則會立即清理，適合掃描已停止的情況：

```powershell
.\cloud-setup\microsoft365-cleanup.ps1 -ReceiptPath '.\清理紀錄.json' -WhatIf
.\cloud-setup\microsoft365-cleanup.ps1 -ReceiptPath '.\清理紀錄.json'
```

預覽與列出授權也需要 Microsoft 登入；第一次登入可能要求同意 Graph PowerShell 的管理權限。預覽不會送出清理用的變更要求。若對已完成的紀錄重新執行授權查詢，script 會將它標成需要再檢查，避免新增的管理授權被舊的「已完成」狀態蓋過。一般重跑已完成的清理則不會重新登入。

如果掃描程式已移除、案件狀態無法讀取，且你要立刻收回存取，可明確選擇：

```powershell
.\cloud-setup\microsoft365-cleanup.ps1 -ReceiptPath '.\清理紀錄.json' -RevokeNow
```

這會跳過等待與報告匯出，可能中斷仍在使用這份授權的掃描；既有報告不會被刪除。沒有這個選項，一般重試仍會確認原本指定的掃描已結束。

清理紀錄是撤權依據，請只使用自己保存、沒有被修改過的原始紀錄；不要把來路不明的 JSON 當成清理指令。script 會拒絕缺少原始設定的修改紀錄與不合法的 ID，但不會把未簽署的 JSON 當成可驗證的第三方證明。

清理會保留原有應用程式、原有授權及其他人後來新增的權限。這次建立的應用程式若已被改作其他用途，script 會停下，不會拆掉它。設定與清理共用互斥保護，同一份建立紀錄還在寫入時不會開始拆除。每一項撤除都會向 Microsoft 再確認，刪除結果尚未同步時會短暫重查；未確認的項目保留為待處理，可以重試。若建立要求的回應遺失，又始終查不到對應資源，就需要人工核對，不能把查不到當成從未建立。沒有新用途、仍與本次紀錄一致的連線設定 JSON 也會移除；清理紀錄及其空白 `.lock` 檔會留下，供查核和避免同時清理。

容器與臨時憑證由掃描器原有的本機清理流程處理。這個 script 不會整批刪除容器、雲端資源或電腦暫存目錄，也不會刪掉報告。

舊 script 產生的連線設定 JSON 不是清理紀錄，不能拿來推定資源由哪一次建立。舊的 AWS／Azure／Microsoft 365 殘留仍需核對確切項目，不能按應用程式名稱整批移除。

撤除授權不代表所有既有權杖立刻失效；Microsoft 說明，已發出的存取權杖可能持續有效到原本期限。[Graph 撤除授權說明](https://learn.microsoft.com/en-us/graph/api/oauth2permissiongrant-delete?view=graph-rest-1.0)。應用程式刪除後會進入 Microsoft 的可還原區，通常保留 30 天；本流程不會永久清空該區。[應用程式刪除說明](https://learn.microsoft.com/en-us/graph/api/application-delete?view=graph-rest-1.0)。

## English quick reference

Run `microsoft365-read-only.ps1 -Temporary` to create a separate scan application and a cleanup receipt. Keep both Microsoft 365 scripts together. Start the scan in the installed desktop app, then run `microsoft365-cleanup.ps1` with `-ReceiptPath`, `-WaitForRun`, `-CaseId`, `-RunId`, `-DataDir`, `-ReportPath`, and the installed `-CliPath` as shown above. Keep the PowerShell window open. It waits for that exact run, exports and verifies its HTML report, then removes the recorded setup changes. An export failure does not prevent access cleanup; saved case evidence remains available.

Use `-ListGraphPowerShellGrants` to inspect the helper application's consent. Pass exact `-GraphPowerShellGrantId` values to remove its two setup permissions last. This can also remove pre-existing setup permissions from those explicitly selected grants; tenant-wide grants affect other administrators. Other scopes and grants remain. Preview with `-WhatIf`; signing in can itself require consent even in preview. Without `-WaitForRun`, a new receipt is cleaned immediately. A receipt already bound to a run keeps its completion check on retry.

Cleanup uses only the recorded tenant and resources, preserves reused permissions, verifies provider responses, and keeps incomplete work for retry. Authentication expiry or interruption can require another sign-in. Tokens already issued may remain valid until expiry. The wait flow can renew device-code access with an in-memory refresh token, bounded to this wait plus 15 minutes; Microsoft can still require interactive authentication. Use explicit `-RevokeNow` when you intentionally want to revoke without an available scan status or report export. `-WhatIf` reads status once rather than waiting. Only use your original, unmodified receipts. PowerShell 7 was tested here; Windows PowerShell 5.1 still needs a real-machine run. This is an optional script workflow, not yet the desktop app's default behavior, and does not clean historical AWS/Azure resources without their ownership records.

## AWS 專用存取與清理

AWS 增加了可選用的 `--temporary` 模式。它建立這次掃描專用的 `AISS-…` 權限集，只附加 AWS 的 `SecurityAudit` 政策，並記錄確切的帳號、使用者、資源 ID 與專用標記。原本不加此選項的 `SecurityAudit` 設定方式仍可使用，但屬於長期存取，不會自動撤除。

在管理 IAM Identity Center 的帳號開啟 AWS CloudShell，將 `aws-read-only.sh` 與 `aws-cleanup.py` 放在同一資料夾，再執行：

```bash
bash aws-read-only.sh --temporary --user YOUR_USER_NAME --account 123456789012
```

這個模式需要 Python 3 和已登入的 AWS CLI，適用於一般 AWS 商用區域的組織版 Identity Center。script 不要求或保存密碼、存取金鑰或權杖。將產生的 `ai-security-scanner-aws-setup-識別碼.json` 匯入桌面程式，並保留同次產生的 `ai-security-scanner-aws-cleanup-識別碼.json`。

若掃描在 Windows 上執行，先在桌面程式保存 HTML 報告，再回到原本的 CloudShell，使用畫面列出的清理紀錄：

```bash
python3 aws-cleanup.py cleanup --receipt './ai-security-scanner-aws-cleanup-識別碼.json' --revoke-now --dry-run
python3 aws-cleanup.py cleanup --receipt './ai-security-scanner-aws-cleanup-識別碼.json' --revoke-now
```

第一行預覽，第二行撤除。`--revoke-now` 會立即開始，因此應等掃描停止使用這份授權後再執行。CloudShell 看不到 Windows 上的案件，也不會自動知道 Windows 已經存好報告。

若掃描與清理在同一台 Linux 電腦，且管理員已透過 AWS 官方流程登入，可讓清理程式等待指定掃描、保存報告，再撤權：

```bash
python3 aws-cleanup.py cleanup \
  --receipt './ai-security-scanner-aws-cleanup-識別碼.json' \
  --wait-for-run --case-id CASE_ID --run-id RUN_ID \
  --data-dir '/path/to/scan-data' --report '/path/to/new-report.html' \
  --cli '/path/to/installed/ai-security-scanner-cli'
```

保持視窗開啟。完成、失敗或取消的掃描都可收尾；仍在執行或暫停的掃描不會被當成結束。程式最多等兩小時，核對案件與掃描 ID，保存並驗證 HTML，才撤除專用指派與權限集。HTML 匯出失敗時仍會撤權，保留案件證據，並以退出碼 `2` 回報報告尚未存好。清理未完成則回傳 `1`。

AWS 刪除指派是非同步工作，所以程式會等 AWS 回報完成，再重新查詢指派與權限集，確認已移除。若標記、政策或用途改變，或出現其他帳號／使用者的指派，就停下保留。先前刪除已成功卻又出現的指派也不會被再次刪除。[AWS 指派刪除 API](https://docs.aws.amazon.com/singlesignon/latest/APIReference/API_DeleteAccountAssignment.html)、[權限集刪除 API](https://docs.aws.amazon.com/singlesignon/latest/APIReference/API_DeletePermissionSet.html)。

清理成功後，內容未改變的同次設定檔會移除；報告、清理紀錄及空白鎖定檔會留下。請使用自己保存、未被修改的原始清理紀錄。AWS 登入過期或操作失敗時，保留紀錄重新執行。若建立指派的回應遺失、無法確認請求 ID，或刪除結果不明且指派仍存在，程式會要求人工核對，不會猜測或宣稱已清除。設定與清理的自動測試使用模擬 AWS 回應，本次沒有對真實 AWS 帳號執行這套新流程。

專用角色的工作階段上限設為一小時；撤除指派不代表已發出的工作階段立刻失效。這個 script 不會修改 IAM 角色的信任政策或撤除其他使用者的工作階段。[AWS 工作階段說明](https://docs.aws.amazon.com/singlesignon/latest/userguide/authconcept.html)。

AWS English reference: keep `aws-read-only.sh` and `aws-cleanup.py` together. In CloudShell, use `bash aws-read-only.sh --temporary --user NAME --account ID`, import its unique setup file, and retain the matching receipt. After saving the desktop report, use `python3 aws-cleanup.py cleanup --receipt RECEIPT --revoke-now`; add `--dry-run` to preview. The optional `--wait-for-run` flow requires the installed scanner CLI and its data on the same Linux computer. Cleanup removes only that unchanged dedicated assignment and permission set, verifies AWS completion, and retains reports and receipts. Shared or historical `SecurityAudit` access is preserved. Previously issued sessions can remain valid until expiry. This workflow is optional and has been tested against simulated AWS responses, not a live account.
