# v0.1.8 Foreground 測試歷史紀錄

日期：2026-09-02

本文件只保存當時實際執行的測試與觀察。不同平台或 feature set 會重跑相同邏輯，因此數量分開列示，不合併為單一總數。

## 主要結果

| 範圍 | 當時結果 | 說明 |
| --- | ---: | --- |
| Windows desktop Rust | 1,347/1,347 通過 | Rust 1.98 |
| Windows CLI Rust | 1,340/1,340 通過 | 與 desktop 有重疊 |
| Castle Linux CLI workspace | 1,307/1,307 通過 | locked workspace |
| Provider artifact | Windows desktop 19/19、CLI 19/19、Linux 14/14 通過 | 平台間有重疊 |
| Managed runtime targeted | 141/141 通過 | Windows 後續重跑 |
| Frontend | 364/364 通過 | Windows 與 Castle 均有紀錄 |
| Evidence tests | 53/53 通過 | structured evidence fixtures |
| Usability schema | 5/5 通過 | 自動化 schema，不是真人操作 |
| Prowler adapter | 8/8 通過 | adapter regression |
| Nuclei pinned template tree | 1/1 通過 | Castle 真實 template tree targeted test |
| CI contracts | 23/23 通過 | dependency-free Node tests |
| TypeScript、Vite、Rustfmt、Clippy | 通過 | 各自在所列平台執行 |

`31f137d` 的 GitHub affected-lane CI run `33697821312` 完成當時排定的 Rust/CLI、Tauri Linux compile、Windows repair/NSIS compile 與 aggregate jobs；與 Cargo 變更無關的 frontend、engine、framework jobs被 classifier 略過。CodeQL run `33697821316` 完成 Rust 與 JavaScript/TypeScript analysis。

## 後續安全修正結果

- `8ba7231` 在 Windows 重跑 locked CLI：1,340/1,340 通過。這個 Windows run 沒有執行 Linux-only `nix` path。
- `8ba7231` 的 GitHub CI run `33700815872` 在 Linux Clippy 找到 `ipv4_from_network_order` dead code，因此相關 job 失敗，CLI test step沒有執行。
- `09ff38e` 修正平台 scope 後，Castle target-candidate 10/10、Linux CLI 1,307/1,307、Clippy、Rustfmt、Cargo metadata/tree 通過。
- `09ff38e` 的 CI run `33701122412` 完成受影響的 Rust core/CLI、Tauri Linux compile 與 aggregate jobs。
- CodeQL run `33700815840` 與 `33701122410` 完成 Rust 和 JavaScript/TypeScript analysis；GitHub API 當時將 #2、#4、#5、#7 標示為 fixed。

## 被測到的行為

- fresh Windows managed runtime 選擇 generation 1；可證明的既有 generation 0 可重用。
- provider artifact collision、hardlink、permission、file sync、parent sync 與 bounded retry 行為。
- case bundle 的 case-wide records、selected-run observation/evidence 與 projection disclosure。
- Settings 的 unknown 與 unavailable 狀態分離。
- report redaction、run/locale coordinate、partial/no-check truth、取消與重試行為。
- Browser demo export 只宣告並輸出 selected-run JSON。
- Linux interface enumeration 使用 safe API 後可在實際 Linux CLI graph 編譯與測試。

## 當時觀察到的其他事項

- Vite build 有大於 500 kB 的 chunk warning。
- GitHub Dependabot 當時仍列出 Linux desktop `glib 0.18.5` advisory；Windows 與 Linux CLI-only graph 不含該路徑。
- 一個本機 unsigned NSIS 檔案的 SHA-256 為 `15A74C9EAA9BA0864B03524D7F2B40B1B2C854D6DEA5E8079C81B1C96AAD56B9`；它早於後續 source 修正，且沒有被執行。

## 當時未執行的測試

- 沒有 Windows installed-app 或真人新手流程測試。
- 沒有以真實目標完成「輸入目標、執行有意義安全掃描、理解結果」的紀錄。
- 沒有 installer install、upgrade、restart、uninstall 或 standard-user 測試。
- 沒有真實 signed case bundle 的 installed/human journey。
- 沒有 Nuclei production image build 或 publication。
- 沒有 Linux desktop packaging smoke。

這些項目只說明本測試紀錄的範圍，不是產品路線圖或接手清單。
