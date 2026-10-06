# Check a fix: a real before-and-after scan · 2026-10-06

[繁體中文](README.zh-TW.md) · [View on the website](https://teddashh.github.io/ai-security-scanner/check-fixes-demo.html)

A small demo project was scanned, fixed and checked again with the desktop app. Unlike the [v0.4.0 sample reports](../../samples/v0.4.0/README.md), these are real scans: the eight tools ran on the folder in the app's local scanning runtime.

| Scan | Problems | English | 繁體中文 |
| --- | --- | --- | --- |
| Scan 1, before the fix | 26 | [scan1-before-fix-en.html](scan1-before-fix-en.html) | [scan1-before-fix-zh-TW.html](scan1-before-fix-zh-TW.html) |
| Scan 2, after the fix | 16 | [scan2-after-fix-en.html](scan2-after-fix-en.html) | [scan2-after-fix-zh-TW.html](scan2-after-fix-zh-TW.html) |

Check fixes compared the two scans: 11 no longer observed, 15 still present (5 of them only moved from line 19 to line 21), 1 new, 0 verification incomplete.

## How these files were made

- **App:** a development build of the desktop app on Linux, made from commit [`054e716`](https://github.com/teddashh/ai-security-scanner/commit/054e716), after v0.4.1. Its scanner images are the same ones v0.4.1 pins. Both scans were started from the app window.
- **Tools:** Checkov 3.3.13, Gitleaks 8.30.1, Grype 0.117.0, KICS 2.1.20, Semgrep 1.174.0, Syft 1.51.0, Trivy 0.74.0 and TruffleHog 3.97.0. Syft lists software packages and reports no problems. All eight completed in both scans.
- **Scan times:** Scan 1 ran from 14:40:26 to 14:53:15 UTC, Scan 2 from 14:55:02 to 15:07:20 UTC, on October 6, 2026.
- **Project:** a small Flask service written for this demo, with five planted problems. The fix commit removed the deploy key, switched to `yaml.safe_load`, upgraded PyYAML from 5.3.1 to 6.0.2, ran the container as a non-root user and turned on Flask debug mode on purpose. The project is not published, because it contains the planted private key. That key was created for this demo and never used anywhere.
- **Reports:** saved with the app's HTML exporter and the `standard` redaction profile (**Hide sensitive identifiers**). The Scan 2 reports were saved again with commit [`520dc5c`](https://github.com/teddashh/ai-security-scanner/commit/520dc5c). That version adds the comparison with Scan 1 at the top. Apart from that section they match the earlier export byte for byte, and the Scan 1 reports are the same with either build. The files are unchanged exports; [SHA256SUMS.txt](SHA256SUMS.txt) lists their hashes.
- **Screenshots:** taken from the app window, then cropped and converted to WebP. Nothing else was edited.

## Not covered

- The deleted key is still in the project's git history. A real key must be revoked or rotated.
- Only the source folder was checked: the service was not run, no container image was built and no website was tested.
- Choosing the fixed folder again before Check fixes is not in v0.4.1. In v0.4.1, Check fixes scans the copy saved when the folder was first chosen.
- v0.4.1 reports do not include the comparison with the earlier scan.
