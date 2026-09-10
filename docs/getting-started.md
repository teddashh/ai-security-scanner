# Getting started

[繁體中文](getting-started.zh-TW.md) · [Documentation](README.md)

## Install

Download the current installer from [GitHub Releases](https://github.com/teddashh/ai-security-scanner/releases).

| Platform | Recommended package |
| --- | --- |
| Windows x86-64 | NSIS `.exe`; use `.msi` for managed deployment |
| macOS | Universal `.dmg` |
| Linux x86-64 | Debian `.deb` |

Launch **ai-security-scanner** after installation. The app prepares its local scanning runtime when the selected checks need it.

## Choose the first scan

### IT environment

Use this path when repositories, websites, and internal systems belong in one assessment.

1. Add one or more project folders.
2. Add complete `http://` or `https://` website URLs.
3. Add each approved internal system by exact hostname or IP address. The default profile checks ports 22, 23, 25, 80, 443, 445, 3389, 5900, 8080, and 8443. Advanced settings can replace this list with up to 64 exact ports.
4. Review every asset and network boundary.
5. Confirm the displayed network targets and select **Start scan**.

Each scanner receives only its assigned assets. All completed outcomes are combined in one report.

### Website

1. Select **Check a website**.
2. Enter one complete URL.
3. Review the exact origin and select **Start scan**.

This profile covers the displayed `scheme://host:port` origin. See [Scanning scope](scanning-scope.md#website-or-api) for its request behavior.

### Project folder

1. Select **Check a project folder**.
2. Choose the local folder.
3. Review the snapshot boundary and select **Start scan**.

The app scans a bounded read-only snapshot. The original folder is not changed.

## Follow progress

Progress shows the current asset and check, confirmed problem count, completed work, remaining work, elapsed time, and available controls. Tool preparation appears in the same view and continues into the reviewed scan when ready.

**View results** opens when the run reaches a terminal outcome.

## Act on the result

Start with **Problems found** and the highest-priority item. Each priority includes the affected asset, impact, next action, and verification guidance. Check the asset summary for incomplete or untested work, then save the readable HTML report from Export.

The complete report model is described in [Results and exports](results-and-exports.md).

## Continue an assessment

Open **Cases** to reopen a project, review an earlier terminal run, add or remove assets, retry unfinished checks, or compare a later scan with a completed baseline.
