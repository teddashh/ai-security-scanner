# Managed Gitleaks patch notice

This image builds Gitleaks 8.30.1 from upstream commit
`83d9cd684c87d95d656c1458ef04895a7f1cbd8e` under the MIT License. The
original source archive, license, applied patch, and this build recipe are
included in the image.

The project-owned patch adds the fixed `--no-source-ignore` capability. When
the managed launcher enables it, Gitleaks does not load an ignore file from
its working directory, an explicitly resolved ignore path, or the selected
project. A selected project's `.gitleaksignore` therefore cannot silently
narrow scanner-owned coverage. The file remains part of the selected read-only
snapshot and can still be inspected as ordinary content.

The launcher also fixes the upstream configuration path, ignores inline
`gitleaks:allow` suppression, treats findings as a successful scanner result,
and requires 100% redaction before evidence is accepted.
