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

## Maintained exception — reviewed 2026-10-03

- Capability: scanner-owned coverage must include a synthetic secret even when
  the selected repository's `.gitleaksignore` suppresses it. Upstream 8.30.1
  loads ignore files from both the configured path and the scan source.
- Upstream reference: [the pinned `Detector` implementation](https://github.com/gitleaks/gitleaks/blob/83d9cd684c87d95d656c1458ef04895a7f1cbd8e/cmd/root.go).
  No upstream contribution has been submitted. Shipping depends on enforcing
  this fixed product policy now; changing the default behavior for upstream's
  interactive CLI users is outside this integration. Recheck for a native
  opt-out before every upstream update and propose that narrow flag upstream
  when contribution work is authorized.
- Smallest change: one optional flag and a guard around the three existing
  ignore-file loading paths in `cmd/root.go`. Rule configuration, detectors,
  matching, native finding identifiers and redaction are unchanged.
- Applicability: only 8.30.1 at
  `83d9cd684c87d95d656c1458ef04895a7f1cbd8e` is reviewed; this is not a claim
  about other versions. `git apply --check` and apply succeed without fuzz.
- `cmd/root.go` before: SHA-256
  `275516f78724a075530898e6354e096f2b33ef78de8856f9a5f1b68b9552d994`.
  After: SHA-256
  `855dd4115726bae1e7921fbf557a993daee419fcc039e4992473a2e4184316d2`.
  Patch SHA-256:
  `9e7e7443fe5b5ee52dfb5ebb458d73fa868c441729e98d98a0453e7dd8cc24a7`.
- Behavior fixture: `testdata/fixture.txt`, `.gitleaksignore` and
  `.gitleaks.toml`; the image workflow runs the managed launcher with a
  read-only snapshot and no network. It requires a native `generic-api-key`
  finding, all `Secret` values `REDACTED`, and no synthetic value in the report.
  `launcher/main_test.go` separately binds fixed policy and rejects raw values.
- Security, license and maintenance owner: `teddashh/ai-security-scanner
  maintainers`, responsible for reviewing scope/redaction, the MIT source and
  patch notice, and patch removal. Source, patch and notice ship in the image.
- Remove when upstream provides a reviewed switch disabling all three
  source-ignore paths, or a documented native invocation proves the same
  fixture without a patch. Review again on the next upstream change or by
  2026-11-01, before the current support boundary of 2026-11-22.
