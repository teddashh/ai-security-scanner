# Gitleaks testdata fixtures

Every value in these files is synthetic. They exist so the managed launcher
can prove scanner-owned policy still finds secrets a target would try to hide.

The fixture is expected to produce **at least one** finding under the pinned
image. A zero-finding result means the scanner or its configuration
regressed, not that the target is clean.

- `fixture.txt`: an inline `gitleaks:allow` directive plus a live synthetic
  generic token (not an AWS documentation or high-entropy cloud key) that the
  shipped configuration must detect without tripping GitHub push protection.
- `.gitleaks.toml`: a target-supplied config must not override ours.
- `.gitleaksignore`: a target-supplied ignore file must not suppress findings.

## Measured

Run on 2026-09-19 against the pinned image
`ghcr.io/teddashh/ai-security-scanner-engine-gitleaks@sha256:5b4538ca17201dba53fed7d5ea49f94cfd7815a4ce2a5b36cac408757ff349aa`,
with this directory mounted read-only at `/workspace`:

| workspace | findings |
| --- | --- |
| this fixture | ≥1: live `api_token` line without `gitleaks:allow` (generic rule); allow-marked `api_key` still counted under `--ignore-gitleaks-allow` |
| the same fixture with the AWS documentation example pair substituted | documentation examples alone are ignored by upstream and cannot prove the scanner |

The control is the point: both documentation-example lines produce nothing,
because upstream's own rule allowlist is documented to ignore them. A fixture
built from those values cannot tell a working scanner from a broken one.
