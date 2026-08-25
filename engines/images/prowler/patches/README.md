# Prowler downstream source patches

These patches apply only to Prowler commit
`40ecbd035e5541bf099917c5033cceb8959c4737` (v5.39.1).

They are ai-security-scanner downstream hardening, not native upstream Prowler
capabilities. In particular, upstream at this pin does not provide Azure
`--access-token-auth`, and its GCP project selection lists every accessible
project before filtering requested IDs.

## Patch order and contracts

1. `0001-azure-static-access-token-iam-only.patch`

   - Adds a token-only mode whose sole secret input is `AZURE_ACCESS_TOKEN`.
   - Requires launcher-provided `--access-token-expires-at <UNIX_SECONDS>`.
     The parser, provider, credential constructor, and each token request fail
     closed if expiry is malformed, expired, or more than 3600 seconds away.
   - Uses a non-refreshing `TokenCredential` restricted to the selected Azure
     cloud's single ARM scope. It never instantiates CLI, managed identity,
     service-principal environment, browser, or other default credentials.
   - Skips Microsoft Graph identity discovery.
   - Requires canonical, duplicate-free `--subscription-ids` and exactly
     `--service iam`; subscription resolution uses only individual ARM gets.

2. `0002-gcp-exact-project-lookups.patch`

   - When `project_ids` is non-empty and no organization is selected, resolves
     every requested ID with only
     `projects().get(projectId=<exact>)`.
   - Never lists projects or fabricates requested projects from an ambient
     credential/default project.
   - Treats a missing, unreadable, malformed, mismatched, or non-`ACTIVE`
     requested project as an all-or-nothing failure.

`series` is the authoritative application order. Do not silently rebase these
patches to another Prowler revision; regenerate and re-run the security tests.

## Verification

From this repository:

```console
engines/images/prowler/patches/verify-patches.sh /path/to/prowler
```

The verifier creates an isolated detached worktree at the exact pin, runs
`git apply --check` before each patch, applies them in series, restricts their
changed-file set, runs `git diff --check`, and byte-compiles all touched Python
sources and tests.

To run the upstream targeted tests too, pass a Python executable whose
environment contains Prowler's pinned development dependencies:

```console
PYTHON=/path/to/prowler-venv/bin/python \
  engines/images/prowler/patches/verify-patches.sh /path/to/prowler --pytest
```

The patches add the security regression suites
`tests/providers/azure/azure_access_token_auth_test.py` and
`tests/providers/gcp/gcp_exact_projects_test.py` to the patched tree.

