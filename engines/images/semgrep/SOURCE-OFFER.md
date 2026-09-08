# Semgrep source and upstream rule records

The Semgrep executable is compiled from the LGPL-2.1-or-later source at commit
`a0c13f304151e531c7e7c00838076211a07a790c`. Because GitHub's generated archive
does not include git submodule contents, the build checksum-verifies all 36
gitlink archives in `semgrep-submodules.lock` and creates a complete source
archive. The image carries that archive, the lock, Dockerfile, and deterministic
rule-pack builder under `/usr/share/source`.

The runtime security rule pack is copied without rule rewrites from the pinned
`returntocorp/semgrep-rules` archive at commit
`947bf05744d4c95153173a24879f30b3ba1a65aa`. The builder mechanically includes
rule YAML under `security` and `secrets`, plus `ai/ai-best-practices`, requires
the upstream `security` metadata category, and excludes test fixtures,
non-rule YAML, and Apex rules whose parser is not available in the pinned OSS
engine. The image carries the upstream
README, exact selection metadata, checksum manifest, and unmodified Semgrep
Rules License v1.0 notice under `/usr/share/source` and `/usr/share/licenses`.
That license governs use of the upstream rules and is not replaced by this
project's Apache-2.0 license.

No Semgrep Pro component, registry download, token-driven installer, rule
update, or result upload is used. Runtime scans use the local pack with the OSS
engine, version checks and metrics disabled, and no autofix action.
