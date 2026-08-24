# Semgrep corresponding source

The managed Semgrep image is compiled only from the LGPL-2.1-or-later source at
commit `a0c13f304151e531c7e7c00838076211a07a790c`. GitHub's generated archive does
not contain git submodule contents, so the build separately checksum-verifies
all 36 exact gitlink archives in `semgrep-submodules.lock` and then creates a
complete source archive. That archive, the submodule lock, this project's
Dockerfile, and rule pack are included in the image under `/usr/share/source`
and `/usr/share/licenses`; the fixed launcher source is available alongside
this Dockerfile in the public `ai-security-scanner` repository.

The image does not copy or redistribute `semgrep/semgrep:1.174.0`, whose
attestation names a different proprietary source revision. No Semgrep Pro
component or token-driven installer is used.

The scanner-owned rules in `rules.yml` are Apache-2.0 under the repository's
license. They are intentionally small, offline, and independently versioned.
