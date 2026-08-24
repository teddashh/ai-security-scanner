# Complete corresponding source and notices

The managed ScoutSuite image contains the exact upstream ScoutSuite 5.14.0
source archive at `/usr/share/source/scoutsuite/scoutsuite-5.14.0.tar.gz`.
It corresponds to commit `7909f2fc6186063e5c9e7ddef8c4d7d1072c8f3d` and
to the GPL-2.0-only program in the image.

The same directory contains every scanner-owned build input used to create the
modified JSON-only profile: `scoutsuite-json-only.patch`, `requirements.in`,
the fully hashed `requirements.lock`, `prepare_source.py`, `scout_entry.py`,
the exact Dockerfile, and the complete source of the static cloud launcher.
The public ai-security-scanner repository contains those same files and the
multi-architecture publication workflow.

For the GPL source-request path, open a public issue at
`https://github.com/teddashh/ai-security-scanner`. The source embedded in each
image is the immediate, version-matched offer.
