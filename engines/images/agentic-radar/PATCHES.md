# Agentic Radar 0.14.1 downstream machine-output exception

Baseline: [splx-ai/agentic-radar@65a7e4bd01e2034c7cb52e9620eeed287688cc53](https://github.com/splx-ai/agentic-radar/tree/65a7e4bd01e2034c7cb52e9620eeed287688cc53), Apache-2.0.
Patch: `docs/research/patches/agentic-radar-0.14.1-machine-json.patch`, SHA-256 `d32c61e4c2134141686e950a3f025c1b521a1f0096e5572c6846b65d0afb9d72`.

The patch serializes the same native parser graph in a versioned envelope, records analyzer diagnostics and the explicit empty state, and bypasses hosted assessment for static JSON export. It changes no parser or detector. The native HTML path keeps its existing defaults. Inventory never becomes a vulnerability finding or a completed security check.

It has not been submitted upstream. A public machine contract and offline mode require upstream agreement on compatibility and maintenance; local issue/PR drafts remain unsent. The owner has authorized this product integration. Retain the exception until a documented upstream static export supplies equivalent schema, framework binding, empty-state and completeness semantics without hosted calls. Re-audit every upstream update; do not automatically rebase it.

Security, licensing and maintenance owner: `teddashh/ai-security-scanner maintainers`.
Reviewed: 2026-10-04. Next review: 2026-11-01.

| Native file | Before SHA-256 | After SHA-256 |
| --- | --- | --- |
| `agentic_radar/analysis/openai_agents/analyze.py` | `9d608a2c18ee308fb3e3322d0a01541310eb63f5027de7eed6d68a9a8aa70cdc` | `8e6b284e2ff65ace79887f2e69c0c3ac318dff6679b7dae369f88338ac7c914c` |
| `agentic_radar/cli.py` | `a9ff61e626b21ba58ea677b15834d0986609c4ba8d5a6ebff593b689c8ada0a2` | `e982af1348d006811bfd8efa1f0d2b521bc7cd0914e1df4f587a53ed2a7c7914` |
| `agentic_radar/graph.py` | `760e6badf7b0d61af20a62a4bf0eb3bac67d04d9d39f1cefdb8aa2ffc5030b0d` | `2928ce0926aa819a589995ada093199fffe1da960f6d4a295d24051eb49f7fa7` |
| `tests/graph_json_export_test.py` | Added file | `980292e25b4b4b66f85fa04dc90964b296c688551446fec96637edbbedfdfdb4` |

The source/archive and sequential patch hashes are bound in `plan.json`. Build the dedicated launcher tests and nine patched native tests, then exercise all five framework selectors and the empty state in the offline image. Preserve incomplete CrewAI diagnostics rather than installing/executing the target framework to suppress them. Also verify read-only mounts, mismatched framework refusal, `.env` isolation and target-code non-execution. Requirements locks admit only hashed binary wheels for Python 3.11, Linux amd64/arm64; build/test packages remain outside the runtime. The image contains the upstream license, patch, locks, this record and Dockerfile.
