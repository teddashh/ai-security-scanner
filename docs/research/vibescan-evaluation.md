# VibeScan integration decision

Decision: borrow the user-journey ideas, but do not wrap, bundle, execute, or distribute VibeScan.

This static review is pinned to
[`Armur-Ai/vibescan@52efb12fdcd8118c6f0f2b642558b2f335e7bf66`](https://github.com/Armur-Ai/vibescan/tree/52efb12fdcd8118c6f0f2b642558b2f335e7bf66),
whose repository license is MIT. It is recorded as `RESEARCH / NOT_DISTRIBUTED`; it is not an
`ai-security-scanner` engine, installer component, container image, or transitive release
dependency.

## Why it is not shipped

The audited revision does not satisfy this project's execution and evidence boundaries:

- Repository-controlled `.armur.yml` can declare arbitrary plugin commands, which the scanner
  executes directly in whichever environment runs VibeScan and reports as successful even after a
  non-zero exit
  ([configuration and execution path](https://github.com/Armur-Ai/vibescan/blob/52efb12fdcd8118c6f0f2b642558b2f335e7bf66/internal/config/armurconfig.go#L48-L63),
  [error handling](https://github.com/Armur-Ai/vibescan/blob/52efb12fdcd8118c6f0f2b642558b2f335e7bf66/internal/config/armurconfig.go#L110-L143)).
- Several scan paths perform recursive cleanup on supplied paths; the file-scan path also removes
  the selected file's parent directory
  ([directory scan cleanup](https://github.com/Armur-Ai/vibescan/blob/52efb12fdcd8118c6f0f2b642558b2f335e7bf66/internal/tasks/tasks.go#L298-L311),
  [file scan cleanup](https://github.com/Armur-Ai/vibescan/blob/52efb12fdcd8118c6f0f2b642558b2f335e7bf66/internal/tasks/tasks.go#L586-L613)).
- The API deliberately disables authentication when `ARMUR_API_KEY` is empty
  ([authentication middleware](https://github.com/Armur-Ai/vibescan/blob/52efb12fdcd8118c6f0f2b642558b2f335e7bf66/internal/middleware/auth.go#L12-L20)).
- A request-provided webhook URL flows into an unrestricted HTTP client along with scan results.
  Without destination validation, that creates server-side-request-forgery and result-exfiltration
  risk
  ([request input](https://github.com/Armur-Ai/vibescan/blob/52efb12fdcd8118c6f0f2b642558b2f335e7bf66/internal/api/handlers.go#L40-L46),
  [result forwarding](https://github.com/Armur-Ai/vibescan/blob/52efb12fdcd8118c6f0f2b642558b2f335e7bf66/internal/worker/worker.go#L45-L62),
  [delivery path](https://github.com/Armur-Ai/vibescan/blob/52efb12fdcd8118c6f0f2b642558b2f335e7bf66/internal/webhook/webhook.go#L52-L100)).
- Scanner errors can be swallowed or converted into empty result sets. For example, Checkov ignores
  the process error and Trivy returns success after a non-zero exit or parse failure
  ([Checkov adapter](https://github.com/Armur-Ai/vibescan/blob/52efb12fdcd8118c6f0f2b642558b2f335e7bf66/internal/tools/checkov.go#L12-L37),
  [Trivy adapter](https://github.com/Armur-Ai/vibescan/blob/52efb12fdcd8118c6f0f2b642558b2f335e7bf66/internal/tools/trivy.go#L43-L62)).
  Its OWASP report then labels every category without a mapped finding as `pass`, without first
  proving that every relevant scanner completed
  ([OWASP status mapping](https://github.com/Armur-Ai/vibescan/blob/52efb12fdcd8118c6f0f2b642558b2f335e7bf66/internal/compliance/owasp.go#L80-L114)).
- The image recipe uses mutable base tags and installs multiple tools without versions or with
  `@latest`; its example workflow also pulls a mutable `latest` scanner image and tolerates pull
  failure
  ([Dockerfile](https://github.com/Armur-Ai/vibescan/blob/52efb12fdcd8118c6f0f2b642558b2f335e7bf66/Dockerfile#L4-L35),
  [workflow](https://github.com/Armur-Ai/vibescan/blob/52efb12fdcd8118c6f0f2b642558b2f335e7bf66/.github/workflows/armur-scan.yml#L33-L58)).

These observations apply only to the pinned audited revision. They are not a claim about future
VibeScan releases, and this review did not execute VibeScan or contact a scan target.

## What we keep from the product idea

The useful ideas are a plain-language “scan code you wrote or generated with AI” starting point, a
guided one-project flow, visible per-scanner progress, and a common finding envelope. We implement
those concepts independently using the already selected Semgrep, Gitleaks, TruffleHog, Checkov,
KICS, and Trivy engines, with each engine retaining its own pinned artifact, adapter, evidence, and
failure state.

No VibeScan source code is copied by this decision. If a future change copies or adapts code, that
change must separately preserve the MIT notice and record the exact provenance and modifications.
