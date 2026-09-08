# User-facing honesty audit — historical summary

Status: historical engineering record for `122a5fd..c5c9a41` (2026-09-03 to 2026-09-04)

Current direction comes from the [product specification](product-spec.md), and current gaps come from the [product audit](product-audit.md). This summary does not choose new work, define acceptance, or create version, release, or compliance requirements.

## Why the work mattered

The audit found a recurring product defect: user-facing copy claimed behavior that a different layer did not implement. A beginner cannot detect that mismatch, so a precise false claim is worse than a plainly disclosed limitation.

The durable rule is simple: trace every important promise to the data and execution that make it true, then test the rendered user state. Source text existing somewhere is not proof that the right user saw it.

## Defect families corrected in that work

- Failed or missing runs were presented with completed-looking language.
- Report identity and history sometimes borrowed current-case values instead of the selected run's saved facts.
- Export copy overstated redaction, source attachment, signatures, relationships, or format availability.
- Setup and authorization copy offered actions or outcomes the backend could not provide.
- Scanner output was dropped, flattened, or assigned product-authored severity while appearing upstream-authored.
- English technical prose leaked into the Traditional Chinese first layer.
- Coverage gaps collapsed different causes into one misleading sentence.

The work also added rendered component tests, cross-boundary checks for claims whose truth lives in another layer, and report provenance checks. Exact commit history remains in Git.

## Lasting review method

1. Identify the decision the user will make from a sentence or status.
2. Trace the underlying target, task, scanner output, report record, and export path.
3. Fix the product behavior or replace the claim directly.
4. Render the affected state and assert the decision-relevant outcome.
5. When the change concerns a scan, exercise the real upstream path when practical.

A source regex can support a narrow structural check; it cannot establish that a beginner completed a meaningful scan or understood the report. A large green test count is supporting evidence, not product value.

## Current use

Use this file only for the defect patterns above. Do not resume its old checklist or infer current status from its historical commit range. Review the current code and the current product audit instead.
