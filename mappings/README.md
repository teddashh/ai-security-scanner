# Evidence-to-control mappings

`control-mappings.json` is the versioned, checked-in catalog used to add
control references to normalized findings. A reference means only that the
specific source rule is topically related to the named control. It is not a
compliance result, certification statement, control-effectiveness test, or
substitute for expert assessment.

Mappings are deliberately allowlisted by engine and exact source rule. A
bounded prefix is used only for the standardized `CVE-` identifier family.
Unknown rules remain unmapped; the product never guesses a control from a
finding title, severity, or target-controlled text. Inventory and discovery
observations such as Syft, CloudQuery, Naabu, and httpx output are not mapped
as control failures.

When changing the catalog:

1. Verify the source rule against the pinned engine/rule-set revision.
2. Use only official framework coordinates and a project-authored short title.
3. Explain the evidence relationship without claiming implementation or
   compliance.
4. Increment `mapping_version` and add fixture coverage.
5. Set a real `reviewed_at` date and the allowlisted `review_process`, then recalculate
   `provenance.canonical_sha256` over canonical JSON after removing only that digest field.
6. Keep `control-mappings.schema.json` and the Rust bounded validator aligned. Invalid calendar
   dates, a review date before the mapping-version date, or a digest mismatch fail closed.

The framework exporter revalidates every relationship that carries the current catalog identity.
Its coordinate, title, relationship, rationale, evidence engine, and AIDEFEND applicability must
match one exact reviewed entry. A stored historical digest remains an identifier only; without an
authenticated copy of that historical catalog it is reported as unverified and unavailable, never
as an exact mapping.

The framework source links are metadata only. ISO text is not embedded or
redistributed by this project.

## Pinned AIDEFEND selected data

[`vendor/aidefend/1.20260805/selected-controls.json`](vendor/aidefend/1.20260805/selected-controls.json)
is a small, project-maintained metadata selection from AIDEFEND version
`1.20260805`. It is pinned to upstream commit
`e10c1678ee49f03f8fb0c97d446ba3fbc3543655` and the SHA-256 of that commit's
generated `data/data.json`. The adjacent provenance, attribution, and CC BY
4.0 files state the exact source and modifications.

This snapshot is not part of `control-mappings.json` and does not add a
runtime mapping by itself. Its records are reference coordinates and
classification metadata only. They do not show that a defense is implemented
or effective, do not create a pass or failure, and do not establish
certification, endorsement, or compliance. Only selected actionable leaf
controls are present; non-actionable parent families are recorded solely as
parent coordinates.

Validate the checked-in selection and notices offline:

```bash
npm run validate:aidefend
```

During a source-update review, also prove the selection against an independently
obtained copy of the pinned upstream `data/data.json`:

```bash
npm run validate:aidefend -- --source /path/to/data.json
```

The optional source check recomputes the complete file's byte length and
SHA-256 before deriving the selected records. AIDEFEND tool recommendations or
threat mappings are not included and must never be treated as automatic
scanner-to-control mappings.
