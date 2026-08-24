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
5. Keep `control-mappings.schema.json` and the Rust bounded validator aligned.

The framework source links are metadata only. ISO text is not embedded or
redistributed by this project.
