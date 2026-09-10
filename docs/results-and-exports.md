# Results and exports

[繁體中文](results-and-exports.zh-TW.md) · [Documentation](README.md)

Results open for terminal runs. Active scans stay in Progress.

## Read the first layer

The asset summary gives every selected asset one state:

| State | Meaning |
| --- | --- |
| Problems found | At least one security finding affects the asset. |
| No problems in completed checks | Security checks completed for the stated scope and returned no findings. |
| Incomplete or failed | Requested security work did not finish; completed sibling results remain in the report. |
| Not tested | No applicable security check completed for the asset. |

Observed services are listed separately and never counted as vulnerabilities.

## Work through priorities

Each priority shows:

- severity and confidence;
- affected asset and location;
- plain-language impact;
- one practical next action;
- rollback and verification guidance when applicable;
- the upstream scanner, rule identifier, evidence, and remediation in technical details.

Unknown severity remains **Unknown** when the upstream scanner supplied no rating.

## Check coverage

Coverage records what was selected, which checks completed, which target dimensions they covered, and which work did not run. A terminal run can contain useful findings and incomplete coverage at the same time.

Connection observations and inventory do not produce a completed security-check state. A later scan can use them to select an applicable vulnerability or service-aware profile.

## Reopen and compare

Cases retain targets, runs, findings, coverage, evidence references, and export history. Reopening a terminal run reconstructs the same report from its saved facts. Verification compares a later compatible run with a completed baseline and labels findings as new, persistent, resolved, or not comparable.

## Export

**Readable HTML** is the primary shareable report. It follows the on-screen order and places report terms and the technical record at the end.

Structured exports serve specialist workflows:

- JSON preserves the product report model;
- OCSF preserves normalized security findings;
- OSCAL and framework reports carry reviewed control references where a mapping exists;
- the case bundle preserves selected case data and referenced evidence according to its export options.

Every export is generated from the same terminal report model. SHA-256 records identify the exact saved files.
