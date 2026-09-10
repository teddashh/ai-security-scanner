# Engine maintenance procedure

This procedure keeps each scanner close to its upstream project while preserving safe product operation and one professional report. The machine-readable catalog owns exact artifact facts, [engine-catalog.md](engine-catalog.md) owns the public capability description, and the [product specification](product-spec.md) owns product behavior.

## 1. Default decision: update upstream, not a private detector

For every change, classify it before implementation:

1. **Upstream artifact update:** a new upstream release, source revision, image, plugin, rule/template pack, feed, or vulnerability database. Pin and verify the new upstream closure.
2. **Thin-adapter update:** input serialization, output parsing, resource controls, or authorization/safety enforcement around unchanged upstream detection behavior.
3. **Report-layer update:** shared normalization, localization, deduplication, prioritization, or product-authored guidance after upstream results have been preserved.
4. **Detector behavior change:** a change to what the scanner detects, how it assigns its native severity, or what remediation it emits. This belongs upstream and must not be implemented casually in a wrapper.

Choose an upstream-supported CLI/API/configuration first. If it cannot express the required capability, contribute upstream or select another upstream engine. A downstream detector patch is a narrow, hash-bound exception with a defined removal condition.

## 2. Thin-adapter boundary

An engine wrapper has four responsibilities:

- **Input:** validate and serialize the already-authorized target, artifact, selected upstream profile, and credential reference.
- **Output:** retain raw upstream output and convert its structure into the common schema without changing the finding’s meaning.
- **Resources:** enforce timeout, cancellation, output-size, CPU, memory, disk, process, and cleanup limits.
- **Safety:** enforce exact targets, mounts, provider identity, outbound endpoints, redirects, rate limits, and prohibited operations.

The wrapper must not:

- add private detection rules or reproduce upstream detection logic;
- rewrite upstream severity, title, description, or remediation;
- hide, promote, or suppress findings to make the result look cleaner;
- convert an error, unknown value, inventory record, open port, or empty result into pass/fail security judgment;
- expand the target, provider, port, path, rule, template, or check set beyond the user-authorized input;
- simulate support for an upstream provider or scan mode through an open-ended patch series.

Filtering is allowed only for an explicit safety boundary or an explicitly selected upstream profile. The report must disclose the checks excluded by that boundary; the wrapper must not imply full upstream coverage.

## 3. Common professional report boundary

Wrappers emit evidence, not user-facing prose. The shared normalization/report layer may provide consistent labels and guidance, but it must preserve:

- engine name, upstream version, artifact digest, and rule/template/check identifier;
- original title, severity, message, remediation, locations, and evidence when upstream supplies them;
- whether each displayed severity or recommendation is upstream-provided, deterministically normalized, or product-authored;
- execution status, selected profile, checked scope, excluded scope, and knowledge date.

Localization and concise professional wording may sit beside the preserved upstream fields. They must not silently replace those fields. Deduplication may group equivalent observations, but every contributing engine result remains traceable.

Capability labels use the catalog definitions: connectivity, exposure, vulnerability, configuration, secrets, and inventory. An adapter or report may claim only categories produced by checks that actually completed. Zero matches never means the target is secure.

## 4. Updating an engine

1. Resolve the official upstream tag and full source revision. Update `engines/upstreams.lock.json` and the catalog entry with the exact acquisition source.
2. Record the upstream changelog items relevant to inputs, outputs, detection behavior, rules/data compatibility, resource use, and supported platforms.
3. Review the exact engine, dependencies, image, rules, templates, feed, and database licenses. Update notices, source/source-offer material, and SBOM as required.
4. Pin every build input and base image. Do not use floating tags, runtime plugin downloads, mutable rule sources, shell-expanded targets, or automatic database/feed updates.
5. Prefer an official upstream image by immutable digest. If none is suitable, build pinned upstream source with only the minimum launcher required by section 2.
6. Run representative bounded fixtures through the product adapter. Cover valid and malformed output, unknown fields, empty results, output limits, timeout, cancellation, cleanup, target enforcement, and managed egress where applicable.
7. Compare normalized records to the raw upstream output. Verify that rule IDs, titles, severities, messages, evidence, and remediation were preserved and that report-only additions are labeled.
8. Update the adapter schema/version only when the structural output contract changes. Keep migrations capable of explaining existing cases.
9. Set `knowledge_date` to the newest date genuinely represented by the exact engine/data closure. Set `support_until` to the maintained support window; do not refresh either merely because the application was rebuilt.
10. Update the honest capability and exclusions table if—and only if—the executed upstream profile changed what the product actually checks.

If the product owner separately requests artifact distribution, use the [engine artifact trust reference](release/engine-image-supply-chain.md) to verify the exact architectures, digest, source association, entrypoint, SBOM, notices/source offer, and retrieval claim for that artifact. This is not part of ordinary scanner maintenance.

An engine failure or unavailable artifact remains an explicit per-engine `not_tested`/failed outcome. It must not be replaced by an unpinned artifact, a broader profile, or a fabricated result.

## 5. Downstream patch exception

Before accepting a patch to upstream scanner behavior, record all of the following beside the engine plan:

- the concrete user capability that is otherwise impossible;
- the upstream issue or contribution link, or a written reason contribution is not practical;
- the smallest patch diff and the upstream files/behavior it changes;
- pre-patch and post-patch source hashes and a dedicated behavior fixture;
- security, license, and maintenance ownership;
- the upstream version range to which it applies;
- a removal condition and review date.

Do not stack unrelated behavior into one patch series. Do not add a second downstream feature while the first lacks an upstream or removal plan. A new upstream release triggers a fresh attempt to remove every patch before rebasing it.

The current Prowler Azure static-token and GCP exact-project implementation is such an exception: six hash-bound runtime patches provide behavior that is not native to Prowler 5.39.1. It must remain labeled as the product’s narrow profile, must not be described as general Prowler Azure/GCP coverage, and must not expand without re-evaluating an upstream-supported replacement.

Project launchers that only enforce section 2 boundaries are adapters, not detector forks. Any launcher code that begins deciding whether evidence is vulnerable, changing native severity, or authoring engine-specific remediation has crossed into report or detector logic and must be moved or removed.

## 6. Dates, replacement, and history

`knowledge_date` describes the newest knowledge in the exact engine/rule/template/feed/database closure. `support_until` is the last date maintainers claim support for that closure and is normally no more than 90 days later. Historical cases retain their original engine identity and dates.

An expired but still inspectable artifact remains attributable. New execution must show a stale-knowledge warning or mark the engine unavailable according to product policy. A replacement receives a new revision and immutable digest; it never rewrites an existing case.

Any byte-affecting launcher, Dockerfile, embedded rule/policy, feed, database, or scanner patch change creates a new engine artifact revision. A report-only normalizer change advances the adapter/report version without pretending the upstream engine changed.

If an update cannot meet its source, license, compatibility, safety, or artifact requirements, only that engine’s coverage is unavailable. Preserve completed sibling results and state the exact gap in the report.
