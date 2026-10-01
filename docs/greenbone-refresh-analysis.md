# Greenbone refresh contract and adapter risk analysis

Date of analysis: 2026-09-17

This document records what can change when the managed Greenbone image is
refreshed, which parts of that upstream surface the product consumes, and which
changes can currently degrade a report without stopping the run. It separates
observed facts from recommendations that would change product behavior.

## Evidence and limits

The analysis used these inputs:

- the checked-out 23.50.21 upstream source under
  `.upstreams/greenbone/openvas-scanner-23.50.21`, especially
  `rust/src/models/result.rs` and `rust/src/models/vtdata.rs`;
- the product launcher and its tests under
  `engines/images/greenbone-launcher/`;
- the Rust parser and adapter in `src-tauri/src/adapters/mod.rs`, plus its
  fixture tests;
- the current Dockerfile, image plan, publishing workflow, and catalog
  validator;
- Greenbone's [23.50.22 release](https://github.com/greenbone/openvas-scanner/releases/tag/v23.50.22),
  [23.50.23 release](https://github.com/greenbone/openvas-scanner/releases/tag/v23.50.23),
  and [23.50.24 release](https://github.com/greenbone/openvas-scanner/releases/tag/v23.50.24);
- Greenbone's [official container package history](https://github.com/greenbone/openvas-scanner/pkgs/container/openvas-scanner/versions?filters%5Bversion_type%5D=tagged),
  which associates `stable`, `23.50.24`, and digest
  `sha256:5b950bc273d1d5d123f15dfb7f373b0b3a3b7fb75f67286dfa28e88350a6eb33`;
- Greenbone's [container documentation](https://greenbone.github.io/docs/latest/22.4/container/)
  and [feed-update workflow](https://greenbone.github.io/docs/latest/22.4/container/workflows.html);
- Greenbone's [post-maintenance registry statement](https://forum.greenbone.net/t/missing-tags-in-registry-after-maintenance/22248),
  which says versioned container tags are no longer available;
- the [greenbone-feed-sync configuration](https://github.com/greenbone/greenbone-feed-sync),
  which documents the independently updated NASL and Notus feed trees and the
  current `24.10` feed release; and
- the Greenbone documentation's [scanner and Notus architecture](https://greenbone.github.io/docs/latest/background).

The owner-side measurement record at `/tmp/greenbone-evidence.json` was
captured on 2026-09-17 by pulling and inspecting the actual upstream images and
querying the GitHub API. It establishes these exact inputs:

| Input and rolling tag | Index digest | linux/amd64 | linux/arm64 | Measured content identity |
| --- | --- | --- | --- | --- |
| `openvas-scanner:stable` | `sha256:5b950bc273d1d5d123f15dfb7f373b0b3a3b7fb75f67286dfa28e88350a6eb33` | `sha256:34efa73adac52dd105804964c8b132a13a72f6ec6bc0ac9fe180d8ec7097c98e` | `sha256:8db0bf29310e170b1bd0e0e78a6ffbca37dcf5d248a9bfb3ef683121fdc583ad` | scanner revision `26465a11ff0e6a98d60a253265fab5974fc757b6`, GitHub tag `v23.50.24` |
| `vulnerability-tests:community` | `sha256:d0010b7d8e24e7df8086b85af9fabe64335dccf9a7e1fd4c7774b4712bd061cd` | `sha256:41adc684254909e87fa15f6362bfacab5228a8ed7ce8266b6e50dc02d7be0d2d` | `sha256:47247fcafa211a3bfc26a7719e7fd8c47ae1831f10fa952e53c10322e0893ac1` | `PLUGIN_SET=202609170605`, `FEED_COMMIT=6c8dce2f22bb9e5da081667994be6e9ed79484d8` |
| `notus-data:community` | `sha256:78c6a1198a3effd5a7df22acab826719744dbd16dded5208c6614761386002bc` | `sha256:5d285f56d4a17198b187299311f5b6b2b7333df37d33354b9514013e3ae295b7` | `sha256:a2b8390368544b953b1ae0de4d7f7fb0565137e726a9da81d60577acb5b6c0f7` | timestamp `202609170538`; tar SHA-256 `b178bdea9d3326f352a4dc6a07708ea0a121df1d049630f9b1665e4c1dc1515d` |

The local sandbox still could not open a container runtime or resolve
`github.com` from the terminal. It therefore did not repeat those image
measurements. Its attempted download of the scanner archive failed before any
file was created, so this analysis does not claim a locally re-derived archive
SHA-256. The [Fossies archive index](https://fossies.org/linux/misc/openvas/openvas-scanner-23.50.24.tar.gz/)
corroborates the exact GitHub `v23.50.24` tag archive as
`af8b1e0175dfc57f38bdecc08607dbac294459e684e2f3e7d69c85101fa13517`;
the Dockerfile checksum-locks that archive, and the supplied GitHub API evidence
binds the tag to the measured scanner revision.

## What varies in a refresh

### Scanner program and API

The scanner version, source commit, container manifest, transitive runtime,
and API behavior can move independently of the feed. For this refresh,
Greenbone's package history establishes that `stable` points to 23.50.24 at the
digest above. The release record identifies source commit
`26465a11ff0e6a98d60a253265fab5974fc757b6`.

Even a patch update can change behavior relevant to this adapter. Between
23.50.21 and 23.50.24 the release notes record compact port-list transmission,
Boreas `AliveTest` integration, a packet-capture race fix, namespace
resolution, and registry transport behavior. The product currently sends an
explicit port list and `alive_test_methods`, so those are not merely packaging
details.

The 23.50.21 result model serializes these JSON members: `id`, `type`,
`ip_address`, `hostname`, `oid`, `port`, `protocol`, `message`, and optional
`detail`; `detail` contains `name`, `value`, and `source`, whose members are
`type`, `name`, and `description`. Its result-type enum serializes as
`alarm`, `log`, `error`, `host_start`, `host_end`, `dead_host`, and
`host_detail`. A later source version can add a variant or rename a member.
Whether 23.50.24 changed this exact model could not be established from a local
23.50.24 checkout because the archive could not be fetched.

The scan-status vocabulary is another contract. The launcher recognizes
`stored`, `requested`, `running`, `succeeded`, `failed`, and `stopped`.
Unknown or missing states already stop the run.

### VT feed snapshot

The VT image is a content snapshot, not a scanner release. At minimum these can
change on every snapshot:

- `PLUGIN_SET` (the `yyyymmddhhmm` feed timestamp), `FEED_COMMIT`, signatures,
  and the image manifest;
- the set of NASL files and NVT OIDs;
- an NVT's name, filename, family, ACT/category, dependency filenames,
  deprecation flag, and references;
- summary and solution text;
- CVSS base/severity vectors and quality-of-detection type; and
- the behavior of the NASL program itself, including whether it emits an
  alarm, log, error, host record, or no result for a target.

Greenbone describes the community feed as continuously/daily updated. Its
container workflow explicitly treats pulling the data images and loading their
contents as separate update steps. Consequently a successful scanner version
pin says nothing about the exact VT snapshot.

This refresh moves the scanner from 23.50.21 to 23.50.24 and the feed from
`202608240615` to `202609170605`, a 24-day interval. Detection coverage changes
with that feed replacement. The available measurements do not establish the
scale of that coverage change.

NVT OIDs are stable identifiers only for entries that remain in the snapshot;
entries can be added, deprecated, or removed. This product derives most of its
remote-safe profile from the current feed, but its TCP-scanner dependency and
managed smoke test use fixed OIDs. Removal or renaming of those fixed entries
is therefore a loud build/smoke compatibility event. Changes among dynamically
selected OIDs can change scan coverage without changing product code.

### Notus data

The Notus image contains a separately updated advisory/product data set.
Greenbone documents Notus as comparing discovered installed software with
OS-specific vulnerability lists. The managed profile sets
`table_driven_lsc=no`, supplies no credentials, and excludes local-security-
check families, so the current external profile is not expected to exercise
authenticated package comparison. That conclusion is an inference from this
product's request construction, not proof that the mounted Notus data can never
affect openvasd startup or behavior. Its digest, advisory/product content,
signatures, and content revision must therefore remain independently recorded.

### Severity, result type, and remediation vocabulary

Greenbone's result type and severity are different dimensions:

- `alarm` is the vulnerability verdict. It can be rated or unrated.
- `log` is an observation and is not a finding.
- `error` and `dead_host` represent incomplete evaluation.
- host lifecycle/detail records are scanner bookkeeping.
- a rated alarm carries a numeric CVSS base score in this product's XML;
  an alarm whose vector is absent or unsupported remains an alarm with severity
  `0.0` and threat `Unknown`. It is not converted to a log.

The launcher's threat words are product projections (`Critical`, `High`,
`Medium`, `Low`, `Unknown`, and `Log`) derived from the alarm and numeric score.
They are not used by the Rust adapter to override a present `result_type`.

The checked-out upstream tag vocabulary includes both scalar `solution` and a
separate `solution_type` with `Mitigation`, `NoneAvailable`, `VendorFix`,
`WillNotFix`, and `Workaround`. The launcher binds only `tag.solution` and
emits it as scalar XML text. It does not bind or preserve `solution_type`,
`impact`, `insight`, `affected`, or `vuldetect`. Thus the adapter's remediation
shape is currently one optional text field; a feed change from scalar
`tag.solution` to a nested object would fail JSON decoding, while a rename or
removal would quietly produce empty remediation.

The checked-out upstream QoD vocabulary has fifteen values. The launcher has
explicit numeric cases for only `exploit`, `remote_vul`, `remote_active`,
`package`, `remote_banner`, and `remote_banner_unreliable`; every other value,
including a future unknown value, currently becomes `50`. Upstream itself maps
the known values across 1, 30, 50, 70, 80, 95, 97, 98, 99, and 100. Correcting
this would change reported confidence and is therefore a product decision, not
safe refresh maintenance.

The launcher scores `CVSS:3.*` vectors and falls back to the legacy CVSS v2
shape. A CVSS v4 vector or malformed vector yields an unrated alarm, which is
fail-safe for finding visibility but silently loses the upstream rating.

## Exact dependencies in our code

### Launcher input and feed contract

The launcher decodes the following feed metadata fields:

| JSON field | Use | Missing/unrecognized behavior |
| --- | --- | --- |
| `oid` | feed index, rule identity, closure checks | Missing/invalid fails feed load. Duplicate fails. |
| `name` | finding/NVT title | Missing/unsafe fails feed load. |
| `filename` | dependency resolution and fixed TCP-scanner binding | Missing/unsafe/duplicate fails feed load. |
| `category` | dynamic selection and category allowlist | Missing/unknown entries are omitted from dynamic selection; an emitted result for a prohibited/unknown category fails. Partial loss can therefore be silent. |
| `family` | exclusion by literal family names and report tag | Missing/new wording can bypass a family exclusion and silently change coverage. |
| `dependencies` | transitive NVT closure by filename | Missing becomes empty; an unknown referenced filename fails closure validation. |
| `references[].class`, `references[].id` | valid CVE references | Missing/unknown classes are silently omitted. |
| `tag.deprecated` | dynamic-profile exclusion | Missing becomes `false`, so a schema rename can silently include deprecated tests. |
| `tag.severity_vector`, `tag.cvss_base_vector` | numeric severity | Missing/unsupported leaves an alarm visible but unrated/Unknown. |
| `tag.qod_type` | numeric QoD/confidence | Missing or unrecognized becomes `50`; this is a silent semantic substitution. |
| `tag.summary`, `tag.solution` | scanner detail and remediation | Missing becomes empty text without a warning. |

Unknown JSON fields are ignored by Go. That supports additive upstream schemas,
but it cannot distinguish an intentionally absent optional field from a field
that was renamed.

The request sent to openvasd binds `target.hosts`, `target.ports[].protocol`,
`target.ports[].range[].start/end`, `credentials`, `alive_test_methods`,
`reverse_lookup_unify`, `reverse_lookup_only`, `scan_preferences[].id/value`,
and `vts[].oid`. A server-side rename should normally make request creation or
scan execution fail, but accepting-and-ignoring a renamed preference remains an
upstream risk.

The launcher accepts results as either a top-level array or an object with an
exact `items` member. It reads all result fields listed in the prior section.
`hostname` and `detail` are decoded but not used. `message` is retained only as
target-controlled raw XML evidence; it is deliberately not presented as
remediation. An alarm must have a valid exact-feed OID in the permitted closure
and a TCP relay port in the authorized closure. `error` and `dead_host` may be
OID-less so the adapter can disclose incomplete evaluation. Recognized
OID-less lifecycle/log records are omitted.

The launcher emits these XML fields for the Rust adapter: result `id`, `name`,
`host`, `port`, `result_type`, `severity`, `threat`, `asset_id`, `summary`,
`description`, `solution`, `qod/value`, NVT `oid`, `name`, `family`, and CVE
`ref` attributes `type`/`id`. It additionally emits `raw_host`, `raw_port`,
`relay_mapping`, and `scope_grant_id`; the Rust adapter intentionally leaves
those only in raw evidence.

### Rust parser and normalization contract

The Rust parser reads exactly: result `id`; NVT `oid`; result and NVT `name`;
`host`; `port`; `result_type`; `severity`; `threat`; `summary`; `solution`;
`qod/value`; `asset_id`; NVT `family`; and CVE ref `type`/`id`. Unknown XML
elements are ignored. Invalid XML, DTD/custom entities, excessive nesting,
attributes, text, events, or result counts produce bounded warnings or
rejection rather than inferred findings.

Normalization behaves as follows:

- `alarm`: normalize a finding. A missing, non-numeric, zero, or negative score
  is an unrated alarm with `Unknown` severity; a positive score uses the shared
  numeric-severity mapping.
- `log`: omit it.
- `error`: record scanner-error incomplete coverage when `asset_id` is an
  authorized asset; otherwise retain raw evidence and mark extraction
  incomplete.
- `dead_host`: record target-did-not-respond incomplete coverage under the same
  authorization rule.
- other nonempty result type: retain raw evidence, emit a warning, normalize no
  finding, and withhold completeness.
- missing result type: legacy `threat=log` or `false positive` is omitted;
  positive numeric severity is still accepted as a finding; other cases remain
  raw evidence and withhold completeness.
- missing/invalid NVT OID: fall back to the first valid CVE; if neither exists,
  retain raw evidence and withhold completeness.
- missing host: use `authorized-target`; missing port leaves a host-only
  location.
- invalid/missing QoD: preserve the raw text but use the product's missing-QoD
  confidence fallback. No Greenbone-specific warning is emitted.
- missing title: use result name, then `Greenbone NVT <rule-id>`.
- `summary` and `solution`: copy into scanner details; target-controlled
  `description` is not normalized.
- valid CVEs become references and tags; family and valid QoD become tags.

## Fragility: silent degradation versus loud failure

### Previously silent, hardened in this refresh

1. The launcher used to discard every OID-less result except `dead_host` and
   `error` before validating its type. An OID-less new result type, a missing
   `type`, or an OID-less `alarm` could therefore disappear. It now discards
   only the known lifecycle/log set; all other types reach the existing
   fail-closed validator.
2. A results object without `items` used to deserialize to an empty slice.
   Renaming the envelope member could therefore become a clean zero-result
   scan. The launcher now requires the exact `items` member when the response
   is not a top-level array.
3. Tests now bind every launcher-to-Rust XML field and assert that an unknown
   Rust-side result type withholds completeness.

### Still silent or only partially visible

- A partial `category` omission removes VTs from the derived profile without a
  minimum/expected-set comparison. An all-feed rename makes the profile empty
  and fails loudly, but partial loss does not.
- Literal family exclusions can stop matching when Greenbone renames a family,
  potentially adding checks to the profile.
- Missing/renamed `deprecated`, `references`, `summary`, or `solution` fields
  silently change selection or report detail.
- Unknown QoD types become `50`, which invents a medium detection-quality score
  rather than preserving uncertainty.
- Newly supported CVSS vector generations remain visible as Unknown alarms but
  lose their upstream severity without a schema-compatibility warning.
- The Rust legacy path accepts a missing `result_type` when numeric severity is
  positive. This protects compatibility with older GMP XML, but for the
  product-owned launcher format it can mask loss of the authoritative verdict
  field.
- Empty/malformed QoD silently uses fallback confidence. The raw value is
  preserved, but users do not get a Greenbone-specific schema warning.
- The fixed smoke OID proves one known alarm path, not preservation of the
  dynamic profile's selection count, family distribution, reference density,
  or metadata completeness.

## Making the next refresh boring

### Safe maintenance and compatibility work

1. Record four independent identities on every refresh: scanner release/source
   commit, scanner runtime manifest digest, VT manifest plus `PLUGIN_SET` and
   `FEED_COMMIT`, and Notus manifest plus its own content identity. Never derive
   one from another.
2. Resolve rolling tags and inspect their contents in one captured maintenance
   run. Save the raw manifest/config labels, `openvasd --version`, full
   `plugin_feed_info.inc`, signature verification, and native-architecture
   smoke evidence. The plan should record the rolling tag and UTC resolution
   time as provenance, while Docker continues to use the digest.
3. Treat source-patch application and all targeted upstream Rust tests in the
   Dockerfile as part of refresh compatibility. A release-note review is not a
   substitute for building both native architectures.
4. Keep explicit contract fixtures for the openvasd results array/envelope and
   launcher XML fields. New upstream enum values must stop or withhold
   completeness, never become empty/zero/benign defaults.
5. Add an inspection utility that produces a candidate plan fragment from the
   pulled images without publishing anything. It should fail if a digest,
   version, feed timestamp, revision, or content signature is absent rather
   than asking a maintainer to copy values by hand.

### Registry retention consequence

The 2026-09-17 registry measurement found only rolling tags: `community`,
`latest`, `stable`, `main-*`, and `edge`. The former SHA-style tags for the
scanner, VT feed, and Notus data have been deleted, and the semantic scanner
tag `23.50.21` has also been deleted. All three previously pinned manifests no
longer resolve.

A digest pin is therefore immutable but has a bounded availability lifetime by
construction: after the rolling tag moves and Greenbone garbage-collects the
old manifest, a clean rebuild cannot retrieve the pinned bytes. Recording
`stable` in the plan documents what was resolved; it does not make `stable`
reproducible. Without a controlled archive or mirror, a rebuild that resolves
the rolling tag again produces whatever `stable` points to on that day, not
necessarily the source, runtime, or behavior reviewed here. It implies:

- every upstream digest pin has a limited availability lifetime by design;
- reproducibility requires copying the exact upstream manifests/blobs into a
  controlled, access-approved mirror or archive while they still exist;
- the mirror must preserve upstream provenance, licenses, signatures, and
  architecture manifests, and its operation is a product-owner publication and
  retention decision; and
- until such a mirror exists, refreshes need a scheduled freshness check and
  should happen before garbage collection breaks builds, not only after a build
  fails.

This analysis does not create or publish such a mirror.

The 2026-10-01 rebuild confirmed the lifetime: all three 2026-09-17 digests
returned 404 fourteen days later, and `stable` had moved to 23.50.25. Greenbone
also publishes the scanner on GHCR, where `ghcr.io/greenbone/openvas-scanner:23.50.24`
still resolves to the reviewed
`sha256:5b950bc273d1d5d123f15dfb7f373b0b3a3b7fb75f67286dfa28e88350a6eb33`, so
the runtime base now comes from there with its bytes unchanged. The VT and
Notus images have no public versioned copy, so the data moved to the snapshot
measured that day:

| Input | Index digest | linux/amd64 | linux/arm64 | Measured content identity |
| --- | --- | --- | --- | --- |
| `vulnerability-tests:community` | `sha256:86a44fb7a9f9b982d521f98914aba98846f573b4f9ec9e8c1007c4866ec943af` | `sha256:56080ddcca72ec4e62eb80b704e73423c336db8ae3fa7efd81e02eb997c2c686` | `sha256:89796f262a5f5ae6995d6e06d42e3870ae34ca1cfb8e6d16c8dff8733e600b4c` | `PLUGIN_SET=202610010558`, `FEED_COMMIT=816c24126e0375d32c667b78d20342ce7c58ec58` |
| `notus-data:community` | `sha256:f53836e6ac0eb3abb7f5ab74ccf93b8317fedd2ba5cd293473cd307c148fc4c3` | `sha256:56ff58dda6888bf47d3f54b8eb03981d3b6977e612feb14a72d9b131cdafabb9` | `sha256:9223ebc963a2b233837b5e62443beb2764222eadcb51cfe389caedd5fa5e690f` | timestamp `202610010540`; amd64 tar SHA-256 `4c25ade8a6beb954d4c067dacba9e7fe85f2883283b3fb83105ec498505126bb` |

### Product decisions intentionally not implemented

1. **QoD semantics.** Recommended: preserve Greenbone's complete known QoD
   mapping and represent a missing/new value as unknown confidence. This changes
   reported confidence and needs product approval.
2. **Strict launcher schema version.** Recommended: add a launcher-owned schema
   marker and require `result_type` for that schema, while keeping legacy GMP
   compatibility explicit. Removing the positive-severity fallback would
   change which findings users see.
3. **Profile drift policy.** Recommended: publish profile selection metrics
   (selected count, category/family counts, closure count, and fixed-OID
   presence) and require owner review of material drift. Thresholds determine
   detection coverage and cannot be chosen as implementation detail.
4. **Family exclusions.** Recommended: replace English-name matching with a
   reviewed stable upstream identifier if Greenbone supplies one; otherwise
   version and review the literal set per feed. Changing it changes scan scope.
5. **Metadata completeness.** Recommended: decide which of summary, solution,
   references, family, deprecation, vectors, and QoD are mandatory for selected
   VTs. Rejecting entries changes coverage; accepting them changes report
   quality.
6. **CVSS v4.** Recommended: preserve the upstream vector/version and use the
   shared report layer to map it after product review. Implementing a new score
   calculation changes severity.
7. **Notus use.** Recommended: either remove Notus from this unauthenticated
   profile after proving it is unnecessary, or add an explicit Notus readiness
   contract. Either choice changes the supported scanner closure and requires
   product ownership.
8. **Durable upstream mirror.** Recommended: authorize a controlled immutable
   mirror because rolling-tag garbage collection makes the present Dockerfile
   intentionally perishable. Mirroring is publication/retention work and was
   not performed here.
