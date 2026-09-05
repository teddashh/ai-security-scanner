# User-facing honesty audit — handover

Date: 2026-09-05

Canonical branch: `main`

Audit range: `122a5fd..c5c9a41` (57 commits, 2026-09-03 to 2026-09-04)

Last verified checkpoint: `c5c9a41`, CI green, working tree clean.

This is an engineering handover for one specific line of work: finding and
correcting places where the shipped product tells a user something the code
does not do. It is not release qualification, not an installer recommendation,
and not a replacement for `docs/product-spec.md` or `docs/product-audit.md`.
Note that `docs/product-spec.md:9` declares itself forward-looking, so "the
spec says X and the code does not do X" was **not** treated as a defect here.

## Why this line of work exists

The product's core promise is that a non-expert can trust what it reports. Every
sentence on screen is part of that promise, and a false one costs more than a
missing feature: it produces a wrong decision the user has no way to detect.

The dominant defect class found was **a sentence making a claim about behaviour
implemented somewhere else** — what the report will say, what the export will
contain, what a scan will do. The existing tests assert each literal against the
file it lives in, so they are structurally unable to notice the other side
drifting. Every one of the fixes below passed the full 400-test suite *before*
its own test existed.

## What was done

| | |
|---|---|
| Commits | 57 (21 `fix`, 15 `test`, 6 `feat`, 4 `release`, 4 `docs`, 4 `ci`, 2 `refactor`, 1 `build`) |
| Diff | 95 files, +11,813 / −673 |
| Frontend tests (`node --test`) | 364 → 404 |
| Component tests (vitest + jsdom) | 0 → 95 across 13 files — the harness did not exist before this range |
| CI lane tests | 23 → 29 |
| New test files | 23 |

### The 21 user-facing claims corrected

Each was verified against the code that contradicted it, fixed, covered by a
test, and that test mutation-proved: the fix reverted, the suite re-run, the
failure confirmed by **subprocess exit code**, and the source restored
byte-identical by sha256.

Results screen and beginner report:

1. A failed run presented as completed — `7be0ee4`
2. A case that is not there reported as present — `7be0ee4`
3. `officialReferences` hard-coded `[]`, so every finding claimed no published documentation existed — `7795ee0`
4. `gapNotTested` naming a cause false for two of the three backend producers — `7795ee0`
5. AIDEFEND presented as carrying NIST and ISO's standing — `7795ee0`
6. `firstSeenRunId`/`lastSeenRunId` stamped from the run being viewed, so every recurring finding read as new — `8e28498`
7. `formatDateTime` omitting the year, so a 2024 first sighting rendered as "Mar 2" — `8e28498`
8. Data-quality warnings replaced by one coverage sentence false for all of them — `42d9deb`
9. Four Traditional Chinese coverage labels collapsing onto one string — `46bda14`

Export screen:

10. "Passwords and access keys are **never** included" — false with redaction off; `export.rs` copies every captured artifact in verbatim, and gitleaks and trufflehog ship as engines — `257a27a`
11. "Include source files for specialist review" promising a larger file, when standard redaction drops every artifact and it attaches nothing — `257a27a`
12. A local integrity signature described for five formats hard-coded `signature: None` — `129945c`
13. Asset relationships check-marked for six formats and serialized by one — `129945c`
14. "Every format remains available" rendered by the same flag that greys out OCSF and OSCAL — `c5c9a41`

Scope, setup, and authorization:

15. "Review public records" offering a review whose grant no engine in the catalog can act on — `ba084cb`
16. Cloud sign-in prerequisite buried two disclosures deep — `b90688e`
17. "Results will mark this check as not tested" while the report labels it Failed — `85f7513`
18. "Other available checks can continue" for a blocker raised only at zero runnable — `85f7513`
19. The data-class question promising what the backend refuses to do — `3c6e30a`
20. Microsoft 365 capability cells still describing both engines as planned future work, months after both were published at immutable digests with status `integrated` — `c5ea4b2`
21. The new-case organization field placeheld "You can add this later", when `commands.rs` exposes no case-update path at all — `c5ea4b2`

Separately, five M365 adapter fixes stopped partial and undeclared wrapper
results from reading as complete (`a16e595`, `17fca8c`, `49a5d1b`, `fd9194f`,
`b1684f6`).

### Structural guards built

These matter more than any single fix, because they change what a future
regression costs.

- **Cross-boundary tests.** A copy claim about backend behaviour is now asserted
  by reading both files in one `tests/frontend` test, and proved by mutating the
  *backend* side.
- **`tests/ci/frontend-lane-covers-its-reads.test.mjs`** derives the frontend
  lane's backend entries from what the tests actually open, in both directions.
  A frontend test reading a backend file without a `FRONTEND_PATHS` entry would
  silently never run on the commit most likely to break it. This guard has
  already caught one omission by name, unprompted (`engines/catalog.json`).
- **`tests/frontend/sourceRegions.ts`** replaces the
  `/<details>[\s\S]*needle[\s\S]*<\/details>/` idiom, which cannot express
  containment: it matches from the first disclosure to the last close, 41,000
  characters on `FindingsPage.tsx`. Hoisting the fingerprint out of every
  disclosure left the old assertion green — measured, not assumed.
- **`tests/frontend/publicRecordsScopePromise.test.ts`** derives what the
  public-records copy may claim from `engines/catalog.json`, so the constraint
  lifts by itself the day an engine declares the permission.

### Method, for whoever continues

1. Find a user-facing sentence that asserts behaviour.
2. Find the code that must be true for it to hold. Read it. Do not infer.
3. If it does not hold, fix the copy or the wiring — whichever is wrong.
4. Write a test that renders, rather than matching source text.
5. Mutate the fix, run, confirm failure **by exit code**, restore, verify sha256.
6. A mutation that survives is a defect in the test. Fix the test, never the
   measurement — three survived in this range and each exposed a real gap.

Gates: `npm run typecheck`, `npm run test:frontend`, `npx vitest run`,
`node --test tests/ci/*.test.mjs`. Note `node --test tests/ci/` (directory form)
fails with a module error that reads like a broken test.

## What is left

### Not yet audited

- **`SettingsPage.tsx`** — no render test and no claim audit. The only page in
  `src/pages/` with neither.
- **`AppUpdateControl.tsx`** — no render test. It makes update-availability and
  version claims, which is exactly the shape that has failed elsewhere.
- **`VerificationPage.tsx` data-handling claims.** The page has a render test
  (`05de33e`), but the audit of its evidence-deletion, redaction and
  "stays on your computer" claims was assigned to an agent that stalled; the
  relaunch was narrowed to the export surface and this was dropped. Not audited.
  This is the largest known gap.
- **Evidence-deletion claims on `CasesPage`** beyond the panel rendered in
  `011ed21`.

### Test-strength debt

22 `assert.match` patterns in `tests/frontend` still accept more than 4,000
characters of wildcard slack (45 exceed 500). These are ordering assertions,
not containment ones, so the unbounded span makes them weak rather than
meaningless — but a 40,000-character span asserts only that both anchors exist
somewhere in the file.

To re-measure: `--import` a hook wrapping `assert.match` that records
`regexp.exec(value)[0].length`, and rewrite `[\s\S]*` lazily before measuring —
greedy spans run to the *last* occurrence of the trailing anchor and overstate
the distance. The first measurement of this was wrong for that reason.

### Needs Ted's decision

- **A `Failed` coverage gap's next action is `RetryCheck`**, which contradicts
  the setup panel's "cannot run in this app version" and its absent Retry
  button. Fixing it changes persisted result semantics and comparison
  baselines, so it is not a copy change.
- **`mappingProvenance`** (`reviewedAt`, `reviewProcess`, `catalogSha256`)
  reaches a user only in the exported HTML. Surface it in the app, or drop it.
- **`Confidence::High` is hard-coded across all adapters.** Either it means
  something and should vary, or the field is decoration.

### Blocked on fresh authorization

GHCR publication is outward-facing and requires explicit per-instance
authorization; approval for one version does not extend to the next.

- Maester `Investigate` collapses into `Failed` without surfacing `SourceResult`.
- ScubaGear `Details` and Maester `ResultDetail` are not carried into findings.
  Both need a wrapper change and a `-6` republish.

### Open, reported, not acted on

- Dependabot moderate: `rust/glib 0.18.5` `VariantStrIter` unsoundness, patched
  in 0.20.0, transitive through Tauri's Linux GTK stack. Needs an upstream
  gtk-rs family bump. Linux is a release target.

### Standing honest limits

- **Neither M365 engine has ever run against a real tenant.** Published and
  launcher-verified only.
- **The Windows installed lifecycle has never executed** — NSIS cache seeding,
  corrupt-package recovery, the copied prior-uninstaller path. Statically
  validated only.

## Where this sits

| Stage | State |
|---|---|
| 1. Render sweep — make the UI actually execute | Done, except `SettingsPage` and `AppUpdateControl` |
| 2. Bind cross-boundary claims and guard the CI lane | Done for every claim found; guard is committed and self-deriving |
| 3. Per-surface claim audit | 9 of 12 surfaces (8 pages + 4 components carrying claims); `SettingsPage`, `AppUpdateControl`, and `VerificationPage` data handling remain |
| 4. Test-strength audit (wildcard spans) | Started; containment class fixed, 22 ordering assertions remain |
| 5. Decisions and authorizations | Waiting on Ted |

The next concrete step is the `VerificationPage` data-handling audit, because it
is the largest unaudited surface making the same class of claim that produced
the most serious finding in this range.
