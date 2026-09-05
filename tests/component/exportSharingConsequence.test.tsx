import { cleanup, fireEvent, render, waitFor } from "@testing-library/react";
import { afterEach, beforeEach, expect, test, vi } from "vitest";

import { ExportPage } from "../../src/pages/ExportPage";
import { I18nProvider, localeStorageKey } from "../../src/i18n";
import type { CaseWorkspace, ExportPreview, ScanRun } from "../../src/types";

// The export screen is where a user decides who else may hold this data, and it
// used to answer that question with one unconditional sentence: "Passwords and
// access keys are never included."
//
// That is true under standard redaction and false without it. `export.rs`
// computes `include = include_raw_artifacts && !(Standard && sensitive)`, so
// with redaction off every captured artifact is copied into the bundle
// verbatim, and gitleaks and trufflehog ship as engines whose raw output holds
// the discovered values. The backend even writes the contradicting sentence
// itself -- it was rendered one disclosure below the promise, where a reader
// deciding whether to send the file has no reason to look.
//
// The mirror is the other half of the same predicate: every artifact the
// desktop app captures is marked sensitive, so *with* redaction on the "include
// source files" option attaches nothing at all, while its label promised a
// larger file a specialist could check.
//
// These tests pin the sentence to the settings that produce it. They render the
// page rather than matching its source because the defect was never a missing
// string -- the string was there, and said the wrong thing.
//
// The same shape appears in the summary below the toggles, which described the
// selected format using one format's properties. Those claims are pinned here
// too: this file's subject is everything the screen asserts about the file it is
// about to write.

const CHOSEN = "run-2026-08-31";

const run = (id: string): ScanRun => ({
  id,
  caseId: "case-1",
  label: id,
  status: "completed",
  progress: 100,
  startedAt: "2026-08-31T12:00:00Z",
  finishedAt: "2026-08-31T12:01:00Z",
  knowledgeDate: "2026-08-31",
  engineRuns: [],
  coveredAssetCount: 3,
  totalAssetCount: 3,
});

const workspace: CaseWorkspace = {
  case: {
    id: "case-1",
    name: "Contoso baseline",
    aiGeneratedArtifact: "no",
    organizationName: "Contoso",
    companySize: "small",
    dataClasses: [],
    requestedActivities: [],
    platforms: [],
    createdAt: "2026-08-31T11:00:00Z",
    updatedAt: "2026-09-02T11:00:00Z",
    phase: "reporting",
    latestRunId: CHOSEN,
  },
  sources: [],
  coverage: [],
  assets: [],
  scopeGrants: [],
  runs: [run(CHOSEN)],
  findings: [],
  findingGroups: [],
  findingGroupEvents: [],
  workflowEvents: [],
  exports: [],
};

/**
 * A preview that answers whatever coordinate it was asked about.
 *
 * The page discards a preview whose coordinates disagree with the current
 * selection, so a fixed answer would turn every toggle in these tests into a
 * coordinate mismatch and hide the sentence under test behind an error notice.
 */
const renderExport = () => {
  const onPreview = vi.fn((request: {
    runId: string;
    locale: "en" | "zh-Hant";
    format: string;
    includeRawEvidence: boolean;
    redactSensitiveValues: boolean;
  }) => Promise.resolve({
    caseId: "case-1",
    runId: request.runId,
    locale: request.locale,
    format: request.format,
    redactionProfile: request.redactSensitiveValues ? "standard" : "none",
    includeRawEvidence: request.includeRawEvidence,
    dataSourceCount: 2,
    coverageEntryCount: 4,
    assetCount: 3,
    candidateAssetCount: 3,
    canonicalFindingCount: 7,
    selectedRunFindingCount: 7,
    evidenceIndexCount: 7,
    selectedRunEvidenceCount: 7,
    scanRunCount: 1,
    selectedEngineRunCount: 2,
    externalScopeGrantCount: 0,
    incompleteEngineRunCount: 0,
    notExecutedEngineRunCount: 0,
    unknownSourceCount: 0,
    connectedNoAssetCount: 0,
    rawArtifactCount: 4,
    rawArtifactsIncluded: request.redactSensitiveValues ? 0 : 4,
    rawArtifactsOmitted: request.redactSensitiveValues ? 4 : 0,
    sensitiveRawArtifactsOmitted: request.redactSensitiveValues ? 4 : 0,
    sensitiveDataWarning: "backend warning",
    coverageManifestIncluded: true,
  } as ExportPreview));

  const { container } = render(
    <I18nProvider>
      <ExportPage
        workspace={workspace}
        selectedRunId={CHOSEN}
        exports={[]}
        demoMode={false}
        onPreview={onPreview}
        onExport={() => Promise.resolve()}
        onVerify={() => Promise.resolve()}
        onVerifyReceived={() => Promise.resolve()}
      />
    </I18nProvider>,
  );
  return { container };
};

/** The sentence describing what the current settings leave in the file. */
const consequence = (container: HTMLElement): string => {
  const paragraph = container.querySelector<HTMLElement>(".export-sharing-consequence");
  if (!paragraph) throw new Error("no sharing-consequence sentence rendered");
  return paragraph.textContent ?? "";
};

/** A toggle located by the label text next to it, not by DOM position. */
const toggle = (container: HTMLElement, label: string): HTMLInputElement => {
  const row = Array.from(container.querySelectorAll<HTMLElement>("label.toggle-row")).find(
    (candidate) => candidate.querySelector("strong")?.textContent === label,
  );
  if (!row) throw new Error(`no toggle labelled "${label}"`);
  const input = row.querySelector<HTMLInputElement>("input[type=checkbox]");
  if (!input) throw new Error(`toggle "${label}" has no checkbox`);
  return input;
};

const chooseCaseBundle = (container: HTMLElement) => {
  const card = Array.from(container.querySelectorAll<HTMLElement>("label.format-card")).find(
    (candidate) => candidate.textContent?.includes("Technical case bundle"),
  );
  if (!card) throw new Error("no case-bundle format card rendered");
  const input = card.querySelector<HTMLInputElement>("input");
  if (!input) throw new Error("the case-bundle card has no input");
  fireEvent.click(input);
};

/** The integrity sentence heading the "what will be included" summary. */
const integrityNote = (container: HTMLElement): string => {
  const note = container.querySelector<HTMLElement>(".export-summary__note");
  if (!note) throw new Error("no integrity note rendered");
  return note.textContent ?? "";
};

/** The asset-relationship line of that summary, located by its own wording. */
const assetRelationsLine = (container: HTMLElement): HTMLElement => {
  const line = Array.from(container.querySelectorAll<HTMLElement>(".export-contents li")).find(
    (candidate) => candidate.textContent?.includes("Asset relationships"),
  );
  if (!line) throw new Error("no asset-relationship line rendered");
  return line;
};

beforeEach(() => {
  window.localStorage.setItem(localeStorageKey, "en");
});

afterEach(() => {
  cleanup();
  window.localStorage.clear();
});

test("the default export states that captured source files are left out", async () => {
  const { container } = renderExport();

  await waitFor(() => expect(consequence(container)).toContain("Private details are hidden"));
  expect(consequence(container)).toContain("every source file a scanner captured is left out");

  // The promise that was there before, in the form that made it false.
  expect(container.textContent).not.toContain("Passwords and access keys are never included");
});

test("attaching source files without redaction says the secrets are in the file", async () => {
  const { container } = renderExport();
  await waitFor(() => expect(consequence(container)).toContain("Private details are hidden"));

  chooseCaseBundle(container);
  fireEvent.click(toggle(container, "Hide sensitive identifiers"));
  await waitFor(() => expect(toggle(container, "Include source files for specialist review").disabled).toBe(false));
  fireEvent.click(toggle(container, "Include source files for specialist review"));

  await waitFor(() => expect(consequence(container)).toContain("Any password or access key a scanner found is inside this file"));
  expect(consequence(container)).toContain("attached exactly as the scanners produced them");

  // The notice carrying it is raised to the page's strongest tone, so the
  // sentence is not one grey paragraph among several.
  const notice = container.querySelector(".inline-notice--danger");
  expect(notice?.textContent).toContain("Any password or access key");
});

test("turning redaction off without attaching sources claims neither more nor less", async () => {
  // The third state exists because the two toggles are independent: identifiers
  // become readable, but no scanner output is copied in. Collapsing this into
  // either neighbour would overstate one way or the other.
  const { container } = renderExport();
  await waitFor(() => expect(consequence(container)).toContain("Private details are hidden"));

  fireEvent.click(toggle(container, "Hide sensitive identifiers"));

  await waitFor(() => expect(consequence(container)).toContain("host names, addresses, and system identifiers stay readable"));
  expect(consequence(container)).toContain("No source files are attached");
  expect(consequence(container)).not.toContain("Any password or access key");

  // Again on the one format that *can* carry artifacts, with the option left
  // off. Without this the format clause alone suppresses the secrets sentence
  // and the source-file clause is never exercised -- a mutation dropping it
  // survived until this case existed.
  chooseCaseBundle(container);
  await waitFor(() => expect(toggle(container, "Include source files for specialist review").disabled).toBe(false));
  expect(toggle(container, "Include source files for specialist review").checked).toBe(false);
  expect(consequence(container)).toContain("No source files are attached");
  expect(consequence(container)).not.toContain("Any password or access key");
});

test("the source-file option says it does nothing while private details are hidden", async () => {
  // Every artifact the desktop app captures is marked sensitive and standard
  // redaction drops all of them, so in the default state ticking this box
  // changes nothing about the file. The label used to promise the opposite.
  const { container } = renderExport();
  await waitFor(() => expect(consequence(container)).toContain("Private details are hidden"));

  chooseCaseBundle(container);
  const row = Array.from(container.querySelectorAll<HTMLElement>("label.toggle-row")).find(
    (candidate) => candidate.querySelector("strong")?.textContent === "Include source files for specialist review",
  );
  const detail = row?.querySelector("small")?.textContent ?? "";
  expect(detail).toContain("only when private details are not hidden");
  expect(detail).toContain("this option changes nothing");
  expect(detail).not.toContain("Passwords and access keys are not included");
});

test("the recommended format says plainly that it is not signed", async () => {
  // Only the case bundle is signed. Every other format takes the path that sets
  // `signature: None` and stores UNSIGNED_SCHEMA_NOTICE -- a notice the backend
  // writes and no screen has ever shown. HTML is the default and the
  // recommended one, so this is the sentence most readers get.
  const { container } = renderExport();
  await waitFor(() => expect(consequence(container)).toContain("Private details are hidden"));

  expect(integrityNote(container)).toContain("This format is not signed");
  expect(integrityNote(container)).toContain("SHA-256 digest is kept in your project");
  expect(integrityNote(container)).not.toContain("carries a local integrity signature");
});

test("the case bundle is the one format that describes a signature", async () => {
  // The mirror. Without it the sentence above could be hard-coded and the
  // page would understate the one format that does sign.
  const { container } = renderExport();
  await waitFor(() => expect(consequence(container)).toContain("Private details are hidden"));

  chooseCaseBundle(container);
  await waitFor(() => expect(integrityNote(container)).toContain("carries a local integrity signature"));
  expect(integrityNote(container)).not.toContain("This format is not signed");
});

test("a format that cannot carry asset relationships says so instead of showing a check", async () => {
  // `case.asset_relations` is serialized only into the bundle's assets.json;
  // OCSF names asset relationships in its own omitted list. The line was
  // rendered with a check icon for all six formats.
  const { container } = renderExport();
  await waitFor(() => expect(consequence(container)).toContain("Private details are hidden"));

  const line = assetRelationsLine(container);
  expect(line.className).toContain("export-contents__excluded");
  expect(line.textContent).toContain("not carried by this format");
});

test("the case bundle still lists asset relationships as included", async () => {
  const { container } = renderExport();
  await waitFor(() => expect(consequence(container)).toContain("Private details are hidden"));

  chooseCaseBundle(container);
  await waitFor(() => expect(assetRelationsLine(container).className).not.toContain("export-contents__excluded"));
  expect(assetRelationsLine(container).textContent).toContain("Asset relationships for specialist review");
  expect(assetRelationsLine(container).textContent).not.toContain("not carried by this format");
});

test("the advanced-format note names the two formats it is greying out", async () => {
  // This note is shown exactly when `runSupportsFindingOnlyExport` is false,
  // and that predicate is `Boolean(run)` -- so it appears only in the state
  // where OCSF and OSCAL are the two disabled cards directly beneath it. It
  // used to open with "Every format remains available."
  const onPreview = vi.fn(() => Promise.resolve(undefined));
  const { container } = render(
    <I18nProvider>
      <ExportPage
        workspace={{ ...workspace, runs: [] }}
        selectedRunId={undefined}
        exports={[]}
        demoMode={false}
        onPreview={onPreview}
        onExport={() => Promise.resolve()}
        onVerify={() => Promise.resolve()}
        onVerifyReceived={() => Promise.resolve()}
      />
    </I18nProvider>,
  );

  const note = container.querySelector<HTMLElement>(".page-secondary-feature__intro");
  expect(note?.textContent).toContain("OCSF and OSCAL are unavailable until a saved scan is selected");
  expect(note?.textContent).not.toContain("Every format remains available");

  // The claim and the controls have to agree: those two cards really are the
  // disabled ones in this state.
  // Compared by format id rather than card title: the titles are
  // plain-language ("Send findings to a security platform"), so matching them
  // would not show that the disabled pair is the pair the sentence names.
  const disabled = Array.from(container.querySelectorAll<HTMLInputElement>("input[name=export-format]"))
    .filter((input) => input.disabled)
    .map((input) => input.value)
    .sort();
  expect(disabled).toEqual(["ocsf", "oscal"]);
});

test("with a run selected the advanced formats are introduced, not explained away", async () => {
  // The mirror. Without it the no-run sentence could render in every state,
  // telling a user with a perfectly good run that two formats are unavailable
  // while both cards sit enabled beside it -- a mutation doing exactly that
  // survived until this test existed.
  const { container } = renderExport();
  await waitFor(() => expect(consequence(container)).toContain("Private details are hidden"));

  const note = container.querySelector<HTMLElement>(".page-secondary-feature__intro");
  expect(note?.textContent).toContain("security-specialist handoff");
  expect(note?.textContent).not.toContain("unavailable until a saved scan is selected");

  const disabled = Array.from(container.querySelectorAll<HTMLInputElement>("input[name=export-format]"))
    .filter((input) => input.disabled)
    .map((input) => input.value);
  expect(disabled).toEqual([]);
});
