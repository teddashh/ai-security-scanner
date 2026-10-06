import { cleanup, fireEvent, render } from "@testing-library/react";
import type { ComponentProps } from "react";
import { afterEach, beforeEach, expect, test, vi } from "vitest";

import { CasesPage } from "../../src/pages/CasesPage";
import type { CasesPageProps } from "../../src/pages/CasesPage";
import { VerificationPage } from "../../src/pages/VerificationPage";
import { I18nProvider, localeStorageKey } from "../../src/i18n";
import type { LocalFolderRecheckRow } from "../../src/localFolderRecheck";
import type { AssessmentCase, ScanRun, VerificationDiff, VerificationSummary } from "../../src/types";

const assessmentCase = (): AssessmentCase => ({
  id: "case-1",
  name: "Acme scan",
  aiGeneratedArtifact: "no",
  organizationName: "Acme",
  companySize: "small",
  dataClasses: [],
  requestedActivities: [],
  platforms: [],
  createdAt: "2026-09-01T10:00:00Z",
  updatedAt: "2026-09-02T10:00:00Z",
  phase: "discovering",
});

const completedRun = (): ScanRun => ({
  id: "run-before",
  caseId: "case-1",
  label: "Scan 1",
  status: "completed",
  progress: 100,
  startedAt: "2026-10-01T00:00:00Z",
  finishedAt: "2026-10-01T00:30:00Z",
  knowledgeDate: "2026-10-01",
  engineRuns: [],
  coveredAssetCount: 1,
  totalAssetCount: 1,
});

const folderRow = (
  assetId: string,
  state: LocalFolderRecheckRow["state"],
  extra: Partial<LocalFolderRecheckRow> = {},
): LocalFolderRecheckRow => ({
  assetId,
  name: assetId,
  state,
  ...extra,
});

const renderCases = (overrides: Partial<CasesPageProps> = {}) => {
  const selected = assessmentCase();
  const run = completedRun();
  return render(
    <I18nProvider>
      <CasesPage
        cases={[selected]}
        selectedCase={selected}
        assetCount={0}
        findingCount={0}
        unknownSourceCount={0}
        connectedNoAssetSourceCount={0}
        latestRun={run}
        runs={[run]}
        verificationBaselineRunId={run.id}
        nativeMode
        onCreate={() => Promise.resolve(true)}
        onCreateWithWorkspace={() => Promise.resolve(true)}
        onChooseWorkspace={() => Promise.resolve(null)}
        onSeedDemo={() => Promise.resolve()}
        onArchive={() => Promise.resolve()}
        onDelete={() => Promise.resolve(true)}
        onDeleteArtifacts={() => Promise.resolve(true)}
        onDismissArtifactCleanup={() => {}}
        onStartNewScan={() => {}}
        onOpenCase={() => {}}
        onContinue={() => {}}
        onOpenProgress={() => {}}
        onOpenResults={() => {}}
        onSelectVerificationBaseline={() => {}}
        onStartRescan={() => Promise.resolve()}
        onOpenVerification={() => {}}
        {...overrides}
      />
    </I18nProvider>,
  );
};

const openCasesPanel = (container: HTMLElement) => {
  const panel = container.querySelector<HTMLDetailsElement>("details.verification-baseline-panel");
  if (!panel) throw new Error("Check fixes panel did not render");
  panel.open = true;
};

const diff = (overrides: Partial<VerificationDiff> & Pick<VerificationDiff, "id" | "state">): VerificationDiff => ({
  title: `Finding ${overrides.id}`,
  assetName: "repo",
  explanation: "Recorded comparison detail.",
  evidenceChanged: false,
  ...overrides,
});

const summary = (overrides: Partial<VerificationSummary> = {}): VerificationSummary => ({
  baselineRunId: "run-before",
  comparisonRunId: "run-after",
  baselineAt: "2026-10-01T00:00:00Z",
  comparisonAt: "2026-10-02T00:00:00Z",
  complete: true,
  diffs: [],
  ...overrides,
});

const renderVerification = (
  verification: VerificationSummary | undefined,
  overrides: Partial<ComponentProps<typeof VerificationPage>> = {},
) => render(
  <I18nProvider>
    <VerificationPage
      verification={verification}
      runs={[completedRun(), { ...completedRun(), id: "run-after", startedAt: "2026-10-02T00:00:00Z" }]}
      findings={[]}
      baselineRunId="run-before"
      onSelectBaseline={() => {}}
      onStartRescan={() => Promise.resolve()}
      onOpenFinding={() => {}}
      {...overrides}
    />
  </I18nProvider>,
);

const buttonNamed = (container: HTMLElement, name: RegExp): HTMLButtonElement => {
  const match = Array.from(container.querySelectorAll<HTMLButtonElement>("button")).find(
    (button) => name.test(button.textContent ?? ""),
  );
  if (!match) throw new Error(`missing button ${name}`);
  return match;
};

const recheckRow = (container: HTMLElement, name: string): HTMLElement => {
  const row = Array.from(container.querySelectorAll<HTMLElement>(".local-folder-recheck .form-actions")).find(
    (candidate) => candidate.querySelector("strong")?.textContent === name,
  );
  if (!row) throw new Error(`missing folder row ${name}`);
  return row;
};

beforeEach(() => {
  window.localStorage.setItem(localeStorageKey, "en");
});

afterEach(() => {
  cleanup();
  window.localStorage.clear();
});

test.each([
  ["en", {
    title: "Choose the fixed folder",
    description: "The earlier scan read a copy saved when you chose each folder.",
    notChosen: "Not chosen again yet",
    choose: "Choose folder",
    gate: "Choose each folder again first.",
    casesStart: "Start a new check from this baseline",
    verificationStart: "Check the fix again",
  }],
  ["zh-TW", {
    title: "選擇修正後的資料夾",
    description: "先前的掃描讀取的是你選擇資料夾當時存下的副本。請重新選擇每個資料夾，這次檢查才會讀到你的修改。",
    notChosen: "尚未重新選擇",
    choose: "選擇資料夾",
    gate: "請先重新選擇每個資料夾。",
    casesStart: "以這次結果開始複驗",
    verificationStart: "重新檢查修復結果",
  }],
] as const)("Check fixes asks for each local folder again in %s", (locale, phrase) => {
  window.localStorage.setItem(localeStorageKey, locale);
  const rows = [folderRow("repo", "choose_again")];
  const cases = renderCases({ folderRecheckRows: rows });
  openCasesPanel(cases.container);
  expect(cases.container.textContent).toContain(phrase.title);
  expect(cases.container.textContent).toContain(phrase.description);
  expect(recheckRow(cases.container, "repo").textContent).toContain(phrase.notChosen);
  expect(buttonNamed(recheckRow(cases.container, "repo"), new RegExp(phrase.choose, "u")).disabled).toBe(false);
  expect(cases.container.textContent).toContain(phrase.gate);
  expect(buttonNamed(cases.container, new RegExp(phrase.casesStart, "u")).disabled).toBe(true);
  cleanup();

  const before = renderVerification(undefined, { folderRecheckRows: rows });
  expect(before.container.textContent).toContain(phrase.title);
  expect(before.container.textContent).toContain(phrase.gate);
  expect(buttonNamed(before.container, new RegExp(phrase.verificationStart, "u")).disabled).toBe(true);
  const pickerCard = before.container.querySelector("#verification-baseline-picker-title")?.closest("section");
  expect(pickerCard?.querySelector(".local-folder-recheck")).toBeTruthy();
  cleanup();

  const result = renderVerification(summary({ diffs: [diff({ id: "kept", state: "persistent" })] }), { folderRecheckRows: rows });
  expect(result.container.textContent).toContain(phrase.gate);
  expect(buttonNamed(result.container, new RegExp(phrase.verificationStart, "u")).disabled).toBe(true);
  const resultPickerCard = result.container.querySelector("#verification-baseline-picker-title")?.closest("section");
  expect(resultPickerCard?.querySelector(".local-folder-recheck")).toBeTruthy();
  expect(result.container.querySelectorAll(".local-folder-recheck")).toHaveLength(1);
});

test.each([
  ["en", { title: "Choose the fixed folder", gate: "Choose each folder again first.", notChosen: "Not chosen again yet" }],
  ["zh-TW", { title: "選擇修正後的資料夾", gate: "請先重新選擇每個資料夾。", notChosen: "尚未重新選擇" }],
] as const)("an active check hides the folder rows and the folder gate in %s", (locale, phrase) => {
  window.localStorage.setItem(localeStorageKey, locale);
  const rows = [folderRow("repo", "choose_again")];
  const active: ScanRun = {
    ...completedRun(),
    id: "run-after",
    label: "Scan 2",
    status: "running",
    progress: 40,
    startedAt: "2026-10-02T00:00:00Z",
    finishedAt: undefined,
  };
  const runs = [completedRun(), active];
  const absent = (container: HTMLElement) => {
    expect(container.querySelector(".local-folder-recheck")).toBeNull();
    expect(container.querySelector(".local-folder-recheck-gate")).toBeNull();
    expect(container.textContent).not.toContain(phrase.title);
    expect(container.textContent).not.toContain(phrase.gate);
    expect(container.textContent).not.toContain(phrase.notChosen);
  };

  const cases = renderCases({ folderRecheckRows: rows, runs, latestRun: active });
  openCasesPanel(cases.container);
  absent(cases.container);
  cleanup();

  const before = renderVerification(undefined, { folderRecheckRows: rows, runs });
  absent(before.container);
  cleanup();

  const result = renderVerification(summary({ diffs: [diff({ id: "kept", state: "persistent" })] }), { folderRecheckRows: rows, runs });
  absent(result.container);
});

test("the follow-up check stays disabled until every folder is chosen again", () => {
  const onChooseFolderAgain = vi.fn();
  const waiting = [
    folderRow("first", "choose_again"),
    folderRow("second", "choose_again"),
  ];
  const cases = renderCases({ folderRecheckRows: waiting, onChooseFolderAgain });
  openCasesPanel(cases.container);
  expect(buttonNamed(cases.container, /Start a new check from this baseline/u).disabled).toBe(true);
  fireEvent.click(buttonNamed(recheckRow(cases.container, "first"), /Choose folder/u));
  fireEvent.click(buttonNamed(recheckRow(cases.container, "second"), /Choose folder/u));
  expect(onChooseFolderAgain).toHaveBeenNthCalledWith(1, "first");
  expect(onChooseFolderAgain).toHaveBeenNthCalledWith(2, "second");

  cases.rerender(
    <I18nProvider>
      <CasesPage
        {...casesHostProps()}
        folderRecheckRows={[
          folderRow("first", "choose_again"),
          folderRow("second", "saved", { savedAt: "2026-10-02T00:00:00Z" }),
        ]}
        onChooseFolderAgain={onChooseFolderAgain}
      />
    </I18nProvider>,
  );
  openCasesPanel(cases.container);
  expect(cases.container.textContent).toContain("Choose each folder again first.");
  expect(buttonNamed(cases.container, /Start a new check from this baseline/u).disabled).toBe(true);

  cases.rerender(
    <I18nProvider>
      <CasesPage
        {...casesHostProps()}
        folderRecheckRows={[
          folderRow("first", "saved", { savedAt: "2026-10-02T00:00:00Z" }),
          folderRow("second", "saved", { savedAt: "2026-10-02T00:00:00Z" }),
        ]}
        onChooseFolderAgain={onChooseFolderAgain}
      />
    </I18nProvider>,
  );
  openCasesPanel(cases.container);
  expect(cases.container.textContent).not.toContain("Choose each folder again first.");
  expect(buttonNamed(cases.container, /Start a new check from this baseline/u).disabled).toBe(false);
  fireEvent.click(buttonNamed(recheckRow(cases.container, "first"), /Choose again/u));
  expect(onChooseFolderAgain).toHaveBeenLastCalledWith("first");
});

test("verification stays disabled until every folder is chosen again", () => {
  const onChooseFolderAgain = vi.fn();
  const waiting = [folderRow("repo", "choose_again")];
  const view = renderVerification(undefined, { folderRecheckRows: waiting, onChooseFolderAgain });
  expect(buttonNamed(view.container, /Check the fix again/u).disabled).toBe(true);
  fireEvent.click(buttonNamed(view.container, /Choose folder/u));
  expect(onChooseFolderAgain).toHaveBeenCalledWith("repo");
  view.rerender(
    <I18nProvider>
      <VerificationPage
        verification={undefined}
        runs={[completedRun(), { ...completedRun(), id: "run-after" }]}
        findings={[]}
        baselineRunId="run-before"
        folderRecheckRows={[folderRow("repo", "saved", { savedAt: "2026-10-02T00:00:00Z" })]}
        onSelectBaseline={() => {}}
        onStartRescan={() => Promise.resolve()}
        onChooseFolderAgain={onChooseFolderAgain}
        onOpenFinding={() => {}}
      />
    </I18nProvider>,
  );
  expect(view.container.textContent).not.toContain("Choose each folder again first.");
  expect(buttonNamed(view.container, /Check the fix again/u).disabled).toBe(false);
});

test.each([
  ["en", {
    changed: "2 changed, 1 added, 0 removed",
    unchanged: "No files changed since the earlier copy.",
    summary: "Updated copy saved",
    overlap: "None of the files match the earlier copy. Check that you chose the same project folder.",
    again: "Choose again",
  }],
  ["zh-TW", {
    changed: "變更 2 個檔案、新增 1 個、移除 0 個",
    unchanged: "但檔案和先前的副本相同。",
    summary: "已存下新的副本",
    overlap: "沒有任何檔案和先前的副本相同，請確認選的是同一個專案資料夾。",
    again: "重新選擇",
  }],
] as const)("saved folder copies explain what changed in %s", (locale, phrase) => {
  window.localStorage.setItem(localeStorageKey, locale);
  const savedAt = "2026-10-06T01:02:03Z";
  const change = { changed: 2, added: 1, removed: 0, unchanged: 4 };
  const { container } = renderCases({
    folderRecheckRows: [
      folderRow("changed", "saved", { savedAt, change }),
      folderRow("same", "saved", { savedAt, change: { changed: 0, added: 0, removed: 0, unchanged: 4 } }),
      folderRow("plain", "saved", { savedAt }),
      folderRow("other", "no_overlap", { savedAt, change: { changed: 0, added: 3, removed: 2, unchanged: 0 } }),
    ],
  });
  openCasesPanel(container);
  expect(recheckRow(container, "changed").textContent).toContain(phrase.summary);
  expect(recheckRow(container, "changed").textContent).toContain(phrase.changed);
  expect(recheckRow(container, "same").textContent).toContain(phrase.unchanged);
  expect(recheckRow(container, "plain").textContent).toContain(phrase.summary);
  expect(recheckRow(container, "plain").textContent).not.toContain(phrase.unchanged);
  expect(recheckRow(container, "plain").textContent).not.toContain(phrase.changed);
  const overlap = recheckRow(container, "other");
  expect(overlap.querySelector(".inline-notice--warning")?.textContent).toContain(phrase.overlap);
  expect(buttonNamed(overlap, new RegExp(phrase.again, "u")).disabled).toBe(false);
});

test("a busy recheck disables choosing the folder again", () => {
  const { container } = renderCases({
    busy: true,
    folderRecheckRows: [folderRow("repo", "saved", { savedAt: "2026-10-02T00:00:00Z" })],
  });
  openCasesPanel(container);
  expect(buttonNamed(container, /Choose again/u).disabled).toBe(true);
});

test.each(["en", "zh-TW"] as const)("a website-only case keeps Check fixes open in %s", (locale) => {
  window.localStorage.setItem(localeStorageKey, locale);
  const cases = renderCases();
  openCasesPanel(cases.container);
  expect(cases.container.querySelector(".local-folder-recheck")).toBeNull();
  expect(cases.container.textContent).not.toContain("Choose the fixed folder");
  expect(cases.container.textContent).not.toContain("選擇修正後的資料夾");
  const casesStart = locale === "en" ? /Start a new check from this baseline/u : /以這次結果開始複驗/u;
  expect(buttonNamed(cases.container, casesStart).disabled).toBe(false);
  cleanup();

  const verification = renderVerification(undefined);
  expect(verification.container.querySelector(".local-folder-recheck")).toBeNull();
  const verificationStart = locale === "en" ? /Check the fix again/u : /重新檢查修復結果/u;
  expect(buttonNamed(verification.container, verificationStart).disabled).toBe(false);
});

test.each([
  ["en", {
    copiesTitle: "Folder copies compared",
    changed: "api: abcdef012345 → 1234567890ab",
    same: "web: the same files in both scans (fedcba987654)",
    redacted: "folder-missing: the same files in both scans ([redacted snapshot hash])",
    notice: "web: both scans read the same files. If you changed this folder, choose it again, then check again.",
    missingNotice: "folder-missing: both scans read the same files. If you changed this folder, choose it again, then check again.",
    moved: "The same rule still finds this problem in the same file; only its line moved.",
    persistent: "The same problem is still present.",
    detail: "location moved from line 9 to line 7 in the same file",
  }],
  ["zh-TW", {
    copiesTitle: "比較的資料夾副本",
    changed: "api：abcdef012345 → 1234567890ab",
    same: "web：兩次掃描的檔案相同（fedcba987654）",
    redacted: "folder-missing：兩次掃描的檔案相同（[redacted snapshot hash]）",
    notice: "web：兩次掃描讀到的檔案相同。如果你修改過這個資料夾，請重新選擇後再檢查一次。",
    missingNotice: "folder-missing：兩次掃描讀到的檔案相同。如果你修改過這個資料夾，請重新選擇後再檢查一次。",
    moved: "同一條規則在同一個檔案仍找到這個問題，只是行號改變；請繼續執行建議修復，完成後再次檢查。",
    persistent: "相同問題仍然存在",
    detail: "仍可觀察到這個問題，但同一個檔案中的位置從第 9 行移到第 7 行；證據雜湊有變更。",
  }],
] as const)("compared copies and a moved line are explained in %s", (locale, phrase) => {
  window.localStorage.setItem(localeStorageKey, locale);
  const beforeHash = `${"abcdef012345"}${"0".repeat(52)}`;
  const afterHash = `${"1234567890ab"}${"f".repeat(52)}`;
  const sameHash = `${"fedcba987654"}${"a".repeat(52)}`;
  const { container } = renderVerification(summary({
    diffs: [
      diff({
        id: "moved",
        state: "persistent",
        comparisonStatus: "changed",
        beforeSeverity: "high",
        afterSeverity: "high",
        explanation: "The finding remains observable, but location moved from line 9 to line 7 in the same file; evidence hashes changed.",
        changeReasons: [
          { code: "location_moved", detail: "location moved from line 9 to line 7 in the same file" },
          { code: "evidence_changed", detail: "evidence hashes changed" },
        ],
      }),
      diff({
        id: "still",
        state: "persistent",
        comparisonStatus: "still_present",
        beforeSeverity: "medium",
        afterSeverity: "medium",
      }),
    ],
    localInputChanges: [
      { assetId: "api-id", baselineSha256: beforeHash, currentSha256: afterHash, changed: true },
      { assetId: "web-id", baselineSha256: sameHash, currentSha256: sameHash, changed: false },
      {
        assetId: "folder-missing",
        baselineSha256: "[redacted snapshot hash]",
        currentSha256: "[redacted snapshot hash]",
        changed: false,
      },
    ],
  }), {
    assets: [
      { id: "api-id", name: "api" },
      { id: "web-id", name: "web" },
    ],
  });

  const copies = container.querySelector(".page-technical-details .local-folder-copies");
  expect(copies?.closest("details")?.querySelector("summary")?.textContent).toBe(phrase.copiesTitle);
  expect(copies?.textContent).toContain(phrase.changed);
  expect(copies?.textContent).toContain(phrase.same);
  expect(copies?.textContent).toContain(phrase.redacted);
  const notices = Array.from(container.querySelectorAll(".inline-notice--info")).map((notice) => notice.textContent ?? "");
  expect(notices.some((notice) => notice.includes(phrase.notice))).toBe(true);
  expect(notices.some((notice) => notice.includes(phrase.missingNotice))).toBe(true);
  expect(notices.some((notice) => notice.includes("api"))).toBe(false);
  const results = container.querySelector(".diff-list");
  const sameFiles = Array.from(container.querySelectorAll(".inline-notice--info")).find(
    (notice) => notice.textContent?.includes(phrase.notice),
  );
  expect(sameFiles).toBeTruthy();
  expect(results).toBeTruthy();
  expect(sameFiles!.compareDocumentPosition(results!) & Node.DOCUMENT_POSITION_FOLLOWING).toBeTruthy();

  const moved = Array.from(container.querySelectorAll(".diff-row")).find((item) => item.textContent?.includes("Finding moved"));
  const persistent = Array.from(container.querySelectorAll(".diff-row")).find((item) => item.textContent?.includes("Finding still"));
  expect(moved?.textContent).toContain(phrase.moved);
  expect(moved?.textContent).toContain(phrase.detail);
  expect(moved?.textContent).not.toContain(phrase.persistent);
  expect(persistent?.textContent).toContain(phrase.persistent);
  if (locale === "zh-TW") {
    expect(moved?.textContent).not.toContain("location moved from line 9 to line 7 in the same file");
  }
});

const casesHostProps = (): CasesPageProps => {
  const selected = assessmentCase();
  const run = completedRun();
  return {
    cases: [selected],
    selectedCase: selected,
    assetCount: 0,
    findingCount: 0,
    unknownSourceCount: 0,
    connectedNoAssetSourceCount: 0,
    latestRun: run,
    runs: [run],
    verificationBaselineRunId: run.id,
    nativeMode: true,
    onCreate: () => Promise.resolve(true),
    onCreateWithWorkspace: () => Promise.resolve(true),
    onChooseWorkspace: () => Promise.resolve(null),
    onSeedDemo: () => Promise.resolve(),
    onArchive: () => Promise.resolve(),
    onDelete: () => Promise.resolve(true),
    onDeleteArtifacts: () => Promise.resolve(true),
    onDismissArtifactCleanup: () => {},
    onStartNewScan: () => {},
    onOpenCase: () => {},
    onContinue: () => {},
    onOpenProgress: () => {},
    onOpenResults: () => {},
    onSelectVerificationBaseline: () => {},
    onStartRescan: () => Promise.resolve(),
    onOpenVerification: () => {},
  };
};
