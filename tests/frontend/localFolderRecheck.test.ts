import assert from "node:assert/strict";
import test from "node:test";

import { localFolderRecheckRows, type LocalFolderRecheckRow } from "../../src/localFolderRecheck.ts";

const before = "2026-10-01T00:00:00Z";
const after = "2026-10-02T00:00:00Z";
const later = "2026-10-03T00:00:00Z";

const folder = (
  id: string,
  overrides: {
    localInputProfile?: "repository_working_tree";
    questionnairePlaceholder?: boolean;
    discoveredFromSourceIds?: string[];
    savedAt?: string;
    change?: LocalFolderRecheckRow["change"];
    omitProfile?: boolean;
    omitSavedAt?: boolean;
  } = {},
) => ({
  id,
  name: id,
  ...(overrides.omitProfile ? {} : { localInputProfile: overrides.localInputProfile ?? "repository_working_tree" as const }),
  ...(overrides.questionnairePlaceholder ? { questionnairePlaceholder: true } : {}),
  ...(overrides.discoveredFromSourceIds ? { discoveredFromSourceIds: overrides.discoveredFromSourceIds } : {}),
  ...((overrides.savedAt !== undefined || overrides.change || overrides.omitSavedAt) ? {
    localCopy: {
      sha256: "a".repeat(64),
      ...(overrides.savedAt !== undefined ? { savedAt: overrides.savedAt } : {}),
      ...(overrides.change ? { change: overrides.change } : {}),
    },
  } : {}),
});

const scan = (id: string, startedAt: string, assetIds: string[]) => ({
  id,
  startedAt,
  engineRuns: [{ assetIds }],
});

const row = (rows: LocalFolderRecheckRow[], assetId: string): LocalFolderRecheckRow => {
  const found = rows.find((item) => item.assetId === assetId);
  assert.ok(found, assetId);
  return found;
};

test("no baseline produces no rows and stays ready", () => {
  const assets = [folder("repo")];
  const runs = [scan("run-1", before, ["repo"])];
  assert.deepEqual(
    localFolderRecheckRows({ assets, sources: [], runs }),
    { rows: [], ready: true },
  );
  assert.deepEqual(
    localFolderRecheckRows({ assets, sources: [], runs, baselineRunId: "missing" }),
    { rows: [], ready: true },
  );
});

test("a website-only baseline produces no rows and stays ready", () => {
  const assets = [folder("site", { omitProfile: true })];
  const runs = [scan("run-1", before, ["site"])];
  assert.deepEqual(
    localFolderRecheckRows({ assets, sources: [], runs, baselineRunId: "run-1" }),
    { rows: [], ready: true },
  );
});

test("a folder saved before the baseline must be chosen again", () => {
  const savedBefore = localFolderRecheckRows({
    assets: [folder("repo", { savedAt: "2026-09-01T00:00:00Z" })],
    sources: [],
    runs: [scan("run-1", before, ["repo"])],
    baselineRunId: "run-1",
  });
  assert.equal(savedBefore.ready, false);
  assert.equal(row(savedBefore.rows, "repo").state, "choose_again");

  const savedAtTheSameTime = localFolderRecheckRows({
    assets: [folder("repo", { savedAt: before })],
    sources: [],
    runs: [scan("run-1", before, ["repo"])],
    baselineRunId: "run-1",
  });
  assert.equal(savedAtTheSameTime.ready, false);
  assert.equal(row(savedAtTheSameTime.rows, "repo").state, "choose_again");
});

test("a folder saved after the baseline is ready", () => {
  const change = { changed: 1, added: 2, removed: 0, unchanged: 3 };
  const result = localFolderRecheckRows({
    assets: [folder("repo", { savedAt: after, change })],
    sources: [],
    runs: [scan("run-1", before, ["repo"])],
    baselineRunId: "run-1",
  });
  assert.equal(result.ready, true);
  assert.equal(row(result.rows, "repo").state, "saved");
  assert.equal(row(result.rows, "repo").savedAt, after);
  assert.deepEqual(row(result.rows, "repo").change, change);
});

test("a second recheck after an earlier recheck run asks for the folder again", () => {
  const result = localFolderRecheckRows({
    assets: [folder("repo", { savedAt: after })],
    sources: [],
    runs: [
      scan("baseline", before, ["repo"]),
      scan("recheck", later, ["repo"]),
    ],
    baselineRunId: "baseline",
  });
  assert.equal(result.ready, false);
  assert.equal(row(result.rows, "repo").state, "choose_again");
  assert.equal(row(result.rows, "repo").lastScannedAt, later);
});

test("a missing copy timestamp falls back to the discovering source", () => {
  const fromDiscovery = localFolderRecheckRows({
    assets: [folder("repo", { omitSavedAt: true, discoveredFromSourceIds: ["source-1", "source-2"] })],
    sources: [
      { id: "source-1", lastDiscoveredAt: after },
      { id: "source-2", lastDiscoveredAt: later },
    ],
    runs: [scan("run-1", before, ["repo"])],
    baselineRunId: "run-1",
  });
  assert.equal(fromDiscovery.ready, true);
  assert.equal(row(fromDiscovery.rows, "repo").state, "saved");
  assert.equal(row(fromDiscovery.rows, "repo").savedAt, after);

  const fromConnectedAt = localFolderRecheckRows({
    assets: [folder("repo", { discoveredFromSourceIds: ["source-1"] })],
    sources: [{ id: "source-1", connectedAt: after }],
    runs: [scan("run-1", before, ["repo"])],
    baselineRunId: "run-1",
  });
  assert.equal(row(fromConnectedAt.rows, "repo").savedAt, after);
  assert.equal(row(fromConnectedAt.rows, "repo").state, "saved");

  const copyTimeWins = localFolderRecheckRows({
    assets: [folder("repo", {
      savedAt: "2026-09-01T00:00:00Z",
      discoveredFromSourceIds: ["source-1"],
    })],
    sources: [{ id: "source-1", lastDiscoveredAt: after }],
    runs: [scan("run-1", before, ["repo"])],
    baselineRunId: "run-1",
  });
  assert.equal(row(copyTimeWins.rows, "repo").savedAt, "2026-09-01T00:00:00Z");
  assert.equal(row(copyTimeWins.rows, "repo").state, "choose_again");

  const skipsLaterSources = localFolderRecheckRows({
    assets: [folder("repo", { discoveredFromSourceIds: ["missing", "source-2"] })],
    sources: [{ id: "source-2", lastDiscoveredAt: after }],
    runs: [scan("run-1", before, ["repo"])],
    baselineRunId: "run-1",
  });
  assert.equal(row(skipsLaterSources.rows, "repo").savedAt, undefined);
  assert.equal(row(skipsLaterSources.rows, "repo").state, "choose_again");
});

test("a refreshed copy with no file in common is no_overlap and still ready", () => {
  const removed = { changed: 0, added: 4, removed: 2, unchanged: 0 };
  const result = localFolderRecheckRows({
    assets: [folder("repo", { savedAt: after, change: removed })],
    sources: [],
    runs: [scan("run-1", before, ["repo"])],
    baselineRunId: "run-1",
  });
  assert.equal(result.ready, true);
  assert.equal(row(result.rows, "repo").state, "no_overlap");
  assert.deepEqual(row(result.rows, "repo").change, removed);

  const addedOnly = localFolderRecheckRows({
    assets: [folder("repo", {
      savedAt: after,
      change: { changed: 0, added: 4, removed: 0, unchanged: 0 },
    })],
    sources: [],
    runs: [scan("run-1", before, ["repo"])],
    baselineRunId: "run-1",
  });
  assert.equal(row(addedOnly.rows, "repo").state, "saved");
});

test("a questionnaire placeholder is excluded", () => {
  const result = localFolderRecheckRows({
    assets: [
      folder("placeholder", { questionnairePlaceholder: true, savedAt: after }),
      folder("repo", { savedAt: after }),
    ],
    sources: [],
    runs: [scan("run-1", before, ["placeholder", "repo"])],
    baselineRunId: "run-1",
  });
  assert.deepEqual(result.rows.map((item) => item.assetId), ["repo"]);
  assert.equal(result.ready, true);
});

test("two folders stay unready until each one is chosen again", () => {
  const result = localFolderRecheckRows({
    assets: [
      folder("first", { savedAt: after }),
      folder("second", { savedAt: "2026-09-01T00:00:00Z" }),
      folder("unscanned", { savedAt: after }),
    ],
    sources: [],
    runs: [scan("run-1", before, ["second", "first"])],
    baselineRunId: "run-1",
  });
  assert.deepEqual(result.rows.map((item) => item.assetId), ["first", "second"]);
  assert.equal(row(result.rows, "first").state, "saved");
  assert.equal(row(result.rows, "second").state, "choose_again");
  assert.equal(result.ready, false);
});
