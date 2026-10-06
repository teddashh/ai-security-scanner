import type { Asset, ConnectedSource, EngineRun, ScanRun } from "./types";

export interface LocalFolderRecheckChange {
  changed: number;
  added: number;
  removed: number;
  unchanged: number;
}

export type LocalFolderRecheckRowState = "choose_again" | "no_overlap" | "saved";

export interface LocalFolderRecheckRow {
  assetId: string;
  name: string;
  state: LocalFolderRecheckRowState;
  savedAt?: string;
  change?: LocalFolderRecheckChange;
  lastScannedAt?: string;
}

type RecheckAsset = Pick<
  Asset,
  "id" | "name" | "localInputProfile" | "questionnairePlaceholder" | "discoveredFromSourceIds" | "localCopy"
>;

type RecheckSource = Pick<ConnectedSource, "id" | "lastDiscoveredAt" | "connectedAt">;

type RecheckRun = Pick<ScanRun, "id" | "startedAt"> & {
  engineRuns: ReadonlyArray<Pick<EngineRun, "assetIds">>;
};

export interface LocalFolderRecheckInput {
  assets: readonly RecheckAsset[];
  sources: readonly RecheckSource[];
  runs: readonly RecheckRun[];
  baselineRunId?: string;
}

const parsedTime = (value: string | undefined): number | undefined => {
  if (!value) return undefined;
  const time = Date.parse(value);
  return Number.isFinite(time) ? time : undefined;
};

const latestScanStartedAt = (runs: readonly RecheckRun[], assetId: string): string | undefined => {
  let latest: { startedAt: string; time: number } | undefined;
  for (const run of runs) {
    if (!run.engineRuns.some((engineRun) => engineRun.assetIds.includes(assetId))) continue;
    const time = parsedTime(run.startedAt);
    if (time === undefined) continue;
    if (!latest || time > latest.time) latest = { startedAt: run.startedAt, time };
  }
  return latest?.startedAt;
};

const savedAtFor = (asset: RecheckAsset, sources: readonly RecheckSource[]): string | undefined => {
  if (asset.localCopy?.savedAt !== undefined) return asset.localCopy.savedAt;
  const sourceId = asset.discoveredFromSourceIds?.[0];
  const source = sourceId ? sources.find((item) => item.id === sourceId) : undefined;
  return source?.lastDiscoveredAt ?? source?.connectedAt;
};

/** Folders in the selected baseline that must be chosen again before Check fixes can read new files. */
export const localFolderRecheckRows = (
  input: LocalFolderRecheckInput,
): { rows: LocalFolderRecheckRow[]; ready: boolean } => {
  const baseline = input.baselineRunId
    ? input.runs.find((run) => run.id === input.baselineRunId)
    : undefined;
  if (!baseline) return { rows: [], ready: true };
  const scannedIds = new Set(baseline.engineRuns.flatMap((engineRun) => engineRun.assetIds));
  const rows: LocalFolderRecheckRow[] = [];
  for (const asset of input.assets) {
    if (!asset.localInputProfile || asset.questionnairePlaceholder) continue;
    if (!scannedIds.has(asset.id)) continue;
    const lastScannedAt = latestScanStartedAt(input.runs, asset.id);
    const savedAt = savedAtFor(asset, input.sources);
    const change = asset.localCopy?.change;
    const savedTime = parsedTime(savedAt);
    const scannedTime = parsedTime(lastScannedAt);
    // Equal timestamps still describe the copy that scan read.
    const chosenAgain = savedTime !== undefined && scannedTime !== undefined && savedTime > scannedTime;
    const state: LocalFolderRecheckRowState = !chosenAgain
      ? "choose_again"
      : change && change.unchanged === 0 && change.changed === 0 && change.removed > 0
        ? "no_overlap"
        : "saved";
    rows.push({
      assetId: asset.id,
      name: asset.name,
      state,
      ...(savedAt !== undefined ? { savedAt } : {}),
      ...(change ? { change } : {}),
      ...(lastScannedAt !== undefined ? { lastScannedAt } : {}),
    });
  }
  return { rows, ready: rows.every((row) => row.state !== "choose_again") };
};
