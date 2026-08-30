import { getVersion } from "@tauri-apps/api/app";
import { relaunch } from "@tauri-apps/plugin-process";
import { check, type Update } from "@tauri-apps/plugin-updater";

import {
  resolveAppUpdaterRuntime,
  validateAppUpdateManifest,
} from "./appUpdaterManifest";

export type AppUpdatePhase =
  | "unavailable"
  | "checking"
  | "current"
  | "available"
  | "downloading"
  | "installing"
  | "restarting"
  | "error";

export interface AppUpdateState {
  phase: AppUpdatePhase;
  currentVersion?: string;
  availableVersion?: string;
  publishedAt?: string;
  notes?: string;
  downloadedBytes?: number;
  totalBytes?: number;
  message?: string;
}

let pendingUpdate: Update | null = null;

const packagedTauriPlatform = import.meta.env?.TAURI_ENV_PLATFORM?.trim();
const packagedTauriArchitecture = import.meta.env?.TAURI_ENV_ARCH?.trim();

const boundedText = (value: string | undefined, maximum: number): string | undefined => {
  const normalized = value?.replaceAll("\0", "").trim();
  return normalized ? normalized.slice(0, maximum) : undefined;
};

const describeFailure = (error: unknown): string => {
  const message = error instanceof Error ? error.message : String(error);
  return boundedText(message, 600) ?? "更新服務目前無法使用。";
};

const closePendingUpdate = async () => {
  const prior = pendingUpdate;
  pendingUpdate = null;
  if (prior) await prior.close().catch(() => undefined);
};

const validateReleaseManifest = (update: Update): void => {
  validateAppUpdateManifest(
    update,
    resolveAppUpdaterRuntime(packagedTauriPlatform, packagedTauriArchitecture),
  );
};

export const checkForAppUpdate = async (): Promise<AppUpdateState> => {
  await closePendingUpdate();
  const currentVersion = await getVersion();
  try {
    const update = await check({ timeout: 15_000, allowDowngrades: false });
    if (!update) {
      return { phase: "current", currentVersion };
    }
    try {
      validateReleaseManifest(update);
    } catch (error) {
      pendingUpdate = null;
      await update.close().catch(() => undefined);
      throw error;
    }
    pendingUpdate = update;
    return {
      phase: "available",
      currentVersion: update.currentVersion,
      availableVersion: update.version,
      publishedAt: boundedText(update.date, 64),
      notes: boundedText(update.body, 2_000),
    };
  } catch (error) {
    return {
      phase: "error",
      currentVersion,
      message: describeFailure(error),
    };
  }
};

export const installAppUpdate = async (
  expectedVersion: string,
  onState: (state: AppUpdateState) => void,
): Promise<void> => {
  let update = pendingUpdate;
  if (!update || update.version !== expectedVersion) {
    await closePendingUpdate();
    update = await check({ timeout: 15_000, allowDowngrades: false });
  }
  if (!update || update.version !== expectedVersion) {
    if (update) await update.close().catch(() => undefined);
    throw new Error("可用更新已變更；請重新檢查版本後再安裝。");
  }
  try {
    validateReleaseManifest(update);
  } catch (error) {
    pendingUpdate = null;
    await update.close().catch(() => undefined);
    throw error;
  }

  pendingUpdate = update;
  let downloadedBytes = 0;
  let totalBytes: number | undefined;
  const base = {
    currentVersion: update.currentVersion,
    availableVersion: update.version,
    publishedAt: boundedText(update.date, 64),
    notes: boundedText(update.body, 2_000),
  };
  try {
    await update.downloadAndInstall((event) => {
      if (event.event === "Started") {
        totalBytes = event.data.contentLength;
        downloadedBytes = 0;
      } else if (event.event === "Progress") {
        downloadedBytes += event.data.chunkLength;
      }
      onState({
        ...base,
        phase: event.event === "Finished" ? "installing" : "downloading",
        downloadedBytes,
        totalBytes,
      });
    }, { timeout: 10 * 60_000 });
    onState({ ...base, phase: "restarting", downloadedBytes, totalBytes });
    pendingUpdate = null;
    await relaunch();
  } catch (error) {
    onState({
      ...base,
      phase: "error",
      downloadedBytes,
      totalBytes,
      message: describeFailure(error),
    });
    throw error;
  }
};
