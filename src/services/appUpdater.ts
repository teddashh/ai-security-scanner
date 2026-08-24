import { getVersion } from "@tauri-apps/api/app";
import { relaunch } from "@tauri-apps/plugin-process";
import { check, type Update } from "@tauri-apps/plugin-updater";

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

const EXPECTED_RELEASE_PATH = ["teddashh", "ai-security-scanner", "releases", "download"];
const ALLOWED_PLATFORM_KEYS = new Set([
  "linux-x86_64",
  "linux-x86_64-appimage",
  "linux-x86_64-deb",
  "linux-x86_64-rpm",
  "darwin-x86_64",
  "darwin-x86_64-app",
  "darwin-aarch64",
  "darwin-aarch64-app",
  "windows-x86_64",
  "windows-x86_64-nsis",
  "windows-x86_64-msi",
]);
const PLATFORM_PAYLOAD_SUFFIX: ReadonlyMap<string, string> = new Map([
  ["linux-x86_64", ".AppImage"],
  ["linux-x86_64-appimage", ".AppImage"],
  ["linux-x86_64-deb", ".deb"],
  ["linux-x86_64-rpm", ".rpm"],
  ["darwin-x86_64", ".app.tar.gz"],
  ["darwin-x86_64-app", ".app.tar.gz"],
  ["darwin-aarch64", ".app.tar.gz"],
  ["darwin-aarch64-app", ".app.tar.gz"],
  ["windows-x86_64", ".exe"],
  ["windows-x86_64-nsis", ".exe"],
  ["windows-x86_64-msi", ".msi"],
]);
const EQUIVALENT_PAYLOAD_KEYS = [
  ["linux-x86_64", "linux-x86_64-appimage"],
  ["darwin-x86_64", "darwin-x86_64-app", "darwin-aarch64", "darwin-aarch64-app"],
  ["windows-x86_64", "windows-x86_64-nsis"],
] as const;

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
  const raw = update.rawJson;
  if (raw.version !== update.version || !raw.platforms || typeof raw.platforms !== "object") {
    throw new Error("更新 manifest 的版本或平台資料不完整。");
  }
  const entries = Object.entries(raw.platforms as Record<string, unknown>);
  if (entries.length !== ALLOWED_PLATFORM_KEYS.size) {
    throw new Error("更新 manifest 沒有完整的支援平台集合。");
  }
  const validated = new Map<string, { url: string; signature: string }>();
  for (const [target, value] of entries) {
    if (!ALLOWED_PLATFORM_KEYS.has(target) || !value || typeof value !== "object") {
      throw new Error("更新 manifest 含有未授權的平台目標。");
    }
    const record = value as Record<string, unknown>;
    if (
      typeof record.signature !== "string" ||
      record.signature.length < 64 ||
      record.signature.length > 32 * 1024 ||
      !/^[A-Za-z0-9+/=]+$/u.test(record.signature)
    ) {
      throw new Error("更新 manifest 含有無效的簽章資料。");
    }
    if (typeof record.url !== "string" || record.url.length > 2_048) {
      throw new Error("更新 manifest 含有無效的下載位置。");
    }
    const url = new URL(record.url);
    const pathParts = url.pathname.split("/").filter(Boolean).map(decodeURIComponent);
    const payloadName = pathParts[5] ?? "";
    const expectedSuffix = PLATFORM_PAYLOAD_SUFFIX.get(target);
    if (
      url.protocol !== "https:" ||
      url.hostname !== "github.com" ||
      url.port !== "" ||
      url.username !== "" ||
      url.password !== "" ||
      url.search !== "" ||
      url.hash !== "" ||
      pathParts.length !== 6 ||
      EXPECTED_RELEASE_PATH.some((part, index) => pathParts[index] !== part) ||
      pathParts[4] !== `v${update.version}` ||
      !/^[A-Za-z0-9][A-Za-z0-9._+-]{0,254}$/u.test(payloadName) ||
      !payloadName.includes(update.version) ||
      !expectedSuffix ||
      !payloadName.endsWith(expectedSuffix)
    ) {
      throw new Error("更新 manifest 的下載位置不屬於固定 GitHub Release。");
    }
    validated.set(target, { url: record.url, signature: record.signature });
  }
  for (const group of EQUIVALENT_PAYLOAD_KEYS) {
    const first = validated.get(group[0]);
    if (!first || group.some((key) => {
      const candidate = validated.get(key);
      return !candidate || candidate.url !== first.url || candidate.signature !== first.signature;
    })) {
      throw new Error("更新 manifest 的平台 fallback 沒有綁定相同簽章 payload。");
    }
  }
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
