import { lstat } from "node:fs/promises";
import path from "node:path";

import { sha256File } from "./lib.mjs";
import { validateWindowsNsisGhostDataPreservationFixtureFile } from "./windows-nsis-ghost-recovery-evidence.mjs";
import { validateWindowsNsisUpgradeDataPreservationFixtureFile } from "./windows-nsis-upgrade-evidence.mjs";

export const WINDOWS_NSIS_DATA_PRESERVATION_FILES = Object.freeze([
  Object.freeze({
    role: "n-minus-one-upgrade-evidence",
    path: "windows-nsis-data-preservation/n-minus-one-upgrade/evidence.json",
    maximumBytes: 256 * 1024,
  }),
  Object.freeze({
    role: "n-minus-one-upgrade-report",
    path: "windows-nsis-data-preservation/n-minus-one-upgrade/beginner-report.html",
    maximumBytes: 16 * 1024 * 1024,
  }),
  Object.freeze({
    role: "ghost-repair-uninstall-evidence",
    path: "windows-nsis-data-preservation/ghost-repair-uninstall/evidence.json",
    maximumBytes: 256 * 1024,
  }),
  Object.freeze({
    role: "ghost-repair-uninstall-report",
    path: "windows-nsis-data-preservation/ghost-repair-uninstall/beginner-report.html",
    maximumBytes: 16 * 1024 * 1024,
  }),
]);

function assert(condition, message) {
  if (!condition) throw new Error(message);
}

async function exactRegularFile(root, contract) {
  const absolute = path.join(root, contract.path);
  const metadata = await lstat(absolute);
  assert(
    metadata.isFile() && !metadata.isSymbolicLink() &&
      metadata.size > 0 && metadata.size <= contract.maximumBytes,
    `${contract.path} is not one bounded regular data-preservation evidence file`,
  );
  return {
    role: contract.role,
    path: contract.path,
    bytes: metadata.size,
    sha256: await sha256File(absolute),
  };
}

export async function verifyWindowsNsisSupportingDataPreservationEvidence({
  root,
  artifactDirectory,
  version,
  tag,
  commit,
}) {
  const absoluteRoot = path.resolve(root);
  const records = [];
  for (const contract of WINDOWS_NSIS_DATA_PRESERVATION_FILES) {
    records.push(await exactRegularFile(absoluteRoot, contract));
  }

  await validateWindowsNsisUpgradeDataPreservationFixtureFile({
    file: path.join(absoluteRoot, WINDOWS_NSIS_DATA_PRESERVATION_FILES[0].path),
    beginnerReportFile: path.join(absoluteRoot, WINDOWS_NSIS_DATA_PRESERVATION_FILES[1].path),
    artifactDirectory,
    version,
    tag,
    commit,
  });
  await validateWindowsNsisGhostDataPreservationFixtureFile({
    file: path.join(absoluteRoot, WINDOWS_NSIS_DATA_PRESERVATION_FILES[2].path),
    beginnerReportFile: path.join(absoluteRoot, WINDOWS_NSIS_DATA_PRESERVATION_FILES[3].path),
    artifactDirectory,
    version,
    tag,
    commit,
  });

  // These fixtures prove bounded N-1/ghost/Repair/uninstall data preservation.
  // They do not exercise the installed desktop application's localhost journey,
  // so they can never satisfy the separate public Windows lifecycle requirement.
  return {
    state: "supporting-data-preservation-only",
    evidenceFiles: records,
    reason: "real-installed-app-localhost-lifecycle-not-observed",
  };
}
