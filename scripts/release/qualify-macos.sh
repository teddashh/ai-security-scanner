#!/usr/bin/env bash
set -euo pipefail

if [[ "$#" -ne 2 ]]; then
  printf 'usage: qualify-macos.sh ARTIFACT_DIRECTORY WORK_DIRECTORY\n' >&2
  exit 2
fi

artifact_directory="$(cd -- "$1" && pwd -P)"
work_directory="$2"
case "${work_directory}" in
  "${RUNNER_TEMP}"/*) ;;
  *) printf 'Qualification work directory must be below RUNNER_TEMP.\n' >&2; exit 1 ;;
esac
mkdir -p -- "${work_directory}"
work_directory="$(cd -- "${work_directory}" && pwd -P)"
mount_point="${RUNNER_TEMP}/ai-security-scanner-platform-qualification-mount"
installed_app="/Applications/ai-security-scanner Platform Qualification.app"
data_directory="${RUNNER_TEMP}/ai-security-scanner-platform-qualification-macos-data"
mounted=false
desktop_pid=""
cli=""

cleanup_on_exit() {
  status=$?
  set +e
  if [[ -n "${desktop_pid}" ]] && kill -0 "${desktop_pid}" 2>/dev/null; then
    kill "${desktop_pid}" >/dev/null 2>&1
    wait "${desktop_pid}" >/dev/null 2>&1
  fi
  if [[ "${mounted}" == true ]]; then /usr/bin/hdiutil detach "${mount_point}" >/dev/null; fi
  for exact_path in "${installed_app}" "${data_directory}" "${mount_point}"; do
    case "${exact_path}" in
      "/Applications/ai-security-scanner Platform Qualification.app"|"${RUNNER_TEMP}"/ai-security-scanner-platform-qualification*) rm -rf -- "${exact_path}" ;;
    esac
  done
  exit "${status}"
}
trap cleanup_on_exit EXIT

installer_manifest="${artifact_directory}/installers-macos-universal.json"
installer_name="$(node -e '
  const fs = require("fs");
  const manifest = JSON.parse(fs.readFileSync(process.argv[1], "utf8"));
  const matches = manifest.installers.filter((item) => item.bundleType === "dmg");
  if (matches.length !== 1 || require("path").basename(matches[0].file) !== matches[0].file) process.exit(1);
  process.stdout.write(matches[0].file);
' "${installer_manifest}")"
installer_path="${artifact_directory}/${installer_name}"
[[ -f "${installer_path}" ]]
[[ ! -e "${installed_app}" ]]

mkdir -- "${mount_point}"
PAGER=/bin/cat /usr/bin/hdiutil attach -nobrowse -readonly -mountpoint "${mount_point}" "${installer_path}" <<< 'Y'
mounted=true
shopt -s nullglob
applications=("${mount_point}/"*.app)
[[ "${#applications[@]}" -eq 1 ]]
/usr/bin/ditto "${applications[0]}" "${installed_app}"
/usr/bin/hdiutil detach "${mount_point}"
mounted=false
rmdir -- "${mount_point}"

desktop="${installed_app}/Contents/MacOS/ai-security-scanner"
egress="${installed_app}/Contents/MacOS/ai-security-scanner-egress-gateway"
broker="${installed_app}/Contents/MacOS/ai-security-scanner-bootstrap-broker"
cli="${installed_app}/Contents/MacOS/ai-security-scanner-cli"
runtime_manifest="${installed_app}/Contents/Resources/managed-runtime/manifest.json"
for installed_executable in "${desktop}" "${egress}" "${broker}" "${cli}"; do
  [[ "${installed_executable}" == /* && -f "${installed_executable}" && -x "${installed_executable}" ]]
done
[[ -f "${runtime_manifest}" ]]
node -e '
  const manifest = JSON.parse(require("fs").readFileSync(process.argv[1], "utf8"));
  if (manifest.schema_version !== "2" || typeof manifest.bundle_id !== "string" ||
      manifest.bundle_id.length === 0 || typeof manifest.runtime_version !== "string" ||
      manifest.runtime_version.length === 0 || !Array.isArray(manifest.targets) ||
      !manifest.targets.some((target) => target?.operating_system === "macos" &&
        target?.architecture === "x86_64" && target?.provider === "applehv")) {
    throw new Error("Installed macOS managed-runtime manifest is malformed or lacks its released AppleHV target.");
  }
' "${runtime_manifest}"
cp -- "${runtime_manifest}" "${work_directory}/installed-runtime-manifest.json"

"${cli}" --help >/dev/null
"${desktop}" >"${work_directory}/desktop-startup.log" 2>&1 &
desktop_pid=$!
sleep 12
if ! kill -0 "${desktop_pid}" 2>/dev/null; then
  wait "${desktop_pid}" || true
  cat "${work_directory}/desktop-startup.log" >&2
  printf 'Installed macOS desktop exited before the 12-second observation window.\n' >&2
  exit 1
fi
kill "${desktop_pid}"
wait "${desktop_pid}" || true
desktop_pid=""

mkdir -m 700 -- "${data_directory}"
# GitHub-hosted macOS runners do not support the nested virtualization required by
# the packaged AppleHV machine. Do not invoke any managed-runtime lifecycle command
# here: the evidence below records those operations as not observed instead of
# manufacturing passing status documents.
[[ ! -e "${data_directory}/managed-runtime" && ! -L "${data_directory}/managed-runtime" ]]

rm -rf -- "${installed_app}"
[[ ! -e "${installed_app}" ]]
rmdir -- "${data_directory}"
[[ ! -e "${data_directory}" ]]

export QUAL_DESKTOP="${desktop}"
export QUAL_EGRESS="${egress}"
export QUAL_BROKER="${broker}"
export QUAL_CLI="${cli}"
export QUAL_RUNTIME_MANIFEST="${runtime_manifest}"
export QUAL_DATA_DIRECTORY="${data_directory}"
export QUAL_WORK_DIRECTORY="${work_directory}"
node --input-type=module <<'NODE'
import { writeFileSync } from "node:fs";
import path from "node:path";
const reasonCode = "github_hosted_macos_nested_virtualization_unsupported";
const notObserved = (name) => ({ name, outcome: "not_observed", reasonCode });
const observations = {
  installedLayout: {
    pathsVerifiedAbsolute: true,
    desktop: process.env.QUAL_DESKTOP,
    cli: process.env.QUAL_CLI,
    companions: [
      { name: "ai-security-scanner-egress-gateway", path: process.env.QUAL_EGRESS },
      { name: "ai-security-scanner-bootstrap-broker", path: process.env.QUAL_BROKER },
      { name: "ai-security-scanner-cli", path: process.env.QUAL_CLI },
    ],
    runtimeManifestOriginalPath: process.env.QUAL_RUNTIME_MANIFEST,
  },
  desktopStartup: { outcome: "passed", observationSeconds: 12, installedExecutable: process.env.QUAL_DESKTOP },
  privateDataDirectory: process.env.QUAL_DATA_DIRECTORY,
  operations: [
    notObserved("initial_status"),
    notObserved("install"),
    notObserved("installed_status"),
    notObserved("start"),
    notObserved("running_status"),
    notObserved("stop"),
    notObserved("stopped_status"),
    notObserved("uninstall_purge"),
    notObserved("final_status"),
  ],
  containerExecution: { outcome: "not_observed", reasonCode },
  cleanup: {
    diskImageDetached: true,
    installedApplicationRemoved: true,
    privateDataRemoved: true,
    managedRuntimeState: "not_created",
    machineImageCacheState: "not_created",
  },
  installedManifestSnapshot: "installed-runtime-manifest.json",
};
writeFileSync(path.join(process.env.QUAL_WORK_DIRECTORY, "observations.json"), `${JSON.stringify(observations, null, 2)}\n`, { flag: "wx" });
NODE
