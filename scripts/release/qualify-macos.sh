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
  if [[ -x "${cli}" && -d "${data_directory}" ]]; then
    "${cli}" --json --data-dir "${data_directory}" runtime managed stop --force >/dev/null 2>&1 || true
    "${cli}" --json --data-dir "${data_directory}" runtime managed uninstall --force --purge-image-cache >/dev/null 2>&1 || true
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
run_managed() {
  output_name="$1"
  shift
  "${cli}" --json --data-dir "${data_directory}" runtime managed "$@" >"${work_directory}/${output_name}.json"
  node -e 'JSON.parse(require("fs").readFileSync(process.argv[1], "utf8"))' "${work_directory}/${output_name}.json"
}
run_managed initial-status status
run_managed install install
run_managed installed-status status
run_managed start start
run_managed running-status status
run_managed container-qualification qualify
run_managed stop stop
run_managed stopped-status status
run_managed uninstall-purge uninstall --force --purge-image-cache
run_managed final-status status

for private_root in "${data_directory}/managed-runtime/versions" "${data_directory}/managed-runtime/machine-images"; do
  if [[ -d "${private_root}" ]] && find "${private_root}" -mindepth 1 -print -quit | grep -q .; then
    printf 'Managed runtime cleanup left private entries below %s.\n' "${private_root}" >&2
    exit 1
  fi
done

rm -rf -- "${installed_app}"
[[ ! -e "${installed_app}" ]]
rm -rf -- "${data_directory}"
[[ ! -e "${data_directory}" ]]

export QUAL_DESKTOP="${desktop}"
export QUAL_EGRESS="${egress}"
export QUAL_BROKER="${broker}"
export QUAL_CLI="${cli}"
export QUAL_RUNTIME_MANIFEST="${runtime_manifest}"
export QUAL_DATA_DIRECTORY="${data_directory}"
export QUAL_WORK_DIRECTORY="${work_directory}"
node --input-type=module <<'NODE'
import { readFileSync, writeFileSync } from "node:fs";
import path from "node:path";
const read = (name) => JSON.parse(readFileSync(path.join(process.env.QUAL_WORK_DIRECTORY, `${name}.json`), "utf8"));
const passed = (name, file) => ({ name, outcome: "passed", status: read(file) });
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
    passed("initial_status", "initial-status"),
    passed("install", "install"),
    passed("installed_status", "installed-status"),
    passed("start", "start"),
    passed("running_status", "running-status"),
    passed("stop", "stop"),
    passed("stopped_status", "stopped-status"),
    passed("uninstall_purge", "uninstall-purge"),
    passed("final_status", "final-status"),
  ],
  containerExecution: { outcome: "passed", result: read("container-qualification") },
  cleanup: { managedRuntimePurged: true, machineImageCachePurged: true, installerRemoved: true, privateDataRemoved: true },
  installedManifestSnapshot: "installed-runtime-manifest.json",
};
writeFileSync(path.join(process.env.QUAL_WORK_DIRECTORY, "observations.json"), `${JSON.stringify(observations, null, 2)}\n`, { flag: "wx" });
NODE
