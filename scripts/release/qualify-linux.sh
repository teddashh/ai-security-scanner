#!/usr/bin/env bash
set -euo pipefail

if [[ "$#" -ne 2 ]]; then
  printf 'usage: qualify-linux.sh ARTIFACT_DIRECTORY WORK_DIRECTORY\n' >&2
  exit 2
fi

artifact_directory="$(realpath -- "$1")"
work_directory="$(realpath -m -- "$2")"
case "${work_directory}" in
  "${RUNNER_TEMP}"/*) ;;
  *) printf 'Qualification work directory must be below RUNNER_TEMP.\n' >&2; exit 1 ;;
esac
mkdir -p -- "${work_directory}"
data_directory="${RUNNER_TEMP}/ai-security-scanner-platform-qualification-linux-data"
case "${data_directory}" in
  "${RUNNER_TEMP}"/ai-security-scanner-platform-qualification-*) ;;
  *) printf 'Refusing an unexpected qualification data directory.\n' >&2; exit 1 ;;
esac

package_name=""
cleanup_on_exit() {
  status=$?
  set +e
  if [[ -n "${package_name}" ]] && dpkg-query -W -f='${db:Status-Abbrev}' "${package_name}" 2>/dev/null | grep -q '^ii'; then
    sudo apt-get purge -y "${package_name}" >/dev/null
  fi
  if [[ -d "${data_directory}" ]]; then
    rm -rf -- "${data_directory}"
  fi
  exit "${status}"
}
trap cleanup_on_exit EXIT

installer_manifest="${artifact_directory}/installers-linux-x86_64.json"
installer_name="$(node -e '
  const fs = require("fs");
  const manifest = JSON.parse(fs.readFileSync(process.argv[1], "utf8"));
  const matches = manifest.installers.filter((item) => item.bundleType === "deb");
  if (matches.length !== 1 || require("path").basename(matches[0].file) !== matches[0].file) process.exit(1);
  process.stdout.write(matches[0].file);
' "${installer_manifest}")"
installer_path="$(realpath -- "${artifact_directory}/${installer_name}")"
[[ "$(dirname -- "${installer_path}")" == "${artifact_directory}" && -f "${installer_path}" ]]
package_name="$(dpkg-deb -f "${installer_path}" Package)"
[[ "${package_name}" == "ai-security-scanner" ]]

sudo apt-get update
sudo apt-get install -y --no-install-recommends xvfb "${installer_path}"

desktop="$(command -v ai-security-scanner)"
egress="$(command -v ai-security-scanner-egress-gateway)"
broker="$(command -v ai-security-scanner-bootstrap-broker)"
cli="$(command -v ai-security-scanner-cli)"
for installed_executable in "${desktop}" "${egress}" "${broker}" "${cli}"; do
  [[ "${installed_executable}" == /* && -f "${installed_executable}" && -x "${installed_executable}" ]]
  dpkg-query -S "${installed_executable}" | grep -Fq "${package_name}:"
done

mapfile -t runtime_manifests < <(dpkg -L "${package_name}" | grep -E '/managed-runtime/manifest\.json$')
[[ "${#runtime_manifests[@]}" -eq 1 ]]
runtime_manifest="$(realpath -- "${runtime_manifests[0]}")"
[[ -f "${runtime_manifest}" ]]
cp -- "${runtime_manifest}" "${work_directory}/installed-runtime-manifest.json"

"${cli}" --help >/dev/null
set +e
timeout --signal=TERM 12s xvfb-run --auto-servernum "${desktop}" >"${work_directory}/desktop-startup.log" 2>&1
desktop_status=$?
set -e
if [[ "${desktop_status}" -ne 124 ]]; then
  cat "${work_directory}/desktop-startup.log" >&2
  printf 'Installed Linux desktop exited before the 12-second observation window (status %s).\n' "${desktop_status}" >&2
  exit 1
fi

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

sudo apt-get purge -y "${package_name}"
package_name=""
for removed_path in "${desktop}" "${egress}" "${broker}" "${cli}" "${runtime_manifest}"; do
  [[ ! -e "${removed_path}" ]]
done
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
