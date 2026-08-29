import { createHash } from "node:crypto";
import { readFile } from "node:fs/promises";
import path from "node:path";
import { PROJECT_ROOT, readJson, runMain } from "./lib.mjs";

const TEMPLATE_RELATIVE = "windows/nsis/installer.nsi";
const TEMPLATE_PATH = path.join(PROJECT_ROOT, "src-tauri", TEMPLATE_RELATIVE);
const PROVENANCE_PATH = path.join(
  PROJECT_ROOT,
  "src-tauri/windows/nsis/installer.provenance.json",
);

const PINNED_UPSTREAM = Object.freeze({
  schemaVersion: 1,
  upstreamRepository: "https://github.com/tauri-apps/tauri",
  upstreamTag: "tauri-cli-v2.11.4",
  upstreamCommit: "8909f221d1515955fc843808032bdc5d62209c96",
  upstreamPath: "crates/tauri-bundler/src/bundle/windows/nsis/installer.nsi",
  upstreamUrl:
    "https://raw.githubusercontent.com/tauri-apps/tauri/tauri-cli-v2.11.4/crates/tauri-bundler/src/bundle/windows/nsis/installer.nsi",
  upstreamSha256: "20f4ecc730defb71f1342eaeaec4021df13be3d843abba0effe88ea5835fa079",
  patchContract: "ai-security-scanner.bounded-v0.1.7-ghost-registration/v2",
  vendoredSha256: "71b8773dd1c7dc6c27b56fe40d4986dc496a9dca0cf5402b553e7b911bc76a77",
});

function assert(condition, message) {
  if (!condition) throw new Error(message);
}

function sha256(value) {
  return createHash("sha256").update(value).digest("hex");
}

function exactKeys(value, expected, label) {
  assert(value && typeof value === "object" && !Array.isArray(value), `${label} must be an object`);
  assert(
    JSON.stringify(Object.keys(value).sort()) === JSON.stringify([...expected].sort()),
    `${label} fields changed`,
  );
}

function replaceOnce(source, patched, upstream, label) {
  const first = source.indexOf(patched);
  assert(first !== -1, `vendored NSIS template is missing reviewed patch hunk: ${label}`);
  assert(source.indexOf(patched, first + patched.length) === -1, `reviewed NSIS patch hunk is ambiguous: ${label}`);
  return `${source.slice(0, first)}${upstream}${source.slice(first + patched.length)}`;
}

function reconstructPinnedUpstream(vendored) {
  const rewrites = [
    {
      label: "vendored provenance header",
      patched: `; Vendored from Tauri CLI's NSIS template for reproducible Windows packaging.
; Upstream tag: tauri-cli-v2.11.4
; Upstream commit: 8909f221d1515955fc843808032bdc5d62209c96
; Upstream URL: https://raw.githubusercontent.com/tauri-apps/tauri/tauri-cli-v2.11.4/crates/tauri-bundler/src/bundle/windows/nsis/installer.nsi
; Upstream SHA-256: 20f4ecc730defb71f1342eaeaec4021df13be3d843abba0effe88ea5835fa079
; Upstream license: Apache-2.0 OR MIT
; Local patch: bounded v0.1.7 ghost-registration recovery, observable transition
; receipts, and explicit unattended N-1 upgrade behavior. The release validator
; reverses these reviewed hunks and verifies both complete-file SHA-256 values.

`,
      upstream: "",
    },
    {
      label: "state variables",
      patched: `Var OldMainBinaryName
Var PreviousVersion
Var InstallTransition
Var GhostRegistrationMode
`,
      upstream: `Var OldMainBinaryName
`,
    },
    {
      label: "maintenance-page ghost bypass",
      patched: `  ; .onInit evaluates the one bounded v0.1.7 ghost registration before any
  ; page or silent/passive branching. A custom page Abort skips only this
  ; maintenance page, allowing the normal Install section to repair the exact
  ; product registration without pretending that an old uninstaller ran.
  \${If} $GhostRegistrationMode = 1
    Abort
  \${EndIf}

`,
      upstream: "",
    },
    {
      label: "previous-version receipt source",
      patched: `  StrCpy $PreviousVersion $R0
`,
      upstream: "",
    },
    {
      label: "headless normal-upgrade selection",
      patched: `  ; Passive and silent setup have no usable radio-button HWND. Make their
  ; normal upgrade behavior explicit: select the first (uninstall old version)
  ; choice. Tauri updater mode remains the separate no-uninstall path below.
  \${If} $PassiveMode = 1
    StrCpy $R1 1
  \${ElseIf} \${Silent}
    StrCpy $R1 1
  \${Else}
    \${NSD_GetState} $R2 $R1
  \${EndIf}
`,
      upstream: `  \${NSD_GetState} $R2 $R1
`,
    },
    {
      label: "old-uninstaller unattended-mode propagation",
      patched: `      \${If} $PassiveMode = 1
        StrCpy $R1 "$R1 /P" ; preserve passive mode in the old uninstaller
      \${ElseIf} \${Silent}
        StrCpy $R1 "$R1 /S" ; preserve silent mode in the old uninstaller
      \${EndIf}
`,
      upstream: `      \${IfThen} $PassiveMode = 1 \${|} StrCpy $R1 "$R1 /P" \${|} ; append /P
`,
    },
    {
      label: "updater transition receipt",
      patched: `    \${If} $PreviousVersion == "0.1.7"
      StrCpy $InstallTransition "updated-0.1.7"
    \${EndIf}
`,
      upstream: "",
    },
    {
      label: "interactive overlay transition receipts",
      patched: `      \${If} $PreviousVersion == "0.1.7"
        StrCpy $InstallTransition "overlaid-0.1.7"
      \${EndIf}
`,
      upstream: "",
    },
    {
      label: "normal-uninstaller transition receipt",
      patched: `    \${If} $WixMode <> 1
    \${AndIf} $PreviousVersion == "0.1.7"
      StrCpy $InstallTransition "uninstalled-0.1.7"
    \${EndIf}
`,
      upstream: "",
    },
    {
      label: "unconditional bounded detection",
      patched: `  ; These calls are intentionally unconditional and precede every silent,
  ; passive, custom-page, and install-section path. Qualification can therefore
  ; distinguish the bounded ghost migration from a generic silent overwrite.
  Call DetectBoundedV017GhostRegistration
  Call PreserveBoundedV017TransitionForV018Reinstall
  Call RunBoundedSilentV017Upgrade

`,
      upstream: "",
    },
    {
      label: "transition receipt registry value",
      patched: `  \${If} $InstallTransition == ""
    DeleteRegValue SHCTX "\${UNINSTKEY}" "InstallTransition"
  \${Else}
    WriteRegStr SHCTX "\${UNINSTKEY}" "InstallTransition" "$InstallTransition"
  \${EndIf}
`,
      upstream: "",
    },
    {
      label: "bounded v0.1.7 registration proof",
      patched: `Function DetectBoundedV017GhostRegistration
  StrCpy $GhostRegistrationMode 0
  StrCpy $InstallTransition ""
  ; Tauri's normal upgrade path executes the previous UninstallString before
  ; copying candidate files. v0.1.7 could leave a current-user registration
  ; behind after both installed executables had already disappeared. Accept
  ; only that one fail-closed ghost shape. This exception neither deletes the
  ; registration nor touches LocalAppData/provider/WSL state.
  ;
  ; Every field is checked independently. A different product, publisher,
  ; version, path, command, main-binary name, or any surviving executable keeps
  ; Tauri's ordinary uninstaller and abort behavior.
  !if "\${INSTALLMODE}" == "currentUser"
    ReadRegStr $R2 HKCU "\${UNINSTKEY}" "DisplayName"
    ReadRegStr $R3 HKCU "\${UNINSTKEY}" "Publisher"
    ReadRegStr $R4 HKCU "\${UNINSTKEY}" "DisplayVersion"
    ReadRegStr $R5 HKCU "\${UNINSTKEY}" "InstallLocation"
    ReadRegStr $R6 HKCU "\${UNINSTKEY}" "UninstallString"
    ReadRegStr $R7 HKCU "\${UNINSTKEY}" "MainBinaryName"
    StrCpy $R8 '$\"$LOCALAPPDATA\\\${PRODUCTNAME}$\"'
    StrCpy $R9 '$\"$LOCALAPPDATA\\\${PRODUCTNAME}\\uninstall.exe$\"'
    \${If} $R2 == "\${PRODUCTNAME}"
    \${AndIf} $R3 == "\${MANUFACTURER}"
    \${AndIf} $R4 == "0.1.7"
    \${AndIf} $R5 == $R8
    \${AndIf} $R6 == $R9
    \${AndIf} $R7 == "\${MAINBINARYNAME}.exe"
    \${AndIfNot} \${FileExists} "$LOCALAPPDATA\\\${PRODUCTNAME}\\\${MAINBINARYNAME}.exe"
    \${AndIfNot} \${FileExists} "$LOCALAPPDATA\\\${PRODUCTNAME}\\uninstall.exe"
      StrCpy $INSTDIR "$LOCALAPPDATA\\\${PRODUCTNAME}"
      StrCpy $GhostRegistrationMode 1
      StrCpy $InstallTransition "recovered-ghost-v0.1.7"
      DetailPrint "Recovering the exact incomplete ai-security-scanner v0.1.7 registration."
    \${EndIf}
  !endif
FunctionEnd

`,
      upstream: "",
    },
    {
      label: "bounded same-version transition preservation",
      patched: "",
      upstream: "",
    },
    {
      label: "bounded silent N-1 upgrade",
      patched: "",
      upstream: "",
    },
  ];
  let reconstructed = vendored;
  for (const rewrite of rewrites) {
    if (rewrite.label === "bounded v0.1.7 registration proof") {
      const start = reconstructed.indexOf("Function DetectBoundedV017GhostRegistration\n");
      const functionEnd = reconstructed.indexOf("FunctionEnd\n", start);
      assert(start !== -1 && functionEnd > start, "reviewed NSIS ghost-proof function is missing");
      const end = functionEnd + "FunctionEnd\n\n".length;
      reconstructed = `${reconstructed.slice(0, start)}${reconstructed.slice(end)}`;
      continue;
    }
    if (rewrite.label === "bounded same-version transition preservation") {
      const start = reconstructed.indexOf("Function PreserveBoundedV017TransitionForV018Reinstall\n");
      const functionEnd = reconstructed.indexOf("FunctionEnd\n", start);
      assert(start !== -1 && functionEnd > start, "reviewed NSIS same-version receipt preservation is missing");
      const end = functionEnd + "FunctionEnd\n\n".length;
      reconstructed = `${reconstructed.slice(0, start)}${reconstructed.slice(end)}`;
      continue;
    }
    if (rewrite.label === "bounded silent N-1 upgrade") {
      const start = reconstructed.indexOf("Function RunBoundedSilentV017Upgrade\n");
      const functionEnd = reconstructed.indexOf("FunctionEnd\n", start);
      assert(start !== -1 && functionEnd > start, "reviewed NSIS silent N-1 upgrade function is missing");
      const end = functionEnd + "FunctionEnd\n\n".length;
      reconstructed = `${reconstructed.slice(0, start)}${reconstructed.slice(end)}`;
      continue;
    }
    if (rewrite.label === "interactive overlay transition receipts") {
      assert(
        reconstructed.split(rewrite.patched).length === 3,
        "reviewed NSIS overlay receipt must occur in exactly two interactive branches",
      );
      reconstructed = reconstructed.replaceAll(rewrite.patched, rewrite.upstream);
      continue;
    }
    reconstructed = replaceOnce(
      reconstructed,
      rewrite.patched,
      rewrite.upstream,
      rewrite.label,
    );
  }
  return reconstructed;
}

function validateBoundedPatch(vendored) {
  const start = vendored.indexOf("Function DetectBoundedV017GhostRegistration\n");
  const end = vendored.indexOf("FunctionEnd\n", start);
  assert(start !== -1 && end > start, "bounded ghost registration function is missing");
  const proof = vendored.slice(start, end + "FunctionEnd\n".length);
  for (const required of [
    '!if "${VERSION}" == "0.1.8"',
    '!if "${INSTALLMODE}" == "currentUser"',
    'ReadRegStr $R2 HKCU "${UNINSTKEY}" "DisplayName"',
    'ReadRegStr $R3 HKCU "${UNINSTKEY}" "Publisher"',
    'ReadRegStr $R4 HKCU "${UNINSTKEY}" "DisplayVersion"',
    'ReadRegStr $R5 HKCU "${UNINSTKEY}" "InstallLocation"',
    'ReadRegStr $R6 HKCU "${UNINSTKEY}" "UninstallString"',
    'ReadRegStr $R7 HKCU "${UNINSTKEY}" "MainBinaryName"',
    'ReadRegStr $R0 HKCU "${UNINSTKEY}" "InstallTransition"',
    'StrCpy $R8 \'$\\"$LOCALAPPDATA\\${PRODUCTNAME}$\\"\'',
    'StrCpy $R9 \'$\\"$LOCALAPPDATA\\${PRODUCTNAME}\\uninstall.exe$\\"\'',
    '${If} $R2 == "${PRODUCTNAME}"',
    '${AndIf} $R3 == "${MANUFACTURER}"',
    '${AndIf} $R4 == "0.1.7"',
    '${AndIf} $R5 == $R8',
    '${AndIf} $R6 == $R9',
    '${AndIf} $R7 == "${MAINBINARYNAME}.exe"',
    '${AndIf} $R0 == ""',
    '${AndIfNot} ${FileExists} "$LOCALAPPDATA\\${PRODUCTNAME}\\${MAINBINARYNAME}.exe"',
    '${AndIfNot} ${FileExists} "$LOCALAPPDATA\\${PRODUCTNAME}\\uninstall.exe"',
    'StrCpy $InstallTransition "recovered-ghost-v0.1.7"',
  ]) {
    assert(proof.includes(required), `bounded ghost registration proof is missing: ${required}`);
  }
  for (const forbidden of [
    "EnumRegKey",
    "DeleteRegKey",
    "DeleteRegValue",
    "Delete ",
    "RMDir",
    "CopyFiles",
    "Exec ",
    "ExecWait",
    "nsExec",
    "wsl",
    "--unregister",
  ]) {
    assert(!proof.includes(forbidden), `bounded ghost registration proof mutates or broadens scope: ${forbidden}`);
  }
  const preservationStart = vendored.indexOf("Function PreserveBoundedV017TransitionForV018Reinstall\n");
  const preservationEnd = vendored.indexOf("FunctionEnd\n", preservationStart);
  assert(
    preservationStart !== -1 && preservationEnd > preservationStart,
    "bounded same-version transition preservation function is missing",
  );
  const preservation = vendored.slice(
    preservationStart,
    preservationEnd + "FunctionEnd\n".length,
  );
  for (const required of [
    '!if "${VERSION}" == "0.1.8"',
    '!if "${INSTALLMODE}" == "currentUser"',
    'ReadRegStr $R2 HKCU "${UNINSTKEY}" "DisplayName"',
    'ReadRegStr $R3 HKCU "${UNINSTKEY}" "Publisher"',
    'ReadRegStr $R4 HKCU "${UNINSTKEY}" "DisplayVersion"',
    'ReadRegStr $R5 HKCU "${UNINSTKEY}" "InstallLocation"',
    'ReadRegStr $R6 HKCU "${UNINSTKEY}" "UninstallString"',
    'ReadRegStr $R7 HKCU "${UNINSTKEY}" "MainBinaryName"',
    'ReadRegStr $R0 HKCU "${UNINSTKEY}" "InstallTransition"',
    'StrCpy $R8 \'$\\"$INSTDIR$\\"\'',
    'StrCpy $R9 \'$\\"$INSTDIR\\uninstall.exe$\\"\'',
    '${If} $R2 == "${PRODUCTNAME}"',
    '${AndIf} $R3 == "${MANUFACTURER}"',
    '${AndIf} $R4 == "0.1.8"',
    '${AndIf} $R5 == $R8',
    '${AndIf} $R6 == $R9',
    '${AndIf} $R7 == "${MAINBINARYNAME}.exe"',
    '${AndIf} ${FileExists} "$INSTDIR\\${MAINBINARYNAME}.exe"',
    '${AndIf} ${FileExists} "$INSTDIR\\uninstall.exe"',
    '${If} $R0 == "recovered-ghost-v0.1.7"',
    '${OrIf} $R0 == "uninstalled-0.1.7"',
    '${OrIf} $R0 == "updated-0.1.7"',
    '${OrIf} $R0 == "overlaid-0.1.7"',
    'StrCpy $InstallTransition $R0',
  ]) {
    assert(preservation.includes(required), `same-version transition preservation is missing: ${required}`);
  }
  for (const forbidden of [
    "EnumRegKey",
    "DeleteRegKey",
    "DeleteRegValue",
    "Delete ",
    "RMDir",
    "CopyFiles",
    "Exec ",
    "ExecWait",
    "nsExec",
    "wsl",
    "--unregister",
  ]) {
    assert(
      !preservation.includes(forbidden),
      `same-version transition preservation mutates or broadens scope: ${forbidden}`,
    );
  }
  const silentUpgradeStart = vendored.indexOf("Function RunBoundedSilentV017Upgrade\n");
  const silentUpgradeEnd = vendored.indexOf("FunctionEnd\n", silentUpgradeStart);
  assert(
    silentUpgradeStart !== -1 && silentUpgradeEnd > silentUpgradeStart,
    "bounded silent N-1 upgrade function is missing",
  );
  const silentUpgrade = vendored.slice(
    silentUpgradeStart,
    silentUpgradeEnd + "FunctionEnd\n".length,
  );
  const silentUpgradeRequired = [
    '!if "${VERSION}" == "0.1.8"',
    '!if "${INSTALLMODE}" == "currentUser"',
    '${IfNot} ${Silent}',
    '${If} $UpdateMode = 1',
    '${If} $GhostRegistrationMode = 1',
    'ReadRegStr $R2 HKCU "${UNINSTKEY}" "DisplayName"',
    'ReadRegStr $R3 HKCU "${UNINSTKEY}" "Publisher"',
    'ReadRegStr $R4 HKCU "${UNINSTKEY}" "DisplayVersion"',
    'ReadRegStr $R5 HKCU "${UNINSTKEY}" "InstallLocation"',
    'ReadRegStr $R6 HKCU "${UNINSTKEY}" "UninstallString"',
    'ReadRegStr $R7 HKCU "${UNINSTKEY}" "MainBinaryName"',
    'ReadRegStr $R0 HKCU "${UNINSTKEY}" "InstallTransition"',
    '${If} $R4 != "0.1.7"',
    'StrCpy $R8 \'$\\"$INSTDIR$\\"\'',
    'StrCpy $R9 \'$\\"$INSTDIR\\uninstall.exe$\\"\'',
    '${If} $R2 == "${PRODUCTNAME}"',
    '${AndIf} $R3 == "${MANUFACTURER}"',
    '${AndIf} $R4 == "0.1.7"',
    '${AndIf} $R5 == $R8',
    '${AndIf} $R6 == $R9',
    '${AndIf} $R7 == "${MAINBINARYNAME}.exe"',
    '${AndIf} $R0 == ""',
    '${AndIf} ${FileExists} "$INSTDIR\\${MAINBINARYNAME}.exe"',
    '${AndIf} ${FileExists} "$INSTDIR\\uninstall.exe"',
    'StrCpy $PreviousVersion "0.1.7"',
    "ExecWait '$R6 /S _?=$INSTDIR' $0",
    '${If} ${Errors}',
    '${If} $0 <> 0',
    '${If} ${FileExists} "$INSTDIR\\${MAINBINARYNAME}.exe"',
    'StrCpy $InstallTransition "uninstalled-0.1.7"',
    '${Else}',
    'SetErrorLevel 1',
    'Abort "The existing v0.1.7 registration is incomplete or does not match the reviewed upgrade path."',
  ];
  for (const required of silentUpgradeRequired) {
    assert(silentUpgrade.includes(required), `bounded silent N-1 upgrade is missing: ${required}`);
  }
  for (const forbidden of [
    "EnumRegKey",
    "HKLM",
    "DeleteRegKey",
    "DeleteRegValue",
    "Delete ",
    "RMDir",
    "CopyFiles",
    "Exec ",
    "nsExec",
    "wsl",
    "--unregister",
    "WriteRegStr",
    "WriteRegDWORD",
  ]) {
    assert(!silentUpgrade.includes(forbidden), `bounded silent N-1 upgrade broadens scope: ${forbidden}`);
  }
  assert(
    silentUpgrade.split("ExecWait").length === 2,
    "bounded silent N-1 upgrade must execute exactly one reviewed command",
  );
  assert(
    silentUpgrade.split('StrCpy $InstallTransition "uninstalled-0.1.7"').length === 2,
    "bounded silent N-1 upgrade must issue its receipt exactly once",
  );
  for (const [before, after, label] of [
    ['${IfNot} ${Silent}', '${If} $UpdateMode = 1', "silent before updater guard"],
    ['${If} $UpdateMode = 1', '${If} $GhostRegistrationMode = 1', "updater before ghost guard"],
    ['${If} $GhostRegistrationMode = 1', 'ReadRegStr $R2 HKCU', "guards before registry proof"],
    ['ReadRegStr $R0 HKCU', '${If} $R4 != "0.1.7"', "registry proof before N-1 selection"],
    ['StrCpy $PreviousVersion "0.1.7"', "ExecWait '$R6 /S _?=$INSTDIR' $0", "N-1 binding before execution"],
    ["ExecWait '$R6 /S _?=$INSTDIR' $0", '${If} ${Errors}', "execution before launch-error check"],
    ['${If} ${Errors}', '${If} $0 <> 0', "launch error before exit-code check"],
    ['${If} $0 <> 0', '${If} ${FileExists} "$INSTDIR\\${MAINBINARYNAME}.exe"', "exit code before postcondition"],
    ['${If} ${FileExists} "$INSTDIR\\${MAINBINARYNAME}.exe"', 'StrCpy $InstallTransition "uninstalled-0.1.7"', "postcondition before receipt"],
  ]) {
    assert(
      silentUpgrade.indexOf(before) !== -1 &&
        silentUpgrade.indexOf(after) > silentUpgrade.indexOf(before),
      `bounded silent N-1 upgrade ordering changed: ${label}`,
    );
  }
  const onInit = vendored.slice(vendored.indexOf("Function .onInit\n"), vendored.indexOf("FunctionEnd\n", vendored.indexOf("Function .onInit\n")));
  assert(
    onInit.includes("Call DetectBoundedV017GhostRegistration") &&
      vendored.split("Call DetectBoundedV017GhostRegistration").length === 2,
    "bounded ghost detection is not one unconditional .onInit call",
  );
  assert(
    onInit.includes("Call PreserveBoundedV017TransitionForV018Reinstall") &&
      vendored.split("Call PreserveBoundedV017TransitionForV018Reinstall").length === 2 &&
      onInit.indexOf("Call DetectBoundedV017GhostRegistration") <
        onInit.indexOf("Call PreserveBoundedV017TransitionForV018Reinstall"),
    "bounded same-version receipt preservation is not one ordered .onInit call",
  );
  assert(
    onInit.includes("Call RunBoundedSilentV017Upgrade") &&
      vendored.split("Call RunBoundedSilentV017Upgrade").length === 2 &&
      onInit.indexOf("Call PreserveBoundedV017TransitionForV018Reinstall") <
        onInit.indexOf("Call RunBoundedSilentV017Upgrade"),
    "bounded silent N-1 upgrade is not one ordered .onInit call",
  );
  assert(
    vendored.includes('WriteRegStr SHCTX "${UNINSTKEY}" "InstallTransition" "$InstallTransition"'),
    "installer does not persist an observable migration receipt",
  );
  assert(
    vendored.includes('${AndIf} $PreviousVersion == "0.1.7"') &&
      vendored.includes('StrCpy $InstallTransition "uninstalled-0.1.7"'),
    "normal NSIS upgrade does not persist an old-uninstaller receipt",
  );
  assert(
    vendored.includes('StrCpy $R1 "$R1 /P" ; preserve passive mode in the old uninstaller') &&
      vendored.includes('StrCpy $R1 "$R1 /S" ; preserve silent mode in the old uninstaller'),
    "normal unattended upgrade does not propagate its mode to the old uninstaller",
  );
  assert(
    vendored.includes('StrCpy $InstallTransition "updated-0.1.7"') &&
      vendored.split('StrCpy $InstallTransition "overlaid-0.1.7"').length === 3,
    "updater and interactive overlay transitions are not independently receipted",
  );
  for (const header of [
    `; Upstream tag: ${PINNED_UPSTREAM.upstreamTag}`,
    `; Upstream commit: ${PINNED_UPSTREAM.upstreamCommit}`,
    `; Upstream URL: ${PINNED_UPSTREAM.upstreamUrl}`,
    `; Upstream SHA-256: ${PINNED_UPSTREAM.upstreamSha256}`,
    "; Upstream license: Apache-2.0 OR MIT",
    "; Local patch: bounded v0.1.7 ghost-registration recovery, observable transition",
  ]) {
    assert(vendored.includes(header), `vendored NSIS provenance header is missing: ${header}`);
  }
}

function expectBoundedPatchMutationRejected(vendored, before, after, label) {
  const first = vendored.indexOf(before);
  assert(first !== -1, `NSIS mutation self-test input is missing: ${label}`);
  assert(
    vendored.indexOf(before, first + before.length) === -1,
    `NSIS mutation self-test input is ambiguous: ${label}`,
  );
  const mutated = `${vendored.slice(0, first)}${after}${vendored.slice(first + before.length)}`;
  let rejected = false;
  try {
    validateBoundedPatch(mutated);
  } catch {
    rejected = true;
  }
  assert(rejected, `NSIS patch validator accepted mutation: ${label}`);
}

function expectSilentUpgradeMutationRejected(vendored, before, after, label) {
  const start = vendored.indexOf("Function RunBoundedSilentV017Upgrade\n");
  const functionEnd = vendored.indexOf("FunctionEnd\n", start);
  assert(start !== -1 && functionEnd > start, "NSIS silent-upgrade mutation function is missing");
  const end = functionEnd + "FunctionEnd\n".length;
  const source = vendored.slice(start, end);
  const first = source.indexOf(before);
  assert(first !== -1, `NSIS silent-upgrade mutation input is missing: ${label}`);
  assert(
    source.indexOf(before, first + before.length) === -1,
    `NSIS silent-upgrade mutation input is ambiguous: ${label}`,
  );
  const mutatedFunction = `${source.slice(0, first)}${after}${source.slice(first + before.length)}`;
  const mutated = `${vendored.slice(0, start)}${mutatedFunction}${vendored.slice(end)}`;
  let rejected = false;
  try {
    validateBoundedPatch(mutated);
  } catch {
    rejected = true;
  }
  assert(rejected, `NSIS patch validator accepted silent-upgrade mutation: ${label}`);
}

function validateBoundedPatchMutationGuards(vendored) {
  for (const [before, after, label] of [
    [
      "  Call DetectBoundedV017GhostRegistration\n  Call PreserveBoundedV017TransitionForV018Reinstall\n  Call RunBoundedSilentV017Upgrade\n",
      "  Call DetectBoundedV017GhostRegistration\n  Call RunBoundedSilentV017Upgrade\n  Call PreserveBoundedV017TransitionForV018Reinstall\n",
      "silent upgrade call reordered before receipt preservation",
    ],
    ["  Call RunBoundedSilentV017Upgrade\n", "", "silent upgrade call removed"],
  ]) {
    expectBoundedPatchMutationRejected(vendored, before, after, label);
  }
  for (const [before, after, label] of [
    ["    ${IfNot} ${Silent}\n      Return\n    ${EndIf}\n", "", "silent-mode guard removed"],
    ["    ${If} $UpdateMode = 1\n      Return\n    ${EndIf}\n", "", "updater guard removed"],
    ["    ${If} $GhostRegistrationMode = 1\n      Return\n    ${EndIf}\n", "", "ghost guard removed"],
    ['    ${If} $R4 != "0.1.7"\n      Return\n    ${EndIf}\n', "", "N-1 version selection removed"],
    ['    ${AndIf} $R5 == $R8\n', "", "install-location proof removed"],
    ['    ${AndIf} $R6 == $R9\n', "", "uninstall-command proof removed"],
    ['    ${AndIf} $R0 == ""\n', "", "blank predecessor receipt proof removed"],
    ['    ${AndIf} ${FileExists} "$INSTDIR\\uninstall.exe"\n', "", "uninstaller presence proof removed"],
    ["      ExecWait '$R6 /S _?=$INSTDIR' $0\n", "      ExecWait '$R6 _?=$INSTDIR' $0\n", "silent flag removed from old uninstaller"],
    ['      ${If} $0 <> 0\n', '      ${If} $0 = 0\n', "old-uninstaller exit check inverted"],
    ['      ${If} ${FileExists} "$INSTDIR\\${MAINBINARYNAME}.exe"\n', '      ${IfNot} ${FileExists} "$INSTDIR\\${MAINBINARYNAME}.exe"\n', "post-uninstall file check inverted"],
    [
      "      ClearErrors\n      ExecWait '$R6 /S _?=$INSTDIR' $0\n",
      '      StrCpy $InstallTransition "uninstalled-0.1.7"\n      ClearErrors\n      ExecWait \'$R6 /S _?=$INSTDIR\' $0\n',
      "receipt written before the old uninstaller succeeds",
    ],
  ]) {
    expectSilentUpgradeMutationRejected(vendored, before, after, label);
  }
}

export async function validateWindowsNsisTemplate() {
  const [provenance, tauri, packageLock, vendored, noticeGenerator] = await Promise.all([
    readJson(PROVENANCE_PATH),
    readJson(path.join(PROJECT_ROOT, "src-tauri/tauri.conf.json")),
    readJson(path.join(PROJECT_ROOT, "package-lock.json")),
    readFile(TEMPLATE_PATH, "utf8"),
    readFile(path.join(PROJECT_ROOT, "scripts/release/generate-notices.mjs"), "utf8"),
  ]);
  exactKeys(provenance, Object.keys(PINNED_UPSTREAM), "NSIS template provenance");
  assert(
    JSON.stringify(provenance) === JSON.stringify(PINNED_UPSTREAM),
    "NSIS template provenance differs from the reviewed immutable pin",
  );
  assert(
    tauri.bundle?.windows?.nsis?.template === TEMPLATE_RELATIVE,
    "Tauri is not configured to build the reviewed custom NSIS template",
  );
  assert(
    tauri.bundle?.windows?.nsis?.installMode === "currentUser",
    "bounded NSIS ghost recovery requires the explicit current-user install mode",
  );
  assert(
    packageLock.packages?.["node_modules/@tauri-apps/cli"]?.version === "2.11.4",
    "reviewed NSIS template is not paired with the pinned Tauri CLI 2.11.4",
  );
  assert(sha256(vendored) === provenance.vendoredSha256, "vendored NSIS template digest changed");
  for (const noticeMarker of [
    "VENDORED PACKAGING SOURCE",
    "Tauri CLI NSIS installer template | tauri-cli-v2.11.4 | Apache-2.0 OR MIT",
    provenance.upstreamCommit,
    provenance.upstreamSha256,
  ]) {
    assert(
      noticeGenerator.includes(noticeMarker),
      `release third-party notice does not cover the vendored NSIS template: ${noticeMarker}`,
    );
  }
  validateBoundedPatch(vendored);
  validateBoundedPatchMutationGuards(vendored);
  const reconstructed = reconstructPinnedUpstream(vendored);
  assert(
    sha256(reconstructed) === provenance.upstreamSha256,
    "reversing the reviewed patch does not reconstruct the pinned upstream template",
  );
  process.stdout.write(
    `Validated bounded NSIS template patch against ${provenance.upstreamTag} (${provenance.upstreamCommit})\n`,
  );
}

runMain(validateWindowsNsisTemplate);
