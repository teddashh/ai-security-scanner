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
  patchContract: "ai-security-scanner.version-neutral-product-repair/v1",
  vendoredSha256: "9fe2b6711daff2c94d8748ce19ebed221b33a60acca25dcc3f502fd3fdb9bdcb",
});

function assert(condition, message) {
  if (!condition) throw new Error(message);
}

function sha256(value) {
  return createHash("sha256").update(value).digest("hex");
}

function block(lines) {
  return `${lines.join("\n")}\n`;
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
  assert(
    source.indexOf(patched, first + patched.length) === -1,
    `reviewed NSIS patch hunk is ambiguous: ${label}`,
  );
  return `${source.slice(0, first)}${upstream}${source.slice(first + patched.length)}`;
}

function replaceExactly(source, patched, upstream, expectedCount, label) {
  const actualCount = source.split(patched).length - 1;
  assert(actualCount === expectedCount, `${label} occurs ${actualCount} times instead of ${expectedCount}`);
  return source.replaceAll(patched, upstream);
}

function extractFunction(source, name) {
  const marker = `Function ${name}\n`;
  const start = source.indexOf(marker);
  assert(start !== -1, `NSIS function ${name} is missing`);
  assert(source.indexOf(marker, start + marker.length) === -1, `NSIS function ${name} is duplicated`);
  const functionEnd = source.indexOf("FunctionEnd\n", start);
  assert(functionEnd > start, `NSIS function ${name} has no FunctionEnd`);
  const end = functionEnd + "FunctionEnd\n".length;
  return { start, end, source: source.slice(start, end) };
}

function removeFunction(source, name) {
  const extracted = extractFunction(source, name);
  const trailingBlank = source.slice(extracted.end, extracted.end + 1) === "\n" ? 1 : 0;
  return `${source.slice(0, extracted.start)}${source.slice(extracted.end + trailingBlank)}`;
}

function assertOrdered(source, tokens, label) {
  let cursor = -1;
  for (const token of tokens) {
    const next = source.indexOf(token, cursor + 1);
    assert(next !== -1, `${label} is missing: ${token}`);
    assert(next > cursor, `${label} ordering changed near: ${token}`);
    cursor = next;
  }
}

function reconstructPinnedUpstream(vendored) {
  let reconstructed = vendored;
  const rewrites = [
    {
      label: "vendored provenance header",
      patched: block([
        "; Vendored from Tauri CLI's NSIS template for reproducible Windows packaging.",
        "; Upstream tag: tauri-cli-v2.11.4",
        "; Upstream commit: 8909f221d1515955fc843808032bdc5d62209c96",
        "; Upstream URL: https://raw.githubusercontent.com/tauri-apps/tauri/tauri-cli-v2.11.4/crates/tauri-bundler/src/bundle/windows/nsis/installer.nsi",
        "; Upstream SHA-256: 20f4ecc730defb71f1342eaeaec4021df13be3d843abba0effe88ea5835fa079",
        "; Upstream license: Apache-2.0 OR MIT",
        "; Local patch: version-neutral stale-registration and same-version repair,",
        "; data-preserving upgrade overlays, and the bounded v0.1.7 runtime transition",
        "; receipts. The release validator reverses these reviewed hunks and verifies",
        "; both complete-file SHA-256 values.",
        "",
      ]),
      upstream: "",
    },
    {
      label: "repair state variables",
      patched: block([
        "Var OldMainBinaryName",
        "Var PreviousVersion",
        "Var InstallTransition",
        "Var RegistrationOverlayMode",
      ]),
      upstream: block(["Var OldMainBinaryName"]),
    },
    {
      label: "maintenance-page repair bypass",
      patched: block([
        "  ; .onInit proves an exact current-user product registration before choosing",
        "  ; this path. Stale registrations, same-version repairs, and upgrades replace",
        "  ; only the candidate's known files and registration in place. They never run",
        "  ; an absent or older uninstaller and never touch runtime, cases, or app data.",
        "  ${If} $RegistrationOverlayMode <> 0",
        "    Abort",
        "  ${EndIf}",
        "",
      ]),
      upstream: "",
    },
    {
      label: "repair directory lock",
      patched: "!define MUI_PAGE_CUSTOMFUNCTION_PRE SkipDirectoryIfRepairOrPassive\n",
      upstream: "!define MUI_PAGE_CUSTOMFUNCTION_PRE SkipIfPassive\n",
    },
    {
      label: "previous-version receipt source",
      patched: block(["  StrCpy $PreviousVersion $R0"]),
      upstream: "",
    },
    {
      label: "headless maintenance selection",
      patched: block([
        "  ; Passive and silent setup have no usable radio-button HWND. Make their",
        "  ; normal upgrade behavior explicit: select the first (uninstall old version)",
        "  ; choice. Tauri updater mode remains the separate no-uninstall path below.",
        "  ${If} $PassiveMode = 1",
        "    StrCpy $R1 1",
        "  ${ElseIf} ${Silent}",
        "    StrCpy $R1 1",
        "  ${Else}",
        "    ${NSD_GetState} $R2 $R1",
        "  ${EndIf}",
      ]),
      upstream: block(["  ${NSD_GetState} $R2 $R1"]),
    },
    {
      label: "old-uninstaller unattended-mode propagation",
      patched: block([
        "      ${If} $PassiveMode = 1",
        '        StrCpy $R1 "$R1 /P" ; preserve passive mode in the old uninstaller',
        "      ${ElseIf} ${Silent}",
        '        StrCpy $R1 "$R1 /S" ; preserve silent mode in the old uninstaller',
        "      ${EndIf}",
      ]),
      upstream: block([
        '      ${IfThen} $PassiveMode = 1 ${|} StrCpy $R1 "$R1 /P" ${|} ; append /P',
      ]),
    },
    {
      label: "updater transition receipt",
      patched: block([
        '    ${If} $PreviousVersion == "0.1.7"',
        '      StrCpy $InstallTransition "updated-0.1.7"',
        "    ${EndIf}",
      ]),
      upstream: "",
    },
    {
      label: "interactive overlay transition receipt",
      patched: block([
        '      ${If} $PreviousVersion == "0.1.7"',
        '        StrCpy $InstallTransition "overlaid-0.1.7"',
        "      ${EndIf}",
      ]),
      upstream: "",
      count: 2,
    },
    {
      label: "old-uninstaller transition receipt",
      patched: block([
        "    ${If} $WixMode <> 1",
        '    ${AndIf} $PreviousVersion == "0.1.7"',
        '      StrCpy $InstallTransition "uninstalled-0.1.7"',
        "    ${EndIf}",
      ]),
      upstream: "",
    },
    {
      label: "unconditional product repair detection",
      patched: block([
        "  ; These calls are intentionally unconditional and precede every silent,",
        "  ; passive, custom-page, and install-section path. Product-owned binaries and",
        "  ; registration can therefore be repaired without making private data or a",
        "  ; managed runtime an installer prerequisite.",
        "  Call DetectVersionNeutralProductRepair",
        "  Call PreserveBoundedV017TransitionForV018Reinstall",
        "",
      ]),
      upstream: "",
    },
    {
      label: "transition receipt registry value",
      patched: block([
        '  ${If} $InstallTransition == ""',
        '    DeleteRegValue SHCTX "${UNINSTKEY}" "InstallTransition"',
        "  ${Else}",
        '    WriteRegStr SHCTX "${UNINSTKEY}" "InstallTransition" "$InstallTransition"',
        "  ${EndIf}",
      ]),
      upstream: "",
    },
  ];

  for (const rewrite of rewrites) {
    reconstructed = rewrite.count
      ? replaceExactly(
          reconstructed,
          rewrite.patched,
          rewrite.upstream,
          rewrite.count,
          rewrite.label,
        )
      : replaceOnce(reconstructed, rewrite.patched, rewrite.upstream, rewrite.label);
  }
  reconstructed = removeFunction(reconstructed, "DetectVersionNeutralProductRepair");
  reconstructed = removeFunction(
    reconstructed,
    "PreserveBoundedV017TransitionForV018Reinstall",
  );
  reconstructed = removeFunction(reconstructed, "SkipDirectoryIfRepairOrPassive");
  return reconstructed;
}

function modeledRepairDecision({ exactIdentity, mainBinaryPresent, uninstallerPresent, compare }) {
  if (!exactIdentity) return "normal";
  if (!mainBinaryPresent || !uninstallerPresent) return "stale_repair";
  if (compare === 0) return "same_version_repair";
  if (compare === 1) return "upgrade_overlay";
  return "normal";
}

function validateModeledDecisionTable() {
  const fixtures = [
    [{ exactIdentity: false, mainBinaryPresent: false, uninstallerPresent: false, compare: 1 }, "normal"],
    [{ exactIdentity: true, mainBinaryPresent: false, uninstallerPresent: false, compare: -1 }, "stale_repair"],
    [{ exactIdentity: true, mainBinaryPresent: false, uninstallerPresent: true, compare: 0 }, "stale_repair"],
    [{ exactIdentity: true, mainBinaryPresent: true, uninstallerPresent: false, compare: 0 }, "stale_repair"],
    [{ exactIdentity: true, mainBinaryPresent: true, uninstallerPresent: true, compare: 0 }, "same_version_repair"],
    [{ exactIdentity: true, mainBinaryPresent: true, uninstallerPresent: true, compare: 1 }, "upgrade_overlay"],
    [{ exactIdentity: true, mainBinaryPresent: true, uninstallerPresent: true, compare: -1 }, "normal"],
    [{ exactIdentity: true, mainBinaryPresent: true, uninstallerPresent: true, compare: null }, "normal"],
  ];
  for (const [input, expected] of fixtures) {
    assert(
      modeledRepairDecision(input) === expected,
      `version-neutral installer decision drifted for ${JSON.stringify(input)}`,
    );
  }
}

function validateProductRepairPatch(vendored) {
  const detector = extractFunction(vendored, "DetectVersionNeutralProductRepair").source;
  assertOrdered(
    detector,
    [
      "StrCpy $RegistrationOverlayMode 0",
      'ReadRegStr $R2 HKCU "${UNINSTKEY}" "DisplayName"',
      'ReadRegStr $R3 HKCU "${UNINSTKEY}" "Publisher"',
      'ReadRegStr $R4 HKCU "${UNINSTKEY}" "DisplayVersion"',
      'ReadRegStr $R5 HKCU "${UNINSTKEY}" "InstallLocation"',
      'ReadRegStr $R6 HKCU "${UNINSTKEY}" "UninstallString"',
      'ReadRegStr $R7 HKCU "${UNINSTKEY}" "MainBinaryName"',
      'StrCpy $R8 \'$\\"$INSTDIR$\\"\'',
      'StrCpy $R9 \'$\\"$INSTDIR\\uninstall.exe$\\"\'',
      '${If} $R2 == "${PRODUCTNAME}"',
      '${AndIf} $R3 == "${MANUFACTURER}"',
      "${AndIf} $R5 == $R8",
      "${AndIf} $R6 == $R9",
      '${AndIf} $R7 == "${MAINBINARYNAME}.exe"',
      'StrCpy $PreviousVersion $R4',
      '${If} ${FileExists} "$INSTDIR\\${MAINBINARYNAME}.exe"',
      '${AndIf} ${FileExists} "$INSTDIR\\uninstall.exe"',
      'nsis_tauri_utils::SemverCompare "${VERSION}" $R4',
      "Pop $R1",
      "StrCpy $R0 $R1",
      "${If} $R1 = 0",
      "StrCpy $RegistrationOverlayMode 2",
      "${ElseIf} $R1 = 1",
      "StrCpy $RegistrationOverlayMode 3",
      "${Else}",
      "StrCpy $RegistrationOverlayMode 1",
    ],
    "version-neutral product repair detector",
  );
  for (const required of [
    'StrCpy $InstallTransition "recovered-ghost-v0.1.7"',
    'StrCpy $InstallTransition "overlaid-0.1.7"',
    '${AndIf} $3 == ""',
  ]) {
    assert(detector.includes(required), `bounded runtime receipt bridge is missing: ${required}`);
  }
  assert(
    detector.indexOf("StrCpy $RegistrationOverlayMode 1") <
      detector.lastIndexOf('${If} $R4 == "0.1.7"'),
    "the old version incorrectly gates stale-registration repair",
  );
  assert(
    !/^\s*(?:Delete|DeleteReg|RMDir|Exec|ExecWait|nsExec|WriteReg|EnumRegKey)\b/mu.test(detector),
    "product repair detection mutates state or executes an old command",
  );
  assert(!detector.includes("--unregister"), "product repair detection claims WSL state");

  const preservation = extractFunction(
    vendored,
    "PreserveBoundedV017TransitionForV018Reinstall",
  ).source;
  for (const required of [
    '!if "${VERSION}" == "0.1.8"',
    'ReadRegStr $2 HKCU "${UNINSTKEY}" "InstallTransition"',
    '${If} $2 == "recovered-ghost-v0.1.7"',
    '${OrIf} $2 == "uninstalled-0.1.7"',
    '${OrIf} $2 == "updated-0.1.7"',
    '${OrIf} $2 == "overlaid-0.1.7"',
    "StrCpy $InstallTransition $2",
  ]) {
    assert(preservation.includes(required), `bounded receipt preservation is missing: ${required}`);
  }
  assert(
    !/^\s*(?:Delete|DeleteReg|RMDir|Exec|ExecWait|nsExec|WriteReg|EnumRegKey)\b/mu.test(
      preservation,
    ),
    "same-version receipt preservation mutates product or user state",
  );

  const page = extractFunction(vendored, "PageReinstall").source;
  assertOrdered(
    page,
    [
      "${If} $RegistrationOverlayMode <> 0",
      "Abort",
      "${EndIf}",
      'EnumRegKey $1 HKLM "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Uninstall" $0',
    ],
    "maintenance-page repair bypass",
  );
  const onInit = extractFunction(vendored, ".onInit").source;
  assert(
    onInit.split("Call DetectVersionNeutralProductRepair").length === 2,
    "product repair detector is not one unconditional .onInit call",
  );
  assertOrdered(
    onInit,
    [
      "Call RestorePreviousInstallLocation",
      "Call DetectVersionNeutralProductRepair",
      "Call PreserveBoundedV017TransitionForV018Reinstall",
    ],
    "installer initialization",
  );
  assert(
    vendored.split("!define MUI_PAGE_CUSTOMFUNCTION_PRE SkipDirectoryIfRepairOrPassive").length ===
      2,
    "repair-aware directory page hook is missing or duplicated",
  );
  const directoryGuard = extractFunction(
    vendored,
    "SkipDirectoryIfRepairOrPassive",
  ).source;
  assertOrdered(
    directoryGuard,
    [
      "${If} $RegistrationOverlayMode <> 0",
      "${OrIf} $PassiveMode = 1",
      "Abort",
      "${EndIf}",
    ],
    "repair install-directory lock",
  );
  assert(
    !vendored.includes("RunBoundedSilentV017Upgrade") &&
      !vendored.includes("DetectBoundedV017GhostRegistration"),
    "version-specific installer gate or old-uninstaller path remains",
  );

  const installSectionStart = vendored.indexOf("Section Install\n");
  const installSectionEnd = vendored.indexOf("SectionEnd\n", installSectionStart);
  assert(installSectionStart !== -1 && installSectionEnd > installSectionStart, "Install section is missing");
  const installSection = vendored.slice(installSectionStart, installSectionEnd);
  assert(
    installSection.includes('File "${MAINBINARYSRCPATH}"') &&
      installSection.includes('WriteUninstaller "$INSTDIR\\uninstall.exe"') &&
      installSection.includes('WriteRegStr SHCTX "${UNINSTKEY}" "DisplayVersion" "${VERSION}"'),
    "repair no longer replaces product binaries and registration",
  );
  for (const forbidden of [
    'RmDir /r "$APPDATA',
    'RmDir /r "$LOCALAPPDATA',
    "managed-runtime",
    "wsl",
    "--unregister",
  ]) {
    assert(!installSection.toLowerCase().includes(forbidden.toLowerCase()), `Install section touches excluded data: ${forbidden}`);
  }
}

function expectRepairMutationRejected(vendored, functionName, before, after, label) {
  const scope = extractFunction(vendored, functionName);
  const source = scope.source;
  const first = source.indexOf(before);
  assert(first !== -1, `mutation fixture is missing: ${label}`);
  assert(source.indexOf(before, first + before.length) === -1, `mutation fixture is ambiguous: ${label}`);
  const mutatedFunction = `${source.slice(0, first)}${after}${source.slice(first + before.length)}`;
  const mutated = `${vendored.slice(0, scope.start)}${mutatedFunction}${vendored.slice(scope.end)}`;
  let rejected = false;
  try {
    validateProductRepairPatch(mutated);
  } catch {
    rejected = true;
  }
  assert(rejected, `NSIS repair validator accepted mutation: ${label}`);
}

function validateMutationGuards(vendored) {
  for (const [functionName, before, after, label] of [
    ["DetectVersionNeutralProductRepair", '    ${AndIf} $R3 == "${MANUFACTURER}"\n', "", "publisher binding removed"],
    ["DetectVersionNeutralProductRepair", "    ${AndIf} $R6 == $R9\n", "", "uninstall path binding removed"],
    ["DetectVersionNeutralProductRepair", '      ${AndIf} ${FileExists} "$INSTDIR\\uninstall.exe"\n', "", "uninstaller state removed"],
    ["DetectVersionNeutralProductRepair", "          StrCpy $RegistrationOverlayMode 2\n", "          StrCpy $RegistrationOverlayMode 0\n", "same-version repair disabled"],
    ["DetectVersionNeutralProductRepair", "          StrCpy $RegistrationOverlayMode 3\n", "          StrCpy $RegistrationOverlayMode 0\n", "upgrade overlay disabled"],
    [
      "PageReinstall",
      "  ${If} $RegistrationOverlayMode <> 0\n    Abort\n  ${EndIf}\n",
      "",
      "old-uninstaller bypass removed",
    ],
    [
      "SkipDirectoryIfRepairOrPassive",
      "  ${If} $RegistrationOverlayMode <> 0\n",
      "  ${If} $RegistrationOverlayMode = 0\n",
      "repair install-directory lock disabled",
    ],
  ]) {
    expectRepairMutationRejected(vendored, functionName, before, after, label);
  }
  const detector = extractFunction(vendored, "DetectVersionNeutralProductRepair");
  const injected = `${vendored.slice(0, detector.end - "FunctionEnd\n".length)}  ExecWait '$R6' $0\nFunctionEnd\n${vendored.slice(detector.end)}`;
  let rejected = false;
  try {
    validateProductRepairPatch(injected);
  } catch {
    rejected = true;
  }
  assert(rejected, "NSIS repair validator accepted execution of the old uninstaller");
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
    "version-neutral NSIS repair requires the explicit current-user install mode",
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
  validateModeledDecisionTable();
  validateProductRepairPatch(vendored);
  validateMutationGuards(vendored);
  const reconstructed = reconstructPinnedUpstream(vendored);
  assert(
    sha256(reconstructed) === provenance.upstreamSha256,
    "reversing the reviewed patch does not reconstruct the pinned upstream template",
  );
  process.stdout.write(
    `Validated version-neutral NSIS repair against ${provenance.upstreamTag} (${provenance.upstreamCommit})\n`,
  );
}

runMain(validateWindowsNsisTemplate);
