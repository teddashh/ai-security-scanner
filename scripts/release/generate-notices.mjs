import { execFileSync } from "node:child_process";
import { copyFile, mkdir, readFile } from "node:fs/promises";
import path from "node:path";
import {
  PROJECT_ROOT,
  assertSafeRelativePath,
  isSemver,
  normalizeLicense,
  parseArgs,
  readJson,
  runMain,
  writeJsonAtomic,
  writeTextAtomic,
} from "./lib.mjs";

function git(...arguments_) {
  return execFileSync("git", arguments_, {
    cwd: PROJECT_ROOT,
    encoding: "utf8",
    stdio: ["ignore", "pipe", "ignore"],
  }).trim();
}

function cargoMetadata() {
  const cargo = process.env.CARGO || "cargo";
  return JSON.parse(
    execFileSync(cargo, ["metadata", "--locked", "--format-version=1"], {
      cwd: PROJECT_ROOT,
      encoding: "utf8",
      maxBuffer: 32 * 1024 * 1024,
      stdio: ["ignore", "pipe", "inherit"],
    }),
  );
}

function npmName(lockPath, record) {
  if (typeof record.name === "string" && record.name.length > 0) {
    return record.name;
  }
  const marker = "node_modules/";
  const offset = lockPath.lastIndexOf(marker);
  return offset === -1 ? lockPath : lockPath.slice(offset + marker.length);
}

function npmInventory(lock) {
  return Object.entries(lock.packages ?? {})
    .filter(([lockPath]) => lockPath.length > 0)
    .map(([lockPath, record]) => ({
      name: npmName(lockPath, record),
      version: typeof record.version === "string" ? record.version : "UNKNOWN",
      license: normalizeLicense(record.license),
      developmentOnly: record.dev === true,
      optional: record.optional === true,
      resolved: typeof record.resolved === "string" ? record.resolved : null,
      integrity: typeof record.integrity === "string" ? record.integrity : null,
    }))
    .sort((left, right) => `${left.name}@${left.version}`.localeCompare(`${right.name}@${right.version}`));
}

function cargoInventory(metadata) {
  const unique = new Map();
  for (const record of metadata.packages ?? []) {
    if (record.source === null || record.name === "ai-security-scanner") {
      continue;
    }
    const item = {
      name: record.name,
      version: record.version,
      license: normalizeLicense(record.license),
      source: record.source,
      repository: record.repository ?? null,
    };
    unique.set(`${item.name}@${item.version}|${item.source}`, item);
  }
  return [...unique.values()].sort((left, right) =>
    `${left.name}@${left.version}`.localeCompare(`${right.name}@${right.version}`),
  );
}

async function engineInventory(catalog) {
  const records = [];
  for (const engine of catalog) {
    const planPath = engine.compatibility?.packaging_plan;
    let upstream = null;
    if (typeof planPath === "string") {
      assertSafeRelativePath(planPath);
      const plan = await readJson(path.join(PROJECT_ROOT, planPath));
      upstream = plan.source?.repository ?? null;
    }
    records.push({
      id: engine.id,
      displayName: engine.display_name,
      upstream,
      runnable: engine.compatibility?.runnable === true,
      artifactState: engine.compatibility?.artifact_state ?? "unknown",
      image: engine.image
        ? `${engine.image.repository}@${engine.image.digest}`
        : null,
      bundledInDesktopInstaller: false,
      licenseDisposition: engine.license?.disposition ?? "unknown",
      licenseRationale: engine.license?.rationale ?? null,
      sourceOfferPath: engine.license?.source_offer_path ?? null,
      blockers: Array.isArray(engine.compatibility?.blocked_by)
        ? [...engine.compatibility.blocked_by]
        : [],
    });
  }
  return records.sort((left, right) => left.id.localeCompare(right.id));
}

function dependencyNotices(version, npmPackages, cargoPackages) {
  const lines = [
    `THIRD-PARTY NOTICES FOR ai-security-scanner ${version}`,
    "",
    "This generated inventory accompanies the desktop application. It is not legal advice",
    "and does not replace the license text or NOTICE obligations of any dependency.",
    "Entries marked NOASSERTION require inspection of the resolved artifact metadata.",
    "Engine executables and OCI images are not bundled in the desktop installers; see",
    "ENGINE_NOTICES.md for those separately acquired components.",
    "The first-party ai-security-scanner-egress-gateway,",
    "ai-security-scanner-bootstrap-broker, and ai-security-scanner-cli executables are",
    "bundled beside the desktop executable and built from this repository under Apache-2.0.",
    "",
    "NPM LOCKED PACKAGES",
    "===================",
  ];
  for (const item of npmPackages) {
    const qualifiers = [item.developmentOnly ? "dev" : "runtime", item.optional ? "optional" : null]
      .filter(Boolean)
      .join(", ");
    lines.push(`${item.name} ${item.version} | ${item.license} | ${qualifiers}`);
  }
  lines.push("", "CARGO RESOLVED PACKAGES", "=======================");
  for (const item of cargoPackages) {
    lines.push(`${item.name} ${item.version} | ${item.license} | ${item.source}`);
  }
  lines.push("");
  return lines.join("\n");
}

function engineNotices(version, engines) {
  const lines = [
    `# Engine notices for ai-security-scanner ${version}`,
    "",
    "No engine executable, OCI image, rule pack, vulnerability database, provider plugin, or",
    "feed is bundled in the desktop installers represented by this notice. Engines are separate",
    "artifacts acquired only when the product's engine-install flow explicitly requests them.",
    "An entry being runnable is a compatibility statement, not a claim that it was redistributed",
    "inside this installer or that all uses are license-approved.",
    "",
    "| Engine | Runnable | Artifact state | Remote image | License disposition | Bundled |",
    "|---|---:|---|---|---|---:|",
  ];
  for (const engine of engines) {
    lines.push(
      `| ${engine.displayName} (\`${engine.id}\`) | ${engine.runnable ? "yes" : "no"} | ${engine.artifactState} | ${engine.image ? `\`${engine.image}\`` : "none"} | ${engine.licenseDisposition} | no |`,
    );
  }
  lines.push(
    "",
    "The resolved source, image digest, blockers, and source-offer path for every entry are",
    "preserved in `ENGINE_NOTICES.json`. Consult the corresponding upstream license before use.",
    "",
  );
  return lines.join("\n");
}

async function main() {
  const args = parseArgs(process.argv.slice(2));
  const packageJson = await readJson(path.join(PROJECT_ROOT, "package.json"));
  const version = typeof args.get("version") === "string" ? args.get("version") : packageJson.version;
  if (!isSemver(version)) {
    throw new Error(`release version is not strict SemVer: ${version}`);
  }
  const tag = typeof args.get("tag") === "string" ? args.get("tag") : `v${version}`;
  if (tag !== `v${version}`) {
    throw new Error(`tag ${tag} does not match version ${version}`);
  }
  const commit = typeof args.get("commit") === "string" ? args.get("commit") : git("rev-parse", "HEAD");
  if (!/^[0-9a-f]{40}$/u.test(commit)) {
    throw new Error("commit must be a full lowercase Git object ID");
  }
  const sourceDate =
    typeof args.get("source-date") === "string"
      ? args.get("source-date")
      : git("show", "-s", "--format=%cI", commit);
  if (Number.isNaN(Date.parse(sourceDate))) {
    throw new Error("source date must be an ISO-8601 timestamp");
  }
  const output = path.resolve(
    PROJECT_ROOT,
    typeof args.get("out") === "string" ? args.get("out") : "target/release-evidence",
  );
  const repository =
    typeof args.get("repository") === "string"
      ? args.get("repository")
      : "teddashh/ai-security-scanner";
  if (!/^[A-Za-z0-9_.-]+\/[A-Za-z0-9_.-]+$/u.test(repository)) {
    throw new Error("repository must be an owner/name pair");
  }

  const packageLock = await readJson(path.join(PROJECT_ROOT, "package-lock.json"));
  const catalog = await readJson(path.join(PROJECT_ROOT, "engines/catalog.json"));
  const cargo =
    typeof args.get("cargo-metadata") === "string"
      ? await readJson(path.resolve(PROJECT_ROOT, args.get("cargo-metadata")))
      : cargoMetadata();
  const npmPackages = npmInventory(packageLock);
  const cargoPackages = cargoInventory(cargo);
  const engines = await engineInventory(catalog);

  await mkdir(output, { recursive: true });
  await writeTextAtomic(
    path.join(output, "THIRD_PARTY_NOTICES.txt"),
    dependencyNotices(version, npmPackages, cargoPackages),
  );
  await writeTextAtomic(path.join(output, "ENGINE_NOTICES.md"), engineNotices(version, engines));
  await writeJsonAtomic(path.join(output, "ENGINE_NOTICES.json"), {
    schemaVersion: 1,
    product: "ai-security-scanner",
    version,
    generatedFromCommit: commit,
    bundledEngines: [],
    engines,
  });
  await copyFile(path.join(PROJECT_ROOT, "LICENSE"), path.join(output, "LICENSE.txt"));

  const metadata = {
    schemaVersion: 1,
    product: "ai-security-scanner",
    version,
    tag,
    sourceRepository: `https://github.com/${repository}`,
    sourceCommit: commit,
    sourceDate,
    distribution: {
      desktopInstallers: ["linux-x86_64", "macos-universal", "windows-x86_64"],
      bundledEngines: [],
      bundledAuxiliaryExecutables: [
        "ai-security-scanner-egress-gateway",
        "ai-security-scanner-bootstrap-broker",
        "ai-security-scanner-cli",
      ],
      engineDelivery: "separate-artifacts-not-bundled-in-desktop-installers",
    },
    security: {
      operatingSystemCodeSigning: {
        state: "not-configured",
        statement: "The release workflow does not use Apple Developer ID or Windows Authenticode credentials.",
      },
      appleNotarization: {
        state: "not-configured",
        statement: "The release workflow does not submit artifacts to Apple notarization.",
      },
      updater: {
        state: "enabled-signed",
        artifactsGenerated: true,
        signingConfigured: true,
      },
      checksums: "SHA256SUMS.txt",
      sboms: [
        `ai-security-scanner-${version}.cyclonedx.json`,
        `ai-security-scanner-${version}.spdx.json`,
      ],
      provenanceAttestation: {
        state: "required-before-publication",
        provider: "GitHub artifact attestations",
      },
    },
    inventories: {
      npmPackageCount: npmPackages.length,
      cargoPackageCount: cargoPackages.length,
      engineReferenceCount: engines.length,
    },
  };
  await writeJsonAtomic(path.join(output, "release-metadata.json"), metadata);

  process.stdout.write(
    `Generated notices for ${npmPackages.length} npm packages, ${cargoPackages.length} Cargo packages, and ${engines.length} engine references in ${output}\n`,
  );
}

runMain(main);
