import assert from "node:assert/strict";
import { readdirSync, readFileSync } from "node:fs";
import test from "node:test";

const workflow = readFileSync(
    new URL("../../.github/workflows/managed-egress-gateway-image.yml", import.meta.url),
    "utf8",
  ).replace(/\r\n?/gu, "\n");
const dockerfile = readFileSync(
    new URL("../../engines/images/egress-gateway/Dockerfile", import.meta.url),
    "utf8",
  ).replace(/\r\n?/gu, "\n");

test("managed egress gateway publication is explicit and immutable", () => {
  const triggerBlock = workflow.match(/^on:\n([\s\S]*?)^permissions:/mu)?.[1];
  assert.equal(triggerBlock, "  workflow_dispatch:\n\n");

  const imageTag = workflow.match(/^  IMAGE_TAG: (\S+)$/mu)?.[1];
  assert.ok(imageTag, "the immutable image tag must be statically declared");
  assert.match(
    workflow,
    new RegExp(`^  group: managed-egress-gateway-image-${imageTag.replaceAll(".", "\\.")}$`, "mu"),
  );

  const guardIndex = workflow.indexOf(
    "uses: ./.github/actions/engine-image-evidence/publication-guard",
  );
  const buildIndex = workflow.indexOf("uses: docker/build-push-action@");
  const evidenceIndex = workflow.indexOf("uses: ./.github/actions/engine-image-evidence\n");
  const promotionIndex = workflow.indexOf("uses: ./.github/actions/engine-image-evidence/promote");

  assert.ok(guardIndex >= 0, "publication guard is required");
  assert.ok(guardIndex < buildIndex, "publication guard must run before the publishing build");
  assert.match(workflow, /^        if: steps\.guard\.outputs\.should_build == 'true'$/mu);
  assert.match(
    workflow,
    /^          tags: \$\{\{ env\.IMAGE \}\}:\$\{\{ steps\.guard\.outputs\.candidate_tag \}\}$/mu,
  );
  assert.ok(buildIndex < evidenceIndex, "signed evidence must follow the candidate build");
  assert.ok(evidenceIndex < promotionIndex, "promotion must follow signed evidence");
});

test("the startup smoke expects the status schema the gateway writes", () => {
  const gatewaySource = readFileSync(
    new URL("../../src-tauri/src/bin/egress_gateway.rs", import.meta.url),
    "utf8",
  );
  const statusSchema = gatewaySource.match(
    /^const STATUS_SCHEMA_VERSION: &str = "([^"]+)";$/mu,
  )?.[1];
  assert.ok(statusSchema, "the gateway must declare its status schema version");
  const statusChecks = [
    ...workflow.matchAll(/jq -e '([^']*)' gateway-status\/status\.json/gu),
  ].map((match) => match[1]);
  assert.equal(statusChecks.length, 2, "the smoke reads the status file twice");
  for (const check of statusChecks) {
    assert.ok(
      check.includes(`.schema_version == "${statusSchema}"`),
      `the startup smoke must expect status schema ${statusSchema}: ${check}`,
    );
  }
});

test("managed egress gateway build includes the patched Cargo source", () => {
  const vendoredSourceIndex = dockerfile.indexOf(
    "COPY vendor/glib-0.18.5 vendor/glib-0.18.5",
  );
  const cargoBuildIndex = dockerfile.indexOf("cargo build --locked --release");

  assert.ok(vendoredSourceIndex >= 0, "the build context must include the vendored glib source");
  assert.ok(vendoredSourceIndex < cargoBuildIndex, "the patched Cargo source must exist before cargo build");
});

const crateSourceRoot = new URL("../../src-tauri/src/", import.meta.url);
const repoRootHref = new URL("../../", import.meta.url).href;
const includeMacro = /include_(?:bytes|str)!\(\s*"([^"]+)"\s*\)/gu;
const topLevelModule = /^(?:pub )?mod ([A-Za-z_][A-Za-z0-9_]*);$/u;

function gatedLibraryModules(libSource) {
  const lines = libSource.split("\n");
  const modules = new Set();
  for (let index = 1; index < lines.length; index += 1) {
    const declared = topLevelModule.exec(lines[index]);
    if (!declared) continue;
    if (!lines[index - 1].startsWith("#[cfg(")) continue;
    modules.add(declared[1]);
  }
  return modules;
}

function rustFilesUnder(directoryUrl, relativePrefix = "") {
  const files = [];
  for (const entry of readdirSync(directoryUrl, { withFileTypes: true })) {
    const relative = relativePrefix ? `${relativePrefix}/${entry.name}` : entry.name;
    if (entry.isDirectory()) {
      files.push(...rustFilesUnder(new URL(`${entry.name}/`, directoryUrl), relative));
      continue;
    }
    if (entry.name.endsWith(".rs")) {
      files.push({ relative, url: new URL(entry.name, directoryUrl) });
    }
  }
  return files;
}

function firstPathSegmentModule(relative) {
  const first = relative.split("/")[0];
  return first.endsWith(".rs") ? first.slice(0, -".rs".length) : first;
}

function compiledLibraryText(source) {
  const testCfg = source.indexOf("#[cfg(test)]");
  return testCfg === -1 ? source : source.slice(0, testCfg);
}

function extraTreeLibraryEmbeds() {
  const libSource = readFileSync(new URL("lib.rs", crateSourceRoot), "utf8").replace(
    /\r\n?/gu,
    "\n",
  );
  const gated = gatedLibraryModules(libSource);
  const embeds = new Set();
  for (const file of rustFilesUnder(crateSourceRoot)) {
    if (gated.has(firstPathSegmentModule(file.relative))) continue;
    const compiled = compiledLibraryText(
      readFileSync(file.url, "utf8").replace(/\r\n?/gu, "\n"),
    );
    includeMacro.lastIndex = 0;
    for (const match of compiled.matchAll(includeMacro)) {
      const literal = match[1];
      if (!literal.includes("../")) continue;
      const resolved = new URL(literal, file.url);
      if (!resolved.href.startsWith(repoRootHref)) continue;
      const repoRelative = decodeURIComponent(resolved.href.slice(repoRootHref.length));
      if (repoRelative === "src-tauri/src" || repoRelative.startsWith("src-tauri/src/")) {
        continue;
      }
      embeds.add(repoRelative);
    }
  }
  return [...embeds].sort();
}

function copySourcesBeforeCargoBuild(dockerfileText) {
  const cargoBuildIndex = dockerfileText.indexOf("cargo build --locked --release");
  const sources = [];
  let offset = 0;
  for (const line of dockerfileText.split("\n")) {
    const lineIndex = offset;
    offset += line.length + 1;
    if (lineIndex >= cargoBuildIndex) break;
    if (!line.startsWith("COPY ") || line.startsWith("COPY --from=")) continue;
    const args = line.slice("COPY ".length).trim().split(/\s+/);
    sources.push(...args.slice(0, -1));
  }
  return { cargoBuildIndex, sources };
}

function copySourceCovers(source, embedPath) {
  if (source === embedPath) return true;
  const prefix = source.endsWith("/") ? source : `${source}/`;
  return embedPath.startsWith(prefix);
}

test("managed egress gateway build copies every library embed outside src-tauri/src", () => {
  const embeds = extraTreeLibraryEmbeds();
  const { cargoBuildIndex, sources } = copySourcesBeforeCargoBuild(dockerfile);
  assert.ok(cargoBuildIndex >= 0, "cargo build --locked --release must appear in the Dockerfile");
  const uncovered = embeds.filter(
    (embedPath) => !sources.some((source) => copySourceCovers(source, embedPath)),
  );
  assert.deepEqual(
    uncovered,
    [],
    uncovered
      .map(
        (embedPath) =>
          `library embed ${embedPath} is missing from the gateway image build context`,
      )
      .join("\n"),
  );
});
