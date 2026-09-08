import assert from "node:assert/strict";
import { readFile, stat } from "node:fs/promises";
import path from "node:path";
import test from "node:test";
import { fileURLToPath } from "node:url";

const REPOSITORY_ROOT = path.resolve(fileURLToPath(new URL("../../", import.meta.url)));

const CURRENT_PRODUCT_DOCUMENTS = [
  "AGENTS.md",
  "CLAUDE.md",
  "README.md",
  "README.zh-TW.md",
  "CONTRIBUTING.md",
  "SECURITY.md",
  "THIRD_PARTY.md",
  ".codex/skills/ai-security-scanner/SKILL.md",
  ".claude/skills/ai-security-scanner/SKILL.md",
  "mappings/README.md",
  "docs/architecture.md",
  "docs/engine-catalog.md",
  "docs/engine-maintenance.md",
  "docs/managed-runtime.md",
  "docs/product-audit.md",
  "docs/product-spec.md",
  "docs/provider-authorization.md",
  "docs/release/README.md",
  "docs/release/engine-image-supply-chain.md",
  "docs/research/vibescan-evaluation.md",
  "docs/threat-model.md",
  "docs/usability/iam-naive-first-run.md",
];

async function load(relativePath) {
  return readFile(path.join(REPOSITORY_ROOT, relativePath), "utf8");
}

function localMarkdownTargets(markdown) {
  const targets = [];
  const linkPattern = /!?\[[^\]]*\]\(([^)]+)\)/g;
  for (const match of markdown.matchAll(linkPattern)) {
    let target = match[1].trim();
    if (target.startsWith("<")) {
      target = target.slice(1, target.indexOf(">"));
    } else {
      target = target.split(/\s+["']/u, 1)[0];
    }
    if (target === "" || target.startsWith("#") || /^(?:https?:|mailto:)/iu.test(target)) continue;
    targets.push(decodeURIComponent(target.split("#", 1)[0]));
  }
  return targets;
}

test("the product specification records the owner's four product decisions", async () => {
  const specification = await load("docs/product-spec.md");

  assert.match(specification, /beginner quickly completes a meaningful scan and understands the result/i);
  assert.match(specification, /integrations stay as close to upstream behavior as practical/i);
  assert.match(specification, /one professional, product-owned report/i);
  assert.match(
    specification,
    /Versioning, publication, certification, and compliance positioning belong to the product owner/i,
  );
  assert.match(specification, /socket connection.*not a vulnerability scan/is);
});

test("Codex, Claude, contributors, and the operator skill use the same priorities", async () => {
  for (const document of [
    "AGENTS.md",
    "CLAUDE.md",
    "CONTRIBUTING.md",
    ".codex/skills/ai-security-scanner/SKILL.md",
    ".claude/skills/ai-security-scanner/SKILL.md",
  ]) {
    const content = await load(document);
    assert.match(content, /meaningful (?:security )?scan/i, `${document} must prioritize a meaningful scan`);
    assert.match(content, /upstream/i, `${document} must preserve upstream scanner meaning`);
    assert.match(content, /professional report|shared report/i, `${document} must use the shared report layer`);
    assert.match(content, /product owner|product-owner/i, `${document} must preserve owner authority`);
    assert.match(content, /unless the (?:product )?owner explicitly requests/i, `${document} must not invent release work`);
  }

  assert.equal(
    await load(".codex/skills/ai-security-scanner/SKILL.md"),
    await load(".claude/skills/ai-security-scanner/SKILL.md"),
    "Codex and Claude must operate the product with identical guidance",
  );
});

test("beginner-facing documentation leads to real scans and labels TCP as connectivity", async () => {
  const english = await load("README.md");
  const chinese = await load("README.zh-TW.md");

  for (const content of [english, chinese]) {
    assert.match(content, /website|網站/iu);
    assert.match(content, /project|專案/iu);
    assert.match(content, /report|報告/iu);
    assert.match(content, /TCP/u);
    assert.match(content, /not a vulnerability scan|不是漏洞掃描|不是弱點掃描|不等於弱點掃描/iu);
    assert.match(content, /Nuclei/u);
    assert.match(content, /13/u);
    assert.match(content, /19/u);
    assert.match(content, /GET/u);
    assert.match(content, /scheme:\/\/host:port/u);
  }
  assert.match(english, /entire `scheme:\/\/host:port` origin, not only the path/u);
  assert.match(chinese, /整個 `scheme:\/\/host:port` 網站來源範圍，不只是在網址中輸入的路徑/u);
});

test("release records and optional mappings do not choose the roadmap", async () => {
  const releaseIndex = await load("docs/release/README.md");
  assert.match(releaseIndex, /historical release records/i);
  assert.match(releaseIndex, /not the product roadmap/i);
  assert.match(releaseIndex, /product owner controls version numbers, release timing/is);

  const mappings = await load("mappings/README.md");
  assert.match(mappings, /optional/i);
  assert.match(mappings, /not a compliance result|不是合規結果/i);
});

test("current product documents do not contain broken local Markdown links", async () => {
  for (const document of CURRENT_PRODUCT_DOCUMENTS) {
    const content = await load(document);
    const documentDirectory = path.dirname(path.join(REPOSITORY_ROOT, document));
    for (const target of localMarkdownTargets(content)) {
      const resolved = path.resolve(documentDirectory, target);
      assert.ok(
        resolved === REPOSITORY_ROOT || resolved.startsWith(`${REPOSITORY_ROOT}${path.sep}`),
        `${document} has a local link outside the repository: ${target}`,
      );
      await assert.doesNotReject(stat(resolved), `${document} has a broken local Markdown link: ${target}`);
    }
  }
});
