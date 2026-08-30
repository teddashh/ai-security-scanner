import assert from "node:assert/strict";
import { readFile, stat } from "node:fs/promises";
import path from "node:path";
import test from "node:test";
import { fileURLToPath } from "node:url";

const REPOSITORY_ROOT = path.resolve(fileURLToPath(new URL("../../", import.meta.url)));

const CURRENT_PRODUCT_DOCUMENTS = [
  "README.md",
  "README.zh-TW.md",
  "CONTRIBUTING.md",
  "SECURITY.md",
  "THIRD_PARTY.md",
  "mappings/README.md",
  "docs/architecture.md",
  "docs/engine-catalog.md",
  "docs/engine-maintenance.md",
  "docs/managed-runtime.md",
  "docs/product-audit.md",
  "docs/provider-authorization.md",
  "docs/release/README.md",
  "docs/release/engine-image-supply-chain.md",
  "docs/research/vibescan-evaluation.md",
  "docs/threat-model.md",
  "docs/usability/iam-naive-first-run.md",
];

const SUBORDINATE_DOCUMENTS = CURRENT_PRODUCT_DOCUMENTS.filter(
  (document) => !["README.md", "README.zh-TW.md", "docs/product-audit.md"].includes(document),
);

const CONTRACT_ANCHORS = {
  "CONTRIBUTING.md": [
    /must not reintroduce a full-screen setup gate, global readiness, silent scope reduction, all-or-nothing execution/i,
    /admission failure blocks only execution\/distribution of that exact artifact/i,
  ],
  "SECURITY.md": [
    /must not turn an optional engine or disposable-runtime problem into a product-wide gate/i,
  ],
  "THIRD_PARTY.md": [
    /does not block the installed application, unaffected engines, saved reports, or an independently qualified platform/i,
  ],
  "mappings/README.md": [
    /optional finding\/evidence relationship layers.not scan prerequisites, coverage proof, pass\/fail results, or product-wide release gates/is,
  ],
  "docs/architecture.md": [
    /ambiguous or\s+unrelated runtime\/storage is preserved unchanged while a uniquely named isolated generation is\s+created/is,
    /admission failure is operation-scoped.*cannot block the installed app, unaffected engines, the master report, or readable unsigned export/is,
  ],
  "docs/engine-catalog.md": [
    /One missing, stale, incompatible, unlicensed, unpublished, or failed engine never erases sibling results/is,
  ],
  "docs/engine-maintenance.md": [
    /only that engine task stays `not_tested`.*admitted siblings continue/is,
  ],
  "docs/managed-runtime.md": [
    /Name resembles the product but ownership is ambiguous.*choose a new unique name.*Preserve the ambiguous registration\/storage and continue automatically/is,
    /There is no deterministic-name reclamation flow/i,
  ],
  "docs/provider-authorization.md": [
    /provider setup never blocks localhost, website, internal-network, or local-code first value/i,
  ],
  "docs/release/README.md": [
    /Only an imminent irreversible change to user\/unrelated data, execution of untrusted bytes, prohibited target contact, or a false cryptographic claim permits a hard block/is,
  ],
  "docs/release/engine-image-supply-chain.md": [
    /Failure here blocks promotion\/execution of the exact untrusted image only/is,
  ],
  "docs/research/vibescan-evaluation.md": [
    /cannot block independent source-code scans, the engines already admitted by this project, reporting/is,
  ],
  "docs/threat-model.md": [
    /ambiguous objects are preserved beside a new isolated object, and optional failure leaves independent work plus an honest partial report available/is,
  ],
  "docs/usability/iam-naive-first-run.md": [
    /evaluates only the optional AWS journey.*cannot block localhost, website, internal-network, source-code, reporting/is,
  ],
};

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
    if (
      target === "" ||
      target.startsWith("#") ||
      /^(?:https?:|mailto:)/iu.test(target)
    ) {
      continue;
    }
    targets.push(decodeURIComponent(target.split("#", 1)[0]));
  }
  return targets;
}

test("one canonical specification governs every current product document", async () => {
  const canonical = await load("docs/product-spec.md");
  assert.match(canonical, /sole source of truth for product behavior/i);
  assert.match(canonical, /A precedence banner is not enough to preserve alignment/i);

  for (const document of CURRENT_PRODUCT_DOCUMENTS) {
    const content = await load(document);
    assert.match(
      content,
      /\]\([^)]*product-spec\.md(?:#[^)]*)?\)/i,
      `${document} must link to the canonical product specification`,
    );
  }

  for (const document of SUBORDINATE_DOCUMENTS) {
    const content = await load(document);
    assert.match(
      content,
      /subordinate|not a product specification|canonical product specification.*controls/is,
      `${document} must identify itself as subordinate or explicitly defer product behavior`,
    );
  }

  assert.match(await load("README.md"), /sole source of truth for intended product behavior/i);
  assert.match(await load("README.zh-TW.md"), /預期產品行為唯一的真相來源/u);
  assert.match(
    await load("docs/product-audit.md"),
    /implementation sequence, not a second specification|Companion source of truth/is,
  );
});

test("subordinate documents retain the outcome-first decisions most prone to drift", async () => {
  for (const [document, anchors] of Object.entries(CONTRACT_ANCHORS)) {
    const content = await load(document);
    for (const anchor of anchors) {
      assert.match(content, anchor, `${document} lost the canonical decision represented by ${anchor}`);
    }
  }
});

test("release-line notes remain historical records rather than competing specifications", async () => {
  for (let minor = 1; minor <= 8; minor += 1) {
    const document = `docs/release/v0.1.${minor}.md`;
    const content = await load(document);
    assert.match(content, /Historical \/ non-normative/i, `${document} must remain non-normative`);
    assert.match(content, /canonical product specification/i, `${document} must defer to the spec`);
    assert.match(content, /does not define current product behavior, release gates, recovery, consent, or installation advice/i);
  }

  const proposal = await load("docs/release/v0.2.0.md");
  assert.match(proposal, /Historical \/ non-normative release-plan snapshot/i);
  assert.match(proposal, /all-platform qualification and 21-engine\s+framing do not override/i);
});

test("current product documents do not contain broken local Markdown links", async () => {
  for (const document of ["docs/product-spec.md", ...CURRENT_PRODUCT_DOCUMENTS]) {
    const content = await load(document);
    const documentDirectory = path.dirname(path.join(REPOSITORY_ROOT, document));
    for (const target of localMarkdownTargets(content)) {
      const resolved = path.resolve(documentDirectory, target);
      assert.ok(
        resolved === REPOSITORY_ROOT || resolved.startsWith(`${REPOSITORY_ROOT}${path.sep}`),
        `${document} has a local link outside the repository: ${target}`,
      );
      await assert.doesNotReject(
        stat(resolved),
        `${document} has a broken local Markdown link: ${target}`,
      );
    }
  }
});
