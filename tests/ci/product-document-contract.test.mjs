import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { readFile, readdir, stat } from "node:fs/promises";
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
  "docs/README.md",
  "docs/README.zh-TW.md",
  "docs/architecture.md",
  "docs/development-status.md",
  "docs/engine-catalog.md",
  "docs/engine-alignment-handover.zh-TW.md",
  "docs/engine-maintenance.md",
  "docs/managed-runtime.md",
  "docs/product-audit.md",
  "docs/product-spec.md",
  "docs/provider-authorization.md",
  "docs/getting-started.md",
  "docs/getting-started.zh-TW.md",
  "docs/scanning-scope.md",
  "docs/scanning-scope.zh-TW.md",
  "docs/results-and-exports.md",
  "docs/results-and-exports.zh-TW.md",
  "docs/releasing.md",
  "docs/releasing.zh-TW.md",
  "docs/release/README.md",
  "docs/release/engine-image-supply-chain.md",
  "docs/research/agentic-radar-upstream-drafts.md",
  "docs/research/agentic-radar-evaluation.md",
  "docs/research/augustus-evaluation.md",
  "docs/research/fixtures/agentic-radar/README.md",
  "docs/research/fixtures/augustus/README.md",
  "docs/research/fixtures/mcp-armor/README.md",
  "docs/research/mcp-armor-evaluation.md",
  "docs/research/vibescan-evaluation.md",
  "docs/threat-model.md",
  "docs/usability/iam-naive-first-run.md",
];

async function load(relativePath) {
  return readFile(path.join(REPOSITORY_ROOT, relativePath), "utf8");
}

const AGENTIC_RADAR_RESEARCH_FIXTURES = {
  "autogen.json": [
    "autogen",
    "workflow_found",
    true,
    "640bc21afd1f7d3f588d68c38c188be922ee2be626e73fc2530207c25fd1b34e",
  ],
  "crewai.json": [
    "crewai",
    "workflow_found",
    false,
    "f8c7db002564e9968ac39cad5bd8a48b945190428a14acfa4d1446c1a02a47a8",
  ],
  "langgraph.json": [
    "langgraph",
    "workflow_found",
    true,
    "62e9fb05cd4d6896359f2c1fc8179358ba74a31c98ec5506f3caaebd568fe046",
  ],
  "n8n.json": [
    "n8n",
    "workflow_found",
    true,
    "303b48d29c05c8b5020e77964c3c43080f201abac2d5cb7697f6c29800e2c275",
  ],
  "no-supported-workflow.json": [
    "langgraph",
    "no_supported_workflow",
    true,
    "5c243e84dbb28ec1142a1335cea56519a0f415c43c45de8fb710d6098d103618",
  ],
  "openai-agents.json": [
    "openai-agents",
    "workflow_found",
    true,
    "f344d79b24d604a2ea24a216e273da766d6d309fe857fcf2d3a2812e57611127",
  ],
};
const AGENTIC_RADAR_RESEARCH_PATCH_SHA256 =
  "d32c61e4c2134141686e950a3f025c1b521a1f0096e5572c6846b65d0afb9d72";
const AUGUSTUS_RESEARCH_PATCH_SHA256 =
  "4f6c1e0d16014ac2a638ec50ebbab053b7a3c6a7320911fbff14b8541f45b59a";
const AUGUSTUS_RESEARCH_PROFILE_SHA256 =
  "9dedd3695cd38575ba4137754803e50114c5a0f868a0f71ce5fd6305377e55b4";
const AUGUSTUS_RESEARCH_ENFORCEMENT_SHA256 =
  "cd212569b48ad8186df0924cf0c86b2cbcac9bb7cb9a1bd71e1faed8a85240df";
const AUGUSTUS_RESEARCH_REJECTION_VECTORS_SHA256 =
  "3376e1757f658acbb13863584e105acc043192997ce3c02e71a73c174bedbab7";
const AUGUSTUS_RESEARCH_PREFLIGHT_SCHEMA_SHA256 =
  "eba52bc18c2954df58c127084a6408a76666083e7fa65df32a9908ff9f35cd04";
const AUGUSTUS_PRECONTACT_RULE_CODES = [
  [1, "profile_identity_and_provenance", "augustus_profile_not_admitted"],
  [2, "unresolved_dispatch_blockers", "augustus_dispatch_blocked"],
  [3, "exact_destination_and_model_binding", "augustus_scope_binding_rejected"],
  [4, "base_url_and_redirect_denial", "augustus_destination_policy_rejected"],
  [5, "denied_capabilities", "augustus_capability_rejected"],
  [6, "probe_detector_allowlist", "augustus_plan_allowlist_rejected"],
  [7, "attempt_shape", "augustus_attempt_shape_rejected"],
  [8, "prompt_corpus_attestation", "augustus_prompt_corpus_rejected"],
  [9, "token_request_and_cost_budget", "augustus_cost_budget_rejected"],
  [10, "single_connection_execution", "augustus_concurrency_policy_rejected"],
  [11, "request_rate_retry_and_timeout", "augustus_request_policy_rejected"],
  [12, "probe_scanner_and_process_deadlines", "augustus_deadline_policy_rejected"],
  [13, "process_resource_sandbox", "augustus_sandbox_policy_rejected"],
  [14, "response_and_process_output_bounds", "augustus_output_bound_rejected"],
];
const AUGUSTUS_CURRENT_MECHANICAL_EVIDENCE = [
  [1, "profile_identity_and_provenance", "rejected", [2]],
  [2, "unresolved_dispatch_blockers", "rejected", [0]],
  [3, "exact_destination_and_model_binding", "rejected", [0]],
  [4, "base_url_and_redirect_denial", "unverified", [0, 1]],
  [5, "denied_capabilities", "unverified", [0, 1]],
  [6, "probe_detector_allowlist", "rejected", [2]],
  [7, "attempt_shape", "rejected", [2]],
  [8, "prompt_corpus_attestation", "rejected", [1]],
  [9, "token_request_and_cost_budget", "rejected", [0, 1, 2]],
  [10, "single_connection_execution", "rejected", [0, 1]],
  [11, "request_rate_retry_and_timeout", "rejected", [0, 1]],
  [12, "probe_scanner_and_process_deadlines", "rejected", [0, 1]],
  [13, "process_resource_sandbox", "rejected", [0]],
  [14, "response_and_process_output_bounds", "rejected", [0, 1]],
];
const AUGUSTUS_PREFLIGHT_FIXTURE_PAIRS = [
  ["01-profile-identity", "b8d84b3209badf438256af9a6dac4b44a04900f644d4dcd7dacc2473a73223b2", "b0fa66557b9a37eab418d43d03dd48bb621433bc68e451e31a7f228818faf5a5"],
  ["02-dispatch-blockers", "190c4bf8b969e6019347292d70df4b0f7c4ad948ed2fded4dd9ff724a2943125", "5ff2e8efc83fdc873f65d48a91552d324e69da72d0eac116d3f59329cf266899"],
  ["03-scope-binding", "1dd3a038178b97e64ac8d621538afae9780a0e4fef418a73b706189d16faf6e4", "dc9a2cab3b306db1ac21f6bc9647989a557cc2f243bdc2dcf2107c68821c8288"],
  ["04-destination-policy", "e265f3da4a75ae15a588aaff83f11127446a759ea38ba84385928f2af24d744c", "8adfbb4399bc2c1289b938d7d2474ce68542c38ecc1f998df0d585c8fd31f7c0"],
  ["05-denied-capabilities", "a14356aecc683d6777d326440bada972c646c7640d6072a05a0fe2615cfc2c93", "61c206a6e415b3d8a6dcbb991abcb8899d2549edd1fdbd25e3331b1ff490b83f"],
  ["06-plan-allowlist", "2115248ea0589509bdc919c5755cfe316d5c27d86dd888d5b9c4af32ecd9c405", "318f9b66e97699cef9462f1eff1aa4d2cbcebd6df93ef8ac6625c56bd716d9d0"],
  ["07-attempt-shape", "91b74400b79360aeae6405ada941f66671c52315059b88a02583e0b3f3b6d459", "de4c671474e1d6f4f7c7eb8e1b9f0f98ecb0b9b2ebfcaee5ed411bde6479fcc4"],
  ["08-prompt-corpus", "fcc7fbc9024fb8067c7de51ab5c2052c1170c813d5657da0d95e27daa80ad388", "371288cf26361a4a57c8d0855bc45a526312ac629509a74a5de49cf817aa5e53"],
  ["09-cost-budget", "14308aa686aa34a759f05ce84650fdd2b0bf5cc5567c526ca9ce0ab6afa62f5e", "ebc43709af1eed508a26c7eabd030b5f7adf1a424d83657839debc4df46e43f5"],
  ["10-concurrency", "3b50c21ef03a4efae2af9423771cd8d1e2e3ad65b5ae0da911d01fb674c1c32c", "b778e2e4fe94749fd21f1a1bb9e67c9e11428547712e4acdccf47c9ab9bd8c33"],
  ["11-request-policy", "d9d96727a9ab8dff406fc6d9fe1679717601839d737285d70b7bb02dd9885d38", "c9df47ecf7dcd5d78e24191a95a36ca34e847052a2510fd57235e31736ac1b08"],
  ["12-deadlines", "c6382fd18deae11c30d6cb7f8a4ebd98e165c2773f78901dd4e51ead9c619014", "1f09d7b27ec0e57959abc61bbe822f16c802acca1252d2e4958152c765f5c06a"],
  ["13-sandbox", "908d1fcdd536be9a31718dd1818fe8d6ff63ccfba9da0799bad4a48b7ae36156", "289e6003878310274e3a5123e1d85184bcf9a69e0d93c4b9bf9b5dfeb3d2751f"],
  ["14-output-bounds", "65828090ea29aae481f35af32506affa3c5fc1544d979dc7e66347746fe74fa2", "1b142550a240781399bea5cd47f76d396c235c1658386b86886febd2c5ae39bb"],
];
const AUGUSTUS_PREFLIGHT_NEGATIVE_FIXTURES = {
  "accepted-output.json": "ca1e8fb881e826e12f910c74a3b9644a23ca3968edc1ae50e7faebac0fb1ffc1",
  "all-verified-input.json": "a0043709139d4632259972f585e8a0fee407471062a161cf1cf6482d66512cd4",
  "extra-argv-input.json": "e7507226a66766524e5ea6539caaf8823881cff24c19b54c5c60388574666961",
  "mismatched-error-code.json": "b0c78605017b4513359c32a42a0a24c5d74fefe1d9957fa678032ad7c991ee2a",
};
const AUGUSTUS_RESEARCH_FIXTURES = {
  "machine-complete.json": [
    true,
    [],
    "8482446756cdcd079d8349aa5ac4c828092e7ec4236dae3b43ea5d7f0921f52b",
  ],
  "machine-count-mismatch.json": [
    false,
    ["count_mismatch"],
    "d94b8616c134194f7c8a0ce11e2d2167fd611a4b1117c067347cd4d006eade19",
  ],
  "machine-detector-warning.json": [
    false,
    ["detector_failed"],
    "1fc37120cb27660f1958f30f6ccdbd03aa5d64ff446e637aff671d81342dd2f7",
  ],
};
const MCP_ARMOR_RESEARCH_PATCH_SHA256 =
  "ae7732b5f9c922fbf2bee54e0246cccde6e1e5af829db112eb0f948cbd424122";
const MCP_ARMOR_RESEARCH_FIXTURES = {
  "config-clean.json": [true, "7df09184de483652621090124e0b5aa593ad08552a3fe4527865b0712f78742f"],
  "config-disabled.json": [true, "1932bd98c099da927f00f4e6c94f2dbbe9a8eb3d87c5039d0b60a0561f0c5550"],
  "config-findings.json": [true, "8a94b0b7aa717b106896bf3e86c5da063ab5f8023fcff2b97cac85990a72cffa"],
  "config-partial.json": [false, "804519c14a8e265ef82010c5836a7354aa23732273bf9a3a2e3e487957258669"],
};

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

test("the product specification records the owner's five product decisions", async () => {
  const specification = await load("docs/product-spec.md");

  assert.match(specification, /beginner quickly completes a meaningful scan and understands the result/i);
  assert.match(specification, /integrations stay as close to upstream behavior as practical/i);
  assert.match(specification, /one professional, product-owned report/i);
  assert.match(
    specification,
    /Versioning, publication, certification, and compliance positioning belong to the product owner/i,
  );
  assert.match(specification, /concise first and detailed on demand/i);
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
    assert.match(content, /active work stays in Progress|active scans remain in Progress|keep active work in Progress/i, `${document} must keep active scans out of reports`);
    assert.match(content, /defensive caveat walls/i, `${document} must keep defensive prose out of the primary path`);
  }

  assert.equal(
    await load(".codex/skills/ai-security-scanner/SKILL.md"),
    await load(".claude/skills/ai-security-scanner/SKILL.md"),
    "Codex and Claude must operate the product with identical guidance",
  );
});

test("beginner HTML export documents the closed report locales", async () => {
  for (const relativePath of [
    "docs/getting-started.md",
    "docs/getting-started.zh-TW.md",
    "docs/results-and-exports.md",
    "docs/results-and-exports.zh-TW.md",
  ]) {
    const content = await load(relativePath);
    assert.match(content, /--locale zh-Hant/u, relativePath);
    assert.match(content, /--locale en/u, relativePath);
  }
});

test("beginner documentation leads with the three scan paths and one report", async () => {
  const english = await load("README.md");
  const chinese = await load("README.zh-TW.md");
  const website = await load("docs/index.html");
  const catalog = JSON.parse(await load("engines/catalog.json"));
  const runnableCount = catalog.filter(
    (engine) => engine.status === "integrated" && engine.compatibility?.runnable === true,
  ).length;

  for (const content of [english, chinese]) {
    assert.match(content, /website|網站/iu);
    assert.match(content, /project|專案/iu);
    assert.match(content, /report|報告/iu);
    assert.match(content, /TCP/u);
    assert.match(content, /Nuclei/u);
    assert.match(content, /read-only|唯讀/u);
    assert.match(content, /internal system|內部系統/iu);
    assert.match(content, /Review and start|確認後開始/u);
    assert.match(content, /scanning-scope(?:\.zh-TW)?\.md/u);
  }
  assert.match(english, /One report for every selected asset/u);
  assert.match(chinese, /所有資產集中在一份報告/u);
  assert.match(english, new RegExp(`runnable engine set integrates ${runnableCount} upstream projects`, "iu"));
  assert.match(chinese, new RegExp(`可執行的引擎集合整合了 ${runnableCount} 個上游專案`, "u"));
  assert.match(website, new RegExp(`${runnableCount} runnable upstream projects`, "iu"));
  assert.match(website, new RegExp(`${runnableCount} 個可執行的上游專案`, "u"));
  for (const content of [english, chinese, website]) {
    assert.match(content, /experimental, non-dispatchable|實驗性、不可派送/u);
    assert.match(content, /not (?:current |counted as )?scan capabilities|不(?:計為|是目前的)掃描能力/u);
  }
});

test("scope documentation keeps exact website and connectivity boundaries in technical detail", async () => {
  const english = await load("docs/scanning-scope.md");
  const chinese = await load("docs/scanning-scope.zh-TW.md");

  for (const content of [english, chinese]) {
    assert.match(content, /scheme:\/\/host:port/u);
    assert.match(content, /Nuclei/u);
    assert.match(content, /read-only|唯讀/u);
    assert.match(content, /follow redirects|跟隨重新導向/u);
    assert.match(content, /127\.0\.0\.1:9001/u);
    assert.match(content, /not a vulnerability scan|不是弱點掃描/u);
  }
  assert.match(english, /other paths on the same origin/u);
  assert.match(chinese, /同一 origin 內的其他 path/u);
});

test("release records and optional mappings do not choose the roadmap", async () => {
  const releaseIndex = await load("docs/release/README.md");
  assert.match(releaseIndex, /historical release records/i);
  assert.match(releaseIndex, /not the product roadmap/i);
  assert.match(releaseIndex, /product owner controls version numbers, release timing/is);

  const mappings = await load("mappings/README.md");
  assert.match(mappings, /optional/i);
  assert.match(mappings, /not a compliance result|不是合規結果/i);
  assert.match(
    mappings,
    /Every\s+AIDEFEND and OWASP Top 10 for LLM Applications control must declare either\s+`ai_system` or `ai_generated_artifact`/iu,
  );
  assert.match(
    mappings,
    /Only a CWE identifier assigned by the upstream scanner can select a published\s+OWASP Top 10 2021 category/iu,
  );

  const architecture = await load("docs/architecture.md");
  assert.match(
    architecture,
    /Both AIDEFEND and OWASP Top 10 for LLM Applications coordinates use the same control-level\s+`applicability` gate/iu,
  );

  const threatModel = await load("docs/threat-model.md");
  assert.match(
    threatModel,
    /explicit control-level applicability for both AI-gated frameworks/iu,
  );
  assert.match(threatModel, /does not satisfy or invent an AIDEFEND or\s+OWASP LLM applicability state/iu);
});

test("public development status stays catalog-backed and excludes local handoff detail", async () => {
  const ciTestDirectory = path.join(REPOSITORY_ROOT, "tests", "ci");
  const ciTestFiles = (await readdir(ciTestDirectory)).filter((name) => name.endsWith(".test.mjs"));
  const ciTestSources = await Promise.all(
    ciTestFiles.map((name) => readFile(path.join(ciTestDirectory, name), "utf8")),
  );
  const ciTestCount = ciTestSources.reduce(
    (count, source) => count + (source.match(/^test\(/gmu)?.length ?? 0),
    0,
  );
  const [statusContent, catalogContent, ignoreContent] = await Promise.all([
    load("docs/development-status.md"),
    load("engines/catalog.json"),
    load(".gitignore"),
  ]);
  const catalog = JSON.parse(catalogContent);
  const integrated = catalog.filter(
    (engine) => engine.status === "integrated" && engine.compatibility?.runnable === true,
  );
  const experimental = catalog.filter((engine) => engine.status === "experimental");
  const publicBlockerTerms = {
    "garak": [/No managed image/iu, /model-endpoint scope grant/iu, /credential path/iu],
    "agentic-radar": [/No managed image/iu, /typed framework-selection path/iu, /accepted upstream release/iu],
    "mcp-armor": [/No verified published digest/iu],
    "zap": [/No scope-grant profile/iu, /automation plan/iu, /requests-per-second/iu],
  };

  assert.equal(integrated.length + experimental.length, catalog.length);
  assert.match(
    statusContent,
    new RegExp(
      `contains ${catalog.length} records: ${integrated.length} integrated, runnable engines and ${experimental.length} experimental\\s+integrations that remain non-runnable`,
      "iu",
    ),
  );
  assert.ok(ciTestCount > 0, "CI test census must find top-level tests");
  assert.match(statusContent, new RegExp(`CI document and contract tests: ${ciTestCount} tests`, "u"));
  for (const engine of experimental) {
    assert.equal(engine.compatibility?.runnable, false, `${engine.id} must remain non-runnable`);
    assert.equal(engine.default_enabled, false, `${engine.id} must not be default-enabled`);
    if (engine.image !== null) {
      // A verified upstream artifact may exist before the product can dispatch it. What must
      // never happen is an experimental record claiming a project-managed publication.
      assert.equal(
        engine.compatibility?.artifact_state,
        "verified_upstream_image",
        `${engine.id} may only name an image when it is a verified upstream artifact`,
      );
      assert.ok(
        !engine.image.repository.startsWith("ghcr.io/teddashh/"),
        `${engine.id} must not claim a project-managed image while experimental`,
      );
    }
    assert.ok(engine.compatibility?.blocked_by?.length > 0, `${engine.id} must retain blockers`);
    const statusRowPrefix = `| ${engine.display_name} |`.toLowerCase();
    const statusRow = statusContent
      .split("\n")
      .find((line) => line.toLowerCase().startsWith(statusRowPrefix));
    assert.ok(statusRow, `${engine.id} must appear in development status`);
    const blockerTerms = publicBlockerTerms[engine.id];
    assert.equal(
      blockerTerms?.length,
      engine.compatibility.blocked_by.length,
      `${engine.id} must account for every catalog blocker in public status`,
    );
    for (const term of blockerTerms) assert.match(statusRow, term, `${engine.id} omits a blocker`);
  }

  assert.equal(catalog.some((engine) => engine.id === "augustus"), false);
  const augustusStatusRow = statusContent
    .split("\n")
    .find((line) => line.startsWith("| Augustus |"));
  assert.ok(augustusStatusRow, "Augustus must appear in public development status");
  for (const term of [
    /Research-only/iu,
    /No production catalog entry/iu,
    /adapter/iu,
    /launcher/iu,
    /provider connection/iu,
    /credential path/iu,
    /dispatch path/iu,
  ]) {
    assert.match(augustusStatusRow, term, "Augustus public status omits a production boundary");
  }
  assert.match(statusContent, /^## Current blockers$/mu);
  assert.match(
    statusContent,
    /blockers describe fail-closed admission state; they do not authorize a publication or release\s+plan/iu,
  );
  assert.doesNotMatch(statusContent, /^## Open work$/mu);
  assert.doesNotMatch(
    statusContent,
    /(?:\/home\/|HANDOFF-CODEX|session(?: id| uuid)?|\b(?:Ted|Codex|Claude)\b|\b[0-9a-f]{7,40}\b)/iu,
  );
  assert.match(ignoreContent, /^docs\/HANDOFF-\*\.local\.md$/mu);

  for (const document of [
    "README.md",
    "README.zh-TW.md",
    "docs/README.md",
    "docs/README.zh-TW.md",
    "docs/PRODUCT-DOCTRINE.md",
  ]) {
    assert.doesNotMatch(await load(document), /HANDOFF-CODEX/u, `${document} must use public status`);
  }
});

test("experimental engine documentation distinguishes local builds from published artifacts", async () => {
  const engineCatalog = await load("docs/engine-catalog.md");

  assert.match(engineCatalog, /all remain\s+`runnable: false`/iu);
  assert.match(engineCatalog, /None has a verified published image digest/iu);
  assert.match(
    engineCatalog,
    /local build candidate[\s\S]*build evidence only[\s\S]*does not make a record dispatchable/iu,
  );
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

test("Augustus research keeps hosted model testing fail closed", async () => {
  const decision = await load("docs/research/augustus-evaluation.md");
  const patchContent = await load("docs/research/patches/augustus-0.14.29-machine-json.patch");
  const profileContent = await load("docs/research/augustus-single-destination-profile.json");
  const enforcementContent = await load(
    "docs/research/augustus-launcher-egress-enforcement.json",
  );
  const profile = JSON.parse(profileContent);
  const enforcement = JSON.parse(enforcementContent);

  assert.match(decision, /f032fc6373aaa9983868282b31dc9c59503c78a2/u);
  assert.match(decision, /tagged `v0\.14\.29`/u);
  assert.match(decision, /RESEARCH \/ NOT_DISTRIBUTED/u);
  assert.match(decision, /Do not add Augustus to the engine\s+catalog or\s+adapter registry/u);
  assert.match(decision, /retained narrow machine-output patch.*14-rule pure-data\s+preflight/su);
  assert.match(decision, /### 14-rule convergence audit/u);
  assert.doesNotMatch(decision, /cannot yet support a fail-closed thin adapter/u);
  assert.doesNotMatch(decision, /The next research step is a narrow upstream-oriented patch/u);
  assert.match(decision, /rest\.Rest.*out of scope/su);
  assert.match(decision, /SkipOnError/su);
  assert.match(decision, /complete: false/u);
  assert.match(decision, /test\.Repeat/u);
  assert.match(decision, new RegExp(AUGUSTUS_RESEARCH_PATCH_SHA256, "u"));
  assert.match(decision, new RegExp(AUGUSTUS_RESEARCH_PROFILE_SHA256, "u"));
  assert.match(decision, new RegExp(AUGUSTUS_RESEARCH_ENFORCEMENT_SHA256, "u"));
  assert.match(decision, /13c96bc6a36f880e7f016e02da63eadd64b73674/u);
  assert.equal(
    createHash("sha256").update(patchContent).digest("hex"),
    AUGUSTUS_RESEARCH_PATCH_SHA256,
  );
  assert.match(patchContent, /machine-json/u);
  assert.match(patchContent, /detector_failed/u);
  assert.match(patchContent, /count_mismatch/u);
  assert.match(patchContent, /test\.Repeat/u);
  assert.match(patchContent, /func \(h \*hijackProbe\) ExpectedAttempts\(\) int/u);
  assert.match(patchContent, /TestHijackLongPromptMachinePlanHasExactAttemptCount/u);
  assert.match(patchContent, /testgenerator\.NewRepeat/u);
  assert.match(patchContent, /func \(sw \*StreamWriter\) Append\(a \*attempt\.Attempt\) error/u);
  assert.match(patchContent, /sw\.file\.Sync\(\)/u);
  assert.equal(
    createHash("sha256").update(profileContent).digest("hex"),
    AUGUSTUS_RESEARCH_PROFILE_SHA256,
  );
  assert.equal(profile.schema_version, "1");
  assert.equal(profile.profile_id, "augustus-openai-promptinject-v1");
  assert.equal(profile.normative_status, "research_only_blocked");
  assert.equal(profile.source_revision, "f032fc6373aaa9983868282b31dc9c59503c78a2");
  assert.equal(profile.machine_patch_sha256, AUGUSTUS_RESEARCH_PATCH_SHA256);
  assert.equal(
    createHash("sha256").update(enforcementContent).digest("hex"),
    AUGUSTUS_RESEARCH_ENFORCEMENT_SHA256,
  );
  assert.equal(enforcement.schema_version, "1");
  assert.equal(enforcement.normative_status, "research_only_blocked");
  assert.equal(enforcement.profile_id, profile.profile_id);
  assert.equal(enforcement.profile_sha256, AUGUSTUS_RESEARCH_PROFILE_SHA256);
  assert.equal(enforcement.dispatch_enabled, false);

  const auditRows = [...decision.matchAll(
    /^\| (\d+) \| `([a-z0-9_]+)` \| `(rejected|unverified) \[([0-9,]+)\]` \|/gmu,
  )].map(([, order, ruleId, state, indices]) => [
    Number(order),
    ruleId,
    state,
    indices.split(",").map(Number),
  ]);
  assert.deepEqual(auditRows, AUGUSTUS_CURRENT_MECHANICAL_EVIDENCE);

  const leafPaths = (value, prefix = "") => {
    if (Array.isArray(value)) {
      if (value.length === 0 || value.every((item) => item === null || typeof item !== "object")) {
        return [`${prefix}[]`];
      }
      return [...new Set(value.flatMap((item) => leafPaths(item, `${prefix}[]`)))];
    }
    if (value !== null && typeof value === "object") {
      return Object.entries(value).flatMap(([key, item]) =>
        leafPaths(item, prefix ? `${prefix}.${key}` : key));
    }
    return [prefix];
  };
  const mappedPaths = enforcement.rules.flatMap(({ profile_fields: fields }) => fields);
  assert.equal(new Set(mappedPaths).size, mappedPaths.length, "each profile field has one owner");
  assert.deepEqual(mappedPaths.toSorted(), leafPaths(profile).toSorted());
  assert.equal(mappedPaths.length, 50);
  assert.deepEqual(
    enforcement.rules.map(({ rule_id: ruleId }) => ruleId),
    [
      "profile_identity_and_provenance",
      "exact_destination_and_model_binding",
      "base_url_and_redirect_denial",
      "single_connection_execution",
      "probe_detector_allowlist",
      "attempt_shape",
      "prompt_corpus_attestation",
      "token_request_and_cost_budget",
      "request_rate_retry_and_timeout",
      "probe_scanner_and_process_deadlines",
      "process_resource_sandbox",
      "response_and_process_output_bounds",
      "denied_capabilities",
      "unresolved_dispatch_blockers",
    ],
  );
  for (const rule of enforcement.rules) {
    assert.ok(rule.profile_fields.length > 0, rule.rule_id);
    assert.ok(rule.required_action.length > 0, rule.rule_id);
    assert.ok(rule.reject_conditions.length > 0, rule.rule_id);
    assert.ok(
      rule.enforcement_points.every((point) => /^(?:typed_launcher|egress_gate)\./u.test(point)),
      rule.rule_id,
    );
  }
  assert.match(enforcement.current_gateway_assessment.decision, /Dispatch remains disabled/u);
  assert.match(
    enforcement.current_gateway_assessment.insufficient_controls.join(" "),
    /TCP connection.*HTTP provider request.*redirect.*token budget.*monetary ceiling/su,
  );
  assert.deepEqual(profile.destination, {
    generator: "openai.OpenAI",
    scheme: "https",
    host: "api.openai.com",
    port: 443,
    api_base_path: "/v1",
    model_binding: "exact_scope_grant",
    custom_base_url_allowed: false,
    redirects_allowed: false,
    maximum_concurrent_connections: 1,
  });
  assert.deepEqual(
    profile.allowlist.map(({ probe, detectors }) => ({ probe, detectors })),
    [{
      probe: "promptinject.HijackLongPrompt",
      detectors: ["promptinject.AttackRogueString"],
    }],
  );
  const allowed = profile.allowlist[0];
  assert.deepEqual(allowed.detector_config, { case_sensitive: false });
  assert.equal(allowed.expected_attempts, 15);
  assert.equal(allowed.turns_per_attempt, 1);
  assert.equal(allowed.generations_per_attempt, 1);
  assert.equal(allowed.tools_allowed, false);
  assert.deepEqual(allowed.prompt_corpus, {
    canonicalization: "UTF-8 JSON array in source order with no insignificant whitespace",
    sha256: "8c8c6136d30d94639587e20101d4716589c282ce4e8941d7766758de421c0278",
    count: 15,
    total_utf8_bytes: 3212,
    maximum_prompt_utf8_bytes: 233,
  });

  const cost = profile.cost_limits;
  assert.equal(cost.maximum_provider_requests, allowed.expected_attempts);
  assert.equal(cost.maximum_total_input_tokens, cost.maximum_input_tokens_per_request * 15);
  assert.equal(cost.maximum_total_output_tokens, cost.maximum_output_tokens_per_request * 15);
  assert.equal(
    cost.maximum_total_tokens,
    cost.maximum_total_input_tokens + cost.maximum_total_output_tokens,
  );
  assert.equal(cost.maximum_estimated_charge_usd_micros, 250000);
  assert.match(cost.pricing_requirement, /Refuse dispatch/u);

  assert.deepEqual(profile.execution_limits, {
    concurrency: 1,
    maximum_requests_per_second: 1,
    scanner_retry_count: 0,
    request_timeout_seconds: 20,
    probe_timeout_seconds: 300,
    scanner_timeout_seconds: 300,
    process_timeout_seconds: 330,
    memory_mib: 512,
    cpu_millis: 1000,
    pids: 128,
    writable_tmp_mib: 16,
    maximum_response_body_bytes: 262144,
    maximum_stdout_bytes: 1048576,
    maximum_stderr_bytes: 1048576,
  });
  for (const denied of [
    "all_other_generators",
    "all_other_probes",
    "all_other_detectors",
    "custom_base_url",
    "redirects",
    "reconnaissance",
    "buffs",
    "runtime_hooks",
    "tools",
    "multi_turn",
    "attacker_or_judge_models",
    "detector_network_access",
    "configuration_files",
    "inline_configuration",
    "wildcards",
    "retries",
  ]) {
    assert.ok(profile.denied_capabilities.includes(denied), denied);
  }
  assert.ok(!profile.dispatch_blockers.some((item) => /ExpectedAttemptCounter/u.test(item)));
  assert.ok(profile.dispatch_blockers.some((item) => /scope-grant/u.test(item)));
  assert.ok(profile.dispatch_blockers.some((item) => /credential-delivery/u.test(item)));

  const fixtures = new Map();
  for (const [name, [expectedComplete, expectedWarnings, expectedSha256]] of Object.entries(
    AUGUSTUS_RESEARCH_FIXTURES,
  )) {
    const content = await load(`docs/research/fixtures/augustus/${name}`);
    assert.equal(
      createHash("sha256").update(content).digest("hex"),
      expectedSha256,
      `${name} changed without review`,
    );
    const fixture = JSON.parse(content);
    fixtures.set(name, fixture);
    assert.equal(fixture.schema_version, "1", name);
    assert.equal(fixture.scanner_version, "v0.14.29", name);
    assert.equal(fixture.source_revision, "f032fc6373aaa9983868282b31dc9c59503c78a2", name);
    assert.deepEqual(fixture.target, {
      generator: "test.Repeat",
      endpoint: "local://test-repeat",
    });
    assert.equal(fixture.complete, expectedComplete, name);
    assert.deepEqual(fixture.warnings.map(({ code }) => code), expectedWarnings, name);
    assert.equal(fixture.counts.emitted_attempts, fixture.attempts.length, name);
    assert.ok(fixture.attempts.every(({ prompt, response }) => prompt === response), name);
    assert.ok(!/api[_-]?key|bearer |sk-[a-z0-9]/iu.test(content), `${name} contains credential-shaped text`);
    for (const warning of fixture.warnings) {
      assert.ok(["count_mismatch", "detector_failed"].includes(warning.code), name);
      assert.ok(!Object.hasOwn(warning, "message"), `${name} exposes unbounded error text`);
    }

    const counts = fixture.counts;
    const countsComplete =
      counts.expected_probes === fixture.plan.length
      && counts.started_probes === counts.expected_probes
      && counts.completed_probes === counts.expected_probes
      && counts.succeeded_probes === counts.expected_probes
      && counts.failed_probes === 0
      && counts.produced_attempts === counts.expected_attempts
      && counts.processed_attempts === counts.produced_attempts
      && counts.emitted_attempts === counts.produced_attempts
      && counts.not_tested_attempts === 0
      && counts.errored_attempts === 0;
    assert.equal(
      fixture.complete,
      fixture.warnings.length === 0 && countsComplete,
      `${name} must fail closed`,
    );
  }

  assert.equal(fixtures.get("machine-complete.json").attempts[0].verdict, "safe");
  assert.equal(fixtures.get("machine-detector-warning.json").attempts[0].verdict, "safe");
  assert.equal(fixtures.get("machine-detector-warning.json").complete, false);
});

test("Augustus synthetic precontact rejections have stable order and codes", async () => {
  const decision = await load("docs/research/augustus-evaluation.md");
  const profileContent = await load("docs/research/augustus-single-destination-profile.json");
  const enforcementContent = await load(
    "docs/research/augustus-launcher-egress-enforcement.json",
  );
  const vectorContent = await load(
    "docs/research/fixtures/augustus/precontact-rejections.json",
  );
  const matrix = JSON.parse(enforcementContent);
  const vectors = JSON.parse(vectorContent);

  assert.equal(
    createHash("sha256").update(vectorContent).digest("hex"),
    AUGUSTUS_RESEARCH_REJECTION_VECTORS_SHA256,
  );
  assert.match(decision, new RegExp(AUGUSTUS_RESEARCH_REJECTION_VECTORS_SHA256, "u"));
  assert.equal(vectors.schema_version, "1");
  assert.equal(vectors.normative_status, "synthetic_research_fixture");
  assert.equal(vectors.profile_id, "augustus-openai-promptinject-v1");
  assert.equal(
    vectors.profile_sha256,
    createHash("sha256").update(profileContent).digest("hex"),
  );
  assert.equal(
    vectors.enforcement_matrix_sha256,
    createHash("sha256").update(enforcementContent).digest("hex"),
  );
  assert.deepEqual(vectors.evaluation_contract.all_vector_outcomes, {
    decision: "reject_before_contact",
    egress_lease_created: false,
    target_contact_attempted: false,
    provider_request_count: 0,
    finding_count: 0,
  });
  assert.match(vectors.evaluation_contract.selection, /ascending.*first failing rule/iu);
  assert.match(vectors.evaluation_contract.unknown_or_duplicate_rule, /never dispatch/iu);
  assert.doesNotMatch(vectorContent, /api[_-]?key|bearer\s+|sk-[a-z0-9]/iu);

  assert.deepEqual(
    vectors.rules.map(({ pre_contact_order: order, rule_id: ruleId, error_code: errorCode }) =>
      [order, ruleId, errorCode]),
    AUGUSTUS_PRECONTACT_RULE_CODES,
  );
  assert.equal(new Set(vectors.rules.map(({ error_code: code }) => code)).size, 14);
  assert.ok(vectors.rules.every(({ error_code: code }) => /^augustus_[a-z0-9_]+$/u.test(code)));
  assert.deepEqual(
    new Set(vectors.rules.map(({ rule_id: ruleId }) => ruleId)),
    new Set(matrix.rules.map(({ rule_id: ruleId }) => ruleId)),
  );

  const matrixByRule = new Map(matrix.rules.map((rule) => [rule.rule_id, rule]));
  const vectorIds = [];
  for (const rule of vectors.rules) {
    const matrixRule = matrixByRule.get(rule.rule_id);
    assert.ok(matrixRule, rule.rule_id);
    assert.deepEqual(
      rule.vectors
        .map(({ matrix_reject_condition_index: index }) => index)
        .toSorted((a, b) => a - b),
      matrixRule.reject_conditions.map((_, index) => index),
      `${rule.rule_id} must cover every matrix rejection condition once`,
    );
    for (const vector of rule.vectors) {
      vectorIds.push(vector.vector_id);
      assert.match(vector.vector_id, /^[a-z0-9_]+$/u);
      assert.ok(vector.synthetic_fault.length > 0 && vector.synthetic_fault.length <= 256);
    }
  }
  assert.equal(vectorIds.length, 35);
  assert.equal(new Set(vectorIds).size, vectorIds.length);
  assert.deepEqual(vectors.actual_frozen_profile_first_rejection, {
    pre_contact_order: AUGUSTUS_PRECONTACT_RULE_CODES[0][0],
    rule_id: AUGUSTUS_PRECONTACT_RULE_CODES[0][1],
    error_code: AUGUSTUS_PRECONTACT_RULE_CODES[0][2],
    reason: "normative_status is research_only_blocked",
  });
});

test("Augustus typed preflight schema is data-only and reject-only", async () => {
  const decision = await load("docs/research/augustus-evaluation.md");
  const schemaContent = await load("docs/research/augustus-preflight.schema.json");
  const matrixContent = await load("docs/research/augustus-launcher-egress-enforcement.json");
  const schema = JSON.parse(schemaContent);
  const matrix = JSON.parse(matrixContent);

  assert.equal(
    createHash("sha256").update(schemaContent).digest("hex"),
    AUGUSTUS_RESEARCH_PREFLIGHT_SCHEMA_SHA256,
  );
  assert.match(decision, new RegExp(AUGUSTUS_RESEARCH_PREFLIGHT_SCHEMA_SHA256, "u"));
  assert.equal(schema.$schema, "https://json-schema.org/draft/2020-12/schema");
  assert.deepEqual(schema.oneOf, [
    { $ref: "#/$defs/input" },
    { $ref: "#/$defs/output" },
  ]);

  const references = schema.$defs.artifact_references;
  assert.equal(references.additionalProperties, false);
  assert.equal(references.properties.profile_id.const, "augustus-openai-promptinject-v1");
  assert.equal(references.properties.profile_sha256.const, AUGUSTUS_RESEARCH_PROFILE_SHA256);
  assert.equal(
    references.properties.enforcement_matrix_sha256.const,
    AUGUSTUS_RESEARCH_ENFORCEMENT_SHA256,
  );
  assert.equal(
    references.properties.rejection_vectors_sha256.const,
    AUGUSTUS_RESEARCH_REJECTION_VECTORS_SHA256,
  );

  const input = schema.$defs.input;
  const evidence = schema.$defs.rule_evidence;
  const inputRules = input.properties.rule_evidence.prefixItems;
  assert.equal(input.additionalProperties, false);
  assert.equal(input.properties.document_kind.const, "preflight_input");
  assert.equal(input.properties.normative_status.const, "research_only_non_executable");
  assert.equal(inputRules.length, 14);
  assert.equal(input.properties.rule_evidence.minItems, 14);
  assert.equal(input.properties.rule_evidence.maxItems, 14);
  assert.equal(input.properties.rule_evidence.items, false);
  assert.deepEqual(evidence.properties.state.enum, ["verified", "rejected", "unverified"]);
  assert.equal(evidence.allOf[0].then.properties.rejection_condition_indices.maxItems, 0);
  assert.equal(evidence.allOf[0].else.properties.rejection_condition_indices.minItems, 1);
  assert.deepEqual(
    input.properties.rule_evidence.contains.properties.state.enum,
    ["rejected", "unverified"],
  );
  assert.equal(input.properties.rule_evidence.minContains, 1);

  const matrixByRule = new Map(matrix.rules.map((rule) => [rule.rule_id, rule]));
  assert.deepEqual(
    inputRules.map((item) => {
      const properties = item.allOf[1].properties;
      return [properties.pre_contact_order.const, properties.rule_id.const];
    }),
    AUGUSTUS_PRECONTACT_RULE_CODES.map(([order, ruleId]) => [order, ruleId]),
  );
  for (const item of inputRules) {
    const properties = item.allOf[1].properties;
    const conditionCount = matrixByRule.get(properties.rule_id.const).reject_conditions.length;
    assert.equal(properties.rejection_condition_indices.maxItems, conditionCount);
    assert.equal(properties.rejection_condition_indices.items.maximum, conditionCount - 1);
  }

  const inputPropertyNames = [
    ...Object.keys(input.properties),
    ...Object.keys(references.properties),
    ...Object.keys(evidence.properties),
    ...inputRules.flatMap((item) => Object.keys(item.allOf[1].properties)),
  ];
  assert.doesNotMatch(
    inputPropertyNames.join(" "),
    /credential|api_?key|secret|authorization|target|endpoint|model|argv|environment|command/iu,
  );

  const output = schema.$defs.output;
  assert.equal(output.additionalProperties, false);
  assert.equal(output.properties.document_kind.const, "preflight_output");
  assert.equal(output.properties.normative_status.const, "research_only_non_executable");
  assert.equal(output.properties.artifact_references.$ref, "#/$defs/artifact_references");
  assert.equal(output.properties.input_sha256.pattern, "^[0-9a-f]{64}$");
  assert.deepEqual(output.properties.decision, { const: "reject_before_contact" });
  assert.equal(output.properties.egress_lease_created.const, false);
  assert.equal(output.properties.target_contact_attempted.const, false);
  assert.equal(output.properties.provider_request_count.const, 0);
  assert.equal(output.properties.finding_count.const, 0);
  assert.deepEqual(
    schema.$defs.first_rejection.oneOf.map((variant) => [
      variant.properties.pre_contact_order.const,
      variant.properties.rule_id.const,
      variant.properties.error_code.const,
    ]),
    AUGUSTUS_PRECONTACT_RULE_CODES,
  );
  for (const variant of schema.$defs.first_rejection.oneOf) {
    assert.equal(variant.additionalProperties, false);
    assert.deepEqual(variant.required, ["pre_contact_order", "rule_id", "error_code"]);
  }
});

test("Augustus typed preflight fixtures cover all fourteen rejection codes", async () => {
  const schema = JSON.parse(await load("docs/research/augustus-preflight.schema.json"));
  const references = Object.fromEntries(
    Object.entries(schema.$defs.artifact_references.properties)
      .map(([key, value]) => [key, value.const]),
  );
  const inputRequired = schema.$defs.input.required.toSorted();
  const outputRequired = schema.$defs.output.required.toSorted();
  const evidenceRequired = schema.$defs.rule_evidence.required.toSorted();
  const firstRejectionRequired = ["pre_contact_order", "rule_id", "error_code"].toSorted();
  const seenCodes = [];

  assert.equal(AUGUSTUS_PREFLIGHT_FIXTURE_PAIRS.length, 14);
  assert.deepEqual(
    (await readdir(path.join(REPOSITORY_ROOT, "docs/research/fixtures/augustus/preflight")))
      .toSorted(),
    AUGUSTUS_PREFLIGHT_FIXTURE_PAIRS
      .flatMap(([stem]) => [`${stem}.input.json`, `${stem}.output.json`])
      .toSorted(),
  );
  for (const [index, [stem, inputSha256, outputSha256]] of
    AUGUSTUS_PREFLIGHT_FIXTURE_PAIRS.entries()) {
    const inputContent = await load(`docs/research/fixtures/augustus/preflight/${stem}.input.json`);
    const outputContent = await load(`docs/research/fixtures/augustus/preflight/${stem}.output.json`);
    const input = JSON.parse(inputContent);
    const output = JSON.parse(outputContent);
    const [expectedOrder, expectedRuleId, expectedErrorCode] = AUGUSTUS_PRECONTACT_RULE_CODES[index];

    assert.equal(createHash("sha256").update(inputContent).digest("hex"), inputSha256, stem);
    assert.equal(createHash("sha256").update(outputContent).digest("hex"), outputSha256, stem);
    assert.deepEqual(Object.keys(input).toSorted(), inputRequired, stem);
    assert.deepEqual(Object.keys(output).toSorted(), outputRequired, stem);
    assert.equal(input.document_kind, "preflight_input", stem);
    assert.equal(output.document_kind, "preflight_output", stem);
    assert.equal(input.schema_version, "1", stem);
    assert.equal(output.schema_version, "1", stem);
    assert.equal(input.normative_status, "research_only_non_executable", stem);
    assert.equal(output.normative_status, "research_only_non_executable", stem);
    assert.equal(input.evaluation_id, output.evaluation_id, stem);
    assert.match(input.evaluation_id, /^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$/u, stem);
    assert.deepEqual(input.artifact_references, references, stem);
    assert.deepEqual(output.artifact_references, references, stem);
    assert.equal(output.input_sha256, inputSha256, stem);

    assert.equal(input.rule_evidence.length, 14, stem);
    assert.deepEqual(
      input.rule_evidence.map(({ pre_contact_order: order, rule_id: ruleId }) => [order, ruleId]),
      AUGUSTUS_PRECONTACT_RULE_CODES.map(([order, ruleId]) => [order, ruleId]),
      stem,
    );
    for (const [ruleIndex, evidence] of input.rule_evidence.entries()) {
      assert.deepEqual(Object.keys(evidence).toSorted(), evidenceRequired, stem);
      if (ruleIndex === index) {
        assert.equal(evidence.state, "rejected", stem);
        assert.equal(evidence.rejection_condition_indices.length, 1, stem);
        assert.ok(
          evidence.rejection_condition_indices[0]
            <= schema.$defs.input.properties.rule_evidence.prefixItems[ruleIndex]
              .allOf[1].properties.rejection_condition_indices.items.maximum,
          stem,
        );
      } else {
        assert.equal(evidence.state, "verified", stem);
        assert.deepEqual(evidence.rejection_condition_indices, [], stem);
      }
    }

    assert.equal(output.decision, "reject_before_contact", stem);
    assert.deepEqual(Object.keys(output.first_rejection).toSorted(), firstRejectionRequired, stem);
    assert.deepEqual(
      output.first_rejection,
      {
        pre_contact_order: expectedOrder,
        rule_id: expectedRuleId,
        error_code: expectedErrorCode,
      },
      stem,
    );
    assert.equal(output.egress_lease_created, false, stem);
    assert.equal(output.target_contact_attempted, false, stem);
    assert.equal(output.provider_request_count, 0, stem);
    assert.equal(output.finding_count, 0, stem);
    assert.doesNotMatch(
      `${inputContent}\n${outputContent}`,
      /api[_-]?key|bearer\s+|sk-[a-z0-9]/iu,
      stem,
    );
    seenCodes.push(output.first_rejection.error_code);
  }

  assert.deepEqual(
    seenCodes,
    AUGUSTUS_PRECONTACT_RULE_CODES.map(([, , errorCode]) => errorCode),
  );
});

test("Augustus negative preflight fixtures remain schema-invalid for one named reason", async () => {
  const schema = JSON.parse(await load("docs/research/augustus-preflight.schema.json"));
  const directory = path.join(
    REPOSITORY_ROOT,
    "docs/research/fixtures/augustus/preflight-negative",
  );
  assert.deepEqual(
    (await readdir(directory)).toSorted(),
    Object.keys(AUGUSTUS_PREFLIGHT_NEGATIVE_FIXTURES).toSorted(),
  );

  const negative = new Map();
  for (const [name, expectedSha256] of Object.entries(AUGUSTUS_PREFLIGHT_NEGATIVE_FIXTURES)) {
    const content = await load(`docs/research/fixtures/augustus/preflight-negative/${name}`);
    assert.equal(createHash("sha256").update(content).digest("hex"), expectedSha256, name);
    assert.doesNotMatch(content, /api[_-]?key|bearer\s+|sk-[a-z0-9]/iu, name);
    negative.set(name, JSON.parse(content));
  }

  const validInput = JSON.parse(
    await load("docs/research/fixtures/augustus/preflight/01-profile-identity.input.json"),
  );
  const validOutput = JSON.parse(
    await load("docs/research/fixtures/augustus/preflight/01-profile-identity.output.json"),
  );
  const accepted = negative.get("accepted-output.json");
  assert.deepEqual(accepted, {
    ...validOutput,
    evaluation_id: "synthetic-negative:accepted-output",
    decision: "accepted",
  });
  assert.notEqual(accepted.decision, schema.$defs.output.properties.decision.const);

  const allVerified = negative.get("all-verified-input.json");
  assert.deepEqual(allVerified, {
    ...validInput,
    evaluation_id: "synthetic-negative:all-verified",
    rule_evidence: validInput.rule_evidence.map((evidence) => ({
      ...evidence,
      state: "verified",
      rejection_condition_indices: [],
    })),
  });
  assert.ok(
    !allVerified.rule_evidence.some(({ state }) => ["rejected", "unverified"].includes(state)),
  );
  assert.equal(schema.$defs.input.properties.rule_evidence.minContains, 1);

  const mismatched = negative.get("mismatched-error-code.json");
  assert.deepEqual(mismatched, {
    ...validOutput,
    evaluation_id: "synthetic-negative:mismatched-error-code",
    first_rejection: {
      ...validOutput.first_rejection,
      error_code: "augustus_dispatch_blocked",
    },
  });
  const validTriplets = schema.$defs.first_rejection.oneOf.map((variant) => ({
    pre_contact_order: variant.properties.pre_contact_order.const,
    rule_id: variant.properties.rule_id.const,
    error_code: variant.properties.error_code.const,
  }));
  assert.ok(
    !validTriplets.some(
      (triplet) => JSON.stringify(triplet) === JSON.stringify(mismatched.first_rejection),
    ),
  );

  const extraArgv = negative.get("extra-argv-input.json");
  assert.deepEqual(extraArgv, {
    ...validInput,
    evaluation_id: "synthetic-negative:extra-argv",
    argv: ["scan"],
  });
  assert.equal(schema.$defs.input.additionalProperties, false);
  assert.ok(!schema.$defs.input.required.includes("argv"));
});

test("Agentic Radar research patch and fixtures retain the audited machine-output contract", async () => {
  const patchContent = await load(
    "docs/research/patches/agentic-radar-0.14.1-machine-json.patch",
  );
  assert.equal(
    createHash("sha256").update(patchContent).digest("hex"),
    AGENTIC_RADAR_RESEARCH_PATCH_SHA256,
  );
  assert.match(
    await load("docs/research/agentic-radar-evaluation.md"),
    new RegExp(AGENTIC_RADAR_RESEARCH_PATCH_SHA256, "u"),
  );

  const fixtures = new Map();
  for (const [name, [framework, status, complete, expectedSha256]] of Object.entries(
    AGENTIC_RADAR_RESEARCH_FIXTURES,
  )) {
    const relativePath = `docs/research/fixtures/agentic-radar/${name}`;
    const content = await load(relativePath);
    assert.equal(
      createHash("sha256").update(content).digest("hex"),
      expectedSha256,
      `${name} changed without review`,
    );

    const fixture = JSON.parse(content);
    fixtures.set(name, fixture);
    assert.equal(fixture.schema_version, "1", name);
    assert.equal(fixture.scanner_version, "0.14.1", name);
    assert.equal(fixture.framework, framework, name);
    assert.equal(fixture.status, status, name);
    assert.equal(fixture.complete, complete, name);
    assert.equal(
      fixture.complete,
      fixture.warnings.length === 0,
      `${name} must fail closed`,
    );
    for (const warning of fixture.warnings) {
      assert.deepEqual(Object.keys(warning).sort(), ["code", "message"]);
      assert.equal(warning.code, "analyzer_diagnostic");
      assert.equal(typeof warning.message, "string");
      assert.notEqual(warning.message.trim(), "");
    }
    assert.equal(typeof fixture.graph, "object", name);
    for (const record of [...fixture.graph.nodes, ...fixture.graph.tools, ...fixture.graph.agents]) {
      assert.deepEqual(
        record.vulnerabilities,
        [],
        `${name} unexpectedly contains vulnerability claims`,
      );
    }
  }

  const n8n = fixtures.get("n8n.json");
  const n8nNodeNames = new Set(n8n.graph.nodes.map(({ name }) => name));
  assert.ok(
    n8n.graph.tools.every(({ name }) => n8nNodeNames.has(name)),
    "n8n must retain its duplicate tool collection",
  );

  const openAiAgents = fixtures.get("openai-agents.json");
  assert.ok(openAiAgents.graph.agents.some(({ system_prompt }) => system_prompt.length > 0));

  const autogen = fixtures.get("autogen.json");
  assert.ok(
    autogen.graph.nodes.some(({ description }) =>
      /Authorization.*your-api-key/su.test(description ?? ""),
    ),
  );

  const crewAi = fixtures.get("crewai.json");
  assert.equal(
    crewAi.graph.agents.length,
    0,
    "CrewAI fixture must retain its observed metadata shortfall",
  );
  assert.equal(crewAi.warnings.length, 5);
  assert.ok(crewAi.warnings.some(({ message }) => /Skipping agent metadata/u.test(message)));
  assert.ok(crewAi.warnings.some(({ message }) => /<ast\.Name object>/u.test(message)));
  assert.ok(crewAi.warnings.every(({ message }) => !/0x[0-9a-f]+/iu.test(message)));
  assert.ok(crewAi.graph.nodes.some(({ node_type }) => node_type === "agent"));

  const empty = fixtures.get("no-supported-workflow.json");
  assert.deepEqual(empty.graph, { name: "input", nodes: [], edges: [], agents: [], tools: [] });
});

test("MCP Armor research patch and fixtures retain the model-free fail-closed contract", async () => {
  const patchContent = await load(
    "docs/research/patches/mcp-armor-1.0.2-config-only.patch",
  );
  assert.equal(
    createHash("sha256").update(patchContent).digest("hex"),
    MCP_ARMOR_RESEARCH_PATCH_SHA256,
  );
  assert.match(patchContent, /--config-only/u);
  assert.match(patchContent, /prompt-injection/u);
  assert.match(patchContent, /CONFIGURATION_CHECKS/u);
  const decision = await load("docs/research/mcp-armor-evaluation.md");
  assert.match(decision, new RegExp(MCP_ARMOR_RESEARCH_PATCH_SHA256, "u"));
  assert.match(decision, /d5fbb944d35c98495a64f97a4270112c48fcdcda/u);

  const fixtures = new Map();
  for (const [name, [expectedComplete, expectedSha256]] of Object.entries(
    MCP_ARMOR_RESEARCH_FIXTURES,
  )) {
    const content = await load(`docs/research/fixtures/mcp-armor/${name}`);
    assert.equal(
      createHash("sha256").update(content).digest("hex"),
      expectedSha256,
      `${name} changed without review`,
    );
    const fixture = JSON.parse(content);
    fixtures.set(name, fixture);
    assert.equal(fixture.schema_version, "1", name);
    assert.equal(fixture.scanner_version, "1.0.2", name);
    assert.equal(fixture.mode, "configuration_only", name);
    assert.equal(fixture.input_count, 1, name);
    assert.equal(fixture.evaluated_input_count, 1, name);
    assert.equal(fixture.complete, expectedComplete, name);
    assert.deepEqual(
      fixture.checks.map(({ id }) => id),
      ["hardcoded_secrets", "excessive_tool_permissions"],
      name,
    );
    assert.equal(
      fixture.complete,
      fixture.warnings.length === 0
        && fixture.checks.every(({ status }) => status === "completed"),
      `${name} must fail closed`,
    );
    for (const warning of fixture.warnings) {
      assert.deepEqual(
        Object.keys(warning).sort(),
        ["check_id", "code", "config_file", "message"],
      );
      assert.ok(["config_invalid", "server_config_invalid", "check_failed"].includes(warning.code));
      assert.equal(typeof warning.message, "string");
      assert.notEqual(warning.message.trim(), "");
    }
  }

  const findings = fixtures.get("config-findings.json");
  assert.deepEqual(
    findings.findings.map(({ check_id, severity }) => [check_id, severity]),
    [["hardcoded_secrets", "high"], ["excessive_tool_permissions", "critical"]],
  );
  assert.equal(findings.findings[0].affected_entities.matched_text_redacted, 'sk-A...BBB"');
  assert.deepEqual(fixtures.get("config-clean.json").findings, []);
  assert.deepEqual(
    fixtures.get("config-disabled.json").findings.map(({ check_id, severity }) => [check_id, severity]),
    [["excessive_tool_permissions", "low"]],
  );
  assert.deepEqual(
    fixtures.get("config-partial.json").warnings.map(({ code }) => code),
    ["server_config_invalid"],
  );
});
