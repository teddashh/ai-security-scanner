import { createHash } from "node:crypto";
import { readFile } from "node:fs/promises";
import path from "node:path";
import { fileURLToPath } from "node:url";

const root = fileURLToPath(new URL("../", import.meta.url));
const snapshotDirectory = path.join(
  root,
  "mappings",
  "vendor",
  "aidefend",
  "1.20260805",
);

const PIN = Object.freeze({
  repository: "https://github.com/edward-playground/aidefense-framework",
  commit: "e10c1678ee49f03f8fb0c97d446ba3fbc3543655",
  commitDate: "2026-08-05T03:29:07-07:00",
  frameworkVersion: "1.20260805",
  sourcePath: "data/data.json",
  sourceBlob: "056d4439ecfc2168074bfcc31792316d30e3db88",
  sourceBytes: 1_709_210,
  sourceSha256: "ee0db6542fe28bcb3bd9ead0fba0fb69884b6cb765f2a1a420ceaf119a472786",
  sourceSchemaVersion: "2.3",
  sourceDataVersion: "2026.08.05",
  sourceGeneratedAt: "2026-08-05T03:29:32.409Z",
  retrievedAt: "2026-08-26",
  contentLicenseSha256: "9ba9550ad48438d0836ddab3da480b3b69ffa0aac7b7878b5a0039e7ab429411",
});

const EXPECTED_RECORDS = Object.freeze([
  {
    id: "AID-H-003.001",
    name: "Software Dependency & Package Security",
    tactic: "harden",
    parent: "AID-H-003",
    pillar: ["infra"],
    phase: ["building"],
    contentHash: "5b2108ff050f4b71",
  },
  {
    id: "AID-H-003.005",
    name: "Infrastructure as Code (IaC) Security Scanning for AI Systems",
    tactic: "harden",
    parent: "AID-H-003",
    pillar: ["infra"],
    phase: ["validation"],
    contentHash: "116106615728dd83",
  },
  {
    id: "AID-H-003.010",
    name: "Deployed AI Software Vulnerability Remediation Lifecycle",
    tactic: "harden",
    parent: "AID-H-003",
    pillar: ["infra", "app"],
    phase: ["operation", "improvement"],
    contentHash: "156ee9117ec09d38",
  },
  {
    id: "AID-H-025.001",
    name: "Pre-Execution Static Analysis & Dangerous Construct Blocking",
    tactic: "harden",
    parent: "AID-H-025",
    pillar: ["app"],
    phase: ["building", "operation"],
    contentHash: "c8c62f11c2c90ea5",
  },
  {
    id: "AID-H-031.002",
    name: "Static Admission Gates for AI-Generated Artifacts",
    tactic: "harden",
    parent: "AID-H-031",
    pillar: ["infra", "app"],
    phase: ["building", "validation"],
    contentHash: "9bbf7a3732c4c691",
  },
  {
    id: "AID-I-001.001",
    name: "Container-Based Isolation",
    tactic: "isolate",
    parent: "AID-I-001",
    pillar: ["infra"],
    phase: ["operation"],
    contentHash: "f54f612d01792cff",
  },
]);

const EXPECTED_MAPPING_PROJECTION = Object.freeze([
  { engine_id: "checkov", match_kind: "exact", source_rule: "CKV_AWS_18", controls: ["AID-H-003.005"] },
  { engine_id: "gitleaks", match_kind: "exact", source_rule: "generic-api-key", controls: ["AID-H-031.002"] },
  { engine_id: "grype", match_kind: "prefix", source_rule: "CVE-", controls: ["AID-H-003.001", "AID-H-003.010"] },
  { engine_id: "kics", match_kind: "exact", source_rule: "e24efb0e", controls: ["AID-H-003.005"] },
  { engine_id: "kubescape", match_kind: "exact", source_rule: "C-0002", controls: ["AID-I-001.001"] },
  { engine_id: "semgrep", match_kind: "exact", source_rule: "ai-security-scanner.generic.private-key", controls: ["AID-H-031.002"] },
  { engine_id: "semgrep", match_kind: "exact", source_rule: "ai-security-scanner.javascript.child-process-exec", controls: ["AID-H-025.001", "AID-H-031.002"] },
  { engine_id: "semgrep", match_kind: "exact", source_rule: "ai-security-scanner.python.dynamic-code-execution", controls: ["AID-H-025.001", "AID-H-031.002"] },
  { engine_id: "semgrep", match_kind: "exact", source_rule: "ai-security-scanner.python.shell-true", controls: ["AID-H-025.001", "AID-H-031.002"] },
  { engine_id: "trivy", match_kind: "prefix", source_rule: "CVE-", controls: ["AID-H-003.001", "AID-H-003.010"] },
  { engine_id: "trufflehog", match_kind: "exact", source_rule: "trufflehog:ExampleCredential", controls: ["AID-H-031.002"] },
]);

const EXPECTED_CONTROL_APPLICABILITY = Object.freeze([
  { id: "AID-H-003.001", name: "Software Dependency & Package Security", applicability: "ai_system" },
  { id: "AID-H-003.005", name: "Infrastructure as Code (IaC) Security Scanning for AI Systems", applicability: "ai_system" },
  { id: "AID-H-003.010", name: "Deployed AI Software Vulnerability Remediation Lifecycle", applicability: "ai_system" },
  { id: "AID-H-025.001", name: "Pre-Execution Static Analysis & Dangerous Construct Blocking", applicability: "ai_system" },
  { id: "AID-H-031.002", name: "Static Admission Gates for AI-Generated Artifacts", applicability: "ai_generated_artifact" },
  { id: "AID-I-001.001", name: "Container-Based Isolation", applicability: "ai_system" },
]);

const EXPECTED_APPLICABILITY_SCHEMA = Object.freeze({
  property: { enum: ["ai_system", "ai_generated_artifact"] },
  conditional: [{
    if: {
      properties: { framework: { const: "AIDEFEND" } },
      required: ["framework"],
    },
    then: { required: ["aidefend_applicability"] },
    else: { not: { required: ["aidefend_applicability"] } },
  }],
});

const SNAPSHOT_KEYS = [
  "framework",
  "framework_version",
  "notice",
  "records",
  "schema_version",
  "selection_kind",
  "source_commit",
  "source_data_version",
  "source_file_sha256",
  "source_schema_version",
];
const RECORD_KEYS = ["contentHash", "id", "name", "parent", "phase", "pillar", "tactic"];
const SELECTED_FIELDS = ["id", "name", "tactic", "parent", "pillar", "phase", "contentHash"];
const PROVENANCE_KEYS = [
  "assurance_notice",
  "attribution_file",
  "component",
  "content_license",
  "content_license_sha256",
  "content_license_source_path",
  "content_license_url",
  "framework_version",
  "license_file",
  "modifications",
  "retrieved_at",
  "schema_version",
  "selected_fields",
  "selected_record_count",
  "selected_snapshot",
  "source_bytes",
  "source_data_version",
  "source_generated_at",
  "source_git_blob",
  "source_path",
  "source_schema_version",
  "source_sha256",
  "trademark_notice",
  "upstream_commit",
  "upstream_commit_date",
  "upstream_repository",
];

function fail(message) {
  throw new Error(`AIDEFEND selected snapshot validation failed: ${message}`);
}

function assert(condition, message) {
  if (!condition) fail(message);
}

function assertExactKeys(value, expected, label) {
  assert(value && typeof value === "object" && !Array.isArray(value), `${label} must be an object`);
  const actual = Object.keys(value).sort();
  const wanted = [...expected].sort();
  assert(JSON.stringify(actual) === JSON.stringify(wanted), `${label} keys differ from the pinned schema`);
}

function assertEqual(actual, expected, label) {
  assert(JSON.stringify(actual) === JSON.stringify(expected), `${label} differs from the pinned value`);
}

function assertNoDuplicateObjectKeys(source, label) {
  let offset = 0;
  const lineAt = (position) => 1 + (source.slice(0, position).match(/\n/gu)?.length ?? 0);
  const syntaxError = (message) => fail(`${label} contains invalid JSON near line ${lineAt(offset)}: ${message}`);
  const skipWhitespace = () => {
    while (offset < source.length && /\s/u.test(source[offset])) offset += 1;
  };
  const parseString = () => {
    if (source[offset] !== '"') syntaxError("expected a string");
    const start = offset;
    offset += 1;
    let escaped = false;
    while (offset < source.length) {
      const character = source[offset];
      offset += 1;
      if (escaped) {
        escaped = false;
      } else if (character === "\\") {
        escaped = true;
      } else if (character === '"') {
        try {
          return JSON.parse(source.slice(start, offset));
        } catch (error) {
          syntaxError(error.message);
        }
      } else if (character < " ") {
        syntaxError("unescaped control character in string");
      }
    }
    syntaxError("unterminated string");
  };
  const parseValue = (depth = 0) => {
    if (depth > 256) syntaxError("nesting exceeds 256 levels");
    skipWhitespace();
    if (source[offset] === "{") {
      offset += 1;
      skipWhitespace();
      const keys = new Set();
      if (source[offset] === "}") {
        offset += 1;
        return;
      }
      while (offset < source.length) {
        skipWhitespace();
        const keyOffset = offset;
        const key = parseString();
        if (keys.has(key)) {
          fail(`${label} contains duplicate JSON object key ${JSON.stringify(key)} at line ${lineAt(keyOffset)}`);
        }
        keys.add(key);
        skipWhitespace();
        if (source[offset] !== ":") syntaxError("expected ':' after object key");
        offset += 1;
        parseValue(depth + 1);
        skipWhitespace();
        if (source[offset] === "}") {
          offset += 1;
          return;
        }
        if (source[offset] !== ",") syntaxError("expected ',' or '}' in object");
        offset += 1;
      }
      syntaxError("unterminated object");
    }
    if (source[offset] === "[") {
      offset += 1;
      skipWhitespace();
      if (source[offset] === "]") {
        offset += 1;
        return;
      }
      while (offset < source.length) {
        parseValue(depth + 1);
        skipWhitespace();
        if (source[offset] === "]") {
          offset += 1;
          return;
        }
        if (source[offset] !== ",") syntaxError("expected ',' or ']' in array");
        offset += 1;
      }
      syntaxError("unterminated array");
    }
    if (source[offset] === '"') {
      parseString();
      return;
    }
    const start = offset;
    while (offset < source.length && !/[\s,\]}]/u.test(source[offset])) offset += 1;
    if (start === offset) syntaxError("expected a JSON value");
    try {
      JSON.parse(source.slice(start, offset));
    } catch (error) {
      syntaxError(error.message);
    }
  };

  parseValue();
  skipWhitespace();
  if (offset !== source.length) syntaxError("unexpected trailing content");
}

function parseUniqueJson(source, label) {
  assertNoDuplicateObjectKeys(source, label);
  try {
    return JSON.parse(source);
  } catch (error) {
    fail(`${label} is invalid JSON: ${error.message}`);
  }
}

function validateDuplicateKeyDetector() {
  assertNoDuplicateObjectKeys('{"left":{"value":1},"right":[{"value":2}]}', "duplicate-key detector self-test");
  let duplicateRejected = false;
  try {
    assertNoDuplicateObjectKeys('{"controls":[],"\\u0063ontrols":[]}', "duplicate-key detector self-test");
  } catch (error) {
    duplicateRejected = error.message.includes('duplicate JSON object key "controls"');
  }
  assert(duplicateRejected, "duplicate-key detector must reject equivalent escaped object keys");
}

async function readJson(filename) {
  const pathname = path.join(snapshotDirectory, filename);
  let source;
  try {
    source = await readFile(pathname, "utf8");
  } catch (error) {
    fail(`${filename} is unavailable: ${error.message}`);
  }
  return parseUniqueJson(source, filename);
}

function parseSourceArgument(argv) {
  if (argv.length === 0) return null;
  if (argv.length === 2 && argv[0] === "--source" && argv[1].trim()) {
    return path.resolve(argv[1]);
  }
  fail("usage: node scripts/validate-aidefend-snapshot.mjs [--source /path/to/data.json]");
}

function selectedRecordsFromSource(source) {
  const records = new Map();
  for (const tactic of source.tactics ?? []) {
    for (const technique of tactic.techniques ?? []) {
      const children = technique.subTechniques ?? [];
      const actionable = children.length > 0
        ? children.map((control) => ({ control, parent: technique.id }))
        : [{ control: technique, parent: null }];
      for (const { control, parent } of actionable) {
        if (!EXPECTED_RECORDS.some((expected) => expected.id === control.id)) continue;
        records.set(control.id, {
          id: control.id,
          name: control.name,
          tactic: tactic.id,
          parent,
          pillar: control.pillar,
          phase: control.phase,
          contentHash: control.contentHash,
        });
      }
    }
  }
  return [...records.values()].sort((left, right) => left.id.localeCompare(right.id));
}

async function validatePinnedSource(sourcePath) {
  let bytes;
  try {
    bytes = await readFile(sourcePath);
  } catch (error) {
    fail(`pinned source is unavailable: ${error.message}`);
  }
  assert(bytes.byteLength === PIN.sourceBytes, "pinned source byte length differs");
  assert(createHash("sha256").update(bytes).digest("hex") === PIN.sourceSha256, "pinned source SHA-256 differs");

  let source;
  try {
    source = JSON.parse(bytes.toString("utf8"));
  } catch (error) {
    fail(`pinned source is invalid JSON: ${error.message}`);
  }
  assert(source.version?.schemaVersion === PIN.sourceSchemaVersion, "pinned source schema version differs");
  assert(source.version?.dataVersion === PIN.sourceDataVersion, "pinned source data version differs");
  assert(source.version?.generatedAt === PIN.sourceGeneratedAt, "pinned source generation timestamp differs");
  assertEqual(selectedRecordsFromSource(source), EXPECTED_RECORDS, "records derived from pinned source");
}

async function validateControlMappings() {
  let mappingSource;
  let schemaSource;
  try {
    [mappingSource, schemaSource] = await Promise.all([
      readFile(path.join(root, "mappings", "control-mappings.json"), "utf8"),
      readFile(path.join(root, "mappings", "control-mappings.schema.json"), "utf8"),
    ]);
  } catch (error) {
    fail(`control mapping catalog or schema is unavailable: ${error.message}`);
  }
  const mapping = parseUniqueJson(mappingSource, "control-mappings.json");
  const schema = parseUniqueJson(schemaSource, "control-mappings.schema.json");

  const controlSchema = schema.properties?.controls?.items;
  assert(controlSchema?.additionalProperties === false, "control mapping schema must reject unknown control fields");
  assertEqual(
    controlSchema?.properties?.aidefend_applicability,
    EXPECTED_APPLICABILITY_SCHEMA.property,
    "control mapping schema AIDEFEND applicability property",
  );
  assertEqual(
    controlSchema?.allOf,
    EXPECTED_APPLICABILITY_SCHEMA.conditional,
    "control mapping schema AIDEFEND applicability condition",
  );

  const source = (mapping.sources ?? []).filter((item) => item.framework === "AIDEFEND");
  assertEqual(source, [{
    framework: "AIDEFEND",
    framework_version: PIN.frameworkVersion,
    url: `${PIN.repository}/blob/${PIN.commit}/${PIN.sourcePath}`,
  }], "AIDEFEND mapping source");

  const definitions = (mapping.controls ?? [])
    .filter((control) => control.framework === "AIDEFEND")
    .sort((left, right) => left.control_id.localeCompare(right.control_id));
  assertEqual(
    definitions.map((control) => ({
      id: control.control_id,
      name: control.title,
      applicability: control.aidefend_applicability,
    })),
    EXPECTED_CONTROL_APPLICABILITY,
    "AIDEFEND mapping definitions and applicability",
  );
  assert(
    (mapping.controls ?? []).every((control) => control.framework === "AIDEFEND"
      ? Object.hasOwn(control, "aidefend_applicability")
      : !Object.hasOwn(control, "aidefend_applicability")),
    "only AIDEFEND controls may declare AIDEFEND applicability, and every AIDEFEND control must declare it",
  );
  const idByKey = new Map(definitions.map((control) => [control.key, control.control_id]));
  assert(idByKey.size === EXPECTED_RECORDS.length, "AIDEFEND mapping keys must be unique");

  const projection = (mapping.entries ?? [])
    .map((entry) => ({
      engine_id: entry.engine_id,
      match_kind: entry.match_kind,
      source_rule: entry.source_rule,
      controls: (entry.controls ?? []).filter((key) => idByKey.has(key)).map((key) => idByKey.get(key)),
    }))
    .filter((entry) => entry.controls.length > 0)
    .sort((left, right) => `${left.engine_id}\0${left.source_rule}`.localeCompare(`${right.engine_id}\0${right.source_rule}`));
  assertEqual(projection, EXPECTED_MAPPING_PROJECTION, "reviewed AIDEFEND rule projection");
  assert(
    (mapping.entries ?? []).every((entry) => !Object.hasOwn(entry, "aidefend_applicability")),
    "AIDEFEND applicability must be declared per control, not per mixed mapping entry",
  );
}

async function main() {
  validateDuplicateKeyDetector();
  const sourcePath = parseSourceArgument(process.argv.slice(2));
  const snapshot = await readJson("selected-controls.json");
  const provenance = await readJson("PROVENANCE.json");
  const attribution = await readFile(path.join(snapshotDirectory, "ATTRIBUTION.txt"), "utf8");
  const licenseBytes = await readFile(path.join(snapshotDirectory, "LICENSE-CONTENT"));
  const license = licenseBytes.toString("utf8");

  assertExactKeys(snapshot, SNAPSHOT_KEYS, "selected-controls.json");
  assert(snapshot.schema_version === "1.0", "snapshot schema version differs");
  assert(snapshot.framework === "AIDEFEND", "snapshot framework differs");
  assert(snapshot.framework_version === PIN.frameworkVersion, "snapshot framework version differs");
  assert(snapshot.source_data_version === PIN.sourceDataVersion, "snapshot source data version differs");
  assert(snapshot.source_schema_version === PIN.sourceSchemaVersion, "snapshot source schema version differs");
  assert(snapshot.source_commit === PIN.commit, "snapshot source commit differs");
  assert(snapshot.source_file_sha256 === PIN.sourceSha256, "snapshot source SHA-256 differs");
  assert(snapshot.selection_kind === "project-reviewed-actionable-control-metadata", "snapshot selection kind differs");
  assert(snapshot.notice.includes("do not establish implementation"), "snapshot notice must reject implementation claims");
  assert(snapshot.notice.includes("compliance"), "snapshot notice must reject compliance claims");
  assert(Array.isArray(snapshot.records), "snapshot records must be an array");
  snapshot.records.forEach((record, index) => assertExactKeys(record, RECORD_KEYS, `snapshot record ${index + 1}`));
  assertEqual(snapshot.records, EXPECTED_RECORDS, "selected records");

  const ids = snapshot.records.map((record) => record.id);
  assert(new Set(ids).size === ids.length, "selected record IDs must be unique");
  assertEqual(ids, [...ids].sort(), "selected record order");
  for (const record of snapshot.records) {
    assert(/^AID-(?:H|I)-\d{3}\.\d{3}$/.test(record.id), `${record.id} is not an actionable leaf coordinate`);
    assert(record.id.startsWith(`${record.parent}.`), `${record.id} does not belong to ${record.parent}`);
    assert(/^[a-f0-9]{16}$/.test(record.contentHash), `${record.id} has an invalid upstream contentHash`);
  }

  assertExactKeys(provenance, PROVENANCE_KEYS, "PROVENANCE.json");
  const expectedProvenance = {
    repository: provenance.upstream_repository,
    commit: provenance.upstream_commit,
    commitDate: provenance.upstream_commit_date,
    frameworkVersion: provenance.framework_version,
    sourcePath: provenance.source_path,
    sourceBlob: provenance.source_git_blob,
    sourceBytes: provenance.source_bytes,
    sourceSha256: provenance.source_sha256,
    sourceSchemaVersion: provenance.source_schema_version,
    sourceDataVersion: provenance.source_data_version,
    sourceGeneratedAt: provenance.source_generated_at,
    retrievedAt: provenance.retrieved_at,
    contentLicenseSha256: provenance.content_license_sha256,
  };
  assertEqual(expectedProvenance, PIN, "provenance pin");
  assert(provenance.schema_version === "1.0", "provenance schema version differs");
  assert(provenance.selected_snapshot === "selected-controls.json", "provenance snapshot filename differs");
  assert(provenance.selected_record_count === EXPECTED_RECORDS.length, "provenance selected count differs");
  assertEqual(provenance.selected_fields, SELECTED_FIELDS, "provenance selected fields");
  assert(provenance.content_license === "CC-BY-4.0", "provenance content license differs");
  assert(provenance.content_license_url === "https://creativecommons.org/licenses/by/4.0/legalcode", "provenance license URL differs");
  assert(provenance.content_license_source_path === "LICENSE-CONTENT", "provenance license source path differs");
  assert(provenance.attribution_file === "ATTRIBUTION.txt", "provenance attribution filename differs");
  assert(provenance.license_file === "LICENSE-CONTENT", "provenance license filename differs");
  assert(provenance.modifications.includes("Selected six actionable leaf controls"), "provenance must identify modifications");
  assert(provenance.trademark_notice.includes("not affiliated with, approved, certified, or endorsed"), "provenance must reject affiliation and endorsement");
  assert(provenance.assurance_notice.includes("do not establish control implementation"), "provenance must reject implementation claims");
  assert(provenance.assurance_notice.includes("compliance"), "provenance must reject compliance claims");

  const requiredAttribution = "AIDEFEND AI Defense Framework, created by Edward Lee, https://aidefend.net, licensed under CC BY 4.0.";
  assert(attribution.includes(requiredAttribution), "required CC BY attribution is missing");
  assert(attribution.includes(`Source commit: ${PIN.commit}`), "attribution source commit is missing");
  assert(attribution.includes(`Source file SHA-256: ${PIN.sourceSha256}`), "attribution source hash is missing");
  assert(attribution.includes("Changes made by ai-security-scanner"), "attribution change notice is missing");
  assert(attribution.includes("independent, unofficial integration"), "attribution unofficial-integration notice is missing");
  assert(attribution.includes("not affiliated with, approved, certified, sponsored, or endorsed"), "attribution endorsement disclaimer is missing");
  assert(attribution.includes("do not state that any control is implemented"), "attribution assurance disclaimer is missing");
  assert(attribution.includes("compliant"), "attribution compliance disclaimer is missing");

  assert(license.includes("Creative Commons Attribution 4.0 International Public License"), "CC BY 4.0 legal code heading is missing");
  assert(createHash("sha256").update(licenseBytes).digest("hex") === PIN.contentLicenseSha256, "CC BY 4.0 legal code SHA-256 differs");

  await validateControlMappings();
  if (sourcePath) await validatePinnedSource(sourcePath);

  const sourceMessage = sourcePath ? `; source verified at ${sourcePath}` : "";
  console.log(`AIDEFEND selected snapshot verified: ${EXPECTED_RECORDS.length} actionable records at ${PIN.commit}${sourceMessage}.`);
}

main().catch((error) => {
  console.error(error.message);
  process.exitCode = 1;
});
