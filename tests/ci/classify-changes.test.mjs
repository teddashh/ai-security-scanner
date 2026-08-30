import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import test from "node:test";

import {
  ciBoundaryResultErrors,
  classifyAllBoundaries,
  classifyChangedPaths,
  githubOutputLines,
} from "../../scripts/ci/classify-changes.mjs";

test("documentation-only changes do not schedule product or release lanes", () => {
  assert.deepEqual(classifyChangedPaths([
    "README.md",
    "docs/product-spec.md",
  ]), {
    changed_path_count: 2,
    docs_only: true,
    frontend: false,
    rust_core: false,
    desktop: false,
    engine: false,
    framework: false,
    release_contract: false,
    windows_runtime: false,
  });
});

test("scanner skill copies are documentation contracts, not release triggers", () => {
  const result = classifyChangedPaths([
    ".claude/skills/ai-security-scanner/SKILL.md",
    ".codex/skills/ai-security-scanner/SKILL.md",
  ]);
  assert.equal(result.docs_only, true);
  assert.equal(result.frontend, false);
  assert.equal(result.rust_core, false);
  assert.equal(result.release_contract, false);
  assert.equal(result.windows_runtime, false);
});

test("ordinary frontend changes schedule only the fast frontend lane", () => {
  assert.deepEqual(classifyChangedPaths([
    "src/pages/StartPage.tsx",
    "tests/frontend/scanPresentation.test.ts",
  ]), {
    changed_path_count: 2,
    docs_only: false,
    frontend: true,
    rust_core: false,
    desktop: false,
    engine: false,
    framework: false,
    release_contract: false,
    windows_runtime: false,
  });
});

test("engine inputs schedule engine admission without release or installer work", () => {
  assert.deepEqual(classifyChangedPaths([
    "engines/images/gitleaks/Dockerfile",
    ".github/workflows/engine-image-gitleaks.yml",
  ]), {
    changed_path_count: 2,
    docs_only: false,
    frontend: false,
    rust_core: false,
    desktop: false,
    engine: true,
    framework: false,
    release_contract: false,
    windows_runtime: false,
  });
});

test("engine evidence and OCI fixture scripts cannot bypass engine admission", () => {
  for (const path of [
    "scripts/engine-image-evidence.mjs",
    "scripts/generate-oci-layout-fixture.mjs",
  ]) {
    const result = classifyChangedPaths([path]);
    assert.equal(result.engine, true, `${path} did not schedule engine admission`);
    assert.equal(result.release_contract, false, `${path} scheduled the release lane`);
    assert.equal(result.windows_runtime, false, `${path} scheduled the Windows installer lane`);
  }
});

test("the embedded engine catalog also exercises Rust and desktop integration", () => {
  const result = classifyChangedPaths(["engines/catalog.json"]);
  assert.equal(result.engine, true);
  assert.equal(result.rust_core, true);
  assert.equal(result.desktop, true);
  assert.equal(result.release_contract, false);
  assert.equal(result.windows_runtime, false);
});

test("the master-framework producer exercises Rust, desktop, and release contracts", () => {
  const result = classifyChangedPaths(["src-tauri/src/exporters/framework_report.rs"]);
  assert.equal(result.rust_core, true);
  assert.equal(result.desktop, true);
  assert.equal(result.framework, true);
  assert.equal(result.release_contract, true);
  assert.equal(result.engine, false);
  assert.equal(result.windows_runtime, false);
});

test("AIDEFEND machine inputs use the focused framework lane without full release work", () => {
  assert.deepEqual(classifyChangedPaths([
    "mappings/vendor/aidefend/1.20260805/selected-controls.json",
    "mappings/vendor/aidefend/1.20260805/PROVENANCE.json",
    "scripts/validate-aidefend-snapshot.mjs",
  ]), {
    changed_path_count: 3,
    docs_only: false,
    frontend: false,
    rust_core: false,
    desktop: false,
    engine: false,
    framework: true,
    release_contract: false,
    windows_runtime: false,
  });

  const embeddedMapping = classifyChangedPaths(["mappings/control-mappings.json"]);
  assert.equal(embeddedMapping.framework, true);
  assert.equal(embeddedMapping.rust_core, true);
  assert.equal(embeddedMapping.desktop, true);
  assert.equal(embeddedMapping.release_contract, false);
});

test("installer and managed-runtime inputs schedule their focused heavyweight lanes", () => {
  assert.deepEqual(classifyChangedPaths([
    "runtime/managed-runtime.schema.json",
    "src-tauri/src/managed_runtime.rs",
    "src-tauri/windows/nsis/installer.nsi",
  ]), {
    changed_path_count: 3,
    docs_only: false,
    frontend: false,
    rust_core: true,
    desktop: true,
    engine: false,
    framework: false,
    release_contract: true,
    windows_runtime: true,
  });
});

test("shared Node dependency changes exercise every Node and desktop packaging consumer", () => {
  const result = classifyChangedPaths(["package-lock.json"]);
  assert.equal(result.frontend, true);
  assert.equal(result.desktop, true);
  assert.equal(result.engine, true);
  assert.equal(result.framework, true);
  assert.equal(result.release_contract, true);
  assert.equal(result.windows_runtime, true);
  assert.equal(result.rust_core, false);
});

test("CI classifier changes rely on the always-run classifier test, not heavyweight lanes", () => {
  assert.deepEqual(classifyChangedPaths([
    ".github/workflows/ci.yml",
    "scripts/ci/classify-changes.mjs",
    "tests/ci/classify-changes.test.mjs",
  ]), {
    changed_path_count: 3,
    docs_only: false,
    frontend: false,
    rust_core: false,
    desktop: false,
    engine: false,
    framework: false,
    release_contract: false,
    windows_runtime: false,
  });
});

test("an unavailable push base schedules every lane instead of silently omitting work", () => {
  assert.deepEqual(classifyAllBoundaries(), {
    changed_path_count: 0,
    docs_only: false,
    frontend: true,
    rust_core: true,
    desktop: true,
    engine: true,
    framework: true,
    release_contract: true,
    windows_runtime: true,
  });

  const workflow = readFileSync(new URL("../../.github/workflows/ci.yml", import.meta.url), "utf8");
  assert.match(workflow, /if \[\[ -z "\$base_sha" \]\]; then/);
  assert.match(workflow, /classify-changes\.mjs --all/);
  assert.match(workflow, /git diff-tree --root --no-renames/);
  assert.match(workflow, /git diff --no-renames --name-only/);
  assert.match(workflow, /if git cat-file -e "\$\{base_sha\}\^\{commit\}"; then[\s\S]*Base commit is not present[\s\S]*classify-changes\.mjs --all/);
});

test("heavyweight commands stay behind their focused job conditions", () => {
  const workflow = readFileSync(new URL("../../.github/workflows/ci.yml", import.meta.url), "utf8");
  const frontendBlock = workflow.split("\n  engine-admission:", 1)[0].split("\n  frontend:")[1];
  assert.ok(frontendBlock, "frontend job block is missing");
  assert.doesNotMatch(frontendBlock, /validate:engines|validate:aidefend|release:self-test|vendor-managed-runtime|bundles nsis/);

  assert.match(workflow, /Record intentional documentation-only scope[\s\S]*?steps\.classify\.outputs\.docs_only == 'true'/);
  assert.match(workflow, /Record classifier-only scope[\s\S]*?an unclassified path; only classifier tests are scheduled/);
  assert.match(workflow, /engine-admission:[\s\S]*?if: needs\.changes\.outputs\.engine == 'true'[\s\S]*?npm run validate:engines/);
  assert.match(workflow, /engine-admission:[\s\S]*?node --check scripts\/engine-image-evidence\.mjs[\s\S]*?node --check scripts\/generate-oci-layout-fixture\.mjs/);
  assert.match(workflow, /framework-contract:[\s\S]*?if: needs\.changes\.outputs\.framework == 'true'[\s\S]*?npm run validate:aidefend/);
  assert.match(workflow, /release-contract:[\s\S]*?if: needs\.changes\.outputs\.release_contract == 'true'[\s\S]*?npm run release:self-test/);
  assert.match(workflow, /windows-managed-runtime:[\s\S]*?if: needs\.changes\.outputs\.windows_runtime == 'true'[\s\S]*?vendor-managed-runtime[\s\S]*?bundles nsis/);
});

test("existing required-check names remain stable and one aggregate verifies scheduled lanes", () => {
  const workflow = readFileSync(new URL("../../.github/workflows/ci.yml", import.meta.url), "utf8");
  assert.match(workflow, /\n  frontend:\n    name: Frontend\n/);
  assert.match(workflow, /\n  windows-managed-runtime:\n    name: Windows managed-runtime repair\n/);
  assert.match(workflow, /\n  ci-result:\n    name: CI result\n    if: always\(\)\n/);
  for (const dependency of [
    "changes",
    "frontend",
    "engine-admission",
    "framework-contract",
    "release-contract",
    "rust-core",
    "windows-managed-runtime",
    "desktop-linux",
  ]) {
    assert.match(workflow, new RegExp(`ci-result:[\\s\\S]*?needs:[\\s\\S]*?- ${dependency.replaceAll("-", "\\-")}`));
  }
  assert.match(workflow, /ci-result:[\s\S]*?uses: actions\/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1[\s\S]*?uses: actions\/setup-node@820762786026740c76f36085b0efc47a31fe5020/);
  assert.match(workflow, /run: node scripts\/ci\/classify-changes\.mjs --verify-results/);
  for (const expected of [
    "FRONTEND_EXPECTED",
    "ENGINE_EXPECTED",
    "FRAMEWORK_EXPECTED",
    "RELEASE_EXPECTED",
    "RUST_EXPECTED",
    "WINDOWS_EXPECTED",
    "DESKTOP_EXPECTED",
  ]) {
    assert.match(workflow, new RegExp(`\\n      ${expected}: \\$\\{\\{ needs\\.changes\\.outputs\\.`));
  }
});

test("aggregate result logic accepts intentional skips and rejects every incomplete scheduled lane", () => {
  const lanes = [
    { label: "Frontend", expected: "true", result: "success" },
    { label: "Engine admission", expected: "false", result: "skipped" },
  ];
  assert.deepEqual(ciBoundaryResultErrors("success", lanes), []);
  assert.deepEqual(ciBoundaryResultErrors("failure", lanes), [
    "Changed-boundary classification did not complete successfully (failure).",
  ]);
  assert.deepEqual(ciBoundaryResultErrors("success", [
    { label: "Frontend", expected: "true", result: "skipped" },
    { label: "Engine admission", expected: "false", result: "success" },
    { label: "Framework mapping", expected: "", result: "skipped" },
  ]), [
    "Frontend was scheduled but finished as skipped.",
    "Engine admission was not scheduled but finished as success.",
    "Framework mapping has an invalid classifier output: missing.",
  ]);
  for (const result of ["failure", "cancelled", "skipped", "missing"]) {
    assert.equal(ciBoundaryResultErrors("success", [
      { label: "Scheduled lane", expected: "true", result: result === "missing" ? "" : result },
    ]).length, 1, `scheduled ${result} lane was accepted`);
  }
});

test("GitHub output is deterministic and uses workflow-compatible scalar values", () => {
  assert.deepEqual(
    githubOutputLines(classifyChangedPaths(["src/App.tsx", "./src/App.tsx"])),
    [
      "changed_path_count=1",
      "docs_only=false",
      "frontend=true",
      "rust_core=false",
      "desktop=false",
      "engine=false",
      "framework=false",
      "release_contract=false",
      "windows_runtime=false",
    ],
  );
});
