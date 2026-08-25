import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import path from "node:path";
import test from "node:test";
import { fileURLToPath } from "node:url";

import { validateProwlerCatalogContract } from "../../scripts/prowler-catalog-contract.mjs";

const projectRoot = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "../..");

function fixture() {
  const catalog = JSON.parse(readFileSync(path.join(projectRoot, "engines/catalog.json"), "utf8"));
  return {
    engine: structuredClone(catalog.find(({ id }) => id === "prowler")),
    plan: JSON.parse(readFileSync(path.join(projectRoot, "engines/images/prowler/plan.json"), "utf8")),
  };
}

function validate(subject, overrides = {}) {
  return validateProwlerCatalogContract({ ...subject, projectRoot, ...overrides });
}

test("accepts the exact Prowler three-provider and six-patch closure", () => {
  assert.deepEqual(validate(fixture()), []);
});

test("rejects a provider-to-asset/profile mapping change", () => {
  const subject = fixture();
  subject.engine.provider_execution_contracts[1].profile = "azure_broader_profile";
  assert.match(validate(subject).join("\n"), /provider_execution_contracts must match the exact released Prowler contract/u);
});

test("rejects any endpoint outside the exact provider closure", () => {
  const subject = fixture();
  subject.engine.network_destinations.push("login.microsoftonline.com:443");
  assert.match(validate(subject).join("\n"), /catalog:prowler\.network_destinations/u);
});

test("rejects a declared patch or applier digest change", () => {
  const subject = fixture();
  subject.plan.downstream_runtime_patches.applier.sha256 = `sha256:${"0".repeat(64)}`;
  subject.plan.downstream_runtime_patches.patches[0].sha256 = `sha256:${"1".repeat(64)}`;
  assert.match(validate(subject).join("\n"), /downstream_runtime_patches must match the exact released Prowler contract/u);
});

test("rejects an on-disk patch whose bytes no longer match the reviewed digest", () => {
  const subject = fixture();
  const target = "engines/images/prowler/patches/0002-gcp-exact-project-lookups.patch";
  const readArtifact = (relative) => relative === target
    ? Buffer.from("tampered patch\n", "utf8")
    : readFileSync(path.join(projectRoot, relative));
  assert.match(validate(subject, { readArtifact }).join("\n"), /0002-gcp-exact-project-lookups\.patch: actual SHA-256 differs/u);
});

test("rejects an on-disk applier whose bytes no longer match the reviewed digest", () => {
  const subject = fixture();
  const target = "engines/images/prowler/apply-runtime-patches.py";
  const readArtifact = (relative) => relative === target
    ? Buffer.from("tampered applier\n", "utf8")
    : readFileSync(path.join(projectRoot, relative));
  assert.match(validate(subject, { readArtifact }).join("\n"), /apply-runtime-patches\.py: actual SHA-256 differs/u);
});

test("rejects a runtime source pre/post SHA change", () => {
  const subject = fixture();
  subject.plan.downstream_runtime_patches.runtime_files.find(({ path: runtimePath }) =>
    runtimePath === "prowler/providers/gcp/gcp_provider.py").post_sha256 = `sha256:${"f".repeat(64)}`;
  assert.match(validate(subject).join("\n"), /downstream_runtime_patches must match the exact released Prowler contract/u);
});

test("rejects provenance or knowledge that overstates a different live data source", () => {
  const subject = fixture();
  subject.engine.provenance.data.acquisition_source = "Ambient provider discovery";
  subject.engine.compatibility.knowledge_input.identifier = "All cloud configuration";
  subject.plan.data_acquisition.providers[2].identity_check = "List every accessible GCP project";
  const output = validate(subject).join("\n");
  assert.match(output, /catalog:prowler\.provenance\.data/u);
  assert.match(output, /catalog:prowler\.compatibility\.knowledge_input/u);
  assert.match(output, /engines\/images\/prowler\/plan\.json\.data_acquisition/u);
});
