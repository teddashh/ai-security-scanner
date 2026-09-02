import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import test from "node:test";
import { parse as parseYaml } from "yaml";

const workflow = parseYaml(
  readFileSync(
    new URL("../../.github/workflows/managed-egress-gateway-image.yml", import.meta.url),
    "utf8",
  ),
);

test("managed egress gateway publication is explicit and immutable", () => {
  assert.deepEqual(Object.keys(workflow.on ?? {}).sort(), ["workflow_dispatch"]);

  const imageTag = workflow.env?.IMAGE_TAG;
  assert.equal(typeof imageTag, "string");
  assert.notEqual(imageTag.length, 0);
  assert.equal(workflow.concurrency?.group, `managed-egress-gateway-image-${imageTag}`);

  const steps = workflow.jobs?.publish?.steps ?? [];
  const guardIndex = steps.findIndex(
    (step) => step.uses === "./.github/actions/engine-image-evidence/publication-guard",
  );
  const buildIndex = steps.findIndex(
    (step) => typeof step.uses === "string" && step.uses.startsWith("docker/build-push-action@"),
  );
  const evidenceIndex = steps.findIndex(
    (step) => step.uses === "./.github/actions/engine-image-evidence",
  );
  const promotionIndex = steps.findIndex(
    (step) => step.uses === "./.github/actions/engine-image-evidence/promote",
  );

  assert.ok(guardIndex >= 0, "publication guard is required");
  assert.ok(guardIndex < buildIndex, "publication guard must run before the publishing build");
  assert.equal(steps[buildIndex]?.if, "steps.guard.outputs.should_build == 'true'");
  assert.equal(
    steps[buildIndex]?.with?.tags,
    "${{ env.IMAGE }}:${{ steps.guard.outputs.candidate_tag }}",
  );
  assert.ok(buildIndex < evidenceIndex, "signed evidence must follow the candidate build");
  assert.ok(evidenceIndex < promotionIndex, "promotion must follow signed evidence");
});
