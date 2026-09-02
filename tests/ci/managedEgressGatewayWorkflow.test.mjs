import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import test from "node:test";

const workflow = readFileSync(
    new URL("../../.github/workflows/managed-egress-gateway-image.yml", import.meta.url),
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
