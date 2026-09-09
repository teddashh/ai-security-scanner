import assert from "node:assert/strict";
import test from "node:test";

import {
  localInputDefinitions,
  localInputEngineIds,
  localInputEngines,
  localPathDisplayLabels,
} from "../../src/localInputProfiles.ts";

test("repository scans route Syft inventory with the pinned security engines", () => {
  assert.deepEqual(localInputEngineIds.repository_working_tree, [
    "gitleaks",
    "semgrep",
    "syft",
    "trivy",
    "grype",
    "trufflehog",
    "kics",
    "checkov",
  ]);
  assert.equal(
    localInputEngines.repository_working_tree,
    "Gitleaks, Semgrep, Syft, Trivy, Grype, TruffleHog, KICS, Checkov",
  );
});

test("container scans route Syft inventory before Trivy and Grype vulnerability checks", () => {
  assert.deepEqual(localInputEngineIds.container_image_oci_layout, ["syft", "trivy", "grype"]);
  assert.equal(localInputEngines.container_image_oci_layout, "Syft, Trivy, Grype");
  assert.equal(
    localInputDefinitions.container_image_oci_layout.formIntro.en,
    "Pick one exported OCI image folder. Syft inventories its software components, while Trivy and Grype check them for known vulnerabilities. Everything runs locally without starting the image.",
  );
  assert.equal(
    localInputDefinitions.container_image_oci_layout.formIntro.zhTW,
    "選擇一個匯出的 OCI 映像資料夾；Syft 會盤點其中的軟體元件，Trivy 與 Grype 會檢查已知弱點。所有工作都在本機完成，不會執行映像。",
  );
});

test("repository labels use one parent segment when basenames match", () => {
  assert.deepEqual(localPathDisplayLabels([
    "/work/team-a/api",
    "/work/team-b/api",
    "/work/portal",
  ], "Selected folder"), [
    "team-a/api",
    "team-b/api",
    "portal",
  ]);
});

test("repository labels number an immediate-parent collision without exposing more path", () => {
  assert.deepEqual(localPathDisplayLabels([
    "/private/customer-one/team/api",
    "/private/customer-two/team/api",
  ], "Selected folder"), [
    "team/api (1)",
    "team/api (2)",
  ]);
});
