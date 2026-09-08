import assert from "node:assert/strict";
import test from "node:test";

import { localInputEngineIds, localPathDisplayLabels } from "../../src/localInputProfiles.ts";

test("repository scans route both pinned dependency vulnerability engines", () => {
  assert.deepEqual(localInputEngineIds.repository_working_tree, [
    "gitleaks",
    "semgrep",
    "trivy",
    "grype",
    "trufflehog",
    "kics",
    "checkov",
  ]);
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
