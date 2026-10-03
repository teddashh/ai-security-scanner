#!/usr/bin/env node
import assert from "node:assert/strict";
import { appendFileSync, readFileSync } from "node:fs";
import { resolve } from "node:path";
import { pathToFileURL } from "node:url";

const ENGINE_IDS = ["semgrep", "trufflehog", "trivy", "grype", "kubescape", "kube-bench"];

// A shared launcher edit does not authorize publishing every consuming image.
// The owner assigns a new immutable tag to each intended publication first.
export function selectLocalEnginePublication(matrix, publishedTags, requestedEngine = "") {
  assert.deepEqual(matrix.map((entry) => entry.engine), ENGINE_IDS, "unexpected local engine matrix");
  for (const entry of matrix) {
    assert.match(entry.tag, /^[a-zA-Z0-9_][a-zA-Z0-9_.-]{0,127}$/u);
    assert.equal(entry.dockerfile, `engines/images/${entry.engine}/Dockerfile`);
    assert.equal(typeof publishedTags[entry.engine], "string", "missing recorded artifact tag");
  }
  if (requestedEngine) {
    assert.ok(ENGINE_IDS.includes(requestedEngine), "manual publication requires one known engine");
    return matrix.filter((entry) => entry.engine === requestedEngine);
  }
  return matrix.filter((entry) => entry.tag !== publishedTags[entry.engine]);
}

if (process.argv[1] && import.meta.url === pathToFileURL(resolve(process.argv[1])).href) {
  assert.ok(["push", "workflow_dispatch"].includes(process.env.EVENT_NAME), "unsupported publication event");
  const matrix = JSON.parse(process.env.LOCAL_ENGINE_MATRIX);
  const publishedTags = Object.fromEntries(ENGINE_IDS.map((engine) => [engine,
    JSON.parse(readFileSync(`engines/images/${engine}/plan.json`, "utf8")).final_artifact.tag,
  ]));
  const requested = process.env.EVENT_NAME === "workflow_dispatch" ? process.env.REQUESTED_ENGINE : "";
  assert.ok(process.env.EVENT_NAME !== "workflow_dispatch" || requested, "manual run requires an engine");
  const selected = selectLocalEnginePublication(matrix, publishedTags, requested);
  const outputs = {
    engines: JSON.stringify(selected.map((entry) => entry.engine)),
    matrix: JSON.stringify({ include: selected }),
    has_engines: String(selected.length > 0),
  };
  appendFileSync(process.env.GITHUB_OUTPUT, Object.entries(outputs).map(([key, value]) => `${key}=${value}\n`).join(""));
  process.stdout.write(`Selected managed engine tags: ${selected.map(({ engine, tag }) => `${engine}:${tag}`).join(", ") || "none"}\n`);
}
