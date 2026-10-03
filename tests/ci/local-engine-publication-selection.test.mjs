import assert from "node:assert/strict";
import test from "node:test";
import { readFileSync } from "node:fs";
import { parse } from "yaml";
import { selectLocalEnginePublication } from "../../scripts/select-local-engine-publication.mjs";

const ids = ["semgrep", "trufflehog", "trivy", "grype", "kubescape", "kube-bench"];
const matrix = ids.map((engine) => ({ engine, tag: "1.0.0-1", dockerfile: `engines/images/${engine}/Dockerfile` }));
const tags = Object.fromEntries(ids.map((engine) => [engine, "1.0.0-1"]));

test("only an explicitly new immutable tag is selected after shared input edits", () => {
  const candidate = structuredClone(matrix);
  candidate[0].tag = "1.0.0-2";
  assert.deepEqual(selectLocalEnginePublication(candidate, tags).map(({ engine }) => engine), ["semgrep"]);
});

test("a pin-only follow-up selects no publication", () => {
  assert.deepEqual(selectLocalEnginePublication(matrix, tags), []);
});

test("a manual verification or publication selects exactly one named engine", () => {
  assert.deepEqual(selectLocalEnginePublication(matrix, tags, "grype").map(({ engine }) => engine), ["grype"]);
  assert.throws(() => selectLocalEnginePublication(matrix, tags, "all"), /one known engine/u);
});

test("missing artifact records and altered matrix membership fail closed", () => {
  assert.throws(() => selectLocalEnginePublication(matrix, {}), /missing recorded artifact tag/u);
  assert.throws(() => selectLocalEnginePublication(matrix.slice(1), tags), /unexpected local engine matrix/u);
});

test("a failed native Semgrep validation stops its own publication and leaves sibling jobs independent", () => {
  const workflow = parse(readFileSync(new URL("../../.github/workflows/engine-images-local-k8s.yml", import.meta.url), "utf8"));
  const publish = workflow.jobs.publish;
  assert.ok(publish.needs.includes("semgrep-native-verify"));
  assert.match(publish.if, /always\(\)/u);
  assert.doesNotMatch(publish.if, /needs\.semgrep-native-verify\.result/u);
  assert.deepEqual(publish.steps[0], {
    name: "Require both native Semgrep verifications before publication",
    if: "matrix.engine == 'semgrep'",
    env: { NATIVE_RESULT: "${{ needs.semgrep-native-verify.result }}" },
    run: 'test "${NATIVE_RESULT}" = success',
  });
  assert.equal(workflow.jobs["semgrep-native-verify"].if, "contains(fromJSON(needs.changes.outputs.engines), 'semgrep')");
});

test("manual native verification cannot publish an image, rules cache or build-record artifact", () => {
  const workflow = parse(readFileSync(new URL("../../.github/workflows/engine-images-local-k8s.yml", import.meta.url), "utf8"));
  assert.equal(workflow.on.workflow_dispatch.inputs.mode.default, "verify");
  assert.match(workflow.jobs.publish.if, /inputs\.mode != 'verify'/u);
  const native = workflow.jobs["semgrep-native-verify"];
  assert.equal(native.env.DOCKER_BUILD_RECORD_UPLOAD, "false");
  const build = native.steps.find((step) => step.uses?.startsWith("docker/build-push-action@"));
  assert.equal(build.with.push, false);
  assert.match(build.with["cache-to"], /inputs\.mode != 'verify'/u);
  const upload = native.steps.find((step) => step.uses?.startsWith("actions/upload-artifact@"));
  assert.deepEqual(upload.with.path.trim().split("\n"), [
    "package-evidence/semgrep-native-${{ matrix.arch }}/verification.json",
    "package-evidence/semgrep-native-${{ matrix.arch }}/*.log",
    "package-evidence/semgrep-native-${{ matrix.arch }}/*/semgrep.json",
  ]);
});
