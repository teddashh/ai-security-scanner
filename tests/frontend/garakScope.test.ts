import assert from "node:assert/strict";
import test from "node:test";
import { garakProbeIds, modelEndpointScope, validatedModelEndpoint } from "../../src/garakProfile.ts";

test("model coordinates normalize only an exact HTTPS URL and bounded model identifier", () => {
  const input = validatedModelEndpoint(" https://MODEL.example.test:443/v1/chat/completions ", " fixture/model ");
  assert.deepEqual(input, { endpoint: "https://model.example.test/v1/chat/completions", model: "fixture/model" });
  for (const url of ["http://model.example.test/a", "https://key@model.example.test/a", "https://model.example.test/",
    "https://model.example.test:0/a", "https://model.example.test/a/../b", "https://model.example.test/a%2fb",
    "https://model.example.test/a?key=x", "https://model.example.test/a#b", "https://model.example.test/a//b"]) {
    assert.equal(validatedModelEndpoint(url, "fixture"), undefined, url);
  }
  for (const model of ["", "--model", "a b", "a\nkey", "x".repeat(129)]) {
    assert.equal(validatedModelEndpoint(input!.endpoint, model), undefined);
  }
});

test("the reviewed model scope binds the one HTTPS host and port with a closed native probe profile", () => {
  const input = validatedModelEndpoint("https://model.example.test:8443/v1/chat/completions", "fixture/model")!;
  const scope = modelEndpointScope(input, true, "owned fixture with provider charges");
  assert.equal(scope.target, "model.example.test"); assert.deepEqual(scope.ports, [8443]);
  assert.equal(scope.allowSensitiveNetworks, true); assert.equal(scope.protocol, "https");
  assert.equal(scope.activity, "active_external");
  assert.deepEqual(scope.ratePolicy, { requestsPerSecond: 1, concurrency: 1, timeoutSeconds: 20 });
  assert.deepEqual(scope.templatePolicy.allowedTemplateIds, []);
  assert.equal(garakProbeIds.length, 4);
  assert.equal(scope.templatePolicy.profileId, "garak_https_v1");
  for (const [key, value] of Object.entries(scope.templatePolicy)) if (/^allow[A-Z]/u.test(key)) assert.equal(value, false);
  assert.ok(!JSON.stringify(scope).includes("API_KEY"));
});
