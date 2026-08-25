import assert from "node:assert/strict";
import test from "node:test";

import { build } from "esbuild";

const bundled = await build({
  entryPoints: [new URL("../../src/providerAuthorizationPolicy.ts", import.meta.url).pathname],
  bundle: true,
  format: "esm",
  platform: "node",
  target: "node22",
  write: false,
});
const source = bundled.outputFiles[0]?.text;
assert.ok(source, "the provider authorization policy bundle should contain JavaScript");
const {
  providerAuthorizationRequiredFields,
  providerAuthorizationTechnicalDetail,
  providerCheckoutLimits,
  providerEngineBindings,
} = await import(`data:text/javascript;base64,${Buffer.from(source).toString("base64")}`);

test("provider authorization UI requests the exact released engine capability sets", () => {
  assert.deepEqual(providerEngineBindings, {
    aws: [
      "provider-native-discovery",
      "cloudquery",
      "steampipe",
      "prowler",
      "scoutsuite",
      "cloudsplaining",
    ],
    azure: ["provider-native-discovery", "prowler"],
    gcp: ["provider-native-discovery", "prowler"],
    microsoft365: ["provider-native-discovery", "scubagear", "maester"],
  });
});

test("Azure and GCP authorize narrow Prowler without inheriting AWS-only engines", () => {
  const awsOnly = ["cloudquery", "steampipe", "scoutsuite", "cloudsplaining"];

  for (const provider of ["azure", "gcp"] as const) {
    assert.equal(providerEngineBindings[provider].includes("prowler"), true);
    for (const engineId of awsOnly) {
      assert.equal(providerEngineBindings[provider].includes(engineId), false);
    }
  }
});

test("provider checkout ceilings cover bounded executions without becoming unbounded", () => {
  assert.deepEqual(providerCheckoutLimits, {
    aws: 8,
    azure: 8,
    gcp: 1_001,
    microsoft365: 8,
  });
  assert.equal(providerCheckoutLimits.gcp, 1 + 1_000);
  assert.equal(providerCheckoutLimits.gcp > 1 + 9, true);
});

test("progressive setup keeps every released provider coordinate without accepting secrets", () => {
  assert.deepEqual(providerAuthorizationRequiredFields, {
    aws: {
      preferred: ["start_url", "region", "account_id", "role_name", "role_arn"],
      bootstrap: ["start_url", "region", "account_id", "role_name", "role_arn"],
    },
    azure: {
      preferred: ["tenant_id", "public_client_id", "subscription_id"],
      bootstrap: ["tenant_id", "public_client_id", "subscription_id"],
    },
    gcp: {
      preferred: ["public_client_id", "organization_id", "redirect_uri"],
      bootstrap: ["public_client_id", "organization_id", "project_id", "redirect_uri"],
    },
    microsoft365: {
      preferred: ["tenant_id", "public_client_id"],
      bootstrap: ["tenant_id", "public_client_id"],
    },
  });

  const forbiddenFields = new Set([
    "password",
    "admin_password",
    "client_secret",
    "access_key",
    "secret_access_key",
    "access_token",
    "refresh_token",
  ]);
  for (const paths of Object.values(providerAuthorizationRequiredFields)) {
    for (const fields of Object.values(paths)) {
      for (const field of fields) assert.equal(forbiddenFields.has(field), false, field);
    }
  }
});

test("technical error disclosure is bounded and redacts credential-shaped values", () => {
  const detail = providerAuthorizationTechnicalDetail(
    new Error(
      "provider returned 401 client_secret=do-not-show access_token: top-secret "
      + "Bearer abc.def.ghi AKIA1234567890ABCDEF",
    ),
  );

  assert.ok(detail);
  assert.match(detail, /provider returned 401/u);
  assert.match(detail, /client_secret=\[REDACTED\]/u);
  assert.match(detail, /access_token: \[REDACTED\]/u);
  assert.match(detail, /Bearer \[REDACTED\]/u);
  assert.match(detail, /\[REDACTED AWS ACCESS KEY\]/u);
  assert.doesNotMatch(detail, /do-not-show|top-secret|AKIA1234567890ABCDEF/u);

  const oversized = providerAuthorizationTechnicalDetail("x".repeat(5_000));
  assert.ok(oversized);
  assert.equal(Array.from(oversized).length, 4_097);
  assert.equal(oversized.endsWith("…"), true);
  assert.equal(providerAuthorizationTechnicalDetail({ message: "not trusted" }), undefined);
});
