import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
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
const panelSource = readFileSync(
  new URL("../../src/components/ProviderAuthorizationPanel.tsx", import.meta.url),
  "utf8",
);
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

test("provider sign-in leads with the setup-file journey and keeps manual entry secondary", () => {
  assert.match(panelSource, /connectionDetailsSummary/u);
  assert.match(panelSource, /provider-preparation-steps/u);
  assert.match(panelSource, /requestTitle/u);
  assert.match(panelSource, /importTitle/u);
  assert.match(panelSource, /continueTitlePreferred/u);
  assert.match(panelSource, /copyItRequest/u);
  assert.match(panelSource, /importConnectionSetup/u);
  assert.match(panelSource, /type="file"/u);
  assert.match(panelSource, /className="provider-manual-details"/u);
  assert.match(panelSource, /manualSummary/u);
  assert.match(panelSource, /Your IT team prepares this once for your organization/u);
  assert.match(panelSource, /ai-security-scanner does not provide a shared OAuth registration/u);
  assert.doesNotMatch(panelSource, /IT \/ admin advanced setup/u);
  assert.doesNotMatch(panelSource, /product-owned OAuth|shared OAuth client/u);

  const stepsStart = panelSource.indexOf('<ol className="provider-preparation-steps provider-connection-steps"');
  const manualStart = panelSource.indexOf('<details\n            className="provider-manual-details"', stepsStart);
  assert.notEqual(stepsStart, -1);
  assert.notEqual(manualStart, -1);
  const primaryJourney = panelSource.slice(stepsStart, manualStart);
  assert.match(primaryJourney, /copy\.requestTitle/u);
  assert.match(primaryJourney, /copy\.importTitle/u);
  assert.match(primaryJourney, /copy\.continueTitlePreferred/u);
  assert.doesNotMatch(primaryJourney, /copy\.fields\./u);
});

test("connection setup files are bounded, exact, credential-free, and never retained", () => {
  assert.match(panelSource, /CONNECTION_SETUP_MAX_BYTES = 64 \* 1024/u);
  assert.match(panelSource, /CONNECTION_SETUP_MAX_DEPTH = 4/u);
  assert.match(panelSource, /CONNECTION_SETUP_MAX_NODES = 64/u);
  assert.match(panelSource, /file\.size > CONNECTION_SETUP_MAX_BYTES/u);
  assert.match(panelSource, /new TextEncoder\(\)\.encode\(content\)\.byteLength > CONNECTION_SETUP_MAX_BYTES/u);
  assert.match(panelSource, /file\.name\.toLocaleLowerCase\("en-US"\)\.endsWith\("\.json"\)/u);
  assert.match(panelSource, /mediaType !== "application\/json"/u);
  assert.match(panelSource, /JSON\.parse\(content\.replace/u);
  assert.match(panelSource, /rejectSecretFieldsAndExcessiveNesting\(value\)/u);
  assert.match(panelSource, /fieldNameContainsSecret\(key\)/u);
  assert.match(panelSource, /FORBIDDEN_SETUP_FIELD_PARTS/u);
  assert.match(panelSource, /sameKeys\(sortedKeys\(value\), expectedTopLevel\)/u);
  assert.match(panelSource, /value\.schema_version !== CONNECTION_SETUP_SCHEMA_VERSION/u);
  assert.match(panelSource, /value\.provider !== expectedProvider/u);
  assert.match(panelSource, /flowForConnectionMethod\(value\.connection_method\)/u);
  assert.match(panelSource, /input\.value = ""/u);
  assert.doesNotMatch(panelSource, /useState<(?:File|Blob)|setSetupFile\(|localStorage|sessionStorage/u);
});

test("setup-file schema keeps provider formats exact and derives app-local coordinates", () => {
  const setupFieldsStart = panelSource.indexOf("const connectionSetupFileFields");
  const forbiddenPartsStart = panelSource.indexOf("const FORBIDDEN_SETUP_FIELD_PARTS", setupFieldsStart);
  assert.notEqual(setupFieldsStart, -1);
  assert.notEqual(forbiddenPartsStart, -1);
  const setupFields = panelSource.slice(setupFieldsStart, forbiddenPartsStart);
  assert.match(setupFields, /aws:[\s\S]*?preferred: \["start_url", "region", "account_id", "role_name"\]/u);
  assert.match(setupFields, /gcp:[\s\S]*?preferred: \["public_client_id", "organization_id"\]/u);
  assert.match(setupFields, /bootstrap: \["public_client_id", "organization_id", "project_id"\]/u);
  assert.doesNotMatch(setupFields, /role_arn|redirect_uri/u);

  assert.match(panelSource, /provider === "gcp"\s*\? GCP_CLIENT_ID_PATTERN\.test\(value\)\s*:\s*UUID_PATTERN\.test\(value\)/u);
  assert.doesNotMatch(panelSource, /UUID_PATTERN\.test\(value\) \|\| GCP_CLIENT_ID_PATTERN/u);
  assert.match(panelSource, /supplied\.role_arn = deriveAwsRoleArn\(supplied\.region, supplied\.account_id, supplied\.role_name\)/u);
  assert.match(panelSource, /supplied\.redirect_uri = localGcpRedirectUri/u);
  assert.match(panelSource, /normalizeAndValidateDetails\(provider, flow, supplied\)/u);
});

test("provider device code remains a primary, actionable sign-in step", () => {

  const promptStart = panelSource.indexOf("{prompt && (");
  const promptEnd = panelSource.indexOf('{flowMode === "bootstrap" && bootstrapPlan', promptStart);
  assert.notEqual(promptStart, -1);
  assert.notEqual(promptEnd, -1);
  const promptMarkup = panelSource.slice(promptStart, promptEnd);
  const technicalStart = promptMarkup.indexOf(
    '<details className="provider-auth-technical provider-prompt__technical">',
  );
  assert.notEqual(technicalStart, -1);

  const primaryPrompt = promptMarkup.slice(0, technicalStart);
  const technicalPrompt = promptMarkup.slice(technicalStart);
  assert.match(primaryPrompt, /provider-device-code--primary/u);
  assert.match(primaryPrompt, /prompt\.prompt\.user_code/u);
  assert.match(primaryPrompt, /copyPromptDeviceCode/u);
  assert.match(primaryPrompt, /copyDeviceCode/u);
  assert.doesNotMatch(technicalPrompt, /prompt\.prompt\.user_code/u);
  assert.match(technicalPrompt, /copy\.technicalFlow/u);
  assert.match(technicalPrompt, /promptSafetyNotice/u);
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
