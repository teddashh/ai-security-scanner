import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import test from "node:test";
import { fileURLToPath } from "node:url";

import { build } from "esbuild";

const bundle = async (entry: string) => {
  const built = await build({
    entryPoints: [fileURLToPath(new URL(entry, import.meta.url))],
    bundle: true,
    format: "esm",
    platform: "node",
    target: "node22",
    write: false,
  });
  const source = built.outputFiles[0]?.text;
  assert.ok(source, `${entry} should bundle to JavaScript`);
  return import(`data:text/javascript;base64,${Buffer.from(source).toString("base64")}`);
};

const {
  AWS_READ_ONLY_PERMISSION_SET,
  AWS_SETUP_PERMISSION_SET,
  AZURE_SCAN_ROLES,
  AZURE_SETUP_PERMISSIONS,
  GCP_READ_ROLES,
  MICROSOFT_365_READ_PERMISSIONS,
  MICROSOFT_365_SETUP_PERMISSIONS,
  cloudSetupGuide,
} = await bundle("../../src/cloudSetupGuide.ts");
const { explainProviderRejection } = await bundle("../../src/providerSignInRejection.ts");

const read = (path: string) => readFileSync(new URL(path, import.meta.url), "utf8");
const providerSource = read("../../src-tauri/src/source_authorization/provider.rs");
const executorSource = read("../../src-tauri/src/bootstrap/executor.rs");
const panelSource = read("../../src/components/ProviderAuthorizationPanel.tsx");
const gcpBindings = JSON.parse(read("../../bootstrap/gcp-readonly-bindings.json"));

const quotedStrings = (block: string): string[] =>
  Array.from(block.matchAll(/"([^"]+)"/gu), (match) => match[1]!);

const rustFunctionBody = (name: string): string => {
  const start = providerSource.indexOf(`fn ${name}()`);
  assert.notEqual(start, -1, `provider.rs should define ${name}`);
  return providerSource.slice(start, providerSource.indexOf("\n}\n", start));
};

const providers = ["aws", "azure", "gcp", "microsoft365"] as const;
const paths = ["preferred", "bootstrap"] as const;

test("the Microsoft 365 steps ask for exactly the read permissions the sign-in requires", () => {
  assert.deepEqual(
    [...MICROSOFT_365_READ_PERMISSIONS],
    quotedStrings(rustFunctionBody("microsoft365_required_permissions")),
  );
  const listed = cloudSetupGuide("microsoft365", "preferred").steps.flatMap((step) => step.values ?? []);
  assert.deepEqual(listed, [...MICROSOFT_365_READ_PERMISSIONS]);
  for (const prohibited of quotedStrings(rustFunctionBody("microsoft_prohibited_scopes"))) {
    assert.equal(listed.includes(prohibited), false, `${prohibited} would make the sign-in fail`);
  }
  for (const permission of listed) {
    assert.doesNotMatch(permission, /readwrite|\.write|accessasuser/iu);
  }
});

test("the temporary-access steps ask for exactly the scopes the setup helper requires", () => {
  const microsoftAdmin = executorSource.slice(executorSource.indexOf("fn microsoft_admin_device_authorization"));
  const required = microsoftAdmin.slice(0, microsoftAdmin.indexOf("let mut scopes"));
  const azure = /MicrosoftAdminPurpose::Azure => vec!\[([^\]]+)\]/u.exec(required)?.[1];
  const microsoft365 = /MicrosoftAdminPurpose::Microsoft365 => vec!\[([^\]]+)\]/u.exec(required)?.[1];
  assert.ok(azure && microsoft365, "executor.rs should list the administrator scopes per purpose");
  assert.deepEqual([...AZURE_SETUP_PERMISSIONS], quotedStrings(azure));
  assert.deepEqual([...MICROSOFT_365_SETUP_PERMISSIONS], quotedStrings(microsoft365));
  assert.deepEqual(
    cloudSetupGuide("microsoft365", "bootstrap").steps.flatMap((step) => step.values ?? []),
    [...MICROSOFT_365_SETUP_PERMISSIONS],
  );
  const azureValues = cloudSetupGuide("azure", "bootstrap").steps.flatMap((step) => step.values ?? []);
  for (const permission of AZURE_SETUP_PERMISSIONS) {
    assert.ok(azureValues.includes(`Microsoft Graph: ${permission}`));
  }
  // The administrator token is refreshed for Azure Resource Manager.
  assert.ok(azureValues.includes("Azure Service Management: user_impersonation"));
});

test("the Azure steps grant only the two roles the sign-in accepts", () => {
  const reader = /const READER: &str = "([0-9a-f-]+)"/u.exec(providerSource)?.[1];
  const securityReader = /const SECURITY_READER: &str = "([0-9a-f-]+)"/u.exec(providerSource)?.[1];
  assert.equal(reader, "acdd72a7-3385-48ef-bd42-f606fba81ae7");
  assert.equal(securityReader, "39bc4728-0917-49c7-9d2c-d95423bc2eb4");
  assert.deepEqual([...AZURE_SCAN_ROLES], ["Reader", "Security Reader"]);
  const values = cloudSetupGuide("azure", "preferred").steps.flatMap((step) => step.values ?? []);
  assert.deepEqual(values.slice(0, 2), [...AZURE_SCAN_ROLES]);
  assert.ok(values.includes("Microsoft Graph: User.Read"));
  assert.ok(values.includes("Microsoft Graph: Organization.Read.All"));
  assert.ok(values.includes("Azure Service Management: user_impersonation"));
});

test("the Google Cloud steps grant the same read roles as the temporary-access template", () => {
  assert.deepEqual(GCP_READ_ROLES.map(([role]: readonly [string, string]) => role), gcpBindings.roles);
  assert.deepEqual(
    cloudSetupGuide("gcp", "preferred").steps.flatMap((step) => step.values ?? []),
    GCP_READ_ROLES.map(([, name]: readonly [string, string]) => name),
  );
});

test("the AWS steps create the permission set the panel fills in", () => {
  assert.equal(AWS_READ_ONLY_PERMISSION_SET, "SecurityAudit");
  assert.equal(AWS_SETUP_PERMISSION_SET, "AdministratorAccess");
  assert.ok(cloudSetupGuide("aws", "preferred").steps.some((step) => step.values?.includes("SecurityAudit")));
  assert.ok(cloudSetupGuide("aws", "bootstrap").steps.some((step) => step.values?.includes("AdministratorAccess")));
  assert.match(panelSource, /useState\(AWS_READ_ONLY_PERMISSION_SET\)/u);
});

test("every guide is bilingual, written for the person doing the setup, and never routes to IT", () => {
  for (const provider of providers) {
    for (const path of paths) {
      const guide = cloudSetupGuide(provider, path);
      assert.ok(guide.title.en && guide.title.zhTW);
      assert.ok(guide.steps.length >= 3, `${provider}/${path} should have its console steps`);
      for (const step of guide.steps) {
        assert.ok(step.text.en.trim() && step.text.zhTW.trim());
        assert.doesNotMatch(`${step.text.en} ${step.text.zhTW}`, /\bIT\b/u);
      }
      if (path === "bootstrap") {
        assert.match(guide.steps.at(-1)!.text.en, /Remove only what this setup created/u);
      }
    }
  }
});

const refusals: ReadonlyArray<{
  provider: "aws" | "azure" | "gcp" | "microsoft365";
  detail: string;
  cause: RegExp;
  fix: RegExp;
}> = [
  {
    provider: "aws",
    detail: "operation is not authorized: AWS credential permits prohibited mutation iam:CreateUser",
    cause: /can change the account \(iam:CreateUser\)/u,
    fix: /read-only permission set such as SecurityAudit/u,
  },
  {
    provider: "aws",
    detail: "operation is not authorized: AWS read-only profile is missing required permission securityhub:GetFindings",
    cause: /cannot read securityhub:GetFindings/u,
    fix: /SecurityAudit policy/u,
  },
  {
    provider: "aws",
    detail: "operation is not authorized: AWS IAM read-only policy simulation failed with provider HTTP status 403 (AccessDenied)",
    cause: /cannot check its own permissions/u,
    fix: /SecurityAudit policy/u,
  },
  {
    provider: "aws",
    detail: "operation is not authorized: the AWS account/role is not assigned to the authenticated IAM Identity Center user",
    cause: /does not have this permission set on this account/u,
    fix: /IAM Identity Center → AWS accounts/u,
  },
  {
    provider: "aws",
    detail: "operation is not authorized: the AWS role ARN in the connection details is not the role the person signed in with",
    cause: /not the one entered in step 2/u,
    fix: /permission set name in step 2/u,
  },
  {
    provider: "aws",
    detail: "operation is not authorized: AWS IAM Identity Center device authorization failed with provider HTTP status 400 (InvalidRequestException)",
    cause: /access portal URL or Region/u,
    fix: /IAM Identity Center dashboard/u,
  },
  {
    provider: "microsoft365",
    detail: "operation is not authorized: Microsoft token includes prohibited write permission Directory.ReadWrite.All",
    cause: /grants Directory\.ReadWrite\.All, which can change the tenant/u,
    fix: /Remove that permission/u,
  },
  {
    provider: "microsoft365",
    detail: "operation is not authorized: Microsoft token is missing required read permission Policy.Read.All",
    cause: /does not grant Policy\.Read\.All, or admin consent is missing/u,
    fix: /Grant admin consent/u,
  },
  {
    provider: "microsoft365",
    detail: "operation is not authorized: Microsoft 365 policy permission probe failed with provider HTTP status 403 (Authorization_RequestDenied)",
    cause: /cannot read these Microsoft 365 settings/u,
    fix: /Global Administrator or Global Reader/u,
  },
  {
    provider: "microsoft365",
    detail: "operation is not authorized: Microsoft device authorization failed with provider HTTP status 400 (invalid_client, error code 7000218)",
    cause: /does not allow sign-in from a desktop app/u,
    fix: /Allow public client flows/u,
  },
  {
    provider: "microsoft365",
    detail: "operation is not authorized: the Microsoft sign-in failed with invalid_grant (error code 65001)",
    cause: /Admin consent has not been granted/u,
    fix: /Grant admin consent/u,
  },
  {
    provider: "microsoft365",
    detail: "operation is not authorized: Microsoft Graph organization does not match the configured tenant",
    cause: /different Microsoft tenant/u,
    fix: /tenant ID in step 2/u,
  },
  {
    provider: "azure",
    detail: "operation is not authorized: Azure principal has an additional unapproved role assignment 8e3af657-a8ff-443c-a75c-2fe8c4bcb635",
    cause: /also has the Owner role/u,
    fix: /only the Reader and Security Reader roles/u,
  },
  {
    provider: "azure",
    detail: "operation is not authorized: Azure principal has an additional unapproved role assignment 11111111-2222-4333-8444-555555555555",
    cause: /another role on the subscription \(11111111-2222-4333-8444-555555555555\)/u,
    fix: /only the Reader and Security Reader roles/u,
  },
  {
    provider: "azure",
    detail: "operation is not authorized: Azure principal must have exactly the Reader and Security Reader profiles at the assessed subscription scope",
    cause: /does not have both the Reader and Security Reader roles/u,
    fix: /Access control \(IAM\)/u,
  },
  {
    provider: "azure",
    detail: "operation is not authorized: Azure Resource Manager token exchange failed with provider HTTP status 400 (invalid_grant, error code 650057)",
    cause: /does not include a permission this sign-in asks for/u,
    fix: /every permission listed in step 1/u,
  },
  {
    provider: "gcp",
    detail: "operation is not authorized: Google Cloud credential permits prohibited mutation resourcemanager.organizations.setIamPolicy",
    cause: /can change the organization's access settings \(resourcemanager\.organizations\.setIamPolicy\)/u,
    fix: /only the read roles from step 1/u,
  },
  {
    provider: "gcp",
    detail: "operation is not authorized: Google Cloud read-only profile is missing required permission resourcemanager.projects.list",
    cause: /cannot read resourcemanager\.projects\.list/u,
    fix: /read roles from step 1 at the organization/u,
  },
  {
    provider: "gcp",
    detail: "operation is not authorized: provider token omitted requested scope cloud-platform.read-only",
    cause: /Google's page did not grant cloud-platform\.read-only/u,
    fix: /allow every access/u,
  },
  {
    provider: "aws",
    detail: "operation is not authorized: the AWS sign-in code expired before sign-in finished; start the sign-in again",
    cause: /took too long/u,
    fix: /Start again/u,
  },
  {
    provider: "gcp",
    detail: "operation is not authorized: Google PKCE callback is expired or has an invalid state binding",
    cause: /took too long/u,
    fix: /Start again/u,
  },
  {
    provider: "microsoft365",
    detail: "operation is not authorized: the Microsoft sign-in was declined",
    cause: /declined on the provider's page/u,
    fix: /approve the read access/u,
  },
];

test("a sign-in refused for too much or too little access names the cause and the fix", () => {
  for (const refusal of refusals) {
    const explained = explainProviderRejection(refusal.provider, refusal.detail);
    assert.ok(explained, `${refusal.detail} should be explained`);
    assert.match(explained.cause.en, refusal.cause, refusal.detail);
    assert.match(explained.fix.en, refusal.fix, refusal.detail);
    assert.ok(explained.cause.zhTW.trim() && explained.fix.zhTW.trim());
    assert.doesNotMatch(explained.cause.en, /retry/iu);
  }
});

test("rejection rules read sentences the Rust sign-in actually writes", () => {
  const rust = `${providerSource}\n${executorSource}`;
  for (const anchor of [
    "AWS credential permits prohibited mutation {permission}",
    "AWS read-only profile is missing required permission {permission}",
    "the AWS account/role is not assigned to the authenticated IAM Identity Center user",
    "AWS STS identity does not match the configured account and read-only role",
    "AWS IAM returned a different role than the signed-in IAM Identity Center session",
    "the AWS role ARN in the connection details is not the role the person signed in with",
    "\"AWS IAM read-only policy simulation\"",
    "\"AWS IAM Identity Center role lookup\"",
    "\"AWS account role listing\"",
    "\"AWS short-lived role credential retrieval\"",
    "\"AWS IAM Identity Center client registration\"",
    "\"AWS IAM Identity Center device authorization\"",
    "Microsoft token includes prohibited write permission {permission}",
    "Microsoft token contains a non-read-only permission {}",
    "Microsoft token is missing required read permission {permission}",
    "provider token omitted requested scope {}",
    "Azure principal has an additional unapproved role assignment {}",
    "Azure principal must have exactly the Reader and Security Reader profiles",
    "\"Azure subscription identity verification\"",
    "\"Azure role assignment verification\"",
    "Azure token identity does not match the configured tenant",
    "Microsoft Graph organization does not match the configured tenant",
    "Microsoft administrator signed into a different tenant",
    "\"Microsoft 365 audit metadata permission probe\"",
    "\"Microsoft 365 policy permission probe\"",
    "\"Microsoft 365 role management permission probe\"",
    "Google Cloud credential permits prohibited mutation {permission}",
    "Google Cloud read-only profile is missing required permission {permission}",
    "Google Cloud returned a different organization identity",
    "\"Google Cloud organization identity verification\"",
    "the {provider} sign-in code expired before sign-in finished",
    "device authorization expired before completion",
    "did not complete device authorization in time",
    "PKCE callback is expired",
    "the {provider} sign-in was declined",
    "{operation} failed with provider HTTP status {}{}",
    "(error code {code})",
    "{name}, error code {code}",
  ]) {
    assert.ok(rust.includes(anchor), `the Rust sign-in no longer writes: ${anchor}`);
  }
});

test("an unrecognized refusal keeps the panel's general message", () => {
  assert.equal(explainProviderRejection("aws", undefined), undefined);
  assert.equal(explainProviderRejection("aws", "provider unavailable: connection reset"), undefined);
  // Microsoft identity-platform codes belong to Microsoft sign-ins only.
  assert.equal(
    explainProviderRejection("aws", "operation is not authorized: the AWS sign-in failed with invalid_grant (error code 7000218)"),
    undefined,
  );
  assert.equal(
    explainProviderRejection("microsoft365", "operation is not authorized: the Microsoft sign-in failed with invalid_grant (error code 1)"),
    undefined,
  );
});
