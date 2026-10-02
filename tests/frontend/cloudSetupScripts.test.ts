import assert from "node:assert/strict";
import { spawn, spawnSync } from "node:child_process";
import { chmodSync, existsSync, mkdirSync, mkdtempSync, readFileSync, rmSync, symlinkSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import test from "node:test";
import { fileURLToPath } from "node:url";

import { build } from "esbuild";

// The setup scripts change a real AWS account or Microsoft 365 tenant, so they
// run here end to end against stand-ins that answer in the providers'
// documented response shapes: a fake `aws` command for the AWS script and a
// fake Microsoft Graph sign-in module for the PowerShell script.

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

const { AWS_READ_ONLY_PERMISSION_SET, MICROSOFT_365_READ_PERMISSIONS } = await bundle("../../src/cloudSetupGuide.ts");

const path = (relative: string) => fileURLToPath(new URL(relative, import.meta.url));
const awsScript = path("../../cloud-setup/aws-read-only.sh");
const microsoftScript = path("../../cloud-setup/microsoft365-read-only.ps1");
const fakeAws = path("../fixtures/cloud-setup/fake-aws.mjs");
const fakeGraphModules = path("../fixtures/cloud-setup/modules");
const panelSource = readFileSync(path("../../src/components/ProviderAuthorizationPanel.tsx"), "utf8");
const providerSource = readFileSync(path("../../src-tauri/src/source_authorization/provider.rs"), "utf8");

const schemaVersion = /const CONNECTION_SETUP_SCHEMA_VERSION = "([^"]+)";/u.exec(panelSource)?.[1];
const setupFields = (provider: string): string[] => {
  const block = panelSource.slice(panelSource.indexOf("const connectionSetupFileFields"));
  const preferred = new RegExp(`${provider}: \\{\\s*preferred: \\[([^\\]]+)\\]`, "u").exec(block)?.[1];
  assert.ok(preferred, `the panel should list the ${provider} setup file fields`);
  return Array.from(preferred.matchAll(/"([^"]+)"/gu), (match) => match[1]!).sort();
};
const uuid = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/iu;

interface Run {
  status: number | null;
  stdout: string;
  stderr: string;
}

// Each run gets its own session, so it has no terminal to prompt on.
const run = (command: string, args: string[], cwd: string, env: Record<string, string>): Promise<Run> =>
  new Promise((resolve, reject) => {
    const child = spawn(command, args, { cwd, env, detached: true, stdio: ["ignore", "pipe", "pipe"] });
    let stdout = "";
    let stderr = "";
    child.stdout.on("data", (chunk) => { stdout += chunk; });
    child.stderr.on("data", (chunk) => { stderr += chunk; });
    const timer = setTimeout(() => child.kill("SIGKILL"), 90_000);
    child.on("error", reject);
    child.on("close", (status) => {
      clearTimeout(timer);
      resolve({ status, stdout, stderr });
    });
  });

const workspace = (t: { after: (fn: () => void) => void }) => {
  const dir = mkdtempSync(join(tmpdir(), "aiss-cloud-setup-"));
  t.after(() => rmSync(dir, { recursive: true, force: true }));
  return dir;
};

// ---------------------------------------------------------------- AWS

const managementAccount = "111122223333";
const instanceArn = "arn:aws:sso:::instance/ssoins-1111222233334444";
const securityAuditArn = `arn:aws:iam::aws:policy/${AWS_READ_ONLY_PERMISSION_SET}`;

const awsState = (overrides: Record<string, unknown> = {}) => ({
  caller: { UserId: "AIDAEXAMPLE", Account: managementAccount, Arn: `arn:aws:iam::${managementAccount}:user/owner` },
  organization: {
    Id: "o-exampleorgid",
    Arn: `arn:aws:organizations::${managementAccount}:organization/o-exampleorgid`,
    FeatureSet: "ALL",
    MasterAccountArn: `arn:aws:organizations::${managementAccount}:account/o-exampleorgid/${managementAccount}`,
    MasterAccountId: managementAccount,
    MasterAccountEmail: "owner@example.com",
  },
  enabledRegions: ["us-east-1", "us-east-2", "us-west-2"],
  instances: {
    "us-east-2": [{
      InstanceArn: instanceArn,
      IdentityStoreId: "d-9a67221e13",
      OwnerAccountId: managementAccount,
      Name: "",
      CreatedDate: "2026-10-01T12:00:00+00:00",
      Status: "ACTIVE",
    }],
  },
  permissionSets: [],
  users: [{
    IdentityStoreId: "d-9a67221e13",
    UserId: "94482488-3041-7026-18f3-be45837cd0e4",
    UserName: "ted",
    DisplayName: "Ted Owner",
    Emails: [{ Value: "ted@example.com", Type: "work", Primary: true }],
  }],
  assignments: [],
  requests: {},
  calls: [],
  ...overrides,
});

const runAws = async (dir: string, state: object, args: string[] = []) => {
  const statePath = join(dir, "aws-state.json");
  writeFileSync(statePath, JSON.stringify(state));
  const bin = join(dir, "bin");
  if (!existsSync(bin)) {
    mkdirSync(bin);
    writeFileSync(join(bin, "aws"), `#!/bin/sh\nexec "${process.execPath}" "${fakeAws}" "$@"\n`);
    chmodSync(join(bin, "aws"), 0o755);
  }
  const result = await run("bash", [awsScript, ...args], dir, {
    PATH: `${bin}:${process.env.PATH ?? "/usr/bin:/bin"}`,
    HOME: dir,
    AWS_REGION: "us-east-1",
    FAKE_AWS_STATE: statePath,
  });
  const after = JSON.parse(readFileSync(statePath, "utf8"));
  return { ...result, state: after, calls: after.calls as Array<{ service: string; operation: string; options: Record<string, string> }> };
};

const writes = (calls: Array<{ operation: string }>) =>
  calls.map((call) => call.operation).filter((operation) => !/^(get|list|describe)-/u.test(operation));

test("the AWS script prepares a fresh account, and a second run changes nothing", async (t) => {
  const dir = workspace(t);
  const first = await runAws(dir, awsState());
  assert.equal(first.status, 0, first.stderr);
  assert.deepEqual(writes(first.calls), [
    "create-permission-set",
    "attach-managed-policy-to-permission-set",
    "create-account-assignment",
  ]);
  const [permissionSet] = first.state.permissionSets;
  assert.equal(permissionSet.name, AWS_READ_ONLY_PERMISSION_SET);
  assert.deepEqual(permissionSet.managed, [{ Name: AWS_READ_ONLY_PERMISSION_SET, Arn: securityAuditArn }]);
  assert.equal(permissionSet.sessionDuration, "PT1H");
  assert.deepEqual(first.state.assignments, [{
    AccountId: managementAccount,
    PermissionSetArn: permissionSet.arn,
    PrincipalType: "USER",
    PrincipalId: "94482488-3041-7026-18f3-be45837cd0e4",
  }]);
  // Identity Center was found outside CloudShell's own Region.
  assert.ok(first.calls.some((call) => call.operation === "describe-regions"));
  assert.match(first.stdout, /AWS access portal start URL:\s+https:\/\/d-9a67221e13\.awsapps\.com\/start/u);
  assert.match(first.stdout, /IAM Identity Center region:\s+us-east-2/u);
  assert.match(first.stdout, /sign in as ted, not as the root user/u);

  const setup = JSON.parse(readFileSync(join(dir, "ai-security-scanner-aws-setup.json"), "utf8"));
  assert.deepEqual(setup, {
    schema_version: schemaVersion,
    provider: "aws",
    connection_method: "existing_read_only",
    details: {
      start_url: "https://d-9a67221e13.awsapps.com/start",
      region: "us-east-2",
      account_id: managementAccount,
      role_name: AWS_READ_ONLY_PERMISSION_SET,
    },
  });
  assert.deepEqual(Object.keys(setup.details).sort(), setupFields("aws"));

  const second = await runAws(dir, { ...first.state, calls: [] });
  assert.equal(second.status, 0, second.stderr);
  assert.deepEqual(writes(second.calls), []);
  assert.match(second.stdout, /Permission set SecurityAudit is already in place/u);
  assert.match(second.stdout, /ted already holds SecurityAudit/u);
});

test("the AWS script reuses a console-made SecurityAudit permission set", async (t) => {
  const dir = workspace(t);
  const existing = {
    arn: `${instanceArn.replace(":::instance/", ":::permissionSet/")}/ps-0123456789abcdef`,
    name: AWS_READ_ONLY_PERMISSION_SET,
    description: "",
    sessionDuration: "PT1H",
    managed: [{ Name: AWS_READ_ONLY_PERMISSION_SET, Arn: securityAuditArn }],
    customer: [],
    inline: "",
    provisionedAccounts: [],
  };
  const result = await runAws(dir, awsState({ permissionSets: [existing] }));
  assert.equal(result.status, 0, result.stderr);
  assert.deepEqual(writes(result.calls), ["create-account-assignment"]);
});

test("the AWS script stops before touching a SecurityAudit permission set that grants more", async (t) => {
  const dir = workspace(t);
  const broader = {
    arn: `${instanceArn.replace(":::instance/", ":::permissionSet/")}/ps-0123456789abcdef`,
    name: AWS_READ_ONLY_PERMISSION_SET,
    description: "",
    sessionDuration: "PT1H",
    managed: [
      { Name: AWS_READ_ONLY_PERMISSION_SET, Arn: securityAuditArn },
      { Name: "AdministratorAccess", Arn: "arn:aws:iam::aws:policy/AdministratorAccess" },
    ],
    customer: [],
    inline: "{\"Version\":\"2012-10-17\",\"Statement\":[]}",
    provisionedAccounts: [managementAccount],
  };
  const result = await runAws(dir, awsState({ permissionSets: [broader] }));
  assert.equal(result.status, 1);
  assert.match(result.stderr, /also grants AdministratorAccess, an inline policy/u);
  assert.deepEqual(writes(result.calls), []);
  assert.equal(existsSync(join(dir, "ai-security-scanner-aws-setup.json")), false);
});

test("the AWS script names the console step when IAM Identity Center is off", async (t) => {
  const dir = workspace(t);
  const result = await runAws(dir, awsState({ instances: {} }));
  assert.equal(result.status, 1);
  assert.match(result.stderr, /choose Enable, then Enable with AWS Organizations/u);
  assert.deepEqual(writes(result.calls), []);
});

test("the AWS script refuses an account instance, which cannot grant AWS account access", async (t) => {
  const dir = workspace(t);
  const state = awsState();
  state.instances["us-east-2"][0]!.OwnerAccountId = "444455556666";
  const result = await runAws(dir, state);
  assert.equal(result.status, 1);
  assert.match(result.stderr, /belongs to account 444455556666 alone/u);
  assert.deepEqual(writes(result.calls), []);
});

test("the AWS script refuses an account instance in an account outside AWS Organizations", async (t) => {
  const dir = workspace(t);
  const result = await runAws(dir, awsState({ organization: null }));
  assert.equal(result.status, 1);
  assert.match(result.stderr, /is an account instance\. AWS does not let an account instance grant access/u);
  assert.deepEqual(writes(result.calls), []);
});

test("with several users the AWS script asks which one, and --user picks by email", async (t) => {
  const dir = workspace(t);
  const users = [
    ...awsState().users,
    {
      IdentityStoreId: "d-9a67221e13",
      UserId: "c4b8f4a8-1001-70c2-5a1e-0b2c3d4e5f60",
      UserName: "alex",
      DisplayName: "Alex Analyst",
      Emails: [{ Value: "Alex@Example.com", Type: "work", Primary: true }],
    },
  ];
  const withoutTerminal = await runAws(dir, awsState({ users }));
  assert.equal(withoutTerminal.status, 1);
  assert.match(withoutTerminal.stderr, /several users\. Run this script again with --user/u);
  assert.deepEqual(writes(withoutTerminal.calls), []);

  const chosen = await runAws(dir, { ...withoutTerminal.state, calls: [] }, ["--user", "alex@example.com"]);
  assert.equal(chosen.status, 0, chosen.stderr);
  assert.deepEqual(writes(chosen.calls), [
    "create-permission-set",
    "attach-managed-policy-to-permission-set",
    "create-account-assignment",
  ]);
  assert.equal(chosen.state.assignments[0].PrincipalId, "c4b8f4a8-1001-70c2-5a1e-0b2c3d4e5f60");
  assert.match(chosen.stdout, /sign in as alex/u);
});

test("the AWS script asks for the permission set the app signs in with", () => {
  const source = readFileSync(awsScript, "utf8");
  assert.match(source, new RegExp(`readonly PERMISSION_SET_NAME="${AWS_READ_ONLY_PERMISSION_SET}"`, "u"));
  assert.match(source, new RegExp(`readonly POLICY_ARN="${securityAuditArn}"`, "u"));
  assert.doesNotMatch(source, /\b(delete|detach|remove)-[a-z-]+/u, "the script never removes anything");
});

// ---------------------------------------------------------------- Microsoft 365

const pwsh = process.env.PWSH ?? "pwsh";
const pwshAvailable = spawnSync(pwsh, ["-NoProfile", "-Command", "exit 0"]).status === 0;
const skipWithoutPwsh = pwshAvailable
  ? false
  : process.env.CI ? false : "PowerShell 7 (pwsh) is not installed here; CI runs these";

const tenantId = "60a3a040-7223-457a-b1c9-48a2447faff4";
const graphAppId = "00000003-0000-0000-c000-000000000000";
const graphPrincipalId = "1f0e2d3c-4b5a-4968-8776-655443322110";

// The OpenID Connect scopes the Microsoft 365 sign-in requests besides the
// read permissions.
const signInScopes = Array.from(
  (/Microsoft365TenantReadOnlyAccessToken => \{\s*let mut scopes = vec!\[([^\]]+)\]/u.exec(providerSource)?.[1] ?? "")
    .matchAll(/"([^"]+)"/gu),
  (match) => match[1]!,
);
const appPermissions: string[] = [...signInScopes, ...MICROSOFT_365_READ_PERMISSIONS];

// Scope IDs are stand-ins; the script looks every ID up by permission name.
const graphScopes = [
  ...appPermissions,
  "User.Read",
  "Directory.ReadWrite.All",
  "User.ReadWrite.All",
  "Application.ReadWrite.All",
].map((value: string, index: number) => ({
  id: `00000000-0000-4000-8000-${String(index + 1).padStart(12, "0")}`,
  value,
  type: value.endsWith(".All") || value.endsWith(".Directory") ? "Admin" : "User",
  isEnabled: true,
}));
const scopeId = (name: string) => graphScopes.find((scope) => scope.value === name)!.id;

const graphState = (overrides: Record<string, unknown> = {}) => ({
  tenantId,
  graphServicePrincipal: { id: graphPrincipalId, oauth2PermissionScopes: graphScopes },
  applications: [],
  servicePrincipals: [],
  oauth2PermissionGrants: [],
  replicationDelays: 0,
  calls: [],
  ...overrides,
});

const runMicrosoft = async (dir: string, state: object, args: string[] = []) => {
  const statePath = join(dir, "graph-state.json");
  writeFileSync(statePath, JSON.stringify(state));
  // PowerShell searches the user's own module folder before the machine-wide
  // ones, so the fake sign-in module goes there. A runner that has the real
  // Microsoft Graph module installed for all users would otherwise load it.
  const userModules = join(dir, ".local", "share", "powershell", "Modules");
  if (!existsSync(userModules)) {
    mkdirSync(dirname(userModules), { recursive: true });
    symlinkSync(fakeGraphModules, userModules, "dir");
  }
  const result = await run(pwsh, ["-NoProfile", "-NonInteractive", "-File", microsoftScript, ...args], dir, {
    PATH: process.env.PATH ?? "/usr/bin:/bin",
    HOME: dir,
    FAKE_GRAPH_STATE: statePath,
    POWERSHELL_TELEMETRY_OPTOUT: "1",
    POWERSHELL_UPDATECHECK: "Off",
    DOTNET_CLI_TELEMETRY_OPTOUT: "1",
  });
  const after = JSON.parse(readFileSync(statePath, "utf8"));
  const calls = (after.calls ?? []) as Array<{ method: string; uri: string; body: string | null }>;
  return { ...result, state: after, calls, changes: calls.filter((call) => call.method !== "GET") };
};

const appAccess = () => appPermissions.map((name) => ({ id: scopeId(name), type: "Scope" }));

test("the Microsoft 365 script prepares a fresh tenant, and a second run changes nothing", { skip: skipWithoutPwsh }, async (t) => {
  const dir = workspace(t);
  const first = await runMicrosoft(dir, graphState({ replicationDelays: 1 }));
  assert.equal(first.status, 0, first.stdout + first.stderr);
  assert.deepEqual(first.state.connect, {
    scopes: ["Application.ReadWrite.All", "DelegatedPermissionGrant.ReadWrite.All"],
    tenantId: "",
    contextScope: "Process",
    useDeviceCode: false,
  });
  assert.equal(first.state.disconnected, true);
  assert.deepEqual(first.changes.map((call) => `${call.method} ${call.uri}`), [
    "POST /v1.0/applications",
    "POST /v1.0/servicePrincipals",
    "POST /v1.0/servicePrincipals",
    "POST /v1.0/oauth2PermissionGrants",
  ]);

  const [app] = first.state.applications;
  assert.equal(app.displayName, "ai-security-scanner");
  assert.equal(app.signInAudience, "AzureADMyOrg");
  assert.equal(app.isFallbackPublicClient, true);
  assert.deepEqual(app.requiredResourceAccess, [{ resourceAppId: graphAppId, resourceAccess: appAccess() }]);
  const [principal] = first.state.servicePrincipals;
  assert.equal(principal.appId, app.appId);
  assert.deepEqual(first.state.oauth2PermissionGrants.map(({ id: _id, ...grant }: Record<string, unknown>) => grant), [{
    clientId: principal.id,
    consentType: "AllPrincipals",
    principalId: null,
    resourceId: graphPrincipalId,
    scope: appPermissions.join(" "),
  }]);

  assert.match(first.stdout, new RegExp(`Tenant ID:\\s+${tenantId}`, "u"));
  assert.match(first.stdout, new RegExp(`Application \\(client\\) ID:\\s+${app.appId}`, "u"));
  const setup = JSON.parse(readFileSync(join(dir, "ai-security-scanner-microsoft365-setup.json"), "utf8"));
  assert.deepEqual(setup, {
    schema_version: schemaVersion,
    provider: "microsoft365",
    connection_method: "existing_read_only",
    details: { tenant_id: tenantId, public_client_id: app.appId },
  });
  assert.deepEqual(Object.keys(setup.details).sort(), setupFields("microsoft365"));
  assert.match(setup.details.public_client_id, uuid);

  const second = await runMicrosoft(dir, { ...first.state, calls: [], disconnected: false });
  assert.equal(second.status, 0, second.stdout + second.stderr);
  assert.deepEqual(second.changes, []);
  assert.match(second.stdout, /The app ai-security-scanner is already in place/u);
  assert.match(second.stdout, /Admin consent is already in place/u);
});

test("the Microsoft 365 script completes an app registered in the portal", { skip: skipWithoutPwsh }, async (t) => {
  const dir = workspace(t);
  const app = {
    id: "7d1c2b3a-4f5e-4d6c-8b7a-695847362514",
    appId: "3e2d1c0b-9a8f-4e7d-8c6b-5a4938271605",
    displayName: "ai-security-scanner",
    signInAudience: "AzureADMyOrg",
    isFallbackPublicClient: null,
    requiredResourceAccess: [{ resourceAppId: graphAppId, resourceAccess: [{ id: scopeId("User.Read"), type: "Scope" }] }],
  };
  const principal = { id: "a1b2c3d4-e5f6-4a7b-8c9d-0e1f2a3b4c5d", appId: app.appId };
  const grant = {
    id: "l5eW7x0ga0-WDOntXzHateQDNpSH5-lPk9HjD3Sarjk",
    clientId: principal.id,
    consentType: "AllPrincipals",
    principalId: null,
    resourceId: graphPrincipalId,
    scope: "User.Read",
  };
  const result = await runMicrosoft(dir, graphState({
    applications: [app],
    servicePrincipals: [principal],
    oauth2PermissionGrants: [grant],
  }));
  assert.equal(result.status, 0, result.stdout + result.stderr);
  assert.deepEqual(result.changes.map((call) => `${call.method} ${call.uri}`), [
    `PATCH /v1.0/applications/${app.id}`,
    `PATCH /v1.0/applications/${app.id}`,
    "PATCH /v1.0/oauth2PermissionGrants/l5eW7x0ga0-WDOntXzHateQDNpSH5-lPk9HjD3Sarjk",
  ]);
  const [updated] = result.state.applications;
  assert.equal(updated.isFallbackPublicClient, true);
  assert.deepEqual(updated.requiredResourceAccess, [{
    resourceAppId: graphAppId,
    resourceAccess: [{ id: scopeId("User.Read"), type: "Scope" }, ...appAccess()],
  }]);
  assert.equal(result.state.oauth2PermissionGrants[0].scope, ["User.Read", ...appPermissions].join(" "));
  assert.match(result.stdout, new RegExp(`Application \\(client\\) ID:\\s+${app.appId}`, "u"));
});

test("the Microsoft 365 script stops before an app that can change the tenant", { skip: skipWithoutPwsh }, async (t) => {
  const dir = workspace(t);
  const asksForWrite = {
    id: "7d1c2b3a-4f5e-4d6c-8b7a-695847362514",
    appId: "3e2d1c0b-9a8f-4e7d-8c6b-5a4938271605",
    displayName: "ai-security-scanner",
    signInAudience: "AzureADMyOrg",
    isFallbackPublicClient: true,
    requiredResourceAccess: [{
      resourceAppId: graphAppId,
      resourceAccess: [...appAccess(), { id: scopeId("Directory.ReadWrite.All"), type: "Scope" }],
    }],
  };
  const requested = await runMicrosoft(dir, graphState({ applications: [asksForWrite] }));
  assert.equal(requested.status, 1);
  assert.match(requested.stdout, /also asks for Directory\.ReadWrite\.All/u);
  assert.deepEqual(requested.changes, []);
  assert.equal(requested.state.disconnected, true);
  assert.equal(existsSync(join(dir, "ai-security-scanner-microsoft365-setup.json")), false);

  const readOnly = { ...asksForWrite, requiredResourceAccess: [{ resourceAppId: graphAppId, resourceAccess: appAccess() }] };
  const principal = { id: "a1b2c3d4-e5f6-4a7b-8c9d-0e1f2a3b4c5d", appId: readOnly.appId };
  const consented = await runMicrosoft(dir, graphState({
    applications: [readOnly],
    servicePrincipals: [principal],
    oauth2PermissionGrants: [{
      id: "m6fX8y1hb1-XEPouYaIbufREOqTI6-mQl0IkE4Tbskl",
      clientId: principal.id,
      consentType: "Principal",
      principalId: "5e4d3c2b-1a09-4f8e-9d7c-6b5a49382716",
      resourceId: graphPrincipalId,
      scope: "User.ReadWrite.All",
    }],
  }));
  assert.equal(consented.status, 1);
  assert.match(consented.stdout, /already has consent for User\.ReadWrite\.All/u);
  assert.deepEqual(consented.changes, []);
});

test("the Microsoft 365 script stops when two apps share the name", { skip: skipWithoutPwsh }, async (t) => {
  const dir = workspace(t);
  const twin = (id: string) => ({
    id,
    appId: id.replace(/^./u, "e"),
    displayName: "ai-security-scanner",
    signInAudience: "AzureADMyOrg",
    isFallbackPublicClient: true,
    requiredResourceAccess: [],
  });
  const result = await runMicrosoft(dir, graphState({
    applications: [twin("1d1c2b3a-4f5e-4d6c-8b7a-695847362514"), twin("2d1c2b3a-4f5e-4d6c-8b7a-695847362514")],
  }));
  assert.equal(result.status, 1);
  assert.match(result.stdout, /2 app registrations named ai-security-scanner/u);
  assert.deepEqual(result.changes, []);
});

test("the Microsoft 365 script asks for exactly the permissions the sign-in requests", () => {
  const source = readFileSync(microsoftScript, "utf8");
  const listed = (name: string) => {
    const body = new RegExp(`\\$${name} = @\\(([^)]*)\\)`, "u").exec(source)?.[1];
    assert.ok(body, `the script should list $${name}`);
    return Array.from(body.matchAll(/'([^']+)'/gu), (match) => match[1]);
  };
  assert.deepEqual(listed("ReadPermissions"), [...MICROSOFT_365_READ_PERMISSIONS]);
  assert.deepEqual(signInScopes, ["openid", "profile", "offline_access"]);
  assert.deepEqual(listed("SignInPermissions"), signInScopes);
  assert.doesNotMatch(source, /Invoke-Graph DELETE|-Method DELETE/u, "the script never removes anything");
});
