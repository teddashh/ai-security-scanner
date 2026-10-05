import assert from "node:assert/strict";
import { spawn, spawnSync } from "node:child_process";
import { chmodSync, existsSync, mkdirSync, mkdtempSync, readFileSync, readdirSync, rmSync, symlinkSync, writeFileSync } from "node:fs";
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

// What the script signs in with, and a token for them in Microsoft's JWT shape.
const graphPowerShellClientId = "14d82eec-204b-4c2f-b7e8-296a70dab67e";
const setupScopes = ["Application.ReadWrite.All", "DelegatedPermissionGrant.ReadWrite.All"];
const base64url = (value: object) => Buffer.from(JSON.stringify(value)).toString("base64url");
const setupClaims = { tid: tenantId, scp: setupScopes.join(" "), exp: 4102444800 };
const setupToken = [base64url({ typ: "JWT", alg: "RS256" }), base64url(setupClaims), "c2lnbmF0dXJl"].join(".");

const graphState = (overrides: Record<string, unknown> = {}) => ({
  tenantId,
  graphServicePrincipal: { id: graphPrincipalId, oauth2PermissionScopes: graphScopes },
  applications: [],
  servicePrincipals: [],
  oauth2PermissionGrants: [],
  replicationDelays: 0,
  calls: [],
  signIn: { pending: 1, token: setupToken, refusal: null },
  login: [],
  ...overrides,
});

const runMicrosoft = async (dir: string, state: object, args: string[] = [], script = microsoftScript) => {
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
  const result = await run(pwsh, ["-NoProfile", "-NonInteractive", "-File", script, ...args], dir, {
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
  assert.deepEqual(first.state.connect, { scopes: setupScopes, tenantId: "", contextScope: "Process" });
  assert.deepEqual(first.state.login, []);
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

test("the Microsoft 365 script signs in with a one-time code when asked, and always on Windows", { skip: skipWithoutPwsh }, async (t) => {
  const dir = workspace(t);
  const result = await runMicrosoft(dir, graphState(), ["-UseDeviceCode"]);
  assert.equal(result.status, 0, result.stdout + result.stderr);

  // Windows PowerShell 5.1 crashed inside Connect-MgGraph's own device-code
  // sign-in, so the script asks Microsoft's sign-in service for the code and
  // polls for the token itself, then hands Connect-MgGraph only the token.
  const endpoint = "https://login.microsoftonline.com/organizations/oauth2/v2.0";
  const [request, ...polls] = result.state.login;
  assert.equal(request.uri, `${endpoint}/devicecode`);
  assert.deepEqual(request.body, {
    client_id: graphPowerShellClientId,
    scope: setupScopes.map((scope) => `https://graph.microsoft.com/${scope}`).join(" "),
  });
  assert.equal(polls.length, 2, "one answer that the sign-in is pending, then the token");
  for (const poll of polls) {
    assert.equal(poll.uri, `${endpoint}/token`);
    assert.deepEqual(poll.body, {
      grant_type: "urn:ietf:params:oauth:grant-type:device_code",
      client_id: graphPowerShellClientId,
      device_code: "fake-device-code",
    });
  }
  assert.deepEqual(result.state.connect, { accessToken: true, tenantId, scopes: setupScopes });

  // The person can sign in only if the script shows the code, and the token
  // never reaches the screen.
  assert.match(result.stdout, /login\.microsoft\.com\/device and enter the code FAKECODE1/u);
  assert.equal((result.stdout + result.stderr).includes(setupToken.split(".")[1]!), false);
  const setup = JSON.parse(readFileSync(join(dir, "ai-security-scanner-microsoft365-setup.json"), "utf8"));
  assert.equal(setup.details.tenant_id, tenantId);

  // On Windows the interactive sign-in is Windows's own window, which offers to
  // let the organization manage the computer. CI runs on Linux, so pin the
  // branch that keeps Windows on the one-time code.
  const source = readFileSync(microsoftScript, "utf8");
  assert.match(source, /\$onWindows = \[Environment\]::OSVersion\.Platform -eq \[PlatformID\]::Win32NT\n/u);
  assert.match(source, /if \(\$UseDeviceCode -or \$onWindows -or [^\n]+\) \{\n\s+\$token = Get-SignInToken\n/u);
});

test("the Microsoft 365 script stops when the one-time code sign-in is declined", { skip: skipWithoutPwsh }, async (t) => {
  const dir = workspace(t);
  const refusal = {
    error: "authorization_declined",
    error_description: "The end user denied the authorization request. Trace ID: 00000000-0000-0000-0000-000000000000 Correlation ID: 00000000-0000-0000-0000-000000000000 Timestamp: 2026-10-02 22:00:00Z",
  };
  const result = await runMicrosoft(
    dir,
    graphState({ signIn: { pending: 0, token: setupToken, refusal } }),
    ["-UseDeviceCode", "-TenantId", tenantId],
  );
  assert.equal(result.status, 1);
  assert.equal(result.state.login[0].uri, `https://login.microsoftonline.com/${tenantId}/oauth2/v2.0/devicecode`);
  assert.match(result.stdout, /Stopped: Microsoft stopped the sign-in: The end user denied the authorization request\.\n/u);
  assert.equal(result.state.connect, undefined);
  assert.deepEqual(result.calls, []);
  assert.equal(existsSync(join(dir, "ai-security-scanner-microsoft365-setup.json")), false);
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

const cleanupScript = path("../../cloud-setup/microsoft365-cleanup.ps1");
const receiptPath = (dir: string) => join(dir, readdirSync(dir).find((file) => /^ai-security-scanner-microsoft365-cleanup-.*\.json$/u.test(file))!);
const runCleanup = (dir: string, state: object, args: string[] = []) => runMicrosoft(dir, state, ["-ReceiptPath", receiptPath(dir), ...args], cleanupScript);

test("Microsoft 365 cleanup removes its own consent, principal and application, and can run twice", { skip: skipWithoutPwsh }, async (t) => {
  const dir = workspace(t);
  const setup = await runMicrosoft(dir, graphState({ replicationDelays: 1 }));
  assert.equal(setup.status, 0, setup.stdout + setup.stderr);
  const receipt = JSON.parse(readFileSync(receiptPath(dir), "utf8"));
  assert.equal(receipt.tenant_id, tenantId);
  assert.equal(receipt.actions.length, 4, "a failed replication attempt also keeps its intent");
  assert.equal(readFileSync(receiptPath(dir), "utf8").includes(setupToken), false);
  const cleanup = await runCleanup(dir, { ...setup.state, calls: [] });
  assert.equal(cleanup.status, 0, cleanup.stdout + cleanup.stderr);
  assert.deepEqual(cleanup.state.applications, []);
  assert.deepEqual(cleanup.state.servicePrincipals, []);
  assert.deepEqual(cleanup.state.oauth2PermissionGrants, []);
  assert.deepEqual(cleanup.changes.map((call) => call.method), ["DELETE", "DELETE", "DELETE"]);
  assert.equal(JSON.parse(readFileSync(receiptPath(dir), "utf8")).state, "completed");
  const again = await runCleanup(dir, { ...cleanup.state, calls: [], connect: null, disconnected: false });
  assert.equal(again.status, 0, again.stdout + again.stderr);
  assert.deepEqual(again.changes, []);
  assert.equal(again.state.connect, null, "a completed retry must not grant Graph helper consent again");
  assert.equal(again.state.disconnected, false);
});

test("Microsoft 365 cleanup preserves reused resources and permissions added by someone else", { skip: skipWithoutPwsh }, async (t) => {
  const dir = workspace(t);
  const app = {
    id: "7d1c2b3a-4f5e-4d6c-8b7a-695847362514", appId: "3e2d1c0b-9a8f-4e7d-8c6b-5a4938271605",
    displayName: "ai-security-scanner", isFallbackPublicClient: null,
    requiredResourceAccess: [{ resourceAppId: graphAppId, resourceAccess: [{ id: scopeId("User.Read"), type: "Scope" }] }],
  };
  const principal = { id: "a1b2c3d4-e5f6-4a7b-8c9d-0e1f2a3b4c5d", appId: app.appId };
  const grant = { id: "l5eW7x0ga0-WDOntXzHateQDNpSH5-lPk9HjD3Sarjk", clientId: principal.id, consentType: "AllPrincipals", principalId: null, resourceId: graphPrincipalId, scope: "User.Read" };
  const setup = await runMicrosoft(dir, graphState({ applications: [app], servicePrincipals: [principal], oauth2PermissionGrants: [grant] }));
  assert.equal(setup.status, 0, setup.stdout + setup.stderr);
  setup.state.oauth2PermissionGrants[0].scope += " Mail.Read";
  const otherResource = { resourceAppId: "9d1c2b3a-4f5e-4d6c-8b7a-695847362514", resourceAccess: [{ id: "8d1c2b3a-4f5e-4d6c-8b7a-695847362514", type: "Scope" }] };
  setup.state.applications[0].requiredResourceAccess.push(otherResource);
  const cleanup = await runCleanup(dir, { ...setup.state, calls: [] });
  assert.equal(cleanup.status, 0, cleanup.stdout + cleanup.stderr);
  assert.equal(cleanup.state.oauth2PermissionGrants[0].scope, "User.Read Mail.Read");
  assert.deepEqual(cleanup.state.servicePrincipals, [principal]);
  assert.deepEqual(cleanup.state.applications[0].requiredResourceAccess, [...app.requiredResourceAccess, otherResource]);
  assert.equal(cleanup.state.applications[0].isFallbackPublicClient, null);
  assert.equal(cleanup.changes.some((call) => call.method === "DELETE"), false);
});

test("Microsoft 365 cleanup previews without writes and retains failed work for retry", { skip: skipWithoutPwsh }, async (t) => {
  const dir = workspace(t);
  const setup = await runMicrosoft(dir, graphState());
  assert.equal(setup.status, 0, setup.stdout + setup.stderr);
  const original = readFileSync(receiptPath(dir), "utf8");
  const preview = await runCleanup(dir, { ...setup.state, calls: [] }, ["-WhatIf"]);
  assert.equal(preview.status, 0, preview.stdout + preview.stderr);
  assert.deepEqual(preview.changes, []);
  assert.equal(readFileSync(receiptPath(dir), "utf8"), original);
  const failure = await runCleanup(dir, { ...setup.state, calls: [], failDelete: true });
  assert.equal(failure.status, 1, failure.stdout + failure.stderr);
  assert.match(failure.stdout, /Cleanup incomplete/u);
  assert.equal(JSON.parse(readFileSync(receiptPath(dir), "utf8")).state, "cleanup_pending");
  const retry = await runCleanup(dir, { ...failure.state, calls: [], failDelete: false });
  assert.equal(retry.status, 0, retry.stdout + retry.stderr);
  assert.deepEqual(retry.state.applications, []);
});

test("Microsoft 365 cleanup refuses another tenant and malformed IDs before mutation", { skip: skipWithoutPwsh }, async (t) => {
  const dir = workspace(t);
  const setup = await runMicrosoft(dir, graphState());
  const otherTenant = await runCleanup(dir, { ...setup.state, calls: [], tenantId: "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa" });
  assert.equal(otherTenant.status, 1);
  assert.deepEqual(otherTenant.changes, []);
  const receipt = JSON.parse(readFileSync(receiptPath(dir), "utf8"));
  receipt.actions[0].id = "../other";
  writeFileSync(receiptPath(dir), JSON.stringify(receipt));
  const invalid = await runCleanup(dir, { ...setup.state, calls: [] });
  assert.equal(invalid.status, 1);
  assert.deepEqual(invalid.calls, []);
});

test("Graph PowerShell cleanup removes only two setup scopes from explicitly selected grants", { skip: skipWithoutPwsh }, async (t) => {
  const dir = workspace(t);
  const setup = await runMicrosoft(dir, graphState());
  const helper = { id: "c1b2c3d4-e5f6-4a7b-8c9d-0e1f2a3b4c5d", appId: graphPowerShellClientId };
  const selected = { id: "selected-helper-grant", clientId: helper.id, resourceId: graphPrincipalId, consentType: "Principal", principalId: "d1b2c3d4-e5f6-4a7b-8c9d-0e1f2a3b4c5d", scope: [...setupScopes, "User.Read"].join(" ") };
  const untouched = { ...selected, id: "other-helper-grant", consentType: "AllPrincipals", principalId: null };
  setup.state.servicePrincipals.push(helper);
  setup.state.oauth2PermissionGrants.push(selected, untouched);
  const cleanup = await runCleanup(dir, { ...setup.state, calls: [] }, ["-GraphPowerShellGrantId", selected.id]);
  assert.equal(cleanup.status, 0, cleanup.stdout + cleanup.stderr);
  assert.deepEqual(cleanup.state.servicePrincipals, [helper]);
  assert.deepEqual(cleanup.state.oauth2PermissionGrants, [{ ...selected, scope: "User.Read" }, untouched]);
  const again = await runCleanup(dir, { ...cleanup.state, calls: [], connect: null }, ["-GraphPowerShellGrantId", selected.id]);
  assert.equal(again.status, 0, again.stdout + again.stderr);
  assert.equal(again.state.connect, null);
  assert.deepEqual(again.changes, []);
});

const fakeScanner = path("../fixtures/cloud-setup/fake-scanner-cli.mjs");
const caseId = "case-cloud-test";
const runId = "run-cloud-test";
const scanStatus = (status: string, completed = false) => ({ case_id: caseId, runs: [{ id: runId, case_id: caseId, completed_at: completed ? "2026-10-04T00:00:00Z" : null, engine_runs: [{ status }] }] });
const prepareWatcher = (dir: string, statuses: object[], failExport = false) => {
  writeFileSync(join(dir, "scanner-state.json"), JSON.stringify({ caseId, runId, statuses, failExport, calls: [] }));
  return ["-WaitForRun", "-CaseId", caseId, "-RunId", runId, "-DataDir", dir, "-ReportPath", join(dir, "saved report.html"), "-CliPath", fakeScanner, "-PollSeconds", "1"];
};

test("automatic Graph cleanup waits through running and paused states, saves the report, then revokes", { skip: skipWithoutPwsh }, async (t) => {
  const dir = workspace(t);
  const setup = await runMicrosoft(dir, graphState(), ["-Temporary"]);
  assert.equal(setup.status, 0, setup.stdout + setup.stderr);
  assert.match(setup.state.applications[0].displayName, /^ai-security-scanner-[a-f0-9-]+$/u);
  const args = prepareWatcher(dir, [scanStatus("running"), scanStatus("paused"), scanStatus("failed", true)]);
  const cleanup = await runCleanup(dir, { ...setup.state, calls: [] }, args);
  assert.equal(cleanup.status, 0, cleanup.stdout + cleanup.stderr);
  const scanner = JSON.parse(readFileSync(join(dir, "scanner-state.json"), "utf8"));
  assert.equal(scanner.calls.length, 4);
  assert.equal(scanner.grantsAtExport, 1, "the report is saved before cloud permissions are revoked");
  assert.ok(existsSync(join(dir, "saved report.html")));
  assert.deepEqual(cleanup.state.applications, []);
  const receipt = JSON.parse(readFileSync(receiptPath(dir), "utf8"));
  assert.equal(receipt.report.run_id, runId);
  assert.equal(receipt.state, "completed");
});

test("automatic cleanup treats cancelled as terminal and still revokes if HTML export fails", { skip: skipWithoutPwsh }, async (t) => {
  const dir = workspace(t);
  const setup = await runMicrosoft(dir, graphState());
  const args = prepareWatcher(dir, [scanStatus("cancelled", true)], true);
  const cleanup = await runCleanup(dir, { ...setup.state, calls: [] }, args);
  assert.equal(cleanup.status, 1, cleanup.stdout + cleanup.stderr);
  assert.match(cleanup.stdout, /Access cleanup finished, but HTML export failed/u);
  assert.deepEqual(cleanup.state.applications, []);
  assert.equal(JSON.parse(readFileSync(receiptPath(dir), "utf8")).report, null);
});

test("automatic cleanup refuses to infer completion from queued, unknown, or unreadable scan state", { skip: skipWithoutPwsh }, async (t) => {
  const dir = workspace(t);
  const setup = await runMicrosoft(dir, graphState());
  // A completed timestamp alone does not make queued/resumable work terminal.
  const args = prepareWatcher(dir, [scanStatus("queued", true), scanStatus("future_unknown_state", true)]);
  const cleanup = await runCleanup(dir, { ...setup.state, calls: [] }, args);
  assert.equal(cleanup.status, 1, cleanup.stdout + cleanup.stderr);
  assert.deepEqual(cleanup.changes, []);
  assert.equal(existsSync(join(dir, "saved report.html")), false);
});

test("automatic cleanup refuses a mismatched run without exporting or revoking", { skip: skipWithoutPwsh }, async (t) => {
  const dir = workspace(t);
  const setup = await runMicrosoft(dir, graphState());
  const wrong = scanStatus("completed", true);
  wrong.runs[0]!.id = "different-run";
  const args = prepareWatcher(dir, [wrong]);
  const cleanup = await runCleanup(dir, { ...setup.state, calls: [] }, args);
  assert.equal(cleanup.status, 1);
  assert.deepEqual(cleanup.changes, []);
  assert.equal(existsSync(join(dir, "saved report.html")), false);
});

test("partial setup can be cleaned after Graph refuses consent creation", { skip: skipWithoutPwsh }, async (t) => {
  const dir = workspace(t);
  const setup = await runMicrosoft(dir, graphState({ denyGrantCreate: true }));
  assert.equal(setup.status, 1);
  assert.equal(setup.state.applications.length, 1);
  const cleanup = await runCleanup(dir, { ...setup.state, calls: [] });
  assert.equal(cleanup.status, 0, cleanup.stdout + cleanup.stderr);
  assert.deepEqual(cleanup.state.applications, []);
  assert.deepEqual(cleanup.state.servicePrincipals, []);
});

test("cleanup reconciles a creation whose response was not saved", { skip: skipWithoutPwsh }, async (t) => {
  const dir = workspace(t);
  const setup = await runMicrosoft(dir, graphState());
  const receipt = JSON.parse(readFileSync(receiptPath(dir), "utf8"));
  receipt.actions[0].id = null;
  delete receipt.actions[0].after.appId;
  receipt.actions[0].state = "pending";
  writeFileSync(receiptPath(dir), JSON.stringify(receipt));
  const cleanup = await runCleanup(dir, { ...setup.state, calls: [] });
  assert.equal(cleanup.status, 0, cleanup.stdout + cleanup.stderr);
  assert.deepEqual(cleanup.state.applications, []);
});

test("cleanup reports incomplete until Graph confirms deletion", { skip: skipWithoutPwsh }, async (t) => {
  const dir = workspace(t);
  const setup = await runMicrosoft(dir, graphState());
  const cleanup = await runCleanup(dir, { ...setup.state, calls: [], ignoreDelete: true });
  assert.equal(cleanup.status, 1);
  assert.match(cleanup.stdout, /has not confirmed the deletion/u);
  assert.equal(cleanup.state.servicePrincipals.length, 1);
  assert.equal(JSON.parse(readFileSync(receiptPath(dir), "utf8")).state, "cleanup_pending");
});

test("cleanup refuses any teardown when its created app has been repurposed", { skip: skipWithoutPwsh }, async (t) => {
  const dir = workspace(t);
  const setup = await runMicrosoft(dir, graphState());
  setup.state.applications[0].passwordCredentials.push({ keyId: "another-credential-id" });
  const cleanup = await runCleanup(dir, { ...setup.state, calls: [] });
  assert.equal(cleanup.status, 1);
  assert.deepEqual(cleanup.changes, []);
});

test("cleanup cannot consume a journal while setup is still creating resources", { skip: skipWithoutPwsh }, async (t) => {
  const dir = workspace(t);
  const setupTask = runMicrosoft(dir, graphState({ pauseBeforeUri: "/v1.0/applications" }));
  const deadline = Date.now() + 10_000;
  while (!existsSync(join(dir, "graph-paused"))) {
    assert.ok(Date.now() < deadline, "setup should reach the paused Graph request");
    await new Promise((resolve) => setTimeout(resolve, 25));
  }
  let result: Awaited<ReturnType<typeof runCleanup>>;
  try {
    const state = JSON.parse(readFileSync(join(dir, "graph-state.json"), "utf8"));
    result = await runCleanup(dir, { ...state, calls: [], connect: null });
    assert.equal(result.status, 1);
    assert.equal(result.state.connect, null, "lock conflict must stop before signing in");
    assert.deepEqual(result.changes, []);
  } finally { writeFileSync(join(dir, "graph-continue"), "continue"); }
  const setup = await setupTask;
  assert.equal(setup.status, 0, setup.stdout + setup.stderr);
  const cleanup = await runCleanup(dir, { ...setup.state, calls: [] });
  assert.equal(cleanup.status, 0, cleanup.stdout + cleanup.stderr);
});

test("setup refuses to overwrite a permission added after its initial app lookup", { skip: skipWithoutPwsh }, async (t) => {
  const dir = workspace(t);
  const other = { resourceAppId: "9d1c2b3a-4f5e-4d6c-8b7a-695847362514", resourceAccess: [{ id: "8d1c2b3a-4f5e-4d6c-8b7a-695847362514", type: "Scope" }] };
  const app = { id: "7d1c2b3a-4f5e-4d6c-8b7a-695847362514", appId: "3e2d1c0b-9a8f-4e7d-8c6b-5a4938271605", displayName: "ai-security-scanner", isFallbackPublicClient: true, requiredResourceAccess: [] };
  const setup = await runMicrosoft(dir, graphState({ applications: [app], changeAppOnRead: other }));
  assert.equal(setup.status, 1, setup.stdout + setup.stderr);
  assert.match(setup.stdout, /No stale update was sent/u);
  assert.deepEqual(setup.changes, []);
  assert.deepEqual(setup.state.applications[0].requiredResourceAccess, [other]);
});

test("cleanup requires the service principal creation marker before touching its grants", { skip: skipWithoutPwsh }, async (t) => {
  const dir = workspace(t);
  const setup = await runMicrosoft(dir, graphState());
  setup.state.servicePrincipals[0].tags = [];
  const cleanup = await runCleanup(dir, { ...setup.state, calls: [] });
  assert.equal(cleanup.status, 1);
  assert.deepEqual(cleanup.changes, []);
});

test("device-code cleanup renews expired access only in memory after waiting", { skip: skipWithoutPwsh }, async (t) => {
  const dir = workspace(t);
  const setup = await runMicrosoft(dir, graphState());
  const args = prepareWatcher(dir, [scanStatus("completed", true)]);
  const scannerStatePath = join(dir, "scanner-state.json");
  const scanner = JSON.parse(readFileSync(scannerStatePath, "utf8"));
  writeFileSync(scannerStatePath, JSON.stringify({ ...scanner, expireTokenOnFinish: true }));
  const refreshToken = "fake-refresh-token-only-for-tests";
  const cleanup = await runCleanup(dir, { ...setup.state, calls: [], login: [], signIn: { ...setup.state.signIn, pending: 0, refreshToken } }, [...args, "-UseDeviceCode"]);
  assert.equal(cleanup.status, 0, cleanup.stdout + cleanup.stderr);
  assert.equal(cleanup.state.refreshCount, 1);
  assert.equal(cleanup.state.login.filter((item: { uri: string }) => item.uri.endsWith("/devicecode")).length, 1);
  assert.ok(cleanup.state.login[0].body.scope.endsWith(" offline_access"));
  assert.deepEqual(cleanup.state.applications, []);
  assert.equal((readFileSync(receiptPath(dir), "utf8") + cleanup.stdout + cleanup.stderr).includes(refreshToken), false);
});

test("preview inspects an active scan once without waiting or exporting", { skip: skipWithoutPwsh }, async (t) => {
  const dir = workspace(t);
  const setup = await runMicrosoft(dir, graphState());
  const args = prepareWatcher(dir, [scanStatus("running")]);
  const cleanup = await runCleanup(dir, { ...setup.state, calls: [] }, [...args, "-WhatIf"]);
  assert.equal(cleanup.status, 0, cleanup.stdout + cleanup.stderr);
  assert.deepEqual(cleanup.changes, []);
  assert.equal(JSON.parse(readFileSync(join(dir, "scanner-state.json"), "utf8")).calls.length, 1);
  assert.equal(existsSync(join(dir, "saved report.html")), false);
});

test("explicit immediate revocation recovers a watched receipt when the scan status is unavailable", { skip: skipWithoutPwsh }, async (t) => {
  const dir = workspace(t);
  const setup = await runMicrosoft(dir, graphState());
  const args = prepareWatcher(dir, []);
  const first = await runCleanup(dir, { ...setup.state, calls: [] }, args);
  assert.equal(first.status, 1);
  assert.deepEqual(first.changes, []);
  const retry = await runCleanup(dir, { ...first.state, calls: [] }, ["-RevokeNow"]);
  assert.equal(retry.status, 0, retry.stdout + retry.stderr);
  assert.deepEqual(retry.state.applications, []);
  const receipt = JSON.parse(readFileSync(receiptPath(dir), "utf8"));
  assert.ok(receipt.immediate_revocation_requested_at);
  assert.equal(receipt.report, null);
});

test("listing helper grants after cleanup invalidates the completed shortcut", { skip: skipWithoutPwsh }, async (t) => {
  const dir = workspace(t);
  const setup = await runMicrosoft(dir, graphState());
  const helper = { id: "c1b2c3d4-e5f6-4a7b-8c9d-0e1f2a3b4c5d", appId: graphPowerShellClientId };
  const grant = { id: "repeat-helper-grant", clientId: helper.id, resourceId: graphPrincipalId, consentType: "Principal", principalId: "d1b2c3d4-e5f6-4a7b-8c9d-0e1f2a3b4c5d", scope: [...setupScopes, "User.Read"].join(" ") };
  setup.state.servicePrincipals.push(helper);
  setup.state.oauth2PermissionGrants.push(grant);
  const cleaned = await runCleanup(dir, { ...setup.state, calls: [] }, ["-GraphPowerShellGrantId", grant.id]);
  assert.equal(cleaned.status, 0, cleaned.stdout + cleaned.stderr);
  const listed = await runCleanup(dir, { ...cleaned.state, calls: [], helperConsentOnConnect: grant }, ["-ListGraphPowerShellGrants"]);
  assert.equal(listed.status, 0, listed.stdout + listed.stderr);
  assert.equal(JSON.parse(readFileSync(receiptPath(dir), "utf8")).state, "cleanup_pending");
  const again = await runCleanup(dir, { ...listed.state, calls: [] }, ["-GraphPowerShellGrantId", grant.id]);
  assert.equal(again.status, 0, again.stdout + again.stderr);
  assert.equal(again.state.oauth2PermissionGrants[0].scope, "User.Read");
});

test("a second no-change setup receipt never claims to have revoked existing access", { skip: skipWithoutPwsh }, async (t) => {
  const dir = workspace(t);
  const first = await runMicrosoft(dir, graphState());
  const original = receiptPath(dir);
  const second = await runMicrosoft(dir, { ...first.state, calls: [] });
  assert.equal(second.status, 0, second.stdout + second.stderr);
  assert.match(second.stdout, /This record revokes nothing/u);
  const latest = readdirSync(dir).map((name) => join(dir, name)).find((name) => name !== original && /microsoft365-cleanup-.*\.json$/u.test(name))!;
  const cleanup = await runMicrosoft(dir, { ...second.state, calls: [] }, ["-ReceiptPath", latest], cleanupScript);
  assert.equal(cleanup.status, 0, cleanup.stdout + cleanup.stderr);
  assert.match(cleanup.stdout, /No scanner access was revoked/u);
  assert.deepEqual(cleanup.changes, []);
  assert.equal(cleanup.state.oauth2PermissionGrants.length, 1);
});

test("relative receipt and Unicode report paths follow PowerShell's current location", { skip: skipWithoutPwsh }, async (t) => {
  const dir = workspace(t);
  const setup = await runMicrosoft(dir, graphState());
  prepareWatcher(dir, [scanStatus("completed", true)]);
  const sub = join(dir, "中文 子目錄");
  mkdirSync(sub);
  const quote = (value: string) => `'${value.replaceAll("'", "''")}'`;
  const wrapper = join(dir, "relative-path-test.ps1");
  writeFileSync(wrapper, `Set-Location -LiteralPath ${quote(sub)}\n& ${quote(cleanupScript)} -ReceiptPath ${quote("../" + receiptPath(dir).split("/").at(-1))} -WaitForRun -CaseId ${quote(caseId)} -RunId ${quote(runId)} -DataDir '..' -ReportPath './報告.html' -CliPath ${quote(fakeScanner)}\n`);
  const cleanup = await runMicrosoft(dir, { ...setup.state, calls: [] }, [], wrapper);
  assert.equal(cleanup.status, 0, cleanup.stdout + cleanup.stderr);
  assert.ok(existsSync(join(sub, "報告.html")));
  const saved = JSON.parse(readFileSync(receiptPath(dir), "utf8"));
  assert.equal(saved.report.path, join(sub, "報告.html"));
});

test("setup recovers a lost principal creation response using its creation marker without another POST", { skip: skipWithoutPwsh }, async (t) => {
  const dir = workspace(t);
  const setup = await runMicrosoft(dir, graphState({ losePrincipalResponse: true }));
  assert.equal(setup.status, 0, setup.stdout + setup.stderr);
  assert.equal(setup.changes.filter((call) => call.method === "POST" && call.uri === "/v1.0/servicePrincipals").length, 1);
  const cleanup = await runCleanup(dir, { ...setup.state, calls: [] });
  assert.equal(cleanup.status, 0, cleanup.stdout + cleanup.stderr);
  assert.deepEqual(cleanup.state.servicePrincipals, []);
});

test("a malformed patch receipt cannot turn a missing baseline into revocation", { skip: skipWithoutPwsh }, async (t) => {
  const dir = workspace(t);
  const setup = await runMicrosoft(dir, graphState());
  const receipt = JSON.parse(readFileSync(receiptPath(dir), "utf8"));
  receipt.actions.at(-1).method = "PATCH";
  receipt.actions.at(-1).before = null;
  writeFileSync(receiptPath(dir), JSON.stringify(receipt));
  const cleanup = await runCleanup(dir, { ...setup.state, calls: [], connect: null });
  assert.equal(cleanup.status, 1);
  assert.equal(cleanup.state.connect, null);
  assert.deepEqual(cleanup.changes, []);
});

test("a mistyped new helper grant ID stops before cleanup", { skip: skipWithoutPwsh }, async (t) => {
  const dir = workspace(t);
  const setup = await runMicrosoft(dir, graphState());
  const cleanup = await runCleanup(dir, { ...setup.state, calls: [] }, ["-GraphPowerShellGrantId", "wrong-grant-id"]);
  assert.equal(cleanup.status, 1);
  assert.match(cleanup.stdout, /GrantId was not found/u);
  assert.deepEqual(cleanup.changes, []);
});

test("refresh refusal leaves access cleanup pending without leaking the refresh token", { skip: skipWithoutPwsh }, async (t) => {
  const dir = workspace(t);
  const setup = await runMicrosoft(dir, graphState());
  const args = prepareWatcher(dir, [scanStatus("completed", true)]);
  const scannerStatePath = join(dir, "scanner-state.json");
  const scanner = JSON.parse(readFileSync(scannerStatePath, "utf8"));
  writeFileSync(scannerStatePath, JSON.stringify({ ...scanner, expireTokenOnFinish: true }));
  const refreshToken = "fake-refresh-token-refused";
  const cleanup = await runCleanup(dir, { ...setup.state, calls: [], login: [], denyRefresh: true, signIn: { ...setup.state.signIn, pending: 0, refreshToken } }, [...args, "-UseDeviceCode"]);
  assert.equal(cleanup.status, 1);
  assert.deepEqual(cleanup.changes, []);
  assert.equal(JSON.parse(readFileSync(receiptPath(dir), "utf8")).state, "cleanup_pending");
  assert.equal((cleanup.stdout + cleanup.stderr + readFileSync(receiptPath(dir), "utf8")).includes(refreshToken), false);
});

test("a new helper consent ID after interrupted cleanup must be explicitly selected before revocation", { skip: skipWithoutPwsh }, async (t) => {
  const dir = workspace(t);
  const setup = await runMicrosoft(dir, graphState());
  const helper = { id: "c1b2c3d4-e5f6-4a7b-8c9d-0e1f2a3b4c5d", appId: graphPowerShellClientId };
  const original = { id: "original-helper-grant", clientId: helper.id, resourceId: graphPrincipalId, consentType: "Principal", principalId: "d1b2c3d4-e5f6-4a7b-8c9d-0e1f2a3b4c5d", scope: setupScopes.join(" ") };
  setup.state.servicePrincipals.push(helper);
  setup.state.oauth2PermissionGrants.push(original);
  const cleaned = await runCleanup(dir, { ...setup.state, calls: [] }, ["-GraphPowerShellGrantId", original.id]);
  assert.equal(cleaned.status, 0, cleaned.stdout + cleaned.stderr);
  // Model a lost final checkpoint after the provider already deleted the grant.
  const receipt = JSON.parse(readFileSync(receiptPath(dir), "utf8"));
  receipt.state = "cleanup_pending";
  writeFileSync(receiptPath(dir), JSON.stringify(receipt));
  const replacement = { ...original, id: "replacement-helper-grant" };
  const retry = await runCleanup(dir, { ...cleaned.state, calls: [], helperConsentOnConnect: replacement });
  assert.equal(retry.status, 1, retry.stdout + retry.stderr);
  assert.match(retry.stdout, /new helper consent record/u);
  assert.deepEqual(retry.changes, []);
  const selected = await runCleanup(dir, { ...retry.state, calls: [] }, ["-GraphPowerShellGrantId", replacement.id]);
  assert.equal(selected.status, 0, selected.stdout + selected.stderr);
  assert.deepEqual(selected.state.oauth2PermissionGrants, []);
});
