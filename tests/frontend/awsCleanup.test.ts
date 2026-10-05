import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { chmodSync, existsSync, mkdirSync, mkdtempSync, readFileSync, readdirSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
import test from "node:test";

const script = fileURLToPath(new URL("../../cloud-setup/aws-cleanup.py", import.meta.url));
const setupScript = fileURLToPath(new URL("../../cloud-setup/aws-read-only.sh", import.meta.url));
const fake = fileURLToPath(new URL("../fixtures/cloud-setup/fake-aws.mjs", import.meta.url));
const account = "111122223333";
const instance = "arn:aws:sso:::instance/ssoins-1111222233334444";
const principal = "94482488-3041-7026-18f3-be45837cd0e4";
const caseId = "aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa";
const runId = "bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb";
const state = () => ({
  caller: { Account: account }, organization: { MasterAccountId: account }, enabledRegions: ["us-east-2"],
  instances: { "us-east-2": [{ InstanceArn: instance, IdentityStoreId: "d-9a67221e13", OwnerAccountId: account, Status: "ACTIVE" }] },
  users: [{ UserId: principal, UserName: "tester", Emails: [{ Value: "tester@example.com" }] }],
  permissionSets: [], assignments: [], requests: {}, calls: [],
});

const workspace = (t: { after: (fn: () => void) => void }) => {
  const dir = mkdtempSync(join(tmpdir(), "aiss-aws-cleanup-"));
  t.after(() => rmSync(dir, { recursive: true, force: true }));
  mkdirSync(join(dir, "bin"));
  writeFileSync(join(dir, "bin", "aws"), `#!/bin/sh\nexec "${process.execPath}" "${fake}" "$@"\n`);
  chmodSync(join(dir, "bin", "aws"), 0o755);
  return dir;
};

const call = (dir: string, current: any, args: string[], setup = false) => {
  const statePath = join(dir, "aws-state.json");
  writeFileSync(statePath, JSON.stringify({ ...current, calls: [] }));
  const result = spawnSync(setup ? "bash" : "python3", [setup ? setupScript : script, ...args], {
    cwd: dir, encoding: "utf8", timeout: 60_000,
    env: { ...process.env, PATH: `${join(dir, "bin")}:${process.env.PATH}`, HOME: dir, AWS_REGION: "us-east-2", FAKE_AWS_STATE: statePath },
  });
  const after = JSON.parse(readFileSync(statePath, "utf8"));
  return { ...result, state: after, writes: after.calls.filter((c: any) => !/^(get|list|describe)-/u.test(c.operation)).map((c: any) => c.operation) };
};
const receiptPath = (dir: string) => join(dir, readdirSync(dir).find((name) => /^ai-security-scanner-aws-cleanup-.*\.json$/u.test(name))!);
const receipt = (dir: string) => JSON.parse(readFileSync(receiptPath(dir), "utf8"));
const setupFile = (dir: string) => join(dir, `ai-security-scanner-aws-setup-${receipt(dir).id}.json`);
const prepare = (dir: string, current: any = state()) => {
  const result = call(dir, current, ["--temporary"], true);
  assert.equal(result.status, 0, result.stderr);
  return result.state;
};
const cleanup = (dir: string, current: any, extras: string[] = []) =>
  call(dir, current, ["cleanup", "--receipt", receiptPath(dir), "--revoke-now", ...extras]);

test("AWS temporary setup uses a unique role, preserves shared access, and cleanup verifies removal", (t) => {
  const dir = workspace(t);
  const initial: any = state();
  initial.permissionSets.push({ arn: instance.replace("instance/", "permissionSet/") + "/ps-0000000000000000", name: "SecurityAudit", managed: [], customer: [], inline: "", provisionedAccounts: [] });
  const ready = prepare(dir, initial);
  const saved = receipt(dir);
  assert.equal(saved.state, "ready");
  assert.equal(saved.assignment_state, "complete");
  assert.equal(ready.permissionSets.length, 2);
  assert.match(saved.name, /^AISS-[a-f0-9]{20}$/u);
  assert.deepEqual(JSON.parse(readFileSync(setupFile(dir), "utf8")).details, {
    account_id: account, role_name: saved.name, region: "us-east-2", start_url: "https://d-9a67221e13.awsapps.com/start",
  });
  const result = cleanup(dir, ready);
  assert.equal(result.status, 0, result.stderr);
  assert.deepEqual(result.writes, ["delete-account-assignment", "delete-permission-set"]);
  assert.deepEqual(result.state.permissionSets, initial.permissionSets);
  assert.deepEqual(result.state.assignments, []);
  assert.equal(receipt(dir).state, "completed");
  assert.equal(existsSync(setupFile(dir)), false);
  assert.match(result.stdout, /sessions may remain valid/u);
  assert.deepEqual(cleanup(dir, result.state).state.calls, [], "completed retries must not reauthenticate");
});

test("AWS cleanup preview performs no writes and retains both setup and receipt", (t) => {
  const dir = workspace(t);
  const ready = prepare(dir);
  const before = readFileSync(receiptPath(dir), "utf8");
  const result = cleanup(dir, ready, ["--dry-run"]);
  assert.equal(result.status, 0, result.stderr);
  assert.deepEqual(result.writes, []);
  assert.equal(readFileSync(receiptPath(dir), "utf8"), before);
  assert.equal(existsSync(setupFile(dir)), true);
});

for (const [name, alter] of [
  ["wrong administrator account", (s: any) => { s.caller.Account = "999988887777"; }],
  ["different instance owner", (s: any) => { s.instances["us-east-2"][0].OwnerAccountId = "999988887777"; }],
  ["changed ownership tag", (s: any) => { s.permissionSets[0].tags[0].Value = "other"; }],
  ["changed description", (s: any) => { s.permissionSets[0].description = "Shared now"; }],
  ["changed session duration", (s: any) => { s.permissionSets[0].sessionDuration = "PT8H"; }],
  ["new inline policy", (s: any) => { s.permissionSets[0].inline = "{}"; }],
  ["new permission boundary", (s: any) => { s.permissionSets[0].boundary = { ManagedPolicyArn: "arn:aws:iam::aws:policy/ReadOnlyAccess" }; }],
  ["new group assignment", (s: any) => { s.assignments.push({ ...s.assignments[0], PrincipalType: "GROUP" }); }],
  ["another provisioned account", (s: any) => { s.permissionSets[0].provisionedAccounts.push("999988887777"); }],
] as const) {
  test(`AWS cleanup preserves access when it finds ${name}`, (t) => {
    const dir = workspace(t);
    const ready = prepare(dir);
    alter(ready);
    const result = cleanup(dir, ready);
    assert.equal(result.status, 1);
    assert.deepEqual(result.writes, []);
    assert.notEqual(receipt(dir).state, "completed");
    assert.equal(existsSync(setupFile(dir)), true);
  });
}

test("AWS partial setup has a durable receipt and its unassigned role can be cleaned", (t) => {
  const dir = workspace(t);
  const result = call(dir, { ...state(), failOperation: "attach-managed-policy-to-permission-set" }, ["--temporary"], true);
  assert.equal(result.status, 1);
  assert.equal(receipt(dir).creation_confirmed, true);
  assert.equal(receipt(dir).assignment_state, "not_attempted");
  const cleaned = cleanup(dir, { ...result.state, failOperation: null });
  assert.equal(cleaned.status, 0, cleaned.stderr);
  assert.deepEqual(cleaned.writes, ["delete-permission-set"]);
});

test("AWS lost permission-set creation reply is recovered only by exact ownership marker", (t) => {
  const dir = workspace(t);
  const result = call(dir, { ...state(), loseReply: "create-permission-set" }, ["--temporary"], true);
  assert.equal(result.status, 1);
  assert.equal(receipt(dir).permission_set_arn, null);
  const cleaned = cleanup(dir, { ...result.state, loseReply: null });
  assert.equal(cleaned.status, 0, cleaned.stderr);
  assert.deepEqual(cleaned.writes, ["delete-permission-set"]);
});

test("AWS lost assignment creation reply cannot be reported as cleaned", (t) => {
  const dir = workspace(t);
  const result = call(dir, { ...state(), loseReply: "create-account-assignment" }, ["--temporary"], true);
  assert.equal(result.status, 1);
  assert.equal(receipt(dir).assignment_state, "pending");
  const cleaned = cleanup(dir, { ...result.state, loseReply: null });
  assert.equal(cleaned.status, 1);
  assert.deepEqual(cleaned.writes, []);
  assert.match(cleaned.stderr, /no confirmed request ID/u);
});

test("AWS denied or unconfirmed deletion stays incomplete; retry preserves an already removed assignment", (t) => {
  const dir = workspace(t);
  const ready = prepare(dir);
  const failed = cleanup(dir, { ...ready, failOperation: "delete-permission-set" });
  assert.equal(failed.status, 1);
  assert.equal(receipt(dir).assignment_state, "deleted");
  assert.notEqual(receipt(dir).state, "completed");
  const retry = cleanup(dir, { ...failed.state, failOperation: null });
  assert.equal(retry.status, 0, retry.stderr);
  assert.deepEqual(retry.writes, ["delete-permission-set"]);
});

test("AWS replacement assignment after deletion is preserved", (t) => {
  const dir = workspace(t);
  const ready = prepare(dir);
  const failed = cleanup(dir, { ...ready, failOperation: "delete-permission-set" });
  failed.state.assignments = ready.assignments;
  failed.state.permissionSets[0].provisionedAccounts = [account];
  const retry = cleanup(dir, { ...failed.state, failOperation: null });
  assert.equal(retry.status, 1);
  assert.deepEqual(retry.writes, []);
  assert.match(retry.stderr, /replacement assignment/u);
});

test("AWS successful deletion replies require read-back verification", (t) => {
  const dir = workspace(t);
  const ready = prepare(dir);
  const failed = cleanup(dir, { ...ready, ignoreDelete: true });
  assert.equal(failed.status, 1);
  assert.notEqual(receipt(dir).state, "completed");
  assert.equal(failed.state.permissionSets.length, 1);
  assert.deepEqual(failed.writes, ["delete-account-assignment"]);
});

test("AWS cleanup retains a changed setup file and all report files", (t) => {
  const dir = workspace(t);
  const ready = prepare(dir);
  writeFileSync(setupFile(dir), "changed by user");
  writeFileSync(join(dir, "report.html"), "retained report");
  const result = cleanup(dir, ready);
  assert.equal(result.status, 0, result.stderr);
  assert.equal(receipt(dir).setup_file_state, "preserved_changed");
  assert.equal(readFileSync(setupFile(dir), "utf8"), "changed by user");
  assert.equal(readFileSync(join(dir, "report.html"), "utf8"), "retained report");
});

function scannerFixture(dir: string, statuses: object[], failExport = false) {
  const cli = join(dir, "bin", "scanner");
  const source = `#!/usr/bin/env node
import {readFileSync,writeFileSync} from 'node:fs';
import {createHash} from 'node:crypto';
const root=process.env.HOME, path=root+'/scanner.json';
const s=JSON.parse(readFileSync(path,'utf8')), a=process.argv.slice(2), val=(f)=>a[a.indexOf(f)+1];
s.calls.push(a);
if(a.includes('status')) { const answer=s.statuses.shift(); writeFileSync(path,JSON.stringify(s)); console.log(JSON.stringify(answer)); }
else { s.assignmentsAtExport=JSON.parse(readFileSync(root+'/aws-state.json','utf8')).assignments.length; writeFileSync(path,JSON.stringify(s)); if(s.failExport)process.exit(3); const p=val('--destination'), html='<!doctype html><html>Fixture report</html>'; writeFileSync(p,html,{flag:'wx'}); console.log(JSON.stringify({case_id:val('--case-id'),run_id:val('--run-id'),path:p,sha256:createHash('sha256').update(html).digest('hex')})); }
`;
  writeFileSync(cli, source);
  chmodSync(cli, 0o755);
  writeFileSync(join(dir, "scanner.json"), JSON.stringify({ statuses, calls: [], failExport }));
  return ["cleanup", "--receipt", receiptPath(dir), "--wait-for-run", "--case-id", caseId, "--run-id", runId,
    "--data-dir", dir, "--cli", cli, "--report", join(dir, "report.html"), "--wait-minutes", "0", "--poll-seconds", "0.01"];
}
const scanStatus = (status: string, completed = true) => ({ case_id: caseId, runs: [{ id: runId, case_id: caseId, completed_at: completed ? "2026-10-05T00:00:00Z" : null, engine_runs: [{ status }] }] });

test("AWS waits for the exact run and saves a verified report before revoking access", (t) => {
  const dir = workspace(t);
  const ready = prepare(dir);
  const result = call(dir, ready, scannerFixture(dir, [scanStatus("partially_completed")]));
  assert.equal(result.status, 0, result.stderr);
  assert.equal(JSON.parse(readFileSync(join(dir, "scanner.json"), "utf8")).assignmentsAtExport, 1);
  assert.match(receipt(dir).report.sha256, /^[a-f0-9]{64}$/u);
  assert.equal(existsSync(join(dir, "report.html")), true);
  assert.equal(receipt(dir).state, "completed");
});

for (const [name, status] of [
  ["active run", scanStatus("running", false)],
  ["unknown engine status", scanStatus("paused")],
  ["wrong run", { case_id: caseId, runs: [{ ...scanStatus("completed").runs[0], id: caseId }] }],
] as const) {
  test(`AWS cannot revoke access for ${name}`, (t) => {
    const dir = workspace(t);
    const ready = prepare(dir);
    const result = call(dir, ready, scannerFixture(dir, [status]));
    assert.equal(result.status, 1);
    assert.deepEqual(result.writes, []);
    assert.equal(result.state.assignments.length, 1);
  });
}

test("AWS report export failure still revokes access but returns a report failure", (t) => {
  const dir = workspace(t);
  const ready = prepare(dir);
  const result = call(dir, ready, scannerFixture(dir, [scanStatus("failed")], true));
  assert.equal(result.status, 2, result.stderr);
  assert.equal(receipt(dir).state, "completed");
  assert.ok(receipt(dir).report_error);
  assert.deepEqual(result.state.assignments, []);
  const retry = cleanup(dir, result.state);
  assert.equal(retry.status, 2);
  assert.deepEqual(retry.state.calls, []);
});

test("AWS absent permissions boundary accepts a not-found response after rechecking the permission set", (t) => {
  const dir = workspace(t);
  const ready = prepare(dir, { ...state(), boundaryNotFound: true });
  const result = cleanup(dir, ready);
  assert.equal(result.status, 0, result.stderr);
  assert.equal(receipt(dir).state, "completed");
});

test("AWS refuses unsupported partitions before creating a permission set or receipt", (t) => {
  const dir = workspace(t);
  const initial = state();
  initial.instances["us-east-2"][0]!.InstanceArn = instance.replace("arn:aws:", "arn:aws-cn:");
  const result = call(dir, initial, ["--temporary"], true);
  assert.equal(result.status, 1);
  assert.deepEqual(result.writes, []);
  assert.equal(readdirSync(dir).filter((n) => n.startsWith("ai-security-scanner-aws-cleanup-")).length, 0);
});

test("AWS explicitly refused creation leaves the unassigned role cleanable", (t) => {
  const dir = workspace(t);
  const failed = call(dir, { ...state(), failOperation: "create-account-assignment" }, ["--temporary"], true);
  assert.equal(failed.status, 1);
  assert.equal(receipt(dir).assignment_state, "not_attempted");
  const result = cleanup(dir, { ...failed.state, failOperation: null });
  assert.equal(result.status, 0, result.stderr);
  assert.deepEqual(result.writes, ["delete-permission-set"]);
});

test("AWS explicitly refused assignment deletion can be retried after access is restored", (t) => {
  const dir = workspace(t);
  const ready = prepare(dir);
  const failed = cleanup(dir, { ...ready, failOperation: "delete-account-assignment" });
  assert.equal(failed.status, 1);
  assert.equal(receipt(dir).deletion_sent, false);
  const result = cleanup(dir, { ...failed.state, failOperation: null });
  assert.equal(result.status, 0, result.stderr);
  assert.deepEqual(result.writes, ["delete-account-assignment", "delete-permission-set"]);
});

test("AWS confirmed failed async deletion can be retried without treating it as completion", (t) => {
  const dir = workspace(t);
  const ready = prepare(dir);
  const failed = cleanup(dir, { ...ready, deleteStatus: "FAILED" });
  assert.equal(failed.status, 1);
  const reset = cleanup(dir, { ...failed.state, deleteStatus: null });
  assert.equal(reset.status, 1);
  assert.equal(receipt(dir).deletion_sent, false);
  assert.equal(receipt(dir).deletion_request, null);
  const result = cleanup(dir, reset.state);
  assert.equal(result.status, 0, result.stderr);
  assert.deepEqual(result.writes, ["delete-account-assignment", "delete-permission-set"]);
});

test("AWS verified assignment deletion does not depend on an expired request-status record", (t) => {
  const dir = workspace(t);
  const ready = prepare(dir);
  const failed = cleanup(dir, { ...ready, failOperation: "delete-permission-set" });
  const result = cleanup(dir, { ...failed.state, failOperation: "describe-account-assignment-deletion-status", requests: {} });
  assert.equal(result.status, 0, result.stderr);
  assert.deepEqual(result.writes, ["delete-permission-set"]);
});

test("AWS unconfirmed permission-set deletion leaves a pending receipt", (t) => {
  const dir = workspace(t);
  const ready = prepare(dir);
  const result = cleanup(dir, { ...ready, ignorePermissionSetDelete: true });
  assert.equal(result.status, 1);
  assert.notEqual(receipt(dir).state, "completed");
  assert.match(result.stderr, /not confirmed permission-set removal/u);
});

test("AWS dry-run for an active scan only previews waiting", (t) => {
  const dir = workspace(t);
  const ready = prepare(dir);
  const before = readFileSync(receiptPath(dir), "utf8");
  const result = call(dir, ready, [...scannerFixture(dir, [scanStatus("running", false)]), "--dry-run"]);
  assert.equal(result.status, 0, result.stderr);
  assert.match(result.stdout, /would wait/u);
  assert.doesNotMatch(result.stdout, /Would remove/u);
  assert.deepEqual(result.writes, []);
  assert.equal(readFileSync(receiptPath(dir), "utf8"), before);
});

test("AWS missing CLI and wrong admin account are detected before waiting or exporting", (t) => {
  const dir = workspace(t);
  const ready = prepare(dir);
  const args = scannerFixture(dir, [scanStatus("completed")]);
  const wrongAccount = call(dir, { ...ready, caller: { Account: "999988887777" } }, args);
  assert.equal(wrongAccount.status, 1);
  assert.deepEqual(JSON.parse(readFileSync(join(dir, "scanner.json"), "utf8")).calls, []);
  args[args.indexOf("--cli") + 1] = join(dir, "missing-cli");
  const missing = call(dir, ready, args);
  assert.equal(missing.status, 1);
  assert.match(missing.stderr, /must be on this computer/u);
  assert.deepEqual(missing.writes, []);
});
