import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { lstat, mkdtemp, readFile, rm, writeFile } from "node:fs/promises";
import http from "node:http";
import net from "node:net";
import os from "node:os";
import path from "node:path";
import test from "node:test";

import {
  WINDOWS_LOCALHOST_FIXTURE_CONTRACT,
  WINDOWS_LOCALHOST_FIXTURE_RUNTIME_POLICY,
  WINDOWS_LOCALHOST_FIXTURE_TEST_ONLY,
  parseFixtureArguments,
} from "../../scripts/release/windows-localhost-fixture.mjs";
import { WINDOWS_LOCALHOST_FIXTURE_SCRIPT_POLICY } from "../../scripts/release/windows-installed-lifecycle-evidence.mjs";

const RECEIPT_FILENAME = "windows-localhost-fixture-receipt.json";
const DOCUMENTED_POWERSHELL_INVOCATION =
  "& '<absolute-runtime-directory>\\node.exe' '<absolute-version-pinned-checkout>\\scripts\\release\\windows-localhost-fixture.mjs' --receipt '<absolute-existing-directory>\\windows-localhost-fixture-receipt.json'";

test("Windows localhost fixture contract pins one immutable endpoint and response fingerprint", () => {
  assert.equal(Object.isFrozen(WINDOWS_LOCALHOST_FIXTURE_CONTRACT), true);
  assert.deepEqual(WINDOWS_LOCALHOST_FIXTURE_CONTRACT, {
    schemaVersion: 1,
    fixture: "ai-security-scanner-windows-host-loopback",
    contractVersion: 1,
    address: "127.0.0.1",
    port: 9001,
    family: "IPv4",
    healthPath: "/healthz",
    healthStatusCode: 200,
    healthContentType: "text/plain; charset=utf-8",
    healthBodyBytes: 41,
    healthBodySha256: "80cdb676cf3d0fd08c450cd7b2de79b44e0c4ae4bdb040221f756ae1a9f72715",
  });
});

test("Windows localhost fixture pins and validates one portable Windows Node runtime", () => {
  assert.deepEqual(WINDOWS_LOCALHOST_FIXTURE_RUNTIME_POLICY, {
    name: "node",
    version: "v24.15.0",
    platform: "win32",
    architecture: "x64",
    distribution: {
      file: "node-v24.15.0-win-x64.zip",
      bytes: 36_465_163,
      sha256: "cc5149eabd53779ce1e7bdc5401643622d0c7e6800ade18928a767e940bb0e62",
    },
    executable: {
      file: "node.exe",
      bytes: 91_694_408,
      sha256: "3331e1ffe19874215472217c5e94f5a0c6d8e18c4ac7111d3937aa0ad5e9b4a5",
    },
  });
  const approved = {
    name: "node",
    version: "v24.15.0",
    platform: "win32",
    architecture: "x64",
    executableFile: "node.exe",
    executableBytes: 91_694_408,
    executableSha256: "3331e1ffe19874215472217c5e94f5a0c6d8e18c4ac7111d3937aa0ad5e9b4a5",
  };
  assert.doesNotThrow(() => WINDOWS_LOCALHOST_FIXTURE_TEST_ONLY.assertApprovedRuntimeIdentity(approved));
  for (const patch of [
    { platform: "linux" },
    { version: "v24.16.0" },
    { architecture: "arm64" },
    { executableBytes: 1 },
    { executableSha256: "f".repeat(64) },
  ]) {
    assert.throws(
      () => WINDOWS_LOCALHOST_FIXTURE_TEST_ONLY.assertApprovedRuntimeIdentity({ ...approved, ...patch }),
      /exact approved Windows Node runtime/u,
    );
  }
});

test("both qualification plans document the same unambiguous absolute PowerShell invocation", async () => {
  const fixtureBytes = await readFile(new URL("../../scripts/release/windows-localhost-fixture.mjs", import.meta.url));
  assert.equal(
    createHash("sha256").update(fixtureBytes).digest("hex"),
    WINDOWS_LOCALHOST_FIXTURE_SCRIPT_POLICY.sha256,
  );
  for (const filename of [
    "windows-external-qualification-plan.md",
    "windows-external-qualification-plan.zh-TW.md",
  ]) {
    const document = await readFile(new URL(`../../docs/release/${filename}`, import.meta.url), "utf8");
    assert.equal(document.includes(DOCUMENTED_POWERSHELL_INVOCATION), true, filename);
    assert.equal(document.includes(WINDOWS_LOCALHOST_FIXTURE_SCRIPT_POLICY.sha256), true, filename);
    assert.equal(document.includes(".<runtime-directory>\\node.exe"), false, filename);
  }
});

function request({ port, method = "GET", requestPath = "/healthz", headers = {}, body = null } = {}) {
  return new Promise((resolve, reject) => {
    const client = http.request({
      host: "127.0.0.1",
      port,
      method,
      path: requestPath,
      headers,
      agent: false,
    });
    const chunks = [];
    let bytes = 0;
    client.on("response", (response) => {
      response.on("data", (chunk) => {
        bytes += chunk.length;
        if (bytes > 4_096) {
          response.destroy(new Error("fixture response exceeded its test bound"));
          return;
        }
        chunks.push(chunk);
      });
      response.on("end", () => resolve({
        statusCode: response.statusCode,
        headers: response.headers,
        body: Buffer.concat(chunks).toString("utf8"),
      }));
    });
    client.on("error", reject);
    if (body !== null) client.write(body);
    client.end();
  });
}

function makeRawTcpConnection(port) {
  return new Promise((resolve, reject) => {
    const socket = net.createConnection({ host: "127.0.0.1", port });
    socket.once("connect", () => socket.end());
    socket.once("error", reject);
    socket.once("close", resolve);
  });
}

function listen(server) {
  return new Promise((resolve, reject) => {
    server.once("error", reject);
    server.listen({ host: "127.0.0.1", port: 9001, exclusive: true }, resolve);
  });
}

function close(server) {
  return new Promise((resolve, reject) => {
    server.close((error) => {
      if (error) reject(error);
      else resolve();
    });
  });
}

test("Windows localhost fixture core emits deterministic health and only redacted counters", { concurrency: false }, async (t) => {
  const directory = await mkdtemp(path.join(os.tmpdir(), "assm-localhost-fixture-"));
  const receiptPath = path.join(directory, RECEIPT_FILENAME);
  const times = [new Date("2026-09-07T12:00:00.000Z"), new Date("2026-09-07T12:01:00.000Z")];
  let fixture;
  let stopped = false;
  t.after(async () => {
    if (fixture && !stopped) await fixture.shutdown("test").catch(() => {});
    await rm(directory, { recursive: true, force: true });
  });

  fixture = await WINDOWS_LOCALHOST_FIXTURE_TEST_ONLY.startEphemeral({
    receiptPath,
    now: () => times.shift(),
  });
  assert.equal(fixture.address.address, "127.0.0.1");
  assert.equal(fixture.address.family, "IPv4");
  assert.equal(Number.isSafeInteger(fixture.address.port), true);
  assert.equal(fixture.address.port > 0 && fixture.address.port <= 65_535, true);

  const health = await request({ port: fixture.address.port });
  assert.equal(health.statusCode, 200);
  assert.equal(health.body, "ai-security-scanner-localhost-fixture/v1\n");
  assert.equal(health.headers["content-type"], "text/plain; charset=utf-8");
  assert.equal(health.headers["content-length"], String(WINDOWS_LOCALHOST_FIXTURE_CONTRACT.healthBodyBytes));
  assert.equal(health.headers.date, undefined);

  const head = await request({ port: fixture.address.port, method: "HEAD" });
  assert.equal(head.statusCode, 200);
  assert.equal(head.body, "");
  assert.equal(head.headers["content-length"], String(WINDOWS_LOCALHOST_FIXTURE_CONTRACT.healthBodyBytes));
  assert.equal(head.headers.date, undefined);

  const secretHeader = "Bearer must-not-enter-the-receipt";
  const secretBody = "raw-body-must-not-enter-the-receipt";
  const rejected = await request({
    port: fixture.address.port,
    method: "POST",
    requestPath: "/not-health",
    headers: { Authorization: secretHeader, Cookie: "private-cookie=yes" },
    body: secretBody,
  });
  assert.equal(rejected.statusCode, 404);
  assert.equal(rejected.body, "not-found\n");

  await assert.rejects(
    fixture.shutdown("unreviewed-reason"),
    /shutdown reason is not allowed/u,
  );
  await makeRawTcpConnection(fixture.address.port);
  const receipt = await fixture.shutdown("test");
  stopped = true;
  const receiptText = await readFile(receiptPath, "utf8");
  assert.deepEqual(JSON.parse(receiptText), receipt);
  assert.equal(receiptText.includes(secretHeader), false);
  assert.equal(receiptText.includes(secretBody), false);
  assert.equal(receiptText.includes("private-cookie"), false);
  assert.deepEqual(Object.keys(receipt), [
    "schemaVersion",
    "receiptType",
    "fixture",
    "fixtureContractVersion",
    "runtime",
    "binding",
    "healthResponse",
    "startedAt",
    "endedAt",
    "shutdownReason",
    "counters",
  ]);
  assert.equal(receipt.runtime.qualificationEligible, false);
  assert.equal(receipt.runtime.name, "test-only-injected-runtime");
  assert.deepEqual(receipt.binding, fixture.address);
  assert.deepEqual(receipt.healthResponse, {
    path: "/healthz",
    statusCode: 200,
    contentType: "text/plain; charset=utf-8",
    bodyBytes: WINDOWS_LOCALHOST_FIXTURE_CONTRACT.healthBodyBytes,
    bodySha256: WINDOWS_LOCALHOST_FIXTURE_CONTRACT.healthBodySha256,
  });
  assert.equal(receipt.startedAt, "2026-09-07T12:00:00.000Z");
  assert.equal(receipt.endedAt, "2026-09-07T12:01:00.000Z");
  assert.equal(receipt.shutdownReason, "test");
  assert.equal(receipt.counters.tcpConnectionsAccepted >= 4, true);
  assert.equal(receipt.counters.tcpConnectionsDropped, 0);
  assert.equal(receipt.counters.httpRequestsReceived, 3);
  assert.equal(receipt.counters.healthResponsesSent, 2);
  assert.equal(receipt.counters.rejectedHttpRequests, 1);
  assert.equal(receipt.counters.socketErrors, 0);
});

test("Windows localhost fixture fails closed when the exact port is already owned", { concurrency: false }, async (t) => {
  const directory = await mkdtemp(path.join(os.tmpdir(), "assm-localhost-fixture-owned-"));
  const receiptPath = path.join(directory, RECEIPT_FILENAME);
  const blocker = net.createServer((socket) => socket.end());
  let ownsPort = false;
  t.after(async () => {
    if (ownsPort && blocker.listening) await close(blocker);
    await rm(directory, { recursive: true, force: true });
  });
  try {
    await listen(blocker);
    ownsPort = true;
  } catch (error) {
    if (error?.code !== "EADDRINUSE") throw error;
  }

  await assert.rejects(
    WINDOWS_LOCALHOST_FIXTURE_TEST_ONLY.startCanonical({ receiptPath }),
    (error) => error?.code === "EADDRINUSE",
  );
  await assert.rejects(lstat(receiptPath), (error) => error?.code === "ENOENT");
});

test("Windows localhost fixture rejects bind overrides, relative receipts, and receipt replacement", { concurrency: false }, async (t) => {
  const directory = await mkdtemp(path.join(os.tmpdir(), "assm-localhost-fixture-contract-"));
  const receiptPath = path.join(directory, RECEIPT_FILENAME);
  t.after(() => rm(directory, { recursive: true, force: true }));

  assert.deepEqual(parseFixtureArguments(["--receipt", receiptPath]), { receiptPath });
  assert.throws(
    () => parseFixtureArguments(["--receipt", receiptPath, "--host", "0.0.0.0"]),
    /usage/u,
  );
  assert.throws(
    () => parseFixtureArguments(["--receipt", receiptPath, "--port", "9002"]),
    /usage/u,
  );
  await assert.rejects(
    WINDOWS_LOCALHOST_FIXTURE_TEST_ONLY.startCanonical({ receiptPath: RECEIPT_FILENAME }),
    /absolute Windows-local JSON path/u,
  );

  await writeFile(receiptPath, "preserve-existing-receipt\n", "utf8");
  await assert.rejects(
    WINDOWS_LOCALHOST_FIXTURE_TEST_ONLY.startCanonical({ receiptPath }),
    /refuses to replace an existing receipt/u,
  );
  assert.equal(await readFile(receiptPath, "utf8"), "preserve-existing-receipt\n");
});
