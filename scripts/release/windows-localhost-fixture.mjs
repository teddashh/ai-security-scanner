#!/usr/bin/env node

import { createHash } from "node:crypto";
import { createReadStream } from "node:fs";
import { lstat, open } from "node:fs/promises";
import http from "node:http";
import path from "node:path";
import { fileURLToPath } from "node:url";

const HOST = "127.0.0.1";
const PORT = 9001;
const RECEIPT_FILENAME = "windows-localhost-fixture-receipt.json";
const HEALTH_PATH = "/healthz";
const HEALTH_BODY = Buffer.from("ai-security-scanner-localhost-fixture/v1\n", "utf8");
const NOT_FOUND_BODY = Buffer.from("not-found\n", "utf8");
const MAX_CONNECTIONS = 16;
const SOCKET_TIMEOUT_MILLISECONDS = 5_000;
const ALLOWED_SHUTDOWN_REASONS = new Set(["SIGINT", "SIGTERM", "operator", "test"]);

export const WINDOWS_LOCALHOST_FIXTURE_CONTRACT = Object.freeze({
  schemaVersion: 1,
  fixture: "ai-security-scanner-windows-host-loopback",
  contractVersion: 1,
  address: HOST,
  port: PORT,
  family: "IPv4",
  healthPath: HEALTH_PATH,
  healthStatusCode: 200,
  healthContentType: "text/plain; charset=utf-8",
  healthBodyBytes: HEALTH_BODY.length,
  healthBodySha256: createHash("sha256").update(HEALTH_BODY).digest("hex"),
});

export const WINDOWS_LOCALHOST_FIXTURE_RUNTIME_POLICY = Object.freeze({
  name: "node",
  version: "v24.15.0",
  platform: "win32",
  architecture: "x64",
  distribution: Object.freeze({
    file: "node-v24.15.0-win-x64.zip",
    bytes: 36_465_163,
    sha256: "cc5149eabd53779ce1e7bdc5401643622d0c7e6800ade18928a767e940bb0e62",
  }),
  executable: Object.freeze({
    file: "node.exe",
    bytes: 91_694_408,
    sha256: "3331e1ffe19874215472217c5e94f5a0c6d8e18c4ac7111d3937aa0ad5e9b4a5",
  }),
});

function assertApprovedRuntimeIdentity(identity) {
  const policy = WINDOWS_LOCALHOST_FIXTURE_RUNTIME_POLICY;
  if (
    identity?.name !== policy.name
    || identity?.version !== policy.version
    || identity?.platform !== policy.platform
    || identity?.architecture !== policy.architecture
    || identity?.executableFile !== policy.executable.file
    || identity?.executableBytes !== policy.executable.bytes
    || identity?.executableSha256 !== policy.executable.sha256
  ) {
    throw new Error("localhost fixture requires the exact approved Windows Node runtime");
  }
  return Object.freeze({ ...identity });
}

async function sha256RegularFile(file) {
  const metadata = await lstat(file);
  if (!metadata.isFile() || metadata.isSymbolicLink()) {
    throw new Error("localhost fixture Node executable must be one regular non-symlink file");
  }
  const hash = createHash("sha256");
  for await (const chunk of createReadStream(file)) hash.update(chunk);
  return { bytes: metadata.size, sha256: hash.digest("hex") };
}

async function observeApprovedWindowsRuntime() {
  if (process.platform !== "win32") {
    throw new Error("localhost fixture production entry point requires Windows");
  }
  const executable = await sha256RegularFile(process.execPath);
  return assertApprovedRuntimeIdentity({
    name: "node",
    version: process.version,
    platform: process.platform,
    architecture: process.arch,
    executableFile: path.basename(process.execPath).toLocaleLowerCase("en-US"),
    executableBytes: executable.bytes,
    executableSha256: executable.sha256,
  });
}

const testRuntimeReceipt = Object.freeze({
  qualificationEligible: false,
  name: "test-only-injected-runtime",
  version: "test-only",
  platform: process.platform,
  architecture: process.arch,
  executableFile: "test-only",
  executableBytes: 0,
  executableSha256: "0".repeat(64),
});

function increment(counters, field) {
  if (!Number.isSafeInteger(counters[field]) || counters[field] < 0 || counters[field] === Number.MAX_SAFE_INTEGER) {
    throw new Error(`localhost fixture counter is invalid: ${field}`);
  }
  counters[field] += 1;
}

function isoTimestamp(now, label) {
  const value = now();
  if (!(value instanceof Date) || !Number.isFinite(value.getTime())) {
    throw new Error(`localhost fixture ${label} clock is invalid`);
  }
  return value.toISOString();
}

async function assertUnusedReceiptPath(receiptPath) {
  if (typeof receiptPath !== "string" || !path.isAbsolute(receiptPath) || receiptPath.includes("\0")) {
    throw new Error("--receipt must be one absolute Windows-local JSON path");
  }
  if (process.platform === "win32" && /^[\\/]{2}/u.test(receiptPath)) {
    throw new Error("--receipt must not use a Windows UNC or device-namespace path");
  }
  if (path.basename(receiptPath) !== RECEIPT_FILENAME) {
    throw new Error(`--receipt filename must be exactly ${RECEIPT_FILENAME}`);
  }

  const parent = await lstat(path.dirname(receiptPath));
  if (!parent.isDirectory() || parent.isSymbolicLink()) {
    throw new Error("localhost fixture receipt parent must be one existing real directory");
  }

  try {
    await lstat(receiptPath);
  } catch (error) {
    if (error?.code === "ENOENT") return;
    throw error;
  }
  throw new Error("localhost fixture refuses to replace an existing receipt");
}

async function writeReceiptExclusive(receiptPath, receipt) {
  const bytes = Buffer.from(`${JSON.stringify(receipt, null, 2)}\n`, "utf8");
  if (bytes.length > 64 * 1024) {
    throw new Error("localhost fixture receipt exceeded its fixed byte bound");
  }
  const handle = await open(receiptPath, "wx", 0o600);
  try {
    await handle.writeFile(bytes);
    await handle.sync();
  } finally {
    await handle.close();
  }
}

function respond(response, statusCode, body) {
  response.statusCode = statusCode;
  response.sendDate = false;
  response.shouldKeepAlive = false;
  response.setHeader("Cache-Control", "no-store");
  response.setHeader("Connection", "close");
  response.setHeader("Content-Length", String(body.length));
  response.setHeader("Content-Type", "text/plain; charset=utf-8");
  response.setHeader("X-Content-Type-Options", "nosniff");
  response.end(body);
}

function listenExactly(server, port) {
  return new Promise((resolve, reject) => {
    const onError = (error) => {
      server.off("listening", onListening);
      reject(error);
    };
    const onListening = () => {
      server.off("error", onError);
      resolve();
    };
    server.once("error", onError);
    server.once("listening", onListening);
    server.listen({ host: HOST, port, exclusive: true, backlog: MAX_CONNECTIONS });
  });
}

function closeServer(server) {
  return new Promise((resolve, reject) => {
    server.close((error) => {
      if (error) reject(error);
      else resolve();
    });
    server.closeIdleConnections?.();
    server.closeAllConnections?.();
  });
}

async function startLoopbackFixture({ receiptPath, now, requestedPort, requireCanonicalPort, runtime }) {
  await assertUnusedReceiptPath(receiptPath);

  const counters = {
    tcpConnectionsAccepted: 0,
    tcpConnectionsDropped: 0,
    httpRequestsReceived: 0,
    healthResponsesSent: 0,
    rejectedHttpRequests: 0,
    socketErrors: 0,
  };
  let runtimeError = null;

  const server = http.createServer((request, response) => {
    increment(counters, "httpRequestsReceived");
    request.resume();

    const isHealthRequest =
      (request.method === "GET" || request.method === "HEAD") && request.url === HEALTH_PATH;
    if (!isHealthRequest) {
      increment(counters, "rejectedHttpRequests");
      respond(response, 404, NOT_FOUND_BODY);
      return;
    }

    response.once("finish", () => increment(counters, "healthResponsesSent"));
    if (request.method === "HEAD") {
      response.statusCode = WINDOWS_LOCALHOST_FIXTURE_CONTRACT.healthStatusCode;
      response.sendDate = false;
      response.shouldKeepAlive = false;
      response.setHeader("Cache-Control", "no-store");
      response.setHeader("Connection", "close");
      response.setHeader("Content-Length", String(HEALTH_BODY.length));
      response.setHeader("Content-Type", WINDOWS_LOCALHOST_FIXTURE_CONTRACT.healthContentType);
      response.setHeader("X-Content-Type-Options", "nosniff");
      response.end();
      return;
    }
    respond(response, WINDOWS_LOCALHOST_FIXTURE_CONTRACT.healthStatusCode, HEALTH_BODY);
  });

  server.maxConnections = MAX_CONNECTIONS;
  server.headersTimeout = SOCKET_TIMEOUT_MILLISECONDS;
  server.requestTimeout = SOCKET_TIMEOUT_MILLISECONDS;
  server.keepAliveTimeout = 1;
  server.on("connection", (socket) => {
    increment(counters, "tcpConnectionsAccepted");
    socket.setNoDelay(true);
    socket.setTimeout(SOCKET_TIMEOUT_MILLISECONDS, () => socket.destroy());
    socket.on("error", () => increment(counters, "socketErrors"));
  });
  server.on("drop", () => increment(counters, "tcpConnectionsDropped"));

  await listenExactly(server, requestedPort);
  let startedAt;
  let boundAddress;
  try {
    const address = server.address();
    const exactBinding =
      address &&
      typeof address === "object" &&
      address.address === HOST &&
      Number.isSafeInteger(address.port) &&
      address.port > 0 &&
      address.port <= 65_535 &&
      (!requireCanonicalPort || address.port === PORT) &&
      (address.family === "IPv4" || address.family === 4);
    if (!exactBinding) {
      throw new Error("localhost fixture refused a non-canonical bind result");
    }
    boundAddress = Object.freeze({ address: HOST, port: address.port, family: "IPv4" });
    startedAt = isoTimestamp(now, "start");
  } catch (error) {
    await closeServer(server);
    throw error;
  }

  let resolveFailure;
  const failure = new Promise((resolve) => {
    resolveFailure = resolve;
  });
  let shutdownStarted = false;
  const recordRuntimeError = (error) => {
    if (runtimeError) return;
    runtimeError = error instanceof Error ? error : new Error("localhost fixture server failed");
    resolveFailure(runtimeError);
  };
  server.on("error", recordRuntimeError);
  server.on("close", () => {
    if (shutdownStarted) return;
    const error = new Error("localhost fixture stopped listening before clean shutdown");
    error.code = "EUNEXPECTEDCLOSE";
    recordRuntimeError(error);
  });
  let shutdownPromise = null;

  const shutdown = (reason = "operator") => {
    if (!ALLOWED_SHUTDOWN_REASONS.has(reason)) {
      return Promise.reject(new Error("localhost fixture shutdown reason is not allowed"));
    }
    if (shutdownPromise) return shutdownPromise;
    shutdownStarted = true;
    shutdownPromise = (async () => {
      await closeServer(server);
      if (runtimeError) {
        throw new Error(`localhost fixture server failed before clean shutdown (${runtimeError.code ?? "unknown"})`);
      }
      const receipt = {
        schemaVersion: WINDOWS_LOCALHOST_FIXTURE_CONTRACT.schemaVersion,
        receiptType: "windows-host-loopback-fixture-connection",
        fixture: WINDOWS_LOCALHOST_FIXTURE_CONTRACT.fixture,
        fixtureContractVersion: WINDOWS_LOCALHOST_FIXTURE_CONTRACT.contractVersion,
        runtime,
        binding: {
          address: HOST,
          port: boundAddress.port,
          family: "IPv4",
        },
        healthResponse: {
          path: HEALTH_PATH,
          statusCode: WINDOWS_LOCALHOST_FIXTURE_CONTRACT.healthStatusCode,
          contentType: WINDOWS_LOCALHOST_FIXTURE_CONTRACT.healthContentType,
          bodyBytes: WINDOWS_LOCALHOST_FIXTURE_CONTRACT.healthBodyBytes,
          bodySha256: WINDOWS_LOCALHOST_FIXTURE_CONTRACT.healthBodySha256,
        },
        startedAt,
        endedAt: isoTimestamp(now, "shutdown"),
        shutdownReason: reason,
        counters: { ...counters },
      };
      await writeReceiptExclusive(receiptPath, receipt);
      return receipt;
    })();
    return shutdownPromise;
  };

  return Object.freeze({
    address: boundAddress,
    failure,
    receiptPath,
    shutdown,
  });
}

export async function startWindowsLocalhostFixture({ receiptPath, now = () => new Date() } = {}) {
  const runtimeIdentity = await observeApprovedWindowsRuntime();
  return startLoopbackFixture({
    receiptPath,
    now,
    requestedPort: PORT,
    requireCanonicalPort: true,
    runtime: { qualificationEligible: true, ...runtimeIdentity },
  });
}

// Test seam only: the production starter and CLI can never select a port.
export const WINDOWS_LOCALHOST_FIXTURE_TEST_ONLY = Object.freeze({
  assertApprovedRuntimeIdentity,
  startCanonical({ receiptPath, now = () => new Date() } = {}) {
    return startLoopbackFixture({
      receiptPath,
      now,
      requestedPort: PORT,
      requireCanonicalPort: true,
      runtime: testRuntimeReceipt,
    });
  },
  startEphemeral({ receiptPath, now = () => new Date() } = {}) {
    return startLoopbackFixture({
      receiptPath,
      now,
      requestedPort: 0,
      requireCanonicalPort: false,
      runtime: testRuntimeReceipt,
    });
  },
});

export function parseFixtureArguments(argv) {
  if (!Array.isArray(argv) || argv.length !== 2 || argv[0] !== "--receipt") {
    throw new Error(`usage: windows-localhost-fixture.mjs --receipt <absolute-path\\${RECEIPT_FILENAME}>`);
  }
  return { receiptPath: argv[1] };
}

async function main() {
  const options = parseFixtureArguments(process.argv.slice(2));
  const fixture = await startWindowsLocalhostFixture(options);
  process.stdout.write(`${JSON.stringify({ event: "ready", ...fixture.address })}\n`);

  let onSigint;
  let onSigterm;
  const signal = new Promise((resolve) => {
    const onSignal = (signal) => {
      process.off("SIGINT", onSigint);
      process.off("SIGTERM", onSigterm);
      resolve(signal);
    };
    onSigint = () => onSignal("SIGINT");
    onSigterm = () => onSignal("SIGTERM");
    process.once("SIGINT", onSigint);
    process.once("SIGTERM", onSigterm);
  });
  const outcome = await Promise.race([
    signal.then((reason) => ({ kind: "signal", reason })),
    fixture.failure.then((error) => ({ kind: "failure", error })),
  ]);
  process.off("SIGINT", onSigint);
  process.off("SIGTERM", onSigterm);
  if (outcome.kind === "failure") {
    await fixture.shutdown("operator").catch(() => {});
    throw outcome.error;
  }
  const receipt = await fixture.shutdown(outcome.reason);
  process.stdout.write(`${JSON.stringify({ event: "stopped", counters: receipt.counters })}\n`);
}

if (process.argv[1] && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  main().catch((error) => {
    const code = typeof error?.code === "string" ? error.code : "failed";
    process.stderr.write(`windows localhost fixture: ${code}: ${error instanceof Error ? error.message : String(error)}\n`);
    process.exitCode = 1;
  });
}
