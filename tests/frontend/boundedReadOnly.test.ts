import assert from "node:assert/strict";
import test from "node:test";

import {
  createInFlightReadCoalescer,
  settleReadOnlyWithin,
} from "../../src/services/boundedReadOnly.ts";

test("a bounded read returns an authoritative value or error before its deadline", async () => {
  assert.deepEqual(await settleReadOnlyWithin(Promise.resolve("ready"), 100), {
    outcome: "completed",
    value: "ready",
  });

  const failure = new Error("read failed");
  assert.deepEqual(await settleReadOnlyWithin(Promise.reject(failure), 100), {
    outcome: "failed",
    error: failure,
  });
});

test("a timed-out read releases its caller while its late result is ignored", async () => {
  let resolveLateRead: ((value: string) => void) | undefined;
  const lateRead = new Promise<string>((resolve) => {
    resolveLateRead = resolve;
  });

  assert.deepEqual(await settleReadOnlyWithin(lateRead, 5), { outcome: "timed_out" });

  resolveLateRead?.("stale result");
  await Promise.resolve();

  assert.deepEqual(await settleReadOnlyWithin(Promise.resolve("new truth"), 100), {
    outcome: "completed",
    value: "new truth",
  });
});

test("repeated UI timeouts reuse one underlying read and late truth remains observable", async () => {
  const reads = createInFlightReadCoalescer<string, string>();
  let invokeCount = 0;
  let resolveRead: ((value: string) => void) | undefined;
  const start = () => {
    invokeCount += 1;
    return new Promise<string>((resolve) => {
      resolveRead = resolve;
    });
  };

  let generation = 0;
  let unavailable = false;
  let acceptedTruth: string | undefined;
  let first: Promise<string> | undefined;
  const refresh = async () => {
    const requestGeneration = ++generation;
    const read = reads.read("case-a", start);
    first ??= read;
    const observation = await settleReadOnlyWithin(read, 5);
    if (observation.outcome === "timed_out") {
      unavailable = true;
      void read.then((value) => {
        if (generation !== requestGeneration) return;
        acceptedTruth = value;
        unavailable = false;
      });
    }
    return { read };
  };

  const { read: firstObservation } = await refresh();
  const { read: retryObservation } = await refresh();
  assert.equal(firstObservation, first);
  assert.equal(retryObservation, first);
  assert.equal(invokeCount, 1);

  resolveRead?.("authoritative snapshot");
  await retryObservation;
  await Promise.resolve();
  assert.equal(acceptedTruth, "authoritative snapshot");
  assert.equal(unavailable, false);

  await Promise.resolve();
  assert.notEqual(reads.read("case-a", () => Promise.resolve("new snapshot")), first);
});

test("managed-runtime status retry reuses one raw invoke and reconciles late status", async () => {
  const reads = createInFlightReadCoalescer<string, { phase: string }>();
  let invokeCount = 0;
  let resolveStatus: ((status: { phase: string }) => void) | undefined;
  let generation = 0;
  let reconciledPhase: string | undefined;

  const refresh = async () => {
    const requestGeneration = ++generation;
    const rawStatus = reads.read("managed-runtime-status", () => {
      invokeCount += 1;
      return new Promise<{ phase: string }>((resolve) => {
        resolveStatus = resolve;
      });
    });
    const observation = await settleReadOnlyWithin(rawStatus, 5);
    if (observation.outcome === "timed_out") {
      void rawStatus.then((status) => {
        if (generation === requestGeneration) reconciledPhase = status.phase;
      });
    }
  };

  await refresh();
  await refresh();
  assert.equal(invokeCount, 1);

  resolveStatus?.({ phase: "completed" });
  await Promise.resolve();
  await Promise.resolve();
  assert.equal(reconciledPhase, "completed");
});
