import assert from "node:assert/strict";
import test from "node:test";

import {
  subscribeAllThenReconcile,
  subscribeBufferedEvents,
} from "../../src/services/bufferedEventSubscription.ts";

const deferred = <T,>() => {
  let resolve!: (value: T) => void;
  let reject!: (error: unknown) => void;
  const promise = new Promise<T>((promiseResolve, promiseReject) => {
    resolve = promiseResolve;
    reject = promiseReject;
  });
  return { promise, resolve, reject };
};

test("scan listeners register together and replay events buffered while manifests load", async () => {
  type EventName = "progress" | "finished";
  const context = deferred<string>();
  const registrations = {
    progress: deferred<() => void>(),
    finished: deferred<() => void>(),
  };
  const callbacks = new Map<EventName, (payload: number) => void>();
  const requested: EventName[] = [];
  const handled: string[] = [];
  const cleaned: EventName[] = [];

  const subscription = subscribeBufferedEvents({
    eventNames: ["progress", "finished"] as const,
    loadContext: () => context.promise,
    listen: (eventName, handler) => {
      requested.push(eventName);
      callbacks.set(eventName, handler);
      return registrations[eventName].promise;
    },
    adapt: (payload, manifestContext) => `${manifestContext}:${payload}`,
    handle: (value, eventName) => handled.push(`${eventName}:${value}`),
  });

  await Promise.resolve();
  assert.deepEqual(requested, ["progress", "finished"], "neither listener waits for the other");
  callbacks.get("progress")?.(10);
  callbacks.get("finished")?.(100);
  assert.deepEqual(handled, [], "events wait until their adaptation context is ready");

  context.resolve("manifest-v1");
  registrations.progress.resolve(() => cleaned.push("progress"));
  registrations.finished.resolve(() => cleaned.push("finished"));
  const unlisten = await subscription;
  assert.deepEqual(handled, [
    "progress:manifest-v1:10",
    "finished:manifest-v1:100",
  ]);

  callbacks.get("progress")?.(20);
  assert.equal(handled.at(-1), "progress:manifest-v1:20");
  unlisten();
  callbacks.get("finished")?.(200);
  assert.deepEqual(cleaned.sort(), ["finished", "progress"]);
  assert.equal(handled.at(-1), "progress:manifest-v1:20", "closed listeners ignore late callbacks");
});

test("a partial listener-registration failure cleans up every listener that did register", async () => {
  let cleaned = 0;
  await assert.rejects(
    subscribeBufferedEvents({
      eventNames: ["progress", "finished"] as const,
      loadContext: async () => "manifest-v1",
      listen: async (eventName, _handler: (payload: number) => void) => {
        if (eventName === "finished") throw new Error("registration failed");
        return () => { cleaned += 1; };
      },
      adapt: (payload, context) => `${context}:${payload}`,
      handle: () => undefined,
    }),
    /registration failed/u,
  );
  assert.equal(cleaned, 1);
});

test("startup reconciliation waits for run, coverage, and bootstrap listeners", async () => {
  const registrations = {
    run: deferred<() => void>(),
    coverage: deferred<() => void>(),
    bootstrap: deferred<() => void>(),
  };
  const requested: string[] = [];
  const cleaned: string[] = [];
  const reconciledStates: string[] = [];
  let authoritativeState = "runtime-needs-repair";

  const lifecycle = subscribeAllThenReconcile({
    subscriptions: Object.entries(registrations).map(([name, registration]) => () => {
      requested.push(name);
      return registration.promise;
    }),
    reconcile: async () => {
      reconciledStates.push(authoritativeState);
    },
  });

  assert.deepEqual(requested, ["run", "coverage", "bootstrap"], "all registrations start together");
  registrations.run.resolve(() => cleaned.push("run"));
  registrations.coverage.resolve(() => cleaned.push("coverage"));
  authoritativeState = "runtime-ready"; // Bootstrap changed while its listener did not yet exist.
  await Promise.resolve();
  assert.deepEqual(reconciledStates, [], "no early snapshot read can miss the bootstrap transition");

  registrations.bootstrap.resolve(() => cleaned.push("bootstrap"));
  await lifecycle.ready;
  assert.deepEqual(reconciledStates, ["runtime-ready"]);

  lifecycle.close();
  assert.deepEqual(cleaned.sort(), ["bootstrap", "coverage", "run"]);
});

test("closing during registration unlistens both ready and late subscriptions without reconciling", async () => {
  const early = deferred<() => void>();
  const late = deferred<() => void>();
  const cleaned: string[] = [];
  let reconciliations = 0;
  const lifecycle = subscribeAllThenReconcile({
    subscriptions: [() => early.promise, () => late.promise],
    reconcile: async () => { reconciliations += 1; },
  });

  early.resolve(() => cleaned.push("early"));
  await Promise.resolve();
  lifecycle.close();
  late.resolve(() => cleaned.push("late"));
  await lifecycle.ready;

  assert.deepEqual(cleaned.sort(), ["early", "late"]);
  assert.equal(reconciliations, 0);
});
