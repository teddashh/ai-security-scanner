import assert from "node:assert/strict";
import test from "node:test";

import {
  isCurrentScanReadinessRequest,
  isCurrentScanReadinessResponse,
} from "../../src/scanReadinessRequest.ts";

test("an older readiness response cannot overwrite a newer request", () => {
  assert.equal(isCurrentScanReadinessRequest(2, 1), false);
  assert.equal(isCurrentScanReadinessResponse(2, 1, "case-a", "case-a"), false);
  assert.equal(isCurrentScanReadinessResponse(2, 2, "case-b", "case-b"), true);
});

test("a response for another case is rejected even at the current generation", () => {
  assert.equal(isCurrentScanReadinessResponse(4, 4, "case-b", "case-a"), false);
  assert.equal(isCurrentScanReadinessResponse(4, 4, "case-b", "case-b"), true);
});

test("a terminal readiness response supersedes an older same-case response", async () => {
  let generation = 0;
  let appliedState: string | undefined;
  const deferred = <T,>() => {
    let resolve!: (value: T) => void;
    const promise = new Promise<T>((fulfill) => { resolve = fulfill; });
    return { promise, resolve };
  };
  const older = deferred<{ caseId: string; state: string }>();
  const terminal = deferred<{ caseId: string; state: string }>();
  const apply = async (response: Promise<{ caseId: string; state: string }>) => {
    const requestGeneration = ++generation;
    const value = await response;
    if (isCurrentScanReadinessResponse(generation, requestGeneration, "case-a", value.caseId)) {
      appliedState = value.state;
    }
  };

  const olderRequest = apply(older.promise);
  const terminalRequest = apply(terminal.promise);
  terminal.resolve({ caseId: "case-a", state: "ready" });
  await terminalRequest;
  older.resolve({ caseId: "case-a", state: "scan_already_active" });
  await olderRequest;

  assert.equal(appliedState, "ready");
});

test("a terminal response for the prior case is ignored after a case switch", async () => {
  let generation = 0;
  let selectedCaseId = "case-a";
  let appliedState: string | undefined;
  let resolve!: (value: { caseId: string; state: string }) => void;
  const response = new Promise<{ caseId: string; state: string }>((fulfill) => { resolve = fulfill; });
  const requestGeneration = ++generation;
  const terminalRequest = response.then((value) => {
    if (
      selectedCaseId === "case-a"
      && isCurrentScanReadinessResponse(generation, requestGeneration, "case-a", value.caseId)
    ) appliedState = value.state;
  });

  selectedCaseId = "case-b";
  generation += 1;
  resolve({ caseId: "case-a", state: "ready" });
  await terminalRequest;

  assert.equal(appliedState, undefined);
});
