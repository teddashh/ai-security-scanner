import assert from "node:assert/strict";
import test from "node:test";

import { build } from "esbuild";

const bundled = await build({
  stdin: {
    contents: `export {
      createStoredDemoCase,
      deleteStoredDemoCase,
      getDemoWorkspace,
      loadStoredDemoCases,
    } from "./src/data/demo.ts";`,
    loader: "ts",
    resolveDir: process.cwd(),
    sourcefile: "demo-persistence-test-entry.ts",
  },
  bundle: true,
  format: "esm",
  platform: "node",
  target: "node22",
  write: false,
});

const moduleUrl = `data:text/javascript;base64,${Buffer.from(bundled.outputFiles[0].text).toString("base64")}`;
const demo = await import(moduleUrl) as {
  createStoredDemoCase: (input: {
    name: string;
    assessmentIntent?: string;
    aiGeneratedArtifact: "yes" | "no" | "unknown";
    organizationName: string;
    companySize: string;
    dataClasses: string[];
    requestedActivities: string[];
    platforms: string[];
    knownAssets: Array<{
      kind: string;
      value: string;
      internetExposure?: string;
      webService?: { protocol: string; port: number; path: string };
    }>;
  }) => { id: string; phase: string };
  deleteStoredDemoCase: (caseId: string, confirmation: string) => boolean;
  getDemoWorkspace: (caseId: string) => {
    case: { phase: string };
    sources: Array<{
      id: string;
      kind: string;
      status: string;
      readOnly: boolean;
    }>;
    coverage: Array<{
      assetId?: string;
      sourceKind: string;
      state: string;
      assetCount: number;
      scanAttempted?: boolean;
    }>;
    assets: Array<{
      id: string;
      type: string;
      platform: string;
      locator: string;
      identifiers?: Array<{ namespace: string; value: string }>;
      discoveredFromSourceIds?: string[];
      internetExposed?: boolean;
      coverageState: string;
      authorizationState: string;
      allowedModes: string[];
      findingCount: number;
      scanAttempted?: boolean;
      declaredWebService?: { protocol: string; port: number; path: string };
    }>;
    scopeGrants: unknown[];
    runs: unknown[];
    findings: unknown[];
  };
  loadStoredDemoCases: () => Array<{ aiGeneratedArtifact: unknown }>;
};

let storedValue = "[]";
Object.defineProperty(globalThis, "window", {
  configurable: true,
  value: {
    localStorage: {
      getItem: () => storedValue,
      setItem: (_key: string, value: string) => {
        storedValue = value;
      },
    },
  },
});

const loadAnswer = (value: unknown, includeProperty = true): unknown => {
  storedValue = JSON.stringify([{
    id: "case-demo-persisted",
    ...(includeProperty ? { aiGeneratedArtifact: value } : {}),
  }]);
  return demo.loadStoredDemoCases()[0]?.aiGeneratedArtifact;
};

const websiteCaseInput = {
  name: "Example website review",
  assessmentIntent: "deployed_website",
  aiGeneratedArtifact: "no" as const,
  organizationName: "Example",
  companySize: "small",
  dataClasses: ["public"],
  requestedActivities: ["external_assessment"],
  platforms: ["external"],
  knownAssets: [{
    kind: "external_target",
    value: "example.com",
    internetExposure: "public",
    webService: {
      protocol: "https",
      port: 443,
      path: "/",
    },
  }],
};

test("stored demo AI-origin answers preserve the three supported values", () => {
  for (const answer of ["yes", "no", "unknown"] as const) {
    assert.equal(loadAnswer(answer), answer);
  }
});

test("stored demo AI-origin answers fail closed when missing or malformed", () => {
  assert.equal(loadAnswer(undefined, false), "unknown");
  for (const malformed of [null, "maybe", true, false, 1, {}, []]) {
    assert.equal(loadAnswer(malformed), "unknown");
  }
});

test("browser-persisted website targets project into an honest pending workspace", () => {
  storedValue = "[]";
  const assessmentCase = demo.createStoredDemoCase(websiteCaseInput);
  const workspace = demo.getDemoWorkspace(assessmentCase.id);

  assert.equal(assessmentCase.phase, "scope_review");
  assert.equal(workspace.case.phase, "scope_review");
  assert.equal(workspace.sources.length, 1);
  const source = workspace.sources[0];
  assert.equal(source?.kind, "user_declared");
  assert.equal(source?.status, "connected");
  assert.equal(source?.readOnly, true);

  assert.equal(workspace.assets.length, 1);
  const asset = workspace.assets[0];
  assert.equal(asset?.type, "domain");
  assert.equal(asset?.platform, "external");
  assert.equal(asset?.locator, "example.com");
  assert.deepEqual(asset?.identifiers, [{ namespace: "dns_name", value: "example.com" }]);
  assert.deepEqual(asset?.discoveredFromSourceIds, [source?.id]);
  assert.equal(asset?.internetExposed, true);
  assert.deepEqual(asset?.declaredWebService, { protocol: "https", port: 443, path: "/" });
  assert.equal(asset?.coverageState, "discovered_not_authorized");
  assert.equal(asset?.authorizationState, "pending");
  assert.deepEqual(asset?.allowedModes, []);
  assert.equal(asset?.findingCount, 0);
  assert.equal(asset?.scanAttempted, false);

  assert.equal(workspace.coverage.length, 1);
  assert.equal(workspace.coverage[0]?.assetId, asset?.id);
  assert.equal(workspace.coverage[0]?.sourceKind, "user_declared");
  assert.equal(workspace.coverage[0]?.state, "discovered_not_authorized");
  assert.equal(workspace.coverage[0]?.assetCount, 1);
  assert.equal(workspace.coverage[0]?.scanAttempted, false);
  assert.deepEqual(workspace.scopeGrants, []);
  assert.deepEqual(workspace.runs, []);
  assert.deepEqual(workspace.findings, []);

  const reloaded = demo.getDemoWorkspace(assessmentCase.id);
  assert.equal(reloaded.assets[0]?.id, asset?.id, "browser reloads must preserve candidate identity");
});

test("browser projection preserves exact target classes and fails sensitive targets to internal", () => {
  storedValue = "[]";
  const input = {
    ...websiteCaseInput,
    name: "Mixed exact targets",
    assessmentIntent: "external_ip_or_domain",
    knownAssets: [
      { kind: "external_target", value: "203.0.113.10", internetExposure: "public" },
      { kind: "external_target", value: "203.0.113.0/28", internetExposure: "public" },
      { kind: "external_target", value: "127.0.0.1", internetExposure: "public" },
      { kind: "external_target", value: "unclassified.example" },
      { kind: "repository", value: "C:/saved/project" },
    ],
  };
  const assessmentCase = demo.createStoredDemoCase(input);
  const workspace = demo.getDemoWorkspace(assessmentCase.id);

  assert.deepEqual(
    workspace.assets.map((asset) => asset.identifiers?.[0]),
    [
      { namespace: "ip_address", value: "203.0.113.10" },
      { namespace: "ip_network", value: "203.0.113.0/28" },
      { namespace: "ip_address", value: "127.0.0.1" },
      { namespace: "dns_name", value: "unclassified.example" },
      { namespace: "repository_locator", value: "C:/saved/project" },
    ],
  );
  assert.equal(workspace.assets[0]?.internetExposed, true);
  assert.equal(workspace.assets[1]?.internetExposed, true);
  assert.equal(workspace.assets[2]?.internetExposed, false);
  assert.equal(workspace.assets[3]?.internetExposed, undefined);
  assert.equal(
    (workspace.assets[4] as { questionnairePlaceholder?: boolean })?.questionnairePlaceholder,
    true,
    "a questionnaire path is not an attached local snapshot",
  );
  assert.ok(workspace.assets.every((asset) => asset.authorizationState === "pending"));
  assert.ok(workspace.assets.every((asset) => asset.allowedModes.length === 0));
});

test("malformed browser-persisted known assets fail closed", () => {
  const malformedKnownAssets = [
    "example.com",
    [{ kind: "external_target", value: "" }],
    [{ kind: "unsupported", value: "example.com" }],
    [{
      kind: "external_target",
      value: "example.com",
      internetExposure: "public",
      webService: { protocol: "ftp", port: 443, path: "/" },
    }],
  ];

  for (const [index, knownAssets] of malformedKnownAssets.entries()) {
    storedValue = JSON.stringify([{
      id: `case-malformed-${index}`,
      name: `Malformed ${index}`,
      assessmentIntent: "deployed_website",
      aiGeneratedArtifact: "no",
      organizationName: "Example",
      companySize: "small",
      dataClasses: ["public"],
      requestedActivities: ["external_assessment"],
      platforms: ["external"],
      createdAt: "2026-09-07T00:00:00.000Z",
      updatedAt: "2026-09-07T00:00:00.000Z",
      phase: "draft",
      isDemo: true,
      knownAssets,
    }]);

    const workspace = demo.getDemoWorkspace(`case-malformed-${index}`);
    assert.deepEqual(workspace.sources, [], `malformed record ${index} must not create a source`);
    assert.deepEqual(workspace.assets, [], `malformed record ${index} must not create an asset`);
    assert.deepEqual(workspace.scopeGrants, [], `malformed record ${index} must not create a grant`);
    assert.deepEqual(workspace.runs, [], `malformed record ${index} must not create a run`);
    assert.deepEqual(workspace.findings, [], `malformed record ${index} must not create a finding`);
  }
});

test("exact-name deletion removes only a browser-persisted preview project", () => {
  storedValue = JSON.stringify([
    { id: "case-local-delete", name: "Delete this preview", aiGeneratedArtifact: "unknown" },
    { id: "case-local-keep", name: "Keep this preview", aiGeneratedArtifact: "unknown" },
  ]);

  assert.equal(demo.deleteStoredDemoCase("case-local-delete", "wrong name"), false);
  assert.equal(demo.loadStoredDemoCases().length, 2);
  assert.equal(demo.deleteStoredDemoCase("case-local-delete", "Delete this preview"), true);
  assert.deepEqual(
    demo.loadStoredDemoCases().map((assessmentCase) => (assessmentCase as { id: string }).id),
    ["case-local-keep"],
  );
});

test("built-in and missing preview projects cannot be deleted through browser storage", () => {
  storedValue = "[]";

  assert.equal(demo.deleteStoredDemoCase("case-demo-northstar", "Northstar 初步安全健檢"), false);
  assert.equal(demo.deleteStoredDemoCase("missing", "Missing"), false);
  assert.equal(storedValue, "[]");
});
