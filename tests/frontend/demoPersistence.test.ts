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
      webService?: { protocol: string; port: number; path: string; scanProfile?: string };
      networkService?: { protocol: string; port: number; scanProfile: string };
      hostScan?: { protocol: string; ports: number[]; scanProfile: string };
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
      declaredWebService?: { protocol: string; port: number; path: string; scanProfile?: string };
      declaredNetworkService?: { protocol: string; port: number; scanProfile: string };
      declaredHostScan?: { protocol: string; ports: number[]; scanProfile: string };
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

const internalDeviceCaseInput = {
  ...websiteCaseInput,
  name: "Branch gateway review",
  assessmentIntent: "internal_it_environment",
  knownAssets: [{
    kind: "external_target",
    value: "10.20.30.40",
    internetExposure: "internal",
    webService: {
      protocol: "https",
      port: 8080,
      path: "/",
      scanProfile: "internal_device_https",
    },
  }],
};

const internalEndpointCaseInput = {
  ...websiteCaseInput,
  name: "SSH endpoint review",
  assessmentIntent: "internal_it_environment",
  knownAssets: [{
    kind: "external_target",
    value: "server.example.test",
    internetExposure: "internal",
    networkService: {
      protocol: "tcp",
      port: 2222,
      scanProfile: "internal_endpoint_ssh",
    },
  }],
};

const internalHostCaseInput = {
  ...websiteCaseInput,
  name: "Internal host review",
  assessmentIntent: "internal_it_environment",
  knownAssets: [{
    kind: "external_target",
    value: "host.example.test",
    internetExposure: "internal",
    hostScan: {
      protocol: "tcp",
      ports: [22, 25, 443, 445, 3389],
      scanProfile: "internal_host_greenbone_remote_safe",
    },
  }],
};

const rdpTlsEndpointCaseInput = {
  ...websiteCaseInput,
  name: "RDP transport review",
  assessmentIntent: "internal_it_environment",
  knownAssets: [{
    kind: "external_target",
    value: "desktop.example.test",
    internetExposure: "internal",
    networkService: {
      protocol: "tcp",
      port: 3389,
      scanProfile: "internal_endpoint_rdp_tls",
    },
  }],
};

const vncEndpointCaseInput = {
  ...websiteCaseInput,
  name: "VNC transport review",
  assessmentIntent: "internal_it_environment",
  knownAssets: [{
    kind: "external_target",
    value: "workstation.example.test",
    internetExposure: "internal",
    networkService: {
      protocol: "tcp",
      port: 5900,
      scanProfile: "internal_endpoint_vnc",
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

test("browser persistence retains the generic internal-device HTTPS profile", () => {
  storedValue = "[]";
  const assessmentCase = demo.createStoredDemoCase(internalDeviceCaseInput);
  const workspace = demo.getDemoWorkspace(assessmentCase.id);

  assert.deepEqual(workspace.assets[0]?.declaredWebService, {
    protocol: "https",
    port: 8080,
    path: "/",
    scanProfile: "internal_device_https",
  });
  assert.deepEqual(demo.getDemoWorkspace(assessmentCase.id).assets[0]?.declaredWebService, {
    protocol: "https",
    port: 8080,
    path: "/",
    scanProfile: "internal_device_https",
  });
});

test("browser persistence retains one generic exact-host Greenbone profile", () => {
  storedValue = "[]";
  const assessmentCase = demo.createStoredDemoCase(internalHostCaseInput);
  const workspace = demo.getDemoWorkspace(assessmentCase.id);

  assert.equal(workspace.assets[0]?.type, "domain");
  assert.equal(workspace.assets[0]?.internetExposed, false);
  assert.deepEqual(workspace.assets[0]?.declaredHostScan, {
    protocol: "tcp",
    ports: [22, 25, 443, 445, 3389],
    scanProfile: "internal_host_greenbone_remote_safe",
  });
  assert.deepEqual(demo.getDemoWorkspace(assessmentCase.id).assets[0]?.declaredHostScan,
    workspace.assets[0]?.declaredHostScan);
});

test("browser persistence retains an exact SSH endpoint as an external service", () => {
  storedValue = "[]";
  const assessmentCase = demo.createStoredDemoCase(internalEndpointCaseInput);
  const workspace = demo.getDemoWorkspace(assessmentCase.id);
  const asset = workspace.assets[0];

  assert.equal(asset?.type, "service");
  assert.equal(asset?.platform, "external");
  assert.equal(asset?.internetExposed, false);
  assert.deepEqual(asset?.identifiers, [{ namespace: "dns_name", value: "server.example.test" }]);
  assert.deepEqual(asset?.declaredNetworkService, {
    protocol: "tcp",
    port: 2222,
    scanProfile: "internal_endpoint_ssh",
  });
  assert.deepEqual(demo.getDemoWorkspace(assessmentCase.id).assets[0]?.declaredNetworkService, {
    protocol: "tcp",
    port: 2222,
    scanProfile: "internal_endpoint_ssh",
  });
});

test("browser persistence retains the serialized RDP transport endpoint profile", () => {
  storedValue = "[]";
  const assessmentCase = demo.createStoredDemoCase(rdpTlsEndpointCaseInput);
  const workspace = demo.getDemoWorkspace(assessmentCase.id);
  const asset = workspace.assets[0];

  assert.equal(asset?.type, "service");
  assert.equal(asset?.platform, "external");
  assert.equal(asset?.internetExposed, false);
  assert.deepEqual(asset?.identifiers, [{ namespace: "dns_name", value: "desktop.example.test" }]);
  assert.deepEqual(asset?.declaredNetworkService, {
    protocol: "tcp",
    port: 3389,
    scanProfile: "internal_endpoint_rdp_tls",
  });
  assert.deepEqual(demo.getDemoWorkspace(assessmentCase.id).assets[0]?.declaredNetworkService, {
    protocol: "tcp",
    port: 3389,
    scanProfile: "internal_endpoint_rdp_tls",
  });
});

test("browser persistence retains an exact VNC transport endpoint profile", () => {
  storedValue = "[]";
  const assessmentCase = demo.createStoredDemoCase(vncEndpointCaseInput);
  const workspace = demo.getDemoWorkspace(assessmentCase.id);
  const asset = workspace.assets[0];

  assert.equal(asset?.type, "service");
  assert.equal(asset?.platform, "external");
  assert.equal(asset?.internetExposed, false);
  assert.deepEqual(asset?.identifiers, [{ namespace: "dns_name", value: "workstation.example.test" }]);
  assert.deepEqual(asset?.declaredNetworkService, {
    protocol: "tcp",
    port: 5900,
    scanProfile: "internal_endpoint_vnc",
  });
  assert.deepEqual(demo.getDemoWorkspace(assessmentCase.id).assets[0]?.declaredNetworkService, {
    protocol: "tcp",
    port: 5900,
    scanProfile: "internal_endpoint_vnc",
  });
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
    [{
      kind: "external_target",
      value: "example.com",
      internetExposure: "public",
      webService: {
        protocol: "https",
        port: 443,
        path: "/",
        scanProfile: "website_quick",
      },
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
