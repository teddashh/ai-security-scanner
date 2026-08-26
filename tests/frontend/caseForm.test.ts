import assert from "node:assert/strict";
import test from "node:test";

import { buildKnownAssets, lineValues } from "../../src/caseForm.ts";

const emptyDraft = {
  selectedUseCase: undefined,
  websiteUrl: "",
  publicTargets: "",
  internalTargets: "",
  repositories: "",
  iacProjects: "",
  containerImages: "",
  kubernetesClusters: "",
};

test("case asset lines are trimmed, empty lines removed, and exact duplicates collapsed", () => {
  assert.deepEqual(lineValues(" a.example.test\n\n a.example.test \r\nb.example.test"), [
    "a.example.test",
    "b.example.test",
  ]);
});

test("website preset stores only the hostname candidate and preserves public intent", () => {
  assert.deepEqual(buildKnownAssets({
    ...emptyDraft,
    selectedUseCase: "deployed_website",
    websiteUrl: "https://portal.example.test:8443/login",
  }), {
    ok: true,
    knownAssets: [{
      kind: "external_target",
      value: "portal.example.test",
      internetExposure: "public",
      webService: {
        protocol: "https",
        port: 8443,
        path: "/login",
      },
    }],
  });
});

test("public and internal target intent reaches separate known-asset records", () => {
  assert.deepEqual(buildKnownAssets({
    ...emptyDraft,
    publicTargets: "public.example.test\n203.0.113.10",
    internalTargets: "10.0.0.8\n10.0.0.0/28",
  }), {
    ok: true,
    knownAssets: [
      { kind: "external_target", value: "public.example.test", internetExposure: "public" },
      { kind: "external_target", value: "203.0.113.10", internetExposure: "public" },
      { kind: "external_target", value: "10.0.0.8", internetExposure: "internal" },
      { kind: "external_target", value: "10.0.0.0/28", internetExposure: "internal" },
    ],
  });
});

test("guided public and internal network cases require a real target", () => {
  assert.deepEqual(buildKnownAssets({
    ...emptyDraft,
    selectedUseCase: "external_ip_or_domain",
  }), {
    ok: false,
    error: { kind: "missing_target", target: "public" },
  });
  assert.deepEqual(buildKnownAssets({
    ...emptyDraft,
    selectedUseCase: "internal_it_environment",
  }), {
    ok: false,
    error: { kind: "missing_target", target: "internal" },
  });
});

test("the same target cannot silently acquire conflicting public and internal intent", () => {
  assert.deepEqual(buildKnownAssets({
    ...emptyDraft,
    publicTargets: "10.0.0.8",
    internalTargets: "10.0.0.8",
  }), {
    ok: false,
    error: { kind: "conflicting_exposure", target: "10.0.0.8" },
  });
});

test("exposure conflicts are detected after hostname case and IDNA normalization", () => {
  assert.deepEqual(buildKnownAssets({
    ...emptyDraft,
    publicTargets: "BÜCHER.Example.",
    internalTargets: "xn--bcher-kva.example",
  }), {
    ok: false,
    error: { kind: "conflicting_exposure", target: "xn--bcher-kva.example" },
  });
});

test("all existing local artifact coordinates remain available", () => {
  assert.deepEqual(buildKnownAssets({
    ...emptyDraft,
    repositories: "service-api",
    iacProjects: "infra/prod",
    containerImages: `registry.example/app@sha256:${"a".repeat(64)}`,
    kubernetesClusters: "production-eks",
  }), {
    ok: true,
    knownAssets: [
      { kind: "repository", value: "service-api" },
      { kind: "iac_project", value: "infra/prod" },
      { kind: "container_image", value: `registry.example/app@sha256:${"a".repeat(64)}` },
      { kind: "kubernetes_cluster", value: "production-eks" },
    ],
  });
});

test("guided local routes wait for the real picker snapshot instead of creating text placeholders", () => {
  for (const [selectedUseCase, field] of [
    ["ai_application", "repositories"],
    ["source_code", "repositories"],
    ["infrastructure_as_code", "iacProjects"],
    ["container_image", "containerImages"],
    ["kubernetes", "kubernetesClusters"],
  ] as const) {
    assert.deepEqual(buildKnownAssets({
      ...emptyDraft,
      selectedUseCase,
      [field]: "placeholder-that-must-not-become-an-asset",
    }), {
      ok: true,
      knownAssets: [],
    });
  }
});
