import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import test from "node:test";

import {
  buildKnownAssets,
  explicitTargetRequiresSensitiveNetworkAllowance,
  lineValues,
  validateExternalTarget,
} from "../../src/caseForm.ts";

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

const externalTargetCorpus = JSON.parse(readFileSync(
  new URL("../fixtures/external-target-corpus.json", import.meta.url),
  "utf8",
)) as { accepted: string[]; rejected: string[] };

test("case asset lines are trimmed, empty lines removed, and exact duplicates collapsed", () => {
  assert.deepEqual(lineValues(" a.example.test\n\n a.example.test \r\nb.example.test"), [
    "a.example.test",
    "b.example.test",
  ]);
});

test("external target validation accepts the native CanonicalTarget shapes", () => {
  for (const target of [
    "scanner.example.test",
    "BÜCHER.Example.",
    "localhost",
    "203.0.113.10",
    "10.20.0.0/28",
    "2001:db8::10",
    "2001:db8::/64",
    "::1",
  ]) {
    assert.deepEqual(validateExternalTarget(target), { ok: true }, target);
  }
});

test("external target acceptance stays aligned with the shared native corpus", () => {
  for (const target of externalTargetCorpus.accepted) {
    assert.equal(validateExternalTarget(target).ok, true, `accepted: ${target}`);
  }
  for (const target of externalTargetCorpus.rejected) {
    assert.equal(validateExternalTarget(target).ok, false, `rejected: ${target}`);
  }
});

test("leading-zero IPv4 CIDRs retain native acceptance and sensitive-network classification", () => {
  assert.deepEqual(validateExternalTarget("010.0.0.0/08"), { ok: true });
  assert.deepEqual(validateExternalTarget("2001:db8::/064"), { ok: true });
  assert.equal(explicitTargetRequiresSensitiveNetworkAllowance("010.0.0.0/08"), true);
});

test("external target validation rejects service coordinates and malformed targets", () => {
  for (const [target, error] of [
    ["https://example.com/path", "service_coordinate_not_allowed"],
    ["user@example.com", "service_coordinate_not_allowed"],
    ["example.com:443", "service_coordinate_not_allowed"],
    ["127.0.0.1:9001", "service_coordinate_not_allowed"],
    ["[2001:db8::10]", "service_coordinate_not_allowed"],
    ["%65xample.com", "invalid_target"],
    ["not a host", "invalid_target"],
    ["single-label", "invalid_target"],
    ["*.example.com", "wildcard_not_allowed"],
    ["10.20.0.0/33", "invalid_cidr"],
    ["2001:db8::/129", "invalid_cidr"],
    ["example.com/24", "invalid_cidr"],
  ] as const) {
    assert.deepEqual(validateExternalTarget(target), { ok: false, error }, target);
  }
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

test("website preset classifies explicit private and loopback targets as internal", () => {
  for (const [websiteUrl, target] of [
    ["http://127.0.0.1:9001/", "127.0.0.1"],
    ["https://10.20.30.40/", "10.20.30.40"],
    ["http://[::1]:9001/", "::1"],
    ["http://localhost:9001/", "localhost"],
  ]) {
    const result = buildKnownAssets({
      ...emptyDraft,
      selectedUseCase: "deployed_website",
      websiteUrl,
    });
    assert.equal(result.ok, true);
    if (!result.ok) continue;
    assert.equal(result.knownAssets[0]?.value, target);
    assert.equal(result.knownAssets[0]?.internetExposure, "internal");
  }
});

test("explicit private IPv4 and IPv6 CIDRs require internal-network permission", () => {
  for (const target of ["192.168.102.0/23", "127.0.0.0/8", "fd00::/8", "fe80::/10"]) {
    assert.equal(explicitTargetRequiresSensitiveNetworkAllowance(target), true, target);
  }
  for (const target of ["203.0.113.0/24", "2001:db8::/32", "example.test"]) {
    assert.equal(explicitTargetRequiresSensitiveNetworkAllowance(target), false, target);
  }
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

test("website preset rejects hostnames outside the native target boundary", () => {
  for (const websiteUrl of ["https://printer/", "https://bad_host.example/"]) {
    assert.deepEqual(buildKnownAssets({
      ...emptyDraft,
      selectedUseCase: "deployed_website",
      websiteUrl,
    }), {
      ok: false,
      error: { kind: "website", error: "hostname_invalid" },
    }, websiteUrl);
  }
  assert.deepEqual(buildKnownAssets({
    ...emptyDraft,
    selectedUseCase: "deployed_website",
    websiteUrl: "https://example.test:0/",
  }), {
    ok: false,
    error: { kind: "website", error: "port_invalid" },
  });
  assert.deepEqual(buildKnownAssets({
    ...emptyDraft,
    selectedUseCase: "deployed_website",
    websiteUrl: `https://example.test/${"界".repeat(300)}`,
  }), {
    ok: false,
    error: { kind: "website", error: "path_too_long" },
  });
});

test("invalid public and internal target lines are rejected before case creation", () => {
  assert.deepEqual(buildKnownAssets({
    ...emptyDraft,
    selectedUseCase: "external_ip_or_domain",
    publicTargets: "127.0.0.1\nhttps://example.com/path\nnot a host",
  }), {
    ok: false,
    error: {
      kind: "invalid_target",
      target: "public",
      value: "https://example.com/path",
      error: "service_coordinate_not_allowed",
    },
  });

  assert.deepEqual(buildKnownAssets({
    ...emptyDraft,
    selectedUseCase: "internal_it_environment",
    internalTargets: "10.20.0.8\n10.20.0.0/99",
  }), {
    ok: false,
    error: {
      kind: "invalid_target",
      target: "internal",
      value: "10.20.0.0/99",
      error: "invalid_cidr",
    },
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

test("exposure conflicts are detected across every canonical target alias", () => {
  for (const [publicTarget, internalTarget, canonical] of [
    ["10.0.0.1/24", "10.0.0.0/24", "10.0.0.0/24"],
    ["010.000.000.001/24", "10.0.0.0/24", "10.0.0.0/24"],
    ["2001:db8:0:0:0:0:0:1", "2001:db8::1", "2001:db8::1"],
    ["2001:db8::1234/64", "2001:db8:0:0::/064", "2001:db8::/64"],
    ["Example.COM...", "example.com", "example.com"],
  ]) {
    assert.deepEqual(buildKnownAssets({
      ...emptyDraft,
      publicTargets: publicTarget,
      internalTargets: internalTarget,
    }), {
      ok: false,
      error: { kind: "conflicting_exposure", target: canonical },
    });
  }
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
