import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import test from "node:test";

import {
  buildKnownAssets,
  explicitTargetRequiresSensitiveNetworkAllowance,
  lineValues,
  prepareInternalEndpointService,
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

test("SSH endpoint input accepts one exact host and port without contacting it", () => {
  assert.deepEqual(prepareInternalEndpointService(" Server.Example.test. ", "22"), {
    ok: true,
    value: { target: "server.example.test", port: 22 },
  });
  assert.deepEqual(prepareInternalEndpointService("2001:db8::10", 2222), {
    ok: true,
    value: { target: "2001:db8::10", port: 2222 },
  });
});

test("SSH endpoint input rejects URLs, CIDRs, credentials, service coordinates, and invalid ports", () => {
  for (const [target, port, error] of [
    ["", "22", "empty_target"],
    ["ssh://server.example.test", "22", "url_not_allowed"],
    ["admin@server.example.test", "22", "credentials_not_allowed"],
    ["10.20.0.0/24", "22", "cidr_not_allowed"],
    ["server.example.test:22", "22", "invalid_target"],
    ["server.example.test", "0", "invalid_port"],
    ["server.example.test", "65536", "invalid_port"],
    ["server.example.test", "22.5", "invalid_port"],
  ] as const) {
    assert.deepEqual(prepareInternalEndpointService(target, port), { ok: false, error }, target);
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

test("guided public and combined environment cases require a useful target", () => {
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
    error: { kind: "missing_environment" },
  });
  assert.deepEqual(buildKnownAssets({
    ...emptyDraft,
    selectedUseCase: "internal_it_environment",
    internalTargets: "10.0.0.0/28",
  }), {
    ok: false,
    error: { kind: "missing_environment" },
  });
  assert.deepEqual(buildKnownAssets({
    ...emptyDraft,
    selectedUseCase: "internal_it_environment",
    hasLocalWorkspace: true,
    internalTargets: "10.0.0.0/28",
  }), {
    ok: true,
    knownAssets: [{
      kind: "external_target",
      value: "10.0.0.0/28",
      internetExposure: "internal",
    }],
  });
});

test("one IT environment emits one generic host scan with reviewed common ports", () => {
  assert.deepEqual(buildKnownAssets({
    ...emptyDraft,
    selectedUseCase: "internal_it_environment",
    internalHosts: [{ target: " Server.Example.Internal. ", ports: "" }],
  }), {
    ok: true,
    knownAssets: [{
      kind: "external_target",
      value: "server.example.internal",
      internetExposure: "internal",
      hostScan: {
        protocol: "tcp",
        ports: [22, 23, 25, 80, 443, 445, 3389, 5900, 8080, 8443],
        scanProfile: "internal_host_greenbone_remote_safe",
      },
    }],
  });
});

test("generic host rows normalize custom ports and merge duplicate exact hosts", () => {
  assert.deepEqual(buildKnownAssets({
    ...emptyDraft,
    selectedUseCase: "internal_it_environment",
    internalHosts: [
      { target: "10.20.0.8", ports: "8443, 22, 22" },
      { target: "10.20.0.8", ports: "443, 25" },
    ],
  }), {
    ok: true,
    knownAssets: [{
      kind: "external_target",
      value: "10.20.0.8",
      internetExposure: "internal",
      hostScan: {
        protocol: "tcp",
        ports: [22, 25, 443, 8443],
        scanProfile: "internal_host_greenbone_remote_safe",
      },
    }],
  });
});

test("generic host rows reject ranges and invalid custom ports at the exact row", () => {
  assert.deepEqual(buildKnownAssets({
    ...emptyDraft,
    selectedUseCase: "internal_it_environment",
    internalHosts: [{ target: "10.20.0.0/24", ports: "" }],
  }), {
    ok: false,
    error: {
      kind: "internal_host",
      field: "target",
      error: "cidr_not_allowed",
      value: "10.20.0.0/24",
      index: 0,
    },
  });
  assert.deepEqual(buildKnownAssets({
    ...emptyDraft,
    selectedUseCase: "internal_it_environment",
    internalHosts: [{ target: "host.example.internal", ports: "22, 65536" }],
  }), {
    ok: false,
    error: {
      kind: "internal_host",
      field: "ports",
      error: "port_out_of_range",
      value: "22, 65536",
      index: 0,
    },
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
      error: { kind: "website", error: "hostname_invalid", value: websiteUrl },
    }, websiteUrl);
  }
  assert.deepEqual(buildKnownAssets({
    ...emptyDraft,
    selectedUseCase: "deployed_website",
    websiteUrl: "https://example.test:0/",
  }), {
    ok: false,
    error: { kind: "website", error: "port_invalid", value: "https://example.test:0/" },
  });
  assert.deepEqual(buildKnownAssets({
    ...emptyDraft,
    selectedUseCase: "deployed_website",
    websiteUrl: `https://example.test/${"界".repeat(300)}`,
  }), {
    ok: false,
    error: {
      kind: "website",
      error: "path_too_long",
      value: `https://example.test/${"界".repeat(300)}`,
    },
  });
});

test("one IT environment keeps multiple websites distinct by origin", () => {
  assert.deepEqual(buildKnownAssets({
    ...emptyDraft,
    selectedUseCase: "internal_it_environment",
    websiteUrls: [
      "https://portal.example.test/login",
      "https://portal.example.test/another-path",
      "http://portal.example.test/",
      "https://portal.example.test:8443/admin",
      "https://192.168.20.1/",
    ].join("\n"),
    internalTargets: "192.168.20.10\n192.168.20.11",
    hasLocalWorkspace: true,
  }), {
    ok: true,
    knownAssets: [
      {
        kind: "external_target",
        value: "portal.example.test",
        internetExposure: "public",
        webService: { protocol: "https", port: 443, path: "/login" },
      },
      {
        kind: "external_target",
        value: "portal.example.test",
        internetExposure: "public",
        webService: { protocol: "http", port: 80, path: "/" },
      },
      {
        kind: "external_target",
        value: "portal.example.test",
        internetExposure: "public",
        webService: { protocol: "https", port: 8443, path: "/admin" },
      },
      {
        kind: "external_target",
        value: "192.168.20.1",
        internetExposure: "internal",
        webService: { protocol: "https", port: 443, path: "/" },
      },
      { kind: "external_target", value: "192.168.20.10", internetExposure: "internal" },
      { kind: "external_target", value: "192.168.20.11", internetExposure: "internal" },
    ],
  });
});

test("a web-admin URL is the one specific asset when its host is also listed", () => {
  assert.deepEqual(buildKnownAssets({
    ...emptyDraft,
    selectedUseCase: "internal_it_environment",
    websiteUrls: "https://192.168.20.1/admin",
    internalTargets: "192.168.20.1\n192.168.20.2",
  }), {
    ok: true,
    knownAssets: [
      {
        kind: "external_target",
        value: "192.168.20.1",
        internetExposure: "internal",
        webService: { protocol: "https", port: 443, path: "/admin" },
      },
      { kind: "external_target", value: "192.168.20.2", internetExposure: "internal" },
    ],
  });
});

test("one IT environment preserves the generic HTTPS device scan profile", () => {
  assert.deepEqual(buildKnownAssets({
    ...emptyDraft,
    selectedUseCase: "internal_it_environment",
    internalDeviceEndpoints: [
      { url: "https://10.20.0.8" },
      { url: "https://gateway.internal.example:8080/admin" },
      { url: "   " },
    ],
  }), {
    ok: true,
    knownAssets: [
      {
        kind: "external_target",
        value: "10.20.0.8",
        internetExposure: "internal",
        webService: {
          protocol: "https",
          port: 443,
          path: "/",
          scanProfile: "internal_device_https",
        },
      },
      {
        kind: "external_target",
        value: "gateway.internal.example",
        internetExposure: "internal",
        webService: {
          protocol: "https",
          port: 8080,
          path: "/admin",
          scanProfile: "internal_device_https",
        },
      },
    ],
  });
});

test("one IT environment preserves exact SSH, RDP, VNC, SMTP, and Telnet endpoints and keeps bare inventory separate", () => {
  assert.deepEqual(buildKnownAssets({
    ...emptyDraft,
    selectedUseCase: "internal_it_environment",
    internalEndpointServices: [
      { target: "Server.Example.test.", port: "22" },
      { target: "server.example.test", port: "2222" },
      { target: "10.20.0.12", port: "22" },
      { service: "rdp_tls", target: "desktop.example.test", port: "3389" },
      { service: "vnc", target: "workstation.example.test", port: "5900" },
      { service: "smtp", target: "mail.example.test", port: "587" },
      { service: "telnet", target: "switch.example.test", port: "23" },
    ],
    internalTargets: "10.20.0.12\n10.20.0.0/28",
  }), {
    ok: true,
    knownAssets: [
      {
        kind: "external_target",
        value: "server.example.test",
        internetExposure: "internal",
        networkService: {
          protocol: "tcp",
          port: 22,
          scanProfile: "internal_endpoint_ssh",
        },
      },
      {
        kind: "external_target",
        value: "server.example.test",
        internetExposure: "internal",
        networkService: {
          protocol: "tcp",
          port: 2222,
          scanProfile: "internal_endpoint_ssh",
        },
      },
      {
        kind: "external_target",
        value: "10.20.0.12",
        internetExposure: "internal",
        networkService: {
          protocol: "tcp",
          port: 22,
          scanProfile: "internal_endpoint_ssh",
        },
      },
      {
        kind: "external_target",
        value: "desktop.example.test",
        internetExposure: "internal",
        networkService: {
          protocol: "tcp",
          port: 3389,
          scanProfile: "internal_endpoint_rdp_tls",
        },
      },
      {
        kind: "external_target",
        value: "workstation.example.test",
        internetExposure: "internal",
        networkService: {
          protocol: "tcp",
          port: 5900,
          scanProfile: "internal_endpoint_vnc",
        },
      },
      {
        kind: "external_target",
        value: "mail.example.test",
        internetExposure: "internal",
        networkService: {
          protocol: "tcp",
          port: 587,
          scanProfile: "internal_endpoint_smtp",
        },
      },
      {
        kind: "external_target",
        value: "switch.example.test",
        internetExposure: "internal",
        networkService: {
          protocol: "tcp",
          port: 23,
          scanProfile: "internal_endpoint_telnet",
        },
      },
      { kind: "external_target", value: "10.20.0.0/28", internetExposure: "internal" },
    ],
  });
});

test("one exact TCP service cannot silently receive different endpoint profiles", () => {
  for (const [first, second] of [
    ["ssh", "rdp_tls"],
    ["rdp_tls", "vnc"],
    ["vnc", "smtp"],
    ["smtp", "telnet"],
    ["telnet", "ssh"],
  ] as const) {
    assert.deepEqual(buildKnownAssets({
      ...emptyDraft,
      selectedUseCase: "internal_it_environment",
      internalEndpointServices: [
        { service: first, target: "Server.Example.test.", port: "5900" },
        { service: second, target: "server.example.test", port: 5900 },
      ],
    }), {
      ok: false,
      error: {
        kind: "conflicting_scan_profile",
        target: "server.example.test:5900",
        internalEndpointIndex: 1,
      },
    });
  }
});

test("an added endpoint row requires an exact host and valid port", () => {
  assert.deepEqual(buildKnownAssets({
    ...emptyDraft,
    selectedUseCase: "internal_it_environment",
    internalEndpointServices: [{ target: "", port: "22" }],
  }), {
    ok: false,
    error: { kind: "internal_endpoint", error: "empty_target", value: undefined, index: 0 },
  });
  assert.deepEqual(buildKnownAssets({
    ...emptyDraft,
    selectedUseCase: "internal_it_environment",
    internalEndpointServices: [{ target: "server.example.test", port: "70000" }],
  }), {
    ok: false,
    error: { kind: "internal_endpoint", error: "invalid_port", value: "server.example.test", index: 0 },
  });
});

test("an internal device row requires HTTPS and never accepts credentials", () => {
  assert.deepEqual(buildKnownAssets({
    ...emptyDraft,
    selectedUseCase: "internal_it_environment",
    internalDeviceEndpoints: [{ url: "http://10.20.0.8" }],
  }), {
    ok: false,
    error: { kind: "internal_device", error: "https_required", value: "http://10.20.0.8" },
  });
  assert.deepEqual(buildKnownAssets({
    ...emptyDraft,
    selectedUseCase: "internal_it_environment",
    internalDeviceEndpoints: [{ url: "https://admin:secret@10.20.0.9:8080" }],
  }), {
    ok: false,
    error: {
      kind: "internal_device",
      error: "userinfo_not_allowed",
      value: "https://admin:secret@10.20.0.9:8080",
    },
  });
});

test("one HTTPS origin cannot silently receive incompatible website and device profiles", () => {
  assert.deepEqual(buildKnownAssets({
    ...emptyDraft,
    selectedUseCase: "internal_it_environment",
    websiteUrls: "https://10.20.0.8/admin",
    internalDeviceEndpoints: [{ url: "https://10.20.0.8" }],
  }), {
    ok: false,
    error: { kind: "conflicting_scan_profile", target: "https://10.20.0.8:443" },
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
