import assert from "node:assert/strict";
import test from "node:test";

import {
  INTERNAL_HOST_DEFAULT_PORTS,
  internalHostGreenboneProfile,
  parseInternalHostPorts,
  prepareInternalHostTarget,
} from "../../src/internalHostProfile.ts";

test("internal host profile pins one generic Greenbone remote-safe boundary", () => {
  assert.equal(internalHostGreenboneProfile.scanProfile, "internal_host_greenbone_remote_safe");
  assert.equal(internalHostGreenboneProfile.profileId, "greenbone_remote_safe_v1");
  assert.match(internalHostGreenboneProfile.templateRevision, /^greenbone-community-feed@[0-9a-f]{40}$/u);
  assert.deepEqual(internalHostGreenboneProfile.allowedTemplateIds, []);
  assert.deepEqual(internalHostGreenboneProfile.defaultPorts, [22, 23, 25, 80, 443, 445, 3389, 5900, 8080, 8443]);
  assert.deepEqual(internalHostGreenboneProfile.ratePolicy, {
    requestsPerSecond: 2,
    concurrency: 1,
    timeoutSeconds: 15,
  });
});

test("internal host input accepts and canonicalizes one exact hostname or IP without contact", () => {
  assert.deepEqual(prepareInternalHostTarget(" Server.Example.Internal. "), {
    ok: true,
    value: "server.example.internal",
  });
  assert.deepEqual(prepareInternalHostTarget("10.20.0.8"), { ok: true, value: "10.20.0.8" });
  assert.deepEqual(prepareInternalHostTarget("2001:0db8::1"), { ok: true, value: "2001:db8::1" });
});

test("internal host input rejects URLs, credentials, CIDR ranges, and service coordinates", () => {
  assert.deepEqual(prepareInternalHostTarget(""), { ok: false, error: "empty_target" });
  assert.deepEqual(prepareInternalHostTarget("https://10.20.0.8"), { ok: false, error: "url_not_allowed" });
  assert.deepEqual(prepareInternalHostTarget("admin@example.internal"), { ok: false, error: "credentials_not_allowed" });
  assert.deepEqual(prepareInternalHostTarget("10.20.0.0/24"), { ok: false, error: "cidr_not_allowed" });
  assert.deepEqual(prepareInternalHostTarget("localhost"), { ok: false, error: "invalid_target" });
  assert.deepEqual(prepareInternalHostTarget("server.example.internal:443"), {
    ok: false,
    error: "service_coordinate_not_allowed",
  });
});

test("internal host ports use defaults or normalize up to 64 comma-separated ports", () => {
  assert.deepEqual(parseInternalHostPorts(""), { ok: true, value: [...INTERNAL_HOST_DEFAULT_PORTS] });
  assert.deepEqual(parseInternalHostPorts("8443, 22,443,22"), { ok: true, value: [22, 443, 8443] });
  assert.deepEqual(parseInternalHostPorts("22 443"), { ok: false, error: "invalid_ports" });
  assert.deepEqual(parseInternalHostPorts("0,443"), { ok: false, error: "invalid_ports" });
  assert.deepEqual(parseInternalHostPorts("65536"), { ok: false, error: "port_out_of_range" });
  assert.deepEqual(parseInternalHostPorts(Array.from({ length: 65 }, (_, index) => index + 1).join(",")), {
    ok: false,
    error: "too_many_ports",
  });
});
