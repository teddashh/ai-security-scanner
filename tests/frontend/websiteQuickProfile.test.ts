import assert from "node:assert/strict";
import test from "node:test";

import { websiteQuickOrigin, websiteQuickProfile } from "../../src/websiteQuickProfile.ts";

test("the public website quick profile is one exact pinned Nuclei contract", () => {
  assert.equal(
    websiteQuickProfile.templateRevision,
    "nuclei-templates@24858b4bfabfa86f0bcfd36aea24fb535152b012",
  );
  assert.deepEqual(websiteQuickProfile.engineIds, ["nuclei"]);
  assert.deepEqual(websiteQuickProfile.ratePolicy, {
    requestsPerSecond: 3,
    concurrency: 2,
    timeoutSeconds: 10,
  });
  assert.deepEqual(websiteQuickProfile.allowedTemplateIds, [
    "htpasswd-detection",
    "git-credentials-disclosure",
    "npmrc-authtoken",
    "configuration-listing",
    "ds-store-file",
    "webpack-sourcemap-disclosure",
    "cgi-printenv",
    "debug-vars",
    "prometheus-metrics",
    "apache-server-status",
    "django-debug-config-enabled",
    "springboot-configprops",
    "dockerfile-hidden-disclosure",
  ]);
  assert.equal(websiteQuickProfile.maximumGetRequests, 19);
});

test("the website boundary always names an explicit scheme, host, and port", () => {
  assert.equal(websiteQuickOrigin("portal.example.test", "https", 443), "https://portal.example.test:443");
  assert.equal(websiteQuickOrigin("2001:db8::10", "http", 8080), "http://[2001:db8::10]:8080");
});
