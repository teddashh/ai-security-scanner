import assert from "node:assert/strict";
import test from "node:test";

import {
  startPageCopy,
  useCaseById,
  useCaseDefinitions,
  type UseCaseId,
} from "../../src/useCases.ts";
import { prepareDeployedWebsiteTarget } from "../../src/caseForm.ts";

const requiredUseCases = [
  "deployed_website",
  "external_ip_or_domain",
  "internal_it_environment",
  "source_code",
  "infrastructure_as_code",
  "cloud_account",
  "container_image",
  "kubernetes",
] satisfies UseCaseId[];

test("the plain-language start page preserves every required assessment use case", () => {
  assert.deepEqual(useCaseDefinitions.map(({ id }) => id), requiredUseCases);
  assert.equal(new Set(useCaseDefinitions.map(({ id }) => id)).size, requiredUseCases.length);
});

test("both locales explain preparation, product behavior, and boundaries", () => {
  for (const locale of ["en", "zh-TW"] as const) {
    const copy = startPageCopy[locale];
    for (const id of requiredUseCases) {
      const card = copy.cards[id];
      assert.ok(card.title.trim(), `${locale}.${id}.title`);
      assert.ok(card.summary.trim(), `${locale}.${id}.summary`);
      assert.ok(card.want.trim(), `${locale}.${id}.want`);
      assert.ok(card.prepare.trim(), `${locale}.${id}.prepare`);
      assert.ok(card.productDoes.trim(), `${locale}.${id}.productDoes`);
      assert.ok(card.productDoesNot.trim(), `${locale}.${id}.productDoesNot`);
    }
  }
});

test("cloud onboarding names every released provider path", () => {
  assert.deepEqual(useCaseById("cloud_account").supportedProviders, [
    "aws",
    "azure",
    "gcp",
    "microsoft365",
  ]);
  assert.deepEqual(useCaseById("cloud_account").suggestedPlatforms, [
    "aws",
    "azure",
    "gcp",
    "m365",
  ]);
});

test("local artifacts never inherit an external-contact activity", () => {
  for (const id of ["source_code", "container_image"] as const) {
    assert.deepEqual(useCaseById(id).suggestedActivities, ["local_artifact_analysis"]);
  }
});

test("external presets begin with low-impact checks while keeping active testing available elsewhere", () => {
  for (const id of [
    "deployed_website",
    "external_ip_or_domain",
    "internal_it_environment",
  ] as const) {
    assert.deepEqual(useCaseById(id).suggestedActivities, ["low_impact_external_checks"]);
  }
});

test("each artifact scenario maps to the existing case questionnaire coordinate", () => {
  assert.deepEqual(
    Object.fromEntries(
      ([
        "deployed_website",
        "external_ip_or_domain",
        "internal_it_environment",
        "source_code",
        "infrastructure_as_code",
        "container_image",
        "kubernetes",
      ] as const).map((id) => [id, useCaseById(id).knownAssetKind]),
    ),
    {
      deployed_website: "external_target",
      external_ip_or_domain: "external_target",
      internal_it_environment: "external_target",
      source_code: "repository",
      infrastructure_as_code: "iac_project",
      container_image: "container_image",
      kubernetes: "kubernetes_cluster",
    },
  );
  assert.equal(useCaseById("deployed_website").internetExposure, "public");
  assert.equal(useCaseById("internal_it_environment").internetExposure, "internal");
});

test("deployed website URLs become exact backend target coordinates without losing service context", () => {
  assert.deepEqual(prepareDeployedWebsiteTarget(" https://Portal.Example.test:8443/login?next=%2F "), {
    ok: true,
    value: {
      target: "portal.example.test",
      service: {
        protocol: "https",
        port: 8_443,
        path: "/login",
        queryWasRemoved: true,
      },
    },
  });
  assert.deepEqual(prepareDeployedWebsiteTarget("http://[2001:db8::1]/health"), {
    ok: true,
    value: {
      target: "2001:db8::1",
      service: {
        protocol: "http",
        port: 80,
        path: "/health",
        queryWasRemoved: false,
      },
    },
  });
});

test("deployed website parsing rejects credentials, non-web protocols, and ambiguous host input", () => {
  assert.deepEqual(prepareDeployedWebsiteTarget("https://admin:secret@example.test"), {
    ok: false,
    error: "userinfo_not_allowed",
  });
  assert.deepEqual(prepareDeployedWebsiteTarget("ftp://example.test/archive"), {
    ok: false,
    error: "unsupported_protocol",
  });
  assert.deepEqual(prepareDeployedWebsiteTarget("example.test"), {
    ok: false,
    error: "invalid_url",
  });
});
