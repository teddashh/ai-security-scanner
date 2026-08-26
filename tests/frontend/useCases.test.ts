import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
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

const startPageSource = readFileSync(
  new URL("../../src/pages/StartPage.tsx", import.meta.url),
  "utf8",
);
const casesPageSource = readFileSync(
  new URL("../../src/pages/CasesPage.tsx", import.meta.url),
  "utf8",
);

test("the plain-language start page preserves every required assessment use case", () => {
  assert.deepEqual(useCaseDefinitions.map(({ id }) => id), requiredUseCases);
  assert.equal(new Set(useCaseDefinitions.map(({ id }) => id)).size, requiredUseCases.length);
});

test("both locales preserve optional preparation, behavior, and boundary details", () => {
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

test("the start page leads with outcomes and keeps technical guidance progressive", () => {
  assert.ok(startPageSource.includes('className="use-case-card__more"'));
  assert.ok(startPageSource.includes('className="start-page__more-use-cases"'));
  assert.ok(startPageSource.includes('className="start-page__scope-note"'));
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

test("case creation persists the chosen route and starts cloud setup with exactly one provider", () => {
  assert.ok(casesPageSource.includes("assessmentIntent: selectedUseCase"));
  assert.ok(casesPageSource.includes('selectedDefinition.id === "cloud_account"'));
  assert.ok(casesPageSource.includes('type="radio" name="cloud-platform"'));
  assert.ok(casesPageSource.includes("setPlatforms([platform])"));
});

test("guided local routes defer asset creation to the real local picker", () => {
  assert.ok(casesPageSource.includes("guidedLocalUseCase"));
  assert.ok(casesPageSource.includes("pageCopy.localPickerNextTitle"));
  assert.ok(casesPageSource.includes("pageCopy.localPickerBoundary"));
  assert.ok(casesPageSource.includes("!guidedLocalUseCase && ("));
});

test("guided public and internal target fields expose required field errors", () => {
  assert.ok(casesPageSource.includes("publicTargetsInputRef"));
  assert.ok(casesPageSource.includes("internalTargetsInputRef"));
  assert.ok(casesPageSource.includes('kind: "missing_target", target: "public"'));
  assert.ok(casesPageSource.includes('kind: "missing_target", target: "internal"'));
  assert.ok(casesPageSource.includes("pageCopy.publicTargetRequired"));
  assert.ok(casesPageSource.includes("pageCopy.internalTargetRequired"));
});

test("internal network detection stays an explicit bilingual suggestion", () => {
  for (const phrase of [
    "We found a likely local network",
    "找到一個可能的區域網路",
    "This computer is connected to more than one possible network, so we won't guess.",
    "這台電腦連到多個可能的網路，因此我們不會猜測",
    "Using it only fills the box below. It does not start the scan.",
    "使用它只會填入下方欄位，不會開始掃描",
  ]) assert.ok(casesPageSource.includes(phrase), phrase);
  assert.ok(casesPageSource.includes("scannerService.detectLocalPrivateSubnets()"));
  assert.ok(casesPageSource.includes("onClick={() => useDetectedLocalNetwork(detectedLocalNetwork.target)}"));
  assert.ok(casesPageSource.includes('status: "unavailable", candidates: []'));
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
