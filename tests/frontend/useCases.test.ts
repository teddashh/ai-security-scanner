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
  "ai_application",
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

test("company or team details are optional and never block scan-project creation", () => {
  assert.ok(casesPageSource.includes('Company or team name (optional)'));
  assert.ok(casesPageSource.includes('公司或團隊名稱（選填）'));
  assert.doesNotMatch(casesPageSource, /!organizationName\.trim\(\)/u);
  const fieldStart = casesPageSource.indexOf("<span>{text(pageCopy.organizationName)}</span>");
  const fieldEnd = casesPageSource.indexOf("</label>", fieldStart);
  const field = casesPageSource.slice(fieldStart, fieldEnd);
  assert.match(field, /<input value=\{organizationName\}/u);
  assert.match(field, /pageCopy\.organizationPlaceholder/u);
  assert.doesNotMatch(field, /\brequired\b/u);
});

test("AI-application onboarding is explicit, local, and does not ask users to hide secrets", () => {
  const aiEnglish = startPageCopy.en.cards.ai_application;
  const aiTraditionalChinese = startPageCopy["zh-TW"].cards.ai_application;
  const english = startPageCopy.en.cards.source_code;
  const traditionalChinese = startPageCopy["zh-TW"].cards.source_code;

  assert.equal(aiEnglish.title, "An AI app or agent you are building");
  assert.equal(aiTraditionalChinese.title, "正在開發的 AI 應用或 Agent");
  assert.equal(english.title, "Source code you have written");
  assert.equal(traditionalChinese.title, "自己寫的程式碼");
  assert.match(english.productDoes, /this device/u);
  assert.match(english.productDoes, /masks detected secret values/u);
  assert.match(english.productDoes, /never changes project files/u);
  assert.match(traditionalChinese.productDoes, /這台裝置/u);
  assert.match(traditionalChinese.productDoes, /遮罩找到的秘密值/u);
  assert.match(traditionalChinese.productDoes, /不會修改專案檔案/u);
  assert.doesNotMatch(english.prepare, /remove|exclude.*secrets?/iu);
  assert.doesNotMatch(traditionalChinese.prepare, /移除|排除.*秘密/u);
  assert.match(aiEnglish.productDoes, /AIDEFEND/u);
  assert.match(aiTraditionalChinese.productDoes, /AIDEFEND/u);
  assert.match(aiEnglish.productDoesNot, /does not upload or change project files/u);
  assert.match(aiTraditionalChinese.productDoesNot, /不會上傳或修改專案檔案/u);

  assert.ok(startPageSource.includes("Check an AI project"));
  assert.ok(startPageSource.includes("檢查 AI 專案"));
  assert.doesNotMatch(startPageSource, /committed secrets|不小心放進程式碼的秘密/u);
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

test("code onboarding asks one plain-language bilingual AI-origin question and saves all three answers", () => {
  for (const phrase of [
    "Did AI generate or substantially change any code in this project?",
    "這個專案有程式碼是由 AI 產生，或經 AI 大幅修改嗎？",
    "Yes, AI wrote or changed some of it",
    "有，AI 寫過或大幅修改過",
    "No, it was mostly written by people",
    "沒有，主要是人寫的",
    "I'm not sure",
    "我不確定",
  ]) assert.ok(casesPageSource.includes(phrase), phrase);

  assert.ok(casesPageSource.includes("useState<AiGeneratedArtifactAnswer>"));
  assert.ok(casesPageSource.includes('setAiGeneratedArtifact("unknown")'));
  assert.ok(casesPageSource.includes("aiGeneratedArtifact,"));
  assert.ok(casesPageSource.includes('name="ai-generated-artifact"'));
  assert.match(casesPageSource, /\{primaryTarget\}[\s\S]+\{platforms\.includes\("code"\) && \(/u);
  assert.ok(casesPageSource.includes(
    'aiGeneratedArtifact: platforms.includes("code") ? aiGeneratedArtifact : "unknown"',
  ));
  assert.ok(casesPageSource.includes(
    'platform === "code" && platforms.includes("code")',
  ));
  assert.doesNotMatch(casesPageSource, /aiGeneratedQuestionUseCaseIds/u);
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
  for (const id of ["ai_application", "source_code", "container_image"] as const) {
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
        "ai_application",
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
      ai_application: "repository",
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
