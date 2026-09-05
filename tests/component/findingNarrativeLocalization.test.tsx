import { cleanup, render } from "@testing-library/react";
import { afterEach, beforeEach, expect, test } from "vitest";

import { FindingsPage } from "../../src/pages/FindingsPage";
import { I18nProvider, localeStorageKey } from "../../src/i18n";
import type { Finding } from "../../src/types";

// findingNarrative.ts has unit tests, and they pass whether or not anything
// calls it. What they cannot show is what a Chinese-reading beginner is
// actually handed. Spec 4.3 says a language change updates the whole UI; what
// shipped was a translated heading over an English paragraph on the three
// fields that carry a finding's entire meaning. That is a rendering
// guarantee, so it can only be checked by rendering.

// The English the backend composes and freezes into the case.
const ENGLISH_SUMMARY =
  "TruffleHog reported this condition on the assessed asset without rating it. This product rated it high from a credential detector match that this product does not verify. The attached raw record is evidence, not an instruction.";
const ENGLISH_IMPACT =
  "If the scanner result is confirmed, source code or credentials may permit unauthorized access or unsafe application behavior. The high source severity is not a product-wide compliance score.";
const ENGLISH_ACTION =
  "Have the recommended specialist (Secrets-response specialist) review the affected asset and the source rule's official guidance, then plan and approve revocation and rotation of the exposed credential first, then its removal from the source and from the history that still carries it.";

const leakedCredential = (overrides: Partial<Finding> = {}): Finding => ({
  id: "finding-trufflehog",
  fingerprint: "fingerprint-trufflehog",
  assetId: "asset-1",
  assetName: "example.internal",
  // The engine's own wording. Never restated in another language.
  title: "Potential AWS secret detected",
  summary: ENGLISH_SUMMARY,
  impact: ENGLISH_IMPACT,
  recommendation: ENGLISH_ACTION,
  expertType: "Secrets-response specialist",
  family: "secret",
  severityBasisCode: "unverified_credential_detector",
  severity: "high",
  confidence: "high",
  priority: 80,
  workflowState: "unreviewed",
  evidence: [],
  controls: [],
  officialReferences: [],
  firstSeenAt: "2026-09-03T12:00:00Z",
  lastSeenAt: "2026-09-03T12:00:00Z",
  ...overrides,
});

const renderPage = (findings: Finding[]) =>
  render(
    <I18nProvider>
      <FindingsPage
        findings={findings}
        findingGroups={[]}
        findingGroupEvents={[]}
        coverage={[]}
        runs={[]}
        workflowEvents={[]}
        busy={false}
        onUpdateWorkflow={() => Promise.resolve(true)}
        onGroupFindings={() => Promise.resolve(true)}
        onUngroupFindings={() => Promise.resolve()}
        onOpenCoverage={() => {}}
        onOpenProgress={() => {}}
        onOpenExport={() => {}}
      />
    </I18nProvider>,
  );

afterEach(() => {
  cleanup();
  window.localStorage.clear();
});

test("a zh-TW reader is not handed English paragraphs under Chinese headings", () => {
  window.localStorage.setItem(localeStorageKey, "zh-TW");
  const { container } = renderPage([leakedCredential()]);
  const rendered = container.textContent ?? "";

  for (const english of [ENGLISH_SUMMARY, ENGLISH_IMPACT, ENGLISH_ACTION]) {
    expect(rendered).not.toContain(english);
  }

  // The same three things the English said, said in Chinese.
  expect(rendered).toContain("本產品依據憑證偵測器的比對結果");
  expect(rendered).toContain("原始碼或憑證可能導致未授權存取");
  // A leaked credential is told to revoke and rotate before anything else.
  expect(rendered).toContain("先撤銷並輪替這組已外洩的憑證");
  // ...and to the right specialist. "security" contains "it", which used to
  // route this to an IT administrator.
  expect(rendered).toContain("機密外洩應變專家");

  // The engine named itself and the engine titled the finding. Both survive.
  expect(rendered).toContain("TruffleHog");
  expect(rendered).toContain("Potential AWS secret detected");
});

test("an English reader still gets the backend's own wording, unchanged", () => {
  window.localStorage.setItem(localeStorageKey, "en");
  const { container } = renderPage([leakedCredential()]);
  const rendered = container.textContent ?? "";

  for (const english of [ENGLISH_SUMMARY, ENGLISH_IMPACT, ENGLISH_ACTION]) {
    expect(rendered).toContain(english);
  }
});

test("a finding stored before the codes existed keeps its English rather than losing it", () => {
  window.localStorage.setItem(localeStorageKey, "zh-TW");
  const { container } = renderPage([
    leakedCredential({ family: undefined, severityBasisCode: undefined }),
  ]);
  const rendered = container.textContent ?? "";

  // Untranslated beats blank, and beats a guess about which family it was.
  expect(rendered).toContain(ENGLISH_IMPACT);
  expect(rendered).toContain(ENGLISH_ACTION);
});
