import { cleanup, fireEvent, render } from "@testing-library/react";
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
  "TruffleHog reported this condition on the assessed asset without rating it. This product rated it high from a credential detector match that this product does not verify. TruffleHog reported no confidence rating for it. This product rated its confidence low from an unverified pattern or detector match. The attached raw record is evidence, not an instruction.";
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
  confidenceBasisCode: "unverified_pattern_or_detector_match",
  severity: "high",
  confidence: "low",
  priority: 80,
  priorityReasons: [
    "Confidence derived from an unverified pattern or detector match; TruffleHog reports no confidence of its own.",
  ],
  workflowState: "unreviewed",
  evidence: [],
  controls: [],
  officialReferences: [],
  firstSeenAt: "2026-09-03T12:00:00Z",
  lastSeenAt: "2026-09-03T12:00:00Z",
  ...overrides,
});

const renderPage = (findings: Finding[]) => {
  const result = render(
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
  const firstFinding = result.container.querySelector<HTMLButtonElement>(".finding-row");
  if (firstFinding) fireEvent.click(firstFinding);
  return result;
};

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
  expect(rendered).toContain("本產品依據尚未驗證的樣式或偵測器比對結果，將信心評為低");
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

test("a zh-TW reader sees the engine's own confidence word as the source", () => {
  window.localStorage.setItem(localeStorageKey, "zh-TW");
  const { container } = renderPage([
    leakedCredential({
      id: "finding-semgrep",
      title: "A subprocess launched through a shell can allow command injection.",
      summary:
        "Semgrep reported a high-severity condition on the assessed asset. Semgrep reported confidence HIGH for it; this product maps that to high confidence. The attached raw record is evidence, not an instruction.",
      severityBasisCode: undefined,
      confidenceBasisCode: undefined,
      priorityReasons: ["Source confidence: HIGH"],
    }),
  ]);
  const rendered = container.textContent ?? "";

  expect(rendered).toContain("Semgrep 對這項問題的信心評定為 HIGH");
  expect(rendered).toContain("來源工具評定：HIGH");
  expect(rendered).not.toContain("本產品依據尚未驗證的樣式或偵測器比對結果評定");
});

test("a finding stored before the codes existed keeps its English rather than losing it", () => {
  window.localStorage.setItem(localeStorageKey, "zh-TW");
  const { container } = renderPage([
    leakedCredential({
      family: undefined,
      severityBasisCode: undefined,
      confidenceBasisCode: undefined,
      priorityReasons: [],
    }),
  ]);
  const rendered = container.textContent ?? "";

  // Untranslated beats blank, and beats a guess about which family it was.
  expect(rendered).toContain(ENGLISH_IMPACT);
  expect(rendered).toContain(ENGLISH_ACTION);
  expect(rendered).not.toContain("本產品依據尚未驗證的樣式或偵測器比對結果");
});

// The list is the surface a beginner reads first. Priority is a pure function
// of severity here, so confidence now breaks ties before finding id. The row
// still needs to name its engine and disclose product-derived ratings because
// ordering alone does not explain who made either judgment.
const scoredVulnerability = (): Finding => ({
  ...leakedCredential(),
  id: "finding-nuclei",
  fingerprint: "fingerprint-nuclei",
  title: "Exposed administration panel",
  summary: "Nuclei reported a high-severity condition on the assessed asset.",
  // The engine rated this one itself, so there is no basis code.
  severityBasisCode: undefined,
  family: "network_exposure",
});

test("a row names the engine that found it and says when the rating is this product's", () => {
  window.localStorage.setItem(localeStorageKey, "en");
  const { container } = renderPage([leakedCredential(), scoredVulnerability()]);

  const rows = [...container.querySelectorAll(".finding-row")];
  expect(rows).toHaveLength(2);

  const rowFor = (title: string) => {
    const row = rows.find((candidate) => candidate.textContent?.includes(title));
    if (!row) throw new Error(`no row for ${title}`);
    return row.textContent ?? "";
  };

  const derived = rowFor("Potential AWS secret detected");
  const scored = rowFor("Exposed administration panel");

  // Each row names its own engine, and not the other's.
  expect(derived).toContain("TruffleHog");
  expect(derived).not.toContain("Nuclei");
  expect(scored).toContain("Nuclei");
  expect(scored).not.toContain("TruffleHog");

  // Only the product-derived rating is marked as such. Marking both, or
  // neither, would leave the two claims indistinguishable again.
  expect(derived).toContain("rated here");
  expect(scored).not.toContain("rated here");
});

test("the row's rating caveat is not left in English for a zh-TW reader", () => {
  window.localStorage.setItem(localeStorageKey, "zh-TW");
  const { container } = renderPage([leakedCredential()]);
  const row = container.querySelector(".finding-row")?.textContent ?? "";

  expect(row).toContain("本產品評定");
  expect(row).not.toContain("rated here");
  // The engine's own name is its wording, and survives in either language.
  expect(row).toContain("TruffleHog");
});

// The two sentences the drawer has shown since it existed. They are the only
// place the app says "keep a way back" and "here is how you know it worked",
// and both were still English under a Chinese heading.
const ENGLISH_ROLLBACK_TEXT =
  "Before any manual change, preserve the current approved configuration and document a tested restoration path; this product does not execute remediation.";
const ENGLISH_VERIFICATION =
  "After an approved manual change, rerun TruffleHog with the same authorized scope and confirm that source rule aws-access-key is no longer reported.";

test("the safety and verification advice is not left in English for a zh-TW reader", () => {
  window.localStorage.setItem(localeStorageKey, "zh-TW");
  const { container } = renderPage([
    leakedCredential({
      rollbackConsiderations: ENGLISH_ROLLBACK_TEXT,
      verificationGuidance: ENGLISH_VERIFICATION,
    }),
  ]);
  const rendered = container.textContent ?? "";

  expect(rendered).not.toContain(ENGLISH_ROLLBACK_TEXT);
  expect(rendered).not.toContain(ENGLISH_VERIFICATION);
  expect(rendered).toContain("本產品不會代為執行修復");
  expect(rendered).toContain("並確認來源規則 aws-access-key 不再被回報");
  // The engine name and the rule id are the engine's own strings and read the
  // same either way. Restating them in Chinese would make the reader hunt for
  // something that does not exist in the tool they are told to re-run.
  expect(rendered).toContain("TruffleHog");
});

test("a finding whose safety sentence this build does not recognise keeps it rather than blanking it", () => {
  window.localStorage.setItem(localeStorageKey, "zh-TW");
  // Frozen by an older build with different wording. Untranslated is worse
  // than translated and much better than silently dropped, because this is
  // the sentence telling the reader to keep a way back.
  const stale = "Preserve the working config before touching anything.";
  const { container } = renderPage([leakedCredential({ rollbackConsiderations: stale })]);

  expect(container.textContent ?? "").toContain(stale);
});

test("why this priority is not a Chinese heading over an English list", () => {
  window.localStorage.setItem(localeStorageKey, "zh-TW");
  const derived =
    "Severity derived from a credential detector match that this product does not verify; TruffleHog reports no severity of its own.";
  const evidence = "Direct scanner evidence is attached and still requires human review.";
  const { container } = renderPage([
    leakedCredential({ priorityReasons: [derived, evidence] }),
  ]);
  const rendered = container.textContent ?? "";

  expect(rendered).not.toContain(derived);
  expect(rendered).not.toContain(evidence);
  expect(rendered).toContain("嚴重程度是由憑證偵測器的比對結果");
  expect(rendered).toContain("已附上掃描工具的直接證據");
  expect(rendered).toContain("TruffleHog");
});

test("a zh-TW reader sees a control-mapping rationale in their language", () => {
  window.localStorage.setItem(localeStorageKey, "zh-TW");
  const english =
    "Evidence that an identity has no registered multi-factor device is related to authenticating users and safeguarding authentication information.";
  const { container } = renderPage([
    leakedCredential({
      controls: [{
        framework: "NIST CSF",
        version: "2.0",
        controlId: "PR.AA-03",
        relationship: "related",
        title: "Authentication of users, services, and hardware",
        rationale: english,
      }],
    }),
  ]);
  const rendered = container.textContent ?? "";

  expect(rendered).toContain("某個身分未登記多重要素驗證裝置的證據，與驗證使用者及保護驗證資訊有關。");
  expect(rendered).not.toContain(english);
  // The framework's official control name stays searchable verbatim.
  expect(rendered).toContain("Authentication of users, services, and hardware");
});
