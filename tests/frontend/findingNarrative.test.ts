import assert from "node:assert/strict";
import test from "node:test";

import {
  ALL_CONFIDENCE_BASIS_CODES,
  ENGLISH_EXPOSURE_OBSERVATION_REASON,
  ENGLISH_ROLLBACK,
  findingActionSentence,
  findingConfidencePresentation,
  findingPriorityReason,
  findingRollbackSentence,
  findingSeverityIsUnrated,
  findingVerificationSentence,
  findingImpactSentence,
  findingSummarySentence,
  localizedExpertType,
} from "../../src/findingNarrative.ts";
import type {
  AwsIamPolicyFindingDetails,
  ConfidenceBasisCode,
  FindingFamily,
  SeverityBasisCode,
} from "../../src/types.ts";

const HAN = /\p{Script=Han}/u;
const LATIN_SENTENCE = /[A-Za-z]{4,}\s+[A-Za-z]{4,}/u;

const FAMILIES: FindingFamily[] = [
  "cloud_posture",
  "cloud_identity",
  "microsoft365",
  "network_exposure",
  "source_code",
  "secret",
  "infrastructure_as_code",
  "vulnerable_component",
  "kubernetes",
];

const BASES: SeverityBasisCode[] = [
  "open_port",
  "reachable_http_service",
  "secret_pattern_match",
  "unverified_credential_detector",
  "iac_policy_check",
  "cis_kubernetes_benchmark",
  "cloud_control_query",
  "cloudsplaining_iam_policy_finding",
  "unrated_vulnerability_test_alarm",
];

const ENGLISH_IMPACT =
  "If the scanner result is confirmed, a container or software component may expose the workload to a known weakness. The medium source severity is not a product-wide compliance score.";
const ENGLISH_ACTION =
  "Have the recommended specialist (Container security engineer) review the affected asset and the source rule's official guidance, then plan and approve an upgrade to a fixed version of the affected component, or a recorded reason it cannot be upgraded yet.";
const ENGLISH_SUMMARY =
  "Trivy reported a medium-severity condition on the assessed asset. The attached raw record is evidence, not an instruction.";

test("English findings use direct report-layer impact and action wording", () => {
  for (const family of FAMILIES) {
    const impact = findingImpactSentence("en", {
      englishFallback: ENGLISH_IMPACT,
      severityLabel: "Medium",
      family,
    });
    const action = findingActionSentence("en", {
      englishFallback: ENGLISH_ACTION,
      family,
    });
    assert.doesNotMatch(impact, /If the scanner result is confirmed|compliance score/u);
    assert.doesNotMatch(action, /Have the recommended specialist|plan and approve/u);
    assert.match(impact, /\.$/u);
    assert.match(action, /\.$/u);
  }
  assert.equal(
    findingSummarySentence("en", { englishFallback: ENGLISH_SUMMARY, severityLabel: "Medium" }),
    "Trivy reported a medium-severity condition on the assessed asset.",
  );
});

test("every family a finding can carry has Chinese for both sentences it composes", () => {
  // A family with no entry silently falls back to the English paragraph, which
  // is the exact defect this module exists to remove -- and it looks identical
  // to a legacy finding, so nothing else would flag it.
  const impacts = new Set<string>();
  const actions = new Set<string>();
  for (const family of FAMILIES) {
    const impact = findingImpactSentence("zh-TW", {
      englishFallback: ENGLISH_IMPACT,
      severityLabel: "中",
      family,
    });
    const action = findingActionSentence("zh-TW", {
      englishFallback: ENGLISH_ACTION,
      family,
    });
    assert.ok(HAN.test(impact), `${family} impact is not Chinese: ${impact}`);
    assert.ok(HAN.test(action), `${family} action is not Chinese: ${action}`);
    assert.ok(!LATIN_SENTENCE.test(impact), `${family} impact kept English prose: ${impact}`);
    impacts.add(impact);
    actions.add(action);
  }
  // Nine families, but source_code and secret deliberately share a consequence.
  assert.equal(impacts.size, FAMILIES.length - 1, [...impacts].join("\n"));
  assert.equal(actions.size, FAMILIES.length, [...actions].join("\n"));
});

test("a leaked credential is told to revoke first, not to adjust permissions", () => {
  // The whole reason `secret` splits from `source_code`: the key stays valid
  // until it is revoked, so anything else first leaves it valid that long.
  const action = findingActionSentence("zh-TW", {
    englishFallback: ENGLISH_ACTION,
    family: "secret",
  });
  assert.ok(action.includes("撤銷"), action);
  assert.ok(action.includes("輪替"), action);
  assert.doesNotMatch(action, /人工確認|專業人員|規劃並核准/u);
});

test("Cloudsplaining actions tell a Chinese reader how each upstream policy source can be changed", () => {
  const details = (
    policySource: AwsIamPolicyFindingDetails["policySource"],
    complete = true,
  ): AwsIamPolicyFindingDetails => ({
    policySource,
    policyName: "BillingReadPolicy",
    findingIdentity: "PrivilegeEscalation",
    actions: ["iam:PassRole"],
    actionsComplete: true,
    attachedTo: {
      roles: ["ApplicationRole"],
      groups: ["BillingOperators"],
      users: ["break-glass-user"],
      complete,
    },
  });

  const action = (awsIamPolicy: AwsIamPolicyFindingDetails) => findingActionSentence("zh-TW", {
    englishFallback: "ENGLISH_IAM_FALLBACK_MUST_NOT_RENDER",
    family: "cloud_identity",
    awsIamPolicy,
  });

  const awsManaged = action(details("aws_managed", false));
  assert.match(awsManaged, /^在角色 ApplicationRole、群組 BillingOperators、使用者 break-glass-user上/u);
  assert.match(awsManaged, /將 AWS 受管政策 BillingReadPolicy 改為權限較小的政策/u);
  assert.match(awsManaged, /AWS 受管政策無法由此帳戶直接編輯/u);
  assert.match(awsManaged, /請先核對目前的 IAM 附加關係/u);
  assert.doesNotMatch(awsManaged, /ENGLISH_IAM_FALLBACK/u);

  const unknownAttachments = details("aws_managed", false);
  unknownAttachments.attachedTo.roles = [];
  unknownAttachments.attachedTo.groups = [];
  unknownAttachments.attachedTo.users = [];
  const unknownAttachmentAction = action(unknownAttachments);
  assert.match(unknownAttachmentAction, /先確認目前有哪些角色、群組與使用者附加/u);
  assert.doesNotMatch(unknownAttachmentAction, /維持未附加狀態/u);

  const customerManaged = action(details("customer_managed"));
  assert.match(customerManaged, /縮小客戶受管政策 BillingReadPolicy 的權限/u);
  assert.match(customerManaged, /ApplicationRole/u);
  assert.doesNotMatch(customerManaged, /無法由此帳戶直接編輯|附加清單不完整/u);

  const inline = action(details("inline"));
  assert.match(inline, /直接在角色 ApplicationRole、群組 BillingOperators、使用者 break-glass-user上/u);
  assert.match(inline, /縮小內嵌政策 BillingReadPolicy 的權限/u);
  assert.doesNotMatch(inline, /AWS 受管政策無法由此帳戶直接編輯|附加清單不完整/u);
});

test("every severity basis this product can derive has Chinese", () => {
  const seen = new Set<string>();
  for (const severityBasisCode of BASES) {
    const summary = findingSummarySentence("zh-TW", {
      englishFallback: ENGLISH_SUMMARY,
      severityLabel: "高",
      severityBasisCode,
    });
    assert.ok(HAN.test(summary), `${severityBasisCode}: ${summary}`);
    assert.ok(summary.includes("未評定嚴重程度"), `${severityBasisCode} hid the derivation: ${summary}`);
    assert.ok(summary.startsWith("Trivy "), `${severityBasisCode} lost the engine name: ${summary}`);
    seen.add(summary);
  }
  assert.equal(seen.size, BASES.length);
});

test("every confidence basis has distinct Chinese prose and a visible product attribution", () => {
  // The labelled confidence field carries the basis. The risk summary used to
  // repeat it and no longer does, so distinctness is asserted where the reader
  // actually sees it.
  const seen = new Set<string>();
  for (const confidenceBasisCode of ALL_CONFIDENCE_BASIS_CODES) {
    const presentation = findingConfidencePresentation(
      "zh-TW",
      "高",
      confidenceBasisCode,
      [],
    );
    assert.ok(HAN.test(presentation), `${confidenceBasisCode}: ${presentation}`);
    assert.ok(presentation.includes("本產品依據"), presentation);
    assert.ok(presentation.startsWith("高"), presentation);
    seen.add(presentation);

    // The summary states what the scanner reported and stops there.
    const summary = findingSummarySentence("zh-TW", {
      englishFallback: ENGLISH_SUMMARY,
      severityLabel: "中",
      confidenceLabel: "高",
      confidenceBasisCode,
    });
    assert.ok(HAN.test(summary), `${confidenceBasisCode}: ${summary}`);
    assert.ok(!summary.includes("信心"), summary);
  }
  assert.equal(seen.size, ALL_CONFIDENCE_BASIS_CODES.length);
  assert.equal(ALL_CONFIDENCE_BASIS_CODES.length, 6);
});

test("engine confidence keeps its source word and legacy confidence stays unchanged", () => {
  const code: ConfidenceBasisCode | undefined = undefined;
  assert.equal(
    findingConfidencePresentation("zh-TW", "高", code, ["Source confidence: HIGH"]),
    "高 — 來源工具評定：HIGH",
  );
  assert.equal(findingConfidencePresentation("zh-TW", "高", code, []), "高");
});

test("only unknown findings without a scanner severity use the unrated presentation", () => {
  assert.equal(findingSeverityIsUnrated({ severity: "unknown" }), true);
  assert.equal(findingSeverityIsUnrated({
    severity: "unknown",
    severityBasisCode: "unverified_credential_detector",
    priorityReasons: ["Source severity: stale-value"],
  }), true);

  // An unfamiliar word is still a rating the scanner supplied. Preserve it
  // as unknown without claiming the scanner stayed silent.
  assert.equal(findingSeverityIsUnrated({
    severity: "unknown",
    priorityReasons: ["Source severity: IMPORTANT"],
  }), false);

  // Existing derived severities keep their established product attribution.
  for (const severity of ["high", "medium"] as const) {
    assert.equal(findingSeverityIsUnrated({
      severity,
      severityBasisCode: "unverified_credential_detector",
      priorityReasons: [],
    }), false);
  }
});

test("the engine's own display name survives verbatim", () => {
  // Lowercase and multi-word names are the engines' own spelling. Reading it
  // back off the English is what keeps it byte-identical.
  for (const engine of ["httpx", "kube-bench", "Greenbone Community Edition"]) {
    const summary = findingSummarySentence("zh-TW", {
      englishFallback: `${engine} reported a high-severity condition on the assessed asset. The attached raw record is evidence, not an instruction.`,
      severityLabel: "高",
    });
    assert.ok(summary.startsWith(`${engine} `), summary);
  }
});

test("a finding with no code keeps its substance and drops superseded defensive wording", () => {
  // Cases written before the codes existed, and any family a newer backend
  // adds. The stored substance remains even when no localized family exists.
  assert.equal(
    findingImpactSentence("zh-TW", { englishFallback: ENGLISH_IMPACT, severityLabel: "中" }),
    "A container or software component may expose the workload to a known weakness.",
  );
  assert.equal(
    findingActionSentence("zh-TW", {
      englishFallback: ENGLISH_ACTION,
    }),
    "An upgrade to a fixed version of the affected component, or a recorded reason it cannot be upgraded yet.",
  );
  assert.equal(
    findingImpactSentence("zh-TW", {
      englishFallback: ENGLISH_IMPACT,
      severityLabel: "中",
      family: "quantum_posture" as FindingFamily,
    }),
    "A container or software component may expose the workload to a known weakness.",
  );
  // A sentence this product did not write is not taken apart for a name.
  const foreign = "Some other text entirely.";
  assert.equal(
    findingSummarySentence("zh-TW", { englishFallback: foreign, severityLabel: "高" }),
    foreign,
  );
});

test("each recommended specialist is named, not sorted by whether their title contains 'it'", () => {
  // "security" and "vulnerability" both contain the substring "it", so a
  // substring rule sent Kubernetes, container, Microsoft 365 and vulnerability
  // findings all to the same "IT administrator".
  const experts = [
    "Cloud security engineer",
    "Cloud identity specialist",
    "Microsoft 365 security administrator",
    "Network security engineer",
    "Application security engineer",
    "Vulnerability manager",
    "Secrets-response specialist",
    "Infrastructure-as-code engineer",
    "Container security engineer",
    "Software supply-chain engineer",
    "Kubernetes security engineer",
  ];
  const translated = experts.map((expert) => localizedExpertType(expert, "zh-TW"));
  for (const [index, name] of translated.entries()) {
    assert.ok(HAN.test(name), `${experts[index]} is untranslated: ${name}`);
  }
  assert.equal(
    new Set(translated).size,
    experts.length,
    `distinct specialists collapsed together: ${translated.join(", ")}`,
  );
  assert.equal(localizedExpertType("Cloud security engineer", "en"), "Cloud security engineer");
  // An unknown title still says something, and says it generally.
  assert.ok(HAN.test(localizedExpertType("Quantum risk officer", "zh-TW")));
});

test("case context that raised the priority survives being said in Chinese", () => {
  // `apply_case_context` appends these sentences to the English impact and
  // raises the priority by up to ten points. Composing a fresh Chinese
  // sentence replaces the string they live in, so without putting them back
  // the zh-TW reader sees a finding promoted above the scanner's own rating
  // with the explanation removed -- while the English reader, on the same
  // finding, is told exactly why. Mirrors the Rust twin's test of the same
  // name; the parity test pins the wording, this pins the behaviour.
  const englishFallback = "If the scanner result is confirmed, something may happen.";
  const base = findingImpactSentence("zh-TW", {
    englishFallback,
    severityLabel: "高",
    family: "cloud_posture",
  });
  assert.ok(!base.includes("受影響的資產被標記"), base);

  for (const [factor, expected] of [
    ["internet_exposed_asset", "可從網際網路存取"],
    ["sensitive_data_asset", "含有敏感資料"],
  ] as const) {
    const composed = findingImpactSentence("zh-TW", {
      englishFallback,
      severityLabel: "高",
      family: "cloud_posture",
      contextFactors: [factor],
    });
    assert.ok(composed.includes(expected), `${factor} lost: ${composed}`);
    assert.ok(composed.startsWith(base), `${factor} rewrote the base sentence`);
  }

  // English uses the same direct composition as the exported report.
  assert.equal(
    findingImpactSentence("en", {
      englishFallback,
      severityLabel: "High",
      family: "cloud_posture",
      contextFactors: ["internet_exposed_asset"],
    }),
    "Cloud resources or data may be exposed, changed, or used beyond the organization's intent. The affected asset is internet-accessible, increasing the reachable attack surface.",
  );
});

test("the safety sentence is translated only when it is the one this product wrote", () => {
  const zh = findingRollbackSentence("zh-TW", ENGLISH_ROLLBACK);
  assert.ok(HAN.test(zh), zh);
  assert.ok(!LATIN_SENTENCE.test(zh), `left English behind: ${zh}`);
  // English keeps the canonical wording.
  assert.equal(findingRollbackSentence("en", ENGLISH_ROLLBACK), ENGLISH_ROLLBACK);
  // A sentence this product did not write is left exactly as found, rather
  // than being confidently replaced with wording that no longer describes it.
  const foreign = "Some other rollback advice from a build this one does not know.";
  assert.equal(findingRollbackSentence("zh-TW", foreign), foreign);
});

test("the verification sentence keeps the engine name and rule id verbatim", () => {
  const english =
    "After an approved manual change, rerun kube-bench with the same authorized scope and confirm that source rule 4.2.1 is no longer reported.";
  const zh = findingVerificationSentence("zh-TW", english);
  assert.ok(HAN.test(zh), zh);
  // Both are the engine's own strings and have to read identically either way.
  assert.ok(zh.includes("kube-bench"), zh);
  assert.ok(zh.includes("4.2.1"), zh);
  assert.equal(
    findingVerificationSentence("en", english),
    "Rerun kube-bench with the same scope after the change and confirm that source rule 4.2.1 is no longer reported.",
  );
  // Not this shape -> returned untouched rather than half-rewritten.
  const foreign = "Re-run the responsible engine.";
  assert.equal(findingVerificationSentence("zh-TW", foreign), foreign);
});

test("why this priority is said in Chinese, keeping the engine's own words", () => {
  const derived =
    "Severity derived from a secret pattern match in scanned source; Gitleaks reports no severity of its own.";
  const zh = findingPriorityReason("zh-TW", derived);
  assert.ok(HAN.test(zh), zh);
  assert.ok(!LATIN_SENTENCE.test(zh), `left English behind: ${zh}`);
  assert.ok(zh.includes("Gitleaks"), zh);

  // The engine's raw severity word stays verbatim: rendering "High" as 高 stops
  // it matching what the reader sees in the engine's own output.
  const raw = findingPriorityReason("zh-TW", "Source severity: High");
  assert.ok(HAN.test(raw), raw);
  assert.ok(raw.includes("High"), raw);

  const unrated = findingPriorityReason(
    "zh-TW",
    "Severity remains Unknown because Gitleaks did not assign one; human review is required.",
  );
  assert.equal(
    unrated,
    "嚴重程度為未知，因為 Gitleaks 未提供評級。",
  );

  assert.equal(findingPriorityReason("en", derived), derived);
  assert.equal(
    findingPriorityReason("zh-TW", ENGLISH_EXPOSURE_OBSERVATION_REASON),
    "這是可連線服務的盤點觀察，不是漏洞。",
  );
});

test("a priority reason this build cannot identify is left alone, not invented", () => {
  // A reason is the product's account of why it moved a finding up the list.
  // A confident Chinese sentence here would be a different account.
  const unknown = "Raised because the on-call rota flagged this asset last week.";
  assert.equal(findingPriorityReason("zh-TW", unknown), unknown);
  // Near-misses of the two parsed shapes fall back rather than half-translate.
  assert.equal(findingPriorityReason("zh-TW", "Source severity: "), "Source severity: ");
  assert.equal(
    findingPriorityReason("zh-TW", "Severity derived from something unheard of; X reports no severity of its own."),
    "Severity derived from something unheard of; X reports no severity of its own.",
  );
});

test("the control verdict survives being normalized twice", () => {
  // The report bakes the English verdict into the stored summary, and the
  // exporter then normalizes that stored summary again for the reader's
  // locale. The second pass sees its own output as input, so a Chinese reader
  // got the English sentence until the sentence could be read back.
  const adapter =
    "ScubaGear reported this control as failing. ScubaGear reported confidence High for it.";
  const stored = findingSummarySentence("en", {
    englishFallback: adapter,
    severityLabel: "High",
    family: "microsoft365",
  });
  assert.equal(
    stored,
    "ScubaGear checked this Microsoft 365 requirement and the tenant did not meet it.",
  );
  assert.equal(
    findingSummarySentence("en", {
      englishFallback: stored,
      severityLabel: "High",
      family: "microsoft365",
    }),
    stored,
    "a second English pass must not rewrite the sentence it just wrote",
  );

  const zh = findingSummarySentence("zh-TW", {
    englishFallback: stored,
    severityLabel: "高",
    family: "microsoft365",
  });
  assert.equal(zh, "ScubaGear 檢查了這項 Microsoft 365 要求，這個租戶未通過。");
  assert.equal(
    findingSummarySentence("zh-TW", {
      englishFallback: adapter,
      severityLabel: "高",
      family: "microsoft365",
    }),
    zh,
    "both passes must reach the same Chinese sentence",
  );
});

test("only Microsoft 365 findings get a control verdict", () => {
  const english = "Trivy reported this control as failing.";
  for (const family of [
    "cloudPosture",
    "cloudIdentity",
    "networkExposure",
    "sourceCode",
    "secret",
    "infrastructureAsCode",
    "vulnerableComponent",
    "kubernetes",
  ] as const) {
    const summary = findingSummarySentence("zh-TW", {
      englishFallback: english,
      severityLabel: "高",
      family,
    });
    assert.ok(
      !summary.includes("Microsoft 365 要求"),
      `${family} does not check a Microsoft 365 requirement: ${summary}`,
    );
  }
});
