import assert from "node:assert/strict";
import test from "node:test";

import {
  findingActionSentence,
  findingImpactSentence,
  findingSummarySentence,
  localizedExpertType,
} from "../../src/findingNarrative.ts";
import type { FindingFamily, SeverityBasisCode } from "../../src/types.ts";

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
];

const ENGLISH_IMPACT =
  "If the scanner result is confirmed, a container or software component may expose the workload to a known weakness. The medium source severity is not a product-wide compliance score.";
const ENGLISH_ACTION =
  "Have the recommended specialist (Container security engineer) review the affected asset and the source rule's official guidance, then plan and approve an upgrade to a fixed version of the affected component, or a recorded reason it cannot be upgraded yet.";
const ENGLISH_SUMMARY =
  "Trivy reported a medium-severity condition on the assessed asset. The attached raw record is evidence, not an instruction.";

test("English is the backend's own prose, returned untouched", () => {
  // Re-deriving it here would let the rendered wording and the exported
  // wording drift apart with nothing to notice.
  for (const family of FAMILIES) {
    assert.equal(
      findingImpactSentence("en", { englishFallback: ENGLISH_IMPACT, severityLabel: "Medium", family }),
      ENGLISH_IMPACT,
    );
    assert.equal(
      findingActionSentence("en", {
        englishFallback: ENGLISH_ACTION,
        expertType: "Container security engineer",
        family,
      }),
      ENGLISH_ACTION,
    );
  }
  assert.equal(
    findingSummarySentence("en", { englishFallback: ENGLISH_SUMMARY, severityLabel: "Medium" }),
    ENGLISH_SUMMARY,
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
      expertType: "Container security engineer",
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
    expertType: "Secrets-response specialist",
    family: "secret",
  });
  assert.ok(action.includes("撤銷"), action);
  assert.ok(action.includes("輪替"), action);
  assert.ok(action.includes("機密外洩應變專家"), action);
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

test("a finding with no code keeps the English rather than losing the sentence", () => {
  // Cases written before the codes existed, and any family a newer backend
  // adds. Untranslated beats blank, and beats a guess.
  assert.equal(
    findingImpactSentence("zh-TW", { englishFallback: ENGLISH_IMPACT, severityLabel: "中" }),
    ENGLISH_IMPACT,
  );
  assert.equal(
    findingActionSentence("zh-TW", {
      englishFallback: ENGLISH_ACTION,
      expertType: "Container security engineer",
    }),
    ENGLISH_ACTION,
  );
  assert.equal(
    findingImpactSentence("zh-TW", {
      englishFallback: ENGLISH_IMPACT,
      severityLabel: "中",
      family: "quantum_posture" as FindingFamily,
    }),
    ENGLISH_IMPACT,
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

  // English stays the backend's own prose, appendices and all.
  assert.equal(
    findingImpactSentence("en", {
      englishFallback,
      severityLabel: "High",
      family: "cloud_posture",
      contextFactors: ["internet_exposed_asset"],
    }),
    englishFallback,
  );
});
