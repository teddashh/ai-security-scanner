import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import test from "node:test";

import {
  controlMappingRationaleZhHant,
  localizedControlMappingRationale,
} from "../../src/findingNarrative.ts";

interface MappingCatalog {
  entries: Array<{
    engine_id: string;
    match_kind: string;
    source_rule: string;
    rationale: string;
  }>;
  cwe_derived_controls: Array<{ control: string; rationale: string }>;
}

const catalog = JSON.parse(readFileSync(
  new URL("../../mappings/control-mappings.json", import.meta.url),
  "utf8",
)) as MappingCatalog;

test("every reviewed catalog rationale has a Traditional Chinese presentation", () => {
  const coordinates = catalog.entries
    .map(({ engine_id, match_kind, source_rule }) => `${engine_id}|${match_kind}|${source_rule}`)
    .sort();
  assert.deepEqual(coordinates, [
    "checkov|exact|CKV_AWS_18",
    "cloudsplaining|exact|CredentialsExposure",
    "cloudsplaining|exact|DataExfiltration",
    "cloudsplaining|exact|InfrastructureModification",
    "cloudsplaining|exact|PrivilegeEscalation",
    "cloudsplaining|exact|ResourceExposure",
    "cloudsplaining|exact|ServiceWildcard",
    "garak|prefix|ansiescape.",
    "garak|prefix|dan.",
    "garak|prefix|divergence.Repeat/",
    "garak|prefix|encoding.",
    "garak|prefix|latentinjection.",
    "garak|prefix|leakreplay.",
    "garak|prefix|misleading.",
    "garak|prefix|packagehallucination.",
    "garak|prefix|snowball.",
    "garak|prefix|sysprompt_extraction.",
    "garak|prefix|web_injection.",
    "gitleaks|exact|generic-api-key",
    "greenbone|prefix|1.3.6.1.4.1.25623.",
    "greenbone|prefix|CVE-",
    "grype|prefix|CVE-",
    "kics|exact|5fb49a69-8d46-4495-a2f8-9c8c622b2b6e",
    "kube-bench|exact|4.1.1",
    "kube-bench|exact|4.1.10",
    "kube-bench|exact|4.1.9",
    "kube-bench|exact|4.2.1",
    "kube-bench|exact|4.2.10",
    "kube-bench|exact|4.3.1",
    "kubescape|exact|C-0002",
    "kubescape|exact|C-0009",
    "kubescape|exact|C-0017",
    "maester|exact|MT.1001",
    "mcp-armor|exact|excessive_tool_permissions",
    "mcp-armor|exact|hardcoded_secrets",
    "nuclei|exact|phpmyadmin-panel",
    "prowler|exact|iam_customer_attached_policy_no_administrative_privileges",
    "scoutsuite|exact|iam-ec2-role-without-instances",
    "scoutsuite|exact|iam-password-policy-no-uppercase-required",
    "scoutsuite|exact|s3-bucket-world-policy-star",
    "scubagear|exact|MS.AAD.1.1v1",
    "semgrep|exact|ai-security-scanner.generic.private-key",
    "semgrep|exact|ai-security-scanner.javascript.child-process-exec",
    "semgrep|exact|ai-security-scanner.python.dynamic-code-execution",
    "semgrep|exact|ai-security-scanner.python.shell-true",
    "trivy|prefix|CVE-",
    "trufflehog|prefix|trufflehog:",
  ]);
  for (const { rationale } of catalog.entries) {
    const translated = controlMappingRationaleZhHant(rationale);
    assert.ok(translated, `no Traditional Chinese for catalog rationale: ${rationale}`);
    assert.match(translated, /\p{Script=Han}/u);
    assert.equal(localizedControlMappingRationale(rationale, "en"), rationale);
  }
});

test("every CWE-derived category rationale has a Traditional Chinese presentation", () => {
  const controls = catalog.cwe_derived_controls.map(({ control }) => control).sort();
  assert.deepEqual(controls, [
    "owasp-2021-a01",
    "owasp-2021-a02",
    "owasp-2021-a03",
    "owasp-2021-a04",
    "owasp-2021-a05",
    "owasp-2021-a06",
    "owasp-2021-a07",
    "owasp-2021-a08",
    "owasp-2021-a09",
    "owasp-2021-a10",
  ]);
  for (const { rationale } of catalog.cwe_derived_controls) {
    const translated = controlMappingRationaleZhHant(rationale);
    assert.ok(translated, `no Traditional Chinese for catalog rationale: ${rationale}`);
    assert.match(translated, /\p{Script=Han}/u);
    const code = rationale.match(/A\d\d:2021/u)?.[0];
    assert.ok(code, `no category code in rationale: ${rationale}`);
    assert.ok(
      translated.includes(code),
      `translation missing category code ${code}: ${translated}`,
    );
    assert.equal(localizedControlMappingRationale(rationale, "zh-TW"), translated);
    assert.equal(localizedControlMappingRationale(rationale, "en"), rationale);
  }
});

test("a rationale from another build stays in its stored language", () => {
  const future = "A rationale from another build.";
  assert.equal(controlMappingRationaleZhHant(future), undefined);
  assert.equal(localizedControlMappingRationale(future, "zh-TW"), future);
});
