import assert from "node:assert/strict";
import test from "node:test";
import { readFileSync } from "node:fs";
import { projectProblemRows, problemGroupAction, problemGroupImpact, problemGroupTitle } from "../../src/reportProblemPresentation.ts";
import type { BeginnerReportProblemGroup, Finding } from "../../src/types.ts";

const finding = (id: string, severity: Finding["severity"] = "low", assetId = "aws"): Finding => ({
  id, fingerprint: id, assetId, assetIds: [assetId], assetName: "AWS account", title: id,
  summary: id, impact: id, recommendation: id, expertType: "cloud", severity, confidence: "high",
  priority: 50, workflowState: "unreviewed", evidence: [], controls: [], officialReferences: [],
  firstSeenAt: "2026-10-02T12:00:00Z", lastSeenAt: "2026-10-02T12:00:00Z",
});
const group: BeginnerReportProblemGroup = {
  groupId: "group", ruleVersion: "aws-related-checks-1", kind: "iam_password_policy",
  title: "IAM password policy needs attention", targetAssetId: "aws",
  representativeFindingId: "high", findingIds: ["low","high"],
};

test("report rows preserve originals and use the highest visible severity", () => {
  const findings = [finding("low"),finding("other","medium"),finding("high","high")];
  const before = structuredClone(findings);
  const rows = projectProblemRows(findings,[group]);
  assert.equal(rows.length,2);
  assert.equal(rows[0].finding.id,"high");
  assert.deepEqual(rows[0].members.map(member => member.id),["low","high"]);
  assert.deepEqual(findings,before);
  assert.deepEqual(projectProblemRows([findings[0]], [group]),[{finding:findings[0],members:[findings[0]]}]);
});
test("asset boundaries, missing members and overlapping groups cannot hide originals", () => {
  const findings = [finding("low"),finding("high","high","other-account")];
  assert.equal(projectProblemRows(findings,[group]).length,2);
  assert.equal(projectProblemRows([findings[0]], [group]).length,1);
  assert.equal(projectProblemRows(findings).length,2);
  const sameAsset = [finding("low"),finding("high","high"),finding("third")];
  const rows = projectProblemRows(sameAsset,[group,{...group,groupId:"overlap",findingIds:["high","third"]}]);
  assert.equal(rows.length,2);
  assert.equal(rows[1].finding.id,"third");
});
test("group titles translate product wording and keep the recorded policy label", () => {
  assert.equal(problemGroupTitle(group,"zh-TW"),"IAM 密碼政策需要調整");
  assert.equal(problemGroupTitle({...group,kind:"root_account_usage"},"zh-TW"),"最近使用過 root 帳號");
  assert.equal(problemGroupTitle({...group,kind:"iam_policy_permissions",policyName:"Policy 1"},"zh-TW"),"檢查 IAM policy 的權限：Policy 1");
});

test("Results group guidance matches the shared HTML report in both languages", () => {
  const shared = readFileSync(new URL("../../src-tauri/src/report_problem_groups.rs", import.meta.url), "utf8");
  for (const kind of ["iam_password_policy", "root_account_usage"] as const) {
    for (const locale of ["en", "zh-TW"] as const) {
      const candidate = {...group, kind};
      for (const sentence of [problemGroupTitle(candidate, locale), problemGroupAction(candidate, locale), problemGroupImpact(candidate, locale)]) {
        assert.ok(sentence);
        assert.ok(shared.includes(JSON.stringify(sentence)), `Shared report must retain ${locale} guidance: ${sentence}`);
      }
    }
  }
  assert.equal(problemGroupAction({...group,kind:"iam_policy_permissions"},"en"),undefined);
});
