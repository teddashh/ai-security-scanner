import assert from "node:assert/strict";
import test from "node:test";

import { unavailableRunBoundReportCopy } from "../../src/findingsReportAvailability.ts";

test("an unavailable run-bound report explicitly fails closed in both locales", () => {
  assert.equal(unavailableRunBoundReportCopy.title.en, "This saved report is unavailable");
  assert.equal(unavailableRunBoundReportCopy.title.zhTW, "這份已保存的報告目前無法使用");
  assert.match(unavailableRunBoundReportCopy.body.en, /Findings from other scan runs are not shown/u);
  assert.match(unavailableRunBoundReportCopy.body.zhTW, /不會改顯示其他掃描輪次的問題/u);
  assert.doesNotMatch(unavailableRunBoundReportCopy.body.en, /showing the older result view/u);
  assert.doesNotMatch(unavailableRunBoundReportCopy.body.zhTW, /顯示舊版結果畫面/u);
});
