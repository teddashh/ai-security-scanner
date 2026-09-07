import assert from "node:assert/strict";
import test from "node:test";

import {
  unavailableRunBoundReportCopy,
  unavailableSelectedRunCopy,
} from "../../src/findingsReportAvailability.ts";

test("a missing durable run-bound report preserves the exact saved result without overstating availability", () => {
  assert.equal(unavailableRunBoundReportCopy.title.en, "This scan has no durable master report");
  assert.equal(unavailableRunBoundReportCopy.title.zhTW, "這次掃描缺少可持續保存的主要報告");
  assert.match(unavailableRunBoundReportCopy.body.en, /Findings from other scan runs are not shown/u);
  assert.match(unavailableRunBoundReportCopy.body.zhTW, /不會改顯示其他掃描輪次的問題/u);
  assert.match(unavailableRunBoundReportCopy.body.en, /exact saved run remains available from the Review scanner status view and can still be exported/u);
  assert.match(unavailableRunBoundReportCopy.body.zhTW, /精確掃描紀錄仍可在「查看掃描器狀態」中查看，也可以匯出/u);
  assert.doesNotMatch(unavailableRunBoundReportCopy.body.en, /available below/u);
  assert.doesNotMatch(unavailableRunBoundReportCopy.body.zhTW, /下方仍會保留/u);
  assert.doesNotMatch(unavailableRunBoundReportCopy.body.en, /showing the older result view/u);
  assert.doesNotMatch(unavailableRunBoundReportCopy.body.zhTW, /顯示舊版結果畫面/u);
});

test("a stale selected run fails closed without promising unavailable routes", () => {
  assert.equal(unavailableSelectedRunCopy.title.en, "This selected scan is no longer available");
  assert.equal(unavailableSelectedRunCopy.title.zhTW, "選取的掃描輪次已無法使用");
  assert.match(unavailableSelectedRunCopy.body.en, /will not substitute a different scan run/u);
  assert.match(unavailableSelectedRunCopy.body.zhTW, /不會改用其他掃描輪次代替/u);
  assert.doesNotMatch(unavailableSelectedRunCopy.body.en, /export|Review scanner status/u);
  assert.doesNotMatch(unavailableSelectedRunCopy.body.zhTW, /匯出|查看掃描器狀態/u);
});
