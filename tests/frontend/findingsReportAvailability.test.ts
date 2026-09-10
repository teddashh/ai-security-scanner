import assert from "node:assert/strict";
import test from "node:test";

import {
  unavailableRunBoundReportCopy,
  unavailableSelectedRunCopy,
} from "../../src/findingsReportAvailability.ts";

test("a missing durable run-bound report gives one direct recovery path", () => {
  assert.equal(unavailableRunBoundReportCopy.title.en, "Master report unavailable for this scan");
  assert.equal(unavailableRunBoundReportCopy.title.zhTW, "這次掃描沒有主要報告");
  assert.equal(unavailableRunBoundReportCopy.body.en, "Open Review scanner status, then start a new scan to create the report.");
  assert.equal(unavailableRunBoundReportCopy.body.zhTW, "請開啟「查看掃描器狀態」，再開始新的掃描以建立主要報告。");
  assert.doesNotMatch(unavailableRunBoundReportCopy.body.en, /or Export/u);
  assert.doesNotMatch(unavailableRunBoundReportCopy.body.en, /available below/u);
  assert.doesNotMatch(unavailableRunBoundReportCopy.body.zhTW, /下方仍會保留/u);
  assert.doesNotMatch(unavailableRunBoundReportCopy.body.en, /showing the older result view/u);
  assert.doesNotMatch(unavailableRunBoundReportCopy.body.zhTW, /顯示舊版結果畫面/u);
});

test("a stale selected run gives the refresh action without defensive explanation", () => {
  assert.equal(unavailableSelectedRunCopy.title.en, "This selected scan is no longer available");
  assert.equal(unavailableSelectedRunCopy.title.zhTW, "選取的掃描輪次已無法使用");
  assert.match(unavailableSelectedRunCopy.body.en, /Refresh this project in My scans/u);
  assert.match(unavailableSelectedRunCopy.body.zhTW, /在「我的掃描」重新整理專案/u);
  assert.doesNotMatch(unavailableSelectedRunCopy.body.en, /will not substitute/u);
  assert.doesNotMatch(unavailableSelectedRunCopy.body.en, /export|Review scanner status/u);
  assert.doesNotMatch(unavailableSelectedRunCopy.body.zhTW, /匯出|查看掃描器狀態/u);
});
