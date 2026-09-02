import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import test from "node:test";

import {
  caseDisplayLabels,
  caseIdentityPresentation,
} from "../../src/caseIdentityPresentation.ts";

const savedQuickScan = (overrides: Partial<{
  id: string;
  name: string;
  organizationName: string;
  createdAt: string;
  productIdentity: { kind: "localhost_quick_scan"; port: number } | undefined;
}> = {}) => ({
  id: "quick-scan-a",
  name: "This computer · 127.0.0.1:9001",
  organizationName: "This computer",
  createdAt: "2026-08-30T12:00:00.000000001Z",
  productIdentity: { kind: "localhost_quick_scan", port: 9001 },
  ...overrides,
});

test("the exact saved localhost identity is localized only for display", () => {
  const saved = savedQuickScan();

  assert.deepEqual(caseIdentityPresentation(saved, "zh-TW"), {
    name: "這台電腦 · 127.0.0.1:9001",
    organizationName: "這台電腦",
    isProductLocalhostQuickScan: true,
  });
  assert.deepEqual(caseIdentityPresentation(saved, "en"), {
    name: saved.name,
    organizationName: saved.organizationName,
    isProductLocalhostQuickScan: true,
  });
  assert.equal(saved.name, "This computer · 127.0.0.1:9001");
  assert.equal(saved.organizationName, "This computer");
});

test("display-string collisions and malformed lookalikes are never rewritten without canonical identity", () => {
  for (const saved of [
    savedQuickScan({ productIdentity: undefined }),
    savedQuickScan({ name: "This computer · localhost:9001", productIdentity: undefined }),
    savedQuickScan({ name: "This computer · 127.0.0.1:65536", productIdentity: undefined }),
    savedQuickScan({ organizationName: "My lab", productIdentity: undefined }),
    savedQuickScan({ name: "My computer · 127.0.0.1:9001", productIdentity: undefined }),
  ]) {
    const presented = caseIdentityPresentation(saved, "zh-TW");
    assert.equal(presented.name, saved.name);
    assert.equal(presented.organizationName, saved.organizationName);
    assert.equal(presented.isProductLocalhostQuickScan, false);
  }
});

test("canonical product identity controls presentation instead of persisted display text", () => {
  const saved = savedQuickScan({
    name: "legacy product label",
    organizationName: "legacy organization label",
    productIdentity: { kind: "localhost_quick_scan", port: 8765 },
  });
  assert.equal(caseIdentityPresentation(saved, "zh-TW").name, "這台電腦 · 127.0.0.1:8765");
});

test("repeated quick scans get stable, distinct created-time labels", () => {
  const first = savedQuickScan();
  const second = savedQuickScan({
    id: "quick-scan-b",
    createdAt: "2026-08-30T12:00:01.250000000Z",
  });
  const labels = caseDisplayLabels([first, second], "zh-TW");

  assert.equal(
    labels.get(first.id),
    "這台電腦 · 127.0.0.1:9001 · 2026-08-30 12:00:00.000000001 UTC",
  );
  assert.equal(
    labels.get(second.id),
    "這台電腦 · 127.0.0.1:9001 · 2026-08-30 12:00:01.25 UTC",
  );
  assert.notEqual(labels.get(first.id), labels.get(second.id));
});

test("an exact created-time tie remains distinguishable by immutable id", () => {
  const first = savedQuickScan();
  const second = savedQuickScan({ id: "quick-scan-b" });
  const labels = caseDisplayLabels([first, second], "en");

  assert.match(labels.get(first.id) ?? "", / · quick-scan-a$/u);
  assert.match(labels.get(second.id) ?? "", / · quick-scan-b$/u);
});

test("a single quick scan keeps a concise localized label", () => {
  const saved = savedQuickScan();
  assert.equal(caseDisplayLabels([saved], "zh-TW").get(saved.id), "這台電腦 · 127.0.0.1:9001");
});

test("AppShell and Cases use display labels while delete confirmation keeps saved identity", async () => {
  const [appShell, casesPage] = await Promise.all([
    readFile(new URL("../../src/components/AppShell.tsx", import.meta.url), "utf8"),
    readFile(new URL("../../src/pages/CasesPage.tsx", import.meta.url), "utf8"),
  ]);

  assert.match(appShell, /caseDisplayLabels\(cases, locale\)/u);
  assert.match(
    appShell,
    /displayedCaseLabels\.get\(assessmentCase\.id\) \?\? assessmentCase\.name/u,
  );
  assert.match(casesPage, /caseIdentityPresentation\(assessmentCase, locale\)/u);
  assert.match(casesPage, /<strong>\{displayedName\}<\/strong>/u);
  assert.match(casesPage, /deleteConfirmation !== assessmentCase\.name/u);
  assert.match(casesPage, /name: assessmentCase\.name/u);
});
