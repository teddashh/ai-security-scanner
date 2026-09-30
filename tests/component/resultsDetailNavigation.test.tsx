import { cleanup, fireEvent, render, waitFor, within } from "@testing-library/react";
import { afterEach, expect, test, vi } from "vitest";

import { I18nProvider } from "../../src/i18n";
import { FindingsPage } from "../../src/pages/FindingsPage";
import type { Finding } from "../../src/types";

const finding = (id: string, priority: number): Finding => ({
  id,
  fingerprint: id,
  assetId: `asset-${id}`,
  assetName: `Asset ${id}`,
  title: `Problem ${id}`,
  summary: `Problem ${id} was observed.`,
  impact: `Problem ${id} may affect this asset.`,
  recommendation: `Fix problem ${id}.`,
  expertType: "security",
  severity: "high",
  confidence: "high",
  priority,
  workflowState: "unreviewed",
  evidence: [],
  controls: [],
  officialReferences: [],
  firstSeenAt: "2026-09-04T12:00:00Z",
  lastSeenAt: "2026-09-04T12:00:00Z",
});

const renderResults = () => render(
  <I18nProvider>
    <FindingsPage
      findings={[finding("one", 2), finding("two", 1)]}
      findingGroups={[]}
      findingGroupEvents={[]}
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

const originalScrollIntoView = Element.prototype.scrollIntoView;

afterEach(() => {
  cleanup();
  vi.unstubAllGlobals();
  Element.prototype.scrollIntoView = originalScrollIntoView;
});

test("on a narrow screen, priority cards and result rows reveal the selected evidence panel", async () => {
  vi.stubGlobal("matchMedia", () => ({ matches: true }));
  const scrolled: Element[] = [];
  Element.prototype.scrollIntoView = function () { scrolled.push(this); };
  const { container } = renderResults();

  fireEvent.click(container.querySelector<HTMLButtonElement>(".priority-card")!);
  await waitFor(() => expect(scrolled.at(-1)).toBe(container.querySelector(".finding-detail")));
  expect(container.querySelector(".finding-detail h2")?.textContent).toBe("Problem one");

  scrolled.length = 0;
  fireEvent.click(container.querySelectorAll<HTMLButtonElement>(".finding-row")[1]!);
  await waitFor(() => expect(scrolled.at(-1)).toBe(container.querySelector(".finding-detail")));
  expect(container.querySelector(".finding-detail h2")?.textContent).toBe("Problem two");
});

test("on a wide screen, priority cards reveal the side-by-side browser without moving row readers", async () => {
  vi.stubGlobal("matchMedia", () => ({ matches: false }));
  const scrolled: Element[] = [];
  Element.prototype.scrollIntoView = function () { scrolled.push(this); };
  const { container } = renderResults();

  fireEvent.click(container.querySelector<HTMLButtonElement>(".priority-card")!);
  await waitFor(() => expect(scrolled.at(-1)).toBe(container.querySelector("#finding-browser")));

  scrolled.length = 0;
  fireEvent.click(container.querySelectorAll<HTMLButtonElement>(".finding-row")[1]!);
  await waitFor(() => expect(container.querySelector(".finding-detail h2")?.textContent).toBe("Problem two"));
  expect(scrolled).toEqual([]);
});

test("filters hide details for excluded problems and a priority link reveals its problem", async () => {
  const { container } = renderResults();

  fireEvent.click(container.querySelector<HTMLButtonElement>(".finding-row")!);
  expect(container.querySelector(".finding-detail h2")?.textContent).toBe("Problem one");

  fireEvent.change(within(container).getByRole("combobox", { name: "Severity" }), {
    target: { value: "low" },
  });
  expect(container.querySelectorAll(".finding-row")).toHaveLength(0);
  expect(container.querySelector(".finding-detail--empty")).not.toBeNull();

  fireEvent.click(container.querySelector<HTMLButtonElement>(".priority-card")!);
  await waitFor(() => expect(container.querySelector(".finding-detail h2")?.textContent).toBe("Problem one"));
  expect(container.querySelectorAll(".finding-row")).toHaveLength(2);
  expect((within(container).getByRole("combobox", { name: "Severity" }) as HTMLSelectElement).value).toBe("all");
});
