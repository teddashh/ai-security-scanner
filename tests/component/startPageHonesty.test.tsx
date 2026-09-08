import { cleanup, fireEvent, render } from "@testing-library/react";
import { afterEach, expect, test, vi } from "vitest";

import { StartPage } from "../../src/pages/StartPage";
import { DEFAULT_LOCALHOST_QUICK_SCAN_PORT } from "../../src/localhostQuickScan";
import { startPageCopy, useCaseDefinitions } from "../../src/useCases";

// The first screen must lead beginners to a meaningful security scan. The
// built-in TCP attempt remains available only as a collapsed connection
// utility, and its copy must make the narrower capability unmistakable.
//
// Every use-case card also carries a "what this does not do" line beside its
// pitch. A card that loses it advertises a capability with no limit attached.

const renderStart = (props: Partial<Parameters<typeof StartPage>[0]> = {}) => {
  const onStartLocalhostQuickScan = vi.fn();
  const onChoose = vi.fn();
  const locale = props.locale ?? "en";
  const result = render(
    <StartPage
      locale={locale}
      copy={startPageCopy[locale]}
      nativeMode
      onStartLocalhostQuickScan={onStartLocalhostQuickScan}
      onChoose={onChoose}
      {...props}
    />,
  );
  return { ...result, onStartLocalhostQuickScan, onChoose };
};

const quickScanButton = (container: HTMLElement): HTMLButtonElement =>
  container.querySelector<HTMLButtonElement>(".start-page__connection-action")!;

const boundaryText = (container: HTMLElement): string =>
  container.querySelector(".start-page__localhost-boundary")?.textContent ?? "";

const portInput = (container: HTMLElement): HTMLInputElement =>
  container.querySelector<HTMLInputElement>("#localhost-quick-scan-port")!;

afterEach(cleanup);

test("the connection utility states its exact boundary and is not called a vulnerability scan", () => {
  const { container } = renderStart();

  const boundary = boundaryText(container);
  // Every clause here is a commitment about behaviour, not a mood.
  expect(boundary).toContain("one TCP connection");
  expect(boundary).toContain(`127.0.0.1:${DEFAULT_LOCALHOST_QUICK_SCAN_PORT}`);
  expect(boundary).toContain("up to 3 seconds");
  expect(boundary).toContain("no payload");
  expect(boundary).toContain("not a vulnerability scan");
  expect(container.querySelector<HTMLDetailsElement>(".start-page__connection-tools")?.open).toBe(false);
});

test("choosing another port changes what the app says it will do, with no stale port left behind", () => {
  // The port is substituted into both sentences by string replacement. A
  // replacement that missed one, or hit the wrong digits, would leave the app
  // naming a port it is not going to touch -- a precise-sounding false claim.
  const { container } = renderStart();

  fireEvent.change(portInput(container), { target: { value: "8080" } });

  expect(quickScanButton(container).textContent).toContain("127.0.0.1:8080");
  expect(boundaryText(container)).toContain("127.0.0.1:8080");
  expect(quickScanButton(container).textContent).not.toContain(String(DEFAULT_LOCALHOST_QUICK_SCAN_PORT));
  expect(boundaryText(container)).not.toContain(String(DEFAULT_LOCALHOST_QUICK_SCAN_PORT));
  // The rest of the statement survives the substitution intact.
  expect(boundaryText(container)).toContain("up to 3 seconds");
  expect(boundaryText(container)).toContain("not a vulnerability scan");
});

test("the port the app scans is the port it just named", () => {
  // Honest limit: the click handler also guards with `if (localhostPort !==
  // undefined)`, which is unreachable behaviourally because `disabled` already
  // blocks the click -- the test below proves `disabled` is what stops it.
  // Replacing that inner guard with a fallback to the default port therefore
  // survives every assertion here. It is defence in depth, not covered.
  const { container, onStartLocalhostQuickScan } = renderStart();

  fireEvent.change(portInput(container), { target: { value: "8080" } });
  fireEvent.click(quickScanButton(container));

  expect(onStartLocalhostQuickScan).toHaveBeenCalledTimes(1);
  expect(onStartLocalhostQuickScan).toHaveBeenCalledWith(8080);
});

test("a port the app cannot scan does not start a scan it already described", () => {
  // The boundary sentence is rendered from whatever is typed. While that value
  // is not a port the app can act on, the action must stay closed rather than
  // fall back to a default the user did not ask for.
  const { container, onStartLocalhostQuickScan } = renderStart();

  for (const rejected of ["70000", "0", "abc", "80.5", "", "  "]) {
    fireEvent.change(portInput(container), { target: { value: rejected } });
    expect(quickScanButton(container).disabled, `"${rejected}" must not be scannable`).toBe(true);
    expect(container.querySelector(".start-page__localhost-port-error")?.textContent)
      .toContain("Enter a whole-number port from 1 to 65535");
    fireEvent.click(quickScanButton(container));
  }

  expect(onStartLocalhostQuickScan).not.toHaveBeenCalled();
});

test("a build that cannot run the quick scan does not offer it", () => {
  // In the browser there is no local TCP connection to make. Rendering the
  // offer anyway would advertise a check the app cannot perform.
  const { container } = renderStart({ nativeMode: false });

  expect(container.querySelector(".start-page__localhost-quick-scan")).toBeNull();
  expect(container.querySelector(".start-page__localhost-boundary")).toBeNull();
});

test("the first screen does not offer the example project action", () => {
  const { queryByRole } = renderStart();
  expect(queryByRole("button", { name: "See an example project" })).toBeNull();
  expect(queryByRole("button", { name: "查看範例專案" })).toBeNull();
});

test("the first screen leads with a combined environment scan plus the website and code shortcuts", () => {
  const onOpenExistingCase = vi.fn();
  const { container, getByRole, queryByRole, queryByText } = renderStart({ onOpenExistingCase });

  expect(getByRole("heading", { level: 1, name: "Security checks" })).toBeTruthy();
  const primaryActions = Array.from(container.querySelectorAll<HTMLButtonElement>(".start-page__choices > .use-case-grid .use-case-card__action"));
  expect(primaryActions.map((button) => button.textContent?.trim())).toEqual([
    "Scan my environment",
    "Check a website",
    "Check code or an AI project",
  ]);
  const environmentCard = Array.from(container.querySelectorAll<HTMLElement>(".use-case-card"))
    .find((card) => card.textContent?.includes("Scan my environment"));
  expect(environmentCard?.textContent).toContain("Company IT environment");
  expect(environmentCard?.textContent).toContain("repositories, websites or APIs, and exact internal hosts");
  expect(environmentCard?.textContent).toContain("Greenbone discovers services on the chosen ports");
  expect(environmentCard?.textContent).toContain("not tested");
  const websiteCard = Array.from(container.querySelectorAll<HTMLElement>(".use-case-card"))
    .find((card) => card.textContent?.includes("Check a website"));
  expect(websiteCard?.textContent).toContain(
    "Let Nuclei identify the website technology and run matching upstream vulnerability and exposure checks against the displayed website origin.",
  );
  expect(websiteCard?.textContent).not.toContain("basic exposure signals");
  expect(container.querySelector(".start-page__choices > .use-case-grid")?.textContent)
    .toContain("Code or AI project");
  expect(quickScanButton(container).classList.contains("button--primary")).toBe(false);
  expect(container.querySelector<HTMLDetailsElement>(".start-page__connection-tools")?.open).toBe(false);
  expect(queryByRole("link", { name: "Start a security check" })).toBeNull();
  expect(getByRole("button", { name: "Open my scans" })).toBeTruthy();
  expect(queryByText("What you get")).toBeNull();
  expect(queryByText("How it works")).toBeNull();
});

test("every offered scan keeps its capability and limit in one collapsed disclosure", () => {
  const { container } = renderStart();

  const cards = Array.from(container.querySelectorAll<HTMLElement>(".use-case-card"));
  // Primary and additional cards both render; progressive disclosure changes
  // prominence without removing any supported path.
  expect(cards.length).toBe(useCaseDefinitions.length);
  const disclosure = container.querySelector<HTMLDetailsElement>(".start-page__scan-limits");
  expect(disclosure).not.toBeNull();
  expect(disclosure!.open).toBe(false);
  const limits = Array.from(disclosure!.querySelectorAll<HTMLElement>(".start-page__scan-limit"));
  expect(limits.length).toBe(useCaseDefinitions.length);

  for (const limit of limits) {
    const heading = limit.querySelector("h3")?.textContent ?? "(unnamed)";
    const does = limit.querySelector(".use-case-card__does dd")?.textContent?.trim() ?? "";
    const doesNot = limit.querySelector(".use-case-card__does-not dd")?.textContent?.trim() ?? "";
    expect(does.length, `${heading} states no capability`).toBeGreaterThan(0);
    expect(doesNot.length, `${heading} states no limit`).toBeGreaterThan(0);
    expect(doesNot, `${heading} restates its capability as its limit`).not.toBe(does);
  }
});

test("the Traditional Chinese boundary statement carries the same commitments", () => {
  // The English copy was checked above. These are separate literals, and a
  // reader of one never sees the other.
  const { container } = renderStart({ locale: "zh-TW" });

  expect(boundaryText(container)).toContain(`127.0.0.1:${DEFAULT_LOCALHOST_QUICK_SCAN_PORT}`);
  expect(boundaryText(container)).toContain("不傳送內容");
  expect(boundaryText(container)).toContain("這不是漏洞掃描");

  fireEvent.change(portInput(container), { target: { value: "8080" } });
  expect(boundaryText(container)).toContain("127.0.0.1:8080");
  expect(boundaryText(container)).not.toContain(String(DEFAULT_LOCALHOST_QUICK_SCAN_PORT));
  expect(boundaryText(container)).toContain("最長等待 3 秒");
});

test("the Traditional Chinese first layer names the upstream website and internal-host paths", () => {
  const { container } = renderStart({ locale: "zh-TW" });
  const primaryLayer = container.querySelector(".start-page__choices > .use-case-grid");

  expect(primaryLayer?.textContent).toContain("辨識網站技術");
  expect(primaryLayer?.textContent).toContain("精確內部主機");
  expect(primaryLayer?.textContent).toContain("Greenbone 會探索所選連接埠的服務");
  expect(primaryLayer?.textContent).toContain("僅供盤點的網段仍會明列為未測試");
  expect(primaryLayer?.textContent).toContain("程式碼或 AI 專案");
  expect(primaryLayer?.textContent).toContain("檢查程式碼或 AI 專案");
});
