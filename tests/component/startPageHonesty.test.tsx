import { cleanup, fireEvent, render } from "@testing-library/react";
import { afterEach, expect, test, vi } from "vitest";

import { StartPage } from "../../src/pages/StartPage";
import { DEFAULT_LOCALHOST_QUICK_SCAN_PORT } from "../../src/localhostQuickScan";
import { startPageCopy, useCaseDefinitions } from "../../src/useCases";

// This is the first screen, and the only one a user reads before they have any
// results to calibrate against. Two claims on it are load-bearing.
//
// The quick scan is the one action the app performs straight from marketing
// copy, and the copy states exactly what it will do: one TCP connection, to a
// named port, for at most three seconds, with no payload. The port is
// substituted into that sentence at render time, so the sentence and the action
// can drift apart -- and a boundary statement naming a port the app is not
// about to touch is worse than no statement at all.
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
  container.querySelector<HTMLButtonElement>(".start-page__primary-action")!;

const boundaryText = (container: HTMLElement): string =>
  container.querySelector(".start-page__localhost-boundary")?.textContent ?? "";

const portInput = (container: HTMLElement): HTMLInputElement =>
  container.querySelector<HTMLInputElement>("#localhost-quick-scan-port")!;

afterEach(cleanup);

test("the quick scan states its exact boundary rather than a reassurance", () => {
  const { container } = renderStart();

  const boundary = boundaryText(container);
  // Every clause here is a commitment about behaviour, not a mood.
  expect(boundary).toContain("one TCP connection");
  expect(boundary).toContain(`127.0.0.1:${DEFAULT_LOCALHOST_QUICK_SCAN_PORT}`);
  expect(boundary).toContain("no more than 3 seconds");
  expect(boundary).toContain("sends no payload");
  expect(boundary).toContain("is not a security guarantee");
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
  expect(boundaryText(container)).toContain("no more than 3 seconds");
  expect(boundaryText(container)).toContain("is not a security guarantee");
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

test("every scan the page offers also says what it will not do", () => {
  const { container } = renderStart();

  const cards = Array.from(container.querySelectorAll<HTMLElement>(".use-case-card"));
  // Primary and additional cards both render; a page showing only the first
  // four would leave five offers undescribed.
  expect(cards.length).toBe(useCaseDefinitions.length);

  for (const card of cards) {
    const heading = card.querySelector("h3")?.textContent ?? "(unnamed)";
    const does = card.querySelector(".use-case-card__does dd")?.textContent?.trim() ?? "";
    const doesNot = card.querySelector(".use-case-card__does-not dd")?.textContent?.trim() ?? "";
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
  expect(boundaryText(container)).toContain("不會傳送內容");
  expect(boundaryText(container)).toContain("不代表這台電腦一定安全");

  fireEvent.change(portInput(container), { target: { value: "8080" } });
  expect(boundaryText(container)).toContain("127.0.0.1:8080");
  expect(boundaryText(container)).not.toContain(String(DEFAULT_LOCALHOST_QUICK_SCAN_PORT));
  expect(boundaryText(container)).toContain("最長等待 3 秒");
});
