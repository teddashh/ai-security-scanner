import { cleanup, fireEvent, render } from "@testing-library/react";
import { afterEach, expect, test, vi } from "vitest";

import { RuntimeSetupAssistant } from "../../src/components/RuntimeSetupAssistant";
import type { ManagedRuntimeSetupStatus } from "../../src/types";

// Rendered checks pin the setup lifecycle, available action, and concise copy
// presented for each state. Pure presentation-state coverage lives in the
// matching frontend test.

const setupStatus = (
  overrides: Partial<ManagedRuntimeSetupStatus> = {},
): ManagedRuntimeSetupStatus => ({
  phase: "idle",
  active: false,
  prerequisiteRepairActive: false,
  cancelRequested: false,
  receivedBytes: 0,
  resumedFromBytes: 0,
  canCancel: false,
  canRetry: true,
  detail: "runtime_setup_detail",
  ...overrides,
});

/** The exact shape the backend reports for a packaged runtime that failed admission. */
const packagedAdmissionFailure = setupStatus({
  phase: "failed",
  active: false,
  canRetry: false,
  canCancel: false,
  failureReason: "packaged_runtime_verification_failed",
  nextAction: undefined,
});

const renderAssistant = (props: Partial<Parameters<typeof RuntimeSetupAssistant>[0]> = {}) => {
  const onSetup = vi.fn();
  const onCheckScannerAvailability = vi.fn();
  const onCancel = vi.fn();
  const result = render(
    <RuntimeSetupAssistant
      locale="en"
      mode="native"
      runtime={{ provider: "podman", available: false, phase: "unavailable", detail: "" }}
      onSetup={onSetup}
      onCheckScannerAvailability={onCheckScannerAvailability}
      onCancel={onCancel}
      {...props}
    />,
  );
  return { ...result, onSetup, onCheckScannerAvailability, onCancel };
};

const heading = (container: HTMLElement): string =>
  container.querySelector("#runtime-assistant-title")?.textContent ?? "";

const explanation = (container: HTMLElement): string =>
  container.querySelector(".runtime-assistant__header p:not(.eyebrow)")?.textContent ?? "";

const actionButtons = (container: HTMLElement): HTMLButtonElement[] =>
  Array.from(container.querySelectorAll<HTMLButtonElement>(".runtime-assistant__actions button"));

afterEach(cleanup);

test("a check that can never run gives the required version action", () => {
  // The whole point of this state is that no amount of waiting fixes it, so the
  // user's only remaining question is what their report will claim about the
  // check. A silent omission would read as a clean pass.
  const { container } = renderAssistant({ status: packagedAdmissionFailure });

  expect(heading(container)).toBe("An advanced local scan tool is unavailable in this app version");
  expect(explanation(container)).toContain("Install a compatible app version");
  expect(explanation(container)).not.toContain("saved results");
  expect(explanation(container)).not.toContain("localhost");
  // No phase line: "Setup needs attention" beside a terminal failure implies
  // something is still being attempted.
  expect(container.querySelector(".runtime-assistant__status")).toBeNull();
});

test("a failure that can never succeed offers nothing to retry", () => {
  const { container } = renderAssistant({ status: packagedAdmissionFailure });

  expect(actionButtons(container)).toHaveLength(0);
});

test("a failure that could succeed on another attempt does offer the retry", () => {
  // The mirror of the test above. Without it, a component that rendered no
  // buttons at all in any state would pass, and the absence proved nothing.
  const { container } = renderAssistant({
    status: setupStatus({
      phase: "failed",
      canRetry: true,
      failureReason: "windows_wsl_command_failed",
    }),
  });

  const buttons = actionButtons(container);
  expect(buttons).toHaveLength(1);
  expect(buttons[0].textContent).toContain("Try advanced scan setup again");
  expect(buttons[0].disabled).toBe(false);

  expect(heading(container)).toBe("Advanced local scan-tool setup did not finish");
  expect(explanation(container)).toContain("Try advanced scan setup again");
  expect(explanation(container)).not.toContain("localhost");
  // A failure names a bounded category rather than leaving the user with a
  // headline and nothing to quote to anyone.
  const technical = container.querySelector(".runtime-assistant__technical");
  expect(technical?.querySelector("summary")?.textContent).toBe("Technical details");
  expect(technical?.querySelector("code")?.textContent).toBe("local_scan_tool_unavailable");
});

test("an admitted idle setup gives one start action", () => {
  const { container, onSetup } = renderAssistant({ status: setupStatus({ phase: "idle" }) });

  expect(heading(container)).toBe("This scan needs additional local tools");
  expect(explanation(container)).toContain("Select Prepare scan tools to begin");
  expect(explanation(container)).not.toContain("localhost");
  expect(actionButtons(container)[0].textContent).toContain("Prepare scan tools");
  expect(onSetup).not.toHaveBeenCalled();
  fireEvent.click(actionButtons(container)[0]);
  expect(onSetup).toHaveBeenCalledTimes(1);
});

test("a Windows restart requirement replaces the generic failure", () => {
  // `restart_windows` is the one failure whose cause is outside the app. Losing
  // the specific text would tell the user to keep retrying something that
  // cannot change until Windows restarts.
  const { container } = renderAssistant({
    status: setupStatus({
      phase: "failed",
      failureReason: "windows_restart_required",
      nextAction: "restart_windows",
    }),
  });

  expect(heading(container)).toBe("Windows restart required for advanced local scan tools");
  expect(explanation(container)).toContain("Restart Windows, reopen ai-security-scanner");
  expect(explanation(container)).not.toContain("localhost");
  expect(actionButtons(container)[0]?.textContent).toContain("Continue after restarting Windows");
});

test("a stale attempt shows the stop state and opens Retry only after stopping", () => {
  const { container } = renderAssistant({
    status: setupStatus({ phase: "start", active: true, stale: true, canCancel: true }),
  });

  expect(heading(container)).toBe("Stopping advanced local scan-tool setup");
  expect(explanation(container)).toContain("Current setup step is stopping");
  expect(explanation(container)).not.toContain("localhost");

  const buttons = actionButtons(container);
  expect(buttons).toHaveLength(1);
  expect(buttons[0].textContent).not.toContain("Try");
});

test("stopping and cancelled setup use direct lifecycle states", () => {
  const running = renderAssistant({
    status: setupStatus({ phase: "download", active: true, canCancel: true }),
  });
  const stopButton = actionButtons(running.container)[0];
  expect(stopButton.textContent).toContain("Stop advanced scan setup");
  expect(stopButton.textContent).not.toContain("keep");
  fireEvent.click(stopButton);
  expect(running.onCancel).toHaveBeenCalledTimes(1);
  expect(running.onSetup).not.toHaveBeenCalled();

  cleanup();

  const { container } = renderAssistant({ status: setupStatus({ phase: "cancelled" }) });
  expect(heading(container)).toBe("Advanced local scan-tool setup cancelled");
  expect(explanation(container)).toContain("Scan-tool status: not ready");
  expect(explanation(container)).not.toContain("localhost");
  expect(actionButtons(container)[0].textContent).toContain("Continue advanced scan setup");
  expect(container.textContent).not.toMatch(/paused|saved download|download was kept/iu);
  expect(container.querySelector(".runtime-assistant__technical")).toBeNull();
});

test("a stop already under way says so instead of looking unclicked", () => {
  const { container } = renderAssistant({
    status: setupStatus({
      phase: "download",
      active: true,
      canCancel: true,
      cancelRequested: true,
    }),
  });

  const button = actionButtons(container)[0];
  expect(button.textContent).toContain("Stopping…");
  expect(button.disabled).toBe(true);
});

test("a gap in the installed version points at the right retry", () => {
  // Runtime truth here says everything is available; the blocker is what makes
  // this state reachable, and it must win. The action also has to be the
  // availability re-check -- running setup again cannot change what shipped.
  const { container, onCheckScannerAvailability, onSetup } = renderAssistant({
    runtime: { provider: "podman", available: true, phase: "ready", detail: "" },
    scannerSetupBlocker: "no_runnable_authorized_targets",
    status: setupStatus({ phase: "failed", failureReason: "windows_wsl_command_failed" }),
  });

  expect(container.querySelector(".runtime-assistant--ready")).toBeNull();
  expect(heading(container)).toBe("This check is unavailable in the installed version");
  expect(explanation(container)).toContain("Install the latest app version");
  expect(explanation(container)).not.toContain("Other available checks can continue");

  const buttons = actionButtons(container);
  expect(buttons).toHaveLength(1);
  expect(buttons[0].textContent).toContain("Check availability again");
  fireEvent.click(buttons[0]);
  expect(onCheckScannerAvailability).toHaveBeenCalledTimes(1);
  expect(onSetup).not.toHaveBeenCalled();
});

test("a runtime that worked at the last check is not reported as working now", () => {
  // The app cannot know the tools still run; it knows they ran when it looked.
  // The hedge and the re-check promise are the difference between a status and
  // a guarantee.
  const { container } = renderAssistant({
    runtime: { provider: "podman", available: true, phase: "ready", detail: "" },
  });

  const ready = container.querySelector(".runtime-assistant--ready");
  expect(ready).not.toBeNull();
  expect(ready!.querySelector("strong")?.textContent).toBe(
    "Advanced local scan tools were ready at the last check",
  );
  expect(ready!.querySelector("p")?.textContent).toContain("checks the tools again before it runs");
});

test("a build that cannot prepare local checks does not offer to", () => {
  // In the browser there is no local runtime to set up. Rendering the setup
  // path anyway would offer an action the build cannot perform.
  const { container } = renderAssistant({ mode: "demo" });

  expect(container.querySelector(".runtime-assistant--demo")).not.toBeNull();
  expect(container.querySelectorAll("button")).toHaveLength(0);
  expect(container.textContent).toContain("Open the desktop app when you are ready");
  expect(container.textContent).not.toContain("preparation");
});

test("a resumed download is only claimed when bytes were actually carried over", () => {
  // "Existing download reused" is a factual claim about this machine's disk.
  const fresh = renderAssistant({
    status: setupStatus({
      phase: "download",
      active: true,
      receivedBytes: 2048,
      totalBytes: 8192,
      resumedFromBytes: 0,
    }),
  });
  const freshStatus = fresh.container.querySelector(".runtime-assistant__status");
  expect(freshStatus?.textContent).toContain("Downloading advanced local scan tools");
  expect(freshStatus?.textContent).toContain("2,048 bytes / 8,192 bytes");
  expect(freshStatus?.textContent).not.toContain("Existing download reused");

  cleanup();

  const { container } = renderAssistant({
    status: setupStatus({
      phase: "download",
      active: true,
      receivedBytes: 2048,
      totalBytes: 8192,
      resumedFromBytes: 1024,
    }),
  });
  expect(container.querySelector(".runtime-assistant__status")?.textContent)
    .toContain("Existing download reused");
});

test("the Traditional Chinese panel gives the same direct actions", () => {
  const untested = renderAssistant({ locale: "zh-TW", status: packagedAdmissionFailure });
  expect(explanation(untested.container)).toContain("請安裝相容的程式版本");
  expect(explanation(untested.container)).not.toContain("localhost");
  expect(actionButtons(untested.container)).toHaveLength(0);

  cleanup();

  const { container } = renderAssistant({
    locale: "zh-TW",
    runtime: { provider: "podman", available: true, phase: "ready", detail: "" },
    scannerSetupBlocker: "no_runnable_authorized_targets",
  });
  expect(heading(container)).toBe("目前安裝版本無法執行這項檢查");
  expect(explanation(container)).toContain("請安裝最新版本，再重新檢查可用性");
});
