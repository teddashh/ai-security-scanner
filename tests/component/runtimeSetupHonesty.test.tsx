import { cleanup, fireEvent, render } from "@testing-library/react";
import { afterEach, expect, test, vi } from "vitest";

import { RuntimeSetupAssistant } from "../../src/components/RuntimeSetupAssistant";
import type { ManagedRuntimeSetupStatus } from "../../src/types";

// This panel is the app's account of why a check it advertised cannot run. Its
// claims are unusually load-bearing because the user reads them *instead of* a
// result: there is nothing on screen to calibrate against, so whatever the panel
// says about the consequences is all they get.
//
// Three kinds of claim are pinned below.
//
//   - What the report will say. Two sentences here promise something about a
//     document the user has not opened yet -- that an unrunnable check is
//     marked not tested, and that a coverage gap is named. Those cross a
//     boundary this component cannot see over.
//   - What has and has not happened to their data. "The download was kept",
//     "your scan projects are unchanged", "no saved scan was changed".
//   - What the app is still offering. An affordance is a claim too: a Retry
//     button beside a failure that can never succeed says the failure is
//     temporary. Absence of a button is therefore an assertion, and is tested
//     as one -- always against a sibling case where the button must appear, so
//     a component that simply never renders buttons cannot pass.
//
// `resolveRuntimeSetupPresentation` is already covered as a pure function in
// tests/frontend/runtimeSetupAssistant.test.ts. What was not covered is whether
// the nine-branch title/description cascade and the four-branch action cascade
// actually resolve to those strings, which only rendering can show.

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

test("a check that can never run says the results will record it as untested", () => {
  // The whole point of this state is that no amount of waiting fixes it, so the
  // user's only remaining question is what their report will claim about the
  // check. A silent omission would read as a clean pass.
  const { container } = renderAssistant({ status: packagedAdmissionFailure });

  expect(heading(container)).toBe("One local check cannot run in this app version");
  // Worded against the report heading the gap is actually rendered under, not
  // against the "Not tested" count tile, which stays 0 on this path. See
  // tests/frontend/setupPanelReportPromises.test.ts for the binding.
  expect(explanation(container)).toContain(
    "lists this check under what was not tested, never as a pass",
  );
  expect(explanation(container)).toContain("saved projects, reports, and exports remain available");
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
  expect(buttons[0].textContent).toContain("Try setup again");
  expect(buttons[0].disabled).toBe(false);

  expect(heading(container)).toBe("One local check is unavailable");
  expect(explanation(container)).toContain(
    "Other checks, saved projects, reports, and readable exports remain available",
  );
  // A failure names a bounded category rather than leaving the user with a
  // headline and nothing to quote to anyone.
  const technical = container.querySelector(".runtime-assistant__technical");
  expect(technical?.querySelector("summary")?.textContent).toBe("Technical details");
  expect(technical?.querySelector("code")?.textContent).toBe("local_scan_tool_unavailable");
});

test("a Windows restart requirement replaces the generic failure, and still says the scans are intact", () => {
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

  expect(heading(container)).toBe("One local scan tool is unavailable right now");
  expect(explanation(container)).toContain("Windows requires a restart to finish its change");
  expect(explanation(container)).toContain("Your saved scans are unchanged");
  expect(explanation(container)).not.toContain("readable exports remain available");
});

test("a slow attempt says Retry comes later, and does not show a Retry now", () => {
  // The copy makes a promise about sequence: the app is stopping this attempt
  // and "will offer Retry when it has stopped". A Retry button rendered
  // alongside it would mean the sentence describes a state the UI is not in.
  const { container } = renderAssistant({
    status: setupStatus({ phase: "start", active: true, stale: true, canCancel: true }),
  });

  expect(heading(container)).toBe("Preparation took longer than expected");
  expect(explanation(container)).toContain("will offer Retry when it has stopped");
  expect(explanation(container)).toContain("Your projects and reports remain available");

  const buttons = actionButtons(container);
  expect(buttons).toHaveLength(1);
  expect(buttons[0].textContent).not.toContain("Try");
});

test("stopping promises the download is kept, and the paused state confirms it was", () => {
  // Two separate strings written at different times, and the second is the only
  // evidence the user ever gets for the first.
  const running = renderAssistant({
    status: setupStatus({ phase: "download", active: true, canCancel: true }),
  });
  const stopButton = actionButtons(running.container)[0];
  expect(stopButton.textContent).toContain("Stop setup and keep the download");
  fireEvent.click(stopButton);
  expect(running.onCancel).toHaveBeenCalledTimes(1);
  expect(running.onSetup).not.toHaveBeenCalled();

  cleanup();

  const { container } = renderAssistant({ status: setupStatus({ phase: "cancelled" }) });
  expect(heading(container)).toBe("Setup paused");
  expect(explanation(container)).toContain("The download was kept on this computer");
  expect(explanation(container)).toContain("your scan projects are unchanged");
  // "Continue" and "Try again" are different claims about what was kept.
  expect(actionButtons(container)[0].textContent).toContain("Continue setup");
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

test("a gap in the installed version promises the report will name it, and points at the right retry", () => {
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
  expect(explanation(container)).toContain("The report will still name this coverage gap");
  // This blocker is raised only when the runnable count over the compatible
  // engines is zero, so there is no sibling check left to continue.
  expect(explanation(container)).toContain("No check in this version can run for this target");
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
    "Local scan tools were ready at the last check",
  );
  expect(ready!.querySelector("p")?.textContent).toContain("checks them again before it runs");
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
  expect(freshStatus?.textContent).toContain("Downloading the scan tools");
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

test("the Traditional Chinese panel carries the same two report promises", () => {
  // Separate literals, and a reader of one locale never sees the other. These
  // are the two claims about a document the user has not opened yet.
  const untested = renderAssistant({ locale: "zh-TW", status: packagedAdmissionFailure });
  // 「沒有測到的內容」 is the exact FindingsPage gaps heading in this locale.
  expect(explanation(untested.container)).toContain("報告會把這項檢查列在「沒有測到的內容」裡，不會當成通過");
  expect(actionButtons(untested.container)).toHaveLength(0);

  cleanup();

  const { container } = renderAssistant({
    locale: "zh-TW",
    runtime: { provider: "podman", available: true, phase: "ready", detail: "" },
    scannerSetupBlocker: "no_runnable_authorized_targets",
  });
  expect(heading(container)).toBe("目前安裝版本無法執行這項檢查");
  expect(explanation(container)).toContain("報告仍會列出這個涵蓋缺口");
  expect(explanation(container)).toContain("這個版本沒有任何檢查能處理這個目標");
});
