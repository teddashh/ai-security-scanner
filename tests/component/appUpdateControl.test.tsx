import { cleanup, render } from "@testing-library/react";
import { afterEach, beforeEach, expect, test } from "vitest";

import { AppUpdateControl } from "../../src/components/AppUpdateControl";
import { I18nProvider, localeStorageKey } from "../../src/i18n";
import type { AppUpdateState } from "../../src/services/appUpdater";

const renderControl = (state: AppUpdateState) =>
  render(
    <I18nProvider>
      <AppUpdateControl state={state} onCheck={() => {}} onInstall={() => {}} />
    </I18nProvider>,
  );

beforeEach(() => {
  window.localStorage.setItem(localeStorageKey, "en");
});

afterEach(() => {
  cleanup();
  window.localStorage.clear();
});

test.each([
  {
    phase: "downloading",
    state: { phase: "downloading", downloadedBytes: 1, totalBytes: 4 } satisfies AppUpdateState,
    label: "Downloading update · 25%",
    role: "status",
  },
  {
    phase: "installing",
    state: { phase: "installing" } satisfies AppUpdateState,
    label: "Verifying and installing…",
    role: "status",
  },
  {
    phase: "restarting",
    state: { phase: "restarting" } satisfies AppUpdateState,
    label: "Restarting shortly…",
    role: "status",
  },
  {
    phase: "available",
    state: { phase: "available", availableVersion: "2.0.0" } satisfies AppUpdateState,
    label: "Update to 2.0.0",
    role: "button",
  },
  {
    phase: "unreachable",
    state: { phase: "unreachable" } satisfies AppUpdateState,
    label: "Update service unavailable · Retry",
    role: "button",
  },
  {
    phase: "error",
    state: { phase: "error" } satisfies AppUpdateState,
    label: "Update check failed · Try again",
    role: "button",
  },
  {
    phase: "checking",
    state: { phase: "checking" } satisfies AppUpdateState,
    label: "Checking for updates…",
    role: "button",
  },
  {
    phase: "current",
    state: { phase: "current", currentVersion: "1.2.3" } satisfies AppUpdateState,
    label: "Version 1.2.3",
    role: "button",
  },
  {
    phase: "unoffered",
    state: { phase: "unoffered", currentVersion: "1.2.3" } satisfies AppUpdateState,
    label: "Version 1.2.3",
    role: "button",
  },
])("the $phase phase renders its label in the truncating element", ({ state, label, role }) => {
  const { getByRole } = renderControl(state);
  const control = getByRole(role);
  const labelElement = control.querySelector(".update-control__label");

  expect(labelElement).not.toBeNull();
  expect(labelElement!.textContent).toBe(label);
});

test.each([
  {
    locale: "en" as const,
    label: "Update service unavailable · Retry",
    description: "The app is offline or the update service is unavailable. Select this button to try again.",
  },
  {
    locale: "zh-TW" as const,
    label: "更新服務無法使用 · 重試",
    description: "目前離線，或更新服務無法使用。按下此按鈕再試一次。",
  },
])("an unreachable update check has a concise, explained $locale action", ({
  locale,
  label,
  description,
}) => {
  window.localStorage.setItem(localeStorageKey, locale);
  const { getByRole } = renderControl({ phase: "unreachable" });
  const button = getByRole("button", { name: label, description });

  expect(button.className).toBe("update-control");
  expect(button.className).not.toContain("update-control--error");
  expect(button.textContent).toBe(label);
  expect(button.querySelector("svg")?.innerHTML).not.toContain("M10.3 3.6");
});

test("an untrusted update check stays a warning", () => {
  const { container } = renderControl({ phase: "error" });
  const button = container.querySelector("button");

  expect(button).not.toBeNull();
  expect(button!.className).toContain("update-control--error");
  expect(button!.textContent).toContain("Update check failed");
  expect(button!.querySelector("svg")?.innerHTML).toContain("M10.3 3.6");
});

test.each([
  {
    locale: "en" as const,
    label: "Version 0.3.0",
    description: "The latest published release has no update for this computer. Select this button to check again.",
  },
  {
    locale: "zh-TW" as const,
    label: "版本 0.3.0",
    description: "最新發布的版本沒有適用於這台電腦的更新。按下此按鈕再檢查一次。",
  },
])("a release without an installer for this computer shows the version, not an outage, in $locale", ({
  locale,
  label,
  description,
}) => {
  window.localStorage.setItem(localeStorageKey, locale);
  const { getByRole } = renderControl({ phase: "unoffered", currentVersion: "0.3.0" });
  const button = getByRole("button", { name: label, description });

  expect(button.className).toBe("update-control");
  expect(button.textContent).not.toMatch(/unavailable|無法使用/u);
});
