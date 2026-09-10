import { cleanup, fireEvent, render } from "@testing-library/react";
import { afterEach, beforeEach, expect, test, vi } from "vitest";

import { I18nProvider, localeStorageKey } from "../../src/i18n";
import { SettingsPage } from "../../src/pages/SettingsPage";

const renderSettings = ({
  mode = "native",
  runtimeAvailable,
}: {
  mode?: "native" | "demo";
  runtimeAvailable?: boolean;
} = {}) => {
  const onLocaleChange = vi.fn();
  const onOpenNewScan = vi.fn();
  const onOpenProjects = vi.fn();
  const view = render(
    <I18nProvider>
      <SettingsPage
        locale="en"
        mode={mode}
        runtimeAvailable={runtimeAvailable}
        onLocaleChange={onLocaleChange}
        onOpenNewScan={onOpenNewScan}
        onOpenProjects={onOpenProjects}
      />
    </I18nProvider>,
  );
  return { ...view, onLocaleChange, onOpenNewScan, onOpenProjects };
};

const settingsCard = (container: HTMLElement, title: string): HTMLElement => {
  const card = Array.from(container.querySelectorAll<HTMLElement>("article.settings-section"))
    .find((candidate) => candidate.querySelector("h2")?.textContent === title);
  if (!card) throw new Error(`no settings card titled ${title}`);
  return card;
};

beforeEach(() => {
  window.localStorage.setItem(localeStorageKey, "en");
});

afterEach(() => {
  cleanup();
  window.localStorage.clear();
});

test("Settings uses a title-only header and keeps the language choice explicit", () => {
  const { container, getByRole, onLocaleChange } = renderSettings({ runtimeAvailable: true });

  expect(getByRole("heading", { level: 1, name: "Settings" })).not.toBeNull();
  expect(container.querySelector(".page-header p")).toBeNull();
  expect(getByRole("group", { name: "Language" })).not.toBeNull();
  expect(getByRole("button", { name: "English" }).getAttribute("aria-pressed")).toBe("true");
  fireEvent.click(getByRole("button", { name: "繁體中文" }));
  expect(onLocaleChange).toHaveBeenCalledWith("zh-TW");
});

test("storage and privacy expose one compact state and one action before closed details", () => {
  const { container, getByRole, onOpenProjects } = renderSettings({ runtimeAvailable: true });
  const card = settingsCard(container, "Storage & privacy");

  expect(card.querySelector(".settings-status-card__primary strong")?.textContent)
    .toBe("Local by default · connections and exports can send data out");
  expect(card.querySelectorAll(":scope > button")).toHaveLength(1);
  fireEvent.click(getByRole("button", { name: "My scans" }));
  expect(onOpenProjects).toHaveBeenCalledOnce();

  const details = card.querySelector<HTMLDetailsElement>("details.settings-details");
  expect(details?.open).toBe(false);
  expect(details?.textContent).toContain("unless you connect a source or choose an export destination");
  expect(details?.textContent).toContain("never widen their scope automatically");
});

test.each([
  { mode: "native" as const, runtimeAvailable: true, state: "ready", status: "Ready at the last check", action: "New scan" },
  { mode: "native" as const, runtimeAvailable: false, state: "unavailable", status: "Some scan tools are unavailable", action: "Choose a scan" },
  { mode: "native" as const, runtimeAvailable: undefined, state: "unchecked", status: "Scan tools not checked yet", action: "Choose a scan" },
  { mode: "demo" as const, runtimeAvailable: true, state: "demo", status: "Preview only · real checks do not run", action: "Open preview" },
])("runtime $state keeps one truthful status and one action", ({ mode, runtimeAvailable, state, status, action }) => {
  const { container, getByRole, onOpenNewScan } = renderSettings({ mode, runtimeAvailable });
  const card = settingsCard(container, "Local scan tools");

  const stateLabel = card.querySelector<HTMLElement>("[data-runtime-state]");
  expect(stateLabel?.dataset.runtimeState).toBe(state);
  expect(stateLabel?.textContent).toBe(status);
  expect(card.querySelectorAll(":scope > button")).toHaveLength(1);
  fireEvent.click(getByRole("button", { name: action }));
  expect(onOpenNewScan).toHaveBeenCalledOnce();
  expect(card.querySelector<HTMLDetailsElement>("details.settings-details")?.open).toBe(false);
});

test("native runtime mechanics and consequences stay in closed details", () => {
  const { container } = renderSettings({ runtimeAvailable: false });
  const card = settingsCard(container, "Local scan tools");
  const details = card.querySelector<HTMLDetailsElement>("details.settings-details");
  const content = details?.textContent ?? "";

  expect(details?.open).toBe(false);
  expect(content).toContain("Retry reuses completed download progress");
  expect(content).toContain("Pause keeps the download");
  expect(content).toContain("Continue resumes it");
  expect(content).toContain("After a required Windows restart");
  expect(content).toContain("appear as Not tested");
  expect(content).not.toContain("Saved projects and reports remain available");
});
