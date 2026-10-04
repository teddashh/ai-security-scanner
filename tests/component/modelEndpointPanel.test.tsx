import { cleanup, fireEvent, render, waitFor } from "@testing-library/react";
import { afterEach, beforeEach, expect, test, vi } from "vitest";
import { ModelEndpointPanel } from "../../src/components/ModelEndpointPanel";
import { I18nProvider, localeStorageKey } from "../../src/i18n";
import type { StartModelCheckInput } from "../../src/types";

beforeEach(() => window.localStorage.setItem(localeStorageKey, "en"));
afterEach(() => { cleanup(); window.localStorage.clear(); });
function panel(nativeMode = true, onStart = vi.fn(async (_input: StartModelCheckInput) => true)) {
  const view = render(<I18nProvider><ModelEndpointPanel nativeMode={nativeMode} onStart={onStart} /></I18nProvider>);
  document.querySelector<HTMLDetailsElement>("details[data-model-check]")!.open = true;
  const endpoint = view.getByLabelText("Chat completions URL");
  const model = view.getByLabelText("Model identifier");
  const key = view.getByLabelText(/^API key for this check/);
  const consent = view.getByRole("checkbox", { name: /I am authorized/ });
  const button = view.getByRole("button", { name: "Start model check" });
  fireEvent.change(endpoint, { target: { value: "https://MODEL.example.test:443/v1/chat/completions" } });
  fireEvent.change(model, { target: { value: "fixture/model" } });
  fireEvent.change(key, { target: { value: "synthetic-key" } });
  return { view, endpoint, model, key, consent, button, onStart };
}

test("exact model and provider-charge consent are required, and changing any coordinates resets consent", () => {
  const p = panel();
  expect((p.button as HTMLInputElement).disabled).toBe(true); fireEvent.click(p.consent); expect((p.button as HTMLInputElement).disabled).toBe(false);
  fireEvent.change(p.model, { target: { value: "different/model" } });
  expect((p.consent as HTMLInputElement).checked).toBe(false); expect((p.button as HTMLInputElement).disabled).toBe(true);
  fireEvent.click(p.consent);
  fireEvent.click(p.view.getByRole("checkbox", { name: /internal or local network/ }));
  expect((p.consent as HTMLInputElement).checked).toBe(false); expect((p.button as HTMLInputElement).disabled).toBe(true);
  fireEvent.change(p.endpoint, { target: { value: "https://key@model.example.test/a" } });
  expect((p.consent as HTMLInputElement).disabled).toBe(true); expect(p.onStart).not.toHaveBeenCalled();
});

test("the opaque key clears before dispatch settles and another check requires a new key and consent", async () => {
  let finish!: (accepted: boolean) => void;
  const onStart = vi.fn((_input: StartModelCheckInput) => new Promise<boolean>((resolve) => { finish = resolve; }));
  const p = panel(true, onStart);
  fireEvent.click(p.consent); fireEvent.click(p.button);
  expect(onStart).toHaveBeenCalledWith(expect.objectContaining({ endpoint: "https://model.example.test/v1/chat/completions", model: "fixture/model", key: "synthetic-key", privateNetwork: false }));
  expect((p.key as HTMLInputElement).value).toBe(""); expect((p.key as HTMLInputElement).disabled).toBe(true);
  expect(window.localStorage.getItem("synthetic-key")).toBeNull();
  finish(false);
  await waitFor(() => expect((p.key as HTMLInputElement).disabled).toBe(false));
  expect((p.consent as HTMLInputElement).checked).toBe(false); expect((p.button as HTMLInputElement).disabled).toBe(true);
  fireEvent.click(p.consent); expect((p.button as HTMLInputElement).disabled).toBe(true);
});

test("browser demonstration cannot transmit model probes", () => {
  const p = panel(false); fireEvent.click(p.consent); fireEvent.click(p.button);
  expect((p.button as HTMLInputElement).disabled).toBe(true); expect(p.onStart).not.toHaveBeenCalled();
});

test.each(["en", "zh-TW"])("the optional panel states native coverage and inference limits in %s", (locale) => {
  window.localStorage.setItem(localeStorageKey, locale);
  const view = render(<I18nProvider><ModelEndpointPanel nativeMode onStart={async () => true} /></I18nProvider>);
  expect(document.querySelector<HTMLDetailsElement>("details[data-model-check]")!.open).toBe(false);
  for (const value of ["54", "64", "150", "9,600", "30"]) expect(view.container.textContent).toContain(value);
  expect(view.container.textContent).toMatch(locale === "en" ? /provider sets the charges/ : /實際費用由服務商計算/);
});
