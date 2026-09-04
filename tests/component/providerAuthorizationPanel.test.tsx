import { cleanup, render, within } from "@testing-library/react";
import { afterEach, beforeEach, expect, test } from "vitest";

import { ProviderAuthorizationPanel } from "../../src/components/ProviderAuthorizationPanel";
import { I18nProvider, localeStorageKey } from "../../src/i18n";
import { projectSourceCapabilityView } from "../../src/sourceCapabilityPresentation";
import type { ConnectedSource, EngineManifest } from "../../src/types";

// The capability matrix itself is covered by tests/frontend. What was never
// covered is that the matrix reaches the screen: `node --experimental-strip-types`
// cannot import a `.tsx` file, so every frontend test asserts on component
// source text instead of rendered output, and this JSX had never executed.
// These tests therefore compare the rendered DOM against the projection rather
// than restating the matrix, so they fail on a render regression without
// duplicating an assertion that already has a home.

const tenantScope = "microsoft365-tenant:aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee";

const microsoft365Source: ConnectedSource = {
  id: "source-m365",
  kind: "microsoft365_tenant",
  label: "Microsoft 365",
  status: "connected",
  readOnly: true,
  providerBinding: {
    profile: "microsoft365_tenant_read_only_access_token",
    resourceScope: tenantScope,
  },
};

const manifest = (
  id: string,
  providers: EngineManifest["supportedProviders"],
  overrides: Partial<EngineManifest> = {},
): EngineManifest => ({
  id,
  name: id,
  category: "cloud_configuration",
  version: "1.0.0",
  imageDigest: `sha256:${id}`,
  license: "Apache-2.0",
  redistribution: "on_demand",
  platforms: providers,
  supportedProviders: providers,
  status: "ready",
  runnable: true,
  blockedBy: [],
  compatibilityValid: true,
  providerExecutionProfiles: [],
  supportUntil: "9999-12-31",
  supportStatus: "supported",
  ...overrides,
});

// Mirrors the shipped posture: both managed Microsoft 365 engines are awaiting
// immutable publication, so neither is runnable.
const manifests = [
  manifest("scubagear", ["m365"], { status: "not_downloaded", runnable: false }),
  manifest("maester", ["m365"], { status: "not_downloaded", runnable: false }),
];

const renderPanel = () =>
  render(
    <I18nProvider>
      <ProviderAuthorizationPanel
        caseId="case-1"
        sources={[microsoft365Source]}
        engineManifests={manifests}
        nativeMode={false}
        onAuthorizationChanged={() => Promise.resolve()}
        onFindAssets={() => Promise.resolve()}
      />
    </I18nProvider>,
  );

beforeEach(() => {
  // `nativeMode` is false so no Tauri call is reachable, but the locale must be
  // pinned or the rendered copy follows whatever languages jsdom advertises.
  window.localStorage.setItem(localeStorageKey, "en");
});

afterEach(() => {
  cleanup();
  window.localStorage.clear();
});

// The section is named by `aria-labelledby`, so it has no stable locale
// independent accessible name to query on. Its class is the stable hook.
const capabilitySection = () => {
  const section = document.querySelector<HTMLElement>("section.provider-capability");
  expect(section).not.toBeNull();
  return section!;
};

test("the capability section renders one card per projected dimension, in order", () => {
  const projection = projectSourceCapabilityView({
    provider: "microsoft365",
    source: microsoft365Source,
    manifests,
  });
  expect(projection).toBeDefined();

  renderPanel();

  const cards = capabilitySection().querySelectorAll("article.provider-capability-card");
  expect(cards).toHaveLength(projection!.cells.length);
  expect(projection!.cells.length).toBe(6);
});

test("the capability section is a region named by its own heading", () => {
  renderPanel();

  const section = capabilitySection();
  const heading = document.getElementById(section.getAttribute("aria-labelledby") ?? "");
  expect(heading?.tagName).toBe("H3");
  expect(heading?.textContent?.trim()).toBeTruthy();
});

test("each card carries the state the projection assigned to that dimension", () => {
  const projection = projectSourceCapabilityView({
    provider: "microsoft365",
    source: microsoft365Source,
    manifests,
  })!;

  renderPanel();

  const cards = Array.from(
    document.querySelectorAll("article.provider-capability-card"),
  );
  // The state reaches the DOM only as a class modifier, which is also the hook
  // the stylesheet uses to colour the card. Asserting it here is locale
  // independent and fails if the projection is ever rendered against the wrong
  // dimension, which reordering alone would not reveal.
  expect(cards.map((card) => card.className)).toEqual(
    projection.cells.map(
      (cell) => `provider-capability-card provider-capability-card--${cell.state}`,
    ),
  );
});

test("the tenant scope is shown verbatim rather than as an unknown-scope fallback", () => {
  renderPanel();

  expect(within(capabilitySection()).getByText(tenantScope).tagName).toBe("CODE");
});

test("every rendered card resolves its copy instead of leaking a translation key", () => {
  renderPanel();

  const cards = Array.from(
    document.querySelectorAll("article.provider-capability-card"),
  );
  expect(cards.length).toBeGreaterThan(0);
  for (const card of cards) {
    const heading = card.querySelector("h4");
    expect(heading?.textContent?.trim()).toBeTruthy();
    // A missing bilingual entry surfaces as the raw key, which reads as copy to
    // a source-text assertion but is obvious once the component actually runs.
    expect(heading?.textContent).not.toMatch(/^capability[A-Z]/u);
  }
});
