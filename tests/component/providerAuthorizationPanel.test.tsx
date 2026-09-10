import { cleanup, fireEvent, render, waitFor, within } from "@testing-library/react";
import { afterEach, beforeEach, expect, test, vi } from "vitest";

import { ProviderAuthorizationPanel } from "../../src/components/ProviderAuthorizationPanel";
import { I18nProvider, localeStorageKey } from "../../src/i18n";
import { scannerService } from "../../src/services/scanner";
import { projectSourceCapabilityView } from "../../src/sourceCapabilityPresentation";
import type { ConnectedSource, EngineManifest, InstalledProviderAuthorization } from "../../src/types";

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

const renderPanel = ({
  nativeMode = false,
  onFindAssets = () => Promise.resolve(),
}: {
  nativeMode?: boolean;
  onFindAssets?: () => Promise<void>;
} = {}) =>
  render(
    <I18nProvider>
      <ProviderAuthorizationPanel
        caseId="case-1"
        sources={[microsoft365Source]}
        engineManifests={manifests}
        nativeMode={nativeMode}
        onAuthorizationChanged={() => Promise.resolve()}
        onFindAssets={onFindAssets}
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

const capabilityDisclosure = () => {
  const details = document.querySelector<HTMLDetailsElement>("details.provider-capability");
  expect(details).not.toBeNull();
  return details!;
};

test("the capability disclosure renders one card per projected dimension, in order", () => {
  const projection = projectSourceCapabilityView({
    provider: "microsoft365",
    source: microsoft365Source,
    manifests,
  });
  expect(projection).toBeDefined();

  renderPanel();

  const cards = capabilityDisclosure().querySelectorAll("article.provider-capability-card");
  expect(cards).toHaveLength(projection!.cells.length);
  expect(projection!.cells.length).toBe(6);
});

test("capability information is in one default-collapsed details disclosure", () => {
  renderPanel();

  const disclosures = document.querySelectorAll<HTMLDetailsElement>("details.provider-capability");
  expect(disclosures).toHaveLength(1);
  expect(disclosures[0]?.open).toBe(false);
  expect(disclosures[0]?.querySelector(":scope > summary")?.textContent).toBe("Product capability details");
  expect(disclosures[0]?.querySelector("h3")?.textContent).toBe("What this installed product can inspect");
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

  expect(within(capabilityDisclosure()).getByText(tenantScope).tagName).toBe("CODE");
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

// A closed `<details>` is still in the DOM under jsdom, which has no layout, so
// `textContent` cannot tell a visible sentence from a collapsed one. This is the
// only reading that matters for the tests below: what a user has read by the
// time they decide whether this app can scan their cloud account at all.
const textBeforeAnyDisclosureIsOpened = (root: HTMLElement): string => {
  const clone = root.cloneNode(true) as HTMLElement;
  for (const disclosure of Array.from(clone.querySelectorAll("details"))) {
    const summary = disclosure.querySelector(":scope > summary");
    disclosure.replaceChildren(...(summary ? [summary] : []));
  }
  return clone.textContent ?? "";
};

const setupSection = (): HTMLElement => {
  const section = document.querySelector<HTMLElement>("section.provider-auth-details");
  expect(section).not.toBeNull();
  return section!;
};

const panel = (): HTMLElement => {
  const root = document.querySelector<HTMLElement>("section.provider-auth-panel");
  expect(root).not.toBeNull();
  return root!;
};

test("the unconnected first layer is limited to account, state, CTA, and one safety boundary", () => {
  renderPanel();

  const firstLayer = textBeforeAnyDisclosureIsOpened(panel());
  expect(firstLayer).toContain("Prepare Microsoft 365 sign-in");
  expect(firstLayer).toContain("Not connected");
  expect(firstLayer).toContain("Account to scan");
  expect(firstLayer).toContain("Microsoft 365 · Microsoft 365");
  expect(firstLayer).toContain("Microsoft 365 scanner access is read-only and expires automatically");
  expect(firstLayer).toContain("Starting a scan remains a separate step");
  expect(firstLayer).toContain("Open the connection guide");
  expect(firstLayer).toContain("Product capability details");
  expect(firstLayer.match(/Starting a scan remains a separate step/gu)).toHaveLength(1);
  expect(firstLayer).not.toContain("may create");

  expect(firstLayer).not.toContain("Choose a connection method");
  expect(firstLayer).not.toContain("Your IT team prepares this once");
  expect(firstLayer).not.toContain("What this installed product can inspect");
  expect(firstLayer).not.toContain("Capability definition");
  expect(firstLayer).not.toContain(tenantScope);
  expect(firstLayer).not.toContain("Installed profiles");
  expect(firstLayer).not.toContain("9999-12-31");
  expect(firstLayer).not.toContain("OAuth");
  expect(firstLayer).not.toContain("clientId");
  expect(firstLayer).not.toContain("Ask IT for the setup file");

  expect(setupSection().textContent).toContain("Your IT team prepares this once for your organization");
  expect(setupSection().textContent).toContain(
    "Shared OAuth registration is not provided",
  );
});

test("temporary access distinguishes reviewed IAM setup from read-only scanner activity", () => {
  renderPanel();

  const guide = panel().querySelector<HTMLDetailsElement>("details.provider-connection-guide");
  expect(guide).not.toBeNull();
  guide!.open = true;
  const temporaryAccess = within(guide!).getByRole("button", { name: /Have IT create temporary scan access/ });
  fireEvent.click(temporaryAccess);

  const firstLayer = textBeforeAnyDisclosureIsOpened(panel());
  expect(firstLayer).toContain("scanner access is read-only and expires automatically");
  expect(firstLayer).toContain("The next step lists its dedicated IAM resources before creation");
  expect(firstLayer).not.toContain("does not change cloud resources");
});

test("the IT request is neutral copy and the document fallback completes clipboard copy", async () => {
  const clipboardDescriptor = Object.getOwnPropertyDescriptor(navigator, "clipboard");
  const execCommandDescriptor = Object.getOwnPropertyDescriptor(document, "execCommand");
  const primaryCopy = vi.fn().mockRejectedValue(new Error("clipboard denied"));
  let fallbackCopy = "";
  const execCommand = vi.fn((command: string) => {
    fallbackCopy = document.querySelector<HTMLTextAreaElement>(
      'textarea[aria-hidden="true"]',
    )?.value ?? "";
    return command === "copy";
  });

  try {
    Object.defineProperty(navigator, "clipboard", {
      configurable: true,
      value: { writeText: primaryCopy },
    });
    Object.defineProperty(document, "execCommand", {
      configurable: true,
      value: execCommand,
    });
    renderPanel();

    const guide = panel().querySelector<HTMLDetailsElement>("details.provider-connection-guide");
    expect(guide).not.toBeNull();
    guide!.open = true;
    const request = guide!.querySelector("blockquote")?.textContent ?? "";
    expect(request).toContain(
      "Provide the non-secret Microsoft 365 connection setup JSON for ai-security-scanner",
    );
    expect(request).not.toMatch(/\b(?:me|our)\b/iu);

    const copyButton = within(guide!).getByRole("button", { name: "Copy request for IT" });
    copyButton.focus();
    fireEvent.click(copyButton);

    await waitFor(() => {
      expect(within(guide!).getByRole("status").textContent).toBe("Request copied");
    });
    expect(primaryCopy).toHaveBeenCalledOnce();
    expect(execCommand).toHaveBeenCalledWith("copy");
    expect(fallbackCopy).toContain(request);
    expect(fallbackCopy).toContain('"schema_version": "1.0.0"');
    expect(document.querySelector('textarea[aria-hidden="true"]')).toBeNull();
    expect(document.activeElement).toBe(copyButton);
  } finally {
    if (clipboardDescriptor) {
      Object.defineProperty(navigator, "clipboard", clipboardDescriptor);
    } else {
      Reflect.deleteProperty(navigator, "clipboard");
    }
    if (execCommandDescriptor) {
      Object.defineProperty(document, "execCommand", execCommandDescriptor);
    } else {
      Reflect.deleteProperty(document, "execCommand");
    }
  }
});

test("collapsed capability details preserve exact scope, version, profiles, and support dates", () => {
  const projection = projectSourceCapabilityView({
    provider: "microsoft365",
    source: microsoft365Source,
    manifests,
  })!;

  renderPanel();

  const details = capabilityDisclosure();
  const detailText = details.textContent ?? "";
  expect(details.open).toBe(false);
  expect(detailText).toContain(tenantScope);
  expect(detailText).toContain(`Capability definition ${projection.definitionVersion}`);
  for (const cell of projection.cells) {
    for (const engine of cell.engines) {
      expect(detailText).toContain(engine.profile);
      if (engine.id !== "provider-native-discovery" && engine.supportUntil) {
        expect(detailText).toContain(engine.supportUntil);
      }
    }
  }
});

test("the connected first layer keeps exact account, permission state, expiry, and primary action", async () => {
  const authorization: InstalledProviderAuthorization = {
    schema_version: "1.0.0",
    case_id: "case-1",
    source_id: microsoft365Source.id,
    provider: "microsoft365",
    source_kind: microsoft365Source.kind,
    profile: "microsoft365_tenant_read_only_access_token",
    credential_source: "provider_hosted",
    provider_identity: "aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee",
    permissions: ["inventory", "configuration"],
    expires_at: "2099-05-17T15:00:00.000Z",
    allowed_engine_ids: [],
    max_checkouts: 1,
    safety_notice: "Read-only",
  };
  vi.spyOn(scannerService, "providerAuthorizationStatus").mockResolvedValue({
    data: authorization,
    mode: "native",
  });

  renderPanel({ nativeMode: true });

  await waitFor(() => {
    expect(panel().textContent).toContain("Connected until");
    expect(panel().textContent).toContain("May 17");
  });
  const firstLayer = textBeforeAnyDisclosureIsOpened(panel());
  expect(firstLayer).toContain("Microsoft 365 · Microsoft 365");
  expect(firstLayer).toContain("Continue: find cloud assets");
  expect(firstLayer).toContain("Disconnect account");
  expect(firstLayer).toContain("Microsoft 365 scanner access is read-only and expires automatically");
  expect(firstLayer.match(/Starting a scan remains a separate step/gu)).toHaveLength(1);
  expect(firstLayer).not.toContain("Cloud scan connected");
  expect(firstLayer).not.toContain("Sign-in is ready");
  expect(firstLayer).not.toContain("What this installed product can inspect");
  expect(firstLayer).not.toContain(tenantScope);
});

test("the Traditional Chinese first layer keeps the same concise safety boundary", () => {
  window.localStorage.setItem(localeStorageKey, "zh-TW");
  renderPanel();

  const firstLayer = textBeforeAnyDisclosureIsOpened(panel());
  expect(firstLayer).toContain("尚未連接");
  expect(firstLayer).toContain("要掃描的帳號");
  expect(firstLayer).toContain("掃描存取只有讀取權限，並會自動到期");
  expect(firstLayer).toContain("開始掃描是另一個獨立步驟");
  expect(firstLayer).toContain("開啟連線指南");
  expect(firstLayer).toContain("產品能力詳細資料");
  expect(firstLayer).not.toContain("目前安裝版本可檢查的項目");
});
