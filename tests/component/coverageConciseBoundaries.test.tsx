import { cleanup, fireEvent, render, waitFor, within } from "@testing-library/react";
import { afterEach, beforeEach, expect, test, vi } from "vitest";

import { CoveragePage } from "../../src/pages/CoveragePage";
import { I18nProvider, localeStorageKey } from "../../src/i18n";
import { scannerService } from "../../src/services/scanner";
import type { Asset, ConnectedSource, InstalledProviderAuthorization } from "../../src/types";

const pendingAsset = (overrides: Partial<Asset>): Asset => ({
  id: "asset-1",
  name: "asset-1",
  type: "repository",
  platform: "code",
  locator: "private-copy://asset-1",
  coverageState: "discovered_not_authorized",
  authorizationState: "pending",
  allowedModes: [],
  findingCount: 0,
  scanAttempted: false,
  ...overrides,
});

const renderRoute = ({
  assessmentIntent,
  requestedActivities,
  assets,
  sources = [],
  nativeMode = true,
  onStartScan = () => Promise.resolve(true),
}: Pick<React.ComponentProps<typeof CoveragePage>, "assessmentIntent" | "requestedActivities" | "assets"> & {
  sources?: ConnectedSource[];
  nativeMode?: boolean;
  onStartScan?: React.ComponentProps<typeof CoveragePage>["onStartScan"];
}) => render(
  <I18nProvider>
    <CoveragePage
      caseId="case-1"
      assessmentIntent={assessmentIntent}
      requestedActivities={requestedActivities}
      coverage={[]}
      sources={sources}
      engineManifests={[]}
      assets={assets}
      scopeGrants={[]}
      nativeMode={nativeMode}
      onChooseSnapshot={() => Promise.resolve(null)}
      onConnectSourceSnapshot={() => Promise.resolve()}
      onChooseWorkspace={() => Promise.resolve(null)}
      onAttachWorkspaceSnapshot={() => Promise.resolve(true)}
      onStartDiscovery={() => Promise.resolve()}
      onAuthorizationChanged={() => Promise.resolve()}
      onStartScan={onStartScan}
    />
  </I18nProvider>,
);

beforeEach(() => {
  window.localStorage.setItem(localeStorageKey, "en");
  Object.defineProperty(window, "requestAnimationFrame", {
    configurable: true,
    value: (callback: FrameRequestCallback) => window.setTimeout(() => callback(performance.now()), 0),
  });
  Object.defineProperty(window, "cancelAnimationFrame", {
    configurable: true,
    value: (handle: number) => window.clearTimeout(handle),
  });
  Object.defineProperty(HTMLElement.prototype, "scrollIntoView", {
    configurable: true,
    value: () => undefined,
  });
});

afterEach(() => {
  cleanup();
  window.localStorage.clear();
});

test("guided local Start keeps the exact copy, read-only check, and unchanged-source boundary visible", async () => {
  const { container } = renderRoute({
    assessmentIntent: "source_code",
    requestedActivities: ["local_artifact_analysis"],
    assets: [pendingAsset({
      name: "source-tree-copy",
      localInputProfile: "repository_working_tree",
    })],
  });

  await waitFor(() => {
    expect(container.querySelector(".coverage-guided-boundary")?.textContent).toBe(
      "Saved copy: source-tree-copy · Read-only checks: Review the saved local copy. The original source stays unchanged.",
    );
  });
  expect(container.querySelector(".scope-mode-fieldset")).toBeNull();
});

test("guided cloud Start keeps the exact signed-in account, checks, and no-change boundary visible", async () => {
  const source: ConnectedSource = {
    id: "source-aws",
    kind: "aws_organization",
    label: "Production AWS",
    status: "connected",
    readOnly: true,
  };
  const authorization: InstalledProviderAuthorization = {
    schema_version: "1.0.0",
    case_id: "case-1",
    source_id: source.id,
    provider: "aws",
    source_kind: source.kind,
    profile: "aws_read_only_role",
    credential_source: "provider_hosted",
    provider_identity: "123456789012",
    permissions: ["inventory", "configuration"],
    expires_at: "2099-01-01T00:00:00.000Z",
    allowed_engine_ids: [],
    max_checkouts: 1,
    safety_notice: "Read-only",
  };
  vi.spyOn(scannerService, "providerAuthorizationStatus").mockResolvedValue({
    data: authorization,
    mode: "native",
  });

  const { container } = renderRoute({
    assessmentIntent: "cloud_account",
    requestedActivities: ["configuration_assessment"],
    sources: [source],
    assets: [pendingAsset({
      name: "Production AWS (123456789012)",
      type: "cloud_account",
      platform: "aws",
      locator: "aws://123456789012",
      discoveredFromSourceIds: [source.id],
    })],
  });

  await waitFor(() => {
    expect(container.querySelector(".coverage-guided-boundary")?.textContent).toBe(
      "Signed-in account: Production AWS (123456789012) · Read-only checks: Read-only inventory, Review settings. No cloud settings or data will be changed.",
    );
  });
  const advanced = container.querySelector<HTMLDetailsElement>(".coverage-scan-type-advanced");
  expect(advanced).not.toBeNull();
  expect(advanced?.open).toBe(false);
});

test("browser-preview website flow keeps one concise boundary and starts without another form", async () => {
  const onStartScan = vi.fn().mockResolvedValue(true);
  const { container, queryByText } = renderRoute({
    assessmentIntent: "deployed_website",
    requestedActivities: ["low_impact_external_checks"],
    nativeMode: false,
    onStartScan,
    assets: [pendingAsset({
      id: "asset-example",
      name: "example.com",
      type: "domain",
      platform: "external",
      locator: "example.com",
      identifiers: [{ namespace: "dns_name", value: "example.com" }],
      internetExposed: true,
      declaredWebService: { protocol: "https", port: 443, path: "/" },
    })],
  });

  await waitFor(() => {
    expect(container.querySelector(".coverage-guided-boundary")?.textContent).toBe(
      "example.com · HTTPS 443 · max 25/s · 10 concurrent · 3s timeout. No exploitation, credentials, destructive actions, or added targets. Start confirms authorization.",
    );
  });

  const pageHeader = container.querySelector(".page-header");
  expect(pageHeader?.querySelector("h1")?.textContent).toBe("Review and start");
  expect(pageHeader?.querySelector("p")?.textContent).toBe("Confirm the target and limits.");
  expect(container.querySelector("#coverage-step-1")).toBeNull();
  expect(container.querySelector("#coverage-step-2")).toBeNull();
  expect(Array.from(container.querySelectorAll("button")).filter((button) => button.textContent?.trim() === "Refresh items")).toHaveLength(0);
  expect(queryByText("1 selected")).toBeNull();
  expect(container.querySelector(".scope-confirmation-panel__heading")).toBeNull();
  expect(container.querySelector(".scope-confirmation-panel__assets")).toBeNull();
  expect(container.querySelector(".asset-review-list")).toBeNull();
  expect(container.querySelector(".coverage-scan-type-advanced")).toBeNull();
  expect(queryByText("Use a different scan type (advanced)")).toBeNull();
  expect(queryByText("I confirm this is my website or a system I am allowed to scan")).toBeNull();
  expect(queryByText("Note (optional)")).toBeNull();

  const advancedSettings = container.querySelectorAll<HTMLDetailsElement>("details.coverage-scan-advanced");
  expect(advancedSettings).toHaveLength(1);
  const advancedSummary = advancedSettings[0]?.querySelector("summary");
  expect(advancedSummary?.textContent).toContain("Advanced scan settings");
  fireEvent.click(advancedSummary!);
  expect(advancedSettings[0]?.open).toBe(true);
  expect((within(advancedSettings[0]).getByLabelText(/Website or system to check/) as HTMLSelectElement).value).toBe("example.com");
  expect((within(advancedSettings[0]).getByLabelText(/Allowed ports/) as HTMLInputElement).value).toBe("443");

  const editInputs = Array.from(pageHeader?.querySelectorAll<HTMLButtonElement>("button") ?? [])
    .find((button) => button.textContent?.includes("Edit inputs"));
  expect(editInputs).toBeTruthy();
  fireEvent.click(editInputs!);
  expect(container.querySelector("#coverage-step-1")).not.toBeNull();
  expect(container.querySelector("#coverage-step-2")).not.toBeNull();
  const backToReview = Array.from(pageHeader?.querySelectorAll<HTMLButtonElement>("button") ?? [])
    .find((button) => button.textContent?.includes("Back to review"));
  expect(backToReview).toBeTruthy();
  fireEvent.click(backToReview!);
  expect(container.querySelector("#coverage-step-1")).toBeNull();
  expect(container.querySelector("#coverage-step-2")).toBeNull();

  const start = Array.from(container.querySelectorAll<HTMLButtonElement>(".scope-confirmation-panel button[type='submit']"))
    .find((button) => button.textContent?.includes("Confirm and start scan"));
  expect(start).toBeTruthy();
  expect(start!.disabled).toBe(false);
  fireEvent.click(start!);

  expect(onStartScan).toHaveBeenCalledTimes(1);
  expect(onStartScan).toHaveBeenCalledWith(
    ["asset-example"],
    ["low_impact_external"],
    "The user explicitly confirmed this exact low-impact network target in the guided local interface.",
    expect.objectContaining({
      target: "example.com",
      protocol: "https",
      ports: [443],
      activity: "low_impact_external",
      ratePolicy: {
        requestsPerSecond: 25,
        concurrency: 10,
        timeoutSeconds: 3,
      },
    }),
  );
}, 15_000);

test("public-record mode keeps the exact website and honest no-contact boundary visible", async () => {
  const { container } = renderRoute({
    assessmentIntent: "deployed_website",
    requestedActivities: [],
    nativeMode: false,
    assets: [pendingAsset({
      id: "asset-public-records",
      name: "example.com",
      type: "domain",
      platform: "external",
      locator: "example.com",
      identifiers: [{ namespace: "dns_name", value: "example.com" }],
      internetExposed: true,
      declaredWebService: { protocol: "https", port: 443, path: "/" },
    })],
  });

  await waitFor(() => expect(container.querySelector(".scope-mode-fieldset")).not.toBeNull());
  const publicRecordsMode = Array.from(container.querySelectorAll<HTMLLabelElement>(".scope-mode-card"))
    .find((label) => label.textContent?.includes("Use public records"))
    ?.querySelector<HTMLInputElement>("input");
  expect(publicRecordsMode).toBeTruthy();
  fireEvent.click(publicRecordsMode!);

  expect(container.querySelector(".page-header h1")?.textContent).toBe("Set up scan");
  expect(container.querySelector("#coverage-step-1")).not.toBeNull();
  expect(container.querySelector("#coverage-step-2")).not.toBeNull();
  expect(container.querySelector(".scope-confirmation-panel__assets")?.textContent).toContain("example.com");
  expect(container.querySelector(".asset-review-list")?.textContent).toContain("example.com");
  expect(container.querySelector(".asset-review-list input")?.getAttribute("aria-label")).toBe("Choose example.com");
  expect(container.querySelector(".form-actions p")?.textContent).toContain(
    "This saves the boundary and starts a scan. The selected system will not be contacted. No check in this version reads public records, so this permission on its own adds nothing to what is tested.",
  );
  expect(Array.from(container.querySelectorAll<HTMLButtonElement>(".scope-confirmation-panel button[type='submit']"))
    .some((button) => button.textContent?.includes("Start without contacting this system"))).toBe(true);
}, 15_000);
