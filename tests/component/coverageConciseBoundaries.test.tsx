import { cleanup, fireEvent, render, waitFor, within } from "@testing-library/react";
import { afterEach, beforeEach, expect, test, vi } from "vitest";

import { CoveragePage } from "../../src/pages/CoveragePage";
import { I18nProvider, localeStorageKey } from "../../src/i18n";
import { scannerService } from "../../src/services/scanner";
import type { Asset, BootstrapCleanupObligationSummary, ConnectedSource, CoverageRecord, InstalledProviderAuthorization } from "../../src/types";

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

type RouteOptions = Pick<React.ComponentProps<typeof CoveragePage>, "assessmentIntent" | "requestedActivities" | "assets"> & {
  caseId?: string;
  sources?: ConnectedSource[];
  coverage?: CoverageRecord[];
  nativeMode?: boolean;
  onStartScan?: React.ComponentProps<typeof CoveragePage>["onStartScan"];
};

const routeElement = ({
  caseId = "case-1",
  assessmentIntent,
  requestedActivities,
  assets,
  coverage = [],
  sources = [],
  nativeMode = true,
  onStartScan = () => Promise.resolve(true),
}: RouteOptions) => (
  <I18nProvider>
    <CoveragePage
      caseId={caseId}
      assessmentIntent={assessmentIntent}
      requestedActivities={requestedActivities}
      coverage={coverage}
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
  </I18nProvider>
);

const renderRoute = (options: RouteOptions) => render(routeElement(options));

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

test("existing inputs collapse source setup without unmounting the cloud panel", () => {
  const source: ConnectedSource = {
    id: "source-aws",
    kind: "aws_organization",
    label: "Production AWS",
    status: "not_connected",
    readOnly: true,
  };
  vi.spyOn(scannerService, "providerAuthorizationStatus").mockResolvedValue({
    data: null,
    mode: "native",
  });
  const { container, getByRole } = renderRoute({
    assessmentIntent: undefined,
    requestedActivities: [],
    assets: [pendingAsset({ name: "existing-project" })],
    sources: [source],
  });

  const setup = container.querySelector<HTMLDetailsElement>(".coverage-source-setup");
  expect(setup).not.toBeNull();
  expect(setup!.open).toBe(false);
  expect(setup!.querySelectorAll(".coverage-input-card")).toHaveLength(4);
  const providerSlot = setup!.querySelector<HTMLElement>(".coverage-provider-slot");
  const providerPanel = providerSlot?.querySelector(".provider-auth-panel");
  expect(providerSlot?.hidden).toBe(true);
  expect(providerPanel).not.toBeNull();

  fireEvent.click(setup!.querySelector("summary")!);
  expect(setup!.open).toBe(true);
  fireEvent.click(getByRole("button", { name: "Connect a cloud account" }));
  expect(providerSlot?.hidden).toBe(false);
  fireEvent.click(getByRole("button", { name: "Close cloud setup" }));
  expect(providerSlot?.hidden).toBe(true);
  expect(providerSlot?.querySelector(".provider-auth-panel")).toBe(providerPanel);
});

test("a collapsed source setup keeps unresolved temporary-cloud cleanup visible and directly reviewable", async () => {
  const source: ConnectedSource = {
    id: "source-aws",
    kind: "aws_organization",
    label: "Production AWS",
    status: "not_connected",
    readOnly: true,
  };
  const obligation: BootstrapCleanupObligationSummary = {
    operationId: "bootstrap-1",
    provider: "aws",
    caseId: "case-1",
    schemaVersion: "1.0.0",
    status: "pending",
    totalItems: 1,
    pendingItems: 1,
    inProgressItems: 0,
    retryableItems: 0,
    waitingItems: 0,
    completedItems: 0,
    createdAt: "2026-09-07T12:00:00Z",
  };
  vi.spyOn(scannerService, "providerAuthorizationStatus").mockResolvedValue({ data: null, mode: "native" });
  vi.spyOn(scannerService, "listProviderBootstrapCleanup").mockResolvedValue({ data: [obligation], mode: "native" });

  const { container, getByRole, getByText } = renderRoute({
    assessmentIntent: undefined,
    requestedActivities: [],
    assets: [pendingAsset({ name: "existing-project" })],
    sources: [source],
  });

  const setup = container.querySelector<HTMLDetailsElement>(".coverage-source-setup")!;
  expect(setup.open).toBe(false);
  await waitFor(() => expect(setup.querySelector("summary")?.textContent).toBe("Temporary cloud cleanup needs attention"));
  const attentionTitle = getByText("Temporary cloud access needs cleanup");
  expect(attentionTitle.closest("[role='alert']")).not.toBeNull();

  fireEvent.click(getByRole("button", { name: "Review cleanup" }));
  expect(setup.open).toBe(true);
  expect(container.querySelector<HTMLElement>(".coverage-provider-slot")?.hidden).toBe(false);
  expect(getByRole("heading", { name: "Earlier setup work still has a cleanup record" })).not.toBeNull();
  expect(getByRole("button", { name: "Reconnect and continue cleanup" })).not.toBeNull();
  const cleanupRegion = getByRole("region", { name: "Temporary-access cleanup" });
  await waitFor(() => expect(document.activeElement).toBe(cleanupRegion));
});

test("an unresolved cleanup record remains actionable when its provider source is missing", async () => {
  const obligation: BootstrapCleanupObligationSummary = {
    operationId: "bootstrap-missing-source",
    provider: "aws",
    caseId: "case-1",
    schemaVersion: "1.0.0",
    status: "pending",
    totalItems: 1,
    pendingItems: 1,
    inProgressItems: 0,
    retryableItems: 0,
    waitingItems: 0,
    completedItems: 0,
    createdAt: "2026-09-07T12:00:00Z",
  };
  vi.spyOn(scannerService, "listProviderBootstrapCleanup").mockResolvedValue({ data: [obligation], mode: "native" });

  const { container, getByRole, getByText } = renderRoute({
    assessmentIntent: undefined,
    requestedActivities: [],
    assets: [pendingAsset({ name: "existing-project" })],
    sources: [],
  });

  const setup = container.querySelector<HTMLDetailsElement>(".coverage-source-setup")!;
  await waitFor(() => expect(setup.querySelector("summary")?.textContent).toBe("Temporary cloud cleanup needs attention"));
  fireEvent.click(getByRole("button", { name: "Review cleanup" }));

  expect(getByText("Use Add an inventory file above to add the matching cloud account. Then return here to reconnect and remove only its recorded temporary resources.")).not.toBeNull();
  expect(getByRole("heading", { name: "Earlier setup work still has a cleanup record" })).not.toBeNull();
  expect((getByRole("button", { name: "Select the AWS source first" }) as HTMLButtonElement).disabled).toBe(true);
  const cleanupRegion = getByRole("region", { name: "Temporary-access cleanup" });
  await waitFor(() => expect(document.activeElement).toBe(cleanupRegion));
});

test("a failed cleanup lookup remains actionable without a provider source and offers a retry", async () => {
  const cleanupLookup = vi.spyOn(scannerService, "listProviderBootstrapCleanup")
    .mockRejectedValueOnce(new Error("private backend detail"))
    .mockResolvedValue({ data: [], mode: "native" });

  const { container, getByRole, getByText, queryByText } = renderRoute({
    assessmentIntent: undefined,
    requestedActivities: [],
    assets: [pendingAsset({ name: "existing-project" })],
    sources: [],
  });

  const setup = container.querySelector<HTMLDetailsElement>(".coverage-source-setup")!;
  await waitFor(() => expect(setup.querySelector("summary")?.textContent).toBe("Temporary cloud cleanup needs attention"));
  fireEvent.click(getByRole("button", { name: "Review cleanup" }));
  expect(getByText("Use Add an inventory file above to add the matching cloud account. Then return here to reconnect and remove only its recorded temporary resources.")).not.toBeNull();
  const cleanupError = getByText("We could not check whether an earlier temporary setup still needs cleanup.").closest<HTMLElement>("[role='alert']")!;
  expect(cleanupError).not.toBeNull();
  const cleanupRegion = getByRole("region", { name: "Temporary-access cleanup" });
  await waitFor(() => expect(document.activeElement).toBe(cleanupRegion));

  fireEvent.click(within(cleanupError).getByRole("button", { name: "Check cleanup again" }));
  await waitFor(() => expect(cleanupLookup).toHaveBeenCalledTimes(2));
  await waitFor(() => expect(queryByText("We could not check whether an earlier temporary setup still needs cleanup.")).toBeNull());
  expect(setup.querySelector("summary")?.textContent).toBe("Add or change source");
});

test("changing scan projects remounts and clears the hidden provider subtree", () => {
  const sources: ConnectedSource[] = [
    {
      id: "source-aws",
      kind: "aws_organization",
      label: "Production AWS",
      status: "not_connected",
      readOnly: true,
    },
    {
      id: "source-m365",
      kind: "microsoft365_tenant",
      label: "Microsoft 365",
      status: "not_connected",
      readOnly: true,
    },
  ];
  const route = {
    assessmentIntent: undefined,
    requestedActivities: [],
    assets: [pendingAsset({ name: "existing-project" })],
    sources,
    nativeMode: false,
  } satisfies RouteOptions;
  const { container, getByLabelText, rerender } = renderRoute({ ...route, caseId: "case-1" });

  const firstPanel = container.querySelector(".provider-auth-panel");
  const firstSelect = getByLabelText("Account to scan") as HTMLSelectElement;
  fireEvent.change(firstSelect, { target: { value: "source-m365" } });
  expect(firstSelect.value).toBe("source-m365");

  rerender(routeElement({ ...route, caseId: "case-2" }));

  const nextPanel = container.querySelector(".provider-auth-panel");
  const nextSelect = getByLabelText("Account to scan") as HTMLSelectElement;
  expect(nextPanel).not.toBe(firstPanel);
  expect(nextSelect.value).toBe("source-aws");
});

test("a fresh project keeps all source choices visible", () => {
  const { container } = renderRoute({
    assessmentIntent: undefined,
    requestedActivities: [],
    assets: [],
  });

  const setup = container.querySelector<HTMLDetailsElement>(".coverage-source-setup");
  expect(setup?.open).toBe(true);
  expect(setup?.querySelector("summary")?.textContent).toBe("Add or change source");
  expect(setup?.querySelectorAll(".coverage-input-card")).toHaveLength(4);
});

test("review uses compact summary chips and keeps missing-source truth visible", () => {
  const unknownSource: CoverageRecord = {
    id: "coverage-unknown",
    label: "AWS inventory",
    platform: "aws",
    sourceKind: "aws_organization",
    state: "source_unavailable_unknown",
    assetCount: 0,
    detail: "not connected",
  };
  const { container, queryByText } = renderRoute({
    assessmentIntent: undefined,
    requestedActivities: [],
    assets: [pendingAsset({
      name: "existing-project",
      coverageState: "discovered_authorized_scanned",
      authorizationState: "authorized",
      allowedModes: ["inventory"],
      scanAttempted: true,
    })],
    coverage: [unknownSource],
  });

  const step = container.querySelector("#coverage-step-2");
  expect(step?.querySelector(".coverage-step-heading p")).toBeNull();
  expect(step?.querySelector(".coverage-step-heading .button")).toBeNull();
  expect(step?.querySelectorAll(".metric-card")).toHaveLength(0);
  expect(step?.querySelector(".coverage-summary-row")?.textContent).toContain("Items found1");
  expect(step?.querySelector(".coverage-summary-row")?.textContent).toContain("Items fully checked1");
  expect(step?.querySelector(".coverage-summary-row")?.textContent).not.toContain("Checks completed");
  expect(queryByText("Sources still needing data: 1")).not.toBeNull();
  expect(container.querySelector(".page-header p")).toBeNull();
});

test("many assets render as compact selectable rows with closed technical details", () => {
  const assets = Array.from({ length: 8 }, (_, index) => pendingAsset({
    id: `asset-${index + 1}`,
    name: `project-${index + 1}`,
  }));
  const { container } = renderRoute({
    assessmentIntent: undefined,
    requestedActivities: [],
    assets,
  });

  const list = container.querySelector(".asset-review-list--compact");
  expect(list?.getAttribute("role")).toBe("list");
  expect(list?.querySelectorAll(".asset-review-card--list-row")).toHaveLength(8);
  expect(list?.querySelectorAll(".asset-review-card__next")).toHaveLength(0);
  expect(list?.querySelectorAll(".asset-review-card__next-inline")).toHaveLength(8);
  expect(Array.from(list?.querySelectorAll<HTMLDetailsElement>(".asset-review-card__technical") ?? [])
    .every((details) => details.open === false)).toBe(true);
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
  expect(container.querySelector<HTMLElement>("#coverage-step-1")?.hidden).toBe(true);
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
  expect(container.querySelector<HTMLElement>("#coverage-step-1")?.hidden).toBe(false);
  expect(container.querySelector("#coverage-step-2")).not.toBeNull();
  const backToReview = Array.from(pageHeader?.querySelectorAll<HTMLButtonElement>("button") ?? [])
    .find((button) => button.textContent?.includes("Back to review"));
  expect(backToReview).toBeTruthy();
  fireEvent.click(backToReview!);
  expect(container.querySelector<HTMLElement>("#coverage-step-1")?.hidden).toBe(true);
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
