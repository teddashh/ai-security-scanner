import { cleanup, fireEvent, render, waitFor, within } from "@testing-library/react";
import { afterEach, beforeEach, expect, test, vi } from "vitest";

import { CoveragePage } from "../../src/pages/CoveragePage";
import { I18nProvider, localeStorageKey } from "../../src/i18n";
import { scannerService } from "../../src/services/scanner";
import type { Asset, BootstrapCleanupObligationSummary, ConnectedSource, CoverageRecord, InstalledProviderAuthorization } from "../../src/types";
import { internalDeviceHttpsProfile } from "../../src/internalDeviceProfile";
import { internalEndpointProfiles } from "../../src/internalEndpointProfile";
import { internalHostGreenboneProfile } from "../../src/internalHostProfile";
import { websiteQuickProfile } from "../../src/websiteQuickProfile";

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
  busy?: boolean;
  runtimeSetupNotice?: React.ReactNode;
  onStartScan?: React.ComponentProps<typeof CoveragePage>["onStartScan"];
  onStartEnvironmentScan?: React.ComponentProps<typeof CoveragePage>["onStartEnvironmentScan"];
};

const routeElement = ({
  caseId = "case-1",
  assessmentIntent,
  requestedActivities,
  assets,
  coverage = [],
  sources = [],
  nativeMode = true,
  busy = false,
  runtimeSetupNotice,
  onStartScan = () => Promise.resolve(true),
  onStartEnvironmentScan = () => Promise.resolve(true),
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
      busy={busy}
      runtimeSetupNotice={runtimeSetupNotice}
      onChooseSnapshot={() => Promise.resolve(null)}
      onConnectSourceSnapshot={() => Promise.resolve()}
      onChooseWorkspace={() => Promise.resolve(null)}
      onAttachWorkspaceSnapshot={() => Promise.resolve(true)}
      onStartDiscovery={() => Promise.resolve()}
      onAuthorizationChanged={() => Promise.resolve()}
      onStartScan={onStartScan}
      onStartEnvironmentScan={onStartEnvironmentScan}
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
  const cleanupError = getByText("Temporary-access cleanup status unavailable. Check again.").closest<HTMLElement>("[role='alert']")!;
  expect(cleanupError).not.toBeNull();
  const cleanupRegion = getByRole("region", { name: "Temporary-access cleanup" });
  await waitFor(() => expect(document.activeElement).toBe(cleanupRegion));

  fireEvent.click(within(cleanupError).getByRole("button", { name: "Check cleanup again" }));
  await waitFor(() => expect(cleanupLookup).toHaveBeenCalledTimes(2));
  await waitFor(() => expect(queryByText("Temporary-access cleanup status unavailable. Check again.")).toBeNull());
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

test("a host-shaped local snapshot keeps local guidance instead of external-target guidance", () => {
  const { queryByText, getByText } = renderRoute({
    assessmentIntent: undefined,
    requestedActivities: ["local_artifact_analysis"],
    assets: [pendingAsset({
      id: "node-snapshot",
      name: "saved-node-settings",
      type: "service",
      platform: "external",
      locator: "private-copy://node-snapshot",
      internetExposed: false,
      localInputProfile: "kubernetes_node_snapshot",
      scanAttempted: true,
    })],
  });

  expect(getByText("Allow offline review of this saved Kubernetes input only.")).not.toBeNull();
  expect(queryByText(/Confirm this is your internal system/u)).toBeNull();
});

test("guided local Start keeps the exact copy, read-only check, and unchanged-source boundary visible", async () => {
  const onStartScan = vi.fn().mockResolvedValue(true);
  const { container } = renderRoute({
    assessmentIntent: "source_code",
    requestedActivities: ["local_artifact_analysis"],
    onStartScan,
    assets: [pendingAsset({
      name: "source-tree-copy",
      localInputProfile: "repository_working_tree",
    })],
  });

  await waitFor(() => {
    expect(container.querySelector(".coverage-guided-boundary")?.textContent).toBe(
      "Saved copy: source-tree-copy · Read-only checks: Review the saved local copy.",
    );
  });
  expect(container.querySelector(".coverage-review-timing")?.textContent).toBe(
    "Timing target: a useful result within minutes after tools are ready.",
  );
  expect(container.querySelector(".scope-mode-fieldset")).toBeNull();

  const start = Array.from(container.querySelectorAll<HTMLButtonElement>(".scope-confirmation-panel button[type='submit']"))
    .find((button) => button.textContent?.includes("Confirm and start scan"));
  expect(start).toBeTruthy();
  fireEvent.click(start!);

  expect(onStartScan).toHaveBeenCalledWith(
    ["asset-1"],
    ["local_artifact"],
    "The user explicitly selected this saved local copy and confirmed the recommended read-only checks.",
    undefined,
    ["gitleaks", "semgrep", "syft", "trivy", "grype", "trufflehog", "kics", "checkov"],
  );
});

test("guided container Start routes Syft inventory with Trivy and Grype vulnerability checks", async () => {
  const onStartScan = vi.fn().mockResolvedValue(true);
  const { container, getByText } = renderRoute({
    assessmentIntent: "container_image",
    requestedActivities: ["local_artifact_analysis"],
    onStartScan,
    assets: [pendingAsset({
      name: "payments-image-copy",
      type: "image",
      platform: "container",
      localInputProfile: "container_image_oci_layout",
    })],
  });

  expect(getByText(
    "Pick one exported OCI image folder. Syft inventories its software components, while Trivy and Grype check them for known vulnerabilities. Everything runs locally without starting the image.",
  )).not.toBeNull();

  await waitFor(() => {
    expect(container.querySelector(".coverage-guided-boundary")?.textContent).toBe(
      "Saved copy: payments-image-copy · Read-only checks: Review the saved local copy.",
    );
  });

  const start = Array.from(container.querySelectorAll<HTMLButtonElement>(".scope-confirmation-panel button[type='submit']"))
    .find((button) => button.textContent?.includes("Confirm and start scan"));
  expect(start).toBeTruthy();
  fireEvent.click(start!);

  expect(onStartScan).toHaveBeenCalledWith(
    ["asset-1"],
    ["local_artifact"],
    "The user explicitly selected this saved local copy and confirmed the recommended read-only checks.",
    undefined,
    ["syft", "trivy", "grype"],
  );
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
      "Signed-in account: Production AWS (123456789012) · Read-only checks: Read-only inventory, Review settings.",
    );
  });
  const advanced = container.querySelector<HTMLDetailsElement>(".coverage-scan-type-advanced");
  expect(advanced).not.toBeNull();
  expect(advanced?.open).toBe(false);
});

test("public website flow applies the fixed Nuclei quick profile and starts without another form", async () => {
  const onStartScan = vi.fn().mockResolvedValue(true);
  const { container, queryByText } = renderRoute({
    assessmentIntent: "deployed_website",
    requestedActivities: ["active_external_vulnerability_tests"],
    nativeMode: false,
    onStartScan,
    assets: [pendingAsset({
      id: "asset-example",
      name: "https://example.com:443",
      type: "service",
      platform: "external",
      locator: "https://example.com:443",
      identifiers: [
        { namespace: "web_origin", value: "https://example.com:443" },
        { namespace: "dns_name", value: "example.com" },
      ],
      internetExposed: true,
      declaredWebService: { protocol: "https", port: 443, path: "/account" },
    })],
  });

  await waitFor(() => {
    expect(container.querySelector(".coverage-guided-boundary")?.textContent).toBe(
      "Scope: https://example.com:443, not only /account. Nuclei applies matching pinned read-only checks at max 10/s, 5 concurrent, and 10s timeout. No sign-in, forms, redirects, or exploitation. Start only with permission for the full origin.",
    );
  });
  expect(container.querySelector(".coverage-review-timing")?.textContent).toBe(
    "Timing target: a useful result within minutes after tools are ready.",
  );

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
  expect(queryByText("Approval reference (required)")).toBeNull();

  const advancedSettings = container.querySelectorAll<HTMLDetailsElement>("details.coverage-scan-advanced");
  expect(advancedSettings).toHaveLength(1);
  const advancedSummary = advancedSettings[0]?.querySelector("summary");
  expect(advancedSummary?.textContent).toContain("Advanced scan settings");
  fireEvent.click(advancedSummary!);
  expect(advancedSettings[0]?.open).toBe(true);
  expect((within(advancedSettings[0]).getByLabelText(/Website or system to check/) as HTMLSelectElement).value).toBe("example.com");
  expect((within(advancedSettings[0]).getByLabelText(/Allowed ports/) as HTMLInputElement).value).toBe("443");
  expect(within(advancedSettings[0]).queryByLabelText(/Exact active-test IDs/)).toBeNull();

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
    ["active_external"],
    "The user explicitly confirmed authorization to scan the exact https://example.com:443 origin with the displayed fixed quick profile.",
    {
      target: "example.com",
      protocol: "https",
      ports: [443],
      activity: "active_external",
      ratePolicy: {
        requestsPerSecond: 10,
        concurrency: 5,
        timeoutSeconds: 10,
      },
      templatePolicy: {
        revision: "nuclei-templates@24858b4bfabfa86f0bcfd36aea24fb535152b012",
        profileId: "nuclei_web_safe_v1",
        allowedTemplateIds: [],
        allowHeadless: false,
        allowOutOfBand: false,
        allowFuzzing: false,
        allowFileUpload: false,
        allowDenialOfService: false,
        allowCredentialAttacks: false,
      },
      assertedAuthority: "The user explicitly confirmed authorization to scan the exact https://example.com:443 origin with the displayed fixed quick profile.",
      allowSensitiveNetworks: false,
    },
    ["nuclei"],
  );
}, 15_000);

test("one IT-environment Start routes repositories and exact website origins into one combined run", async () => {
  const onStartScan = vi.fn().mockResolvedValue(true);
  const onStartEnvironmentScan = vi.fn().mockResolvedValue(true);
  const { getAllByText, getByRole, getByText } = renderRoute({
    assessmentIntent: "internal_it_environment",
    requestedActivities: ["local_artifact_analysis", "active_external_vulnerability_tests"],
    nativeMode: false,
    onStartScan,
    onStartEnvironmentScan,
    assets: [
      pendingAsset({
        id: "repo-a",
        name: "billing-api",
        locator: "private-copy://repo-a",
        localInputProfile: "repository_working_tree",
      }),
      pendingAsset({
        id: "repo-b",
        name: "customer-portal",
        locator: "private-copy://repo-b",
        localInputProfile: "repository_working_tree",
      }),
      pendingAsset({
        id: "website-public",
        name: "https://portal.example.com:443",
        type: "service",
        platform: "external",
        locator: "https://portal.example.com:443",
        identifiers: [
          { namespace: "web_origin", value: "https://portal.example.com:443" },
          { namespace: "dns_name", value: "portal.example.com" },
        ],
        internetExposed: true,
        declaredWebService: { protocol: "https", port: 443, path: "/login" },
      }),
      pendingAsset({
        id: "website-internal",
        name: "https://10.20.0.5:8443",
        type: "service",
        platform: "external",
        locator: "https://10.20.0.5:8443",
        identifiers: [
          { namespace: "web_origin", value: "https://10.20.0.5:8443" },
          { namespace: "ip_address", value: "10.20.0.5" },
        ],
        internetExposed: false,
        declaredWebService: { protocol: "https", port: 8443, path: "/admin" },
      }),
      pendingAsset({
        id: "internal-host",
        name: "host.internal.example",
        type: "domain",
        platform: "external",
        locator: "host.internal.example",
        identifiers: [{ namespace: "dns_name", value: "host.internal.example" }],
        internetExposed: false,
        declaredHostScan: {
          protocol: "tcp",
          ports: [22, 25, 443, 445, 3389],
          scanProfile: "internal_host_greenbone_remote_safe",
        },
      }),
      pendingAsset({
        id: "device-gateway",
        name: "https://10.20.0.8:443",
        type: "service",
        platform: "external",
        locator: "https://10.20.0.8:443",
        identifiers: [
          { namespace: "web_origin", value: "https://10.20.0.8:443" },
          { namespace: "ip_address", value: "10.20.0.8" },
        ],
        internetExposed: false,
        declaredWebService: {
          protocol: "https",
          port: 443,
          path: "/",
          scanProfile: "internal_device_https",
        },
      }),
      pendingAsset({
        id: "endpoint-ssh",
        name: "server.internal.example",
        type: "service",
        platform: "external",
        locator: "server.internal.example",
        identifiers: [{ namespace: "dns_name", value: "server.internal.example" }],
        internetExposed: false,
        declaredNetworkService: {
          protocol: "tcp",
          port: 2222,
          scanProfile: "internal_endpoint_ssh",
        },
      }),
      pendingAsset({
        id: "endpoint-rdp",
        name: "desktop.internal.example",
        type: "service",
        platform: "external",
        locator: "desktop.internal.example",
        identifiers: [{ namespace: "dns_name", value: "desktop.internal.example" }],
        internetExposed: false,
        declaredNetworkService: {
          protocol: "tcp",
          port: 3389,
          scanProfile: "internal_endpoint_rdp_tls",
        },
      }),
      pendingAsset({
        id: "endpoint-vnc",
        name: "workstation.internal.example",
        type: "service",
        platform: "external",
        locator: "workstation.internal.example",
        identifiers: [{ namespace: "dns_name", value: "workstation.internal.example" }],
        internetExposed: false,
        declaredNetworkService: {
          protocol: "tcp",
          port: 5900,
          scanProfile: "internal_endpoint_vnc",
        },
      }),
      pendingAsset({
        id: "endpoint-smtp",
        name: "mail.internal.example",
        type: "service",
        platform: "external",
        locator: "mail.internal.example",
        identifiers: [{ namespace: "dns_name", value: "mail.internal.example" }],
        internetExposed: false,
        declaredNetworkService: {
          protocol: "tcp",
          port: 587,
          scanProfile: "internal_endpoint_smtp",
        },
      }),
      pendingAsset({
        id: "endpoint-telnet",
        name: "switch.internal.example",
        type: "service",
        platform: "external",
        locator: "switch.internal.example",
        identifiers: [{ namespace: "dns_name", value: "switch.internal.example" }],
        internetExposed: false,
        declaredNetworkService: {
          protocol: "tcp",
          port: 23,
          scanProfile: "internal_endpoint_telnet",
        },
      }),
      pendingAsset({
        id: "device-switch",
        name: "https://10.20.0.9:8080",
        type: "service",
        platform: "external",
        locator: "https://10.20.0.9:8080",
        identifiers: [
          { namespace: "web_origin", value: "https://10.20.0.9:8080" },
          { namespace: "ip_address", value: "10.20.0.9" },
        ],
        internetExposed: false,
        declaredWebService: {
          protocol: "https",
          port: 8080,
          path: "/",
          scanProfile: "internal_device_https",
        },
      }),
      pendingAsset({
        id: "inventory-only",
        name: "10.20.0.19",
        type: "ip",
        platform: "external",
        locator: "10.20.0.19",
        identifiers: [{ namespace: "ip_address", value: "10.20.0.19" }],
        internetExposed: false,
      }),
    ],
  });

  expect(getByText(
    "Timing target: a useful result within minutes after tools are ready.",
  )).not.toBeNull();
  expect(getByText("1 bare host(s) or range(s) are inventory only — not scanned")).not.toBeNull();
  expect(getByText(/These legacy bare hosts or ranges will not be contacted or vulnerability-scanned in this run/i)).not.toBeNull();
  expect(getByText("10.20.0.19")).not.toBeNull();
  expect(getByText("host.internal.example")).not.toBeNull();
  expect(getByText("Greenbone remote-safe profile · TCP 22, 25, 443, 445, 3389")).not.toBeNull();
  expect(getByText("server.internal.example:2222")).not.toBeNull();
  expect(getByText("desktop.internal.example:3389")).not.toBeNull();
  expect(getByText("workstation.internal.example:5900")).not.toBeNull();
  expect(getByText("mail.internal.example:587")).not.toBeNull();
  expect(getByText("switch.internal.example:23")).not.toBeNull();
  expect(getByText("SSH service · Greenbone · 7 security checks")).not.toBeNull();
  expect(getByText("RDP transport security · Greenbone · 11 security checks")).not.toBeNull();
  expect(getByText("VNC transport security · Greenbone · 1 security check")).not.toBeNull();
  expect(getByText("SMTP transport security · Greenbone · 11 security checks")).not.toBeNull();
  expect(getByText("Telnet cleartext exposure · Greenbone · 1 security check")).not.toBeNull();
  expect(getByText(/Reads the RFB security types offered by the exact VNC service/i)).not.toBeNull();
  expect(getByText(/It does not sign in, start a desktop session/i)).not.toBeNull();
  expect(getAllByText(/HTTPS management-service security · Greenbone · 11 TLS vulnerability checks/i)).toHaveLength(2);
  expect(getAllByText(/does not sign in, inspect the whole device/i)).toHaveLength(1);

  const start = getByRole("button", { name: "Start one combined scan" });
  await waitFor(() => expect((start as HTMLButtonElement).disabled).toBe(true));
  fireEvent.click(getByRole("checkbox", {
    name: /I confirm I am allowed to scan every selected website, API, and exact internal system/i,
  }));
  expect((start as HTMLButtonElement).disabled).toBe(false);
  fireEvent.click(start);

  await waitFor(() => expect(onStartEnvironmentScan).toHaveBeenCalledTimes(1));
  expect(onStartScan).not.toHaveBeenCalled();
  const [authorizations, routes] = onStartEnvironmentScan.mock.calls[0] as [
    Array<{ assetIds: string[]; modes: string[]; externalScope?: Record<string, unknown> }>,
    Array<{ engineId: string; assetIds: string[] }>,
  ];
  expect(authorizations).toHaveLength(12);
  expect(authorizations.filter(({ modes }) => modes.includes("local_artifact"))).toHaveLength(2);
  expect(authorizations.find(({ assetIds }) => assetIds[0] === "website-public")?.externalScope).toMatchObject({
    target: "portal.example.com",
    ports: [443],
    protocol: "https",
    activity: "active_external",
    allowSensitiveNetworks: false,
    templatePolicy: {
      revision: websiteQuickProfile.templateRevision,
      profileId: websiteQuickProfile.profileId,
      allowedTemplateIds: [...websiteQuickProfile.allowedTemplateIds],
    },
  });
  expect(authorizations.find(({ assetIds }) => assetIds[0] === "website-internal")?.externalScope).toMatchObject({
    target: "10.20.0.5",
    ports: [8443],
    allowSensitiveNetworks: true,
  });
  expect(authorizations.find(({ assetIds }) => assetIds[0] === "internal-host")?.externalScope).toMatchObject({
    target: "host.internal.example",
    ports: [22, 25, 443, 445, 3389],
    protocol: "tcp",
    activity: "active_external",
    allowSensitiveNetworks: true,
    ratePolicy: internalHostGreenboneProfile.ratePolicy,
    templatePolicy: {
      revision: internalHostGreenboneProfile.templateRevision,
      profileId: "greenbone_remote_safe_v1",
      allowedTemplateIds: [],
      allowCredentialAttacks: false,
      allowDenialOfService: false,
    },
  });
  expect(authorizations.find(({ assetIds }) => assetIds[0] === "endpoint-ssh")?.externalScope).toMatchObject({
    target: "server.internal.example",
    ports: [2222],
    protocol: "tcp",
    activity: "active_external",
    allowSensitiveNetworks: true,
    ratePolicy: internalEndpointProfiles.ssh.ratePolicy,
    templatePolicy: {
      revision: internalEndpointProfiles.ssh.templateRevision,
      allowedTemplateIds: [...internalEndpointProfiles.ssh.allowedTemplateIds],
      allowCredentialAttacks: false,
    },
  });
  expect(authorizations.find(({ assetIds }) => assetIds[0] === "endpoint-rdp")?.externalScope).toMatchObject({
    target: "desktop.internal.example",
    ports: [3389],
    protocol: "tcp",
    activity: "active_external",
    allowSensitiveNetworks: true,
    ratePolicy: internalEndpointProfiles.rdp_tls.ratePolicy,
    templatePolicy: {
      revision: internalEndpointProfiles.rdp_tls.templateRevision,
      allowedTemplateIds: [...internalEndpointProfiles.rdp_tls.allowedTemplateIds],
      allowCredentialAttacks: false,
      allowDenialOfService: false,
      allowFileUpload: false,
      allowFuzzing: false,
      allowHeadless: false,
      allowOutOfBand: false,
    },
  });
  expect(authorizations.find(({ assetIds }) => assetIds[0] === "endpoint-vnc")?.externalScope).toMatchObject({
    target: "workstation.internal.example",
    ports: [5900],
    protocol: "tcp",
    activity: "active_external",
    allowSensitiveNetworks: true,
    ratePolicy: internalEndpointProfiles.vnc.ratePolicy,
    templatePolicy: {
      revision: internalEndpointProfiles.vnc.templateRevision,
      allowedTemplateIds: [...internalEndpointProfiles.vnc.allowedTemplateIds],
      allowCredentialAttacks: false,
      allowDenialOfService: false,
      allowFileUpload: false,
      allowFuzzing: false,
      allowHeadless: false,
      allowOutOfBand: false,
    },
  });
  expect(authorizations.find(({ assetIds }) => assetIds[0] === "endpoint-smtp")?.externalScope).toMatchObject({
    target: "mail.internal.example",
    ports: [587],
    protocol: "tcp",
    activity: "active_external",
    allowSensitiveNetworks: true,
    ratePolicy: internalEndpointProfiles.smtp.ratePolicy,
    templatePolicy: {
      revision: internalEndpointProfiles.smtp.templateRevision,
      allowedTemplateIds: [...internalEndpointProfiles.smtp.allowedTemplateIds],
      allowCredentialAttacks: false,
      allowDenialOfService: false,
      allowFileUpload: false,
      allowFuzzing: false,
      allowHeadless: false,
      allowOutOfBand: false,
    },
  });
  expect(authorizations.find(({ assetIds }) => assetIds[0] === "endpoint-telnet")?.externalScope).toMatchObject({
    target: "switch.internal.example",
    ports: [23],
    protocol: "tcp",
    activity: "active_external",
    allowSensitiveNetworks: true,
    ratePolicy: internalEndpointProfiles.telnet.ratePolicy,
    templatePolicy: {
      revision: internalEndpointProfiles.telnet.templateRevision,
      allowedTemplateIds: [...internalEndpointProfiles.telnet.allowedTemplateIds],
      allowCredentialAttacks: false,
      allowDenialOfService: false,
      allowFileUpload: false,
      allowFuzzing: false,
      allowHeadless: false,
      allowOutOfBand: false,
    },
  });
  expect(authorizations.find(({ assetIds }) => assetIds[0] === "device-gateway")?.externalScope).toMatchObject({
    target: "10.20.0.8",
    ports: [443],
    protocol: "https",
    activity: "active_external",
    allowSensitiveNetworks: true,
    templatePolicy: {
      revision: internalDeviceHttpsProfile.templateRevision,
      allowedTemplateIds: [...internalDeviceHttpsProfile.allowedTemplateIds],
    },
  });
  expect(authorizations.find(({ assetIds }) => assetIds[0] === "device-switch")?.externalScope).toMatchObject({
    target: "10.20.0.9",
    ports: [8080],
    templatePolicy: {
      revision: internalDeviceHttpsProfile.templateRevision,
      allowedTemplateIds: [...internalDeviceHttpsProfile.allowedTemplateIds],
    },
  });
  expect(routes.find(({ engineId }) => engineId === "semgrep")).toEqual({
    engineId: "semgrep",
    assetIds: ["repo-a", "repo-b"],
  });
  expect(routes.find(({ engineId }) => engineId === "grype")).toEqual({
    engineId: "grype",
    assetIds: ["repo-a", "repo-b"],
  });
  expect(routes.find(({ engineId }) => engineId === "nuclei")).toEqual({
    engineId: "nuclei",
    assetIds: ["website-public", "website-internal"],
  });
  expect(routes.find(({ engineId }) => engineId === "greenbone")).toEqual({
    engineId: "greenbone",
    assetIds: [
      "internal-host",
      "endpoint-ssh",
      "endpoint-rdp",
      "endpoint-vnc",
      "endpoint-smtp",
      "endpoint-telnet",
      "device-gateway",
      "device-switch",
    ],
  });
  expect(routes.flatMap(({ assetIds }) => assetIds)).not.toContain("inventory-only");
  expect(routes.some(({ engineId }) => engineId === "naabu" || engineId === "httpx")).toBe(false);
}, 15_000);

test("changing the selected environment network targets requires authorization again", async () => {
  const onStartEnvironmentScan = vi.fn().mockResolvedValue(true);
  const { getByRole } = renderRoute({
    assessmentIntent: "internal_it_environment",
    requestedActivities: ["local_artifact_analysis", "active_external_vulnerability_tests"],
    nativeMode: false,
    onStartEnvironmentScan,
    assets: [
      pendingAsset({
        id: "repo-a",
        name: "billing-api",
        locator: "private-copy://repo-a",
        localInputProfile: "repository_working_tree",
      }),
      pendingAsset({
        id: "website-a",
        name: "https://portal.example.com:443",
        type: "service",
        platform: "external",
        locator: "https://portal.example.com:443",
        identifiers: [
          { namespace: "web_origin", value: "https://portal.example.com:443" },
          { namespace: "dns_name", value: "portal.example.com" },
        ],
        internetExposed: true,
        declaredWebService: { protocol: "https", port: 443, path: "/" },
      }),
      pendingAsset({
        id: "website-b",
        name: "https://api.example.com:443",
        type: "service",
        platform: "external",
        locator: "https://api.example.com:443",
        identifiers: [
          { namespace: "web_origin", value: "https://api.example.com:443" },
          { namespace: "dns_name", value: "api.example.com" },
        ],
        internetExposed: true,
        declaredWebService: { protocol: "https", port: 443, path: "/" },
      }),
    ],
  });

  const start = getByRole("button", { name: "Start one combined scan" }) as HTMLButtonElement;
  const confirmation = getByRole("checkbox", {
    name: /I confirm I am allowed to scan every selected website, API, and exact internal system/i,
  }) as HTMLInputElement;

  await waitFor(() => expect(start.disabled).toBe(true));
  fireEvent.click(confirmation);
  expect(confirmation.checked).toBe(true);
  expect(start.disabled).toBe(false);

  fireEvent.click(getByRole("checkbox", { name: "Choose billing-api" }));
  expect(confirmation.checked).toBe(true);
  expect(start.disabled).toBe(false);

  fireEvent.click(getByRole("checkbox", { name: "Choose https://portal.example.com:443" }));
  expect(confirmation.checked).toBe(false);
  expect(start.disabled).toBe(true);

  fireEvent.click(confirmation);
  expect(start.disabled).toBe(false);
  fireEvent.click(getByRole("checkbox", { name: "Choose https://portal.example.com:443" }));
  expect(confirmation.checked).toBe(false);
  expect(start.disabled).toBe(true);
  expect(onStartEnvironmentScan).not.toHaveBeenCalled();
});

test("a scan waiting for its tools keeps the reviewed website request immutable", async () => {
  const { container } = renderRoute({
    assessmentIntent: "deployed_website",
    requestedActivities: ["active_external_vulnerability_tests"],
    busy: true,
    runtimeSetupNotice: <div data-testid="runtime-progress">Downloading scan tools: 42%</div>,
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

  await waitFor(() => expect(container.querySelector(".scope-confirmation-panel")).not.toBeNull());
  const reviewControls = Array.from(container.querySelectorAll<
    HTMLInputElement | HTMLSelectElement | HTMLTextAreaElement | HTMLButtonElement
  >(".scope-confirmation-panel input, .scope-confirmation-panel select, .scope-confirmation-panel textarea, .scope-confirmation-panel button"));
  expect(reviewControls.length).toBeGreaterThan(0);
  expect(reviewControls.every((control) => control.disabled)).toBe(true);
  expect(container.querySelector('[data-testid="runtime-progress"]')?.textContent).toContain("42%");
  expect(container.querySelector(".scope-confirmation-panel .button--primary")?.textContent).toContain("Preparing scan tools");

  const editInputs = Array.from(container.querySelectorAll<HTMLButtonElement>(".page-header button"))
    .find((button) => button.textContent?.includes("Edit inputs"));
  expect(editInputs?.disabled).toBe(true);
});

test("public-record mode keeps the exact website and honest no-contact boundary visible", async () => {
  const { container } = renderRoute({
    assessmentIntent: "external_ip_or_domain",
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

test("an internal website uses the fixed Nuclei profile only after explicit private-network confirmation", async () => {
  const onStartScan = vi.fn().mockResolvedValue(true);
  const { container, getByRole, queryByText } = renderRoute({
    assessmentIntent: "deployed_website",
    requestedActivities: ["active_external_vulnerability_tests"],
    onStartScan,
    assets: [pendingAsset({
      id: "asset-internal-website",
      name: "app.internal.test",
      type: "domain",
      platform: "external",
      locator: "app.internal.test",
      identifiers: [{ namespace: "dns_name", value: "app.internal.test" }],
      internetExposed: false,
      declaredWebService: { protocol: "https", port: 8443, path: "/health" },
    })],
  });

  await waitFor(() => expect(container.querySelector(".coverage-guided-boundary")?.textContent).toContain(
    "Scope: https://app.internal.test:8443, not only /health.",
  ));

  expect(container.querySelector(".scope-mode-fieldset")).toBeNull();
  expect(queryByText("Approval reference (required)")).toBeNull();
  expect(queryByText("Exact active-test IDs (required)")).toBeNull();

  const start = getByRole("button", { name: "Confirm and start scan" }) as HTMLButtonElement;
  const privateNetworkConfirmation = getByRole("checkbox", {
    name: /I confirm this scan may connect to the selected internal network/i,
  }) as HTMLInputElement;
  expect(privateNetworkConfirmation.checked).toBe(false);
  expect(start.disabled).toBe(true);
  expect(onStartScan).not.toHaveBeenCalled();

  fireEvent.click(privateNetworkConfirmation);
  expect(privateNetworkConfirmation.checked).toBe(true);
  expect(start.disabled).toBe(false);
  fireEvent.click(start);

  await waitFor(() => expect(onStartScan).toHaveBeenCalledTimes(1));
  expect(onStartScan).toHaveBeenCalledWith(
    ["asset-internal-website"],
    ["active_external"],
    "The user explicitly confirmed authorization to scan the exact https://app.internal.test:8443 origin with the displayed fixed quick profile.",
    {
      target: "app.internal.test",
      protocol: "https",
      ports: [8443],
      activity: "active_external",
      ratePolicy: {
        requestsPerSecond: 10,
        concurrency: 5,
        timeoutSeconds: 10,
      },
      templatePolicy: {
        revision: websiteQuickProfile.templateRevision,
        profileId: websiteQuickProfile.profileId,
        allowedTemplateIds: [],
        allowHeadless: false,
        allowOutOfBand: false,
        allowFuzzing: false,
        allowFileUpload: false,
        allowDenialOfService: false,
        allowCredentialAttacks: false,
      },
      assertedAuthority: "The user explicitly confirmed authorization to scan the exact https://app.internal.test:8443 origin with the displayed fixed quick profile.",
      allowSensitiveNetworks: true,
    },
    ["nuclei"],
  );
});
