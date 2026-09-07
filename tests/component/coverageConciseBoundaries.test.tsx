import { cleanup, render, waitFor } from "@testing-library/react";
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
}: Pick<React.ComponentProps<typeof CoveragePage>, "assessmentIntent" | "requestedActivities" | "assets"> & {
  sources?: ConnectedSource[];
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
      nativeMode={true}
      onChooseSnapshot={() => Promise.resolve(null)}
      onConnectSourceSnapshot={() => Promise.resolve()}
      onChooseWorkspace={() => Promise.resolve(null)}
      onAttachWorkspaceSnapshot={() => Promise.resolve(true)}
      onStartDiscovery={() => Promise.resolve()}
      onAuthorizationChanged={() => Promise.resolve()}
      onStartScan={() => Promise.resolve(true)}
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
