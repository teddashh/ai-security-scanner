import assert from "node:assert/strict";
import test from "node:test";

import {
  SOURCE_CAPABILITY_DEFINITION_VERSION,
  projectSourceCapabilityView,
} from "../../src/sourceCapabilityPresentation.ts";
import type {
  ConnectedSource,
  EngineManifest,
  SourceCapabilityProvider,
} from "../../src/types.ts";

const sourceByProvider: Record<SourceCapabilityProvider, ConnectedSource> = {
  aws: {
    id: "source-aws",
    kind: "aws_organization",
    label: "AWS",
    status: "connected",
    readOnly: true,
    providerBinding: {
      profile: "aws_organization_read_only_session",
      resourceScope: "aws-account:123456789012",
    },
  },
  azure: {
    id: "source-azure",
    kind: "azure_tenant",
    label: "Azure",
    status: "connected",
    readOnly: true,
    providerBinding: {
      profile: "azure_tenant_read_only_access_token",
      resourceScope: "azure-subscription:11111111-2222-4333-8444-555555555555",
    },
  },
  gcp: {
    id: "source-gcp",
    kind: "gcp_organization",
    label: "GCP",
    status: "connected",
    readOnly: true,
    providerBinding: {
      profile: "gcp_organization_read_only_access_token",
      resourceScope: "gcp-organization:123456789012",
    },
  },
  microsoft365: {
    id: "source-m365",
    kind: "microsoft365_tenant",
    label: "Microsoft 365",
    status: "connected",
    readOnly: true,
    providerBinding: {
      profile: "microsoft365_tenant_read_only_access_token",
      resourceScope: "microsoft365-tenant:aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee",
    },
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

const prowler = manifest("prowler", ["aws", "azure", "gcp"], {
  providerExecutionProfiles: [
    { provider: "aws", assetKind: "cloud_account", profile: "aws_iam_service_exact_account" },
    { provider: "azure", assetKind: "subscription", profile: "azure_iam_service_static_token_exact_subscription" },
    { provider: "gcp", assetKind: "project", profile: "gcp_iam_four_checks_exact_project" },
  ],
});

const currentManifests = [
  manifest("cloudquery", ["aws"]),
  manifest("steampipe", ["aws"]),
  prowler,
  manifest("scoutsuite", ["aws"]),
  manifest("cloudsplaining", ["aws"]),
  manifest("scubagear", ["m365"], { status: "not_downloaded", runnable: false }),
  manifest("maester", ["m365"], { status: "not_downloaded", runnable: false }),
];

test("the versioned curated matrix preserves six dimensions and conservative provider states", () => {
  const expected = {
    aws: ["partial", "partial", "unavailable", "unavailable", "unavailable", "partial"],
    azure: ["supported", "partial", "unavailable", "unavailable", "unavailable", "partial"],
    gcp: ["partial", "partial", "unavailable", "unavailable", "unavailable", "partial"],
    microsoft365: ["partial", "unavailable", "unavailable", "unavailable", "unavailable", "unavailable"],
  } as const;
  const dimensions = [
    "inventory",
    "identity_and_access",
    "network_exposure",
    "storage_exposure",
    "logging",
    "secret_and_configuration",
  ];

  for (const provider of Object.keys(expected) as SourceCapabilityProvider[]) {
    const view = projectSourceCapabilityView({
      provider,
      source: sourceByProvider[provider],
      manifests: currentManifests,
    });
    assert.equal(view.schemaVersion, "1.0.0");
    assert.equal(view.definitionVersion, SOURCE_CAPABILITY_DEFINITION_VERSION);
    assert.deepEqual(view.cells.map((cell) => cell.dimension), dimensions);
    assert.deepEqual(view.cells.map((cell) => cell.state), expected[provider]);
  }
});

test("Microsoft 365 capability becomes partial only for an explicitly runnable exact engine", () => {
  const nonRunnable = projectSourceCapabilityView({
    provider: "microsoft365",
    source: sourceByProvider.microsoft365,
    manifests: currentManifests,
  });
  assert.equal(nonRunnable.cells[1]?.state, "unavailable");
  assert.equal(nonRunnable.cells[5]?.state, "unavailable");

  const runnable = projectSourceCapabilityView({
    provider: "microsoft365",
    source: sourceByProvider.microsoft365,
    manifests: [
      manifest("scubagear", ["m365"]),
      manifest("maester", ["m365"], { status: "not_downloaded", runnable: false }),
    ],
  });
  assert.equal(runnable.cells[1]?.state, "partial");
  assert.equal(runnable.cells[5]?.state, "partial");

  const undeclared = projectSourceCapabilityView({
    provider: "microsoft365",
    source: sourceByProvider.microsoft365,
    manifests: [manifest("scubagear", ["m365"], { runnable: undefined })],
  });
  assert.equal(undeclared.cells[1]?.state, "unknown");
  assert.equal(undeclared.cells[5]?.state, "unknown");

  const wrongProvider = projectSourceCapabilityView({
    provider: "microsoft365",
    source: sourceByProvider.microsoft365,
    manifests: [manifest("scubagear", ["aws"])],
  });
  assert.equal(wrongProvider.cells[1]?.state, "unknown");
});

test("generic categories and provider labels cannot invent unsupported capability", () => {
  const view = projectSourceCapabilityView({
    provider: "aws",
    source: sourceByProvider.aws,
    manifests: [manifest("broad-cloud-scanner", ["aws"], { category: "cloud_configuration" })],
  });
  assert.deepEqual(view.cells.slice(2, 5).map((cell) => cell.state), [
    "unavailable",
    "unavailable",
    "unavailable",
  ]);
  assert.equal(view.cells[1]?.state, "unknown");
});

test("only a matching verified source binding supplies the displayed source scope", () => {
  const valid = projectSourceCapabilityView({
    provider: "gcp",
    source: sourceByProvider.gcp,
    manifests: currentManifests,
  });
  assert.equal(valid.resourceScope, "gcp-organization:123456789012");
  assert.match(valid.cells[1]?.limitation.en ?? "", /per verified project/u);

  const mismatched: ConnectedSource = {
    ...sourceByProvider.gcp,
    providerBinding: {
      profile: "gcp_organization_read_only_access_token",
      resourceScope: "gcp-project:not-an-organization-scope",
    },
  };
  assert.equal(projectSourceCapabilityView({ provider: "gcp", source: mismatched, manifests: currentManifests }).resourceScope, undefined);
});

test("expired support is an engine limitation and does not erase runnable capability", () => {
  const expiredCloudQuery = manifest("cloudquery", ["aws"], {
    supportStatus: "expired",
    supportUntil: "0001-01-01",
  });
  const view = projectSourceCapabilityView({
    provider: "aws",
    source: sourceByProvider.aws,
    manifests: [expiredCloudQuery, manifest("steampipe", ["aws"]), prowler, manifest("scoutsuite", ["aws"]), manifest("cloudsplaining", ["aws"])],
  });
  const projected = view.cells[0]?.engines.find((engine) => engine.id === "cloudquery");
  assert.equal(view.cells[0]?.state, "partial");
  assert.equal(projected?.availability, "available");
  assert.equal(projected?.supportStatus, "expired");
  assert.equal(projected?.supportUntil, "0001-01-01");
});

test("contradictory compatibility data fails soft to unknown", () => {
  const view = projectSourceCapabilityView({
    provider: "microsoft365",
    source: sourceByProvider.microsoft365,
    manifests: [manifest("scubagear", ["m365"], {
      runnable: true,
      blockedBy: ["not actually released"],
      compatibilityValid: false,
    })],
  });
  assert.equal(view.cells[1]?.state, "unknown");
  assert.equal(view.cells[1]?.engines[0]?.availability, "unknown");
});

test("a capability the product actually ships is not still described as planned", () => {
  // Both Microsoft 365 engines were unpublished when this matrix was written,
  // so their cells read "Only the fixed Entra profiles are planned. This
  // becomes partial only when at least one pinned engine is runnable in this
  // product." Both are now published at immutable digests, so once the runtime
  // reports them ready the cell state resolves to "partial" while the sentence
  // beside it still says the capability has not been reached. The state and the
  // prose contradict each other, and the prose understates what ships.
  const readyM365 = [
    manifest("scubagear", ["m365"], { status: "ready", runnable: true }),
    manifest("maester", ["m365"], { status: "ready", runnable: true }),
  ];
  const view = projectSourceCapabilityView({
    provider: "microsoft365",
    source: sourceByProvider.microsoft365,
    manifests: readyM365,
  });

  const reached = view.cells.filter((cell) => cell.state === "partial" || cell.state === "supported");
  assert.ok(reached.length >= 2, `expected the M365 engines to reach a state, saw ${JSON.stringify(view.cells.map((cell) => cell.state))}`);

  for (const cell of reached) {
    for (const locale of ["en", "zhTW"] as const) {
      const limitation = cell.limitation[locale];
      assert.doesNotMatch(
        limitation,
        /\bplanned\b|becomes partial only when|規劃|才會顯示為/u,
        `${cell.dimension} (${locale}) reports state "${cell.state}" while its limitation calls the capability future: ${limitation}`,
      );
    }
  }
});

test("a limitation still says what is out of scope rather than going silent", () => {
  // The mirror of the test above: replacing the stale sentence with nothing
  // would satisfy it while removing the disclosure entirely.
  const readyM365 = [
    manifest("scubagear", ["m365"], { status: "ready", runnable: true }),
    manifest("maester", ["m365"], { status: "ready", runnable: true }),
  ];
  const view = projectSourceCapabilityView({
    provider: "microsoft365",
    source: sourceByProvider.microsoft365,
    manifests: readyM365,
  });

  for (const cell of view.cells) {
    for (const locale of ["en", "zhTW"] as const) {
      assert.ok(
        cell.limitation[locale].trim().length > 0,
        `${cell.dimension} (${locale}) states no limit at all`,
      );
    }
  }
  const identity = view.cells.find((cell) => cell.dimension === "identity_and_access")!;
  assert.match(identity.limitation.en, /Only the fixed Entra profiles/u);
  assert.match(identity.limitation.en, /No other Microsoft 365 service is checked/u);
  assert.match(identity.limitation.zhTW, /其他 Microsoft 365 服務都不檢查/u);
});
