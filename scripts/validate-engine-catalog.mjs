#!/usr/bin/env node

import { createHash } from "node:crypto";
import { existsSync, readFileSync, readdirSync } from "node:fs";
import { basename, resolve } from "node:path";

const root = resolve(import.meta.dirname, "..");
const catalogPath = resolve(root, "engines/catalog.json");
const schemaPath = resolve(root, "engines/compatibility.schema.json");
const upstreamLockPath = resolve(root, "engines/upstreams.lock.json");
const expectedIds = [
  "cloudquery",
  "steampipe",
  "prowler",
  "scoutsuite",
  "cloudsplaining",
  "scubagear",
  "maester",
  "naabu",
  "httpx",
  "nuclei",
  "greenbone",
  "semgrep",
  "gitleaks",
  "trufflehog",
  "checkov",
  "kics",
  "trivy",
  "grype",
  "syft",
  "kubescape",
  "kube-bench",
];
const managedCloudIds = new Set([
  "cloudquery",
  "cloudsplaining",
  "prowler",
  "scoutsuite",
  "steampipe",
]);
const managedExternalIds = new Set(["naabu", "httpx", "nuclei"]);
const managedM365Ids = new Set(["scubagear", "maester"]);
const shellNames = new Set([
  "sh", "bash", "dash", "zsh", "fish", "cmd", "cmd.exe",
  "powershell", "powershell.exe", "pwsh", "pwsh.exe",
]);
const floatingTags = new Set([
  "latest", "stable", "edge", "dev", "development", "main", "master",
  "nightly", "canary", "current", "rolling",
]);
const digestPattern = /^sha256:[0-9a-f]{64}$/;
const revisionPattern = /^[0-9a-f]{40}$/;
const planKinds = new Set(["upstream_image", "managed_build", "managed_rebase", "managed_source_image", "multi_component_build"]);
const errors = [];

function parseJson(path) {
  try {
    return JSON.parse(readFileSync(path, "utf8"));
  } catch (error) {
    errors.push(`${path}: invalid JSON (${error.message})`);
    return null;
  }
}

function jsonType(value) {
  if (value === null) return "null";
  if (Array.isArray(value)) return "array";
  if (Number.isInteger(value)) return "integer";
  return typeof value === "number" ? "number" : typeof value;
}

function deepEqual(left, right) {
  return JSON.stringify(left) === JSON.stringify(right);
}

function resolveReference(rootSchema, reference) {
  if (!reference.startsWith("#/")) return null;
  return reference.slice(2).split("/").reduce((value, token) => {
    const key = token.replaceAll("~1", "/").replaceAll("~0", "~");
    return value?.[key];
  }, rootSchema);
}

function validateSchemaValue(value, rule, path, rootSchema, targetErrors) {
  if (rule.$ref) {
    const resolved = resolveReference(rootSchema, rule.$ref);
    if (!resolved) {
      targetErrors.push(`${path}: schema has unresolved reference ${rule.$ref}`);
      return;
    }
    validateSchemaValue(value, resolved, path, rootSchema, targetErrors);
    return;
  }
  if (rule.anyOf) {
    const matched = rule.anyOf.some((candidate) => {
      const candidateErrors = [];
      validateSchemaValue(value, candidate, path, rootSchema, candidateErrors);
      return candidateErrors.length === 0;
    });
    if (!matched) targetErrors.push(`${path}: does not match any allowed schema`);
    return;
  }
  if (rule.const !== undefined && !deepEqual(value, rule.const)) {
    targetErrors.push(`${path}: expected constant ${JSON.stringify(rule.const)}`);
  }
  if (rule.enum && !rule.enum.some((candidate) => deepEqual(value, candidate))) {
    targetErrors.push(`${path}: value ${JSON.stringify(value)} is not in the allowed enum`);
  }
  if (rule.type) {
    const allowedTypes = Array.isArray(rule.type) ? rule.type : [rule.type];
    if (!allowedTypes.includes(jsonType(value))) {
      targetErrors.push(`${path}: expected ${allowedTypes.join(" or ")}, got ${jsonType(value)}`);
      return;
    }
  }
  if (typeof value === "string") {
    if (rule.minLength !== undefined && value.length < rule.minLength) targetErrors.push(`${path}: string is too short`);
    if (rule.maxLength !== undefined && value.length > rule.maxLength) targetErrors.push(`${path}: string is too long`);
    if (rule.pattern && !new RegExp(rule.pattern).test(value)) targetErrors.push(`${path}: does not match ${rule.pattern}`);
    if (rule.format === "date" && !/^\d{4}-\d{2}-\d{2}$/.test(value)) targetErrors.push(`${path}: is not an ISO date`);
  }
  if (typeof value === "number") {
    if (rule.minimum !== undefined && value < rule.minimum) targetErrors.push(`${path}: is below minimum ${rule.minimum}`);
    if (rule.maximum !== undefined && value > rule.maximum) targetErrors.push(`${path}: exceeds maximum ${rule.maximum}`);
  }
  if (Array.isArray(value)) {
    if (rule.minItems !== undefined && value.length < rule.minItems) targetErrors.push(`${path}: has fewer than ${rule.minItems} items`);
    if (rule.maxItems !== undefined && value.length > rule.maxItems) targetErrors.push(`${path}: has more than ${rule.maxItems} items`);
    if (rule.uniqueItems) {
      const serialized = value.map((item) => JSON.stringify(item));
      if (new Set(serialized).size !== serialized.length) targetErrors.push(`${path}: contains duplicate items`);
    }
    if (rule.items) value.forEach((item, index) => validateSchemaValue(item, rule.items, `${path}[${index}]`, rootSchema, targetErrors));
  }
  if (value !== null && typeof value === "object" && !Array.isArray(value)) {
    for (const required of rule.required ?? []) {
      if (!Object.hasOwn(value, required)) targetErrors.push(`${path}: missing required property ${required}`);
    }
    if (rule.additionalProperties === false) {
      const known = new Set(Object.keys(rule.properties ?? {}));
      for (const key of Object.keys(value)) if (!known.has(key)) targetErrors.push(`${path}: unknown property ${key}`);
    }
    for (const [key, childRule] of Object.entries(rule.properties ?? {})) {
      if (Object.hasOwn(value, key)) validateSchemaValue(value[key], childRule, `${path}.${key}`, rootSchema, targetErrors);
    }
  }
}

function validateStaticCommand(engine) {
  const path = `catalog:${engine.id}.command`;
  if (!Array.isArray(engine.command) || engine.command.length === 0) return;
  const program = basename(engine.command[0]).toLowerCase();
  if (shellNames.has(program)) errors.push(`${path}: may not invoke shell ${program}`);
  for (const token of engine.command) {
    const lower = token.toLowerCase();
    if (shellNames.has(basename(lower))) errors.push(`${path}: shell token ${token} is forbidden`);
    if (token.includes("\0") || token.includes("${") || token.includes("$(") || token.includes("{{") || token.includes("`")) {
      errors.push(`${path}: dynamic or unsafe token ${JSON.stringify(token)}`);
    }
    if ([";", "&&", "||", "|", ">", ">>", "<"].includes(token)) errors.push(`${path}: shell operator ${token} is forbidden`);
  }
}

function validateTag(tag, path) {
  if (typeof tag !== "string" || tag.length === 0) {
    errors.push(`${path}: exact tag is required`);
    return;
  }
  const normalized = tag.toLowerCase();
  if (floatingTags.has(normalized) || [...floatingTags].some((value) => normalized === `${value}-latest`)) {
    errors.push(`${path}: floating tag ${tag} is forbidden`);
  }
  if (/[${}]/.test(tag)) errors.push(`${path}: templated tag ${tag} is forbidden`);
  if (!/^(?:v?\d+(?:\.\d+){1,3}(?:[-.][0-9A-Za-z]+)*|[0-9a-f]{40})$/.test(tag)) {
    errors.push(`${path}: tag ${tag} is not an exact version or commit tag`);
  }
}

function validateImage(image, path, { allowDigestPinnedAlias = false } = {}) {
  if (!image || typeof image !== "object") {
    errors.push(`${path}: image object is required`);
    return;
  }
  if (typeof image.repository !== "string" || image.repository.includes("@") || /\s/.test(image.repository)) {
    errors.push(`${path}.repository: invalid repository`);
  }
  const normalizedTag = typeof image.tag === "string" ? image.tag.toLowerCase() : "";
  if (allowDigestPinnedAlias && image.tag && !floatingTags.has(normalizedTag) && !/[${}]/.test(image.tag)) {
    // A human-readable distro codename remains immutable because the digest
    // below is mandatory; latest/nightly/template aliases stay forbidden.
  } else {
    validateTag(image.tag, `${path}.tag`);
  }
  if (!digestPattern.test(image.digest ?? "")) errors.push(`${path}.digest: immutable sha256 digest is required`);
}

function walkFiles(path) {
  if (!existsSync(path)) return [];
  const files = [];
  for (const entry of readdirSync(path, { withFileTypes: true })) {
    const child = resolve(path, entry.name);
    if (entry.isDirectory()) files.push(...walkFiles(child));
    else if (entry.isFile()) files.push(child);
  }
  return files;
}

function sha256File(path) {
  return `sha256:${createHash("sha256").update(readFileSync(path)).digest("hex")}`;
}

function validateCloudManagedImage(plan, planRelative, engine) {
  const expectedPath = `engines/images/${engine.id}/Dockerfile`;
  const dockerfile = plan.dockerfile;
  if (dockerfile?.emitted !== true || dockerfile?.path !== expectedPath) {
    errors.push(`${planRelative}: managed cloud image must emit ${expectedPath}`);
    return;
  }
  const dockerfilePath = resolve(root, expectedPath);
  if (!existsSync(dockerfilePath)) {
    errors.push(`${planRelative}: managed cloud Dockerfile is missing`);
    return;
  }
  const dockerfileText = readFileSync(dockerfilePath, "utf8");
  const actualDockerfileSha256 = sha256File(dockerfilePath);
  if (dockerfile.sha256 !== actualDockerfileSha256) {
    errors.push(`${planRelative}: Dockerfile digest ${dockerfile.sha256 ?? "missing"} does not match ${actualDockerfileSha256}`);
  }
  if (!/^# syntax=[^\s]+@sha256:[0-9a-f]{64}$/m.test(dockerfileText.split(/\r?\n/, 1)[0])) {
    errors.push(`${planRelative}: managed cloud Dockerfile frontend must be digest-pinned`);
  }

  if (engine.image) {
    const publication = plan.publication;
    if (plan.publish_state !== "published_managed_artifact") {
      errors.push(`${planRelative}: runnable cloud image must be marked as a published managed artifact`);
    }
    if (!publication || publication.anonymous_pull_verified !== true || !deepEqual(publication.platforms, ["linux/amd64", "linux/arm64"])) {
      errors.push(`${planRelative}: runnable cloud image requires anonymous multi-platform publication evidence`);
    }
    if (!deepEqual(Object.keys(publication?.platform_digests ?? {}), ["linux/amd64", "linux/arm64"]) ||
        !Object.values(publication.platform_digests).every((digest) => digestPattern.test(digest))) {
      errors.push(`${planRelative}: cloud publication evidence requires exact amd64 and arm64 manifest digests`);
    }
    if (!revisionPattern.test(publication?.source_revision ?? "") || !/^https:\/\/github\.com\/teddashh\/ai-security-scanner\/actions\/runs\/[1-9][0-9]*$/.test(publication?.workflow_run ?? "")) {
      errors.push(`${planRelative}: cloud publication evidence must identify an exact repository revision and workflow run`);
    }
    if (!new RegExp(`^${engine.id}-image-manifest-[1-9][0-9]*$`).test(publication?.evidence_artifact ?? "")) {
      errors.push(`${planRelative}: cloud publication evidence artifact name is invalid`);
    }
  } else if (plan.publication !== undefined) {
    errors.push(`${planRelative}: unpublished cloud image must not claim publication evidence`);
  }

  const launcherPath = resolve(root, "engines/images/cloud-launcher/main.go");
  const expectedLauncherSha256 = sha256File(launcherPath);
  if (plan.wrapper?.entrypoint !== "/usr/local/bin/ai-security-scanner-cloud-launcher") {
    errors.push(`${planRelative}: managed cloud wrapper must use the scanner-owned launcher`);
  }
  if (plan.wrapper?.launcher_sha256 !== expectedLauncherSha256) {
    errors.push(`${planRelative}: launcher digest ${plan.wrapper?.launcher_sha256 ?? "missing"} does not match ${expectedLauncherSha256}`);
  }
  if (!dockerfileText.includes(`ENTRYPOINT ${JSON.stringify([plan.wrapper?.entrypoint])}`)) {
    errors.push(`${planRelative}: managed cloud Dockerfile does not set its declared direct entrypoint`);
  }

  const expectedCommand = [
    "--engine", engine.id,
    "--scope", "/run/ai-security-scanner/scope.json",
    "--output", "/output",
  ];
  if (!deepEqual(plan.command, expectedCommand)) {
    errors.push(`${planRelative}: managed cloud command must use the fixed scope and output mounts`);
  }

  const runtime = plan.managed_runtime;
  if (!runtime || typeof runtime !== "object") {
    errors.push(`${planRelative}: managed cloud image requires a runtime contract`);
    return;
  }
  if (!/^[1-9][0-9]*:[1-9][0-9]*$/.test(runtime.non_root_user ?? "")) {
    errors.push(`${planRelative}: managed cloud runtime must declare a numeric non-root uid:gid`);
  } else if (!dockerfileText.split(/\r?\n/).some((line) => line.trim() === `USER ${runtime.non_root_user}`)) {
    errors.push(`${planRelative}: managed cloud Dockerfile does not set its declared non-root user`);
  }
  if (runtime.read_only_rootfs !== true) errors.push(`${planRelative}: managed cloud runtime must require a read-only root filesystem`);
  if (runtime.network_mode !== "managed_allowlist" || engine.execution?.network?.mode !== "managed_allowlist") {
    errors.push(`${planRelative}: managed cloud runtime must use the managed network allowlist`);
  }
  if (!deepEqual(runtime.network_destinations, engine.execution?.network?.destinations)) {
    errors.push(`${planRelative}: managed cloud endpoint closure does not match the catalog`);
  }
  if (runtime.updates !== false || runtime.telemetry !== false) {
    errors.push(`${planRelative}: managed cloud runtime must disable updates and telemetry`);
  }
  for (const destination of runtime.network_destinations ?? []) {
    if (!/^[a-z0-9.-]+:443$/.test(destination)) {
      errors.push(`${planRelative}: managed cloud destination must be an exact lowercase fqdn:443 (${destination})`);
    }
  }

  if (plan.plan_kind === "managed_rebase") {
    validateImage(plan.verified_upstream_artifact, `${planRelative}.verified_upstream_artifact`);
    const expectedBase = `${plan.verified_upstream_artifact?.repository}@${plan.verified_upstream_artifact?.digest}`;
    if (!dockerfileText.split(/\r?\n/).some((line) => line.trim() === `FROM ${expectedBase}`)) {
      errors.push(`${planRelative}: managed cloud rebase does not use its verified upstream artifact`);
    }
    return;
  }

  const recipe = plan.build_recipe;
  if (!recipe || typeof recipe !== "object") {
    errors.push(`${planRelative}: managed cloud source image requires a build recipe`);
    return;
  }
  if (recipe.source_revision !== engine.source_revision) {
    errors.push(`${planRelative}: managed cloud source recipe must match the catalog source revision`);
  }
  const sourceArchive = recipe.source_archive;
  if (!sourceArchive?.url?.startsWith("https://") || !sourceArchive.url.includes(engine.source_revision) || !digestPattern.test(sourceArchive?.sha256 ?? "")) {
    errors.push(`${planRelative}: managed cloud source archive must have an immutable URL and digest`);
  } else if (!dockerfileText.includes(`ADD --checksum=${sourceArchive.sha256}`) || !dockerfileText.includes(sourceArchive.url)) {
    errors.push(`${planRelative}: managed cloud Dockerfile does not acquire its checksum-pinned source archive`);
  }
  if (!deepEqual(recipe.target_platforms, ["linux/amd64", "linux/arm64"])) {
    errors.push(`${planRelative}: managed cloud source image must target amd64 and arm64`);
  }
  if (!Number.isInteger(recipe.source_date_epoch) || recipe.source_date_epoch < 1) {
    errors.push(`${planRelative}: managed cloud source image requires a positive SOURCE_DATE_EPOCH`);
  }
  for (const [index, image] of (recipe.base_images ?? []).entries()) {
    validateImage(image, `${planRelative}.build_recipe.base_images[${index}]`, { allowDigestPinnedAlias: true });
    const reference = `${image.repository}:${image.tag}@${image.digest}`;
    if (!dockerfileText.includes(reference)) errors.push(`${planRelative}: declared cloud build image ${reference} is unused`);
  }
  if (recipe.dependency_lock && !digestPattern.test(recipe.dependency_lock.sha256 ?? "")) {
    errors.push(`${planRelative}: managed cloud dependency lock requires an immutable digest`);
  }
  if (recipe.source_patch) {
    const patchPath = resolve(root, recipe.source_patch.path ?? "__missing_patch__");
    if (!existsSync(patchPath) || sha256File(patchPath) !== recipe.source_patch.sha256) {
      errors.push(`${planRelative}: managed cloud source patch is missing or does not match its digest`);
    }
  }
  if (engine.id === "steampipe") {
    for (const [label, value] of [
      ["AWS plugin archive", recipe.aws_plugin?.archive_sha256],
      ["embedded database OCI artifact", recipe.embedded_database?.oci_digest],
      ["PostgreSQL FDW archive", recipe.postgres_fdw?.archive_sha256],
      ["PostgreSQL FDW OCI artifact", recipe.postgres_fdw?.oci_digest],
    ]) {
      if (!digestPattern.test(value ?? "") || !dockerfileText.includes(value)) {
        errors.push(`${planRelative}: ${label} digest is missing from the build closure`);
      }
    }
    for (const revision of [recipe.aws_plugin?.revision, recipe.postgres_fdw?.revision]) {
      if (!revisionPattern.test(revision ?? "") || !dockerfileText.includes(revision)) {
        errors.push(`${planRelative}: Steampipe component revision is missing from the build closure`);
      }
    }
  }
}

function validateCloudQueryPlan(plan, planRelative, engine) {
  const expectedPlugins = [
    {
      name: "cloudquery-source-aws",
      version: "9.2.0",
      release_ref: "plugins-source-aws-v9.2.0",
      source_revision: "804be3a90d6f15d3e6c662c0eb7afa88a9596180",
      path: "/usr/local/libexec/cloudquery-source-aws",
      registry: "local",
    },
    {
      name: "cloudquery-destination-file",
      version: "1.0.2",
      release_ref: "plugins-destination-file-v1.0.2",
      source_revision: "05f02334b9d6ed5de344fd9a9cf7ddead31ce453",
      path: "/usr/local/libexec/cloudquery-destination-file",
      registry: "local",
    },
  ];
  if (!deepEqual(plan.provider_plugins, expectedPlugins)) {
    errors.push(`${planRelative}: CloudQuery provider plugins must retain the exact local public-release closure`);
  }
  const providerLock = plan.provider_lock;
  const lockPath = resolve(root, providerLock?.path ?? "__missing_cloudquery_lock__");
  if (!existsSync(lockPath) || !digestPattern.test(providerLock?.sha256 ?? "") || sha256File(lockPath) !== providerLock.sha256) {
    errors.push(`${planRelative}: CloudQuery provider lock is missing or does not match its digest`);
    return;
  }
  if (providerLock?.install_result !== "anonymous_public_release_artifacts" || providerLock?.source_closure !== "complete" || providerLock?.registry !== "local") {
    errors.push(`${planRelative}: CloudQuery provider lock must declare the complete anonymous local closure`);
  }
  const configurationLock = plan.configuration_lock;
  const configurationPath = resolve(root, configurationLock?.path ?? "__missing_cloudquery_configuration__");
  if (!existsSync(configurationPath) || !digestPattern.test(configurationLock?.sha256 ?? "") || sha256File(configurationPath) !== configurationLock.sha256) {
    errors.push(`${planRelative}: CloudQuery fixed local-plugin configuration is missing or does not match its digest`);
    return;
  }

  const lock = parseJson(lockPath);
  if (!lock) return;
  const expectedTables = [
    "aws_iam_accounts",
    "aws_iam_credential_reports",
    "aws_iam_groups",
    "aws_iam_password_policies",
    "aws_iam_policies",
    "aws_iam_roles",
    "aws_iam_users",
  ];
  const expectedDestinations = [
    "ec2.us-east-1.amazonaws.com:443",
    "iam.amazonaws.com:443",
    "sts.us-east-1.amazonaws.com:443",
  ];
  const expectedAwsActions = [
    "ec2:DescribeRegions",
    "iam:GenerateCredentialReport",
    "iam:GetAccessKeyLastUsed",
    "iam:GetAccountAuthorizationDetails",
    "iam:GetAccountPasswordPolicy",
    "iam:GetAccountSummary",
    "iam:GetCredentialReport",
    "iam:GetGroupPolicy",
    "iam:GetRole",
    "iam:GetRolePolicy",
    "iam:GetUser",
    "iam:GetUserPolicy",
    "iam:ListAccessKeys",
    "iam:ListAccountAliases",
    "iam:ListAttachedGroupPolicies",
    "iam:ListAttachedRolePolicies",
    "iam:ListAttachedUserPolicies",
    "iam:ListGroupPolicies",
    "iam:ListGroups",
    "iam:ListGroupsForUser",
    "iam:ListPolicyTags",
    "iam:ListRolePolicies",
    "iam:ListRoles",
    "iam:ListSSHPublicKeys",
    "iam:ListUserPolicies",
    "iam:ListUsers",
    "sts:GetCallerIdentity",
  ];
  if (lock.schema_version !== "1.0.0" || lock.profile !== "aws-iam-us-east-1" || lock.knowledge_date !== "2023-01-10" ||
      lock.source_repository !== "https://github.com/cloudquery/cloudquery" ||
      !deepEqual(lock.registry, { mode: "local", authenticated: false, runtime_downloads: false })) {
    errors.push(`${providerLock.path}: CloudQuery lock identity or anonymous local registry policy changed`);
  }
  if (!deepEqual(lock.tables, expectedTables)) errors.push(`${providerLock.path}: CloudQuery table allowlist changed`);
  if (!deepEqual(lock.network_destinations, expectedDestinations) || !deepEqual(engine.network_destinations, expectedDestinations)) {
    errors.push(`${providerLock.path}: CloudQuery exact AWS endpoint closure changed`);
  }
  if (!deepEqual(lock.required_aws_actions, expectedAwsActions)) errors.push(`${providerLock.path}: CloudQuery exact AWS read action closure changed`);
  if (!deepEqual(lock.output, { directory: "/output", format: "ndjson-per-table", file_suffix: ".json" })) {
    errors.push(`${providerLock.path}: CloudQuery per-table NDJSON output contract changed`);
  }

  const expectedComponents = new Map([
    ["cloudquery-cli", { version: "2.0.31", release_ref: "cli-v2.0.31", source_revision: "e27e4ab61ad85479a5d53dae9b08440bc63e72b3" }],
    ["cloudquery-source-aws", { version: "9.2.0", release_ref: "plugins-source-aws-v9.2.0", source_revision: "804be3a90d6f15d3e6c662c0eb7afa88a9596180" }],
    ["cloudquery-destination-file", { version: "1.0.2", release_ref: "plugins-destination-file-v1.0.2", source_revision: "05f02334b9d6ed5de344fd9a9cf7ddead31ce453" }],
  ]);
  if (!Array.isArray(lock.components) || lock.components.length !== expectedComponents.size) {
    errors.push(`${providerLock.path}: CloudQuery lock must contain exactly three components`);
  }
  const dockerfilePath = resolve(root, "engines/images/cloudquery/Dockerfile");
  const dockerfileText = existsSync(dockerfilePath) ? readFileSync(dockerfilePath, "utf8") : "";
  for (const component of lock.components ?? []) {
    const expected = expectedComponents.get(component.name);
    if (!expected || component.version !== expected.version || component.release_ref !== expected.release_ref || component.source_revision !== expected.source_revision) {
      errors.push(`${providerLock.path}: CloudQuery component identity changed (${component.name ?? "missing"})`);
      continue;
    }
    const sourceArchive = component.source_archive;
    if (!sourceArchive?.url?.includes(component.source_revision) || !digestPattern.test(sourceArchive?.sha256 ?? "") ||
        !dockerfileText.includes(sourceArchive.url) || !dockerfileText.includes(`ADD --checksum=${sourceArchive.sha256}`)) {
      errors.push(`${providerLock.path}: ${component.name} source archive is not checksum-closed by the Dockerfile`);
    }
    if (!deepEqual(Object.keys(component.artifacts ?? {}), ["linux/amd64", "linux/arm64"])) {
      errors.push(`${providerLock.path}: ${component.name} must lock amd64 and arm64 release artifacts`);
      continue;
    }
    for (const [platform, artifact] of Object.entries(component.artifacts)) {
      const checksums = [artifact.sha256, artifact.archive_sha256, artifact.binary_sha256].filter(Boolean);
      if (!artifact.url?.startsWith("https://github.com/cloudquery/cloudquery/releases/download/") ||
          checksums.length === 0 || checksums.some((digest) => !digestPattern.test(digest)) ||
          !dockerfileText.includes(artifact.url) || checksums.some((digest) => !dockerfileText.includes(digest.slice("sha256:".length)))) {
        errors.push(`${providerLock.path}: ${component.name} ${platform} artifact is not fully checksum-closed by the Dockerfile`);
      }
    }
  }

  const pluginsText = readFileSync(configurationPath, "utf8");
  const launcherPath = resolve(root, "engines/images/cloud-launcher/main.go");
  const launcherText = readFileSync(launcherPath, "utf8");
  const generatedConfiguration = launcherText.match(/func cloudQueryConfiguration\(\) \[\]byte \{\s*return \[\]byte\(`([\s\S]*?)`\)\s*\}/)?.[1];
  if (generatedConfiguration === undefined || generatedConfiguration !== pluginsText) {
    errors.push(`${planRelative}: scanner launcher and reviewed CloudQuery configuration lock differ`);
  }
  const authenticatedRegistry = /(?:hub\.cloudquery\.io|registry:\s*(?:cloudquery|grpc|github)|path:\s*cloudquery\/(?:aws|file)|"authenticated"\s*:\s*true)/i;
  for (const [path, text] of [[configurationLock.path, pluginsText], ["engines/images/cloud-launcher/main.go", launcherText], ["engines/images/cloudquery/Dockerfile", dockerfileText]]) {
    if (authenticatedRegistry.test(text)) errors.push(`${path}: authenticated or remote CloudQuery plugin registry is forbidden`);
  }
  if (!deepEqual(plan.blockers, []) || !engine.compatibility?.runnable || engine.status !== "integrated" || plan.knowledge_date !== "2023-01-10") {
    errors.push(`${planRelative}: CloudQuery must be runnable, integrated, blocker-free, and disclose its 2023-01-10 knowledge date`);
  }
}

function validateManagedRebase(plan, planRelative, engine) {
  if (!plan.verified_upstream_artifact) {
    errors.push(`${planRelative}: managed rebase requires an immutable verified upstream artifact`);
  }
  if (plan.build_recipe !== null) {
    errors.push(`${planRelative}: managed rebase must not compile or download additional build inputs`);
  }
  const dockerfile = plan.dockerfile;
  const expectedPath = `engines/images/${engine.id}/Dockerfile`;
  if (dockerfile?.emitted !== true || dockerfile?.path !== expectedPath) {
    errors.push(`${planRelative}: managed rebase must emit ${expectedPath}`);
    return;
  }
  const dockerfilePath = resolve(root, expectedPath);
  if (!existsSync(dockerfilePath)) {
    errors.push(`${planRelative}: managed rebase Dockerfile is missing`);
    return;
  }
  const actualSha256 = sha256File(dockerfilePath);
  if (dockerfile.sha256 !== actualSha256) {
    errors.push(`${planRelative}: Dockerfile digest ${dockerfile.sha256 ?? "missing"} does not match ${actualSha256}`);
  }
  if (dockerfile.reason !== null) {
    errors.push(`${planRelative}: emitted managed Dockerfile must have a null absence reason`);
  }
  const dockerfileText = readFileSync(dockerfilePath, "utf8");
  const expectedBase = `${plan.verified_upstream_artifact?.repository}@${plan.verified_upstream_artifact?.digest}`;
  if (!dockerfileText.split(/\r?\n/).some((line) => line.trim() === `FROM ${expectedBase}`)) {
    errors.push(`${planRelative}: managed Dockerfile base does not match the verified upstream artifact`);
  }

  const runtime = plan.managed_runtime;
  if (!runtime || typeof runtime !== "object") {
    errors.push(`${planRelative}: managed rebase requires a runtime contract`);
    return;
  }
  if (!/^[1-9][0-9]*:[1-9][0-9]*$/.test(runtime.non_root_user ?? "")) {
    errors.push(`${planRelative}: managed runtime must declare a numeric non-root uid:gid`);
  } else if (!dockerfileText.split(/\r?\n/).some((line) => line.trim() === `USER ${runtime.non_root_user}`)) {
    errors.push(`${planRelative}: managed Dockerfile does not set its declared non-root user`);
  }
  if (!Array.isArray(runtime.entrypoint) || runtime.entrypoint.length !== 1 || shellNames.has(basename(runtime.entrypoint[0] ?? "").toLowerCase())) {
    errors.push(`${planRelative}: managed runtime requires one direct non-shell entrypoint`);
  } else if (!dockerfileText.split(/\r?\n/).some((line) => line.trim() === `ENTRYPOINT ${JSON.stringify(runtime.entrypoint)}`)) {
    errors.push(`${planRelative}: managed Dockerfile does not set its declared direct entrypoint`);
  }
  if (runtime.network_mode !== "disabled" || engine.execution?.network?.mode !== "disabled") {
    errors.push(`${planRelative}: managed offline runtime must disable networking`);
  }
  if (typeof runtime.cache_path !== "string" || !runtime.cache_path.startsWith("/tmp/") || runtime.cache_path.includes("..")) {
    errors.push(`${planRelative}: managed runtime cache must be bounded by the /tmp tmpfs`);
  }
  const environment = runtime.environment;
  if (!environment || Object.values(environment).some((value) => typeof value !== "string" || value.length === 0)) {
    errors.push(`${planRelative}: managed runtime environment must be a non-empty static string map`);
  } else {
    for (const [key, value] of Object.entries(environment)) {
      if (!/^[A-Z][A-Z0-9_]*$/.test(key) || !dockerfileText.includes(`${key}="${value}"`)) {
        errors.push(`${planRelative}: managed Dockerfile is missing declared environment ${key}`);
      }
    }
  }
  if (engine.id === "syft" && environment?.SYFT_CHECK_FOR_APP_UPDATE !== "false") {
    errors.push(`${planRelative}: managed Syft runtime must disable its update check`);
  }
}

function validateManagedSourceImage(plan, planRelative, engine) {
  const recipe = plan.build_recipe;
  if (!recipe || typeof recipe !== "object") {
    errors.push(`${planRelative}: managed source image requires a build recipe`);
    return;
  }
  if (recipe.source_revision !== engine.source_revision) {
    errors.push(`${planRelative}: managed source image recipe must use the catalog source revision`);
  }

  const sourceArchive = recipe.source_archive;
  if (!sourceArchive || typeof sourceArchive.url !== "string" || !sourceArchive.url.startsWith("https://") || !sourceArchive.url.includes(engine.source_revision)) {
    errors.push(`${planRelative}: managed source archive URL must embed the exact source revision`);
  }
  if (!digestPattern.test(sourceArchive?.sha256 ?? "")) {
    errors.push(`${planRelative}: managed source archive requires an immutable sha256 digest`);
  }

  const dependencyLock = recipe.dependency_lock;
  if (dependencyLock?.path !== "Pipfile.lock" || !digestPattern.test(dependencyLock?.sha256 ?? "")) {
    errors.push(`${planRelative}: managed Python source image requires the exact Pipfile.lock digest`);
  }
  if (!Number.isInteger(dependencyLock?.records) || dependencyLock.records < 1) {
    errors.push(`${planRelative}: managed Python source image must declare its runtime lock record count`);
  }
  if (!digestPattern.test(dependencyLock?.rendered_requirements_sha256 ?? "")) {
    errors.push(`${planRelative}: managed Python source image must pin its rendered requirements digest`);
  }
  if (dependencyLock?.require_hashes !== true || dependencyLock?.only_binary !== true) {
    errors.push(`${planRelative}: managed Python dependencies must require hashes and binary distributions`);
  }

  const preparer = recipe.source_preparer;
  const expectedPreparer = `engines/images/${engine.id}/prepare_source.py`;
  if (preparer?.path !== expectedPreparer || !digestPattern.test(preparer?.sha256 ?? "")) {
    errors.push(`${planRelative}: managed source image requires a pinned ${expectedPreparer}`);
  } else {
    const preparerPath = resolve(root, expectedPreparer);
    if (!existsSync(preparerPath)) {
      errors.push(`${planRelative}: managed source preparer is missing`);
    } else {
      const actualPreparerSha256 = sha256File(preparerPath);
      if (preparer.sha256 !== actualPreparerSha256) {
        errors.push(`${planRelative}: source preparer digest ${preparer.sha256} does not match ${actualPreparerSha256}`);
      }
      const preparerText = readFileSync(preparerPath, "utf8");
      for (const expected of [
        engine.source_revision,
        sourceArchive?.sha256?.slice("sha256:".length),
        dependencyLock?.sha256?.slice("sha256:".length),
        `EXPECTED_DEPENDENCIES = ${dependencyLock?.records}`,
      ]) {
        if (expected && !preparerText.includes(expected)) errors.push(`${planRelative}: source preparer is missing locked value ${expected}`);
      }
    }
  }

  if (!Number.isInteger(recipe.source_date_epoch) || recipe.source_date_epoch < 1) {
    errors.push(`${planRelative}: managed source image requires a positive SOURCE_DATE_EPOCH`);
  }
  if (!deepEqual(recipe.target_platforms, ["linux/amd64", "linux/arm64"])) {
    errors.push(`${planRelative}: managed source image must declare its exact publication platforms`);
  }
  if (!Array.isArray(recipe.base_images) || recipe.base_images.length === 0) {
    errors.push(`${planRelative}: managed source image requires at least one digest-pinned base image`);
  }
  const frontend = recipe.dockerfile_frontend;
  validateImage(frontend, `${planRelative}.build_recipe.dockerfile_frontend`);

  const expectedDockerignore = `engines/images/${engine.id}/.dockerignore`;
  const buildContext = recipe.build_context;
  if (buildContext?.dockerignore_path !== expectedDockerignore || !digestPattern.test(buildContext?.dockerignore_sha256 ?? "")) {
    errors.push(`${planRelative}: managed source image requires a pinned minimal .dockerignore`);
  } else {
    const dockerignorePath = resolve(root, expectedDockerignore);
    if (!existsSync(dockerignorePath)) {
      errors.push(`${planRelative}: managed source image .dockerignore is missing`);
    } else if (sha256File(dockerignorePath) !== buildContext.dockerignore_sha256) {
      errors.push(`${planRelative}: managed source image .dockerignore digest does not match its plan`);
    }
  }

  const dockerfile = plan.dockerfile;
  const expectedPath = `engines/images/${engine.id}/Dockerfile`;
  if (dockerfile?.emitted !== true || dockerfile?.path !== expectedPath) {
    errors.push(`${planRelative}: managed source image must emit ${expectedPath}`);
    return;
  }
  const dockerfilePath = resolve(root, expectedPath);
  if (!existsSync(dockerfilePath)) {
    errors.push(`${planRelative}: managed source Dockerfile is missing`);
    return;
  }
  const actualDockerfileSha256 = sha256File(dockerfilePath);
  if (dockerfile.sha256 !== actualDockerfileSha256) {
    errors.push(`${planRelative}: Dockerfile digest ${dockerfile.sha256 ?? "missing"} does not match ${actualDockerfileSha256}`);
  }
  if (dockerfile.reason !== null) {
    errors.push(`${planRelative}: emitted managed Dockerfile must have a null absence reason`);
  }
  const dockerfileText = readFileSync(dockerfilePath, "utf8");
  const expectedFrontend = `# syntax=${frontend?.repository}:${frontend?.tag}@${frontend?.digest}`;
  if (dockerfileText.split(/\r?\n/)[0] !== expectedFrontend) {
    errors.push(`${planRelative}: managed Dockerfile frontend is not digest-pinned to its build recipe`);
  }
  const declaredBases = new Set((recipe.base_images ?? []).map((image) => `${image.repository}:${image.tag}@${image.digest}`));
  const actualBases = [...dockerfileText.matchAll(/^\s*FROM\s+([^\s]+)(?:\s+AS\s+[^\s]+)?\s*$/gmi)].map((match) => match[1]);
  if (actualBases.length === 0 || actualBases.some((reference) => !declaredBases.has(reference))) {
    errors.push(`${planRelative}: managed Dockerfile FROM instructions must match declared base images`);
  }
  for (const reference of declaredBases) {
    if (!actualBases.includes(reference)) errors.push(`${planRelative}: declared base image ${reference} is unused`);
  }
  if (!dockerfileText.includes(`ADD --checksum=${sourceArchive?.sha256 ?? ""}`) || !dockerfileText.includes(sourceArchive?.url ?? "")) {
    errors.push(`${planRelative}: managed Dockerfile does not acquire the checksum-pinned source archive`);
  }
  if (!dockerfileText.includes("--require-hashes") || !dockerfileText.includes("--only-binary=:all:")) {
    errors.push(`${planRelative}: managed Dockerfile does not enforce the hashed binary dependency lock`);
  }
  if (!dockerfileText.includes(`ARG SOURCE_DATE_EPOCH=${recipe.source_date_epoch}`)) {
    errors.push(`${planRelative}: managed Dockerfile does not fix SOURCE_DATE_EPOCH`);
  }
  if (!dockerfileText.includes(`COPY ${expectedPreparer.split("/").at(-1)} `)) {
    errors.push(`${planRelative}: managed Dockerfile does not copy the pinned source preparer`);
  }
  if (!dockerfileText.includes(dependencyLock?.sha256?.slice("sha256:".length) ?? "__missing_lock_digest__")) {
    errors.push(`${planRelative}: managed Dockerfile does not record the dependency lock digest`);
  }

  const runtime = plan.managed_runtime;
  if (!runtime || typeof runtime !== "object") {
    errors.push(`${planRelative}: managed source image requires a runtime contract`);
    return;
  }
  if (!/^[1-9][0-9]*:[1-9][0-9]*$/.test(runtime.non_root_user ?? "")) {
    errors.push(`${planRelative}: managed runtime must declare a numeric non-root uid:gid`);
  } else if (!dockerfileText.split(/\r?\n/).some((line) => line.trim() === `USER ${runtime.non_root_user}`)) {
    errors.push(`${planRelative}: managed Dockerfile does not set its declared non-root user`);
  }
  if (!Array.isArray(runtime.entrypoint) || runtime.entrypoint.length !== 1 || shellNames.has(basename(runtime.entrypoint[0] ?? "").toLowerCase())) {
    errors.push(`${planRelative}: managed runtime requires one direct non-shell entrypoint`);
  } else if (!dockerfileText.split(/\r?\n/).some((line) => line.trim() === `ENTRYPOINT ${JSON.stringify(runtime.entrypoint)}`)) {
    errors.push(`${planRelative}: managed Dockerfile does not set its declared direct entrypoint`);
  }
  if (runtime.network_mode !== "disabled" || engine.execution?.network?.mode !== "disabled") {
    errors.push(`${planRelative}: managed offline runtime must disable networking`);
  }
  if (typeof runtime.cache_path !== "string" || !runtime.cache_path.startsWith("/tmp/") || runtime.cache_path.includes("..")) {
    errors.push(`${planRelative}: managed runtime cache must be bounded by the /tmp tmpfs`);
  }
  const environment = runtime.environment;
  if (!environment || Object.values(environment).some((value) => typeof value !== "string" || value.length === 0)) {
    errors.push(`${planRelative}: managed runtime environment must be a non-empty static string map`);
  } else {
    for (const [key, value] of Object.entries(environment)) {
      if (!/^[A-Z][A-Z0-9_]*$/.test(key) || !dockerfileText.includes(`${key}="${value}"`)) {
        errors.push(`${planRelative}: managed Dockerfile is missing declared environment ${key}`);
      }
    }
  }
  if (engine.id === "checkov") {
    const requiredEnvironment = {
      BC_ENABLE_PERSIST_GRAPHS: "false",
      CKV_BITBUCKET_CONFIG_FETCH_DATA: "false",
      CKV_GITHUB_CONFIG_FETCH_DATA: "false",
      CKV_GITLAB_CONFIG_FETCH_DATA: "false",
      CKV_SKIP_PACKAGE_UPDATE_CHECK: "true",
      XDG_CACHE_HOME: runtime.cache_path,
    };
    for (const [key, value] of Object.entries(requiredEnvironment)) {
      if (environment?.[key] !== value) errors.push(`${planRelative}: managed Checkov runtime requires ${key}=${value}`);
    }
    if (!engine.command.includes("--skip-download") || !engine.command.includes("terraform")) {
      errors.push(`${planRelative}: managed Checkov runtime must retain its fixed offline Terraform command`);
    }
  }
}

function validateManagedExternalImage(plan, planRelative, engine) {
  const dockerfilePath = resolve(root, `engines/images/${engine.id}/Dockerfile`);
  if (plan.dockerfile?.emitted !== true || plan.dockerfile?.path !== `engines/images/${engine.id}/Dockerfile` || !existsSync(dockerfilePath)) {
    errors.push(`${planRelative}: managed external image must emit its engine Dockerfile`);
    return;
  }
  const dockerfileText = readFileSync(dockerfilePath, "utf8");
  if (plan.dockerfile.sha256 !== sha256File(dockerfilePath)) {
    errors.push(`${planRelative}: managed external Dockerfile digest does not match`);
  }
  const launcherPath = resolve(root, "engines/images/external-launcher/main.go");
  if (plan.wrapper?.entrypoint !== "/usr/local/bin/ai-security-scanner-engine-entrypoint" || plan.wrapper?.launcher_sha256 !== sha256File(launcherPath)) {
    errors.push(`${planRelative}: external launcher identity does not match the project-owned source`);
  }
  if (!dockerfileText.includes(`ENTRYPOINT ${JSON.stringify([plan.wrapper?.entrypoint])}`)) {
    errors.push(`${planRelative}: managed external image lacks its direct non-shell entrypoint`);
  }
  const expectedCommand = [
    "--engine", engine.id,
    "--scope", "/run/ai-security-scanner/scope.json", "--output", "/output",
  ];
  if (!deepEqual(plan.command, expectedCommand)) {
    errors.push(`${planRelative}: external command is not the fixed launcher contract`);
  }

  const recipe = plan.build_recipe;
  if (recipe?.source_revision !== engine.source_revision || !recipe?.source_archive?.url?.includes(engine.source_revision) || !digestPattern.test(recipe?.source_archive?.sha256 ?? "")) {
    errors.push(`${planRelative}: external source archive is not closed over the catalog commit and digest`);
  } else if (!dockerfileText.includes(`ADD --checksum=${recipe.source_archive.sha256}`) || !dockerfileText.includes(recipe.source_archive.url)) {
    errors.push(`${planRelative}: external Dockerfile does not acquire the declared exact source archive`);
  }
  if (recipe?.dependency_lock?.path !== "go.sum" || !digestPattern.test(recipe?.dependency_lock?.sha256 ?? "") || !dockerfileText.includes(recipe?.dependency_lock?.sha256?.slice("sha256:".length) ?? "__missing_lock__")) {
    errors.push(`${planRelative}: external Go dependency closure is not checksum-pinned`);
  }
  if (!Number.isInteger(recipe?.source_date_epoch) || recipe.source_date_epoch < 1 || !deepEqual(recipe?.target_platforms, ["linux/amd64", "linux/arm64"])) {
    errors.push(`${planRelative}: external source epoch or publication platforms are invalid`);
  }
  validateImage(recipe?.dockerfile_frontend, `${planRelative}.build_recipe.dockerfile_frontend`);
  const expectedFrontend = `# syntax=${recipe?.dockerfile_frontend?.repository}:${recipe?.dockerfile_frontend?.tag}@${recipe?.dockerfile_frontend?.digest}`;
  if (dockerfileText.split(/\r?\n/)[0] !== expectedFrontend) {
    errors.push(`${planRelative}: external Dockerfile frontend is not the declared immutable frontend`);
  }
  for (const [index, image] of (recipe?.base_images ?? []).entries()) {
    validateImage(image, `${planRelative}.build_recipe.base_images[${index}]`, { allowDigestPinnedAlias: true });
    if (!dockerfileText.includes(`${image.repository}:${image.tag}@${image.digest}`)) {
      errors.push(`${planRelative}: external Dockerfile does not use declared base image ${index}`);
    }
  }
  if (!dockerfileText.includes("-mod=readonly") || !dockerfileText.includes("go mod verify") || !dockerfileText.includes("CGO_ENABLED=0")) {
    errors.push(`${planRelative}: external source build does not enforce its Go module/static-build closure`);
  }

  const runtime = plan.managed_runtime;
  if (runtime?.non_root_user !== "65532:65532" || runtime?.read_only_rootfs !== true || runtime?.network_mode !== "managed_allowlist" || runtime?.proxy !== "AI_SECURITY_SCANNER_PROXY" || runtime?.per_grant_target_execution !== true || runtime?.updates !== false || runtime?.stdin !== false || runtime?.redirects !== false) {
    errors.push(`${planRelative}: external runtime contract is not fail-closed`);
  }
  if (!dockerfileText.split(/\r?\n/).some((line) => line.trim() === `USER ${runtime?.non_root_user}`)) {
    errors.push(`${planRelative}: external Dockerfile does not set its declared non-root user`);
  }
  if (engine.id === "nuclei") {
    const templates = recipe?.templates;
    if (templates?.revision !== engine.rule_version || templates?.revision !== "24858b4bfabfa86f0bcfd36aea24fb535152b012" || !templates?.source_archive?.url?.includes(templates.revision) || !digestPattern.test(templates?.source_archive?.sha256 ?? "")) {
      errors.push(`${planRelative}: Nuclei template artifact is not the required exact revision`);
    } else if (!dockerfileText.includes(`ADD --checksum=${templates.source_archive.sha256}`) || !dockerfileText.includes(templates.source_archive.url)) {
      errors.push(`${planRelative}: Nuclei Dockerfile does not embed the declared exact template artifact`);
    }
    if (!runtime?.template_policy || runtime.template_policy.revision !== `nuclei-templates@${templates?.revision}` || runtime.template_policy.exact_allowlist !== true || runtime.template_policy.denied_capabilities?.some((value) => typeof value !== "string") || runtime.template_policy.denied_capabilities?.length !== 6) {
      errors.push(`${planRelative}: Nuclei runtime lacks the exact conservative template contract`);
    }
  }
}

function validateManagedM365Image(plan, planRelative, engine) {
  const engineRoot = `engines/images/${engine.id}`;
  const dockerfileRelative = `${engineRoot}/Dockerfile`;
  const dockerfilePath = resolve(root, dockerfileRelative);
  if (plan.plan_kind !== "managed_build" || plan.dockerfile?.emitted !== true || plan.dockerfile?.path !== dockerfileRelative || !existsSync(dockerfilePath)) {
    errors.push(`${planRelative}: managed Microsoft 365 image must emit its engine Dockerfile`);
    return;
  }
  const dockerfileText = readFileSync(dockerfilePath, "utf8");
  if (plan.dockerfile.sha256 !== sha256File(dockerfilePath) || plan.dockerfile.reason !== null) {
    errors.push(`${planRelative}: managed Microsoft 365 Dockerfile identity does not match`);
  }
  const frontend = plan.build_recipe?.dockerfile_frontend;
  validateImage(frontend, `${planRelative}.build_recipe.dockerfile_frontend`);
  if (dockerfileText.split(/\r?\n/)[0] !== `# syntax=${frontend?.repository}:${frontend?.tag}@${frontend?.digest}`) {
    errors.push(`${planRelative}: Microsoft 365 Dockerfile frontend is not the declared immutable frontend`);
  }

  const publication = plan.publication;
  if (plan.publish_state !== "published_managed_artifact" ||
      publication?.anonymous_pull_verified !== true ||
      !deepEqual(publication?.platforms, ["linux/amd64", "linux/arm64"]) ||
      !deepEqual(Object.keys(publication?.platform_digests ?? {}), ["linux/amd64", "linux/arm64"]) ||
      !Object.values(publication?.platform_digests ?? {}).every((digest) => digestPattern.test(digest)) ||
      !revisionPattern.test(publication?.source_revision ?? "") ||
      !/^https:\/\/github\.com\/teddashh\/ai-security-scanner\/actions\/runs\/[1-9][0-9]*$/.test(publication?.workflow_run ?? "") ||
      !new RegExp(`^${engine.id}-image-manifest-[1-9][0-9]*$`).test(publication?.evidence_artifact ?? "")) {
    errors.push(`${planRelative}: managed Microsoft 365 image lacks exact anonymous multi-platform publication evidence`);
  }

  const recipe = plan.build_recipe;
  const sourceArchive = recipe?.source_archive;
  if (recipe?.source_revision !== engine.source_revision ||
      !sourceArchive?.url?.includes(engine.source_revision) ||
      !digestPattern.test(sourceArchive?.sha256 ?? "") ||
      !dockerfileText.includes(`ADD --checksum=${sourceArchive?.sha256}`) ||
      !dockerfileText.includes(sourceArchive?.url ?? "")) {
    errors.push(`${planRelative}: Microsoft 365 source archive is not closed over the catalog commit and digest`);
  }
  if (!Number.isInteger(recipe?.source_date_epoch) || recipe.source_date_epoch < 1 ||
      !deepEqual(recipe?.target_platforms, ["linux/amd64", "linux/arm64"])) {
    errors.push(`${planRelative}: Microsoft 365 source epoch or publication platforms are invalid`);
  }
  for (const [index, image] of (recipe?.base_images ?? []).entries()) {
    validateImage(image, `${planRelative}.build_recipe.base_images[${index}]`, { allowDigestPinnedAlias: true });
    if (!dockerfileText.includes(`${image.repository}:${image.tag}@${image.digest}`)) {
      errors.push(`${planRelative}: Microsoft 365 Dockerfile does not use declared base image ${index}`);
    }
  }

  const lockRelative = `${engineRoot}/dependencies.lock.json`;
  const lockPath = resolve(root, lockRelative);
  const lock = existsSync(lockPath) ? parseJson(lockPath) : null;
  const lockText = existsSync(lockPath) ? readFileSync(lockPath, "utf8") : "";
  if (recipe?.dependency_lock?.path !== lockRelative ||
      recipe?.dependency_lock?.sha256 !== sha256File(lockPath) ||
      lock?.engine_id !== engine.id || lock?.source?.revision !== engine.source_revision) {
    errors.push(`${planRelative}: Microsoft 365 dependency closure does not match its exact lock`);
  }
  const preparerPath = resolve(root, "engines/images/m365-launcher/prepare_source.py");
  if (recipe?.source_preparer?.path !== "engines/images/m365-launcher/prepare_source.py" ||
      recipe?.source_preparer?.sha256 !== sha256File(preparerPath) ||
      !dockerfileText.includes("COPY engines/images/m365-launcher/prepare_source.py /opt/prepare_source.py")) {
    errors.push(`${planRelative}: Microsoft 365 source preparer identity does not match`);
  }
  for (const dependency of [...(lock?.powershell_modules ?? []), ...(lock?.native_dependencies ?? [])]) {
    const locations = [dependency.package_url, dependency.license_url, ...Object.values(dependency.artifacts ?? {}).map((artifact) => artifact.url)].filter(Boolean);
    const digests = [dependency.package_sha256, dependency.license_sha256, ...Object.values(dependency.artifacts ?? {}).map((artifact) => artifact.sha256)].filter(Boolean);
    for (const location of locations) if (!dockerfileText.includes(location)) errors.push(`${planRelative}: dependency URL ${location} is absent from the Dockerfile closure`);
    for (const digest of digests) if (!digestPattern.test(digest) || !dockerfileText.includes(digest.slice("sha256:".length)) && !lockText.includes(digest)) errors.push(`${planRelative}: dependency digest ${digest} is absent from the declared build closure`);
  }

  const launcherPath = resolve(root, "engines/images/m365-launcher/main.go");
  const scriptRelative = `${engineRoot}/run-${engine.id}.ps1`;
  const scriptPath = resolve(root, scriptRelative);
  const scriptText = readFileSync(scriptPath, "utf8");
  if (plan.wrapper?.entrypoint !== "/usr/local/bin/ai-security-scanner-m365-launcher" ||
      plan.wrapper?.launcher_sha256 !== sha256File(launcherPath) ||
      plan.wrapper?.script?.path !== scriptRelative ||
      plan.wrapper?.script?.sha256 !== sha256File(scriptPath) ||
      !dockerfileText.includes(`ENTRYPOINT ${JSON.stringify([plan.wrapper?.entrypoint])}`)) {
    errors.push(`${planRelative}: Microsoft 365 launcher or fixed script identity does not match`);
  }
  const expectedCommand = ["--engine", engine.id, "--scope", "/run/ai-security-scanner/scope.json", "--output", "/output"];
  if (!deepEqual(plan.command, expectedCommand)) errors.push(`${planRelative}: Microsoft 365 command is not the fixed launcher contract`);
  for (const forbidden of ["Invoke-WebRequest", "Invoke-RestMethod", "raw.githubusercontent.com", "Resolve-DnsName", "Test-NetConnection", "MSGRAPH_ACCESS_TOKEN="]) {
    if (scriptText.includes(forbidden)) errors.push(`${planRelative}: fixed Microsoft 365 script contains forbidden network or credential behavior ${forbidden}`);
  }
  for (const required of ["/run/ai-security-scanner/credentials.json", "Connect-MgGraph -AccessToken $secureToken", "Get-MgContext", "Disconnect-MgGraph"]) {
    if (!scriptText.includes(required)) errors.push(`${planRelative}: fixed Microsoft 365 script lacks ${required}`);
  }

  const runtime = plan.managed_runtime;
  if (runtime?.non_root_user !== "65532:65532" || runtime?.read_only_rootfs !== true ||
      runtime?.network_mode !== "managed_allowlist" || runtime?.proxy !== "AI_SECURITY_SCANNER_PROXY" ||
      runtime?.updates !== false || runtime?.telemetry !== false || runtime?.stdin !== false ||
      runtime?.credentials_path !== "/run/ai-security-scanner/credentials.json" ||
      runtime?.credential_key !== "MSGRAPH_ACCESS_TOKEN" || runtime?.credential_max_lifetime_minutes !== 65 ||
      !deepEqual(runtime?.network_destinations, ["graph.microsoft.com:443"]) ||
      !deepEqual(runtime?.network_destinations, engine.execution?.network?.destinations) ||
      engine.execution?.network?.mode !== "managed_allowlist") {
    errors.push(`${planRelative}: Microsoft 365 managed runtime is not the exact Graph-only fail-closed contract`);
  }
  if (!dockerfileText.split(/\r?\n/).some((line) => line.trim() === `USER ${runtime?.non_root_user}`)) {
    errors.push(`${planRelative}: Microsoft 365 Dockerfile does not set its declared non-root user`);
  }

  if (engine.id === "scubagear") {
    if (!deepEqual(recipe?.profile, { products: ["aad"], environment: "commercial", login: false, skip_dns_over_https: true, version_check: false, telemetry: false }) ||
        !deepEqual(lock?.product_profile?.network_destinations, ["graph.microsoft.com:443"]) ||
        !scriptText.includes("-ProductNames @('aad')") || !scriptText.includes("-M365Environment 'commercial'") || !scriptText.includes("-SkipDoH $true")) {
      errors.push(`${planRelative}: ScubaGear must retain its exact AAD commercial Graph-only profile`);
    }
  } else {
    const exclusions = ["MT.1025", "MT.1026", "MT.1027", "MT.1028", "MT.1030", "MT.1031", "MT.1182"];
    if (recipe?.profile?.test_path !== "/opt/ai-security-scanner/maester-tests/Maester/Entra" ||
        !deepEqual(recipe?.profile?.exclude_tags, exclusions) || recipe?.profile?.include_long_running !== false ||
        recipe?.profile?.include_preview !== false || recipe?.profile?.version_check !== false || recipe?.profile?.telemetry !== false ||
        !deepEqual(lock?.test_profile?.exclude_tags, exclusions) || !deepEqual(lock?.test_profile?.network_destinations, ["graph.microsoft.com:443"]) ||
        !exclusions.every((tag) => scriptText.includes(`'${tag}'`))) {
      errors.push(`${planRelative}: Maester must retain its exact Graph-only Entra test profile`);
    }
  }
}

const schema = parseJson(schemaPath);
const catalog = parseJson(catalogPath);
const upstreamLock = parseJson(upstreamLockPath);

if (schema && catalog) validateSchemaValue(catalog, schema, "catalog", schema, errors);
if (schema?.$schema !== "https://json-schema.org/draft/2020-12/schema") errors.push("compatibility schema must use JSON Schema draft 2020-12");
if (schema?.minItems !== 21 || schema?.maxItems !== 21) errors.push("compatibility schema must require exactly 21 entries");

const catalogIds = Array.isArray(catalog) ? catalog.map((engine) => engine.id) : [];
if (!deepEqual(catalogIds, expectedIds)) {
  errors.push(`catalog ids/order must be exactly: ${expectedIds.join(", ")}`);
}
if (new Set(catalogIds).size !== catalogIds.length) errors.push("catalog engine ids must be unique");

const lockedRepositories = new Map((upstreamLock?.repositories ?? []).map((entry) => [entry.remote.replace(/\.git$/, ""), entry]));
const supportDates = new Set();

for (const engine of Array.isArray(catalog) ? catalog : []) {
  const label = `catalog:${engine.id}`;
  supportDates.add(engine.compatibility?.support_date);
  validateStaticCommand(engine);
  if (!revisionPattern.test(engine.source_revision ?? "")) errors.push(`${label}.source_revision: exact 40-character commit is required`);
  if (engine.source_revision !== engine.provenance?.engine?.source_revision) errors.push(`${label}: top-level and provenance source revisions differ`);
  if (engine.engine_version !== engine.provenance?.engine?.version) errors.push(`${label}: top-level and provenance engine versions differ`);
  if (engine.rule_version !== engine.provenance?.rules?.revision) errors.push(`${label}: top-level and provenance rule versions differ`);
  if (engine.adapter_version !== engine.provenance?.adapter?.version) errors.push(`${label}: top-level and provenance adapter versions differ`);
  if (engine.compatibility?.runnable && engine.status !== "integrated") errors.push(`${label}: runnable engines must be integrated`);
  if (engine.compatibility?.runnable && engine.compatibility.blocked_by?.length > 0) errors.push(`${label}: runnable engines cannot retain compatibility blockers`);
  if (!engine.compatibility?.runnable && engine.compatibility?.blocked_by?.length === 0) errors.push(`${label}: non-runnable engines must state at least one compatibility blocker`);
  if (engine.default_enabled && (!engine.compatibility?.runnable || engine.status !== "integrated")) errors.push(`${label}: only integrated runnable engines may be default-enabled`);
  if (engine.status === "integrated" && engine.provenance?.adapter?.release_state !== "released") errors.push(`${label}: integrated engine requires a released adapter`);
  if (engine.provenance?.adapter?.release_state === "released" && !revisionPattern.test(engine.provenance.adapter.source_revision ?? "")) {
    errors.push(`${label}: released adapter requires an exact source revision`);
  }
  if (["license_review", "blocked"].includes(engine.license?.disposition) && engine.compatibility?.runnable) errors.push(`${label}: unresolved license disposition cannot be runnable`);
  if (engine.license?.disposition === "source_offer") {
    const offer = engine.license.source_offer_path;
    if (!offer || !existsSync(resolve(root, offer))) errors.push(`${label}: source-offer disposition requires an existing source offer notice`);
  } else if (engine.license?.source_offer_path !== null) {
    errors.push(`${label}: source_offer_path must be null unless disposition is source_offer`);
  }
  if (engine.active_external) {
    const permissions = new Set(engine.required_permissions ?? []);
    if (!permissions.has("low_impact_external_connection") && !permissions.has("active_external_testing")) {
      errors.push(`${label}: active external engine requires an external-connection permission`);
    }
    if (engine.execution?.network?.mode !== "managed_allowlist" || !engine.execution?.network?.required) {
      errors.push(`${label}: active external engine requires a managed network allowlist`);
    }
  }
  if ((engine.network_destinations?.length > 0) !== engine.execution?.network?.required) errors.push(`${label}: network required flag disagrees with declared destinations`);
  if (!deepEqual(engine.network_destinations, engine.execution?.network?.destinations)) errors.push(`${label}: network destinations disagree between runtime and compatibility declarations`);
  if (engine.execution?.network?.mode === "disabled" && engine.network_destinations?.length > 0) errors.push(`${label}: disabled network cannot declare destinations`);
  if (engine.execution?.output && !engine.output_formats?.includes(engine.execution.output.primary_format)) errors.push(`${label}: primary output format is absent from output_formats`);
  if (engine.execution?.resources?.memory_mb !== engine.estimated_memory_mb || engine.execution?.resources?.disk_mb !== engine.estimated_disk_mb) {
    errors.push(`${label}: resource declarations disagree`);
  }
  if (engine.provenance?.data?.mode === "external_pin_required") {
    if (engine.provenance.data.revision !== null || engine.compatibility?.runnable) errors.push(`${label}: unpinned external knowledge must remain non-runnable with null revision`);
    if (engine.compatibility?.knowledge_input?.pin_state !== "awaiting_pin") errors.push(`${label}: unpinned external knowledge must be marked awaiting_pin`);
  }
  if (engine.provenance?.engine?.source_association !== "attested_match" && engine.compatibility?.runnable) {
    errors.push(`${label}: runnable image requires attested matching source provenance`);
  }
  if (engine.distribution_mode === "pull_pinned_image" || engine.distribution_mode === "bundled_image") {
    validateImage(engine.image, `${label}.image`);
  } else if (engine.image !== null) {
    errors.push(`${label}: non-image distribution must not expose an executable image reference`);
  }

  const planRelative = engine.compatibility?.packaging_plan;
  const planPath = planRelative ? resolve(root, planRelative) : null;
  if (!planPath || !existsSync(planPath)) {
    errors.push(`${label}: packaging plan is missing`);
    continue;
  }
  const plan = parseJson(planPath);
  if (!plan) continue;
  if (!planKinds.has(plan.plan_kind)) errors.push(`${planRelative}: unsupported plan kind ${plan.plan_kind}`);
  if (plan.engine_id !== engine.id) errors.push(`${planRelative}: engine id does not match catalog`);
  if (plan.support_date !== engine.compatibility.support_date) errors.push(`${planRelative}: support date does not match catalog`);
  if (plan.source?.revision !== engine.source_revision || plan.build_recipe?.source_revision && plan.build_recipe.source_revision !== engine.source_revision) {
    errors.push(`${planRelative}: source revision does not match catalog`);
  }
  if (!revisionPattern.test(plan.source?.revision ?? "")) errors.push(`${planRelative}: source must be pinned to a commit`);
  if (!deepEqual(plan.command, engine.command)) errors.push(`${planRelative}: command does not match catalog`);
  if (!deepEqual(plan.output, engine.execution?.output)) errors.push(`${planRelative}: output contract does not match catalog`);
  if (!deepEqual(plan.license, engine.license)) errors.push(`${planRelative}: license disposition does not match catalog`);
  if (engine.compatibility?.runnable && plan.blockers?.length > 0) errors.push(`${planRelative}: runnable engine plan cannot retain blockers`);
  if (!engine.compatibility?.runnable && (!Array.isArray(plan.blockers) || plan.blockers.length === 0)) errors.push(`${planRelative}: non-runnable engine plan must state blockers`);
  if (plan.verified_upstream_artifact) validateImage(plan.verified_upstream_artifact, `${planRelative}.verified_upstream_artifact`);
  for (const [index, image] of (plan.build_recipe?.base_images ?? []).entries()) {
    validateImage(image, `${planRelative}.build_recipe.base_images[${index}]`, { allowDigestPinnedAlias: managedCloudIds.has(engine.id) });
  }
  for (const [index, step] of (plan.build_recipe?.static_steps ?? []).entries()) {
    const stepPath = `${planRelative}.build_recipe.static_steps[${index}]`;
    if (!Array.isArray(step) || step.length === 0 || step.some((token) => typeof token !== "string" || token.length === 0)) {
      errors.push(`${stepPath}: must be a static argv array`);
      continue;
    }
    if (shellNames.has(basename(step[0]).toLowerCase())) errors.push(`${stepPath}: shell-based build steps are forbidden`);
    for (const token of step) {
      if (token.includes("${") || token.includes("$(") || token.includes("{{") || token.includes("`") || [";", "&&", "||", "|", ">", ">>", "<"].includes(token)) {
        errors.push(`${stepPath}: dynamic or shell-interpreted token ${JSON.stringify(token)} is forbidden`);
      }
    }
  }
  if (engine.image) {
    validateImage(plan.final_artifact, `${planRelative}.final_artifact`);
    if (!deepEqual(plan.final_artifact, { repository: engine.image.repository, tag: engine.image.tag, digest: engine.image.digest })) errors.push(`${planRelative}: final artifact does not match catalog image`);
  } else if (managedCloudIds.has(engine.id)) {
    const pending = plan.final_artifact;
    if (!pending || typeof pending.repository !== "string" || typeof pending.tag !== "string" || pending.digest !== null || plan.publish_state !== "publication_in_progress") {
      errors.push(`${planRelative}: cloud image publication in progress must retain its exact repository/tag and null digest`);
    } else {
      validateTag(pending.tag, `${planRelative}.final_artifact.tag`);
    }
  } else if (plan.final_artifact?.digest !== null || plan.final_artifact?.tag !== null || plan.publish_state !== "managed_artifact_not_published") {
    errors.push(`${planRelative}: unpublished managed artifact must have null tag/digest and explicit publish state`);
  }
  if (engine.id === "cloudquery") {
    validateCloudManagedImage(plan, planRelative, engine);
    validateCloudQueryPlan(plan, planRelative, engine);
  } else if (managedCloudIds.has(engine.id)) {
    validateCloudManagedImage(plan, planRelative, engine);
  } else if (managedExternalIds.has(engine.id)) {
    validateManagedExternalImage(plan, planRelative, engine);
  } else if (managedM365Ids.has(engine.id)) {
    validateManagedM365Image(plan, planRelative, engine);
  } else if (plan.plan_kind === "managed_rebase") {
    validateManagedRebase(plan, planRelative, engine);
  } else if (plan.plan_kind === "managed_source_image") {
    validateManagedSourceImage(plan, planRelative, engine);
  } else if (plan.plan_kind !== "upstream_image") {
    const lock = lockedRepositories.get(engine.repository_url);
    if (!lock || lock.revision !== engine.source_revision) errors.push(`${planRelative}: managed build source is not pinned by engines/upstreams.lock.json`);
    if (plan.dockerfile?.emitted !== false || !plan.dockerfile?.reason) errors.push(`${planRelative}: absent managed Dockerfile requires an explicit reason`);
  }
}

if (supportDates.size !== 1 || !/^\d{4}-\d{2}-\d{2}$/.test([...supportDates][0] ?? "")) errors.push("all engines must share one explicit ISO support date");

const cloudWorkflowPath = resolve(root, ".github/workflows/engine-images-cloud.yml");
if (!existsSync(cloudWorkflowPath)) {
  errors.push("managed cloud publication workflow is missing");
} else {
  const workflowText = readFileSync(cloudWorkflowPath, "utf8");
  if (!/^\s*workflow_dispatch:\s*$/m.test(workflowText)) {
    errors.push("managed cloud publication workflow must retain workflow_dispatch");
  }
  if (/^\s*-\s*["']?\.github\/workflows\/engine-images-cloud\.yml["']?\s*$/m.test(workflowText)) {
    errors.push("managed cloud publication workflow must not trigger itself");
  }
  for (const engineId of managedCloudIds) {
    const positive = new RegExp(`^\\s*-\\s*["']?engines/images/${engineId}/\\*\\*["']?\\s*$`, "m");
    const negative = new RegExp(`^\\s*-\\s*["']?!engines/images/${engineId}/plan\\.json["']?\\s*$`, "m");
    if (!positive.test(workflowText) || !negative.test(workflowText)) {
      errors.push(`managed cloud publication workflow must watch ${engineId} inputs while excluding digest writeback`);
    }
  }
  if (!/^\s*-\s*["']?engines\/images\/cloud-launcher\/\*\*["']?\s*$/m.test(workflowText)) {
    errors.push("managed cloud publication workflow must watch the shared launcher source");
  }
}

const m365WorkflowPath = resolve(root, ".github/workflows/engine-images-m365.yml");
if (!existsSync(m365WorkflowPath)) {
  errors.push("managed Microsoft 365 publication workflow is missing");
} else {
  const workflowText = readFileSync(m365WorkflowPath, "utf8");
  if (!/^\s*workflow_dispatch:\s*$/m.test(workflowText) ||
      !/^\s*-\s*["']?engines\/images\/m365-launcher\/\*\*["']?\s*$/m.test(workflowText)) {
    errors.push("managed Microsoft 365 workflow must retain dispatch and shared-launcher triggers");
  }
  for (const engineId of managedM365Ids) {
    const positive = new RegExp(`^\\s*-\\s*["']?engines/images/${engineId}/\\*\\*["']?\\s*$`, "m");
    const negative = new RegExp(`^\\s*-\\s*["']?!engines/images/${engineId}/plan\\.json["']?\\s*$`, "m");
    if (!positive.test(workflowText) || !negative.test(workflowText)) {
      errors.push(`managed Microsoft 365 workflow must watch ${engineId} inputs while excluding digest writeback`);
    }
  }
  for (const required of [
    "platforms: linux/amd64,linux/arm64",
    "docker logout ghcr.io",
    "Verify anonymous multi-platform access",
    "Run the anonymous amd64 smoke contract",
    "protectedMountFailClosed: true",
  ]) {
    if (!workflowText.includes(required)) errors.push(`managed Microsoft 365 workflow lacks ${required}`);
  }
}

for (const dockerfile of walkFiles(resolve(root, "engines/images")).filter((path) => {
  const name = basename(path).toLowerCase();
  return name === "dockerfile" || name.startsWith("dockerfile.") && !name.endsWith(".dockerignore");
})) {
  const lines = readFileSync(dockerfile, "utf8").split(/\r?\n/);
  const fromLines = lines.filter((line) => /^\s*FROM\s+/i.test(line));
  if (fromLines.length === 0) errors.push(`${dockerfile}: Dockerfile has no FROM instruction`);
  const stageAliases = new Set();
  for (const line of fromLines) {
    const match = line.trim().match(/^FROM\s+(?:--platform=\S+\s+)?(\S+)(?:\s+AS\s+(\S+))?$/i);
    const reference = match?.[1];
    const dynamicStage = reference?.includes("${TARGETARCH}") && ["amd64", "arm64"].every((architecture) =>
      stageAliases.has(reference.replace("${TARGETARCH}", architecture).toLowerCase()));
    if (!reference || reference !== "scratch" && !stageAliases.has(reference.toLowerCase()) && !dynamicStage && !/@sha256:[0-9a-f]{64}$/.test(reference)) {
      errors.push(`${dockerfile}: every external base image must be pinned by digest (${line.trim()})`);
    }
    if (match?.[2]) stageAliases.add(match[2].toLowerCase());
  }
}

if (errors.length > 0) {
  for (const error of [...new Set(errors)].sort()) console.error(`ERROR ${error}`);
  process.exit(1);
}

const imagePins = catalog.filter((engine) => engine.image).length;
const candidatePins = catalog.filter((engine) => {
  const plan = parseJson(resolve(root, engine.compatibility.packaging_plan));
  return !engine.image && Boolean(plan?.verified_upstream_artifact);
}).length;
const managedPlans = catalog.filter((engine) => engine.compatibility.artifact_state === "managed_build_plan").length;
const multiComponentPlans = catalog.filter((engine) => engine.compatibility.artifact_state === "multi_component_plan").length;
const runnable = catalog.filter((engine) => engine.compatibility.runnable).map((engine) => engine.id);
const licenseReview = catalog.filter((engine) => ["license_review", "blocked"].includes(engine.license.disposition)).map((engine) => engine.id);

console.log(`Validated ${catalog.length} engine compatibility records against ${schemaPath.replace(`${root}/`, "")}.`);
console.log(`Verified final upstream image pins: ${imagePins}; verified candidate/base pins: ${candidatePins}; managed build plans: ${managedPlans}; multi-component plans: ${multiComponentPlans}.`);
console.log(`Runnable now: ${runnable.length ? runnable.join(", ") : "none"}.`);
console.log(`License review: ${licenseReview.join(", ") || "none"}.`);
