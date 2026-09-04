#!/usr/bin/env node

import { readFileSync } from "node:fs";
import { pathToFileURL } from "node:url";

const FRONTEND_PATHS = [
  /^src\//,
  /^tests\/frontend\//,
  /^tests\/component\//,
  /^public\//,
  /^index\.html$/,
  /^tsconfig(?:\.[^/]+)?\.json$/,
  // Matches both the Vite build config and the Vitest component-test config.
  /^vite(?:st)?\.config\.[cm]?[jt]s$/,
  // Frontend tests read these two Rust files directly to check contracts that
  // span the boundary: the coverage-dimension vocabulary the beginner report
  // emits, and the export run coordinate the native command consumes. Without
  // these entries a backend-only commit that breaks either contract runs the
  // Rust lane and skips the lane holding the test that would catch it.
  /^src-tauri\/src\/beginner_report\.rs$/,
  /^src-tauri\/src\/prioritization\.rs$/,
  /^src-tauri\/src\/commands\.rs$/,
];

const RUST_PATHS = [
  /^Cargo\.(?:toml|lock)$/,
  /^src-tauri\/(?:Cargo\.toml|build\.rs|src\/|tests\/|examples\/)/,
  /^bootstrap\//,
  /^engines\/catalog\.json$/,
  /^mappings\/control-mappings\.json$/,
  /^schemas\/master-framework-report\.schema\.json$/,
  /^runtime\/managed-egress-gateway\.json$/,
];

const DESKTOP_PATHS = [
  /^Cargo\.(?:toml|lock)$/,
  /^src-tauri\/(?:Cargo\.toml|app-icon\.svg$|binaries\/|build\.rs|capabilities\/|icons\/|src\/|tauri\.conf\.json$)/,
  /^bootstrap\//,
  /^engines\/catalog\.json$/,
  /^mappings\/control-mappings\.json$/,
  /^schemas\/master-framework-report\.schema\.json$/,
  /^runtime\/managed-egress-gateway\.json$/,
];

const ENGINE_PATHS = [
  /^engines\//,
  /^tests\/engines\//,
  /^scripts\/(?:validate-engine-|prowler-catalog-contract\.mjs$|prepare-offline-engine-data\.mjs$|lock-upstreams\.mjs$|engine-image-evidence\.mjs$|generate-oci-layout-fixture\.mjs$)/,
  /^\.github\/actions\/engine-image-evidence(?:\/|$)/,
  /^\.github\/workflows\/(?:engine-image|engine-images|managed-egress-gateway-image)[^/]*\.ya?ml$/,
  /^\.gitattributes$/,
];

const FRAMEWORK_PATHS = [
  /^mappings\/(?:control-mappings(?:\.schema)?\.json$|vendor\/aidefend(?:\/|$))/,
  /^scripts\/validate-aidefend-snapshot\.mjs$/,
  /^schemas\/master-framework-report\.schema\.json$/,
  /^src-tauri\/src\/exporters\/framework_report\.rs$/,
];

const RELEASE_CONTRACT_PATHS = [
  /^Cargo\.(?:toml|lock)$/,
  /^scripts\/release\//,
  /^tests\/release\//,
  /^\.github\/workflows\/release\.ya?ml$/,
  /^docs\/release\/(?:release-metadata|engine-image-supply-chain)\.schema\.json$/,
  /^runtime\//,
  /^schemas\/master-framework-report\.schema\.json$/,
  /^src-tauri\/(?:Cargo\.toml|tauri\.conf\.json)$/,
  /^src-tauri\/src\/exporters\/framework_report\.rs$/,
  /^src-tauri\/windows\//,
];

const WINDOWS_RUNTIME_PATHS = [
  /^Cargo\.(?:toml|lock)$/,
  /^runtime\/(?:managed-egress-gateway\.json$|managed-runtime\.schema\.json$|upstreams\.lock\.json$|vendor-managed-runtime\.mjs$)/,
  /^src-tauri\/windows\//,
  /^src-tauri\/binaries\//,
  /^src-tauri\/(?:Cargo\.toml|app-icon\.svg$|build\.rs|icons\/|tauri\.conf\.json$)/,
  /^src-tauri\/src\/(?:lib\.rs$|bootstrap\.rs$|bootstrap\/|container_runtime\.rs$|export_identity\.rs$|gateway_release\.rs$|managed_network\.rs$|managed_runtime\.rs$|product_uninstall\.rs$|runtime\.rs$|runtime_health_monitor\.rs$|bin\/(?:bootstrap_broker|cli|egress_gateway)\.rs$)/,
  /^scripts\/release\/(?:build-sidecar|stage-sidecar|generate-runtime-evidence|validate-windows-nsis-template|windows-nsis-[^/]+-evidence)\.mjs$/,
  /^scripts\/release\/qualify-windows[^/]*\.ps1$/,
];

const DOCUMENTATION_PATHS = [
  /^docs\//,
  /^(?:README(?:\.[^/]+)?|CONTRIBUTING|CODE_OF_CONDUCT|SECURITY|THIRD_PARTY)\.md$/,
  /^\.(?:claude|codex)\/skills\/ai-security-scanner\/SKILL\.md$/,
  /^\.github\/(?:ISSUE_TEMPLATE|PULL_REQUEST_TEMPLATE)(?:\/|\.)/,
];

const SHARED_NODE_FILES = new Set(["package.json", "package-lock.json"]);

const CI_RESULT_LANES = Object.freeze([
  Object.freeze({ label: "Frontend", expected: "FRONTEND_EXPECTED", result: "FRONTEND_RESULT" }),
  Object.freeze({ label: "Engine admission", expected: "ENGINE_EXPECTED", result: "ENGINE_RESULT" }),
  Object.freeze({ label: "Framework mapping", expected: "FRAMEWORK_EXPECTED", result: "FRAMEWORK_RESULT" }),
  Object.freeze({ label: "Release contract", expected: "RELEASE_EXPECTED", result: "RELEASE_RESULT" }),
  Object.freeze({ label: "Rust core", expected: "RUST_EXPECTED", result: "RUST_RESULT" }),
  Object.freeze({ label: "Windows managed runtime", expected: "WINDOWS_EXPECTED", result: "WINDOWS_RESULT" }),
  Object.freeze({ label: "Desktop Linux", expected: "DESKTOP_EXPECTED", result: "DESKTOP_RESULT" }),
]);

function matchesAny(path, patterns) {
  return patterns.some((pattern) => pattern.test(path));
}

function normalizePath(value) {
  return value.replaceAll("\\", "/").replace(/^\.\//, "");
}

export function classifyChangedPaths(inputPaths) {
  const paths = [...new Set(inputPaths.map(normalizePath).filter(Boolean))].sort();
  const sharedNodeChanged = paths.some((path) => SHARED_NODE_FILES.has(path));

  const frontend = sharedNodeChanged || paths.some((path) => matchesAny(path, FRONTEND_PATHS));
  const rustCore = paths.some((path) => matchesAny(path, RUST_PATHS));
  const desktop = sharedNodeChanged || paths.some((path) => matchesAny(path, DESKTOP_PATHS));
  const engine = sharedNodeChanged || paths.some((path) => matchesAny(path, ENGINE_PATHS));
  const framework = sharedNodeChanged || paths.some((path) => matchesAny(path, FRAMEWORK_PATHS));
  const releaseContract = sharedNodeChanged || paths.some((path) => matchesAny(path, RELEASE_CONTRACT_PATHS));
  const windowsRuntime = sharedNodeChanged || paths.some((path) => matchesAny(path, WINDOWS_RUNTIME_PATHS));
  const docsOnly = paths.length > 0 && paths.every((path) => matchesAny(path, DOCUMENTATION_PATHS)) &&
    !frontend && !rustCore && !desktop && !engine && !framework && !releaseContract && !windowsRuntime;

  return {
    changed_path_count: paths.length,
    docs_only: docsOnly,
    frontend,
    rust_core: rustCore,
    desktop,
    engine,
    framework,
    release_contract: releaseContract,
    windows_runtime: windowsRuntime,
  };
}

export function classifyAllBoundaries() {
  return {
    changed_path_count: 0,
    docs_only: false,
    frontend: true,
    rust_core: true,
    desktop: true,
    engine: true,
    framework: true,
    release_contract: true,
    windows_runtime: true,
  };
}

export function githubOutputLines(classification) {
  return Object.entries(classification).map(([key, value]) => `${key}=${value}`);
}

export function ciBoundaryResultErrors(changesResult, lanes) {
  if (changesResult !== "success") {
    return [`Changed-boundary classification did not complete successfully (${changesResult || "missing"}).`];
  }

  const errors = [];
  for (const { label, expected, result } of lanes) {
    if (expected === "true") {
      if (result !== "success") errors.push(`${label} was scheduled but finished as ${result || "missing"}.`);
    } else if (expected === "false") {
      if (result !== "skipped") errors.push(`${label} was not scheduled but finished as ${result || "missing"}.`);
    } else {
      errors.push(`${label} has an invalid classifier output: ${expected || "missing"}.`);
    }
  }
  return errors;
}

function verifyCiResultFromEnvironment(environment) {
  const lanes = CI_RESULT_LANES.map(({ label, expected, result }) => ({
    label,
    expected: environment[expected] ?? "",
    result: environment[result] ?? "",
  }));
  return ciBoundaryResultErrors(environment.CHANGES_RESULT ?? "", lanes);
}

function readChangedPaths(arguments_) {
  const bytes = readFileSync(0);
  if (arguments_.includes("--nul")) {
    return bytes.toString("utf8").split("\0");
  }
  return bytes.toString("utf8").split(/\r?\n/);
}

const isMain = process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href;
if (isMain) {
  const arguments_ = process.argv.slice(2);
  if (arguments_.includes("--verify-results")) {
    const errors = verifyCiResultFromEnvironment(process.env);
    if (errors.length > 0) {
      for (const error of errors) process.stderr.write(`::error::${error}\n`);
      process.exitCode = 1;
    } else {
      process.stdout.write("Every scheduled CI boundary completed successfully.\n");
    }
  } else {
    const classification = arguments_.includes("--all")
      ? classifyAllBoundaries()
      : classifyChangedPaths(readChangedPaths(arguments_));
    process.stdout.write(`${githubOutputLines(classification).join("\n")}\n`);
    process.stderr.write(`CI path classification: ${JSON.stringify(classification)}\n`);
  }
}
