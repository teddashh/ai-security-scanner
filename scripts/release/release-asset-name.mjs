import path from "node:path";

import { assertSafeRelativePath, toPosix } from "./lib.mjs";

export const NESTED_RELEASE_ASSET_PREFIX = "path-v1-";

const SAFE_ASSET_NAME = /^[0-9A-Za-z](?:[0-9A-Za-z._-]*[0-9A-Za-z_-])?$/u;

function assert(condition, message) {
  if (!condition) throw new Error(message);
}

export function publishedReleaseAssetName(relative) {
  assertSafeRelativePath(relative);
  assert(
    relative === toPosix(relative) &&
      relative === path.posix.normalize(relative) &&
      relative === relative.normalize("NFC") &&
      relative === relative.normalize("NFKC"),
    `release asset path is not canonical POSIX text: ${relative}`,
  );
  const nested = relative.includes("/");
  assert(
    nested || !relative.toLowerCase().startsWith(NESTED_RELEASE_ASSET_PREFIX),
    `flat release asset uses the reserved nested-path prefix: ${relative}`,
  );
  const name = nested
    ? `${NESTED_RELEASE_ASSET_PREFIX}${Buffer.from(relative, "utf8").toString("base64url")}`
    : relative;
  assert(
    name.length <= 255 && SAFE_ASSET_NAME.test(name),
    `release asset has no canonical GitHub-safe publication name: ${relative}`,
  );
  if (nested) {
    assert(
      Buffer.from(name.slice(NESTED_RELEASE_ASSET_PREFIX.length), "base64url").toString("utf8") === relative,
      `release asset publication name is not reversible: ${relative}`,
    );
  }
  return name;
}
