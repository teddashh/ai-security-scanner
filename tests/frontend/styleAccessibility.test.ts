import assert from "node:assert/strict";
import { readdir, readFile } from "node:fs/promises";
import test from "node:test";

const srcUrl = new URL("../../src/", import.meta.url);
const stylesUrl = new URL("styles.css", srcUrl);
const knownLightSurfaces = ["#ffffff", "#f7f8f5", "#f0f9f6", "#edf7d8", "#fff3d9", "#f2faf6"];

const cssFiles = async (): Promise<Array<{ path: string; url: URL }>> => {
  const paths = (await readdir(srcUrl, { recursive: true }))
    .filter((path) => path.endsWith(".css"))
    .sort();
  return paths.map((path) => ({ path, url: new URL(path, srcUrl) }));
};

const channelLuminance = (channel: number): number => {
  const value = channel / 255;
  return value <= 0.04045 ? value / 12.92 : ((value + 0.055) / 1.055) ** 2.4;
};

const luminance = (hex: string): number => {
  const channels = hex.match(/[0-9a-f]{2}/giu)?.map((value) => Number.parseInt(value, 16));
  assert.equal(channels?.length, 3, `expected a six-digit colour, received ${hex}`);
  return 0.2126 * channelLuminance(channels[0]!)
    + 0.7152 * channelLuminance(channels[1]!)
    + 0.0722 * channelLuminance(channels[2]!);
};

const contrastRatio = (left: string, right: string): number => {
  const [lighter, darker] = [luminance(left), luminance(right)].sort((a, b) => b - a);
  return (lighter! + 0.05) / (darker! + 0.05);
};

test("secondary text tokens retain WCAG AA contrast on known light product surfaces", async () => {
  const styles = await readFile(stylesUrl, "utf8");

  for (const token of ["muted", "subtle"]) {
    const color = styles.match(new RegExp(`--${token}:\\s*(#[0-9a-f]{6})\\s*;`, "iu"))?.[1];
    assert.ok(color, `src/styles.css must define a six-digit --${token} colour`);

    for (const surface of knownLightSurfaces) {
      assert.ok(
        contrastRatio(color, surface) >= 4.5,
        `--${token} (${color}) must have at least 4.5:1 contrast against ${surface}`,
      );
    }
  }
});

test("all source stylesheets keep explicit font sizes above the product text floor", async () => {
  const files = await cssFiles();
  assert.ok(files.length > 1, "the check must enumerate every CSS file below src");

  for (const file of files) {
    const styles = await readFile(file.url, "utf8");
    const declarations = styles.matchAll(/font-size:\s*([0-9]*\.?[0-9]+)(rem|em|px)\b/giu);

    for (const match of declarations) {
      const value = Number(match[1]);
      const minimum = match[2]?.toLowerCase() === "px" ? 11.5 : 0.72;
      assert.ok(
        value >= minimum,
        `${file.path}: font-size: ${match[1]}${match[2]} is below ${minimum}${match[2]}`,
      );
    }
  }
});

test("finding status labels wrap instead of widening the 320px layout", async () => {
  const styles = await readFile(stylesUrl, "utf8");
  assert.match(styles, /\.finding-row__top\s*\{[^}]*flex-wrap:\s*wrap\s*;/su);
  assert.match(
    styles,
    /\.finding-row__top\s+\.status-pill\s*\{[^}]*max-width:\s*100%\s*;[^}]*white-space:\s*normal\s*;/su,
  );
});
