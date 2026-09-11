import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import test from "node:test";

type CatalogEngine = {
  id: string;
  repository_url: string;
  status: string;
};

type StarSnapshot = {
  schemaVersion: number;
  checkedAt: string;
  source: string;
  tools: Array<{ id: string; repository: string; stars: number }>;
  ruleSources: Array<{ repository: string; stars: number }>;
};

const workspaceFile = (path: string) => readFile(new URL(`../../${path}`, import.meta.url), "utf8");

const occurrences = (source: string, value: string) => source.split(value).length - 1;

test("the bilingual project site lists every integrated upstream engine exactly once", async () => {
  const [catalogSource, site, readme, readmeZh] = await Promise.all([
    workspaceFile("engines/catalog.json"),
    workspaceFile("docs/index.html"),
    workspaceFile("README.md"),
    workspaceFile("README.zh-TW.md"),
  ]);
  const catalog = JSON.parse(catalogSource) as CatalogEngine[];
  const integrated = catalog.filter((engine) => engine.status === "integrated");

  assert.equal(integrated.length, 21);
  assert.equal(occurrences(site, 'class="tool-card" data-tool='), integrated.length);
  for (const engine of integrated) {
    assert.equal(occurrences(site, `data-tool="${engine.id}"`), 1, `${engine.id} site card`);
    assert.equal(occurrences(site, `href="${engine.repository_url}"`), 1, `${engine.id} site link`);
    assert.ok(readme.includes(engine.repository_url), `${engine.id} English README link`);
    assert.ok(readmeZh.includes(engine.repository_url), `${engine.id} Chinese README link`);
  }

  assert.match(site, /Many security tools[\s\S]*One clear report/u);
  assert.match(site, /多種安全工具[\s\S]*一份清楚報告/u);
  assert.match(site, /completed sibling results survive/iu);
  assert.match(site, /其他已完成結果仍會保留/u);
  assert.match(readme, /Selected assets → applicable upstream tools → thin adapters → one prioritized report organized by asset/u);
  assert.match(readmeZh, /選定資產 → 適用的上游工具 → 薄層轉接器 → 一份依資產整理、排好優先順序的報告/u);
});

test("the displayed GitHub stars match the dated API snapshot", async () => {
  const [snapshotSource, site] = await Promise.all([
    workspaceFile("docs/tool-stars.json"),
    workspaceFile("docs/index.html"),
  ]);
  const snapshot = JSON.parse(snapshotSource) as StarSnapshot;

  assert.equal(snapshot.schemaVersion, 1);
  assert.equal(snapshot.source, "GitHub REST API");
  assert.ok(Number.isFinite(Date.parse(snapshot.checkedAt)));
  assert.equal(snapshot.tools.length, 21);
  assert.equal(new Set(snapshot.tools.map((entry) => entry.id)).size, 21);

  for (const entry of [...snapshot.tools, ...snapshot.ruleSources]) {
    assert.ok(Number.isSafeInteger(entry.stars) && entry.stars >= 0, entry.repository);
    assert.equal(occurrences(site, `<data value="${entry.stars}">`), 1, `${entry.repository} star count`);
    assert.equal(occurrences(site, `href="https://github.com/${entry.repository}"`), 1, `${entry.repository} link`);
  }
});

test("the project site stays local, responsive, bilingual, and GitHub Pages ready", async () => {
  const [site, styles, script, noJekyll, packageSource] = await Promise.all([
    workspaceFile("docs/index.html"),
    workspaceFile("docs/project-site.css"),
    workspaceFile("docs/project-site.js"),
    workspaceFile("docs/.nojekyll"),
    workspaceFile("package.json"),
  ]);

  assert.equal(noJekyll, "\n");
  assert.match(site, /<html lang="en" data-lang="en">/u);
  assert.ok(occurrences(site, 'class="lang-en"') >= 50);
  assert.ok(occurrences(site, 'class="lang-zh"') >= 50);
  assert.match(site, /<link rel="stylesheet" href="project-site\.css">/u);
  assert.match(site, /<script src="project-site\.js" defer><\/script>/u);
  assert.doesNotMatch(site, /<(?:script|img)[^>]+src="https?:\/\//iu);
  assert.doesNotMatch(site, /<link[^>]+rel="stylesheet"[^>]+href="https?:\/\//iu);
  assert.match(styles, /@media \(max-width: 720px\)/u);
  assert.match(styles, /@media \(prefers-reduced-motion: reduce\)/u);
  assert.match(script, /document\.documentElement\.lang/u);
  assert.match(script, /aria-pressed/u);
  assert.doesNotMatch(script, /innerHTML|document\.write/u);

  const packageMetadata = JSON.parse(packageSource) as { homepage?: string };
  assert.equal(packageMetadata.homepage, "https://teddashh.github.io/ai-security-scanner/");
});
