import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import test from "node:test";

const readSource = (name: string) => readFile(
  new URL(`../../src/${name}`, import.meta.url),
  "utf8",
);

test("the edited localhost port path keeps its action and validation feedback accessible", async () => {
  const source = await readSource("pages/StartPage.tsx");

  assert.match(source, /localhostQuickScanAction\.replace\([\s\S]*localhostPortDisplay/u);
  assert.match(source, /disabled=\{localhostQuickScanBusy \|\| localhostPort === undefined\}/u);
  assert.match(source, /aria-describedby="localhost-quick-scan-port-help"/u);
  assert.match(
    source,
    /id="localhost-quick-scan-port-help"[\s\S]*aria-live="polite"[\s\S]*aria-atomic="true"/u,
  );
});

test("the two primary report formats form a named radio group and the save action names the selection", async () => {
  const source = await readSource("pages/ExportPage.tsx");

  assert.match(source, /const primaryFormats = \["html", "json"\]/u);
  assert.match(source, /useState<ExportFormat>\("html"\)/u);
  assert.match(
    source,
    /<fieldset className="export-format-fieldset">[\s\S]*<legend className="sr-only">\{text\(copy\.formatTitle\)\}<\/legend>[\s\S]*primaryFormats\.map\(renderFormatCard\)/u,
  );
  assert.match(source, /Save \{format\}/u);
  assert.match(source, /儲存「\{format\}」/u);
  assert.match(source, /text\(copy\.createExport, \{ format: text\(currentFormat\.title\) \}\)/u);
});

test("preview readiness is announced before export becomes actionable", async () => {
  const source = await readSource("pages/ExportPage.tsx");

  assert.match(source, /disabled=\{busy \|\| previewPending \|\| !previewMatchesSelection\}/u);
  assert.match(source, /aria-busy=\{busy \|\| previewPending\}/u);
  assert.match(
    source,
    /id="export-preview-status"[\s\S]*role=\{previewError \? undefined : "status"\}[\s\S]*aria-live=\{previewError \? undefined : "polite"\}[\s\S]*aria-atomic=\{previewError \? undefined : "true"\}/u,
  );
  assert.doesNotMatch(source, /id="export-preview-status" role="status"/u);
});

test("the export summary follows the current locale for product-owned case and run identities", async () => {
  const source = await readSource("pages/ExportPage.tsx");

  assert.match(source, /caseIdentityPresentation\(workspace\.case, locale\)\.name/u);
  assert.match(source, /scanRunIdentityPresentation\(selectedRun, locale\)/u);
  assert.doesNotMatch(source, /<dd>\{workspace\.case\.name\}<\/dd>/u);
});

test("export history presents a localized run name and keeps the immutable ID technical", async () => {
  const source = await readSource("pages/ExportPage.tsx");
  const historyStart = source.indexOf("{exports.map((item) => {");
  const detailsStart = source.indexOf('<details className="page-technical-details export-row__technical">', historyStart);
  const historyEnd = source.indexOf("</section>", detailsStart);

  assert.ok(historyStart >= 0 && detailsStart > historyStart && historyEnd > detailsStart);
  const beginnerLayer = source.slice(historyStart, detailsStart);
  const technicalLayer = source.slice(detailsStart, historyEnd);

  assert.match(beginnerLayer, /workspace\.runs\.find\(\(run\) => run\.id === item\.runId\)/u);
  assert.match(beginnerLayer, /scanRunIdentityPresentation\(historyRun, locale\)/u);
  assert.match(beginnerLayer, /\{historyRunName\} · \{formatDateTime\(item\.createdAt\)\}/u);
  assert.doesNotMatch(beginnerLayer, /<code>\{item\.runId\}<\/code>/u);
  assert.match(technicalLayer, /text\(copy\.scanRunId\)[\s\S]*<code>\{item\.runId\}<\/code>/u);
});

test("a stale export run offers a real recovery path instead of an endless preview retry", async () => {
  const source = await readSource("pages/ExportPage.tsx");

  assert.match(source, /const selectedRunUnavailable = !selectedRun/u);
  assert.match(
    source,
    /previewError && selectedRunUnavailable[\s\S]*href="#findings"[\s\S]*copy\.chooseRun/u,
  );
  assert.match(source, /previewError && !selectedRunUnavailable[\s\S]*copy\.retryPreview/u);
});

test("a stale results selection is announced instead of visually selecting the first saved run", async () => {
  const source = await readSource("pages/FindingsPage.tsx");

  assert.match(source, /runs\.length > 1 \|\| \(runs\.length > 0 && !latestRun\)/u);
  assert.match(
    source,
    /<select value=\{latestRun\?\.id \?\? ""\}[\s\S]*!latestRun && <option value="" disabled>\{text\(copy\.reportRunUnavailable\)\}<\/option>/u,
  );
});

test("a missing run-bound report never borrows the project's findings from another run", async () => {
  const [app, source] = await Promise.all([
    readSource("App.tsx"),
    readSource("pages/FindingsPage.tsx"),
  ]);

  assert.match(app, /reportUnavailable=\{Boolean\(\(currentRun \|\| selectedReportRunId\) && !currentBeginnerReport\)\}/u);
  assert.match(
    source,
    /report\s*\?[\s\S]*projectReportFindings\(report, canonicalFindings, locale\)[\s\S]*:\s*reportUnavailable\s*\? \[\][\s\S]*:\s*canonicalFindings/u,
  );
  assert.match(source, /\[canonicalFindings, locale, report, reportUnavailable\]/u);
});

test("the shell wires the tested viewport reconciliation into every mobile modal gate", async () => {
  const [shell, styles] = await Promise.all([
    readSource("components/AppShell.tsx"),
    readSource("styles.css"),
  ]);

  assert.match(shell, /id="primary-navigation"/u);
  assert.match(shell, /aria-controls="primary-navigation"/u);
  assert.match(shell, /window\.matchMedia\(MOBILE_NAVIGATION_MEDIA_QUERY\)/u);
  assert.match(shell, /setMobileOpen\(\(current\) => reconcileMobileNavigationOpen\(current, matches\)\)/u);
  assert.match(shell, /mobileDialogOpen = reconcileMobileNavigationOpen\(mobileOpen, narrowViewport\)/u);
  assert.match(shell, /aria-expanded=\{mobileDialogOpen\}/u);
  assert.match(shell, /mobileCloseButtonRef\.current\?\.focus\(\)/u);
  assert.match(shell, /event\.key === "Escape"/u);
  assert.match(shell, /mobileMenuButtonRef\.current\?\.focus\(\)/u);
  assert.match(shell, /event\.key !== "Tab"/u);
  assert.match(shell, /navigation\.querySelectorAll<HTMLElement>/u);
  assert.match(shell, /event\.shiftKey[\s\S]*last\.focus\(\)/u);
  assert.match(shell, /!event\.shiftKey[\s\S]*first\.focus\(\)/u);
  assert.match(shell, /aria-modal=\{mobileDialogOpen \|\| undefined\}/u);
  assert.match(shell, /role=\{mobileDialogOpen \? "dialog" : undefined\}/u);
  assert.match(shell, /\{mobileDialogOpen && \([\s\S]*className="sidebar-backdrop"/u);
  assert.match(shell, /className="workspace" aria-hidden=\{mobileDialogOpen \|\| undefined\}/u);
  assert.match(shell, /if \(narrowViewport\) \{[\s\S]*mobileMenuButtonRef\.current\?\.focus\(\)/u);
  assert.match(shell, /setMobileOpen\(false\), \[page, selectedCase\?\.id\]/u);
  assert.match(
    styles,
    /@media \(max-width: 820px\)[\s\S]*\.sidebar \{ visibility: hidden; pointer-events: none;[\s\S]*\.sidebar--open \{ visibility: visible; pointer-events: auto;/u,
  );
});

test("verification reload restores the saved comparison coordinate before choosing a newer run", async () => {
  const app = await readSource("App.tsx");

  assert.match(app, /selectVerificationBaselineRunId\(\{/u);
  assert.match(app, /previousCaseId: verificationBaselineCaseIdRef\.current/u);
  assert.match(app, /savedRunId: workspace\?\.verification\?\.baselineRunId/u);
  assert.match(app, /verificationBaselineCaseIdRef\.current = nextCaseId/u);
});

test("recoverable scan and export failures stay visible and expose a real destination", async () => {
  const app = await readSource("App.tsx");

  assert.match(app, /if \(!toast\.persistent\) \{[\s\S]*window\.setTimeout/u);
  assert.match(app, /const recoverScanProgress = \(\) => \{[\s\S]*loadSnapshot\(undefined, true\)\.finally\(\(\) => navigate\("progress"\)\)/u);
  assert.match(app, /persistent: result\.mode === "native"[\s\S]*action: result\.mode === "native" \? recoverScanProgress/u);
  assert.match(app, /recordTechnicalError\("start localhost quick scan"[\s\S]*persistent: true[\s\S]*action: recoverScanProgress/u);
  assert.match(app, /recordTechnicalError\("export case"[\s\S]*persistent: true[\s\S]*actionCaseId: exportCaseId/u);
  assert.match(app, /selectedCaseIdRef\.current === exportCaseId\)[\s\S]*exportCase\(options\)/u);
  assert.match(app, /appendExportToMatchingSnapshot\(current, exportCaseId, exported\)/u);
  assert.match(app, /appendExportToMatchingSnapshot\(current, exportCaseId, exported\)[\s\S]*selectedCaseIdRef\.current !== exportCaseId\) return/u);
  assert.match(app, /recordTechnicalError\("export case", error\);[\s\S]*selectedCaseIdRef\.current !== exportCaseId\) return/u);
  assert.match(app, /toast\.actionCaseId === undefined \|\| toast\.actionCaseId === caseId/u);
  assert.match(app, /toast\.titleText \? text\(toast\.titleText\) : toast\.title/u);
  assert.match(app, /toast\.actionLabel && \(toast\.action \|\| toast\.actionPage\)[\s\S]*if \(toast\.action\) toast\.action\(\)[\s\S]*navigate\(toast\.actionPage\)/u);
});
