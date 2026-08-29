import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import test from "node:test";

import {
  buildNativeExportCaseArguments,
  normalizeNativeExportDestination,
} from "../../src/exportRequest.ts";
import type { ExportCaseInput } from "../../src/types.ts";

const input = (format: ExportCaseInput["format"]): ExportCaseInput => ({
  caseId: "case-1",
  format,
  includeRawEvidence: false,
  redactSensitiveValues: true,
});

test("native export arguments preserve absolute Windows save-dialog paths", () => {
  for (const [format, destination] of [
    ["html", String.raw`C:\Users\example\Downloads\assessment-report.html`],
    ["json", String.raw`C:\Users\example\Downloads\assessment-report.json`],
    ["framework_report", String.raw`C:\Users\example\Downloads\assessment-report.frameworks.json`],
  ] as const) {
    assert.deepEqual(buildNativeExportCaseArguments(input(format), destination), {
      input: { ...input(format), destination },
    });
  }
});

test("Windows case-bundle save names receive the required gzip suffix", () => {
  const destination = String.raw`C:\Users\example\Downloads\assessment.case.tar`;

  assert.equal(
    normalizeNativeExportDestination("case_bundle", destination),
    String.raw`C:\Users\example\Downloads\assessment.case.tar.gz`,
  );
  assert.deepEqual(buildNativeExportCaseArguments(input("case_bundle"), destination), {
    input: {
      ...input("case_bundle"),
      destination: String.raw`C:\Users\example\Downloads\assessment.case.tar.gz`,
    },
  });
  assert.equal(
    normalizeNativeExportDestination(
      "case_bundle",
      String.raw`C:\Users\example\Downloads\Assessment.CASE.TAR`,
    ),
    String.raw`C:\Users\example\Downloads\Assessment.case.tar.gz`,
  );
});

test("case-bundle destination repair always supplies the backend's compound suffix", () => {
  assert.equal(
    normalizeNativeExportDestination(
      "case_bundle",
      String.raw`\\server\share\Assessment.CASE.TAR.GZ`,
    ),
    String.raw`\\server\share\Assessment.case.tar.gz`,
  );
  assert.equal(
    normalizeNativeExportDestination(
      "case_bundle",
      String.raw`C:\Users\example\Downloads\assessment.tar.gz`,
    ),
    String.raw`C:\Users\example\Downloads\assessment.case.tar.gz`,
  );
  assert.equal(
    normalizeNativeExportDestination(
      "case_bundle",
      String.raw`C:\Users\example\Downloads\assessment.gz`,
    ),
    String.raw`C:\Users\example\Downloads\assessment.case.tar.gz`,
  );
  assert.equal(
    normalizeNativeExportDestination(
      "case_bundle",
      String.raw`C:\Users\example\Downloads\assessment`,
    ),
    String.raw`C:\Users\example\Downloads\assessment.case.tar.gz`,
  );
  assert.equal(
    normalizeNativeExportDestination(
      "html",
      String.raw`C:\Users\example\Downloads\assessment.case.tar`,
    ),
    String.raw`C:\Users\example\Downloads\assessment.case.tar`,
  );
});

test("the native scanner forwards the path returned by the save dialog", () => {
  const source = readFileSync(new URL("../../src/services/scanner.ts", import.meta.url), "utf8");
  assert.match(source, /buildNativeExportCaseArguments\(input, destination\)/u);
  assert.match(source, /framework_report:[\s\S]*suffix: "frameworks\.json"/u);
});
