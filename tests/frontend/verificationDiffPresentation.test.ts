import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import test from "node:test";

import {
  isVerificationDiffReasonDetailRecognized,
  verificationDiffExplanation,
  verificationDiffReasonLabelZhTW,
} from "../../src/verificationPresentation.ts";

const storedExplanation = "Stored comparison explanation from the backend.";

const explanation = (
  comparisonStatus: string,
  beforeSeverity?: string,
  afterSeverity?: string,
): string => verificationDiffExplanation("zh-TW", {
  explanation: storedExplanation,
  comparisonStatus,
  beforeSeverity,
  afterSeverity,
  changeReasons: comparisonStatus === "changed" ? [{
    code: "evidence_changed",
    detail: "evidence hashes changed",
  }] : comparisonStatus === "unable_to_verify" ? [{
    code: "coordinate_not_completed",
    engineId: "engine-verbatim",
    assetId: "asset-verbatim",
    detail: "candidate engine=engine-verbatim, asset=asset-verbatim did not complete",
  }] : [],
});

test("each finding-diff frame is composed in Traditional Chinese", () => {
  for (const [status, before, after, expected] of [
    ["still_present", "high", "high", "目前掃描再次觀察到相同的指紋"],
    ["changed", "high", "high", "仍可觀察到這個問題，但證據雜湊有變更"],
    ["resolved", "high", undefined, "目前掃描已針對原始座標"],
    ["newly_observed", undefined, "high", "基準掃描已完成版本、知識、對照映射"],
    ["unable_to_verify", "high", "high", "兩次掃描都觀察到這個問題，但其座標無法比較"],
    ["unable_to_verify", "high", undefined, "無法判定已解決"],
    ["unable_to_verify", undefined, "high", "無法判定為新問題"],
  ] as const) {
    const presented = explanation(status, before, after);
    assert.ok(presented.includes(expected), `${status}: ${presented}`);
    assert.ok(!presented.includes(storedExplanation), `${status} kept its English frame`);
  }
});

test("reason values and structured coordinates remain verbatim", () => {
  const severity = verificationDiffExplanation("zh-TW", {
    explanation: storedExplanation,
    comparisonStatus: "changed",
    beforeSeverity: "high",
    afterSeverity: "critical",
    changeReasons: [{
      code: "severity_changed",
      detail: "severity changed from high to critical",
    }],
  });
  assert.ok(severity.includes("嚴重程度從 high 變更為 critical"), severity);

  const coordinate = verificationDiffExplanation("zh-TW", {
    explanation: storedExplanation,
    comparisonStatus: "unable_to_verify",
    beforeSeverity: "high",
    changeReasons: [{
      code: "engine_version_changed",
      engineId: "scanner/v9.7",
      assetId: "acct:PersonTypedName",
      detail: "engine version changed",
    }],
  });
  assert.ok(coordinate.includes("scanner/v9.7"), coordinate);
  assert.ok(coordinate.includes("acct:PersonTypedName"), coordinate);
  assert.ok(coordinate.includes("掃描工具版本有變更"), coordinate);

  const missingFields = verificationDiffExplanation("zh-TW", {
    explanation: storedExplanation,
    comparisonStatus: "unable_to_verify",
    beforeSeverity: "high",
    changeReasons: [{
      code: "comparison_identity_missing",
      engineId: "scanner-stays-verbatim",
      assetId: "asset-stays-verbatim",
      detail: "reference missing manifest_schema_version, image_digest; candidate missing knowledge_input",
    }],
  });
  for (const value of [
    "scanner-stays-verbatim",
    "asset-stays-verbatim",
    "manifest_schema_version, image_digest",
    "knowledge_input",
  ]) assert.ok(missingFields.includes(value), `${value} was lost from ${missingFields}`);
  assert.ok(missingFields.includes("參考執行缺少"), missingFields);
  assert.ok(missingFields.includes("候選執行缺少"), missingFields);
});

test("a known code with an unknown detail shape labels and preserves the stored detail", () => {
  const futureDetail = "engine version changed under a future comparison contract";
  const presented = verificationDiffExplanation("zh-TW", {
    explanation: storedExplanation,
    comparisonStatus: "unable_to_verify",
    beforeSeverity: "high",
    changeReasons: [{ code: "engine_version_changed", detail: futureDetail }],
  });
  assert.ok(presented.includes("掃描工具版本有變更"), presented);
  assert.ok(presented.includes(futureDetail), presented);
});

test("an unknown reason code preserves its stored English detail", () => {
  const futureDetail = "A future build recorded an unfamiliar comparison reason.";
  const presented = verificationDiffExplanation("zh-TW", {
    explanation: storedExplanation,
    comparisonStatus: "unable_to_verify",
    beforeSeverity: "high",
    changeReasons: [{ code: "future_reason_code", detail: futureDetail }],
  });
  assert.ok(presented.includes(futureDetail), presented);
  assert.ok(!presented.includes("future_reason_code"), presented);
});

test("English returns the stored explanation untouched", () => {
  assert.equal(verificationDiffExplanation("en", {
    explanation: storedExplanation,
    comparisonStatus: "changed",
    beforeSeverity: "high",
    afterSeverity: "critical",
    changeReasons: [{
      code: "severity_changed",
      detail: "severity changed from high to critical",
    }],
  }), storedExplanation);
});

const diffSource = readFileSync(
  new URL("../../src-tauri/src/diff.rs", import.meta.url),
  "utf8",
);
const diffProduction = diffSource.slice(0, diffSource.indexOf("#[cfg(test)]"));
const domainSource = readFileSync(
  new URL("../../src-tauri/src/domain.rs", import.meta.url),
  "utf8",
);

const matchingParen = (source: string, open: number): number => {
  let depth = 0;
  let quoted = false;
  let escaped = false;
  for (let index = open; index < source.length; index += 1) {
    const character = source[index];
    if (quoted) {
      if (escaped) escaped = false;
      else if (character === "\\") escaped = true;
      else if (character === "\"") quoted = false;
      continue;
    }
    if (character === "\"") quoted = true;
    else if (character === "(") depth += 1;
    else if (character === ")" && --depth === 0) return index;
  }
  throw new Error(`unclosed call at source offset ${open}`);
};

const calls = (source: string, name: string): string[] => {
  const bodies: string[] = [];
  const pattern = new RegExp(`\\b${name}\\s*\\(`, "gu");
  for (const match of source.matchAll(pattern)) {
    const open = (match.index ?? 0) + match[0].lastIndexOf("(");
    const close = matchingParen(source, open);
    bodies.push(source.slice(open + 1, close));
  }
  return bodies;
};

const splitArguments = (body: string): string[] => {
  const parts: string[] = [];
  let start = 0;
  let depth = 0;
  let quoted = false;
  let escaped = false;
  for (let index = 0; index < body.length; index += 1) {
    const character = body[index];
    if (quoted) {
      if (escaped) escaped = false;
      else if (character === "\\") escaped = true;
      else if (character === "\"") quoted = false;
      continue;
    }
    if (character === "\"") quoted = true;
    else if ("([{<".includes(character)) depth += 1;
    else if ([")", "]", "}", ">"].includes(character)) depth -= 1;
    else if (character === "," && depth === 0) {
      parts.push(body.slice(start, index).trim());
      start = index + 1;
    }
  }
  parts.push(body.slice(start).trim());
  return parts;
};

const rustString = (expression: string): string | undefined =>
  expression.match(/"([^"\\]*(?:\\.[^"\\]*)*)"/u)?.[1];
const rustCode = (expression: string): string | undefined =>
  expression.match(/FindingDiffReasonCode::([A-Za-z0-9_]+)/u)?.[1];
const snakeCase = (value: string): string =>
  value.replace(/([a-z0-9])([A-Z])/gu, "$1_$2").toLowerCase();

interface ProducerDetailShape {
  code: string;
  frame: string;
}

const detailShapes: ProducerDetailShape[] = [];
for (const body of calls(diffProduction, "reason")) {
  const args = splitArguments(body);
  const code = rustCode(args[0] ?? "");
  const detailExpression = args[3] ?? "";
  const frame = /^(?:format!\s*\(|")/u.test(detailExpression)
    ? rustString(detailExpression)
    : undefined;
  if (code && frame) detailShapes.push({ code: snakeCase(code), frame });
}
for (const body of calls(diffProduction, "compare_identity_field")) {
  const args = splitArguments(body);
  const code = rustCode(args[3] ?? "");
  const frame = rustString(args[6] ?? "");
  if (code && frame) detailShapes.push({ code: snakeCase(code), frame });
}
for (const match of diffProduction.matchAll(/details\.push\(format!\("([^"]+)"/gu)) {
  detailShapes.push({ code: "comparison_identity_missing", frame: match[1] ?? "" });
}

const uniqueDetailShapes = [...new Map(
  detailShapes.map((shape) => [`${shape.code}\0${shape.frame}`, shape]),
).values()];
const producerCodes = [...new Set(Array.from(
  diffProduction.matchAll(/FindingDiffReasonCode::([A-Za-z0-9_]+)/gu),
  (match) => snakeCase(match[1] ?? ""),
))];
const enumBody = domainSource.match(/pub enum FindingDiffReasonCode\s*\{([\s\S]*?)\n\}/u)?.[1] ?? "";
const enumCodes = Array.from(
  enumBody.matchAll(/^\s*([A-Z][A-Za-z0-9_]*),\s*$/gmu),
  (match) => snakeCase(match[1] ?? ""),
);

const fillFrame = (frame: string): string => {
  let positional = 0;
  return frame
    .replaceAll("{side}", "reference")
    .replaceAll("{engine_id}", "engine-census")
    .replaceAll("{coordinate}", "asset-census")
    .replaceAll("{}", () => positional++ === 0 ? "high" : "critical");
};

test("the finding-diff reason producer vocabulary was found", () => {
  // Lower bounds: a new, fully presented code or detail shape is valid; every
  // extracted value still has to pass the completeness assertions below.
  assert.ok(producerCodes.length >= 20, `found only ${producerCodes.length} reason codes`);
  assert.ok(uniqueDetailShapes.length >= 27, `found only ${uniqueDetailShapes.length} detail shapes`);
  assert.ok(uniqueDetailShapes.some(({ frame }) => frame.includes("severity changed from")));
  assert.ok(uniqueDetailShapes.some(({ frame }) => frame.includes("reference missing")));
  assert.ok(uniqueDetailShapes.some(({ frame }) => frame.includes("scope-grant snapshot")));
});

test("every reason code constructed by the producer has a Chinese label", () => {
  for (const code of producerCodes) {
    assert.ok(verificationDiffReasonLabelZhTW(code), `reason code has no Chinese label: ${code}`);
  }
});

test("every FindingDiffReasonCode enum variant has a Chinese label", () => {
  assert.ok(enumCodes.length >= 20, `found only ${enumCodes.length} enum variants`);
  for (const code of enumCodes) {
    assert.ok(verificationDiffReasonLabelZhTW(code), `enum reason code has no Chinese label: ${code}`);
  }
});

test("every detail shape authored by the producer is recognized", () => {
  for (const { code, frame } of uniqueDetailShapes) {
    const detail = fillFrame(frame);
    assert.ok(
      isVerificationDiffReasonDetailRecognized(code, detail),
      `unrecognized ${code} detail shape: ${frame} -> ${detail}`,
    );
  }
});
