/**
 * Names the exact dimension of coverage a beginner-report row is speaking
 * about. The backend authors these as English prose and they are the only thing
 * distinguishing one gap from the next: the surrounding row text is generated
 * from the gap's `kind` and `nextActionCode`, so two gaps sharing a kind are
 * told apart by this string alone.
 *
 * The implementation lives in `findingNarrative.ts` because the shared HTML
 * report names the same rows and Rust composes the identical sentence there —
 * that file is where the two languages are held to each other. Re-exported here
 * so the pages that show coverage keep importing it from one obvious place.
 */
export { localizedCoverageDimension } from "./findingNarrative.ts";

/** Appends the identifier a composed name carries, when it has one. */
const withIdentifier = (label: string, identifier: string): string =>
  identifier ? `${label}（${identifier}）` : label;

/**
 * Names one limit the run was executed under. The backend composes most of
 * these as "<engine or asset id> <limit kind>", so translating the kind alone
 * erases the only part saying which scanner or which authorized target the
 * limit applied to. A case with three scope grants would otherwise show three
 * rows all reading "approved ports" with no way to attribute them.
 */
export const localizedRequestedLimitName = (
  name: string,
  locale: "en" | "zh-TW",
): string => {
  if (locale === "en") return name;
  if (name === "endpoint") return "連線端點";
  if (name === "connection timeout") return "連線逾時限制";
  if (name === "application payload") return "應用資料量";
  for (const [suffix, label] of [
    ["approved ports", "允許檢查的連接埠"],
    ["request rate", "請求速率"],
    ["network timeout", "網路逾時限制"],
    ["authorized network target", "已確認的網路目標"],
    ["execution timeout", "檢查逾時限制"],
  ] as const) {
    if (name.endsWith(suffix)) {
      return withIdentifier(label, name.slice(0, name.length - suffix.length).trim());
    }
  }
  return `本輪使用的限制：${name}`;
};
