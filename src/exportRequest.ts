import type { ExportCaseInput } from "./types";

export type NativeExportCaseArguments = Record<string, unknown> & {
  input: ExportCaseInput & { destination: string };
};

/**
 * Windows can return the visible `.case.tar` name from its save dialog even
 * though the selected bundle filter is gzip. The backend deliberately refuses
 * misleading bundle names. Canonicalize every case-bundle filename at the
 * desktop boundary while leaving destinations for every other format exact.
 */
export const normalizeNativeExportDestination = (
  format: ExportCaseInput["format"],
  destination: string,
): string => {
  if (format !== "case_bundle") return destination;
  if (/\.case\.tar\.gz$/iu.test(destination)) {
    return destination.replace(/\.case\.tar\.gz$/iu, ".case.tar.gz");
  }
  if (/\.case\.tar$/iu.test(destination)) {
    return destination.replace(/\.case\.tar$/iu, ".case.tar.gz");
  }
  if (/\.tar\.gz$/iu.test(destination)) {
    return destination.replace(/\.tar\.gz$/iu, ".case.tar.gz");
  }
  if (/\.gz$/iu.test(destination)) {
    return destination.replace(/\.gz$/iu, ".case.tar.gz");
  }
  return `${destination}.case.tar.gz`;
};

/** Keep the native save-dialog path, including an absolute Windows drive prefix. */
export const buildNativeExportCaseArguments = (
  input: ExportCaseInput,
  destination: string,
): NativeExportCaseArguments => ({
  input: {
    ...input,
    destination: normalizeNativeExportDestination(input.format, destination),
  },
});
