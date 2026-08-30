export const DEFAULT_LOCALHOST_QUICK_SCAN_PORT = 9001;

export const isValidLocalhostQuickScanPort = (port: number): boolean =>
  Number.isInteger(port) && port >= 1 && port <= 65_535;

export const parseLocalhostQuickScanPort = (value: string): number | undefined => {
  const normalized = value.trim();
  if (!/^\d{1,5}$/u.test(normalized)) return undefined;
  const port = Number(normalized);
  return isValidLocalhostQuickScanPort(port) ? port : undefined;
};
