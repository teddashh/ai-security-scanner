export interface NetworkScanEstimate {
  addressCount: number;
  probeCount: number;
  effectiveRequestsPerSecond: number;
  minimumSeconds: number;
  conservativeUpperSeconds: number;
  engineCeilingSeconds: number;
  mayExceedEngineCeiling: boolean;
}

const IPV4_OCTETS = 4;

// Mirrors the released Naabu host-side execution contract. Keep this named and
// tested so a future engine timeout change cannot silently leave the setup copy
// describing a different ceiling.
export const NAABU_ENGINE_CEILING_SECONDS = 4 * 60 * 60;
const NAABU_PROCESS_ALLOWANCE_SECONDS = 5;

/**
 * Mirrors the backend's `IpNet::hosts()` count for IPv4 CIDRs: ordinary
 * networks exclude their network and broadcast addresses, while /31 and /32
 * retain every address.
 */
export function ipv4CidrHostCount(value: string): number | undefined {
  const match = value.trim().match(/^([^/]+)\/(\d{1,2})$/);
  if (!match) return undefined;
  const address = match[1];
  const prefixText = match[2];
  if (!address || !prefixText) return undefined;

  const octets = address.split(".");
  const prefix = Number(prefixText);
  if (
    octets.length !== IPV4_OCTETS
    || !Number.isInteger(prefix)
    || prefix < 0
    || prefix > 32
    || octets.some((octet) => !/^\d{1,3}$/.test(octet) || Number(octet) > 255)
  ) {
    return undefined;
  }

  const addressCount = 2 ** (32 - prefix);
  return prefix <= 30 ? addressCount - 2 : addressCount;
}

/**
 * Returns only the deterministic pacing floor. Connection timeouts and process
 * setup can make a real scan take longer, so callers must present this as a
 * minimum rather than an ETA.
 */
export function estimateNetworkScanMinimum(
  target: string,
  portCount: number,
  requestsPerSecond: number,
  concurrency: number,
  timeoutSeconds: number,
): NetworkScanEstimate | undefined {
  const addressCount = ipv4CidrHostCount(target);
  if (
    addressCount === undefined
    || !Number.isInteger(portCount)
    || portCount < 1
    || !Number.isInteger(requestsPerSecond)
    || requestsPerSecond < 1
    || !Number.isInteger(concurrency)
    || concurrency < 1
    || !Number.isInteger(timeoutSeconds)
    || timeoutSeconds < 1
  ) {
    return undefined;
  }

  // The pinned Naabu launcher caps proxy-adjusted throughput at the lower of
  // the request-rate and concurrency grants. Using the requested rate alone
  // can substantially understate the pacing floor.
  const effectiveRequestsPerSecond = Math.min(requestsPerSecond, concurrency);
  const probeCount = addressCount * portCount;
  const wavesPerAddress = Math.ceil(portCount / effectiveRequestsPerSecond);
  const conservativeSecondsPerAddress = (
    wavesPerAddress * (timeoutSeconds + 1)
    + NAABU_PROCESS_ALLOWANCE_SECONDS
  );
  const conservativeUpperSeconds = addressCount * conservativeSecondsPerAddress;
  return {
    addressCount,
    probeCount,
    effectiveRequestsPerSecond,
    minimumSeconds: Math.ceil(probeCount / effectiveRequestsPerSecond),
    conservativeUpperSeconds,
    engineCeilingSeconds: NAABU_ENGINE_CEILING_SECONDS,
    mayExceedEngineCeiling: conservativeUpperSeconds > NAABU_ENGINE_CEILING_SECONDS,
  };
}

export function durationParts(totalSeconds: number): { hours: number; minutes: number } {
  const totalMinutes = Math.max(1, Math.ceil(totalSeconds / 60));
  return {
    hours: Math.floor(totalMinutes / 60),
    minutes: totalMinutes % 60,
  };
}
