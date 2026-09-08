import type { TransportProtocol } from "./types";

export const websiteQuickProfile = {
  templateRevision: "nuclei-templates@24858b4bfabfa86f0bcfd36aea24fb535152b012",
  profileId: "nuclei_web_safe_v1",
  engineIds: ["nuclei"],
  ratePolicy: {
    requestsPerSecond: 10,
    concurrency: 5,
    timeoutSeconds: 10,
  },
  allowedTemplateIds: [] as string[],
} as const;

export const websiteQuickOrigin = (
  target: string,
  protocol: Extract<TransportProtocol, "http" | "https">,
  port: number,
): string => {
  const host = target.includes(":") && !target.startsWith("[") ? `[${target}]` : target;
  return `${protocol}://${host}:${port}`;
};
