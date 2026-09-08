import type { TransportProtocol } from "./types";

export const websiteQuickProfile = {
  templateRevision: "nuclei-templates@24858b4bfabfa86f0bcfd36aea24fb535152b012",
  engineIds: ["nuclei"],
  ratePolicy: {
    requestsPerSecond: 3,
    concurrency: 2,
    timeoutSeconds: 10,
  },
  allowedTemplateIds: [
    "htpasswd-detection",
    "git-credentials-disclosure",
    "npmrc-authtoken",
    "configuration-listing",
    "ds-store-file",
    "webpack-sourcemap-disclosure",
    "cgi-printenv",
    "debug-vars",
    "prometheus-metrics",
    "apache-server-status",
    "django-debug-config-enabled",
    "springboot-configprops",
    "dockerfile-hidden-disclosure",
  ],
  maximumGetRequests: 19,
} as const;

export const websiteQuickOrigin = (
  target: string,
  protocol: Extract<TransportProtocol, "http" | "https">,
  port: number,
): string => {
  const host = target.includes(":") && !target.startsWith("[") ? `[${target}]` : target;
  return `${protocol}://${host}:${port}`;
};
