import type { SeverityBasisCode } from "./types";

type FindingClassificationInput = {
  severityBasisCode?: SeverityBasisCode;
};

/**
 * Naabu and httpx produce useful reachability inventory. Their records share
 * the durable finding pipeline, but an open port or responding HTTP service is
 * not, by itself, evidence of a vulnerability.
 */
export const isExposureObservation = ({
  severityBasisCode,
}: FindingClassificationInput): boolean =>
  severityBasisCode === "open_port" || severityBasisCode === "reachable_http_service";

export const isSecurityFinding = (record: FindingClassificationInput): boolean =>
  !isExposureObservation(record);
