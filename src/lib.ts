import { getActiveLocale, translateActiveStatic, type StaticTranslationKey } from "./i18n/core";
import type {
  CasePhase,
  CloudPlatform,
  Confidence,
  CoverageState,
  DiffState,
  EngineRunStatus,
  ExecutionStage,
  FindingWorkflowState,
  RunStatus,
  Severity,
} from "./types";

export const cx = (...values: Array<string | false | null | undefined>): string =>
  values.filter(Boolean).join(" ");

export const formatDateTime = (value?: string): string => {
  if (!value) return "—";
  const date = new Date(value);
  if (Number.isNaN(date.getTime())) return value;
  return new Intl.DateTimeFormat(getActiveLocale(), {
    month: "short",
    day: "numeric",
    hour: "2-digit",
    minute: "2-digit",
  }).format(date);
};

export const formatDate = (value?: string): string => {
  if (!value) return "—";
  const date = new Date(value);
  if (Number.isNaN(date.getTime())) return value;
  return new Intl.DateTimeFormat(getActiveLocale(), {
    year: "numeric",
    month: "short",
    day: "numeric",
  }).format(date);
};

const labelMeta = (labelKey: StaticTranslationKey, tone: string) => ({
  get label() { return translateActiveStatic(labelKey); },
  tone,
});

const descriptiveMeta = (
  labelKey: StaticTranslationKey,
  descriptionKey: StaticTranslationKey,
) => ({
  get label() { return translateActiveStatic(labelKey); },
  get description() { return translateActiveStatic(descriptionKey); },
});

const descriptiveToneMeta = (
  labelKey: StaticTranslationKey,
  descriptionKey: StaticTranslationKey,
  tone: string,
) => ({
  get label() { return translateActiveStatic(labelKey); },
  get description() { return translateActiveStatic(descriptionKey); },
  tone,
});

const coverageStatusMeta = (
  labelKey: StaticTranslationKey,
  shortLabelKey: StaticTranslationKey,
  descriptionKey: StaticTranslationKey,
  tone: string,
) => ({
  get label() { return translateActiveStatic(labelKey); },
  get shortLabel() { return translateActiveStatic(shortLabelKey); },
  get description() { return translateActiveStatic(descriptionKey); },
  tone,
});

export const coverageMeta: Record<
  CoverageState,
  { label: string; shortLabel: string; tone: string; description: string }
> = {
  discovered_authorized_scanned: coverageStatusMeta(
    "status.coverage.scanned.label",
    "status.coverage.scanned.short",
    "status.coverage.scanned.description",
    "positive",
  ),
  discovered_not_authorized: coverageStatusMeta(
    "status.coverage.unauthorized.label",
    "status.coverage.unauthorized.short",
    "status.coverage.unauthorized.description",
    "warning",
  ),
  authorized_incomplete: coverageStatusMeta(
    "status.coverage.incomplete.label",
    "status.coverage.incomplete.short",
    "status.coverage.incomplete.description",
    "danger",
  ),
  source_connected_none: coverageStatusMeta(
    "status.coverage.none.label",
    "status.coverage.none.short",
    "status.coverage.none.description",
    "neutral",
  ),
  source_unavailable_unknown: coverageStatusMeta(
    "status.coverage.unknown.label",
    "status.coverage.unknown.short",
    "status.coverage.unknown.description",
    "unknown",
  ),
  not_applicable: coverageStatusMeta(
    "status.coverage.notApplicable.label",
    "status.coverage.notApplicable.short",
    "status.coverage.notApplicable.description",
    "neutral",
  ),
};

export const engineStatusMeta: Record<EngineRunStatus, { label: string; tone: string }> = {
  pending: labelMeta("status.engine.pending", "neutral"),
  running: labelMeta("status.engine.running", "info"),
  paused: labelMeta("status.engine.paused", "warning"),
  completed: labelMeta("status.engine.completed", "positive"),
  partial: labelMeta("status.engine.partial", "warning"),
  failed: labelMeta("status.engine.failed", "danger"),
  not_executed: labelMeta("status.engine.notExecuted", "unknown"),
  cancelled: labelMeta("status.engine.cancelled", "neutral"),
};

export const executionStageMeta: Record<ExecutionStage, { label: string; description: string }> = {
  planned: descriptiveMeta("status.stage.planned.label", "status.stage.planned.description"),
  preflight: descriptiveMeta("status.stage.preflight.label", "status.stage.preflight.description"),
  pulling_image: descriptiveMeta("status.stage.pullingImage.label", "status.stage.pullingImage.description"),
  running: descriptiveMeta("status.stage.running.label", "status.stage.running.description"),
  capturing_artifacts: descriptiveMeta("status.stage.capturing.label", "status.stage.capturing.description"),
  adapting_artifacts: descriptiveMeta("status.stage.adapting.label", "status.stage.adapting.description"),
  captured_awaiting_adapter: descriptiveMeta(
    "status.stage.awaitingAdapter.label",
    "status.stage.awaitingAdapter.description",
  ),
  cleanup_pending: descriptiveMeta(
    "status.stage.cleanupPending.label",
    "status.stage.cleanupPending.description",
  ),
  completed: descriptiveMeta("status.stage.completed.label", "status.stage.completed.description"),
  cancelled: descriptiveMeta("status.stage.cancelled.label", "status.stage.cancelled.description"),
  failed: descriptiveMeta("status.stage.failed.label", "status.stage.failed.description"),
};

export const runStatusMeta: Record<RunStatus, { label: string; tone: string }> = {
  queued: labelMeta("status.run.queued", "neutral"),
  running: labelMeta("status.run.running", "info"),
  paused: labelMeta("status.run.paused", "warning"),
  completed: labelMeta("status.run.completed", "positive"),
  no_checks_completed: labelMeta("status.run.noChecksCompleted", "warning"),
  partial: labelMeta("status.run.partial", "warning"),
  failed: labelMeta("status.run.failed", "danger"),
  cancelled: labelMeta("status.run.cancelled", "neutral"),
};

export const severityMeta: Record<Severity, { label: string; tone: string }> = {
  critical: labelMeta("status.severity.critical", "critical"),
  high: labelMeta("status.severity.high", "danger"),
  medium: labelMeta("status.severity.medium", "warning"),
  low: labelMeta("status.severity.low", "info"),
  unknown: labelMeta("status.severity.unknown", "warning"),
  info: labelMeta("status.severity.info", "neutral"),
};

export const confidenceMeta: Record<Confidence, string> = {
  get high() { return translateActiveStatic("status.confidence.high"); },
  get medium() { return translateActiveStatic("status.confidence.medium"); },
  get low() { return translateActiveStatic("status.confidence.low"); },
};

export const workflowMeta: Record<FindingWorkflowState, string> = {
  get unreviewed() { return translateActiveStatic("status.workflow.unreviewed"); },
  get expert_review_requested() { return translateActiveStatic("status.workflow.expertReview"); },
  get confirmed() { return translateActiveStatic("status.workflow.confirmed"); },
  get unconfirmed() { return translateActiveStatic("status.workflow.unconfirmed"); },
  get assigned() { return translateActiveStatic("status.workflow.assigned"); },
  get false_positive() { return translateActiveStatic("status.workflow.falsePositive"); },
  get remediation_reported() { return translateActiveStatic("status.workflow.remediationReported"); },
  get remediated_pending_verification() { return translateActiveStatic("status.workflow.pendingVerification"); },
  get verified_resolved() { return translateActiveStatic("status.workflow.resolved"); },
};

export const diffMeta: Record<DiffState, { label: string; tone: string; description: string }> = {
  resolved: descriptiveToneMeta("status.diff.resolved.label", "status.diff.resolved.description", "positive"),
  persistent: descriptiveToneMeta(
    "status.diff.persistent.label",
    "status.diff.persistent.description",
    "danger",
  ),
  new: descriptiveToneMeta("status.diff.new.label", "status.diff.new.description", "warning"),
  unverifiable: descriptiveToneMeta(
    "status.diff.unverifiable.label",
    "status.diff.unverifiable.description",
    "unknown",
  ),
};

export const phaseMeta: Record<CasePhase, { label: string; tone: string }> = {
  draft: labelMeta("status.case.draft", "neutral"),
  discovering: labelMeta("status.case.discovering", "info"),
  scope_review: labelMeta("status.case.scopeReview", "warning"),
  ready: labelMeta("status.case.ready", "positive"),
  scanning: labelMeta("status.case.scanning", "info"),
  needs_attention: labelMeta("status.case.needsAttention", "warning"),
  ready_for_handoff: labelMeta("status.case.readyForHandoff", "positive"),
  verifying: labelMeta("status.case.verifying", "info"),
  archived: labelMeta("status.case.archived", "neutral"),
  complete: labelMeta("status.case.complete", "positive"),
  verification_due: labelMeta("status.case.verificationDue", "warning"),
};

const platform = (labelKey: StaticTranslationKey, abbreviation: string) => ({
  get label() { return translateActiveStatic(labelKey); },
  abbreviation,
});

export const platformMeta: Record<CloudPlatform, { label: string; abbreviation: string }> = {
  aws: platform("platform.aws", "AWS"),
  azure: platform("platform.azure", "AZ"),
  gcp: platform("platform.gcp", "GCP"),
  m365: platform("platform.m365", "365"),
  external: platform("platform.external", "WEB"),
  code: platform("platform.code", "CODE"),
  container: platform("platform.container", "IMG"),
  kubernetes: platform("platform.kubernetes", "K8S"),
};

export const percentage = (part: number, total: number): number =>
  total <= 0 ? 0 : Math.round((part / total) * 100);
