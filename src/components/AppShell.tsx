import { useEffect, useLayoutEffect, useRef, useState, type ReactNode } from "react";

import { caseDisplayLabels, caseIdentityPresentation } from "../caseIdentityPresentation";
import {
  classifyRuntimeIssue,
  useI18n,
  type RuntimeIssue,
  type TranslationKey,
} from "../i18n";
import { cx, phaseMeta } from "../lib";
import {
  MOBILE_NAVIGATION_MEDIA_QUERY,
  reconcileMobileNavigationOpen,
} from "../mobileNavigation";
import { completePageTransition } from "../pageNavigation";
import {
  hasUnconfirmedManagedRuntimeCompletion,
  isManagedRuntimePackageAdmissionFailure,
} from "../runtimeSetupPresentation";
import type {
  AppMode,
  AppSnapshot,
  AssessmentCase,
  ManagedRuntimeSetupNextAction,
  ManagedRuntimeSetupPhase,
  ManagedRuntimeSetupStatus,
  PageId,
} from "../types";
import type { AppUpdateState } from "../services/appUpdater";
import { AppUpdateControl } from "./AppUpdateControl";
import { Icon, type IconName } from "./Icon";
import { StatusPill } from "./StatusPill";

const navigation = [
  { id: "start", labelKey: "nav.start.label", hintKey: "nav.start.hint", icon: "spark" },
  { id: "cases", labelKey: "nav.cases.label", hintKey: "nav.cases.hint", icon: "cases" },
  { id: "findings", labelKey: "nav.findings.label", hintKey: "nav.findings.hint", icon: "findings" },
  { id: "settings", labelKey: "nav.settings.label", hintKey: "nav.settings.hint", icon: "settings" },
] as const satisfies ReadonlyArray<{
  id: PageId;
  labelKey: TranslationKey;
  hintKey: TranslationKey;
  icon: IconName;
}>;

const pageLabelKeys = {
  start: "nav.start.label",
  cases: "nav.cases.label",
  coverage: "nav.coverage.label",
  progress: "nav.progress.label",
  findings: "nav.findings.label",
  export: "nav.export.label",
  settings: "nav.settings.label",
  verification: "nav.verification.label",
} as const satisfies Record<PageId, TranslationKey>;

const runtimeSetupLabelKeys = {
  idle: "runtime.phase.idle.label",
  install: "runtime.phase.install.label",
  prerequisite: "runtime.phase.prerequisite.label",
  download: "runtime.phase.download.label",
  recovery: "runtime.phase.recovery.label",
  init: "runtime.phase.init.label",
  start: "runtime.phase.start.label",
  verify: "runtime.phase.verify.label",
  completed: "runtime.phase.completed.label",
  failed: "runtime.phase.failed.label",
  cancelled: "runtime.phase.cancelled.label",
} as const satisfies Record<ManagedRuntimeSetupPhase, TranslationKey>;

const runtimeSetupDetailKeys = {
  idle: "runtime.phase.idle.detail",
  install: "runtime.phase.install.detail",
  prerequisite: "runtime.phase.prerequisite.detail",
  download: "runtime.phase.download.detail",
  recovery: "runtime.phase.recovery.detail",
  init: "runtime.phase.init.detail",
  start: "runtime.phase.start.detail",
  verify: "runtime.phase.verify.detail",
  completed: "runtime.phase.completed.detail",
  failed: "runtime.phase.failed.detail",
  cancelled: "runtime.phase.cancelled.detail",
} as const satisfies Record<ManagedRuntimeSetupPhase, TranslationKey>;

const runtimeIssueKeys = {
  wsl: "runtime.prerequisite.localSupport",
  virtualization: "runtime.prerequisite.virtualization",
  permission: "runtime.prerequisite.permission",
  network: "runtime.prerequisite.network",
  storage: "runtime.prerequisite.storage",
  generic: "runtime.prerequisite.generic",
} as const satisfies Record<RuntimeIssue, TranslationKey>;

const runtimeRecoveryKeys = {
  install_wsl: "runtime.recovery.retryAutomatic",
  enable_wsl_optional_features: "runtime.recovery.retryAutomatic",
  update_wsl: "runtime.recovery.retryAutomatic",
  restart_windows: "runtime.recovery.windowsPending",
  retry_wsl_check: "runtime.recovery.retryAutomatic",
} as const satisfies Record<ManagedRuntimeSetupNextAction, TranslationKey>;

const casePhaseLabelKeys = {
  draft: "status.case.draft",
  discovering: "status.case.discovering",
  scope_review: "status.case.scopeReview",
  ready: "status.case.ready",
  scanning: "status.case.scanning",
  needs_attention: "status.case.needsAttention",
  ready_for_handoff: "status.case.readyForHandoff",
  verifying: "status.case.verifying",
  archived: "status.case.archived",
  complete: "status.case.complete",
  verification_due: "status.case.verificationDue",
} as const satisfies Record<AssessmentCase["phase"], TranslationKey>;

interface AppShellProps {
  children: ReactNode;
  page: PageId;
  mode: AppMode;
  cases: AssessmentCase[];
  selectedCase?: AssessmentCase;
  loading?: boolean;
  dataUnavailable?: boolean;
  dataRetrying?: boolean;
  onRetryData: () => void;
  caseRecoveryDiagnostics?: AppSnapshot["caseRecoveryDiagnostics"];
  caseSelectionUnavailable?: boolean;
  caseSelectionRetrying?: boolean;
  onRetryCaseSelection: () => void;
  onNavigate: (page: PageId) => void;
  onSelectCase: (caseId: string) => void;
  appUpdate: AppUpdateState;
  onCheckForUpdate: () => void;
  onInstallUpdate: (version: string) => void;
  runtime?: AppSnapshot["runtime"];
  runtimeSetup?: ManagedRuntimeSetupStatus;
  runtimeBusy?: boolean;
  onSetupRuntime: () => void;
  onCancelRuntime: () => void;
}

export function AppShell({
  children,
  page,
  mode,
  cases,
  selectedCase,
  loading,
  dataUnavailable,
  dataRetrying,
  onRetryData,
  caseRecoveryDiagnostics,
  caseSelectionUnavailable,
  caseSelectionRetrying,
  onRetryCaseSelection,
  onNavigate,
  onSelectCase,
  appUpdate,
  onCheckForUpdate,
  onInstallUpdate,
  runtime,
  runtimeSetup,
  runtimeBusy,
  onSetupRuntime,
  onCancelRuntime,
}: AppShellProps) {
  const [mobileOpen, setMobileOpen] = useState(false);
  const [narrowViewport, setNarrowViewport] = useState(
    () => window.matchMedia?.(MOBILE_NAVIGATION_MEDIA_QUERY).matches ?? false,
  );
  const mobileNavigationRef = useRef<HTMLElement>(null);
  const mobileMenuButtonRef = useRef<HTMLButtonElement>(null);
  const mobileCloseButtonRef = useRef<HTMLButtonElement>(null);
  const pageTransitionKey = `${page}:${selectedCase?.id ?? ""}`;
  const previousPageTransitionKey = useRef(pageTransitionKey);
  const mobileDialogOpen = reconcileMobileNavigationOpen(mobileOpen, narrowViewport);
  const { locale, setLocale, t, formatNumber } = useI18n();
  const displayedCaseLabels = caseDisplayLabels(cases, locale);
  const selectedCaseDisplayName = selectedCase
    ? displayedCaseLabels.get(selectedCase.id)
      ?? caseIdentityPresentation(selectedCase, locale).name
    : undefined;

  const exactBytes = (value: number): string =>
    t(value === 1 ? "common.byte" : "common.bytes", { value: formatNumber(value) });
  const runtimeSetupNonRetryable = isManagedRuntimePackageAdmissionFailure(runtimeSetup);
  const runtimeSetupWorking = !runtimeSetupNonRetryable && (
    runtimeBusy
    || runtimeSetup?.active === true
    || runtimeSetup?.prerequisiteRepairActive === true
  );
  const runtimeIssue = runtimeIssueKeys[
    runtimeSetup?.failureReason && !runtimeSetupNonRetryable
      ? "wsl"
      : classifyRuntimeIssue(runtime?.prerequisite, runtime?.detail, runtimeSetup?.detail)
  ];
  const runtimeGuidance: TranslationKey = runtimeSetupNonRetryable
    ? "runtime.phase.failed.nonRetryable.detail"
    : runtimeSetup?.nextAction
      ? runtimeRecoveryKeys[runtimeSetup.nextAction]
      : runtimeIssue;
  const runtimeSetupStarting = runtimeBusy
    && runtimeSetup?.active !== true
    && runtimeSetup?.prerequisiteRepairActive !== true;
  const runtimeSetupCompletionUnconfirmed = hasUnconfirmedManagedRuntimeCompletion(
    runtime?.available,
    runtimeSetup?.phase,
  );
  const displayedRuntimeSetupPhase = runtimeSetupStarting
    ? "install"
    : runtimeSetupCompletionUnconfirmed
      ? undefined
      : runtimeSetup?.phase;
  const genericSetupFailure = !runtimeSetupWorking
    && !runtimeSetupNonRetryable
    && runtimeSetup?.phase === "failed"
    && !runtimeSetup.nextAction;
  const runtimeGuidanceTitle: TranslationKey = runtimeSetupNonRetryable
    ? "runtime.phase.failed.nonRetryable.label"
    : genericSetupFailure
      ? "runtime.phase.failed.generic.label"
      : "runtime.nextStep";
  const runtimeSetupDetail: TranslationKey | undefined = displayedRuntimeSetupPhase
    ? genericSetupFailure
      ? "runtime.phase.failed.generic.detail"
      : runtimeSetupDetailKeys[displayedRuntimeSetupPhase]
    : undefined;
  const runtimeSetupAction: TranslationKey = runtimeSetup?.phase === "failed"
    || runtimeSetupCompletionUnconfirmed
    ? "runtime.setup.retry"
    : runtimeSetup?.phase === "cancelled"
      ? "runtime.setup.continue"
      : "runtime.setup.action";

  useEffect(() => setMobileOpen(false), [page, selectedCase?.id]);

  useEffect(() => {
    const viewport = window.matchMedia(MOBILE_NAVIGATION_MEDIA_QUERY);
    const reconcileViewport = (matches: boolean) => {
      setNarrowViewport(matches);
      setMobileOpen((current) => reconcileMobileNavigationOpen(current, matches));
    };
    const onViewportChange = (event: MediaQueryListEvent) => reconcileViewport(event.matches);
    reconcileViewport(viewport.matches);
    viewport.addEventListener("change", onViewportChange);
    return () => viewport.removeEventListener("change", onViewportChange);
  }, []);

  useEffect(() => {
    if (!mobileDialogOpen) return undefined;
    mobileCloseButtonRef.current?.focus();
    const containMobileNavigationFocus = (event: KeyboardEvent) => {
      if (event.key === "Escape") {
        setMobileOpen(false);
        window.setTimeout(() => mobileMenuButtonRef.current?.focus(), 0);
        return;
      }
      if (event.key !== "Tab") return;
      const navigation = mobileNavigationRef.current;
      if (!navigation) return;
      const focusable = Array.from(navigation.querySelectorAll<HTMLElement>(
        'a[href], button:not([disabled]), input:not([disabled]), select:not([disabled]), textarea:not([disabled]), [tabindex]:not([tabindex="-1"])',
      ));
      const first = focusable[0];
      const last = focusable.at(-1);
      if (!first || !last) {
        event.preventDefault();
        mobileCloseButtonRef.current?.focus();
        return;
      }
      const active = document.activeElement;
      if (event.shiftKey && (active === first || !navigation.contains(active))) {
        event.preventDefault();
        last.focus();
      } else if (!event.shiftKey && (active === last || !navigation.contains(active))) {
        event.preventDefault();
        first.focus();
      }
    };
    document.addEventListener("keydown", containMobileNavigationFocus);
    return () => document.removeEventListener("keydown", containMobileNavigationFocus);
  }, [mobileDialogOpen]);

  const closeMobileNavigation = () => {
    setMobileOpen(false);
    if (narrowViewport) {
      window.setTimeout(() => mobileMenuButtonRef.current?.focus(), 0);
    }
  };

  useLayoutEffect(() => {
    completePageTransition({
      previousKey: previousPageTransitionKey.current,
      nextKey: pageTransitionKey,
      mainContent: document.getElementById("main-content"),
      viewport: window,
    });
    previousPageTransitionKey.current = pageTransitionKey;
  }, [pageTransitionKey]);

  return (
    <div className="app-shell">
      <a className="skip-link" href="#main-content">{t("shell.skipToContent")}</a>

      <aside
        ref={mobileNavigationRef}
        id="primary-navigation"
        className={cx("sidebar", mobileDialogOpen && "sidebar--open")}
        aria-label={t("shell.primaryNavigation")}
        aria-modal={mobileDialogOpen || undefined}
        role={mobileDialogOpen ? "dialog" : undefined}
      >
        <div className="brand">
          <span className="brand__mark"><Icon name="shield" size={22} /></span>
          <span className="brand__copy">
            <strong>ai-security-scanner</strong>
            <small>{t("shell.brandSubtitle")}</small>
          </span>
          <button
            ref={mobileCloseButtonRef}
            className="icon-button sidebar__close"
            type="button"
            aria-label={t("shell.closeNavigation")}
            onClick={closeMobileNavigation}
          >
            <Icon name="close" />
          </button>
        </div>

        <div className="sidebar__case">
          <label htmlFor="case-switcher">{t("shell.currentCase")}</label>
          <div className="select-wrap select-wrap--dark">
            <select
              id="case-switcher"
              value={selectedCase?.id ?? ""}
              onChange={(event) => onSelectCase(event.target.value)}
              disabled={loading || cases.length === 0}
            >
              {cases.length === 0 && <option value="">{t("shell.noCases")}</option>}
              {cases.map((assessmentCase) => (
                <option key={assessmentCase.id} value={assessmentCase.id}>
                  {displayedCaseLabels.get(assessmentCase.id) ?? assessmentCase.name}
                </option>
              ))}
            </select>
            <Icon name="chevron" size={16} />
          </div>
          {selectedCase && (
            <StatusPill
              label={t(casePhaseLabelKeys[selectedCase.phase])}
              tone={phaseMeta[selectedCase.phase].tone}
              className="sidebar__phase"
            />
          )}
        </div>

        <div className="language-switcher" role="group" aria-label={t("language.label")}>
          <button
            type="button"
            className={cx(locale === "en" && "language-switcher__active")}
            aria-pressed={locale === "en"}
            onClick={() => setLocale("en")}
          >
            {t("language.english")}
          </button>
          <button
            type="button"
            className={cx(locale === "zh-TW" && "language-switcher__active")}
            aria-pressed={locale === "zh-TW"}
            onClick={() => setLocale("zh-TW")}
          >
            {t("language.traditionalChinese")}
          </button>
        </div>

        <nav className="nav-list">
          {navigation.map((item) => (
            <button
              key={item.id}
              type="button"
              className={cx("nav-item", page === item.id && "nav-item--active")}
              aria-current={page === item.id ? "page" : undefined}
              onClick={() => onNavigate(item.id)}
            >
              <Icon name={item.icon} size={20} />
              <span>
                <strong>{t(item.labelKey)}</strong>
                <small>{t(item.hintKey)}</small>
              </span>
            </button>
          ))}
        </nav>

        <div className="sidebar__footer">
          <div className="privacy-note">
            <Icon name="lock" size={17} />
            <span>
              <strong>{t("shell.privacy.title")}</strong>
              <small>{t("shell.privacy.detail")}</small>
            </span>
          </div>
          <span className={cx("runtime-badge", mode === "native" && runtime?.available ? "runtime-badge--native" : "runtime-badge--demo")}>
            <span aria-hidden="true" />
            {mode === "native"
              ? runtime?.available
                ? t("runtime.badge.ready")
                : runtimeSetupNonRetryable
                  ? t("runtime.phase.failed.nonRetryable.label")
                  : t("runtime.badge.needsSetup")
              : t("runtime.badge.demo")}
          </span>
          {mode === "native" && runtime && !runtime.available && (
            <div className="runtime-setup" aria-live="polite">
              {!runtimeSetupWorking && (
                <div className="runtime-setup__guidance">
                  <strong>{t(runtimeGuidanceTitle)}</strong>
                  <small>{t(runtimeGuidance)}</small>
                </div>
              )}
              {!runtimeSetupNonRetryable && displayedRuntimeSetupPhase && displayedRuntimeSetupPhase !== "idle" && (
                <div className="runtime-setup__progress" role="status">
                  <strong>{t(runtimeSetupLabelKeys[displayedRuntimeSetupPhase])}</strong>
                  {runtimeSetupDetail && <small>{t(runtimeSetupDetail)}</small>}
                  {!runtimeSetupStarting && runtimeSetup?.totalBytes !== undefined && (
                    <>
                      <progress
                        max={runtimeSetup.totalBytes}
                        value={Math.min(runtimeSetup.receivedBytes, runtimeSetup.totalBytes)}
                        aria-label={t("runtime.download.progress")}
                      />
                      <small className="runtime-setup__bytes">
                        {exactBytes(runtimeSetup.receivedBytes)} / {exactBytes(runtimeSetup.totalBytes)}
                        {runtimeSetup.progressPercent !== undefined
                          ? ` · ${formatNumber(runtimeSetup.progressPercent, { maximumFractionDigits: 2 })}%`
                          : ""}
                      </small>
                      {runtimeSetup.resumedFromBytes > 0 && (
                        <small>{t("runtime.download.resumed", { bytes: exactBytes(runtimeSetup.resumedFromBytes) })}</small>
                      )}
                    </>
                  )}
                </div>
              )}
              {runtimeSetup?.active ? (
                <button
                  className="button button--small button--danger"
                  type="button"
                  disabled={!runtimeSetup.canCancel || runtimeSetup.cancelRequested}
                  onClick={onCancelRuntime}
                >
                  <Icon name="close" size={15} />
                  {runtimeSetup.cancelRequested ? t("runtime.cancel.pending") : t("runtime.cancel.action")}
                </button>
              ) : runtimeSetupWorking ? (
                <button className="button button--small" type="button" disabled aria-busy="true">
                  <Icon name="progress" size={15} />
                  {t(runtimeSetupLabelKeys[displayedRuntimeSetupPhase ?? "install"])}
                </button>
              ) : !runtimeSetupWorking && !runtimeSetupNonRetryable ? (
                <button
                  className="button button--small"
                  type="button"
                  disabled={runtimeBusy}
                  onClick={onSetupRuntime}
                >
                  <Icon name="progress" size={15} />
                  {t(runtimeSetupAction)}
                </button>
              ) : null}
            </div>
          )}
        </div>
      </aside>

      {mobileDialogOpen && (
        <div
          className="sidebar-backdrop"
          aria-hidden="true"
          onClick={closeMobileNavigation}
        />
      )}

      <div className="workspace" aria-hidden={mobileDialogOpen || undefined}>
        <header className="topbar">
          <button
            ref={mobileMenuButtonRef}
            className="icon-button topbar__menu"
            type="button"
            aria-label={t("shell.openNavigation")}
            aria-controls="primary-navigation"
            aria-expanded={mobileDialogOpen}
            onClick={() => setMobileOpen(true)}
          >
            <Icon name="menu" />
          </button>
          <div className="topbar__context">
            <span>{t(pageLabelKeys[page])}</span>
            {selectedCaseDisplayName && <strong>{selectedCaseDisplayName}</strong>}
          </div>
          <div className="topbar__right">
            <AppUpdateControl
              state={appUpdate}
              onCheck={onCheckForUpdate}
              onInstall={onInstallUpdate}
            />
          </div>
        </header>

        {(mode === "demo" || selectedCase?.isDemo) && (
          <div className="demo-banner" role="status">
            <Icon name="spark" size={19} />
            <div>
              <strong>{selectedCase?.isDemo ? t("shell.demo.selectedTitle") : t("shell.demo.title")}</strong>
              <span>{t("shell.demo.fallback")}</span>
            </div>
          </div>
        )}

        {caseRecoveryDiagnostics && caseRecoveryDiagnostics.length > 0 && (
          <div className="data-status-banner" role="status">
            <Icon name="warning" size={19} />
            <div className="data-status-banner__copy">
              <strong>{t("shell.caseRecovery.title")}</strong>
              <span>{t("shell.caseRecovery.detail")}</span>
              <details>
                <summary>{t("shell.caseRecovery.technical")}</summary>
                <ul>
                  {caseRecoveryDiagnostics.map((diagnostic) => (
                    <li key={`${diagnostic.caseId}:${diagnostic.code}`}>
                      <strong>{diagnostic.title}</strong>{" — "}
                      {t(diagnostic.preserved
                        ? "shell.caseRecovery.preserved"
                        : "shell.caseRecovery.missing")}{" · "}
                      <code>{diagnostic.code}</code>
                    </li>
                  ))}
                </ul>
              </details>
            </div>
            <button
              className="button button--small"
              type="button"
              disabled={dataRetrying}
              aria-busy={dataRetrying || undefined}
              onClick={onRetryData}
            >
              <Icon name="refresh" size={15} />
              {t(dataRetrying ? "shell.data.retrying" : "shell.data.retry")}
            </button>
          </div>
        )}

        {dataUnavailable && (
          <div className="data-status-banner" role="alert">
            <Icon name="warning" size={19} />
            <div className="data-status-banner__copy">
              <strong>{t("shell.data.refreshErrorTitle")}</strong>
              <span>{t("shell.data.refreshErrorDetail")}</span>
            </div>
            <button
              className="button button--small"
              type="button"
              disabled={dataRetrying}
              aria-busy={dataRetrying || undefined}
              onClick={onRetryData}
            >
              <Icon name="refresh" size={15} />
              {t(dataRetrying ? "shell.data.retrying" : "shell.data.retry")}
            </button>
          </div>
        )}

        {caseSelectionUnavailable && (
          <div className="data-status-banner" role="alert">
            <Icon name="warning" size={19} />
            <div className="data-status-banner__copy">
              <strong>{t("shell.data.selectionErrorTitle")}</strong>
              <span>{t("shell.data.selectionErrorDetail")}</span>
            </div>
            <button
              className="button button--small"
              type="button"
              disabled={caseSelectionRetrying}
              aria-busy={caseSelectionRetrying || undefined}
              onClick={onRetryCaseSelection}
            >
              <Icon name="refresh" size={15} />
              {t(caseSelectionRetrying ? "shell.data.retrying" : "shell.data.retry")}
            </button>
          </div>
        )}

        <main id="main-content" className="main-content" tabIndex={-1}>
          {children}
        </main>
      </div>
    </div>
  );
}
