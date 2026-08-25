import { useCallback, useEffect, useMemo, useRef, useState, type FormEvent } from "react";
import { openUrl } from "@tauri-apps/plugin-opener";

import { formatDateTime } from "../lib";
import { EVENTS, scannerService } from "../services/scanner";
import type {
  BootstrapOperatorConfig,
  BootstrapCleanupObligationSummary,
  BootstrapRequest,
  ConnectedSource,
  InstalledProviderAuthorization,
  ProviderAuthorizationConfig,
  ProviderAuthorizationPrompt,
  ProviderBootstrapPlan,
} from "../types";
import { Icon } from "./Icon";
import { InlineNotice } from "./Shared";
import { StatusPill } from "./StatusPill";

type Provider = "aws" | "azure" | "gcp" | "microsoft365";

interface ProviderAuthorizationPanelProps {
  caseId: string;
  sources: ConnectedSource[];
  nativeMode: boolean;
  disabled?: boolean;
  onAuthorizationChanged: () => Promise<void>;
}

const providerBySourceKind: Partial<Record<ConnectedSource["kind"], Provider>> = {
  aws_organization: "aws",
  azure_tenant: "azure",
  gcp_organization: "gcp",
  microsoft365_tenant: "microsoft365",
};

const providerLabels: Record<Provider, string> = {
  aws: "AWS",
  azure: "Azure",
  gcp: "Google Cloud",
  microsoft365: "Microsoft 365",
};

const engineBindings: Record<Provider, string[]> = {
  // This remains an exact subset of ProviderSourceProfile::allowed_engine_ids;
  // adding an engine here never widens the provider-side read-only profile.
  aws: ["provider-native-discovery", "cloudquery", "steampipe", "prowler", "scoutsuite", "cloudsplaining"],
  azure: ["provider-native-discovery"],
  gcp: ["provider-native-discovery"],
  microsoft365: ["provider-native-discovery", "scubagear", "maester"],
};

const bootstrapCapabilities: Record<Provider, BootstrapRequest["capabilities"]> = {
  aws: ["inventory", "configuration", "identity_and_access", "security_posture", "audit_metadata"],
  azure: ["inventory", "configuration", "identity_and_access", "security_posture", "audit_metadata"],
  gcp: ["inventory", "configuration", "identity_and_access", "security_posture", "audit_metadata"],
  microsoft365: ["configuration", "identity_and_access", "security_posture", "audit_metadata"],
};

const trustedProviderUrl = (value: string): string | undefined => {
  try {
    const url = new URL(value);
    const host = url.hostname.toLocaleLowerCase("en-US");
    const trusted = [
      "amazonaws.com",
      "awsapps.com",
      "microsoft.com",
      "microsoftonline.com",
      "google.com",
      "googleusercontent.com",
    ].some((suffix) => host === suffix || host.endsWith(`.${suffix}`));
    return url.protocol === "https:" && trusted && !url.username && !url.password ? url.toString() : undefined;
  } catch {
    return undefined;
  }
};

const firstTrustedProviderUrl = (value: string): string | undefined => {
  const candidate = value.match(/https:\/\/[^\s<>"']+/)?.[0]?.replace(/[),.;]+$/, "");
  return candidate ? trustedProviderUrl(candidate) : undefined;
};

const messageFromError = (error: unknown): string => {
  if (error instanceof Error) return error.message;
  return typeof error === "string" ? error : "Provider 授權未完成。";
};

const randomLoopback = (): string => {
  const values = new Uint16Array(1);
  crypto.getRandomValues(values);
  const port = 49_152 + ((values[0] ?? 0) % (65_535 - 49_152));
  return `http://127.0.0.1:${port}/oauth2/callback`;
};

const operationId = (): string =>
  `bootstrap-${Date.now().toString(36)}-${crypto.randomUUID().replaceAll("-", "").slice(0, 12)}`;

const scanIdentityName = (provider: Provider, caseId: string): string => {
  const suffix = caseId.toLocaleLowerCase("en-US").replace(/[^a-z0-9-]/g, "-").replace(/-+/g, "-").replace(/^-|-$/g, "").slice(0, 24) || "case";
  return `ai-security-scanner-${provider}-${suffix}`.slice(0, 63).replace(/-$/, "");
};

export function ProviderAuthorizationPanel({
  caseId,
  sources,
  nativeMode,
  disabled,
  onAuthorizationChanged,
}: ProviderAuthorizationPanelProps) {
  const providerSources = useMemo(
    () => sources.filter((source) => Boolean(providerBySourceKind[source.kind])),
    [sources],
  );
  const [selectedSourceId, setSelectedSourceId] = useState(providerSources[0]?.id ?? "");
  const selectedSource = providerSources.find((source) => source.id === selectedSourceId) ?? providerSources[0];
  const provider = selectedSource ? providerBySourceKind[selectedSource.kind] : undefined;
  const [flowMode, setFlowMode] = useState<"preferred" | "bootstrap">("preferred");
  const [working, setWorking] = useState(false);
  const [error, setError] = useState<string>();
  const [notice, setNotice] = useState<string>();
  const [installed, setInstalled] = useState<InstalledProviderAuthorization>();
  const [prompt, setPrompt] = useState<ProviderAuthorizationPrompt>();
  const pollTimer = useRef<number | undefined>(undefined);
  const schedulePollRef = useRef<(sessionId: string, delaySeconds: number) => void>(() => undefined);

  const [awsStartUrl, setAwsStartUrl] = useState("");
  const [awsRegion, setAwsRegion] = useState("us-east-1");
  const [awsAccountId, setAwsAccountId] = useState("");
  const [awsRoleName, setAwsRoleName] = useState("ai-security-scanner-readonly");
  const [awsRoleArn, setAwsRoleArn] = useState("");
  const [tenantId, setTenantId] = useState("");
  const [publicClientId, setPublicClientId] = useState("");
  const [subscriptionId, setSubscriptionId] = useState("");
  const [gcpOrganizationId, setGcpOrganizationId] = useState("");
  const [gcpProjectId, setGcpProjectId] = useState("");
  const [gcpRedirectUri, setGcpRedirectUri] = useState(randomLoopback);
  const [bootstrapPlan, setBootstrapPlan] = useState<ProviderBootstrapPlan>();
  const [bootstrapOperation, setBootstrapOperation] = useState<{ id: string; cleanupPath: string }>();
  const bootstrapOperationIdRef = useRef<string | undefined>(undefined);
  const [bootstrapMessages, setBootstrapMessages] = useState<string[]>([]);
  const [cleanupObligations, setCleanupObligations] = useState<BootstrapCleanupObligationSummary[]>([]);

  const refreshCleanupObligations = useCallback(async () => {
    if (!nativeMode) {
      setCleanupObligations([]);
      return;
    }
    const result = await scannerService.listProviderBootstrapCleanup(caseId);
    setCleanupObligations(result.data);
  }, [caseId, nativeMode]);

  useEffect(() => {
    if (!providerSources.some((source) => source.id === selectedSourceId)) {
      setSelectedSourceId(providerSources[0]?.id ?? "");
    }
  }, [providerSources, selectedSourceId]);

  useEffect(() => () => {
    if (pollTimer.current) window.clearTimeout(pollTimer.current);
  }, []);

  useEffect(() => {
    if (!nativeMode || !selectedSource) {
      setInstalled(undefined);
      return;
    }
    let disposed = false;
    void scannerService.providerAuthorizationStatus(caseId, selectedSource.id)
      .then((result) => { if (!disposed) setInstalled(result.data ?? undefined); })
      .catch(() => { if (!disposed) setInstalled(undefined); });
    return () => { disposed = true; };
  }, [caseId, nativeMode, selectedSource]);

  useEffect(() => {
    let disposed = false;
    if (!nativeMode) {
      setCleanupObligations([]);
      return undefined;
    }
    void scannerService.listProviderBootstrapCleanup(caseId)
      .then((result) => { if (!disposed) setCleanupObligations(result.data); })
      .catch((listError) => {
        if (!disposed) setError(`無法安全讀取 cleanup obligations：${messageFromError(listError)}`);
      });
    return () => { disposed = true; };
  }, [caseId, nativeMode]);

  useEffect(() => {
    if (!nativeMode) return undefined;
    let disposed = false;
    let unlisten: (() => void) | undefined;
    void scannerService.subscribe(EVENTS.bootstrapMessage, (payload) => {
      if (disposed) return;
      if (!payload || typeof payload !== "object") return;
      const message = payload as { operationId?: unknown; operation_id?: unknown; message?: unknown };
      const id = typeof message.operationId === "string" ? message.operationId : message.operation_id;
      const safeMessage = message.message;
      if (typeof id !== "string" || id !== bootstrapOperationIdRef.current || typeof safeMessage !== "string") return;
      setBootstrapMessages((current) => [...current.slice(-11), safeMessage.slice(0, 4096)]);
    }).then((next) => {
      if (disposed) next();
      else unlisten = next;
    }).catch((subscribeError) => {
      if (!disposed) setError(`無法接收 bootstrap 狀態通知：${messageFromError(subscribeError)}`);
    });
    return () => {
      disposed = true;
      unlisten?.();
    };
  }, [nativeMode]);

  useEffect(() => {
    setBootstrapPlan(undefined);
  }, [provider, awsStartUrl, awsRegion, awsAccountId, awsRoleName, awsRoleArn, tenantId, publicClientId, subscriptionId, gcpOrganizationId, gcpProjectId, gcpRedirectUri]);

  useEffect(() => {
    if (awsAccountId && awsRoleName) setAwsRoleArn(`arn:aws:iam::${awsAccountId}:role/${awsRoleName}`);
  }, [awsAccountId, awsRoleName]);

  const authorizationConfig = useCallback((): ProviderAuthorizationConfig => {
    if (!provider) throw new Error("請先選擇 provider 來源。");
    if (provider === "aws") return {
      provider,
      config: {
        start_url: awsStartUrl.trim(),
        region: awsRegion.trim(),
        account_id: awsAccountId.trim(),
        role_name: awsRoleName.trim(),
        role_arn: awsRoleArn.trim(),
      },
    };
    if (provider === "gcp") return {
      provider,
      config: {
        public_client_id: publicClientId.trim(),
        redirect_uri: gcpRedirectUri.trim(),
        organization_id: gcpOrganizationId.trim(),
      },
    };
    return {
      provider,
      config: {
        tenant_id: tenantId.trim(),
        public_client_id: publicClientId.trim(),
        profile: provider === "azure" ? "azure_tenant_read_only_access_token" : "microsoft365_tenant_read_only_access_token",
        subscription_id: provider === "azure" ? subscriptionId.trim() : null,
      },
    };
  }, [provider, awsStartUrl, awsRegion, awsAccountId, awsRoleName, awsRoleArn, publicClientId, gcpRedirectUri, gcpOrganizationId, tenantId, subscriptionId]);

  const operatorConfig = useCallback((): BootstrapOperatorConfig => {
    const authorization = authorizationConfig();
    if (authorization.provider === "aws") return { provider: "aws", administrator: authorization.config };
    if (authorization.provider === "azure") return { provider: "azure", authorization: authorization.config };
    if (authorization.provider === "microsoft365") return { provider: "microsoft365", authorization: authorization.config };
    return { provider: "gcp", authorization: authorization.config, project_id: gcpProjectId.trim() };
  }, [authorizationConfig, gcpProjectId]);

  const schedulePoll = useCallback((sessionId: string, delaySeconds: number) => {
    if (pollTimer.current) window.clearTimeout(pollTimer.current);
    pollTimer.current = window.setTimeout(() => {
      void (async () => {
        try {
          const result = await scannerService.pollProviderAuthorization(sessionId);
          if (result.data.status === "pending") {
            schedulePollRef.current(result.data.session_id, Math.max(1, result.data.retry_after_seconds));
            return;
          }
          setInstalled(result.data.authorization);
          setPrompt(undefined);
          setWorking(false);
          setNotice("Provider 已驗證唯讀身分；短期 capability 只保留在本次桌面程序記憶體中。");
          await onAuthorizationChanged();
        } catch (pollError) {
          setError(messageFromError(pollError));
          setWorking(false);
        }
      })();
    }, Math.min(30, Math.max(1, delaySeconds)) * 1000);
  }, [onAuthorizationChanged]);

  useEffect(() => {
    schedulePollRef.current = schedulePoll;
  }, [schedulePoll]);

  const beginPreferred = async (event: FormEvent) => {
    event.preventDefault();
    if (!selectedSource || !provider) return;
    setWorking(true);
    setError(undefined);
    setNotice(undefined);
    setPrompt(undefined);
    try {
      const result = await scannerService.beginProviderAuthorization({
        case_id: caseId,
        source_id: selectedSource.id,
        allowed_engine_ids: engineBindings[provider],
        max_checkouts: 8,
        authorization: authorizationConfig(),
      });
      setPrompt(result.data);
      const initialDelay = result.data.flow === "device" ? result.data.prompt.poll_interval_seconds : 2;
      schedulePoll(result.data.session_id, initialDelay);
    } catch (beginError) {
      setError(messageFromError(beginError));
      setWorking(false);
    }
  };

  const cancelPreferred = async () => {
    if (!prompt) return;
    if (pollTimer.current) window.clearTimeout(pollTimer.current);
    try { await scannerService.cancelProviderAuthorization(prompt.session_id); } catch { /* session may already be gone */ }
    setPrompt(undefined);
    setWorking(false);
    setNotice("本次登入已取消；沒有安裝 scanner capability。");
  };

  const revokePreferred = async () => {
    if (!selectedSource) return;
    setWorking(true);
    setError(undefined);
    try {
      await scannerService.revokeProviderAuthorization(caseId, selectedSource.id);
      setInstalled(undefined);
      setNotice("記憶體中的 provider capability 已撤銷；來源證據與歷史 provenance 不受影響。");
      await onAuthorizationChanged();
    } catch (revokeError) {
      setError(messageFromError(revokeError));
    } finally {
      setWorking(false);
    }
  };

  const makeBootstrapRequest = (): BootstrapRequest => {
    if (!provider) throw new Error("請先選擇 provider 來源。");
    return {
      schema_version: "1.0.0",
      case_id: caseId,
      provider,
      scan_identity_name: scanIdentityName(provider, caseId),
      capabilities: bootstrapCapabilities[provider],
      expires_at: new Date(Date.now() + 55 * 60_000).toISOString(),
    };
  };

  const planBootstrap = async (event: FormEvent) => {
    event.preventDefault();
    setWorking(true);
    setError(undefined);
    setNotice(undefined);
    try {
      // Validate the non-secret operator coordinates before presenting a mutation plan.
      operatorConfig();
      const result = await scannerService.planProviderBootstrap(makeBootstrapRequest());
      setBootstrapPlan(result.data);
    } catch (planError) {
      setError(messageFromError(planError));
    } finally {
      setWorking(false);
    }
  };

  const executeBootstrap = async () => {
    if (!selectedSource || !provider || !bootstrapPlan) return;
    const id = operationId();
    bootstrapOperationIdRef.current = id;
    setBootstrapOperation({ id, cleanupPath: "" });
    setBootstrapMessages([]);
    setWorking(true);
    setError(undefined);
    try {
      const result = await scannerService.executeProviderBootstrap({
        operationId: id,
        execution: {
          schema_version: "1.0.0",
          bootstrap: {
            schema_version: "1.0.0",
            case_id: bootstrapPlan.case_id,
            provider: bootstrapPlan.provider,
            scan_identity_name: bootstrapPlan.scan_identity_name,
            capabilities: bootstrapPlan.capabilities,
            expires_at: bootstrapPlan.expires_at,
          },
          operator: operatorConfig(),
        },
        sourceId: selectedSource.id,
        allowedEngineIds: engineBindings[provider],
        maxCheckouts: 8,
      });
      setInstalled(result.data.authorization);
      setBootstrapOperation({ id: result.data.operationId, cleanupPath: result.data.cleanupLedgerPath });
      setNotice("隔離 broker 已建立並驗證短期唯讀身分。清理義務會保留到精確資源都移除且短期憑證到期。");
      await refreshCleanupObligations();
      await onAuthorizationChanged();
    } catch (executeError) {
      setError(`${messageFromError(executeError)} 若 provider 已建立部分資源，請保留 operation ID ${id} 並執行精確清理。`);
    } finally {
      setWorking(false);
    }
  };

  const cleanupBootstrap = async (requestedOperationId = bootstrapOperation?.id) => {
    if (!requestedOperationId) return;
    setWorking(true);
    setError(undefined);
    bootstrapOperationIdRef.current = requestedOperationId;
    try {
      await scannerService.cleanupProviderBootstrap(caseId, requestedOperationId, operatorConfig());
      await refreshCleanupObligations();
      setNotice("隔離 broker 已執行精確清理；尚未到期的短期憑證會在 ledger 中保持可追蹤義務，直到自然到期。");
    } catch (cleanupError) {
      setError(`${messageFromError(cleanupError)} Cleanup ledger 仍保留，可用相同 operation ID 重試。`);
    } finally {
      setWorking(false);
    }
  };

  if (providerSources.length === 0) {
    return (
      <InlineNotice tone="info" title="此案件沒有 provider 來源">
        <p>建立案件時選擇 AWS、Azure、GCP 或 Microsoft 365，才會產生可綁定的唯讀來源。</p>
      </InlineNotice>
    );
  }

  const promptUrl = prompt?.flow === "device"
    ? trustedProviderUrl(prompt.prompt.verification_uri_complete ?? prompt.prompt.verification_uri)
    : prompt ? trustedProviderUrl(prompt.prompt.authorization_url) : undefined;

  const openProviderLogin = async () => {
    if (!promptUrl) {
      setError("Provider URL 未通過官方 host allowlist；沒有開啟任何頁面。");
      return;
    }
    try {
      await openUrl(promptUrl);
    } catch (openError) {
      setError(`無法交給系統瀏覽器開啟官方登入頁：${messageFromError(openError)}`);
    }
  };

  const openTrustedUrl = async (url: string) => {
    try {
      await openUrl(url);
    } catch (openError) {
      setError(`無法交給系統瀏覽器開啟官方登入頁：${messageFromError(openError)}`);
    }
  };

  return (
    <section className="provider-auth-panel" aria-labelledby="provider-auth-title">
      <div className="section-heading section-heading--row">
        <div>
          <p className="eyebrow">Provider-native read only</p>
          <h2 id="provider-auth-title">連接短期唯讀 provider 身分</h2>
          <p>只在 provider 官方頁面登入。密碼、token、device code 與 PKCE code 不會進入案件、前端 state、命令列或 scanner。</p>
        </div>
        {installed
          ? <StatusPill label={`有效至 ${formatDateTime(installed.expires_at)}`} tone="positive" />
          : <StatusPill label="未持有 capability" tone="unknown" />}
      </div>

      {!nativeMode && (
        <InlineNotice tone="info" title="展示模式不會登入 provider">
          <p>請在簽署的 Tauri 桌面程式使用此流程；瀏覽器展示頁不會建立任何 OAuth 或雲端工作階段。</p>
        </InlineNotice>
      )}

      <div className="provider-auth-tabs" role="tablist" aria-label="Provider 授權方式">
        <button type="button" role="tab" aria-selected={flowMode === "preferred"} className={flowMode === "preferred" ? "provider-auth-tab provider-auth-tab--active" : "provider-auth-tab"} onClick={() => setFlowMode("preferred")}>既有唯讀身分（建議）</button>
        <button type="button" role="tab" aria-selected={flowMode === "bootstrap"} className={flowMode === "bootstrap" ? "provider-auth-tab provider-auth-tab--active" : "provider-auth-tab"} onClick={() => setFlowMode("bootstrap")}>隔離建立唯讀身分</button>
      </div>

      <form className="provider-auth-form" onSubmit={flowMode === "preferred" ? beginPreferred : planBootstrap}>
        <div className="form-grid form-grid--two">
          <label className="field">
            <span>案件來源</span>
            <select value={selectedSource?.id ?? ""} disabled={working || disabled} onChange={(event) => { setSelectedSourceId(event.target.value); setPrompt(undefined); setInstalled(undefined); setError(undefined); }}>
              {providerSources.map((source) => <option key={source.id} value={source.id}>{providerLabels[providerBySourceKind[source.kind]!]} · {source.label}</option>)}
            </select>
            <small>Capability 精確綁定這個 case/source，不可跨案件重用。</small>
          </label>

          {provider === "aws" && <>
            <label className="field"><span>IAM Identity Center start URL</span><input required type="url" autoComplete="off" spellCheck={false} value={awsStartUrl} onChange={(event) => setAwsStartUrl(event.target.value)} placeholder="https://company.awsapps.com/start" /><small>只接受 provider-hosted awsapps.com HTTPS URL。</small></label>
            <label className="field"><span>Region</span><input required autoComplete="off" spellCheck={false} value={awsRegion} onChange={(event) => setAwsRegion(event.target.value)} placeholder="us-east-1" /></label>
            <label className="field"><span>12 位 account ID</span><input required inputMode="numeric" pattern="[0-9]{12}" autoComplete="off" value={awsAccountId} onChange={(event) => setAwsAccountId(event.target.value)} /></label>
            <label className="field"><span>{flowMode === "bootstrap" ? "管理員登入所使用的 role name" : "唯讀 role name"}</span><input required autoComplete="off" spellCheck={false} value={awsRoleName} onChange={(event) => setAwsRoleName(event.target.value)} /></label>
            <label className="field field--wide"><span>精確 role ARN</span><input required autoComplete="off" spellCheck={false} value={awsRoleArn} onChange={(event) => setAwsRoleArn(event.target.value)} /><small>Account ID 與 role name 變更時會重新產生；可補上合法 IAM path。</small></label>
          </>}

          {(provider === "azure" || provider === "microsoft365") && <>
            <label className="field"><span>Tenant UUID</span><input required autoComplete="off" spellCheck={false} value={tenantId} onChange={(event) => setTenantId(event.target.value)} placeholder="xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx" /></label>
            <label className="field"><span>Public client UUID</span><input required autoComplete="off" spellCheck={false} value={publicClientId} onChange={(event) => setPublicClientId(event.target.value)} placeholder="xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx" /><small>只填 public-client ID；不要貼 client secret。</small></label>
            {provider === "azure" && <label className="field"><span>Subscription UUID</span><input required autoComplete="off" spellCheck={false} value={subscriptionId} onChange={(event) => setSubscriptionId(event.target.value)} placeholder="xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx" /></label>}
          </>}

          {provider === "gcp" && <>
            <label className="field"><span>OAuth Desktop client ID</span><input required autoComplete="off" spellCheck={false} value={publicClientId} onChange={(event) => setPublicClientId(event.target.value)} placeholder="…apps.googleusercontent.com" /></label>
            <label className="field"><span>Numeric organization ID</span><input required inputMode="numeric" pattern="[0-9]+" autoComplete="off" value={gcpOrganizationId} onChange={(event) => setGcpOrganizationId(event.target.value)} /></label>
            {flowMode === "bootstrap" && <label className="field"><span>Service-account project ID</span><input required autoComplete="off" spellCheck={false} value={gcpProjectId} onChange={(event) => setGcpProjectId(event.target.value)} /><small>隔離身分建立於這個精確 project。</small></label>}
            <label className="field"><span>Random-port loopback redirect</span><span className="field-inline"><input required readOnly value={gcpRedirectUri} /><button className="button button--ghost button--small" type="button" disabled={working} onClick={() => setGcpRedirectUri(randomLoopback())}>重產生</button></span></label>
          </>}
        </div>

        <InlineNotice tone={flowMode === "bootstrap" ? "warning" : "info"} title={flowMode === "bootstrap" ? "這個流程會在 provider 建立資源" : "前端不接受任何秘密值"}>
          <p>{flowMode === "bootstrap" ? "先產生固定、可檢查的 mutation plan；確認後由獨立 broker 登入、建立、驗證與記錄精確清理義務。Scanner 永遠不取得管理員權限。" : "以上欄位只有公開 client ID 與 provider 座標。實際登入、device code、PKCE verifier、token 與短期金鑰全由本機核心處理。"}</p>
        </InlineNotice>

        {error && <p className="form-error" role="alert"><Icon name="warning" size={16} />{error}</p>}
        {notice && <p className="provider-auth-success" role="status"><Icon name="check" size={16} />{notice}</p>}

        <div className="form-actions">
          <p><Icon name="lock" size={16} /> {provider
            ? engineBindings[provider].filter((id) => id !== "provider-native-discovery").join("、") || "目前僅 provider-native discovery；尚無 released scanner image"
            : "固定引擎集合"}；最多 8 次 checkout。</p>
          <div className="button-group">
            {installed && <button className="button button--ghost" type="button" disabled={working || disabled} onClick={() => void revokePreferred()}>撤銷記憶體 capability</button>}
            <button className="button button--primary" type="submit" disabled={!nativeMode || working || disabled || !provider}>{working ? "處理中…" : flowMode === "preferred" ? "開始 provider 登入" : "產生固定 bootstrap plan"}<Icon name="arrow" size={17} /></button>
          </div>
        </div>
      </form>

      {prompt && (
        <section className="provider-prompt" aria-live="polite">
          <div><p className="eyebrow">Provider-hosted sign-in</p><h3>在官方頁面完成登入</h3><p>{prompt.prompt.safety_notice}</p></div>
          {prompt.flow === "device" && <div className="provider-device-code"><span>Device code</span><code>{prompt.prompt.user_code}</code></div>}
          {promptUrl ? <button className="button button--primary" type="button" onClick={() => void openProviderLogin()}>開啟官方登入頁 <Icon name="arrow" size={17} /></button> : <InlineNotice tone="warning" title="Provider URL 未通過前端 allowlist"><p>為避免導向非官方網站，請取消並重試；沒有自動開啟任何 URL。</p></InlineNotice>}
          <p>等待本機核心驗證；到期 {formatDateTime(prompt.prompt.expires_at)}。關閉頁面不會把登入資料交給 scanner。</p>
          <button className="button button--ghost button--small" type="button" onClick={() => void cancelPreferred()}>取消本次登入</button>
        </section>
      )}

      {flowMode === "bootstrap" && bootstrapPlan && (
        <section className="bootstrap-plan" aria-labelledby="bootstrap-plan-title">
          <div className="section-heading"><p className="eyebrow">Immutable mutation plan</p><h3 id="bootstrap-plan-title">確認隔離 broker 的固定動作</h3><p>{bootstrapPlan.safety_notice}</p></div>
          <dl>
            <div><dt>Identity</dt><dd><code>{bootstrapPlan.scan_identity_name}</code></dd></div>
            <div><dt>Template SHA-256</dt><dd><code>{bootstrapPlan.template_sha256}</code></dd></div>
            <div><dt>到期</dt><dd>{formatDateTime(bootstrapPlan.expires_at)}</dd></div>
            <div><dt>Endpoint hosts</dt><dd>{bootstrapPlan.allowed_endpoint_hosts.join("、")}</dd></div>
          </dl>
          <ol>{bootstrapPlan.operations.map((operation) => <li key={operation.operation_id}><strong>{operation.description}</strong><span>{operation.provider_api_operations.join(" · ")}</span></li>)}</ol>
          <details><summary>查看 provider template（唯讀）</summary><pre>{bootstrapPlan.template}</pre></details>
          <div className="form-actions"><p><Icon name="warning" size={16} /> 此確認只授權上述固定建立流程，不授權 scanner 寫入或修復目標。</p><button className="button button--primary" type="button" disabled={working || disabled} onClick={() => void executeBootstrap()}>{working ? "隔離 broker 執行中…" : "確認並啟動隔離 broker"}</button></div>
        </section>
      )}

      {bootstrapMessages.length > 0 && <section className="bootstrap-messages" aria-live="polite"><h3>Broker 安全提示</h3>{bootstrapMessages.map((message, index) => {
        const url = firstTrustedProviderUrl(message);
        return <div key={`${index}-${message}`}><p>{message}</p>{url && <button className="button button--ghost button--small" type="button" onClick={() => void openTrustedUrl(url)}>開啟這個官方頁面</button>}</div>;
      })}</section>}

      {bootstrapOperation && (
        <InlineNotice tone="warning" title="保留精確 cleanup operation">
          <p><code>{bootstrapOperation.id}</code>{bootstrapOperation.cleanupPath ? <> · ledger <code>{bootstrapOperation.cleanupPath}</code></> : " · broker 可能仍在建立或記錄部分資源"}</p>
          <button className="button button--secondary button--small" type="button" disabled={working || !nativeMode} onClick={() => void cleanupBootstrap()}>執行／重試精確清理</button>
        </InlineNotice>
      )}

      {cleanupObligations.length > 0 && (
        <section className="bootstrap-plan" aria-labelledby="bootstrap-cleanup-title">
          <div className="section-heading">
            <p className="eyebrow">Durable cleanup recovery</p>
            <h3 id="bootstrap-cleanup-title">Bootstrap 清理義務</h3>
            <p>此清單不含憑證、resource ID 或 endpoint。每次恢復都會重新在 provider 官方流程取得管理員授權，且只處理 ledger 已記錄的精確 target。</p>
          </div>
          <ol>
            {cleanupObligations.map((obligation) => {
              const canResume = obligation.status !== "completed" && provider === obligation.provider;
              return (
                <li key={obligation.operationId}>
                  <strong>{providerLabels[obligation.provider]} · <code>{obligation.operationId}</code></strong>
                  <span>{obligation.status} · {obligation.completedItems}/{obligation.totalItems} completed · schema {obligation.schemaVersion}</span>
                  {obligation.status !== "completed" && (
                    <button className="button button--secondary button--small" type="button" disabled={working || !nativeMode || !canResume} onClick={() => void cleanupBootstrap(obligation.operationId)}>
                      {provider === obligation.provider ? "重新授權並逐項恢復" : `先選擇 ${providerLabels[obligation.provider]} 來源`}
                    </button>
                  )}
                </li>
              );
            })}
          </ol>
        </section>
      )}
    </section>
  );
}
