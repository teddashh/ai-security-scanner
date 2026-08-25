import { useCallback, useEffect, useMemo, useRef, useState, type FormEvent } from "react";
import { openUrl } from "@tauri-apps/plugin-opener";

import { useI18n, type BilingualText } from "../i18n";
import {
  providerAuthorizationRequiredFields,
  providerAuthorizationTechnicalDetail,
  providerCheckoutLimits,
  providerEngineBindings,
  type Provider,
  type ProviderAuthorizationPath,
} from "../providerAuthorizationPolicy";
import { EVENTS, scannerService } from "../services/scanner";
import type {
  BootstrapCleanupObligationSummary,
  BootstrapOperatorConfig,
  BootstrapRequest,
  ConnectedSource,
  InstalledProviderAuthorization,
  ProviderAuthorizationConfig,
  ProviderAuthorizationPrompt,
  ProviderBootstrapPlan,
} from "../types";
import "../provider-authorization-panel.css";
import { Icon } from "./Icon";
import { InlineNotice } from "./Shared";
import { StatusPill } from "./StatusPill";

interface ProviderAuthorizationPanelProps {
  caseId: string;
  sources: ConnectedSource[];
  nativeMode: boolean;
  disabled?: boolean;
  onAuthorizationChanged: () => Promise<void>;
}

interface FieldCopy {
  label: BilingualText;
  what: BilingualText;
  where: BilingualText;
  example: string;
}

const copy = {
  emptyTitle: { en: "No cloud account is attached to this case", zhTW: "這個案件還沒有雲端帳號" },
  emptyBody: {
    en: "Add an AWS, Azure, Google Cloud, or Microsoft 365 source first. Then you can connect temporary read-only access here.",
    zhTW: "請先加入 AWS、Azure、Google Cloud 或 Microsoft 365 來源，再回到這裡連接短期唯讀存取。",
  },
  eyebrow: { en: "Cloud read-only access", zhTW: "雲端唯讀存取" },
  title: { en: "Let the scanner see this cloud account—without giving it control", zhTW: "讓掃描工具看得到這個雲端帳號，但不能控制它" },
  intro: {
    en: "Sign in only on the provider's official website. This app never asks for a password, client secret, access key, or long-lived token.",
    zhTW: "只在雲端服務商的官方網站登入。本程式不會要求密碼、用戶端密鑰、存取金鑰或長效權杖。",
  },
  statusActive: { en: "Read-only access until {expires}", zhTW: "唯讀存取有效至 {expires}" },
  statusMissing: { en: "Not connected", zhTW: "尚未連接" },
  demoTitle: { en: "Demo mode cannot sign in to a cloud account", zhTW: "展示模式不會登入雲端帳號" },
  demoBody: {
    en: "Open the signed desktop app for a real connection. This browser preview does not start a cloud sign-in session.",
    zhTW: "請使用已簽章的桌面程式進行真實連接；這個瀏覽器預覽不會啟動任何雲端登入。",
  },
  sourceLabel: { en: "Cloud account for this case", zhTW: "這次要檢查的雲端帳號" },
  sourceHelp: {
    en: "Choose the account, tenant, or organization already listed in this case. Access stays tied to this one source.",
    zhTW: "選擇案件中已有的帳號、租用戶或組織。這次存取只會綁定這一個來源。",
  },
  connectedTitle: { en: "Read-only access is connected", zhTW: "唯讀存取已連接" },
  connectedBody: {
    en: "The scanner can use this short-lived access only for the selected case and cloud source.",
    zhTW: "掃描工具只能在這個案件與這個雲端來源使用這份短期存取。",
  },
  disconnect: { en: "Disconnect read-only access", zhTW: "中斷唯讀存取" },
  choiceQuestion: { en: "How would you like to provide read-only access?", zhTW: "你想怎麼提供唯讀存取？" },
  choiceHelp: {
    en: "Choose the situation that matches what you have today. You can switch before starting sign-in.",
    zhTW: "選擇最符合你現在狀況的一項；開始登入前都可以切換。",
  },
  choiceAria: { en: "Read-only access setup method", zhTW: "唯讀存取設定方式" },
  preferredBadge: { en: "Recommended", zhTW: "建議" },
  preferredTitle: { en: "A · I already have read-only access", zhTW: "方式一 · 我已有唯讀存取" },
  preferredBody: {
    en: "Use an existing read-only role or public app registration. We will verify it before any scan starts.",
    zhTW: "使用既有的唯讀角色或公開應用程式註冊；開始掃描前會先驗證它確實只有唯讀權限。",
  },
  bootstrapTitle: { en: "B · I can create temporary read-only access", zhTW: "方式二 · 我可以建立暫時唯讀存取" },
  bootstrapBody: {
    en: "Use the provider's official management page to create a dedicated, short-lived scanner identity. The scanner never receives administrator access.",
    zhTW: "到雲端服務商的官方管理頁建立專用、短效的掃描身分；掃描工具不會取得管理員權限。",
  },
  formTitlePreferred: { en: "Connect existing {provider} read-only access", zhTW: "連接既有的 {provider} 唯讀存取" },
  formTitleBootstrap: { en: "Prepare temporary {provider} read-only access", zhTW: "準備暫時的 {provider} 唯讀存取" },
  formIntro: {
    en: "Only the non-secret account details needed for {provider} are shown below.",
    zhTW: "下方只顯示 {provider} 真正需要、而且不是秘密值的帳號資料。",
  },
  scopeTitle: { en: "What this lets the scanner check", zhTW: "這份存取會讓掃描工具檢查什麼" },
  scope: {
    aws: {
      en: "Cloud resources, configuration, identities and access, security posture, and audit metadata in the selected AWS boundary.",
      zhTW: "選定 AWS 範圍內的雲端資源、設定、身分與存取、安全狀態及稽核中繼資料。",
    },
    azure: {
      en: "Resources, configuration, identities and access, security posture, and audit metadata in one exact Azure tenant and subscription.",
    zhTW: "一個明確 Azure 租用戶與訂閱內的資源、設定、身分與存取、安全狀態及稽核中繼資料。",
    },
    gcp: {
      en: "Resources, configuration, identities and access, security posture, and audit metadata under one exact Google Cloud organization.",
    zhTW: "一個明確 Google Cloud 組織下的資源、設定、身分與存取、安全狀態及稽核中繼資料。",
    },
    microsoft365: {
      en: "Directory configuration, identities and access, security posture, and audit metadata in one exact Microsoft 365 tenant.",
      zhTW: "一個明確 Microsoft 365 租用戶內的目錄設定、身分與存取、安全狀態及稽核中繼資料。",
    },
  } satisfies Record<Provider, BilingualText>,
  what: { en: "What it is:", zhTW: "這是什麼：" },
  where: { en: "Where to find it:", zhTW: "去哪裡找：" },
  example: { en: "Example:", zhTW: "範例：" },
  noSecretsTitle: { en: "Never paste a password or secret here", zhTW: "不要在這裡貼密碼或秘密值" },
  noSecretsPreferred: {
    en: "Every field below is a public identifier or account coordinate. The actual sign-in and short-lived credentials stay in the local core and the provider's official page.",
    zhTW: "下方欄位都只是公開識別碼或帳號座標。實際登入與短期憑證只留在本機核心及雲端服務商的官方頁面。",
  },
  noSecretsBootstrap: {
    en: "The official provider page may ask you to confirm administrator access for the fixed setup steps. This form never receives that password or session, and the scanner receives only the resulting read-only identity.",
    zhTW: "雲端服務商的官方頁面可能要求你確認固定建立步驟所需的管理權限；本表單不會收到該密碼或工作階段，掃描工具只會拿到最後建立的唯讀身分。",
  },
  submitPreferred: { en: "Continue to official sign-in", zhTW: "前往官方登入" },
  submitBootstrap: { en: "Review what will be created", zhTW: "查看將建立的內容" },
  working: { en: "Working…", zhTW: "處理中…" },
  technicalSummary: { en: "Technical details", zhTW: "技術細節" },
  technicalFlow: { en: "Sign-in protocol", zhTW: "登入協定" },
  technicalEngines: { en: "Bound scanner engine IDs", zhTW: "綁定的掃描引擎 ID" },
  technicalCheckouts: { en: "Maximum bounded credential checkouts", zhTW: "短期憑證最多可取用次數" },
  technicalFields: { en: "Non-secret request fields", zhTW: "非秘密請求欄位" },
  technicalBoundary: {
    en: "The backend binds access to the exact case, source, provider profile, engine set, expiry, and checkout limit. It cannot be reused for another case or source.",
    zhTW: "後端會把存取綁定到明確的案件、來源、服務商設定檔、引擎集合、到期時間與取用上限，不能跨案件或來源重用。",
  },
  protocolDevice: { en: "Provider-hosted device authorization", zhTW: "雲端服務商官方的裝置授權流程" },
  protocolPkce: { en: "Provider-hosted browser sign-in with a local PKCE callback", zhTW: "雲端服務商官方瀏覽器登入與本機 PKCE 回呼" },
  errorTechnical: { en: "Show technical error details", zhTW: "查看技術錯誤細節" },
  errors: {
    status: { en: "We could not check whether this account is already connected. Try again in a moment.", zhTW: "目前無法確認這個帳號是否已連接，請稍後再試。" },
    cleanupList: { en: "We could not check whether an earlier temporary setup still needs cleanup.", zhTW: "目前無法確認先前的暫時存取是否仍需清理。" },
    subscribe: { en: "We could not receive live setup updates. You can retry the setup safely.", zhTW: "目前收不到即時設定進度；你可以安全地重試設定。" },
    poll: { en: "The provider did not finish verifying read-only access. Check the official sign-in page and try again.", zhTW: "雲端服務商尚未完成唯讀存取驗證；請檢查官方登入頁後再試一次。" },
    begin: { en: "We could not start the official provider sign-in. Check the account details and try again.", zhTW: "目前無法開始雲端服務商的官方登入；請確認帳號資料後再試一次。" },
    revoke: { en: "We could not disconnect this read-only access. Try again before closing the app.", zhTW: "目前無法中斷這份唯讀存取；請在關閉程式前再試一次。" },
    plan: { en: "We could not prepare the temporary read-only setup. Check the account details and try again.", zhTW: "目前無法準備暫時唯讀存取；請確認帳號資料後再試一次。" },
    execute: { en: "The temporary setup did not finish. Its private cleanup record was kept so you can retry safely.", zhTW: "暫時存取沒有建立完成；私人清理紀錄已保留，可以安全重試。" },
    cleanup: { en: "Cleanup did not finish. The exact cleanup record is still available, so you can retry without widening the scope.", zhTW: "清理尚未完成；精確清理紀錄仍在，可以在不擴大範圍的情況下重試。" },
    untrustedUrl: { en: "The sign-in link was not an approved provider website, so nothing was opened.", zhTW: "登入連結不是核准的雲端服務商官方網站，因此沒有開啟任何頁面。" },
    openUrl: { en: "Your system browser could not open the provider's official page. Copy the next step from the technical details or try again.", zhTW: "系統瀏覽器無法開啟雲端服務商的官方頁面；請查看技術細節中的下一步或再試一次。" },
  },
  notices: {
    authorized: { en: "Read-only access was verified. It stays only in this desktop session and expires automatically.", zhTW: "唯讀存取已驗證；它只留在這次桌面程式工作階段，並會自動到期。" },
    cancelled: { en: "Sign-in was cancelled. No scanner access was added.", zhTW: "本次登入已取消，沒有加入任何掃描存取。" },
    revoked: { en: "Read-only access was disconnected. Existing evidence and case history were not changed.", zhTW: "唯讀存取已中斷；既有證據與案件歷史沒有被修改。" },
    bootstrapped: { en: "Temporary read-only access was created and verified. Its exact cleanup record is ready.", zhTW: "暫時唯讀存取已建立並驗證；精確清理紀錄也已備妥。" },
    cleaned: { en: "Cleanup ran only for resources recorded by this temporary setup. Any credential still expiring remains tracked.", zhTW: "清理只處理這次暫時設定所記錄的資源；尚在到期中的憑證仍會持續追蹤。" },
  },
  promptEyebrow: { en: "Official provider sign-in", zhTW: "雲端服務商官方登入" },
  promptTitle: { en: "Finish sign-in in your browser", zhTW: "請在瀏覽器完成登入" },
  promptBody: {
    en: "The official page will ask you to choose an account and approve only the displayed read access. Return here when it is done.",
    zhTW: "官方頁面會請你選擇帳號，並只同意畫面列出的讀取權限；完成後回到這裡即可。",
  },
  openProvider: { en: "Open official sign-in page", zhTW: "開啟官方登入頁" },
  promptExpiry: { en: "Complete this step before {expires}.", zhTW: "請在 {expires} 前完成這一步。" },
  promptTechnical: { en: "Device code and sign-in details", zhTW: "裝置代碼與登入細節" },
  deviceCode: { en: "Device code", zhTW: "裝置代碼" },
  backendSafety: { en: "Provider safety note", zhTW: "雲端服務商安全提示" },
  cancel: { en: "Cancel this sign-in", zhTW: "取消本次登入" },
  unsafePromptTitle: { en: "The provider link could not be verified", zhTW: "無法驗證雲端服務商連結" },
  unsafePromptBody: { en: "For your safety, cancel this attempt and start again. No page was opened automatically.", zhTW: "為了安全，請取消這次嘗試後重新開始；系統沒有自動開啟任何頁面。" },
  planEyebrow: { en: "Temporary read-only setup", zhTW: "暫時唯讀設定" },
  planTitle: { en: "Confirm the dedicated read-only access", zhTW: "確認要建立的專用唯讀存取" },
  planBody: {
    en: "A separate local helper will use the provider's official management flow for only the reviewed setup steps. It will not change existing workloads or remediate findings.",
    zhTW: "獨立的本機輔助程式只會透過雲端服務商的官方管理流程執行已檢查的建立步驟；不會改動既有工作負載，也不會修復任何問題。",
  },
  planExpiry: { en: "The temporary scanner access expires at {expires}.", zhTW: "暫時掃描存取會在 {expires} 到期。" },
  planTechnical: { en: "Review the fixed setup plan", zhTW: "查看固定建立計畫" },
  planIdentity: { en: "Dedicated identity", zhTW: "專用身分" },
  planHash: { en: "Template SHA-256", zhTW: "範本 SHA-256 指紋" },
  planHosts: { en: "Allowed provider hosts", zhTW: "允許的雲端服務商主機" },
  planOperations: { en: "Exact provider operations", zhTW: "精確的雲端服務商操作" },
  planTemplate: { en: "Read-only provider template", zhTW: "雲端服務商唯讀範本" },
  planConfirmBoundary: {
    en: "Confirming authorizes only this fixed identity-creation plan. It does not authorize the scanner to write to or repair the target.",
    zhTW: "確認後只會授權這份固定的身分建立計畫；不會授權掃描工具寫入或修復目標。",
  },
  executePlan: { en: "Create temporary read-only access", zhTW: "建立暫時唯讀存取" },
  executingPlan: { en: "Creating read-only access…", zhTW: "正在建立唯讀存取…" },
  messagesTitle: { en: "The provider setup may need your attention", zhTW: "雲端服務商設定可能需要你操作" },
  messagesBody: { en: "Use only the official provider buttons shown here. Progress messages are available under technical details.", zhTW: "請只使用這裡顯示的雲端服務商官方按鈕；進度訊息收在技術細節中。" },
  openOfficialPage: { en: "Open this official provider page", zhTW: "開啟這個雲端服務商官方頁面" },
  messagesTechnical: { en: "Setup progress details", zhTW: "設定進度細節" },
  cleanupCurrentTitle: { en: "Keep this cleanup record until setup is fully removed", zhTW: "請保留這份清理紀錄，直到暫時設定完全移除" },
  cleanupCurrentBody: { en: "The app recorded exactly what this setup may have created. Cleanup will use only that recorded list.", zhTW: "程式已精確記錄這次設定可能建立的內容；清理只會使用該記錄清單。" },
  cleanupCurrentTechnical: { en: "Cleanup record details", zhTW: "清理紀錄細節" },
  operationId: { en: "Operation ID", zhTW: "操作識別碼" },
  ledgerPath: { en: "Private ledger path", zhTW: "私人清理台帳路徑" },
  cleanupAction: { en: "Remove only what this setup created", zhTW: "只移除這次設定建立的內容" },
  cleanupListEyebrow: { en: "Temporary-access cleanup", zhTW: "暫時存取清理" },
  cleanupListTitle: { en: "Earlier setup work still has a cleanup record", zhTW: "先前的暫時設定仍有清理紀錄" },
  cleanupListBody: { en: "These records contain no credentials. Reconnecting lets the app remove only the exact resources already recorded.", zhTW: "這些紀錄不含憑證；重新授權後，程式只會移除已精確記錄的資源。" },
  cleanupProgress: { en: "{completed} of {total} cleanup items finished", zhTW: "{total} 個清理項目已完成 {completed} 個" },
  cleanupResume: { en: "Reconnect and continue cleanup", zhTW: "重新授權並繼續清理" },
  cleanupSelectProvider: { en: "Select the {provider} source first", zhTW: "請先選擇 {provider} 來源" },
  cleanupTechnical: { en: "Cleanup tracking details", zhTW: "清理追蹤細節" },
  cleanupSchema: { en: "Record schema", zhTW: "紀錄格式版本" },
  cleanupStatus: { en: "Status", zhTW: "狀態" },
  cleanupStatuses: {
    pending: { en: "Ready to clean up", zhTW: "可開始清理" },
    in_progress: { en: "Cleanup in progress", zhTW: "正在清理" },
    retryable_failure: { en: "Cleanup needs another try", zhTW: "清理需要重試" },
    waiting_for_credential_expiry: { en: "Waiting for temporary access to expire", zhTW: "等待暫時存取到期" },
    completed: { en: "Cleanup complete", zhTW: "清理完成" },
  } satisfies Record<BootstrapCleanupObligationSummary["status"], BilingualText>,
  fields: {
    awsStartUrl: {
      label: { en: "AWS access portal start URL", zhTW: "AWS 存取入口起始網址" },
      what: { en: "The official IAM Identity Center page where your organization signs in.", zhTW: "組織用來登入 IAM Identity Center 的官方頁面。" },
      where: { en: "AWS access portal or IAM Identity Center dashboard → Settings.", zhTW: "AWS 存取入口，或 IAM Identity Center 控制台 → 設定（Settings）。" },
      example: "https://company.awsapps.com/start",
    },
    awsRegion: {
      label: { en: "IAM Identity Center region", zhTW: "IAM Identity Center 區域" },
      what: { en: "The AWS region where your IAM Identity Center instance is configured.", zhTW: "IAM Identity Center 執行個體所在的 AWS 區域。" },
      where: { en: "IAM Identity Center dashboard, next to the instance details.", zhTW: "IAM Identity Center 控制台的執行個體詳細資料旁。" },
      example: "us-east-1",
    },
    awsAccountId: {
      label: { en: "AWS account ID", zhTW: "AWS 帳號識別碼" },
      what: { en: "The 12-digit account the scanner is allowed to inspect.", zhTW: "允許掃描工具檢查的 12 位數帳號。" },
      where: { en: "AWS account menu or AWS Organizations → Accounts.", zhTW: "AWS 帳號選單，或組織（AWS Organizations）→ 帳號（Accounts）。" },
      example: "123456789012",
    },
    awsRolePreferred: {
      label: { en: "Assigned read-only role name", zhTW: "已指派的唯讀角色名稱" },
      what: { en: "The IAM Identity Center role already assigned to you for security review.", zhTW: "IAM Identity Center 已指派給你、用於安全檢查的唯讀角色。" },
      where: { en: "AWS access portal → select the account → role list.", zhTW: "AWS 存取入口 → 選擇帳號 → 角色清單。" },
      example: "SecurityAuditReader",
    },
    awsRoleBootstrap: {
      label: { en: "Role used to create the temporary access", zhTW: "用來建立暫時存取的角色名稱" },
      what: { en: "The role you will choose on AWS's official page to run only the reviewed setup plan.", zhTW: "你會在 AWS 官方頁面選擇、且只用來執行已檢查建立計畫的角色。" },
      where: { en: "AWS access portal → select the account → role list.", zhTW: "AWS 存取入口 → 選擇帳號 → 角色清單。" },
      example: "AdministratorAccess",
    },
    awsRoleArnPreferred: {
      label: { en: "Exact read-only role ARN", zhTW: "精確唯讀角色 ARN" },
      what: { en: "The full AWS identifier for that exact role; it prevents access from widening to another role.", zhTW: "該角色的完整 AWS 識別碼，用來避免存取擴大到其他角色。" },
      where: { en: "IAM → Roles → choose the role → ARN. The app fills the common form automatically.", zhTW: "IAM → 角色（Roles）→ 選擇該角色 → ARN。程式會先自動填入常見格式。" },
      example: "arn:aws:iam::123456789012:role/SecurityAuditReader",
    },
    awsRoleArnBootstrap: {
      label: { en: "Exact setup role ARN", zhTW: "精確設定角色 ARN" },
      what: { en: "The full AWS identifier for the role used only by the reviewed setup flow.", zhTW: "只供已檢查建立流程使用的角色完整 AWS 識別碼。" },
      where: { en: "IAM → Roles → choose the role → ARN. The app fills the common form automatically.", zhTW: "IAM → 角色（Roles）→ 選擇該角色 → ARN。程式會先自動填入常見格式。" },
      example: "arn:aws:iam::123456789012:role/AdministratorAccess",
    },
    tenantId: {
      label: { en: "Tenant ID", zhTW: "租用戶識別碼" },
      what: { en: "The UUID for the one Microsoft Entra tenant this case may inspect.", zhTW: "這個案件可檢查的單一 Microsoft Entra 租用戶 UUID。" },
      where: { en: "Microsoft Entra admin center → Overview → Tenant ID.", zhTW: "Microsoft Entra 系統管理中心 → 概觀（Overview）→ 租用戶識別碼（Tenant ID）。" },
      example: "11111111-2222-4333-8444-555555555555",
    },
    publicClientId: {
      label: { en: "Public application (client) ID", zhTW: "公開應用程式（用戶端）識別碼" },
      what: { en: "The public client UUID registered by your organization. It is an identifier, not a client secret.", zhTW: "由你的組織註冊的公開用戶端 UUID；它是識別碼，不是用戶端密鑰。" },
      where: { en: "Microsoft Entra admin center → App registrations → app → Overview.", zhTW: "Microsoft Entra 系統管理中心 → 應用程式註冊（App registrations）→ 選擇應用程式 → 概觀（Overview）。" },
      example: "aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee",
    },
    subscriptionId: {
      label: { en: "Azure subscription ID", zhTW: "Azure 訂閱識別碼" },
      what: { en: "The UUID for the one Azure subscription the scanner may inspect.", zhTW: "掃描工具可檢查的單一 Azure 訂閱 UUID。" },
      where: { en: "Azure portal → Subscriptions → choose the subscription.", zhTW: "Azure 入口網站 → 訂閱（Subscriptions）→ 選擇該訂閱。" },
      example: "22222222-3333-4444-8555-666666666666",
    },
    gcpClientId: {
      label: { en: "OAuth Desktop client ID", zhTW: "OAuth 桌面用戶端識別碼" },
      what: { en: "Your organization's Desktop-app client identifier. This app does not include or accept a client secret.", zhTW: "你的組織所註冊桌面應用程式用戶端識別碼；本程式不內建也不接收用戶端密鑰。" },
      where: { en: "Google Cloud console → APIs & Services → Credentials → OAuth 2.0 Client IDs.", zhTW: "Google Cloud 控制台 → API 和服務（APIs & Services）→ 憑證（Credentials）→ OAuth 2.0 用戶端識別碼。" },
      example: "123456789012-example.apps.googleusercontent.com",
    },
    gcpOrganizationId: {
      label: { en: "Google Cloud organization ID", zhTW: "Google Cloud 組織識別碼" },
      what: { en: "The numeric identifier for the one organization this case may inspect.", zhTW: "這個案件可檢查的單一組織數字識別碼。" },
      where: { en: "Google Cloud console → IAM & Admin → Settings.", zhTW: "Google Cloud 控制台 → IAM 與管理（IAM & Admin）→ 設定（Settings）。" },
      example: "123456789012",
    },
    gcpProjectId: {
      label: { en: "Project for the temporary scanner identity", zhTW: "建立暫時掃描身分的專案識別碼" },
      what: { en: "The exact Google Cloud project where the dedicated service account will be created.", zhTW: "將建立專用服務帳戶的明確 Google Cloud 專案。" },
      where: { en: "Google Cloud console project selector or project dashboard.", zhTW: "Google Cloud 控制台的專案選擇器或專案資訊主頁。" },
      example: "security-scanner-access",
    },
    gcpRedirect: {
      label: { en: "Local browser return address", zhTW: "本機瀏覽器返回位址" },
      what: { en: "A random local-only address used to return from Google's official sign-in page.", zhTW: "從 Google 官方登入頁返回時使用的隨機本機位址。" },
      where: { en: "Generated by this app; you do not need to look it up or edit it.", zhTW: "由本程式產生，不需要查找或手動編輯。" },
      example: "http://127.0.0.1:49152/oauth2/callback",
    },
  } satisfies Record<string, FieldCopy>,
  regenerate: { en: "Generate another local address", zhTW: "重新產生本機位址" },
} as const;

type PanelErrorKind = keyof typeof copy.errors;
type PanelNoticeKind = keyof typeof copy.notices;

interface PanelError {
  kind: PanelErrorKind;
  detail?: string;
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
  const { text, formatDateTime, formatNumber } = useI18n();
  const providerSources = useMemo(
    () => sources.filter((source) => Boolean(providerBySourceKind[source.kind])),
    [sources],
  );
  const [selectedSourceId, setSelectedSourceId] = useState(providerSources[0]?.id ?? "");
  const selectedSource = providerSources.find((source) => source.id === selectedSourceId) ?? providerSources[0];
  const provider = selectedSource ? providerBySourceKind[selectedSource.kind] : undefined;
  const [flowMode, setFlowMode] = useState<ProviderAuthorizationPath>();
  const [working, setWorking] = useState(false);
  const [error, setError] = useState<PanelError>();
  const [notice, setNotice] = useState<PanelNoticeKind>();
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

  const showError = useCallback((kind: PanelErrorKind, cause?: unknown) => {
    setError({ kind, detail: providerAuthorizationTechnicalDetail(cause) });
  }, []);

  const clearFeedback = () => {
    setError(undefined);
    setNotice(undefined);
  };

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
      setFlowMode(undefined);
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
      .catch((statusError) => {
        if (!disposed) {
          setInstalled(undefined);
          showError("status", statusError);
        }
      });
    return () => { disposed = true; };
  }, [caseId, nativeMode, selectedSource, showError]);

  useEffect(() => {
    let disposed = false;
    if (!nativeMode) {
      setCleanupObligations([]);
      return undefined;
    }
    void scannerService.listProviderBootstrapCleanup(caseId)
      .then((result) => { if (!disposed) setCleanupObligations(result.data); })
      .catch((listError) => {
        if (!disposed) showError("cleanupList", listError);
      });
    return () => { disposed = true; };
  }, [caseId, nativeMode, showError]);

  useEffect(() => {
    if (!nativeMode) return undefined;
    let disposed = false;
    let unlisten: (() => void) | undefined;
    void scannerService.subscribe(EVENTS.bootstrapMessage, (payload) => {
      if (disposed || !payload || typeof payload !== "object") return;
      const message = payload as { operationId?: unknown; operation_id?: unknown; message?: unknown };
      const id = typeof message.operationId === "string" ? message.operationId : message.operation_id;
      if (typeof id !== "string" || id !== bootstrapOperationIdRef.current || typeof message.message !== "string") return;
      const safeMessage = providerAuthorizationTechnicalDetail(message.message);
      if (safeMessage) setBootstrapMessages((current) => [...current.slice(-11), safeMessage]);
    }).then((next) => {
      if (disposed) next();
      else unlisten = next;
    }).catch((subscribeError) => {
      if (!disposed) showError("subscribe", subscribeError);
    });
    return () => {
      disposed = true;
      unlisten?.();
    };
  }, [nativeMode, showError]);

  useEffect(() => {
    setBootstrapPlan(undefined);
  }, [provider, awsStartUrl, awsRegion, awsAccountId, awsRoleName, awsRoleArn, tenantId, publicClientId, subscriptionId, gcpOrganizationId, gcpProjectId, gcpRedirectUri]);

  useEffect(() => {
    if (awsAccountId && awsRoleName) setAwsRoleArn(`arn:aws:iam::${awsAccountId}:role/${awsRoleName}`);
  }, [awsAccountId, awsRoleName]);

  const authorizationConfig = useCallback((): ProviderAuthorizationConfig => {
    if (!provider) throw new Error("provider source was not selected");
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
          setNotice("authorized");
          await onAuthorizationChanged();
        } catch (pollError) {
          showError("poll", pollError);
          setWorking(false);
        }
      })();
    }, Math.min(30, Math.max(1, delaySeconds)) * 1000);
  }, [onAuthorizationChanged, showError]);

  useEffect(() => {
    schedulePollRef.current = schedulePoll;
  }, [schedulePoll]);

  const beginPreferred = async (event: FormEvent) => {
    event.preventDefault();
    if (!selectedSource || !provider) return;
    setWorking(true);
    clearFeedback();
    setPrompt(undefined);
    try {
      const result = await scannerService.beginProviderAuthorization({
        case_id: caseId,
        source_id: selectedSource.id,
        allowed_engine_ids: [...providerEngineBindings[provider]],
        max_checkouts: providerCheckoutLimits[provider],
        authorization: authorizationConfig(),
      });
      setPrompt(result.data);
      const initialDelay = result.data.flow === "device" ? result.data.prompt.poll_interval_seconds : 2;
      schedulePoll(result.data.session_id, initialDelay);
    } catch (beginError) {
      showError("begin", beginError);
      setWorking(false);
    }
  };

  const cancelPreferred = async () => {
    if (!prompt) return;
    if (pollTimer.current) window.clearTimeout(pollTimer.current);
    try { await scannerService.cancelProviderAuthorization(prompt.session_id); } catch { /* session may already be gone */ }
    setPrompt(undefined);
    setWorking(false);
    setError(undefined);
    setNotice("cancelled");
  };

  const revokePreferred = async () => {
    if (!selectedSource) return;
    setWorking(true);
    clearFeedback();
    try {
      await scannerService.revokeProviderAuthorization(caseId, selectedSource.id);
      setInstalled(undefined);
      setNotice("revoked");
      await onAuthorizationChanged();
    } catch (revokeError) {
      showError("revoke", revokeError);
    } finally {
      setWorking(false);
    }
  };

  const makeBootstrapRequest = (): BootstrapRequest => {
    if (!provider) throw new Error("provider source was not selected");
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
    clearFeedback();
    try {
      operatorConfig();
      const result = await scannerService.planProviderBootstrap(makeBootstrapRequest());
      setBootstrapPlan(result.data);
    } catch (planError) {
      showError("plan", planError);
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
    clearFeedback();
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
        allowedEngineIds: [...providerEngineBindings[provider]],
        maxCheckouts: providerCheckoutLimits[provider],
      });
      setInstalled(result.data.authorization);
      setBootstrapOperation({ id: result.data.operationId, cleanupPath: result.data.cleanupLedgerPath });
      setNotice("bootstrapped");
      await refreshCleanupObligations();
      await onAuthorizationChanged();
    } catch (executeError) {
      showError("execute", executeError);
    } finally {
      setWorking(false);
    }
  };

  const cleanupBootstrap = async (requestedOperationId = bootstrapOperation?.id) => {
    if (!requestedOperationId) return;
    setWorking(true);
    clearFeedback();
    bootstrapOperationIdRef.current = requestedOperationId;
    try {
      await scannerService.cleanupProviderBootstrap(caseId, requestedOperationId, operatorConfig());
      await refreshCleanupObligations();
      setNotice("cleaned");
    } catch (cleanupError) {
      showError("cleanup", cleanupError);
    } finally {
      setWorking(false);
    }
  };

  const promptUrl = prompt?.flow === "device"
    ? trustedProviderUrl(prompt.prompt.verification_uri_complete ?? prompt.prompt.verification_uri)
    : prompt ? trustedProviderUrl(prompt.prompt.authorization_url) : undefined;
  const promptSafetyNotice = providerAuthorizationTechnicalDetail(prompt?.prompt.safety_notice);
  const bootstrapSafetyNotice = providerAuthorizationTechnicalDetail(bootstrapPlan?.safety_notice);
  const bootstrapTemplate = providerAuthorizationTechnicalDetail(bootstrapPlan?.template);

  const bootstrapProviderUrls = useMemo(
    () => [...new Set(bootstrapMessages.map(firstTrustedProviderUrl).filter((url): url is string => Boolean(url)))],
    [bootstrapMessages],
  );

  const openProviderLogin = async () => {
    if (!promptUrl) {
      showError("untrustedUrl");
      return;
    }
    try {
      await openUrl(promptUrl);
    } catch (openError) {
      showError("openUrl", openError);
    }
  };

  const openTrustedUrl = async (url: string) => {
    try {
      await openUrl(url);
    } catch (openError) {
      showError("openUrl", openError);
    }
  };

  const chooseFlow = (nextFlow: ProviderAuthorizationPath) => {
    if (working || disabled) return;
    setFlowMode(nextFlow);
    setBootstrapPlan(undefined);
    setPrompt(undefined);
    clearFeedback();
  };

  const changeSource = (sourceId: string) => {
    if (working || disabled) return;
    setSelectedSourceId(sourceId);
    setFlowMode(undefined);
    setPrompt(undefined);
    setInstalled(undefined);
    setBootstrapPlan(undefined);
    setBootstrapOperation(undefined);
    setBootstrapMessages([]);
    clearFeedback();
  };

  const fieldHelp = (field: FieldCopy) => (
    <small className="provider-field-help">
      <span><strong>{text(copy.what)}</strong> {text(field.what)}</span>
      <span><strong>{text(copy.where)}</strong> {text(field.where)}</span>
      <span><strong>{text(copy.example)}</strong> <code>{field.example}</code></span>
    </small>
  );

  if (providerSources.length === 0) {
    return (
      <InlineNotice tone="info" title={text(copy.emptyTitle)}>
        <p>{text(copy.emptyBody)}</p>
      </InlineNotice>
    );
  }

  const providerName = provider ? providerLabels[provider] : "—";
  const awsRoleField = flowMode === "bootstrap" ? copy.fields.awsRoleBootstrap : copy.fields.awsRolePreferred;
  const awsRoleArnField = flowMode === "bootstrap" ? copy.fields.awsRoleArnBootstrap : copy.fields.awsRoleArnPreferred;

  return (
    <section className="provider-auth-panel" aria-labelledby="provider-auth-title">
      <div className="section-heading section-heading--row">
        <div>
          <p className="eyebrow">{text(copy.eyebrow)}</p>
          <h2 id="provider-auth-title">{text(copy.title)}</h2>
          <p>{text(copy.intro)}</p>
        </div>
        {installed
          ? <StatusPill label={text(copy.statusActive, { expires: formatDateTime(installed.expires_at) })} tone="positive" />
          : <StatusPill label={text(copy.statusMissing)} tone="unknown" />}
      </div>

      {!nativeMode && (
        <InlineNotice tone="info" title={text(copy.demoTitle)}>
          <p>{text(copy.demoBody)}</p>
        </InlineNotice>
      )}

      <label className="field provider-auth-source">
        <span>{text(copy.sourceLabel)}</span>
        <select
          value={selectedSource?.id ?? ""}
          disabled={working || disabled}
          onChange={(event) => changeSource(event.target.value)}
        >
          {providerSources.map((source) => (
            <option key={source.id} value={source.id}>
              {providerLabels[providerBySourceKind[source.kind]!]} · {source.label}
            </option>
          ))}
        </select>
        <small>{text(copy.sourceHelp)}</small>
      </label>

      {installed && (
        <div className="provider-current-access">
          <div>
            <strong><Icon name="check" size={17} />{text(copy.connectedTitle)}</strong>
            <p>{text(copy.connectedBody)}</p>
          </div>
          <button className="button button--ghost button--small" type="button" disabled={working || disabled} onClick={() => void revokePreferred()}>
            {text(copy.disconnect)}
          </button>
        </div>
      )}

      <div className="provider-auth-choice-heading">
        <h3 id="provider-auth-choice-title">{text(copy.choiceQuestion)}</h3>
        <p>{text(copy.choiceHelp)}</p>
      </div>
      <div className="provider-auth-choice-grid" role="group" aria-labelledby="provider-auth-choice-title" aria-label={text(copy.choiceAria)}>
        <button
          type="button"
          className={flowMode === "preferred" ? "provider-auth-choice provider-auth-choice--active" : "provider-auth-choice"}
          aria-pressed={flowMode === "preferred"}
          disabled={working || disabled}
          onClick={() => chooseFlow("preferred")}
        >
          <span className="provider-auth-choice__badge">{text(copy.preferredBadge)}</span>
          <strong>{text(copy.preferredTitle)}</strong>
          <span>{text(copy.preferredBody)}</span>
        </button>
        <button
          type="button"
          className={flowMode === "bootstrap" ? "provider-auth-choice provider-auth-choice--active" : "provider-auth-choice"}
          aria-pressed={flowMode === "bootstrap"}
          disabled={working || disabled}
          onClick={() => chooseFlow("bootstrap")}
        >
          <strong>{text(copy.bootstrapTitle)}</strong>
          <span>{text(copy.bootstrapBody)}</span>
        </button>
      </div>

      {flowMode && provider && (
        <form className="provider-auth-form" onSubmit={flowMode === "preferred" ? beginPreferred : planBootstrap}>
          <div className="provider-auth-form__heading">
            <h3>{text(flowMode === "preferred" ? copy.formTitlePreferred : copy.formTitleBootstrap, { provider: providerName })}</h3>
            <p>{text(copy.formIntro, { provider: providerName })}</p>
          </div>

          <div className="provider-scope-summary">
            <strong><Icon name="lock" size={17} />{text(copy.scopeTitle)}</strong>
            <p>{text(copy.scope[provider])}</p>
          </div>

          <fieldset className="provider-auth-fields" disabled={working || disabled}>
            <legend className="visually-hidden">{providerName}</legend>
            <div className="form-grid form-grid--two">
              {provider === "aws" && <>
                <label className="field field--wide">
                  <span>{text(copy.fields.awsStartUrl.label)}</span>
                  <input required type="url" autoComplete="off" spellCheck={false} value={awsStartUrl} onChange={(event) => setAwsStartUrl(event.target.value)} placeholder={copy.fields.awsStartUrl.example} />
                  {fieldHelp(copy.fields.awsStartUrl)}
                </label>
                <label className="field">
                  <span>{text(copy.fields.awsRegion.label)}</span>
                  <input required autoComplete="off" spellCheck={false} value={awsRegion} onChange={(event) => setAwsRegion(event.target.value)} placeholder={copy.fields.awsRegion.example} />
                  {fieldHelp(copy.fields.awsRegion)}
                </label>
                <label className="field">
                  <span>{text(copy.fields.awsAccountId.label)}</span>
                  <input required inputMode="numeric" pattern="[0-9]{12}" autoComplete="off" value={awsAccountId} onChange={(event) => setAwsAccountId(event.target.value)} placeholder={copy.fields.awsAccountId.example} />
                  {fieldHelp(copy.fields.awsAccountId)}
                </label>
                <label className="field">
                  <span>{text(awsRoleField.label)}</span>
                  <input required pattern="[A-Za-z0-9+=,.@_/-]{1,64}" autoComplete="off" spellCheck={false} value={awsRoleName} onChange={(event) => setAwsRoleName(event.target.value)} placeholder={awsRoleField.example} />
                  {fieldHelp(awsRoleField)}
                </label>
                <label className="field field--wide">
                  <span>{text(awsRoleArnField.label)}</span>
                  <input required autoComplete="off" spellCheck={false} value={awsRoleArn} onChange={(event) => setAwsRoleArn(event.target.value)} placeholder={awsRoleArnField.example} />
                  {fieldHelp(awsRoleArnField)}
                </label>
              </>}

              {(provider === "azure" || provider === "microsoft365") && <>
                <label className="field">
                  <span>{text(copy.fields.tenantId.label)}</span>
                  <input required pattern="[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}" autoComplete="off" spellCheck={false} value={tenantId} onChange={(event) => setTenantId(event.target.value)} placeholder={copy.fields.tenantId.example} />
                  {fieldHelp(copy.fields.tenantId)}
                </label>
                <label className="field">
                  <span>{text(copy.fields.publicClientId.label)}</span>
                  <input required pattern="[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}" autoComplete="off" spellCheck={false} value={publicClientId} onChange={(event) => setPublicClientId(event.target.value)} placeholder={copy.fields.publicClientId.example} />
                  {fieldHelp(copy.fields.publicClientId)}
                </label>
                {provider === "azure" && (
                  <label className="field field--wide">
                    <span>{text(copy.fields.subscriptionId.label)}</span>
                    <input required pattern="[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}" autoComplete="off" spellCheck={false} value={subscriptionId} onChange={(event) => setSubscriptionId(event.target.value)} placeholder={copy.fields.subscriptionId.example} />
                    {fieldHelp(copy.fields.subscriptionId)}
                  </label>
                )}
              </>}

              {provider === "gcp" && <>
                <label className="field field--wide">
                  <span>{text(copy.fields.gcpClientId.label)}</span>
                  <input required pattern="[0-9]+-[A-Za-z0-9_-]+\.apps\.googleusercontent\.com" autoComplete="off" spellCheck={false} value={publicClientId} onChange={(event) => setPublicClientId(event.target.value)} placeholder={copy.fields.gcpClientId.example} />
                  {fieldHelp(copy.fields.gcpClientId)}
                </label>
                <label className="field">
                  <span>{text(copy.fields.gcpOrganizationId.label)}</span>
                  <input required inputMode="numeric" pattern="[0-9]+" autoComplete="off" value={gcpOrganizationId} onChange={(event) => setGcpOrganizationId(event.target.value)} placeholder={copy.fields.gcpOrganizationId.example} />
                  {fieldHelp(copy.fields.gcpOrganizationId)}
                </label>
                {flowMode === "bootstrap" && (
                  <label className="field">
                    <span>{text(copy.fields.gcpProjectId.label)}</span>
                    <input required pattern="[a-z][a-z0-9-]{4,28}[a-z0-9]" autoComplete="off" spellCheck={false} value={gcpProjectId} onChange={(event) => setGcpProjectId(event.target.value)} placeholder={copy.fields.gcpProjectId.example} />
                    {fieldHelp(copy.fields.gcpProjectId)}
                  </label>
                )}
                <div className="field field--wide provider-generated-field">
                  <span>{text(copy.fields.gcpRedirect.label)}</span>
                  <span className="field-inline">
                    <input readOnly aria-readonly="true" value={gcpRedirectUri} />
                    <button className="button button--ghost button--small" type="button" disabled={working} onClick={() => setGcpRedirectUri(randomLoopback())}>{text(copy.regenerate)}</button>
                  </span>
                  {fieldHelp(copy.fields.gcpRedirect)}
                </div>
              </>}
            </div>
          </fieldset>

          <InlineNotice tone={flowMode === "bootstrap" ? "warning" : "info"} title={text(copy.noSecretsTitle)}>
            <p>{text(flowMode === "bootstrap" ? copy.noSecretsBootstrap : copy.noSecretsPreferred)}</p>
          </InlineNotice>

          {error && (
            <div className="provider-auth-error" role="alert">
              <p><Icon name="warning" size={16} />{text(copy.errors[error.kind])}</p>
              {error.detail && <details><summary>{text(copy.errorTechnical)}</summary><pre>{error.detail}</pre></details>}
            </div>
          )}
          {notice && <p className="provider-auth-success" role="status"><Icon name="check" size={16} />{text(copy.notices[notice])}</p>}

          <details className="provider-auth-technical">
            <summary>{text(copy.technicalSummary)}</summary>
            <dl>
              <div><dt>{text(copy.technicalFlow)}</dt><dd>{text(provider === "gcp" ? copy.protocolPkce : copy.protocolDevice)}</dd></div>
              <div><dt>{text(copy.technicalEngines)}</dt><dd><code>{providerEngineBindings[provider].join(", ")}</code></dd></div>
              <div><dt>{text(copy.technicalCheckouts)}</dt><dd>{formatNumber(providerCheckoutLimits[provider])}</dd></div>
              <div><dt>{text(copy.technicalFields)}</dt><dd><code>{providerAuthorizationRequiredFields[provider][flowMode].join(", ")}</code></dd></div>
            </dl>
            <p>{text(copy.technicalBoundary)}</p>
          </details>

          <div className="form-actions provider-auth-actions">
            <span />
            <button className="button button--primary" type="submit" disabled={!nativeMode || working || disabled}>
              {working ? text(copy.working) : text(flowMode === "preferred" ? copy.submitPreferred : copy.submitBootstrap)}
              <Icon name="arrow" size={17} />
            </button>
          </div>
        </form>
      )}

      {error && !flowMode && (
        <div className="provider-auth-error" role="alert">
          <p><Icon name="warning" size={16} />{text(copy.errors[error.kind])}</p>
          {error.detail && <details><summary>{text(copy.errorTechnical)}</summary><pre>{error.detail}</pre></details>}
        </div>
      )}
      {notice && !flowMode && <p className="provider-auth-success" role="status"><Icon name="check" size={16} />{text(copy.notices[notice])}</p>}

      {prompt && (
        <section className="provider-prompt" aria-live="polite">
          <div>
            <p className="eyebrow">{text(copy.promptEyebrow)}</p>
            <h3>{text(copy.promptTitle)}</h3>
            <p>{text(copy.promptBody)}</p>
          </div>
          {promptUrl
            ? <button className="button button--primary" type="button" onClick={() => void openProviderLogin()}>{text(copy.openProvider)} <Icon name="arrow" size={17} /></button>
            : <InlineNotice tone="warning" title={text(copy.unsafePromptTitle)}><p>{text(copy.unsafePromptBody)}</p></InlineNotice>}
          <p>{text(copy.promptExpiry, { expires: formatDateTime(prompt.prompt.expires_at) })}</p>
          <details className="provider-auth-technical provider-prompt__technical">
            <summary>{text(copy.promptTechnical)}</summary>
            {prompt.flow === "device" && <div className="provider-device-code"><span>{text(copy.deviceCode)}</span><code>{prompt.prompt.user_code}</code></div>}
            {promptSafetyNotice && <p><strong>{text(copy.backendSafety)}:</strong> {promptSafetyNotice}</p>}
          </details>
          <button className="button button--ghost button--small" type="button" onClick={() => void cancelPreferred()}>{text(copy.cancel)}</button>
        </section>
      )}

      {flowMode === "bootstrap" && bootstrapPlan && (
        <section className="bootstrap-plan" aria-labelledby="bootstrap-plan-title">
          <div className="section-heading">
            <p className="eyebrow">{text(copy.planEyebrow)}</p>
            <h3 id="bootstrap-plan-title">{text(copy.planTitle)}</h3>
            <p>{text(copy.planBody)}</p>
            <p><strong>{text(copy.planExpiry, { expires: formatDateTime(bootstrapPlan.expires_at) })}</strong></p>
          </div>
          <details className="provider-auth-technical bootstrap-plan__technical">
            <summary>{text(copy.planTechnical)}</summary>
            {bootstrapSafetyNotice && <p>{bootstrapSafetyNotice}</p>}
            <dl>
              <div><dt>{text(copy.planIdentity)}</dt><dd><code>{bootstrapPlan.scan_identity_name}</code></dd></div>
              <div><dt>{text(copy.planHash)}</dt><dd><code>{bootstrapPlan.template_sha256}</code></dd></div>
              <div><dt>{text(copy.planHosts)}</dt><dd>{bootstrapPlan.allowed_endpoint_hosts.join(", ")}</dd></div>
            </dl>
            <h4>{text(copy.planOperations)}</h4>
            <ol>{bootstrapPlan.operations.map((operation) => {
              const description = providerAuthorizationTechnicalDetail(operation.description);
              return <li key={operation.operation_id}>{description && <strong>{description}</strong>}<span>{operation.provider_api_operations.join(" · ")}</span></li>;
            })}</ol>
            {bootstrapTemplate && <details><summary>{text(copy.planTemplate)}</summary><pre>{bootstrapTemplate}</pre></details>}
          </details>
          <div className="form-actions">
            <p><Icon name="warning" size={16} /> {text(copy.planConfirmBoundary)}</p>
            <button className="button button--primary" type="button" disabled={working || disabled} onClick={() => void executeBootstrap()}>{working ? text(copy.executingPlan) : text(copy.executePlan)}</button>
          </div>
        </section>
      )}

      {bootstrapMessages.length > 0 && (
        <section className="bootstrap-messages" aria-live="polite">
          <h3>{text(copy.messagesTitle)}</h3>
          <p>{text(copy.messagesBody)}</p>
          {bootstrapProviderUrls.map((url) => <button key={url} className="button button--secondary button--small" type="button" onClick={() => void openTrustedUrl(url)}>{text(copy.openOfficialPage)}</button>)}
          <details className="provider-auth-technical">
            <summary>{text(copy.messagesTechnical)}</summary>
            {bootstrapMessages.map((message, index) => <pre key={`${index}-${message}`}>{message}</pre>)}
          </details>
        </section>
      )}

      {bootstrapOperation && (
        <InlineNotice tone="warning" title={text(copy.cleanupCurrentTitle)}>
          <p>{text(copy.cleanupCurrentBody)}</p>
          <details className="provider-auth-technical">
            <summary>{text(copy.cleanupCurrentTechnical)}</summary>
            <dl>
              <div><dt>{text(copy.operationId)}</dt><dd><code>{bootstrapOperation.id}</code></dd></div>
              {bootstrapOperation.cleanupPath && <div><dt>{text(copy.ledgerPath)}</dt><dd><code>{bootstrapOperation.cleanupPath}</code></dd></div>}
            </dl>
          </details>
          <button className="button button--secondary button--small" type="button" disabled={working || !nativeMode} onClick={() => void cleanupBootstrap()}>{text(copy.cleanupAction)}</button>
        </InlineNotice>
      )}

      {cleanupObligations.length > 0 && (
        <section className="bootstrap-plan provider-cleanup-list" aria-labelledby="bootstrap-cleanup-title">
          <div className="section-heading">
            <p className="eyebrow">{text(copy.cleanupListEyebrow)}</p>
            <h3 id="bootstrap-cleanup-title">{text(copy.cleanupListTitle)}</h3>
            <p>{text(copy.cleanupListBody)}</p>
          </div>
          <ol>
            {cleanupObligations.map((obligation) => {
              const canResume = obligation.status !== "completed" && provider === obligation.provider;
              return (
                <li key={obligation.operationId}>
                  <strong>{providerLabels[obligation.provider]} · {text(copy.cleanupStatuses[obligation.status])}</strong>
                  <span>{text(copy.cleanupProgress, { completed: formatNumber(obligation.completedItems), total: formatNumber(obligation.totalItems) })}</span>
                  <details className="provider-auth-technical">
                    <summary>{text(copy.cleanupTechnical)}</summary>
                    <dl>
                      <div><dt>{text(copy.operationId)}</dt><dd><code>{obligation.operationId}</code></dd></div>
                      <div><dt>{text(copy.cleanupSchema)}</dt><dd><code>{obligation.schemaVersion}</code></dd></div>
                      <div><dt>{text(copy.cleanupStatus)}</dt><dd><code>{obligation.status}</code></dd></div>
                    </dl>
                  </details>
                  {obligation.status !== "completed" && (
                    <button className="button button--secondary button--small" type="button" disabled={working || !nativeMode || !canResume} onClick={() => void cleanupBootstrap(obligation.operationId)}>
                      {provider === obligation.provider
                        ? text(copy.cleanupResume)
                        : text(copy.cleanupSelectProvider, { provider: providerLabels[obligation.provider] })}
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
