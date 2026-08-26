import {
  useCallback,
  useEffect,
  useMemo,
  useRef,
  useState,
  type ChangeEvent,
  type FormEvent,
} from "react";
import { openUrl } from "@tauri-apps/plugin-opener";

import { useI18n, type BilingualText } from "../i18n";
import {
  providerAuthorizationRequiredFields,
  providerAuthorizationTechnicalDetail,
  providerCheckoutLimits,
  providerEngineBindings,
  type Provider,
  type ProviderAuthorizationPath,
  type ProviderCoordinateField,
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
  onConnectionStateChanged?: (connection: ProviderConnectionBoundary | undefined) => void;
}

export interface ProviderConnectionBoundary {
  sourceId: string;
  platform: "aws" | "azure" | "gcp" | "m365";
}

interface FieldCopy {
  label: BilingualText;
  what: BilingualText;
  where: BilingualText;
  example: string;
}

const copy = {
  emptyTitle: { en: "Add a cloud account to this scan", zhTW: "把雲端帳號加入這次掃描" },
  emptyBody: {
    en: "Choose AWS, Azure, Google Cloud, or Microsoft 365 above. Then prepare its official sign-in here.",
    zhTW: "請先在上方選擇 AWS、Azure、Google Cloud 或 Microsoft 365，再回到這裡準備官方登入。",
  },
  eyebrow: { en: "CLOUD SCAN", zhTW: "掃描雲端" },
  title: { en: "Prepare {provider} sign-in", zhTW: "準備登入 {provider}" },
  intro: {
    en: "Use {provider}'s official sign-in to find risky settings, exposed resources, and access problems. The connection is read-only and expires automatically.",
    zhTW: "透過 {provider} 官方登入，找出危險設定、暴露資源與權限問題。連線只有讀取權限，並會自動到期。",
  },
  statusActive: { en: "Connected until {expires}", zhTW: "已連接至 {expires}" },
  statusMissing: { en: "Not connected", zhTW: "尚未連接" },
  demoTitle: { en: "Use the desktop app to connect a real account", zhTW: "請使用桌面版連接真實帳號" },
  demoBody: {
    en: "This preview uses sample data and will not open a cloud sign-in page.",
    zhTW: "這個預覽只使用範例資料，不會開啟雲端登入頁。",
  },
  sourceLabel: { en: "Account to scan", zhTW: "要掃描的帳號" },
  sourceHelp: {
    en: "Choose the cloud account, tenant, or organization you added to this scan project.",
    zhTW: "選擇你已加入這個掃描專案的雲端帳號、租用戶或組織。",
  },
  connectedTitle: { en: "Cloud scan connected", zhTW: "雲端掃描已連接" },
  connectedBody: {
    en: "This scan project can now check the selected account with short-lived, read-only access.",
    zhTW: "這個掃描專案現在可以使用短期唯讀權限檢查所選帳號。",
  },
  disconnect: { en: "Disconnect account", zhTW: "中斷帳號連線" },
  connectCtaTitle: { en: "Prepare {provider} sign-in", zhTW: "準備登入 {provider}" },
  connectCtaBody: {
    en: "Ask IT for one small connection file—no passwords or keys. Choose it here, then sign in on the provider's official page.",
    zhTW: "向 IT 取得一個不含密碼或金鑰的小型連線設定檔，在這裡選取後，再到雲端服務商的官方頁面登入。",
  },
  connectCta: { en: "Set up cloud sign-in", zhTW: "設定雲端登入" },
  connectionDetailsSummary: { en: "Set up {provider} sign-in", zhTW: "設定 {provider} 登入" },
  connectionDetailsIntro: {
    en: "Your IT team prepares this once for your organization.",
    zhTW: "這份設定由 IT 為組織準備一次即可。",
  },
  preparationStepsLabel: { en: "Three steps to connect a cloud account", zhTW: "連接雲端帳號的三個步驟" },
  preparationStep1: {
    en: "Ask IT for the connection setup file.",
    zhTW: "向 IT 取得連線設定檔。",
  },
  preparationStep2: {
    en: "Choose the file. It is checked locally and is not kept.",
    zhTW: "選擇檔案；程式只在本機檢查，不會保存原檔。",
  },
  preparationStep3: {
    en: "Continue to {provider}'s official sign-in page.",
    zhTW: "前往 {provider} 官方登入頁。",
  },
  requestTitle: { en: "Ask IT for the setup file", zhTW: "向 IT 取得設定檔" },
  requestIntro: {
    en: "Send this short request to your IT or cloud admin:",
    zhTW: "把這段簡短訊息傳給 IT 或雲端管理員：",
  },
  requestMessagePreferred: {
    en: "Please send me the non-secret {provider} connection setup JSON for ai-security-scanner, using our existing read-only access.",
    zhTW: "請提供 ai-security-scanner 使用的 {provider} 非機密 connection setup JSON，並使用組織既有的唯讀權限。",
  },
  requestMessageBootstrap: {
    en: "Please send me the non-secret {provider} connection setup JSON for ai-security-scanner, for temporary read-only scan access.",
    zhTW: "請提供 ai-security-scanner 使用的 {provider} 非機密 connection setup JSON，用來建立暫時的唯讀掃描權限。",
  },
  copyRequest: { en: "Copy request for IT", zhTW: "複製給 IT 的請求" },
  requestCopied: { en: "Request copied", zhTW: "已複製請求" },
  requestCopyFailed: {
    en: "Copy was unavailable. Select the request and copy it manually.",
    zhTW: "無法自動複製；請選取上方訊息並手動複製。",
  },
  requestExactDetails: { en: "See the JSON template for IT", zhTW: "查看給 IT 的 JSON 範本" },
  registrationNote: {
    en: "Your organization must supply its own public cloud app or role details. ai-security-scanner does not provide a shared OAuth registration.",
    zhTW: "你的組織必須提供自己的雲端公開應用程式或角色資料；ai-security-scanner 不提供共用 OAuth 註冊。",
  },
  importTitle: { en: "Import the setup file", zhTW: "匯入設定檔" },
  importBody: {
    en: "Choose the file from IT. It is read once to fill the connection details, then discarded.",
    zhTW: "選擇 IT 提供的檔案；程式只讀取一次、填入連線資料後就丟棄原檔。",
  },
  chooseSetupFile: { en: "Choose setup file", zhTW: "選擇設定檔" },
  setupFileReady: {
    en: "Setup ready. The non-secret details were added.",
    zhTW: "設定完成。非機密資料已填入。",
  },
  continueTitlePreferred: { en: "Sign in with {provider}", zhTW: "登入 {provider}" },
  continueTitleBootstrap: { en: "Review temporary access", zhTW: "查看暫時權限" },
  continueBodyPreferred: {
    en: "Your browser will open the provider's official page. Your password is entered there, never in this app.",
    zhTW: "瀏覽器會開啟雲端服務商的官方頁面。密碼只在該頁面輸入，不會輸入本程式。",
  },
  continueBodyBootstrap: {
    en: "Review the temporary read-only access first. After you confirm it, {provider}'s official sign-in opens.",
    zhTW: "先查看將建立的暫時唯讀權限；確認後，才會開啟 {provider} 官方登入。",
  },
  continueWaiting: { en: "Import the setup file first", zhTW: "請先匯入設定檔" },
  manualSummary: { en: "Enter details manually", zhTW: "手動輸入資料" },
  manualIntro: {
    en: "If IT cannot send a file, enter the same non-secret details here.",
    zhTW: "如果 IT 無法提供檔案，也可以在這裡手動輸入相同的非機密資料。",
  },
  setupFileErrors: {
    missing: { en: "Choose a setup JSON file to continue.", zhTW: "請選擇設定 JSON 檔案。" },
    size: { en: "This file is too large. Ask IT for a setup JSON smaller than 64 KB.", zhTW: "檔案太大。請向 IT 索取小於 64 KB 的設定 JSON。" },
    type: { en: "Choose a .json file. Other file types are not accepted.", zhTW: "請選擇 .json 檔案；不接受其他檔案類型。" },
    json: { en: "This is not valid JSON. Ask IT to create the file again from the template.", zhTW: "這不是有效的 JSON。請 IT 依範本重新建立檔案。" },
    shape: { en: "The setup file has an unexpected structure. Ask IT to use the template shown here.", zhTW: "設定檔結構不正確。請 IT 使用這裡顯示的範本。" },
    schema: { en: "This setup file uses an unsupported version. Ask IT to use the current template.", zhTW: "這個設定檔版本不支援。請 IT 使用目前的範本。" },
    provider: { en: "This setup file is for a different cloud provider. Choose the matching account or file.", zhTW: "這個設定檔屬於其他雲端服務商。請選擇相符的帳號或檔案。" },
    method: { en: "The connection method in this file is not supported.", zhTW: "這個檔案指定的連接方式不支援。" },
    forbidden: { en: "This file may contain a password, secret, token, key, or credential field, so it was not imported.", zhTW: "這個檔案可能包含密碼、秘密、token、金鑰或憑證欄位，因此沒有匯入。" },
    fields: { en: "Required details are missing or extra fields were added. Ask IT to use the exact template shown here.", zhTW: "必要資料有缺漏，或檔案含有額外欄位。請 IT 使用這裡顯示的完整範本。" },
    values: { en: "One or more account details are not in the expected format. Ask IT to check the values and try again.", zhTW: "一個或多個帳號資料格式不正確。請 IT 確認內容後再試一次。" },
  },
  choiceQuestion: { en: "Choose a connection method", zhTW: "選擇連接方式" },
  choiceHelp: {
    en: "Choose the option your IT or cloud admin prepared. The setup file will match it.",
    zhTW: "選擇 IT 或雲端管理員已準備的方式；連線設定檔會和它相符。",
  },
  choiceAria: { en: "Read-only access setup method", zhTW: "唯讀存取設定方式" },
  preferredBadge: { en: "Recommended", zhTW: "建議" },
  preferredTitle: { en: "Use my organization's sign-in", zhTW: "使用組織既有登入" },
  preferredBody: {
    en: "Best when IT has already prepared a read-only role or app for security checks.",
    zhTW: "適合 IT 已經準備好資安檢查用的唯讀角色或應用程式。",
  },
  bootstrapTitle: { en: "Have IT create temporary scan access", zhTW: "由 IT 建立暫時掃描權限" },
  bootstrapBody: {
    en: "Choose this when IT wants separate read-only access that expires after the scan.",
    zhTW: "適合 IT 希望使用獨立、並會在掃描後到期的唯讀權限。",
  },
  formTitlePreferred: { en: "Details for existing {provider} access", zhTW: "既有 {provider} 存取所需資料" },
  formTitleBootstrap: { en: "Details for temporary {provider} scan access", zhTW: "暫時 {provider} 掃描權限所需資料" },
  formIntro: {
    en: "Complete every required non-secret field from your IT or cloud admin, then continue to {provider}.",
    zhTW: "請填妥 IT 或雲端管理員提供的所有必要非機密資料，再前往 {provider}。",
  },
  scopeTitle: { en: "What the cloud scan checks", zhTW: "雲端掃描會檢查什麼" },
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
    en: "The backend binds access to this exact scan project, source, provider profile, engine set, expiry, and checkout limit. It cannot be reused for another scan project or source.",
    zhTW: "後端會把存取綁定到這個掃描專案、來源、服務商設定檔、引擎集合、到期時間與取用上限，不能跨掃描專案或來源重用。",
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
    openUrl: { en: "Your system browser could not open the provider's official page. This sign-in step remains here, so you can try again.", zhTW: "系統瀏覽器無法開啟雲端服務商的官方頁面；這個登入步驟仍會留在畫面上，可以再試一次。" },
  },
  notices: {
    authorized: { en: "Read-only access was verified. It stays only in this desktop session and expires automatically.", zhTW: "唯讀存取已驗證；它只留在這次桌面程式工作階段，並會自動到期。" },
    cancelled: { en: "Sign-in was cancelled. No scanner access was added.", zhTW: "本次登入已取消，沒有加入任何掃描存取。" },
    revoked: { en: "Read-only access was disconnected. Existing results and scan history were not changed.", zhTW: "唯讀存取已中斷；既有結果與掃描記錄沒有被修改。" },
    bootstrapped: { en: "Temporary read-only access was created and verified. Its exact cleanup record is ready.", zhTW: "暫時唯讀存取已建立並驗證；精確清理紀錄也已備妥。" },
    cleaned: { en: "Cleanup ran only for resources recorded by this temporary setup. Any credential still expiring remains tracked.", zhTW: "清理只處理這次暫時設定所記錄的資源；尚在到期中的憑證仍會持續追蹤。" },
  },
  promptEyebrow: { en: "Official provider sign-in", zhTW: "雲端服務商官方登入" },
  promptTitle: { en: "Finish sign-in in your browser", zhTW: "請在瀏覽器完成登入" },
  promptBodyDevice: {
    en: "Open the official page, enter the one-time code shown below, choose your account, and approve only the displayed read access.",
    zhTW: "開啟官方頁面，輸入下方一次性代碼、選擇帳號，並只同意畫面列出的讀取權限。",
  },
  promptBodyBrowser: {
    en: "Open the official page, choose your account, and approve only the displayed read access. Return here when it is done.",
    zhTW: "開啟官方頁面、選擇帳號，並只同意畫面列出的讀取權限；完成後回到這裡即可。",
  },
  openProvider: { en: "Open official sign-in page", zhTW: "開啟官方登入頁" },
  promptExpiry: { en: "Complete this step before {expires}.", zhTW: "請在 {expires} 前完成這一步。" },
  promptTechnical: { en: "Sign-in protocol and safety details", zhTW: "登入協定與安全細節" },
  deviceCode: { en: "One-time sign-in code", zhTW: "一次性登入代碼" },
  copyDeviceCode: { en: "Copy code", zhTW: "複製代碼" },
  deviceCodeCopied: { en: "Code copied", zhTW: "已複製代碼" },
  deviceCodeCopyFailed: {
    en: "Copy was unavailable. Select the code above and copy it manually.",
    zhTW: "無法自動複製；請選取上方代碼並手動複製。",
  },
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
  editSetup: { en: "Change IT setup details", zhTW: "修改 IT 設定資料" },
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
      what: { en: "The UUID for the Microsoft Entra tenant in this scan project.", zhTW: "這個掃描專案要檢查的 Microsoft Entra 租用戶 UUID。" },
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
      what: { en: "The numeric identifier for the organization in this scan project.", zhTW: "這個掃描專案要檢查的組織數字識別碼。" },
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
type DeviceCodeCopyState = "idle" | "copied" | "failed";
type CopyState = "idle" | "copied" | "failed";
type SetupFileErrorKind = keyof typeof copy.setupFileErrors;
type ConnectionMethod = "existing_read_only" | "temporary_read_only";

interface ParsedConnectionSetup {
  flow: ProviderAuthorizationPath;
  details: Record<ProviderCoordinateField, string>;
}

interface PanelError {
  kind: PanelErrorKind;
  detail?: string;
}

const CONNECTION_SETUP_SCHEMA_VERSION = "1.0.0";
const CONNECTION_SETUP_MAX_BYTES = 64 * 1024;
const CONNECTION_SETUP_MAX_DEPTH = 4;
const CONNECTION_SETUP_MAX_NODES = 64;
const UUID_PATTERN = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/iu;
const GCP_CLIENT_ID_PATTERN = /^[0-9]+-[A-Za-z0-9_-]+\.apps\.googleusercontent\.com$/u;
const GCP_PROJECT_ID_PATTERN = /^[a-z][a-z0-9-]{4,28}[a-z0-9]$/u;
const AWS_REGION_PATTERN = /^(?:[a-z]{2}(?:-gov)?-[a-z]+-\d)$/u;
const AWS_ROLE_NAME_PATTERN = /^[A-Za-z0-9+=,.@_/-]{1,64}$/u;
const connectionSetupFileFields: Readonly<
  Record<Provider, Readonly<Record<ProviderAuthorizationPath, readonly ProviderCoordinateField[]>>>
> = {
  aws: {
    preferred: ["start_url", "region", "account_id", "role_name"],
    bootstrap: ["start_url", "region", "account_id", "role_name"],
  },
  azure: {
    preferred: ["tenant_id", "public_client_id", "subscription_id"],
    bootstrap: ["tenant_id", "public_client_id", "subscription_id"],
  },
  gcp: {
    preferred: ["public_client_id", "organization_id"],
    bootstrap: ["public_client_id", "organization_id", "project_id"],
  },
  microsoft365: {
    preferred: ["tenant_id", "public_client_id"],
    bootstrap: ["tenant_id", "public_client_id"],
  },
};
const FORBIDDEN_SETUP_FIELD_PARTS = new Set([
  "password",
  "passwd",
  "secret",
  "token",
  "key",
  "keys",
  "credential",
  "credentials",
  "certificate",
  "private",
]);

class ConnectionSetupFileError extends Error {
  constructor(readonly kind: SetupFileErrorKind) {
    super(kind);
  }
}

const isPlainRecord = (value: unknown): value is Record<string, unknown> =>
  Boolean(value) && typeof value === "object" && !Array.isArray(value)
  && (Object.getPrototypeOf(value) === Object.prototype || Object.getPrototypeOf(value) === null);

const sortedKeys = (value: Record<string, unknown>): string[] => Object.keys(value).sort();

const sameKeys = (actual: readonly string[], expected: readonly string[]): boolean =>
  actual.length === expected.length && actual.every((key, index) => key === expected[index]);

const fieldNameContainsSecret = (fieldName: string): boolean => {
  const separated = fieldName.replace(/([a-z0-9])([A-Z])/gu, "$1_$2").toLocaleLowerCase("en-US");
  return separated.split(/[^a-z0-9]+/u).some((part) => FORBIDDEN_SETUP_FIELD_PARTS.has(part));
};

const rejectSecretFieldsAndExcessiveNesting = (value: unknown): void => {
  let nodes = 0;
  const visit = (current: unknown, depth: number): void => {
    nodes += 1;
    if (nodes > CONNECTION_SETUP_MAX_NODES || depth > CONNECTION_SETUP_MAX_DEPTH) {
      throw new ConnectionSetupFileError("shape");
    }
    if (Array.isArray(current)) {
      for (const item of current) visit(item, depth + 1);
      return;
    }
    if (!isPlainRecord(current)) return;
    for (const [key, item] of Object.entries(current)) {
      if (fieldNameContainsSecret(key)) throw new ConnectionSetupFileError("forbidden");
      visit(item, depth + 1);
    }
  };
  visit(value, 0);
};

const flowForConnectionMethod = (method: unknown): ProviderAuthorizationPath => {
  if (method === "existing_read_only") return "preferred";
  if (method === "temporary_read_only") return "bootstrap";
  throw new ConnectionSetupFileError("method");
};

const connectionMethodForFlow = (flow: ProviderAuthorizationPath): ConnectionMethod =>
  flow === "preferred" ? "existing_read_only" : "temporary_read_only";

const validateLoopbackRedirect = (value: string): boolean => {
  try {
    const url = new URL(value);
    const port = Number(url.port);
    return url.protocol === "http:"
      && url.hostname === "127.0.0.1"
      && Number.isInteger(port)
      && port >= 49_152
      && port <= 65_535
      && url.pathname === "/oauth2/callback"
      && !url.username
      && !url.password
      && !url.search
      && !url.hash;
  } catch {
    return false;
  }
};

const validateAwsStartUrl = (value: string): boolean => {
  try {
    const url = new URL(value);
    const host = url.hostname.toLocaleLowerCase("en-US");
    return url.protocol === "https:"
      && (host === "awsapps.com" || host.endsWith(".awsapps.com"))
      && (url.pathname === "/start" || url.pathname === "/start/")
      && !url.username
      && !url.password
      && !url.search
      && !url.hash;
  } catch {
    return false;
  }
};

const validateConnectionValue = (
  provider: Provider,
  field: ProviderCoordinateField,
  value: string,
  details: Readonly<Record<string, string>>,
): boolean => {
  if (!value || value.length > 2_048) return false;
  switch (field) {
    case "start_url": return validateAwsStartUrl(value);
    case "region": return AWS_REGION_PATTERN.test(value);
    case "account_id": return /^[0-9]{12}$/u.test(value);
    case "role_name": return AWS_ROLE_NAME_PATTERN.test(value);
    case "role_arn": {
      const match = /^arn:(?:aws|aws-us-gov|aws-cn):iam::([0-9]{12}):role\/[A-Za-z0-9+=,.@_/-]{1,64}$/u.exec(value);
      return Boolean(match && match[1] === details.account_id);
    }
    case "tenant_id":
    case "subscription_id": return UUID_PATTERN.test(value);
    case "public_client_id": return provider === "gcp"
      ? GCP_CLIENT_ID_PATTERN.test(value)
      : UUID_PATTERN.test(value);
    case "organization_id": return /^[0-9]+$/u.test(value);
    case "project_id": return GCP_PROJECT_ID_PATTERN.test(value);
    case "redirect_uri": return validateLoopbackRedirect(value);
  }
};

const deriveAwsRoleArn = (region: string, accountId: string, roleName: string): string => {
  const partition = region.startsWith("us-gov-") ? "aws-us-gov" : region.startsWith("cn-") ? "aws-cn" : "aws";
  return `arn:${partition}:iam::${accountId}:role/${roleName}`;
};

const normalizeAndValidateDetails = (
  provider: Provider,
  flow: ProviderAuthorizationPath,
  value: unknown,
  requireExactKeys = true,
): Record<ProviderCoordinateField, string> => {
  if (!isPlainRecord(value)) throw new ConnectionSetupFileError("shape");
  const expectedFields = [...providerAuthorizationRequiredFields[provider][flow]].sort();
  if (requireExactKeys && !sameKeys(sortedKeys(value), expectedFields)) {
    throw new ConnectionSetupFileError("fields");
  }
  const details = {} as Record<ProviderCoordinateField, string>;
  for (const field of expectedFields) {
    const raw = value[field];
    if (typeof raw !== "string") throw new ConnectionSetupFileError("values");
    details[field] = raw.trim();
  }
  for (const field of expectedFields) {
    if (!validateConnectionValue(provider, field, details[field], details)) {
      throw new ConnectionSetupFileError("values");
    }
  }
  return details;
};

const normalizeConnectionSetupDetails = (
  provider: Provider,
  flow: ProviderAuthorizationPath,
  value: unknown,
  localGcpRedirectUri: string,
): Record<ProviderCoordinateField, string> => {
  if (!isPlainRecord(value)) throw new ConnectionSetupFileError("shape");
  const expectedFields = [...connectionSetupFileFields[provider][flow]].sort();
  if (!sameKeys(sortedKeys(value), expectedFields)) throw new ConnectionSetupFileError("fields");
  const supplied = {} as Record<ProviderCoordinateField, string>;
  for (const field of expectedFields) {
    const raw = value[field];
    if (typeof raw !== "string") throw new ConnectionSetupFileError("values");
    supplied[field] = raw.trim();
  }
  if (provider === "aws") {
    supplied.role_arn = deriveAwsRoleArn(supplied.region, supplied.account_id, supplied.role_name);
  }
  if (provider === "gcp") supplied.redirect_uri = localGcpRedirectUri;
  return normalizeAndValidateDetails(provider, flow, supplied);
};

const parseConnectionSetup = (
  content: string,
  expectedProvider: Provider,
  localGcpRedirectUri: string,
): ParsedConnectionSetup => {
  let value: unknown;
  try {
    value = JSON.parse(content.replace(/^\uFEFF/u, ""));
  } catch {
    throw new ConnectionSetupFileError("json");
  }
  rejectSecretFieldsAndExcessiveNesting(value);
  if (!isPlainRecord(value)) throw new ConnectionSetupFileError("shape");
  const expectedTopLevel = ["connection_method", "details", "provider", "schema_version"].sort();
  if (!sameKeys(sortedKeys(value), expectedTopLevel)) throw new ConnectionSetupFileError("shape");
  if (value.schema_version !== CONNECTION_SETUP_SCHEMA_VERSION) throw new ConnectionSetupFileError("schema");
  if (value.provider !== expectedProvider) throw new ConnectionSetupFileError("provider");
  const flow = flowForConnectionMethod(value.connection_method);
  return {
    flow,
    details: normalizeConnectionSetupDetails(expectedProvider, flow, value.details, localGcpRedirectUri),
  };
};

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

const connectionSetupDetailsTemplate = (
  provider: Provider,
  flow: ProviderAuthorizationPath,
): Record<string, string> => {
  if (provider === "aws") {
    const roleName = flow === "preferred" ? "SecurityAuditReader" : "AdministratorAccess";
    return {
      start_url: "https://company.awsapps.com/start",
      region: "us-east-1",
      account_id: "123456789012",
      role_name: roleName,
    };
  }
  if (provider === "azure") return {
    tenant_id: "11111111-2222-4333-8444-555555555555",
    public_client_id: "aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee",
    subscription_id: "22222222-3333-4444-8555-666666666666",
  };
  if (provider === "microsoft365") return {
    tenant_id: "11111111-2222-4333-8444-555555555555",
    public_client_id: "aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee",
  };
  return {
    public_client_id: "123456789012-example.apps.googleusercontent.com",
    organization_id: "123456789012",
    ...(flow === "bootstrap" ? { project_id: "security-scanner-access" } : {}),
  };
};

const connectionSetupTemplate = (
  provider: Provider,
  flow: ProviderAuthorizationPath,
): string => JSON.stringify({
  schema_version: CONNECTION_SETUP_SCHEMA_VERSION,
  provider,
  connection_method: connectionMethodForFlow(flow),
  details: connectionSetupDetailsTemplate(provider, flow),
}, null, 2);

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
  onConnectionStateChanged,
}: ProviderAuthorizationPanelProps) {
  const { text, formatDateTime, formatNumber } = useI18n();
  const providerSources = useMemo(
    () => sources.filter((source) => Boolean(providerBySourceKind[source.kind])),
    [sources],
  );
  const [selectedSourceId, setSelectedSourceId] = useState(providerSources[0]?.id ?? "");
  const selectedSource = providerSources.find((source) => source.id === selectedSourceId) ?? providerSources[0];
  const provider = selectedSource ? providerBySourceKind[selectedSource.kind] : undefined;
  const [flowMode, setFlowMode] = useState<ProviderAuthorizationPath>("preferred");
  const [connectionDetailsOpen, setConnectionDetailsOpen] = useState(false);
  const [working, setWorking] = useState(false);
  const [error, setError] = useState<PanelError>();
  const [notice, setNotice] = useState<PanelNoticeKind>();
  const [installed, setInstalled] = useState<InstalledProviderAuthorization>();
  const [prompt, setPrompt] = useState<ProviderAuthorizationPrompt>();
  const [deviceCodeCopyState, setDeviceCodeCopyState] = useState<DeviceCodeCopyState>("idle");
  const [requestCopyState, setRequestCopyState] = useState<CopyState>("idle");
  const [setupFileError, setSetupFileError] = useState<SetupFileErrorKind>();
  const [setupFileReady, setSetupFileReady] = useState(false);
  const [manualDetailsUsed, setManualDetailsUsed] = useState(false);
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
      setFlowMode("preferred");
      setConnectionDetailsOpen(false);
      setSetupFileReady(false);
      setManualDetailsUsed(false);
      setSetupFileError(undefined);
      setRequestCopyState("idle");
    }
  }, [providerSources, selectedSourceId]);

  useEffect(() => () => {
    if (pollTimer.current) window.clearTimeout(pollTimer.current);
  }, []);

  useEffect(() => {
    setDeviceCodeCopyState("idle");
  }, [prompt?.session_id]);

  useEffect(() => {
    if (!nativeMode || !selectedSource) {
      setInstalled(undefined);
      return;
    }
    let disposed = false;
    setInstalled((current) => current?.source_id === selectedSource.id ? current : undefined);
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
    onConnectionStateChanged?.(installed ? {
      sourceId: installed.source_id,
      platform: installed.provider === "microsoft365" ? "m365" : installed.provider,
    } : undefined);
  }, [installed?.provider, installed?.source_id, onConnectionStateChanged]);

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
    if (awsRegion && awsAccountId && awsRoleName) {
      setAwsRoleArn(deriveAwsRoleArn(awsRegion, awsAccountId, awsRoleName));
    }
  }, [awsRegion, awsAccountId, awsRoleName]);

  const currentConnectionDetails = useMemo<Record<string, string>>(() => {
    const details: Record<string, string> = {};
    if (provider === "aws") Object.assign(details, {
      start_url: awsStartUrl.trim(),
      region: awsRegion.trim(),
      account_id: awsAccountId.trim(),
      role_name: awsRoleName.trim(),
      role_arn: awsRoleArn.trim(),
    });
    if (provider === "azure") Object.assign(details, {
      tenant_id: tenantId.trim(),
      public_client_id: publicClientId.trim(),
      subscription_id: subscriptionId.trim(),
    });
    if (provider === "microsoft365") Object.assign(details, {
      tenant_id: tenantId.trim(),
      public_client_id: publicClientId.trim(),
    });
    if (provider === "gcp") Object.assign(details, {
      public_client_id: publicClientId.trim(),
      organization_id: gcpOrganizationId.trim(),
      ...(flowMode === "bootstrap" ? { project_id: gcpProjectId.trim() } : {}),
      redirect_uri: gcpRedirectUri.trim(),
    });
    return details;
  }, [
    provider,
    flowMode,
    awsStartUrl,
    awsRegion,
    awsAccountId,
    awsRoleName,
    awsRoleArn,
    tenantId,
    publicClientId,
    subscriptionId,
    gcpOrganizationId,
    gcpProjectId,
    gcpRedirectUri,
  ]);

  const configurationReady = useMemo(() => {
    if (!provider) return false;
    try {
      normalizeAndValidateDetails(provider, flowMode, currentConnectionDetails);
      return true;
    } catch {
      return false;
    }
  }, [provider, flowMode, currentConnectionDetails]);
  const canContinue = configurationReady && (setupFileReady || manualDetailsUsed);

  const markManualDetailsChanged = () => {
    setSetupFileReady(false);
    setManualDetailsUsed(true);
    setSetupFileError(undefined);
  };

  const applyConnectionDetails = (
    nextProvider: Provider,
    nextFlow: ProviderAuthorizationPath,
    details: Readonly<Record<ProviderCoordinateField, string>>,
  ) => {
    if (nextProvider === "aws") {
      setAwsStartUrl(details.start_url);
      setAwsRegion(details.region);
      setAwsAccountId(details.account_id);
      setAwsRoleName(details.role_name);
      setAwsRoleArn(details.role_arn);
    } else if (nextProvider === "azure") {
      setTenantId(details.tenant_id);
      setPublicClientId(details.public_client_id);
      setSubscriptionId(details.subscription_id);
    } else if (nextProvider === "microsoft365") {
      setTenantId(details.tenant_id);
      setPublicClientId(details.public_client_id);
    } else {
      setPublicClientId(details.public_client_id);
      setGcpOrganizationId(details.organization_id);
      setGcpProjectId(nextFlow === "bootstrap" ? details.project_id : "");
      setGcpRedirectUri(details.redirect_uri);
    }
  };

  const importConnectionSetup = async (event: ChangeEvent<HTMLInputElement>) => {
    const input = event.currentTarget;
    const file = input.files?.[0];
    setSetupFileReady(false);
    setSetupFileError(undefined);
    setRequestCopyState("idle");
    try {
      if (!file || !provider) throw new ConnectionSetupFileError("missing");
      if (file.size > CONNECTION_SETUP_MAX_BYTES) throw new ConnectionSetupFileError("size");
      const mediaType = file.type.toLocaleLowerCase("en-US");
      if (!file.name.toLocaleLowerCase("en-US").endsWith(".json")
        || (mediaType !== "" && mediaType !== "application/json" && mediaType !== "text/json")) {
        throw new ConnectionSetupFileError("type");
      }
      const content = await file.text();
      if (new TextEncoder().encode(content).byteLength > CONNECTION_SETUP_MAX_BYTES) {
        throw new ConnectionSetupFileError("size");
      }
      const parsed = parseConnectionSetup(content, provider, gcpRedirectUri);
      applyConnectionDetails(provider, parsed.flow, parsed.details);
      setFlowMode(parsed.flow);
      setConnectionDetailsOpen(false);
      setManualDetailsUsed(false);
      setBootstrapPlan(undefined);
      setPrompt(undefined);
      clearFeedback();
      setSetupFileReady(true);
    } catch (cause) {
      setSetupFileError(cause instanceof ConnectionSetupFileError ? cause.kind : "json");
    } finally {
      input.value = "";
    }
  };

  const copyItRequest = async (request: string) => {
    try {
      if (!navigator.clipboard?.writeText) throw new Error("clipboard unavailable");
      await navigator.clipboard.writeText(request);
      setRequestCopyState("copied");
    } catch {
      setRequestCopyState("failed");
    }
  };

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

  const beginPreferred = async (event?: FormEvent) => {
    event?.preventDefault();
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
      setConnectionDetailsOpen(false);
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

  const planBootstrap = async (event?: FormEvent) => {
    event?.preventDefault();
    setWorking(true);
    clearFeedback();
    try {
      operatorConfig();
      const result = await scannerService.planProviderBootstrap(makeBootstrapRequest());
      setBootstrapPlan(result.data);
      setConnectionDetailsOpen(false);
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

  const copyPromptDeviceCode = async () => {
    if (prompt?.flow !== "device") return;
    try {
      if (!navigator.clipboard?.writeText) throw new Error("clipboard unavailable");
      await navigator.clipboard.writeText(prompt.prompt.user_code);
      setDeviceCodeCopyState("copied");
    } catch {
      setDeviceCodeCopyState("failed");
    }
  };

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
    setConnectionDetailsOpen(false);
    setSetupFileReady(false);
    setManualDetailsUsed(false);
    setSetupFileError(undefined);
    setRequestCopyState("idle");
    setBootstrapPlan(undefined);
    setPrompt(undefined);
    clearFeedback();
  };

  const changeSource = (sourceId: string) => {
    if (working || disabled) return;
    setSelectedSourceId(sourceId);
    setFlowMode("preferred");
    setConnectionDetailsOpen(false);
    setSetupFileReady(false);
    setManualDetailsUsed(false);
    setSetupFileError(undefined);
    setRequestCopyState("idle");
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
  const setupTemplate = provider ? connectionSetupTemplate(provider, flowMode) : "";
  const requestMessage = text(
    flowMode === "preferred" ? copy.requestMessagePreferred : copy.requestMessageBootstrap,
    { provider: providerName },
  );
  const requestForIt = `${requestMessage}\n\n${text(copy.requestExactDetails)}:\n${setupTemplate}`;

  return (
    <section className="provider-auth-panel" aria-labelledby="provider-auth-title">
      <div className="section-heading section-heading--row">
        <div>
          <p className="eyebrow">{text(copy.eyebrow)}</p>
          <h2 id="provider-auth-title">{text(copy.title, { provider: providerName })}</h2>
          <p>{text(copy.intro, { provider: providerName })}</p>
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

      {!installed && !prompt && !bootstrapPlan && provider && (
        <section className="provider-auth-details" aria-labelledby="provider-setup-title">
          <div className="provider-setup-heading">
            <h3 id="provider-setup-title">{text(copy.connectionDetailsSummary, { provider: providerName })}</h3>
            <p>{text(copy.connectCtaBody)}</p>
            <small>{text(copy.connectionDetailsIntro)}</small>
          </div>

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

          <ol className="provider-preparation-steps provider-connection-steps" aria-label={text(copy.preparationStepsLabel)}>
            <li>
              <span aria-hidden="true">1</span>
              <div>
                <h3>{text(copy.requestTitle)}</h3>
                <p>{text(copy.requestIntro)}</p>
                <blockquote>{requestMessage}</blockquote>
                <button className="button button--secondary button--small" type="button" disabled={working || disabled} onClick={() => void copyItRequest(requestForIt)}>
                  {text(copy.copyRequest)}
                </button>
                {requestCopyState !== "idle" && (
                  <small className={`provider-setup-status provider-setup-status--${requestCopyState}`} role="status">
                    {text(requestCopyState === "copied" ? copy.requestCopied : copy.requestCopyFailed)}
                  </small>
                )}
                <details className="provider-auth-technical provider-setup-template">
                  <summary>{text(copy.requestExactDetails)}</summary>
                  <p>{text(copy.registrationNote)}</p>
                  <pre>{setupTemplate}</pre>
                </details>
              </div>
            </li>
            <li>
              <span aria-hidden="true">2</span>
              <div>
                <h3>{text(copy.importTitle)}</h3>
                <p>{text(copy.importBody)}</p>
                <label className="button button--secondary button--small provider-file-picker">
                  <Icon name="file" size={16} />
                  {text(copy.chooseSetupFile)}
                  <input
                    className="visually-hidden"
                    type="file"
                    accept=".json,application/json"
                    disabled={!nativeMode || working || disabled}
                    onChange={(event) => void importConnectionSetup(event)}
                  />
                </label>
                {setupFileReady && (
                  <small className="provider-setup-status provider-setup-status--copied" role="status">
                    <Icon name="check" size={15} />{text(copy.setupFileReady)}
                  </small>
                )}
                {setupFileError && (
                  <small className="provider-setup-status provider-setup-status--failed" role="alert">
                    <Icon name="warning" size={15} />{text(copy.setupFileErrors[setupFileError])}
                  </small>
                )}
              </div>
            </li>
            <li>
              <span aria-hidden="true">3</span>
              <div>
                <h3>{text(
                  flowMode === "preferred" ? copy.continueTitlePreferred : copy.continueTitleBootstrap,
                  { provider: providerName },
                )}</h3>
                <p>{text(
                  flowMode === "preferred" ? copy.continueBodyPreferred : copy.continueBodyBootstrap,
                  { provider: providerName },
                )}</p>
                <button
                  className="button button--primary button--small"
                  type="button"
                  disabled={!nativeMode || working || disabled || !canContinue}
                  onClick={() => void (flowMode === "preferred" ? beginPreferred() : planBootstrap())}
                >
                  {working ? text(copy.working) : text(flowMode === "preferred" ? copy.submitPreferred : copy.submitBootstrap)}
                  <Icon name="arrow" size={17} />
                </button>
                {!canContinue && <small className="provider-setup-status">{text(copy.continueWaiting)}</small>}
              </div>
            </li>
          </ol>

          <details
            className="provider-manual-details"
            open={connectionDetailsOpen}
            onToggle={(event) => setConnectionDetailsOpen(event.currentTarget.open)}
          >
            <summary>{text(copy.manualSummary)}</summary>
            <p>{text(copy.manualIntro)}</p>
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
                  <input required type="url" autoComplete="off" spellCheck={false} value={awsStartUrl} onChange={(event) => { markManualDetailsChanged(); setAwsStartUrl(event.target.value); }} placeholder={copy.fields.awsStartUrl.example} />
                  {fieldHelp(copy.fields.awsStartUrl)}
                </label>
                <label className="field">
                  <span>{text(copy.fields.awsRegion.label)}</span>
                  <input required autoComplete="off" spellCheck={false} value={awsRegion} onChange={(event) => { markManualDetailsChanged(); setAwsRegion(event.target.value); }} placeholder={copy.fields.awsRegion.example} />
                  {fieldHelp(copy.fields.awsRegion)}
                </label>
                <label className="field">
                  <span>{text(copy.fields.awsAccountId.label)}</span>
                  <input required inputMode="numeric" pattern="[0-9]{12}" autoComplete="off" value={awsAccountId} onChange={(event) => { markManualDetailsChanged(); setAwsAccountId(event.target.value); }} placeholder={copy.fields.awsAccountId.example} />
                  {fieldHelp(copy.fields.awsAccountId)}
                </label>
                <label className="field">
                  <span>{text(awsRoleField.label)}</span>
                  <input required pattern="[A-Za-z0-9+=,.@_/-]{1,64}" autoComplete="off" spellCheck={false} value={awsRoleName} onChange={(event) => { markManualDetailsChanged(); setAwsRoleName(event.target.value); }} placeholder={awsRoleField.example} />
                  {fieldHelp(awsRoleField)}
                </label>
                <label className="field field--wide">
                  <span>{text(awsRoleArnField.label)}</span>
                  <input required autoComplete="off" spellCheck={false} value={awsRoleArn} onChange={(event) => { markManualDetailsChanged(); setAwsRoleArn(event.target.value); }} placeholder={awsRoleArnField.example} />
                  {fieldHelp(awsRoleArnField)}
                </label>
              </>}

              {(provider === "azure" || provider === "microsoft365") && <>
                <label className="field">
                  <span>{text(copy.fields.tenantId.label)}</span>
                  <input required pattern="[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}" autoComplete="off" spellCheck={false} value={tenantId} onChange={(event) => { markManualDetailsChanged(); setTenantId(event.target.value); }} placeholder={copy.fields.tenantId.example} />
                  {fieldHelp(copy.fields.tenantId)}
                </label>
                <label className="field">
                  <span>{text(copy.fields.publicClientId.label)}</span>
                  <input required pattern="[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}" autoComplete="off" spellCheck={false} value={publicClientId} onChange={(event) => { markManualDetailsChanged(); setPublicClientId(event.target.value); }} placeholder={copy.fields.publicClientId.example} />
                  {fieldHelp(copy.fields.publicClientId)}
                </label>
                {provider === "azure" && (
                  <label className="field field--wide">
                    <span>{text(copy.fields.subscriptionId.label)}</span>
                    <input required pattern="[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}" autoComplete="off" spellCheck={false} value={subscriptionId} onChange={(event) => { markManualDetailsChanged(); setSubscriptionId(event.target.value); }} placeholder={copy.fields.subscriptionId.example} />
                    {fieldHelp(copy.fields.subscriptionId)}
                  </label>
                )}
              </>}

              {provider === "gcp" && <>
                <label className="field field--wide">
                  <span>{text(copy.fields.gcpClientId.label)}</span>
                  <input required pattern="[0-9]+-[A-Za-z0-9_-]+\.apps\.googleusercontent\.com" autoComplete="off" spellCheck={false} value={publicClientId} onChange={(event) => { markManualDetailsChanged(); setPublicClientId(event.target.value); }} placeholder={copy.fields.gcpClientId.example} />
                  {fieldHelp(copy.fields.gcpClientId)}
                </label>
                <label className="field">
                  <span>{text(copy.fields.gcpOrganizationId.label)}</span>
                  <input required inputMode="numeric" pattern="[0-9]+" autoComplete="off" value={gcpOrganizationId} onChange={(event) => { markManualDetailsChanged(); setGcpOrganizationId(event.target.value); }} placeholder={copy.fields.gcpOrganizationId.example} />
                  {fieldHelp(copy.fields.gcpOrganizationId)}
                </label>
                {flowMode === "bootstrap" && (
                  <label className="field">
                    <span>{text(copy.fields.gcpProjectId.label)}</span>
                    <input required pattern="[a-z][a-z0-9-]{4,28}[a-z0-9]" autoComplete="off" spellCheck={false} value={gcpProjectId} onChange={(event) => { markManualDetailsChanged(); setGcpProjectId(event.target.value); }} placeholder={copy.fields.gcpProjectId.example} />
                    {fieldHelp(copy.fields.gcpProjectId)}
                  </label>
                )}
                <div className="field field--wide provider-generated-field">
                  <span>{text(copy.fields.gcpRedirect.label)}</span>
                  <span className="field-inline">
                    <input readOnly aria-readonly="true" value={gcpRedirectUri} />
                    <button className="button button--ghost button--small" type="button" disabled={working} onClick={() => { markManualDetailsChanged(); setGcpRedirectUri(randomLoopback()); }}>{text(copy.regenerate)}</button>
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
            <button className="button button--primary" type="submit" disabled={!nativeMode || working || disabled || !canContinue}>
              {working ? text(copy.working) : text(flowMode === "preferred" ? copy.submitPreferred : copy.submitBootstrap)}
              <Icon name="arrow" size={17} />
            </button>
          </div>
            </form>
          </details>
        </section>
      )}

      {error && !connectionDetailsOpen && (
        <div className="provider-auth-error" role="alert">
          <p><Icon name="warning" size={16} />{text(copy.errors[error.kind])}</p>
          {error.detail && <details><summary>{text(copy.errorTechnical)}</summary><pre>{error.detail}</pre></details>}
        </div>
      )}
      {notice && !connectionDetailsOpen && <p className="provider-auth-success" role="status"><Icon name="check" size={16} />{text(copy.notices[notice])}</p>}

      {prompt && (
        <section className="provider-prompt" aria-live="polite">
          <div>
            <p className="eyebrow">{text(copy.promptEyebrow)}</p>
            <h3>{text(copy.promptTitle)}</h3>
            <p>{text(prompt.flow === "device" ? copy.promptBodyDevice : copy.promptBodyBrowser)}</p>
          </div>
          {prompt.flow === "device" && (
            <div className="provider-device-code provider-device-code--primary">
              <span>{text(copy.deviceCode)}</span>
              <div className="provider-device-code__row">
                <code>{prompt.prompt.user_code}</code>
                <button className="button button--secondary button--small" type="button" onClick={() => void copyPromptDeviceCode()}>
                  {text(copy.copyDeviceCode)}
                </button>
              </div>
              {deviceCodeCopyState !== "idle" && (
                <small className={`provider-device-code__status provider-device-code__status--${deviceCodeCopyState}`} role="status">
                  {text(deviceCodeCopyState === "copied" ? copy.deviceCodeCopied : copy.deviceCodeCopyFailed)}
                </small>
              )}
            </div>
          )}
          {promptUrl
            ? <button className="button button--primary" type="button" onClick={() => void openProviderLogin()}>{text(copy.openProvider)} <Icon name="arrow" size={17} /></button>
            : <InlineNotice tone="warning" title={text(copy.unsafePromptTitle)}><p>{text(copy.unsafePromptBody)}</p></InlineNotice>}
          <p>{text(copy.promptExpiry, { expires: formatDateTime(prompt.prompt.expires_at) })}</p>
          <details className="provider-auth-technical provider-prompt__technical">
            <summary>{text(copy.promptTechnical)}</summary>
            <p><strong>{text(copy.technicalFlow)}:</strong> {text(prompt.flow === "device" ? copy.protocolDevice : copy.protocolPkce)}</p>
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
            <span className="button-row">
              <button className="button button--ghost" type="button" disabled={working || disabled} onClick={() => {
                setBootstrapPlan(undefined);
                setConnectionDetailsOpen(true);
              }}>{text(copy.editSetup)}</button>
              <button className="button button--primary" type="button" disabled={working || disabled} onClick={() => void executeBootstrap()}>{working ? text(copy.executingPlan) : text(copy.executePlan)}</button>
            </span>
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
