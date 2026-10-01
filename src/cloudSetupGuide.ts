import type { BilingualText } from "./i18n";
import type { Provider, ProviderAuthorizationPath } from "./providerAuthorizationPolicy";

/**
 * The provider-console steps a person follows to prepare a cloud sign-in
 * themselves. Most people scanning a cloud account own or administer it, so
 * the read-only path is written for that person; handing the setup to
 * someone else stays a secondary choice in the panel.
 *
 * Every name a step asks for is one the sign-in verifies: the tests compare
 * these lists with the permissions the Rust verifier requires and with the
 * pinned bootstrap templates, so a step cannot drift from what the app
 * accepts.
 */
export interface CloudSetupStep {
  text: BilingualText;
  /** Exact names to select or type, shown as code after the step. */
  values?: readonly string[];
}

export interface CloudSetupGuide {
  title: BilingualText;
  steps: readonly CloudSetupStep[];
}

/**
 * The AWS managed policy behind the read-only permission set. It grants
 * every read the sign-in simulates, `iam:SimulatePrincipalPolicy` included,
 * and no write the sign-in refuses.
 */
export const AWS_READ_ONLY_PERMISSION_SET = "SecurityAudit";
/** A permission set that may create the temporary role's stack. */
export const AWS_SETUP_PERMISSION_SET = "AdministratorAccess";

/** Microsoft Graph delegated permissions the Microsoft 365 sign-in requires. */
export const MICROSOFT_365_READ_PERMISSIONS = [
  "AdministrativeUnit.Read.All",
  "Application.Read.All",
  "AuditLog.Read.All",
  "Directory.Read.All",
  "Domain.Read.All",
  "Group.Read.All",
  "IdentityRiskEvent.Read.All",
  "Organization.Read.All",
  "Policy.Read.All",
  "Reports.Read.All",
  "RoleManagement.Read.Directory",
  "SecurityEvents.Read.All",
  "User.Read.All",
] as const;

/** Delegated permissions the Microsoft 365 temporary-access setup signs in with. */
export const MICROSOFT_365_SETUP_PERMISSIONS = [
  "Application.ReadWrite.All",
  "AppRoleAssignment.ReadWrite.All",
  "Directory.Read.All",
] as const;

/** Delegated permissions the Azure temporary-access setup signs in with. */
export const AZURE_SETUP_PERMISSIONS = ["Application.ReadWrite.All", "Directory.Read.All"] as const;

/** The only two roles an Azure scanning account may hold on the subscription. */
export const AZURE_SCAN_ROLES = ["Reader", "Security Reader"] as const;

/**
 * The read-only Google Cloud roles, as (role ID, console name). They are the
 * roles the temporary-access setup grants its service account.
 */
export const GCP_READ_ROLES = [
  ["roles/browser", "Browser"],
  ["roles/iam.securityReviewer", "Security Reviewer"],
  ["roles/cloudasset.viewer", "Cloud Asset Viewer"],
  ["roles/logging.viewer", "Logs Viewer"],
  ["roles/monitoring.viewer", "Monitoring Viewer"],
  ["roles/serviceusage.serviceUsageViewer", "Service Usage Viewer"],
] as const;

const azureAppPermission = (api: string, permission: string): string => `${api}: ${permission}`;

const microsoftAppRegistration = (name: string): BilingualText => ({
  en: `Sign in to the Microsoft Entra admin center as a Global Administrator. Under App registrations, choose New registration, name it ${name}, keep Single tenant, and choose Register.`,
  zhTW: `以全域管理員身分登入 Microsoft Entra 系統管理中心。在「應用程式註冊」（App registrations）選擇「新增註冊」（New registration），名稱填 ${name}，保留「單一租用戶」（Single tenant），再選擇「註冊」（Register）。`,
});

const publicClientFlows: CloudSetupStep = {
  text: {
    en: "Under Authentication, turn on Allow public client flows and save.",
    zhTW: "在「驗證」（Authentication）開啟「允許公用用戶端流程」（Allow public client flows）並儲存。",
  },
};

const removeTemporaryAccess: CloudSetupStep = {
  text: {
    en: "After the scan, choose Remove only what this setup created.",
    zhTW: "掃描結束後，選擇「只移除這次設定建立的內容」。",
  },
};

const enableIdentityCenter: CloudSetupStep = {
  text: {
    en: "Sign in to the AWS console as the account owner and open IAM Identity Center. If it is off, choose Enable, then Enable with AWS Organizations.",
    zhTW: "以帳號擁有者身分登入 AWS 主控台，開啟 IAM Identity Center。尚未啟用時，選擇「啟用」（Enable），再選「透過 AWS Organizations 啟用」（Enable with AWS Organizations）。",
  },
};

const googleOrganization: CloudSetupStep = {
  text: {
    en: "This needs a Google Cloud organization (Google Workspace or Cloud Identity). Projects under a personal Gmail account cannot be scanned.",
    zhTW: "這需要 Google Cloud 組織（Google Workspace 或 Cloud Identity）；個人 Gmail 帳號底下的專案無法掃描。",
  },
};

const googleDesktopClient: CloudSetupStep = {
  text: {
    en: "In the Google Cloud console, open Google Auth Platform and set it up for Internal users. Under Clients, create a Desktop app client and copy its client ID; the client secret is not needed.",
    zhTW: "在 Google Cloud 控制台開啟「Google Auth Platform」，設定為「內部」（Internal）使用者。在「用戶端」（Clients）建立「電腦版應用程式」（Desktop app）用戶端並複製用戶端 ID；不需要用戶端密鑰。",
  },
};

const guides: Readonly<Record<Provider, Readonly<Record<ProviderAuthorizationPath, CloudSetupGuide>>>> = {
  aws: {
    preferred: {
      title: { en: "Set up read-only access in AWS once", zhTW: "在 AWS 設定一次唯讀存取" },
      steps: [
        enableIdentityCenter,
        {
          text: {
            en: "Under Users, add yourself with your email address, then set a password from the invitation email.",
            zhTW: "在「使用者」（Users）用你的電子郵件新增自己，再從邀請信設定密碼。",
          },
        },
        {
          text: {
            en: "Under Permission sets, create a predefined permission set and choose:",
            zhTW: "在「權限集」（Permission sets）建立預先定義的權限集（Predefined permission set），選擇：",
          },
          values: [AWS_READ_ONLY_PERMISSION_SET],
        },
        {
          text: {
            en: "Under AWS accounts, select this account, choose Assign users or groups, and assign yourself that permission set.",
            zhTW: "在「AWS 帳戶」（AWS accounts）選取這個帳號，選擇「指派使用者或群組」（Assign users or groups），把這個權限集指派給你自己。",
          },
        },
        {
          text: {
            en: "Copy the AWS access portal URL and the Region from the IAM Identity Center dashboard into step 2. On the sign-in page, sign in as the user you added, not as the root user.",
            zhTW: "從 IAM Identity Center 儀表板複製「AWS 存取入口網址」（AWS access portal URL）與區域（Region），填入步驟 2。登入時使用剛新增的使用者，不要用根使用者（root user）。",
          },
        },
      ],
    },
    bootstrap: {
      title: { en: "Prepare AWS for temporary access", zhTW: "讓 AWS 可以建立暫時存取" },
      steps: [
        enableIdentityCenter,
        {
          text: {
            en: "Under AWS accounts, assign yourself a permission set on this account that can create IAM roles and CloudFormation stacks, such as:",
            zhTW: "在「AWS 帳戶」（AWS accounts）把可以建立 IAM 角色與 CloudFormation 堆疊的權限集指派給你自己，例如：",
          },
          values: [AWS_SETUP_PERMISSION_SET],
        },
        {
          text: {
            en: "Copy the AWS access portal URL and the Region from the IAM Identity Center dashboard into step 2, with that permission set's name.",
            zhTW: "從 IAM Identity Center 儀表板複製「AWS 存取入口網址」（AWS access portal URL）與區域（Region），連同該權限集名稱填入步驟 2。",
          },
        },
        removeTemporaryAccess,
      ],
    },
  },
  microsoft365: {
    preferred: {
      title: { en: "Set up read-only access in Microsoft 365 once", zhTW: "在 Microsoft 365 設定一次唯讀存取" },
      steps: [
        { text: microsoftAppRegistration("ai-security-scanner") },
        publicClientFlows,
        {
          text: {
            en: "Under API permissions, add these Microsoft Graph delegated permissions, then choose Grant admin consent:",
            zhTW: "在「API 權限」（API permissions）新增下列 Microsoft Graph 委派權限（Delegated permissions），再選擇「授與管理員同意」（Grant admin consent）：",
          },
          values: MICROSOFT_365_READ_PERMISSIONS,
        },
        {
          text: {
            en: "Copy the Directory (tenant) ID and Application (client) ID from the app's Overview into step 2. Sign in with your administrator account; the scan receives only these read permissions.",
            zhTW: "從應用程式的「概觀」（Overview）複製「目錄（租用戶）識別碼」與「應用程式（用戶端）識別碼」，填入步驟 2。登入時使用你的管理員帳號即可；掃描只會取得上列讀取權限。",
          },
        },
      ],
    },
    bootstrap: {
      title: { en: "Prepare Microsoft 365 for temporary access", zhTW: "讓 Microsoft 365 可以建立暫時存取" },
      steps: [
        { text: microsoftAppRegistration("ai-security-scanner-setup") },
        publicClientFlows,
        {
          text: {
            en: "Under API permissions, add these Microsoft Graph delegated permissions, then choose Grant admin consent. Keep this app separate from a read-only one:",
            zhTW: "在「API 權限」（API permissions）新增下列 Microsoft Graph 委派權限，再選擇「授與管理員同意」（Grant admin consent）。這個應用程式不要和唯讀用的共用：",
          },
          values: MICROSOFT_365_SETUP_PERMISSIONS,
        },
        {
          text: {
            en: "Copy its tenant ID and client ID into step 2, and sign in as a Global Administrator.",
            zhTW: "把它的租用戶識別碼與用戶端識別碼填入步驟 2，並以全域管理員身分登入。",
          },
        },
        removeTemporaryAccess,
      ],
    },
  },
  azure: {
    preferred: {
      title: { en: "Set up read-only access in Azure once", zhTW: "在 Azure 設定一次唯讀存取" },
      steps: [
        {
          text: {
            en: "Sign in to the Azure portal as the subscription owner. In Microsoft Entra ID → Users, create a user for scanning.",
            zhTW: "以訂用帳戶擁有者身分登入 Azure 入口網站。在 Microsoft Entra ID →「使用者」（Users）建立一個掃描專用使用者。",
          },
        },
        {
          text: {
            en: "Open the subscription → Access control (IAM) → Add role assignment, and give that user only these two roles:",
            zhTW: "開啟訂用帳戶 →「存取控制 (IAM)」（Access control (IAM)）→「新增角色指派」（Add role assignment），只把下列兩個角色指派給該使用者：",
          },
          values: AZURE_SCAN_ROLES,
        },
        { text: microsoftAppRegistration("ai-security-scanner") },
        publicClientFlows,
        {
          text: {
            en: "Under API permissions, add these delegated permissions, then choose Grant admin consent:",
            zhTW: "在「API 權限」（API permissions）新增下列委派權限，再選擇「授與管理員同意」（Grant admin consent）：",
          },
          values: [
            azureAppPermission("Microsoft Graph", "User.Read"),
            azureAppPermission("Microsoft Graph", "Organization.Read.All"),
            azureAppPermission("Azure Service Management", "user_impersonation"),
          ],
        },
        {
          text: {
            en: "Copy the tenant ID and client ID from the app's Overview, and the subscription ID from Subscriptions, into step 2. Sign in as the scanning user, not as the owner.",
            zhTW: "把應用程式「概觀」（Overview）中的租用戶與用戶端識別碼，以及「訂用帳戶」（Subscriptions）中的訂用帳戶識別碼填入步驟 2。登入時使用掃描專用使用者，不要用擁有者帳號。",
          },
        },
      ],
    },
    bootstrap: {
      title: { en: "Prepare Azure for temporary access", zhTW: "讓 Azure 可以建立暫時存取" },
      steps: [
        { text: microsoftAppRegistration("ai-security-scanner-setup") },
        publicClientFlows,
        {
          text: {
            en: "Under API permissions, add these delegated permissions, then choose Grant admin consent:",
            zhTW: "在「API 權限」（API permissions）新增下列委派權限，再選擇「授與管理員同意」（Grant admin consent）：",
          },
          values: [
            ...AZURE_SETUP_PERMISSIONS.map((permission) => azureAppPermission("Microsoft Graph", permission)),
            azureAppPermission("Azure Service Management", "user_impersonation"),
          ],
        },
        {
          text: {
            en: "Copy the tenant ID, client ID and subscription ID into step 2, and sign in as the subscription owner.",
            zhTW: "把租用戶、用戶端與訂用帳戶識別碼填入步驟 2，並以訂用帳戶擁有者身分登入。",
          },
        },
        removeTemporaryAccess,
      ],
    },
  },
  gcp: {
    preferred: {
      title: { en: "Set up read-only access in Google Cloud once", zhTW: "在 Google Cloud 設定一次唯讀存取" },
      steps: [
        googleOrganization,
        googleDesktopClient,
        {
          text: {
            en: "In the Google Admin console, add a user for scanning. Then in IAM for the organization, grant that user only these roles:",
            zhTW: "在 Google 管理控制台新增一個掃描專用使用者，再到組織的「IAM」只授予該使用者下列角色：",
          },
          values: GCP_READ_ROLES.map(([, name]) => name),
        },
        {
          text: {
            en: "Copy the client ID and the organization ID (IAM & Admin → Settings) into step 2. Sign in as the scanning user, not as an administrator.",
            zhTW: "把用戶端 ID 與組織 ID（「IAM 與管理」→「設定」）填入步驟 2。登入時使用掃描專用使用者，不要用管理員帳號。",
          },
        },
      ],
    },
    bootstrap: {
      title: { en: "Prepare Google Cloud for temporary access", zhTW: "讓 Google Cloud 可以建立暫時存取" },
      steps: [
        googleOrganization,
        googleDesktopClient,
        {
          text: {
            en: "Pick a project for the temporary service account. Sign in as an administrator who can create service accounts there, change the organization's IAM policy, and holds this role on that project:",
            zhTW: "選一個專案放暫時服務帳戶。登入的管理員要能在該專案建立服務帳戶、變更組織的 IAM 政策，並在該專案具備下列角色：",
          },
          values: ["Service Account Token Creator"],
        },
        removeTemporaryAccess,
      ],
    },
  },
};

export const cloudSetupGuide = (
  provider: Provider,
  flow: ProviderAuthorizationPath,
): CloudSetupGuide => guides[provider][flow];
