import { AWS_READ_ONLY_PERMISSION_SET } from "./cloudSetupGuide";
import type { BilingualText } from "./i18n";
import type { Provider } from "./providerAuthorizationPolicy";

/**
 * Why a provider refused a sign-in, and what to change. A sign-in refused for
 * having too much or too little access says which, instead of asking for a
 * retry that would fail the same way.
 *
 * Each rule reads a sentence the Rust sign-in verifier writes, or a code the
 * provider returned with its refusal. A detail no rule recognizes keeps the
 * panel's general message.
 */
export interface ProviderRejection {
  cause: BilingualText;
  fix: BilingualText;
}

type Rule = (detail: string, provider: Provider) => ProviderRejection | undefined;

const AZURE_ROLE_NAMES: Readonly<Record<string, BilingualText>> = {
  "8e3af657-a8ff-443c-a75c-2fe8c4bcb635": { en: "Owner", zhTW: "Owner（擁有者）" },
  "b24988ac-6180-42a0-ab88-20f7382dd24c": { en: "Contributor", zhTW: "Contributor（參與者）" },
  "18d7d88d-d35e-4fb5-a5c3-7773c20a72d9": {
    en: "User Access Administrator",
    zhTW: "User Access Administrator（使用者存取系統管理員）",
  },
};

const awsReadOnlyFix: BilingualText = {
  en: `Use a permission set with the ${AWS_READ_ONLY_PERMISSION_SET} policy, then sign in again.`,
  zhTW: `請使用含 ${AWS_READ_ONLY_PERMISSION_SET} 政策的權限集，再重新登入。`,
};

const microsoftConsent: ProviderRejection = {
  cause: { en: "Admin consent has not been granted for this app.", zhTW: "這個應用程式尚未取得管理員同意。" },
  fix: {
    en: "In the app registration, open API permissions and choose Grant admin consent.",
    zhTW: "請在應用程式註冊的「API 權限」（API permissions）選擇「授與管理員同意」（Grant admin consent）。",
  },
};

const microsoftAccountOutsideTenant: ProviderRejection = {
  cause: {
    en: "The account you signed in with is not in this tenant.",
    zhTW: "你登入的帳號不屬於這個租用戶。",
  },
  fix: {
    en: "Sign in with an account from the tenant entered in step 2.",
    zhTW: "請改用步驟 2 所填租用戶中的帳號登入。",
  },
};

/** Microsoft identity platform (AADSTS) codes a person can fix themselves. */
const MICROSOFT_ERROR_CODES: Readonly<Record<string, ProviderRejection>> = {
  "7000218": {
    cause: {
      en: "The app registration does not allow sign-in from a desktop app.",
      zhTW: "應用程式註冊不允許從桌面應用程式登入。",
    },
    fix: {
      en: "In the app registration, open Authentication, turn on Allow public client flows, and save.",
      zhTW: "請在應用程式註冊的「驗證」（Authentication）開啟「允許公用用戶端流程」（Allow public client flows）並儲存。",
    },
  },
  "700016": {
    cause: {
      en: "The client ID in step 2 is not an app in this tenant.",
      zhTW: "步驟 2 的用戶端識別碼不是這個租用戶中的應用程式。",
    },
    fix: {
      en: "Copy the Directory (tenant) ID and Application (client) ID again from the app's Overview.",
      zhTW: "請從應用程式的「概觀」（Overview）重新複製「目錄（租用戶）識別碼」與「應用程式（用戶端）識別碼」。",
    },
  },
  "65001": microsoftConsent,
  "90094": microsoftConsent,
  "650057": {
    cause: {
      en: "The app registration does not include a permission this sign-in asks for.",
      zhTW: "應用程式註冊缺少這次登入要求的權限。",
    },
    fix: {
      en: "Add every permission listed in step 1 under API permissions, then choose Grant admin consent.",
      zhTW: "請在「API 權限」（API permissions）加入步驟 1 列出的所有權限，再選擇「授與管理員同意」（Grant admin consent）。",
    },
  },
  "90002": {
    cause: {
      en: "No Microsoft tenant matches the tenant ID in step 2.",
      zhTW: "找不到與步驟 2 租用戶識別碼相符的 Microsoft 租用戶。",
    },
    fix: {
      en: "Copy the Directory (tenant) ID again from the app's Overview.",
      zhTW: "請從應用程式的「概觀」（Overview）重新複製「目錄（租用戶）識別碼」。",
    },
  },
  "50020": microsoftAccountOutsideTenant,
  "90072": microsoftAccountOutsideTenant,
  "53003": {
    cause: {
      en: "A Conditional Access policy in this tenant blocked the sign-in.",
      zhTW: "這個租用戶的條件式存取（Conditional Access）原則封鎖了這次登入。",
    },
    fix: {
      en: "Sign in from a device or location the policy allows, or exclude this app from the policy.",
      zhTW: "請在原則允許的裝置或位置登入，或把這個應用程式排除在原則之外。",
    },
  },
};

const rules: readonly Rule[] = [
  (detail) => {
    const permission = /AWS credential permits prohibited mutation (\S+)/u.exec(detail)?.[1];
    return permission ? {
      cause: {
        en: `This AWS role can change the account (${permission}), and the scan accepts only read-only access.`,
        zhTW: `這個 AWS 角色可以變更帳號（${permission}），而掃描只接受唯讀存取。`,
      },
      fix: {
        en: `Sign in with a read-only permission set such as ${AWS_READ_ONLY_PERMISSION_SET}.`,
        zhTW: `請改用唯讀的權限集登入，例如 ${AWS_READ_ONLY_PERMISSION_SET}。`,
      },
    } : undefined;
  },
  (detail) => {
    const permission = /AWS read-only profile is missing required permission (\S+)/u.exec(detail)?.[1];
    return permission ? {
      cause: {
        en: `This AWS role cannot read ${permission}, which the check needs.`,
        zhTW: `這個 AWS 角色無法讀取檢查需要的 ${permission}。`,
      },
      fix: awsReadOnlyFix,
    } : undefined;
  },
  (detail) => /AWS IAM read-only policy simulation failed with provider HTTP status 403/u.test(detail) ? {
    cause: {
      en: "This AWS role cannot check its own permissions, so read-only access cannot be confirmed.",
      zhTW: "這個 AWS 角色無法檢查自己的權限，因此無法確認是唯讀存取。",
    },
    fix: awsReadOnlyFix,
  } : undefined,
  (detail) => /the AWS account\/role is not assigned|AWS (?:IAM Identity Center role lookup|account role listing|short-lived role credential retrieval) failed with provider HTTP status 403/u.test(detail) ? {
    cause: {
      en: "The person who signed in does not have this permission set on this account.",
      zhTW: "登入的使用者在這個帳號沒有這個權限集。",
    },
    fix: {
      en: "Check the account ID and permission set name in step 2, or assign the permission set under IAM Identity Center → AWS accounts.",
      zhTW: "請確認步驟 2 的帳號識別碼與權限集名稱，或在 IAM Identity Center →「AWS 帳戶」（AWS accounts）指派這個權限集。",
    },
  } : undefined,
  (detail) => /AWS STS identity does not match|AWS IAM returned a different role|AWS role ARN in the connection details is not the role/u.test(detail) ? {
    cause: {
      en: "The account or role used to sign in is not the one entered in step 2.",
      zhTW: "登入使用的帳號或角色和步驟 2 填寫的不同。",
    },
    fix: {
      en: "Correct the account ID or permission set name in step 2, then sign in again.",
      zhTW: "請修正步驟 2 的帳號識別碼或權限集名稱，再重新登入。",
    },
  } : undefined,
  (detail) => /AWS IAM Identity Center (?:client registration|device authorization) failed with provider HTTP status 400/u.test(detail) ? {
    cause: {
      en: "AWS did not accept the access portal URL or Region in step 2.",
      zhTW: "AWS 不接受步驟 2 的存取入口網址或區域。",
    },
    fix: {
      en: "Copy both again from the IAM Identity Center dashboard. The Region is the one shown there, not where your resources run.",
      zhTW: "請從 IAM Identity Center 儀表板重新複製這兩項。區域要填儀表板上顯示的區域，不是資源所在的區域。",
    },
  } : undefined,
  (detail) => {
    const permission = /Microsoft token (?:includes prohibited write permission|contains a non-read-only permission) (\S+)/u.exec(detail)?.[1];
    return permission ? {
      cause: {
        en: `The app registration grants ${permission}, which can change the tenant, and the scan accepts only read-only access.`,
        zhTW: `應用程式註冊授予了可以變更租用戶的 ${permission}，而掃描只接受唯讀存取。`,
      },
      fix: {
        en: "Remove that permission under API permissions, keep only the read permissions from step 1, and grant admin consent again.",
        zhTW: "請在「API 權限」（API permissions）移除這個權限，只保留步驟 1 的讀取權限，再重新授與管理員同意。",
      },
    } : undefined;
  },
  (detail, provider) => {
    const permission = /(?:Microsoft token is missing required read permission|provider token omitted requested scope) (\S+)/u.exec(detail)?.[1];
    if (!permission) return undefined;
    if (provider === "gcp") return {
      cause: {
        en: `Google's page did not grant ${permission}.`,
        zhTW: `Google 頁面沒有授予 ${permission}。`,
      },
      fix: {
        en: "Start again and allow every access Google's page lists.",
        zhTW: "請重新開始，並允許 Google 頁面列出的所有存取。",
      },
    };
    return {
      cause: {
        en: `The app registration does not grant ${permission}, or admin consent is missing.`,
        zhTW: `應用程式註冊沒有授予 ${permission}，或尚未授與管理員同意。`,
      },
      fix: {
        en: "Add it under API permissions, then choose Grant admin consent.",
        zhTW: "請在「API 權限」（API permissions）新增它，再選擇「授與管理員同意」（Grant admin consent）。",
      },
    };
  },
  (detail) => {
    const roleId = /Azure principal has an additional unapproved role assignment ([0-9a-f-]{36})/iu.exec(detail)?.[1]?.toLowerCase();
    if (!roleId) return undefined;
    const role = AZURE_ROLE_NAMES[roleId];
    return {
      cause: role ? {
        en: `This account also has the ${role.en} role on the subscription, and the scan accepts only read-only access.`,
        zhTW: `這個帳號在訂用帳戶上還有 ${role.zhTW} 角色，而掃描只接受唯讀存取。`,
      } : {
        en: `This account also has another role on the subscription (${roleId}), and the scan accepts only read-only access.`,
        zhTW: `這個帳號在訂用帳戶上還有其他角色（${roleId}），而掃描只接受唯讀存取。`,
      },
      fix: {
        en: "Sign in with an account that has only the Reader and Security Reader roles.",
        zhTW: "請改用只有 Reader（讀者）與 Security Reader（安全性讀取者）角色的帳號登入。",
      },
    };
  },
  (detail) => /Azure principal must have exactly the Reader and Security Reader|Azure (?:subscription identity|role assignment) verification failed with provider HTTP status 403/u.test(detail) ? {
    cause: {
      en: "This account does not have both the Reader and Security Reader roles on the subscription in step 2.",
      zhTW: "這個帳號在步驟 2 的訂用帳戶上沒有同時具備 Reader（讀者）與 Security Reader（安全性讀取者）角色。",
    },
    fix: {
      en: "Assign both roles under the subscription's Access control (IAM), then sign in again.",
      zhTW: "請在訂用帳戶的「存取控制 (IAM)」（Access control (IAM)）指派這兩個角色，再重新登入。",
    },
  } : undefined,
  (detail) => /Azure token identity does not match the configured tenant|Microsoft Graph organization does not match the configured tenant|Microsoft administrator signed into a different tenant/u.test(detail) ? {
    cause: {
      en: "You signed in to a different Microsoft tenant than the one in step 2.",
      zhTW: "你登入的 Microsoft 租用戶和步驟 2 填寫的不同。",
    },
    fix: {
      en: "Sign in with an account from that tenant, or correct the tenant ID in step 2.",
      zhTW: "請改用該租用戶的帳號登入，或修正步驟 2 的租用戶識別碼。",
    },
  } : undefined,
  (detail) => /Microsoft 365 (?:audit metadata|policy|role management) permission probe failed with provider HTTP status 403/u.test(detail) ? {
    cause: {
      en: "The account you signed in with cannot read these Microsoft 365 settings.",
      zhTW: "你登入的帳號無法讀取這些 Microsoft 365 設定。",
    },
    fix: {
      en: "Sign in with a Global Administrator or Global Reader account.",
      zhTW: "請改用全域管理員（Global Administrator）或全域讀取者（Global Reader）帳號登入。",
    },
  } : undefined,
  (detail) => {
    const permission = /Google Cloud credential permits prohibited mutation (\S+)/u.exec(detail)?.[1];
    return permission ? {
      cause: {
        en: `This Google account can change the organization's access settings (${permission}), and the scan accepts only read-only access.`,
        zhTW: `這個 Google 帳號可以變更組織的存取設定（${permission}），而掃描只接受唯讀存取。`,
      },
      fix: {
        en: "Sign in as a user that has only the read roles from step 1.",
        zhTW: "請改用只具備步驟 1 讀取角色的使用者登入。",
      },
    } : undefined;
  },
  (detail) => {
    const permission = /Google Cloud read-only profile is missing required permission (\S+)/u.exec(detail)?.[1];
    return permission ? {
      cause: {
        en: `This Google account cannot read ${permission}, which the check needs.`,
        zhTW: `這個 Google 帳號無法讀取檢查需要的 ${permission}。`,
      },
      fix: {
        en: "Grant the read roles from step 1 at the organization, then sign in again.",
        zhTW: "請在組織層級授予步驟 1 的讀取角色，再重新登入。",
      },
    } : undefined;
  },
  (detail) => /Google Cloud (?:organization identity verification failed with provider HTTP status 403|returned a different organization identity)/u.test(detail) ? {
    cause: {
      en: "This Google account cannot see the organization in step 2.",
      zhTW: "這個 Google 帳號看不到步驟 2 的組織。",
    },
    fix: {
      en: "Check the organization ID under IAM & Admin → Settings, and grant the read roles from step 1 at that organization.",
      zhTW: "請到「IAM 與管理」→「設定」確認組織 ID，並在該組織授予步驟 1 的讀取角色。",
    },
  } : undefined,
  (detail) => /sign-in code expired|device authorization expired before completion|did not complete device authorization in time|PKCE callback is expired/u.test(detail) ? {
    cause: { en: "The sign-in took too long and expired.", zhTW: "登入花太久，已經逾時。" },
    fix: {
      en: "Start again and finish on the provider's page before the time shown.",
      zhTW: "請重新開始，並在畫面顯示的時間前完成服務商頁面上的步驟。",
    },
  } : undefined,
  (detail) => /sign-in was declined/u.test(detail) ? {
    cause: { en: "The sign-in was declined on the provider's page.", zhTW: "登入在服務商頁面被拒絕。" },
    fix: { en: "Start again and approve the read access.", zhTW: "請重新開始，並同意讀取權限。" },
  } : undefined,
  (detail, provider) => {
    if (provider !== "azure" && provider !== "microsoft365") return undefined;
    const code = /error code (\d+)/u.exec(detail)?.[1];
    return code ? MICROSOFT_ERROR_CODES[code] : undefined;
  },
];

export const explainProviderRejection = (
  provider: Provider,
  detail: string | undefined,
): ProviderRejection | undefined => {
  if (!detail) return undefined;
  for (const rule of rules) {
    const rejection = rule(detail, provider);
    if (rejection) return rejection;
  }
  return undefined;
};
