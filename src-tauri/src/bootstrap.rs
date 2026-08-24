use crate::error::{AppError, AppResult};
use chrono::{DateTime, Duration, Utc};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

const AWS_TEMPLATE: &str = include_str!("../../bootstrap/aws-readonly-cloudformation.yaml");
const AZURE_TEMPLATE: &str = include_str!("../../bootstrap/azure-readonly-arm.json");
const GCP_TEMPLATE: &str = include_str!("../../bootstrap/gcp-readonly-bindings.json");
const MICROSOFT_365_TEMPLATE: &str =
    include_str!("../../bootstrap/microsoft365-readonly-permissions.json");

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum BootstrapProvider {
    Aws,
    Azure,
    Gcp,
    Microsoft365,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum ReadOnlyCapability {
    Inventory,
    Configuration,
    IdentityAndAccess,
    SecurityPosture,
    AuditMetadata,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct BootstrapRequest {
    pub schema_version: String,
    pub case_id: String,
    pub provider: BootstrapProvider,
    pub scan_identity_name: String,
    pub capabilities: Vec<ReadOnlyCapability>,
    pub expires_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct BootstrapOperation {
    pub operation_id: String,
    pub description: String,
    pub mutates_provider: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct CleanupObligation {
    pub obligation_id: String,
    pub description: String,
    pub required: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct BootstrapPlan {
    pub schema_version: String,
    pub case_id: String,
    pub provider: BootstrapProvider,
    pub scan_identity_name: String,
    pub capabilities: Vec<ReadOnlyCapability>,
    pub provider_authentication_url: String,
    pub allowed_endpoint_hosts: Vec<String>,
    pub operations: Vec<BootstrapOperation>,
    pub template_media_type: String,
    pub template_sha256: String,
    pub template: String,
    pub expires_at: DateTime<Utc>,
    pub cleanup_obligations: Vec<CleanupObligation>,
    pub safety_notice: String,
}

pub fn create_bootstrap_plan(
    request: BootstrapRequest,
    now: DateTime<Utc>,
) -> AppResult<BootstrapPlan> {
    validate_request(&request, now)?;
    let provider = provider_profile(request.provider);
    let template_sha256 = hex::encode(Sha256::digest(provider.template.as_bytes()));

    Ok(BootstrapPlan {
        schema_version: "1.0.0".into(),
        case_id: request.case_id,
        provider: request.provider,
        scan_identity_name: request.scan_identity_name,
        capabilities: request.capabilities,
        provider_authentication_url: provider.authentication_url.into(),
        allowed_endpoint_hosts: provider.allowed_endpoint_hosts.iter().map(ToString::to_string).collect(),
        operations: vec![
            BootstrapOperation {
                operation_id: "create_dedicated_identity".into(),
                description: "Create a dedicated, time-bounded assessment identity in the provider-hosted administration surface.".into(),
                mutates_provider: true,
            },
            BootstrapOperation {
                operation_id: "attach_read_only_policy".into(),
                description: "Attach only the pinned read-only permissions declared by this plan.".into(),
                mutates_provider: true,
            },
            BootstrapOperation {
                operation_id: "verify_non_mutating_access".into(),
                description: "Verify the identity with inventory-only provider calls before issuing a scanner capability.".into(),
                mutates_provider: false,
            },
        ],
        template_media_type: provider.template_media_type.into(),
        template_sha256,
        template: provider.template.into(),
        expires_at: request.expires_at,
        cleanup_obligations: cleanup_obligations(request.provider),
        safety_notice: "Authenticate only in the provider-hosted surface. Administrative credentials must never be pasted into ai-security-scanner, its CLI, logs, containers, or AI assistants. This plan creates provider resources; review it before approval.".into(),
    })
}

fn validate_request(request: &BootstrapRequest, now: DateTime<Utc>) -> AppResult<()> {
    if request.schema_version != "1.0.0" {
        return Err(AppError::InvalidRequest(
            "unsupported bootstrap protocol version".into(),
        ));
    }
    if !valid_identifier(&request.case_id, 128) {
        return Err(AppError::InvalidRequest(
            "bootstrap case identifier is invalid".into(),
        ));
    }
    if !valid_scan_identity_name(&request.scan_identity_name) {
        return Err(AppError::InvalidRequest(
            "scan identity name must start with ai-security-scanner- and contain only lowercase letters, digits, and hyphens".into(),
        ));
    }
    if request.capabilities.is_empty() {
        return Err(AppError::InvalidRequest(
            "at least one read-only capability is required".into(),
        ));
    }
    if request.expires_at <= now || request.expires_at > now + Duration::hours(24) {
        return Err(AppError::InvalidRequest(
            "bootstrap plan expiry must be within the next 24 hours".into(),
        ));
    }
    Ok(())
}

fn valid_identifier(value: &str, max_length: usize) -> bool {
    !value.is_empty()
        && value.len() <= max_length
        && value.chars().all(|character| {
            character.is_ascii_alphanumeric() || matches!(character, '-' | '_' | '.')
        })
}

fn valid_scan_identity_name(value: &str) -> bool {
    value.starts_with("ai-security-scanner-")
        && value.len() <= 63
        && value.len() > "ai-security-scanner-".len()
        && value.chars().all(|character| {
            character.is_ascii_lowercase() || character.is_ascii_digit() || character == '-'
        })
}

struct ProviderProfile {
    authentication_url: &'static str,
    allowed_endpoint_hosts: &'static [&'static str],
    template_media_type: &'static str,
    template: &'static str,
}

fn provider_profile(provider: BootstrapProvider) -> ProviderProfile {
    match provider {
        BootstrapProvider::Aws => ProviderProfile {
            authentication_url: "https://console.aws.amazon.com/iam/",
            allowed_endpoint_hosts: &[
                "signin.aws.amazon.com",
                "console.aws.amazon.com",
                "iam.amazonaws.com",
                "sts.amazonaws.com",
                "cloudformation.amazonaws.com",
            ],
            template_media_type: "application/yaml",
            template: AWS_TEMPLATE,
        },
        BootstrapProvider::Azure => ProviderProfile {
            authentication_url: "https://portal.azure.com/#view/Microsoft_AAD_IAM/ActiveDirectoryMenuBlade/~/RegisteredApps",
            allowed_endpoint_hosts: &[
                "login.microsoftonline.com",
                "management.azure.com",
                "graph.microsoft.com",
                "portal.azure.com",
            ],
            template_media_type: "application/json",
            template: AZURE_TEMPLATE,
        },
        BootstrapProvider::Gcp => ProviderProfile {
            authentication_url: "https://console.cloud.google.com/iam-admin/serviceaccounts",
            allowed_endpoint_hosts: &[
                "accounts.google.com",
                "cloudresourcemanager.googleapis.com",
                "iam.googleapis.com",
                "sts.googleapis.com",
                "console.cloud.google.com",
            ],
            template_media_type: "application/json",
            template: GCP_TEMPLATE,
        },
        BootstrapProvider::Microsoft365 => ProviderProfile {
            authentication_url: "https://entra.microsoft.com/#view/Microsoft_AAD_RegisteredApps/ApplicationsListBlade",
            allowed_endpoint_hosts: &[
                "login.microsoftonline.com",
                "graph.microsoft.com",
                "entra.microsoft.com",
            ],
            template_media_type: "application/json",
            template: MICROSOFT_365_TEMPLATE,
        },
    }
}

fn cleanup_obligations(provider: BootstrapProvider) -> Vec<CleanupObligation> {
    let provider_resource = match provider {
        BootstrapProvider::Aws => "Delete the CloudFormation stack and dedicated IAM role.",
        BootstrapProvider::Azure => {
            "Remove both role assignments, certificate, application, and service principal."
        }
        BootstrapProvider::Gcp => {
            "Remove IAM bindings, disable keys, and delete the dedicated service account."
        }
        BootstrapProvider::Microsoft365 => {
            "Revoke consent and sessions, remove certificates, and delete the application and service principal."
        }
    };
    vec![
        CleanupObligation {
            obligation_id: "remove_scan_identity".into(),
            description: provider_resource.into(),
            required: true,
        },
        CleanupObligation {
            obligation_id: "revoke_sessions_and_tokens".into(),
            description: "Enumerate and revoke assessment sessions, refresh tokens, access keys, and temporary credentials.".into(),
            required: true,
        },
        CleanupObligation {
            obligation_id: "review_prior_admin_access".into(),
            description: "Review older administrator sessions, keys, OAuth grants, roles, and service principals; revoke anything no longer required.".into(),
            required: true,
        },
        CleanupObligation {
            obligation_id: "rotate_exposed_password".into(),
            description: "If an administrator password was exposed outside the provider surface, change it after separately revoking sessions and keys.".into(),
            required: true,
        },
    ]
}

pub fn ensure_no_secret_environment() -> AppResult<()> {
    const FORBIDDEN_MARKERS: &[&str] = &[
        "AWS_SECRET_ACCESS_KEY",
        "AWS_SESSION_TOKEN",
        "AZURE_CLIENT_SECRET",
        "GOOGLE_APPLICATION_CREDENTIALS",
        "GOOGLE_OAUTH_ACCESS_TOKEN",
        "ARM_CLIENT_SECRET",
        "MSGRAPH_CLIENT_SECRET",
        "ADMIN_PASSWORD",
    ];
    if std::env::vars_os().any(|(key, _)| {
        let key = key.to_string_lossy().to_ascii_uppercase();
        FORBIDDEN_MARKERS.iter().any(|marker| key == *marker)
    }) {
        return Err(AppError::NotAuthorized(
            "bootstrap broker refuses to start with provider or administrator secrets in its environment".into(),
        ));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn plan_contains_only_allowlisted_operations_and_a_hashed_template() {
        let now = Utc::now();
        let plan = create_bootstrap_plan(
            BootstrapRequest {
                schema_version: "1.0.0".into(),
                case_id: "case-123".into(),
                provider: BootstrapProvider::Aws,
                scan_identity_name: "ai-security-scanner-case-123".into(),
                capabilities: vec![
                    ReadOnlyCapability::Inventory,
                    ReadOnlyCapability::SecurityPosture,
                ],
                expires_at: now + Duration::hours(1),
            },
            now,
        )
        .expect("plan");
        assert_eq!(plan.operations.len(), 3);
        assert_eq!(plan.template_sha256.len(), 64);
        assert!(plan.operations.iter().all(|operation| {
            matches!(
                operation.operation_id.as_str(),
                "create_dedicated_identity"
                    | "attach_read_only_policy"
                    | "verify_non_mutating_access"
            )
        }));
        let encoded = serde_json::to_string(&plan).expect("encoded plan");
        assert!(!encoded.contains("must-never-be-accepted"));
    }

    #[test]
    fn request_schema_rejects_unknown_secret_fields() {
        let input = r#"{
          "schema_version":"1.0.0",
          "case_id":"case-1",
          "provider":"aws",
          "scan_identity_name":"ai-security-scanner-case-1",
          "capabilities":["inventory"],
          "expires_at":"2099-01-01T00:00:00Z",
          "admin_password":"must-never-be-accepted"
        }"#;
        assert!(serde_json::from_str::<BootstrapRequest>(input).is_err());
    }

    #[test]
    fn plans_are_short_lived() {
        let now = Utc::now();
        let result = create_bootstrap_plan(
            BootstrapRequest {
                schema_version: "1.0.0".into(),
                case_id: "case-123".into(),
                provider: BootstrapProvider::Gcp,
                scan_identity_name: "ai-security-scanner-case-123".into(),
                capabilities: vec![ReadOnlyCapability::Inventory],
                expires_at: now + Duration::days(2),
            },
            now,
        );
        assert!(result.is_err());
    }
}
