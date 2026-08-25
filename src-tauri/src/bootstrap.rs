use crate::error::{AppError, AppResult};
use chrono::{DateTime, Duration, Utc};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::fs::{self, OpenOptions};
use std::io::Write;
use std::path::Path;

pub mod executor;

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
#[serde(deny_unknown_fields)]
pub struct BootstrapOperation {
    pub operation_id: String,
    pub description: String,
    pub mutates_provider: bool,
    pub provider_api_operations: Vec<String>,
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

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(tag = "provider", rename_all = "snake_case", deny_unknown_fields)]
pub enum CreatedBootstrapResources {
    Aws {
        stack_id: String,
        stack_name: String,
        role_arn: String,
        role_name: String,
    },
    Azure {
        tenant_id: String,
        subscription_id: String,
        application_object_id: String,
        application_client_id: String,
        service_principal_object_id: String,
        reader_role_assignment_id: String,
        security_reader_role_assignment_id: String,
        temporary_password_key_id: String,
    },
    Gcp {
        organization_id: String,
        project_id: String,
        service_account_email: String,
        service_account_unique_id: String,
        bound_role_names: Vec<String>,
        created_key_ids: Vec<String>,
    },
    Microsoft365 {
        tenant_id: String,
        application_object_id: String,
        application_client_id: String,
        service_principal_object_id: String,
        temporary_password_key_id: String,
        app_role_assignment_ids: Vec<String>,
        oauth_grant_ids: Vec<String>,
        directory_role_assignment_ids: Vec<String>,
    },
}

impl CreatedBootstrapResources {
    pub fn provider(&self) -> BootstrapProvider {
        match self {
            Self::Aws { .. } => BootstrapProvider::Aws,
            Self::Azure { .. } => BootstrapProvider::Azure,
            Self::Gcp { .. } => BootstrapProvider::Gcp,
            Self::Microsoft365 { .. } => BootstrapProvider::Microsoft365,
        }
    }
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum CleanupState {
    Pending,
    RetryableFailure,
    WaitingForCredentialExpiry,
    Completed,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum CleanupAttemptOutcome {
    Succeeded,
    ProviderResourceAlreadyAbsent,
    RetryableFailure,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct ExactCleanupItem {
    pub item_id: String,
    pub obligation: String,
    pub exact_resource_id: String,
    pub provider_api_method: String,
    pub provider_api_endpoint: String,
    pub required: bool,
    pub state: CleanupState,
    pub attempts: u32,
    pub last_attempt_at: Option<DateTime<Utc>>,
    pub last_provider_status: Option<String>,
    pub not_before: Option<DateTime<Utc>>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct CleanupLedger {
    pub schema_version: String,
    pub ledger_id: String,
    pub case_id: String,
    pub provider: BootstrapProvider,
    pub created_at: DateTime<Utc>,
    pub scanner_credential_expires_at: DateTime<Utc>,
    pub resources: CreatedBootstrapResources,
    pub items: Vec<ExactCleanupItem>,
    pub admin_material_destroyed_at: DateTime<Utc>,
    pub safety_notice: String,
}

impl CleanupLedger {
    pub fn unresolved_items(&self) -> impl Iterator<Item = &ExactCleanupItem> {
        self.items
            .iter()
            .filter(|item| item.required && item.state != CleanupState::Completed)
    }

    pub fn is_complete(&self) -> bool {
        self.unresolved_items().next().is_none()
    }
}

/// Builds a durable, non-secret cleanup ledger from exact IDs returned by the
/// provider. It does not accept resource-name patterns or discovery queries.
pub fn create_cleanup_ledger(
    case_id: &str,
    resources: CreatedBootstrapResources,
    scanner_credential_expires_at: DateTime<Utc>,
    admin_material_destroyed_at: DateTime<Utc>,
    now: DateTime<Utc>,
) -> AppResult<CleanupLedger> {
    if !valid_identifier(case_id, 128) {
        return Err(AppError::InvalidRequest(
            "cleanup ledger case identifier is invalid".into(),
        ));
    }
    if scanner_credential_expires_at <= now
        || scanner_credential_expires_at > now + Duration::hours(1)
        || admin_material_destroyed_at < now - Duration::minutes(5)
        || admin_material_destroyed_at > now + Duration::minutes(1)
    {
        return Err(AppError::InvalidRequest(
            "cleanup ledger requires a live, at-most-one-hour scanner credential and immediate admin destruction proof"
                .into(),
        ));
    }
    validate_created_resources(&resources)?;
    let provider = resources.provider();
    let items = cleanup_items(&resources, scanner_credential_expires_at)?;
    let digest_input = serde_json::to_vec(&(case_id, provider, now, &resources))
        .map_err(|_| AppError::Internal("cleanup ledger ID could not be derived".into()))?;
    Ok(CleanupLedger {
        schema_version: "1.0.0".into(),
        ledger_id: format!("cleanup-{}", &hex::encode(Sha256::digest(digest_input))[..24]),
        case_id: case_id.into(),
        provider,
        created_at: now,
        scanner_credential_expires_at,
        resources,
        items,
        admin_material_destroyed_at,
        safety_notice: "This ledger contains no credentials. Reauthenticate in the isolated broker to execute only these exact cleanup operations; never use a wildcard or broad delete. A password change alone does not satisfy session, key, grant, role, or service-principal cleanup.".into(),
    })
}

/// Records one exact cleanup result. Success and provider `not found` are both
/// idempotent completion; a retryable failure remains visible and can be tried
/// again without widening the target.
pub fn record_cleanup_attempt(
    ledger: &mut CleanupLedger,
    item_id: &str,
    outcome: CleanupAttemptOutcome,
    provider_status: &str,
    now: DateTime<Utc>,
) -> AppResult<bool> {
    if !safe_ledger_value(provider_status, 256) {
        return Err(AppError::InvalidRequest(
            "cleanup provider status is invalid".into(),
        ));
    }
    let item = ledger
        .items
        .iter_mut()
        .find(|item| item.item_id == item_id)
        .ok_or_else(|| AppError::InvalidRequest("cleanup item is not in this ledger".into()))?;
    if item.state == CleanupState::Completed {
        return Ok(false);
    }
    if item.state == CleanupState::WaitingForCredentialExpiry
        && item.not_before.is_some_and(|not_before| now < not_before)
    {
        return Err(AppError::NotAuthorized(
            "scanner session expiry obligation cannot complete before its exact expiry".into(),
        ));
    }
    item.attempts = item
        .attempts
        .checked_add(1)
        .ok_or_else(|| AppError::Internal("cleanup attempt counter overflowed".into()))?;
    item.last_attempt_at = Some(now);
    item.last_provider_status = Some(provider_status.into());
    item.state = match outcome {
        CleanupAttemptOutcome::Succeeded | CleanupAttemptOutcome::ProviderResourceAlreadyAbsent => {
            CleanupState::Completed
        }
        CleanupAttemptOutcome::RetryableFailure => CleanupState::RetryableFailure,
    };
    Ok(true)
}

/// Atomically writes the non-secret ledger with user-only permissions. Secret
/// material is structurally absent from the serializable ledger schema.
pub fn write_cleanup_ledger(path: &Path, ledger: &CleanupLedger) -> AppResult<()> {
    let parent = path.parent().ok_or_else(|| {
        AppError::InvalidRequest("cleanup ledger path has no parent directory".into())
    })?;
    fs::create_dir_all(parent)?;
    let parent = fs::canonicalize(parent)?;
    let file_name = path
        .file_name()
        .and_then(|name| name.to_str())
        .ok_or_else(|| AppError::InvalidRequest("cleanup ledger filename is invalid".into()))?;
    if file_name.is_empty() || file_name.contains('/') || file_name.contains('\\') {
        return Err(AppError::InvalidRequest(
            "cleanup ledger filename is invalid".into(),
        ));
    }
    let destination = parent.join(file_name);
    if fs::symlink_metadata(&destination).is_ok_and(|metadata| metadata.file_type().is_symlink()) {
        return Err(AppError::InvalidRequest(
            "cleanup ledger destination must not be a symlink".into(),
        ));
    }
    let temporary = parent.join(format!(".{file_name}.{}.tmp", std::process::id()));
    let mut options = OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let mut file = options.open(&temporary)?;
    let encoded = serde_json::to_vec_pretty(ledger)
        .map_err(|_| AppError::Internal("cleanup ledger could not be encoded".into()))?;
    file.write_all(&encoded)?;
    file.sync_all()?;
    drop(file);
    fs::rename(&temporary, &destination)?;
    Ok(())
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
                provider_api_operations: bootstrap_create_operations(request.provider),
            },
            BootstrapOperation {
                operation_id: "attach_read_only_policy".into(),
                description: "Attach only the pinned read-only permissions declared by this plan.".into(),
                mutates_provider: true,
                provider_api_operations: bootstrap_permission_operations(request.provider),
            },
            BootstrapOperation {
                operation_id: "verify_non_mutating_access".into(),
                description: "Verify the identity with inventory-only provider calls before issuing a scanner capability.".into(),
                mutates_provider: false,
                provider_api_operations: bootstrap_verify_operations(request.provider),
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
    if request.expires_at <= now || request.expires_at > now + Duration::hours(1) {
        return Err(AppError::InvalidRequest(
            "bootstrap plan and resulting scanner credential expiry must be within the next hour"
                .into(),
        ));
    }
    Ok(())
}

fn bootstrap_create_operations(provider: BootstrapProvider) -> Vec<String> {
    match provider {
        BootstrapProvider::Aws => vec![
            "cloudformation:CreateStack".into(),
            "cloudformation:DescribeStacks(exact-stack-id)".into(),
            "sts:AssumeRole(exact-created-role-arn,DurationSeconds<=3600)".into(),
        ],
        BootstrapProvider::Azure => vec![
            "graph:POST /applications".into(),
            "graph:POST /servicePrincipals".into(),
            "graph:POST /applications/{exact-id}/addPassword".into(),
            "graph:POST /applications/{exact-id}/removePassword immediately after token mint"
                .into(),
        ],
        BootstrapProvider::Gcp => vec![
            "iam.googleapis.com:projects.serviceAccounts.create(exact-project)".into(),
            "iamcredentials.googleapis.com:projects.serviceAccounts.generateAccessToken(lifetime<=3600s)".into(),
        ],
        BootstrapProvider::Microsoft365 => vec![
            "graph:POST /applications".into(),
            "graph:POST /servicePrincipals".into(),
            "graph:POST /applications/{exact-id}/addPassword".into(),
            "graph:POST /applications/{exact-id}/removePassword immediately after token mint"
                .into(),
        ],
    }
}

fn bootstrap_permission_operations(provider: BootstrapProvider) -> Vec<String> {
    match provider {
        BootstrapProvider::Aws => vec![
            "iam:AttachRolePolicy(SecurityAudit)".into(),
            "iam:AttachRolePolicy(ViewOnlyAccess)".into(),
            "iam:PutRolePolicy(ai-security-scanner-verification:SimulatePrincipalPolicy-only)"
                .into(),
        ],
        BootstrapProvider::Azure => vec![
            "authorization:roleAssignments/write(exact Reader role ID)".into(),
            "authorization:roleAssignments/write(exact Security Reader role ID)".into(),
        ],
        BootstrapProvider::Gcp => vec![
            "cloudresourcemanager.organizations.getIamPolicy(exact organization)".into(),
            "cloudresourcemanager.organizations.setIamPolicy(etag, exact member+role bindings)"
                .into(),
        ],
        BootstrapProvider::Microsoft365 => vec![
            "graph:POST /servicePrincipals/{exact-id}/appRoleAssignments(exact read app-role IDs)"
                .into(),
        ],
    }
}

fn bootstrap_verify_operations(provider: BootstrapProvider) -> Vec<String> {
    match provider {
        BootstrapProvider::Aws => vec![
            "sts:GetCallerIdentity".into(),
            "iam:SimulatePrincipalPolicy(required-read + prohibited-write actions)".into(),
        ],
        BootstrapProvider::Azure => vec![
            "graph:GET /servicePrincipals/{exact-id}".into(),
            "arm:GET /subscriptions/{exact-id}".into(),
            "authorization:roleAssignments/read(assignedTo exact principal)".into(),
        ],
        BootstrapProvider::Gcp => vec![
            "oauth2:GET /v1/userinfo".into(),
            "cloudresourcemanager:GET /v3/organizations/{exact-id}".into(),
            "cloudresourcemanager:organizations.testIamPermissions(discovery-read + organization-write denial)"
                .into(),
        ],
        BootstrapProvider::Microsoft365 => vec![
            "graph:GET /organization".into(),
            "graph:GET /auditLogs/directoryAudits?$top=1".into(),
            "graph:GET /policies/authorizationPolicy".into(),
            "graph:GET /roleManagement/directory/roleDefinitions?$top=1".into(),
        ],
    }
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

fn validate_created_resources(resources: &CreatedBootstrapResources) -> AppResult<()> {
    let values: Vec<&str> = match resources {
        CreatedBootstrapResources::Aws {
            stack_id,
            stack_name,
            role_arn,
            role_name,
        } => vec![stack_id, stack_name, role_arn, role_name],
        CreatedBootstrapResources::Azure {
            tenant_id,
            subscription_id,
            application_object_id,
            application_client_id,
            service_principal_object_id,
            reader_role_assignment_id,
            security_reader_role_assignment_id,
            temporary_password_key_id,
        } => vec![
            tenant_id,
            subscription_id,
            application_object_id,
            application_client_id,
            service_principal_object_id,
            reader_role_assignment_id,
            security_reader_role_assignment_id,
            temporary_password_key_id,
        ],
        CreatedBootstrapResources::Gcp {
            organization_id,
            project_id,
            service_account_email,
            service_account_unique_id,
            bound_role_names,
            created_key_ids,
        } => {
            let mut values: Vec<&str> = vec![
                organization_id.as_str(),
                project_id.as_str(),
                service_account_email.as_str(),
                service_account_unique_id.as_str(),
            ];
            values.extend(bound_role_names.iter().map(String::as_str));
            values.extend(created_key_ids.iter().map(String::as_str));
            values
        }
        CreatedBootstrapResources::Microsoft365 {
            tenant_id,
            application_object_id,
            application_client_id,
            service_principal_object_id,
            temporary_password_key_id,
            app_role_assignment_ids,
            oauth_grant_ids,
            directory_role_assignment_ids,
        } => {
            let mut values: Vec<&str> = vec![
                tenant_id.as_str(),
                application_object_id.as_str(),
                application_client_id.as_str(),
                service_principal_object_id.as_str(),
                temporary_password_key_id.as_str(),
            ];
            values.extend(app_role_assignment_ids.iter().map(String::as_str));
            values.extend(oauth_grant_ids.iter().map(String::as_str));
            values.extend(directory_role_assignment_ids.iter().map(String::as_str));
            values
        }
    };
    if values.is_empty() || values.iter().any(|value| !safe_ledger_value(value, 2048)) {
        return Err(AppError::InvalidRequest(
            "created bootstrap resource identifiers are incomplete or malformed".into(),
        ));
    }
    Ok(())
}

fn cleanup_items(
    resources: &CreatedBootstrapResources,
    scanner_expiry: DateTime<Utc>,
) -> AppResult<Vec<ExactCleanupItem>> {
    let mut specs: Vec<(String, String, String, String)> = Vec::new();
    match resources {
        CreatedBootstrapResources::Aws {
            stack_id,
            stack_name,
            role_arn,
            role_name,
        } => {
            let stack_region = stack_id.split(':').nth(3).ok_or_else(|| {
                AppError::InvalidRequest("AWS cleanup stack ARN has no region".into())
            })?;
            if stack_region.is_empty()
                || !stack_region
                    .bytes()
                    .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'-')
            {
                return Err(AppError::InvalidRequest(
                    "AWS cleanup stack ARN region is malformed".into(),
                ));
            }
            specs.push((
                "delete_stack".into(),
                stack_id.clone(),
                "POST".into(),
                format!(
                    "https://cloudformation.{stack_region}.amazonaws.com/?Action=DeleteStack&StackName={stack_name}&Version=2010-05-15"
                ),
            ));
            specs.push((
                "verify_role_absent".into(),
                role_arn.clone(),
                "POST".into(),
                format!(
                    "https://iam.amazonaws.com/?Action=GetRole&RoleName={role_name}&Version=2010-05-08"
                ),
            ));
        }
        CreatedBootstrapResources::Azure {
            tenant_id,
            subscription_id,
            application_object_id,
            service_principal_object_id,
            reader_role_assignment_id,
            security_reader_role_assignment_id,
            temporary_password_key_id,
            ..
        } => {
            for (label, assignment) in [
                ("delete_reader_role_assignment", reader_role_assignment_id),
                (
                    "delete_security_reader_role_assignment",
                    security_reader_role_assignment_id,
                ),
            ] {
                specs.push((
                    label.into(),
                    assignment.clone(),
                    "DELETE".into(),
                    format!(
                        "https://management.azure.com/subscriptions/{subscription_id}/providers/Microsoft.Authorization/roleAssignments/{assignment}?api-version=2022-04-01"
                    ),
                ));
            }
            specs.push((
                "remove_temporary_password".into(),
                temporary_password_key_id.clone(),
                "POST".into(),
                format!(
                    "https://graph.microsoft.com/v1.0/applications/{application_object_id}/removePassword"
                ),
            ));
            specs.push((
                "delete_service_principal".into(),
                service_principal_object_id.clone(),
                "DELETE".into(),
                format!(
                    "https://graph.microsoft.com/v1.0/servicePrincipals/{service_principal_object_id}"
                ),
            ));
            specs.push((
                "delete_application".into(),
                application_object_id.clone(),
                "DELETE".into(),
                format!(
                    "https://graph.microsoft.com/v1.0/applications/{application_object_id}?tenant={tenant_id}"
                ),
            ));
        }
        CreatedBootstrapResources::Gcp {
            organization_id,
            project_id,
            service_account_email,
            service_account_unique_id,
            bound_role_names,
            created_key_ids,
        } => {
            for role in bound_role_names {
                specs.push((
                    format!("remove_iam_binding_{}", short_hash(role)),
                    format!("organizations/{organization_id}:serviceAccount:{service_account_email}:{role}"),
                    "POST".into(),
                    format!(
                        "https://cloudresourcemanager.googleapis.com/v3/organizations/{organization_id}:setIamPolicy"
                    ),
                ));
            }
            for key_id in created_key_ids {
                specs.push((
                    format!("delete_service_account_key_{}", short_hash(key_id)),
                    key_id.clone(),
                    "DELETE".into(),
                    format!(
                        "https://iam.googleapis.com/v1/projects/{project_id}/serviceAccounts/{service_account_email}/keys/{key_id}"
                    ),
                ));
            }
            specs.push((
                "delete_service_account".into(),
                service_account_unique_id.clone(),
                "DELETE".into(),
                format!(
                    "https://iam.googleapis.com/v1/projects/{project_id}/serviceAccounts/{service_account_email}"
                ),
            ));
        }
        CreatedBootstrapResources::Microsoft365 {
            tenant_id,
            application_object_id,
            service_principal_object_id,
            temporary_password_key_id,
            app_role_assignment_ids,
            oauth_grant_ids,
            directory_role_assignment_ids,
            ..
        } => {
            for assignment in app_role_assignment_ids {
                specs.push((
                    format!("delete_app_role_assignment_{}", short_hash(assignment)),
                    assignment.clone(),
                    "DELETE".into(),
                    format!(
                        "https://graph.microsoft.com/v1.0/servicePrincipals/{service_principal_object_id}/appRoleAssignments/{assignment}"
                    ),
                ));
            }
            for grant in oauth_grant_ids {
                specs.push((
                    format!("delete_oauth_grant_{}", short_hash(grant)),
                    grant.clone(),
                    "DELETE".into(),
                    format!("https://graph.microsoft.com/v1.0/oauth2PermissionGrants/{grant}"),
                ));
            }
            for assignment in directory_role_assignment_ids {
                specs.push((
                    format!("delete_directory_role_assignment_{}", short_hash(assignment)),
                    assignment.clone(),
                    "DELETE".into(),
                    format!(
                        "https://graph.microsoft.com/v1.0/roleManagement/directory/roleAssignments/{assignment}"
                    ),
                ));
            }
            specs.extend([
                (
                    "remove_temporary_password".into(),
                    temporary_password_key_id.clone(),
                    "POST".into(),
                    format!(
                        "https://graph.microsoft.com/v1.0/applications/{application_object_id}/removePassword"
                    ),
                ),
                (
                    "delete_service_principal".into(),
                    service_principal_object_id.clone(),
                    "DELETE".into(),
                    format!(
                        "https://graph.microsoft.com/v1.0/servicePrincipals/{service_principal_object_id}"
                    ),
                ),
                (
                    "delete_application".into(),
                    application_object_id.clone(),
                    "DELETE".into(),
                    format!(
                        "https://graph.microsoft.com/v1.0/applications/{application_object_id}?tenant={tenant_id}"
                    ),
                ),
            ]);
        }
    }
    let mut items = specs
        .into_iter()
        .map(
            |(obligation, resource, method, endpoint)| ExactCleanupItem {
                item_id: format!(
                    "cleanup-item-{}",
                    short_hash(&format!("{obligation}:{resource}"))
                ),
                obligation,
                exact_resource_id: resource,
                provider_api_method: method,
                provider_api_endpoint: endpoint,
                required: true,
                state: CleanupState::Pending,
                attempts: 0,
                last_attempt_at: None,
                last_provider_status: None,
                not_before: None,
            },
        )
        .collect::<Vec<_>>();
    items.push(ExactCleanupItem {
        item_id: format!(
            "cleanup-item-{}",
            short_hash("wait-for-scanner-session-expiry")
        ),
        obligation: "confirm_all_short_lived_scanner_sessions_expired".into(),
        exact_resource_id: scanner_expiry.to_rfc3339(),
        provider_api_method: "LOCAL_TIME_BOUND".into(),
        provider_api_endpoint: "none".into(),
        required: true,
        state: CleanupState::WaitingForCredentialExpiry,
        attempts: 0,
        last_attempt_at: None,
        last_provider_status: None,
        not_before: Some(scanner_expiry),
    });
    let mut seen = std::collections::BTreeSet::new();
    if items.iter().any(|item| !seen.insert(item.item_id.clone())) {
        return Err(AppError::Internal(
            "cleanup ledger generated duplicate item identifiers".into(),
        ));
    }
    Ok(items)
}

/// Validates that every cleanup target is the exact deterministic target for
/// the provider-returned resource IDs. Mutable attempt state is intentionally
/// excluded from this comparison.
pub fn validate_cleanup_ledger(ledger: &CleanupLedger) -> AppResult<()> {
    if ledger.schema_version != "1.0.0"
        || ledger.provider != ledger.resources.provider()
        || ledger.scanner_credential_expires_at <= ledger.created_at
    {
        return Err(AppError::InvalidRequest(
            "cleanup ledger header is inconsistent".into(),
        ));
    }
    validate_created_resources(&ledger.resources)?;
    let expected = cleanup_items(&ledger.resources, ledger.scanner_credential_expires_at)?;
    if expected.len() != ledger.items.len() {
        return Err(AppError::NotAuthorized(
            "cleanup ledger target set was modified".into(),
        ));
    }
    for expected_item in expected {
        let actual = ledger
            .items
            .iter()
            .find(|item| item.item_id == expected_item.item_id)
            .ok_or_else(|| AppError::NotAuthorized("cleanup ledger target is missing".into()))?;
        if actual.obligation != expected_item.obligation
            || actual.exact_resource_id != expected_item.exact_resource_id
            || actual.provider_api_method != expected_item.provider_api_method
            || actual.provider_api_endpoint != expected_item.provider_api_endpoint
            || actual.required != expected_item.required
            || actual.not_before != expected_item.not_before
        {
            return Err(AppError::NotAuthorized(
                "cleanup ledger exact target was modified".into(),
            ));
        }
    }
    Ok(())
}

fn short_hash(value: &str) -> String {
    hex::encode(Sha256::digest(value.as_bytes()))[..16].into()
}

fn safe_ledger_value(value: &str, max: usize) -> bool {
    !value.trim().is_empty()
        && value.len() <= max
        && !value.chars().any(char::is_control)
        && !value.contains('\0')
}

pub fn ensure_no_secret_environment() -> AppResult<()> {
    const FORBIDDEN_MARKERS: &[&str] = &[
        "AWS_ACCESS_KEY_ID",
        "AWS_SECRET_ACCESS_KEY",
        "AWS_SESSION_TOKEN",
        "AZURE_ACCESS_TOKEN",
        "AZURE_CLIENT_SECRET",
        "GOOGLE_APPLICATION_CREDENTIALS",
        "GOOGLE_OAUTH_ACCESS_TOKEN",
        "ARM_CLIENT_SECRET",
        "MSGRAPH_ACCESS_TOKEN",
        "MSGRAPH_CLIENT_SECRET",
        "ADMIN_PASSWORD",
        "CLIENT_SECRET",
        "REFRESH_TOKEN",
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

    fn azure_resources() -> CreatedBootstrapResources {
        CreatedBootstrapResources::Azure {
            tenant_id: "11111111-1111-4111-8111-111111111111".into(),
            subscription_id: "22222222-2222-4222-8222-222222222222".into(),
            application_object_id: "33333333-3333-4333-8333-333333333333".into(),
            application_client_id: "44444444-4444-4444-8444-444444444444".into(),
            service_principal_object_id: "55555555-5555-4555-8555-555555555555".into(),
            reader_role_assignment_id: "66666666-6666-4666-8666-666666666666".into(),
            security_reader_role_assignment_id: "77777777-7777-4777-8777-777777777777".into(),
            temporary_password_key_id: "88888888-8888-4888-8888-888888888888".into(),
        }
    }

    #[test]
    fn cleanup_retry_and_not_found_completion_are_idempotent() {
        let now = Utc::now();
        let mut ledger = create_cleanup_ledger(
            "case-1",
            azure_resources(),
            now + Duration::minutes(30),
            now,
            now,
        )
        .unwrap();
        let item_id = ledger.items[0].item_id.clone();
        assert!(
            record_cleanup_attempt(
                &mut ledger,
                &item_id,
                CleanupAttemptOutcome::RetryableFailure,
                "provider_429",
                now + Duration::minutes(1),
            )
            .unwrap()
        );
        assert_eq!(ledger.items[0].state, CleanupState::RetryableFailure);
        assert!(
            record_cleanup_attempt(
                &mut ledger,
                &item_id,
                CleanupAttemptOutcome::ProviderResourceAlreadyAbsent,
                "provider_404",
                now + Duration::minutes(2),
            )
            .unwrap()
        );
        assert_eq!(ledger.items[0].state, CleanupState::Completed);
        assert!(
            !record_cleanup_attempt(
                &mut ledger,
                &item_id,
                CleanupAttemptOutcome::Succeeded,
                "provider_204",
                now + Duration::minutes(3),
            )
            .unwrap()
        );
        assert_eq!(ledger.items[0].attempts, 2);
    }

    #[test]
    fn cleanup_ledger_has_exact_ids_and_no_secret_schema() {
        let now = Utc::now();
        let ledger = create_cleanup_ledger(
            "case-1",
            azure_resources(),
            now + Duration::minutes(30),
            now,
            now,
        )
        .unwrap();
        let encoded = serde_json::to_string(&ledger).unwrap();
        assert!(encoded.contains("66666666-6666-4666-8666-666666666666"));
        assert!(!encoded.contains("access_token"));
        assert!(!encoded.contains("client_secret"));
        assert!(
            ledger
                .items
                .iter()
                .filter(|item| item.provider_api_method == "DELETE")
                .all(|item| item.provider_api_endpoint.contains(&item.exact_resource_id))
        );
    }

    #[test]
    fn broker_request_cannot_deserialize_admin_or_scanner_secrets() {
        let request = r#"{
          "schema_version":"1.0.0",
          "case_id":"case-1",
          "provider":"gcp",
          "scan_identity_name":"ai-security-scanner-case-1",
          "capabilities":["inventory"],
          "expires_at":"2099-01-01T00:00:00Z",
          "access_token":"must-never-enter-the-broker-protocol"
        }"#;
        assert!(serde_json::from_str::<BootstrapRequest>(request).is_err());
    }
}
