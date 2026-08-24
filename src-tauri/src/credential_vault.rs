use crate::container_runtime::{CredentialSource, ScannerCredential, ScannerCredentialSet};
use crate::error::{AppError, AppResult};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::{BTreeSet, HashMap};
use std::fmt;
use std::sync::Mutex;
use zeroize::Zeroizing;

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum CredentialProvider {
    Aws,
    Azure,
    Gcp,
    Microsoft365,
    Kubernetes,
    ContainerRegistry,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum ReadOnlyCredentialSource {
    ProviderNative,
    VerifiedBootstrap,
}

pub enum SecretMaterial {
    AwsSession {
        access_key_id: Zeroizing<String>,
        secret_access_key: Zeroizing<String>,
        session_token: Zeroizing<String>,
    },
    BearerToken(Zeroizing<String>),
    KubernetesToken(Zeroizing<String>),
    RegistryToken {
        username: Zeroizing<String>,
        token: Zeroizing<String>,
    },
}

impl fmt::Debug for SecretMaterial {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("SecretMaterial")
            .field("kind", &self.kind())
            .field("value", &"[REDACTED]")
            .finish()
    }
}

impl SecretMaterial {
    fn kind(&self) -> &'static str {
        match self {
            Self::AwsSession { .. } => "aws_session",
            Self::BearerToken(_) => "bearer_token",
            Self::KubernetesToken(_) => "kubernetes_token",
            Self::RegistryToken { .. } => "registry_token",
        }
    }

    fn validate(&self) -> AppResult<()> {
        let non_empty = match self {
            Self::AwsSession {
                access_key_id,
                secret_access_key,
                session_token,
            } => {
                !access_key_id.is_empty()
                    && !secret_access_key.is_empty()
                    && !session_token.is_empty()
            }
            Self::BearerToken(token) | Self::KubernetesToken(token) => !token.is_empty(),
            Self::RegistryToken { username, token } => !username.is_empty() && !token.is_empty(),
        };
        if !non_empty {
            return Err(AppError::InvalidRequest(
                "read-only credential material is incomplete".into(),
            ));
        }
        Ok(())
    }
}

pub struct CredentialBundle {
    pub provider: CredentialProvider,
    pub source: ReadOnlyCredentialSource,
    pub provider_identity: String,
    pub issued_at: DateTime<Utc>,
    pub expires_at: DateTime<Utc>,
    pub verified_read_only: bool,
    material: SecretMaterial,
}

impl fmt::Debug for CredentialBundle {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("CredentialBundle")
            .field("provider", &self.provider)
            .field("source", &self.source)
            .field("provider_identity", &self.provider_identity)
            .field("issued_at", &self.issued_at)
            .field("expires_at", &self.expires_at)
            .field("verified_read_only", &self.verified_read_only)
            .field("material", &"[REDACTED]")
            .finish()
    }
}

impl CredentialBundle {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        provider: CredentialProvider,
        source: ReadOnlyCredentialSource,
        provider_identity: impl Into<String>,
        issued_at: DateTime<Utc>,
        expires_at: DateTime<Utc>,
        verified_read_only: bool,
        material: SecretMaterial,
    ) -> AppResult<Self> {
        let provider_identity = provider_identity.into();
        if provider_identity.trim().is_empty() || provider_identity.len() > 512 {
            return Err(AppError::InvalidRequest(
                "provider identity metadata is missing or too long".into(),
            ));
        }
        if expires_at <= issued_at || expires_at <= Utc::now() {
            return Err(AppError::NotAuthorized(
                "scan credential must be unexpired".into(),
            ));
        }
        if expires_at - issued_at > chrono::Duration::hours(24) {
            return Err(AppError::NotAuthorized(
                "scan credential lifetime cannot exceed 24 hours".into(),
            ));
        }
        if !verified_read_only {
            return Err(AppError::NotAuthorized(
                "credential capability cannot be issued before read-only verification".into(),
            ));
        }
        material.validate()?;
        Ok(Self {
            provider,
            source,
            provider_identity,
            issued_at,
            expires_at,
            verified_read_only,
            material,
        })
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct CapabilityBinding {
    pub case_id: String,
    pub run_id: String,
    pub connector_id: String,
    pub allowed_engine_ids: BTreeSet<String>,
    pub allowed_asset_ids: BTreeSet<String>,
    pub expires_at: DateTime<Utc>,
}

impl CapabilityBinding {
    fn validate(&self, credential_expiry: DateTime<Utc>) -> AppResult<()> {
        for (label, value) in [
            ("case", self.case_id.as_str()),
            ("run", self.run_id.as_str()),
            ("connector", self.connector_id.as_str()),
        ] {
            if value.is_empty()
                || value.len() > 128
                || !value.chars().all(|character| {
                    character.is_ascii_alphanumeric() || matches!(character, '-' | '_' | '.')
                })
            {
                return Err(AppError::InvalidRequest(format!(
                    "credential capability {label} identifier is invalid"
                )));
            }
        }
        if self.allowed_engine_ids.is_empty() || self.allowed_asset_ids.is_empty() {
            return Err(AppError::InvalidRequest(
                "credential capability must be bound to engines and assets".into(),
            ));
        }
        if self.expires_at > credential_expiry || self.expires_at <= Utc::now() {
            return Err(AppError::NotAuthorized(
                "credential capability expiry is outside the credential lifetime".into(),
            ));
        }
        Ok(())
    }
}

/// An in-memory bearer capability. It deliberately implements neither `Clone`
/// nor `Serialize`, so it cannot be persisted into case documents or copied freely.
pub struct CapabilityHandle(Zeroizing<[u8; 32]>);

impl fmt::Debug for CapabilityHandle {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("CapabilityHandle([REDACTED])")
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct CapabilitySummary {
    pub provider: CredentialProvider,
    pub source: ReadOnlyCredentialSource,
    pub provider_identity: String,
    pub binding: CapabilityBinding,
    pub used_by_engine_ids: BTreeSet<String>,
    pub revoked: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CredentialUseRequest<'a> {
    pub case_id: &'a str,
    pub run_id: &'a str,
    pub engine_id: &'a str,
    pub asset_ids: &'a BTreeSet<String>,
}

struct StoredCapability {
    credential: CredentialBundle,
    binding: CapabilityBinding,
    used_by_engine_ids: BTreeSet<String>,
}

#[derive(Default)]
pub struct CredentialVault {
    entries: Mutex<HashMap<[u8; 32], StoredCapability>>,
}

impl CredentialVault {
    pub fn issue(
        &self,
        credential: CredentialBundle,
        binding: CapabilityBinding,
    ) -> AppResult<(CapabilityHandle, CapabilitySummary)> {
        binding.validate(credential.expires_at)?;
        let mut token = Zeroizing::new([0_u8; 32]);
        getrandom::fill(token.as_mut())
            .map_err(|_| AppError::Internal("operating system random source failed".into()))?;
        let digest = capability_digest(token.as_ref());
        let summary = CapabilitySummary {
            provider: credential.provider,
            source: credential.source,
            provider_identity: credential.provider_identity.clone(),
            binding: binding.clone(),
            used_by_engine_ids: BTreeSet::new(),
            revoked: false,
        };
        let mut entries = self
            .entries
            .lock()
            .map_err(|_| AppError::Internal("credential vault lock was poisoned".into()))?;
        if entries
            .insert(
                digest,
                StoredCapability {
                    credential,
                    binding,
                    used_by_engine_ids: BTreeSet::new(),
                },
            )
            .is_some()
        {
            return Err(AppError::Internal(
                "random credential capability collision".into(),
            ));
        }
        Ok((CapabilityHandle(token), summary))
    }

    /// Runs a bounded callback while the credential remains inside the vault.
    /// Callers cannot retain or serialize `CredentialView`.
    pub fn with_credential<T>(
        &self,
        handle: &CapabilityHandle,
        request: CredentialUseRequest<'_>,
        operation: impl FnOnce(CredentialView<'_>) -> AppResult<T>,
    ) -> AppResult<T> {
        let digest = capability_digest(handle.0.as_ref());
        let mut entries = self
            .entries
            .lock()
            .map_err(|_| AppError::Internal("credential vault lock was poisoned".into()))?;
        let stored = entries.get_mut(&digest).ok_or_else(|| {
            AppError::NotAuthorized("credential capability is invalid or revoked".into())
        })?;
        authorize_use(stored, &request, Utc::now())?;
        let result = operation(CredentialView {
            provider: stored.credential.provider,
            source: stored.credential.source,
            expires_at: stored.credential.expires_at,
            material: &stored.credential.material,
        });
        if result.is_ok() {
            stored.used_by_engine_ids.insert(request.engine_id.into());
        }
        result
    }

    pub fn with_scanner_credentials<T>(
        &self,
        handle: &CapabilityHandle,
        request: CredentialUseRequest<'_>,
        operation: impl FnOnce(&ScannerCredentialSet) -> AppResult<T>,
    ) -> AppResult<T> {
        self.with_credential(handle, request, |view| {
            let credentials = view.scanner_credentials()?;
            operation(&credentials)
        })
    }

    pub fn revoke(&self, handle: CapabilityHandle) -> AppResult<CapabilitySummary> {
        let digest = capability_digest(handle.0.as_ref());
        let mut entries = self
            .entries
            .lock()
            .map_err(|_| AppError::Internal("credential vault lock was poisoned".into()))?;
        let stored = entries.remove(&digest).ok_or_else(|| {
            AppError::NotAuthorized("credential capability is invalid or already revoked".into())
        })?;
        Ok(summary_from_stored(stored, true))
    }

    pub fn purge_expired(&self, now: DateTime<Utc>) -> AppResult<usize> {
        let mut entries = self
            .entries
            .lock()
            .map_err(|_| AppError::Internal("credential vault lock was poisoned".into()))?;
        let before = entries.len();
        entries
            .retain(|_, entry| entry.credential.expires_at > now && entry.binding.expires_at > now);
        Ok(before - entries.len())
    }
}

pub struct CredentialView<'a> {
    pub provider: CredentialProvider,
    pub source: ReadOnlyCredentialSource,
    pub expires_at: DateTime<Utc>,
    material: &'a SecretMaterial,
}

impl fmt::Debug for CredentialView<'_> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("CredentialView")
            .field("provider", &self.provider)
            .field("source", &self.source)
            .field("expires_at", &self.expires_at)
            .field("material_kind", &self.material.kind())
            .field("material", &"[REDACTED]")
            .finish()
    }
}

impl CredentialView<'_> {
    pub fn material_kind(&self) -> &'static str {
        self.material.kind()
    }

    pub(crate) fn scanner_credentials(&self) -> AppResult<ScannerCredentialSet> {
        let source = match self.source {
            ReadOnlyCredentialSource::ProviderNative => CredentialSource::ExternalReadOnlyGrant,
            ReadOnlyCredentialSource::VerifiedBootstrap => CredentialSource::EphemeralScanRole,
        };
        let credential = |key: &str, value: Zeroizing<String>| {
            ScannerCredential::from_vault(key, value, self.expires_at, source)
        };
        let credentials = match self.material {
            SecretMaterial::AwsSession {
                access_key_id,
                secret_access_key,
                session_token,
            } => vec![
                credential("AWS_ACCESS_KEY_ID", access_key_id.clone())?,
                credential("AWS_SECRET_ACCESS_KEY", secret_access_key.clone())?,
                credential("AWS_SESSION_TOKEN", session_token.clone())?,
            ],
            SecretMaterial::BearerToken(token) => {
                let key = match self.provider {
                    CredentialProvider::Azure => "AZURE_ACCESS_TOKEN",
                    CredentialProvider::Gcp => "GOOGLE_OAUTH_ACCESS_TOKEN",
                    CredentialProvider::Microsoft365 => "MSGRAPH_ACCESS_TOKEN",
                    _ => {
                        return Err(AppError::InvalidRequest(
                            "bearer token provider does not have a supported adapter channel"
                                .into(),
                        ));
                    }
                };
                vec![credential(key, token.clone())?]
            }
            SecretMaterial::KubernetesToken(token) => {
                vec![credential("KUBERNETES_BEARER_TOKEN", token.clone())?]
            }
            SecretMaterial::RegistryToken { username, token } => vec![
                credential("REGISTRY_USERNAME", username.clone())?,
                credential("REGISTRY_TOKEN", token.clone())?,
            ],
        };
        ScannerCredentialSet::new(credentials)
    }
}

fn authorize_use(
    stored: &StoredCapability,
    request: &CredentialUseRequest<'_>,
    now: DateTime<Utc>,
) -> AppResult<()> {
    if now >= stored.credential.expires_at || now >= stored.binding.expires_at {
        return Err(AppError::NotAuthorized(
            "credential capability is expired".into(),
        ));
    }
    if request.case_id != stored.binding.case_id || request.run_id != stored.binding.run_id {
        return Err(AppError::NotAuthorized(
            "credential capability is bound to a different case or run".into(),
        ));
    }
    if !stored
        .binding
        .allowed_engine_ids
        .contains(request.engine_id)
    {
        return Err(AppError::NotAuthorized(
            "engine is outside the credential capability".into(),
        ));
    }
    if request.asset_ids.is_empty()
        || !request
            .asset_ids
            .iter()
            .all(|asset| stored.binding.allowed_asset_ids.contains(asset))
    {
        return Err(AppError::NotAuthorized(
            "asset set is outside the credential capability".into(),
        ));
    }
    Ok(())
}

fn capability_digest(token: &[u8]) -> [u8; 32] {
    Sha256::digest(token).into()
}

fn summary_from_stored(stored: StoredCapability, revoked: bool) -> CapabilitySummary {
    CapabilitySummary {
        provider: stored.credential.provider,
        source: stored.credential.source,
        provider_identity: stored.credential.provider_identity,
        binding: stored.binding,
        used_by_engine_ids: stored.used_by_engine_ids,
        revoked,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::Duration;

    fn credential() -> CredentialBundle {
        let now = Utc::now();
        CredentialBundle::new(
            CredentialProvider::Aws,
            ReadOnlyCredentialSource::VerifiedBootstrap,
            "arn:aws:iam::111122223333:role/ai-security-scanner-test",
            now,
            now + Duration::hours(1),
            true,
            SecretMaterial::AwsSession {
                access_key_id: Zeroizing::new("AKIAEXAMPLE".into()),
                secret_access_key: Zeroizing::new("secret-value".into()),
                session_token: Zeroizing::new("session-value".into()),
            },
        )
        .expect("credential")
    }

    fn binding() -> CapabilityBinding {
        CapabilityBinding {
            case_id: "case-1".into(),
            run_id: "run-1".into(),
            connector_id: "aws-1".into(),
            allowed_engine_ids: ["prowler".into()].into_iter().collect(),
            allowed_asset_ids: ["account-1".into()].into_iter().collect(),
            expires_at: Utc::now() + Duration::minutes(30),
        }
    }

    fn assets(id: &str) -> BTreeSet<String> {
        [id.to_owned()].into_iter().collect()
    }

    #[test]
    fn handle_and_debug_output_never_reveal_secret_material() {
        let vault = CredentialVault::default();
        let (handle, summary) = vault.issue(credential(), binding()).expect("issued");
        assert_eq!(format!("{handle:?}"), "CapabilityHandle([REDACTED])");
        assert!(!format!("{summary:?}").contains("secret-value"));
        let allowed_assets = assets("account-1");
        vault
            .with_credential(
                &handle,
                CredentialUseRequest {
                    case_id: "case-1",
                    run_id: "run-1",
                    engine_id: "prowler",
                    asset_ids: &allowed_assets,
                },
                |view| {
                    assert!(!format!("{view:?}").contains("secret-value"));
                    assert_eq!(view.material_kind(), "aws_session");
                    Ok(())
                },
            )
            .expect("authorized use");
        vault
            .with_scanner_credentials(
                &handle,
                CredentialUseRequest {
                    case_id: "case-1",
                    run_id: "run-1",
                    engine_id: "prowler",
                    asset_ids: &allowed_assets,
                },
                |credentials| {
                    let keys: BTreeSet<&str> = credentials.environment_keys().collect();
                    assert_eq!(
                        keys,
                        [
                            "AWS_ACCESS_KEY_ID",
                            "AWS_SECRET_ACCESS_KEY",
                            "AWS_SESSION_TOKEN"
                        ]
                        .into_iter()
                        .collect()
                    );
                    assert!(!format!("{credentials:?}").contains("secret-value"));
                    Ok(())
                },
            )
            .expect("vault-created scanner credentials");
    }

    #[test]
    fn capability_cannot_cross_case_engine_or_asset() {
        let vault = CredentialVault::default();
        let (handle, _) = vault.issue(credential(), binding()).expect("issued");
        let allowed_assets = assets("account-1");
        let wrong_assets = assets("account-2");
        for request in [
            CredentialUseRequest {
                case_id: "case-2",
                run_id: "run-1",
                engine_id: "prowler",
                asset_ids: &allowed_assets,
            },
            CredentialUseRequest {
                case_id: "case-1",
                run_id: "run-1",
                engine_id: "scoutsuite",
                asset_ids: &allowed_assets,
            },
            CredentialUseRequest {
                case_id: "case-1",
                run_id: "run-1",
                engine_id: "prowler",
                asset_ids: &wrong_assets,
            },
        ] {
            assert!(vault.with_credential(&handle, request, |_| Ok(())).is_err());
        }
    }

    #[test]
    fn unverified_or_long_lived_credentials_are_rejected() {
        let now = Utc::now();
        assert!(
            CredentialBundle::new(
                CredentialProvider::Azure,
                ReadOnlyCredentialSource::ProviderNative,
                "scanner-object-id",
                now,
                now + Duration::hours(1),
                false,
                SecretMaterial::BearerToken(Zeroizing::new("token".into())),
            )
            .is_err()
        );
        assert!(
            CredentialBundle::new(
                CredentialProvider::Azure,
                ReadOnlyCredentialSource::ProviderNative,
                "scanner-object-id",
                now,
                now + Duration::days(2),
                true,
                SecretMaterial::BearerToken(Zeroizing::new("token".into())),
            )
            .is_err()
        );
    }
}
