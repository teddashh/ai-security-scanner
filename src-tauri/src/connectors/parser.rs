//! Bounded parsing primitives shared by source-specific snapshot profiles.

mod cloud;
mod local;
mod provider_native;
mod public_sources;

use crate::discovery::{
    ConnectorDiscovery, DiscoveredAsset, DiscoveredRelation, DiscoveryAssetRef, DiscoveryError,
};
use crate::domain::{AssetIdentifier, AssetKind, RelationKind, SourceKind};
use chrono::{DateTime, Utc};
use serde_json::{Map, Value};
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet};

pub(crate) const MAX_RECORDS: usize = 10_000;
pub(crate) const MAX_LINE_BYTES: usize = 1024 * 1024;
const MAX_NOTICES: usize = 128;
const MAX_NAME_CHARS: usize = 512;
const MAX_ID_CHARS: usize = 2_048;
const MAX_METADATA_TEXT_CHARS: usize = 1_024;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum ParserProfile {
    CloudQuery,
    Steampipe,
    Prowler,
    ScubaGear,
    Maester,
    AwsOrganizationsListAccounts,
    AzureResourceManagerResources,
    GcpResourceManagerProjects,
    MicrosoftGraphDirectoryInventory,
    DnsResponse,
    CertificateTransparencyResponse,
    BillingExport,
    GitManifest,
    TerraformState,
    KubernetesManifest,
    ContainerRegistryManifest,
    FileSystemManifest,
    UserDeclaredManifest,
}

impl ParserProfile {
    pub(crate) fn from_id(value: &str) -> Option<Self> {
        Some(match value {
            "cloudquery" => Self::CloudQuery,
            "steampipe" => Self::Steampipe,
            "prowler" => Self::Prowler,
            "scubagear" => Self::ScubaGear,
            "maester" => Self::Maester,
            "aws-organizations-list-accounts" => Self::AwsOrganizationsListAccounts,
            "azure-resource-manager-resources" => Self::AzureResourceManagerResources,
            "gcp-resource-manager-projects" => Self::GcpResourceManagerProjects,
            "microsoft-graph-directory-inventory" => Self::MicrosoftGraphDirectoryInventory,
            "dns-response" => Self::DnsResponse,
            "certificate-transparency-response" => Self::CertificateTransparencyResponse,
            "billing-export" => Self::BillingExport,
            "git-manifest" => Self::GitManifest,
            "terraform-state" => Self::TerraformState,
            "kubernetes-manifest" => Self::KubernetesManifest,
            "container-registry-manifest" => Self::ContainerRegistryManifest,
            "filesystem-manifest" => Self::FileSystemManifest,
            "user-declared-manifest" => Self::UserDeclaredManifest,
            _ => return None,
        })
    }
}

pub(crate) fn parse_snapshot(
    profile: ParserProfile,
    source_kind: &SourceKind,
    bytes: &[u8],
    artifact_id: &str,
    observed_at: DateTime<Utc>,
) -> Result<ConnectorDiscovery, DiscoveryError> {
    let mut collector = Collector::new(artifact_id, profile);
    if profile == ParserProfile::AwsOrganizationsListAccounts {
        provider_native::parse_aws_organizations(bytes, source_kind, &mut collector)?;
        return Ok(collector.finish(observed_at));
    }
    let document = parse_json_or_json_lines(bytes)?;
    match profile {
        ParserProfile::CloudQuery
        | ParserProfile::Steampipe
        | ParserProfile::Prowler
        | ParserProfile::ScubaGear
        | ParserProfile::Maester => cloud::parse(profile, source_kind, &document, &mut collector)?,
        ParserProfile::AzureResourceManagerResources
        | ParserProfile::GcpResourceManagerProjects
        | ParserProfile::MicrosoftGraphDirectoryInventory => {
            provider_native::parse_json(profile, source_kind, &document, &mut collector)?
        }
        ParserProfile::AwsOrganizationsListAccounts => unreachable!("handled before JSON parsing"),
        ParserProfile::DnsResponse
        | ParserProfile::CertificateTransparencyResponse
        | ParserProfile::BillingExport => {
            public_sources::parse(profile, source_kind, &document, &mut collector)?
        }
        ParserProfile::GitManifest
        | ParserProfile::TerraformState
        | ParserProfile::KubernetesManifest
        | ParserProfile::ContainerRegistryManifest
        | ParserProfile::FileSystemManifest
        | ParserProfile::UserDeclaredManifest => {
            local::parse(profile, source_kind, &document, &mut collector)?
        }
    }
    Ok(collector.finish(observed_at))
}

fn parse_json_or_json_lines(bytes: &[u8]) -> Result<Value, DiscoveryError> {
    if bytes.is_empty() {
        return Err(DiscoveryError::Connector(
            "connector snapshot artifact is empty".into(),
        ));
    }
    if let Ok(value) = serde_json::from_slice::<Value>(bytes) {
        return Ok(value);
    }

    let text = std::str::from_utf8(bytes).map_err(|_| {
        DiscoveryError::Connector("connector snapshot is not valid UTF-8 JSON".into())
    })?;
    let mut records = Vec::new();
    for (index, line) in text.lines().enumerate() {
        let line = line.trim();
        if line.is_empty() {
            continue;
        }
        if line.len() > MAX_LINE_BYTES {
            return Err(DiscoveryError::Connector(format!(
                "connector snapshot JSON line {} exceeds the byte limit",
                index + 1
            )));
        }
        if records.len() >= MAX_RECORDS {
            return Err(DiscoveryError::Connector(format!(
                "connector snapshot exceeds the {} record limit",
                MAX_RECORDS
            )));
        }
        let value = serde_json::from_str::<Value>(line).map_err(|_| {
            DiscoveryError::Connector(format!(
                "connector snapshot is malformed at JSON line {}",
                index + 1
            ))
        })?;
        records.push(value);
    }
    if records.is_empty() {
        return Err(DiscoveryError::Connector(
            "connector snapshot is neither JSON nor non-empty JSON Lines".into(),
        ));
    }
    Ok(Value::Array(records))
}

pub(crate) struct Collector<'a> {
    artifact_id: &'a str,
    profile: ParserProfile,
    assets: Vec<DiscoveredAsset>,
    asset_keys: BTreeMap<String, String>,
    relations: Vec<DiscoveredRelation>,
    relation_keys: BTreeSet<String>,
    notices: Vec<String>,
    records_seen: usize,
}

pub(crate) struct AssetDraft<'a> {
    pub kind: AssetKind,
    pub name: &'a str,
    pub provider: Option<&'a str>,
    pub region: Option<&'a str>,
    pub namespace: &'a str,
    pub native_id: &'a str,
    pub additional_identifiers: Vec<AssetIdentifier>,
    pub internet_exposed: Option<bool>,
    pub contains_sensitive_data: Option<bool>,
    pub metadata: BTreeMap<String, Value>,
}

impl<'a> Collector<'a> {
    fn new(artifact_id: &'a str, profile: ParserProfile) -> Self {
        Self {
            artifact_id,
            profile,
            assets: Vec::new(),
            asset_keys: BTreeMap::new(),
            relations: Vec::new(),
            relation_keys: BTreeSet::new(),
            notices: Vec::new(),
            records_seen: 0,
        }
    }

    pub fn count_record(&mut self, pointer: &str) -> bool {
        if self.records_seen >= MAX_RECORDS {
            self.notice(format!(
                "record limit reached at {}; remaining preserved records were not parsed",
                safe_text(pointer, 160)
            ));
            return false;
        }
        self.records_seen += 1;
        true
    }

    pub fn asset(&mut self, draft: AssetDraft<'_>, pointer: &str) -> Option<String> {
        let name = safe_text(draft.name, MAX_NAME_CHARS);
        let namespace = normalize_namespace(draft.namespace)?;
        let native_id = safe_identifier(draft.native_id)?;
        if name.is_empty() {
            self.notice(format!(
                "ignored an asset with an empty display name at {}",
                safe_text(pointer, 160)
            ));
            return None;
        }
        let provider = draft.provider.and_then(normalize_optional);
        let region = draft.region.and_then(normalize_optional);
        let identity_material = format!(
            "{:?}\0{}\0{}\0{}\0{}",
            draft.kind,
            provider.as_deref().unwrap_or_default(),
            region.as_deref().unwrap_or_default(),
            namespace,
            native_id
        );
        if let Some(key) = self.asset_keys.get(&identity_material) {
            return Some(key.clone());
        }

        let observation_key = format!(
            "snapshot-{}",
            &hex::encode(Sha256::digest(identity_material.as_bytes()))[..24]
        );
        let mut metadata = BTreeMap::new();
        metadata.insert(
            "source_artifact_id".into(),
            Value::String(safe_text(self.artifact_id, MAX_METADATA_TEXT_CHARS)),
        );
        metadata.insert(
            "connector_profile".into(),
            Value::String(format!("{:?}", self.profile).to_ascii_lowercase()),
        );
        metadata.insert(
            "source_record_pointer".into(),
            Value::String(safe_text(pointer, MAX_METADATA_TEXT_CHARS)),
        );
        for (key, value) in draft.metadata {
            if safe_metadata_key(&key)
                && !is_secret_like_key(&key)
                && let Some(value) = safe_metadata_value(&value)
            {
                metadata.insert(key, value);
            }
        }

        let mut identifiers = Vec::new();
        for identifier in draft.additional_identifiers {
            let Some(additional_namespace) = normalize_namespace(&identifier.namespace) else {
                continue;
            };
            let Some(additional_value) = safe_identifier(&identifier.value) else {
                continue;
            };
            if !is_secret_like_key(&additional_namespace) {
                identifiers.push(AssetIdentifier {
                    namespace: additional_namespace,
                    value: additional_value,
                });
            }
        }

        self.assets.push(DiscoveredAsset {
            observation_key: observation_key.clone(),
            kind: draft.kind,
            name,
            provider,
            region,
            stable_identifier: AssetIdentifier {
                namespace,
                value: native_id,
            },
            additional_identifiers: identifiers,
            internet_exposed: draft.internet_exposed,
            contains_sensitive_data: draft.contains_sensitive_data,
            metadata,
        });
        self.asset_keys
            .insert(identity_material, observation_key.clone());
        Some(observation_key)
    }

    pub fn relation(&mut self, from: &str, to: &str, kind: RelationKind) {
        if from == to {
            return;
        }
        let material = format!("{from}\0{to}\0{kind:?}");
        if !self.relation_keys.insert(material) {
            return;
        }
        self.relations.push(DiscoveredRelation {
            from: DiscoveryAssetRef::Observation(from.into()),
            to: DiscoveryAssetRef::Observation(to.into()),
            kind,
            evidence_ids: vec![self.artifact_id.to_owned()],
        });
    }

    pub fn notice(&mut self, message: impl Into<String>) {
        if self.notices.len() < MAX_NOTICES {
            self.notices
                .push(safe_text(&message.into(), MAX_METADATA_TEXT_CHARS));
        }
    }

    fn finish(mut self, observed_at: DateTime<Utc>) -> ConnectorDiscovery {
        if self.assets.is_empty() {
            self.notice(
                "the preserved snapshot contained no supported asset records; the connected source is recorded as connected but empty",
            );
        }
        ConnectorDiscovery {
            observed_at,
            assets: self.assets,
            relations: self.relations,
            notices: self.notices,
        }
    }
}

pub(crate) fn object(value: &Value) -> Option<&Map<String, Value>> {
    value.as_object()
}

pub(crate) fn array_at<'a>(value: &'a Value, keys: &[&str]) -> Option<&'a Vec<Value>> {
    if let Some(array) = value.as_array() {
        return Some(array);
    }
    let object = value.as_object()?;
    keys.iter().find_map(|key| {
        get_ci(object, key)
            .and_then(Value::as_array)
            .or_else(|| get_path_ci(value, key).and_then(Value::as_array))
    })
}

pub(crate) fn get_ci<'a>(object: &'a Map<String, Value>, key: &str) -> Option<&'a Value> {
    object.get(key).or_else(|| {
        object
            .iter()
            .find(|(name, _)| name.eq_ignore_ascii_case(key))
            .map(|(_, value)| value)
    })
}

pub(crate) fn get_path_ci<'a>(value: &'a Value, path: &str) -> Option<&'a Value> {
    let mut current = value;
    for component in path.split('.') {
        current = get_ci(current.as_object()?, component)?;
    }
    Some(current)
}

pub(crate) fn string_at<'a>(value: &'a Value, paths: &[&str]) -> Option<&'a str> {
    paths
        .iter()
        .find_map(|path| get_path_ci(value, path).and_then(Value::as_str))
        .map(str::trim)
        .filter(|value| !value.is_empty())
}

pub(crate) fn bool_at(value: &Value, paths: &[&str]) -> Option<bool> {
    paths.iter().find_map(|path| {
        let value = get_path_ci(value, path)?;
        value.as_bool().or_else(|| {
            value
                .as_str()
                .and_then(|text| match text.trim().to_ascii_lowercase().as_str() {
                    "true" | "yes" | "public" | "internet" => Some(true),
                    "false" | "no" | "private" | "internal" => Some(false),
                    _ => None,
                })
        })
    })
}

pub(crate) fn metadata(pairs: &[(&str, Option<&str>)]) -> BTreeMap<String, Value> {
    pairs
        .iter()
        .filter_map(|(key, value)| {
            value.map(|value| ((*key).into(), Value::String(safe_text(value, 512))))
        })
        .collect()
}

pub(crate) fn safe_text(value: &str, limit: usize) -> String {
    value
        .chars()
        .filter(|character| !character.is_control())
        .take(limit)
        .collect::<String>()
        .trim()
        .to_owned()
}

fn safe_identifier(value: &str) -> Option<String> {
    let value = safe_text(value, MAX_ID_CHARS);
    (!value.is_empty()).then_some(value)
}

fn normalize_namespace(value: &str) -> Option<String> {
    let value = value.trim().to_ascii_lowercase();
    if value.is_empty()
        || value.len() > 128
        || value
            .chars()
            .any(|character| !(character.is_ascii_alphanumeric() || "._:-".contains(character)))
        || is_secret_like_key(&value)
    {
        None
    } else {
        Some(value)
    }
}

fn normalize_optional(value: &str) -> Option<String> {
    let value = safe_text(value, 256);
    (!value.is_empty()).then_some(value)
}

fn safe_metadata_key(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 128
        && !value.starts_with("ai_security_scanner.")
        && value
            .chars()
            .all(|character| character.is_ascii_alphanumeric() || "._-".contains(character))
}

fn safe_metadata_value(value: &Value) -> Option<Value> {
    match value {
        Value::Null | Value::Bool(_) | Value::Number(_) => Some(value.clone()),
        Value::String(value) => Some(Value::String(safe_text(value, MAX_METADATA_TEXT_CHARS))),
        // Never carry arbitrary nested scanner/provider data into the canonical
        // asset model. Raw bytes remain preserved as the evidence artifact.
        Value::Array(_) | Value::Object(_) => None,
    }
}

pub(crate) fn is_secret_like_key(key: &str) -> bool {
    let normalized = key.to_ascii_lowercase().replace(['-', '.', ' '], "_");
    let words = normalized.split('_').collect::<Vec<_>>();
    matches!(
        normalized.as_str(),
        "password"
            | "passwd"
            | "secret"
            | "private_key"
            | "api_key"
            | "access_key"
            | "access_key_id"
            | "token"
            | "access_token"
            | "id_token"
            | "oauth_token"
            | "auth_token"
            | "client_secret"
            | "session_token"
            | "refresh_token"
            | "authorization"
            | "cookie"
    ) || words.iter().any(|word| {
        matches!(
            *word,
            "password" | "passwd" | "secret" | "token" | "credential" | "credentials"
        )
    })
}

pub(crate) fn id(namespace: &str, value: &str) -> AssetIdentifier {
    AssetIdentifier {
        namespace: namespace.into(),
        value: value.into(),
    }
}

pub(crate) fn relation_kind(value: &str) -> Option<RelationKind> {
    Some(match value.trim().to_ascii_lowercase().as_str() {
        "contains" => RelationKind::Contains,
        "hosted_by" => RelationKind::HostedBy,
        "resolves_to" => RelationKind::ResolvesTo,
        "exposes" => RelationKind::Exposes,
        "uses_identity" => RelationKind::UsesIdentity,
        "built_from" => RelationKind::BuiltFrom,
        "deployed_to" => RelationKind::DeployedTo,
        "references" => RelationKind::References,
        "related" => RelationKind::Related,
        _ => return None,
    })
}
