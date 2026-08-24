//! Source-grounded asset discovery and non-destructive reconciliation.
//!
//! Connectors return observations, not authorization decisions. This module
//! stamps every result with the source and connector that produced it, then
//! reconciles stable identities into a case without deleting observations
//! that a later discovery pass did not return.

use crate::domain::{
    AssessmentCase, Asset, AssetIdentifier, AssetKind, AssetRelation, DataSource, Id, RelationKind,
    SourceConnectionStatus, SourceKind,
};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value, json};
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet};
use thiserror::Error;

const INTERNAL_METADATA_PREFIX: &str = "ai_security_scanner.";
const STABLE_KEY_METADATA: &str = "ai_security_scanner.stable_key";
const CONNECTOR_ID_METADATA: &str = "ai_security_scanner.last_connector_id";
const CONNECTOR_VERSION_METADATA: &str = "ai_security_scanner.last_connector_version";
const LAST_OBSERVED_METADATA: &str = "ai_security_scanner.last_discovered_at";
const SOURCE_OBSERVATIONS_METADATA: &str = "ai_security_scanner.source_observations";
const OBSERVED_VALUES_METADATA: &str = "ai_security_scanner.observed_values";

/// A connector-owned observation before the core stamps source attribution.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConnectorDiscovery {
    pub observed_at: DateTime<Utc>,
    #[serde(default)]
    pub assets: Vec<DiscoveredAsset>,
    #[serde(default)]
    pub relations: Vec<DiscoveredRelation>,
    #[serde(default)]
    pub notices: Vec<String>,
}

/// A validated connector result with immutable source attribution.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DiscoveryBatch {
    pub source_id: Id,
    pub source_kind: SourceKind,
    pub connector_id: String,
    pub connector_version: String,
    pub observed_at: DateTime<Utc>,
    pub assets: Vec<DiscoveredAsset>,
    pub relations: Vec<DiscoveredRelation>,
    pub notices: Vec<String>,
}

/// A candidate asset returned by a source connector.
///
/// `stable_identifier` must be provider-native and immutable for the asset's
/// lifetime. Display names, tags, and ephemeral IP addresses should be placed
/// in `additional_identifiers` or `metadata`, never in this field.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DiscoveredAsset {
    /// Batch-local key used by relation observations.
    pub observation_key: String,
    pub kind: AssetKind,
    pub name: String,
    pub provider: Option<String>,
    pub region: Option<String>,
    pub stable_identifier: AssetIdentifier,
    #[serde(default)]
    pub additional_identifiers: Vec<AssetIdentifier>,
    pub internet_exposed: Option<bool>,
    pub contains_sensitive_data: Option<bool>,
    #[serde(default)]
    pub metadata: BTreeMap<String, Value>,
}

/// A relation endpoint can be another observation in the same batch or an
/// already-reconciled asset in the case.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "reference_type", content = "value", rename_all = "snake_case")]
pub enum DiscoveryAssetRef {
    Observation(String),
    ExistingAsset(Id),
}

/// A source-grounded relation observation.
///
/// Evidence IDs are mandatory. They should refer to preserved discovery
/// artifacts so the relation remains attributable after the batch is applied.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DiscoveredRelation {
    pub from: DiscoveryAssetRef,
    pub to: DiscoveryAssetRef,
    pub kind: RelationKind,
    pub evidence_ids: Vec<Id>,
}

/// Synchronous connector boundary. Provider SDK implementations may perform
/// their asynchronous work outside this trait or provide a small blocking
/// facade; the reconciliation core itself remains deterministic and testable.
pub trait DiscoveryConnector: Send + Sync {
    fn connector_id(&self) -> &str;
    fn connector_version(&self) -> &str;
    fn source_kind(&self) -> SourceKind;
    fn discover(&self, source: &DataSource) -> Result<ConnectorDiscovery, DiscoveryError>;
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ReconciliationReport {
    pub source_id: Id,
    pub observed_at: DateTime<Utc>,
    pub created_asset_ids: Vec<Id>,
    pub updated_asset_ids: Vec<Id>,
    pub seen_asset_ids: Vec<Id>,
    pub retained_unseen_asset_ids: Vec<Id>,
    pub created_relation_ids: Vec<Id>,
    pub updated_relation_ids: Vec<Id>,
    pub notices: Vec<String>,
}

#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum DiscoveryError {
    #[error("discovery source not found: {0}")]
    SourceNotFound(Id),
    #[error("source {source_id} is not connected (status: {status})")]
    SourceNotConnected { source_id: Id, status: String },
    #[error("source {0} is not configured for read-only discovery")]
    SourceNotReadOnly(Id),
    #[error("connector source kind does not match source {source_id}")]
    SourceKindMismatch { source_id: Id },
    #[error("discovery batch attribution does not match source {0}")]
    AttributionMismatch(Id),
    #[error("discovery batch for source {source_id} predates its latest accepted observation")]
    StaleBatch { source_id: Id },
    #[error("connector identity and version must be non-empty")]
    MissingConnectorIdentity,
    #[error("invalid discovery observation: {0}")]
    InvalidObservation(String),
    #[error("duplicate discovery observation key: {0}")]
    DuplicateObservationKey(String),
    #[error("duplicate stable asset identity in discovery batch: {0}")]
    DuplicateStableIdentity(String),
    #[error("asset identity {stable_key} matches more than one existing asset")]
    AmbiguousIdentity { stable_key: String },
    #[error("relation refers to an unknown asset: {0}")]
    UnknownRelationEndpoint(String),
    #[error("relation observations require at least one evidence identifier")]
    RelationEvidenceRequired,
    #[error("connector failed: {0}")]
    Connector(String),
}

/// Executes a connector only for a matching, connected, read-only source and
/// stamps the returned observations with trustworthy attribution.
pub fn run_connector(
    connector: &dyn DiscoveryConnector,
    source: &DataSource,
) -> Result<DiscoveryBatch, DiscoveryError> {
    validate_source(source)?;
    if connector.source_kind() != source.kind {
        return Err(DiscoveryError::SourceKindMismatch {
            source_id: source.id.clone(),
        });
    }
    if connector.connector_id().trim().is_empty() || connector.connector_version().trim().is_empty()
    {
        return Err(DiscoveryError::MissingConnectorIdentity);
    }

    let result = connector.discover(source)?;
    Ok(DiscoveryBatch {
        source_id: source.id.clone(),
        source_kind: source.kind.clone(),
        connector_id: connector.connector_id().trim().to_owned(),
        connector_version: connector.connector_version().trim().to_owned(),
        observed_at: result.observed_at,
        assets: result.assets,
        relations: result.relations,
        notices: result.notices,
    })
}

/// Runs a connector against a source in `case` and atomically reconciles its
/// observations. The case is left untouched if validation or reconciliation
/// fails.
pub fn discover_and_reconcile(
    connector: &dyn DiscoveryConnector,
    case: &mut AssessmentCase,
    source_id: &str,
) -> Result<ReconciliationReport, DiscoveryError> {
    let source = case
        .data_sources
        .iter()
        .find(|source| source.id == source_id)
        .cloned()
        .ok_or_else(|| DiscoveryError::SourceNotFound(source_id.to_owned()))?;
    let batch = run_connector(connector, &source)?;
    reconcile_discovery(case, &batch)
}

/// Applies a source-attributed discovery batch without implicitly authorizing
/// new candidates and without deleting assets or relations absent from it.
pub fn reconcile_discovery(
    case: &mut AssessmentCase,
    batch: &DiscoveryBatch,
) -> Result<ReconciliationReport, DiscoveryError> {
    validate_batch(case, batch)?;

    // Work on a clone so an error can never leave a partially-mutated case.
    let mut next = case.clone();
    let previously_attributed: BTreeSet<Id> = next
        .assets
        .iter()
        .filter(|asset| asset.discovered_from.contains(&batch.source_id))
        .map(|asset| asset.id.clone())
        .collect();

    let mut created_asset_ids = Vec::new();
    let mut updated_asset_ids = Vec::new();
    let mut seen_asset_ids = Vec::new();
    let mut observation_asset_ids = BTreeMap::<String, Id>::new();

    for observation in &batch.assets {
        let stable_key = stable_asset_key(observation)?;
        let matching_indices = matching_asset_indices(&next.assets, observation, &stable_key);
        if matching_indices.len() > 1 {
            return Err(DiscoveryError::AmbiguousIdentity { stable_key });
        }

        let asset_id = if let Some(index) = matching_indices.first().copied() {
            let asset = &mut next.assets[index];
            merge_asset(asset, observation, batch, &stable_key);
            updated_asset_ids.push(asset.id.clone());
            asset.id.clone()
        } else {
            let id = deterministic_id("asset", &stable_key);
            if next.assets.iter().any(|asset| asset.id == id) {
                return Err(DiscoveryError::AmbiguousIdentity { stable_key });
            }
            let asset = new_candidate_asset(id.clone(), observation, batch, &stable_key);
            next.assets.push(asset);
            created_asset_ids.push(id.clone());
            id
        };

        observation_asset_ids.insert(
            observation.observation_key.trim().to_owned(),
            asset_id.clone(),
        );
        seen_asset_ids.push(asset_id);
    }

    let mut created_relation_ids = Vec::new();
    let mut updated_relation_ids = Vec::new();
    for relation in &batch.relations {
        let from_asset_id = resolve_endpoint(&next, &observation_asset_ids, &relation.from)?;
        let to_asset_id = resolve_endpoint(&next, &observation_asset_ids, &relation.to)?;
        if from_asset_id == to_asset_id {
            return Err(DiscoveryError::InvalidObservation(
                "self-referential asset relation".into(),
            ));
        }

        if let Some(existing) = next.asset_relations.iter_mut().find(|existing| {
            existing.from_asset_id == from_asset_id
                && existing.to_asset_id == to_asset_id
                && existing.kind == relation.kind
        }) {
            merge_unique(&mut existing.evidence_ids, &relation.evidence_ids);
            updated_relation_ids.push(existing.id.clone());
        } else {
            let relation_key = format!(
                "{}\u{0}{}\u{0}{}",
                from_asset_id,
                to_asset_id,
                enum_key(&relation.kind)
            );
            let id = deterministic_id("relation", &relation_key);
            next.asset_relations.push(AssetRelation {
                id: id.clone(),
                from_asset_id,
                to_asset_id,
                kind: relation.kind.clone(),
                evidence_ids: unique_values(&relation.evidence_ids),
            });
            created_relation_ids.push(id);
        }
    }

    let seen: BTreeSet<&Id> = seen_asset_ids.iter().collect();
    let retained_unseen_asset_ids = previously_attributed
        .into_iter()
        .filter(|id| !seen.contains(id))
        .collect::<Vec<_>>();

    if let Some(source) = next
        .data_sources
        .iter_mut()
        .find(|source| source.id == batch.source_id)
    {
        source.last_discovered_at = Some(batch.observed_at);
    }
    if batch.observed_at > next.updated_at {
        next.updated_at = batch.observed_at;
    }

    let report = ReconciliationReport {
        source_id: batch.source_id.clone(),
        observed_at: batch.observed_at,
        created_asset_ids,
        updated_asset_ids,
        seen_asset_ids,
        retained_unseen_asset_ids,
        created_relation_ids,
        updated_relation_ids,
        notices: batch.notices.clone(),
    };
    *case = next;
    Ok(report)
}

/// Stable key derived only from provider-native identity coordinates. It is
/// safe to display for diagnostics but is not itself proof of ownership.
pub fn stable_asset_key(asset: &DiscoveredAsset) -> Result<String, DiscoveryError> {
    let namespace = normalize_namespace(&asset.stable_identifier.namespace)?;
    let value = normalize_identifier_value(&namespace, &asset.stable_identifier.value)?;
    let provider = normalize_optional(&asset.provider);
    let region = normalize_optional(&asset.region);
    let material = format!(
        "asset-identity/v1\u{0}{}\u{0}{}\u{0}{}\u{0}{}\u{0}{}",
        enum_key(&asset.kind),
        provider.as_deref().unwrap_or(""),
        region.as_deref().unwrap_or(""),
        namespace,
        value
    );
    Ok(format!("asset/v1/{}", hex_sha256(&material)))
}

fn validate_source(source: &DataSource) -> Result<(), DiscoveryError> {
    if source.status != SourceConnectionStatus::Connected {
        return Err(DiscoveryError::SourceNotConnected {
            source_id: source.id.clone(),
            status: enum_key(&source.status),
        });
    }
    if !source.read_only {
        return Err(DiscoveryError::SourceNotReadOnly(source.id.clone()));
    }
    Ok(())
}

fn validate_batch(case: &AssessmentCase, batch: &DiscoveryBatch) -> Result<(), DiscoveryError> {
    let source = case
        .data_sources
        .iter()
        .find(|source| source.id == batch.source_id)
        .ok_or_else(|| DiscoveryError::SourceNotFound(batch.source_id.clone()))?;
    validate_source(source)?;
    if source.kind != batch.source_kind {
        return Err(DiscoveryError::AttributionMismatch(batch.source_id.clone()));
    }
    if source
        .last_discovered_at
        .is_some_and(|last_discovered_at| batch.observed_at < last_discovered_at)
    {
        return Err(DiscoveryError::StaleBatch {
            source_id: batch.source_id.clone(),
        });
    }
    if batch.connector_id.trim().is_empty() || batch.connector_version.trim().is_empty() {
        return Err(DiscoveryError::MissingConnectorIdentity);
    }

    let mut observation_keys = BTreeSet::new();
    let mut stable_keys = BTreeSet::new();
    for asset in &batch.assets {
        let observation_key = asset.observation_key.trim();
        if observation_key.is_empty() {
            return Err(DiscoveryError::InvalidObservation(
                "asset observation key is empty".into(),
            ));
        }
        if !observation_keys.insert(observation_key.to_owned()) {
            return Err(DiscoveryError::DuplicateObservationKey(
                observation_key.to_owned(),
            ));
        }
        if asset.name.trim().is_empty() {
            return Err(DiscoveryError::InvalidObservation(format!(
                "asset {observation_key} has an empty display name"
            )));
        }
        if asset
            .metadata
            .keys()
            .any(|key| key.starts_with(INTERNAL_METADATA_PREFIX))
        {
            return Err(DiscoveryError::InvalidObservation(format!(
                "asset {observation_key} attempts to set reserved metadata"
            )));
        }
        let stable_key = stable_asset_key(asset)?;
        if !stable_keys.insert(stable_key.clone()) {
            return Err(DiscoveryError::DuplicateStableIdentity(stable_key));
        }
        for identifier in &asset.additional_identifiers {
            normalize_namespace(&identifier.namespace)?;
            if identifier.value.trim().is_empty() {
                return Err(DiscoveryError::InvalidObservation(format!(
                    "asset {observation_key} has an empty additional identifier"
                )));
            }
        }
    }

    for relation in &batch.relations {
        if relation.evidence_ids.is_empty()
            || relation.evidence_ids.iter().any(|id| id.trim().is_empty())
        {
            return Err(DiscoveryError::RelationEvidenceRequired);
        }
        validate_endpoint(case, &observation_keys, &relation.from)?;
        validate_endpoint(case, &observation_keys, &relation.to)?;
    }
    Ok(())
}

fn validate_endpoint(
    case: &AssessmentCase,
    observation_keys: &BTreeSet<String>,
    endpoint: &DiscoveryAssetRef,
) -> Result<(), DiscoveryError> {
    match endpoint {
        DiscoveryAssetRef::Observation(key) if observation_keys.contains(key.trim()) => Ok(()),
        DiscoveryAssetRef::ExistingAsset(id) if case.assets.iter().any(|asset| &asset.id == id) => {
            Ok(())
        }
        DiscoveryAssetRef::Observation(key) => {
            Err(DiscoveryError::UnknownRelationEndpoint(key.clone()))
        }
        DiscoveryAssetRef::ExistingAsset(id) => {
            Err(DiscoveryError::UnknownRelationEndpoint(id.clone()))
        }
    }
}

fn matching_asset_indices(
    assets: &[Asset],
    observation: &DiscoveredAsset,
    stable_key: &str,
) -> Vec<usize> {
    let primary = normalized_identifier(&observation.stable_identifier).ok();
    assets
        .iter()
        .enumerate()
        .filter_map(|(index, asset)| {
            let metadata_match = asset
                .metadata
                .get(STABLE_KEY_METADATA)
                .and_then(Value::as_str)
                == Some(stable_key);
            let primary_match = primary.as_ref().is_some_and(|primary| {
                asset.kind == observation.kind
                    && normalize_optional(&asset.provider)
                        == normalize_optional(&observation.provider)
                    && normalize_optional(&asset.region) == normalize_optional(&observation.region)
                    && asset
                        .identifiers
                        .iter()
                        .filter_map(|identifier| normalized_identifier(identifier).ok())
                        .any(|existing| &existing == primary)
            });
            (metadata_match || primary_match).then_some(index)
        })
        .collect()
}

fn new_candidate_asset(
    id: Id,
    observation: &DiscoveredAsset,
    batch: &DiscoveryBatch,
    stable_key: &str,
) -> Asset {
    let mut metadata = observation.metadata.clone();
    stamp_internal_metadata(&mut metadata, batch, stable_key);
    let mut identifiers = vec![observation.stable_identifier.clone()];
    merge_identifiers(&mut identifiers, &observation.additional_identifiers);
    Asset {
        id,
        kind: observation.kind.clone(),
        name: observation.name.trim().to_owned(),
        provider: trimmed_optional(&observation.provider),
        region: trimmed_optional(&observation.region),
        identifiers,
        discovered_from: vec![batch.source_id.clone()],
        candidate: true,
        owner_confirmed: false,
        internet_exposed: observation.internet_exposed,
        contains_sensitive_data: observation.contains_sensitive_data,
        metadata,
    }
}

fn merge_asset(
    asset: &mut Asset,
    observation: &DiscoveredAsset,
    batch: &DiscoveryBatch,
    stable_key: &str,
) {
    merge_unique(
        &mut asset.discovered_from,
        std::slice::from_ref(&batch.source_id),
    );
    merge_identifiers(
        &mut asset.identifiers,
        std::slice::from_ref(&observation.stable_identifier),
    );
    merge_identifiers(&mut asset.identifiers, &observation.additional_identifiers);

    if asset.name.trim().is_empty() {
        asset.name = observation.name.trim().to_owned();
    } else if asset.name != observation.name.trim() {
        record_observed_value(
            &mut asset.metadata,
            "display_name",
            Value::String(asset.name.clone()),
            Value::String(observation.name.trim().to_owned()),
        );
    }
    merge_optional_field(
        &mut asset.provider,
        &observation.provider,
        &mut asset.metadata,
        "provider",
    );
    merge_optional_field(
        &mut asset.region,
        &observation.region,
        &mut asset.metadata,
        "region",
    );
    record_bool_conflict(
        &mut asset.metadata,
        "internet_exposed",
        asset.internet_exposed,
        observation.internet_exposed,
    );
    record_bool_conflict(
        &mut asset.metadata,
        "contains_sensitive_data",
        asset.contains_sensitive_data,
        observation.contains_sensitive_data,
    );
    asset.internet_exposed =
        conservative_bool(asset.internet_exposed, observation.internet_exposed);
    asset.contains_sensitive_data = conservative_bool(
        asset.contains_sensitive_data,
        observation.contains_sensitive_data,
    );
    for (key, incoming) in &observation.metadata {
        match asset.metadata.get(key).cloned() {
            None => {
                asset.metadata.insert(key.clone(), incoming.clone());
            }
            Some(existing) if existing != *incoming => {
                record_observed_value(&mut asset.metadata, key, existing, incoming.clone())
            }
            Some(_) => {}
        }
    }
    stamp_internal_metadata(&mut asset.metadata, batch, stable_key);

    // Crucially, discovery never changes candidate/owner-confirmed state. A
    // previously approved asset stays approved; a new one starts unapproved.
}

fn stamp_internal_metadata(
    metadata: &mut BTreeMap<String, Value>,
    batch: &DiscoveryBatch,
    stable_key: &str,
) {
    metadata.insert(
        STABLE_KEY_METADATA.into(),
        Value::String(stable_key.to_owned()),
    );
    metadata.insert(
        CONNECTOR_ID_METADATA.into(),
        Value::String(batch.connector_id.clone()),
    );
    metadata.insert(
        CONNECTOR_VERSION_METADATA.into(),
        Value::String(batch.connector_version.clone()),
    );
    metadata.insert(
        LAST_OBSERVED_METADATA.into(),
        Value::String(batch.observed_at.to_rfc3339()),
    );
    let source_observations = metadata
        .entry(SOURCE_OBSERVATIONS_METADATA.into())
        .or_insert_with(|| Value::Object(Map::new()));
    if !source_observations.is_object() {
        *source_observations = Value::Object(Map::new());
    }
    source_observations
        .as_object_mut()
        .expect("object was just created")
        .insert(
            batch.source_id.clone(),
            Value::String(batch.observed_at.to_rfc3339()),
        );
}

fn resolve_endpoint(
    case: &AssessmentCase,
    observation_asset_ids: &BTreeMap<String, Id>,
    endpoint: &DiscoveryAssetRef,
) -> Result<Id, DiscoveryError> {
    match endpoint {
        DiscoveryAssetRef::Observation(key) => observation_asset_ids
            .get(key.trim())
            .cloned()
            .ok_or_else(|| DiscoveryError::UnknownRelationEndpoint(key.clone())),
        DiscoveryAssetRef::ExistingAsset(id) if case.assets.iter().any(|asset| &asset.id == id) => {
            Ok(id.clone())
        }
        DiscoveryAssetRef::ExistingAsset(id) => {
            Err(DiscoveryError::UnknownRelationEndpoint(id.clone()))
        }
    }
}

fn merge_identifiers(target: &mut Vec<AssetIdentifier>, incoming: &[AssetIdentifier]) {
    let mut known = target
        .iter()
        .filter_map(|identifier| normalized_identifier(identifier).ok())
        .collect::<BTreeSet<_>>();
    for identifier in incoming {
        if let Ok(normalized) = normalized_identifier(identifier)
            && known.insert(normalized)
        {
            target.push(identifier.clone());
        }
    }
}

fn normalized_identifier(identifier: &AssetIdentifier) -> Result<(String, String), DiscoveryError> {
    let namespace = normalize_namespace(&identifier.namespace)?;
    let value = normalize_identifier_value(&namespace, &identifier.value)?;
    Ok((namespace, value))
}

fn normalize_namespace(namespace: &str) -> Result<String, DiscoveryError> {
    let namespace = namespace.trim().to_ascii_lowercase();
    if namespace.is_empty() {
        return Err(DiscoveryError::InvalidObservation(
            "identifier namespace is empty".into(),
        ));
    }
    Ok(namespace)
}

fn normalize_identifier_value(namespace: &str, value: &str) -> Result<String, DiscoveryError> {
    let value = value.trim();
    if value.is_empty() {
        return Err(DiscoveryError::InvalidObservation(
            "stable identifier value is empty".into(),
        ));
    }
    let case_insensitive = matches!(
        namespace,
        "dns" | "domain" | "hostname" | "fqdn" | "email" | "azure_tenant"
    );
    Ok(if case_insensitive {
        value.to_ascii_lowercase()
    } else {
        value.to_owned()
    })
}

fn merge_optional_field(
    current: &mut Option<String>,
    incoming: &Option<String>,
    metadata: &mut BTreeMap<String, Value>,
    field: &str,
) {
    let incoming = trimmed_optional(incoming);
    match (current.clone(), incoming) {
        (None, Some(value)) => *current = Some(value),
        (Some(existing), Some(value)) if existing != value => record_observed_value(
            metadata,
            field,
            Value::String(existing),
            Value::String(value),
        ),
        _ => {}
    }
}

fn record_observed_value(
    metadata: &mut BTreeMap<String, Value>,
    field: &str,
    existing: Value,
    incoming: Value,
) {
    let observations = metadata
        .entry(OBSERVED_VALUES_METADATA.into())
        .or_insert_with(|| Value::Object(Map::new()));
    if !observations.is_object() {
        *observations = json!({});
    }
    let fields = observations
        .as_object_mut()
        .expect("object was just created");
    let values = fields
        .entry(field.to_owned())
        .or_insert_with(|| Value::Array(Vec::new()));
    if !values.is_array() {
        *values = Value::Array(Vec::new());
    }
    let values = values.as_array_mut().expect("array was just created");
    if !values.contains(&existing) {
        values.push(existing);
    }
    if !values.contains(&incoming) {
        values.push(incoming);
    }
}

fn conservative_bool(current: Option<bool>, incoming: Option<bool>) -> Option<bool> {
    match (current, incoming) {
        (Some(true), _) | (_, Some(true)) => Some(true),
        (Some(false), Some(false)) => Some(false),
        (Some(value), None) | (None, Some(value)) => Some(value),
        (None, None) => None,
    }
}

fn record_bool_conflict(
    metadata: &mut BTreeMap<String, Value>,
    field: &str,
    current: Option<bool>,
    incoming: Option<bool>,
) {
    if let (Some(current), Some(incoming)) = (current, incoming)
        && current != incoming
    {
        record_observed_value(metadata, field, Value::Bool(current), Value::Bool(incoming));
    }
}

fn normalize_optional(value: &Option<String>) -> Option<String> {
    trimmed_optional(value).map(|value| value.to_ascii_lowercase())
}

fn trimmed_optional(value: &Option<String>) -> Option<String> {
    value
        .as_deref()
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(str::to_owned)
}

fn enum_key<T: Serialize>(value: &T) -> String {
    serde_json::to_value(value)
        .ok()
        .and_then(|value| value.as_str().map(str::to_owned))
        .unwrap_or_else(|| "unknown".into())
}

fn deterministic_id(prefix: &str, material: &str) -> String {
    format!("{prefix}-{}", &hex_sha256(material)[..32])
}

fn hex_sha256(material: &str) -> String {
    hex::encode(Sha256::digest(material.as_bytes()))
}

fn merge_unique<T: Clone + Ord>(target: &mut Vec<T>, incoming: &[T]) {
    let mut values = target.iter().cloned().collect::<BTreeSet<_>>();
    values.extend(incoming.iter().cloned());
    *target = values.into_iter().collect();
}

fn unique_values<T: Clone + Ord>(values: &[T]) -> Vec<T> {
    values
        .iter()
        .cloned()
        .collect::<BTreeSet<_>>()
        .into_iter()
        .collect()
}
