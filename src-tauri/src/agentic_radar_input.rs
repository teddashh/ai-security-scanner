//! One typed framework selection on an immutable repository snapshot.
//! Selecting inventory does not change local-artifact scan authorization.

use crate::domain::{Asset, AssetIdentifier, AssetKind};
use crate::error::{AppError, AppResult};
use serde::{Deserialize, Serialize};

pub const AGENTIC_RADAR_ENGINE_ID: &str = "agentic-radar";
pub const FRAMEWORK_METADATA_KEY: &str = "agentic_radar_framework";
pub const FRAMEWORK_IDENTIFIER_NAMESPACE: &str = "ai-security-scanner:agentic-radar-framework";

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "kebab-case")]
pub enum AgenticFramework {
    Langgraph,
    Crewai,
    N8n,
    OpenaiAgents,
    Autogen,
}

impl AgenticFramework {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Langgraph => "langgraph",
            Self::Crewai => "crewai",
            Self::N8n => "n8n",
            Self::OpenaiAgents => "openai-agents",
            Self::Autogen => "autogen",
        }
    }
}

pub fn select_framework(asset: &mut Asset, framework: Option<AgenticFramework>) -> AppResult<()> {
    if asset.kind != AssetKind::Repository
        || asset
            .metadata
            .get("workspace_snapshot_sha256")
            .and_then(serde_json::Value::as_str)
            .is_none_or(|sha| {
                sha.len() != 64
                    || !sha
                        .bytes()
                        .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
            })
    {
        return Err(AppError::InvalidRequest(
            "AI workflow inventory requires an immutable repository snapshot".into(),
        ));
    }
    asset.metadata.remove(FRAMEWORK_METADATA_KEY);
    asset
        .identifiers
        .retain(|id| id.namespace != FRAMEWORK_IDENTIFIER_NAMESPACE);
    if let Some(framework) = framework {
        asset.metadata.insert(
            FRAMEWORK_METADATA_KEY.into(),
            serde_json::to_value(framework)?,
        );
        asset.identifiers.push(AssetIdentifier {
            namespace: FRAMEWORK_IDENTIFIER_NAMESPACE.into(),
            value: framework.as_str().into(),
        });
    }
    Ok(())
}

pub fn selected_framework(asset: &Asset) -> AppResult<Option<AgenticFramework>> {
    let identifiers = asset
        .identifiers
        .iter()
        .filter(|id| id.namespace == FRAMEWORK_IDENTIFIER_NAMESPACE)
        .collect::<Vec<_>>();
    let Some(value) = asset.metadata.get(FRAMEWORK_METADATA_KEY) else {
        if identifiers.is_empty() {
            return Ok(None);
        }
        return Err(AppError::NotAuthorized(
            "AI workflow framework identifier lacks its typed selection".into(),
        ));
    };
    let framework: AgenticFramework = serde_json::from_value(value.clone()).map_err(|_| {
        AppError::InvalidRequest("unsupported AI workflow framework selection".into())
    })?;
    if asset.kind != AssetKind::Repository
        || identifiers.len() != 1
        || identifiers[0].value != framework.as_str()
    {
        return Err(AppError::NotAuthorized(
            "AI workflow framework selection does not match its frozen identifier".into(),
        ));
    }
    Ok(Some(framework))
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn repository() -> Asset {
        Asset {
            id: "asset-1".into(),
            kind: AssetKind::Repository,
            name: "fixture".into(),
            provider: None,
            region: None,
            identifiers: vec![],
            discovered_from: vec![],
            candidate: false,
            owner_confirmed: true,
            internet_exposed: None,
            contains_sensitive_data: None,
            metadata: std::collections::BTreeMap::from([(
                "workspace_snapshot_sha256".into(),
                json!("a".repeat(64)),
            )]),
        }
    }

    #[test]
    fn selection_replaces_and_clears_only_its_own_frozen_identifier() {
        let mut asset = repository();
        asset.identifiers.push(AssetIdentifier {
            namespace: "other".into(),
            value: "preserved".into(),
        });
        assert_eq!(selected_framework(&asset).unwrap(), None);
        select_framework(&mut asset, Some(AgenticFramework::Langgraph)).unwrap();
        select_framework(&mut asset, Some(AgenticFramework::N8n)).unwrap();
        assert_eq!(
            selected_framework(&asset).unwrap(),
            Some(AgenticFramework::N8n)
        );
        assert_eq!(asset.identifiers.len(), 2);
        select_framework(&mut asset, None).unwrap();
        assert_eq!(selected_framework(&asset).unwrap(), None);
        assert_eq!(asset.identifiers.len(), 1);
        assert_eq!(asset.identifiers[0].value, "preserved");
    }

    #[test]
    fn selection_rejects_missing_snapshot_and_mismatched_or_duplicate_identity() {
        let mut asset = repository();
        asset.metadata.clear();
        assert!(select_framework(&mut asset, Some(AgenticFramework::Langgraph)).is_err());
        let mut asset = repository();
        select_framework(&mut asset, Some(AgenticFramework::Langgraph)).unwrap();
        asset.identifiers[0].value = "n8n".into();
        assert!(selected_framework(&asset).is_err());
        asset.identifiers[0].value = "langgraph".into();
        asset.identifiers.push(asset.identifiers[0].clone());
        assert!(selected_framework(&asset).is_err());
        asset.kind = AssetKind::ContainerImage;
        assert!(select_framework(&mut asset, Some(AgenticFramework::Langgraph)).is_err());
    }

    #[test]
    fn framework_is_a_closed_upstream_selector() {
        for value in ["langgraph", "crewai", "n8n", "openai-agents", "autogen"] {
            let framework: AgenticFramework = serde_json::from_value(json!(value)).unwrap();
            assert_eq!(framework.as_str(), value);
        }
        for value in ["auto", "test", "--harden-prompts", "langgraph;sh", ""] {
            assert!(serde_json::from_value::<AgenticFramework>(json!(value)).is_err());
        }
    }
}
