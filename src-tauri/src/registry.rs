use crate::domain::EngineManifest;
use crate::error::{AppError, AppResult};

const BUILTIN_CATALOG: &str = include_str!("../../engines/catalog.json");

#[derive(Debug)]
pub struct EngineRegistry {
    manifests: Vec<EngineManifest>,
}

impl EngineRegistry {
    pub fn load_builtin() -> AppResult<Self> {
        let manifests: Vec<EngineManifest> = serde_json::from_str(BUILTIN_CATALOG)
            .map_err(|error| AppError::EngineRegistry(error.to_string()))?;

        let mut ids = std::collections::BTreeSet::new();
        for manifest in &manifests {
            if !ids.insert(&manifest.id) {
                return Err(AppError::EngineRegistry(format!(
                    "duplicate engine id: {}",
                    manifest.id
                )));
            }
        }

        Ok(Self { manifests })
    }

    pub fn manifests(&self) -> &[EngineManifest] {
        &self.manifests
    }

    pub fn get(&self, id: &str) -> Option<&EngineManifest> {
        self.manifests.iter().find(|manifest| manifest.id == id)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn builtin_catalog_has_unique_supported_engines() {
        let registry = EngineRegistry::load_builtin().expect("valid catalog");
        assert!(registry.manifests().len() >= 21);
        assert!(registry.get("prowler").is_some());
        assert!(registry.get("scubagear").is_some());
        assert!(registry.get("nuclei").is_some());
    }
}
