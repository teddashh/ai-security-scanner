use crate::domain::{AssetKind, EngineManifest, LocalInputProfile, ScanPermission};
use crate::error::{AppError, AppResult};
use chrono::NaiveDate;

const EXPECTED_ENGINE_IDS: [&str; 21] = [
    "cloudquery",
    "steampipe",
    "prowler",
    "scoutsuite",
    "cloudsplaining",
    "scubagear",
    "maester",
    "naabu",
    "httpx",
    "nuclei",
    "greenbone",
    "semgrep",
    "gitleaks",
    "trufflehog",
    "checkov",
    "kics",
    "trivy",
    "grype",
    "syft",
    "kubescape",
    "kube-bench",
];

const AWS_ONLY_ENGINE_IDS: [&str; 4] = ["cloudquery", "steampipe", "scoutsuite", "cloudsplaining"];
const MICROSOFT365_ONLY_ENGINE_IDS: [&str; 2] = ["scubagear", "maester"];

const BUILTIN_CATALOG: &str = include_str!("../../engines/catalog.json");

#[derive(Debug)]
pub struct EngineRegistry {
    manifests: Vec<EngineManifest>,
}

impl EngineRegistry {
    pub fn load_builtin() -> AppResult<Self> {
        let manifests: Vec<EngineManifest> = serde_json::from_str(BUILTIN_CATALOG)
            .map_err(|error| AppError::EngineRegistry(error.to_string()))?;

        let actual_ids = manifests
            .iter()
            .map(|manifest| manifest.id.as_str())
            .collect::<Vec<_>>();
        if actual_ids != EXPECTED_ENGINE_IDS {
            return Err(AppError::EngineRegistry(
                "built-in engine catalog does not match the fixed 21-engine release set".into(),
            ));
        }

        let mut ids = std::collections::BTreeSet::new();
        for manifest in &manifests {
            if !ids.insert(&manifest.id) {
                return Err(AppError::EngineRegistry(format!(
                    "duplicate engine id: {}",
                    manifest.id
                )));
            }
            validate_release_contract(manifest)?;
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

fn validate_release_contract(manifest: &EngineManifest) -> AppResult<()> {
    let fail =
        |message: &str| AppError::EngineRegistry(format!("engine {}: {message}", manifest.id));
    if manifest.schema_version != "2.0.0" {
        return Err(fail("unsupported manifest schema version"));
    }
    let supported_providers = manifest
        .supported_providers
        .iter()
        .map(String::as_str)
        .collect::<std::collections::BTreeSet<_>>();
    if supported_providers.len() != manifest.supported_providers.len()
        || supported_providers
            .iter()
            .any(|provider| !matches!(*provider, "aws" | "azure" | "gcp" | "microsoft365"))
    {
        return Err(fail(
            "supported providers must be unique exact catalog identifiers",
        ));
    }
    let expected_providers = if manifest.id == "prowler" {
        ["aws", "azure", "gcp"].into_iter().collect()
    } else if AWS_ONLY_ENGINE_IDS.contains(&manifest.id.as_str()) {
        ["aws"].into_iter().collect()
    } else if MICROSOFT365_ONLY_ENGINE_IDS.contains(&manifest.id.as_str()) {
        ["microsoft365"].into_iter().collect()
    } else {
        std::collections::BTreeSet::new()
    };
    if supported_providers != expected_providers {
        return Err(fail(
            "supported providers overstate or omit the released provider applicability contract",
        ));
    }
    if manifest.supported_providers.len() > 1 && manifest.provider_execution_contracts.is_empty() {
        return Err(fail(
            "a multi-provider engine must bind every provider to an exact execution contract",
        ));
    }
    if manifest.supported_providers.is_empty() && !manifest.provider_execution_contracts.is_empty()
    {
        return Err(fail(
            "a provider-agnostic engine cannot declare provider execution contracts",
        ));
    }
    if !manifest.provider_execution_contracts.is_empty() {
        let contract_providers = manifest
            .provider_execution_contracts
            .iter()
            .map(|contract| contract.provider.as_str())
            .collect::<std::collections::BTreeSet<_>>();
        let contract_asset_kinds = manifest
            .provider_execution_contracts
            .iter()
            .map(|contract| &contract.asset_kind)
            .collect::<Vec<_>>();
        let supported_asset_kinds = manifest.supported_asset_kinds.iter().collect::<Vec<_>>();
        let contract_profiles = manifest
            .provider_execution_contracts
            .iter()
            .map(|contract| contract.profile.as_str())
            .collect::<std::collections::BTreeSet<_>>();
        let contract_destinations = manifest
            .provider_execution_contracts
            .iter()
            .flat_map(|contract| contract.network_destinations.iter().map(String::as_str))
            .collect::<std::collections::BTreeSet<_>>();
        let manifest_destinations = manifest
            .network_destinations
            .iter()
            .map(String::as_str)
            .collect::<std::collections::BTreeSet<_>>();
        if contract_providers != supported_providers
            || contract_providers.len() != manifest.provider_execution_contracts.len()
            || contract_asset_kinds
                .iter()
                .enumerate()
                .any(|(index, kind)| contract_asset_kinds[..index].contains(kind))
            || contract_asset_kinds.len() != supported_asset_kinds.len()
            || supported_asset_kinds
                .iter()
                .any(|kind| !contract_asset_kinds.contains(kind))
            || contract_profiles.len() != manifest.provider_execution_contracts.len()
            || contract_destinations != manifest_destinations
        {
            return Err(fail(
                "provider execution contracts must uniquely and completely bind provider, asset kind, profile, and the declared network closure",
            ));
        }
        for contract in &manifest.provider_execution_contracts {
            if contract.profile.len() < 3
                || contract.profile.len() > 64
                || !contract.profile.bytes().enumerate().all(|(index, byte)| {
                    byte.is_ascii_lowercase()
                        || byte.is_ascii_digit()
                        || (index > 0 && matches!(byte, b'_' | b'-'))
                })
                || contract.network_destinations.is_empty()
                || contract
                    .network_destinations
                    .iter()
                    .any(|destination| destination.trim().is_empty())
            {
                return Err(fail("provider execution contract is malformed"));
            }
        }
    }
    let local_artifact = manifest
        .required_permissions
        .contains(&ScanPermission::LocalArtifactRead);
    if local_artifact {
        if manifest.input_contracts.len() != manifest.supported_asset_kinds.len()
            || manifest
                .input_contracts
                .iter()
                .zip(&manifest.supported_asset_kinds)
                .any(|(contract, asset_kind)| {
                    contract.asset_kind != *asset_kind
                        || expected_input_profile(asset_kind)
                            .is_none_or(|profile| contract.input_profile != profile)
                })
        {
            return Err(fail(
                "local input contracts must exactly bind every supported asset kind",
            ));
        }
    } else if !manifest.input_contracts.is_empty() {
        return Err(fail(
            "an engine without local-artifact permission cannot declare local input contracts",
        ));
    }
    let knowledge_date = parse_iso_date(&manifest.compatibility.knowledge_date)
        .ok_or_else(|| fail("compatibility knowledge date is not a real ISO calendar date"))?;
    let support_until = parse_iso_date(&manifest.compatibility.support_until)
        .ok_or_else(|| fail("compatibility support-until date is not a real ISO calendar date"))?;
    if support_until < knowledge_date {
        return Err(fail(
            "compatibility support-until date precedes the knowledge date",
        ));
    }
    let maintenance_owner = manifest.compatibility.maintenance_owner.trim();
    if maintenance_owner.is_empty()
        || maintenance_owner.chars().count() > 200
        || maintenance_owner.chars().any(char::is_control)
    {
        return Err(fail("compatibility maintenance owner is invalid"));
    }
    if manifest.compatibility.update_procedure != "docs/engine-maintenance.md" {
        return Err(fail(
            "compatibility update procedure must reference the release-reviewed engine maintenance procedure",
        ));
    }
    if manifest.compatibility.packaging_plan != format!("engines/images/{}/plan.json", manifest.id)
    {
        return Err(fail("packaging plan path does not match the engine id"));
    }
    if manifest.compatibility.runnable {
        if let Some(blocker) = manifest.release_blocker() {
            return Err(fail(&blocker));
        }
        let image = manifest
            .image
            .as_ref()
            .ok_or_else(|| fail("runnable release has no immutable container image"))?;
        if image.repository.trim().is_empty()
            || !image.digest.as_deref().is_some_and(valid_sha256_digest)
        {
            return Err(fail(
                "runnable release image is not pinned by sha256 digest",
            ));
        }
        if manifest.command.is_empty() || manifest.command.iter().any(|part| part.trim().is_empty())
        {
            return Err(fail("runnable release has no complete static command"));
        }
    } else {
        if manifest.compatibility.blocked_by.is_empty() {
            return Err(fail("non-runnable release must state at least one blocker"));
        }
        if manifest.default_enabled {
            return Err(fail("non-runnable release cannot be enabled by default"));
        }
    }
    Ok(())
}

fn expected_input_profile(asset_kind: &AssetKind) -> Option<LocalInputProfile> {
    match asset_kind {
        AssetKind::Repository => Some(LocalInputProfile::RepositoryWorkingTree),
        AssetKind::IacProject => Some(LocalInputProfile::IacWorkingTree),
        AssetKind::ContainerImage => Some(LocalInputProfile::ContainerImageOciLayout),
        AssetKind::KubernetesCluster => Some(LocalInputProfile::KubernetesManifests),
        AssetKind::Host => Some(LocalInputProfile::KubernetesNodeSnapshot),
        _ => None,
    }
}

fn parse_iso_date(value: &str) -> Option<NaiveDate> {
    if value.len() != 10
        || value.as_bytes().get(4) != Some(&b'-')
        || value.as_bytes().get(7) != Some(&b'-')
    {
        return None;
    }
    NaiveDate::parse_from_str(value, "%Y-%m-%d").ok()
}

fn valid_sha256_digest(value: &str) -> bool {
    value.strip_prefix("sha256:").is_some_and(|hex| {
        hex.len() == 64 && hex.chars().all(|character| character.is_ascii_hexdigit())
    })
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
        for id in AWS_ONLY_ENGINE_IDS {
            assert_eq!(registry.get(id).unwrap().supported_providers, ["aws"]);
        }
        assert_eq!(
            registry.get("prowler").unwrap().supported_providers,
            ["aws", "azure", "gcp"]
        );
        assert!(
            registry
                .get("gitleaks")
                .unwrap()
                .supported_providers
                .is_empty()
        );
    }

    #[test]
    fn compatibility_dates_require_real_calendar_days() {
        assert_eq!(
            parse_iso_date("2024-02-29"),
            NaiveDate::from_ymd_opt(2024, 2, 29)
        );
        assert!(parse_iso_date("2026-02-29").is_none());
        assert!(parse_iso_date("2026-13-01").is_none());
        assert!(parse_iso_date("2026-8-24").is_none());
        assert!(parse_iso_date("not-a-date").is_none());
    }
}
