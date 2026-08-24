use crate::domain::EngineManifest;
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

const AWS_ONLY_ENGINE_IDS: [&str; 5] = [
    "cloudquery",
    "steampipe",
    "prowler",
    "scoutsuite",
    "cloudsplaining",
];
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
    let expected_providers = if AWS_ONLY_ENGINE_IDS.contains(&manifest.id.as_str()) {
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
