use crate::domain::{Asset, EngineManifest, Finding, FindingStatus, RawArtifact};
use crate::error::{AppError, AppResult};
use std::collections::{BTreeMap, BTreeSet};
use std::path::Path;
use std::sync::Arc;

/// Exact native provider identifiers for the assets authorized in one engine
/// run. Candidate sets preserve collisions so adapters can fail closed instead
/// of guessing when two assets expose the same identifier.
#[derive(Debug, Clone, Default)]
pub struct AdapterAssetIdentifierMap {
    by_provider_and_identifier: BTreeMap<(String, String), BTreeSet<String>>,
    by_identifier: BTreeMap<String, BTreeSet<String>>,
}

impl AdapterAssetIdentifierMap {
    pub fn from_assets(assets: &[Asset]) -> Self {
        let mut result = Self::default();
        for asset in assets {
            let asset_id = asset.id.trim();
            if asset_id.is_empty() {
                continue;
            }
            for identifier in &asset.identifiers {
                let Some(identifier_provider) =
                    native_provider_for_namespace(&identifier.namespace)
                else {
                    continue;
                };
                if asset
                    .provider
                    .as_deref()
                    .and_then(normalize_provider)
                    .as_deref()
                    != Some(identifier_provider)
                {
                    continue;
                }
                let value = identifier.value.trim();
                if value.is_empty() {
                    continue;
                }
                result
                    .by_identifier
                    .entry(value.to_owned())
                    .or_default()
                    .insert(asset_id.to_owned());
                result
                    .by_provider_and_identifier
                    .entry((identifier_provider.to_owned(), value.to_owned()))
                    .or_default()
                    .insert(asset_id.to_owned());
            }
        }
        result
    }

    pub(crate) fn candidates(
        &self,
        provider: Option<&str>,
        identifier: &str,
    ) -> Option<&BTreeSet<String>> {
        let identifier = identifier.trim();
        if identifier.is_empty() {
            return None;
        }
        if let Some(provider) = provider.and_then(normalize_provider) {
            return self
                .by_provider_and_identifier
                .get(&(provider, identifier.to_owned()));
        }
        self.by_identifier.get(identifier)
    }
}

fn normalize_provider(provider: &str) -> Option<String> {
    let provider = provider.trim().to_ascii_lowercase();
    (!provider.is_empty()).then_some(provider)
}

fn native_provider_for_namespace(namespace: &str) -> Option<&'static str> {
    match namespace.trim().to_ascii_lowercase().as_str() {
        "aws_account_id" => Some("aws"),
        "azure_subscription_id" => Some("azure"),
        "gcp_project_id" => Some("gcp"),
        _ => None,
    }
}

pub struct AdapterInput<'a> {
    pub case_id: &'a str,
    pub scan_run_id: &'a str,
    pub engine_run_id: &'a str,
    pub manifest: &'a EngineManifest,
    /// True only when the case was explicitly created through the AI
    /// application journey. It controls AI-framework references; it never
    /// changes scan scope, permissions, or scanner execution.
    pub ai_system_applicable: bool,
    /// True only when the user explicitly answered that selected code was
    /// generated or materially changed by AI. Unknown and legacy cases remain
    /// false; this changes references only, never scanner execution.
    pub ai_generated_artifact_applicable: bool,
    pub asset_ids: &'a [String],
    pub asset_identifier_map: &'a AdapterAssetIdentifierMap,
    pub artifact_root: &'a Path,
    pub raw_artifacts: &'a [RawArtifact],
}

#[derive(Debug, Clone)]
pub struct AdapterOutput {
    pub findings: Vec<Finding>,
    pub warnings: Vec<String>,
    /// False when any captured evidence could not be fully normalized. Valid
    /// findings remain usable, but the engine run must not claim completion.
    pub complete: bool,
}

impl Default for AdapterOutput {
    fn default() -> Self {
        Self {
            findings: Vec::new(),
            warnings: Vec::new(),
            complete: true,
        }
    }
}

pub trait EngineAdapter: Send + Sync {
    fn engine_id(&self) -> &str;
    fn adapter_version(&self) -> &str;
    fn normalize(&self, input: &AdapterInput<'_>) -> AppResult<AdapterOutput>;
}

#[derive(Default)]
pub struct AdapterRegistry {
    adapters: BTreeMap<String, Arc<dyn EngineAdapter>>,
}

impl AdapterRegistry {
    pub fn register(&mut self, adapter: Arc<dyn EngineAdapter>) -> AppResult<()> {
        let id = adapter.engine_id().trim();
        if id.is_empty() {
            return Err(AppError::EngineRegistry(
                "adapter engine id cannot be empty".into(),
            ));
        }
        if self.adapters.contains_key(id) {
            return Err(AppError::EngineRegistry(format!(
                "duplicate adapter for engine {id}"
            )));
        }
        self.adapters.insert(id.to_owned(), adapter);
        Ok(())
    }

    pub fn get(&self, engine_id: &str) -> Option<&dyn EngineAdapter> {
        self.adapters.get(engine_id).map(AsRef::as_ref)
    }

    pub fn normalize(&self, input: &AdapterInput<'_>) -> AppResult<Option<AdapterOutput>> {
        let Some(adapter) = self.get(&input.manifest.id) else {
            return Ok(None);
        };
        if adapter.adapter_version() != input.manifest.adapter_version {
            return Err(AppError::Runtime(format!(
                "adapter version mismatch for {}: manifest requires {}, loaded {}",
                input.manifest.id,
                input.manifest.adapter_version,
                adapter.adapter_version()
            )));
        }
        let output = adapter.normalize(input)?;
        validate_adapter_output(input, adapter, &output)?;
        Ok(Some(output))
    }
}

pub fn validate_adapter_output(
    input: &AdapterInput<'_>,
    adapter: &dyn EngineAdapter,
    output: &AdapterOutput,
) -> AppResult<()> {
    if adapter.engine_id() != input.manifest.id {
        return Err(AppError::Runtime(format!(
            "adapter {} cannot normalize output for {}",
            adapter.engine_id(),
            input.manifest.id
        )));
    }
    if adapter.adapter_version() != input.manifest.adapter_version {
        return Err(AppError::Runtime(format!(
            "adapter version {} does not match manifest version {}",
            adapter.adapter_version(),
            input.manifest.adapter_version
        )));
    }

    let allowed_assets: BTreeSet<&str> = input.asset_ids.iter().map(String::as_str).collect();
    let artifacts: BTreeMap<&str, &RawArtifact> = input
        .raw_artifacts
        .iter()
        .map(|artifact| (artifact.id.as_str(), artifact))
        .collect();
    let mut fingerprints = BTreeSet::new();

    for finding in &output.findings {
        if finding.case_id != input.case_id || finding.last_seen_run_id != input.scan_run_id {
            return Err(AppError::Runtime(format!(
                "adapter produced a finding outside the current case or scan run: {}",
                finding.fingerprint
            )));
        }
        if finding.fingerprint.trim().is_empty()
            || !fingerprints.insert(finding.fingerprint.as_str())
        {
            return Err(AppError::Runtime(
                "adapter finding fingerprints must be non-empty and unique".into(),
            ));
        }
        if finding.asset_ids.is_empty()
            || finding
                .asset_ids
                .iter()
                .any(|asset_id| !allowed_assets.contains(asset_id.as_str()))
        {
            return Err(AppError::Runtime(format!(
                "adapter finding {} references an asset outside the authorized run",
                finding.fingerprint
            )));
        }
        if finding.evidence.is_empty() {
            return Err(AppError::Runtime(format!(
                "adapter finding {} has no raw evidence",
                finding.fingerprint
            )));
        }
        if finding.status != FindingStatus::Unreviewed {
            return Err(AppError::Runtime(format!(
                "adapter may not assign a human review state to {}",
                finding.fingerprint
            )));
        }
        if finding.tags.iter().any(|tag| tag == "synthetic-demo") {
            return Err(AppError::Runtime(
                "synthetic demo findings cannot be emitted by a scanner adapter".into(),
            ));
        }

        for evidence in &finding.evidence {
            if evidence.finding_id != finding.id
                || evidence.run_id != input.scan_run_id
                || evidence.engine_run_id.as_deref() != Some(input.engine_run_id)
                || evidence.engine_id != input.manifest.id
            {
                return Err(AppError::Runtime(format!(
                    "finding {} has evidence with a mismatched finding, scan run, or engine execution",
                    finding.fingerprint
                )));
            }
            let artifact = artifacts
                .get(evidence.artifact_id.as_str())
                .ok_or_else(|| {
                    AppError::Runtime(format!(
                        "finding {} references an unknown raw artifact",
                        finding.fingerprint
                    ))
                })?;
            if artifact.sha256 != evidence.artifact_sha256
                || artifact.case_id != input.case_id
                || artifact.run_id != input.scan_run_id
                || artifact.engine_run_id != input.engine_run_id
            {
                return Err(AppError::Runtime(format!(
                    "finding {} raw artifact hash or execution context does not match",
                    finding.fingerprint
                )));
            }
        }
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::domain::{
        AssetKind, Confidence, DistributionMode, EngineCategory, EngineCompatibility, Evidence,
        EvidenceKind, FindingStatus, ImageReference, ManifestStatus, ScanPermission, Severity,
    };
    use chrono::Utc;

    struct TestAdapter {
        output: AdapterOutput,
    }

    impl EngineAdapter for TestAdapter {
        fn engine_id(&self) -> &str {
            "scanner"
        }

        fn adapter_version(&self) -> &str {
            "1"
        }

        fn normalize(&self, _input: &AdapterInput<'_>) -> AppResult<AdapterOutput> {
            Ok(self.output.clone())
        }
    }

    fn manifest() -> EngineManifest {
        EngineManifest {
            schema_version: "1".into(),
            id: "scanner".into(),
            display_name: "Scanner".into(),
            category: EngineCategory::CodeAndSecrets,
            description: "test".into(),
            repository_url: "https://example.invalid/scanner".into(),
            homepage_url: None,
            license_spdx: "Apache-2.0".into(),
            distribution_mode: DistributionMode::PullPinnedImage,
            image: Some(ImageReference {
                repository: "registry.example/scanner".into(),
                tag: None,
                digest: Some(format!("sha256:{}", "a".repeat(64))),
                signature_identity: None,
            }),
            source_revision: None,
            engine_version: Some("1".into()),
            rule_version: None,
            adapter_version: "1".into(),
            supported_providers: vec![],
            supported_asset_kinds: vec![AssetKind::Repository],
            input_contracts: vec![],
            provider_execution_contracts: vec![],
            direct_network_contract: None,
            required_permissions: vec![ScanPermission::LocalArtifactRead],
            active_external: false,
            default_enabled: false,
            estimated_memory_mb: 512,
            estimated_disk_mb: 512,
            network_destinations: vec![],
            output_formats: vec!["json".into()],
            command: vec!["scanner".into()],
            status: ManifestStatus::Experimental,
            notices: vec![],
            compatibility: EngineCompatibility::default(),
            execution: None,
        }
    }

    fn artifact() -> RawArtifact {
        RawArtifact {
            id: "artifact-1".into(),
            case_id: "case-1".into(),
            run_id: "run-1".into(),
            engine_run_id: "engine-run-1".into(),
            relative_path: "raw/result.json".into(),
            media_type: "application/json".into(),
            sha256: "abc123".into(),
            byte_length: 2,
            created_at: Utc::now(),
            contains_sensitive_data: true,
        }
    }

    fn finding(artifact: &RawArtifact) -> Finding {
        Finding {
            id: "finding-1".into(),
            case_id: "case-1".into(),
            first_seen_run_id: "run-1".into(),
            last_seen_run_id: "run-1".into(),
            fingerprint: "scanner:asset-1:check-1".into(),
            title: "Finding".into(),
            plain_language_summary: "Summary".into(),
            possible_impact: "Impact".into(),
            severity: Severity::High,
            confidence: Confidence::High,
            priority: 80,
            priority_reasons: vec![],
            asset_ids: vec!["asset-1".into()],
            evidence: vec![Evidence {
                id: "evidence-1".into(),
                finding_id: "finding-1".into(),
                run_id: "run-1".into(),
                engine_run_id: Some(artifact.engine_run_id.clone()),
                kind: EvidenceKind::RawToolOutput,
                engine_id: "scanner".into(),
                observed_at: Utc::now(),
                summary: "raw evidence".into(),
                artifact_id: artifact.id.clone(),
                artifact_sha256: artifact.sha256.clone(),
                pointer: Some("/result/0".into()),
                redacted: false,
            }],
            control_references: vec![],
            recommendation: "Ask an expert".into(),
            verification_guidance: "Run again".into(),
            rollback_considerations: None,
            official_references: vec![],
            recommended_expert_type: "Security engineer".into(),
            status: FindingStatus::Unreviewed,
            tags: vec![],
        }
    }

    #[test]
    fn native_identifier_map_requires_an_explicit_matching_provider() {
        let make_asset = |id: &str, provider: Option<&str>| Asset {
            id: id.into(),
            kind: AssetKind::CloudAccount,
            name: id.into(),
            provider: provider.map(str::to_owned),
            region: None,
            identifiers: vec![crate::domain::AssetIdentifier {
                namespace: "aws_account_id".into(),
                value: "111122223333".into(),
            }],
            discovered_from: vec![],
            candidate: false,
            owner_confirmed: true,
            internet_exposed: None,
            contains_sensitive_data: None,
            metadata: BTreeMap::new(),
        };
        let map = AdapterAssetIdentifierMap::from_assets(&[
            make_asset("missing-provider", None),
            make_asset("wrong-provider", Some("azure")),
            make_asset("exact-provider", Some("AWS")),
        ]);

        assert_eq!(
            map.candidates(Some("aws"), "111122223333"),
            Some(&BTreeSet::from(["exact-provider".to_owned()]))
        );
    }

    #[test]
    fn missing_adapter_returns_none_instead_of_fake_findings() {
        let manifest = manifest();
        let artifacts = vec![artifact()];
        let assets = vec!["asset-1".into()];
        let asset_identifier_map = AdapterAssetIdentifierMap::default();
        let input = AdapterInput {
            case_id: "case-1",
            scan_run_id: "run-1",
            engine_run_id: "engine-run-1",
            manifest: &manifest,
            ai_system_applicable: false,
            ai_generated_artifact_applicable: false,
            asset_ids: &assets,
            asset_identifier_map: &asset_identifier_map,
            artifact_root: Path::new("/tmp"),
            raw_artifacts: &artifacts,
        };

        let output = AdapterRegistry::default()
            .normalize(&input)
            .expect("registry result");
        assert!(output.is_none());
    }

    #[test]
    fn evidence_must_reference_the_exact_hashed_artifact() {
        let manifest = manifest();
        let artifact = artifact();
        let mut bad_finding = finding(&artifact);
        bad_finding.evidence[0].artifact_sha256 = "forged".into();
        let adapter = TestAdapter {
            output: AdapterOutput {
                findings: vec![bad_finding],
                warnings: vec![],
                complete: true,
            },
        };
        let artifacts = vec![artifact];
        let assets = vec!["asset-1".into()];
        let asset_identifier_map = AdapterAssetIdentifierMap::default();
        let input = AdapterInput {
            case_id: "case-1",
            scan_run_id: "run-1",
            engine_run_id: "engine-run-1",
            manifest: &manifest,
            ai_system_applicable: false,
            ai_generated_artifact_applicable: false,
            asset_ids: &assets,
            asset_identifier_map: &asset_identifier_map,
            artifact_root: Path::new("/tmp"),
            raw_artifacts: &artifacts,
        };

        let error = validate_adapter_output(&input, &adapter, &adapter.output)
            .expect_err("forged evidence rejected");
        assert!(error.to_string().contains("hash or execution context"));
    }

    #[test]
    fn evidence_must_name_the_exact_producing_engine_run() {
        let manifest = manifest();
        let artifact = artifact();
        let mut bad_finding = finding(&artifact);
        bad_finding.evidence[0].engine_run_id = Some("another-engine-run".into());
        let adapter = TestAdapter {
            output: AdapterOutput {
                findings: vec![bad_finding],
                warnings: vec![],
                complete: true,
            },
        };
        let artifacts = vec![artifact];
        let assets = vec!["asset-1".into()];
        let asset_identifier_map = AdapterAssetIdentifierMap::default();
        let input = AdapterInput {
            case_id: "case-1",
            scan_run_id: "run-1",
            engine_run_id: "engine-run-1",
            manifest: &manifest,
            ai_system_applicable: false,
            ai_generated_artifact_applicable: false,
            asset_ids: &assets,
            asset_identifier_map: &asset_identifier_map,
            artifact_root: Path::new("/tmp"),
            raw_artifacts: &artifacts,
        };

        let error = validate_adapter_output(&input, &adapter, &adapter.output)
            .expect_err("cross-run evidence rejected");
        assert!(error.to_string().contains("mismatched finding, scan run"));
    }
}
