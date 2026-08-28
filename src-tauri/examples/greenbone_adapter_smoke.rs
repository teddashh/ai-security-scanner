use ai_security_scanner_lib::adapter::{AdapterAssetIdentifierMap, AdapterInput};
use ai_security_scanner_lib::adapters::builtin_adapter_registry;
use ai_security_scanner_lib::domain::RawArtifact;
use ai_security_scanner_lib::registry::EngineRegistry;
use chrono::Utc;
use sha2::{Digest, Sha256};
use std::env;
use std::fs;
use std::path::PathBuf;

const MAX_ARTIFACT_BYTES: u64 = 512 * 1024 * 1024;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let arguments = env::args_os().skip(1).collect::<Vec<_>>();
    if arguments.len() != 1 {
        return Err("usage: greenbone_adapter_smoke <absolute-greenbone.xml>".into());
    }
    let path = PathBuf::from(&arguments[0]);
    if !path.is_absolute()
        || path.file_name().and_then(|name| name.to_str()) != Some("greenbone.xml")
    {
        return Err("artifact must be the absolute greenbone.xml path".into());
    }
    let metadata = fs::symlink_metadata(&path)?;
    if metadata.file_type().is_symlink()
        || !metadata.is_file()
        || metadata.len() == 0
        || metadata.len() > MAX_ARTIFACT_BYTES
    {
        return Err("artifact is not a bounded regular file".into());
    }
    let bytes = fs::read(&path)?;
    let artifact_root = path
        .parent()
        .ok_or("artifact has no parent")?
        .canonicalize()?;
    if path.canonicalize()?.parent() != Some(artifact_root.as_path()) {
        return Err("artifact escaped its root".into());
    }

    let engines = EngineRegistry::load_builtin()?;
    let manifest = engines
        .get("greenbone")
        .ok_or("Greenbone is not in the catalog")?;
    let artifact = RawArtifact {
        id: "greenbone-managed-socks-smoke-artifact".into(),
        case_id: "case-greenbone-managed-socks-smoke".into(),
        run_id: "run-greenbone-managed-socks-smoke".into(),
        engine_run_id: "engine-run-greenbone-managed-socks-smoke".into(),
        relative_path: "greenbone.xml".into(),
        media_type: "application/xml".into(),
        sha256: hex::encode(Sha256::digest(&bytes)),
        byte_length: bytes.len() as u64,
        created_at: Utc::now(),
        contains_sensitive_data: true,
    };
    let assets = vec!["asset-greenbone-managed-socks-smoke".to_owned()];
    let artifacts = vec![artifact];
    let asset_identifier_map = AdapterAssetIdentifierMap::default();
    let input = AdapterInput {
        case_id: "case-greenbone-managed-socks-smoke",
        scan_run_id: "run-greenbone-managed-socks-smoke",
        engine_run_id: "engine-run-greenbone-managed-socks-smoke",
        manifest,
        ai_system_applicable: false,
        ai_generated_artifact_applicable: false,
        asset_ids: &assets,
        artifact_root: &artifact_root,
        raw_artifacts: &artifacts,
        asset_identifier_map: &asset_identifier_map,
    };
    let output = builtin_adapter_registry()?
        .normalize(&input)?
        .ok_or("Greenbone adapter is not registered")?;
    if output.findings.is_empty() {
        return Err(format!(
            "real Greenbone artifact parsed without an actionable finding; warnings: {:?}",
            output.warnings
        )
        .into());
    }
    if output.findings.iter().any(|finding| {
        !finding
            .asset_ids
            .iter()
            .any(|asset| asset == "asset-greenbone-managed-socks-smoke")
            || finding.evidence.is_empty()
    }) {
        return Err("adapter finding escaped its authorized asset or raw evidence".into());
    }
    println!(
        "{}",
        serde_json::json!({
            "artifact_sha256": artifacts[0].sha256,
            "finding_count": output.findings.len(),
            "finding_titles": output.findings.iter().map(|finding| finding.title.clone()).collect::<Vec<_>>(),
            "warnings": output.warnings,
        })
    );
    Ok(())
}
