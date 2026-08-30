//! Product-level uninstall coordination for the installed Windows package.
//!
//! This module deliberately does not open the case database or engine catalog.
//! The uninstaller must still be able to stop exact product runtimes when the
//! database is corrupt, and no user-data cleanup may begin until target contact
//! has stopped. Ambiguous runtime state is retained and reported; it is never
//! promoted to deletion authority by a name match.

use crate::error::{AppError, AppResult};
use crate::managed_network::ManagedNetworkRegistry;
use crate::managed_runtime::{ManagedRuntimeManager, ManagedStopMode, ManagedUninstallOptions};
use crate::process_lease::DataDirectoryExclusiveLease;
use chrono::Utc;
use serde::Serialize;
use sha2::{Digest, Sha256};
use std::collections::BTreeSet;
use std::fs::{self, File, OpenOptions};
use std::io::{self, Read};
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

pub const ALL_DATA_CONFIRMATION: &str = "REMOVE ALL AI-SECURITY-SCANNER DATA";
pub const PRODUCT_DATA_DIRECTORY_NAME: &str = "dev.teddashh.ai-security-scanner";
pub const PRODUCT_UNINSTALL_COMPLETED_EXIT_CODE: u8 = 0;
pub const PRODUCT_UNINSTALL_RETAINED_EXIT_CODE: u8 = 10;
pub const PRODUCT_UNINSTALL_CONTACT_NOT_STOPPED_EXIT_CODE: u8 = 20;

const MANAGED_RUNTIME_DIRECTORY: &str = "managed-runtime";
const MANAGED_RUNTIME_VERSIONS_DIRECTORY: &str = "versions";
const MANAGED_RUNTIME_PROVIDER_DIRECTORY: &str = "provider-home";
const MANAGED_RUNTIME_LIFECYCLE_LOCK: &str = "lifecycle.lock";
const DATA_DIRECTORY_LEASE_FILE: &str = ".exclusive-process.lock";
const MANAGED_RUNTIME_MANIFEST: &str = "manifest.json";
const ARTIFACT_DIRECTORY: &str = "artifacts";
const MANAGED_NETWORK_REGISTRY_DIRECTORY: &str = ".managed-egress-registry";
const MAX_INSTALLED_RUNTIME_ENTRIES: usize = 32;
const MAX_RUNTIME_MANIFEST_BYTES: u64 = 1024 * 1024;
const MAX_PRODUCT_DATA_ENTRIES: usize = 200_000;
const MAX_PRODUCT_DATA_DEPTH: usize = 64;
const MAX_RETAINED_ITEMS: usize = 128;
const PRODUCT_DATA_CLEANUP_TIMEOUT: Duration = Duration::from_secs(30);

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ProductUninstallMode {
    AppOnly,
    ScanTools,
    AllData,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ProductUninstallResultClass {
    Completed,
    CompletedWithRetainedState,
    ContactNotStopped,
}

impl ProductUninstallResultClass {
    pub fn exit_code(self) -> u8 {
        match self {
            Self::Completed => PRODUCT_UNINSTALL_COMPLETED_EXIT_CODE,
            Self::CompletedWithRetainedState => PRODUCT_UNINSTALL_RETAINED_EXIT_CODE,
            Self::ContactNotStopped => PRODUCT_UNINSTALL_CONTACT_NOT_STOPPED_EXIT_CODE,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProductUninstallRequest {
    pub mode: ProductUninstallMode,
    pub non_interactive: bool,
    pub confirmation: Option<String>,
}

impl ProductUninstallRequest {
    pub fn validate(&self) -> AppResult<()> {
        if !self.non_interactive {
            return Err(AppError::InvalidRequest(
                "product-uninstall requires --non-interactive; the package uninstaller owns the visible choice and confirmation"
                    .into(),
            ));
        }
        match self.mode {
            ProductUninstallMode::AllData
                if self.confirmation.as_deref() != Some(ALL_DATA_CONFIRMATION) =>
            {
                Err(AppError::NotAuthorized(format!(
                    "--confirmation must exactly equal {ALL_DATA_CONFIRMATION:?} for all-data"
                )))
            }
            ProductUninstallMode::AllData => Ok(()),
            _ if self.confirmation.is_some() => Err(AppError::InvalidRequest(
                "--confirmation is accepted only with --mode all-data".into(),
            )),
            _ => Ok(()),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ProductUninstallRetainedItem {
    /// Stable, non-sensitive class. No filesystem path, runtime name, target,
    /// scanner message, or case identifier is emitted by this result.
    pub item_class: &'static str,
    pub reason_code: &'static str,
}

impl ProductUninstallRetainedItem {
    fn new(item_class: &'static str, reason_code: &'static str) -> Self {
        Self {
            item_class,
            reason_code,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ProductUninstallResult {
    pub schema_version: &'static str,
    pub mode: ProductUninstallMode,
    pub result_class: ProductUninstallResultClass,
    pub exit_code: u8,
    pub verified_runtimes_found: usize,
    pub verified_runtimes_stopped: usize,
    pub verified_runtimes_removed: usize,
    pub verified_compatibility_gateways_found: usize,
    pub verified_compatibility_gateways_stopped: usize,
    pub retained_items: Vec<ProductUninstallRetainedItem>,
    pub preserved: Vec<&'static str>,
    pub removed: Vec<&'static str>,
}

impl ProductUninstallResult {
    fn new(mode: ProductUninstallMode) -> Self {
        let preserved = match mode {
            ProductUninstallMode::AppOnly => vec![
                "projects_findings_evidence_and_exports",
                "preferences_and_signing_identity",
                "managed_scan_tools",
            ],
            ProductUninstallMode::ScanTools => vec![
                "projects_findings_evidence_and_exports",
                "preferences_and_signing_identity",
            ],
            ProductUninstallMode::AllData => vec!["ambiguous_or_unrelated_entries"],
        };
        Self {
            schema_version: "ai-security-scanner.product-uninstall/v1",
            mode,
            result_class: ProductUninstallResultClass::Completed,
            exit_code: PRODUCT_UNINSTALL_COMPLETED_EXIT_CODE,
            verified_runtimes_found: 0,
            verified_runtimes_stopped: 0,
            verified_runtimes_removed: 0,
            verified_compatibility_gateways_found: 0,
            verified_compatibility_gateways_stopped: 0,
            retained_items: Vec::new(),
            preserved,
            removed: Vec::new(),
        }
    }

    fn retain(&mut self, item: ProductUninstallRetainedItem) {
        if self.retained_items.iter().any(|existing| existing == &item) {
            return;
        }
        if self.retained_items.len() < MAX_RETAINED_ITEMS {
            self.retained_items.push(item);
        } else if !self
            .retained_items
            .iter()
            .any(|item| item.reason_code == "retained_report_limit_reached")
        {
            self.retained_items.push(ProductUninstallRetainedItem::new(
                "uninstall_result",
                "retained_report_limit_reached",
            ));
        }
    }

    fn finish(&mut self, contact_not_stopped: bool) {
        self.result_class = if contact_not_stopped {
            ProductUninstallResultClass::ContactNotStopped
        } else if self.retained_items.is_empty() {
            ProductUninstallResultClass::Completed
        } else {
            ProductUninstallResultClass::CompletedWithRetainedState
        };
        self.exit_code = self.result_class.exit_code();
    }

    pub fn record_finalization_retained(
        &mut self,
        item_class: &'static str,
        reason_code: &'static str,
    ) {
        if item_class == "product_data" {
            self.removed.retain(|class| *class != "product_user_data");
            if !self.preserved.contains(&"unremoved_product_user_data") {
                self.preserved.push("unremoved_product_user_data");
            }
        }
        self.retain(ProductUninstallRetainedItem::new(item_class, reason_code));
        self.finish(false);
    }

    pub fn canonical_data_root_can_be_staged(&self) -> bool {
        !self.retained_items.iter().any(|item| {
            matches!(
                item.item_class,
                "product_data"
                    | "managed_runtime_state"
                    | "managed_runtime_entry"
                    | "verified_runtime"
                    | "compatibility_gateway_state"
                    | "verified_compatibility_gateway"
            )
        })
    }
}

#[derive(Debug, Default)]
pub struct ProductRuntimeInventory {
    pub verified_manifest_sha256: Vec<String>,
    pub retained: Vec<ProductUninstallRetainedItem>,
    /// True only when a bounded enumeration failed or exceeded its ceiling and
    /// could therefore have hidden an otherwise verifiable active runtime.
    pub contact_inventory_incomplete: bool,
}

#[derive(Debug, Clone, Default)]
pub struct ProductCompatibilityGatewayStopOutcome {
    pub exact_gateways_found: usize,
    pub exact_gateways_stopped: usize,
    pub exact_stop_failures: usize,
    pub retained_ambiguities: usize,
    pub contact_inventory_incomplete: bool,
}

/// Narrow backend seam used to unit-test sequencing without touching a real
/// runtime or real product data.
pub trait ProductUninstallBackend {
    fn inventory_runtimes(&mut self) -> AppResult<ProductRuntimeInventory>;
    fn stop_verified_runtime(&mut self, manifest_sha256: &str) -> bool;
    fn stop_verified_compatibility_gateways(&mut self) -> ProductCompatibilityGatewayStopOutcome;
    fn remove_verified_runtime(&mut self, manifest_sha256: &str) -> bool;
    fn cleanup_scan_tool_residue(&mut self) -> Vec<ProductUninstallRetainedItem>;
    fn cleanup_all_product_user_data(
        &mut self,
        preserve_compatibility_gateway_state: bool,
    ) -> Vec<ProductUninstallRetainedItem>;
}

/// Executes the product contract in two phases. All exact runtimes are given a
/// bounded stop attempt before the first cleanup mutation. If one cannot be
/// stopped, exit class 20 is returned and neither runtime nor user data is
/// removed. Ambiguous and failed-removal state is retained with exit class 10.
pub fn coordinate_product_uninstall<B: ProductUninstallBackend>(
    request: &ProductUninstallRequest,
    backend: &mut B,
) -> AppResult<ProductUninstallResult> {
    request.validate()?;
    let inventory = backend.inventory_runtimes()?;
    let mut result = ProductUninstallResult::new(request.mode);
    result.verified_runtimes_found = inventory.verified_manifest_sha256.len();
    for retained in inventory.retained {
        result.retain(retained);
    }

    let mut contact_not_stopped = false;
    if inventory.contact_inventory_incomplete {
        contact_not_stopped = true;
        result.retain(ProductUninstallRetainedItem::new(
            "managed_runtime_state",
            "target_contact_inventory_incomplete",
        ));
    }
    for manifest_sha256 in &inventory.verified_manifest_sha256 {
        if backend.stop_verified_runtime(manifest_sha256) {
            result.verified_runtimes_stopped += 1;
        } else {
            contact_not_stopped = true;
            result.retain(ProductUninstallRetainedItem::new(
                "verified_runtime",
                "target_contact_not_stopped",
            ));
        }
    }
    // Compatibility gateways are a separate target-contact path from the
    // managed machine. Attempt every exact durable gateway even if one managed
    // machine stop failed; no cleanup begins until both stop passes finish.
    let gateways = backend.stop_verified_compatibility_gateways();
    result.verified_compatibility_gateways_found = gateways.exact_gateways_found;
    result.verified_compatibility_gateways_stopped = gateways.exact_gateways_stopped;
    if gateways.retained_ambiguities > 0 {
        result.retain(ProductUninstallRetainedItem::new(
            "compatibility_gateway_state",
            "ambiguous_gateway_state_preserved",
        ));
    }
    if gateways.exact_stop_failures > 0 {
        contact_not_stopped = true;
        result.retain(ProductUninstallRetainedItem::new(
            "verified_compatibility_gateway",
            "target_contact_not_stopped",
        ));
    }
    if gateways.contact_inventory_incomplete {
        contact_not_stopped = true;
        result.retain(ProductUninstallRetainedItem::new(
            "compatibility_gateway_state",
            "target_contact_inventory_incomplete",
        ));
    }
    if contact_not_stopped {
        result.finish(true);
        return Ok(result);
    }

    if request.mode != ProductUninstallMode::AppOnly
        && (gateways.exact_gateways_found > 0 || gateways.retained_ambiguities > 0)
    {
        // Docker/Podman compatibility images live in a provider-wide cache.
        // The product cannot prove that another container or user does not use
        // the same immutable image, so scan-tool removal leaves that shared
        // cache untouched and says so instead of claiming a complete purge.
        result.retain(ProductUninstallRetainedItem::new(
            "compatibility_provider_image",
            "shared_provider_image_cache_preserved",
        ));
    }

    if request.mode != ProductUninstallMode::AppOnly {
        let retained_before_runtime_removal = result.retained_items.len();
        for manifest_sha256 in &inventory.verified_manifest_sha256 {
            if backend.remove_verified_runtime(manifest_sha256) {
                result.verified_runtimes_removed += 1;
            } else {
                result.retain(ProductUninstallRetainedItem::new(
                    "verified_runtime",
                    "runtime_removal_incomplete",
                ));
            }
        }
        let runtime_residue = backend.cleanup_scan_tool_residue();
        for retained in runtime_residue {
            result.retain(retained);
        }
        if result.verified_runtimes_removed == result.verified_runtimes_found
            && result.retained_items.len() == retained_before_runtime_removal
            && !result.retained_items.iter().any(|item| {
                matches!(
                    item.item_class,
                    "managed_runtime_state"
                        | "managed_runtime_entry"
                        | "verified_runtime"
                        | "compatibility_gateway_state"
                        | "verified_compatibility_gateway"
                        | "compatibility_provider_image"
                )
            })
        {
            result.removed.push("verified_scan_tools");
        } else {
            result
                .preserved
                .push("ambiguous_or_unremoved_scan_tool_state");
        }
    }

    if request.mode == ProductUninstallMode::AllData {
        // Ambiguous compatibility-gateway records are the only durable clue
        // that a legacy or replaced object was deliberately left untouched.
        // An all-data choice is authority to remove verified product data, not
        // authority to erase the record of an object we could not classify.
        let preserve_compatibility_gateway_state = result.retained_items.iter().any(|item| {
            matches!(
                item.item_class,
                "compatibility_gateway_state" | "verified_compatibility_gateway"
            )
        });
        let user_data_residue =
            backend.cleanup_all_product_user_data(preserve_compatibility_gateway_state);
        let user_data_complete = user_data_residue.is_empty();
        for retained in user_data_residue {
            result.retain(retained);
        }
        if user_data_complete {
            result.removed.push("product_user_data");
        }
    }
    result.finish(false);
    Ok(result)
}

#[derive(Debug)]
pub struct LocalProductUninstallBackend {
    data_root: PathBuf,
    verified_digests: BTreeSet<String>,
}

impl LocalProductUninstallBackend {
    pub fn new(data_root: PathBuf) -> Self {
        Self {
            data_root,
            verified_digests: BTreeSet::new(),
        }
    }

    fn managed_root(&self) -> PathBuf {
        self.data_root.join(MANAGED_RUNTIME_DIRECTORY)
    }

    fn compatibility_network_registry(&self) -> Result<Option<ManagedNetworkRegistry>, ()> {
        let artifact_root = self.data_root.join(ARTIFACT_DIRECTORY);
        let registry_root = artifact_root.join(MANAGED_NETWORK_REGISTRY_DIRECTORY);
        let mut guards = Vec::new();
        for path in [&artifact_root, &registry_root] {
            match fs::symlink_metadata(path) {
                Ok(_) => guards.push(open_directory_no_follow(path).map_err(|_| ())?),
                Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(None),
                _ => return Err(()),
            }
        }
        // ManagedNetworkRegistry binds both roots by canonical parent
        // relationship. Canonicalize them together here so Windows' verbatim
        // path representation cannot turn the normal LocalAppData path into a
        // false ambiguity.
        let artifact_root = artifact_root.canonicalize().map_err(|_| ())?;
        let registry_root = registry_root.canonicalize().map_err(|_| ())?;
        let result = ManagedNetworkRegistry::new(&registry_root, &artifact_root)
            .map(Some)
            .map_err(|_| ());
        drop(guards);
        result
    }

    fn inspect_remaining_runtime_state(&self) -> Vec<ProductUninstallRetainedItem> {
        let root = self.managed_root();
        let mut retained = Vec::new();
        let root_guard = match open_directory_no_follow(&root) {
            Ok(guard) => guard,
            Err(error) if error.kind() == io::ErrorKind::NotFound => return retained,
            Err(_) => {
                retained.push(ProductUninstallRetainedItem::new(
                    "managed_runtime_state",
                    "ambiguous_runtime_root_preserved",
                ));
                return retained;
            }
        };

        // Managers have dropped their lifecycle lock before this method runs.
        // Removing this one exact regular lock file cannot widen runtime
        // ownership. Other regular files remain preserved unless a manager
        // already removed them under an exact manifest contract.
        let lifecycle_lock = root.join(MANAGED_RUNTIME_LIFECYCLE_LOCK);
        if let Ok(lock_guard) = open_file_no_follow(&lifecycle_lock) {
            drop(lock_guard);
            let _ = fs::remove_file(&lifecycle_lock);
        }
        for child in [
            MANAGED_RUNTIME_VERSIONS_DIRECTORY,
            MANAGED_RUNTIME_PROVIDER_DIRECTORY,
            "machine-images",
            "wsl-ownership",
            "wsl-generations",
            "wsl-recovery",
            "wsl-recovery-workspaces",
            "wsl-legacy-retained",
        ] {
            // Reject every reparse form before a single non-recursive removal.
            // This preserves even unusual Windows directory reparse points
            // instead of relying only on FileType::is_symlink.
            let child_path = root.join(child);
            match fs::symlink_metadata(&child_path) {
                Err(error) if error.kind() == io::ErrorKind::NotFound => {}
                Ok(_) => match open_directory_no_follow(&child_path) {
                    Ok(child_guard) => {
                        drop(child_guard);
                        let _ = fs::remove_dir(&child_path);
                    }
                    Err(_) => retained.push(ProductUninstallRetainedItem::new(
                        "managed_runtime_entry",
                        "ambiguous_runtime_entry_preserved",
                    )),
                },
                Err(_) => retained.push(ProductUninstallRetainedItem::new(
                    "managed_runtime_entry",
                    "runtime_entry_inventory_unavailable",
                )),
            }
        }
        drop(root_guard);
        let _ = fs::remove_dir(&root);
        if fs::symlink_metadata(&root).is_ok() {
            let has_entries_or_is_unreadable = fs::read_dir(&root)
                .map(|mut entries| entries.next().is_some())
                .unwrap_or(true);
            if has_entries_or_is_unreadable {
                retained.push(ProductUninstallRetainedItem::new(
                    "managed_runtime_state",
                    "ambiguous_runtime_state_preserved",
                ));
            }
        }
        retained
    }
}

impl ProductUninstallBackend for LocalProductUninstallBackend {
    fn inventory_runtimes(&mut self) -> AppResult<ProductRuntimeInventory> {
        let mut inventory = ProductRuntimeInventory::default();
        let managed_root = self.managed_root();
        let versions = managed_root.join(MANAGED_RUNTIME_VERSIONS_DIRECTORY);
        let managed_metadata = match fs::symlink_metadata(&managed_root) {
            Ok(metadata) => metadata,
            Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(inventory),
            Err(_) => {
                inventory.retained.push(ProductUninstallRetainedItem::new(
                    "managed_runtime_state",
                    "runtime_inventory_unavailable",
                ));
                inventory.contact_inventory_incomplete = true;
                return Ok(inventory);
            }
        };
        if managed_metadata.file_type().is_symlink() || !managed_metadata.is_dir() {
            inventory.retained.push(ProductUninstallRetainedItem::new(
                "managed_runtime_state",
                "ambiguous_runtime_root_preserved",
            ));
            return Ok(inventory);
        }
        let _managed_root_guard = match open_directory_no_follow(&managed_root) {
            Ok(guard) => guard,
            Err(_) => {
                inventory.retained.push(ProductUninstallRetainedItem::new(
                    "managed_runtime_state",
                    "ambiguous_runtime_root_preserved",
                ));
                return Ok(inventory);
            }
        };
        let version_metadata = match fs::symlink_metadata(&versions) {
            Ok(metadata) => metadata,
            Err(error) if error.kind() == io::ErrorKind::NotFound => {
                let provider_root = managed_root.join(MANAGED_RUNTIME_PROVIDER_DIRECTORY);
                match open_directory_no_follow(&provider_root) {
                    Ok(_guard) => {
                        if fs::read_dir(&provider_root)
                            .is_ok_and(|mut entries| entries.next().is_some())
                        {
                            inventory.retained.push(ProductUninstallRetainedItem::new(
                                "managed_runtime_state",
                                "runtime_ownership_unavailable",
                            ));
                        }
                    }
                    Err(error) if error.kind() == io::ErrorKind::NotFound => {}
                    Err(_) => inventory.retained.push(ProductUninstallRetainedItem::new(
                        "managed_runtime_entry",
                        "ambiguous_runtime_entry_preserved",
                    )),
                }
                return Ok(inventory);
            }
            Err(_) => {
                inventory.retained.push(ProductUninstallRetainedItem::new(
                    "managed_runtime_state",
                    "runtime_inventory_unavailable",
                ));
                inventory.contact_inventory_incomplete = true;
                return Ok(inventory);
            }
        };
        if version_metadata.file_type().is_symlink() || !version_metadata.is_dir() {
            inventory.retained.push(ProductUninstallRetainedItem::new(
                "managed_runtime_state",
                "ambiguous_versions_root_preserved",
            ));
            return Ok(inventory);
        }
        let _versions_root_guard = match open_directory_no_follow(&versions) {
            Ok(guard) => guard,
            Err(_) => {
                inventory.retained.push(ProductUninstallRetainedItem::new(
                    "managed_runtime_state",
                    "ambiguous_versions_root_preserved",
                ));
                return Ok(inventory);
            }
        };

        let mut entries = match fs::read_dir(&versions) {
            Ok(entries) => {
                let mut readable = Vec::new();
                for entry in entries {
                    match entry {
                        Ok(entry) => readable.push(entry),
                        Err(_) => inventory.retained.push(ProductUninstallRetainedItem::new(
                            "managed_runtime_entry",
                            "runtime_entry_inventory_unavailable",
                        )),
                    }
                }
                readable
            }
            Err(_) => {
                inventory.retained.push(ProductUninstallRetainedItem::new(
                    "managed_runtime_state",
                    "runtime_inventory_unavailable",
                ));
                inventory.contact_inventory_incomplete = true;
                return Ok(inventory);
            }
        };
        if inventory
            .retained
            .iter()
            .any(|item| item.reason_code == "runtime_entry_inventory_unavailable")
        {
            inventory.contact_inventory_incomplete = true;
        }
        entries.sort_by_key(|entry| entry.file_name());
        if entries.len() > MAX_INSTALLED_RUNTIME_ENTRIES {
            inventory.retained.push(ProductUninstallRetainedItem::new(
                "managed_runtime_state",
                "runtime_inventory_limit_reached",
            ));
            inventory.contact_inventory_incomplete = true;
            entries.truncate(MAX_INSTALLED_RUNTIME_ENTRIES);
        }

        for entry in entries {
            let path = entry.path();
            let exact_digest = (|| -> AppResult<String> {
                let metadata = fs::symlink_metadata(&path)?;
                if metadata.file_type().is_symlink() || !metadata.is_dir() {
                    return Err(AppError::NotAuthorized(
                        "runtime entry is not a real directory".into(),
                    ));
                }
                let digest = bounded_regular_file_sha256(&path.join(MANAGED_RUNTIME_MANIFEST))?;
                ManagedRuntimeManager::open_installed_for_product_uninstall(
                    &self.data_root,
                    &digest,
                )?;
                Ok(digest)
            })();
            match exact_digest {
                Ok(digest) if self.verified_digests.insert(digest.clone()) => {
                    inventory.verified_manifest_sha256.push(digest);
                }
                Ok(_) => {}
                Err(error) => {
                    if matches!(error, AppError::Internal(_)) {
                        inventory.contact_inventory_incomplete = true;
                    }
                    inventory.retained.push(ProductUninstallRetainedItem::new(
                        "managed_runtime_entry",
                        "unverified_runtime_entry_preserved",
                    ));
                }
            }
        }
        inventory.verified_manifest_sha256.sort();
        Ok(inventory)
    }

    fn stop_verified_runtime(&mut self, manifest_sha256: &str) -> bool {
        if !self.verified_digests.contains(manifest_sha256) {
            return false;
        }
        ManagedRuntimeManager::open_installed_for_product_uninstall(
            &self.data_root,
            manifest_sha256,
        )
        .and_then(|manager| manager.stop_for_product_uninstall())
        .is_ok()
    }

    fn stop_verified_compatibility_gateways(&mut self) -> ProductCompatibilityGatewayStopOutcome {
        let registry = match self.compatibility_network_registry() {
            Ok(Some(registry)) => registry,
            Ok(None) => return ProductCompatibilityGatewayStopOutcome::default(),
            Err(()) => {
                return ProductCompatibilityGatewayStopOutcome {
                    retained_ambiguities: 1,
                    contact_inventory_incomplete: true,
                    ..Default::default()
                };
            }
        };
        let summary = registry.stop_verified_compatibility_gateways(Utc::now());
        ProductCompatibilityGatewayStopOutcome {
            exact_gateways_found: summary.exact_gateways_found,
            exact_gateways_stopped: summary.exact_gateways_stopped,
            exact_stop_failures: summary.exact_stop_failures,
            retained_ambiguities: summary.retained_ambiguities,
            contact_inventory_incomplete: summary.contact_inventory_incomplete,
        }
    }

    fn remove_verified_runtime(&mut self, manifest_sha256: &str) -> bool {
        if !self.verified_digests.contains(manifest_sha256) {
            return false;
        }
        ManagedRuntimeManager::open_installed_for_product_uninstall(
            &self.data_root,
            manifest_sha256,
        )
        .and_then(|manager| {
            manager.uninstall(ManagedUninstallOptions {
                stop_mode: ManagedStopMode::Force,
                remove_machine_image_cache: true,
            })
        })
        .is_ok()
    }

    fn cleanup_scan_tool_residue(&mut self) -> Vec<ProductUninstallRetainedItem> {
        let mut retained = self.inspect_remaining_runtime_state();
        match self.compatibility_network_registry() {
            Ok(Some(registry)) => {
                let summary = registry.reconcile_verified_compatibility_gateway_records(Utc::now());
                if summary.incomplete > 0 {
                    retained.push(ProductUninstallRetainedItem::new(
                        "compatibility_gateway_state",
                        "compatibility_gateway_cleanup_incomplete",
                    ));
                }
            }
            Ok(None) => {}
            Err(()) => retained.push(ProductUninstallRetainedItem::new(
                "compatibility_gateway_state",
                "ambiguous_gateway_state_preserved",
            )),
        }
        retained
    }

    fn cleanup_all_product_user_data(
        &mut self,
        preserve_compatibility_gateway_state: bool,
    ) -> Vec<ProductUninstallRetainedItem> {
        remove_bounded_product_data(&self.data_root, preserve_compatibility_gateway_state)
    }
}

/// Confirms that a product-uninstall path is the fixed direct child of the
/// platform local-data directory. This validation occurs before the process
/// lease or any runtime command. An arbitrary global `--data-dir` never reaches
/// this function from the CLI.
pub fn validate_fixed_product_data_root(data_root: &Path, local_data_root: &Path) -> AppResult<()> {
    if !data_root.is_absolute() || !local_data_root.is_absolute() {
        return Err(AppError::NotAuthorized(
            "product-uninstall requires an absolute platform data directory".into(),
        ));
    }
    if data_root.file_name().and_then(|name| name.to_str()) != Some(PRODUCT_DATA_DIRECTORY_NAME)
        || data_root.parent() != Some(local_data_root)
    {
        return Err(AppError::NotAuthorized(
            "product-uninstall refused a noncanonical application-data directory".into(),
        ));
    }
    match fs::symlink_metadata(data_root) {
        Ok(_) => {
            open_directory_no_follow(data_root).map_err(|_| {
                AppError::NotAuthorized(
                    "product-uninstall preserved an application-data path that is not a real, non-reparse directory"
                        .into(),
                )
            })?;
        }
        Err(error) if error.kind() == io::ErrorKind::NotFound => {}
        Err(error) => return Err(error.into()),
    }
    Ok(())
}

/// Creates the one fixed product root when absent and pins that real,
/// non-reparse directory before the caller acquires its process lease.
///
/// Keeping the returned handle alive prevents Windows from replacing the root
/// while uninstall inventory, target-contact stop, and bounded cleanup run. A
/// concurrent desktop that wins the lease race still causes the lease acquire
/// to fail before the coordinator mutates product state.
pub fn prepare_fixed_product_data_root(
    data_root: &Path,
    local_data_root: &Path,
) -> AppResult<(bool, File)> {
    validate_fixed_product_data_root(data_root, local_data_root)?;
    let existed_before = match fs::symlink_metadata(data_root) {
        Ok(_) => true,
        Err(error) if error.kind() == io::ErrorKind::NotFound => match fs::create_dir(data_root) {
            Ok(()) => false,
            Err(error) if error.kind() == io::ErrorKind::AlreadyExists => true,
            Err(error) => return Err(error.into()),
        },
        Err(error) => return Err(error.into()),
    };
    let guard = open_directory_no_follow(data_root).map_err(|_| {
        AppError::NotAuthorized(
            "product-uninstall could not pin the real application-data directory".into(),
        )
    })?;
    Ok((existed_before, guard))
}

/// Atomically moves a fully cleaned canonical product root out of the path
/// used by the desktop while the caller still owns its exclusive lease.
///
/// Dropping the lease and then deleting the canonical root would allow a newly
/// launched process to recreate or write that path between those two steps.
/// Renaming a root that contains exactly the lease sentinel closes that race:
/// any later launch gets a fresh canonical directory, while finalization stays
/// bound to the already isolated empty root. A failed rename is reported and
/// leaves the canonical root untouched.
pub fn stage_all_data_root_for_finalization(
    data_root: &Path,
    lease: &DataDirectoryExclusiveLease,
) -> AppResult<PathBuf> {
    if lease.path() != data_root.join(DATA_DIRECTORY_LEASE_FILE) {
        return Err(AppError::NotAuthorized(
            "all-data finalization requires the exact product-directory lease".into(),
        ));
    }
    let data_root_guard = open_directory_no_follow(data_root).map_err(|_| {
        AppError::NotAuthorized(
            "all-data finalization preserved a non-directory or reparse product root".into(),
        )
    })?;
    let mut entries = fs::read_dir(data_root)?;
    let only = entries.next().transpose()?.ok_or_else(|| {
        AppError::Internal("all-data finalization lost its lease sentinel".into())
    })?;
    let lease_guard = open_file_no_follow(&only.path()).map_err(|error| {
        AppError::NotAvailable(format!(
            "all-data finalization could not recheck its lease sentinel: {error}"
        ))
    })?;
    if entries.next().transpose()?.is_some() || only.file_name() != DATA_DIRECTORY_LEASE_FILE {
        return Err(AppError::NotAvailable(
            "all-data finalization retained product state that was not empty".into(),
        ));
    }
    let parent = data_root.parent().ok_or_else(|| {
        AppError::NotAuthorized("product data root has no local-data parent".into())
    })?;
    let staged = parent.join(format!(
        ".{PRODUCT_DATA_DIRECTORY_NAME}.uninstall-staged-{}",
        uuid::Uuid::new_v4().hyphenated()
    ));
    match fs::symlink_metadata(&staged) {
        Ok(_) => {
            return Err(AppError::NotAvailable(
                "all-data finalization staging path already exists".into(),
            ));
        }
        Err(error) if error.kind() == io::ErrorKind::NotFound => {}
        Err(error) => {
            return Err(AppError::NotAvailable(format!(
                "all-data finalization could not inspect its staging path: {error}"
            )));
        }
    }
    // Windows deliberately denies root replacement while the no-reparse guard
    // is open. The exclusive sentinel remains locked while the exact root is
    // atomically renamed, so another desktop cannot acquire product state in
    // this short handoff.
    drop(lease_guard);
    drop(data_root_guard);
    fs::rename(data_root, &staged).map_err(|error| {
        AppError::NotAvailable(format!(
            "all-data finalization could not isolate the empty product root: {error}"
        ))
    })?;
    Ok(staged)
}

/// Removes the lease sentinel and one already staged empty product root after
/// the coordinator and process lease have both been dropped. A nonempty root
/// is retained. This never traverses or removes the local-data parent.
pub fn finalize_all_data_root(data_root: &Path) -> Vec<ProductUninstallRetainedItem> {
    let mut retained = Vec::new();
    let root_guard = match open_directory_no_follow(data_root) {
        Ok(guard) => guard,
        Err(error) if error.kind() == io::ErrorKind::NotFound => return retained,
        _ => {
            retained.push(ProductUninstallRetainedItem::new(
                "product_data",
                "ambiguous_product_data_root_preserved",
            ));
            return retained;
        }
    };
    let lease = data_root.join(DATA_DIRECTORY_LEASE_FILE);
    match open_file_no_follow(&lease) {
        Ok(lease_guard) => {
            drop(lease_guard);
            if fs::remove_file(&lease).is_err() {
                retained.push(ProductUninstallRetainedItem::new(
                    "product_data",
                    "lease_file_removal_incomplete",
                ));
            }
        }
        Err(error) if error.kind() == io::ErrorKind::NotFound => {}
        Err(_) => retained.push(ProductUninstallRetainedItem::new(
            "product_data",
            "ambiguous_lease_entry_preserved",
        )),
    }
    drop(root_guard);
    match fs::remove_dir(data_root) {
        Ok(()) => {}
        Err(error) if error.kind() == io::ErrorKind::NotFound => {}
        Err(_) => retained.push(ProductUninstallRetainedItem::new(
            "product_data",
            "product_data_root_retained",
        )),
    }
    retained
}

fn bounded_regular_file_sha256(path: &Path) -> AppResult<String> {
    let metadata = fs::symlink_metadata(path)?;
    if metadata.file_type().is_symlink()
        || !metadata.is_file()
        || metadata.len() == 0
        || metadata.len() > MAX_RUNTIME_MANIFEST_BYTES
    {
        return Err(AppError::NotAuthorized(
            "managed runtime manifest is not one bounded regular file".into(),
        ));
    }
    let mut file = open_file_no_follow(path)?;
    let opened = file.metadata()?;
    if !opened.is_file() || opened.len() != metadata.len() {
        return Err(AppError::NotAuthorized(
            "managed runtime manifest changed during exact inventory".into(),
        ));
    }
    let mut bytes = Vec::with_capacity(opened.len() as usize);
    file.by_ref()
        .take(MAX_RUNTIME_MANIFEST_BYTES + 1)
        .read_to_end(&mut bytes)?;
    if bytes.len() as u64 != opened.len() || bytes.len() as u64 > MAX_RUNTIME_MANIFEST_BYTES {
        return Err(AppError::NotAuthorized(
            "managed runtime manifest changed during bounded inventory".into(),
        ));
    }
    Ok(hex::encode(Sha256::digest(bytes)))
}

fn open_file_no_follow(path: &Path) -> io::Result<File> {
    let mut options = OpenOptions::new();
    options.read(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.custom_flags(libc::O_NOFOLLOW);
    }
    #[cfg(windows)]
    {
        use std::os::windows::fs::{MetadataExt, OpenOptionsExt};
        use windows_sys::Win32::Storage::FileSystem::{
            FILE_ATTRIBUTE_REPARSE_POINT, FILE_FLAG_OPEN_REPARSE_POINT, FILE_SHARE_READ,
            FILE_SHARE_WRITE,
        };
        // Other readers/writers may finish, but replacement/rename is denied
        // while this inspection handle is alive.
        options.share_mode(FILE_SHARE_READ | FILE_SHARE_WRITE);
        options.custom_flags(FILE_FLAG_OPEN_REPARSE_POINT);
        let file = options.open(path)?;
        let metadata = file.metadata()?;
        if !metadata.is_file() || metadata.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT != 0 {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "file is not one real non-reparse regular file",
            ));
        }
        return Ok(file);
    }
    #[cfg(not(windows))]
    {
        let file = options.open(path)?;
        if !file.metadata()?.is_file() {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "file is not one real regular file",
            ));
        }
        Ok(file)
    }
}

fn open_directory_no_follow(path: &Path) -> io::Result<File> {
    let mut options = OpenOptions::new();
    options.read(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.custom_flags(libc::O_DIRECTORY | libc::O_NOFOLLOW);
    }
    #[cfg(windows)]
    {
        use std::os::windows::fs::{MetadataExt, OpenOptionsExt};
        use windows_sys::Win32::Storage::FileSystem::{
            FILE_ATTRIBUTE_REPARSE_POINT, FILE_FLAG_BACKUP_SEMANTICS, FILE_FLAG_OPEN_REPARSE_POINT,
            FILE_SHARE_READ, FILE_SHARE_WRITE,
        };
        options
            .share_mode(FILE_SHARE_READ | FILE_SHARE_WRITE)
            .custom_flags(FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT);
        let directory = options.open(path)?;
        let metadata = directory.metadata()?;
        if !metadata.is_dir() || metadata.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT != 0 {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "directory is not one real non-reparse directory",
            ));
        }
        return Ok(directory);
    }
    #[cfg(not(windows))]
    {
        let directory = options.open(path)?;
        if !directory.metadata()?.is_dir() {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "directory is not one real directory",
            ));
        }
        Ok(directory)
    }
}

struct CleanupBudget {
    remaining_entries: usize,
    deadline: Instant,
}

impl CleanupBudget {
    fn consume(&mut self) -> bool {
        if self.remaining_entries == 0 || Instant::now() >= self.deadline {
            return false;
        }
        self.remaining_entries -= 1;
        true
    }
}

fn remove_bounded_product_data(
    data_root: &Path,
    preserve_compatibility_gateway_state: bool,
) -> Vec<ProductUninstallRetainedItem> {
    let mut retained = Vec::new();
    match fs::symlink_metadata(data_root) {
        Ok(metadata) if metadata.is_dir() && !metadata.file_type().is_symlink() => {}
        Err(error) if error.kind() == io::ErrorKind::NotFound => return retained,
        _ => {
            retained.push(ProductUninstallRetainedItem::new(
                "product_data",
                "ambiguous_product_data_root_preserved",
            ));
            return retained;
        }
    }
    let mut budget = CleanupBudget {
        remaining_entries: MAX_PRODUCT_DATA_ENTRIES,
        deadline: Instant::now() + PRODUCT_DATA_CLEANUP_TIMEOUT,
    };
    let preserved_gateway_registry = preserve_compatibility_gateway_state.then(|| {
        data_root
            .join(ARTIFACT_DIRECTORY)
            .join(MANAGED_NETWORK_REGISTRY_DIRECTORY)
    });
    let root_guard = match open_directory_no_follow(data_root) {
        Ok(guard) => guard,
        Err(_) => {
            retained.push(ProductUninstallRetainedItem::new(
                "product_data",
                "ambiguous_product_data_root_preserved",
            ));
            return retained;
        }
    };
    let entries = match fs::read_dir(data_root) {
        Ok(entries) => entries.filter_map(Result::ok).collect::<Vec<_>>(),
        Err(error) if error.kind() == io::ErrorKind::NotFound => return retained,
        Err(_) => {
            retained.push(ProductUninstallRetainedItem::new(
                "product_data",
                "product_data_inventory_failed",
            ));
            return retained;
        }
    };
    for entry in entries {
        let name = entry.file_name();
        if name == MANAGED_RUNTIME_DIRECTORY || name == DATA_DIRECTORY_LEASE_FILE {
            continue;
        }
        remove_bounded_entry(
            &entry.path(),
            preserved_gateway_registry.as_deref(),
            0,
            &mut budget,
            &mut retained,
        );
    }
    drop(root_guard);
    retained
}

fn remove_bounded_entry(
    path: &Path,
    preserved_exact_path: Option<&Path>,
    depth: usize,
    budget: &mut CleanupBudget,
    retained: &mut Vec<ProductUninstallRetainedItem>,
) -> bool {
    if preserved_exact_path == Some(path) {
        push_retained_bounded(
            retained,
            ProductUninstallRetainedItem::new(
                "compatibility_gateway_state",
                "ambiguous_gateway_state_preserved",
            ),
        );
        return false;
    }
    if depth > MAX_PRODUCT_DATA_DEPTH || !budget.consume() {
        push_retained_bounded(
            retained,
            ProductUninstallRetainedItem::new("product_data", "cleanup_bound_reached"),
        );
        return false;
    }
    let metadata = match fs::symlink_metadata(path) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == io::ErrorKind::NotFound => return true,
        Err(_) => {
            push_retained_bounded(
                retained,
                ProductUninstallRetainedItem::new("product_data", "data_entry_inspection_failed"),
            );
            return false;
        }
    };
    if metadata.file_type().is_symlink() {
        push_retained_bounded(
            retained,
            ProductUninstallRetainedItem::new("product_data", "ambiguous_link_preserved"),
        );
        return false;
    }
    if metadata.is_file() {
        if fs::remove_file(path).is_ok() {
            return true;
        }
        push_retained_bounded(
            retained,
            ProductUninstallRetainedItem::new("product_data", "data_file_removal_incomplete"),
        );
        return false;
    }
    if !metadata.is_dir() {
        push_retained_bounded(
            retained,
            ProductUninstallRetainedItem::new("product_data", "special_entry_preserved"),
        );
        return false;
    }

    // Keep a no-reparse directory handle open while enumerating and visiting
    // children. On Windows the handle deliberately withholds delete sharing,
    // so a junction/reparse swap cannot occur between the type check and
    // traversal. It is dropped only before the final non-recursive `remove_dir`.
    let directory_guard = match open_directory_no_follow(path) {
        Ok(guard) => guard,
        Err(_) => {
            push_retained_bounded(
                retained,
                ProductUninstallRetainedItem::new(
                    "product_data",
                    "ambiguous_or_replaced_directory_preserved",
                ),
            );
            return false;
        }
    };

    let entries = match fs::read_dir(path) {
        Ok(entries) => entries.filter_map(Result::ok).collect::<Vec<_>>(),
        Err(_) => {
            push_retained_bounded(
                retained,
                ProductUninstallRetainedItem::new("product_data", "data_tree_inventory_failed"),
            );
            return false;
        }
    };
    let mut complete = true;
    for entry in entries {
        complete &= remove_bounded_entry(
            &entry.path(),
            preserved_exact_path,
            depth + 1,
            budget,
            retained,
        );
    }
    drop(directory_guard);
    if complete && fs::remove_dir(path).is_ok() {
        true
    } else {
        if complete {
            push_retained_bounded(
                retained,
                ProductUninstallRetainedItem::new(
                    "product_data",
                    "data_directory_removal_incomplete",
                ),
            );
        }
        false
    }
}

fn push_retained_bounded(
    retained: &mut Vec<ProductUninstallRetainedItem>,
    item: ProductUninstallRetainedItem,
) {
    if retained.len() < MAX_RETAINED_ITEMS {
        retained.push(item);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeMap;

    #[cfg(windows)]
    fn create_windows_directory_junction(link: &Path, target: &Path) {
        use std::process::Command;

        let command = PathBuf::from(std::env::var_os("SystemRoot").expect("SystemRoot"))
            .join("System32")
            .join("cmd.exe");
        let output = Command::new(command)
            .arg("/d")
            .arg("/c")
            .arg(format!(
                "mklink /J \"{}\" \"{}\"",
                link.display(),
                target.display()
            ))
            .output()
            .expect("create Windows junction fixture");
        assert!(
            output.status.success(),
            "mklink fixture failed: {}",
            String::from_utf8_lossy(&output.stderr)
        );
    }

    #[derive(Default)]
    struct FakeBackend {
        runtimes: Vec<String>,
        retained: Vec<ProductUninstallRetainedItem>,
        contact_inventory_incomplete: bool,
        stop: BTreeMap<String, bool>,
        gateway_stop: ProductCompatibilityGatewayStopOutcome,
        remove: BTreeMap<String, bool>,
        calls: Vec<String>,
        scan_tool_residue: Vec<ProductUninstallRetainedItem>,
        user_data_residue: Vec<ProductUninstallRetainedItem>,
        preserve_gateway_state_on_user_cleanup: Option<bool>,
    }

    impl ProductUninstallBackend for FakeBackend {
        fn inventory_runtimes(&mut self) -> AppResult<ProductRuntimeInventory> {
            self.calls.push("inventory".into());
            Ok(ProductRuntimeInventory {
                verified_manifest_sha256: self.runtimes.clone(),
                retained: self.retained.clone(),
                contact_inventory_incomplete: self.contact_inventory_incomplete,
            })
        }

        fn stop_verified_runtime(&mut self, manifest_sha256: &str) -> bool {
            self.calls.push(format!("stop:{manifest_sha256}"));
            self.stop.get(manifest_sha256).copied().unwrap_or(true)
        }

        fn stop_verified_compatibility_gateways(
            &mut self,
        ) -> ProductCompatibilityGatewayStopOutcome {
            self.calls.push("stop_gateways".into());
            self.gateway_stop.clone()
        }

        fn remove_verified_runtime(&mut self, manifest_sha256: &str) -> bool {
            self.calls.push(format!("remove:{manifest_sha256}"));
            self.remove.get(manifest_sha256).copied().unwrap_or(true)
        }

        fn cleanup_scan_tool_residue(&mut self) -> Vec<ProductUninstallRetainedItem> {
            self.calls.push("cleanup_scan_tools".into());
            self.scan_tool_residue.clone()
        }

        fn cleanup_all_product_user_data(
            &mut self,
            preserve_compatibility_gateway_state: bool,
        ) -> Vec<ProductUninstallRetainedItem> {
            self.calls.push("cleanup_user_data".into());
            self.preserve_gateway_state_on_user_cleanup =
                Some(preserve_compatibility_gateway_state);
            self.user_data_residue.clone()
        }
    }

    fn request(mode: ProductUninstallMode) -> ProductUninstallRequest {
        ProductUninstallRequest {
            mode,
            non_interactive: true,
            confirmation: (mode == ProductUninstallMode::AllData)
                .then(|| ALL_DATA_CONFIRMATION.into()),
        }
    }

    #[test]
    fn exact_all_data_confirmation_is_required_before_inventory_or_mutation() {
        let mut backend = FakeBackend::default();
        let mut invalid = request(ProductUninstallMode::AllData);
        invalid.confirmation = Some("remove everything".into());
        assert!(coordinate_product_uninstall(&invalid, &mut backend).is_err());
        assert!(backend.calls.is_empty());

        let mut extra = request(ProductUninstallMode::ScanTools);
        extra.confirmation = Some(ALL_DATA_CONFIRMATION.into());
        assert!(coordinate_product_uninstall(&extra, &mut backend).is_err());
        assert!(backend.calls.is_empty());
    }

    #[test]
    fn app_only_stops_all_verified_runtimes_and_preserves_every_data_class() {
        let mut backend = FakeBackend {
            runtimes: vec!["a".repeat(64), "b".repeat(64)],
            ..Default::default()
        };
        let result =
            coordinate_product_uninstall(&request(ProductUninstallMode::AppOnly), &mut backend)
                .unwrap();
        assert_eq!(result.result_class, ProductUninstallResultClass::Completed);
        assert_eq!(result.exit_code, 0);
        assert_eq!(result.verified_runtimes_stopped, 2);
        assert_eq!(result.verified_runtimes_removed, 0);
        assert!(result.preserved.contains(&"managed_scan_tools"));
        assert_eq!(
            backend.calls,
            vec![
                "inventory",
                &format!("stop:{}", "a".repeat(64)),
                &format!("stop:{}", "b".repeat(64)),
                "stop_gateways",
            ]
        );
    }

    #[test]
    fn one_failed_stop_attempts_every_verified_runtime_then_aborts_before_cleanup() {
        let first = "a".repeat(64);
        let second = "b".repeat(64);
        let mut backend = FakeBackend {
            runtimes: vec![first.clone(), second.clone()],
            stop: BTreeMap::from([(first.clone(), false)]),
            ..Default::default()
        };
        let result =
            coordinate_product_uninstall(&request(ProductUninstallMode::AllData), &mut backend)
                .unwrap();
        assert_eq!(
            result.result_class,
            ProductUninstallResultClass::ContactNotStopped
        );
        assert_eq!(result.exit_code, 20);
        assert_eq!(result.verified_runtimes_stopped, 1);
        assert!(backend.calls.contains(&format!("stop:{second}")));
        assert!(backend.calls.contains(&"stop_gateways".into()));
        assert!(!backend.calls.iter().any(|call| call.starts_with("remove:")));
        assert!(!backend.calls.contains(&"cleanup_scan_tools".into()));
        assert!(!backend.calls.contains(&"cleanup_user_data".into()));
    }

    #[test]
    fn incomplete_runtime_inventory_retains_the_controller_before_any_cleanup() {
        let digest = "9".repeat(64);
        let mut backend = FakeBackend {
            runtimes: vec![digest.clone()],
            contact_inventory_incomplete: true,
            ..Default::default()
        };

        let result =
            coordinate_product_uninstall(&request(ProductUninstallMode::AllData), &mut backend)
                .unwrap();

        assert_eq!(result.exit_code, 20);
        assert!(backend.calls.contains(&format!("stop:{digest}")));
        assert!(backend.calls.contains(&"stop_gateways".into()));
        assert!(!backend.calls.contains(&"cleanup_scan_tools".into()));
        assert!(!backend.calls.contains(&"cleanup_user_data".into()));
        assert!(result.retained_items.iter().any(|item| {
            item.item_class == "managed_runtime_state"
                && item.reason_code == "target_contact_inventory_incomplete"
        }));
    }

    #[test]
    fn scan_tools_preserves_user_data_and_reports_incomplete_exact_removal() {
        let digest = "c".repeat(64);
        let mut backend = FakeBackend {
            runtimes: vec![digest.clone()],
            remove: BTreeMap::from([(digest, false)]),
            ..Default::default()
        };
        let result =
            coordinate_product_uninstall(&request(ProductUninstallMode::ScanTools), &mut backend)
                .unwrap();
        assert_eq!(
            result.result_class,
            ProductUninstallResultClass::CompletedWithRetainedState
        );
        assert_eq!(result.exit_code, 10);
        assert!(
            result
                .preserved
                .contains(&"projects_findings_evidence_and_exports")
        );
        assert!(!result.removed.contains(&"verified_scan_tools"));
        assert!(
            result
                .preserved
                .contains(&"ambiguous_or_unremoved_scan_tool_state")
        );
        assert!(!backend.calls.contains(&"cleanup_user_data".into()));
    }

    #[test]
    fn exact_gateway_stop_failure_is_exit_twenty_and_prevents_every_cleanup() {
        let mut backend = FakeBackend {
            gateway_stop: ProductCompatibilityGatewayStopOutcome {
                exact_gateways_found: 2,
                exact_gateways_stopped: 1,
                exact_stop_failures: 1,
                retained_ambiguities: 0,
                contact_inventory_incomplete: false,
            },
            ..Default::default()
        };

        let result =
            coordinate_product_uninstall(&request(ProductUninstallMode::AllData), &mut backend)
                .unwrap();

        assert_eq!(result.exit_code, 20);
        assert_eq!(result.verified_compatibility_gateways_found, 2);
        assert_eq!(result.verified_compatibility_gateways_stopped, 1);
        assert_eq!(backend.calls, vec!["inventory", "stop_gateways"]);
        assert!(!backend.calls.contains(&"cleanup_scan_tools".into()));
        assert!(!backend.calls.contains(&"cleanup_user_data".into()));
    }

    #[test]
    fn incomplete_gateway_inventory_retains_the_controller_before_any_cleanup() {
        let mut backend = FakeBackend {
            gateway_stop: ProductCompatibilityGatewayStopOutcome {
                retained_ambiguities: 1,
                contact_inventory_incomplete: true,
                ..Default::default()
            },
            ..Default::default()
        };

        let result =
            coordinate_product_uninstall(&request(ProductUninstallMode::ScanTools), &mut backend)
                .unwrap();

        assert_eq!(result.exit_code, 20);
        assert_eq!(backend.calls, vec!["inventory", "stop_gateways"]);
        assert!(!backend.calls.contains(&"cleanup_scan_tools".into()));
        assert!(result.retained_items.iter().any(|item| {
            item.item_class == "compatibility_gateway_state"
                && item.reason_code == "target_contact_inventory_incomplete"
        }));
    }

    #[test]
    fn ambiguous_gateway_state_is_exit_ten_but_does_not_block_safe_cleanup() {
        let mut backend = FakeBackend {
            gateway_stop: ProductCompatibilityGatewayStopOutcome {
                retained_ambiguities: 1,
                ..Default::default()
            },
            ..Default::default()
        };

        let result =
            coordinate_product_uninstall(&request(ProductUninstallMode::ScanTools), &mut backend)
                .unwrap();

        assert_eq!(result.exit_code, 10);
        assert!(backend.calls.contains(&"cleanup_scan_tools".into()));
        assert!(!result.removed.contains(&"verified_scan_tools"));
        assert!(
            result
                .preserved
                .contains(&"ambiguous_or_unremoved_scan_tool_state")
        );
        assert!(result.retained_items.iter().any(|item| {
            item.item_class == "compatibility_gateway_state"
                && item.reason_code == "ambiguous_gateway_state_preserved"
        }));
    }

    #[test]
    fn all_data_preserves_the_record_for_ambiguous_gateway_state() {
        let mut backend = FakeBackend {
            gateway_stop: ProductCompatibilityGatewayStopOutcome {
                retained_ambiguities: 1,
                ..Default::default()
            },
            ..Default::default()
        };

        let result =
            coordinate_product_uninstall(&request(ProductUninstallMode::AllData), &mut backend)
                .unwrap();

        assert_eq!(result.exit_code, 10);
        assert_eq!(backend.preserve_gateway_state_on_user_cleanup, Some(true));
        assert!(result.retained_items.iter().any(|item| {
            item.item_class == "compatibility_gateway_state"
                && item.reason_code == "ambiguous_gateway_state_preserved"
        }));
    }

    #[test]
    fn retained_user_data_is_not_reported_as_removed() {
        let mut backend = FakeBackend {
            user_data_residue: vec![ProductUninstallRetainedItem::new(
                "product_data",
                "ambiguous_link_preserved",
            )],
            ..Default::default()
        };

        let result =
            coordinate_product_uninstall(&request(ProductUninstallMode::AllData), &mut backend)
                .unwrap();

        assert_eq!(result.exit_code, 10);
        assert!(!result.removed.contains(&"product_user_data"));
    }

    #[test]
    fn failed_root_finalization_retracts_a_completed_user_data_claim() {
        let mut backend = FakeBackend::default();
        let mut result =
            coordinate_product_uninstall(&request(ProductUninstallMode::AllData), &mut backend)
                .unwrap();
        assert!(result.removed.contains(&"product_user_data"));

        result.record_finalization_retained("product_data", "product_data_root_retained");

        assert_eq!(result.exit_code, 10);
        assert!(!result.removed.contains(&"product_user_data"));
        assert!(result.preserved.contains(&"unremoved_product_user_data"));
    }

    #[test]
    fn ambiguous_runtime_state_is_reported_but_does_not_block_an_exact_stop() {
        let digest = "e".repeat(64);
        let mut backend = FakeBackend {
            runtimes: vec![digest.clone()],
            retained: vec![ProductUninstallRetainedItem::new(
                "managed_runtime_entry",
                "unverified_runtime_entry_preserved",
            )],
            ..Default::default()
        };

        let result =
            coordinate_product_uninstall(&request(ProductUninstallMode::AppOnly), &mut backend)
                .unwrap();

        assert_eq!(result.exit_code, 10);
        assert_eq!(result.verified_runtimes_stopped, 1);
        assert!(backend.calls.contains(&format!("stop:{digest}")));
        assert_eq!(
            result.retained_items[0].reason_code,
            "unverified_runtime_entry_preserved"
        );
    }

    #[test]
    fn successful_all_data_runs_stop_then_runtime_removal_then_user_cleanup() {
        let first = "f".repeat(64);
        let second = "1".repeat(64);
        let mut backend = FakeBackend {
            runtimes: vec![first.clone(), second.clone()],
            ..Default::default()
        };

        let result =
            coordinate_product_uninstall(&request(ProductUninstallMode::AllData), &mut backend)
                .unwrap();

        assert_eq!(result.exit_code, 0);
        assert_eq!(result.verified_runtimes_removed, 2);
        let last_stop = backend
            .calls
            .iter()
            .rposition(|call| call.starts_with("stop:"))
            .unwrap();
        let gateway_stop = backend
            .calls
            .iter()
            .position(|call| call == "stop_gateways")
            .unwrap();
        let first_remove = backend
            .calls
            .iter()
            .position(|call| call.starts_with("remove:"))
            .unwrap();
        let user_cleanup = backend
            .calls
            .iter()
            .position(|call| call == "cleanup_user_data")
            .unwrap();
        assert!(
            last_stop < gateway_stop && gateway_stop < first_remove && first_remove < user_cleanup
        );
    }

    #[test]
    fn corrupt_case_database_is_never_opened_before_runtime_stop() {
        let temporary = tempfile::tempdir().unwrap();
        fs::write(temporary.path().join("casework.db"), b"not sqlite").unwrap();
        let mut backend = FakeBackend {
            runtimes: vec!["d".repeat(64)],
            ..Default::default()
        };
        let result =
            coordinate_product_uninstall(&request(ProductUninstallMode::AppOnly), &mut backend)
                .unwrap();
        assert_eq!(result.verified_runtimes_stopped, 1);
        assert_eq!(
            fs::read(temporary.path().join("casework.db")).unwrap(),
            b"not sqlite"
        );
    }

    #[test]
    fn all_data_keeps_ambiguous_gateway_records_while_removing_other_product_data() {
        let temporary = tempfile::tempdir().unwrap();
        let root = temporary.path().join(PRODUCT_DATA_DIRECTORY_NAME);
        let registry = root
            .join(ARTIFACT_DIRECTORY)
            .join(MANAGED_NETWORK_REGISTRY_DIRECTORY);
        fs::create_dir_all(&registry).unwrap();
        fs::write(registry.join("must-remain"), b"ambiguous gateway record").unwrap();
        fs::write(root.join("casework.db"), b"product data").unwrap();

        let retained = remove_bounded_product_data(&root, true);

        assert!(!root.join("casework.db").exists());
        assert_eq!(
            fs::read(registry.join("must-remain")).unwrap(),
            b"ambiguous gateway record"
        );
        assert!(retained.iter().any(|item| {
            item.item_class == "compatibility_gateway_state"
                && item.reason_code == "ambiguous_gateway_state_preserved"
        }));
    }

    #[cfg(unix)]
    #[test]
    fn all_data_cleanup_does_not_follow_or_remove_an_ambiguous_link() {
        use std::os::unix::fs::symlink;

        let temporary = tempfile::tempdir().unwrap();
        let root = temporary.path().join(PRODUCT_DATA_DIRECTORY_NAME);
        let outside = temporary.path().join("outside");
        fs::create_dir(&root).unwrap();
        fs::create_dir(&outside).unwrap();
        fs::write(outside.join("must-remain"), b"user data").unwrap();
        fs::write(root.join("casework.db"), b"corrupt but product-owned").unwrap();
        symlink(&outside, root.join("linked-user-data")).unwrap();

        let retained = remove_bounded_product_data(&root, false);
        assert!(!root.join("casework.db").exists());
        assert!(root.join("linked-user-data").exists());
        assert_eq!(fs::read(outside.join("must-remain")).unwrap(), b"user data");
        assert!(
            retained
                .iter()
                .any(|item| item.reason_code == "ambiguous_link_preserved")
        );
    }

    #[test]
    fn fixed_product_root_validation_rejects_a_sibling_or_nested_override() {
        let temporary = tempfile::tempdir().unwrap();
        let expected = temporary.path().join(PRODUCT_DATA_DIRECTORY_NAME);
        assert!(validate_fixed_product_data_root(&expected, temporary.path()).is_ok());
        assert!(
            validate_fixed_product_data_root(
                &temporary.path().join("some-other-product"),
                temporary.path(),
            )
            .is_err()
        );
        assert!(
            validate_fixed_product_data_root(
                &expected.join(PRODUCT_DATA_DIRECTORY_NAME),
                temporary.path(),
            )
            .is_err()
        );
    }

    #[test]
    fn newly_created_product_root_is_pinned_and_always_leased() {
        let temporary = tempfile::tempdir().unwrap();
        let root = temporary.path().join(PRODUCT_DATA_DIRECTORY_NAME);

        let (existed_before, guard) =
            prepare_fixed_product_data_root(&root, temporary.path()).unwrap();
        assert!(!existed_before);
        let first = DataDirectoryExclusiveLease::acquire(&root).unwrap();
        assert!(matches!(
            DataDirectoryExclusiveLease::acquire(&root),
            Err(AppError::NotAvailable(_))
        ));

        drop(guard);
        drop(first);
        assert!(root.exists());
    }

    #[cfg(unix)]
    #[test]
    fn fixed_product_root_rejects_a_link_before_creating_its_lease() {
        use std::os::unix::fs::symlink;

        let temporary = tempfile::tempdir().unwrap();
        let outside = temporary.path().join("outside");
        let root = temporary.path().join(PRODUCT_DATA_DIRECTORY_NAME);
        fs::create_dir(&outside).unwrap();
        symlink(&outside, &root).unwrap();

        assert!(prepare_fixed_product_data_root(&root, temporary.path()).is_err());
        assert!(!outside.join(DATA_DIRECTORY_LEASE_FILE).exists());
    }

    #[cfg(windows)]
    #[test]
    fn fixed_product_root_rejects_a_windows_junction_before_creating_its_lease() {
        let temporary = tempfile::tempdir().unwrap();
        let outside = temporary.path().join("outside");
        let root = temporary.path().join(PRODUCT_DATA_DIRECTORY_NAME);
        fs::create_dir(&outside).unwrap();
        create_windows_directory_junction(&root, &outside);

        assert!(prepare_fixed_product_data_root(&root, temporary.path()).is_err());
        assert!(!outside.join(DATA_DIRECTORY_LEASE_FILE).exists());
    }

    #[test]
    fn over_limit_runtime_inventory_cannot_authorize_cleanup() {
        let temporary = tempfile::tempdir().unwrap();
        let root = temporary.path().join(PRODUCT_DATA_DIRECTORY_NAME);
        let versions = root
            .join(MANAGED_RUNTIME_DIRECTORY)
            .join(MANAGED_RUNTIME_VERSIONS_DIRECTORY);
        fs::create_dir_all(&versions).unwrap();
        for index in 0..=MAX_INSTALLED_RUNTIME_ENTRIES {
            fs::create_dir(versions.join(format!("runtime-{index:02}"))).unwrap();
        }
        let mut backend = LocalProductUninstallBackend::new(root);

        let inventory = backend.inventory_runtimes().unwrap();

        assert!(inventory.contact_inventory_incomplete);
        assert!(inventory.retained.iter().any(|item| {
            item.item_class == "managed_runtime_state"
                && item.reason_code == "runtime_inventory_limit_reached"
        }));
    }

    #[cfg(unix)]
    #[test]
    fn scan_tool_residue_preserves_a_linked_managed_root_and_target() {
        use std::os::unix::fs::symlink;

        let temporary = tempfile::tempdir().unwrap();
        let root = temporary.path().join(PRODUCT_DATA_DIRECTORY_NAME);
        let outside = temporary.path().join("outside-runtime");
        fs::create_dir(&root).unwrap();
        fs::create_dir(&outside).unwrap();
        fs::write(outside.join("must-remain"), b"unrelated").unwrap();
        symlink(&outside, root.join(MANAGED_RUNTIME_DIRECTORY)).unwrap();
        let mut backend = LocalProductUninstallBackend::new(root.clone());

        let retained = backend.cleanup_scan_tool_residue();

        assert!(root.join(MANAGED_RUNTIME_DIRECTORY).exists());
        assert_eq!(fs::read(outside.join("must-remain")).unwrap(), b"unrelated");
        assert!(retained.iter().any(|item| {
            item.item_class == "managed_runtime_state"
                && item.reason_code == "ambiguous_runtime_root_preserved"
        }));
    }

    #[cfg(unix)]
    #[test]
    fn scan_tool_inventory_and_cleanup_preserve_a_linked_provider_home() {
        use std::os::unix::fs::symlink;

        let temporary = tempfile::tempdir().unwrap();
        let root = temporary.path().join(PRODUCT_DATA_DIRECTORY_NAME);
        let managed = root.join(MANAGED_RUNTIME_DIRECTORY);
        let outside = temporary.path().join("outside-provider-home");
        fs::create_dir_all(&managed).unwrap();
        fs::create_dir(&outside).unwrap();
        fs::write(outside.join("must-remain"), b"unrelated").unwrap();
        symlink(&outside, managed.join(MANAGED_RUNTIME_PROVIDER_DIRECTORY)).unwrap();
        let mut backend = LocalProductUninstallBackend::new(root);

        let inventory = backend.inventory_runtimes().unwrap();
        let retained = backend.cleanup_scan_tool_residue();

        assert!(inventory.retained.iter().any(|item| {
            item.item_class == "managed_runtime_entry"
                && item.reason_code == "ambiguous_runtime_entry_preserved"
        }));
        assert!(retained.iter().any(|item| {
            item.item_class == "managed_runtime_entry"
                && item.reason_code == "ambiguous_runtime_entry_preserved"
        }));
        assert_eq!(fs::read(outside.join("must-remain")).unwrap(), b"unrelated");
        assert!(managed.join(MANAGED_RUNTIME_PROVIDER_DIRECTORY).exists());
    }

    #[cfg(windows)]
    #[test]
    fn scan_tool_inventory_and_cleanup_preserve_windows_runtime_junctions() {
        let temporary = tempfile::tempdir().unwrap();
        let root = temporary.path().join(PRODUCT_DATA_DIRECTORY_NAME);
        let outside_managed = temporary.path().join("outside-managed");
        fs::create_dir(&root).unwrap();
        fs::create_dir(&outside_managed).unwrap();
        fs::write(outside_managed.join("must-remain"), b"unrelated").unwrap();
        create_windows_directory_junction(&root.join(MANAGED_RUNTIME_DIRECTORY), &outside_managed);
        let mut backend = LocalProductUninstallBackend::new(root.clone());

        let inventory = backend.inventory_runtimes().unwrap();
        let retained = backend.cleanup_scan_tool_residue();

        assert!(inventory.retained.iter().any(|item| {
            item.item_class == "managed_runtime_state"
                && item.reason_code == "ambiguous_runtime_root_preserved"
        }));
        assert!(retained.iter().any(|item| {
            item.item_class == "managed_runtime_state"
                && item.reason_code == "ambiguous_runtime_root_preserved"
        }));
        assert_eq!(
            fs::read(outside_managed.join("must-remain")).unwrap(),
            b"unrelated"
        );

        fs::remove_dir(root.join(MANAGED_RUNTIME_DIRECTORY)).unwrap();
        let managed = root.join(MANAGED_RUNTIME_DIRECTORY);
        let outside_provider = temporary.path().join("outside-provider");
        fs::create_dir(&managed).unwrap();
        fs::create_dir(&outside_provider).unwrap();
        fs::write(outside_provider.join("must-remain"), b"unrelated").unwrap();
        create_windows_directory_junction(
            &managed.join(MANAGED_RUNTIME_PROVIDER_DIRECTORY),
            &outside_provider,
        );
        let mut backend = LocalProductUninstallBackend::new(root);

        let inventory = backend.inventory_runtimes().unwrap();
        let retained = backend.cleanup_scan_tool_residue();

        assert!(inventory.retained.iter().any(|item| {
            item.item_class == "managed_runtime_entry"
                && item.reason_code == "ambiguous_runtime_entry_preserved"
        }));
        assert!(retained.iter().any(|item| {
            item.item_class == "managed_runtime_entry"
                && item.reason_code == "ambiguous_runtime_entry_preserved"
        }));
        assert_eq!(
            fs::read(outside_provider.join("must-remain")).unwrap(),
            b"unrelated"
        );
    }

    #[test]
    fn successful_all_data_finalization_removes_only_the_empty_exact_root() {
        let temporary = tempfile::tempdir().unwrap();
        let root = temporary.path().join(PRODUCT_DATA_DIRECTORY_NAME);
        fs::create_dir(&root).unwrap();
        fs::write(root.join(DATA_DIRECTORY_LEASE_FILE), b"lease").unwrap();

        assert!(finalize_all_data_root(&root).is_empty());
        assert!(!root.exists());
        assert!(temporary.path().exists());
    }

    #[test]
    fn staged_finalization_cannot_delete_a_newly_recreated_canonical_root() {
        let temporary = tempfile::tempdir().unwrap();
        let root = temporary.path().join(PRODUCT_DATA_DIRECTORY_NAME);
        let first = DataDirectoryExclusiveLease::acquire(&root).unwrap();

        let staged = stage_all_data_root_for_finalization(&root, &first).unwrap();
        assert!(!root.exists());
        assert!(staged.exists());

        let second = DataDirectoryExclusiveLease::acquire(&root).unwrap();
        fs::write(root.join("new-process-data"), b"must remain").unwrap();
        drop(first);
        assert!(finalize_all_data_root(&staged).is_empty());

        assert_eq!(
            fs::read(root.join("new-process-data")).unwrap(),
            b"must remain"
        );
        drop(second);
    }
}
