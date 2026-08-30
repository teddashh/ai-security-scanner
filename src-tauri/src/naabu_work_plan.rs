//! Pure, durable Naabu work-plan construction.
//!
//! This module has no runtime, gateway, storage, or network side effects. It
//! turns already resolved external grants into an exact set of independently
//! retryable address/port rectangles. A caller must persist a newly built plan
//! before provisioning a gateway or contacting a target. Retrying an existing
//! run validates and reuses the saved plan unchanged; it never repartitions the
//! scope, regenerates unit identities, or resolves a hostname again.

use crate::external_scope::{
    CanonicalTarget, ExternalActivity, RatePolicy, ResolvedExternalPlan, TemplatePolicy,
    TransportProtocol, validate_frozen_address_policy,
};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::{BTreeSet, HashSet};
use std::net::IpAddr;
use thiserror::Error;
use uuid::Uuid;

pub const NAABU_WORK_PLAN_SCHEMA_VERSION: u32 = 1;
pub const NAABU_ENGINE_ID: &str = "naabu";
pub const MAX_NAABU_WORK_UNITS: usize = 512;
pub const MAX_NAABU_FROZEN_GRANTS: usize = 128;
pub const MAX_NAABU_FROZEN_ADDRESSES: usize = 4_096;
pub const MAX_NAABU_ENDPOINT_PAIRS_PER_UNIT: u64 = 10_000;
pub const QUICK_DISCOVERY_WINDOW_SECONDS: u64 = 120;
pub const PREFERRED_WORK_UNIT_WINDOW_SECONDS: u64 = 30 * 60;
pub const HARD_WORK_UNIT_WINDOW_SECONDS: u64 = 4 * 60 * 60;
pub const SCANNER_PROCESS_ALLOWANCE_SECONDS: u64 = 5;
const WORK_UNIT_ID_PREFIX: &str = "wu_";
const WORK_UNIT_ID_HEX_CHARACTERS: usize = 32;
const SCOPE_HASH_SCHEMA_VERSION: u32 = 1;
const SERVICE_PORT_PRIORITY: &[u16] = &[
    443, 80, 22, 3389, 445, 8080, 8443, 21, 25, 53, 110, 139, 143, 465, 587, 993, 995, 3306, 5432,
    6379, 9100,
];

#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum NaabuWorkPlanError {
    #[error("Naabu work-plan identity is invalid: {0}")]
    InvalidIdentity(String),
    #[error("Naabu resolved scope is invalid: {0}")]
    InvalidScope(String),
    #[error(
        "the exact Naabu scope requires at least {required} work units at the hard execution bound; the supported maximum is {maximum}; no target may be contacted until the displayed scope or policy is explicitly revised"
    )]
    TooManyWorkUnits { required: usize, maximum: usize },
    #[error("the saved Naabu work plan does not exactly match the frozen execution semantics: {0}")]
    ExistingPlanMismatch(String),
    #[error("Naabu work-plan arithmetic overflowed")]
    ArithmeticOverflow,
    #[error("Naabu scope hashing failed: {0}")]
    Hashing(String),
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct NaabuWorkPlanIdentity {
    pub schema_version: u32,
    pub case_id: String,
    pub scan_run_id: String,
    pub engine_run_id: String,
    pub engine_id: String,
    pub frozen_at: DateTime<Utc>,
}

impl NaabuWorkPlanIdentity {
    pub fn new(
        case_id: impl Into<String>,
        scan_run_id: impl Into<String>,
        engine_run_id: impl Into<String>,
        frozen_at: DateTime<Utc>,
    ) -> Self {
        Self {
            schema_version: NAABU_WORK_PLAN_SCHEMA_VERSION,
            case_id: case_id.into(),
            scan_run_id: scan_run_id.into(),
            engine_run_id: engine_run_id.into(),
            engine_id: NAABU_ENGINE_ID.into(),
            frozen_at,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct FrozenNaabuGrant {
    pub grant_id: String,
    pub case_id: String,
    pub asset_id: String,
    pub target: CanonicalTarget,
    pub resolved_hostname: Option<String>,
    pub resolved_at: DateTime<Utc>,
    /// Canonically ordered exact address corpus. No unit may address an entry
    /// outside this vector.
    pub addresses: Vec<IpAddr>,
    /// Canonically ordered exact port corpus. No unit may address an entry
    /// outside this vector.
    pub ports: Vec<u16>,
    pub protocol: TransportProtocol,
    pub activity: ExternalActivity,
    pub rate_policy: RatePolicy,
    pub template_policy: TemplatePolicy,
    pub grant_frozen_at: DateTime<Utc>,
    pub expires_at: DateTime<Utc>,
    pub allow_sensitive_networks: bool,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum NaabuWorkStage {
    QuickDiscovery,
    FullInventory,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct NaabuWorkUnit {
    pub plan_index: u32,
    /// Random, stable, target-free identity used by the launcher journal.
    pub unit_id: String,
    /// Hash of the expanded exact semantic slice. The random unit ID and
    /// attempt number are intentionally excluded.
    pub scope_sha256: String,
    pub stage: NaabuWorkStage,
    pub grant_index: u32,
    pub address_start: u32,
    pub address_len: u32,
    pub port_start: u32,
    pub port_len: u32,
    pub endpoint_pair_count: u64,
    pub conservative_deadline_seconds: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct NaabuWorkPlanV1 {
    pub identity: NaabuWorkPlanIdentity,
    pub frozen_grants: Vec<FrozenNaabuGrant>,
    pub work_units: Vec<NaabuWorkUnit>,
}

impl NaabuWorkPlanV1 {
    /// Intrinsically validates one saved plan without consulting DNS, a live
    /// grant, a gateway, or disposable runtime state.
    pub fn validate(&self) -> Result<(), NaabuWorkPlanError> {
        validate_identity(&self.identity)?;
        validate_frozen_grants(&self.identity, &self.frozen_grants)?;
        validate_saved_work_units(self)
    }
}

/// Build a new immutable semantic plan, or validate and return an existing one
/// byte-for-byte-equivalently at the data-model level.
///
/// `resolved_plans` must already contain the one DNS/address snapshot that the
/// run will use. This function performs no resolution. Callers resuming a run
/// must reconstruct these values from the saved plan rather than consulting
/// live DNS.
pub fn build_naabu_work_plan(
    identity: NaabuWorkPlanIdentity,
    resolved_plans: &[ResolvedExternalPlan],
    existing: Option<&NaabuWorkPlanV1>,
) -> Result<NaabuWorkPlanV1, NaabuWorkPlanError> {
    validate_identity(&identity)?;
    let frozen_grants = freeze_grants(&identity, resolved_plans)?;
    if let Some(existing) = existing {
        validate_existing_plan(existing, &identity, &frozen_grants)?;
        return Ok(existing.clone());
    }

    let inventory_window = choose_inventory_window(&frozen_grants)?;
    let templates = emit_templates(&frozen_grants, inventory_window)?;

    let mut work_units = Vec::with_capacity(templates.len());
    for (plan_index, template) in templates.into_iter().enumerate() {
        let unit_id = new_work_unit_id();
        let scope_sha256 = hash_unit_scope(&identity, &frozen_grants, &template)?;
        work_units.push(template.into_unit(plan_index, unit_id, scope_sha256)?);
    }
    let plan = NaabuWorkPlanV1 {
        identity,
        frozen_grants,
        work_units,
    };
    plan.validate()?;
    Ok(plan)
}

fn validate_identity(identity: &NaabuWorkPlanIdentity) -> Result<(), NaabuWorkPlanError> {
    if identity.schema_version != NAABU_WORK_PLAN_SCHEMA_VERSION {
        return Err(NaabuWorkPlanError::InvalidIdentity(
            "schema version is not supported".into(),
        ));
    }
    if identity.engine_id != NAABU_ENGINE_ID {
        return Err(NaabuWorkPlanError::InvalidIdentity(
            "engine identity must be exactly naabu".into(),
        ));
    }
    for (label, value) in [
        ("case", identity.case_id.as_str()),
        ("scan run", identity.scan_run_id.as_str()),
        ("engine run", identity.engine_run_id.as_str()),
    ] {
        if value.is_empty()
            || value.len() > 128
            || !value
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_'))
        {
            return Err(NaabuWorkPlanError::InvalidIdentity(format!(
                "{label} ID must be one bounded opaque ASCII identifier"
            )));
        }
    }
    Ok(())
}

fn freeze_grants(
    identity: &NaabuWorkPlanIdentity,
    resolved_plans: &[ResolvedExternalPlan],
) -> Result<Vec<FrozenNaabuGrant>, NaabuWorkPlanError> {
    if resolved_plans.is_empty() || resolved_plans.len() > MAX_NAABU_FROZEN_GRANTS {
        return Err(NaabuWorkPlanError::InvalidScope(format!(
            "Naabu requires between 1 and {MAX_NAABU_FROZEN_GRANTS} frozen grants"
        )));
    }

    let mut grants = Vec::with_capacity(resolved_plans.len());
    let mut grant_ids = HashSet::with_capacity(resolved_plans.len());
    for plan in resolved_plans {
        if plan.case_id != identity.case_id {
            return Err(NaabuWorkPlanError::InvalidScope(
                "a frozen grant belongs to a different case".into(),
            ));
        }
        if plan.grant_id.is_empty()
            || plan.grant_id.len() > 128
            || plan.asset_id.is_empty()
            || plan.asset_id.len() > 128
        {
            return Err(NaabuWorkPlanError::InvalidScope(
                "grant and asset identities must be bounded and non-empty".into(),
            ));
        }
        if !grant_ids.insert(plan.grant_id.clone()) {
            return Err(NaabuWorkPlanError::InvalidScope(
                "frozen grant identities must be unique".into(),
            ));
        }
        if plan.activity != ExternalActivity::LowImpactExternal {
            return Err(NaabuWorkPlanError::InvalidScope(
                "Naabu accepts only the low-impact external activity contract".into(),
            ));
        }
        if plan.protocol == TransportProtocol::Udp {
            return Err(NaabuWorkPlanError::InvalidScope(
                "Naabu work units cannot claim UDP coverage".into(),
            ));
        }
        validate_rate_policy(&plan.rate_policy)?;
        if plan.expires_at <= identity.frozen_at {
            return Err(NaabuWorkPlanError::InvalidScope(
                "a frozen grant is already expired at plan creation".into(),
            ));
        }
        let addresses = plan
            .resolution
            .addresses
            .iter()
            .copied()
            .collect::<Vec<_>>();
        if addresses.is_empty() || addresses.len() > MAX_NAABU_FROZEN_ADDRESSES {
            return Err(NaabuWorkPlanError::InvalidScope(format!(
                "each Naabu grant requires 1 to {MAX_NAABU_FROZEN_ADDRESSES} frozen addresses"
            )));
        }
        let ports = ordered_ports(&plan.ports);
        if ports.is_empty() || ports.first() == Some(&0) {
            return Err(NaabuWorkPlanError::InvalidScope(
                "each Naabu grant requires at least one non-zero port".into(),
            ));
        }
        let expected_hostname = match &plan.target {
            CanonicalTarget::Hostname(hostname) => Some(hostname.as_str()),
            CanonicalTarget::Address(_) | CanonicalTarget::Network(_) => None,
        };
        if plan.resolution.hostname.as_deref() != expected_hostname {
            return Err(NaabuWorkPlanError::InvalidScope(
                "the frozen hostname label does not match its canonical target".into(),
            ));
        }

        grants.push(FrozenNaabuGrant {
            grant_id: plan.grant_id.clone(),
            case_id: plan.case_id.clone(),
            asset_id: plan.asset_id.clone(),
            target: plan.target.clone(),
            resolved_hostname: plan.resolution.hostname.clone(),
            resolved_at: plan.resolution.resolved_at,
            addresses,
            ports,
            protocol: plan.protocol,
            activity: plan.activity,
            rate_policy: plan.rate_policy.clone(),
            template_policy: plan.template_policy.clone(),
            grant_frozen_at: plan.frozen_at,
            expires_at: plan.expires_at,
            allow_sensitive_networks: plan.allow_sensitive_networks,
        });
    }
    grants.sort_by(|left, right| {
        (&left.asset_id, &left.grant_id).cmp(&(&right.asset_id, &right.grant_id))
    });
    validate_frozen_grants(identity, &grants)?;
    Ok(grants)
}

fn validate_rate_policy(policy: &RatePolicy) -> Result<(), NaabuWorkPlanError> {
    if policy.requests_per_second == 0
        || policy.requests_per_second > 25
        || policy.concurrency == 0
        || policy.concurrency > 10
        || policy.timeout_seconds == 0
        || policy.timeout_seconds > 1_800
    {
        return Err(NaabuWorkPlanError::InvalidScope(
            "Naabu rate, concurrency, or timeout is outside the low-impact contract".into(),
        ));
    }
    Ok(())
}

fn validate_frozen_grants(
    identity: &NaabuWorkPlanIdentity,
    grants: &[FrozenNaabuGrant],
) -> Result<(), NaabuWorkPlanError> {
    if grants.is_empty() || grants.len() > MAX_NAABU_FROZEN_GRANTS {
        return Err(NaabuWorkPlanError::InvalidScope(format!(
            "a saved Naabu plan requires between 1 and {MAX_NAABU_FROZEN_GRANTS} frozen grants"
        )));
    }
    let mut grant_ids = BTreeSet::new();
    for grant in grants {
        if grant.case_id != identity.case_id {
            return Err(NaabuWorkPlanError::InvalidScope(
                "a saved frozen grant belongs to a different case".into(),
            ));
        }
        if grant.grant_id.is_empty()
            || grant.grant_id.len() > 128
            || grant.asset_id.is_empty()
            || grant.asset_id.len() > 128
            || !grant_ids.insert(grant.grant_id.as_str())
        {
            return Err(NaabuWorkPlanError::InvalidScope(
                "saved grant and asset identities are empty, oversized, or duplicated".into(),
            ));
        }
        if grant.activity != ExternalActivity::LowImpactExternal
            || grant.protocol == TransportProtocol::Udp
        {
            return Err(NaabuWorkPlanError::InvalidScope(
                "saved Naabu grant has an unsupported activity or transport".into(),
            ));
        }
        validate_rate_policy(&grant.rate_policy)?;
        if grant.grant_frozen_at != identity.frozen_at
            || grant.resolved_at != grant.grant_frozen_at
            || grant.expires_at <= grant.grant_frozen_at
        {
            return Err(NaabuWorkPlanError::InvalidScope(
                "saved grant freeze, resolution, or expiry time is inconsistent".into(),
            ));
        }
        if grant.addresses.is_empty()
            || grant.addresses.len() > MAX_NAABU_FROZEN_ADDRESSES
            || grant
                .addresses
                .iter()
                .copied()
                .collect::<BTreeSet<_>>()
                .len()
                != grant.addresses.len()
        {
            return Err(NaabuWorkPlanError::InvalidScope(
                "saved address corpus is empty, oversized, or duplicated".into(),
            ));
        }
        for address in &grant.addresses {
            validate_frozen_address_policy(*address, grant.allow_sensitive_networks).map_err(
                |_| {
                    NaabuWorkPlanError::InvalidScope(
                        "saved address corpus violates the external target safety policy".into(),
                    )
                },
            )?;
        }
        if grant.ports.is_empty()
            || grant.ports.iter().any(|port| *port == 0)
            || grant.ports.iter().copied().collect::<BTreeSet<_>>().len() != grant.ports.len()
        {
            return Err(NaabuWorkPlanError::InvalidScope(
                "saved port corpus is empty, duplicated, or invalid".into(),
            ));
        }
        match &grant.target {
            CanonicalTarget::Hostname(hostname) => {
                if grant.resolved_hostname.as_deref() != Some(hostname.as_str()) {
                    return Err(NaabuWorkPlanError::InvalidScope(
                        "saved hostname resolution label changed".into(),
                    ));
                }
            }
            CanonicalTarget::Address(address) => {
                if grant.resolved_hostname.is_some() || grant.addresses.as_slice() != [*address] {
                    return Err(NaabuWorkPlanError::InvalidScope(
                        "saved address target does not have its exact one-address corpus".into(),
                    ));
                }
            }
            CanonicalTarget::Network(network) => {
                if grant.resolved_hostname.is_some() {
                    return Err(NaabuWorkPlanError::InvalidScope(
                        "saved network target unexpectedly has a hostname label".into(),
                    ));
                }
                let expected = network
                    .hosts()
                    .take(MAX_NAABU_FROZEN_ADDRESSES + 1)
                    .collect::<BTreeSet<_>>();
                let saved = grant.addresses.iter().copied().collect::<BTreeSet<_>>();
                if expected.len() > MAX_NAABU_FROZEN_ADDRESSES || expected != saved {
                    return Err(NaabuWorkPlanError::InvalidScope(
                        "saved network address corpus is truncated or expanded".into(),
                    ));
                }
            }
        }
    }
    Ok(())
}

fn ordered_ports(ports: &BTreeSet<u16>) -> Vec<u16> {
    let mut remaining = ports.clone();
    let mut ordered = Vec::with_capacity(ports.len());
    for port in SERVICE_PORT_PRIORITY {
        if remaining.remove(port) {
            ordered.push(*port);
        }
    }
    ordered.extend(remaining);
    ordered
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct UnitTemplate {
    stage: NaabuWorkStage,
    grant_index: usize,
    address_start: usize,
    address_len: usize,
    port_start: usize,
    port_len: usize,
    endpoint_pair_count: u64,
    conservative_deadline_seconds: u64,
}

impl UnitTemplate {
    fn into_unit(
        self,
        plan_index: usize,
        unit_id: String,
        scope_sha256: String,
    ) -> Result<NaabuWorkUnit, NaabuWorkPlanError> {
        Ok(NaabuWorkUnit {
            plan_index: u32::try_from(plan_index)
                .map_err(|_| NaabuWorkPlanError::ArithmeticOverflow)?,
            unit_id,
            scope_sha256,
            stage: self.stage,
            grant_index: u32::try_from(self.grant_index)
                .map_err(|_| NaabuWorkPlanError::ArithmeticOverflow)?,
            address_start: u32::try_from(self.address_start)
                .map_err(|_| NaabuWorkPlanError::ArithmeticOverflow)?,
            address_len: u32::try_from(self.address_len)
                .map_err(|_| NaabuWorkPlanError::ArithmeticOverflow)?,
            port_start: u32::try_from(self.port_start)
                .map_err(|_| NaabuWorkPlanError::ArithmeticOverflow)?,
            port_len: u32::try_from(self.port_len)
                .map_err(|_| NaabuWorkPlanError::ArithmeticOverflow)?,
            endpoint_pair_count: self.endpoint_pair_count,
            conservative_deadline_seconds: self.conservative_deadline_seconds,
        })
    }
}

#[derive(Debug, Clone, Copy)]
struct PartitionShape {
    address_width: usize,
    port_width: usize,
    unit_count: usize,
}

fn choose_inventory_window(grants: &[FrozenNaabuGrant]) -> Result<u64, NaabuWorkPlanError> {
    let preferred = count_templates(grants, PREFERRED_WORK_UNIT_WINDOW_SECONDS)?;
    if preferred <= MAX_NAABU_WORK_UNITS {
        return Ok(PREFERRED_WORK_UNIT_WINDOW_SECONDS);
    }
    let hard = count_templates(grants, HARD_WORK_UNIT_WINDOW_SECONDS)?;
    if hard > MAX_NAABU_WORK_UNITS {
        return Err(NaabuWorkPlanError::TooManyWorkUnits {
            required: hard,
            maximum: MAX_NAABU_WORK_UNITS,
        });
    }

    let mut low = PREFERRED_WORK_UNIT_WINDOW_SECONDS + 1;
    let mut high = HARD_WORK_UNIT_WINDOW_SECONDS;
    while low < high {
        let middle = low + (high - low) / 2;
        if count_templates(grants, middle)? <= MAX_NAABU_WORK_UNITS {
            high = middle;
        } else {
            low = middle + 1;
        }
    }
    Ok(low)
}

fn count_templates(
    grants: &[FrozenNaabuGrant],
    inventory_window: u64,
) -> Result<usize, NaabuWorkPlanError> {
    let mut count = 0_usize;
    for grant in grants {
        let quick_capacity = endpoint_capacity(
            &grant.rate_policy,
            QUICK_DISCOVERY_WINDOW_SECONDS.max(u64::from(grant.rate_policy.timeout_seconds) + 6),
        )?;
        let inventory_capacity = endpoint_capacity(
            &grant.rate_policy,
            inventory_window.max(u64::from(grant.rate_policy.timeout_seconds) + 6),
        )?;
        let quick_addresses = grant.addresses.len().min(usize_from_u64(quick_capacity)?);
        count = checked_add(count, 1)?;
        if quick_addresses < grant.addresses.len() {
            count = checked_add(
                count,
                best_partition_shape(
                    grant.addresses.len() - quick_addresses,
                    1,
                    inventory_capacity,
                )?
                .unit_count,
            )?;
        }
        if grant.ports.len() > 1 {
            count = checked_add(
                count,
                best_partition_shape(
                    grant.addresses.len(),
                    grant.ports.len() - 1,
                    inventory_capacity,
                )?
                .unit_count,
            )?;
        }
    }
    Ok(count)
}

fn emit_templates(
    grants: &[FrozenNaabuGrant],
    inventory_window: u64,
) -> Result<Vec<UnitTemplate>, NaabuWorkPlanError> {
    let expected = count_templates(grants, inventory_window)?;
    if expected > MAX_NAABU_WORK_UNITS {
        return Err(NaabuWorkPlanError::TooManyWorkUnits {
            required: expected,
            maximum: MAX_NAABU_WORK_UNITS,
        });
    }
    let mut quick = Vec::with_capacity(grants.len());
    let mut inventory = Vec::with_capacity(expected.saturating_sub(grants.len()));

    for (grant_index, grant) in grants.iter().enumerate() {
        let quick_capacity = endpoint_capacity(
            &grant.rate_policy,
            QUICK_DISCOVERY_WINDOW_SECONDS.max(u64::from(grant.rate_policy.timeout_seconds) + 6),
        )?;
        let inventory_capacity = endpoint_capacity(
            &grant.rate_policy,
            inventory_window.max(u64::from(grant.rate_policy.timeout_seconds) + 6),
        )?;
        let quick_addresses = grant.addresses.len().min(usize_from_u64(quick_capacity)?);
        quick.push(unit_template(
            grant,
            NaabuWorkStage::QuickDiscovery,
            grant_index,
            0,
            quick_addresses,
            0,
            1,
        )?);

        if quick_addresses < grant.addresses.len() {
            emit_partition(
                &mut inventory,
                grant,
                grant_index,
                quick_addresses,
                grant.addresses.len() - quick_addresses,
                0,
                1,
                inventory_capacity,
            )?;
        }
        if grant.ports.len() > 1 {
            emit_partition(
                &mut inventory,
                grant,
                grant_index,
                0,
                grant.addresses.len(),
                1,
                grant.ports.len() - 1,
                inventory_capacity,
            )?;
        }
    }
    quick.extend(inventory);
    debug_assert_eq!(quick.len(), expected);
    Ok(quick)
}

#[allow(clippy::too_many_arguments)]
fn emit_partition(
    output: &mut Vec<UnitTemplate>,
    grant: &FrozenNaabuGrant,
    grant_index: usize,
    address_start: usize,
    address_len: usize,
    port_start: usize,
    port_len: usize,
    capacity: u64,
) -> Result<(), NaabuWorkPlanError> {
    let shape = best_partition_shape(address_len, port_len, capacity)?;
    let port_end = checked_add(port_start, port_len)?;
    let address_end = checked_add(address_start, address_len)?;
    for current_port in (port_start..port_end).step_by(shape.port_width) {
        let current_port_len = shape.port_width.min(port_end - current_port);
        for current_address in (address_start..address_end).step_by(shape.address_width) {
            let current_address_len = shape.address_width.min(address_end - current_address);
            output.push(unit_template(
                grant,
                NaabuWorkStage::FullInventory,
                grant_index,
                current_address,
                current_address_len,
                current_port,
                current_port_len,
            )?);
        }
    }
    Ok(())
}

fn best_partition_shape(
    address_count: usize,
    port_count: usize,
    capacity: u64,
) -> Result<PartitionShape, NaabuWorkPlanError> {
    if address_count == 0 || port_count == 0 || capacity == 0 {
        return Err(NaabuWorkPlanError::InvalidScope(
            "a work-unit partition cannot be empty".into(),
        ));
    }
    let capacity = usize_from_u64(capacity)?;
    let maximum_port_width = port_count.min(capacity);
    let mut best: Option<PartitionShape> = None;
    for port_width in 1..=maximum_port_width {
        let address_width = address_count.min(capacity / port_width);
        if address_width == 0 {
            continue;
        }
        let address_chunks = div_ceil(address_count, address_width);
        let port_chunks = div_ceil(port_count, port_width);
        let unit_count = address_chunks
            .checked_mul(port_chunks)
            .ok_or(NaabuWorkPlanError::ArithmeticOverflow)?;
        let candidate = PartitionShape {
            address_width,
            port_width,
            unit_count,
        };
        let replace = best.is_none_or(|current| {
            (
                candidate.unit_count,
                std::cmp::Reverse(candidate.address_width),
                std::cmp::Reverse(candidate.port_width),
            ) < (
                current.unit_count,
                std::cmp::Reverse(current.address_width),
                std::cmp::Reverse(current.port_width),
            )
        });
        if replace {
            best = Some(candidate);
        }
    }
    best.ok_or(NaabuWorkPlanError::ArithmeticOverflow)
}

fn unit_template(
    grant: &FrozenNaabuGrant,
    stage: NaabuWorkStage,
    grant_index: usize,
    address_start: usize,
    address_len: usize,
    port_start: usize,
    port_len: usize,
) -> Result<UnitTemplate, NaabuWorkPlanError> {
    let endpoint_pair_count = u64::try_from(address_len)
        .map_err(|_| NaabuWorkPlanError::ArithmeticOverflow)?
        .checked_mul(u64::try_from(port_len).map_err(|_| NaabuWorkPlanError::ArithmeticOverflow)?)
        .ok_or(NaabuWorkPlanError::ArithmeticOverflow)?;
    if endpoint_pair_count == 0 || endpoint_pair_count > MAX_NAABU_ENDPOINT_PAIRS_PER_UNIT {
        return Err(NaabuWorkPlanError::InvalidScope(format!(
            "one work unit contains {endpoint_pair_count} endpoint pairs"
        )));
    }
    Ok(UnitTemplate {
        stage,
        grant_index,
        address_start,
        address_len,
        port_start,
        port_len,
        endpoint_pair_count,
        conservative_deadline_seconds: conservative_deadline_seconds(
            &grant.rate_policy,
            endpoint_pair_count,
        )?,
    })
}

fn endpoint_capacity(policy: &RatePolicy, window_seconds: u64) -> Result<u64, NaabuWorkPlanError> {
    let effective_rate = u64::from(policy.requests_per_second.min(policy.concurrency));
    let per_wave = u64::from(policy.timeout_seconds) + 1;
    let usable = window_seconds.saturating_sub(SCANNER_PROCESS_ALLOWANCE_SECONDS);
    let waves = (usable / per_wave).max(1);
    Ok(waves
        .checked_mul(effective_rate)
        .ok_or(NaabuWorkPlanError::ArithmeticOverflow)?
        .min(MAX_NAABU_ENDPOINT_PAIRS_PER_UNIT))
}

fn conservative_deadline_seconds(
    policy: &RatePolicy,
    endpoint_pairs: u64,
) -> Result<u64, NaabuWorkPlanError> {
    let effective_rate = u64::from(policy.requests_per_second.min(policy.concurrency));
    let waves = endpoint_pairs
        .checked_add(effective_rate - 1)
        .ok_or(NaabuWorkPlanError::ArithmeticOverflow)?
        / effective_rate;
    waves
        .checked_mul(u64::from(policy.timeout_seconds) + 1)
        .and_then(|seconds| seconds.checked_add(SCANNER_PROCESS_ALLOWANCE_SECONDS))
        .ok_or(NaabuWorkPlanError::ArithmeticOverflow)
}

#[derive(Serialize)]
struct UnitScopeHashDocument<'a> {
    schema_version: u32,
    case_id: &'a str,
    scan_run_id: &'a str,
    engine_run_id: &'a str,
    engine_id: &'static str,
    asset_id: &'a str,
    scope_grant_id: &'a str,
    stage: NaabuWorkStage,
    target: &'a CanonicalTarget,
    addresses: &'a [IpAddr],
    ports: &'a [u16],
    requested_protocol: TransportProtocol,
    tested_operation: &'static str,
    activity: ExternalActivity,
    rate_policy: &'a RatePolicy,
    template_policy: &'a TemplatePolicy,
    allow_sensitive_networks: bool,
}

fn hash_unit_scope(
    identity: &NaabuWorkPlanIdentity,
    grants: &[FrozenNaabuGrant],
    template: &UnitTemplate,
) -> Result<String, NaabuWorkPlanError> {
    let grant = grants
        .get(template.grant_index)
        .ok_or(NaabuWorkPlanError::ArithmeticOverflow)?;
    let addresses = checked_slice(
        &grant.addresses,
        template.address_start,
        template.address_len,
    )?;
    let ports = checked_slice(&grant.ports, template.port_start, template.port_len)?;
    let document = UnitScopeHashDocument {
        schema_version: SCOPE_HASH_SCHEMA_VERSION,
        case_id: &identity.case_id,
        scan_run_id: &identity.scan_run_id,
        engine_run_id: &identity.engine_run_id,
        engine_id: NAABU_ENGINE_ID,
        asset_id: &grant.asset_id,
        scope_grant_id: &grant.grant_id,
        stage: template.stage,
        target: &grant.target,
        addresses,
        ports,
        requested_protocol: grant.protocol,
        tested_operation: "tcp_connect",
        activity: grant.activity,
        rate_policy: &grant.rate_policy,
        template_policy: &grant.template_policy,
        allow_sensitive_networks: grant.allow_sensitive_networks,
    };
    let encoded = serde_json::to_vec(&document)
        .map_err(|error| NaabuWorkPlanError::Hashing(error.to_string()))?;
    Ok(hex::encode(Sha256::digest(encoded)))
}

fn validate_existing_plan(
    existing: &NaabuWorkPlanV1,
    identity: &NaabuWorkPlanIdentity,
    frozen_grants: &[FrozenNaabuGrant],
) -> Result<(), NaabuWorkPlanError> {
    existing
        .validate()
        .map_err(|error| NaabuWorkPlanError::ExistingPlanMismatch(error.to_string()))?;
    if &existing.identity != identity {
        return Err(NaabuWorkPlanError::ExistingPlanMismatch(
            "plan identity changed".into(),
        ));
    }
    if !same_frozen_semantics(&existing.frozen_grants, frozen_grants) {
        return Err(NaabuWorkPlanError::ExistingPlanMismatch(
            "target, resolution, port, rate, or grant semantics changed".into(),
        ));
    }
    Ok(())
}

fn same_frozen_semantics(saved: &[FrozenNaabuGrant], current: &[FrozenNaabuGrant]) -> bool {
    saved.len() == current.len()
        && saved.iter().all(|left| {
            current
                .iter()
                .find(|right| right.grant_id == left.grant_id)
                .is_some_and(|right| {
                    left.case_id == right.case_id
                        && left.asset_id == right.asset_id
                        && left.target == right.target
                        && left.resolved_hostname == right.resolved_hostname
                        && left.resolved_at == right.resolved_at
                        && left.addresses.iter().copied().collect::<BTreeSet<_>>()
                            == right.addresses.iter().copied().collect::<BTreeSet<_>>()
                        && left.ports.iter().copied().collect::<BTreeSet<_>>()
                            == right.ports.iter().copied().collect::<BTreeSet<_>>()
                        && left.protocol == right.protocol
                        && left.activity == right.activity
                        && left.rate_policy == right.rate_policy
                        && left.template_policy == right.template_policy
                        && left.grant_frozen_at == right.grant_frozen_at
                        && left.expires_at == right.expires_at
                        && left.allow_sensitive_networks == right.allow_sensitive_networks
                })
        })
}

/// Validate the stable V1 coverage contract without regenerating today's
/// preferred partition. Builder tuning may change only a new plan; an already
/// saved V1 plan remains usable when its bounded rectangles still prove exact,
/// disjoint coverage and retain their original hashes and identities.
fn validate_saved_work_units(plan: &NaabuWorkPlanV1) -> Result<(), NaabuWorkPlanError> {
    if plan.work_units.is_empty() || plan.work_units.len() > MAX_NAABU_WORK_UNITS {
        return Err(NaabuWorkPlanError::ExistingPlanMismatch(
            "work-unit count is invalid".into(),
        ));
    }

    let mut unit_ids = BTreeSet::new();
    let mut inventory_started = false;
    let mut quick_units = vec![0_usize; plan.frozen_grants.len()];
    let mut covered_pairs = vec![0_u64; plan.frozen_grants.len()];
    let mut units_by_grant = vec![Vec::<&NaabuWorkUnit>::new(); plan.frozen_grants.len()];

    for (plan_index, unit) in plan.work_units.iter().enumerate() {
        if unit.plan_index != u32::try_from(plan_index).unwrap_or(u32::MAX) {
            return Err(NaabuWorkPlanError::ExistingPlanMismatch(format!(
                "work-unit {plan_index} is not in stable plan order"
            )));
        }
        if !valid_work_unit_id(&unit.unit_id) || !unit_ids.insert(unit.unit_id.as_str()) {
            return Err(NaabuWorkPlanError::ExistingPlanMismatch(format!(
                "work-unit {plan_index} identity is invalid or duplicated"
            )));
        }
        let grant_index = usize::try_from(unit.grant_index)
            .map_err(|_| NaabuWorkPlanError::ArithmeticOverflow)?;
        let address_start = usize::try_from(unit.address_start)
            .map_err(|_| NaabuWorkPlanError::ArithmeticOverflow)?;
        let address_len = usize::try_from(unit.address_len)
            .map_err(|_| NaabuWorkPlanError::ArithmeticOverflow)?;
        let port_start =
            usize::try_from(unit.port_start).map_err(|_| NaabuWorkPlanError::ArithmeticOverflow)?;
        let port_len =
            usize::try_from(unit.port_len).map_err(|_| NaabuWorkPlanError::ArithmeticOverflow)?;
        let grant = plan.frozen_grants.get(grant_index).ok_or_else(|| {
            NaabuWorkPlanError::ExistingPlanMismatch(format!(
                "work-unit {plan_index} refers to a missing grant"
            ))
        })?;
        checked_slice(&grant.addresses, address_start, address_len)?;
        checked_slice(&grant.ports, port_start, port_len)?;
        let endpoint_pair_count = u64::try_from(address_len)
            .map_err(|_| NaabuWorkPlanError::ArithmeticOverflow)?
            .checked_mul(
                u64::try_from(port_len).map_err(|_| NaabuWorkPlanError::ArithmeticOverflow)?,
            )
            .ok_or(NaabuWorkPlanError::ArithmeticOverflow)?;
        if endpoint_pair_count == 0
            || endpoint_pair_count > MAX_NAABU_ENDPOINT_PAIRS_PER_UNIT
            || endpoint_pair_count != unit.endpoint_pair_count
        {
            return Err(NaabuWorkPlanError::ExistingPlanMismatch(format!(
                "work-unit {plan_index} has invalid endpoint-pair bounds"
            )));
        }
        let expected_deadline =
            conservative_deadline_seconds(&grant.rate_policy, endpoint_pair_count)?;
        if unit.conservative_deadline_seconds != expected_deadline {
            return Err(NaabuWorkPlanError::ExistingPlanMismatch(format!(
                "work-unit {plan_index} has an invalid conservative deadline"
            )));
        }
        match unit.stage {
            NaabuWorkStage::QuickDiscovery => {
                if inventory_started
                    || address_start != 0
                    || port_start != 0
                    || port_len != 1
                    || expected_deadline
                        > QUICK_DISCOVERY_WINDOW_SECONDS
                            .max(u64::from(grant.rate_policy.timeout_seconds) + 6)
                {
                    return Err(NaabuWorkPlanError::ExistingPlanMismatch(format!(
                        "work-unit {plan_index} is not a bounded leading quick-discovery slice"
                    )));
                }
                quick_units[grant_index] = quick_units[grant_index]
                    .checked_add(1)
                    .ok_or(NaabuWorkPlanError::ArithmeticOverflow)?;
            }
            NaabuWorkStage::FullInventory => {
                inventory_started = true;
                if expected_deadline > HARD_WORK_UNIT_WINDOW_SECONDS {
                    return Err(NaabuWorkPlanError::ExistingPlanMismatch(format!(
                        "work-unit {plan_index} exceeds the hard execution window"
                    )));
                }
            }
        }
        covered_pairs[grant_index] = covered_pairs[grant_index]
            .checked_add(endpoint_pair_count)
            .ok_or(NaabuWorkPlanError::ArithmeticOverflow)?;
        units_by_grant[grant_index].push(unit);

        let template = UnitTemplate {
            stage: unit.stage,
            grant_index,
            address_start,
            address_len,
            port_start,
            port_len,
            endpoint_pair_count,
            conservative_deadline_seconds: expected_deadline,
        };
        let expected_hash = hash_unit_scope(&plan.identity, &plan.frozen_grants, &template)?;
        if !valid_sha256(&unit.scope_sha256) || unit.scope_sha256 != expected_hash {
            return Err(NaabuWorkPlanError::ExistingPlanMismatch(format!(
                "work-unit {plan_index} scope hash changed or is invalid"
            )));
        }
    }

    for (grant_index, grant) in plan.frozen_grants.iter().enumerate() {
        if quick_units[grant_index] != 1 {
            return Err(NaabuWorkPlanError::ExistingPlanMismatch(format!(
                "grant {grant_index} does not have exactly one quick-discovery slice"
            )));
        }
        let expected_pairs = u64::try_from(grant.addresses.len())
            .map_err(|_| NaabuWorkPlanError::ArithmeticOverflow)?
            .checked_mul(
                u64::try_from(grant.ports.len())
                    .map_err(|_| NaabuWorkPlanError::ArithmeticOverflow)?,
            )
            .ok_or(NaabuWorkPlanError::ArithmeticOverflow)?;
        if covered_pairs[grant_index] != expected_pairs {
            return Err(NaabuWorkPlanError::ExistingPlanMismatch(format!(
                "grant {grant_index} coverage is incomplete or expanded"
            )));
        }
        let units = &units_by_grant[grant_index];
        for (left_index, left) in units.iter().enumerate() {
            for right in units.iter().skip(left_index + 1) {
                if unit_rectangles_overlap(left, right)? {
                    return Err(NaabuWorkPlanError::ExistingPlanMismatch(format!(
                        "grant {grant_index} contains overlapping work-unit coverage"
                    )));
                }
            }
        }
    }
    Ok(())
}

fn unit_rectangles_overlap(
    left: &NaabuWorkUnit,
    right: &NaabuWorkUnit,
) -> Result<bool, NaabuWorkPlanError> {
    if left.grant_index != right.grant_index {
        return Ok(false);
    }
    let left_address_end = left
        .address_start
        .checked_add(left.address_len)
        .ok_or(NaabuWorkPlanError::ArithmeticOverflow)?;
    let right_address_end = right
        .address_start
        .checked_add(right.address_len)
        .ok_or(NaabuWorkPlanError::ArithmeticOverflow)?;
    let left_port_end = left
        .port_start
        .checked_add(left.port_len)
        .ok_or(NaabuWorkPlanError::ArithmeticOverflow)?;
    let right_port_end = right
        .port_start
        .checked_add(right.port_len)
        .ok_or(NaabuWorkPlanError::ArithmeticOverflow)?;
    Ok(left.address_start < right_address_end
        && right.address_start < left_address_end
        && left.port_start < right_port_end
        && right.port_start < left_port_end)
}

fn new_work_unit_id() -> String {
    format!("{WORK_UNIT_ID_PREFIX}{}", Uuid::new_v4().simple())
}

fn valid_work_unit_id(value: &str) -> bool {
    value
        .strip_prefix(WORK_UNIT_ID_PREFIX)
        .is_some_and(|suffix| {
            suffix.len() == WORK_UNIT_ID_HEX_CHARACTERS
                && suffix
                    .bytes()
                    .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
        })
}

fn valid_sha256(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

fn checked_slice<T>(values: &[T], start: usize, len: usize) -> Result<&[T], NaabuWorkPlanError> {
    let end = checked_add(start, len)?;
    values
        .get(start..end)
        .ok_or(NaabuWorkPlanError::ArithmeticOverflow)
}

fn checked_add(left: usize, right: usize) -> Result<usize, NaabuWorkPlanError> {
    left.checked_add(right)
        .ok_or(NaabuWorkPlanError::ArithmeticOverflow)
}

fn div_ceil(value: usize, divisor: usize) -> usize {
    value / divisor + usize::from(value % divisor != 0)
}

fn usize_from_u64(value: u64) -> Result<usize, NaabuWorkPlanError> {
    usize::try_from(value).map_err(|_| NaabuWorkPlanError::ArithmeticOverflow)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::external_scope::{ResolutionSnapshot, TemplatePolicy};
    use chrono::TimeZone;
    use ipnet::IpNet;

    fn frozen_at() -> DateTime<Utc> {
        Utc.with_ymd_and_hms(2026, 8, 30, 12, 0, 0)
            .single()
            .expect("fixture time")
    }

    fn identity() -> NaabuWorkPlanIdentity {
        NaabuWorkPlanIdentity::new("case-a", "run-a", "engine-run-a", frozen_at())
    }

    fn resolved_plan(
        target: CanonicalTarget,
        hostname: Option<&str>,
        addresses: BTreeSet<IpAddr>,
        ports: impl IntoIterator<Item = u16>,
        policy: RatePolicy,
    ) -> ResolvedExternalPlan {
        ResolvedExternalPlan {
            grant_id: "grant-a".into(),
            case_id: "case-a".into(),
            asset_id: "asset-a".into(),
            target,
            resolution: ResolutionSnapshot {
                hostname: hostname.map(str::to_owned),
                addresses,
                resolved_at: frozen_at(),
            },
            ports: ports.into_iter().collect(),
            protocol: TransportProtocol::Tcp,
            activity: ExternalActivity::LowImpactExternal,
            rate_policy: policy,
            template_policy: TemplatePolicy::conservative("not_applicable", Vec::new()),
            frozen_at: frozen_at(),
            expires_at: frozen_at() + chrono::Duration::hours(24),
            allow_sensitive_networks: true,
        }
    }

    fn default_policy() -> RatePolicy {
        RatePolicy {
            requests_per_second: 25,
            concurrency: 10,
            timeout_seconds: 3,
        }
    }

    fn network_plan(prefix: &str, port_count: u16, policy: RatePolicy) -> ResolvedExternalPlan {
        let network = prefix.parse::<IpNet>().expect("fixture network");
        let addresses = network.hosts().collect::<BTreeSet<_>>();
        resolved_plan(
            CanonicalTarget::Network(network),
            None,
            addresses,
            1..=port_count,
            policy,
        )
    }

    fn expanded_pairs(plan: &NaabuWorkPlanV1) -> BTreeSet<(IpAddr, u16)> {
        let mut pairs = BTreeSet::new();
        for unit in &plan.work_units {
            let grant = &plan.frozen_grants[unit.grant_index as usize];
            let addresses = &grant.addresses
                [unit.address_start as usize..(unit.address_start + unit.address_len) as usize];
            let ports =
                &grant.ports[unit.port_start as usize..(unit.port_start + unit.port_len) as usize];
            for address in addresses {
                for port in ports {
                    assert!(
                        pairs.insert((*address, *port)),
                        "work-unit rectangles must never overlap"
                    );
                }
            }
        }
        pairs
    }

    #[test]
    fn slash_24_with_40_ports_is_four_exact_disjoint_units() {
        let resolved = network_plan("192.168.50.0/24", 40, default_policy());
        let expected = resolved
            .resolution
            .addresses
            .iter()
            .flat_map(|address| resolved.ports.iter().map(move |port| (*address, *port)))
            .collect::<BTreeSet<_>>();
        let plan = build_naabu_work_plan(identity(), &[resolved], None).expect("work plan");

        plan.validate().expect("intrinsic plan validation");
        assert_eq!(plan.frozen_grants[0].addresses.len(), 254);
        assert_eq!(plan.work_units.len(), 4);
        assert_eq!(plan.work_units[0].stage, NaabuWorkStage::QuickDiscovery);
        assert_eq!(plan.work_units[0].endpoint_pair_count, 254);
        assert_eq!(
            plan.work_units
                .iter()
                .map(|unit| unit.endpoint_pair_count)
                .sum::<u64>(),
            10_160
        );
        assert!(plan.work_units.iter().all(|unit| {
            unit.endpoint_pair_count <= MAX_NAABU_ENDPOINT_PAIRS_PER_UNIT
                && unit.conservative_deadline_seconds <= PREFERRED_WORK_UNIT_WINDOW_SECONDS
        }));
        assert_eq!(expanded_pairs(&plan), expected);
    }

    #[test]
    fn existing_hostname_plan_is_reused_without_new_dns_or_identities() {
        let addresses = [
            "192.0.2.10".parse().unwrap(),
            "2001:db8::10".parse().unwrap(),
        ]
        .into_iter()
        .collect();
        let resolved = resolved_plan(
            CanonicalTarget::Hostname("app.example.test".into()),
            Some("app.example.test"),
            addresses,
            [80, 443, 8443],
            default_policy(),
        );
        let first = build_naabu_work_plan(identity(), &[resolved.clone()], None).expect("first");
        let reused = build_naabu_work_plan(identity(), &[resolved], Some(&first)).expect("reuse");

        assert_eq!(reused, first);
        assert_eq!(
            reused
                .work_units
                .iter()
                .map(|unit| (&unit.unit_id, &unit.scope_sha256))
                .collect::<Vec<_>>(),
            first
                .work_units
                .iter()
                .map(|unit| (&unit.unit_id, &unit.scope_sha256))
                .collect::<Vec<_>>()
        );
    }

    #[test]
    fn existing_plan_rejects_changed_resolution_or_port_semantics() {
        let original = resolved_plan(
            CanonicalTarget::Hostname("app.example.test".into()),
            Some("app.example.test"),
            ["192.0.2.10".parse().unwrap()].into_iter().collect(),
            [443],
            default_policy(),
        );
        let saved =
            build_naabu_work_plan(identity(), &[original.clone()], None).expect("saved plan");

        let mut changed_dns = original.clone();
        changed_dns
            .resolution
            .addresses
            .insert("192.0.2.11".parse().unwrap());
        assert!(matches!(
            build_naabu_work_plan(identity(), &[changed_dns], Some(&saved)),
            Err(NaabuWorkPlanError::ExistingPlanMismatch(_))
        ));

        let mut changed_ports = original;
        changed_ports.ports.insert(8443);
        assert!(matches!(
            build_naabu_work_plan(identity(), &[changed_ports], Some(&saved)),
            Err(NaabuWorkPlanError::ExistingPlanMismatch(_))
        ));
    }

    #[test]
    fn scope_that_cannot_fit_512_units_fails_before_any_execution_contract_exists() {
        let resolved = network_plan(
            "192.168.60.0/24",
            20,
            RatePolicy {
                requests_per_second: 1,
                concurrency: 1,
                timeout_seconds: 1_800,
            },
        );
        let error =
            build_naabu_work_plan(identity(), &[resolved], None).expect_err("oversized exact plan");
        assert!(matches!(
            error,
            NaabuWorkPlanError::TooManyWorkUnits {
                required: 513..,
                maximum: MAX_NAABU_WORK_UNITS
            }
        ));
    }

    #[test]
    fn saved_ids_and_hashes_are_closed_and_revalidated() {
        let resolved = network_plan("10.20.30.0/24", 3, default_policy());
        let saved = build_naabu_work_plan(identity(), &[resolved.clone()], None).expect("plan");
        let mut ids = BTreeSet::new();
        for unit in &saved.work_units {
            assert!(valid_work_unit_id(&unit.unit_id));
            assert!(valid_sha256(&unit.scope_sha256));
            assert!(ids.insert(unit.unit_id.as_str()));
        }

        let mut invalid_id = saved.clone();
        invalid_id.work_units[0].unit_id = "192.0.2.10".into();
        assert!(matches!(
            build_naabu_work_plan(identity(), &[resolved.clone()], Some(&invalid_id)),
            Err(NaabuWorkPlanError::ExistingPlanMismatch(_))
        ));

        let mut invalid_hash = saved;
        invalid_hash.work_units[0].scope_sha256 = "0".repeat(64);
        assert!(matches!(
            build_naabu_work_plan(identity(), &[resolved], Some(&invalid_hash)),
            Err(NaabuWorkPlanError::ExistingPlanMismatch(_))
        ));
    }

    #[test]
    fn random_ids_do_not_change_deterministic_semantic_shapes_or_hashes() {
        let resolved = network_plan("172.16.8.0/24", 40, default_policy());
        let first = build_naabu_work_plan(identity(), &[resolved.clone()], None).expect("first");
        let second = build_naabu_work_plan(identity(), &[resolved], None).expect("second");
        assert_eq!(first.frozen_grants, second.frozen_grants);
        assert_eq!(first.work_units.len(), second.work_units.len());
        for (left, right) in first.work_units.iter().zip(second.work_units.iter()) {
            assert_eq!(left.plan_index, right.plan_index);
            assert_eq!(left.scope_sha256, right.scope_sha256);
            assert_eq!(left.stage, right.stage);
            assert_eq!(left.grant_index, right.grant_index);
            assert_eq!(left.address_start, right.address_start);
            assert_eq!(left.address_len, right.address_len);
            assert_eq!(left.port_start, right.port_start);
            assert_eq!(left.port_len, right.port_len);
            assert_eq!(left.endpoint_pair_count, right.endpoint_pair_count);
            assert_eq!(
                left.conservative_deadline_seconds,
                right.conservative_deadline_seconds
            );
        }
    }

    #[test]
    fn intrinsic_v1_validation_accepts_an_exact_nonpreferred_partition() {
        let resolved = network_plan("192.168.70.0/30", 2, default_policy());
        let mut saved = build_naabu_work_plan(identity(), &[resolved.clone()], None).expect("plan");
        let grant = &saved.frozen_grants[0];
        let templates = [
            unit_template(grant, NaabuWorkStage::QuickDiscovery, 0, 0, 1, 0, 1).unwrap(),
            unit_template(grant, NaabuWorkStage::FullInventory, 0, 1, 1, 0, 1).unwrap(),
            unit_template(grant, NaabuWorkStage::FullInventory, 0, 0, 2, 1, 1).unwrap(),
        ];
        saved.work_units = templates
            .into_iter()
            .enumerate()
            .map(|(index, template)| {
                let hash = hash_unit_scope(&saved.identity, &saved.frozen_grants, &template)
                    .expect("scope hash");
                template
                    .into_unit(index, new_work_unit_id(), hash)
                    .expect("work unit")
            })
            .collect();

        saved.validate().expect("exact alternate V1 partition");
        let reused = build_naabu_work_plan(identity(), &[resolved], Some(&saved))
            .expect("saved partition remains reusable");
        assert_eq!(reused, saved);
        assert_eq!(expanded_pairs(&reused).len(), 4);
    }

    #[test]
    fn hostname_snapshots_reapply_sensitive_and_metadata_address_policy() {
        let hostname = CanonicalTarget::Hostname("app.example.test".into());
        let mut private_without_allowance = resolved_plan(
            hostname.clone(),
            Some("app.example.test"),
            ["127.0.0.1".parse().unwrap()].into_iter().collect(),
            [443],
            default_policy(),
        );
        private_without_allowance.allow_sensitive_networks = false;
        assert!(matches!(
            build_naabu_work_plan(identity(), &[private_without_allowance], None),
            Err(NaabuWorkPlanError::InvalidScope(_))
        ));

        let mut metadata_with_allowance = resolved_plan(
            hostname.clone(),
            Some("app.example.test"),
            ["169.254.169.254".parse().unwrap()].into_iter().collect(),
            [443],
            default_policy(),
        );
        metadata_with_allowance.allow_sensitive_networks = true;
        assert!(matches!(
            build_naabu_work_plan(identity(), &[metadata_with_allowance], None),
            Err(NaabuWorkPlanError::InvalidScope(_))
        ));

        let mut allowed_private = resolved_plan(
            hostname,
            Some("app.example.test"),
            ["10.0.0.10".parse().unwrap()].into_iter().collect(),
            [443],
            default_policy(),
        );
        allowed_private.allow_sensitive_networks = true;
        let mut forged =
            build_naabu_work_plan(identity(), &[allowed_private], None).expect("internal plan");
        forged.frozen_grants[0].addresses[0] = "169.254.169.254".parse().unwrap();
        let unit = &forged.work_units[0];
        let template = UnitTemplate {
            stage: unit.stage,
            grant_index: unit.grant_index as usize,
            address_start: unit.address_start as usize,
            address_len: unit.address_len as usize,
            port_start: unit.port_start as usize,
            port_len: unit.port_len as usize,
            endpoint_pair_count: unit.endpoint_pair_count,
            conservative_deadline_seconds: unit.conservative_deadline_seconds,
        };
        forged.work_units[0].scope_sha256 =
            hash_unit_scope(&forged.identity, &forged.frozen_grants, &template).unwrap();
        assert!(matches!(
            forged.validate(),
            Err(NaabuWorkPlanError::InvalidScope(_))
        ));
    }

    #[test]
    fn quick_discovery_uses_service_priority_without_dropping_any_port() {
        let resolved = resolved_plan(
            CanonicalTarget::Address("192.0.2.10".parse().unwrap()),
            None,
            ["192.0.2.10".parse().unwrap()].into_iter().collect(),
            [5_000, 22, 80, 443],
            default_policy(),
        );
        let expected_ports = resolved.ports.clone();
        let plan = build_naabu_work_plan(identity(), &[resolved], None).expect("work plan");

        assert_eq!(plan.frozen_grants[0].ports, [443, 80, 22, 5_000]);
        let quick = &plan.work_units[0];
        assert_eq!(quick.stage, NaabuWorkStage::QuickDiscovery);
        assert_eq!(quick.port_start, 0);
        assert_eq!(quick.port_len, 1);
        assert_eq!(plan.frozen_grants[0].ports[quick.port_start as usize], 443);
        assert_eq!(
            expanded_pairs(&plan)
                .into_iter()
                .map(|(_, port)| port)
                .collect::<BTreeSet<_>>(),
            expected_ports
        );
    }
}
