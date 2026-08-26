use crate::container_runtime::{NetworkPolicy, RuntimeCommandContext, RuntimeProvider};
use crate::error::{AppError, AppResult};
use crate::external_scope::{
    CanonicalTarget, ExternalActivity, ResolvedExternalPlan, TransportProtocol,
};
use chrono::{DateTime, Duration as ChronoDuration, Utc};
use ipnet::IpNet;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet};
use std::ffi::{OsStr, OsString};
use std::fs::{self, OpenOptions};
use std::io::{self, Write};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, TcpStream, ToSocketAddrs};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::Arc;
use std::thread;
use std::time::{Duration, Instant};
use uuid::Uuid;

const POLICY_SCHEMA_VERSION: &str = "2.0.0";
const REGISTRY_SCHEMA_VERSION: &str = "1.0.0";
const GATEWAY_PORT: u16 = 1080;
const MAX_POLICY_BYTES: usize = 2 * 1024 * 1024;
const MAX_REGISTRY_RECORD_BYTES: usize = 64 * 1024;
const MAX_REGISTRY_RECORDS: usize = 3_072;
const MAX_INSPECT_BYTES: usize = 2 * 1024 * 1024;
const MAX_DIAGNOSTIC_BYTES: usize = 4 * 1024;
const RUNTIME_COMMAND_TIMEOUT: Duration = Duration::from_secs(30);
const MAX_DESTINATIONS: usize = 10_000;
const MAX_EXTERNAL_PLANS_PER_LEASE: usize = 128;
const MAX_AUTHORIZED_ENDPOINTS: usize = 10_000;
const GATEWAY_READY_TIMEOUT: Duration = Duration::from_secs(5);
const GATEWAY_READY_INTERVAL: Duration = Duration::from_millis(25);
const GATEWAY_CONNECT_PROBE_TIMEOUT: Duration = Duration::from_millis(50);
const MANAGED_LABEL_KEY: &str = "ai.security-scanner.managed";
const POLICY_LABEL_KEY: &str = "ai.security-scanner.policy-id";

/// Bounded, non-secret identity copied into the durable execution checkpoint.
///
/// The runtime resource is never recovered by a name prefix. Reconciliation
/// requires this exact provider/name/id/policy tuple and re-inspects all labels
/// immediately before removing the network by its immutable runtime id.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct ManagedNetworkIdentity {
    pub schema_version: String,
    pub provider: RuntimeProvider,
    pub network_name: String,
    pub network_id: String,
    pub policy_id: String,
    pub policy_sha256: String,
    pub expires_at: DateTime<Utc>,
    pub provenance: EgressGatewayProvenance,
}

impl ManagedNetworkIdentity {
    pub fn validate(&self) -> AppResult<()> {
        if self.schema_version != REGISTRY_SCHEMA_VERSION {
            return Err(AppError::InvalidRequest(
                "managed-network checkpoint schema is unsupported".into(),
            ));
        }
        validate_network_name(&self.network_name)?;
        validate_runtime_id(&self.network_id)?;
        validate_policy_id(&self.policy_id)?;
        validate_network_policy_relation(&self.network_name, &self.policy_id)?;
        decode_sha256(&self.policy_sha256)?;
        validate_egress_provenance(&self.provenance)?;
        Ok(())
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct ManagedNetworkOwner {
    pub case_id: String,
    pub scan_run_id: String,
    pub engine_run_id: String,
    pub attempt: u32,
}

impl ManagedNetworkOwner {
    pub fn new(
        case_id: impl Into<String>,
        scan_run_id: impl Into<String>,
        engine_run_id: impl Into<String>,
        attempt: u32,
    ) -> AppResult<Self> {
        let owner = Self {
            case_id: case_id.into(),
            scan_run_id: scan_run_id.into(),
            engine_run_id: engine_run_id.into(),
            attempt,
        };
        owner.validate()?;
        Ok(owner)
    }

    fn validate(&self) -> AppResult<()> {
        for (label, value) in [
            ("case", self.case_id.as_str()),
            ("scan run", self.scan_run_id.as_str()),
            ("engine run", self.engine_run_id.as_str()),
        ] {
            if value.is_empty()
                || value.len() > 256
                || !value.chars().all(|character| {
                    character.is_ascii_alphanumeric() || matches!(character, '-' | '_')
                })
            {
                return Err(AppError::InvalidRequest(format!(
                    "managed-network {label} identity is invalid"
                )));
            }
        }
        if self.attempt == 0 {
            return Err(AppError::InvalidRequest(
                "managed-network execution attempt must start at one".into(),
            ));
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
#[serde(rename_all = "snake_case")]
enum RegistryPhase {
    Intent,
    NetworkVerified,
    Ready,
}

impl RegistryPhase {
    fn sequence(&self) -> u8 {
        match self {
            Self::Intent => 0,
            Self::NetworkVerified => 1,
            Self::Ready => 2,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
struct ManagedNetworkRecord {
    schema_version: String,
    owner: ManagedNetworkOwner,
    provider: RuntimeProvider,
    network_name: String,
    policy_id: String,
    created_at: DateTime<Utc>,
    expires_at: DateTime<Utc>,
    phase: RegistryPhase,
    network_id: Option<String>,
    policy_sha256: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ManagedNetworkCleanupOutcome {
    pub removed: bool,
    pub detail: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Default)]
pub struct ManagedNetworkReconciliationSummary {
    pub reconciled: usize,
    pub incomplete: usize,
    pub details: Vec<String>,
}

/// The file consumed by the isolated host-side SOCKS gateway.
///
/// It is intentionally derived only from already-frozen external plans. Creating this
/// policy does not imply that an engine is packaged, compatible, or runnable.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct EgressGatewayPolicy {
    pub schema_version: String,
    pub policy_id: String,
    pub expires_at: DateTime<Utc>,
    pub listen_address: SocketAddr,
    pub allowed_client_network: IpNet,
    pub limits: EgressGatewayLimits,
    pub provenance: EgressGatewayProvenance,
    pub destinations: Vec<GatewayDestination>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum EgressGatewayProvenance {
    ExternalAssetGrants {
        case_id: String,
        grant_ids: Vec<String>,
        activities: Vec<ExternalActivity>,
    },
    ProviderService {
        case_id: String,
        source_id: String,
        source_kind: String,
        source_profile: String,
        manifest_id: String,
        manifest_revision: String,
    },
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct ProviderServiceEgressRequest {
    pub case_id: String,
    pub source_id: String,
    pub source_kind: String,
    pub source_profile: String,
    pub manifest_id: String,
    pub manifest_revision: String,
    pub exact_destinations: Vec<String>,
    pub expires_at: DateTime<Utc>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ResolvedProviderServicePlan {
    request: ProviderServiceEgressRequest,
    frozen_at: DateTime<Utc>,
    destinations: Vec<GatewayDestination>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct EgressGatewayLimits {
    pub max_concurrency: usize,
    pub max_connections_per_second: usize,
    pub connect_timeout_seconds: u64,
    pub max_connection_seconds: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
#[serde(deny_unknown_fields)]
pub struct GatewayDestination {
    pub hostname: Option<String>,
    pub addresses: BTreeSet<IpAddr>,
    pub ports: BTreeSet<u16>,
    pub allow_sensitive_networks: bool,
}

impl EgressGatewayPolicy {
    pub fn from_resolved_plans(
        policy_id: impl Into<String>,
        listen_address: SocketAddr,
        allowed_client_network: IpNet,
        plans: &[ResolvedExternalPlan],
        now: DateTime<Utc>,
    ) -> AppResult<Self> {
        let policy_id = policy_id.into();
        validate_policy_id(&policy_id)?;
        validate_bridge_network(allowed_client_network, listen_address.ip())?;
        if listen_address.port() != GATEWAY_PORT {
            return Err(AppError::InvalidRequest(format!(
                "egress gateway must listen on port {GATEWAY_PORT}"
            )));
        }
        if plans.is_empty() || plans.len() > MAX_EXTERNAL_PLANS_PER_LEASE {
            return Err(AppError::NotAuthorized(
                "managed egress requires one or more bounded frozen plans".into(),
            ));
        }

        let expected_case_id = plans[0].case_id.as_str();
        let mut expires_at = now + ChronoDuration::hours(24);
        let mut max_concurrency = usize::MAX;
        let mut max_connections_per_second = usize::MAX;
        let mut timeout_seconds = u64::MAX;
        let mut endpoint_count = 0_usize;
        let mut destinations = Vec::with_capacity(plans.len());
        let mut grant_ids = Vec::with_capacity(plans.len());
        let mut activities = BTreeSet::new();

        for plan in plans {
            validate_resolved_plan(plan, expected_case_id, now)?;
            grant_ids.push(plan.grant_id.clone());
            activities.insert(plan.activity);
            expires_at = expires_at.min(plan.expires_at);
            max_concurrency = max_concurrency.min(usize::from(plan.rate_policy.concurrency));
            max_connections_per_second =
                max_connections_per_second.min(usize::from(plan.rate_policy.requests_per_second));
            timeout_seconds = timeout_seconds.min(u64::from(plan.rate_policy.timeout_seconds));

            let plan_endpoints = plan
                .resolution
                .addresses
                .len()
                .checked_mul(plan.ports.len())
                .ok_or_else(|| {
                    AppError::InvalidRequest("external destination set is too large".into())
                })?;
            endpoint_count = endpoint_count.checked_add(plan_endpoints).ok_or_else(|| {
                AppError::InvalidRequest("external destination set is too large".into())
            })?;
            if endpoint_count > MAX_AUTHORIZED_ENDPOINTS {
                return Err(AppError::InvalidRequest(format!(
                    "managed egress supports at most {MAX_AUTHORIZED_ENDPOINTS} frozen address-port pairs"
                )));
            }
            if plan
                .resolution
                .addresses
                .iter()
                .any(|address| allowed_client_network.contains(address))
            {
                return Err(AppError::NotAuthorized(
                    "an authorized destination overlaps the isolated scanner bridge".into(),
                ));
            }

            destinations.push(GatewayDestination {
                hostname: match &plan.target {
                    CanonicalTarget::Hostname(hostname) => Some(hostname.clone()),
                    CanonicalTarget::Address(_) | CanonicalTarget::Network(_) => None,
                },
                addresses: plan.resolution.addresses.clone(),
                ports: plan.ports.clone(),
                allow_sensitive_networks: plan.allow_sensitive_networks,
            });
        }

        destinations.sort();
        destinations.dedup();
        grant_ids.sort();
        grant_ids.dedup();
        if destinations.is_empty() || expires_at <= now {
            return Err(AppError::NotAuthorized(
                "managed egress policy is empty or expired".into(),
            ));
        }

        Ok(Self {
            schema_version: POLICY_SCHEMA_VERSION.into(),
            policy_id,
            expires_at,
            listen_address,
            allowed_client_network,
            limits: EgressGatewayLimits {
                max_concurrency,
                max_connections_per_second,
                connect_timeout_seconds: timeout_seconds.min(120),
                max_connection_seconds: timeout_seconds.min(86_400),
            },
            provenance: EgressGatewayProvenance::ExternalAssetGrants {
                case_id: expected_case_id.to_owned(),
                grant_ids,
                activities: activities.into_iter().collect(),
            },
            destinations,
        })
    }

    pub fn from_provider_service_plan(
        policy_id: impl Into<String>,
        listen_address: SocketAddr,
        allowed_client_network: IpNet,
        plan: &ResolvedProviderServicePlan,
        now: DateTime<Utc>,
    ) -> AppResult<Self> {
        let policy_id = policy_id.into();
        validate_policy_id(&policy_id)?;
        validate_bridge_network(allowed_client_network, listen_address.ip())?;
        if listen_address.port() != GATEWAY_PORT {
            return Err(AppError::InvalidRequest(format!(
                "egress gateway must listen on port {GATEWAY_PORT}"
            )));
        }
        validate_provider_service_request_static(&plan.request, now)?;
        if plan.frozen_at > now
            || plan.destinations.is_empty()
            || plan.destinations.len() > MAX_DESTINATIONS
        {
            return Err(AppError::NotAuthorized(
                "provider-service plan is empty, future-dated, or oversized".into(),
            ));
        }
        let mut endpoint_count = 0_usize;
        for destination in &plan.destinations {
            endpoint_count = endpoint_count
                .checked_add(destination.addresses.len())
                .ok_or_else(|| {
                    AppError::InvalidRequest("provider endpoint set is too large".into())
                })?;
            if endpoint_count > MAX_AUTHORIZED_ENDPOINTS
                || destination.hostname.is_none()
                || destination.ports != BTreeSet::from([443])
                || destination.allow_sensitive_networks
                || destination.addresses.iter().any(|address| {
                    is_sensitive_address(*address)
                        || is_cloud_metadata(*address)
                        || allowed_client_network.contains(address)
                })
            {
                return Err(AppError::NotAuthorized(
                    "provider-service plan contains an unbounded or sensitive endpoint".into(),
                ));
            }
        }
        Ok(Self {
            schema_version: POLICY_SCHEMA_VERSION.into(),
            policy_id,
            expires_at: plan.request.expires_at.min(now + ChronoDuration::hours(1)),
            listen_address,
            allowed_client_network,
            limits: EgressGatewayLimits {
                max_concurrency: 10,
                max_connections_per_second: 25,
                connect_timeout_seconds: 30,
                max_connection_seconds: 300,
            },
            provenance: EgressGatewayProvenance::ProviderService {
                case_id: plan.request.case_id.clone(),
                source_id: plan.request.source_id.clone(),
                source_kind: plan.request.source_kind.clone(),
                source_profile: plan.request.source_profile.clone(),
                manifest_id: plan.request.manifest_id.clone(),
                manifest_revision: plan.request.manifest_revision.clone(),
            },
            destinations: plan.destinations.clone(),
        })
    }

    fn allowed_destination_labels(&self) -> Vec<String> {
        let mut labels = BTreeSet::new();
        for destination in &self.destinations {
            for port in &destination.ports {
                if let Some(hostname) = &destination.hostname {
                    labels.insert(format!("{hostname}:{port}"));
                } else {
                    for address in &destination.addresses {
                        labels.insert(SocketAddr::new(*address, *port).to_string());
                    }
                }
            }
        }
        labels.into_iter().collect()
    }
}

pub fn resolve_provider_service_plan(
    request: ProviderServiceEgressRequest,
    now: DateTime<Utc>,
) -> AppResult<ResolvedProviderServicePlan> {
    validate_provider_service_request_static(&request, now)?;
    let mut destinations = Vec::with_capacity(request.exact_destinations.len());
    let mut total_addresses = 0_usize;
    for endpoint in &request.exact_destinations {
        let (hostname, port) = parse_exact_provider_destination(endpoint)?;
        let addresses = (hostname.as_str(), port)
            .to_socket_addrs()
            .map_err(|error| {
                AppError::NotAvailable(format!(
                    "provider endpoint {hostname} DNS resolution failed: {error}"
                ))
            })?
            .map(|socket| socket.ip())
            .collect::<BTreeSet<_>>();
        if addresses.is_empty() || addresses.len() > 64 {
            return Err(AppError::NotAvailable(format!(
                "provider endpoint {hostname} did not resolve to a bounded address set"
            )));
        }
        if addresses
            .iter()
            .any(|address| is_sensitive_address(*address) || is_cloud_metadata(*address))
        {
            return Err(AppError::NotAuthorized(format!(
                "provider endpoint {hostname} resolved to a sensitive or metadata address"
            )));
        }
        total_addresses = total_addresses
            .checked_add(addresses.len())
            .ok_or_else(|| AppError::InvalidRequest("provider endpoint set is too large".into()))?;
        if total_addresses > 1_024 {
            return Err(AppError::InvalidRequest(
                "provider endpoint resolution exceeds 1024 frozen addresses".into(),
            ));
        }
        destinations.push(GatewayDestination {
            hostname: Some(hostname),
            addresses,
            ports: BTreeSet::from([port]),
            allow_sensitive_networks: false,
        });
    }
    destinations.sort();
    destinations.dedup();
    Ok(ResolvedProviderServicePlan {
        request,
        frozen_at: now,
        destinations,
    })
}

/// Validates the complete static provider-service contract without resolving
/// DNS, opening a socket, provisioning a network, or starting the gateway.
/// Execution still resolves and freezes the exact endpoint addresses in
/// [`resolve_provider_service_plan`] immediately before provisioning.
pub(crate) fn validate_provider_service_request_static(
    request: &ProviderServiceEgressRequest,
    now: DateTime<Utc>,
) -> AppResult<()> {
    for (label, value) in [
        ("case", request.case_id.as_str()),
        ("source", request.source_id.as_str()),
        ("source kind", request.source_kind.as_str()),
        ("source profile", request.source_profile.as_str()),
        ("manifest", request.manifest_id.as_str()),
        ("manifest revision", request.manifest_revision.as_str()),
    ] {
        if value.trim().is_empty() || value.len() > 256 || value.contains(['\n', '\r', '\0']) {
            return Err(AppError::InvalidRequest(format!(
                "provider-service {label} provenance is invalid"
            )));
        }
    }
    if request.expires_at <= now || request.expires_at > now + ChronoDuration::hours(1) {
        return Err(AppError::NotAuthorized(
            "provider-service authorization must be live and no longer than one hour".into(),
        ));
    }
    if request.exact_destinations.is_empty()
        || request.exact_destinations.len() > 128
        || request
            .exact_destinations
            .iter()
            .collect::<BTreeSet<_>>()
            .len()
            != request.exact_destinations.len()
    {
        return Err(AppError::InvalidRequest(
            "provider-service manifest must declare a finite unique endpoint list".into(),
        ));
    }
    for endpoint in &request.exact_destinations {
        let (hostname, _) = parse_exact_provider_destination(endpoint)?;
        if !provider_hostname_matches_source(&request.source_kind, &hostname) {
            return Err(AppError::NotAvailable(format!(
                "provider endpoint {hostname} is not valid for source kind {}",
                request.source_kind
            )));
        }
    }
    Ok(())
}

fn provider_hostname_matches_source(source_kind: &str, hostname: &str) -> bool {
    match source_kind {
        "aws_organization" => hostname.ends_with(".amazonaws.com"),
        "azure_tenant" => matches!(
            hostname,
            "management.azure.com" | "graph.microsoft.com" | "login.microsoftonline.com"
        ),
        "gcp_organization" => hostname.ends_with(".googleapis.com"),
        "microsoft365_tenant" => matches!(
            hostname,
            "graph.microsoft.com"
                | "login.microsoftonline.com"
                | "manage.office.com"
                | "outlook.office.com"
        ),
        // These public-source profiles still require a pinned manifest with
        // exact FQDNs; unlike cloud APIs there is no shared vendor suffix.
        "dns" | "certificate_transparency" => true,
        _ => false,
    }
}

fn parse_exact_provider_destination(value: &str) -> AppResult<(String, u16)> {
    if value.is_empty()
        || value.len() > 260
        || value.contains(['*', '/', '\\', '\n', '\r', '\0', '@'])
        || value.contains("://")
    {
        return Err(AppError::NotAvailable(
            "provider-service endpoint is not an exact FQDN:443 destination".into(),
        ));
    }
    let (hostname, port) = value.rsplit_once(':').ok_or_else(|| {
        AppError::NotAvailable(
            "provider-service endpoint must use exact lowercase FQDN:443 syntax".into(),
        )
    })?;
    if port != "443" || hostname.contains(':') || hostname != hostname.to_ascii_lowercase() {
        return Err(AppError::NotAvailable(
            "provider-service endpoint must use exact lowercase FQDN:443 syntax".into(),
        ));
    }
    let canonical = CanonicalTarget::parse(hostname)?;
    let CanonicalTarget::Hostname(canonical) = canonical else {
        return Err(AppError::NotAvailable(
            "provider-service endpoint must be a fully qualified hostname".into(),
        ));
    };
    if canonical != hostname {
        return Err(AppError::NotAvailable(
            "provider-service endpoint is not in canonical lowercase form".into(),
        ));
    }
    Ok((canonical, 443))
}

/// Owns the runtime network and gateway process for one bounded scan operation.
pub struct ManagedNetworkController {
    provider: RuntimeProvider,
    gateway_binary: PathBuf,
    policy_directory: PathBuf,
    registry_directory: PathBuf,
    runtime: Arc<dyn RuntimeCommands>,
    gateway_launcher: Arc<dyn GatewayLauncher>,
    readiness: Arc<dyn GatewayReadiness>,
}

impl ManagedNetworkController {
    pub fn new(
        provider: RuntimeProvider,
        gateway_binary: impl AsRef<Path>,
        policy_directory: impl AsRef<Path>,
    ) -> AppResult<Self> {
        require_compatibility_provider(provider)?;
        let local_registry = policy_directory.as_ref().join(".managed-network-registry");
        ensure_private_directory(&local_registry)?;
        Self::with_components(
            provider,
            gateway_binary.as_ref(),
            policy_directory.as_ref(),
            &local_registry,
            Arc::new(DirectRuntimeCommands),
            Arc::new(DirectGatewayLauncher),
            Arc::new(SocketGatewayReadiness),
        )
    }

    pub fn new_with_registry(
        provider: RuntimeProvider,
        gateway_binary: impl AsRef<Path>,
        policy_directory: impl AsRef<Path>,
        registry_directory: impl AsRef<Path>,
    ) -> AppResult<Self> {
        require_compatibility_provider(provider)?;
        Self::with_components(
            provider,
            gateway_binary.as_ref(),
            policy_directory.as_ref(),
            registry_directory.as_ref(),
            Arc::new(DirectRuntimeCommands),
            Arc::new(DirectGatewayLauncher),
            Arc::new(SocketGatewayReadiness),
        )
    }

    pub fn new_with_registry_context(
        context: RuntimeCommandContext,
        gateway_binary: impl AsRef<Path>,
        policy_directory: impl AsRef<Path>,
        registry_directory: impl AsRef<Path>,
    ) -> AppResult<Self> {
        let provider = context.provider();
        Self::with_components(
            provider,
            gateway_binary.as_ref(),
            policy_directory.as_ref(),
            registry_directory.as_ref(),
            Arc::new(ContextRuntimeCommands { context }),
            Arc::new(DirectGatewayLauncher),
            Arc::new(SocketGatewayReadiness),
        )
    }

    fn with_components(
        provider: RuntimeProvider,
        gateway_binary: &Path,
        policy_directory: &Path,
        registry_directory: &Path,
        runtime: Arc<dyn RuntimeCommands>,
        gateway_launcher: Arc<dyn GatewayLauncher>,
        readiness: Arc<dyn GatewayReadiness>,
    ) -> AppResult<Self> {
        let gateway_binary = inspect_gateway_binary(gateway_binary)?;
        let policy_directory = validate_policy_directory(policy_directory)?;
        let registry_directory = validate_policy_directory(registry_directory)?;
        Ok(Self {
            provider,
            gateway_binary,
            policy_directory,
            registry_directory,
            runtime,
            gateway_launcher,
            readiness,
        })
    }

    pub fn provision(
        &self,
        owner: &ManagedNetworkOwner,
        plans: &[ResolvedExternalPlan],
        now: DateTime<Utc>,
    ) -> AppResult<ManagedNetworkLease> {
        owner.validate()?;
        inspect_gateway_binary(&self.gateway_binary)?;
        validate_policy_directory(&self.policy_directory)?;
        validate_policy_directory(&self.registry_directory)?;
        // Validate the plans before making any host or runtime changes. The bridge-specific
        // overlap check is repeated after the runtime allocates its private subnet.
        validate_plans_without_bridge(plans, now)?;
        if plans
            .first()
            .is_none_or(|plan| plan.case_id != owner.case_id)
        {
            return Err(AppError::InvalidRequest(
                "managed-network owner does not match the frozen external plans".into(),
            ));
        }

        let expires_at = plans
            .iter()
            .map(|plan| plan.expires_at)
            .min()
            .unwrap_or(now)
            .min(now + ChronoDuration::hours(24));
        self.provision_policy(owner, expires_at, now, |policy_id, listen, subnet| {
            EgressGatewayPolicy::from_resolved_plans(policy_id, listen, subnet, plans, now)
        })
    }

    pub fn provision_provider_service(
        &self,
        owner: &ManagedNetworkOwner,
        plan: &ResolvedProviderServicePlan,
        now: DateTime<Utc>,
    ) -> AppResult<ManagedNetworkLease> {
        owner.validate()?;
        inspect_gateway_binary(&self.gateway_binary)?;
        validate_policy_directory(&self.policy_directory)?;
        validate_policy_directory(&self.registry_directory)?;
        validate_provider_service_request_static(&plan.request, now)?;
        if plan.request.case_id != owner.case_id {
            return Err(AppError::InvalidRequest(
                "managed-network owner does not match provider-service provenance".into(),
            ));
        }
        self.provision_policy(
            owner,
            plan.request.expires_at.min(now + ChronoDuration::hours(1)),
            now,
            |policy_id, listen, subnet| {
                EgressGatewayPolicy::from_provider_service_plan(
                    policy_id, listen, subnet, plan, now,
                )
            },
        )
    }

    fn provision_policy<F>(
        &self,
        owner: &ManagedNetworkOwner,
        expires_at: DateTime<Utc>,
        now: DateTime<Utc>,
        build_policy: F,
    ) -> AppResult<ManagedNetworkLease>
    where
        F: FnOnce(&str, SocketAddr, IpNet) -> AppResult<EgressGatewayPolicy>,
    {
        let unique = Uuid::new_v4().simple().to_string();
        let policy_id = format!("egress-{unique}");
        let network_name = format!("ass-egress-{unique}");
        let expected_labels = expected_labels(&policy_id);
        let mut record = ManagedNetworkRecord {
            schema_version: REGISTRY_SCHEMA_VERSION.into(),
            owner: owner.clone(),
            provider: self.provider,
            network_name: network_name.clone(),
            policy_id: policy_id.clone(),
            created_at: now,
            expires_at,
            phase: RegistryPhase::Intent,
            network_id: None,
            policy_sha256: None,
        };
        let mut registry_files = vec![write_registry_snapshot(&self.registry_directory, &record)?];
        if let Err(error) = create_internal_network(
            self.runtime.as_ref(),
            self.provider,
            &network_name,
            &expected_labels,
        ) {
            for file in registry_files {
                let _ = remove_registry_file(&file);
            }
            return Err(error);
        }

        let mut lease = ManagedNetworkLease {
            provider: self.provider,
            runtime: Arc::clone(&self.runtime),
            network_name: Some(network_name.clone()),
            network_id: None,
            remove_unverified_network: true,
            expected_labels: expected_labels.clone(),
            gateway_process: None,
            policy_file: None,
            network_policy: None,
            egress_policy: None,
            registry_files: std::mem::take(&mut registry_files),
        };

        let inspected = inspect_network(
            self.runtime.as_ref(),
            self.provider,
            &network_name,
            &expected_labels,
        )?;
        lease.network_id = Some(inspected.id.clone());
        lease.remove_unverified_network = false;
        record.phase = RegistryPhase::NetworkVerified;
        record.network_id = Some(inspected.id.clone());
        lease
            .registry_files
            .push(write_registry_snapshot(&self.registry_directory, &record)?);

        let listen_address = SocketAddr::new(inspected.gateway, GATEWAY_PORT);
        let egress_policy = build_policy(&policy_id, listen_address, inspected.subnet)?;
        if egress_policy.expires_at != expires_at {
            return Err(AppError::Internal(
                "managed egress policy lifetime diverged from its durable registry".into(),
            ));
        }
        let policy_file = write_policy_file(&self.policy_directory, &egress_policy)?;
        record.phase = RegistryPhase::Ready;
        record.policy_sha256 = Some(hex::encode(policy_file.sha256));
        lease
            .registry_files
            .push(write_registry_snapshot(&self.registry_directory, &record)?);
        lease.policy_file = Some(policy_file);

        let gateway_process = self
            .gateway_launcher
            .spawn(
                &self.gateway_binary,
                lease.policy_path().expect("policy path set"),
            )
            .map_err(|error| {
                AppError::Runtime(format!("egress gateway could not start: {error}"))
            })?;
        lease.gateway_process = Some(gateway_process);
        self.readiness.wait_until_ready(
            lease
                .gateway_process
                .as_mut()
                .expect("gateway process set")
                .as_mut(),
            listen_address,
        )?;

        let endpoint = gateway_endpoint(inspected.gateway);
        let network_policy = NetworkPolicy::managed(
            network_name,
            policy_id,
            egress_policy.allowed_destination_labels(),
            endpoint,
        )?;
        lease.network_policy = Some(network_policy);
        lease.egress_policy = Some(egress_policy);
        Ok(lease)
    }
}

/// Keeping this value alive keeps the gateway process and its isolated bridge alive.
/// Explicit cleanup reports failures; `Drop` still performs the same best-effort cleanup.
pub struct ManagedNetworkLease {
    provider: RuntimeProvider,
    runtime: Arc<dyn RuntimeCommands>,
    network_name: Option<String>,
    network_id: Option<String>,
    remove_unverified_network: bool,
    expected_labels: BTreeMap<String, String>,
    gateway_process: Option<Box<dyn GatewayProcess>>,
    policy_file: Option<PolicyFile>,
    network_policy: Option<NetworkPolicy>,
    egress_policy: Option<EgressGatewayPolicy>,
    registry_files: Vec<RegistryFile>,
}

impl ManagedNetworkLease {
    pub fn network_policy(&self) -> &NetworkPolicy {
        self.network_policy
            .as_ref()
            .expect("a returned managed-network lease always has a policy")
    }

    pub fn egress_policy(&self) -> &EgressGatewayPolicy {
        self.egress_policy
            .as_ref()
            .expect("a returned managed-network lease always has an egress policy")
    }

    pub fn network_name(&self) -> Option<&str> {
        self.network_name.as_deref()
    }

    pub fn durable_identity(&self) -> AppResult<ManagedNetworkIdentity> {
        let policy = self.egress_policy.as_ref().ok_or_else(|| {
            AppError::Runtime("managed network has no verified egress policy".into())
        })?;
        let policy_file = self.policy_file.as_ref().ok_or_else(|| {
            AppError::Runtime("managed network has no verified policy file".into())
        })?;
        let identity = ManagedNetworkIdentity {
            schema_version: REGISTRY_SCHEMA_VERSION.into(),
            provider: self.provider,
            network_name: self
                .network_name
                .clone()
                .ok_or_else(|| AppError::Runtime("managed network has no name".into()))?,
            network_id: self
                .network_id
                .clone()
                .ok_or_else(|| AppError::Runtime("managed network has no runtime id".into()))?,
            policy_id: policy.policy_id.clone(),
            policy_sha256: hex::encode(policy_file.sha256),
            expires_at: policy.expires_at,
            provenance: policy.provenance.clone(),
        };
        identity.validate()?;
        Ok(identity)
    }

    pub fn policy_path(&self) -> Option<&Path> {
        self.policy_file
            .as_ref()
            .map(|policy| policy.path.as_path())
    }

    pub fn is_active(&self) -> bool {
        self.gateway_process.is_some()
            || self.network_name.is_some()
            || self.policy_file.is_some()
            || !self.registry_files.is_empty()
    }

    pub fn cleanup(&mut self) -> AppResult<()> {
        self.cleanup_with_outcome().map(|_| ())
    }

    pub fn cleanup_with_outcome(&mut self) -> AppResult<ManagedNetworkCleanupOutcome> {
        let mut failures = Vec::new();
        let mut details = Vec::new();

        if let Some(mut process) = self.gateway_process.take() {
            if let Err(error) = stop_gateway(process.as_mut()) {
                failures.push(error.to_string());
                self.gateway_process = Some(process);
            } else {
                details.push("gateway process stopped".to_owned());
            }
        }

        if let Some(network_name) = self.network_name.clone() {
            let removal = if self.remove_unverified_network {
                remove_intent_network(
                    self.runtime.as_ref(),
                    self.provider,
                    &network_name,
                    &self.expected_labels,
                )
            } else {
                self.remove_verified_network(&network_name)
            };
            match removal {
                Ok(()) => {
                    self.network_name = None;
                    self.network_id = None;
                    details.push("exact internal network removed or already absent".to_owned());
                }
                Err(error) => failures.push(error.to_string()),
            }
        }

        if let Some(policy_file) = self.policy_file.as_ref() {
            match remove_policy_file(policy_file) {
                Ok(()) => {
                    self.policy_file = None;
                    details.push("exact policy file removed or already absent".to_owned());
                }
                Err(error) => failures.push(error.to_string()),
            }
        }

        if failures.is_empty() {
            for registry_file in std::mem::take(&mut self.registry_files) {
                if let Err(error) = remove_registry_file(&registry_file) {
                    failures.push(error.to_string());
                    self.registry_files.push(registry_file);
                }
            }
        }

        if failures.is_empty() {
            self.network_policy = None;
            self.egress_policy = None;
            details.push("durable recovery records removed".to_owned());
            Ok(ManagedNetworkCleanupOutcome {
                removed: true,
                detail: bounded_cleanup_detail(&details.join("; ")),
            })
        } else {
            Err(AppError::Runtime(format!(
                "managed network cleanup was incomplete: {}",
                failures.join("; ")
            )))
        }
    }

    fn remove_verified_network(&self, network_name: &str) -> AppResult<()> {
        let output = runtime_output(
            self.runtime.as_ref(),
            self.provider,
            &["network".into(), "inspect".into(), network_name.into()],
        )?;
        if !output.success {
            if runtime_reports_absent(&output.stderr) {
                return Ok(());
            }
            return Err(runtime_failure(
                "managed network cleanup inspection",
                &output,
            ));
        }
        let inspected = parse_network_inspect(
            self.provider,
            &output.stdout,
            network_name,
            &self.expected_labels,
        )?;
        if Some(inspected.id.as_str()) != self.network_id.as_deref() {
            return Err(AppError::NotAuthorized(format!(
                "refusing to remove replaced container network {network_name}"
            )));
        }
        remove_network(self.runtime.as_ref(), self.provider, &inspected.id)
    }
}

impl Drop for ManagedNetworkLease {
    fn drop(&mut self) {
        let _ = self.cleanup();
    }
}

#[derive(Debug)]
struct InspectedNetwork {
    id: String,
    subnet: IpNet,
    gateway: IpAddr,
}

#[derive(Debug)]
struct RuntimeOutput {
    success: bool,
    stdout: Vec<u8>,
    stderr: Vec<u8>,
}

trait RuntimeCommands: Send + Sync {
    fn output(&self, provider: RuntimeProvider, args: &[OsString]) -> io::Result<RuntimeOutput>;
}

struct DirectRuntimeCommands;

impl RuntimeCommands for DirectRuntimeCommands {
    fn output(&self, provider: RuntimeProvider, args: &[OsString]) -> io::Result<RuntimeOutput> {
        if provider == RuntimeProvider::ManagedLocal {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "managed-local runtime requires its verified private command context",
            ));
        }
        let context = RuntimeCommandContext::compatibility(
            provider,
            PathBuf::from(runtime_program(provider)),
        );
        let output = context.output(args, MAX_INSPECT_BYTES as u64, RUNTIME_COMMAND_TIMEOUT)?;
        Ok(RuntimeOutput {
            success: output.status.success(),
            stdout: output.stdout,
            stderr: output.stderr,
        })
    }
}

struct ContextRuntimeCommands {
    context: RuntimeCommandContext,
}

impl RuntimeCommands for ContextRuntimeCommands {
    fn output(&self, provider: RuntimeProvider, args: &[OsString]) -> io::Result<RuntimeOutput> {
        if provider != self.context.provider() {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "durable managed-network provider differs from the trusted runtime context",
            ));
        }
        let output =
            self.context
                .output(args, MAX_INSPECT_BYTES as u64, RUNTIME_COMMAND_TIMEOUT)?;
        Ok(RuntimeOutput {
            success: output.status.success(),
            stdout: output.stdout,
            stderr: output.stderr,
        })
    }
}

trait GatewayProcess: Send {
    fn has_exited(&mut self) -> io::Result<bool>;
    fn kill(&mut self) -> io::Result<()>;
    fn wait(&mut self) -> io::Result<()>;
}

impl GatewayProcess for Child {
    fn has_exited(&mut self) -> io::Result<bool> {
        self.try_wait().map(|status| status.is_some())
    }

    fn kill(&mut self) -> io::Result<()> {
        Child::kill(self)
    }

    fn wait(&mut self) -> io::Result<()> {
        Child::wait(self).map(|_| ())
    }
}

trait GatewayLauncher: Send + Sync {
    fn spawn(&self, binary: &Path, policy_path: &Path) -> io::Result<Box<dyn GatewayProcess>>;
}

struct DirectGatewayLauncher;

impl GatewayLauncher for DirectGatewayLauncher {
    fn spawn(&self, binary: &Path, policy_path: &Path) -> io::Result<Box<dyn GatewayProcess>> {
        let mut command = Command::new(binary);
        command.arg("--policy").arg(policy_path);
        command.env_clear();
        command.stdin(Stdio::null());
        command.stdout(Stdio::null());
        command.stderr(Stdio::null());
        command.spawn().map(|child| Box::new(child) as _)
    }
}

trait GatewayReadiness: Send + Sync {
    fn wait_until_ready(
        &self,
        process: &mut dyn GatewayProcess,
        listen_address: SocketAddr,
    ) -> AppResult<()>;
}

struct SocketGatewayReadiness;

impl GatewayReadiness for SocketGatewayReadiness {
    fn wait_until_ready(
        &self,
        process: &mut dyn GatewayProcess,
        listen_address: SocketAddr,
    ) -> AppResult<()> {
        let deadline = Instant::now() + GATEWAY_READY_TIMEOUT;
        loop {
            if process.has_exited().map_err(|error| {
                AppError::Runtime(format!("egress gateway could not be observed: {error}"))
            })? {
                return Err(AppError::Runtime(
                    "egress gateway exited before becoming ready".into(),
                ));
            }
            if TcpStream::connect_timeout(&listen_address, GATEWAY_CONNECT_PROBE_TIMEOUT).is_ok() {
                return Ok(());
            }
            if Instant::now() >= deadline {
                return Err(AppError::Runtime(
                    "egress gateway did not become ready within five seconds".into(),
                ));
            }
            thread::sleep(GATEWAY_READY_INTERVAL);
        }
    }
}

#[derive(Debug)]
struct PolicyFile {
    path: PathBuf,
    sha256: [u8; 32],
}

#[derive(Debug)]
struct RegistryFile {
    path: PathBuf,
    sha256: [u8; 32],
}

/// Reconciles only resources named by bounded, backend-owned recovery records
/// or by an exact durable execution identity. It deliberately has no prefix or
/// "remove all managed" operation.
pub struct ManagedNetworkRegistry {
    root: PathBuf,
    artifact_root: PathBuf,
    runtime: Arc<dyn RuntimeCommands>,
}

impl ManagedNetworkRegistry {
    pub fn new(root: impl AsRef<Path>, artifact_root: impl AsRef<Path>) -> AppResult<Self> {
        Self::with_runtime(
            root.as_ref(),
            artifact_root.as_ref(),
            Arc::new(DirectRuntimeCommands),
        )
    }

    pub fn new_with_runtime_context(
        root: impl AsRef<Path>,
        artifact_root: impl AsRef<Path>,
        context: RuntimeCommandContext,
    ) -> AppResult<Self> {
        Self::with_runtime(
            root.as_ref(),
            artifact_root.as_ref(),
            Arc::new(ContextRuntimeCommands { context }),
        )
    }

    fn with_runtime(
        root: &Path,
        artifact_root: &Path,
        runtime: Arc<dyn RuntimeCommands>,
    ) -> AppResult<Self> {
        let root = validate_policy_directory(root)?;
        let artifact_root = validate_policy_directory(artifact_root)?;
        if !root.starts_with(&artifact_root) || root == artifact_root {
            return Err(AppError::NotAuthorized(
                "managed-network registry must be a dedicated artifact subdirectory".into(),
            ));
        }
        Ok(Self {
            root,
            artifact_root,
            runtime,
        })
    }

    pub fn root(&self) -> &Path {
        &self.root
    }

    pub fn reconcile_all(
        &self,
        now: DateTime<Utc>,
    ) -> AppResult<ManagedNetworkReconciliationSummary> {
        let mut summary = ManagedNetworkReconciliationSummary::default();
        let groups = self.load_groups(now, &mut summary)?;
        for (_policy_id, entries) in groups {
            match self.reconcile_record_group(&entries) {
                Ok(outcome) => {
                    summary.reconciled = summary.reconciled.saturating_add(1);
                    push_summary_detail(&mut summary, outcome.detail);
                }
                Err(error) => {
                    summary.incomplete = summary.incomplete.saturating_add(1);
                    push_summary_detail(
                        &mut summary,
                        bounded_cleanup_detail(&format!(
                            "managed-network recovery was safely retained: {error}"
                        )),
                    );
                }
            }
        }
        Ok(summary)
    }

    pub fn reconcile_identity(
        &self,
        owner: &ManagedNetworkOwner,
        identity: &ManagedNetworkIdentity,
        now: DateTime<Utc>,
    ) -> AppResult<ManagedNetworkCleanupOutcome> {
        owner.validate()?;
        identity.validate()?;
        validate_identity_relation(identity)?;
        let provenance_case = match &identity.provenance {
            EgressGatewayProvenance::ExternalAssetGrants { case_id, .. }
            | EgressGatewayProvenance::ProviderService { case_id, .. } => case_id,
        };
        if provenance_case != &owner.case_id {
            return Err(AppError::NotAuthorized(
                "managed-network checkpoint provenance belongs to a different case".into(),
            ));
        }

        let mut ignored_summary = ManagedNetworkReconciliationSummary::default();
        let mut groups = self.load_groups(now, &mut ignored_summary)?;
        let entries = groups.remove(&identity.policy_id).unwrap_or_default();
        if !entries.is_empty() {
            let latest = latest_record(&entries)?;
            if latest.owner != *owner
                || latest.provider != identity.provider
                || latest.network_name != identity.network_name
                || latest.policy_id != identity.policy_id
                || latest.expires_at != identity.expires_at
                || latest
                    .network_id
                    .as_deref()
                    .is_some_and(|id| id != identity.network_id)
                || latest
                    .policy_sha256
                    .as_deref()
                    .is_some_and(|sha| sha != identity.policy_sha256)
            {
                return Err(AppError::NotAuthorized(
                    "durable checkpoint does not match its managed-network registry record".into(),
                ));
            }
        }

        self.remove_exact_runtime_network(
            identity.provider,
            &identity.network_name,
            &identity.network_id,
            &identity.policy_id,
        )?;
        self.remove_exact_policy(
            &owner.case_id,
            &identity.policy_id,
            identity.expires_at,
            Some(&identity.policy_sha256),
        )?;
        for (_, file) in entries {
            remove_registry_file(&file)?;
        }
        Ok(ManagedNetworkCleanupOutcome {
            removed: true,
            detail: format!(
                "exact managed egress policy {} was reconciled before resume",
                identity.policy_id
            ),
        })
    }

    fn reconcile_record_group(
        &self,
        entries: &[(ManagedNetworkRecord, RegistryFile)],
    ) -> AppResult<ManagedNetworkCleanupOutcome> {
        let latest = latest_record(entries)?;
        let expected_id = latest.network_id.as_deref();
        self.remove_runtime_network_from_record(latest, expected_id)?;
        self.remove_exact_policy(
            &latest.owner.case_id,
            &latest.policy_id,
            latest.expires_at,
            latest.policy_sha256.as_deref(),
        )?;
        for (_, file) in entries {
            remove_registry_file(file)?;
        }
        Ok(ManagedNetworkCleanupOutcome {
            removed: true,
            detail: format!(
                "reconciled exact orphaned managed egress policy {}",
                latest.policy_id
            ),
        })
    }

    fn remove_runtime_network_from_record(
        &self,
        record: &ManagedNetworkRecord,
        expected_id: Option<&str>,
    ) -> AppResult<()> {
        let inspected = inspect_optional_network(
            self.runtime.as_ref(),
            record.provider,
            &record.network_name,
            &expected_labels(&record.policy_id),
        )?;
        let Some(inspected) = inspected else {
            return Ok(());
        };
        if expected_id.is_some_and(|expected| expected != inspected.id) {
            return Err(AppError::NotAuthorized(format!(
                "refusing to remove replaced container network {}",
                record.network_name
            )));
        }
        // Remove by the immutable id returned by the exact name/label/internal
        // inspection, never by a prefix or an unverified reusable name.
        remove_network(self.runtime.as_ref(), record.provider, &inspected.id)
    }

    fn remove_exact_runtime_network(
        &self,
        provider: RuntimeProvider,
        network_name: &str,
        network_id: &str,
        policy_id: &str,
    ) -> AppResult<()> {
        let inspected = inspect_optional_network(
            self.runtime.as_ref(),
            provider,
            network_name,
            &expected_labels(policy_id),
        )?;
        let Some(inspected) = inspected else {
            return Ok(());
        };
        if inspected.id != network_id {
            return Err(AppError::NotAuthorized(format!(
                "refusing to remove replaced container network {network_name}"
            )));
        }
        remove_network(self.runtime.as_ref(), provider, network_id)
    }

    fn remove_exact_policy(
        &self,
        case_id: &str,
        policy_id: &str,
        expires_at: DateTime<Utc>,
        expected_sha256: Option<&str>,
    ) -> AppResult<()> {
        validate_owner_segment(case_id, "case")?;
        validate_policy_id(policy_id)?;
        let case_root = self.artifact_root.join(case_id);
        let policy_directory = case_root.join("network-policies");
        for (directory, expected_parent) in [
            (case_root.as_path(), self.artifact_root.as_path()),
            (policy_directory.as_path(), case_root.as_path()),
        ] {
            let metadata = match fs::symlink_metadata(directory) {
                Ok(metadata) => metadata,
                Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(()),
                Err(error) => return Err(error.into()),
            };
            if metadata.file_type().is_symlink() || !metadata.is_dir() {
                return Err(AppError::NotAuthorized(
                    "managed-network recovery case path is not a real directory".into(),
                ));
            }
            let canonical = directory.canonicalize()?;
            let canonical_parent = expected_parent.canonicalize()?;
            if canonical.parent() != Some(canonical_parent.as_path()) {
                return Err(AppError::NotAuthorized(
                    "managed-network recovery case path escaped the artifact root".into(),
                ));
            }
        }
        let path = policy_directory.join(format!("egress-{policy_id}.json"));
        if path.parent() != Some(policy_directory.as_path()) {
            return Err(AppError::NotAuthorized(
                "managed-network recovery policy path escaped its case directory".into(),
            ));
        }
        let metadata = match fs::symlink_metadata(&path) {
            Ok(metadata) => metadata,
            Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(()),
            Err(error) => return Err(error.into()),
        };
        if metadata.file_type().is_symlink()
            || !metadata.is_file()
            || metadata.len() == 0
            || metadata.len() > MAX_POLICY_BYTES as u64
        {
            return Err(AppError::NotAuthorized(
                "refusing to remove a replaced managed egress policy path".into(),
            ));
        }
        let bytes = fs::read(&path)?;
        let policy: EgressGatewayPolicy = serde_json::from_slice(&bytes).map_err(|_| {
            AppError::NotAuthorized(
                "refusing to remove a malformed managed egress policy file".into(),
            )
        })?;
        if policy.schema_version != POLICY_SCHEMA_VERSION
            || policy.policy_id != policy_id
            || policy.expires_at != expires_at
        {
            return Err(AppError::NotAuthorized(
                "refusing to remove a policy file with a different durable identity".into(),
            ));
        }
        validate_egress_provenance(&policy.provenance)?;
        let provenance_case = match &policy.provenance {
            EgressGatewayProvenance::ExternalAssetGrants { case_id, .. }
            | EgressGatewayProvenance::ProviderService { case_id, .. } => case_id,
        };
        if provenance_case != case_id {
            return Err(AppError::NotAuthorized(
                "refusing to remove a policy file owned by a different case".into(),
            ));
        }
        let actual: [u8; 32] = Sha256::digest(&bytes).into();
        if expected_sha256.is_some_and(|expected| hex::encode(actual) != expected) {
            return Err(AppError::NotAuthorized(
                "refusing to remove a modified managed egress policy file".into(),
            ));
        }
        remove_policy_file(&PolicyFile {
            path,
            sha256: actual,
        })
    }

    fn load_groups(
        &self,
        now: DateTime<Utc>,
        summary: &mut ManagedNetworkReconciliationSummary,
    ) -> AppResult<BTreeMap<String, Vec<(ManagedNetworkRecord, RegistryFile)>>> {
        let mut paths = fs::read_dir(&self.root)?
            .collect::<Result<Vec<_>, _>>()?
            .into_iter()
            .map(|entry| entry.path())
            .collect::<Vec<_>>();
        paths.sort();
        if paths.len() > MAX_REGISTRY_RECORDS {
            return Err(AppError::Runtime(format!(
                "managed-network registry exceeds its bounded limit of {MAX_REGISTRY_RECORDS} records"
            )));
        }
        let mut groups = BTreeMap::<String, Vec<(ManagedNetworkRecord, RegistryFile)>>::new();
        for path in paths {
            match read_registry_snapshot(&self.root, &path, now) {
                Ok((record, file)) => groups
                    .entry(record.policy_id.clone())
                    .or_default()
                    .push((record, file)),
                Err(error) => {
                    summary.incomplete = summary.incomplete.saturating_add(1);
                    push_summary_detail(
                        summary,
                        bounded_cleanup_detail(&format!(
                            "unrecognized managed-network recovery record was retained: {error}"
                        )),
                    );
                }
            }
        }
        for entries in groups.values_mut() {
            entries.sort_by_key(|(record, _)| record.phase.sequence());
        }
        Ok(groups)
    }
}

fn validate_record_shape(record: &ManagedNetworkRecord, now: DateTime<Utc>) -> AppResult<()> {
    if record.schema_version != REGISTRY_SCHEMA_VERSION {
        return Err(AppError::InvalidRequest(
            "managed-network registry schema is unsupported".into(),
        ));
    }
    record.owner.validate()?;
    validate_network_name(&record.network_name)?;
    validate_policy_id(&record.policy_id)?;
    validate_network_policy_relation(&record.network_name, &record.policy_id)?;
    if record.created_at > now + ChronoDuration::minutes(5)
        || record.expires_at <= record.created_at
        || record.expires_at > record.created_at + ChronoDuration::hours(24)
    {
        return Err(AppError::InvalidRequest(
            "managed-network registry lifetime is invalid".into(),
        ));
    }
    match record.phase {
        RegistryPhase::Intent if record.network_id.is_none() && record.policy_sha256.is_none() => {}
        RegistryPhase::NetworkVerified
            if record.network_id.is_some() && record.policy_sha256.is_none() => {}
        RegistryPhase::Ready if record.network_id.is_some() && record.policy_sha256.is_some() => {}
        _ => {
            return Err(AppError::InvalidRequest(
                "managed-network registry phase is inconsistent".into(),
            ));
        }
    }
    if let Some(network_id) = record.network_id.as_deref() {
        validate_runtime_id(network_id)?;
    }
    if let Some(sha256) = record.policy_sha256.as_deref() {
        decode_sha256(sha256)?;
    }
    Ok(())
}

fn validate_record_chain(entries: &[(ManagedNetworkRecord, RegistryFile)]) -> AppResult<()> {
    let Some((first, _)) = entries.first() else {
        return Err(AppError::InvalidRequest(
            "managed-network registry group is empty".into(),
        ));
    };
    let mut previous_sequence = None;
    for (record, _) in entries {
        let sequence = record.phase.sequence();
        if previous_sequence == Some(sequence)
            || record.owner != first.owner
            || record.provider != first.provider
            || record.network_name != first.network_name
            || record.policy_id != first.policy_id
            || record.created_at != first.created_at
            || record.expires_at != first.expires_at
        {
            return Err(AppError::NotAuthorized(
                "managed-network registry snapshots do not form one exact identity chain".into(),
            ));
        }
        previous_sequence = Some(sequence);
    }
    Ok(())
}

fn latest_record(
    entries: &[(ManagedNetworkRecord, RegistryFile)],
) -> AppResult<&ManagedNetworkRecord> {
    validate_record_chain(entries)?;
    entries
        .last()
        .map(|(record, _)| record)
        .ok_or_else(|| AppError::InvalidRequest("managed-network registry group is empty".into()))
}

fn registry_filename(record: &ManagedNetworkRecord) -> String {
    format!(
        "{}.{}-{}.json",
        record.policy_id,
        record.phase.sequence(),
        match record.phase {
            RegistryPhase::Intent => "intent",
            RegistryPhase::NetworkVerified => "network",
            RegistryPhase::Ready => "ready",
        }
    )
}

fn write_registry_snapshot(
    directory: &Path,
    record: &ManagedNetworkRecord,
) -> AppResult<RegistryFile> {
    validate_record_shape(record, Utc::now())?;
    let bytes = serde_json::to_vec(record).map_err(|error| {
        AppError::Internal(format!(
            "managed-network registry serialization failed: {error}"
        ))
    })?;
    if bytes.is_empty() || bytes.len() > MAX_REGISTRY_RECORD_BYTES {
        return Err(AppError::InvalidRequest(
            "managed-network registry record exceeds its bounded size".into(),
        ));
    }
    let path = directory.join(registry_filename(record));
    if path.parent() != Some(directory) {
        return Err(AppError::NotAuthorized(
            "managed-network registry path escaped its control directory".into(),
        ));
    }
    let mut options = OpenOptions::new();
    options.write(true).create_new(true);
    configure_private_create(&mut options);
    let mut file = options.open(&path).map_err(|error| {
        AppError::Runtime(format!(
            "managed-network registry record could not be created: {error}"
        ))
    })?;
    let result = (|| -> AppResult<()> {
        file.write_all(&bytes)?;
        file.sync_all()?;
        restrict_registry_file(&path)?;
        sync_directory(directory)?;
        Ok(())
    })();
    if let Err(error) = result {
        let _ = remove_exact_regular_file(&path);
        return Err(error);
    }
    Ok(RegistryFile {
        path,
        sha256: Sha256::digest(&bytes).into(),
    })
}

fn read_registry_snapshot(
    root: &Path,
    path: &Path,
    now: DateTime<Utc>,
) -> AppResult<(ManagedNetworkRecord, RegistryFile)> {
    if path.parent() != Some(root) {
        return Err(AppError::NotAuthorized(
            "managed-network registry entry escaped its root".into(),
        ));
    }
    let metadata = fs::symlink_metadata(path)?;
    if metadata.file_type().is_symlink()
        || !metadata.is_file()
        || metadata.len() == 0
        || metadata.len() > MAX_REGISTRY_RECORD_BYTES as u64
    {
        return Err(AppError::NotAuthorized(
            "managed-network registry entry is not a bounded regular file".into(),
        ));
    }
    let bytes = fs::read(path)?;
    let record: ManagedNetworkRecord = serde_json::from_slice(&bytes).map_err(|_| {
        AppError::InvalidRequest("managed-network registry entry is malformed".into())
    })?;
    validate_record_shape(&record, now)?;
    if path.file_name() != Some(OsStr::new(&registry_filename(&record))) {
        return Err(AppError::NotAuthorized(
            "managed-network registry filename does not match its identity".into(),
        ));
    }
    Ok((
        record,
        RegistryFile {
            path: path.to_owned(),
            sha256: Sha256::digest(&bytes).into(),
        },
    ))
}

fn remove_registry_file(file: &RegistryFile) -> AppResult<()> {
    let metadata = match fs::symlink_metadata(&file.path) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(()),
        Err(error) => return Err(error.into()),
    };
    if metadata.file_type().is_symlink()
        || !metadata.is_file()
        || metadata.len() == 0
        || metadata.len() > MAX_REGISTRY_RECORD_BYTES as u64
    {
        return Err(AppError::NotAuthorized(
            "refusing to remove a replaced managed-network registry path".into(),
        ));
    }
    let actual: [u8; 32] = Sha256::digest(fs::read(&file.path)?).into();
    if actual != file.sha256 {
        return Err(AppError::NotAuthorized(
            "refusing to remove a modified managed-network registry entry".into(),
        ));
    }
    fs::remove_file(&file.path)?;
    if let Some(parent) = file.path.parent() {
        sync_directory(parent)?;
    }
    Ok(())
}

fn inspect_optional_network(
    runtime: &dyn RuntimeCommands,
    provider: RuntimeProvider,
    network_name: &str,
    labels: &BTreeMap<String, String>,
) -> AppResult<Option<InspectedNetwork>> {
    let output = runtime_output(
        runtime,
        provider,
        &["network".into(), "inspect".into(), network_name.into()],
    )?;
    if !output.success {
        if runtime_reports_absent(&output.stderr) {
            return Ok(None);
        }
        return Err(runtime_failure("managed network inspection", &output));
    }
    parse_network_inspect(provider, &output.stdout, network_name, labels).map(Some)
}

fn remove_intent_network(
    runtime: &dyn RuntimeCommands,
    provider: RuntimeProvider,
    network_name: &str,
    labels: &BTreeMap<String, String>,
) -> AppResult<()> {
    let Some(inspected) = inspect_optional_network(runtime, provider, network_name, labels)? else {
        return Ok(());
    };
    remove_network(runtime, provider, &inspected.id)
}

fn validate_network_name(value: &str) -> AppResult<()> {
    if value.is_empty()
        || value.len() > 128
        || !value.chars().all(|character| {
            character.is_ascii_alphanumeric() || matches!(character, '-' | '_' | '.')
        })
    {
        return Err(AppError::InvalidRequest(
            "managed-network runtime name is invalid".into(),
        ));
    }
    Ok(())
}

fn validate_runtime_id(value: &str) -> AppResult<()> {
    if value.trim().is_empty()
        || value.len() > 256
        || value.contains(['\n', '\r', '\0'])
        || value.starts_with('-')
        || value.chars().any(char::is_whitespace)
    {
        return Err(AppError::InvalidRequest(
            "managed-network runtime id is invalid".into(),
        ));
    }
    Ok(())
}

fn validate_owner_segment(value: &str, label: &str) -> AppResult<()> {
    if value.is_empty()
        || value.len() > 256
        || !value
            .chars()
            .all(|character| character.is_ascii_alphanumeric() || matches!(character, '-' | '_'))
    {
        return Err(AppError::InvalidRequest(format!(
            "managed-network {label} identity is invalid"
        )));
    }
    Ok(())
}

fn validate_network_policy_relation(network_name: &str, policy_id: &str) -> AppResult<()> {
    let unique = policy_id.strip_prefix("egress-").ok_or_else(|| {
        AppError::InvalidRequest("managed egress policy id has no generated prefix".into())
    })?;
    if unique.len() != 32
        || !unique
            .chars()
            .all(|character| character.is_ascii_hexdigit())
        || network_name != format!("ass-egress-{unique}")
    {
        return Err(AppError::InvalidRequest(
            "managed network name does not match its generated policy identity".into(),
        ));
    }
    Ok(())
}

fn validate_identity_relation(identity: &ManagedNetworkIdentity) -> AppResult<()> {
    validate_network_policy_relation(&identity.network_name, &identity.policy_id)
}

fn validate_egress_provenance(provenance: &EgressGatewayProvenance) -> AppResult<()> {
    let valid_text = |value: &str| {
        !value.trim().is_empty() && value.len() <= 256 && !value.contains(['\n', '\r', '\0'])
    };
    let valid = match provenance {
        EgressGatewayProvenance::ExternalAssetGrants {
            case_id,
            grant_ids,
            activities,
        } => {
            valid_text(case_id)
                && !grant_ids.is_empty()
                && grant_ids.len() <= MAX_EXTERNAL_PLANS_PER_LEASE
                && grant_ids.iter().all(|value| valid_text(value))
                && !activities.is_empty()
                && activities.len() <= 3
        }
        EgressGatewayProvenance::ProviderService {
            case_id,
            source_id,
            source_kind,
            source_profile,
            manifest_id,
            manifest_revision,
        } => [
            case_id.as_str(),
            source_id.as_str(),
            source_kind.as_str(),
            source_profile.as_str(),
            manifest_id.as_str(),
            manifest_revision.as_str(),
        ]
        .into_iter()
        .all(valid_text),
    };
    if !valid {
        return Err(AppError::InvalidRequest(
            "managed-network policy provenance is invalid".into(),
        ));
    }
    Ok(())
}

fn decode_sha256(value: &str) -> AppResult<[u8; 32]> {
    if value.len() != 64 || !value.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        return Err(AppError::InvalidRequest(
            "managed-network policy digest is invalid".into(),
        ));
    }
    let mut decoded = [0_u8; 32];
    hex::decode_to_slice(value, &mut decoded)
        .map_err(|_| AppError::InvalidRequest("managed-network policy digest is invalid".into()))?;
    Ok(decoded)
}

fn bounded_cleanup_detail(value: &str) -> String {
    value
        .replace(['\n', '\r', '\0'], " ")
        .chars()
        .take(2_000)
        .collect()
}

fn push_summary_detail(summary: &mut ManagedNetworkReconciliationSummary, detail: String) {
    if summary.details.len() < 128 {
        summary.details.push(detail);
    }
}

fn ensure_private_directory(path: &Path) -> AppResult<()> {
    match fs::create_dir(path) {
        Ok(()) => {}
        Err(error) if error.kind() == io::ErrorKind::AlreadyExists => {}
        Err(error) => return Err(error.into()),
    }
    let metadata = fs::symlink_metadata(path)?;
    if metadata.file_type().is_symlink() || !metadata.is_dir() {
        return Err(AppError::NotAuthorized(
            "managed-network registry path must be a real directory".into(),
        ));
    }
    restrict_private_directory(path)?;
    Ok(())
}

#[cfg(unix)]
fn restrict_private_directory(path: &Path) -> AppResult<()> {
    use std::os::unix::fs::PermissionsExt;
    fs::set_permissions(path, fs::Permissions::from_mode(0o700))?;
    Ok(())
}

#[cfg(not(unix))]
fn restrict_private_directory(_path: &Path) -> AppResult<()> {
    Ok(())
}

#[cfg(unix)]
fn sync_directory(path: &Path) -> AppResult<()> {
    std::fs::File::open(path)?.sync_all()?;
    Ok(())
}

#[cfg(not(unix))]
fn sync_directory(_path: &Path) -> AppResult<()> {
    Ok(())
}

#[cfg(unix)]
fn restrict_registry_file(path: &Path) -> AppResult<()> {
    use std::os::unix::fs::PermissionsExt;
    fs::set_permissions(path, fs::Permissions::from_mode(0o400))?;
    Ok(())
}

#[cfg(not(unix))]
fn restrict_registry_file(path: &Path) -> AppResult<()> {
    let mut permissions = fs::metadata(path)?.permissions();
    permissions.set_readonly(true);
    fs::set_permissions(path, permissions)?;
    Ok(())
}

fn validate_plans_without_bridge(
    plans: &[ResolvedExternalPlan],
    now: DateTime<Utc>,
) -> AppResult<()> {
    if plans.is_empty() || plans.len() > MAX_EXTERNAL_PLANS_PER_LEASE {
        return Err(AppError::NotAuthorized(
            "managed egress requires one or more bounded frozen plans".into(),
        ));
    }
    let case_id = plans[0].case_id.as_str();
    for plan in plans {
        validate_resolved_plan(plan, case_id, now)?;
    }
    Ok(())
}

fn validate_resolved_plan(
    plan: &ResolvedExternalPlan,
    expected_case_id: &str,
    now: DateTime<Utc>,
) -> AppResult<()> {
    for (name, value) in [
        ("grant", plan.grant_id.as_str()),
        ("case", plan.case_id.as_str()),
        ("asset", plan.asset_id.as_str()),
    ] {
        if value.trim().is_empty() || value.len() > 256 || value.contains(['\n', '\r', '\0']) {
            return Err(AppError::InvalidRequest(format!(
                "external plan {name} identifier is invalid"
            )));
        }
    }
    if expected_case_id.is_empty() || plan.case_id != expected_case_id {
        return Err(AppError::InvalidRequest(
            "one managed network cannot combine plans from different cases".into(),
        ));
    }
    if plan.expires_at <= now
        || plan.frozen_at > now
        || plan.resolution.resolved_at != plan.frozen_at
        || plan.expires_at - plan.frozen_at > ChronoDuration::days(30)
    {
        return Err(AppError::NotAuthorized(
            "external plan is expired, future-dated, or not a frozen resolution".into(),
        ));
    }
    if plan.resolution.addresses.is_empty() || plan.ports.is_empty() {
        return Err(AppError::NotAuthorized(
            "SOCKS egress requires explicit frozen addresses and ports".into(),
        ));
    }
    if plan.ports.contains(&0) {
        return Err(AppError::InvalidRequest(
            "external destination contains port zero".into(),
        ));
    }
    if plan.protocol == TransportProtocol::Udp {
        return Err(AppError::NotAvailable(
            "the managed gateway supports bounded TCP CONNECT only; UDP engines are not runnable through it"
                .into(),
        ));
    }

    validate_plan_rate_policy(plan)?;
    if plan.template_policy.allow_denial_of_service || plan.template_policy.allow_credential_attacks
    {
        return Err(AppError::NotAuthorized(
            "prohibited external template classes cannot enter managed egress".into(),
        ));
    }
    if plan.activity == ExternalActivity::ActiveExternal
        && plan.template_policy.allowed_template_ids.is_empty()
    {
        return Err(AppError::NotAuthorized(
            "active external testing requires a frozen template allowlist".into(),
        ));
    }

    match &plan.target {
        CanonicalTarget::Hostname(hostname) => {
            let reparsed = CanonicalTarget::parse(hostname)?;
            if reparsed != plan.target
                || plan.resolution.hostname.as_deref() != Some(hostname.as_str())
            {
                return Err(AppError::InvalidRequest(
                    "external hostname is not the canonical frozen target".into(),
                ));
            }
        }
        CanonicalTarget::Address(expected) => {
            if plan.resolution.hostname.is_some()
                || plan.resolution.addresses.len() != 1
                || !plan.resolution.addresses.contains(expected)
            {
                return Err(AppError::InvalidRequest(
                    "address target does not match its frozen resolution".into(),
                ));
            }
        }
        CanonicalTarget::Network(network) => {
            if plan.resolution.hostname.is_some()
                || plan
                    .resolution
                    .addresses
                    .iter()
                    .any(|address| !network.contains(address))
            {
                return Err(AppError::InvalidRequest(
                    "network target contains an out-of-scope frozen address".into(),
                ));
            }
        }
    }

    for address in &plan.resolution.addresses {
        if is_cloud_metadata(*address) {
            return Err(AppError::NotAuthorized(format!(
                "cloud metadata address {address} is never an egress destination"
            )));
        }
        if is_sensitive_address(*address) && !plan.allow_sensitive_networks {
            return Err(AppError::NotAuthorized(format!(
                "sensitive address {address} lacks an explicit internal-network grant"
            )));
        }
    }
    Ok(())
}

fn validate_plan_rate_policy(plan: &ResolvedExternalPlan) -> AppResult<()> {
    let (max_rate, max_concurrency, max_timeout) = match plan.activity {
        ExternalActivity::PassivePublicDiscovery => (100, 20, 3_600),
        ExternalActivity::LowImpactExternal => (25, 10, 1_800),
        ExternalActivity::ActiveExternal => (10, 5, 3_600),
    };
    let rate = plan.rate_policy.requests_per_second;
    let concurrency = plan.rate_policy.concurrency;
    let timeout = plan.rate_policy.timeout_seconds;
    if rate == 0
        || rate > max_rate
        || concurrency == 0
        || concurrency > max_concurrency
        || timeout == 0
        || timeout > max_timeout
    {
        return Err(AppError::InvalidRequest(
            "external plan rate, concurrency, or timeout exceeds its activity class".into(),
        ));
    }
    Ok(())
}

fn create_internal_network(
    runtime: &dyn RuntimeCommands,
    provider: RuntimeProvider,
    network_name: &str,
    labels: &BTreeMap<String, String>,
) -> AppResult<()> {
    let mut args = vec![
        "network".into(),
        "create".into(),
        "--driver".into(),
        "bridge".into(),
        "--internal".into(),
    ];
    for (key, value) in labels {
        args.push("--label".into());
        args.push(format!("{key}={value}").into());
    }
    args.push(network_name.into());
    let output = runtime_output(runtime, provider, &args)?;
    if !output.success {
        return Err(runtime_failure(
            "managed internal network creation",
            &output,
        ));
    }
    Ok(())
}

fn inspect_network(
    runtime: &dyn RuntimeCommands,
    provider: RuntimeProvider,
    network_name: &str,
    labels: &BTreeMap<String, String>,
) -> AppResult<InspectedNetwork> {
    let output = runtime_output(
        runtime,
        provider,
        &["network".into(), "inspect".into(), network_name.into()],
    )?;
    if !output.success {
        return Err(runtime_failure("managed network inspection", &output));
    }
    parse_network_inspect(provider, &output.stdout, network_name, labels)
}

fn remove_network(
    runtime: &dyn RuntimeCommands,
    provider: RuntimeProvider,
    network_name: &str,
) -> AppResult<()> {
    let output = runtime_output(
        runtime,
        provider,
        &["network".into(), "rm".into(), network_name.into()],
    )?;
    if output.success || runtime_reports_absent(&output.stderr) {
        Ok(())
    } else {
        Err(runtime_failure("managed network removal", &output))
    }
}

fn runtime_output(
    runtime: &dyn RuntimeCommands,
    provider: RuntimeProvider,
    args: &[OsString],
) -> AppResult<RuntimeOutput> {
    let output = runtime.output(provider, args).map_err(|error| {
        AppError::Runtime(format!(
            "{} could not be executed directly: {error}",
            runtime_program(provider).to_string_lossy()
        ))
    })?;
    if output.stdout.len() > MAX_INSPECT_BYTES || output.stderr.len() > MAX_INSPECT_BYTES {
        return Err(AppError::Runtime(
            "container runtime returned an oversized response".into(),
        ));
    }
    Ok(output)
}

fn runtime_program(provider: RuntimeProvider) -> &'static OsStr {
    match provider {
        RuntimeProvider::ManagedLocal => OsStr::new("managed-local-context-required"),
        RuntimeProvider::Docker => OsStr::new("docker"),
        RuntimeProvider::Podman => OsStr::new("podman"),
    }
}

fn require_compatibility_provider(provider: RuntimeProvider) -> AppResult<()> {
    if provider == RuntimeProvider::ManagedLocal {
        return Err(AppError::NotAuthorized(
            "managed-local networking requires its verified private runtime context".into(),
        ));
    }
    Ok(())
}

fn expected_labels(policy_id: &str) -> BTreeMap<String, String> {
    BTreeMap::from([
        (MANAGED_LABEL_KEY.into(), "true".into()),
        (POLICY_LABEL_KEY.into(), policy_id.into()),
    ])
}

#[derive(Debug, Deserialize)]
struct DockerNetworkInspect {
    #[serde(rename = "Name")]
    name: String,
    #[serde(rename = "Id")]
    id: String,
    #[serde(rename = "Driver")]
    driver: String,
    #[serde(rename = "Internal")]
    internal: bool,
    #[serde(rename = "Labels")]
    labels: BTreeMap<String, String>,
    #[serde(rename = "IPAM")]
    ipam: DockerIpam,
}

#[derive(Debug, Deserialize)]
struct DockerIpam {
    #[serde(rename = "Config")]
    config: Vec<DockerSubnet>,
}

#[derive(Debug, Deserialize)]
struct DockerSubnet {
    #[serde(rename = "Subnet")]
    subnet: String,
    #[serde(rename = "Gateway")]
    gateway: String,
}

#[derive(Debug, Deserialize)]
struct PodmanNetworkInspect {
    name: String,
    id: String,
    driver: String,
    internal: bool,
    labels: BTreeMap<String, String>,
    subnets: Vec<PodmanSubnet>,
}

#[derive(Debug, Deserialize)]
struct PodmanSubnet {
    subnet: String,
    gateway: String,
}

fn parse_network_inspect(
    provider: RuntimeProvider,
    bytes: &[u8],
    expected_name: &str,
    expected_labels: &BTreeMap<String, String>,
) -> AppResult<InspectedNetwork> {
    if bytes.is_empty() || bytes.len() > MAX_INSPECT_BYTES {
        return Err(AppError::Runtime(
            "container network inspection was empty or oversized".into(),
        ));
    }
    let (name, id, driver, internal, labels, subnets) = match provider {
        RuntimeProvider::Docker => {
            let mut entries: Vec<DockerNetworkInspect> = serde_json::from_slice(bytes)
                .map_err(|_| AppError::Runtime("Docker network inspection was malformed".into()))?;
            if entries.len() != 1 {
                return Err(AppError::Runtime(
                    "Docker must return exactly one inspected network".into(),
                ));
            }
            let entry = entries.pop().expect("one entry");
            (
                entry.name,
                entry.id,
                entry.driver,
                entry.internal,
                entry.labels,
                entry
                    .ipam
                    .config
                    .into_iter()
                    .map(|item| (item.subnet, item.gateway))
                    .collect::<Vec<_>>(),
            )
        }
        RuntimeProvider::ManagedLocal | RuntimeProvider::Podman => {
            let mut entries: Vec<PodmanNetworkInspect> = serde_json::from_slice(bytes)
                .map_err(|_| AppError::Runtime("Podman network inspection was malformed".into()))?;
            if entries.len() != 1 {
                return Err(AppError::Runtime(
                    "Podman must return exactly one inspected network".into(),
                ));
            }
            let entry = entries.pop().expect("one entry");
            (
                entry.name,
                entry.id,
                entry.driver,
                entry.internal,
                entry.labels,
                entry
                    .subnets
                    .into_iter()
                    .map(|item| (item.subnet, item.gateway))
                    .collect::<Vec<_>>(),
            )
        }
    };

    if name != expected_name
        || id.trim().is_empty()
        || id.len() > 256
        || id.contains(['\n', '\r', '\0'])
        || driver != "bridge"
        || !internal
        || labels != *expected_labels
        || subnets.len() != 1
    {
        return Err(AppError::NotAuthorized(
            "container runtime did not prove the exact internal labeled bridge".into(),
        ));
    }
    let (subnet, gateway) = &subnets[0];
    let subnet = subnet
        .parse::<IpNet>()
        .map_err(|_| AppError::Runtime("container bridge subnet is malformed".into()))?;
    let gateway = gateway
        .parse::<IpAddr>()
        .map_err(|_| AppError::Runtime("container bridge gateway is malformed".into()))?;
    validate_bridge_network(subnet, gateway)?;
    Ok(InspectedNetwork {
        id,
        subnet,
        gateway,
    })
}

fn validate_bridge_network(subnet: IpNet, gateway: IpAddr) -> AppResult<()> {
    if subnet.trunc() != subnet || !subnet.contains(&gateway) || is_cloud_metadata(gateway) {
        return Err(AppError::NotAuthorized(
            "container bridge did not provide a canonical private gateway".into(),
        ));
    }
    let valid = match (subnet, gateway) {
        (IpNet::V4(network), IpAddr::V4(address)) => {
            (16..=30).contains(&network.prefix_len())
                && network.network().is_private()
                && address.is_private()
                && address != network.network()
                && address != network.broadcast()
        }
        (IpNet::V6(network), IpAddr::V6(address)) => {
            (48..=126).contains(&network.prefix_len())
                && is_unique_local_v6(network.network())
                && is_unique_local_v6(address)
                && address != network.network()
        }
        _ => false,
    };
    if !valid {
        return Err(AppError::NotAuthorized(
            "container bridge subnet and gateway must be private and bounded".into(),
        ));
    }
    Ok(())
}

fn validate_policy_id(policy_id: &str) -> AppResult<()> {
    if policy_id.is_empty()
        || policy_id.len() > 128
        || !policy_id.chars().all(|character| {
            character.is_ascii_alphanumeric() || matches!(character, '-' | '_' | '.')
        })
    {
        return Err(AppError::InvalidRequest(
            "managed egress policy id is invalid".into(),
        ));
    }
    Ok(())
}

/// Proves an already-installed gateway path is a canonical, non-symlink,
/// executable regular file. This function is inspection-only: it never
/// creates, chmods, opens for writing, or executes the file.
pub(crate) fn inspect_gateway_binary(path: &Path) -> AppResult<PathBuf> {
    if !path.is_absolute() || path.as_os_str().len() > 4096 {
        return Err(AppError::InvalidRequest(
            "egress gateway binary must be a bounded absolute path".into(),
        ));
    }
    let metadata = fs::symlink_metadata(path).map_err(|error| {
        AppError::Runtime(format!(
            "egress gateway binary could not be inspected: {error}"
        ))
    })?;
    if metadata.file_type().is_symlink() || !metadata.is_file() || metadata.len() == 0 {
        return Err(AppError::NotAuthorized(
            "egress gateway must be a non-symlink regular file".into(),
        ));
    }
    let canonical = fs::canonicalize(path).map_err(|error| {
        AppError::Runtime(format!(
            "egress gateway binary could not be resolved: {error}"
        ))
    })?;
    if canonical != path {
        return Err(AppError::NotAuthorized(
            "egress gateway path may not traverse symlinks or aliases".into(),
        ));
    }
    validate_executable_mode(&metadata)?;
    Ok(canonical)
}

fn validate_policy_directory(path: &Path) -> AppResult<PathBuf> {
    if !path.is_absolute() || path.as_os_str().len() > 4096 {
        return Err(AppError::InvalidRequest(
            "egress policy directory must be a bounded absolute path".into(),
        ));
    }
    let metadata = fs::symlink_metadata(path).map_err(|error| {
        AppError::Runtime(format!(
            "egress policy directory could not be inspected: {error}"
        ))
    })?;
    if metadata.file_type().is_symlink() || !metadata.is_dir() {
        return Err(AppError::NotAuthorized(
            "egress policy directory must be a non-symlink directory".into(),
        ));
    }
    let canonical = fs::canonicalize(path).map_err(|error| {
        AppError::Runtime(format!(
            "egress policy directory could not be resolved: {error}"
        ))
    })?;
    if canonical != path {
        return Err(AppError::NotAuthorized(
            "egress policy directory may not traverse symlinks or aliases".into(),
        ));
    }
    Ok(canonical)
}

#[cfg(unix)]
fn validate_executable_mode(metadata: &fs::Metadata) -> AppResult<()> {
    use std::os::unix::fs::PermissionsExt;
    if metadata.permissions().mode() & 0o111 == 0 {
        return Err(AppError::NotAuthorized(
            "egress gateway regular file is not executable".into(),
        ));
    }
    Ok(())
}

#[cfg(not(unix))]
fn validate_executable_mode(_metadata: &fs::Metadata) -> AppResult<()> {
    Ok(())
}

fn write_policy_file(directory: &Path, policy: &EgressGatewayPolicy) -> AppResult<PolicyFile> {
    let bytes = serde_json::to_vec(policy).map_err(|error| {
        AppError::Internal(format!("egress policy serialization failed: {error}"))
    })?;
    if bytes.is_empty() || bytes.len() > MAX_POLICY_BYTES {
        return Err(AppError::InvalidRequest(
            "egress policy exceeds its bounded file size".into(),
        ));
    }
    let path = directory.join(format!("egress-{}.json", policy.policy_id));
    if !path.is_absolute() || path.parent() != Some(directory) {
        return Err(AppError::InvalidRequest(
            "egress policy path escaped its control directory".into(),
        ));
    }

    let write_result = (|| -> AppResult<()> {
        let mut options = OpenOptions::new();
        options.write(true).create_new(true);
        configure_private_create(&mut options);
        let mut file = options.open(&path).map_err(|error| {
            AppError::Runtime(format!("egress policy could not be created: {error}"))
        })?;
        file.write_all(&bytes).map_err(|error| {
            AppError::Runtime(format!("egress policy could not be written: {error}"))
        })?;
        file.sync_all().map_err(|error| {
            AppError::Runtime(format!("egress policy could not be synchronized: {error}"))
        })?;
        restrict_policy_file(&path)?;
        let metadata = fs::symlink_metadata(&path)?;
        if metadata.file_type().is_symlink()
            || !metadata.is_file()
            || metadata.len() != bytes.len() as u64
        {
            return Err(AppError::NotAuthorized(
                "egress policy file identity changed while it was written".into(),
            ));
        }
        Ok(())
    })();
    if let Err(error) = write_result {
        let _ = remove_exact_regular_file(&path);
        return Err(error);
    }

    Ok(PolicyFile {
        path,
        sha256: Sha256::digest(&bytes).into(),
    })
}

#[cfg(unix)]
fn configure_private_create(options: &mut OpenOptions) {
    use std::os::unix::fs::OpenOptionsExt;
    options.mode(0o600);
    options.custom_flags(libc::O_CLOEXEC | libc::O_NOFOLLOW);
}

#[cfg(not(unix))]
fn configure_private_create(_options: &mut OpenOptions) {}

#[cfg(unix)]
fn restrict_policy_file(path: &Path) -> AppResult<()> {
    use std::os::unix::fs::PermissionsExt;
    fs::set_permissions(path, fs::Permissions::from_mode(0o400)).map_err(|error| {
        AppError::Runtime(format!(
            "egress policy permissions could not be restricted: {error}"
        ))
    })
}

#[cfg(not(unix))]
fn restrict_policy_file(path: &Path) -> AppResult<()> {
    let mut permissions = fs::metadata(path)?.permissions();
    permissions.set_readonly(true);
    fs::set_permissions(path, permissions)?;
    Ok(())
}

fn remove_policy_file(policy_file: &PolicyFile) -> AppResult<()> {
    let metadata = match fs::symlink_metadata(&policy_file.path) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(()),
        Err(error) => {
            return Err(AppError::Runtime(format!(
                "egress policy cleanup inspection failed: {error}"
            )));
        }
    };
    if metadata.file_type().is_symlink()
        || !metadata.is_file()
        || metadata.len() > MAX_POLICY_BYTES as u64
    {
        return Err(AppError::NotAuthorized(
            "refusing to remove a replaced egress policy path".into(),
        ));
    }
    let bytes = fs::read(&policy_file.path).map_err(|error| {
        AppError::Runtime(format!("egress policy cleanup read failed: {error}"))
    })?;
    let actual: [u8; 32] = Sha256::digest(&bytes).into();
    if actual != policy_file.sha256 {
        return Err(AppError::NotAuthorized(
            "refusing to remove a modified egress policy file".into(),
        ));
    }
    fs::remove_file(&policy_file.path)
        .map_err(|error| AppError::Runtime(format!("egress policy removal failed: {error}")))
}

fn remove_exact_regular_file(path: &Path) -> io::Result<()> {
    match fs::symlink_metadata(path) {
        Ok(metadata) if metadata.is_file() && !metadata.file_type().is_symlink() => {
            fs::remove_file(path)
        }
        Ok(_) => Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "path is not an exact regular file",
        )),
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(error),
    }
}

fn stop_gateway(process: &mut dyn GatewayProcess) -> AppResult<()> {
    let exited = process.has_exited().map_err(|error| {
        AppError::Runtime(format!("egress gateway status could not be read: {error}"))
    })?;
    if !exited {
        process.kill().map_err(|error| {
            AppError::Runtime(format!("egress gateway could not be stopped: {error}"))
        })?;
    }
    process
        .wait()
        .map_err(|error| AppError::Runtime(format!("egress gateway could not be reaped: {error}")))
}

fn gateway_endpoint(gateway: IpAddr) -> String {
    match gateway {
        IpAddr::V4(address) => format!("socks5h://{address}:{GATEWAY_PORT}"),
        IpAddr::V6(address) => format!("socks5h://[{address}]:{GATEWAY_PORT}"),
    }
}

fn runtime_failure(operation: &str, output: &RuntimeOutput) -> AppError {
    let diagnostic = bounded_diagnostic(&output.stderr);
    if diagnostic.is_empty() {
        AppError::Runtime(format!("{operation} failed"))
    } else {
        AppError::Runtime(format!("{operation} failed: {diagnostic}"))
    }
}

fn bounded_diagnostic(bytes: &[u8]) -> String {
    let end = bytes.len().min(MAX_DIAGNOSTIC_BYTES);
    String::from_utf8_lossy(&bytes[..end])
        .replace(['\n', '\r', '\0'], " ")
        .trim()
        .to_owned()
}

fn runtime_reports_absent(stderr: &[u8]) -> bool {
    let message = bounded_diagnostic(stderr).to_ascii_lowercase();
    message.contains("no such network")
        || message.contains("network not found")
        || message.contains("does not exist")
}

fn is_unique_local_v6(address: Ipv6Addr) -> bool {
    address.segments()[0] & 0xfe00 == 0xfc00
}

fn is_cloud_metadata(address: IpAddr) -> bool {
    match address {
        IpAddr::V4(address) => {
            address == Ipv4Addr::new(169, 254, 169, 254)
                || address == Ipv4Addr::new(169, 254, 170, 2)
                || address == Ipv4Addr::new(100, 100, 100, 200)
        }
        IpAddr::V6(address) => address == "fd00:ec2::254".parse::<Ipv6Addr>().expect("literal"),
    }
}

fn is_sensitive_address(address: IpAddr) -> bool {
    match address {
        IpAddr::V4(address) => {
            address.is_private()
                || address.is_loopback()
                || address.is_link_local()
                || address.is_multicast()
                || address.is_unspecified()
                || address.is_broadcast()
                || address.octets()[0] == 0
                || (address.octets()[0] == 100 && (64..=127).contains(&address.octets()[1]))
                || (address.octets()[0] == 198 && (18..=19).contains(&address.octets()[1]))
                || address.octets()[0] >= 240
        }
        IpAddr::V6(address) => {
            address.is_loopback()
                || address.is_multicast()
                || address.is_unspecified()
                || is_unique_local_v6(address)
                || (address.segments()[0] & 0xffc0) == 0xfe80
                || address
                    .to_ipv4_mapped()
                    .is_some_and(|mapped| is_sensitive_address(IpAddr::V4(mapped)))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::external_scope::{RatePolicy, ResolutionSnapshot, TemplatePolicy};
    use serde_json::json;
    use std::sync::Mutex;
    use tempfile::TempDir;

    fn plan(
        now: DateTime<Utc>,
        address: &str,
        rate: u16,
        concurrency: u16,
        timeout: u32,
    ) -> ResolvedExternalPlan {
        let address = address.parse::<IpAddr>().expect("address");
        ResolvedExternalPlan {
            grant_id: format!("grant-{address}"),
            case_id: "case-1".into(),
            asset_id: format!("asset-{address}"),
            target: CanonicalTarget::Hostname("app.example.test".into()),
            resolution: ResolutionSnapshot {
                hostname: Some("app.example.test".into()),
                addresses: [address].into_iter().collect(),
                resolved_at: now,
            },
            ports: [443].into_iter().collect(),
            protocol: TransportProtocol::Https,
            activity: ExternalActivity::ActiveExternal,
            rate_policy: RatePolicy {
                requests_per_second: rate,
                concurrency,
                timeout_seconds: timeout,
            },
            template_policy: TemplatePolicy::conservative(
                "nuclei-templates@0123456789abcdef0123456789abcdef01234567",
                vec!["http/misconfiguration/example".into()],
            ),
            frozen_at: now,
            expires_at: now + ChronoDuration::hours(5),
            allow_sensitive_networks: false,
        }
    }

    #[test]
    fn policy_uses_only_frozen_destinations_and_most_restrictive_limits() {
        let now = Utc::now();
        let mut first = plan(now, "203.0.113.8", 8, 4, 300);
        first.expires_at = now + ChronoDuration::hours(10);
        let second = plan(now, "203.0.113.9", 3, 2, 45);
        let policy = EgressGatewayPolicy::from_resolved_plans(
            "policy-1",
            "172.29.0.1:1080".parse().expect("listener"),
            "172.29.0.0/24".parse().expect("network"),
            &[first, second],
            now,
        )
        .expect("policy");

        assert_eq!(policy.expires_at, now + ChronoDuration::hours(5));
        assert_eq!(policy.limits.max_connections_per_second, 3);
        assert_eq!(policy.limits.max_concurrency, 2);
        assert_eq!(policy.limits.connect_timeout_seconds, 45);
        assert_eq!(policy.limits.max_connection_seconds, 45);
        assert_eq!(policy.destinations.len(), 2);
        let value = serde_json::to_value(&policy).expect("JSON");
        assert!(value.get("limits").is_some());
        assert!(value.get("max_concurrency").is_none());
    }

    #[test]
    fn policy_caps_lifetime_and_connect_timeout() {
        let now = Utc::now();
        let mut plan = plan(now, "203.0.113.8", 5, 2, 300);
        plan.expires_at = now + ChronoDuration::hours(25);
        let policy = EgressGatewayPolicy::from_resolved_plans(
            "policy-1",
            "172.29.0.1:1080".parse().expect("listener"),
            "172.29.0.0/24".parse().expect("network"),
            &[plan],
            now,
        )
        .expect("policy");
        assert_eq!(policy.expires_at, now + ChronoDuration::hours(24));
        assert_eq!(policy.limits.connect_timeout_seconds, 120);
        assert_eq!(policy.limits.max_connection_seconds, 300);
    }

    #[test]
    fn provider_service_policy_requires_exact_fqdn_443_and_keeps_distinct_provenance() {
        let now = Utc::now();
        for rejected in [
            "AWS IAM API",
            "*.amazonaws.com:443",
            "https://iam.amazonaws.com:443",
            "iam.amazonaws.com:80",
            "IAM.AMAZONAWS.COM:443",
            "203.0.113.8:443",
        ] {
            assert!(parse_exact_provider_destination(rejected).is_err());
        }
        assert_eq!(
            parse_exact_provider_destination("iam.amazonaws.com:443").expect("endpoint"),
            ("iam.amazonaws.com".into(), 443)
        );
        let request = ProviderServiceEgressRequest {
            case_id: "case-1".into(),
            source_id: "source-1".into(),
            source_kind: "aws_organization".into(),
            source_profile: "aws_organization_read_only_session".into(),
            manifest_id: "cloudsplaining".into(),
            manifest_revision: "0123456789abcdef0123456789abcdef01234567".into(),
            exact_destinations: vec![
                "iam.amazonaws.com:443".into(),
                "sts.amazonaws.com:443".into(),
            ],
            expires_at: now + ChronoDuration::minutes(30),
        };
        let mut mismatched_provider = request.clone();
        mismatched_provider.exact_destinations = vec!["attacker.example:443".into()];
        assert!(validate_provider_service_request_static(&mismatched_provider, now).is_err());
        let plan = ResolvedProviderServicePlan {
            request,
            frozen_at: now,
            destinations: vec![GatewayDestination {
                hostname: Some("iam.amazonaws.com".into()),
                addresses: ["203.0.113.8".parse().expect("address")]
                    .into_iter()
                    .collect(),
                ports: [443].into_iter().collect(),
                allow_sensitive_networks: false,
            }],
        };
        let policy = EgressGatewayPolicy::from_provider_service_plan(
            "policy-1",
            "172.29.0.1:1080".parse().expect("listener"),
            "172.29.0.0/24".parse().expect("network"),
            &plan,
            now,
        )
        .expect("provider policy");
        assert!(matches!(
            policy.provenance,
            EgressGatewayProvenance::ProviderService { ref source_id, ref manifest_id, .. }
                if source_id == "source-1" && manifest_id == "cloudsplaining"
        ));
        assert_eq!(
            policy.allowed_destination_labels(),
            vec!["iam.amazonaws.com:443"]
        );
    }

    #[test]
    fn static_provider_service_validation_rejects_invalid_requests_without_dns() {
        let now = Utc::now();
        let request = ProviderServiceEgressRequest {
            case_id: "case-1".into(),
            source_id: "source-1".into(),
            source_kind: "dns".into(),
            source_profile: "snapshot:dns-response".into(),
            manifest_id: "passive-dns".into(),
            manifest_revision: "0123456789abcdef0123456789abcdef01234567".into(),
            // `.invalid` is deliberately non-resolving. Static validation must
            // accept its canonical shape without attempting a lookup.
            exact_destinations: vec!["preflight-does-not-resolve.invalid:443".into()],
            expires_at: now + ChronoDuration::minutes(30),
        };
        validate_provider_service_request_static(&request, now)
            .expect("static request validation does not resolve DNS");

        let mut expired = request.clone();
        expired.expires_at = now;
        assert!(validate_provider_service_request_static(&expired, now).is_err());

        let mut duplicated = request.clone();
        duplicated
            .exact_destinations
            .push("preflight-does-not-resolve.invalid:443".into());
        assert!(validate_provider_service_request_static(&duplicated, now).is_err());

        let mut unpinned = request.clone();
        unpinned.manifest_revision.clear();
        assert!(validate_provider_service_request_static(&unpinned, now).is_err());

        let mut wrong_provider = request;
        wrong_provider.source_kind = "aws_organization".into();
        assert!(validate_provider_service_request_static(&wrong_provider, now).is_err());
    }

    #[test]
    fn parses_and_proves_docker_and_podman_networks() {
        let labels = expected_labels("policy-1");
        let docker = json!([{
            "Name": "ass-egress-1",
            "Id": "docker-network-id",
            "Driver": "bridge",
            "Internal": true,
            "Labels": labels,
            "IPAM": { "Config": [{ "Subnet": "172.29.0.0/24", "Gateway": "172.29.0.1" }] }
        }]);
        let inspected = parse_network_inspect(
            RuntimeProvider::Docker,
            &serde_json::to_vec(&docker).expect("JSON"),
            "ass-egress-1",
            &expected_labels("policy-1"),
        )
        .expect("Docker network");
        assert_eq!(
            inspected.gateway,
            "172.29.0.1".parse::<IpAddr>().expect("address")
        );

        let podman = json!([{
            "name": "ass-egress-1",
            "id": "podman-network-id",
            "driver": "bridge",
            "internal": true,
            "labels": expected_labels("policy-1"),
            "subnets": [{ "subnet": "10.89.1.0/24", "gateway": "10.89.1.1" }]
        }]);
        let inspected = parse_network_inspect(
            RuntimeProvider::Podman,
            &serde_json::to_vec(&podman).expect("JSON"),
            "ass-egress-1",
            &expected_labels("policy-1"),
        )
        .expect("Podman network");
        assert_eq!(inspected.subnet, "10.89.1.0/24".parse().expect("network"));

        let inspected = parse_network_inspect(
            RuntimeProvider::ManagedLocal,
            &serde_json::to_vec(&podman).expect("JSON"),
            "ass-egress-1",
            &expected_labels("policy-1"),
        )
        .expect("managed-local Podman network");
        assert_eq!(inspected.id, "podman-network-id");
    }

    #[test]
    fn managed_local_never_uses_a_path_resolved_runtime_command() {
        let error = DirectRuntimeCommands
            .output(
                RuntimeProvider::ManagedLocal,
                &[OsString::from("network"), OsString::from("inspect")],
            )
            .expect_err("managed local requires a verified command context");
        assert_eq!(error.kind(), io::ErrorKind::PermissionDenied);
        assert!(
            error
                .to_string()
                .contains("verified private command context")
        );
    }

    #[test]
    fn rejects_public_non_internal_or_mislabeled_bridges() {
        let expected = expected_labels("policy-1");
        for (internal, labels, subnet, gateway) in [
            (false, expected.clone(), "172.29.0.0/24", "172.29.0.1"),
            (
                true,
                expected_labels("other-policy"),
                "172.29.0.0/24",
                "172.29.0.1",
            ),
            (true, expected.clone(), "203.0.113.0/24", "203.0.113.1"),
        ] {
            let document = json!([{
                "Name": "ass-egress-1",
                "Id": "network-id",
                "Driver": "bridge",
                "Internal": internal,
                "Labels": labels,
                "IPAM": { "Config": [{ "Subnet": subnet, "Gateway": gateway }] }
            }]);
            assert!(
                parse_network_inspect(
                    RuntimeProvider::Docker,
                    &serde_json::to_vec(&document).expect("JSON"),
                    "ass-egress-1",
                    &expected,
                )
                .is_err()
            );
        }
    }

    #[test]
    fn udp_and_unfrozen_targets_do_not_become_runnable() {
        let now = Utc::now();
        let mut udp = plan(now, "203.0.113.8", 5, 2, 30);
        udp.protocol = TransportProtocol::Udp;
        assert!(
            EgressGatewayPolicy::from_resolved_plans(
                "policy-1",
                "172.29.0.1:1080".parse().expect("listener"),
                "172.29.0.0/24".parse().expect("network"),
                &[udp],
                now,
            )
            .is_err()
        );

        let mut empty = plan(now, "203.0.113.8", 5, 2, 30);
        empty.resolution.addresses.clear();
        assert!(
            EgressGatewayPolicy::from_resolved_plans(
                "policy-1",
                "172.29.0.1:1080".parse().expect("listener"),
                "172.29.0.0/24".parse().expect("network"),
                &[empty],
                now,
            )
            .is_err()
        );
    }

    #[derive(Debug, Clone, Copy)]
    enum FakeInspectKind {
        Docker,
        Podman,
    }

    #[derive(Debug)]
    struct FakeRuntimeState {
        kind: FakeInspectKind,
        calls: Vec<(RuntimeProvider, Vec<String>)>,
        network_name: Option<String>,
        labels: BTreeMap<String, String>,
        removed: bool,
    }

    struct FakeRuntime {
        state: Arc<Mutex<FakeRuntimeState>>,
    }

    impl FakeRuntime {
        fn new(kind: FakeInspectKind) -> (Self, Arc<Mutex<FakeRuntimeState>>) {
            let state = Arc::new(Mutex::new(FakeRuntimeState {
                kind,
                calls: Vec::new(),
                network_name: None,
                labels: BTreeMap::new(),
                removed: false,
            }));
            (
                Self {
                    state: Arc::clone(&state),
                },
                state,
            )
        }
    }

    impl RuntimeCommands for FakeRuntime {
        fn output(
            &self,
            provider: RuntimeProvider,
            args: &[OsString],
        ) -> io::Result<RuntimeOutput> {
            let args = args
                .iter()
                .map(|value| value.to_string_lossy().into_owned())
                .collect::<Vec<_>>();
            let mut state = self.state.lock().expect("fake runtime");
            state.calls.push((provider, args.clone()));
            match args.get(0..2) {
                Some([network, create]) if network == "network" && create == "create" => {
                    let name = args.last().expect("network name").clone();
                    let mut labels = BTreeMap::new();
                    let mut index = 0;
                    while index < args.len() {
                        if args[index] == "--label" {
                            let (key, value) =
                                args[index + 1].split_once('=').expect("label assignment");
                            labels.insert(key.into(), value.into());
                            index += 2;
                        } else {
                            index += 1;
                        }
                    }
                    state.network_name = Some(name);
                    state.labels = labels;
                    state.removed = false;
                    Ok(success_output(Vec::new()))
                }
                Some([network, inspect]) if network == "network" && inspect == "inspect" => {
                    let Some(name) = state.network_name.as_ref() else {
                        return Ok(failure_output("network not found"));
                    };
                    if state.removed {
                        return Ok(failure_output("network not found"));
                    }
                    let value = match state.kind {
                        FakeInspectKind::Docker => json!([{
                            "Name": name,
                            "Id": "network-id-1",
                            "Driver": "bridge",
                            "Internal": true,
                            "Labels": state.labels.clone(),
                            "IPAM": { "Config": [{ "Subnet": "172.29.0.0/24", "Gateway": "172.29.0.1" }] }
                        }]),
                        FakeInspectKind::Podman => json!([{
                            "name": name,
                            "id": "network-id-1",
                            "driver": "bridge",
                            "internal": true,
                            "labels": state.labels.clone(),
                            "subnets": [{ "subnet": "10.89.1.0/24", "gateway": "10.89.1.1" }]
                        }]),
                    };
                    Ok(success_output(serde_json::to_vec(&value).expect("JSON")))
                }
                Some([network, remove]) if network == "network" && remove == "rm" => {
                    state.removed = true;
                    Ok(success_output(Vec::new()))
                }
                _ => Ok(failure_output("unexpected command")),
            }
        }
    }

    #[derive(Default)]
    struct FakeProcessState {
        killed: bool,
        waited: bool,
        spawn_binary: Option<PathBuf>,
        spawn_policy: Option<PathBuf>,
    }

    struct FakeProcess {
        state: Arc<Mutex<FakeProcessState>>,
        exited: bool,
    }

    impl GatewayProcess for FakeProcess {
        fn has_exited(&mut self) -> io::Result<bool> {
            Ok(self.exited)
        }

        fn kill(&mut self) -> io::Result<()> {
            self.exited = true;
            self.state.lock().expect("fake process").killed = true;
            Ok(())
        }

        fn wait(&mut self) -> io::Result<()> {
            self.state.lock().expect("fake process").waited = true;
            Ok(())
        }
    }

    struct FakeLauncher {
        state: Arc<Mutex<FakeProcessState>>,
    }

    impl GatewayLauncher for FakeLauncher {
        fn spawn(&self, binary: &Path, policy_path: &Path) -> io::Result<Box<dyn GatewayProcess>> {
            let mut state = self.state.lock().expect("fake process");
            state.spawn_binary = Some(binary.to_owned());
            state.spawn_policy = Some(policy_path.to_owned());
            drop(state);
            Ok(Box::new(FakeProcess {
                state: Arc::clone(&self.state),
                exited: false,
            }))
        }
    }

    struct FakeReadiness {
        fail: bool,
        observed: Arc<Mutex<Vec<SocketAddr>>>,
    }

    impl GatewayReadiness for FakeReadiness {
        fn wait_until_ready(
            &self,
            _process: &mut dyn GatewayProcess,
            listen_address: SocketAddr,
        ) -> AppResult<()> {
            self.observed
                .lock()
                .expect("readiness observations")
                .push(listen_address);
            if self.fail {
                Err(AppError::Runtime("fake readiness failure".into()))
            } else {
                Ok(())
            }
        }
    }

    fn success_output(stdout: Vec<u8>) -> RuntimeOutput {
        RuntimeOutput {
            success: true,
            stdout,
            stderr: Vec::new(),
        }
    }

    fn failure_output(message: &str) -> RuntimeOutput {
        RuntimeOutput {
            success: false,
            stdout: Vec::new(),
            stderr: message.as_bytes().to_vec(),
        }
    }

    fn test_paths() -> (TempDir, PathBuf, PathBuf) {
        let temporary = tempfile::tempdir().expect("temporary directory");
        let gateway = temporary.path().join("ai-security-scanner-egress-gateway");
        fs::write(&gateway, b"fake executable").expect("gateway file");
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(&gateway, fs::Permissions::from_mode(0o700)).expect("gateway mode");
        }
        let policies = temporary.path().join("policies");
        fs::create_dir(&policies).expect("policy directory");
        (temporary, gateway, policies)
    }

    fn owner() -> ManagedNetworkOwner {
        ManagedNetworkOwner::new("case-1", "run-1", "engine-run-1", 1).expect("owner")
    }

    fn test_registry(policies: &Path) -> PathBuf {
        let registry = policies.join("registry");
        fs::create_dir(&registry).expect("registry directory");
        registry
    }

    fn recovery_paths() -> (TempDir, PathBuf, PathBuf, PathBuf, PathBuf) {
        let temporary = tempfile::tempdir().expect("temporary directory");
        let gateway = temporary.path().join("ai-security-scanner-egress-gateway");
        fs::write(&gateway, b"fake executable").expect("gateway file");
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(&gateway, fs::Permissions::from_mode(0o700)).expect("gateway mode");
        }
        let artifacts = temporary.path().join("artifacts");
        let case_root = artifacts.join("case-1");
        let policies = case_root.join("network-policies");
        let registry = artifacts.join(".managed-egress-registry");
        fs::create_dir(&artifacts).expect("artifact root");
        fs::create_dir(&case_root).expect("case root");
        fs::create_dir(&policies).expect("policy directory");
        fs::create_dir(&registry).expect("registry directory");
        (temporary, gateway, artifacts, policies, registry)
    }

    #[test]
    fn provision_writes_private_policy_and_cleanup_removes_exact_resources() {
        let (_temporary, gateway, policies) = test_paths();
        let (runtime, runtime_state) = FakeRuntime::new(FakeInspectKind::Docker);
        let process_state = Arc::new(Mutex::new(FakeProcessState::default()));
        let observed = Arc::new(Mutex::new(Vec::new()));
        let registry = test_registry(&policies);
        let controller = ManagedNetworkController::with_components(
            RuntimeProvider::Docker,
            &gateway,
            &policies,
            &registry,
            Arc::new(runtime),
            Arc::new(FakeLauncher {
                state: Arc::clone(&process_state),
            }),
            Arc::new(FakeReadiness {
                fail: false,
                observed: Arc::clone(&observed),
            }),
        )
        .expect("controller");
        let now = Utc::now();
        let mut lease = controller
            .provision(&owner(), &[plan(now, "203.0.113.8", 5, 2, 30)], now)
            .expect("managed network");

        assert_eq!(
            lease.network_policy().gateway_endpoint(),
            Some("socks5h://172.29.0.1:1080")
        );
        assert_eq!(
            observed.lock().expect("readiness").as_slice(),
            &["172.29.0.1:1080".parse::<SocketAddr>().expect("socket")]
        );
        let policy_path = lease.policy_path().expect("policy path").to_owned();
        assert!(policy_path.is_absolute());
        let policy: EgressGatewayPolicy =
            serde_json::from_slice(&fs::read(&policy_path).expect("policy bytes"))
                .expect("policy JSON");
        assert_eq!(policy.schema_version, POLICY_SCHEMA_VERSION);
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            assert_eq!(
                fs::metadata(&policy_path)
                    .expect("policy metadata")
                    .permissions()
                    .mode()
                    & 0o777,
                0o400
            );
        }
        {
            let state = process_state.lock().expect("process state");
            assert_eq!(state.spawn_binary.as_deref(), Some(gateway.as_path()));
            assert_eq!(state.spawn_policy.as_deref(), Some(policy_path.as_path()));
        }
        {
            let state = runtime_state.lock().expect("runtime state");
            let create = &state.calls[0].1;
            assert_eq!(
                &create[0..5],
                ["network", "create", "--driver", "bridge", "--internal"]
            );
            assert_eq!(
                create
                    .iter()
                    .filter(|argument| *argument == "--label")
                    .count(),
                2
            );
        }

        lease.cleanup().expect("cleanup");
        assert!(!lease.is_active());
        assert!(!policy_path.exists());
        {
            let state = runtime_state.lock().expect("runtime state");
            assert!(state.removed);
            let removal = state
                .calls
                .iter()
                .find(|(_, args)| {
                    args.first().map(String::as_str) == Some("network")
                        && args.get(1).map(String::as_str) == Some("rm")
                })
                .expect("network removal");
            assert_eq!(removal.1.get(2).map(String::as_str), Some("network-id-1"));
        }
        let process = process_state.lock().expect("process state");
        assert!(process.killed);
        assert!(process.waited);
    }

    #[test]
    fn podman_provision_uses_the_verified_private_gateway() {
        let (_temporary, gateway, policies) = test_paths();
        let (runtime, _runtime_state) = FakeRuntime::new(FakeInspectKind::Podman);
        let process_state = Arc::new(Mutex::new(FakeProcessState::default()));
        let observed = Arc::new(Mutex::new(Vec::new()));
        let registry = test_registry(&policies);
        let controller = ManagedNetworkController::with_components(
            RuntimeProvider::Podman,
            &gateway,
            &policies,
            &registry,
            Arc::new(runtime),
            Arc::new(FakeLauncher {
                state: process_state,
            }),
            Arc::new(FakeReadiness {
                fail: false,
                observed,
            }),
        )
        .expect("controller");
        let now = Utc::now();
        let lease = controller
            .provision(&owner(), &[plan(now, "203.0.113.8", 5, 2, 30)], now)
            .expect("managed network");
        assert_eq!(
            lease.network_policy().gateway_endpoint(),
            Some("socks5h://10.89.1.1:1080")
        );
    }

    #[test]
    fn readiness_failure_rolls_back_process_network_and_policy() {
        let (_temporary, gateway, policies) = test_paths();
        let (runtime, runtime_state) = FakeRuntime::new(FakeInspectKind::Docker);
        let process_state = Arc::new(Mutex::new(FakeProcessState::default()));
        let registry = test_registry(&policies);
        let controller = ManagedNetworkController::with_components(
            RuntimeProvider::Docker,
            &gateway,
            &policies,
            &registry,
            Arc::new(runtime),
            Arc::new(FakeLauncher {
                state: Arc::clone(&process_state),
            }),
            Arc::new(FakeReadiness {
                fail: true,
                observed: Arc::new(Mutex::new(Vec::new())),
            }),
        )
        .expect("controller");
        let now = Utc::now();
        assert!(
            controller
                .provision(&owner(), &[plan(now, "203.0.113.8", 5, 2, 30)], now)
                .is_err()
        );
        assert!(runtime_state.lock().expect("runtime state").removed);
        assert!(
            fs::read_dir(&policies)
                .expect("policy directory")
                .all(|entry| entry.expect("policy entry").path().is_dir())
        );
        // The process was not installed into the lease until readiness succeeded. The
        // controller must still stop it on this failure path.
        let process = process_state.lock().expect("process state");
        assert!(process.killed);
        assert!(process.waited);
    }

    #[test]
    fn startup_reconciles_only_the_exact_durable_orphan_identity() {
        let (_temporary, gateway, artifacts, policies, registry_root) = recovery_paths();
        let (runtime, runtime_state) = FakeRuntime::new(FakeInspectKind::Docker);
        let runtime = Arc::new(runtime);
        let process_state = Arc::new(Mutex::new(FakeProcessState::default()));
        let controller = ManagedNetworkController::with_components(
            RuntimeProvider::Docker,
            &gateway,
            &policies,
            &registry_root,
            runtime.clone(),
            Arc::new(FakeLauncher {
                state: Arc::clone(&process_state),
            }),
            Arc::new(FakeReadiness {
                fail: false,
                observed: Arc::new(Mutex::new(Vec::new())),
            }),
        )
        .expect("controller");
        let now = Utc::now();
        let lease = controller
            .provision(&owner(), &[plan(now, "203.0.113.8", 5, 2, 30)], now)
            .expect("managed network");
        let policy_path = lease.policy_path().expect("policy path").to_owned();
        std::mem::forget(lease);

        let registry = ManagedNetworkRegistry::with_runtime(&registry_root, &artifacts, runtime)
            .expect("registry");
        let summary = registry
            .reconcile_all(now + ChronoDuration::seconds(1))
            .expect("reconciliation");

        assert_eq!(summary.reconciled, 1);
        assert_eq!(summary.incomplete, 0);
        assert!(runtime_state.lock().expect("runtime").removed);
        assert!(!policy_path.exists());
        assert!(
            fs::read_dir(&registry_root)
                .expect("registry")
                .next()
                .is_none()
        );
        // Startup does not kill a persisted numeric PID. The isolated network
        // is gone and the real sidecar independently exits at policy expiry.
        assert!(!process_state.lock().expect("process").killed);
    }

    #[test]
    fn startup_refuses_a_replaced_or_mislabeled_network_and_retains_recovery_records() {
        let (_temporary, gateway, artifacts, policies, registry_root) = recovery_paths();
        let (runtime, runtime_state) = FakeRuntime::new(FakeInspectKind::Docker);
        let runtime = Arc::new(runtime);
        let controller = ManagedNetworkController::with_components(
            RuntimeProvider::Docker,
            &gateway,
            &policies,
            &registry_root,
            runtime.clone(),
            Arc::new(FakeLauncher {
                state: Arc::new(Mutex::new(FakeProcessState::default())),
            }),
            Arc::new(FakeReadiness {
                fail: false,
                observed: Arc::new(Mutex::new(Vec::new())),
            }),
        )
        .expect("controller");
        let now = Utc::now();
        let lease = controller
            .provision(&owner(), &[plan(now, "203.0.113.8", 5, 2, 30)], now)
            .expect("managed network");
        std::mem::forget(lease);
        runtime_state
            .lock()
            .expect("runtime")
            .labels
            .insert(POLICY_LABEL_KEY.into(), "attacker-policy".into());

        let registry = ManagedNetworkRegistry::with_runtime(&registry_root, &artifacts, runtime)
            .expect("registry");
        let summary = registry.reconcile_all(now).expect("safe reconciliation");

        assert_eq!(summary.reconciled, 0);
        assert_eq!(summary.incomplete, 1);
        assert!(!runtime_state.lock().expect("runtime").removed);
        assert!(
            fs::read_dir(&registry_root)
                .expect("registry")
                .next()
                .is_some()
        );
    }

    #[test]
    fn intent_record_recovers_a_crash_between_network_create_and_id_checkpoint() {
        let (_temporary, _gateway, artifacts, _policies, registry_root) = recovery_paths();
        let (runtime, runtime_state) = FakeRuntime::new(FakeInspectKind::Docker);
        let runtime = Arc::new(runtime);
        let now = Utc::now();
        let unique = "a".repeat(32);
        let policy_id = format!("egress-{unique}");
        let network_name = format!("ass-egress-{unique}");
        let record = ManagedNetworkRecord {
            schema_version: REGISTRY_SCHEMA_VERSION.into(),
            owner: owner(),
            provider: RuntimeProvider::Docker,
            network_name: network_name.clone(),
            policy_id: policy_id.clone(),
            created_at: now,
            expires_at: now + ChronoDuration::hours(1),
            phase: RegistryPhase::Intent,
            network_id: None,
            policy_sha256: None,
        };
        write_registry_snapshot(&registry_root, &record).expect("intent record");
        {
            let mut state = runtime_state.lock().expect("runtime");
            state.network_name = Some(network_name);
            state.labels = expected_labels(&policy_id);
            state.removed = false;
        }
        let registry = ManagedNetworkRegistry::with_runtime(&registry_root, &artifacts, runtime)
            .expect("registry");
        let summary = registry.reconcile_all(now).expect("reconciliation");

        assert_eq!(summary.reconciled, 1);
        assert!(runtime_state.lock().expect("runtime").removed);
        assert!(
            fs::read_dir(&registry_root)
                .expect("registry")
                .next()
                .is_none()
        );
    }

    #[cfg(unix)]
    #[test]
    fn symlink_gateway_binary_is_rejected() {
        use std::os::unix::fs::{PermissionsExt, symlink};
        let temporary = tempfile::tempdir().expect("temporary directory");
        let target = temporary.path().join("gateway-real");
        fs::write(&target, b"fake executable").expect("target");
        fs::set_permissions(&target, fs::Permissions::from_mode(0o700)).expect("mode");
        let link = temporary.path().join("ai-security-scanner-egress-gateway");
        symlink(&target, &link).expect("symlink");
        assert!(
            ManagedNetworkController::new(RuntimeProvider::Docker, &link, temporary.path())
                .is_err()
        );
    }

    #[test]
    fn static_gateway_inspection_rejects_a_missing_sidecar_without_creating_it() {
        let temporary = tempfile::tempdir().expect("temporary directory");
        let missing = temporary.path().join("ai-security-scanner-egress-gateway");

        let error = inspect_gateway_binary(&missing).expect_err("missing sidecar rejected");

        assert!(error.to_string().contains("could not be inspected"));
        assert!(!missing.exists(), "inspection must not create the sidecar");
        assert!(
            fs::read_dir(temporary.path())
                .expect("temporary directory")
                .next()
                .is_none(),
            "inspection must not create support files"
        );
    }

    #[cfg(unix)]
    #[test]
    fn static_gateway_inspection_never_makes_a_sidecar_executable() {
        use std::os::unix::fs::PermissionsExt;
        let temporary = tempfile::tempdir().expect("temporary directory");
        let gateway = temporary.path().join("ai-security-scanner-egress-gateway");
        fs::write(&gateway, b"not executable").expect("gateway fixture");
        fs::set_permissions(&gateway, fs::Permissions::from_mode(0o600)).expect("gateway mode");

        let error = inspect_gateway_binary(&gateway).expect_err("non-executable sidecar rejected");

        assert!(error.to_string().contains("not executable"));
        assert_eq!(
            fs::metadata(&gateway)
                .expect("gateway metadata")
                .permissions()
                .mode()
                & 0o777,
            0o600,
            "inspection must not chmod the sidecar"
        );
    }
}
