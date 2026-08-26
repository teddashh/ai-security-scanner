#[cfg(test)]
use ai_security_scanner_lib::managed_network::{EgressGatewayLimits, GatewayDestination};
use ai_security_scanner_lib::managed_network::{EgressGatewayPolicy, EgressGatewayProvenance};
use chrono::{DateTime, Utc};
use ipnet::IpNet;
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet, VecDeque};
use std::env;
use std::ffi::{OsStr, OsString};
use std::fs::{self, OpenOptions};
use std::io::{self, Write};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::{Mutex, Semaphore};
use tokio::time::{Instant as TokioInstant, timeout};

const POLICY_PATH: &str = "/run/ai-security-scanner/egress-policy.json";
const STATUS_FILE_NAME: &str = "status.json";
const STATUS_TEMP_FILE_NAME: &str = "status.tmp";
const STATUS_SCHEMA_VERSION: &str = "1.0.0";
const MAX_STATUS_BYTES: usize = 1024;
const MAX_POLICY_BYTES: u64 = 2 * 1024 * 1024;
const MAX_DESTINATIONS: usize = 10_000;
const MAX_PROVENANCE_GRANTS: usize = 128;
const SOCKS_VERSION: u8 = 5;
const COMMAND_CONNECT: u8 = 1;
const METHOD_NO_AUTH: u8 = 0;
const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(10);

#[derive(Debug)]
struct ValidatedPolicy {
    expires_at: DateTime<Utc>,
    listen_address: SocketAddr,
    allowed_client_network: IpNet,
    max_concurrency: usize,
    max_connections_per_second: usize,
    connect_timeout: Duration,
    max_connection: Duration,
    by_host: BTreeMap<String, BTreeMap<u16, Vec<IpAddr>>>,
    by_address: BTreeSet<(IpAddr, u16)>,
}

#[derive(Debug)]
enum RequestedTarget {
    Address(IpAddr),
    Hostname(String),
}

#[tokio::main]
async fn main() {
    let invocation = match invocation_from_args(env::args_os().skip(1)) {
        Ok(invocation) => invocation,
        Err(_) => {
            eprintln!("egress gateway arguments were rejected");
            std::process::exit(2);
        }
    };
    if let Err(code) = run(&invocation).await {
        if let Some(status_file) = invocation.status_file.as_deref() {
            let _ = write_status(status_file, GatewayPhase::Failed, code);
        }
        eprintln!("egress gateway stopped safely");
        std::process::exit(1);
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct GatewayInvocation {
    policy_path: PathBuf,
    status_file: Option<PathBuf>,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
enum GatewayPhase {
    Starting,
    Ready,
    Failed,
    Stopped,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
enum GatewayStatusCode {
    Initializing,
    Ready,
    PolicyInspectionFailed,
    PolicyInvalid,
    ListenerBindFailed,
    ListenerFailed,
    SignalHandlerFailed,
    StatusWriteFailed,
    PolicyExpired,
}

#[derive(Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
struct GatewayStatus {
    schema_version: String,
    phase: GatewayPhase,
    code: GatewayStatusCode,
}

async fn run(invocation: &GatewayInvocation) -> Result<(), GatewayStatusCode> {
    if let Some(status_file) = invocation.status_file.as_deref() {
        write_status(
            status_file,
            GatewayPhase::Starting,
            GatewayStatusCode::Initializing,
        )?;
    }
    let policy = Arc::new(load_policy(&invocation.policy_path)?);
    let concurrency = Arc::new(Semaphore::new(policy.max_concurrency));
    let rate_window = Arc::new(Mutex::new(VecDeque::<Instant>::new()));
    let listener = TcpListener::bind(policy.listen_address)
        .await
        .map_err(|_| GatewayStatusCode::ListenerBindFailed)?;
    if let Some(status_file) = invocation.status_file.as_deref() {
        write_status(status_file, GatewayPhase::Ready, GatewayStatusCode::Ready)?;
    }
    let expires_after = policy_remaining(&policy).ok_or(GatewayStatusCode::PolicyInvalid)?;
    let expiry_deadline = tokio::time::Instant::now() + expires_after;

    loop {
        tokio::select! {
            biased;
            _ = tokio::time::sleep_until(expiry_deadline) => {
                // Dropping the listener and Tokio runtime also aborts every
                // in-flight relay. The sidecar therefore cannot outlive the
                // durable authorization deadline even if its parent crashes.
                if let Some(status_file) = invocation.status_file.as_deref() {
                    write_status(
                        status_file,
                        GatewayPhase::Stopped,
                        GatewayStatusCode::PolicyExpired,
                    )?;
                }
                return Ok(());
            }
            accepted = listener.accept() => {
                let (client, peer) = accepted.map_err(|_| GatewayStatusCode::ListenerFailed)?;
                if policy.expires_at <= Utc::now() || !authorized_client(&policy, peer.ip()) {
                    continue;
                }
                let policy = Arc::clone(&policy);
                let concurrency = Arc::clone(&concurrency);
                let rate_window = Arc::clone(&rate_window);
                tokio::spawn(async move {
                    let _ = handle_authorized_client(
                        client,
                        policy,
                        concurrency,
                        rate_window,
                    ).await;
                });
            }
            signal = tokio::signal::ctrl_c() => {
                signal.map_err(|_| GatewayStatusCode::SignalHandlerFailed)?;
                return Ok(());
            }
        }
    }
}

async fn handle_authorized_client(
    client: TcpStream,
    policy: Arc<ValidatedPolicy>,
    concurrency: Arc<Semaphore>,
    rate_window: Arc<Mutex<VecDeque<Instant>>>,
) -> io::Result<()> {
    let _permit = concurrency
        .acquire_owned()
        .await
        .map_err(|_| io::Error::new(io::ErrorKind::BrokenPipe, "gateway stopped"))?;
    handle_client(client, &policy, &rate_window).await
}

async fn take_rate_slot(policy: &ValidatedPolicy, rate_window: &Mutex<VecDeque<Instant>>) -> bool {
    if policy.expires_at <= Utc::now() {
        return false;
    }
    let now = Instant::now();
    let mut samples = rate_window.lock().await;
    while samples
        .front()
        .is_some_and(|sample| now.duration_since(*sample) >= Duration::from_secs(1))
    {
        samples.pop_front();
    }
    if samples.len() >= policy.max_connections_per_second {
        return false;
    }
    samples.push_back(now);
    true
}

async fn handle_client(
    mut client: TcpStream,
    policy: &ValidatedPolicy,
    rate_window: &Mutex<VecDeque<Instant>>,
) -> io::Result<()> {
    let remaining = policy_remaining(policy)
        .ok_or_else(|| io::Error::new(io::ErrorKind::PermissionDenied, "expired policy"))?;
    timeout(
        remaining,
        handle_client_before_expiry(&mut client, policy, rate_window),
    )
    .await
    .map_err(|_| io::Error::new(io::ErrorKind::PermissionDenied, "policy expired"))?
}

async fn handle_client_before_expiry(
    client: &mut TcpStream,
    policy: &ValidatedPolicy,
    rate_window: &Mutex<VecDeque<Instant>>,
) -> io::Result<()> {
    timeout(HANDSHAKE_TIMEOUT, negotiate(client))
        .await
        .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "greeting timeout"))??;
    let (target, port) = timeout(HANDSHAKE_TIMEOUT, read_request(client))
        .await
        .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "request timeout"))??;
    let destinations = resolve_request(policy, target, port)
        .map_err(|_| io::Error::new(io::ErrorKind::PermissionDenied, "destination denied"))?;
    // A TCP-only proxy liveness check may open and close the socket without
    // sending CONNECT. Count only a syntactically valid, policy-authorized
    // upstream request so those checks cannot consume the scanner's rate.
    if !take_rate_slot(policy, rate_window).await {
        send_reply(client, 2, None).await?;
        return Err(io::Error::new(
            io::ErrorKind::WouldBlock,
            "connection rate denied",
        ));
    }
    let mut upstream = match connect_frozen_destinations(destinations, policy.connect_timeout).await
    {
        Ok(stream) => stream,
        Err(error) => {
            let reply = if error.kind() == io::ErrorKind::TimedOut {
                6
            } else {
                5
            };
            send_reply(client, reply, None).await?;
            return Err(error);
        }
    };
    let bound = upstream.local_addr().ok();
    send_reply(client, 0, bound).await?;
    // copy_bidirectional propagates EOF as a half-close to the opposite
    // writer. This is essential for banner probes that connect, read, and
    // close without sending a payload: the upstream must see EOF so it can
    // close its response side and release the bounded concurrency permit.
    timeout(
        policy.max_connection,
        tokio::io::copy_bidirectional(client, &mut upstream),
    )
    .await
    .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "connection lifetime exceeded"))??;
    Ok(())
}

fn policy_remaining(policy: &ValidatedPolicy) -> Option<Duration> {
    policy
        .expires_at
        .signed_duration_since(Utc::now())
        .to_std()
        .ok()
        .filter(|duration| !duration.is_zero())
}

/// Connects to the complete host-side frozen address set without performing
/// DNS. Candidates are attempted one at a time so the policy's concurrency
/// bound is never widened, and every remaining address receives a fair share
/// of the one aggregate timeout.
async fn connect_frozen_destinations(
    destinations: Vec<SocketAddr>,
    budget: Duration,
) -> io::Result<TcpStream> {
    if destinations.is_empty() || budget.is_zero() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "frozen destination set is empty",
        ));
    }

    let deadline = TokioInstant::now() + budget;
    let mut last_error = None;
    let mut remaining_count = destinations.len();
    for destination in destinations {
        let remaining = deadline.saturating_duration_since(TokioInstant::now());
        if remaining.is_zero() {
            return Err(io::Error::new(
                io::ErrorKind::TimedOut,
                "aggregate connect timeout",
            ));
        }
        let divisor = u32::try_from(remaining_count).unwrap_or(u32::MAX);
        let attempt_budget = remaining.checked_div(divisor).unwrap_or(remaining);
        match timeout(attempt_budget, TcpStream::connect(destination)).await {
            Ok(Ok(stream)) => return Ok(stream),
            Ok(Err(error)) => last_error = Some(error),
            Err(_) => {
                last_error = Some(io::Error::new(
                    io::ErrorKind::TimedOut,
                    "candidate connect timeout",
                ));
            }
        }
        remaining_count = remaining_count.saturating_sub(1);
    }
    Err(last_error.unwrap_or_else(|| {
        io::Error::new(
            io::ErrorKind::ConnectionRefused,
            "all frozen addresses failed",
        )
    }))
}

async fn negotiate(client: &mut TcpStream) -> io::Result<()> {
    let version = client.read_u8().await?;
    let method_count = client.read_u8().await? as usize;
    if version != SOCKS_VERSION || method_count == 0 || method_count > 32 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "invalid greeting",
        ));
    }
    let mut methods = vec![0_u8; method_count];
    client.read_exact(&mut methods).await?;
    if !methods.contains(&METHOD_NO_AUTH) {
        client.write_all(&[SOCKS_VERSION, 0xff]).await?;
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "method denied",
        ));
    }
    client.write_all(&[SOCKS_VERSION, METHOD_NO_AUTH]).await
}

async fn read_request(client: &mut TcpStream) -> io::Result<(RequestedTarget, u16)> {
    let version = client.read_u8().await?;
    let command = client.read_u8().await?;
    let reserved = client.read_u8().await?;
    let address_type = client.read_u8().await?;
    if version != SOCKS_VERSION || command != COMMAND_CONNECT || reserved != 0 {
        send_reply(client, 7, None).await?;
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "command denied",
        ));
    }
    let target = match address_type {
        1 => {
            let mut octets = [0_u8; 4];
            client.read_exact(&mut octets).await?;
            RequestedTarget::Address(IpAddr::V4(Ipv4Addr::from(octets)))
        }
        4 => {
            let mut octets = [0_u8; 16];
            client.read_exact(&mut octets).await?;
            RequestedTarget::Address(IpAddr::V6(Ipv6Addr::from(octets)))
        }
        3 => {
            let length = client.read_u8().await? as usize;
            if length == 0 || length > 253 {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "hostname length",
                ));
            }
            let mut bytes = vec![0_u8; length];
            client.read_exact(&mut bytes).await?;
            let hostname = std::str::from_utf8(&bytes)
                .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "hostname encoding"))?;
            let canonical = canonical_hostname(hostname)
                .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "hostname"))?;
            RequestedTarget::Hostname(canonical)
        }
        _ => {
            send_reply(client, 8, None).await?;
            return Err(io::Error::new(io::ErrorKind::InvalidData, "address type"));
        }
    };
    Ok((target, client.read_u16().await?))
}

async fn send_reply(
    client: &mut TcpStream,
    reply: u8,
    bound: Option<SocketAddr>,
) -> io::Result<()> {
    match bound.unwrap_or_else(|| SocketAddr::from(([0, 0, 0, 0], 0))) {
        SocketAddr::V4(address) => {
            let mut response = vec![SOCKS_VERSION, reply, 0, 1];
            response.extend(address.ip().octets());
            response.extend(address.port().to_be_bytes());
            client.write_all(&response).await
        }
        SocketAddr::V6(address) => {
            let mut response = vec![SOCKS_VERSION, reply, 0, 4];
            response.extend(address.ip().octets());
            response.extend(address.port().to_be_bytes());
            client.write_all(&response).await
        }
    }
}

fn load_raw_policy(path: &Path) -> Result<EgressGatewayPolicy, GatewayStatusCode> {
    let metadata =
        fs::symlink_metadata(path).map_err(|_| GatewayStatusCode::PolicyInspectionFailed)?;
    if metadata.file_type().is_symlink() || !metadata.is_file() || metadata.len() > MAX_POLICY_BYTES
    {
        return Err(GatewayStatusCode::PolicyInvalid);
    }
    let bytes = fs::read(path).map_err(|_| GatewayStatusCode::PolicyInspectionFailed)?;
    serde_json::from_slice(&bytes).map_err(|_| GatewayStatusCode::PolicyInvalid)
}

fn load_policy(path: &Path) -> Result<ValidatedPolicy, GatewayStatusCode> {
    validate_policy(load_raw_policy(path)?, Utc::now())
        .map_err(|_| GatewayStatusCode::PolicyInvalid)
}

fn invocation_from_args<I, S>(args: I) -> Result<GatewayInvocation, &'static str>
where
    I: IntoIterator<Item = S>,
    S: Into<OsString>,
{
    let arguments = args.into_iter().map(Into::into).collect::<Vec<_>>();
    let (policy_path, status_file) = match arguments.as_slice() {
        [] => (PathBuf::from(POLICY_PATH), None),
        [flag, path] if flag == OsStr::new("--policy") => (PathBuf::from(path), None),
        [policy_flag, policy_path, status_flag, status_file]
            if policy_flag == OsStr::new("--policy")
                && status_flag == OsStr::new("--status-file") =>
        {
            (PathBuf::from(policy_path), Some(PathBuf::from(status_file)))
        }
        _ => return Err("only --policy <absolute-path> is accepted"),
    };
    if !policy_path.is_absolute() || policy_path.as_os_str().len() > 4096 {
        return Err("policy path must be a bounded absolute path");
    }
    if let Some(status_file) = status_file.as_deref()
        && (!status_file.is_absolute()
            || status_file.as_os_str().len() > 4096
            || status_file.file_name() != Some(OsStr::new(STATUS_FILE_NAME))
            || status_file.parent().is_none()
            || status_file == policy_path)
    {
        return Err("status file must be the bounded absolute status.json path");
    }
    Ok(GatewayInvocation {
        policy_path,
        status_file,
    })
}

fn write_status(
    path: &Path,
    phase: GatewayPhase,
    code: GatewayStatusCode,
) -> Result<(), GatewayStatusCode> {
    if !path.is_absolute()
        || path.as_os_str().len() > 4096
        || path.file_name() != Some(OsStr::new(STATUS_FILE_NAME))
    {
        return Err(GatewayStatusCode::StatusWriteFailed);
    }
    let parent = path.parent().ok_or(GatewayStatusCode::StatusWriteFailed)?;
    let parent_metadata =
        fs::symlink_metadata(parent).map_err(|_| GatewayStatusCode::StatusWriteFailed)?;
    if parent_metadata.file_type().is_symlink() || !parent_metadata.is_dir() {
        return Err(GatewayStatusCode::StatusWriteFailed);
    }
    let temporary = parent.join(STATUS_TEMP_FILE_NAME);
    if temporary.parent() != Some(parent) {
        return Err(GatewayStatusCode::StatusWriteFailed);
    }
    let bytes = serde_json::to_vec(&GatewayStatus {
        schema_version: STATUS_SCHEMA_VERSION.to_owned(),
        phase,
        code,
    })
    .map_err(|_| GatewayStatusCode::StatusWriteFailed)?;
    if bytes.is_empty() || bytes.len() > MAX_STATUS_BYTES {
        return Err(GatewayStatusCode::StatusWriteFailed);
    }

    let mut options = OpenOptions::new();
    options.write(true).create_new(true);
    configure_private_status_create(&mut options);
    let mut file = options
        .open(&temporary)
        .map_err(|_| GatewayStatusCode::StatusWriteFailed)?;
    let write_result = file.write_all(&bytes).and_then(|_| file.sync_all());
    drop(file);
    if write_result.is_err() {
        let _ = remove_exact_status_temporary(&temporary);
        return Err(GatewayStatusCode::StatusWriteFailed);
    }
    let publish_result = fs::rename(&temporary, path)
        .and_then(|_| fs::File::open(parent))
        .and_then(|directory| directory.sync_all());
    if publish_result.is_err() {
        let _ = remove_exact_status_temporary(&temporary);
        return Err(GatewayStatusCode::StatusWriteFailed);
    }
    Ok(())
}

#[cfg(unix)]
fn configure_private_status_create(options: &mut OpenOptions) {
    use std::os::unix::fs::OpenOptionsExt;
    options.mode(0o600);
    options.custom_flags(libc::O_CLOEXEC | libc::O_NOFOLLOW);
}

#[cfg(not(unix))]
fn configure_private_status_create(_options: &mut OpenOptions) {}

fn remove_exact_status_temporary(path: &Path) -> io::Result<()> {
    match fs::symlink_metadata(path) {
        Ok(metadata) if metadata.is_file() && !metadata.file_type().is_symlink() => {
            fs::remove_file(path)
        }
        Ok(_) => Ok(()),
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(error),
    }
}

fn validate_policy(
    raw: EgressGatewayPolicy,
    now: DateTime<Utc>,
) -> Result<ValidatedPolicy, &'static str> {
    if raw.schema_version != "2.0.0"
        || raw.policy_id.is_empty()
        || raw.policy_id.len() > 128
        || raw.expires_at <= now
        || raw.expires_at > now + chrono::Duration::hours(24)
        || !valid_listener(raw.listen_address, raw.allowed_client_network)
        || !(1..=256).contains(&raw.limits.max_concurrency)
        || !(1..=1_000).contains(&raw.limits.max_connections_per_second)
        || !(1..=120).contains(&raw.limits.connect_timeout_seconds)
        || !(1..=86_400).contains(&raw.limits.max_connection_seconds)
        || raw.destinations.is_empty()
        || raw.destinations.len() > MAX_DESTINATIONS
    {
        return Err("policy header is invalid");
    }
    validate_provenance(&raw.provenance)?;
    let mut by_host = BTreeMap::<String, BTreeMap<u16, Vec<IpAddr>>>::new();
    let mut by_address = BTreeSet::new();
    for destination in raw.destinations {
        if destination.addresses.is_empty() || destination.ports.is_empty() {
            return Err("policy destination is unbounded");
        }
        let hostname = destination
            .hostname
            .as_deref()
            .map(canonical_hostname)
            .transpose()?;
        for address in destination.addresses {
            if is_metadata(address)
                || (is_sensitive(address) && !destination.allow_sensitive_networks)
            {
                return Err("policy contains a prohibited address");
            }
            for port in &destination.ports {
                if *port == 0 {
                    return Err("policy contains port zero");
                }
                by_address.insert((address, *port));
                if let Some(hostname) = &hostname {
                    by_host
                        .entry(hostname.clone())
                        .or_default()
                        .entry(*port)
                        .or_default()
                        .push(address);
                }
            }
        }
    }
    for ports in by_host.values_mut() {
        for addresses in ports.values_mut() {
            addresses.sort_unstable();
            addresses.dedup();
        }
    }
    Ok(ValidatedPolicy {
        expires_at: raw.expires_at,
        listen_address: raw.listen_address,
        allowed_client_network: raw.allowed_client_network,
        max_concurrency: raw.limits.max_concurrency,
        max_connections_per_second: raw.limits.max_connections_per_second,
        connect_timeout: Duration::from_secs(raw.limits.connect_timeout_seconds),
        max_connection: Duration::from_secs(raw.limits.max_connection_seconds),
        by_host,
        by_address,
    })
}

fn validate_provenance(provenance: &EgressGatewayProvenance) -> Result<(), &'static str> {
    fn token(value: &str) -> bool {
        !value.trim().is_empty() && value.len() <= 256 && !value.contains(['\n', '\r', '\0'])
    }
    match provenance {
        EgressGatewayProvenance::ExternalAssetGrants {
            case_id,
            grant_ids,
            activities,
        } => {
            if !token(case_id)
                || grant_ids.is_empty()
                || grant_ids.len() > MAX_PROVENANCE_GRANTS
                || grant_ids.iter().any(|value| !token(value))
                || activities.is_empty()
                || activities.len() > 3
            {
                return Err("external policy provenance is invalid");
            }
        }
        EgressGatewayProvenance::ProviderService {
            case_id,
            source_id,
            source_kind,
            source_profile,
            manifest_id,
            manifest_revision,
        } => {
            if [
                case_id.as_str(),
                source_id.as_str(),
                source_kind.as_str(),
                source_profile.as_str(),
                manifest_id.as_str(),
                manifest_revision.as_str(),
            ]
            .into_iter()
            .any(|value| !token(value))
            {
                return Err("provider-service policy provenance is invalid");
            }
        }
        EgressGatewayProvenance::ReleaseQualification {
            case_id,
            qualification_id,
        } => {
            if !token(case_id) || !token(qualification_id) {
                return Err("release-qualification policy provenance is invalid");
            }
        }
    }
    Ok(())
}

fn valid_listener(listener: SocketAddr, clients: IpNet) -> bool {
    if listener.port() == 0
        || is_metadata(listener.ip())
        || !clients.contains(&listener.ip())
        || !is_private_network(clients)
    {
        return false;
    }
    match clients {
        IpNet::V4(network) => (16..=30).contains(&network.prefix_len()),
        IpNet::V6(network) => (48..=126).contains(&network.prefix_len()),
    }
}

fn is_private_network(network: IpNet) -> bool {
    match network {
        IpNet::V4(network) => network.network().is_private(),
        IpNet::V6(network) => (network.network().segments()[0] & 0xfe00) == 0xfc00,
    }
}

fn authorized_client(policy: &ValidatedPolicy, peer: IpAddr) -> bool {
    peer != policy.listen_address.ip() && policy.allowed_client_network.contains(&peer)
}

fn resolve_request(
    policy: &ValidatedPolicy,
    target: RequestedTarget,
    port: u16,
) -> Result<Vec<SocketAddr>, &'static str> {
    match target {
        RequestedTarget::Address(address) => policy
            .by_address
            .contains(&(address, port))
            .then_some(vec![SocketAddr::new(address, port)])
            .ok_or("address is outside policy"),
        RequestedTarget::Hostname(hostname) => policy
            .by_host
            .get(&hostname)
            .and_then(|ports| ports.get(&port))
            .filter(|addresses| !addresses.is_empty())
            .map(|addresses| {
                addresses
                    .iter()
                    .copied()
                    .map(|address| SocketAddr::new(address, port))
                    .collect()
            })
            .ok_or("hostname is outside policy"),
    }
}

fn canonical_hostname(value: &str) -> Result<String, &'static str> {
    let ascii = idna::domain_to_ascii(value.trim_end_matches('.'))
        .map_err(|_| "hostname is invalid")?
        .to_ascii_lowercase();
    if ascii.len() > 253
        || !ascii.contains('.')
        || ascii.split('.').any(|label| {
            label.is_empty()
                || label.len() > 63
                || label.starts_with('-')
                || label.ends_with('-')
                || !label
                    .chars()
                    .all(|character| character.is_ascii_alphanumeric() || character == '-')
        })
    {
        return Err("hostname is invalid");
    }
    Ok(ascii)
}

fn is_metadata(address: IpAddr) -> bool {
    match address {
        IpAddr::V4(address) => {
            address == Ipv4Addr::new(169, 254, 169, 254)
                || address == Ipv4Addr::new(169, 254, 170, 2)
                || address == Ipv4Addr::new(100, 100, 100, 200)
        }
        IpAddr::V6(address) => address == "fd00:ec2::254".parse::<Ipv6Addr>().expect("literal"),
    }
}

fn is_sensitive(address: IpAddr) -> bool {
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
                || address.octets()[0] >= 240
        }
        IpAddr::V6(address) => {
            address.is_loopback()
                || address.is_multicast()
                || address.is_unspecified()
                || (address.segments()[0] & 0xfe00) == 0xfc00
                || (address.segments()[0] & 0xffc0) == 0xfe80
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    async fn connected_pair() -> (TcpStream, TcpStream) {
        let listener = TcpListener::bind("127.0.0.1:0").await.expect("listener");
        let address = listener.local_addr().expect("listener address");
        let client = TcpStream::connect(address).await.expect("client");
        let (server, _) = listener.accept().await.expect("server");
        (client, server)
    }

    async fn socks_connect(client: &mut TcpStream, destination: SocketAddr) {
        client
            .write_all(&[SOCKS_VERSION, 1, METHOD_NO_AUTH])
            .await
            .expect("SOCKS greeting");
        let mut greeting = [0_u8; 2];
        client
            .read_exact(&mut greeting)
            .await
            .expect("SOCKS greeting response");
        assert_eq!(greeting, [SOCKS_VERSION, METHOD_NO_AUTH]);
        let SocketAddr::V4(destination) = destination else {
            panic!("test destination must be IPv4")
        };
        let mut request = vec![SOCKS_VERSION, COMMAND_CONNECT, 0, 1];
        request.extend(destination.ip().octets());
        request.extend(destination.port().to_be_bytes());
        client.write_all(&request).await.expect("SOCKS request");
        let mut reply = [0_u8; 10];
        client.read_exact(&mut reply).await.expect("SOCKS reply");
        assert_eq!(&reply[..4], &[SOCKS_VERSION, 0, 0, 1]);
    }

    fn raw_policy() -> EgressGatewayPolicy {
        EgressGatewayPolicy {
            schema_version: "2.0.0".into(),
            policy_id: "policy-1".into(),
            expires_at: Utc::now() + chrono::Duration::minutes(10),
            listen_address: "172.29.0.1:1080".parse().expect("listener"),
            allowed_client_network: "172.29.0.0/24".parse().expect("client network"),
            limits: EgressGatewayLimits {
                max_concurrency: 4,
                max_connections_per_second: 10,
                connect_timeout_seconds: 5,
                max_connection_seconds: 30,
            },
            provenance: EgressGatewayProvenance::ExternalAssetGrants {
                case_id: "case-1".into(),
                grant_ids: vec!["grant-1".into()],
                activities: vec![
                    ai_security_scanner_lib::external_scope::ExternalActivity::ActiveExternal,
                ],
            },
            destinations: vec![GatewayDestination {
                hostname: Some("App.Example.Test.".into()),
                addresses: ["203.0.113.9".parse().expect("address")]
                    .into_iter()
                    .collect(),
                ports: [443].into_iter().collect(),
                allow_sensitive_networks: false,
            }],
        }
    }

    #[test]
    fn frozen_hostname_never_performs_live_dns_resolution() {
        let mut raw = raw_policy();
        raw.destinations[0]
            .addresses
            .insert("203.0.113.10".parse().expect("second address"));
        let policy = validate_policy(raw, Utc::now()).expect("policy");
        assert_eq!(
            resolve_request(
                &policy,
                RequestedTarget::Hostname("app.example.test".into()),
                443
            )
            .expect("destination"),
            vec![
                "203.0.113.9:443".parse().expect("first socket"),
                "203.0.113.10:443".parse().expect("second socket")
            ]
        );
        assert!(
            resolve_request(
                &policy,
                RequestedTarget::Hostname("other.example.test".into()),
                443
            )
            .is_err()
        );
    }

    #[test]
    fn metadata_and_unapproved_ports_are_denied() {
        let mut raw = raw_policy();
        raw.destinations[0].addresses = ["169.254.169.254".parse().expect("metadata")]
            .into_iter()
            .collect();
        raw.destinations[0].allow_sensitive_networks = true;
        assert!(validate_policy(raw, Utc::now()).is_err());

        let policy = validate_policy(raw_policy(), Utc::now()).expect("policy");
        assert!(
            resolve_request(
                &policy,
                RequestedTarget::Address("203.0.113.9".parse().expect("address")),
                80
            )
            .is_err()
        );
    }

    #[test]
    fn policy_expiry_and_limits_fail_closed() {
        let mut raw = raw_policy();
        raw.expires_at = Utc::now() - chrono::Duration::seconds(1);
        assert!(validate_policy(raw, Utc::now()).is_err());
    }

    #[test]
    fn release_qualification_provenance_is_bounded_and_machine_owned() {
        let mut raw = raw_policy();
        raw.provenance = EgressGatewayProvenance::ReleaseQualification {
            case_id: "release-qualification".into(),
            qualification_id: "gateway-no-connect".into(),
        };
        assert!(validate_policy(raw.clone(), Utc::now()).is_ok());
        raw.provenance = EgressGatewayProvenance::ReleaseQualification {
            case_id: "release-qualification".into(),
            qualification_id: "unsafe\nidentifier".into(),
        };
        assert!(validate_policy(raw, Utc::now()).is_err());
    }

    #[tokio::test]
    async fn an_already_accepted_socket_is_denied_after_policy_expiry() {
        let mut policy = validate_policy(raw_policy(), Utc::now()).expect("policy");
        policy.expires_at = Utc::now() - chrono::Duration::milliseconds(1);
        assert!(policy_remaining(&policy).is_none());
        let rate_window = Mutex::new(VecDeque::new());

        let listener = TcpListener::bind("127.0.0.1:0").await.expect("listener");
        let address = listener.local_addr().expect("address");
        let client = TcpStream::connect(address).await.expect("client");
        let (server, _) = listener.accept().await.expect("accepted");
        let error = handle_client(server, &policy, &rate_window)
            .await
            .expect_err("expired socket denied before reading a greeting");
        assert_eq!(error.kind(), io::ErrorKind::PermissionDenied);
        drop(client);
    }

    #[tokio::test]
    async fn tcp_only_proxy_probe_does_not_consume_an_upstream_rate_slot() {
        let policy = Arc::new(validate_policy(raw_policy(), Utc::now()).expect("policy"));
        let concurrency = Arc::new(Semaphore::new(1));
        let rate_window = Arc::new(Mutex::new(VecDeque::new()));
        let (mut probe_client, probe_server) = connected_pair().await;
        let handler = tokio::spawn(handle_authorized_client(
            probe_server,
            policy,
            concurrency,
            Arc::clone(&rate_window),
        ));
        probe_client.shutdown().await.expect("probe EOF");
        handler
            .await
            .expect("probe handler task")
            .expect_err("TCP-only probe has no SOCKS request");
        assert!(rate_window.lock().await.is_empty());
    }

    #[tokio::test]
    async fn frozen_address_connect_falls_back_within_one_bounded_budget() {
        let refused_listener = TcpListener::bind("127.0.0.1:0")
            .await
            .expect("temporary refused listener");
        let refused = refused_listener.local_addr().expect("refused address");
        drop(refused_listener);
        let reachable_listener = TcpListener::bind("127.0.0.1:0")
            .await
            .expect("reachable listener");
        let reachable = reachable_listener.local_addr().expect("reachable address");

        let stream = connect_frozen_destinations(vec![refused, reachable], Duration::from_secs(1))
            .await
            .expect("second frozen address should be attempted");
        assert_eq!(stream.peer_addr().expect("peer"), reachable);
    }

    #[tokio::test]
    async fn client_eof_half_closes_upstream_and_releases_the_only_permit() {
        let target = TcpListener::bind("127.0.0.1:0")
            .await
            .expect("target listener");
        let target_address = target.local_addr().expect("target address");
        let target_task = tokio::spawn(async move {
            let (mut first, _) = target.accept().await.expect("first target connection");
            let mut first_body = Vec::new();
            timeout(Duration::from_secs(1), first.read_to_end(&mut first_body))
                .await
                .expect("first target did not receive EOF")
                .expect("first target read");
            assert!(first_body.is_empty());
            drop(first);

            let (mut second, _) = target.accept().await.expect("second target connection");
            let mut value = [0_u8; 4];
            second.read_exact(&mut value).await.expect("second read");
            second.write_all(&value).await.expect("second write");
        });

        let mut raw = raw_policy();
        raw.limits.max_concurrency = 1;
        raw.limits.max_connection_seconds = 60;
        raw.destinations[0].hostname = None;
        raw.destinations[0].addresses = [target_address.ip()].into_iter().collect();
        raw.destinations[0].ports = [target_address.port()].into_iter().collect();
        raw.destinations[0].allow_sensitive_networks = true;
        let policy = Arc::new(validate_policy(raw, Utc::now()).expect("policy"));
        let concurrency = Arc::new(Semaphore::new(1));
        let rate_window = Arc::new(Mutex::new(VecDeque::new()));

        let (mut first_client, first_server) = connected_pair().await;
        let first_handler = tokio::spawn(handle_authorized_client(
            first_server,
            Arc::clone(&policy),
            Arc::clone(&concurrency),
            Arc::clone(&rate_window),
        ));
        socks_connect(&mut first_client, target_address).await;
        first_client.shutdown().await.expect("first client EOF");
        timeout(Duration::from_secs(1), first_handler)
            .await
            .expect("first permit remained held")
            .expect("first handler task")
            .expect("first relay");
        assert_eq!(concurrency.available_permits(), 1);

        let (mut second_client, second_server) = connected_pair().await;
        let second_handler = tokio::spawn(handle_authorized_client(
            second_server,
            Arc::clone(&policy),
            Arc::clone(&concurrency),
            Arc::clone(&rate_window),
        ));
        timeout(
            Duration::from_secs(1),
            socks_connect(&mut second_client, target_address),
        )
        .await
        .expect("second exact-target connection was blocked by the first");
        second_client
            .write_all(b"ping")
            .await
            .expect("second write");
        let mut response = [0_u8; 4];
        second_client
            .read_exact(&mut response)
            .await
            .expect("second response");
        assert_eq!(&response, b"ping");
        second_client.shutdown().await.expect("second client EOF");
        timeout(Duration::from_secs(1), second_handler)
            .await
            .expect("second handler remained blocked")
            .expect("second handler task")
            .expect("second relay");
        target_task.await.expect("target task");
    }

    #[test]
    fn only_the_dedicated_container_network_can_connect() {
        let policy = validate_policy(raw_policy(), Utc::now()).expect("policy");
        assert!(authorized_client(
            &policy,
            "172.29.0.2".parse().expect("scanner address")
        ));
        assert!(!authorized_client(
            &policy,
            "172.29.0.1".parse().expect("host gateway")
        ));
        assert!(!authorized_client(
            &policy,
            "127.0.0.1".parse().expect("loopback")
        ));
    }

    #[test]
    fn invocation_parser_accepts_only_bounded_fixed_forms() {
        assert_eq!(
            invocation_from_args(Vec::<OsString>::new()).expect("default"),
            GatewayInvocation {
                policy_path: PathBuf::from(POLICY_PATH),
                status_file: None,
            }
        );
        assert_eq!(
            invocation_from_args([
                "--policy",
                "/tmp/policy.json",
                "--status-file",
                "/tmp/status/status.json",
            ])
            .expect("container invocation"),
            GatewayInvocation {
                policy_path: PathBuf::from("/tmp/policy.json"),
                status_file: Some(PathBuf::from("/tmp/status/status.json")),
            }
        );
        assert!(invocation_from_args(["--policy", "relative.json"]).is_err());
        assert!(invocation_from_args(["--other", "/tmp/policy.json"]).is_err());
        assert!(invocation_from_args(["--policy", "/tmp/policy.json", "extra"]).is_err());
        assert!(
            invocation_from_args([
                "--status-file",
                "/tmp/status/status.json",
                "--policy",
                "/tmp/policy.json",
            ])
            .is_err()
        );
        assert!(
            invocation_from_args([
                "--policy",
                "/tmp/policy.json",
                "--status-file",
                "relative/status.json",
            ])
            .is_err()
        );
        assert!(
            invocation_from_args([
                "--policy",
                "/tmp/policy.json",
                "--status-file",
                "/tmp/status/other.json",
            ])
            .is_err()
        );
    }

    #[test]
    fn status_updates_are_bounded_atomic_and_machine_readable() {
        let temporary = tempfile::tempdir().expect("temporary status directory");
        let path = temporary.path().join(STATUS_FILE_NAME);
        write_status(
            &path,
            GatewayPhase::Starting,
            GatewayStatusCode::Initializing,
        )
        .expect("starting status");
        write_status(&path, GatewayPhase::Ready, GatewayStatusCode::Ready).expect("ready status");
        assert!(!temporary.path().join(STATUS_TEMP_FILE_NAME).exists());
        let bytes = fs::read(&path).expect("status bytes");
        assert!(bytes.len() <= MAX_STATUS_BYTES);
        let status: GatewayStatus = serde_json::from_slice(&bytes).expect("status json");
        assert_eq!(
            status,
            GatewayStatus {
                schema_version: STATUS_SCHEMA_VERSION.to_owned(),
                phase: GatewayPhase::Ready,
                code: GatewayStatusCode::Ready,
            }
        );
    }

    #[test]
    fn status_writer_rejects_wrong_name_and_stale_temporary() {
        let temporary = tempfile::tempdir().expect("temporary status directory");
        assert_eq!(
            write_status(
                &temporary.path().join("other.json"),
                GatewayPhase::Starting,
                GatewayStatusCode::Initializing,
            ),
            Err(GatewayStatusCode::StatusWriteFailed)
        );
        fs::write(temporary.path().join(STATUS_TEMP_FILE_NAME), b"occupied")
            .expect("stale temporary");
        assert_eq!(
            write_status(
                &temporary.path().join(STATUS_FILE_NAME),
                GatewayPhase::Starting,
                GatewayStatusCode::Initializing,
            ),
            Err(GatewayStatusCode::StatusWriteFailed)
        );
    }
}
