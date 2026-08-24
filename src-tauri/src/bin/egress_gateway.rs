#[cfg(test)]
use ai_security_scanner_lib::managed_network::{EgressGatewayLimits, GatewayDestination};
use ai_security_scanner_lib::managed_network::{EgressGatewayPolicy, EgressGatewayProvenance};
use chrono::{DateTime, Utc};
use ipnet::IpNet;
use std::collections::{BTreeMap, BTreeSet, VecDeque};
use std::env;
use std::ffi::{OsStr, OsString};
use std::fs;
use std::io;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::{Mutex, Semaphore};
use tokio::time::timeout;

const POLICY_PATH: &str = "/run/ai-security-scanner/egress-policy.json";
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
    let policy_path = match policy_path_from_args(env::args_os().skip(1)) {
        Ok(path) => path,
        Err(_) => {
            eprintln!("egress gateway arguments were rejected");
            std::process::exit(2);
        }
    };
    if run(&policy_path).await.is_err() {
        eprintln!("egress gateway stopped safely");
        std::process::exit(1);
    }
}

async fn run(policy_path: &Path) -> Result<(), &'static str> {
    let policy = Arc::new(load_policy(policy_path)?);
    let concurrency = Arc::new(Semaphore::new(policy.max_concurrency));
    let rate_window = Arc::new(Mutex::new(VecDeque::<Instant>::new()));
    let listener = TcpListener::bind(policy.listen_address)
        .await
        .map_err(|_| "gateway listener could not bind")?;
    let expires_after = policy_remaining(&policy).ok_or("gateway policy expired")?;
    let expiry_deadline = tokio::time::Instant::now() + expires_after;

    loop {
        tokio::select! {
            biased;
            _ = tokio::time::sleep_until(expiry_deadline) => {
                // Dropping the listener and Tokio runtime also aborts every
                // in-flight relay. The sidecar therefore cannot outlive the
                // durable authorization deadline even if its parent crashes.
                return Ok(());
            }
            accepted = listener.accept() => {
                let (client, peer) = accepted.map_err(|_| "gateway listener failed")?;
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
                signal.map_err(|_| "gateway signal handler failed")?;
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
    if !take_rate_slot(&policy, &rate_window).await {
        return Err(io::Error::new(
            io::ErrorKind::WouldBlock,
            "connection rate denied",
        ));
    }
    handle_client(client, &policy).await
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

async fn handle_client(mut client: TcpStream, policy: &ValidatedPolicy) -> io::Result<()> {
    let remaining = policy_remaining(policy)
        .ok_or_else(|| io::Error::new(io::ErrorKind::PermissionDenied, "expired policy"))?;
    timeout(remaining, handle_client_before_expiry(&mut client, policy))
        .await
        .map_err(|_| io::Error::new(io::ErrorKind::PermissionDenied, "policy expired"))?
}

async fn handle_client_before_expiry(
    client: &mut TcpStream,
    policy: &ValidatedPolicy,
) -> io::Result<()> {
    timeout(HANDSHAKE_TIMEOUT, negotiate(client))
        .await
        .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "greeting timeout"))??;
    let (target, port) = timeout(HANDSHAKE_TIMEOUT, read_request(client))
        .await
        .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "request timeout"))??;
    let destination = resolve_request(policy, target, port)
        .map_err(|_| io::Error::new(io::ErrorKind::PermissionDenied, "destination denied"))?;
    let mut upstream = match timeout(policy.connect_timeout, TcpStream::connect(destination)).await
    {
        Ok(Ok(stream)) => stream,
        Ok(Err(error)) => {
            send_reply(client, 5, None).await?;
            return Err(error);
        }
        Err(_) => {
            send_reply(client, 6, None).await?;
            return Err(io::Error::new(io::ErrorKind::TimedOut, "connect timeout"));
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

fn load_raw_policy(path: &Path) -> Result<EgressGatewayPolicy, &'static str> {
    let metadata = fs::symlink_metadata(path).map_err(|_| "policy could not be inspected")?;
    if metadata.file_type().is_symlink() || !metadata.is_file() || metadata.len() > MAX_POLICY_BYTES
    {
        return Err("policy is not a bounded regular file");
    }
    let bytes = fs::read(path).map_err(|_| "policy could not be read")?;
    serde_json::from_slice(&bytes).map_err(|_| "policy is malformed")
}

fn load_policy(path: &Path) -> Result<ValidatedPolicy, &'static str> {
    validate_policy(load_raw_policy(path)?, Utc::now())
}

fn policy_path_from_args<I, S>(args: I) -> Result<PathBuf, &'static str>
where
    I: IntoIterator<Item = S>,
    S: Into<OsString>,
{
    let arguments = args.into_iter().map(Into::into).collect::<Vec<_>>();
    let path = match arguments.as_slice() {
        [] => PathBuf::from(POLICY_PATH),
        [flag, path] if flag == OsStr::new("--policy") => PathBuf::from(path),
        _ => return Err("only --policy <absolute-path> is accepted"),
    };
    if !path.is_absolute() || path.as_os_str().len() > 4096 {
        return Err("policy path must be a bounded absolute path");
    }
    Ok(path)
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
) -> Result<SocketAddr, &'static str> {
    match target {
        RequestedTarget::Address(address) => policy
            .by_address
            .contains(&(address, port))
            .then_some(SocketAddr::new(address, port))
            .ok_or("address is outside policy"),
        RequestedTarget::Hostname(hostname) => policy
            .by_host
            .get(&hostname)
            .and_then(|ports| ports.get(&port))
            .and_then(|addresses| addresses.first().copied())
            .map(|address| SocketAddr::new(address, port))
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
        let policy = validate_policy(raw_policy(), Utc::now()).expect("policy");
        assert_eq!(
            resolve_request(
                &policy,
                RequestedTarget::Hostname("app.example.test".into()),
                443
            )
            .expect("destination"),
            "203.0.113.9:443".parse().expect("socket")
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

    #[tokio::test]
    async fn an_already_accepted_socket_is_denied_after_policy_expiry() {
        let mut policy = validate_policy(raw_policy(), Utc::now()).expect("policy");
        policy.expires_at = Utc::now() - chrono::Duration::milliseconds(1);
        assert!(policy_remaining(&policy).is_none());

        let listener = TcpListener::bind("127.0.0.1:0").await.expect("listener");
        let address = listener.local_addr().expect("address");
        let client = TcpStream::connect(address).await.expect("client");
        let (server, _) = listener.accept().await.expect("accepted");
        let error = handle_client(server, &policy)
            .await
            .expect_err("expired socket denied before reading a greeting");
        assert_eq!(error.kind(), io::ErrorKind::PermissionDenied);
        drop(client);
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
    fn policy_path_parser_rejects_relative_and_extra_arguments() {
        assert_eq!(
            policy_path_from_args(Vec::<OsString>::new()).expect("default"),
            PathBuf::from(POLICY_PATH)
        );
        assert!(policy_path_from_args(["--policy", "relative.json"]).is_err());
        assert!(policy_path_from_args(["--other", "/tmp/policy.json"]).is_err());
        assert!(policy_path_from_args(["--policy", "/tmp/policy.json", "extra"]).is_err());
    }
}
