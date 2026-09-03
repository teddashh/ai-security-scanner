//! Conservative, read-only target suggestions derived from local interface state.
//!
//! This module never probes the network and never creates, authorizes, or starts
//! a scan. It only reads the operating system's interface and routing metadata.

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;
use std::net::Ipv4Addr;

/// A suggested CIDR may contain at most this many IPv4 addresses.
pub const MAX_TARGET_ADDRESSES: u32 = 4096;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum LocalNetworkCandidateStatus {
    Ready,
    None,
    Ambiguous,
    Unavailable,
    Unsupported,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TargetCandidateKind {
    LocalIpv4Subnet,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TargetCandidateUseCase {
    InternalItEnvironment,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TargetInternetExposure {
    Internal,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct LocalPrivateSubnetCandidate {
    pub id: String,
    pub target: String,
    pub kind: TargetCandidateKind,
    pub use_case: TargetCandidateUseCase,
    pub internet_exposure: TargetInternetExposure,
    pub address_count: u32,
    /// The caller must still ask the user before adding this CIDR to a case.
    pub requires_confirmation: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct LocalNetworkCandidateInventory {
    pub status: LocalNetworkCandidateStatus,
    pub candidates: Vec<LocalPrivateSubnetCandidate>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct InterfaceObservation {
    address: Ipv4Addr,
    prefix_len: u8,
    is_up: bool,
    is_running: bool,
    is_loopback: bool,
    is_point_to_point: bool,
    is_virtual_or_tunnel: bool,
    is_default_route: bool,
    has_gateway: bool,
}

/// Returns at most one candidate. Multiple distinct safe subnets are reported
/// as ambiguous without returning an automatic choice.
pub fn detect_local_private_subnets() -> LocalNetworkCandidateInventory {
    match platform_observations() {
        Ok(observations) => classify_observations(observations),
        Err(status) => empty_inventory(status),
    }
}

fn empty_inventory(status: LocalNetworkCandidateStatus) -> LocalNetworkCandidateInventory {
    LocalNetworkCandidateInventory {
        status,
        candidates: Vec::new(),
    }
}

fn classify_observations(
    observations: impl IntoIterator<Item = InterfaceObservation>,
) -> LocalNetworkCandidateInventory {
    let mut candidates = BTreeMap::<String, LocalPrivateSubnetCandidate>::new();

    for observation in observations {
        let Some((network, address_count)) = safe_network(&observation) else {
            continue;
        };
        let target = format!("{network}/{}", observation.prefix_len);
        candidates
            .entry(target.clone())
            .or_insert_with(|| LocalPrivateSubnetCandidate {
                id: candidate_id(&target),
                target,
                kind: TargetCandidateKind::LocalIpv4Subnet,
                use_case: TargetCandidateUseCase::InternalItEnvironment,
                internet_exposure: TargetInternetExposure::Internal,
                address_count,
                requires_confirmation: true,
            });
    }

    match candidates.len() {
        0 => empty_inventory(LocalNetworkCandidateStatus::None),
        1 => LocalNetworkCandidateInventory {
            status: LocalNetworkCandidateStatus::Ready,
            candidates: candidates.into_values().collect(),
        },
        _ => empty_inventory(LocalNetworkCandidateStatus::Ambiguous),
    }
}

fn safe_network(observation: &InterfaceObservation) -> Option<(Ipv4Addr, u32)> {
    if !observation.is_up
        || !observation.is_running
        || observation.is_loopback
        || observation.is_point_to_point
        || observation.is_virtual_or_tunnel
        || !observation.is_default_route
        || !observation.has_gateway
    {
        return None;
    }

    let address = observation.address;
    if !address.is_private()
        || address.is_loopback()
        || address.is_link_local()
        || address.is_multicast()
        || address.is_unspecified()
        || address.is_broadcast()
    {
        return None;
    }

    // /20 is exactly 4096 addresses. /31 and /32 are deliberately omitted:
    // they are commonly point-to-point or host routes rather than a LAN.
    if !(20..=30).contains(&observation.prefix_len) {
        return None;
    }

    let host_bits = 32 - u32::from(observation.prefix_len);
    let address_count = 1_u32.checked_shl(host_bits)?;
    if address_count > MAX_TARGET_ADDRESSES {
        return None;
    }

    let mask = u32::MAX << host_bits;
    let address_bits = u32::from(address);
    let network_bits = address_bits & mask;
    let broadcast_bits = network_bits | !mask;
    if address_bits == network_bits || address_bits == broadcast_bits {
        return None;
    }

    Some((Ipv4Addr::from(network_bits), address_count))
}

fn candidate_id(target: &str) -> String {
    let mut digest = Sha256::new();
    digest.update(b"ai-security-scanner/local-private-ipv4/v1\0");
    digest.update(target.as_bytes());
    format!("local-ipv4-{}", hex::encode(digest.finalize()))
}

#[cfg(any(target_os = "linux", target_os = "macos", test))]
fn prefix_from_mask(mask: Ipv4Addr) -> Option<u8> {
    let bits = u32::from(mask);
    let prefix = bits.leading_ones() as u8;
    let expected = if prefix == 0 {
        0
    } else {
        u32::MAX << (32 - u32::from(prefix))
    };
    (bits == expected).then_some(prefix)
}

#[cfg(any(target_os = "linux", target_os = "macos"))]
#[cfg(target_os = "macos")]
fn ipv4_from_network_order(value: u32) -> Ipv4Addr {
    Ipv4Addr::from(u32::from_be(value))
}

#[cfg(target_os = "linux")]
fn linux_interface_name_is_safe(name: &str) -> bool {
    !name.is_empty()
        && name.len() < libc::IFNAMSIZ
        && name
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || b"_.:-".contains(&byte))
}

#[cfg(target_os = "linux")]
fn linux_default_route_interfaces(contents: &str) -> std::collections::BTreeSet<String> {
    let mut routes = Vec::<(u32, String)>::new();
    for line in contents.lines().skip(1) {
        let fields = line.split_ascii_whitespace().collect::<Vec<_>>();
        if fields.len() < 8 || !linux_interface_name_is_safe(fields[0]) {
            continue;
        }
        let parsed = (
            u32::from_str_radix(fields[1], 16),
            u32::from_str_radix(fields[2], 16),
            u32::from_str_radix(fields[3], 16),
            fields[6].parse::<u32>(),
            u32::from_str_radix(fields[7], 16),
        );
        let (Ok(destination), Ok(gateway), Ok(flags), Ok(metric), Ok(mask)) = parsed else {
            continue;
        };
        let required = (libc::RTF_UP | libc::RTF_GATEWAY) as u32;
        if destination == 0 && mask == 0 && gateway != 0 && flags & required == required {
            routes.push((metric, fields[0].to_owned()));
        }
    }

    let Some(best_metric) = routes.iter().map(|(metric, _)| *metric).min() else {
        return Default::default();
    };
    routes
        .into_iter()
        .filter_map(|(metric, name)| (metric == best_metric).then_some(name))
        .collect()
}

#[cfg(target_os = "linux")]
fn linux_interface_is_physical(name: &str) -> bool {
    use std::path::Path;

    if !linux_interface_name_is_safe(name) {
        return false;
    }
    let interface_path = Path::new("/sys/class/net").join(name);
    let Ok(interface_type) = std::fs::read_to_string(interface_path.join("type")) else {
        return false;
    };
    // ARPHRD_ETHER covers physical Ethernet and Wi-Fi devices.
    if interface_type.trim() != "1" || !interface_path.join("device").exists() {
        return false;
    }
    let Ok(canonical_path) = std::fs::canonicalize(&interface_path) else {
        return false;
    };
    !canonical_path
        .components()
        .any(|component| component.as_os_str() == "virtual")
}

#[cfg(target_os = "linux")]
fn platform_observations() -> Result<Vec<InterfaceObservation>, LocalNetworkCandidateStatus> {
    use nix::ifaddrs::getifaddrs;
    use nix::net::if_::InterfaceFlags;
    use std::fs;

    let route_table = fs::read_to_string("/proc/net/route")
        .map_err(|_| LocalNetworkCandidateStatus::Unavailable)?;
    let default_interfaces = linux_default_route_interfaces(&route_table);
    if default_interfaces.is_empty() {
        return Ok(Vec::new());
    }

    let mut observations = Vec::new();
    let interfaces = getifaddrs().map_err(|_| LocalNetworkCandidateStatus::Unavailable)?;
    for entry in interfaces.take(4096) {
        let name = entry.interface_name;
        if !default_interfaces.contains(&name) || !linux_interface_is_physical(&name) {
            continue;
        }
        let Some(address) = entry
            .address
            .as_ref()
            .and_then(|address| address.as_sockaddr_in())
            .map(|address| address.ip())
        else {
            continue;
        };
        let Some(netmask) = entry
            .netmask
            .as_ref()
            .and_then(|netmask| netmask.as_sockaddr_in())
            .map(|netmask| netmask.ip())
        else {
            continue;
        };
        let Some(prefix_len) = prefix_from_mask(netmask) else {
            continue;
        };
        let flags = entry.flags;
        observations.push(InterfaceObservation {
            address,
            prefix_len,
            is_up: flags.contains(InterfaceFlags::IFF_UP),
            is_running: flags.contains(InterfaceFlags::IFF_RUNNING),
            is_loopback: flags.contains(InterfaceFlags::IFF_LOOPBACK),
            is_point_to_point: flags.contains(InterfaceFlags::IFF_POINTOPOINT),
            is_virtual_or_tunnel: false,
            is_default_route: true,
            has_gateway: true,
        });
    }

    Ok(observations)
}

#[cfg(target_os = "macos")]
fn platform_observations() -> Result<Vec<InterfaceObservation>, LocalNetworkCandidateStatus> {
    use std::collections::{BTreeMap, BTreeSet};
    use std::ffi::CStr;
    use std::mem::size_of;
    use std::ptr;

    const IFT_ETHER: u8 = 6;
    const MAX_ROUTE_TABLE_BYTES: usize = 4 * 1024 * 1024;

    struct IfAddrs(*mut libc::ifaddrs);
    impl Drop for IfAddrs {
        fn drop(&mut self) {
            if !self.0.is_null() {
                // SAFETY: getifaddrs allocated this list and ownership remains here.
                unsafe { libc::freeifaddrs(self.0) };
            }
        }
    }

    fn is_physical_interface_name(name: &CStr) -> bool {
        let bytes = name.to_bytes();
        bytes
            .strip_prefix(b"en")
            .is_some_and(|suffix| !suffix.is_empty() && suffix.iter().all(u8::is_ascii_digit))
    }

    fn default_route_indices() -> Result<BTreeSet<u32>, LocalNetworkCandidateStatus> {
        let mut mib = [
            libc::CTL_NET,
            libc::PF_ROUTE,
            0,
            libc::AF_INET,
            libc::NET_RT_DUMP,
            0,
        ];
        let mut required = 0usize;
        // SAFETY: the MIB and output-size pointers are valid; this query has no output buffer.
        if unsafe {
            libc::sysctl(
                mib.as_mut_ptr(),
                mib.len() as u32,
                ptr::null_mut(),
                &mut required,
                ptr::null_mut(),
                0,
            )
        } != 0
            || required == 0
            || required > MAX_ROUTE_TABLE_BYTES
        {
            return Err(LocalNetworkCandidateStatus::Unavailable);
        }

        let mut bytes = vec![0u8; required];
        // SAFETY: bytes has the size reported by the immediately preceding sysctl query.
        if unsafe {
            libc::sysctl(
                mib.as_mut_ptr(),
                mib.len() as u32,
                bytes.as_mut_ptr().cast(),
                &mut required,
                ptr::null_mut(),
                0,
            )
        } != 0
            || required > bytes.len()
        {
            return Err(LocalNetworkCandidateStatus::Unavailable);
        }
        bytes.truncate(required);

        let mut indices = BTreeSet::new();
        let mut offset = 0usize;
        while offset + size_of::<libc::rt_msghdr>() <= bytes.len() {
            // SAFETY: bounds were checked; route messages may be unaligned.
            let header = unsafe {
                ptr::read_unaligned(bytes.as_ptr().add(offset).cast::<libc::rt_msghdr>())
            };
            let message_len = usize::from(header.rtm_msglen);
            if message_len < size_of::<libc::rt_msghdr>()
                || offset.saturating_add(message_len) > bytes.len()
            {
                break;
            }
            let required_flags = libc::RTF_UP | libc::RTF_GATEWAY;
            if i32::from(header.rtm_version) == libc::RTM_VERSION
                && header.rtm_index != 0
                && header.rtm_flags & required_flags == required_flags
                && header.rtm_addrs & libc::RTA_DST != 0
            {
                let sockaddr_offset = offset + size_of::<libc::rt_msghdr>();
                if sockaddr_offset + 2 <= offset + message_len {
                    let sockaddr_len = usize::from(bytes[sockaddr_offset]);
                    let family = i32::from(bytes[sockaddr_offset + 1]);
                    if family == libc::AF_INET
                        && sockaddr_len >= size_of::<libc::sockaddr_in>()
                        && sockaddr_offset + size_of::<libc::sockaddr_in>() <= offset + message_len
                    {
                        // SAFETY: the sockaddr_in range is inside this route message.
                        let destination = unsafe {
                            ptr::read_unaligned(
                                bytes
                                    .as_ptr()
                                    .add(sockaddr_offset)
                                    .cast::<libc::sockaddr_in>(),
                            )
                        };
                        if destination.sin_addr.s_addr == 0 {
                            indices.insert(u32::from(header.rtm_index));
                        }
                    }
                }
            }
            offset += message_len;
        }
        Ok(indices)
    }

    let default_indices = default_route_indices()?;
    if default_indices.is_empty() {
        return Ok(Vec::new());
    }

    let mut raw = ptr::null_mut();
    // SAFETY: raw is a valid out-pointer and is released by IfAddrs below.
    if unsafe { libc::getifaddrs(&mut raw) } != 0 || raw.is_null() {
        return Err(LocalNetworkCandidateStatus::Unavailable);
    }
    let guard = IfAddrs(raw);

    let mut link_types = BTreeMap::<u32, u8>::new();
    let mut cursor = guard.0;
    let mut visited = 0usize;
    while !cursor.is_null() && visited < 4096 {
        visited += 1;
        // SAFETY: cursor belongs to the live getifaddrs list.
        let entry = unsafe { &*cursor };
        cursor = entry.ifa_next;
        if entry.ifa_addr.is_null() {
            continue;
        }
        // SAFETY: the sockaddr pointer is non-null and belongs to this entry.
        if unsafe { (*entry.ifa_addr).sa_family as i32 } != libc::AF_LINK {
            continue;
        }
        // SAFETY: AF_LINK guarantees sockaddr_dl layout.
        let link = unsafe { &*(entry.ifa_addr.cast::<libc::sockaddr_dl>()) };
        link_types.insert(u32::from(link.sdl_index), link.sdl_type);
    }

    let mut observations = Vec::new();
    let mut cursor = guard.0;
    let mut visited = 0usize;
    while !cursor.is_null() && visited < 4096 {
        visited += 1;
        // SAFETY: cursor belongs to the live getifaddrs list.
        let entry = unsafe { &*cursor };
        cursor = entry.ifa_next;
        if entry.ifa_name.is_null() || entry.ifa_addr.is_null() || entry.ifa_netmask.is_null() {
            continue;
        }
        // SAFETY: getifaddrs provides a NUL-terminated interface name.
        let name = unsafe { CStr::from_ptr(entry.ifa_name) };
        if !is_physical_interface_name(name) {
            continue;
        }
        // SAFETY: name is the live, NUL-terminated name returned by getifaddrs.
        let index = unsafe { libc::if_nametoindex(name.as_ptr()) };
        if !default_indices.contains(&index) || link_types.get(&index) != Some(&IFT_ETHER) {
            continue;
        }
        // SAFETY: non-null sockaddr pointers were checked above.
        if unsafe { (*entry.ifa_addr).sa_family as i32 } != libc::AF_INET
            || unsafe { (*entry.ifa_netmask).sa_family as i32 } != libc::AF_INET
        {
            continue;
        }
        // SAFETY: AF_INET guarantees sockaddr_in layout for both pointers.
        let address = unsafe { &*(entry.ifa_addr.cast::<libc::sockaddr_in>()) };
        let netmask = unsafe { &*(entry.ifa_netmask.cast::<libc::sockaddr_in>()) };
        let Some(prefix_len) = prefix_from_mask(ipv4_from_network_order(netmask.sin_addr.s_addr))
        else {
            continue;
        };
        let flags = entry.ifa_flags as i32;
        observations.push(InterfaceObservation {
            address: ipv4_from_network_order(address.sin_addr.s_addr),
            prefix_len,
            is_up: flags & libc::IFF_UP != 0,
            is_running: flags & libc::IFF_RUNNING != 0,
            is_loopback: flags & libc::IFF_LOOPBACK != 0,
            is_point_to_point: flags & libc::IFF_POINTOPOINT != 0,
            is_virtual_or_tunnel: false,
            is_default_route: true,
            has_gateway: true,
        });
    }

    Ok(observations)
}

#[cfg(target_os = "windows")]
fn platform_observations() -> Result<Vec<InterfaceObservation>, LocalNetworkCandidateStatus> {
    use std::ffi::c_void;
    use std::mem::{align_of, size_of};
    use std::ptr;
    use windows_sys::Win32::Foundation::{ERROR_BUFFER_OVERFLOW, NO_ERROR};
    use windows_sys::Win32::NetworkManagement::IpHelper::{
        GAA_FLAG_INCLUDE_GATEWAYS, GAA_FLAG_INCLUDE_PREFIX, GAA_FLAG_SKIP_ANYCAST,
        GAA_FLAG_SKIP_DNS_SERVER, GAA_FLAG_SKIP_MULTICAST, GetAdaptersAddresses, GetIfEntry2,
        IF_TYPE_ETHERNET_CSMACD, IF_TYPE_IEEE80211, IP_ADAPTER_ADDRESSES_LH,
        IP_ADAPTER_GATEWAY_ADDRESS_LH, IP_ADAPTER_UNICAST_ADDRESS_LH, MIB_IF_ROW2,
    };
    use windows_sys::Win32::NetworkManagement::Ndis::{
        IfOperStatusUp, NET_IF_CONNECTION_DEDICATED, TUNNEL_TYPE_NONE,
    };
    use windows_sys::Win32::Networking::WinSock::{AF_INET, SOCKADDR_IN, SOCKET_ADDRESS};

    const MAX_ADAPTER_BUFFER_BYTES: usize = 1024 * 1024;
    const HARDWARE_INTERFACE_BIT: u8 = 1;

    fn pointer_in_buffer<T>(pointer: *const T, start: usize, length: usize) -> bool {
        let address = pointer as usize;
        address >= start
            && address
                .checked_add(size_of::<T>())
                .is_some_and(|end| end <= start.saturating_add(length))
    }

    fn ipv4_socket_address(
        address: &SOCKET_ADDRESS,
        buffer_start: usize,
        buffer_len: usize,
    ) -> Option<Ipv4Addr> {
        if address.lpSockaddr.is_null()
            || address.iSockaddrLength < size_of::<SOCKADDR_IN>() as i32
            || !pointer_in_buffer::<SOCKADDR_IN>(
                address.lpSockaddr.cast::<SOCKADDR_IN>(),
                buffer_start,
                buffer_len,
            )
        {
            return None;
        }
        // SAFETY: bounds and minimum SOCKADDR_IN length were checked above.
        let sockaddr = unsafe { &*address.lpSockaddr.cast::<SOCKADDR_IN>() };
        if sockaddr.sin_family != AF_INET {
            return None;
        }
        // IN_ADDR is stored in network byte order. Reading its four bytes avoids
        // target-endian assumptions about the generated union representation.
        let octets = unsafe {
            std::slice::from_raw_parts(
                ptr::addr_of!(sockaddr.sin_addr).cast::<u8>(),
                size_of::<windows_sys::Win32::Networking::WinSock::IN_ADDR>(),
            )
        };
        Some(Ipv4Addr::new(octets[0], octets[1], octets[2], octets[3]))
    }

    let flags = GAA_FLAG_INCLUDE_PREFIX
        | GAA_FLAG_INCLUDE_GATEWAYS
        | GAA_FLAG_SKIP_ANYCAST
        | GAA_FLAG_SKIP_MULTICAST
        | GAA_FLAG_SKIP_DNS_SERVER;
    let mut required = 0u32;
    // SAFETY: this is the documented size query and performs no network operation.
    let first_status = unsafe {
        GetAdaptersAddresses(
            u32::from(AF_INET),
            flags,
            ptr::null::<c_void>(),
            ptr::null_mut(),
            &mut required,
        )
    };
    if first_status != ERROR_BUFFER_OVERFLOW
        || required == 0
        || required as usize > MAX_ADAPTER_BUFFER_BYTES
    {
        return Err(LocalNetworkCandidateStatus::Unavailable);
    }

    let words = (required as usize).div_ceil(align_of::<usize>());
    let mut buffer = vec![0usize; words];
    let mut available = (buffer.len() * size_of::<usize>()) as u32;
    // SAFETY: the buffer is aligned and at least as large as available reports.
    let status = unsafe {
        GetAdaptersAddresses(
            u32::from(AF_INET),
            flags,
            ptr::null::<c_void>(),
            buffer.as_mut_ptr().cast::<IP_ADAPTER_ADDRESSES_LH>(),
            &mut available,
        )
    };
    if status != NO_ERROR || available as usize > buffer.len() * size_of::<usize>() {
        return Err(LocalNetworkCandidateStatus::Unavailable);
    }

    let buffer_start = buffer.as_ptr() as usize;
    let buffer_len = buffer.len() * size_of::<usize>();
    let mut observations = Vec::new();
    let mut adapter = buffer.as_ptr().cast::<IP_ADAPTER_ADDRESSES_LH>();
    let mut adapter_count = 0usize;
    while !adapter.is_null()
        && pointer_in_buffer(adapter, buffer_start, buffer_len)
        && adapter_count < 512
    {
        adapter_count += 1;
        // SAFETY: the complete adapter structure is inside the owned buffer.
        let current = unsafe { &*adapter };
        adapter = current.Next;

        let physical_type = matches!(current.IfType, IF_TYPE_ETHERNET_CSMACD | IF_TYPE_IEEE80211);
        if current.OperStatus != IfOperStatusUp
            || !physical_type
            || current.TunnelType != TUNNEL_TYPE_NONE
            || current.ConnectionType != NET_IF_CONNECTION_DEDICATED
            || current.PhysicalAddressLength == 0
            || current.FirstGatewayAddress.is_null()
            || !pointer_in_buffer::<IP_ADAPTER_GATEWAY_ADDRESS_LH>(
                current.FirstGatewayAddress,
                buffer_start,
                buffer_len,
            )
        {
            continue;
        }
        // SAFETY: the complete gateway structure is inside the owned buffer.
        let gateway = unsafe { &*current.FirstGatewayAddress };
        let Some(gateway_address) = ipv4_socket_address(&gateway.Address, buffer_start, buffer_len)
        else {
            continue;
        };
        if gateway_address.is_unspecified() || gateway_address.is_multicast() {
            continue;
        }

        let mut interface_row = MIB_IF_ROW2 {
            InterfaceLuid: current.Luid,
            ..Default::default()
        };
        // SAFETY: interface_row is a fully initialized writable structure.
        if unsafe { GetIfEntry2(&mut interface_row) } != NO_ERROR
            || interface_row.OperStatus != IfOperStatusUp
            || !matches!(
                interface_row.Type,
                IF_TYPE_ETHERNET_CSMACD | IF_TYPE_IEEE80211
            )
            || interface_row.TunnelType != TUNNEL_TYPE_NONE
            || interface_row.InterfaceAndOperStatusFlags._bitfield & HARDWARE_INTERFACE_BIT == 0
        {
            continue;
        }

        let mut unicast = current.FirstUnicastAddress;
        let mut unicast_count = 0usize;
        while !unicast.is_null()
            && pointer_in_buffer::<IP_ADAPTER_UNICAST_ADDRESS_LH>(unicast, buffer_start, buffer_len)
            && unicast_count < 512
        {
            unicast_count += 1;
            // SAFETY: the complete unicast structure is inside the owned buffer.
            let address_entry = unsafe { &*unicast };
            unicast = address_entry.Next;
            let Some(address) =
                ipv4_socket_address(&address_entry.Address, buffer_start, buffer_len)
            else {
                continue;
            };
            observations.push(InterfaceObservation {
                address,
                prefix_len: address_entry.OnLinkPrefixLength,
                is_up: true,
                is_running: true,
                is_loopback: false,
                is_point_to_point: false,
                is_virtual_or_tunnel: false,
                is_default_route: true,
                has_gateway: true,
            });
        }
    }

    Ok(observations)
}

#[cfg(not(any(target_os = "linux", target_os = "macos", target_os = "windows")))]
fn platform_observations() -> Result<Vec<InterfaceObservation>, LocalNetworkCandidateStatus> {
    Err(LocalNetworkCandidateStatus::Unsupported)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn observation(address: [u8; 4], prefix_len: u8) -> InterfaceObservation {
        InterfaceObservation {
            address: Ipv4Addr::from(address),
            prefix_len,
            is_up: true,
            is_running: true,
            is_loopback: false,
            is_point_to_point: false,
            is_virtual_or_tunnel: false,
            is_default_route: true,
            has_gateway: true,
        }
    }

    #[test]
    fn canonicalizes_a_safe_private_lan() {
        let result = classify_observations([observation([192, 168, 42, 57], 24)]);

        assert_eq!(result.status, LocalNetworkCandidateStatus::Ready);
        assert_eq!(result.candidates.len(), 1);
        let candidate = &result.candidates[0];
        assert_eq!(candidate.target, "192.168.42.0/24");
        assert_eq!(candidate.address_count, 256);
        assert!(candidate.requires_confirmation);
        assert_eq!(candidate.id, candidate_id("192.168.42.0/24"));
    }

    #[test]
    fn excludes_non_private_and_special_addresses() {
        for address in [
            [127, 0, 0, 1],
            [169, 254, 3, 4],
            [8, 8, 8, 8],
            [100, 64, 1, 2],
            [224, 0, 0, 1],
            [0, 0, 0, 0],
            [255, 255, 255, 255],
        ] {
            assert!(
                safe_network(&observation(address, 24)).is_none(),
                "{address:?}"
            );
        }
    }

    #[test]
    fn requires_a_live_physical_default_route_with_gateway() {
        let mut values = Vec::new();
        let base = observation([10, 20, 30, 40], 24);
        for mutate in [
            |value: &mut InterfaceObservation| value.is_up = false,
            |value: &mut InterfaceObservation| value.is_running = false,
            |value: &mut InterfaceObservation| value.is_loopback = true,
            |value: &mut InterfaceObservation| value.is_point_to_point = true,
            |value: &mut InterfaceObservation| value.is_virtual_or_tunnel = true,
            |value: &mut InterfaceObservation| value.is_default_route = false,
            |value: &mut InterfaceObservation| value.has_gateway = false,
        ] {
            let mut value = base.clone();
            mutate(&mut value);
            values.push(value);
        }

        assert!(values.iter().all(|value| safe_network(value).is_none()));
    }

    #[test]
    fn enforces_address_limit_and_rejects_host_routes() {
        assert!(safe_network(&observation([10, 1, 2, 3], 19)).is_none());
        assert_eq!(
            safe_network(&observation([10, 1, 2, 3], 20)),
            Some((Ipv4Addr::new(10, 1, 0, 0), MAX_TARGET_ADDRESSES))
        );
        assert!(safe_network(&observation([10, 1, 2, 3], 31)).is_none());
        assert!(safe_network(&observation([10, 1, 2, 3], 32)).is_none());
    }

    #[test]
    fn rejects_network_and_broadcast_interface_addresses() {
        assert!(safe_network(&observation([192, 168, 5, 0], 24)).is_none());
        assert!(safe_network(&observation([192, 168, 5, 255], 24)).is_none());
    }

    #[test]
    fn deduplicates_the_same_subnet() {
        let result = classify_observations([
            observation([172, 16, 8, 4], 24),
            observation([172, 16, 8, 5], 24),
        ]);

        assert_eq!(result.status, LocalNetworkCandidateStatus::Ready);
        assert_eq!(result.candidates.len(), 1);
        assert_eq!(result.candidates[0].target, "172.16.8.0/24");
    }

    #[test]
    fn multiple_safe_subnets_are_ambiguous_without_an_automatic_choice() {
        let result = classify_observations([
            observation([10, 0, 4, 12], 24),
            observation([192, 168, 7, 12], 24),
        ]);

        assert_eq!(result.status, LocalNetworkCandidateStatus::Ambiguous);
        assert!(result.candidates.is_empty());
    }

    #[test]
    fn response_contract_uses_frontend_friendly_fields_and_typed_values() {
        let result = classify_observations([observation([192, 168, 9, 12], 24)]);
        let json = serde_json::to_value(result).expect("serialize inventory");

        assert_eq!(json["status"], "ready");
        assert_eq!(json["candidates"][0]["kind"], "local_ipv4_subnet");
        assert_eq!(json["candidates"][0]["useCase"], "internal_it_environment");
        assert_eq!(json["candidates"][0]["internetExposure"], "internal");
        assert_eq!(json["candidates"][0]["addressCount"], 256);
        assert_eq!(json["candidates"][0]["requiresConfirmation"], true);
    }

    #[test]
    fn rejects_non_contiguous_netmasks() {
        assert_eq!(prefix_from_mask(Ipv4Addr::new(255, 255, 255, 0)), Some(24));
        assert_eq!(prefix_from_mask(Ipv4Addr::new(255, 0, 255, 0)), None);
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn linux_route_parser_uses_only_the_lowest_metric_safe_default_route() {
        use std::collections::BTreeSet;

        let table = "Iface Destination Gateway Flags RefCnt Use Metric Mask MTU Window IRTT\n\
                     eth0 00000000 0101A8C0 0003 0 0 200 00000000 0 0 0\n\
                     wlan0 00000000 0101A8C0 0003 0 0 50 00000000 0 0 0\n\
                     tun0 00000000 0101A8C0 0003 0 0 90 00000000 0 0 0\n\
                     bad/name 00000000 0101A8C0 0003 0 0 1 00000000 0 0 0\n\
                     no-gateway 00000000 00000000 0003 0 0 1 00000000 0 0 0\n";

        let expected = BTreeSet::from(["wlan0".to_owned()]);
        assert_eq!(linux_default_route_interfaces(table), expected);
    }
}
