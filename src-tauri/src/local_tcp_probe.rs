//! Product-owned, payload-free TCP reachability probe for one service on the
//! desktop host.
//!
//! This primitive deliberately does not use the managed container runtime: in
//! a container, `127.0.0.1` would identify the container rather than the
//! desktop host. The production connector performs only `connect_timeout` and
//! immediately drops the connected stream. The injected connector seam returns
//! no stream, so orchestration code cannot send application payload through it.

use std::fmt;
use std::io;
use std::net::{Ipv4Addr, SocketAddr, SocketAddrV4, TcpStream};
use std::time::Duration;

/// The only address this primitive may contact.
pub const DESKTOP_HOST_LOOPBACK: Ipv4Addr = Ipv4Addr::LOCALHOST;

/// Fixed upper bound for the single TCP connection attempt.
pub const LOCAL_TCP_CONNECT_TIMEOUT: Duration = Duration::from_secs(3);

/// Stable, user-independent result of the bounded connection attempt.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LocalTcpProbeOutcome {
    Reachable,
    Closed,
    TimedOut,
}

impl LocalTcpProbeOutcome {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Reachable => "reachable",
            Self::Closed => "closed",
            Self::TimedOut => "timed_out",
        }
    }
}

/// Bounded product-owned failure categories. Raw operating-system error text
/// is intentionally not retained because it can vary by platform and locale.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LocalTcpProbeFailureCode {
    InvalidPort,
    ConnectFailed,
}

impl LocalTcpProbeFailureCode {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::InvalidPort => "invalid_local_tcp_port",
            Self::ConnectFailed => "desktop_host_tcp_connect_failed",
        }
    }
}

/// Failure value that exposes only a stable bounded code.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct LocalTcpProbeFailure {
    pub code: LocalTcpProbeFailureCode,
}

impl LocalTcpProbeFailure {
    const fn new(code: LocalTcpProbeFailureCode) -> Self {
        Self { code }
    }
}

impl fmt::Display for LocalTcpProbeFailure {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.code.as_str())
    }
}

impl std::error::Error for LocalTcpProbeFailure {}

/// Narrow injection boundary used to test the exact desktop-host connection
/// contract without opening a real socket. Returning `()` rather than a stream
/// is intentional: the probe has no API through which it could send a payload.
pub trait LocalTcpConnector: Send + Sync {
    fn connect(&self, endpoint: SocketAddr, timeout: Duration) -> io::Result<()>;
}

/// Production connector. A successful stream is dropped immediately without a
/// read, write, protocol handshake, or application payload.
#[derive(Debug, Default, Clone, Copy)]
pub struct DesktopHostTcpConnector;

impl LocalTcpConnector for DesktopHostTcpConnector {
    fn connect(&self, endpoint: SocketAddr, timeout: Duration) -> io::Result<()> {
        TcpStream::connect_timeout(&endpoint, timeout).map(drop)
    }
}

/// Probe one exact TCP port on this desktop process's IPv4 loopback interface.
pub fn probe_localhost_tcp_port(port: u16) -> Result<LocalTcpProbeOutcome, LocalTcpProbeFailure> {
    probe_localhost_tcp_port_with(&DesktopHostTcpConnector, port)
}

/// Testable implementation of [`probe_localhost_tcp_port`]. The endpoint and
/// timeout remain product constants; callers can inject behavior but cannot
/// widen the target or duration.
pub fn probe_localhost_tcp_port_with(
    connector: &dyn LocalTcpConnector,
    port: u16,
) -> Result<LocalTcpProbeOutcome, LocalTcpProbeFailure> {
    if port == 0 {
        return Err(LocalTcpProbeFailure::new(
            LocalTcpProbeFailureCode::InvalidPort,
        ));
    }

    let endpoint = SocketAddr::V4(SocketAddrV4::new(DESKTOP_HOST_LOOPBACK, port));
    match connector.connect(endpoint, LOCAL_TCP_CONNECT_TIMEOUT) {
        Ok(()) => Ok(LocalTcpProbeOutcome::Reachable),
        Err(error) => match error.kind() {
            io::ErrorKind::ConnectionRefused => Ok(LocalTcpProbeOutcome::Closed),
            io::ErrorKind::TimedOut | io::ErrorKind::WouldBlock => {
                Ok(LocalTcpProbeOutcome::TimedOut)
            }
            _ => Err(LocalTcpProbeFailure::new(
                LocalTcpProbeFailureCode::ConnectFailed,
            )),
        },
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Mutex;

    #[derive(Debug, Clone, Copy)]
    enum StubResult {
        Success,
        Error(io::ErrorKind, &'static str),
    }

    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    struct ConnectCall {
        endpoint: SocketAddr,
        timeout: Duration,
    }

    struct RecordingConnector {
        result: StubResult,
        calls: Mutex<Vec<ConnectCall>>,
    }

    impl RecordingConnector {
        fn returning(result: StubResult) -> Self {
            Self {
                result,
                calls: Mutex::new(Vec::new()),
            }
        }

        fn calls(&self) -> Vec<ConnectCall> {
            self.calls.lock().expect("recording lock").clone()
        }
    }

    impl LocalTcpConnector for RecordingConnector {
        fn connect(&self, endpoint: SocketAddr, timeout: Duration) -> io::Result<()> {
            self.calls
                .lock()
                .expect("recording lock")
                .push(ConnectCall { endpoint, timeout });
            match self.result {
                StubResult::Success => Ok(()),
                StubResult::Error(kind, message) => Err(io::Error::new(kind, message)),
            }
        }
    }

    #[test]
    fn successful_connect_is_reachable() {
        let connector = RecordingConnector::returning(StubResult::Success);

        assert_eq!(
            probe_localhost_tcp_port_with(&connector, 9001),
            Ok(LocalTcpProbeOutcome::Reachable)
        );
    }

    #[test]
    fn refused_connect_is_closed() {
        let connector = RecordingConnector::returning(StubResult::Error(
            io::ErrorKind::ConnectionRefused,
            "platform-specific refusal",
        ));

        assert_eq!(
            probe_localhost_tcp_port_with(&connector, 9001),
            Ok(LocalTcpProbeOutcome::Closed)
        );
    }

    #[test]
    fn timeout_and_would_block_are_timed_out() {
        for kind in [io::ErrorKind::TimedOut, io::ErrorKind::WouldBlock] {
            let connector =
                RecordingConnector::returning(StubResult::Error(kind, "platform-specific timeout"));

            assert_eq!(
                probe_localhost_tcp_port_with(&connector, 9001),
                Ok(LocalTcpProbeOutcome::TimedOut)
            );
        }
    }

    #[test]
    fn other_connect_error_becomes_only_the_stable_bounded_code() {
        const RAW_OS_TEXT: &str = "secret platform-specific path and socket detail";
        let connector = RecordingConnector::returning(StubResult::Error(
            io::ErrorKind::PermissionDenied,
            RAW_OS_TEXT,
        ));

        let failure = probe_localhost_tcp_port_with(&connector, 9001).unwrap_err();

        assert_eq!(failure.code, LocalTcpProbeFailureCode::ConnectFailed);
        assert_eq!(failure.to_string(), "desktop_host_tcp_connect_failed");
        assert!(!format!("{failure:?}").contains(RAW_OS_TEXT));
    }

    #[test]
    fn connector_receives_only_exact_loopback_port_and_fixed_timeout() {
        let connector = RecordingConnector::returning(StubResult::Success);

        probe_localhost_tcp_port_with(&connector, 42_001).unwrap();

        assert_eq!(
            connector.calls(),
            vec![ConnectCall {
                endpoint: SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::LOCALHOST, 42_001)),
                timeout: Duration::from_secs(3),
            }]
        );
    }

    #[test]
    fn zero_port_is_rejected_without_contacting_connector() {
        let connector = RecordingConnector::returning(StubResult::Success);

        let failure = probe_localhost_tcp_port_with(&connector, 0).unwrap_err();

        assert_eq!(failure.code, LocalTcpProbeFailureCode::InvalidPort);
        assert!(connector.calls().is_empty());
    }

    #[test]
    fn connector_contract_exposes_no_stream_or_payload_operation() {
        let connector = RecordingConnector::returning(StubResult::Success);

        probe_localhost_tcp_port_with(&connector, 9001).unwrap();

        // The connector receives one connect request and returns unit. The
        // primitive never receives a stream or payload-capable value.
        assert_eq!(connector.calls().len(), 1);
    }

    #[test]
    fn stable_result_strings_are_bounded() {
        assert_eq!(LocalTcpProbeOutcome::Reachable.as_str(), "reachable");
        assert_eq!(LocalTcpProbeOutcome::Closed.as_str(), "closed");
        assert_eq!(LocalTcpProbeOutcome::TimedOut.as_str(), "timed_out");
        for code in [
            LocalTcpProbeFailureCode::InvalidPort,
            LocalTcpProbeFailureCode::ConnectFailed,
        ] {
            assert!(code.as_str().len() <= 64);
            assert!(
                code.as_str()
                    .bytes()
                    .all(|byte| byte.is_ascii_lowercase() || byte == b'_')
            );
        }
    }
}
