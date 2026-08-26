use std::env;
use std::ffi::{OsStr, OsString};
use std::io::{self, Read, Write};
use std::net::{IpAddr, Ipv6Addr, Shutdown, SocketAddr, TcpStream};
use std::time::Duration;

const GATEWAY_PORT: u16 = 1080;
const PROBE_TIMEOUT: Duration = Duration::from_secs(2);
const SOCKS_GREETING: [u8; 3] = [5, 1, 0];
const SOCKS_ACCEPTED: [u8; 2] = [5, 0];
const SUCCESS_JSON: &str = r#"{"schema_version":"1.0.0","reachability_probe":"socks5_no_connect_greeting","gateway_reachable":true,"upstream_connect_attempted":false}"#;

fn main() {
    let gateway = match gateway_from_args(env::args_os().skip(1)) {
        Ok(gateway) => gateway,
        Err(_) => {
            eprintln!("egress probe arguments were rejected");
            std::process::exit(2);
        }
    };
    if perform_probe(gateway).is_err() {
        eprintln!("egress probe failed safely");
        std::process::exit(1);
    }
    println!("{SUCCESS_JSON}");
}

fn gateway_from_args<I, S>(args: I) -> Result<SocketAddr, &'static str>
where
    I: IntoIterator<Item = S>,
    S: Into<OsString>,
{
    let arguments = args.into_iter().map(Into::into).collect::<Vec<_>>();
    let [flag, address] = arguments.as_slice() else {
        return Err("exactly one gateway address is required");
    };
    if flag != OsStr::new("--gateway") || address.len() > 128 {
        return Err("gateway argument is invalid");
    }
    let address = address
        .to_str()
        .ok_or("gateway address must be UTF-8")?
        .parse::<SocketAddr>()
        .map_err(|_| "gateway must be a literal socket address")?;
    if address.port() != GATEWAY_PORT || !is_private_gateway(address.ip()) {
        return Err("gateway must be a private bridge address on the fixed port");
    }
    Ok(address)
}

fn is_private_gateway(address: IpAddr) -> bool {
    match address {
        IpAddr::V4(address) => address.is_private() && !address.is_loopback(),
        IpAddr::V6(address) => is_unique_local_v6(address) && !address.is_loopback(),
    }
}

fn is_unique_local_v6(address: Ipv6Addr) -> bool {
    address.segments()[0] & 0xfe00 == 0xfc00
}

fn perform_probe(gateway: SocketAddr) -> io::Result<()> {
    let mut stream = TcpStream::connect_timeout(&gateway, PROBE_TIMEOUT)?;
    stream.set_read_timeout(Some(PROBE_TIMEOUT))?;
    stream.set_write_timeout(Some(PROBE_TIMEOUT))?;
    stream.write_all(&SOCKS_GREETING)?;
    let mut response = [0_u8; 2];
    stream.read_exact(&mut response)?;
    let _ = stream.shutdown(Shutdown::Both);
    validate_response(response)
}

fn validate_response(response: [u8; 2]) -> io::Result<()> {
    if response != SOCKS_ACCEPTED {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "gateway rejected the fixed no-authentication greeting",
        ));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parser_accepts_only_a_private_literal_on_the_fixed_port() {
        assert_eq!(
            gateway_from_args(["--gateway", "172.29.0.2:1080"]).expect("private gateway"),
            "172.29.0.2:1080".parse().expect("socket address")
        );
        assert_eq!(
            gateway_from_args(["--gateway", "[fd29::2]:1080"]).expect("private v6 gateway"),
            "[fd29::2]:1080".parse().expect("socket address")
        );
        for arguments in [
            vec!["--gateway"],
            vec!["--gateway", "gateway.example:1080"],
            vec!["--gateway", "203.0.113.4:1080"],
            vec!["--gateway", "127.0.0.1:1080"],
            vec!["--gateway", "172.29.0.2:443"],
            vec!["--other", "172.29.0.2:1080"],
            vec!["--gateway", "172.29.0.2:1080", "extra"],
        ] {
            assert!(gateway_from_args(arguments).is_err());
        }
    }

    #[test]
    fn response_contract_accepts_only_the_socks5_no_authentication_reply() {
        assert!(validate_response(SOCKS_ACCEPTED).is_ok());
        for response in [[4, 0], [5, 1], [5, 0xff]] {
            assert!(validate_response(response).is_err());
        }
        assert!(SUCCESS_JSON.len() < 256);
        assert!(SUCCESS_JSON.contains("\"upstream_connect_attempted\":false"));
    }
}
