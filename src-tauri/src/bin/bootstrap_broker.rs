use ai_security_scanner_lib::bootstrap::create_bootstrap_plan;
use ai_security_scanner_lib::bootstrap::ensure_no_secret_environment;
use ai_security_scanner_lib::bootstrap::executor::{
    BootstrapBrokerCommand, BootstrapInteraction, PkceAuthorizationCallback,
    PkceAuthorizationPrompt, execute_bootstrap, execute_bootstrap_cleanup,
};
use ai_security_scanner_lib::error::{AppError, AppResult};
use ai_security_scanner_lib::source_authorization::provider::{
    DeviceAuthorizationPrompt, ReqwestProviderHttp,
};
use ai_security_scanner_lib::source_authorization::write_verified_authorization_one_shot;
use chrono::{DateTime, Utc};
use std::io::{self, Read, Write};
use std::net::{IpAddr, SocketAddr, TcpListener};
use std::path::Path;
use std::time::Duration as StdDuration;
use url::Url;
use zeroize::Zeroizing;

const MAX_REQUEST_BYTES: u64 = 64 * 1024;
const MAX_CALLBACK_BYTES: u64 = 16 * 1024;

fn main() {
    harden_process();
    if let Err(error) = run() {
        let _ = writeln!(io::stderr().lock(), "{}", public_error(&error));
        std::process::exit(2);
    }
}

fn run() -> AppResult<()> {
    if std::env::args_os().len() != 1 {
        return Err(AppError::InvalidRequest(
            "bootstrap broker accepts no command-line arguments".into(),
        ));
    }
    ensure_no_secret_environment()?;
    let mut input = Zeroizing::new(Vec::new());
    io::stdin()
        .lock()
        .take(MAX_REQUEST_BYTES + 1)
        .read_to_end(&mut input)?;
    if input.len() as u64 > MAX_REQUEST_BYTES {
        return Err(AppError::InvalidRequest(
            "bootstrap request is too large".into(),
        ));
    }
    let command: BootstrapBrokerCommand = serde_json::from_slice(input.as_slice())
        .map_err(|_| AppError::InvalidRequest("bootstrap request is malformed".into()))?;
    drop(input);
    match command {
        BootstrapBrokerCommand::Plan { request } => {
            let plan = create_bootstrap_plan(request, Utc::now())?;
            serde_json::to_writer(io::stdout().lock(), &plan)
                .map_err(|_| AppError::Internal("could not encode broker plan".into()))?;
            io::stdout().lock().write_all(b"\n")?;
        }
        BootstrapBrokerCommand::Execute {
            execution,
            cleanup_ledger_path,
        } => {
            require_protected_stdout_pipe()?;
            let http = ReqwestProviderHttp::new()?;
            let interaction = StdioInteraction;
            let result = execute_bootstrap(
                &http,
                &interaction,
                execution,
                Path::new(&cleanup_ledger_path),
            )?;
            // The ledger has already been durably written by the executor.
            // stdout carries exactly one bounded, non-serde authorization frame.
            write_verified_authorization_one_shot(io::stdout().lock(), result.authorization)?;
            io::stdout().lock().flush()?;
        }
        BootstrapBrokerCommand::Cleanup {
            operator,
            case_id,
            operation_id,
            cleanup_ledger_path,
        } => {
            let http = ReqwestProviderHttp::new()?;
            let interaction = StdioInteraction;
            let ledger = execute_bootstrap_cleanup(
                &http,
                &interaction,
                operator,
                &case_id,
                &operation_id,
                Path::new(&cleanup_ledger_path),
            )?;
            serde_json::to_writer(io::stdout().lock(), &ledger)
                .map_err(|_| AppError::Internal("could not encode cleanup result".into()))?;
            io::stdout().lock().write_all(b"\n")?;
        }
    }
    Ok(())
}

struct StdioInteraction;

impl BootstrapInteraction for StdioInteraction {
    fn present_device_authorization(&self, prompt: &DeviceAuthorizationPrompt) -> AppResult<()> {
        let destination = prompt
            .verification_uri_complete
            .as_deref()
            .unwrap_or(&prompt.verification_uri);
        writeln!(
            io::stderr().lock(),
            "Open this provider URL in a trusted browser:\n{destination}\nEnter code: {}\nExpires: {}\n{}",
            prompt.user_code,
            prompt.expires_at.to_rfc3339(),
            prompt.safety_notice
        )?;
        Ok(())
    }

    fn complete_pkce_authorization(
        &self,
        prompt: &PkceAuthorizationPrompt,
    ) -> AppResult<PkceAuthorizationCallback> {
        let redirect = Url::parse(&prompt.redirect_uri)
            .map_err(|_| AppError::InvalidRequest("PKCE loopback URI is malformed".into()))?;
        let host = redirect
            .host_str()
            .ok_or_else(|| AppError::InvalidRequest("PKCE loopback host is missing".into()))?;
        let ip: IpAddr = host
            .trim_matches(['[', ']'])
            .parse()
            .map_err(|_| AppError::InvalidRequest("PKCE loopback host is not an IP".into()))?;
        if !ip.is_loopback() {
            return Err(AppError::NotAuthorized(
                "PKCE callback listener must bind only to loopback".into(),
            ));
        }
        let port = redirect
            .port()
            .ok_or_else(|| AppError::InvalidRequest("PKCE loopback port is missing".into()))?;
        let listener = TcpListener::bind(SocketAddr::new(ip, port)).map_err(|_| {
            AppError::NotAvailable("PKCE loopback callback listener could not bind".into())
        })?;
        listener
            .set_nonblocking(true)
            .map_err(|_| AppError::NotAvailable("PKCE callback listener could not start".into()))?;
        writeln!(
            io::stderr().lock(),
            "Open this provider URL in a trusted browser:\n{}\nWaiting only on {}\n{}",
            prompt.authorization_url,
            prompt.redirect_uri,
            prompt.safety_notice
        )?;
        let (mut stream, peer) = loop {
            if Utc::now() >= prompt.expires_at {
                return Err(AppError::NotAuthorized(
                    "PKCE callback authorization window expired".into(),
                ));
            }
            match listener.accept() {
                Ok(connection) => break connection,
                Err(error) if error.kind() == io::ErrorKind::WouldBlock => {
                    std::thread::sleep(StdDuration::from_millis(100));
                }
                Err(_) => {
                    return Err(AppError::NotAvailable(
                        "PKCE loopback callback was not received".into(),
                    ));
                }
            }
        };
        if !peer.ip().is_loopback() {
            return Err(AppError::NotAuthorized(
                "PKCE callback did not originate on loopback".into(),
            ));
        }
        stream
            .set_nonblocking(false)
            .map_err(|_| AppError::NotAvailable("PKCE callback stream could not start".into()))?;
        stream
            .set_read_timeout(Some(StdDuration::from_secs(30)))
            .map_err(|_| AppError::NotAvailable("PKCE callback timeout could not be set".into()))?;
        let mut raw = Zeroizing::new(Vec::new());
        let mut chunk = Zeroizing::new([0_u8; 1024]);
        loop {
            let read = stream.read(chunk.as_mut_slice())?;
            if read == 0 {
                break;
            }
            raw.extend_from_slice(&chunk[..read]);
            if raw.windows(4).any(|window| window == b"\r\n\r\n") {
                break;
            }
            if raw.len() as u64 > MAX_CALLBACK_BYTES {
                break;
            }
        }
        if raw.len() as u64 > MAX_CALLBACK_BYTES {
            return Err(AppError::InvalidRequest(
                "PKCE callback request is too large".into(),
            ));
        }
        let request = std::str::from_utf8(raw.as_slice())
            .map_err(|_| AppError::InvalidRequest("PKCE callback is not HTTP text".into()))?;
        let request_target = request
            .lines()
            .next()
            .and_then(|line| line.strip_prefix("GET "))
            .and_then(|line| line.strip_suffix(" HTTP/1.1"))
            .ok_or_else(|| {
                AppError::InvalidRequest("PKCE callback request line is invalid".into())
            })?;
        let callback = redirect
            .join(request_target)
            .map_err(|_| AppError::InvalidRequest("PKCE callback URL is invalid".into()))?;
        if callback.path() != redirect.path() {
            return Err(AppError::NotAuthorized(
                "PKCE callback path does not match the registered redirect".into(),
            ));
        }
        let mut code = None;
        let mut state = None;
        let mut oauth_error = None;
        for (key, value) in callback.query_pairs() {
            match key.as_ref() {
                "code" if code.is_none() => code = Some(Zeroizing::new(value.into_owned())),
                "state" if state.is_none() => state = Some(Zeroizing::new(value.into_owned())),
                "error" if oauth_error.is_none() => oauth_error = Some(value.into_owned()),
                _ => {}
            }
        }
        let success = oauth_error.is_none() && code.is_some() && state.is_some();
        let body = if success {
            "Authorization received. You may close this browser tab."
        } else {
            "Authorization was rejected. Return to ai-security-scanner."
        };
        let response = format!(
            "HTTP/1.1 {}\r\nContent-Type: text/plain; charset=utf-8\r\nContent-Length: {}\r\nConnection: close\r\nCache-Control: no-store\r\n\r\n{}",
            if success { "200 OK" } else { "400 Bad Request" },
            body.len(),
            body
        );
        stream.write_all(response.as_bytes())?;
        stream.flush()?;
        drop(raw);
        if oauth_error.is_some() {
            return Err(AppError::NotAuthorized(
                "provider rejected PKCE authorization".into(),
            ));
        }
        Ok(PkceAuthorizationCallback {
            authorization_code: code.ok_or_else(|| {
                AppError::InvalidRequest("PKCE callback omitted authorization code".into())
            })?,
            returned_state: state
                .ok_or_else(|| AppError::InvalidRequest("PKCE callback omitted state".into()))?,
        })
    }

    fn wait(&self, seconds: u64) -> AppResult<()> {
        if seconds == 0 || seconds > 30 {
            return Err(AppError::NotAuthorized(
                "provider requested an unsafe authorization polling interval".into(),
            ));
        }
        std::thread::sleep(StdDuration::from_secs(seconds));
        Ok(())
    }

    fn now(&self) -> DateTime<Utc> {
        Utc::now()
    }
}

fn public_error(error: &AppError) -> &'static str {
    match error {
        AppError::InvalidRequest(_) => "invalid bootstrap request",
        AppError::NotAuthorized(_) => "bootstrap request is not authorized",
        AppError::NotAvailable(_) => "bootstrap provider is temporarily unavailable",
        _ => "bootstrap broker failed safely",
    }
}

#[cfg(unix)]
fn require_protected_stdout_pipe() -> AppResult<()> {
    let mut stat = std::mem::MaybeUninit::<libc::stat>::uninit();
    // SAFETY: stdout is a process-owned descriptor and `stat` points to valid storage.
    if unsafe { libc::fstat(libc::STDOUT_FILENO, stat.as_mut_ptr()) } != 0 {
        return Err(AppError::NotAvailable(
            "bootstrap output pipe could not be inspected".into(),
        ));
    }
    // SAFETY: fstat initialized the structure on success.
    let stat = unsafe { stat.assume_init() };
    if (stat.st_mode & libc::S_IFMT) != libc::S_IFIFO {
        return Err(AppError::NotAuthorized(
            "bootstrap scanner credential output requires an anonymous pipe".into(),
        ));
    }
    Ok(())
}

#[cfg(windows)]
fn require_protected_stdout_pipe() -> AppResult<()> {
    use std::os::windows::io::AsRawHandle;
    use windows_sys::Win32::Storage::FileSystem::{FILE_TYPE_PIPE, GetFileType};

    let stdout = io::stdout();
    // SAFETY: the borrowed handle is owned by this process for the duration of
    // the call; GetFileType does not close or mutate it.
    let file_type = unsafe { GetFileType(stdout.as_raw_handle()) };
    if file_type != FILE_TYPE_PIPE {
        return Err(AppError::NotAuthorized(
            "bootstrap scanner credential output requires an anonymous pipe".into(),
        ));
    }
    Ok(())
}

#[cfg(not(any(unix, windows)))]
fn require_protected_stdout_pipe() -> AppResult<()> {
    Err(AppError::NotAvailable(
        "protected bootstrap one-shot pipe is not implemented on this platform".into(),
    ))
}

#[cfg(any(target_os = "linux", target_os = "android"))]
fn harden_process() {
    let limit = libc::rlimit {
        rlim_cur: 0,
        rlim_max: 0,
    };
    // SAFETY: setrlimit and prctl receive valid process-local scalar arguments.
    unsafe {
        libc::setrlimit(libc::RLIMIT_CORE, &limit);
        libc::prctl(libc::PR_SET_DUMPABLE, 0, 0, 0, 0);
        libc::prctl(libc::PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0);
    }
}

#[cfg(all(unix, not(any(target_os = "linux", target_os = "android"))))]
fn harden_process() {
    let limit = libc::rlimit {
        rlim_cur: 0,
        rlim_max: 0,
    };
    // SAFETY: setrlimit receives a valid process-local scalar argument. The
    // Linux-only dumpability and no-new-privileges controls are unavailable on
    // these Unix targets, so they are not referenced here.
    unsafe {
        libc::setrlimit(libc::RLIMIT_CORE, &limit);
    }
}

#[cfg(not(unix))]
fn harden_process() {}

#[cfg(test)]
mod tests {
    use super::*;
    use ai_security_scanner_lib::bootstrap::BootstrapProvider;
    use std::net::TcpStream;
    use std::thread;

    #[test]
    fn fragmented_pkce_callback_is_read_after_accept() {
        let reservation = TcpListener::bind("127.0.0.1:0").expect("reserve callback port");
        let port = reservation.local_addr().expect("reserved address").port();
        drop(reservation);

        let prompt = PkceAuthorizationPrompt {
            provider: BootstrapProvider::Gcp,
            authorization_url: "https://accounts.google.com/o/oauth2/v2/auth".into(),
            redirect_uri: format!("http://127.0.0.1:{port}/callback"),
            expires_at: Utc::now() + chrono::Duration::seconds(10),
            safety_notice: "test callback".into(),
        };
        let broker = thread::spawn(move || StdioInteraction.complete_pkce_authorization(&prompt));

        let deadline = std::time::Instant::now() + StdDuration::from_secs(5);
        let mut browser = loop {
            match TcpStream::connect(("127.0.0.1", port)) {
                Ok(stream) => break stream,
                Err(_) if std::time::Instant::now() < deadline => {
                    thread::sleep(StdDuration::from_millis(25));
                }
                Err(error) => panic!("connect to callback listener: {error}"),
            }
        };
        browser
            .write_all(b"GET /callback?code=code-123&state=state-456 HTTP/1.1\r\n")
            .expect("write request line");
        thread::sleep(StdDuration::from_millis(150));
        browser
            .write_all(b"Host: 127.0.0.1\r\nConnection: close\r\n\r\n")
            .expect("write delayed headers");
        let mut response = String::new();
        browser
            .read_to_string(&mut response)
            .expect("read callback response");

        let callback = broker
            .join()
            .expect("broker thread")
            .expect("accepted callback");
        assert_eq!(callback.authorization_code.as_str(), "code-123");
        assert_eq!(callback.returned_state.as_str(), "state-456");
        assert!(response.starts_with("HTTP/1.1 200 OK\r\n"));
    }
}
