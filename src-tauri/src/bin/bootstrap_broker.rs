use ai_security_scanner_lib::bootstrap::{
    BootstrapRequest, create_bootstrap_plan, ensure_no_secret_environment,
};
use ai_security_scanner_lib::error::AppError;
use chrono::Utc;
use serde::Serialize;
use std::io::{self, Read, Write};

const MAX_REQUEST_BYTES: u64 = 64 * 1024;

#[derive(Serialize)]
struct BrokerError<'a> {
    error: &'a str,
}

fn main() {
    disable_core_dumps();
    if let Err(error) = run() {
        let message = public_error(&error);
        let _ = serde_json::to_writer(io::stdout().lock(), &BrokerError { error: message });
        let _ = io::stdout().lock().write_all(b"\n");
        std::process::exit(2);
    }
}

fn run() -> Result<(), AppError> {
    ensure_no_secret_environment()?;
    let mut input = Vec::new();
    io::stdin()
        .lock()
        .take(MAX_REQUEST_BYTES + 1)
        .read_to_end(&mut input)?;
    if input.len() as u64 > MAX_REQUEST_BYTES {
        return Err(AppError::InvalidRequest(
            "bootstrap request is too large".into(),
        ));
    }
    let request: BootstrapRequest = serde_json::from_slice(&input)
        .map_err(|_| AppError::InvalidRequest("bootstrap request is malformed".into()))?;
    let plan = create_bootstrap_plan(request, Utc::now())?;
    serde_json::to_writer(io::stdout().lock(), &plan)
        .map_err(|_| AppError::Internal("could not encode broker response".into()))?;
    io::stdout().lock().write_all(b"\n")?;
    Ok(())
}

fn public_error(error: &AppError) -> &'static str {
    match error {
        AppError::InvalidRequest(_) => "invalid bootstrap request",
        AppError::NotAuthorized(_) => "bootstrap request is not authorized",
        _ => "bootstrap broker failed safely",
    }
}

#[cfg(unix)]
fn disable_core_dumps() {
    let limit = libc::rlimit {
        rlim_cur: 0,
        rlim_max: 0,
    };
    // SAFETY: setrlimit receives a valid pointer to a process-local rlimit value.
    unsafe {
        libc::setrlimit(libc::RLIMIT_CORE, &limit);
    }
}

#[cfg(not(unix))]
fn disable_core_dumps() {}
