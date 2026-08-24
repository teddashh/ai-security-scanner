use chrono::{DateTime, Utc};
use serde::Deserialize;
use std::ffi::OsString;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::{Command, ExitCode};
use zeroize::Zeroizing;

const CREDENTIAL_PATH: &str = "/run/ai-security-scanner/credentials.json";
const MAX_CREDENTIAL_BYTES: u64 = 256 * 1024;
const SAFE_ENVIRONMENT: &[&str] = &[
    "PATH",
    "LANG",
    "LC_ALL",
    "HOME",
    "SSL_CERT_FILE",
    "SSL_CERT_DIR",
    "REQUESTS_CA_BUNDLE",
    "NODE_EXTRA_CA_CERTS",
    "POWERSHELL_TELEMETRY_OPTOUT",
];
const CREDENTIAL_KEYS: &[&str] = &[
    "AWS_ACCESS_KEY_ID",
    "AWS_SECRET_ACCESS_KEY",
    "AWS_SESSION_TOKEN",
    "AZURE_ACCESS_TOKEN",
    "GOOGLE_OAUTH_ACCESS_TOKEN",
    "MSGRAPH_ACCESS_TOKEN",
    "KUBERNETES_BEARER_TOKEN",
    "REGISTRY_USERNAME",
    "REGISTRY_TOKEN",
];

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct CredentialEnvelope<'a> {
    schema_version: &'a str,
    #[serde(borrow)]
    credentials: Vec<CredentialEntry<'a>>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct CredentialEntry<'a> {
    key: &'a str,
    value: &'a str,
    expires_at: DateTime<Utc>,
    source: &'a str,
}

fn main() -> ExitCode {
    match run() {
        Ok(code) => ExitCode::from(code),
        Err(message) => {
            eprintln!("adapter launcher: {message}");
            ExitCode::from(126)
        }
    }
}

fn run() -> Result<u8, &'static str> {
    let mut arguments = std::env::args_os().skip(1);
    let program = arguments.next().ok_or("engine program is missing")?;
    validate_program(&program)?;
    let arguments: Vec<OsString> = arguments.collect();
    if arguments.len() > 256
        || arguments
            .iter()
            .any(|argument| argument.len() > 16 * 1024 || argument.as_encoded_bytes().contains(&0))
    {
        return Err("engine argument vector is malformed");
    }

    let safe_environment: Vec<(String, OsString)> = SAFE_ENVIRONMENT
        .iter()
        .filter_map(|key| std::env::var_os(key).map(|value| ((*key).to_owned(), value)))
        .collect();
    let credential_path = PathBuf::from(CREDENTIAL_PATH);
    let bytes = read_bounded_credentials(&credential_path)?;
    let envelope = if bytes.is_empty() {
        None
    } else {
        Some(parse_envelope(bytes.as_slice())?)
    };

    let mut command = Command::new(program);
    command.args(arguments);
    command.env_clear();
    command.envs(safe_environment);
    if let Some(envelope) = &envelope {
        for entry in &envelope.credentials {
            command.env(entry.key, entry.value);
        }
    }

    #[cfg(unix)]
    {
        use std::os::unix::process::CommandExt;
        let _ = command.exec();
        Err("engine process could not start")
    }

    #[cfg(not(unix))]
    {
        let status = command
            .status()
            .map_err(|_| "engine process could not start")?;
        Ok(status
            .code()
            .and_then(|code| u8::try_from(code).ok())
            .unwrap_or(1))
    }
}

fn read_bounded_credentials(path: &Path) -> Result<Zeroizing<Vec<u8>>, &'static str> {
    match fs::symlink_metadata(path) {
        Ok(metadata) => {
            if metadata.file_type().is_symlink()
                || !metadata.is_file()
                || metadata.len() > MAX_CREDENTIAL_BYTES
            {
                return Err("credential channel is not a bounded regular file");
            }
            fs::read(path)
                .map(Zeroizing::new)
                .map_err(|_| "credential channel could not be read")
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            Ok(Zeroizing::new(Vec::new()))
        }
        Err(_) => Err("credential channel could not be inspected"),
    }
}

fn parse_envelope(bytes: &[u8]) -> Result<CredentialEnvelope<'_>, &'static str> {
    let envelope: CredentialEnvelope<'_> =
        serde_json::from_slice(bytes).map_err(|_| "credential channel is malformed")?;
    if envelope.schema_version != "1.0.0" || envelope.credentials.len() > CREDENTIAL_KEYS.len() {
        return Err("credential channel version or entry count is invalid");
    }
    let now = Utc::now();
    let mut seen = std::collections::BTreeSet::new();
    for entry in &envelope.credentials {
        if !CREDENTIAL_KEYS.contains(&entry.key)
            || !seen.insert(entry.key)
            || entry.value.is_empty()
            || entry.value.len() > 64 * 1024
            || entry.expires_at <= now
            || !matches!(
                entry.source,
                "ephemeral_scan_role" | "external_read_only_grant"
            )
        {
            return Err("credential channel contains an unauthorized entry");
        }
    }
    Ok(envelope)
}

fn validate_program(program: &OsString) -> Result<(), &'static str> {
    let path = Path::new(program);
    let basename = path
        .file_name()
        .and_then(|value| value.to_str())
        .ok_or("engine program name is invalid")?
        .to_ascii_lowercase();
    if program.as_encoded_bytes().contains(&0)
        || matches!(
            basename.as_str(),
            "sh" | "bash"
                | "dash"
                | "zsh"
                | "fish"
                | "cmd"
                | "cmd.exe"
                | "powershell"
                | "powershell.exe"
                | "pwsh"
                | "pwsh.exe"
        )
    {
        return Err("shell interpreters are not valid engine programs");
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::Duration;

    #[test]
    fn validates_only_short_lived_allowlisted_credentials() {
        let input = serde_json::json!({
            "schema_version": "1.0.0",
            "credentials": [{
                "key": "AWS_SESSION_TOKEN",
                "value": "temporary-value",
                "expires_at": (Utc::now() + Duration::minutes(5)).to_rfc3339(),
                "source": "ephemeral_scan_role"
            }]
        });
        let bytes = serde_json::to_vec(&input).expect("json");
        let envelope = parse_envelope(&bytes).expect("envelope");
        assert_eq!(envelope.credentials.len(), 1);
    }

    #[test]
    fn rejects_admin_keys_and_shells() {
        let input = serde_json::json!({
            "schema_version": "1.0.0",
            "credentials": [{
                "key": "ADMIN_PASSWORD",
                "value": "secret",
                "expires_at": (Utc::now() + Duration::minutes(5)).to_rfc3339(),
                "source": "ephemeral_scan_role"
            }]
        });
        assert!(parse_envelope(&serde_json::to_vec(&input).expect("json")).is_err());
        assert!(validate_program(&OsString::from("/bin/sh")).is_err());
        assert!(validate_program(&OsString::from("scanner")).is_ok());
    }
}
