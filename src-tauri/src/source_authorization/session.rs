//! Backend-owned provider authorization sessions for desktop/long-lived CLI
//! processes. Pending device codes, PKCE verifiers, callback codes, and tokens
//! never cross a serde boundary.

use super::provider::{
    AwsNativeAuthorizationConfig, AwsPendingDeviceAuthorization, DeviceAuthorizationPrompt,
    GcpNativeAuthorizationConfig, GooglePendingPkceAuthorization, GooglePkcePrompt,
    MicrosoftNativeAuthorizationConfig, MicrosoftPendingDeviceAuthorization, PollAuthorization,
    ProviderHttp, begin_aws_native_authorization, begin_gcp_native_authorization,
    begin_microsoft_native_authorization, complete_gcp_native_authorization,
    poll_aws_native_authorization, poll_microsoft_native_authorization,
};
use super::{SourceAuthorizationRequest, VerifiedProviderAuthorization};
use crate::error::{AppError, AppResult};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeSet, HashMap};
use std::fmt;
use std::io::{ErrorKind, Read, Write};
use std::net::{IpAddr, SocketAddr, TcpListener};
use std::sync::Mutex;
use std::time::Duration as StdDuration;
use url::Url;
use uuid::Uuid;
use zeroize::Zeroizing;

const MAX_CALLBACK_BYTES: usize = 16 * 1024;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(tag = "provider", rename_all = "snake_case", deny_unknown_fields)]
pub enum ProviderAuthorizationConfig {
    Aws {
        config: AwsNativeAuthorizationConfig,
    },
    Azure {
        config: MicrosoftNativeAuthorizationConfig,
    },
    Gcp {
        config: GcpNativeAuthorizationConfig,
    },
    Microsoft365 {
        config: MicrosoftNativeAuthorizationConfig,
    },
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct BeginProviderAuthorizationRequest {
    pub case_id: String,
    pub source_id: String,
    pub allowed_engine_ids: BTreeSet<String>,
    pub max_checkouts: u8,
    pub authorization: ProviderAuthorizationConfig,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(tag = "flow", rename_all = "snake_case", deny_unknown_fields)]
pub enum ProviderAuthorizationPrompt {
    Device {
        session_id: String,
        prompt: DeviceAuthorizationPrompt,
    },
    Pkce {
        session_id: String,
        prompt: GooglePkcePrompt,
    },
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(tag = "status", rename_all = "snake_case", deny_unknown_fields)]
pub enum ProviderAuthorizationProgress {
    Pending {
        session_id: String,
        retry_after_seconds: u64,
    },
    Installed {
        authorization: Box<super::InstalledSourceAuthorization>,
    },
}

pub enum ProviderSessionPoll {
    Pending {
        session_id: String,
        retry_after_seconds: u64,
    },
    Complete(Box<SourceAuthorizationRequest>),
}

impl fmt::Debug for ProviderSessionPoll {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Pending {
                session_id,
                retry_after_seconds,
            } => formatter
                .debug_struct("Pending")
                .field("session_id", session_id)
                .field("retry_after_seconds", retry_after_seconds)
                .finish(),
            Self::Complete(_) => formatter.write_str("Complete([REDACTED_AUTHORIZATION])"),
        }
    }
}

#[derive(Clone)]
struct BindingRequest {
    case_id: String,
    source_id: String,
    allowed_engine_ids: BTreeSet<String>,
    max_checkouts: u8,
}

enum PendingProviderSession {
    Aws {
        binding: BindingRequest,
        pending: AwsPendingDeviceAuthorization,
        expires_at: DateTime<Utc>,
    },
    Microsoft {
        binding: BindingRequest,
        pending: MicrosoftPendingDeviceAuthorization,
        expires_at: DateTime<Utc>,
    },
    Gcp {
        binding: BindingRequest,
        pending: Option<GooglePendingPkceAuthorization>,
        listener: TcpListener,
        redirect_uri: String,
        expires_at: DateTime<Utc>,
    },
}

impl fmt::Debug for PendingProviderSession {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("PendingProviderSession([REDACTED])")
    }
}

impl PendingProviderSession {
    fn expires_at(&self) -> DateTime<Utc> {
        match self {
            Self::Aws { expires_at, .. }
            | Self::Microsoft { expires_at, .. }
            | Self::Gcp { expires_at, .. } => *expires_at,
        }
    }

    fn case_id(&self) -> &str {
        match self {
            Self::Aws { binding, .. }
            | Self::Microsoft { binding, .. }
            | Self::Gcp { binding, .. } => &binding.case_id,
        }
    }
}

#[derive(Default)]
pub struct ProviderAuthorizationSessions {
    sessions: Mutex<HashMap<String, PendingProviderSession>>,
}

impl fmt::Debug for ProviderAuthorizationSessions {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ProviderAuthorizationSessions")
            .field(
                "session_count",
                &self.sessions.lock().map(|sessions| sessions.len()).ok(),
            )
            .finish()
    }
}

impl ProviderAuthorizationSessions {
    pub fn begin(
        &self,
        http: &dyn ProviderHttp,
        mut request: BeginProviderAuthorizationRequest,
        now: DateTime<Utc>,
    ) -> AppResult<ProviderAuthorizationPrompt> {
        // Live inventory is a fixed backend engine, not a caller-selectable
        // executable. Binding it here ensures discovery cannot borrow another
        // scanner's authorization while keeping credentials out of the DTO.
        request
            .allowed_engine_ids
            .insert(super::PROVIDER_DISCOVERY_ENGINE_ID.into());
        validate_binding_request(&request)?;
        let binding = BindingRequest {
            case_id: request.case_id,
            source_id: request.source_id,
            allowed_engine_ids: request.allowed_engine_ids,
            max_checkouts: request.max_checkouts,
        };
        let session_id = Uuid::new_v4().to_string();
        let (prompt, pending) = match request.authorization {
            ProviderAuthorizationConfig::Aws { config } => {
                let (prompt, pending) = begin_aws_native_authorization(http, config, now)?;
                let expires_at = prompt.expires_at;
                (
                    ProviderAuthorizationPrompt::Device {
                        session_id: session_id.clone(),
                        prompt,
                    },
                    PendingProviderSession::Aws {
                        binding,
                        pending,
                        expires_at,
                    },
                )
            }
            ProviderAuthorizationConfig::Azure { config } => {
                if config.profile != super::ProviderSourceProfile::AzureTenantReadOnlyAccessToken {
                    return Err(AppError::InvalidRequest(
                        "Azure session requires the Azure provider profile".into(),
                    ));
                }
                let (prompt, pending) = begin_microsoft_native_authorization(http, config, now)?;
                let expires_at = prompt.expires_at;
                (
                    ProviderAuthorizationPrompt::Device {
                        session_id: session_id.clone(),
                        prompt,
                    },
                    PendingProviderSession::Microsoft {
                        binding,
                        pending,
                        expires_at,
                    },
                )
            }
            ProviderAuthorizationConfig::Microsoft365 { config } => {
                if config.profile
                    != super::ProviderSourceProfile::Microsoft365TenantReadOnlyAccessToken
                {
                    return Err(AppError::InvalidRequest(
                        "Microsoft 365 session requires the Microsoft 365 provider profile".into(),
                    ));
                }
                let (prompt, pending) = begin_microsoft_native_authorization(http, config, now)?;
                let expires_at = prompt.expires_at;
                (
                    ProviderAuthorizationPrompt::Device {
                        session_id: session_id.clone(),
                        prompt,
                    },
                    PendingProviderSession::Microsoft {
                        binding,
                        pending,
                        expires_at,
                    },
                )
            }
            ProviderAuthorizationConfig::Gcp { config } => {
                let redirect = Url::parse(&config.redirect_uri).map_err(|_| {
                    AppError::InvalidRequest("Google loopback redirect URI is invalid".into())
                })?;
                let host = redirect
                    .host_str()
                    .unwrap_or_default()
                    .trim_matches(['[', ']']);
                let ip: IpAddr = host.parse().map_err(|_| {
                    AppError::InvalidRequest("Google loopback redirect host is invalid".into())
                })?;
                if !ip.is_loopback() {
                    return Err(AppError::NotAuthorized(
                        "Google callback listener must bind only to loopback".into(),
                    ));
                }
                let listener = TcpListener::bind(SocketAddr::new(
                    ip,
                    redirect.port().ok_or_else(|| {
                        AppError::InvalidRequest("Google loopback redirect port is missing".into())
                    })?,
                ))
                .map_err(|_| {
                    AppError::NotAvailable("Google callback listener could not bind".into())
                })?;
                listener.set_nonblocking(true).map_err(|_| {
                    AppError::NotAvailable("Google callback listener could not start".into())
                })?;
                let (prompt, pending) = begin_gcp_native_authorization(config, now)?;
                let redirect_uri = prompt.redirect_uri.clone();
                let expires_at = prompt.expires_at;
                (
                    ProviderAuthorizationPrompt::Pkce {
                        session_id: session_id.clone(),
                        prompt,
                    },
                    PendingProviderSession::Gcp {
                        binding,
                        pending: Some(pending),
                        listener,
                        redirect_uri,
                        expires_at,
                    },
                )
            }
        };
        let mut sessions = self.sessions.lock().map_err(|_| {
            AppError::Internal("provider authorization session lock was poisoned".into())
        })?;
        sessions.retain(|_, session| session.expires_at() > now);
        if sessions.len() >= 32 {
            return Err(AppError::NotAvailable(
                "too many provider authorization sessions are active".into(),
            ));
        }
        sessions.insert(session_id, pending);
        Ok(prompt)
    }

    pub fn poll(
        &self,
        http: &dyn ProviderHttp,
        session_id: &str,
        now: DateTime<Utc>,
    ) -> AppResult<ProviderSessionPoll> {
        let mut pending = self
            .sessions
            .lock()
            .map_err(|_| {
                AppError::Internal("provider authorization session lock was poisoned".into())
            })?
            .remove(session_id)
            .ok_or_else(|| {
                AppError::InvalidRequest("provider authorization session does not exist".into())
            })?;
        let result = match &mut pending {
            PendingProviderSession::Aws {
                binding, pending, ..
            } => match poll_aws_native_authorization(http, pending, now) {
                Ok(PollAuthorization::Pending {
                    retry_after_seconds,
                }) => Ok(ProviderSessionPoll::Pending {
                    session_id: session_id.into(),
                    retry_after_seconds,
                }),
                Ok(PollAuthorization::Complete(authorization)) => Ok(
                    ProviderSessionPoll::Complete(Box::new(bound_request(binding, authorization))),
                ),
                Err(error) => Err(error),
            },
            PendingProviderSession::Microsoft {
                binding, pending, ..
            } => match poll_microsoft_native_authorization(http, pending, now) {
                Ok(PollAuthorization::Pending {
                    retry_after_seconds,
                }) => Ok(ProviderSessionPoll::Pending {
                    session_id: session_id.into(),
                    retry_after_seconds,
                }),
                Ok(PollAuthorization::Complete(authorization)) => Ok(
                    ProviderSessionPoll::Complete(Box::new(bound_request(binding, authorization))),
                ),
                Err(error) => Err(error),
            },
            PendingProviderSession::Gcp {
                binding,
                pending,
                listener,
                redirect_uri,
                ..
            } => match read_pkce_callback(listener, redirect_uri)? {
                Some((code, state)) => {
                    let owned = pending.take().ok_or_else(|| {
                        AppError::Internal("Google authorization state was already consumed".into())
                    })?;
                    let authorization =
                        complete_gcp_native_authorization(http, owned, code, &state, now)?;
                    Ok(ProviderSessionPoll::Complete(Box::new(bound_request(
                        binding,
                        authorization,
                    ))))
                }
                None => Ok(ProviderSessionPoll::Pending {
                    session_id: session_id.into(),
                    retry_after_seconds: 1,
                }),
            },
        };
        if matches!(result, Ok(ProviderSessionPoll::Pending { .. })) {
            self.sessions
                .lock()
                .map_err(|_| {
                    AppError::Internal("provider authorization session lock was poisoned".into())
                })?
                .insert(session_id.into(), pending);
        }
        result
    }

    pub fn cancel(&self, session_id: &str) -> AppResult<bool> {
        Ok(self
            .sessions
            .lock()
            .map_err(|_| {
                AppError::Internal("provider authorization session lock was poisoned".into())
            })?
            .remove(session_id)
            .is_some())
    }

    /// Drops every secret-bearing pending flow for one case. Dropping a
    /// session also closes a loopback listener and zeroizes provider state.
    pub fn cancel_case(&self, case_id: &str) -> AppResult<usize> {
        let mut sessions = self.sessions.lock().map_err(|_| {
            AppError::Internal("provider authorization session lock was poisoned".into())
        })?;
        let before = sessions.len();
        sessions.retain(|_, session| session.case_id() != case_id);
        Ok(before.saturating_sub(sessions.len()))
    }
}

fn validate_binding_request(request: &BeginProviderAuthorizationRequest) -> AppResult<()> {
    if request.case_id.is_empty()
        || request.case_id.len() > 128
        || request.source_id.is_empty()
        || request.source_id.len() > 128
        || request.allowed_engine_ids.is_empty()
        || request.max_checkouts == 0
        || request.max_checkouts > 8
    {
        return Err(AppError::InvalidRequest(
            "provider authorization binding is incomplete or outside limits".into(),
        ));
    }
    Ok(())
}

fn bound_request(
    binding: &BindingRequest,
    verified_authorization: VerifiedProviderAuthorization,
) -> SourceAuthorizationRequest {
    SourceAuthorizationRequest {
        case_id: binding.case_id.clone(),
        source_id: binding.source_id.clone(),
        allowed_engine_ids: binding.allowed_engine_ids.clone(),
        max_checkouts: binding.max_checkouts,
        verified_authorization,
    }
}

fn read_pkce_callback(
    listener: &TcpListener,
    redirect_uri: &str,
) -> AppResult<Option<(Zeroizing<String>, Zeroizing<String>)>> {
    let (mut stream, peer) = match listener.accept() {
        Ok(value) => value,
        Err(error) if error.kind() == ErrorKind::WouldBlock => return Ok(None),
        Err(_) => {
            return Err(AppError::NotAvailable(
                "Google loopback callback could not be accepted".into(),
            ));
        }
    };
    if !peer.ip().is_loopback() {
        return Err(AppError::NotAuthorized(
            "Google callback did not originate on loopback".into(),
        ));
    }
    stream.set_nonblocking(false)?;
    stream.set_read_timeout(Some(StdDuration::from_secs(10)))?;
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
        if raw.len() > MAX_CALLBACK_BYTES {
            return Err(AppError::InvalidRequest(
                "Google callback request exceeded the limit".into(),
            ));
        }
    }
    let request = std::str::from_utf8(raw.as_slice())
        .map_err(|_| AppError::InvalidRequest("Google callback is not HTTP text".into()))?;
    let target = request
        .lines()
        .next()
        .and_then(|line| line.strip_prefix("GET "))
        .and_then(|line| line.strip_suffix(" HTTP/1.1"))
        .ok_or_else(|| {
            AppError::InvalidRequest("Google callback request line is invalid".into())
        })?;
    let registered = Url::parse(redirect_uri)
        .map_err(|_| AppError::Internal("registered Google redirect is invalid".into()))?;
    let callback = registered
        .join(target)
        .map_err(|_| AppError::InvalidRequest("Google callback URL is invalid".into()))?;
    if callback.path() != registered.path() {
        return Err(AppError::NotAuthorized(
            "Google callback path does not match the registered redirect".into(),
        ));
    }
    let mut code = None;
    let mut state = None;
    let mut rejected = false;
    for (key, value) in callback.query_pairs() {
        match key.as_ref() {
            "code" if code.is_none() => code = Some(Zeroizing::new(value.into_owned())),
            "state" if state.is_none() => state = Some(Zeroizing::new(value.into_owned())),
            "error" => rejected = true,
            _ => {}
        }
    }
    let success = !rejected && code.is_some() && state.is_some();
    let body = if success {
        "Authorization received. You may close this tab."
    } else {
        "Authorization rejected. Return to ai-security-scanner."
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
    if rejected {
        return Err(AppError::NotAuthorized(
            "Google operator rejected authorization".into(),
        ));
    }
    Ok(Some((
        code.ok_or_else(|| AppError::InvalidRequest("Google callback omitted code".into()))?,
        state.ok_or_else(|| AppError::InvalidRequest("Google callback omitted state".into()))?,
    )))
}
