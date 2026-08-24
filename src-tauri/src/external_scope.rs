use crate::error::{AppError, AppResult};
use chrono::{DateTime, Utc};
use ipnet::IpNet;
use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use url::Url;

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
#[serde(rename_all = "snake_case")]
pub enum ExternalActivity {
    PassivePublicDiscovery,
    LowImpactExternal,
    ActiveExternal,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum TransportProtocol {
    Tcp,
    Udp,
    Tls,
    Http,
    Https,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(tag = "kind", content = "value", rename_all = "snake_case")]
pub enum CanonicalTarget {
    Hostname(String),
    Address(IpAddr),
    Network(IpNet),
}

impl CanonicalTarget {
    pub fn parse(input: &str) -> AppResult<Self> {
        let input = input.trim();
        if input.is_empty() || input.contains(['\n', '\r', '\0']) {
            return Err(AppError::InvalidRequest(
                "scan target is empty or malformed".into(),
            ));
        }
        if input.contains('*') {
            return Err(AppError::InvalidRequest(
                "wildcard targets are not accepted; authorize each bounded target".into(),
            ));
        }
        if let Ok(network) = input.parse::<IpNet>() {
            return Ok(Self::Network(network.trunc()));
        }
        if let Ok(address) = input.parse::<IpAddr>() {
            return Ok(Self::Address(address));
        }

        let input = input.trim_end_matches('.');
        let ascii = idna::domain_to_ascii(input)
            .map_err(|_| AppError::InvalidRequest("target hostname is not valid IDNA".into()))?
            .to_ascii_lowercase();
        validate_hostname(&ascii)?;
        Ok(Self::Hostname(ascii))
    }

    pub fn canonical_text(&self) -> String {
        match self {
            Self::Hostname(host) => host.clone(),
            Self::Address(address) => address.to_string(),
            Self::Network(network) => network.to_string(),
        }
    }

    fn contains_address(&self, address: IpAddr) -> bool {
        match self {
            Self::Address(approved) => *approved == address,
            Self::Network(approved) => approved.contains(&address),
            Self::Hostname(_) => true,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct RatePolicy {
    pub requests_per_second: u16,
    pub concurrency: u16,
    pub timeout_seconds: u32,
}

impl RatePolicy {
    fn validate(&self, activity: ExternalActivity) -> AppResult<()> {
        let (max_rate, max_concurrency, max_timeout) = match activity {
            ExternalActivity::PassivePublicDiscovery => (100, 20, 3_600),
            ExternalActivity::LowImpactExternal => (25, 10, 1_800),
            ExternalActivity::ActiveExternal => (10, 5, 3_600),
        };
        if self.requests_per_second == 0 || self.requests_per_second > max_rate {
            return Err(AppError::InvalidRequest(format!(
                "request rate must be between 1 and {max_rate} for this activity"
            )));
        }
        if self.concurrency == 0 || self.concurrency > max_concurrency {
            return Err(AppError::InvalidRequest(format!(
                "concurrency must be between 1 and {max_concurrency} for this activity"
            )));
        }
        if self.timeout_seconds == 0 || self.timeout_seconds > max_timeout {
            return Err(AppError::InvalidRequest(format!(
                "timeout must be between 1 and {max_timeout} seconds"
            )));
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct TemplatePolicy {
    pub revision: String,
    pub allowed_template_ids: Vec<String>,
    pub allow_headless: bool,
    pub allow_out_of_band: bool,
    pub allow_fuzzing: bool,
    pub allow_file_upload: bool,
    pub allow_denial_of_service: bool,
    pub allow_credential_attacks: bool,
}

impl TemplatePolicy {
    pub fn conservative(revision: impl Into<String>, allowed_template_ids: Vec<String>) -> Self {
        Self {
            revision: revision.into(),
            allowed_template_ids,
            allow_headless: false,
            allow_out_of_band: false,
            allow_fuzzing: false,
            allow_file_upload: false,
            allow_denial_of_service: false,
            allow_credential_attacks: false,
        }
    }

    fn validate(&self, activity: ExternalActivity) -> AppResult<()> {
        if self.revision.trim().is_empty() {
            return Err(AppError::InvalidRequest(
                "external template policy must have a pinned revision".into(),
            ));
        }
        if activity == ExternalActivity::ActiveExternal && self.allowed_template_ids.is_empty() {
            return Err(AppError::NotAuthorized(
                "active external testing requires an explicit template allowlist".into(),
            ));
        }
        if self
            .allowed_template_ids
            .iter()
            .any(|id| id.trim().is_empty() || id == "*" || id.contains(['\n', '\r', '\0']))
        {
            return Err(AppError::InvalidRequest(
                "external template allowlist contains an invalid identifier".into(),
            ));
        }
        if self.allow_denial_of_service || self.allow_credential_attacks {
            return Err(AppError::NotAuthorized(
                "denial-of-service and credential-attack templates are prohibited".into(),
            ));
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ExternalScopeGrant {
    pub id: String,
    pub case_id: String,
    pub asset_id: String,
    pub target: CanonicalTarget,
    pub ports: BTreeSet<u16>,
    pub protocol: TransportProtocol,
    pub activity: ExternalActivity,
    pub rate_policy: RatePolicy,
    pub template_policy: TemplatePolicy,
    pub asserted_authority: String,
    pub approved_by: String,
    pub approved_at: DateTime<Utc>,
    pub expires_at: DateTime<Utc>,
    pub allow_sensitive_networks: bool,
}

impl ExternalScopeGrant {
    pub fn validate(&self, now: DateTime<Utc>) -> AppResult<()> {
        if self.id.trim().is_empty()
            || self.case_id.trim().is_empty()
            || self.asset_id.trim().is_empty()
        {
            return Err(AppError::InvalidRequest(
                "scope grant, case, and asset identifiers are required".into(),
            ));
        }
        if self.asserted_authority.trim().is_empty() || self.approved_by.trim().is_empty() {
            return Err(AppError::NotAuthorized(
                "the approver and authority assertion must be recorded".into(),
            ));
        }
        if self.expires_at <= now || self.expires_at <= self.approved_at {
            return Err(AppError::NotAuthorized(
                "external scope grant is expired".into(),
            ));
        }
        if self.expires_at - self.approved_at > chrono::Duration::days(30) {
            return Err(AppError::InvalidRequest(
                "external scope grants cannot last longer than 30 days".into(),
            ));
        }
        if self.activity != ExternalActivity::PassivePublicDiscovery && self.ports.is_empty() {
            return Err(AppError::InvalidRequest(
                "direct external activity requires at least one approved port".into(),
            ));
        }
        if self.ports.contains(&0) {
            return Err(AppError::InvalidRequest(
                "port zero is not a valid target".into(),
            ));
        }
        if self.activity == ExternalActivity::ActiveExternal
            && self.asserted_authority.trim().len() < 8
        {
            return Err(AppError::NotAuthorized(
                "active testing requires a meaningful authorization reference".into(),
            ));
        }
        self.rate_policy.validate(self.activity)?;
        self.template_policy.validate(self.activity)?;
        Ok(())
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ResolutionSnapshot {
    pub hostname: Option<String>,
    pub addresses: BTreeSet<IpAddr>,
    pub resolved_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ResolvedExternalPlan {
    pub grant_id: String,
    pub case_id: String,
    pub asset_id: String,
    pub target: CanonicalTarget,
    pub resolution: ResolutionSnapshot,
    pub ports: BTreeSet<u16>,
    pub protocol: TransportProtocol,
    pub activity: ExternalActivity,
    pub rate_policy: RatePolicy,
    pub template_policy: TemplatePolicy,
    pub frozen_at: DateTime<Utc>,
    pub expires_at: DateTime<Utc>,
}

pub fn freeze_external_plan(
    grant: &ExternalScopeGrant,
    resolved_addresses: impl IntoIterator<Item = IpAddr>,
    now: DateTime<Utc>,
) -> AppResult<ResolvedExternalPlan> {
    grant.validate(now)?;
    let addresses: BTreeSet<IpAddr> = match grant.target {
        CanonicalTarget::Address(address) => [address].into_iter().collect(),
        _ => resolved_addresses.into_iter().collect(),
    };
    if grant.activity != ExternalActivity::PassivePublicDiscovery && addresses.is_empty() {
        return Err(AppError::NotAuthorized(
            "target did not resolve to a bounded address set".into(),
        ));
    }
    for address in &addresses {
        validate_resolved_address(grant, *address)?;
    }

    Ok(ResolvedExternalPlan {
        grant_id: grant.id.clone(),
        case_id: grant.case_id.clone(),
        asset_id: grant.asset_id.clone(),
        target: grant.target.clone(),
        resolution: ResolutionSnapshot {
            hostname: match &grant.target {
                CanonicalTarget::Hostname(hostname) => Some(hostname.clone()),
                _ => None,
            },
            addresses,
            resolved_at: now,
        },
        ports: grant.ports.clone(),
        protocol: grant.protocol,
        activity: grant.activity,
        rate_policy: grant.rate_policy.clone(),
        template_policy: grant.template_policy.clone(),
        frozen_at: now,
        expires_at: grant.expires_at,
    })
}

impl ResolvedExternalPlan {
    pub fn authorize_connection(
        &self,
        address: IpAddr,
        port: u16,
        now: DateTime<Utc>,
    ) -> AppResult<()> {
        if now >= self.expires_at {
            return Err(AppError::NotAuthorized(
                "external run plan is expired".into(),
            ));
        }
        if !self.ports.contains(&port) {
            return Err(AppError::NotAuthorized(format!(
                "port {port} is outside the frozen scope"
            )));
        }
        if !self.resolution.addresses.contains(&address) {
            return Err(AppError::NotAuthorized(format!(
                "address {address} was not in the frozen DNS resolution"
            )));
        }
        Ok(())
    }

    pub fn authorize_redirect(
        &self,
        location: &str,
        now: DateTime<Utc>,
    ) -> AppResult<(String, u16)> {
        let url = Url::parse(location)
            .map_err(|_| AppError::NotAuthorized("redirect URL is malformed".into()))?;
        let expected_scheme = match self.protocol {
            TransportProtocol::Https | TransportProtocol::Tls => "https",
            TransportProtocol::Http => "http",
            _ => {
                return Err(AppError::NotAuthorized(
                    "redirects are not allowed for this protocol".into(),
                ));
            }
        };
        if url.scheme() != expected_scheme || url.username() != "" || url.password().is_some() {
            return Err(AppError::NotAuthorized(
                "redirect changed protocol or included user information".into(),
            ));
        }
        let host = url
            .host_str()
            .ok_or_else(|| AppError::NotAuthorized("redirect has no host".into()))?;
        let redirect_target = CanonicalTarget::parse(host)?;
        if redirect_target != self.target {
            return Err(AppError::NotAuthorized(
                "redirect target is outside the frozen scope".into(),
            ));
        }
        let port = url.port_or_known_default().ok_or_else(|| {
            AppError::NotAuthorized("redirect does not resolve to an approved port".into())
        })?;
        if now >= self.expires_at || !self.ports.contains(&port) {
            return Err(AppError::NotAuthorized(
                "redirect port or grant lifetime is outside scope".into(),
            ));
        }
        Ok((redirect_target.canonical_text(), port))
    }
}

fn validate_resolved_address(grant: &ExternalScopeGrant, address: IpAddr) -> AppResult<()> {
    if !grant.target.contains_address(address) {
        return Err(AppError::NotAuthorized(format!(
            "resolved address {address} is outside the approved target"
        )));
    }
    if is_cloud_metadata(address) {
        return Err(AppError::NotAuthorized(format!(
            "cloud metadata address {address} is never accepted as an external target"
        )));
    }
    if is_sensitive_address(address) && !grant.allow_sensitive_networks {
        return Err(AppError::NotAuthorized(format!(
            "sensitive, local, or non-routable address {address} requires an explicit internal-network grant"
        )));
    }
    Ok(())
}

fn validate_hostname(hostname: &str) -> AppResult<()> {
    if hostname.len() > 253 || !hostname.contains('.') {
        return Err(AppError::InvalidRequest(
            "target must be a fully qualified hostname".into(),
        ));
    }
    for label in hostname.split('.') {
        if label.is_empty()
            || label.len() > 63
            || label.starts_with('-')
            || label.ends_with('-')
            || !label
                .chars()
                .all(|character| character.is_ascii_alphanumeric() || character == '-')
        {
            return Err(AppError::InvalidRequest(
                "target hostname is malformed".into(),
            ));
        }
    }
    Ok(())
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
                || (address.segments()[0] & 0xfe00) == 0xfc00
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
    use chrono::Duration;

    fn grant(target: &str, activity: ExternalActivity) -> ExternalScopeGrant {
        let approved_at = Utc::now();
        ExternalScopeGrant {
            id: "grant-1".into(),
            case_id: "case-1".into(),
            asset_id: "asset-1".into(),
            target: CanonicalTarget::parse(target).expect("target"),
            ports: [443].into_iter().collect(),
            protocol: TransportProtocol::Https,
            activity,
            rate_policy: RatePolicy {
                requests_per_second: 5,
                concurrency: 2,
                timeout_seconds: 300,
            },
            template_policy: TemplatePolicy::conservative(
                "templates@sha256:0123456789abcdef",
                vec!["http/misconfiguration/example".into()],
            ),
            asserted_authority: "ticket SEC-1042".into(),
            approved_by: "owner@example.test".into(),
            approved_at,
            expires_at: approved_at + Duration::days(7),
            allow_sensitive_networks: false,
        }
    }

    #[test]
    fn canonicalizes_idna_and_rejects_wildcards() {
        assert_eq!(
            CanonicalTarget::parse("BÜCHER.Example.").expect("idna"),
            CanonicalTarget::Hostname("xn--bcher-kva.example".into())
        );
        assert!(CanonicalTarget::parse("*.example.com").is_err());
    }

    #[test]
    fn freezes_dns_and_rejects_rebinding() {
        let now = Utc::now();
        let plan = freeze_external_plan(
            &grant("app.example.test", ExternalActivity::ActiveExternal),
            ["203.0.113.8".parse().expect("address")],
            now,
        )
        .expect("plan");
        plan.authorize_connection("203.0.113.8".parse().expect("address"), 443, now)
            .expect("approved connection");
        assert!(
            plan.authorize_connection("127.0.0.1".parse().expect("address"), 443, now)
                .is_err()
        );
        assert!(
            plan.authorize_connection("203.0.113.8".parse().expect("address"), 80, now)
                .is_err()
        );
    }

    #[test]
    fn metadata_is_denied_even_with_internal_flag() {
        let now = Utc::now();
        let mut scope = grant("169.254.169.254", ExternalActivity::LowImpactExternal);
        scope.allow_sensitive_networks = true;
        assert!(freeze_external_plan(&scope, [], now).is_err());
    }

    #[test]
    fn redirects_cannot_change_host_or_port() {
        let now = Utc::now();
        let plan = freeze_external_plan(
            &grant("app.example.test", ExternalActivity::LowImpactExternal),
            ["203.0.113.8".parse().expect("address")],
            now,
        )
        .expect("plan");
        plan.authorize_redirect("https://app.example.test/path", now)
            .expect("same-host redirect");
        assert!(
            plan.authorize_redirect("https://other.example.test/path", now)
                .is_err()
        );
        assert!(
            plan.authorize_redirect("https://app.example.test:8443/path", now)
                .is_err()
        );
    }

    #[test]
    fn active_policy_never_allows_denial_of_service() {
        let mut scope = grant("app.example.test", ExternalActivity::ActiveExternal);
        scope.template_policy.allow_denial_of_service = true;
        assert!(scope.validate(Utc::now()).is_err());
    }
}
