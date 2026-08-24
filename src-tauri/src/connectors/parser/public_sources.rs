use super::{
    AssetDraft, Collector, ParserProfile, array_at, get_ci, get_path_ci, metadata, object,
    safe_text, string_at,
};
use crate::discovery::DiscoveryError;
use crate::domain::{AssetKind, RelationKind, SourceKind};
use serde_json::{Map, Value};
use std::net::IpAddr;

pub(super) fn parse(
    profile: ParserProfile,
    source_kind: &SourceKind,
    document: &Value,
    collector: &mut Collector<'_>,
) -> Result<(), DiscoveryError> {
    match (profile, source_kind) {
        (ParserProfile::DnsResponse, SourceKind::Dns) => parse_dns(document, collector),
        (ParserProfile::CertificateTransparencyResponse, SourceKind::CertificateTransparency) => {
            parse_certificate_transparency(document, collector)
        }
        (ParserProfile::BillingExport, SourceKind::Billing) => parse_billing(document, collector),
        _ => {
            return Err(DiscoveryError::Connector(
                "public-source snapshot parser profile does not match the source kind".into(),
            ));
        }
    }
    Ok(())
}

fn parse_dns(document: &Value, collector: &mut Collector<'_>) {
    if let Some(questions) = array_at(document, &["Question", "questions"]) {
        for (index, question) in questions.iter().enumerate() {
            let pointer = format!("/Question/{index}");
            if !collector.count_record(&pointer) {
                return;
            }
            if let Some(name) = string_at(question, &["name", "Name"])
                && let Some(name) = normalize_dns_name(name)
            {
                let query_type = dns_type(question).map(|value| value.to_string());
                collector.asset(
                    AssetDraft {
                        kind: AssetKind::Domain,
                        name: &name,
                        provider: Some("internet"),
                        region: None,
                        namespace: "dns_name",
                        native_id: &name,
                        additional_identifiers: vec![],
                        internet_exposed: Some(true),
                        contains_sensitive_data: None,
                        metadata: metadata(&[("dns_query_type", query_type.as_deref())]),
                    },
                    &pointer,
                );
            }
        }
    }

    let Some(answers) = array_at(document, &["Answer", "answers", "records"]) else {
        return;
    };
    for (index, answer) in answers.iter().enumerate() {
        let pointer = format!("/Answer/{index}");
        if !collector.count_record(&pointer) {
            break;
        }
        let Some(owner_name) =
            string_at(answer, &["name", "Name", "owner_name"]).and_then(normalize_dns_name)
        else {
            collector.notice(format!(
                "ignored DNS answer without a valid owner name at {pointer}"
            ));
            continue;
        };
        let Some(record_type) = dns_type(answer) else {
            collector.notice(format!(
                "ignored DNS answer without a supported explicit record type at {pointer}"
            ));
            continue;
        };
        let Some(data) = string_at(answer, &["data", "Data", "value"]) else {
            collector.notice(format!("ignored DNS answer without data at {pointer}"));
            continue;
        };
        let Some(owner_key) = collector.asset(
            AssetDraft {
                kind: AssetKind::Domain,
                name: &owner_name,
                provider: Some("internet"),
                region: None,
                namespace: "dns_name",
                native_id: &owner_name,
                additional_identifiers: vec![],
                internet_exposed: Some(true),
                contains_sensitive_data: None,
                metadata: metadata(&[("dns_record_type", Some(record_type))]),
            },
            &pointer,
        ) else {
            continue;
        };

        let target = match record_type {
            "A" | "AAAA" => data.trim().parse::<IpAddr>().ok().and_then(|address| {
                let address = address.to_string();
                collector.asset(
                    AssetDraft {
                        kind: AssetKind::IpAddress,
                        name: &address,
                        provider: Some("internet"),
                        region: None,
                        namespace: "ip_address",
                        native_id: &address,
                        additional_identifiers: vec![],
                        internet_exposed: Some(true),
                        contains_sensitive_data: None,
                        metadata: metadata(&[("dns_record_type", Some(record_type))]),
                    },
                    &pointer,
                )
            }),
            "CNAME" | "NS" | "MX" => {
                let host = if record_type == "MX" {
                    data.split_whitespace().last().unwrap_or(data)
                } else {
                    data
                };
                normalize_dns_name(host).and_then(|host| {
                    collector.asset(
                        AssetDraft {
                            kind: AssetKind::Domain,
                            name: &host,
                            provider: Some("internet"),
                            region: None,
                            namespace: "dns_name",
                            native_id: &host,
                            additional_identifiers: vec![],
                            internet_exposed: Some(true),
                            contains_sensitive_data: None,
                            metadata: metadata(&[("dns_record_type", Some(record_type))]),
                        },
                        &pointer,
                    )
                })
            }
            _ => None,
        };
        if let Some(target) = target {
            collector.relation(&owner_key, &target, RelationKind::ResolvesTo);
        } else if matches!(record_type, "A" | "AAAA" | "CNAME" | "NS" | "MX") {
            collector.notice(format!(
                "ignored malformed {record_type} answer data at {pointer}; raw response remains preserved"
            ));
        }
    }
}

fn parse_certificate_transparency(document: &Value, collector: &mut Collector<'_>) {
    let entries = array_at(document, &["entries", "certificates", "results"])
        .map(|values| values.iter().collect::<Vec<_>>())
        .unwrap_or_else(|| vec![document]);
    for (index, entry) in entries.into_iter().enumerate() {
        let pointer = format!("/entries/{index}");
        if !collector.count_record(&pointer) {
            break;
        }
        let Some(entry_object) = object(entry) else {
            collector.notice(format!("ignored non-object CT entry at {pointer}"));
            continue;
        };
        let certificate_id = certificate_identifier(entry_object);
        let certificate_key = certificate_id.as_ref().and_then(|(namespace, native_id)| {
            collector.asset(
                AssetDraft {
                    kind: AssetKind::Other,
                    name: string_at(entry, &["common_name", "commonName"]).unwrap_or(native_id),
                    provider: Some("certificate_transparency"),
                    region: None,
                    namespace: namespace.as_str(),
                    native_id: native_id.as_str(),
                    additional_identifiers: vec![],
                    internet_exposed: Some(true),
                    contains_sensitive_data: None,
                    metadata: metadata(&[
                        ("source_resource_type", Some("x509_certificate_observation")),
                        ("log_name", string_at(entry, &["log_name", "log.name"])),
                    ]),
                },
                &pointer,
            )
        });

        let names = certificate_names(entry);
        if names.is_empty() {
            collector.notice(format!(
                "ignored CT entry without a valid certificate name at {pointer}"
            ));
            continue;
        }
        for name in names {
            let Some(domain_key) = collector.asset(
                AssetDraft {
                    kind: AssetKind::Domain,
                    name: &name,
                    provider: Some("internet"),
                    region: None,
                    namespace: "dns_name",
                    native_id: &name,
                    additional_identifiers: vec![],
                    internet_exposed: Some(true),
                    contains_sensitive_data: None,
                    metadata: metadata(&[("source_resource_type", Some("certificate_name"))]),
                },
                &pointer,
            ) else {
                continue;
            };
            if let Some(certificate_key) = &certificate_key {
                collector.relation(certificate_key, &domain_key, RelationKind::References);
            }
        }
    }
}

fn parse_billing(document: &Value, collector: &mut Collector<'_>) {
    let rows = array_at(document, &["rows", "accounts", "items", "data"])
        .map(|values| values.iter().collect::<Vec<_>>())
        .unwrap_or_else(|| vec![document]);
    for (index, row) in rows.into_iter().enumerate() {
        let pointer = format!("/rows/{index}");
        if !collector.count_record(&pointer) {
            break;
        }
        let Some(provider) =
            string_at(row, &["provider", "cloud_provider"]).map(|value| value.to_ascii_lowercase())
        else {
            collector.notice(format!(
                "ignored billing row without an explicit provider at {pointer}; no provider was guessed from charge text"
            ));
            continue;
        };
        let (provider_name, kind, namespace, native_id, display_name) = match provider.as_str() {
            "aws" => {
                let Some(account_id) =
                    string_at(row, &["account_id", "linked_account_id"]).filter(|value| {
                        value.len() == 12 && value.bytes().all(|byte| byte.is_ascii_digit())
                    })
                else {
                    collector.notice(format!(
                        "ignored AWS billing row without a 12-digit account identifier at {pointer}"
                    ));
                    continue;
                };
                (
                    "aws",
                    AssetKind::CloudAccount,
                    "aws_account_id",
                    account_id,
                    string_at(row, &["account_name", "name"]).unwrap_or(account_id),
                )
            }
            "azure" | "microsoft_azure" => {
                let Some(subscription_id) =
                    string_at(row, &["subscription_id"]).filter(|value| looks_like_uuid(value))
                else {
                    collector.notice(format!(
                        "ignored Azure billing row without a subscription UUID at {pointer}"
                    ));
                    continue;
                };
                (
                    "azure",
                    AssetKind::Subscription,
                    "azure_subscription_id",
                    subscription_id,
                    string_at(row, &["subscription_name", "name"]).unwrap_or(subscription_id),
                )
            }
            "gcp" | "google_cloud" => {
                let Some(project_id) =
                    string_at(row, &["project_id"]).filter(|value| is_gcp_project_id(value))
                else {
                    collector.notice(format!(
                        "ignored GCP billing row without a project identifier at {pointer}"
                    ));
                    continue;
                };
                (
                    "gcp",
                    AssetKind::Project,
                    "gcp_project_id",
                    project_id,
                    string_at(row, &["project_name", "name"]).unwrap_or(project_id),
                )
            }
            _ => {
                collector.notice(format!(
                    "ignored billing row with unsupported explicit provider {} at {pointer}",
                    safe_text(&provider, 64)
                ));
                continue;
            }
        };

        let Some(child) = collector.asset(
            AssetDraft {
                kind,
                name: display_name,
                provider: Some(provider_name),
                region: None,
                namespace,
                native_id,
                additional_identifiers: vec![],
                internet_exposed: None,
                contains_sensitive_data: None,
                metadata: metadata(&[
                    ("source_resource_type", Some("billing_account_reference")),
                    (
                        "billing_period",
                        string_at(row, &["billing_period", "period"]),
                    ),
                ]),
            },
            &pointer,
        ) else {
            continue;
        };
        if let Some((payer_namespace, payer_id)) = billing_parent(provider_name, row) {
            let payer_name =
                string_at(row, &["payer_name", "billing_account_name"]).unwrap_or(payer_id);
            if let Some(parent) = collector.asset(
                AssetDraft {
                    kind: AssetKind::CloudAccount,
                    name: payer_name,
                    provider: Some(provider_name),
                    region: None,
                    namespace: payer_namespace,
                    native_id: payer_id,
                    additional_identifiers: vec![],
                    internet_exposed: None,
                    contains_sensitive_data: None,
                    metadata: metadata(&[("source_resource_type", Some("billing_parent_account"))]),
                },
                &pointer,
            ) {
                collector.relation(&parent, &child, RelationKind::Contains);
            }
        }
    }
}

fn dns_type(value: &Value) -> Option<&'static str> {
    let value = get_path_ci(value, "type").or_else(|| get_path_ci(value, "Type"))?;
    match value {
        Value::Number(number) => match number.as_u64()? {
            1 => Some("A"),
            2 => Some("NS"),
            5 => Some("CNAME"),
            15 => Some("MX"),
            28 => Some("AAAA"),
            _ => None,
        },
        Value::String(value) => match value.trim().to_ascii_uppercase().as_str() {
            "A" => Some("A"),
            "NS" => Some("NS"),
            "CNAME" => Some("CNAME"),
            "MX" => Some("MX"),
            "AAAA" => Some("AAAA"),
            _ => None,
        },
        _ => None,
    }
}

fn normalize_dns_name(value: &str) -> Option<String> {
    let value = value.trim().trim_end_matches('.');
    let value = value.strip_prefix("*.").unwrap_or(value);
    if value.is_empty() || value.len() > 253 || value.contains(['/', '\\', ' ']) {
        return None;
    }
    let ascii = idna::domain_to_ascii(value).ok()?.to_ascii_lowercase();
    if ascii.split('.').count() < 2
        || ascii
            .split('.')
            .any(|label| label.is_empty() || label.len() > 63)
    {
        return None;
    }
    Some(ascii)
}

fn certificate_names(entry: &Value) -> Vec<String> {
    let mut names = Vec::new();
    for path in ["name_value", "dns_names", "common_name", "commonName"] {
        let Some(value) = get_path_ci(entry, path) else {
            continue;
        };
        match value {
            Value::String(value) => {
                for part in value.split(['\n', ',']) {
                    if let Some(name) = normalize_dns_name(part)
                        && !names.contains(&name)
                    {
                        names.push(name);
                    }
                }
            }
            Value::Array(values) => {
                for value in values.iter().filter_map(Value::as_str) {
                    if let Some(name) = normalize_dns_name(value)
                        && !names.contains(&name)
                    {
                        names.push(name);
                    }
                }
            }
            _ => {}
        }
    }
    names
}

fn certificate_identifier(object: &Map<String, Value>) -> Option<(String, String)> {
    for (key, namespace) in [
        ("sha256", "x509_sha256"),
        ("fingerprint_sha256", "x509_sha256"),
        ("certificate_sha256", "x509_sha256"),
    ] {
        if let Some(value) = get_ci(object, key).and_then(Value::as_str) {
            let compact = value.replace(':', "").to_ascii_lowercase();
            if compact.len() == 64 && compact.bytes().all(|byte| byte.is_ascii_hexdigit()) {
                return Some((namespace.into(), compact));
            }
        }
    }
    for key in ["entry_id", "min_cert_id", "id"] {
        if let Some(value) = get_ci(object, key) {
            let value = match value {
                Value::String(value) => value.clone(),
                Value::Number(value) => value.to_string(),
                _ => continue,
            };
            if !value.is_empty() {
                return Some(("certificate_transparency_entry_id".into(), value));
            }
        }
    }
    None
}

fn billing_parent<'a>(provider: &str, row: &'a Value) -> Option<(&'static str, &'a str)> {
    match provider {
        "aws" => string_at(row, &["payer_account_id"])
            .filter(|value| value.len() == 12 && value.bytes().all(|byte| byte.is_ascii_digit()))
            .map(|value| ("aws_account_id", value)),
        "azure" => {
            string_at(row, &["billing_account_id"]).map(|value| ("azure_billing_account_id", value))
        }
        "gcp" => {
            string_at(row, &["billing_account_id"]).map(|value| ("gcp_billing_account_id", value))
        }
        _ => None,
    }
}

fn looks_like_uuid(value: &str) -> bool {
    let compact = value
        .bytes()
        .filter(|byte| *byte != b'-')
        .collect::<Vec<_>>();
    compact.len() == 32 && compact.iter().all(|byte| byte.is_ascii_hexdigit())
}

fn is_gcp_project_id(value: &str) -> bool {
    (6..=63).contains(&value.len())
        && value
            .bytes()
            .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'-')
}
