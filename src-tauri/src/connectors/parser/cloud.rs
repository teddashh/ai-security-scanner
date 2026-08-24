use super::{
    AssetDraft, Collector, ParserProfile, array_at, get_path_ci, id, metadata, safe_text, string_at,
};
use crate::discovery::DiscoveryError;
use crate::domain::{AssetKind, RelationKind, SourceKind};
use serde_json::Value;

pub(super) fn parse(
    profile: ParserProfile,
    source_kind: &SourceKind,
    document: &Value,
    collector: &mut Collector<'_>,
) -> Result<(), DiscoveryError> {
    let allowed = match profile {
        ParserProfile::CloudQuery | ParserProfile::Steampipe | ParserProfile::Prowler => matches!(
            source_kind,
            SourceKind::AwsOrganization | SourceKind::AzureTenant | SourceKind::GcpOrganization
        ),
        ParserProfile::ScubaGear | ParserProfile::Maester => {
            matches!(source_kind, SourceKind::Microsoft365Tenant)
        }
        _ => false,
    };
    if !allowed {
        return Err(DiscoveryError::Connector(
            "cloud snapshot parser profile does not match the source kind".into(),
        ));
    }

    // ScubaGear and Maester commonly keep tenant coordinates on the envelope
    // and individual assessment rows below `Results`/`Tests`. Read the envelope
    // as inventory once; check titles or product names are never made into
    // assets.
    if matches!(source_kind, SourceKind::Microsoft365Tenant) && document.is_object() {
        parse_m365(document, "/", collector);
    }

    for (index, record) in records(profile, document).into_iter().enumerate() {
        let pointer = format!("/records/{index}");
        if !collector.count_record(&pointer) {
            break;
        }
        if !record.is_object() {
            collector.notice(format!(
                "ignored non-object inventory record at {pointer}; raw evidence remains preserved"
            ));
            continue;
        }
        match source_kind {
            SourceKind::AwsOrganization => parse_aws(profile, record, &pointer, collector),
            SourceKind::AzureTenant => parse_azure(profile, record, &pointer, collector),
            SourceKind::GcpOrganization => parse_gcp(profile, record, &pointer, collector),
            SourceKind::Microsoft365Tenant => parse_m365(record, &pointer, collector),
            _ => unreachable!("profile/source compatibility checked above"),
        }
    }
    Ok(())
}

fn records(profile: ParserProfile, document: &Value) -> Vec<&Value> {
    let keys: &[&str] = match profile {
        ParserProfile::CloudQuery => &["rows", "resources", "items", "data"],
        ParserProfile::Steampipe => &["rows", "items", "data"],
        ParserProfile::Prowler => &["findings", "Findings", "results", "items"],
        ParserProfile::ScubaGear => &["Results", "results"],
        ParserProfile::Maester => &["Tests", "tests", "results"],
        _ => &[],
    };
    if let Some(values) = array_at(document, keys) {
        values.iter().collect()
    } else {
        vec![document]
    }
}

fn parse_aws(profile: ParserProfile, record: &Value, pointer: &str, collector: &mut Collector<'_>) {
    let organization_id = string_at(
        record,
        &[
            "organization_id",
            "organizationId",
            "org_id",
            "unmapped.OrganizationId",
        ],
    )
    .filter(|value| value.starts_with("o-"));
    let account_id = string_at(
        record,
        &[
            "account_id",
            "accountId",
            "AccountId",
            "aws_account_id",
            "unmapped.AccountId",
        ],
    )
    .filter(|value| is_aws_account_id(value));

    let organization_key = organization_id.and_then(|native_id| {
        collector.asset(
            AssetDraft {
                kind: AssetKind::CloudOrganization,
                name: string_at(record, &["organization_name", "org_name"]).unwrap_or(native_id),
                provider: Some("aws"),
                region: None,
                namespace: "aws_organization_id",
                native_id,
                additional_identifiers: vec![],
                internet_exposed: None,
                contains_sensitive_data: None,
                metadata: metadata(&[("source_resource_type", Some("aws_organization"))]),
            },
            pointer,
        )
    });
    let account_key = account_id.and_then(|native_id| {
        collector.asset(
            AssetDraft {
                kind: AssetKind::CloudAccount,
                name: string_at(record, &["account_name", "AccountName"]).unwrap_or(native_id),
                provider: Some("aws"),
                region: None,
                namespace: "aws_account_id",
                native_id,
                additional_identifiers: vec![],
                internet_exposed: None,
                contains_sensitive_data: None,
                metadata: metadata(&[("source_resource_type", Some("aws_account"))]),
            },
            pointer,
        )
    });
    if let (Some(from), Some(to)) = (&organization_key, &account_key) {
        collector.relation(from, to, RelationKind::Contains);
    }

    let mut resource_count = 0;
    for (resource_pointer, resource) in resource_values(profile, record, pointer) {
        let Some((namespace, native_id)) = aws_resource_identity(profile, resource) else {
            continue;
        };
        resource_count += 1;
        let arn = native_id.starts_with("arn:").then_some(native_id);
        let derived_account = arn.and_then(aws_account_from_arn);
        let derived_region = arn.and_then(aws_region_from_arn);
        let parent = account_key.clone().or_else(|| {
            derived_account.and_then(|native_id| {
                collector.asset(
                    AssetDraft {
                        kind: AssetKind::CloudAccount,
                        name: native_id,
                        provider: Some("aws"),
                        region: None,
                        namespace: "aws_account_id",
                        native_id,
                        additional_identifiers: vec![],
                        internet_exposed: None,
                        contains_sensitive_data: None,
                        metadata: metadata(&[("source_resource_type", Some("aws_account"))]),
                    },
                    &resource_pointer,
                )
            })
        });
        let resource_type = string_at(resource, &["kind", "type", "resource_type", "table"]);
        let name = string_at(
            resource,
            &["name", "resource_name", "display_name", "resources.0.name"],
        )
        .unwrap_or(native_id);
        let key = collector.asset(
            AssetDraft {
                kind: classify_cloud_resource(resource_type, native_id),
                name,
                provider: Some("aws"),
                region: string_at(resource, &["region", "aws_region"]).or(derived_region),
                namespace,
                native_id,
                additional_identifiers: account_id
                    .map(|value| vec![id("aws_account_id", value)])
                    .unwrap_or_default(),
                internet_exposed: super::bool_at(
                    resource,
                    &["internet_exposed", "public", "is_public"],
                ),
                contains_sensitive_data: super::bool_at(resource, &["contains_sensitive_data"]),
                metadata: metadata(&[
                    ("source_resource_type", resource_type),
                    ("source_service", string_at(resource, &["service"])),
                ]),
            },
            &resource_pointer,
        );
        if let (Some(parent), Some(child)) = (&parent, &key) {
            collector.relation(parent, child, RelationKind::Contains);
        }
    }
    if resource_count == 0 && organization_key.is_none() && account_key.is_none() {
        collector.notice(format!(
            "record {pointer} had no supported AWS provider-native inventory identifier; no asset was inferred"
        ));
    }
}

fn parse_azure(
    profile: ParserProfile,
    record: &Value,
    pointer: &str,
    collector: &mut Collector<'_>,
) {
    let resource_ids = resource_values(profile, record, pointer);
    let explicit_resource_id = resource_ids
        .iter()
        .find_map(|(_, resource)| azure_resource_id(resource));
    let tenant_id = string_at(
        record,
        &["tenant_id", "tenantId", "TenantId", "azure_tenant_id"],
    )
    .filter(|value| looks_like_uuid(value));
    let subscription_id = string_at(
        record,
        &[
            "subscription_id",
            "subscriptionId",
            "SubscriptionId",
            "azure_subscription_id",
        ],
    )
    .filter(|value| looks_like_uuid(value))
    .or_else(|| explicit_resource_id.and_then(azure_subscription_from_id));

    let tenant_key = tenant_id.and_then(|native_id| {
        collector.asset(
            AssetDraft {
                kind: AssetKind::Tenant,
                name: string_at(record, &["tenant_name", "TenantName"]).unwrap_or(native_id),
                provider: Some("azure"),
                region: None,
                namespace: "azure_tenant_id",
                native_id,
                additional_identifiers: vec![],
                internet_exposed: None,
                contains_sensitive_data: None,
                metadata: metadata(&[("source_resource_type", Some("azure_tenant"))]),
            },
            pointer,
        )
    });
    let subscription_key = subscription_id.and_then(|native_id| {
        collector.asset(
            AssetDraft {
                kind: AssetKind::Subscription,
                name: string_at(record, &["subscription_name", "SubscriptionName"])
                    .unwrap_or(native_id),
                provider: Some("azure"),
                region: None,
                namespace: "azure_subscription_id",
                native_id,
                additional_identifiers: vec![],
                internet_exposed: None,
                contains_sensitive_data: None,
                metadata: metadata(&[("source_resource_type", Some("azure_subscription"))]),
            },
            pointer,
        )
    });
    if let (Some(from), Some(to)) = (&tenant_key, &subscription_key) {
        collector.relation(from, to, RelationKind::Contains);
    }

    let mut resource_count = 0;
    for (resource_pointer, resource) in resource_ids {
        let Some(native_id) = azure_resource_id(resource) else {
            continue;
        };
        resource_count += 1;
        let resource_type = string_at(resource, &["kind", "type", "resource_type", "table"]);
        let name = string_at(resource, &["name", "resource_name", "display_name"])
            .or_else(|| native_id.rsplit('/').find(|value| !value.is_empty()))
            .unwrap_or(native_id);
        let key = collector.asset(
            AssetDraft {
                kind: classify_cloud_resource(resource_type, native_id),
                name,
                provider: Some("azure"),
                region: string_at(resource, &["location", "region"]),
                namespace: "azure_resource_id",
                native_id,
                additional_identifiers: subscription_id
                    .map(|value| vec![id("azure_subscription_id", value)])
                    .unwrap_or_default(),
                internet_exposed: super::bool_at(
                    resource,
                    &["internet_exposed", "public", "is_public"],
                ),
                contains_sensitive_data: super::bool_at(resource, &["contains_sensitive_data"]),
                metadata: metadata(&[("source_resource_type", resource_type)]),
            },
            &resource_pointer,
        );
        let parent = subscription_key.clone().or_else(|| {
            azure_subscription_from_id(native_id).and_then(|subscription| {
                collector.asset(
                    AssetDraft {
                        kind: AssetKind::Subscription,
                        name: subscription,
                        provider: Some("azure"),
                        region: None,
                        namespace: "azure_subscription_id",
                        native_id: subscription,
                        additional_identifiers: vec![],
                        internet_exposed: None,
                        contains_sensitive_data: None,
                        metadata: metadata(&[("source_resource_type", Some("azure_subscription"))]),
                    },
                    &resource_pointer,
                )
            })
        });
        if let (Some(parent), Some(child)) = (&parent, &key) {
            collector.relation(parent, child, RelationKind::Contains);
        }
    }
    if resource_count == 0 && tenant_key.is_none() && subscription_key.is_none() {
        collector.notice(format!(
            "record {pointer} had no supported Azure provider-native inventory identifier; no asset was inferred"
        ));
    }
}

fn parse_gcp(profile: ParserProfile, record: &Value, pointer: &str, collector: &mut Collector<'_>) {
    let organization_id = string_at(
        record,
        &[
            "organization_id",
            "organizationId",
            "organization_number",
            "org_id",
        ],
    )
    .map(|value| value.trim_start_matches("organizations/"))
    .filter(|value| value.bytes().all(|byte| byte.is_ascii_digit()));
    let project_id = string_at(
        record,
        &["project_id", "projectId", "gcp_project_id", "project"],
    )
    .filter(|value| is_gcp_project_id(value));

    let organization_key = organization_id.and_then(|native_id| {
        collector.asset(
            AssetDraft {
                kind: AssetKind::CloudOrganization,
                name: string_at(record, &["organization_name"]).unwrap_or(native_id),
                provider: Some("gcp"),
                region: None,
                namespace: "gcp_organization_number",
                native_id,
                additional_identifiers: vec![],
                internet_exposed: None,
                contains_sensitive_data: None,
                metadata: metadata(&[("source_resource_type", Some("gcp_organization"))]),
            },
            pointer,
        )
    });
    let project_key = project_id.and_then(|native_id| {
        collector.asset(
            AssetDraft {
                kind: AssetKind::Project,
                name: string_at(record, &["project_name", "display_name"]).unwrap_or(native_id),
                provider: Some("gcp"),
                region: None,
                namespace: "gcp_project_id",
                native_id,
                additional_identifiers: string_at(record, &["project_number"])
                    .map(|number| vec![id("gcp_project_number", number)])
                    .unwrap_or_default(),
                internet_exposed: None,
                contains_sensitive_data: None,
                metadata: metadata(&[("source_resource_type", Some("gcp_project"))]),
            },
            pointer,
        )
    });
    if let (Some(from), Some(to)) = (&organization_key, &project_key) {
        collector.relation(from, to, RelationKind::Contains);
    }

    let mut resource_count = 0;
    for (resource_pointer, resource) in resource_values(profile, record, pointer) {
        let Some(native_id) = gcp_resource_id(resource) else {
            continue;
        };
        resource_count += 1;
        let derived_project = gcp_project_from_resource(native_id);
        let parent = project_key.clone().or_else(|| {
            derived_project.and_then(|native_id| {
                collector.asset(
                    AssetDraft {
                        kind: AssetKind::Project,
                        name: native_id,
                        provider: Some("gcp"),
                        region: None,
                        namespace: "gcp_project_id",
                        native_id,
                        additional_identifiers: vec![],
                        internet_exposed: None,
                        contains_sensitive_data: None,
                        metadata: metadata(&[("source_resource_type", Some("gcp_project"))]),
                    },
                    &resource_pointer,
                )
            })
        });
        let resource_type = string_at(resource, &["kind", "type", "resource_type", "table"]);
        let key = collector.asset(
            AssetDraft {
                kind: classify_cloud_resource(resource_type, native_id),
                name: string_at(resource, &["name", "display_name", "resource_name"])
                    .unwrap_or(native_id),
                provider: Some("gcp"),
                region: string_at(resource, &["location", "region", "zone"]),
                namespace: "gcp_full_resource_name",
                native_id,
                additional_identifiers: project_id
                    .map(|value| vec![id("gcp_project_id", value)])
                    .unwrap_or_default(),
                internet_exposed: super::bool_at(
                    resource,
                    &["internet_exposed", "public", "is_public"],
                ),
                contains_sensitive_data: super::bool_at(resource, &["contains_sensitive_data"]),
                metadata: metadata(&[("source_resource_type", resource_type)]),
            },
            &resource_pointer,
        );
        if let (Some(parent), Some(child)) = (&parent, &key) {
            collector.relation(parent, child, RelationKind::Contains);
        }
    }
    if resource_count == 0 && organization_key.is_none() && project_key.is_none() {
        collector.notice(format!(
            "record {pointer} had no supported GCP provider-native inventory identifier; no asset was inferred"
        ));
    }
}

fn parse_m365(record: &Value, pointer: &str, collector: &mut Collector<'_>) {
    let tenant_id = string_at(
        record,
        &[
            "tenant_id",
            "tenantId",
            "TenantId",
            "Organization.TenantId",
            "Metadata.TenantId",
        ],
    )
    .filter(|value| looks_like_uuid(value));
    let tenant_key = tenant_id.and_then(|native_id| {
        collector.asset(
            AssetDraft {
                kind: AssetKind::Tenant,
                name: string_at(
                    record,
                    &["tenant_name", "TenantName", "Organization.DisplayName"],
                )
                .unwrap_or(native_id),
                provider: Some("microsoft365"),
                region: None,
                namespace: "microsoft_tenant_id",
                native_id,
                additional_identifiers: vec![],
                internet_exposed: None,
                contains_sensitive_data: None,
                metadata: metadata(&[("source_resource_type", Some("microsoft365_tenant"))]),
            },
            pointer,
        )
    });

    let identity_id = string_at(
        record,
        &[
            "identity.object_id",
            "identity.id",
            "principal.object_id",
            "UserId",
            "PrincipalId",
        ],
    )
    .filter(|value| looks_like_uuid(value));
    let identity_key = identity_id.and_then(|native_id| {
        collector.asset(
            AssetDraft {
                kind: AssetKind::Identity,
                name: string_at(
                    record,
                    &[
                        "identity.display_name",
                        "principal.display_name",
                        "UserPrincipalName",
                    ],
                )
                .unwrap_or(native_id),
                provider: Some("microsoft365"),
                region: None,
                namespace: "microsoft_object_id",
                native_id,
                additional_identifiers: vec![],
                internet_exposed: None,
                contains_sensitive_data: None,
                metadata: metadata(&[("source_resource_type", Some("microsoft_identity"))]),
            },
            pointer,
        )
    });
    if let (Some(tenant), Some(identity)) = (&tenant_key, &identity_key) {
        collector.relation(tenant, identity, RelationKind::Contains);
    }
    if tenant_key.is_none() && identity_key.is_none() {
        collector.notice(format!(
            "record {pointer} was assessment output without a supported tenant or object identifier; no M365 asset was inferred"
        ));
    }
}

fn resource_values<'a>(
    profile: ParserProfile,
    record: &'a Value,
    pointer: &str,
) -> Vec<(String, &'a Value)> {
    let mut resources = Vec::new();
    if matches!(profile, ParserProfile::Prowler)
        && let Some(values) = get_path_ci(record, "resources").and_then(Value::as_array)
    {
        for (index, value) in values.iter().enumerate() {
            resources.push((format!("{pointer}/resources/{index}"), value));
        }
    }
    if resources.is_empty() {
        resources.push((pointer.to_owned(), record));
    }
    resources
}

fn aws_resource_identity(profile: ParserProfile, resource: &Value) -> Option<(&'static str, &str)> {
    let native_id = string_at(
        resource,
        &[
            "arn",
            "resource_arn",
            "resource",
            "resource_id",
            "uid",
            "resources.0.uid",
            "native_id",
        ],
    );
    if let Some(native_id) = native_id.filter(|value| value.starts_with("arn:")) {
        return Some(("aws_arn", native_id));
    }
    if matches!(profile, ParserProfile::CloudQuery) {
        let kind = string_at(resource, &["kind", "type", "table"])?;
        if kind.eq_ignore_ascii_case("aws_s3_bucket") || kind.eq_ignore_ascii_case("aws_s3_buckets")
        {
            return string_at(resource, &["name", "bucket_name"])
                .map(|value| ("aws_s3_bucket_name", value));
        }
        if kind.to_ascii_lowercase().starts_with("aws_") {
            return string_at(resource, &["id", "resource_id", "native_id"])
                .map(|value| ("aws_resource_id", value));
        }
    }
    None
}

fn azure_resource_id(resource: &Value) -> Option<&str> {
    string_at(
        resource,
        &[
            "resource_id",
            "resource",
            "id",
            "uid",
            "resources.0.uid",
            "native_id",
        ],
    )
    .filter(|value| value.to_ascii_lowercase().starts_with("/subscriptions/"))
}

fn gcp_resource_id(resource: &Value) -> Option<&str> {
    string_at(
        resource,
        &[
            "full_resource_name",
            "self_link",
            "resource",
            "resource_id",
            "uid",
            "resources.0.uid",
            "native_id",
        ],
    )
    .filter(|value| {
        value.starts_with("//") || value.starts_with("projects/") || value.contains("/projects/")
    })
}

fn classify_cloud_resource(resource_type: Option<&str>, native_id: &str) -> AssetKind {
    let marker = format!(
        "{} {}",
        resource_type.unwrap_or_default().to_ascii_lowercase(),
        native_id.to_ascii_lowercase()
    );
    if marker.contains("load_balancer")
        || marker.contains("applicationgateway")
        || marker.contains("webapp")
        || marker.contains("run.googleapis.com")
    {
        AssetKind::WebService
    } else {
        AssetKind::CloudResource
    }
}

fn is_aws_account_id(value: &str) -> bool {
    value.len() == 12 && value.bytes().all(|byte| byte.is_ascii_digit())
}

fn aws_account_from_arn(value: &str) -> Option<&str> {
    let account = value.split(':').nth(4)?;
    is_aws_account_id(account).then_some(account)
}

fn aws_region_from_arn(value: &str) -> Option<&str> {
    value.split(':').nth(3).filter(|region| !region.is_empty())
}

fn azure_subscription_from_id(value: &str) -> Option<&str> {
    let parts = value.split('/').collect::<Vec<_>>();
    parts.windows(2).find_map(|pair| {
        pair[0]
            .eq_ignore_ascii_case("subscriptions")
            .then_some(pair[1])
            .filter(|value| looks_like_uuid(value))
    })
}

fn gcp_project_from_resource(value: &str) -> Option<&str> {
    let parts = value.split('/').collect::<Vec<_>>();
    parts.windows(2).find_map(|pair| {
        (pair[0] == "projects")
            .then_some(pair[1])
            .filter(|value| is_gcp_project_id(value))
    })
}

fn looks_like_uuid(value: &str) -> bool {
    let compact = value
        .bytes()
        .filter(|byte| *byte != b'-')
        .collect::<Vec<_>>();
    compact.len() == 32 && compact.iter().all(|byte| byte.is_ascii_hexdigit())
}

fn is_gcp_project_id(value: &str) -> bool {
    let value = safe_text(value, 64);
    (6..=63).contains(&value.len())
        && value
            .bytes()
            .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'-')
}
