//! Parsers for the exact provider-native inventory operations issued by the
//! live discovery client. Network code never calls these functions directly;
//! only SHA-256-verified connector artifacts reach this module.

use super::{AssetDraft, Collector, ParserProfile, array_at, metadata, string_at};
use crate::discovery::DiscoveryError;
use crate::domain::{AssetKind, RelationKind, SourceKind, valid_gcp_project_id};
use serde_json::Value;

/// Parses one AWS Organizations `ListAccounts` page. The API speaks JSON 1.1:
/// `{"Accounts":[{"Arn","Email","Id","JoinedMethod","JoinedTimestamp","Name",
/// "State","Status"}],"NextToken"}`.
fn parse_aws_organizations(
    document: &Value,
    collector: &mut Collector<'_>,
) -> Result<(), DiscoveryError> {
    let accounts = document
        .as_object()
        .and_then(|object| object.get("Accounts"))
        .and_then(Value::as_array)
        .ok_or_else(|| {
            DiscoveryError::Connector(
                "AWS Organizations ListAccounts response omitted the Accounts array".into(),
            )
        })?;
    for (index, account) in accounts.iter().enumerate() {
        let pointer = format!("/Accounts/{index}");
        if !collector.count_record(&pointer) {
            break;
        }
        let id = string_at(account, &["Id"]).unwrap_or_default();
        let arn = string_at(account, &["Arn"]).unwrap_or_default();
        let valid_account_id = id.len() == 12 && id.bytes().all(|byte| byte.is_ascii_digit());
        let valid_account_arn = arn.starts_with("arn:aws:organizations::")
            && arn.contains(":account/")
            && arn.ends_with(&format!("/{id}"));
        if !valid_account_id || !valid_account_arn {
            collector.notice(format!(
                "ignored malformed AWS account identity at {pointer}; raw response remains preserved"
            ));
            continue;
        }
        // Email is intentionally never copied into canonical metadata.
        collector.asset(
            AssetDraft {
                kind: AssetKind::CloudAccount,
                name: string_at(account, &["Name"]).unwrap_or(id),
                provider: Some("aws"),
                region: None,
                namespace: "aws_account_id",
                native_id: id,
                additional_identifiers: vec![],
                internet_exposed: None,
                contains_sensitive_data: None,
                metadata: metadata(&[
                    ("source_resource_type", Some("aws_organizations_account")),
                    ("account_status", string_at(account, &["State", "Status"])),
                ]),
            },
            &pointer,
        );
    }
    Ok(())
}

pub(super) fn parse_json(
    profile: ParserProfile,
    source_kind: &SourceKind,
    document: &Value,
    collector: &mut Collector<'_>,
) -> Result<(), DiscoveryError> {
    match profile {
        ParserProfile::AwsOrganizationsListAccounts => {
            if !matches!(source_kind, SourceKind::AwsOrganization) {
                return mismatch("AWS Organizations");
            }
            parse_aws_organizations(document, collector)
        }
        ParserProfile::AzureResourceManagerResources => {
            if !matches!(source_kind, SourceKind::AzureTenant) {
                return mismatch("Azure Resource Manager");
            }
            parse_azure(document, collector)
        }
        ParserProfile::GcpResourceManagerProjects => {
            if !matches!(source_kind, SourceKind::GcpOrganization) {
                return mismatch("Google Cloud Resource Manager");
            }
            parse_gcp(document, collector)
        }
        ParserProfile::MicrosoftGraphDirectoryInventory => {
            if !matches!(source_kind, SourceKind::Microsoft365Tenant) {
                return mismatch("Microsoft Graph directory");
            }
            parse_microsoft365(document, collector)
        }
        _ => Err(DiscoveryError::Connector(
            "provider-native JSON parser received a different profile".into(),
        )),
    }
}

fn parse_azure(document: &Value, collector: &mut Collector<'_>) -> Result<(), DiscoveryError> {
    let Some(values) = array_at(document, &["value"]) else {
        return parse_azure_subscription_identity(document, collector);
    };
    for (index, resource) in values.iter().enumerate() {
        let pointer = format!("/value/{index}");
        if !collector.count_record(&pointer) {
            break;
        }
        let Some(resource_id) =
            string_at(resource, &["id"]).filter(|value| value.starts_with("/subscriptions/"))
        else {
            collector.notice(format!(
                "ignored Azure inventory row without an absolute resource ID at {pointer}"
            ));
            continue;
        };
        let subscription_id = resource_id
            .split('/')
            .nth(2)
            .filter(|value| looks_like_uuid(value));
        let subscription_key = subscription_id.and_then(|native_id| {
            collector.asset(
                AssetDraft {
                    kind: AssetKind::Subscription,
                    name: native_id,
                    provider: Some("azure"),
                    region: None,
                    namespace: "azure_subscription_id",
                    native_id,
                    additional_identifiers: vec![],
                    internet_exposed: None,
                    contains_sensitive_data: None,
                    metadata: metadata(&[("source_resource_type", Some("azure_subscription"))]),
                },
                &pointer,
            )
        });
        let resource_key = collector.asset(
            AssetDraft {
                kind: AssetKind::CloudResource,
                name: string_at(resource, &["name"]).unwrap_or(resource_id),
                provider: Some("azure"),
                region: string_at(resource, &["location"]),
                namespace: "azure_resource_id",
                native_id: resource_id,
                additional_identifiers: vec![],
                internet_exposed: None,
                contains_sensitive_data: None,
                metadata: metadata(&[
                    ("source_resource_type", string_at(resource, &["type"])),
                    ("resource_group", azure_resource_group(resource_id)),
                ]),
            },
            &pointer,
        );
        if let (Some(parent), Some(child)) = (&subscription_key, &resource_key) {
            collector.relation(parent, child, RelationKind::Contains);
        }
    }
    Ok(())
}

fn parse_azure_subscription_identity(
    document: &Value,
    collector: &mut Collector<'_>,
) -> Result<(), DiscoveryError> {
    let subscription_id = string_at(document, &["subscriptionId"])
        .filter(|value| looks_like_uuid(value))
        .ok_or_else(|| {
            DiscoveryError::Connector(
                "Azure subscription identity omitted a valid subscriptionId".into(),
            )
        })?;
    let state = string_at(document, &["state"]).ok_or_else(|| {
        DiscoveryError::Connector("Azure subscription identity omitted its state".into())
    })?;
    if state != "Enabled" {
        return Err(DiscoveryError::Connector(
            "Azure subscription identity is not in the Enabled state".into(),
        ));
    }
    if !collector.count_record("/") {
        return Ok(());
    }
    collector.asset(
        AssetDraft {
            kind: AssetKind::Subscription,
            name: string_at(document, &["displayName"]).unwrap_or(subscription_id),
            provider: Some("azure"),
            region: None,
            namespace: "azure_subscription_id",
            native_id: subscription_id,
            additional_identifiers: vec![],
            internet_exposed: None,
            contains_sensitive_data: None,
            metadata: metadata(&[
                ("source_resource_type", Some("azure_subscription")),
                ("lifecycle_state", Some(state)),
            ]),
        },
        "/",
    );
    Ok(())
}

fn parse_gcp(document: &Value, collector: &mut Collector<'_>) -> Result<(), DiscoveryError> {
    if document.get("folders").is_some() {
        if document.get("projects").is_some() {
            return Err(DiscoveryError::Connector(
                "Google Resource Manager response mixed folder and project records".into(),
            ));
        }
        return parse_gcp_folders(document, collector);
    }
    let projects = match document.get("projects") {
        None if document.is_object() => return Ok(()),
        Some(Value::Array(projects)) => projects,
        _ => {
            return Err(DiscoveryError::Connector(
                "Google Resource Manager projects field is malformed".into(),
            ));
        }
    };
    for (index, project) in projects.iter().enumerate() {
        let pointer = format!("/projects/{index}");
        if !collector.count_record(&pointer) {
            break;
        }
        let project_id = string_at(project, &["projectId"])
            .filter(|value| valid_gcp_project_id(value))
            .ok_or_else(|| {
                DiscoveryError::Connector(format!(
                    "Google project at {pointer} omitted a valid immutable project ID"
                ))
            })?;
        let project_number = string_at(project, &["name"])
            .filter(|value| valid_gcp_numeric_name(value, "projects/"))
            .ok_or_else(|| {
                DiscoveryError::Connector(format!(
                    "Google project at {pointer} omitted its numeric resource name"
                ))
            })?;
        let state = string_at(project, &["state"])
            .filter(|value| *value == "ACTIVE")
            .ok_or_else(|| {
                DiscoveryError::Connector(format!(
                    "Google project at {pointer} is not in the ACTIVE state"
                ))
            })?;
        let parent = string_at(project, &["parent"]).ok_or_else(|| {
            DiscoveryError::Connector(format!(
                "Google project at {pointer} omitted its exact hierarchy parent"
            ))
        })?;
        let parent_key = gcp_parent_asset(parent, &pointer, collector)?;
        let project_key = collector.asset(
            AssetDraft {
                kind: AssetKind::Project,
                name: string_at(project, &["displayName"]).unwrap_or(project_id),
                provider: Some("gcp"),
                region: None,
                namespace: "gcp_project_id",
                native_id: project_id,
                additional_identifiers: vec![],
                internet_exposed: None,
                contains_sensitive_data: None,
                metadata: metadata(&[
                    ("source_resource_type", Some("gcp_project")),
                    ("lifecycle_state", Some(state)),
                    ("numeric_resource_name", Some(project_number)),
                ]),
            },
            &pointer,
        );
        if let Some(child) = &project_key {
            collector.relation(&parent_key, child, RelationKind::Contains);
        }
    }
    Ok(())
}

fn parse_gcp_folders(
    document: &Value,
    collector: &mut Collector<'_>,
) -> Result<(), DiscoveryError> {
    let folders = document
        .get("folders")
        .and_then(Value::as_array)
        .ok_or_else(|| {
            DiscoveryError::Connector("Google Resource Manager folders field is malformed".into())
        })?;
    for (index, folder) in folders.iter().enumerate() {
        let pointer = format!("/folders/{index}");
        if !collector.count_record(&pointer) {
            break;
        }
        let name = string_at(folder, &["name"])
            .filter(|value| valid_gcp_numeric_name(value, "folders/"))
            .ok_or_else(|| {
                DiscoveryError::Connector(format!(
                    "Google folder at {pointer} omitted its numeric resource name"
                ))
            })?;
        let folder_id = name.trim_start_matches("folders/");
        let parent = string_at(folder, &["parent"]).ok_or_else(|| {
            DiscoveryError::Connector(format!(
                "Google folder at {pointer} omitted its exact hierarchy parent"
            ))
        })?;
        let state = string_at(folder, &["state"])
            .filter(|value| *value == "ACTIVE")
            .ok_or_else(|| {
                DiscoveryError::Connector(format!(
                    "Google folder at {pointer} is not in the ACTIVE state"
                ))
            })?;
        let parent_key = gcp_parent_asset(parent, &pointer, collector)?;
        let folder_key = collector.asset(
            AssetDraft {
                kind: AssetKind::Other,
                name: string_at(folder, &["displayName"]).unwrap_or(folder_id),
                provider: Some("gcp"),
                region: None,
                namespace: "gcp_folder_id",
                native_id: folder_id,
                additional_identifiers: vec![],
                internet_exposed: None,
                contains_sensitive_data: None,
                metadata: metadata(&[
                    ("source_resource_type", Some("gcp_folder")),
                    ("lifecycle_state", Some(state)),
                    ("numeric_resource_name", Some(name)),
                ]),
            },
            &pointer,
        );
        if let Some(child) = &folder_key {
            collector.relation(&parent_key, child, RelationKind::Contains);
        }
    }
    Ok(())
}

fn gcp_parent_asset(
    parent: &str,
    pointer: &str,
    collector: &mut Collector<'_>,
) -> Result<String, DiscoveryError> {
    if let Some(organization_id) = parent
        .strip_prefix("organizations/")
        .filter(|value| valid_gcp_numeric_id(value))
    {
        return collector
            .asset(
                AssetDraft {
                    kind: AssetKind::CloudOrganization,
                    name: organization_id,
                    provider: Some("gcp"),
                    region: None,
                    namespace: "gcp_organization_id",
                    native_id: organization_id,
                    additional_identifiers: vec![],
                    internet_exposed: None,
                    contains_sensitive_data: None,
                    metadata: metadata(&[("source_resource_type", Some("gcp_organization"))]),
                },
                pointer,
            )
            .ok_or_else(|| {
                DiscoveryError::Connector(format!(
                    "Google hierarchy parent at {pointer} could not be represented"
                ))
            });
    }
    if let Some(folder_id) = parent
        .strip_prefix("folders/")
        .filter(|value| valid_gcp_numeric_id(value))
    {
        return collector
            .asset(
                AssetDraft {
                    kind: AssetKind::Other,
                    name: folder_id,
                    provider: Some("gcp"),
                    region: None,
                    namespace: "gcp_folder_id",
                    native_id: folder_id,
                    additional_identifiers: vec![],
                    internet_exposed: None,
                    contains_sensitive_data: None,
                    metadata: metadata(&[("source_resource_type", Some("gcp_folder"))]),
                },
                pointer,
            )
            .ok_or_else(|| {
                DiscoveryError::Connector(format!(
                    "Google hierarchy parent at {pointer} could not be represented"
                ))
            });
    }
    Err(DiscoveryError::Connector(format!(
        "Google hierarchy parent at {pointer} is outside the organization/folder contract"
    )))
}

fn valid_gcp_numeric_name(value: &str, prefix: &str) -> bool {
    value.strip_prefix(prefix).is_some_and(valid_gcp_numeric_id)
}

fn valid_gcp_numeric_id(value: &str) -> bool {
    !value.is_empty() && value.len() <= 32 && value.bytes().all(|byte| byte.is_ascii_digit())
}

fn parse_microsoft365(
    document: &Value,
    collector: &mut Collector<'_>,
) -> Result<(), DiscoveryError> {
    let values = array_at(document, &["value"]).ok_or_else(|| {
        DiscoveryError::Connector("Microsoft Graph response omitted its value array".into())
    })?;
    for (index, record) in values.iter().enumerate() {
        let pointer = format!("/value/{index}");
        if !collector.count_record(&pointer) {
            break;
        }
        let Some(id) = string_at(record, &["id"]).filter(|value| looks_like_uuid(value)) else {
            collector.notice(format!(
                "ignored Microsoft Graph record without an immutable object ID at {pointer}"
            ));
            continue;
        };
        if let Some(user_principal_name) = string_at(record, &["userPrincipalName"]) {
            collector.asset(
                AssetDraft {
                    kind: AssetKind::Identity,
                    name: string_at(record, &["displayName"]).unwrap_or(user_principal_name),
                    provider: Some("microsoft365"),
                    region: None,
                    namespace: "microsoft_graph_object_id",
                    native_id: id,
                    additional_identifiers: vec![],
                    internet_exposed: None,
                    contains_sensitive_data: Some(true),
                    metadata: metadata(&[
                        ("source_resource_type", Some("microsoft_graph_user")),
                        ("user_type", string_at(record, &["userType"])),
                    ]),
                },
                &pointer,
            );
        } else {
            collector.asset(
                AssetDraft {
                    kind: AssetKind::Tenant,
                    name: string_at(record, &["displayName"]).unwrap_or(id),
                    provider: Some("microsoft365"),
                    region: None,
                    namespace: "microsoft_tenant_id",
                    native_id: id,
                    additional_identifiers: vec![],
                    internet_exposed: None,
                    contains_sensitive_data: None,
                    metadata: metadata(&[(
                        "source_resource_type",
                        Some("microsoft_graph_organization"),
                    )]),
                },
                &pointer,
            );
        }
    }
    Ok(())
}

fn mismatch(provider: &str) -> Result<(), DiscoveryError> {
    Err(DiscoveryError::Connector(format!(
        "{provider} parser profile does not match the source kind"
    )))
}

fn looks_like_uuid(value: &str) -> bool {
    uuid::Uuid::parse_str(value).is_ok()
}

fn azure_resource_group(resource_id: &str) -> Option<&str> {
    let components = resource_id.split('/').collect::<Vec<_>>();
    components.windows(2).find_map(|pair| {
        pair[0]
            .eq_ignore_ascii_case("resourceGroups")
            .then_some(pair[1])
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn parse_accounts(document: Value) -> crate::discovery::ConnectorDiscovery {
        let mut collector =
            Collector::new("artifact-1", ParserProfile::AwsOrganizationsListAccounts);
        parse_json(
            ParserProfile::AwsOrganizationsListAccounts,
            &SourceKind::AwsOrganization,
            &document,
            &mut collector,
        )
        .expect("ListAccounts page parses");
        collector.finish(chrono::Utc::now())
    }

    #[test]
    fn aws_organizations_json_page_yields_accounts_without_email() {
        let discovery = parse_accounts(serde_json::json!({
            "Accounts": [
                {
                    "Arn": "arn:aws:organizations::111111111111:account/o-example/111111111111",
                    "Email": "management@example.test",
                    "Id": "111111111111",
                    "JoinedMethod": "INVITED",
                    "JoinedTimestamp": 1.6E9,
                    "Name": "Management",
                    "State": "ACTIVE",
                    "Status": "ACTIVE"
                },
                {
                    "Arn": "arn:aws:organizations::111111111111:account/o-example/222222222222",
                    "Email": "closed@example.test",
                    "Id": "222222222222",
                    "JoinedMethod": "CREATED",
                    "JoinedTimestamp": 1.7E9,
                    "Name": "",
                    "State": "PENDING_CLOSURE",
                    "Status": "PENDING_CLOSURE"
                }
            ],
            "NextToken": "opaque"
        }));
        let accounts = discovery
            .assets
            .iter()
            .map(|asset| {
                (
                    asset.stable_identifier.value.as_str(),
                    asset.name.as_str(),
                    asset.metadata.get("account_status").and_then(Value::as_str),
                )
            })
            .collect::<Vec<_>>();
        assert_eq!(
            accounts,
            vec![
                ("111111111111", "Management", Some("ACTIVE")),
                ("222222222222", "222222222222", Some("PENDING_CLOSURE")),
            ]
        );
        assert!(
            !serde_json::to_string(&discovery.assets)
                .unwrap()
                .contains("@example.test")
        );
    }

    #[test]
    fn aws_organizations_malformed_account_identity_is_skipped_with_a_notice() {
        let discovery = parse_accounts(serde_json::json!({
            "Accounts": [
                {
                    "Arn": "arn:aws:organizations::111111111111:account/o-example/999999999999",
                    "Id": "111111111111",
                    "Name": "Mismatched ARN",
                    "State": "ACTIVE"
                },
                {
                    "Arn": "arn:aws:organizations::111111111111:account/o-example/1234",
                    "Id": "1234",
                    "Name": "Short ID",
                    "State": "ACTIVE"
                }
            ]
        }));
        assert!(discovery.assets.is_empty());
        assert_eq!(
            discovery
                .notices
                .iter()
                .filter(|notice| notice.contains("ignored malformed AWS account identity"))
                .count(),
            2
        );
    }

    #[test]
    fn aws_organizations_response_without_accounts_array_is_rejected() {
        let mut collector =
            Collector::new("artifact-1", ParserProfile::AwsOrganizationsListAccounts);
        let error = parse_json(
            ParserProfile::AwsOrganizationsListAccounts,
            &SourceKind::AwsOrganization,
            &serde_json::json!({ "accounts": "not-a-list" }),
            &mut collector,
        )
        .expect_err("a page without Accounts is outside the response contract");
        assert!(
            matches!(error, DiscoveryError::Connector(message) if message.contains("Accounts array"))
        );
    }
}
