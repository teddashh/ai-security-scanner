//! Parsers for the exact provider-native inventory operations issued by the
//! live discovery client. Network code never calls these functions directly;
//! only SHA-256-verified connector artifacts reach this module.

use super::{AssetDraft, Collector, ParserProfile, array_at, metadata, string_at};
use crate::discovery::DiscoveryError;
use crate::domain::{AssetKind, RelationKind, SourceKind, valid_gcp_project_id};
use quick_xml::Reader;
use quick_xml::events::Event;
use serde_json::Value;

const MAX_XML_EVENTS: usize = 50_000;
const MAX_XML_DEPTH: usize = 64;
const MAX_FIELD_BYTES: usize = 8 * 1024;

#[derive(Default)]
struct AwsAccount {
    id: String,
    arn: String,
    name: String,
    email: String,
    status: String,
}

pub(super) fn parse_aws_organizations(
    bytes: &[u8],
    source_kind: &SourceKind,
    collector: &mut Collector<'_>,
) -> Result<(), DiscoveryError> {
    if !matches!(source_kind, SourceKind::AwsOrganization) {
        return Err(DiscoveryError::Connector(
            "AWS Organizations parser profile does not match the source kind".into(),
        ));
    }
    let mut reader = Reader::from_reader(bytes);
    reader.config_mut().trim_text(true);
    reader.config_mut().check_end_names = true;
    reader.config_mut().expand_empty_elements = true;
    let mut buffer = Vec::new();
    let mut stack = Vec::<String>::new();
    let mut current: Option<AwsAccount> = None;
    let mut event_count = 0_usize;
    let mut account_index = 0_usize;

    loop {
        event_count += 1;
        if event_count > MAX_XML_EVENTS {
            return Err(DiscoveryError::Connector(
                "AWS Organizations XML exceeded the event limit".into(),
            ));
        }
        match reader.read_event_into(&mut buffer) {
            Ok(Event::Eof) => break,
            Ok(Event::DocType(_)) | Ok(Event::GeneralRef(_)) => {
                return Err(DiscoveryError::Connector(
                    "AWS Organizations XML containing a DTD or entity reference was rejected"
                        .into(),
                ));
            }
            Ok(Event::Start(start)) => {
                if stack.len() >= MAX_XML_DEPTH {
                    return Err(DiscoveryError::Connector(
                        "AWS Organizations XML exceeded the nesting limit".into(),
                    ));
                }
                let name = std::str::from_utf8(start.local_name().as_ref())
                    .map_err(|_| {
                        DiscoveryError::Connector(
                            "AWS Organizations XML contains a non-UTF-8 element".into(),
                        )
                    })?
                    .to_owned();
                if name == "member" && stack.last().is_some_and(|parent| parent == "Accounts") {
                    if current.is_some() {
                        return Err(DiscoveryError::Connector(
                            "AWS Organizations XML contains nested account records".into(),
                        ));
                    }
                    current = Some(AwsAccount::default());
                }
                stack.push(name);
            }
            Ok(Event::End(end)) => {
                let local_name = end.local_name();
                let name = std::str::from_utf8(local_name.as_ref()).map_err(|_| {
                    DiscoveryError::Connector(
                        "AWS Organizations XML contains a non-UTF-8 closing element".into(),
                    )
                })?;
                if name == "member"
                    && stack
                        .last()
                        .is_some_and(|current_name| current_name == "member")
                    && current.is_some()
                {
                    let account = current.take().expect("checked above");
                    account_index += 1;
                    let pointer = format!("/ListAccountsResponse/Accounts/member[{account_index}]");
                    if !collector.count_record(&pointer) {
                        break;
                    }
                    let valid_account_id = account.id.len() == 12
                        && account.id.bytes().all(|byte| byte.is_ascii_digit());
                    let valid_account_arn = account.arn.starts_with("arn:aws:organizations::")
                        && account.arn.contains(":account/")
                        && account.arn.ends_with(&format!("/{}", account.id));
                    if valid_account_id && valid_account_arn {
                        collector.asset(
                            AssetDraft {
                                kind: AssetKind::CloudAccount,
                                name: if account.name.trim().is_empty() {
                                    &account.id
                                } else {
                                    &account.name
                                },
                                provider: Some("aws"),
                                region: None,
                                namespace: "aws_account_id",
                                native_id: &account.id,
                                additional_identifiers: vec![],
                                internet_exposed: None,
                                contains_sensitive_data: None,
                                metadata: metadata(&[
                                    ("source_resource_type", Some("aws_organizations_account")),
                                    ("account_status", nonempty(&account.status)),
                                ]),
                            },
                            &pointer,
                        );
                    } else {
                        collector.notice(format!(
                            "ignored malformed AWS account identity at {pointer}; raw XML remains preserved"
                        ));
                    }
                    // Email is intentionally never copied into canonical metadata.
                    let _ = account.email;
                }
                stack.pop();
            }
            Ok(Event::Text(text)) if current.is_some() => {
                let raw_text: &[u8] = text.as_ref();
                if raw_text.len() > MAX_FIELD_BYTES {
                    return Err(DiscoveryError::Connector(
                        "AWS Organizations XML field exceeded the limit".into(),
                    ));
                }
                let Some(field) = stack.last().map(String::as_str) else {
                    buffer.clear();
                    continue;
                };
                if !matches!(field, "Id" | "Arn" | "Name" | "Email" | "Status" | "State") {
                    buffer.clear();
                    continue;
                }
                let decoded = text.decode().map_err(|_| {
                    DiscoveryError::Connector(
                        "AWS Organizations XML text could not be decoded".into(),
                    )
                })?;
                let value = quick_xml::escape::unescape(&decoded).map_err(|_| {
                    DiscoveryError::Connector(
                        "AWS Organizations XML used an unsupported entity".into(),
                    )
                })?;
                let account = current.as_mut().expect("checked above");
                match field {
                    "Id" => account.id.push_str(&value),
                    "Arn" => account.arn.push_str(&value),
                    "Name" => account.name.push_str(&value),
                    "Email" => account.email.push_str(&value),
                    "Status" | "State" => account.status.push_str(&value),
                    _ => {}
                }
            }
            Ok(Event::CData(_)) => {
                return Err(DiscoveryError::Connector(
                    "AWS Organizations XML CDATA fields were rejected".into(),
                ));
            }
            Ok(_) => {}
            Err(error) => {
                return Err(DiscoveryError::Connector(format!(
                    "AWS Organizations XML is malformed at byte {}: {error}",
                    reader.error_position()
                )));
            }
        }
        buffer.clear();
    }
    if current.is_some() {
        return Err(DiscoveryError::Connector(
            "AWS Organizations XML ended inside an account record".into(),
        ));
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

fn nonempty(value: &str) -> Option<&str> {
    (!value.trim().is_empty()).then_some(value.trim())
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
