use super::{
    AssetDraft, Collector, ParserProfile, array_at, bool_at, get_ci, get_path_ci, id,
    is_secret_like_key, metadata, object, relation_kind, string_at,
};
use crate::discovery::DiscoveryError;
use crate::domain::{AssetIdentifier, AssetKind, RelationKind, SourceKind};
use serde_json::{Map, Value};
use std::collections::BTreeMap;

pub(super) fn parse(
    profile: ParserProfile,
    source_kind: &SourceKind,
    document: &Value,
    collector: &mut Collector<'_>,
) -> Result<(), DiscoveryError> {
    match (profile, source_kind) {
        (ParserProfile::GitManifest, SourceKind::GitRepository) => parse_git(document, collector),
        (ParserProfile::TerraformState, SourceKind::TerraformState) => {
            parse_terraform(document, collector)
        }
        (ParserProfile::KubernetesManifest, SourceKind::KubernetesCluster) => {
            parse_kubernetes(document, collector)
        }
        (ParserProfile::ContainerRegistryManifest, SourceKind::ContainerRegistry) => {
            parse_container_registries(document, collector)
        }
        (ParserProfile::FileSystemManifest, SourceKind::FileSystem) => {
            parse_filesystems(document, collector)
        }
        (ParserProfile::UserDeclaredManifest, SourceKind::UserDeclared) => {
            parse_user_declared(document, collector)
        }
        _ => {
            return Err(DiscoveryError::Connector(
                "local snapshot parser profile does not match the source kind".into(),
            ));
        }
    }
    Ok(())
}

fn parse_git(document: &Value, collector: &mut Collector<'_>) {
    let repositories = array_at(document, &["repositories", "repos"])
        .map(|values| values.iter().collect::<Vec<_>>())
        .unwrap_or_else(|| vec![document]);
    let mut keys = BTreeMap::new();
    for (index, repository) in repositories.into_iter().enumerate() {
        let pointer = format!("/repositories/{index}");
        if !collector.count_record(&pointer) {
            break;
        }
        let Some(provider) =
            string_at(repository, &["provider", "forge"]).map(|value| value.to_ascii_lowercase())
        else {
            collector.notice(format!(
                "ignored repository without an explicit provider at {pointer}"
            ));
            continue;
        };
        let Some(repository_id) = string_at(
            repository,
            &["repository_id", "node_id", "project_id", "native_id"],
        ) else {
            collector.notice(format!(
                "ignored repository without a provider-native repository identifier at {pointer}; a mutable URL was not used as identity"
            ));
            continue;
        };
        let namespace = match provider.as_str() {
            "github" => "github_repository_id",
            "gitlab" => "gitlab_project_id",
            "bitbucket" => "bitbucket_repository_uuid",
            "azure_devops" | "azure-devops" => "azure_devops_repository_id",
            _ => "git_repository_id",
        };
        let display_name = string_at(repository, &["full_name", "path_with_namespace", "name"])
            .unwrap_or(repository_id);
        if let Some(observation_key) = collector.asset(
            AssetDraft {
                kind: AssetKind::Repository,
                name: display_name,
                provider: Some(&provider),
                region: None,
                namespace,
                native_id: repository_id,
                additional_identifiers: vec![],
                internet_exposed: bool_at(repository, &["public", "internet_exposed"]),
                contains_sensitive_data: bool_at(repository, &["contains_sensitive_data"]),
                metadata: metadata(&[
                    ("default_branch", string_at(repository, &["default_branch"])),
                    ("source_resource_type", Some("git_repository")),
                ]),
            },
            &pointer,
        ) && let Some(key) = string_at(repository, &["key", "observation_key"])
        {
            keys.insert(key.to_owned(), observation_key);
        }
    }
    parse_explicit_relations(document, &keys, collector);
}

fn parse_terraform(document: &Value, collector: &mut Collector<'_>) {
    let Some(lineage) = string_at(document, &["lineage", "state.lineage"]) else {
        collector.notice(
            "Terraform snapshot has no state lineage; no path- or filename-derived identity was invented",
        );
        return;
    };
    let state_name = string_at(document, &["name", "workspace", "terraform_version"])
        .unwrap_or("Terraform state");
    let Some(state_key) = collector.asset(
        AssetDraft {
            kind: AssetKind::IacProject,
            name: state_name,
            provider: Some("terraform"),
            region: None,
            namespace: "terraform_state_lineage",
            native_id: lineage,
            additional_identifiers: vec![],
            internet_exposed: None,
            contains_sensitive_data: None,
            metadata: metadata(&[
                (
                    "terraform_version",
                    string_at(document, &["terraform_version"]),
                ),
                (
                    "state_serial",
                    get_path_ci(document, "serial")
                        .and_then(Value::as_u64)
                        .map(|value| value.to_string())
                        .as_deref(),
                ),
            ]),
        },
        "/",
    ) else {
        return;
    };

    let Some(resources) = array_at(document, &["resources", "state.resources"]) else {
        return;
    };
    for (index, resource) in resources.iter().enumerate() {
        let pointer = format!("/resources/{index}");
        if !collector.count_record(&pointer) {
            break;
        }
        let Some(resource_type) =
            string_at(resource, &["type"]).filter(|value| is_terraform_coordinate(value))
        else {
            collector.notice(format!(
                "ignored Terraform resource without a bounded type at {pointer}"
            ));
            continue;
        };
        let Some(name) =
            string_at(resource, &["name"]).filter(|value| is_terraform_coordinate(value))
        else {
            collector.notice(format!(
                "ignored Terraform resource without a bounded name at {pointer}"
            ));
            continue;
        };
        let module = string_at(resource, &["module"]).filter(|value| {
            value.len() <= 512
                && value.chars().all(|character| {
                    character.is_ascii_alphanumeric() || "._-[]\"".contains(character)
                })
        });
        let address = string_at(resource, &["address"])
            .filter(|value| value.len() <= 1_024 && !value.chars().any(char::is_control))
            .map(str::to_owned)
            .unwrap_or_else(|| {
                format!(
                    "{}{}.{name}",
                    module.map(|value| format!("{value}.")).unwrap_or_default(),
                    resource_type
                )
            });
        let native_id = format!("{lineage}:{address}");
        let provider = terraform_provider(resource).unwrap_or("terraform");
        if let Some(resource_key) = collector.asset(
            AssetDraft {
                kind: AssetKind::CloudResource,
                name: &address,
                provider: Some(provider),
                region: None,
                namespace: "terraform_state_address",
                native_id: &native_id,
                additional_identifiers: vec![id("terraform_state_lineage", lineage)],
                internet_exposed: None,
                contains_sensitive_data: None,
                metadata: metadata(&[
                    ("terraform_resource_type", Some(resource_type)),
                    ("terraform_module", module),
                    ("terraform_mode", string_at(resource, &["mode"])),
                ]),
            },
            &pointer,
        ) {
            collector.relation(&state_key, &resource_key, RelationKind::Contains);
        }
    }
}

fn parse_kubernetes(document: &Value, collector: &mut Collector<'_>) {
    let cluster = get_path_ci(document, "cluster").unwrap_or(document);
    let cluster_uid = string_at(
        cluster,
        &[
            "uid",
            "cluster_uid",
            "metadata.uid",
            "kube_system_namespace_uid",
        ],
    )
    .or_else(|| string_at(document, &["cluster_uid", "kube_system_namespace_uid"]));
    let cluster_key = cluster_uid.and_then(|native_id| {
        collector.asset(
            AssetDraft {
                kind: AssetKind::KubernetesCluster,
                name: string_at(cluster, &["name", "display_name", "metadata.name"])
                    .unwrap_or(native_id),
                provider: Some(
                    string_at(cluster, &["provider", "distribution"]).unwrap_or("kubernetes"),
                ),
                region: string_at(cluster, &["region", "location"]),
                namespace: "kubernetes_cluster_uid",
                native_id,
                additional_identifiers: vec![],
                internet_exposed: bool_at(cluster, &["internet_exposed", "public_endpoint"]),
                contains_sensitive_data: None,
                metadata: metadata(&[
                    (
                        "kubernetes_version",
                        string_at(cluster, &["version", "kubernetes_version"]),
                    ),
                    ("source_resource_type", Some("kubernetes_cluster")),
                ]),
            },
            "/cluster",
        )
    });
    if cluster_key.is_none() {
        collector.notice(
            "Kubernetes snapshot has no provider-issued cluster UID; no server URL or display-name identity was invented",
        );
    }

    let Some(items) = array_at(document, &["items", "resources", "objects"]) else {
        return;
    };
    for (index, item) in items.iter().enumerate() {
        let pointer = format!("/items/{index}");
        if !collector.count_record(&pointer) {
            break;
        }
        let Some(uid) = string_at(item, &["metadata.uid", "uid"]) else {
            collector.notice(format!(
                "ignored Kubernetes object without metadata.uid at {pointer}"
            ));
            continue;
        };
        let kind = string_at(item, &["kind"]).unwrap_or("KubernetesObject");
        let name = string_at(item, &["metadata.name", "name"]).unwrap_or(uid);
        let namespace = string_at(item, &["metadata.namespace", "namespace"]);
        let display_name = namespace
            .map(|namespace| format!("{namespace}/{name}"))
            .unwrap_or_else(|| name.to_owned());
        let asset_kind = match kind.to_ascii_lowercase().as_str() {
            "service" | "ingress" | "gateway" => AssetKind::WebService,
            _ => AssetKind::Other,
        };
        if let Some(item_key) = collector.asset(
            AssetDraft {
                kind: asset_kind,
                name: &display_name,
                provider: Some("kubernetes"),
                region: None,
                namespace: "kubernetes_object_uid",
                native_id: uid,
                additional_identifiers: cluster_uid
                    .map(|value| vec![id("kubernetes_cluster_uid", value)])
                    .unwrap_or_default(),
                internet_exposed: bool_at(item, &["internet_exposed", "public"]),
                contains_sensitive_data: bool_at(item, &["contains_sensitive_data"]),
                metadata: metadata(&[
                    ("kubernetes_kind", Some(kind)),
                    ("kubernetes_namespace", namespace),
                ]),
            },
            &pointer,
        ) && let Some(cluster_key) = &cluster_key
        {
            collector.relation(cluster_key, &item_key, RelationKind::Contains);
        }
    }
}

fn parse_container_registries(document: &Value, collector: &mut Collector<'_>) {
    let registries = array_at(document, &["registries"])
        .map(|values| values.iter().collect::<Vec<_>>())
        .unwrap_or_else(|| vec![get_path_ci(document, "registry").unwrap_or(document)]);
    for (registry_index, registry) in registries.into_iter().enumerate() {
        let pointer = format!("/registries/{registry_index}");
        if !collector.count_record(&pointer) {
            break;
        }
        let Some(registry_id) =
            string_at(registry, &["registry_id", "native_id", "hostname", "host"])
        else {
            collector.notice(format!(
                "ignored container registry without a provider-native registry ID or hostname at {pointer}"
            ));
            continue;
        };
        let provider = string_at(registry, &["provider"]).unwrap_or("oci");
        let Some(registry_key) = collector.asset(
            AssetDraft {
                kind: AssetKind::ContainerRegistry,
                name: string_at(registry, &["name", "hostname", "host"]).unwrap_or(registry_id),
                provider: Some(provider),
                region: string_at(registry, &["region", "location"]),
                namespace: "oci_registry_id",
                native_id: registry_id,
                additional_identifiers: vec![],
                internet_exposed: bool_at(registry, &["internet_exposed", "public"]),
                contains_sensitive_data: None,
                metadata: metadata(&[("source_resource_type", Some("container_registry"))]),
            },
            &pointer,
        ) else {
            continue;
        };
        let images = get_path_ci(registry, "images")
            .and_then(Value::as_array)
            .or_else(|| {
                if registries_were_nested(document) {
                    None
                } else {
                    get_path_ci(document, "images").and_then(Value::as_array)
                }
            });
        let Some(images) = images else {
            continue;
        };
        for (image_index, image) in images.iter().enumerate() {
            let image_pointer = format!("{pointer}/images/{image_index}");
            if !collector.count_record(&image_pointer) {
                break;
            }
            let Some(digest) = string_at(image, &["digest", "manifest_digest"])
                .filter(|value| valid_oci_digest(value))
            else {
                collector.notice(format!(
                    "ignored container image without a content digest at {image_pointer}; a mutable tag was not used as identity"
                ));
                continue;
            };
            let Some(repository) = string_at(image, &["repository", "name"])
                .filter(|value| valid_repository_name(value))
            else {
                collector.notice(format!(
                    "ignored container image without a bounded repository name at {image_pointer}"
                ));
                continue;
            };
            let native_id = format!("{registry_id}/{repository}@{}", digest.to_ascii_lowercase());
            let display_name = string_at(image, &["display_name"])
                .map(str::to_owned)
                .unwrap_or_else(|| {
                    string_at(image, &["tag"])
                        .map(|tag| format!("{repository}:{tag}"))
                        .unwrap_or_else(|| format!("{repository}@{digest}"))
                });
            if let Some(image_key) = collector.asset(
                AssetDraft {
                    kind: AssetKind::ContainerImage,
                    name: &display_name,
                    provider: Some("oci"),
                    region: None,
                    namespace: "oci_image_reference",
                    native_id: &native_id,
                    additional_identifiers: vec![id("oci_digest", digest)],
                    internet_exposed: None,
                    contains_sensitive_data: bool_at(image, &["contains_sensitive_data"]),
                    metadata: metadata(&[
                        ("image_repository", Some(repository)),
                        ("image_tag_observed", string_at(image, &["tag"])),
                    ]),
                },
                &image_pointer,
            ) {
                collector.relation(&registry_key, &image_key, RelationKind::Contains);
            }
        }
    }
}

fn parse_filesystems(document: &Value, collector: &mut Collector<'_>) {
    let roots = array_at(document, &["roots", "filesystems", "volumes"])
        .map(|values| values.iter().collect::<Vec<_>>())
        .unwrap_or_else(|| vec![document]);
    for (index, root) in roots.into_iter().enumerate() {
        let pointer = format!("/roots/{index}");
        if !collector.count_record(&pointer) {
            break;
        }
        let Some(filesystem_id) = string_at(
            root,
            &["filesystem_id", "volume_id", "filesystem_uuid", "native_id"],
        ) else {
            collector.notice(format!(
                "ignored filesystem root without a volume/filesystem identifier at {pointer}; a mutable local path was not used as identity"
            ));
            continue;
        };
        collector.asset(
            AssetDraft {
                kind: AssetKind::FileSystem,
                name: string_at(root, &["label", "name"]).unwrap_or(filesystem_id),
                provider: Some("local"),
                region: None,
                namespace: "filesystem_id",
                native_id: filesystem_id,
                additional_identifiers: vec![],
                internet_exposed: Some(false),
                contains_sensitive_data: bool_at(root, &["contains_sensitive_data"]),
                metadata: metadata(&[
                    (
                        "filesystem_type",
                        string_at(root, &["filesystem_type", "type"]),
                    ),
                    ("source_resource_type", Some("filesystem_root")),
                ]),
            },
            &pointer,
        );
    }
}

fn parse_user_declared(document: &Value, collector: &mut Collector<'_>) {
    let Some(assets) = array_at(document, &["assets"]) else {
        collector.notice("user-declared snapshot contains no assets array");
        return;
    };
    let mut keys = BTreeMap::new();
    for (index, asset) in assets.iter().enumerate() {
        let pointer = format!("/assets/{index}");
        if !collector.count_record(&pointer) {
            break;
        }
        let Some(asset_object) = object(asset) else {
            collector.notice(format!("ignored non-object declared asset at {pointer}"));
            continue;
        };
        let Some(kind) = string_at(asset, &["kind"]).and_then(asset_kind) else {
            collector.notice(format!(
                "ignored declared asset with an unsupported kind at {pointer}"
            ));
            continue;
        };
        let Some(namespace) = string_at(
            asset,
            &["stable_identifier.namespace", "native_id_namespace"],
        ) else {
            collector.notice(format!(
                "ignored declared asset without a stable identifier namespace at {pointer}"
            ));
            continue;
        };
        let Some(native_id) = string_at(
            asset,
            &["stable_identifier.value", "native_id", "provider_native_id"],
        ) else {
            collector.notice(format!(
                "ignored declared asset without a stable identifier value at {pointer}"
            ));
            continue;
        };
        if is_secret_like_key(namespace) {
            collector.notice(format!(
                "ignored declared asset whose identity namespace is secret-like at {pointer}"
            ));
            continue;
        }
        let name = string_at(asset, &["name", "display_name"]).unwrap_or(native_id);
        let additional_identifiers = declared_identifiers(asset_object);
        if let Some(observation_key) = collector.asset(
            AssetDraft {
                kind,
                name,
                provider: string_at(asset, &["provider"]),
                region: string_at(asset, &["region", "location"]),
                namespace,
                native_id,
                additional_identifiers,
                internet_exposed: bool_at(asset, &["internet_exposed"]),
                contains_sensitive_data: bool_at(asset, &["contains_sensitive_data"]),
                metadata: metadata(&[
                    ("environment", string_at(asset, &["environment"])),
                    ("source_resource_type", Some("user_declared_asset")),
                ]),
            },
            &pointer,
        ) && let Some(key) =
            string_at(asset, &["key", "observation_key"]).filter(|key| valid_manifest_key(key))
        {
            keys.insert(key.into(), observation_key);
        }
    }
    parse_explicit_relations(document, &keys, collector);
}

fn parse_explicit_relations(
    document: &Value,
    keys: &BTreeMap<String, String>,
    collector: &mut Collector<'_>,
) {
    let Some(relations) = get_path_ci(document, "relations").and_then(Value::as_array) else {
        return;
    };
    for (index, relation) in relations.iter().enumerate() {
        let pointer = format!("/relations/{index}");
        if !collector.count_record(&pointer) {
            break;
        }
        let Some(from) = string_at(relation, &["from"]).and_then(|key| keys.get(key)) else {
            collector.notice(format!(
                "ignored relation with an unknown from endpoint at {pointer}"
            ));
            continue;
        };
        let Some(to) = string_at(relation, &["to"]).and_then(|key| keys.get(key)) else {
            collector.notice(format!(
                "ignored relation with an unknown to endpoint at {pointer}"
            ));
            continue;
        };
        let Some(kind) = string_at(relation, &["kind"]).and_then(relation_kind) else {
            collector.notice(format!(
                "ignored relation with an unsupported kind at {pointer}"
            ));
            continue;
        };
        collector.relation(from, to, kind);
    }
}

fn terraform_provider(resource: &Value) -> Option<&str> {
    let value = string_at(resource, &["provider", "provider_name"])?;
    if value.contains("registry.terraform.io/hashicorp/aws") {
        Some("aws")
    } else if value.contains("registry.terraform.io/hashicorp/azurerm") {
        Some("azure")
    } else if value.contains("registry.terraform.io/hashicorp/google") {
        Some("gcp")
    } else if value.len() <= 256 && !value.chars().any(char::is_control) {
        Some(value)
    } else {
        None
    }
}

fn is_terraform_coordinate(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 256
        && value
            .chars()
            .all(|character| character.is_ascii_alphanumeric() || "_-".contains(character))
}

fn registries_were_nested(document: &Value) -> bool {
    get_path_ci(document, "registries")
        .and_then(Value::as_array)
        .is_some()
}

fn valid_oci_digest(value: &str) -> bool {
    let Some((algorithm, digest)) = value.split_once(':') else {
        return false;
    };
    algorithm == "sha256"
        && digest.len() == 64
        && digest.bytes().all(|byte| byte.is_ascii_hexdigit())
}

fn valid_repository_name(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 512
        && !value.starts_with('/')
        && !value.contains("..")
        && value
            .chars()
            .all(|character| character.is_ascii_alphanumeric() || "._/-".contains(character))
}

fn asset_kind(value: &str) -> Option<AssetKind> {
    Some(match value.trim().to_ascii_lowercase().as_str() {
        "cloud_organization" => AssetKind::CloudOrganization,
        "cloud_account" => AssetKind::CloudAccount,
        "subscription" => AssetKind::Subscription,
        "project" => AssetKind::Project,
        "tenant" => AssetKind::Tenant,
        "domain" => AssetKind::Domain,
        "ip_address" => AssetKind::IpAddress,
        "host" => AssetKind::Host,
        "web_service" => AssetKind::WebService,
        "cloud_resource" => AssetKind::CloudResource,
        "identity" => AssetKind::Identity,
        "repository" => AssetKind::Repository,
        "file_system" => AssetKind::FileSystem,
        "iac_project" => AssetKind::IacProject,
        "container_image" => AssetKind::ContainerImage,
        "container_registry" => AssetKind::ContainerRegistry,
        "kubernetes_cluster" => AssetKind::KubernetesCluster,
        "other" => AssetKind::Other,
        _ => return None,
    })
}

fn declared_identifiers(object: &Map<String, Value>) -> Vec<AssetIdentifier> {
    let Some(values) = get_ci(object, "additional_identifiers").and_then(Value::as_array) else {
        return Vec::new();
    };
    values
        .iter()
        .filter_map(|value| {
            let namespace = string_at(value, &["namespace"])?;
            let value = string_at(value, &["value"])?;
            (!is_secret_like_key(namespace)).then(|| id(namespace, value))
        })
        .collect()
}

fn valid_manifest_key(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 256
        && value
            .chars()
            .all(|character| character.is_ascii_alphanumeric() || "._:-".contains(character))
}
