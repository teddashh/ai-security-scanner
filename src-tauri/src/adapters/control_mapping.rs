//! Versioned, allowlisted evidence-to-control relationships.
//!
//! The embedded catalog is project-authored metadata. A match never means a
//! control is implemented, effective, certified, or compliant.

use crate::domain::ControlReference;
use crate::error::{AppError, AppResult};
use serde::Deserialize;
use std::collections::{BTreeMap, BTreeSet};
use std::sync::OnceLock;

const CATALOG_JSON: &str = include_str!("../../../mappings/control-mappings.json");
const MAX_CONTROLS: usize = 1_024;
const MAX_ENTRIES: usize = 4_096;
const MAX_REFERENCES_PER_ENTRY: usize = 8;
const MAX_LOOKUP_RESULTS: usize = 32;

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct MappingCatalog {
    schema_version: String,
    mapping_version: String,
    relationship: String,
    disclaimer: String,
    sources: Vec<FrameworkSource>,
    controls: Vec<ControlDefinition>,
    entries: Vec<MappingEntry>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct FrameworkSource {
    framework: String,
    framework_version: String,
    url: String,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
struct ControlDefinition {
    key: String,
    framework: String,
    framework_version: String,
    control_id: String,
    title: String,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct MappingEntry {
    engine_id: String,
    match_kind: MatchKind,
    source_rule: String,
    #[serde(default)]
    aidefend_applicability: Option<AidefendApplicability>,
    controls: Vec<String>,
    rationale: String,
}

#[derive(Debug, Clone, Copy, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
#[serde(rename_all = "snake_case")]
enum MatchKind {
    Exact,
    Prefix,
}

#[derive(Debug, Clone, Copy, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
enum AidefendApplicability {
    AiSystem,
}

#[derive(Debug)]
struct ValidatedCatalog {
    mapping_version: String,
    relationship: String,
    controls: BTreeMap<String, ControlDefinition>,
    entries: Vec<MappingEntry>,
}

static CATALOG: OnceLock<Result<ValidatedCatalog, String>> = OnceLock::new();

pub(super) fn validate_catalog(known_engines: &[&str]) -> AppResult<()> {
    let catalog = catalog().map_err(AppError::EngineRegistry)?;
    let known = known_engines.iter().copied().collect::<BTreeSet<_>>();
    for entry in &catalog.entries {
        if !known.contains(entry.engine_id.as_str()) {
            return Err(AppError::EngineRegistry(format!(
                "control mapping references unknown engine {}",
                entry.engine_id
            )));
        }
    }
    Ok(())
}

pub(super) fn catalog_version() -> AppResult<&'static str> {
    let catalog = catalog().map_err(AppError::EngineRegistry)?;
    Ok(catalog.mapping_version.as_str())
}

pub(super) fn lookup(
    engine_id: &str,
    source_rule: &str,
    ai_system_applicable: bool,
) -> Vec<ControlReference> {
    let Ok(catalog) = catalog() else {
        // Registry construction validates this immutable embedded catalog. If a
        // future build ships invalid metadata, findings remain evidence-backed
        // and conservatively unmapped instead of crashing normalization.
        return Vec::new();
    };

    let mut references = BTreeMap::new();
    for entry in catalog.entries.iter().filter(|entry| {
        entry.engine_id == engine_id
            && match entry.match_kind {
                MatchKind::Exact => source_rule == entry.source_rule,
                MatchKind::Prefix => source_rule.starts_with(&entry.source_rule),
            }
    }) {
        for key in &entry.controls {
            let Some(control) = catalog.controls.get(key) else {
                continue;
            };
            if control.framework == "AIDEFEND"
                && (!ai_system_applicable
                    || entry.aidefend_applicability != Some(AidefendApplicability::AiSystem))
            {
                continue;
            }
            let identity = (
                control.framework.clone(),
                control.framework_version.clone(),
                control.control_id.clone(),
            );
            references
                .entry(identity)
                .or_insert_with(|| ControlReference {
                    framework: control.framework.clone(),
                    framework_version: control.framework_version.clone(),
                    control_id: control.control_id.clone(),
                    title: control.title.clone(),
                    relationship: catalog.relationship.clone(),
                    rationale: entry.rationale.clone(),
                    mapping_version: catalog.mapping_version.clone(),
                });
            if references.len() >= MAX_LOOKUP_RESULTS {
                break;
            }
        }
        if references.len() >= MAX_LOOKUP_RESULTS {
            break;
        }
    }
    references.into_values().collect()
}

fn catalog() -> Result<&'static ValidatedCatalog, String> {
    match CATALOG.get_or_init(parse_and_validate) {
        Ok(catalog) => Ok(catalog),
        Err(error) => Err(error.clone()),
    }
}

fn parse_and_validate() -> Result<ValidatedCatalog, String> {
    let parsed: MappingCatalog = serde_json::from_str(CATALOG_JSON)
        .map_err(|error| format!("invalid embedded control mapping JSON: {error}"))?;

    if parsed.schema_version != "1.0" {
        return Err(format!(
            "unsupported control mapping schema version {}",
            parsed.schema_version
        ));
    }
    validate_mapping_version(&parsed.mapping_version)?;
    if parsed.relationship != "related" {
        return Err("control mapping relationship must be related".into());
    }
    validate_text("mapping disclaimer", &parsed.disclaimer, 40, 512)?;
    let disclaimer = parsed.disclaimer.to_ascii_lowercase();
    if !disclaimer.contains("do not establish") || !disclaimer.contains("compliance") {
        return Err("control mapping disclaimer must reject compliance claims".into());
    }

    if parsed.sources.is_empty() || parsed.sources.len() > 16 {
        return Err("control mapping sources must contain between 1 and 16 items".into());
    }
    let mut sources = BTreeSet::new();
    for source in parsed.sources {
        validate_text("source framework", &source.framework, 1, 80)?;
        validate_text("source framework version", &source.framework_version, 1, 40)?;
        validate_https_url(&source.url)?;
        if !sources.insert((source.framework, source.framework_version)) {
            return Err("duplicate framework source in control mapping catalog".into());
        }
    }

    if parsed.controls.is_empty() || parsed.controls.len() > MAX_CONTROLS {
        return Err(format!(
            "control mapping definitions must contain between 1 and {MAX_CONTROLS} items"
        ));
    }
    let mut controls = BTreeMap::new();
    let mut coordinates = BTreeSet::new();
    for control in parsed.controls {
        validate_slug("control key", &control.key, 80, true)?;
        validate_text("control framework", &control.framework, 1, 80)?;
        validate_text(
            "control framework version",
            &control.framework_version,
            1,
            40,
        )?;
        validate_text("control id", &control.control_id, 1, 80)?;
        validate_text("control title", &control.title, 1, 160)?;
        if !sources.contains(&(control.framework.clone(), control.framework_version.clone())) {
            return Err(format!(
                "control {} has no matching official framework source",
                control.key
            ));
        }
        let coordinate = (
            control.framework.clone(),
            control.framework_version.clone(),
            control.control_id.clone(),
        );
        if !coordinates.insert(coordinate) {
            return Err(format!(
                "duplicate framework coordinate for control {}",
                control.key
            ));
        }
        let key = control.key.clone();
        if controls.insert(key.clone(), control).is_some() {
            return Err(format!("duplicate control mapping key {key}"));
        }
    }

    if parsed.entries.len() > MAX_ENTRIES {
        return Err(format!(
            "control mapping entries exceed the {MAX_ENTRIES}-entry limit"
        ));
    }
    let mut matchers = BTreeSet::new();
    for entry in &parsed.entries {
        validate_slug("mapping engine id", &entry.engine_id, 64, false)?;
        validate_text("mapping source rule", &entry.source_rule, 1, 512)?;
        if entry
            .source_rule
            .chars()
            .any(|character| matches!(character, '*' | '?' | '[' | ']'))
        {
            return Err(format!(
                "mapping for {} uses a wildcard source rule",
                entry.engine_id
            ));
        }
        if entry.match_kind == MatchKind::Prefix && entry.source_rule.chars().count() < 4 {
            return Err(format!(
                "prefix mapping for {} is too broad",
                entry.engine_id
            ));
        }
        if entry.controls.is_empty() || entry.controls.len() > MAX_REFERENCES_PER_ENTRY {
            return Err(format!(
                "mapping for {} must reference between 1 and {MAX_REFERENCES_PER_ENTRY} controls",
                entry.engine_id
            ));
        }
        let mut unique_controls = BTreeSet::new();
        let mut has_aidefend_control = false;
        for key in &entry.controls {
            let Some(control) = controls.get(key) else {
                return Err(format!(
                    "mapping for {} references unknown control {key}",
                    entry.engine_id
                ));
            };
            has_aidefend_control |= control.framework == "AIDEFEND";
            if !unique_controls.insert(key) {
                return Err(format!(
                    "mapping for {} repeats control {key}",
                    entry.engine_id
                ));
            }
        }
        if has_aidefend_control
            && entry.aidefend_applicability != Some(AidefendApplicability::AiSystem)
        {
            return Err(format!(
                "mapping for {} references AIDEFEND without explicit AI-system applicability",
                entry.engine_id
            ));
        }
        if !has_aidefend_control && entry.aidefend_applicability.is_some() {
            return Err(format!(
                "mapping for {} declares AIDEFEND applicability without an AIDEFEND control",
                entry.engine_id
            ));
        }
        validate_text("mapping rationale", &entry.rationale, 20, 512)?;
        let rationale = entry.rationale.to_ascii_lowercase();
        if rationale.contains("is compliant")
            || rationale.contains("is certified")
            || rationale.contains("passes the control")
        {
            return Err(format!(
                "mapping rationale for {} makes a prohibited assurance claim",
                entry.engine_id
            ));
        }
        let matcher = (
            entry.engine_id.clone(),
            entry.match_kind,
            entry.source_rule.clone(),
        );
        if !matchers.insert(matcher) {
            return Err(format!(
                "duplicate source-rule mapping for {}:{}",
                entry.engine_id, entry.source_rule
            ));
        }
    }

    Ok(ValidatedCatalog {
        mapping_version: parsed.mapping_version,
        relationship: parsed.relationship,
        controls,
        entries: parsed.entries,
    })
}

fn validate_mapping_version(value: &str) -> Result<(), String> {
    let Some((date, revision)) = value.split_once('.') else {
        return Err("control mapping version must be YYYY-MM-DD.N".into());
    };
    let date_is_valid = date.len() == 10
        && date.as_bytes().get(4) == Some(&b'-')
        && date.as_bytes().get(7) == Some(&b'-')
        && date
            .chars()
            .enumerate()
            .all(|(index, character)| matches!(index, 4 | 7) || character.is_ascii_digit());
    let revision_is_valid =
        !revision.starts_with('0') && revision.parse::<u32>().is_ok_and(|revision| revision > 0);
    if !date_is_valid || !revision_is_valid {
        return Err("control mapping version must be YYYY-MM-DD.N".into());
    }
    Ok(())
}

fn validate_https_url(value: &str) -> Result<(), String> {
    validate_text("framework source URL", value, 9, 2_048)?;
    if !value.starts_with("https://")
        || value.contains('@')
        || value.chars().any(char::is_whitespace)
    {
        return Err("framework source URL must be a credential-free HTTPS URL".into());
    }
    Ok(())
}

fn validate_slug(label: &str, value: &str, max: usize, allow_dot: bool) -> Result<(), String> {
    validate_text(label, value, 1, max)?;
    if !value.chars().enumerate().all(|(index, character)| {
        character.is_ascii_lowercase()
            || character.is_ascii_digit()
            || (character == '-' && index > 0)
            || (allow_dot && character == '.' && index > 0)
    }) {
        return Err(format!("{label} contains unsupported characters"));
    }
    Ok(())
}

fn validate_text(label: &str, value: &str, min: usize, max: usize) -> Result<(), String> {
    let length = value.chars().count();
    if length < min || length > max || value.trim() != value || value.chars().any(char::is_control)
    {
        return Err(format!(
            "{label} must contain {min} to {max} safe characters"
        ));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    const ENGINES: &[&str] = &[
        "cloudquery",
        "steampipe",
        "prowler",
        "scoutsuite",
        "cloudsplaining",
        "scubagear",
        "maester",
        "naabu",
        "httpx",
        "nuclei",
        "greenbone",
        "semgrep",
        "gitleaks",
        "trufflehog",
        "checkov",
        "kics",
        "trivy",
        "grype",
        "syft",
        "kubescape",
        "kube-bench",
    ];

    #[test]
    fn embedded_catalog_is_bounded_and_only_uses_known_engines() {
        validate_catalog(ENGINES).expect("valid embedded mappings");
    }

    #[test]
    fn exact_and_standardized_prefix_rules_map_deterministically() {
        let public_bucket = lookup("prowler", "s3_bucket_level_public_access_block", false);
        assert_eq!(public_bucket.len(), 3);
        assert!(public_bucket.iter().all(|item| {
            item.relationship == "related"
                && item.mapping_version == "2026-08-27.1"
                && !item.rationale.to_ascii_lowercase().contains("compliant")
        }));

        let ordinary_cve = lookup("trivy", "CVE-2026-12345", false);
        assert_eq!(ordinary_cve.len(), 2);
        assert!(
            ordinary_cve
                .iter()
                .any(|item| item.control_id == "ID.RA-01")
        );
        assert!(ordinary_cve.iter().all(|item| item.framework != "AIDEFEND"));

        let ai_system_cve = lookup("trivy", "CVE-2026-12345", true);
        assert_eq!(ai_system_cve.len(), 4);
        assert!(
            ai_system_cve
                .iter()
                .any(|item| item.control_id == "AID-H-003.001")
        );

        let generated_code_secret = lookup("gitleaks", "generic-api-key", true);
        assert!(
            generated_code_secret
                .iter()
                .any(|item| item.control_id == "AID-H-031.002")
        );
        assert!(
            lookup("gitleaks", "generic-api-key", false)
                .iter()
                .all(|item| item.framework != "AIDEFEND")
        );

        let shipped_semgrep_rules = [
            "ai-security-scanner.python.dynamic-code-execution",
            "ai-security-scanner.python.shell-true",
            "ai-security-scanner.javascript.child-process-exec",
            "ai-security-scanner.generic.private-key",
        ];
        for source_rule in shipped_semgrep_rules {
            let ordinary = lookup("semgrep", source_rule, false);
            assert!(
                !ordinary.is_empty(),
                "shipped Semgrep rule {source_rule} must have a reviewed mapping"
            );
            assert!(ordinary.iter().all(|item| item.framework != "AIDEFEND"));

            let ai_system = lookup("semgrep", source_rule, true);
            assert!(
                ai_system.iter().any(|item| item.framework == "AIDEFEND"),
                "shipped Semgrep rule {source_rule} must expose its reviewed AI-system coordinate"
            );
        }
    }

    #[test]
    fn unknown_or_observation_rules_are_not_guessed() {
        assert!(lookup("prowler", "new-unknown-check", false).is_empty());
        assert!(lookup("httpx", "http-service-observed", false).is_empty());
        assert!(lookup("naabu", "open-tcp-port", false).is_empty());
    }
}
