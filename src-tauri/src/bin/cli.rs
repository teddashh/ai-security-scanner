use ai_security_scanner_lib::demo::build_demo_case;
use ai_security_scanner_lib::domain::{
    AssessmentCase, CreateCaseRequest, DataClass, OrganizationProfile,
};
use ai_security_scanner_lib::error::{AppError, AppResult};
use ai_security_scanner_lib::registry::EngineRegistry;
use ai_security_scanner_lib::runtime::detect_runtime;
use ai_security_scanner_lib::storage::Storage;
use clap::{Args, Parser, Subcommand};
use directories::ProjectDirs;
use std::path::PathBuf;

#[derive(Debug, Parser)]
#[command(name = "ai-security-scanner")]
#[command(about = "Local-first security assessment casework CLI")]
#[command(version)]
struct Cli {
    /// Override the local application data directory.
    #[arg(long, global = true, env = "AI_SECURITY_SCANNER_DATA_DIR")]
    data_dir: Option<PathBuf>,

    /// Emit machine-readable JSON.
    #[arg(long, global = true)]
    json: bool,

    #[command(subcommand)]
    command: Command,
}

#[derive(Debug, Subcommand)]
enum Command {
    /// Manage long-lived assessment cases.
    Case {
        #[command(subcommand)]
        command: CaseCommand,
    },
    /// Inspect scanner engine metadata and runtime readiness.
    Engine {
        #[command(subcommand)]
        command: EngineCommand,
    },
    /// Check local storage and container runtime readiness.
    Doctor,
}

#[derive(Debug, Subcommand)]
enum CaseCommand {
    Create(CreateCaseArgs),
    List,
    Show {
        case_id: String,
    },
    /// Create or select a clearly labeled synthetic demonstration case.
    SeedDemo,
}

#[derive(Debug, Args)]
struct CreateCaseArgs {
    #[arg(long)]
    title: String,
    #[arg(long)]
    organization: String,
    #[arg(long, default_value = "unknown")]
    employee_range: String,
    /// Comma-separated values: general,pii,phi,pci,financial,secrets,other.
    #[arg(long, value_delimiter = ',')]
    data_class: Vec<String>,
    #[arg(long)]
    notes: Option<String>,
}

#[derive(Debug, Subcommand)]
enum EngineCommand {
    List,
    Show { engine_id: String },
}

#[tokio::main]
async fn main() {
    if let Err(error) = execute(Cli::parse()).await {
        eprintln!("error: {error}");
        std::process::exit(1);
    }
}

async fn execute(cli: Cli) -> AppResult<()> {
    let data_dir = resolve_data_dir(cli.data_dir)?;
    let storage = Storage::open(data_dir.join("casework.db"))?;

    match cli.command {
        Command::Case { command } => match command {
            CaseCommand::Create(args) => {
                let request = CreateCaseRequest {
                    title: args.title,
                    organization_name: args.organization,
                    employee_range: args.employee_range,
                    data_classes: args
                        .data_class
                        .iter()
                        .map(|value| parse_data_class(value))
                        .collect::<AppResult<Vec<_>>>()?,
                    notes: args.notes,
                };
                let case = AssessmentCase::new(
                    request.title,
                    OrganizationProfile {
                        organization_name: request.organization_name,
                        employee_range: request.employee_range,
                        data_classes: request.data_classes,
                        notes: request.notes,
                    },
                );
                storage.save_case(&case, "case.created.cli")?;
                storage.set_selected_case(Some(&case.id))?;
                print_value(&case, cli.json)?;
            }
            CaseCommand::List => print_value(&storage.list_cases()?, cli.json)?,
            CaseCommand::Show { case_id } => print_value(&storage.get_case(&case_id)?, cli.json)?,
            CaseCommand::SeedDemo => {
                let case = if let Some(summary) = storage
                    .list_cases()?
                    .into_iter()
                    .find(|summary| summary.is_demo)
                {
                    storage.get_case(&summary.id)?
                } else {
                    let case = build_demo_case();
                    storage.save_case(&case, "case.demo_seeded.cli")?;
                    case
                };
                storage.set_selected_case(Some(&case.id))?;
                print_value(&case, cli.json)?;
            }
        },
        Command::Engine { command } => {
            let registry = EngineRegistry::load_builtin()?;
            match command {
                EngineCommand::List => print_value(registry.manifests(), cli.json)?,
                EngineCommand::Show { engine_id } => {
                    let manifest = registry.get(&engine_id).ok_or_else(|| {
                        AppError::InvalidRequest(format!("unknown engine: {engine_id}"))
                    })?;
                    print_value(manifest, cli.json)?;
                }
            }
        }
        Command::Doctor => {
            let runtime = detect_runtime().await;
            let report = serde_json::json!({
                "product": "ai-security-scanner",
                "data_dir": data_dir,
                "database": storage.path(),
                "runtime": runtime,
                "engine_manifests": EngineRegistry::load_builtin()?.manifests().len(),
            });
            print_value(&report, cli.json)?;
        }
    }

    Ok(())
}

fn resolve_data_dir(override_path: Option<PathBuf>) -> AppResult<PathBuf> {
    if let Some(path) = override_path {
        return Ok(path);
    }

    ProjectDirs::from("dev", "teddashh", "ai-security-scanner")
        .map(|dirs| dirs.data_local_dir().to_path_buf())
        .ok_or_else(|| {
            AppError::Internal("could not determine local application data directory".into())
        })
}

fn parse_data_class(value: &str) -> AppResult<DataClass> {
    match value.trim().to_ascii_lowercase().as_str() {
        "general" => Ok(DataClass::General),
        "pii" => Ok(DataClass::PersonallyIdentifiableInformation),
        "phi" => Ok(DataClass::ProtectedHealthInformation),
        "pci" => Ok(DataClass::PaymentCardInformation),
        "financial" => Ok(DataClass::Financial),
        "secrets" => Ok(DataClass::CredentialsAndSecrets),
        "other" => Ok(DataClass::Other),
        other => Err(AppError::InvalidRequest(format!(
            "unsupported data class: {other}"
        ))),
    }
}

fn print_value(value: &(impl serde::Serialize + ?Sized), json: bool) -> AppResult<()> {
    if json {
        println!("{}", serde_json::to_string(value)?);
    } else {
        println!("{}", serde_json::to_string_pretty(value)?);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_supported_data_classes() {
        assert!(matches!(
            parse_data_class("PII"),
            Ok(DataClass::PersonallyIdentifiableInformation)
        ));
        assert!(parse_data_class("legal-opinion").is_err());
    }
}
