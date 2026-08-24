use crate::domain::RuntimeHealth;
use tokio::process::Command;

pub async fn detect_runtime() -> RuntimeHealth {
    if let Some(health) =
        command_health("docker", &["version", "--format", "{{.Server.Version}}"]).await
    {
        return health;
    }

    if let Some(health) =
        command_health("podman", &["version", "--format", "{{.Server.Version}}"]).await
    {
        return health;
    }

    RuntimeHealth {
        provider: "none".into(),
        available: false,
        version: None,
        detail: "No compatible Docker or Podman service was detected.".into(),
    }
}

async fn command_health(program: &str, args: &[&str]) -> Option<RuntimeHealth> {
    let output = Command::new(program).args(args).output().await.ok()?;
    if !output.status.success() {
        return None;
    }

    let version = String::from_utf8_lossy(&output.stdout).trim().to_owned();
    Some(RuntimeHealth {
        provider: program.into(),
        available: true,
        version: (!version.is_empty()).then_some(version),
        detail: format!("{program} service is available"),
    })
}
