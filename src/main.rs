use mcp_credentials_vault::{adk_vault::AdkVaultBackend, server::CredentialsVaultServer, *};
use rmcp::{ServiceExt, transport::stdio};

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    rustls::crypto::aws_lc_rs::default_provider()
        .install_default()
        .ok();

    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::from_default_env()
                .add_directive(tracing::Level::INFO.into()),
        )
        .with_writer(std::io::stderr)
        .with_ansi(false)
        .init();

    tracing::info!("Starting Credentials Vault MCP server");

    // Initialize backends based on available config
    let mut backends: Vec<Box<dyn backend::VaultBackend>> = Vec::new();

    // ADK Vault (always available)
    let persist_path = std::env::var("ADK_VAULT_PATH")
        .ok()
        .map(std::path::PathBuf::from);
    let adk = AdkVaultBackend::new(persist_path);

    // Seed a demo credential for testing
    adk.insert(Credential {
        id: "vault://demo-api-key".into(),
        display_name: "Demo API Key".into(),
        owner: "platform".into(),
        scope: vec![],
        backend: BackendType::AdkVault,
        risk_level: adk_mcp_sdk::risk::RiskLevel::Low,
        rotation_policy: Some(RotationPolicy {
            interval_days: 90,
            auto_rotate: false,
            notify_before_days: Some(7),
        }),
        expires_at: None,
        last_rotated: Some(chrono::Utc::now()),
        last_accessed: None,
        status: CredentialStatus::Active,
        tags: vec!["env:dev".into()],
    })
    .await;

    backends.push(Box::new(adk));

    // AWS (if configured)
    #[cfg(feature = "aws")]
    if std::env::var("AWS_REGION").is_ok() || std::env::var("AWS_DEFAULT_REGION").is_ok() {
        let region = std::env::var("AWS_REGION")
            .or_else(|_| std::env::var("AWS_DEFAULT_REGION"))
            .ok();
        backends.push(Box::new(aws::AwsBackend::new(region).await));
        tracing::info!("AWS Secrets Manager backend enabled");
    }

    // GCP (if configured)
    #[cfg(feature = "gcp")]
    if let Ok(project) = std::env::var("GCP_PROJECT_ID")
        .or_else(|_| std::env::var("GOOGLE_CLOUD_PROJECT"))
    {
        match gcp::GcpBackend::new(project).await {
            Ok(gcp) => {
                backends.push(Box::new(gcp));
                tracing::info!("GCP Secret Manager backend enabled");
            }
            Err(e) => tracing::warn!("GCP backend init failed: {}", e),
        }
    }

    tracing::info!("Loaded {} backend(s)", backends.len());

    let server = CredentialsVaultServer::new(backends);
    let service = server.serve(stdio()).await?;
    service.waiting().await?;

    Ok(())
}
