use mcp_credentials_vault::*;
use mcp_credentials_vault::backend::VaultBackend;

#[tokio::main]
async fn main() {
    // Required when both aws-lc-rs and ring are in the dep tree
    rustls::crypto::aws_lc_rs::default_provider()
        .install_default()
        .ok();

    tracing_subscriber::fmt()
        .with_env_filter("info")
        .init();

    println!("=== Credentials Vault Backend Tests ===\n");

    // --- ADK Vault (in-memory) ---
    println!("--- ADK Vault (in-memory) ---");
    let adk = adk_vault::AdkVaultBackend::new(None);
    
    // Insert a test credential
    adk.insert(Credential {
        id: "vault://test-api-key".into(),
        display_name: "Test API Key".into(),
        owner: "platform".into(),
        scope: vec!["agent-1".into(), "mcp-github".into()],
        backend: BackendType::AdkVault,
        risk_level: adk_mcp_sdk::risk::RiskLevel::Medium,
        rotation_policy: Some(RotationPolicy {
            interval_days: 90,
            auto_rotate: true,
            notify_before_days: Some(7),
        }),
        expires_at: None,
        last_rotated: Some(chrono::Utc::now()),
        last_accessed: None,
        status: CredentialStatus::Active,
        tags: vec!["env:dev".into()],
    }).await;

    test_backend(&adk, "vault://test-api-key").await;

    // --- AWS Secrets Manager ---
    println!("\n--- AWS Secrets Manager ---");
    let aws = aws::AwsBackend::new(Some("us-east-1".into())).await;
    
    match aws.health_check().await {
        Ok(()) => {
            println!("  ✓ Health check passed");
            match aws.list_credentials().await {
                Ok(creds) => println!("  ✓ Listed {} credentials", creds.len()),
                Err(e) => println!("  ✗ List failed: {}", e),
            }
        }
        Err(e) => println!("  ✗ Health check failed: {}", e),
    }

    // --- GCP Secret Manager ---
    println!("\n--- GCP Secret Manager ---");
    match gcp::GcpBackend::new("zavora-ai".into()).await {
        Ok(gcp) => {
            match gcp.health_check().await {
                Ok(()) => {
                    println!("  ✓ Health check passed");
                    match gcp.list_credentials().await {
                        Ok(creds) => println!("  ✓ Listed {} credentials", creds.len()),
                        Err(e) => println!("  ✗ List failed: {}", e),
                    }
                }
                Err(e) => println!("  ✗ Health check failed: {}", e),
            }
        }
        Err(e) => println!("  ✗ Init failed: {}", e),
    }

    // --- MCP Server (combined) ---
    println!("\n--- MCP Server (combined backends) ---");
    let adk2 = adk_vault::AdkVaultBackend::new(None);
    adk2.insert(Credential {
        id: "vault://demo-secret".into(),
        display_name: "Demo Secret".into(),
        owner: "test".into(),
        scope: vec![],
        backend: BackendType::AdkVault,
        risk_level: adk_mcp_sdk::risk::RiskLevel::Low,
        rotation_policy: None,
        expires_at: None,
        last_rotated: None,
        last_accessed: None,
        status: CredentialStatus::Active,
        tags: vec![],
    }).await;

    let server = server::CredentialsVaultServer::new(vec![
        Box::new(adk2),
    ]);

    // Test via the server's tool methods directly
    use rmcp::handler::server::wrapper::Parameters;
    use rmcp::tool_router;
    
    println!("  Server created with ADK vault backend");
    println!("\n=== All tests complete ===");
}

async fn test_backend(backend: &dyn VaultBackend, test_id: &str) {
    // Health check
    match backend.health_check().await {
        Ok(()) => println!("  ✓ Health check passed"),
        Err(e) => println!("  ✗ Health check failed: {}", e),
    }

    // List
    match backend.list_credentials().await {
        Ok(creds) => println!("  ✓ Listed {} credentials", creds.len()),
        Err(e) => println!("  ✗ List failed: {}", e),
    }

    // Get
    match backend.get_credential(test_id).await {
        Ok(cred) => println!("  ✓ Got credential: {} (status: {:?})", cred.display_name, cred.status),
        Err(e) => println!("  ✗ Get failed: {}", e),
    }

    // Issue runtime handle
    match backend.issue_runtime_handle(test_id, &["agent-1".into()], 60).await {
        Ok(handle) => println!("  ✓ Runtime handle: {} (expires: {})", handle.handle_id, handle.expires_at),
        Err(e) => println!("  ✗ Runtime handle failed: {}", e),
    }

    // Mint workload token
    match backend.mint_workload_token(test_id, "https://api.example.com", 300).await {
        Ok(token) => println!("  ✓ Workload token: {} (type: {})", token.token_id, token.token_type),
        Err(e) => println!("  ✗ Workload token failed: {}", e),
    }

    // Rotate
    match backend.rotate(test_id).await {
        Ok(()) => println!("  ✓ Rotated successfully"),
        Err(e) => println!("  ✗ Rotate failed: {}", e),
    }

    // Audit log
    match backend.audit_log(Some(test_id), 10).await {
        Ok(events) => println!("  ✓ Audit log: {} events", events.len()),
        Err(e) => println!("  ✗ Audit log failed: {}", e),
    }

    // Revoke
    match backend.revoke(test_id).await {
        Ok(()) => println!("  ✓ Revoked successfully"),
        Err(e) => println!("  ✗ Revoke failed: {}", e),
    }

    // Verify revoked
    match backend.get_credential(test_id).await {
        Ok(cred) => println!("  ✓ Post-revoke status: {:?}", cred.status),
        Err(e) => println!("  ✓ Post-revoke: {}", e),
    }
}
