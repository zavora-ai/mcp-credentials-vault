/// Errors from vault operations.
#[derive(Debug, thiserror::Error)]
pub enum VaultError {
    #[error("credential not found: {0}")]
    NotFound(String),

    #[error("access denied: {0}")]
    AccessDenied(String),

    #[error("backend unavailable: {0}")]
    Unavailable(String),

    #[error("authentication failed: {0}")]
    AuthFailed(String),

    #[error("rotation failed: {0}")]
    RotationFailed(String),

    #[error("invalid scope: {0}")]
    InvalidScope(String),

    #[error("token minting failed: {0}")]
    TokenMintFailed(String),

    #[error("internal error: {0}")]
    Internal(String),
}
