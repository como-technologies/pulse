use std::path::Path;

use anyhow::{Context, Result};
use pulse_crypto::{BrssKeyPair, BrssSecretKey, blind_sig};

/// Load an existing keypair from a PEM file, or generate a new one and save it.
pub fn load_or_generate_keypair(key_path: &Path) -> Result<BrssKeyPair> {
    if key_path.exists() {
        load_keypair(key_path)
    } else {
        generate_and_save_keypair(key_path)
    }
}

fn load_keypair(key_path: &Path) -> Result<BrssKeyPair> {
    let pem = std::fs::read_to_string(key_path)
        .with_context(|| format!("failed to read key file: {}", key_path.display()))?;
    let sk = BrssSecretKey::from_pem(&pem)
        .map_err(|e| anyhow::anyhow!("failed to parse PEM key: {e}"))?;
    let pk = sk
        .public_key()
        .map_err(|e| anyhow::anyhow!("failed to derive public key: {e}"))?;
    tracing::info!(path = %key_path.display(), "Loaded existing signing keypair");
    Ok(BrssKeyPair { pk, sk })
}

fn generate_and_save_keypair(key_path: &Path) -> Result<BrssKeyPair> {
    let kp = blind_sig::generate_keypair().context("keypair generation failed")?;
    let pem = kp
        .sk
        .to_pem()
        .map_err(|e| anyhow::anyhow!("failed to encode key as PEM: {e}"))?;
    std::fs::write(key_path, pem.as_bytes())
        .with_context(|| format!("failed to write key file: {}", key_path.display()))?;
    set_key_file_permissions(key_path);
    tracing::info!(path = %key_path.display(), "Generated new signing keypair");
    Ok(kp)
}

#[cfg(unix)]
fn set_key_file_permissions(key_path: &Path) {
    use std::os::unix::fs::PermissionsExt;
    let perms = std::fs::Permissions::from_mode(0o600);
    if let Err(e) = std::fs::set_permissions(key_path, perms) {
        tracing::warn!(path = %key_path.display(), error = %e, "Failed to set key file permissions to 0600");
    }
}

#[cfg(not(unix))]
fn set_key_file_permissions(_key_path: &Path) {}
