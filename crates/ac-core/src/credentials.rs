//! Secure Local Credential Management for Provider Accounts.
//!
//! Stores credentials securely on disk with restricted permissions (0700/0600)
//! under ~/.config/agentcontrol/credentials/ so that secrets are never stored
//! in SQLite databases, logs, or UI history.
//!
//! Antigravity (`agy`) credentials are handled exclusively by
//! [`crate::agy_auth`], which owns the typed credential format, validation,
//! browser login and per-account profiles.
//!
//! Claude Code / Anthropic credentials and per-account profiles are managed here
//! and in [`crate::adapter::claude`].

use anyhow::{Context, Result};
use chrono::Utc;
use serde::{Deserialize, Serialize};
use std::{
    fs,
    path::{Path, PathBuf},
};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AccountCredential {
    pub id: String,
    pub provider: String,
    pub label: String,
    pub auth_mode: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub token: Option<String>,
    pub created_at: String,
}

pub fn config_dir() -> PathBuf {
    crate::agy_auth::agentcontrol_config_dir()
}

pub fn credentials_dir() -> PathBuf {
    crate::agy_auth::credentials_dir()
}

pub fn profiles_dir() -> PathBuf {
    crate::agy_auth::profiles_dir()
}

pub fn profile_dir(account_id: &crate::types::Id) -> Result<PathBuf> {
    crate::agy_auth::profile_dir(account_id).map_err(|e| anyhow::anyhow!("{e}"))
}

pub fn ensure_credentials_dir() -> Result<PathBuf> {
    let dir = credentials_dir();
    if !dir.exists() {
        fs::create_dir_all(&dir)
            .with_context(|| format!("creating credentials dir at {}", dir.display()))?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let _ = fs::set_permissions(&dir, fs::Permissions::from_mode(0o700));
        }
    }
    Ok(dir)
}

/// Atomically write a file with 0600 mode permissions on Unix.
pub fn write_private_file(path: &Path, content: &[u8]) -> std::io::Result<()> {
    let dir = path.parent().unwrap_or(Path::new("."));
    fs::create_dir_all(dir)?;
    let tmp = dir.join(format!(
        ".{}.tmp-{}",
        path.file_name().and_then(|n| n.to_str()).unwrap_or("cred"),
        ulid::Ulid::new()
    ));
    {
        let mut opts = fs::OpenOptions::new();
        opts.write(true).create_new(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            opts.mode(0o600);
        }
        let mut f = opts.open(&tmp)?;
        std::io::Write::write_all(&mut f, content)?;
        f.sync_all()?;
    }
    fs::rename(&tmp, path).inspect_err(|_| {
        let _ = fs::remove_file(&tmp);
    })
}

/// Parse a credential reference `ref:<provider>:<id>` into its on-disk path.
pub fn credential_path(cred_ref: &str) -> Option<PathBuf> {
    let (prefix, id) = cred_ref.strip_prefix("ref:")?.split_once(':')?;
    if prefix.is_empty()
        || id.is_empty()
        || !prefix
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_')
        || !id
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_')
    {
        return None;
    }
    Some(credentials_dir().join(format!("{prefix}_{id}.json")))
}

/// Save a generic (non-Antigravity) provider credential.
pub fn save_credential(
    provider: &str,
    cred_id: &str,
    label: &str,
    auth_mode: &str,
    token: Option<String>,
) -> Result<String> {
    if matches!(provider, "agy" | "antigravity") {
        anyhow::bail!("Antigravity credentials must be saved through agy_auth");
    }
    let dir = ensure_credentials_dir()?;
    let path = dir.join(format!("{provider}_{cred_id}.json"));

    let cred = AccountCredential {
        id: cred_id.to_string(),
        provider: provider.to_string(),
        label: label.to_string(),
        auth_mode: auth_mode.to_string(),
        token,
        created_at: Utc::now().to_rfc3339(),
    };

    let content = serde_json::to_string_pretty(&cred)?;
    write_private_file(&path, content.as_bytes())?;

    Ok(format!("ref:{provider}:{cred_id}"))
}

/// Helper to save an Anthropic API key credential for Claude Code.
pub fn save_claude_credential(label: &str, api_key: &str) -> Result<String> {
    let cred_id = ulid::Ulid::new().to_string();
    save_credential(
        "claude",
        &cred_id,
        label,
        "api_token",
        Some(api_key.trim().to_string()),
    )
}

/// Load an [`AccountCredential`] from a credential reference.
pub fn load_credential(cred_ref: &str) -> Result<AccountCredential> {
    let path = credential_path(cred_ref)
        .ok_or_else(|| anyhow::anyhow!("Malformed credential reference '{}'", cred_ref))?;
    let content = fs::read_to_string(&path)
        .with_context(|| format!("Reading credential file at {}", path.display()))?;
    serde_json::from_str::<AccountCredential>(&content)
        .with_context(|| format!("Parsing credential JSON from {}", path.display()))
}

/// Delete a stored credential by reference.
pub fn delete_credential(cred_ref: &str) -> Result<bool> {
    if let Some(path) = credential_path(cred_ref) {
        if path.is_file() {
            fs::remove_file(&path)
                .with_context(|| format!("deleting credential file at {}", path.display()))?;
            return Ok(true);
        }
    }
    Ok(false)
}

/// Resolve raw API key from a credential reference (`ref:...`, `env:...`, or direct key).
pub fn resolve_api_key(cred_ref: &str) -> Result<String> {
    let trimmed = cred_ref.trim();
    if trimmed.is_empty() {
        anyhow::bail!("Empty credential reference");
    }
    if let Some(stripped) = trimmed.strip_prefix("env:") {
        std::env::var(stripped)
            .with_context(|| format!("Environment variable '{stripped}' not found"))
    } else if trimmed.starts_with("ref:") {
        let cred = load_credential(trimmed)?;
        cred.token
            .filter(|t| !t.trim().is_empty())
            .ok_or_else(|| anyhow::anyhow!("Credential '{}' contains no token", trimmed))
    } else if let Ok(val) = std::env::var(trimmed) {
        if !val.trim().is_empty() {
            Ok(val)
        } else {
            anyhow::bail!("Environment variable '{}' is empty", trimmed);
        }
    } else {
        // Direct API key string (e.g. sk-ant-...)
        Ok(trimmed.to_string())
    }
}

/// Resolve a credential reference into an Option<String> without throwing if not present.
pub fn resolve_credential(cred_ref: &str) -> Result<Option<String>> {
    let trimmed = cred_ref.trim();
    if trimmed.is_empty() {
        return Ok(None);
    }
    match resolve_api_key(trimmed) {
        Ok(key) => Ok(Some(key)),
        Err(_) if trimmed.starts_with("ref:") || trimmed.starts_with("env:") => Ok(None),
        Err(e) => Err(e),
    }
}

/// Validate that a credential reference can be resolved.
pub fn validate_credential(cred_ref: &str) -> Result<()> {
    resolve_api_key(cred_ref).map(|_| ())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_credential_path_parsing() {
        let path = credential_path("ref:claude:cred-01").unwrap();
        assert!(path.ends_with("claude_cred-01.json"));

        assert!(credential_path("invalid").is_none());
        assert!(credential_path("ref:").is_none());
        assert!(credential_path("ref:claude:").is_none());
        assert!(credential_path("ref:claude:invalid/id").is_none());
    }

    #[test]
    fn test_resolve_api_key_direct_and_env() {
        assert_eq!(
            resolve_api_key("sk-ant-test-key").unwrap(),
            "sk-ant-test-key"
        );
        assert!(resolve_api_key("").is_err());
        assert!(resolve_api_key("   ").is_err());

        std::env::set_var("TEST_ANTHROPIC_KEY_ENV", "secret-from-env");
        assert_eq!(
            resolve_api_key("env:TEST_ANTHROPIC_KEY_ENV").unwrap(),
            "secret-from-env"
        );
        assert_eq!(
            resolve_api_key("TEST_ANTHROPIC_KEY_ENV").unwrap(),
            "secret-from-env"
        );
        std::env::remove_var("TEST_ANTHROPIC_KEY_ENV");
    }
}
