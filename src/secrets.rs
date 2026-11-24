use std::collections::HashMap;
use std::fmt;

use zeroize::ZeroizeOnDrop;

use crate::EdgeGateError;

/// Redacted, zeroized-on-drop wrapper around raw upstream credential bytes.
/// Guarantees secret material never appears in `Debug` or `Display` output.
#[derive(Clone, ZeroizeOnDrop)]
pub struct SecretValue {
    inner: String,
}

impl SecretValue {
    pub fn new(value: String) -> Self {
        Self { inner: value }
    }

    pub fn expose(&self) -> &str {
        &self.inner
    }
}

impl fmt::Debug for SecretValue {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("[REDACTED]")
    }
}

impl fmt::Display for SecretValue {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("[REDACTED]")
    }
}

/// Trait seam for scoped credential retrieval (M1 mock provider; M2 GCP Secret Manager / Vault).
pub trait SecretProvider: Send + Sync {
    fn get_secret(&self, org_id: &str, credential_ref: &str) -> Result<SecretValue, EdgeGateError>;
}

/// In-memory scoped secret provider for Milestone 1.
#[derive(Debug, Clone)]
pub struct MockSecretProvider {
    secrets: HashMap<(String, String), SecretValue>,
}

impl MockSecretProvider {
    pub fn from_map(raw: HashMap<(String, String), String>) -> Self {
        let secrets = raw
            .into_iter()
            .map(|(k, v)| (k, SecretValue::new(v)))
            .collect();
        Self { secrets }
    }
}

impl SecretProvider for MockSecretProvider {
    fn get_secret(&self, org_id: &str, credential_ref: &str) -> Result<SecretValue, EdgeGateError> {
        self.secrets
            .get(&(org_id.to_string(), credential_ref.to_string()))
            .cloned()
            .ok_or_else(|| {
                EdgeGateError::Forbidden(format!(
                    "no scoped credential '{credential_ref}' configured for org '{org_id}'"
                ))
            })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn redacts_debug_and_display_output() {
        let secret = SecretValue::new("ghp_super_secret_token_999".to_string());
        assert_eq!(format!("{secret:?}"), "[REDACTED]");
        assert_eq!(format!("{secret}"), "[REDACTED]");
        assert!(!format!("{secret:?}").contains("ghp_super_secret"));
    }

    #[test]
    fn enforces_org_scoping() {
        let mut raw = HashMap::new();
        raw.insert(
            ("org-alpha".to_string(), "github_pat".to_string()),
            "ghp_alpha".to_string(),
        );
        let provider = MockSecretProvider::from_map(raw);

        let ok = provider
            .get_secret("org-alpha", "github_pat")
            .unwrap_or_else(|e| panic!("expected ok: {e}"));
        assert_eq!(ok.expose(), "ghp_alpha");

        assert!(matches!(
            provider.get_secret("org-beta", "github_pat"),
            Err(EdgeGateError::Forbidden(_))
        ));
    }
}
