use std::collections::HashMap;
use std::fmt;
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use arc_swap::ArcSwap;
use zeroize::ZeroizeOnDrop;

use crate::config::CompiledSecret;
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

#[derive(Debug, Clone)]
pub struct StoredSecret {
    pub secret: SecretValue,
    pub expires_at_epoch_s: Option<u64>,
}

/// Trait seam for scoped credential retrieval and live rotation (`Milestone 6`).
pub trait SecretProvider: Send + Sync {
    fn get_secret(&self, org_id: &str, credential_ref: &str) -> Result<SecretValue, EdgeGateError>;

    fn rotate_secret(
        &self,
        _org_id: &str,
        _credential_ref: &str,
        _new_value: String,
        _expires_at_epoch_s: Option<u64>,
    ) {
    }
}

/// In-memory scoped secret provider supporting TTL expiration and live rotation (`Milestone 6`).
#[derive(Debug, Clone)]
pub struct MockSecretProvider {
    secrets: Arc<ArcSwap<HashMap<(String, String), StoredSecret>>>,
}

pub type CatalogSecretProvider = MockSecretProvider;

impl MockSecretProvider {
    pub fn from_map(raw: HashMap<(String, String), String>) -> Self {
        let secrets = raw
            .into_iter()
            .map(|(k, v)| {
                (
                    k,
                    StoredSecret {
                        secret: SecretValue::new(v),
                        expires_at_epoch_s: None,
                    },
                )
            })
            .collect();
        Self {
            secrets: Arc::new(ArcSwap::from_pointee(secrets)),
        }
    }

    pub fn from_compiled(raw: HashMap<(String, String), CompiledSecret>) -> Self {
        let secrets = raw
            .into_iter()
            .map(|(k, cs)| {
                (
                    k,
                    StoredSecret {
                        secret: SecretValue::new(cs.value),
                        expires_at_epoch_s: cs.expires_at_epoch_s,
                    },
                )
            })
            .collect();
        Self {
            secrets: Arc::new(ArcSwap::from_pointee(secrets)),
        }
    }
}

impl SecretProvider for MockSecretProvider {
    fn get_secret(&self, org_id: &str, credential_ref: &str) -> Result<SecretValue, EdgeGateError> {
        let snap = self.secrets.load();
        let stored = snap
            .get(&(org_id.to_string(), credential_ref.to_string()))
            .cloned()
            .ok_or_else(|| {
                EdgeGateError::Forbidden(format!(
                    "no scoped credential '{credential_ref}' configured for org '{org_id}'"
                ))
            })?;

        if let Some(exp) = stored.expires_at_epoch_s {
            let now_s = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .map(|d| d.as_secs())
                .unwrap_or(0);
            if now_s >= exp {
                return Err(EdgeGateError::Forbidden(format!(
                    "scoped credential '{credential_ref}' for org '{org_id}' has expired"
                )));
            }
        }
        Ok(stored.secret)
    }

    fn rotate_secret(
        &self,
        org_id: &str,
        credential_ref: &str,
        new_value: String,
        expires_at_epoch_s: Option<u64>,
    ) {
        let key = (org_id.to_string(), credential_ref.to_string());
        self.secrets.rcu(move |current| {
            let mut next = (**current).clone();
            next.insert(
                key.clone(),
                StoredSecret {
                    secret: SecretValue::new(new_value.clone()),
                    expires_at_epoch_s,
                },
            );
            next
        });
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
