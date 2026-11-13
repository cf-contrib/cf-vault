//! Secure credential storage.
//!
//! Sessions live in the platform keyring, one JSON entry per profile. There is no fallback: when
//! the keyring cannot be used the command fails (see [`open`]). Adapted from nix-vault (MIT).
//!
//! With the non-default `test-store` cargo feature (never enabled in releases) a file-backed
//! store selected by `CF_VAULT_STORE_DIR` exists so integration tests can drive the binary.

pub mod keyring;
pub mod locker;
#[cfg(feature = "test-store")]
pub mod testing;

use serde::{Deserialize, Serialize};
use time::OffsetDateTime;

use crate::vault::{auth::redact::Secret, Error, Result};

/// Keyring service name under which sessions are stored; the account is the profile name.
pub const SERVICE: &str = "cf-vault";
/// Current layout version of [`Session`].
pub const SCHEMA: u32 = 1;

/// A place that keeps secret values by account name.
pub trait SecretStore: Send {
    /// Returns the value stored for `account`, or `None`.
    fn get(&self, account: &str) -> Result<Option<Secret>>;
    /// Stores `value` for `account`, replacing any existing value.
    fn set(&self, account: &str, value: &Secret) -> Result<()>;
    /// Deletes the value for `account`. Returns false if there was none.
    fn delete(&self, account: &str) -> Result<bool>;
}

/// What kind of authentication a stored session belongs to.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum SessionKind {
    /// OAuth 2.0 tokens.
    Oauth2,
    /// A static API token.
    Token,
}

/// What is kept in the credential store for one profile (see data-model.md).
#[derive(Clone, Serialize, Deserialize)]
pub struct Session {
    /// Layout version, starts at 1.
    pub version: u32,
    /// Must match the profile type, else the profile counts as not signed in.
    pub kind: SessionKind,
    /// OAuth access token, or the static API token.
    pub access_token: Secret,
    /// OIDC ID token, when the provider issued one (needed for broker exchange).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub id_token: Option<Secret>,
    /// Refresh token, when the provider issued one.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub refresh_token: Option<Secret>,
    /// When the access token expires; absent means unknown or never.
    #[serde(default, with = "time::serde::rfc3339::option")]
    pub expires_at: Option<OffsetDateTime>,
    /// When the ID token expires.
    #[serde(default, with = "time::serde::rfc3339::option")]
    pub id_token_expires_at: Option<OffsetDateTime>,
    /// Issuer the session was obtained from (a changed issuer invalidates it).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub issuer: Option<String>,
    /// Client the session was obtained for (a changed client invalidates it).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub client_id: Option<String>,
}

impl std::fmt::Debug for Session {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Session")
            .field("kind", &self.kind)
            .field("tokens", &"[REDACTED]")
            .finish()
    }
}

impl Session {
    /// A session holding a static API token.
    pub fn token(token: Secret) -> Self {
        Session {
            version: SCHEMA,
            kind: SessionKind::Token,
            access_token: token,
            id_token: None,
            refresh_token: None,
            expires_at: None,
            id_token_expires_at: None,
            issuer: None,
            client_id: None,
        }
    }

    /// Checks the invariants of a stored session.
    pub fn validate(&self) -> Result<()> {
        if self.version != SCHEMA {
            return Err(Error::StoreUnavailable(
                "a stored session was written by a newer cf-vault; upgrade cf-vault".into(),
            ));
        }
        let secrets = [
            Some(("access token", &self.access_token)),
            self.id_token.as_ref().map(|s| ("ID token", s)),
            self.refresh_token.as_ref().map(|s| ("refresh token", s)),
        ];
        for (label, secret) in secrets.into_iter().flatten() {
            let value = secret.expose();
            if value.is_empty() || value.chars().any(char::is_control) {
                return Err(Error::Auth(format!(
                    "the {label} is empty or contains control characters"
                )));
            }
        }
        Ok(())
    }
}

/// A store that is opened on first use. A run that supplies credentials through the environment
/// never touches the keychain, so a CI runner without one can use it.
struct LazyStore {
    inner: std::sync::Mutex<Option<Box<dyn SecretStore>>>,
}

impl LazyStore {
    fn with<T>(&self, f: impl FnOnce(&dyn SecretStore) -> Result<T>) -> Result<T> {
        let mut guard = self.inner.lock().unwrap_or_else(|e| e.into_inner());
        if guard.is_none() {
            // A failure is reported to the caller and tried again on the next use
            *guard = Some(open()?);
        }
        f(guard.as_deref().expect("opened above"))
    }
}

impl SecretStore for LazyStore {
    fn get(&self, account: &str) -> Result<Option<Secret>> {
        self.with(|store| store.get(account))
    }
    fn set(&self, account: &str, value: &Secret) -> Result<()> {
        self.with(|store| store.set(account, value))
    }
    fn delete(&self, account: &str) -> Result<bool> {
        self.with(|store| store.delete(account))
    }
}

/// Typed access to the sessions of profiles.
pub struct CredentialStore {
    inner: Box<dyn SecretStore>,
}

impl CredentialStore {
    /// Wraps a secret store.
    pub fn new(inner: Box<dyn SecretStore>) -> Self {
        CredentialStore { inner }
    }

    /// A store that opens the selected one when it is first used.
    pub fn open_lazy() -> Self {
        CredentialStore::new(Box::new(LazyStore {
            inner: std::sync::Mutex::new(None),
        }))
    }

    /// Returns the session stored for `profile`, if any.
    pub fn load(&self, profile: &str) -> Result<Option<Session>> {
        let Some(raw) = self.inner.get(profile)? else {
            return Ok(None);
        };
        let session: Session = serde_json::from_str(raw.expose()).map_err(|_| {
            Error::StoreUnavailable(format!(
                "the stored entry for profile \"{profile}\" is unreadable; \
                 run: cf-vault login -p {profile}"
            ))
        })?;
        session.validate()?;
        Ok(Some(session))
    }

    /// Stores `session` for `profile`, replacing any existing one.
    pub fn save(&self, profile: &str, session: &Session) -> Result<()> {
        session.validate()?;
        let json = serde_json::to_string(session)
            .map_err(|e| Error::StoreUnavailable(format!("cannot encode session: {e}")))?;
        self.inner.set(profile, &Secret::new(json))
    }

    /// Removes the session of `profile`. Returns false if there was none.
    pub fn remove(&self, profile: &str) -> Result<bool> {
        self.inner.delete(profile)
    }
}

/// Opens the secret store: the platform keyring, or, only in builds with the `test-store`
/// feature and when `CF_VAULT_STORE_DIR` is set, the test file store.
pub fn open() -> Result<Box<dyn SecretStore>> {
    #[cfg(feature = "test-store")]
    {
        if std::env::var_os("CF_VAULT_STORE_UNAVAILABLE").is_some() {
            return Err(Error::StoreUnavailable(
                "simulated unavailable store (test build)".into(),
            ));
        }
        if let Some(dir) = std::env::var_os("CF_VAULT_STORE_DIR") {
            return Ok(Box::new(testing::FileStore::open(dir.into())?));
        }
    }
    Ok(Box::new(keyring::Keychain::open()?))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn oauth() -> Session {
        Session {
            version: SCHEMA,
            kind: SessionKind::Oauth2,
            access_token: Secret::new("at-1"),
            id_token: Some(Secret::new("id-1")),
            refresh_token: Some(Secret::new("rt-1")),
            expires_at: Some(OffsetDateTime::UNIX_EPOCH),
            id_token_expires_at: None,
            issuer: Some("https://id.example".into()),
            client_id: Some("c".into()),
        }
    }

    #[test]
    fn round_trips_through_json() {
        let json = serde_json::to_string(&oauth()).unwrap();
        let back: Session = serde_json::from_str(&json).unwrap();
        back.validate().unwrap();
        assert_eq!(back.kind, SessionKind::Oauth2);
        assert_eq!(back.expires_at, Some(OffsetDateTime::UNIX_EPOCH));
        assert!(json.contains("\"kind\":\"oauth2\""));
    }

    #[test]
    fn debug_never_shows_secrets() {
        let text = format!("{:?}", oauth());
        assert!(!text.contains("at-1") && !text.contains("rt-1") && !text.contains("id-1"));
    }

    #[test]
    fn rejects_invalid_sessions() {
        let mut session = Session::token(Secret::new("t"));
        session.validate().unwrap();
        session.access_token = Secret::new("");
        assert!(session.validate().is_err());
        session.access_token = Secret::new("a\nb");
        assert!(session.validate().is_err());
        let mut future = Session::token(Secret::new("t"));
        future.version = 99;
        assert!(future
            .validate()
            .unwrap_err()
            .to_string()
            .contains("upgrade cf-vault"));
    }
}
