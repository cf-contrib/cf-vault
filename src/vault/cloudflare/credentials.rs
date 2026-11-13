//! The credentials delivered to a command. They exist only in memory.

use time::OffsetDateTime;

use crate::vault::auth::redact::Secret;

/// Temporary S3-compatible credentials for one R2 bucket. They cannot be revoked; they expire.
#[derive(Clone, Debug)]
pub struct R2Credentials {
    /// Access key id.
    pub access_key_id: Secret,
    /// Secret access key.
    pub secret_access_key: Secret,
    /// Session token.
    pub session_token: Secret,
    /// `https://<account_id>.r2.cloudflarestorage.com`, or the broker's value.
    pub endpoint: String,
    /// The bucket the credentials are limited to.
    pub bucket: String,
    /// Key prefixes the credentials are limited to; empty means the whole bucket.
    pub prefixes: Vec<String>,
    /// When they expire.
    pub expires_at: Option<OffsetDateTime>,
}

/// A broker-issued API token to release after the command exits (RFC 7009).
#[derive(Clone, Debug)]
pub struct Revocation {
    /// The broker's revocation endpoint.
    pub endpoint: String,
    /// The token to revoke.
    pub token: Secret,
}

/// What the command receives: an API token and, optionally, R2 credentials.
#[derive(Clone, Debug)]
pub struct CredentialSet {
    /// Delivered as `CLOUDFLARE_API_TOKEN`. Absent for bucket-only broker profiles.
    pub api_token: Option<Secret>,
    /// The broker's id for the token, shown (shortened) in the summary.
    pub api_token_id: Option<String>,
    /// Delivered as `CLOUDFLARE_ACCOUNT_ID`.
    pub account_id: String,
    /// Temporary R2 credentials.
    pub r2: Option<R2Credentials>,
    /// The earliest expiry among the parts.
    pub expires_at: Option<OffsetDateTime>,
    /// How to release the API token after the command exits (broker only).
    pub revocation: Option<Revocation>,
}

impl CredentialSet {
    /// A set holding only an API token.
    pub fn token(account_id: &str, token: Secret, expires_at: Option<OffsetDateTime>) -> Self {
        CredentialSet {
            api_token: Some(token),
            api_token_id: None,
            account_id: account_id.to_string(),
            r2: None,
            expires_at,
            revocation: None,
        }
    }

    /// Recomputes the earliest expiry from the API token expiry and the R2 credentials.
    pub fn earliest(&self, api_token_expiry: Option<OffsetDateTime>) -> Option<OffsetDateTime> {
        [
            api_token_expiry,
            self.r2.as_ref().and_then(|r| r.expires_at),
        ]
        .into_iter()
        .flatten()
        .min()
    }
}
