//! The token broker client (the "STS"): discovery, RFC 8693 token exchange and RFC 7009 revocation, exactly as
//! `contracts/broker.md` describes the `cloudflare-sts` API. Request and response bodies are never
//! logged; errors carry the OAuth error code and description only.

use std::time::Duration;

use serde::Deserialize;
use time::OffsetDateTime;

use crate::vault::{
    auth::{redact::Secret, token::http_client},
    cloudflare::creds::R2Credentials,
    config::endpoint_allowed,
    Error, Result,
};

/// An identity provider the broker's metadata lists for people to sign in with.
#[derive(Clone, Debug, Deserialize)]
pub struct IdentityProvider {
    /// The broker's name for it.
    pub name: String,
    /// Its issuer.
    pub issuer: String,
    /// The client to sign in as.
    pub client_id: String,
}

/// What the broker's discovery document says.
#[derive(Clone, Debug)]
pub struct Metadata {
    /// The broker's issuer (its URL).
    pub issuer: String,
    /// `POST` here to exchange a token.
    pub token_endpoint: String,
    /// `POST` here to revoke a token.
    pub revocation_endpoint: String,
    /// Providers people sign in with.
    pub identity_providers: Vec<IdentityProvider>,
}

#[derive(Deserialize)]
struct RawMetadata {
    issuer: String,
    token_endpoint: String,
    revocation_endpoint: String,
    #[serde(default)]
    identity_providers: Vec<IdentityProvider>,
}

fn same_host(a: &str, b: &str) -> bool {
    match (oauth2::url::Url::parse(a), oauth2::url::Url::parse(b)) {
        (Ok(a), Ok(b)) => {
            a.host_str() == b.host_str() && a.port_or_known_default() == b.port_or_known_default()
        }
        _ => false,
    }
}

/// Reads `GET {url}/.well-known/oauth-authorization-server` (RFC 8414). The issuer must equal the
/// configured URL and both endpoints must be `https` (or loopback `http`) on the same host.
pub fn discover(url: &str) -> Result<Metadata> {
    let url = url.trim_end_matches('/');
    let http = http_client()?;
    let response = http
        .get(format!("{url}/.well-known/oauth-authorization-server"))
        .send()
        .map_err(|_| Error::Exchange(format!("could not reach the broker at {url}")))?;
    if !response.status().is_success() {
        return Err(Error::Exchange(format!(
            "the broker at {url} has no metadata (HTTP {})",
            response.status().as_u16()
        )));
    }
    let text = response
        .text()
        .map_err(|_| Error::Exchange("could not read the broker's metadata".into()))?;
    let raw: RawMetadata = serde_json::from_str(&text).map_err(|_| {
        Error::Exchange(format!("the metadata of the broker at {url} is not valid"))
    })?;
    if raw.issuer.trim_end_matches('/') != url {
        return Err(Error::Exchange(format!(
            "the broker's metadata names a different issuer than {url}"
        )));
    }
    for endpoint in [&raw.token_endpoint, &raw.revocation_endpoint] {
        if !endpoint_allowed(endpoint) || !same_host(endpoint, url) {
            return Err(Error::Exchange(format!(
                "the broker at {url} names an endpoint that is not https on its own host"
            )));
        }
    }
    Ok(Metadata {
        issuer: url.to_string(),
        token_endpoint: raw.token_endpoint,
        revocation_endpoint: raw.revocation_endpoint,
        identity_providers: raw.identity_providers,
    })
}

/// Picks the identity provider to sign in with: the named one, or the only one.
pub fn pick_provider(metadata: &Metadata, wanted: Option<&str>) -> Result<IdentityProvider> {
    let names = || {
        metadata
            .identity_providers
            .iter()
            .map(|p| p.name.as_str())
            .collect::<Vec<_>>()
            .join(", ")
    };
    match (wanted, metadata.identity_providers.as_slice()) {
        (_, []) => Err(Error::Exchange(format!(
            "the broker at {} lists no identity providers to sign in with",
            metadata.issuer
        ))),
        (Some(name), providers) => providers
            .iter()
            .find(|p| p.name == name)
            .cloned()
            .ok_or_else(|| {
                Error::Exchange(format!(
                    "the broker lists no identity provider named \"{name}\"; it lists: {}",
                    names()
                ))
            }),
        (None, [only]) => Ok(only.clone()),
        (None, _) => Err(Error::Exchange(format!(
            "the broker lists several identity providers ({}); set oauth2.exchange.provider",
            names()
        ))),
    }
}

/// What an exchange issued.
#[derive(Debug)]
pub struct Issued {
    /// The Cloudflare API token, absent for a bucket-only profile.
    pub access_token: Option<Secret>,
    /// The broker's id for the token.
    pub token_id: Option<String>,
    /// The Cloudflare account the credentials are for.
    pub account_id: Option<String>,
    /// When the token or the R2 credentials expire.
    pub expires_at: Option<OffsetDateTime>,
    /// R2 credentials, for a profile with a bucket.
    pub r2: Option<R2Credentials>,
}

#[derive(Deserialize)]
struct RawIssued {
    #[serde(default)]
    access_token: Option<String>,
    #[serde(default)]
    token_id: Option<String>,
    #[serde(default)]
    account_id: Option<String>,
    #[serde(default)]
    expires_at: Option<i64>,
    #[serde(default)]
    bucket: Option<RawBucket>,
}

#[derive(Deserialize)]
struct RawBucket {
    name: String,
    access_key_id: String,
    secret_access_key: String,
    session_token: String,
    #[serde(default)]
    prefixes: Vec<String>,
    endpoint: String,
}

#[derive(Deserialize)]
struct RawError {
    #[serde(default)]
    error: String,
    #[serde(default)]
    error_description: String,
}

fn describe_error(status: u16, body: &str, secrets: &[&str]) -> String {
    if let Ok(parsed) = serde_json::from_str::<RawError>(body) {
        if !parsed.error.is_empty() {
            let code: String = parsed
                .error
                .chars()
                .filter(|c| c.is_ascii_alphanumeric() || *c == '_')
                .take(60)
                .collect();
            let description: String =
                crate::vault::auth::redact::redact(&parsed.error_description, secrets)
                    .chars()
                    .take(300)
                    .collect();
            return if description.is_empty() {
                code
            } else {
                format!("{code}: {description}")
            };
        }
    }
    format!("the broker answered HTTP {status}")
}

fn retry_delay() -> Duration {
    #[cfg(feature = "test-store")]
    if let Some(ms) = std::env::var("CF_VAULT_RETRY_DELAY_MS")
        .ok()
        .and_then(|v| v.parse::<u64>().ok())
    {
        return Duration::from_millis(ms);
    }
    Duration::from_secs(1)
}

/// Exchanges the user's ID token for what the broker profile grants (RFC 8693). A `503` is
/// retried once after a second; nothing else is retried and no weaker credential is ever tried.
pub fn exchange(
    metadata: &Metadata,
    id_token: &Secret,
    profile: &str,
    ttl: Option<&str>,
) -> Result<Issued> {
    let http = http_client()?;
    let mut form = vec![
        (
            "grant_type",
            "urn:ietf:params:oauth:grant-type:token-exchange",
        ),
        ("subject_token", id_token.expose()),
        (
            "subject_token_type",
            "urn:ietf:params:oauth:token-type:id_token",
        ),
        ("profile", profile),
    ];
    if let Some(ttl) = ttl {
        form.push(("ttl", ttl));
    }
    let secrets = [id_token.expose()];
    for attempt in 0..2 {
        let response = http
            .post(&metadata.token_endpoint)
            .form(&form)
            .send()
            .map_err(|_| {
                Error::Exchange(format!("could not reach the broker at {}", metadata.issuer))
            })?;
        let status = response.status().as_u16();
        let body = response
            .text()
            .map_err(|_| Error::Exchange("could not read the broker's answer".into()))?;
        if status == 503 && attempt == 0 {
            std::thread::sleep(retry_delay());
            continue;
        }
        if status != 200 {
            return Err(Error::Exchange(describe_error(status, &body, &secrets)));
        }
        let raw: RawIssued = serde_json::from_str(&body)
            .map_err(|_| Error::Exchange("the broker returned an unexpected response".into()))?;
        let expires_at = raw
            .expires_at
            .and_then(|t| OffsetDateTime::from_unix_timestamp(t).ok());
        let r2 = raw.bucket.map(|b| R2Credentials {
            access_key_id: Secret::new(b.access_key_id),
            secret_access_key: Secret::new(b.secret_access_key),
            session_token: Secret::new(b.session_token),
            endpoint: b.endpoint,
            bucket: b.name,
            prefixes: b.prefixes,
            expires_at,
        });
        return Ok(Issued {
            access_token: raw.access_token.filter(|t| !t.is_empty()).map(Secret::new),
            token_id: raw.token_id,
            account_id: raw.account_id,
            expires_at,
            r2,
        });
    }
    unreachable!("the loop returns on its second attempt")
}

/// Releases a broker-issued API token (RFC 7009). The broker answers `200` whatever the token's
/// state, so only transport problems are errors.
pub fn revoke(endpoint: &str, token: &Secret) -> std::result::Result<(), String> {
    let http = http_client().map_err(|e| e.to_string())?;
    let response = http
        .post(endpoint)
        .form(&[
            ("token", token.expose()),
            ("token_type_hint", "access_token"),
        ])
        .send()
        .map_err(|_| "could not reach the broker to revoke the token".to_string())?;
    if response.status().is_success() {
        Ok(())
    } else {
        Err(format!(
            "the broker answered HTTP {} to the revocation",
            response.status().as_u16()
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn metadata(names: &[&str]) -> Metadata {
        Metadata {
            issuer: "https://b.example".into(),
            token_endpoint: "https://b.example/oauth/token".into(),
            revocation_endpoint: "https://b.example/oauth/revoke".into(),
            identity_providers: names
                .iter()
                .map(|n| IdentityProvider {
                    name: n.to_string(),
                    issuer: format!("https://{n}.example"),
                    client_id: format!("client-{n}"),
                })
                .collect(),
        }
    }

    #[test]
    fn picks_the_only_or_the_named_provider() {
        assert_eq!(pick_provider(&metadata(&["a"]), None).unwrap().name, "a");
        assert_eq!(
            pick_provider(&metadata(&["a", "b"]), Some("b"))
                .unwrap()
                .name,
            "b"
        );
        let e = pick_provider(&metadata(&["a", "b"]), None)
            .unwrap_err()
            .to_string();
        assert!(e.contains("a, b") && e.contains("oauth2.exchange.provider"));
        assert!(pick_provider(&metadata(&[]), None).is_err());
        let e = pick_provider(&metadata(&["a"]), Some("zzz"))
            .unwrap_err()
            .to_string();
        assert!(e.contains("zzz") && e.contains("it lists: a"));
    }

    #[test]
    fn errors_show_the_code_and_description_but_no_secrets() {
        let body = r#"{"error":"invalid_request","error_description":"the subject token SECRET-9 has expired"}"#;
        let text = describe_error(400, body, &["SECRET-9"]);
        assert!(text.starts_with("invalid_request: ") && !text.contains("SECRET-9"));
        assert_eq!(
            describe_error(502, "<html>SECRET-9</html>", &["SECRET-9"]),
            "the broker answered HTTP 502"
        );
    }
}
