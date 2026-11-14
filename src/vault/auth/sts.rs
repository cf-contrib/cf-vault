//! The token broker client (the "STS"): metadata discovery, RFC 8693 token exchange and RFC 7009
//! revocation. Written against `cloudflare-sts` and usable with any broker that speaks the same
//! standards: what is not standard (`account_id`, `token_id`, `bucket`) is optional in the answer.
//! Request and response bodies are never logged; errors carry the OAuth error code and
//! description only.

use std::{
    collections::HashMap,
    sync::{Mutex, OnceLock},
    time::Duration,
};

use serde::Deserialize;
use time::OffsetDateTime;

use crate::vault::{
    auth::{redact::Secret, token::http_client},
    cloudflare::creds::R2Credentials,
    config::{endpoint_allowed, Exchange},
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

/// What the broker's discovery document says, and the endpoints in use once the configuration
/// has been applied on top of it.
#[derive(Clone, Debug)]
pub struct Metadata {
    /// The broker's issuer (its URL), or the token endpoint's origin when none is configured.
    pub issuer: String,
    /// `POST` here to exchange a token.
    pub token_endpoint: String,
    /// `POST` here to revoke a token, when the broker has such an endpoint.
    pub revocation_endpoint: Option<String>,
    /// Providers people sign in with.
    pub identity_providers: Vec<IdentityProvider>,
}

/// The fields of the broker's metadata that are used.
#[derive(Clone, Deserialize)]
struct RawMetadata {
    issuer: Option<String>,
    token_endpoint: Option<String>,
    revocation_endpoint: Option<String>,
    #[serde(default)]
    identity_providers: Vec<IdentityProvider>,
}

/// Largest metadata document accepted.
const MAX_BYTES: usize = 256 * 1024;

/// Metadata read so far in this process, by issuer: `login` and `exec` ask more than once.
static CACHE: OnceLock<Mutex<HashMap<String, RawMetadata>>> = OnceLock::new();

fn same_host(a: &str, b: &str) -> bool {
    match (oauth2::url::Url::parse(a), oauth2::url::Url::parse(b)) {
        (Ok(a), Ok(b)) => {
            a.host_str() == b.host_str() && a.port_or_known_default() == b.port_or_known_default()
        }
        _ => false,
    }
}

/// The two places a broker may publish its metadata: RFC 8414 (the well-known path goes between
/// the origin and the issuer's path), then OpenID Connect Discovery.
fn metadata_urls(issuer: &str) -> Vec<String> {
    let rfc8414 = oauth2::url::Url::parse(issuer).ok().map(|u| {
        let origin = u.origin().ascii_serialization();
        let path = u.path().trim_end_matches('/');
        format!("{origin}/.well-known/oauth-authorization-server{path}")
    });
    rfc8414
        .into_iter()
        .chain([format!("{issuer}/.well-known/openid-configuration")])
        .collect()
}

fn fetch(url: &str, issuer: &str) -> std::result::Result<RawMetadata, String> {
    let http = http_client().map_err(|e| e.to_string())?;
    let response = http
        .get(url)
        .send()
        .map_err(|_| format!("could not reach the broker at {issuer}"))?;
    if !response.status().is_success() {
        return Err(format!(
            "the broker at {issuer} has no metadata at {url} (HTTP {})",
            response.status().as_u16()
        ));
    }
    let bytes = response
        .bytes()
        .map_err(|_| "could not read the broker's metadata".to_string())?;
    if bytes.len() > MAX_BYTES {
        return Err(format!(
            "the metadata of the broker at {issuer} is too large"
        ));
    }
    let raw: RawMetadata = serde_json::from_slice(&bytes)
        .map_err(|_| format!("the metadata of the broker at {issuer} is not valid"))?;
    if raw.issuer.as_deref().map(|i| i.trim_end_matches('/')) != Some(issuer) {
        return Err(format!(
            "the broker's metadata names a different issuer than {issuer}"
        ));
    }
    Ok(raw)
}

/// Reads the broker's metadata (RFC 8414, else OpenID Connect Discovery); the issuer in the
/// document must be the one asked for. The answer is kept for the life of the process.
fn metadata(issuer: &str) -> Result<RawMetadata> {
    let cache = CACHE.get_or_init(Default::default);
    if let Some(found) = cache.lock().unwrap().get(issuer) {
        return Ok(found.clone());
    }
    let mut first_error = None;
    for url in metadata_urls(issuer) {
        match fetch(&url, issuer) {
            Ok(raw) => {
                cache
                    .lock()
                    .unwrap()
                    .insert(issuer.to_string(), raw.clone());
                return Ok(raw);
            }
            Err(e) => {
                first_error.get_or_insert(e);
            }
        }
    }
    Err(Error::Exchange(first_error.unwrap_or_else(|| {
        format!("the broker at {issuer} has no metadata")
    })))
}

/// The broker's metadata as configured: the issuer's document for what the profile leaves out,
/// the profile's own endpoints over it. Discovered endpoints must be on the broker's own host.
/// With every endpoint set the document is not read at all, unless `need_providers` (sign-in
/// needs the identity provider list, which only the document has).
pub fn discover(exchange: &Exchange, need_providers: bool) -> Result<Metadata> {
    let Some(issuer) = &exchange.issuer else {
        // No issuer: the endpoints are the configuration
        let token_endpoint = exchange
            .token_endpoint
            .clone()
            .expect("validated: an issuer or a token endpoint");
        return Ok(Metadata {
            issuer: token_origin(&token_endpoint),
            token_endpoint,
            revocation_endpoint: exchange.revocation_endpoint.clone(),
            identity_providers: Vec::new(),
        });
    };
    let complete = exchange.token_endpoint.is_some() && exchange.revocation_endpoint.is_some();
    let raw = if complete && !need_providers {
        None
    } else {
        Some(metadata(issuer)?)
    };
    let discovered = |own: &Option<String>, found: Option<&String>, key: &str| match (own, found) {
        (Some(own), _) => Ok(Some(own.clone())),
        (None, Some(found)) => {
            if !endpoint_allowed(found) || !same_host(found, issuer) {
                return Err(Error::Exchange(format!(
                    "the broker at {issuer} names an endpoint that is not https on its own host"
                )));
            }
            Ok(Some(found.clone()))
        }
        (None, None) if key == "revocation_endpoint" => Ok(None),
        (None, None) => Err(Error::Exchange(format!(
            "the metadata of the broker at {issuer} has no \"{key}\"; set \
             oauth2.exchange.{key}"
        ))),
    };
    let token_endpoint = discovered(
        &exchange.token_endpoint,
        raw.as_ref().and_then(|r| r.token_endpoint.as_ref()),
        "token_endpoint",
    )?
    .expect("an endpoint or an error");
    let revocation_endpoint = discovered(
        &exchange.revocation_endpoint,
        raw.as_ref().and_then(|r| r.revocation_endpoint.as_ref()),
        "revocation_endpoint",
    )?;
    Ok(Metadata {
        issuer: issuer.clone(),
        token_endpoint,
        revocation_endpoint,
        identity_providers: raw.map(|r| r.identity_providers).unwrap_or_default(),
    })
}

fn token_origin(endpoint: &str) -> String {
    oauth2::url::Url::parse(endpoint)
        .map(|u| u.origin().ascii_serialization())
        .unwrap_or_else(|_| endpoint.to_string())
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
    pub r2_credentials: Option<R2Credentials>,
}

#[derive(Deserialize)]
struct RawIssued {
    #[serde(default)]
    access_token: Option<String>,
    #[serde(default)]
    token_id: Option<String>,
    #[serde(default)]
    account_id: Option<String>,
    /// The broker's own absolute expiry (unix seconds), when it gives one.
    #[serde(default)]
    expires_at: Option<i64>,
    /// The standard lifetime in seconds (RFC 8693 §2.2.1).
    #[serde(default)]
    expires_in: Option<i64>,
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

/// Exchanges the user's ID token for what the broker grants for the configured scopes (RFC
/// 8693). A `503` is retried once after a second; nothing else is retried and no weaker
/// credential is ever tried.
pub fn exchange(
    metadata: &Metadata,
    id_token: &Secret,
    settings: &Exchange,
    ttl: Option<&str>,
) -> Result<Issued> {
    let http = http_client()?;
    let scope = settings.scopes.join(" ");
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
    ];
    if !scope.is_empty() {
        form.push(("scope", &scope));
    }
    if let Some(audience) = &settings.audience {
        form.push(("audience", audience));
    }
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
            .and_then(|t| OffsetDateTime::from_unix_timestamp(t).ok())
            .or_else(|| {
                raw.expires_in
                    .filter(|s| *s > 0)
                    .map(|s| OffsetDateTime::now_utc() + time::Duration::seconds(s))
            });
        let r2_credentials = raw.bucket.map(|b| R2Credentials {
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
            r2_credentials,
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
            revocation_endpoint: Some("https://b.example/oauth/revoke".into()),
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
    fn metadata_is_looked_up_per_rfc_8414_then_openid() {
        assert_eq!(
            metadata_urls("https://b.example"),
            [
                "https://b.example/.well-known/oauth-authorization-server",
                "https://b.example/.well-known/openid-configuration"
            ]
        );
        // The well-known path goes between the origin and the issuer's path
        assert_eq!(
            metadata_urls("https://b.example/tenant/a")[0],
            "https://b.example/.well-known/oauth-authorization-server/tenant/a"
        );
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
