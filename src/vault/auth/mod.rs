//! Authentication: provider resolution, session state, login and refresh. Adapted from
//! nix-vault's auth module (MIT).

pub mod code;
pub mod env;
pub mod prompt;
pub mod redact;
pub mod sts;
pub mod token;

use std::path::Path;

use time::{Duration, OffsetDateTime};

use crate::vault::{
    auth::{
        redact::Secret,
        token::{Provider, TokenSet},
    },
    config::{Kind, OAuth, Profile, ProviderSource},
    store::{locker::with_profile_lock, CredentialStore, Session, SessionKind, SCHEMA},
    Error, Result,
};

/// Sessions that expire within this margin are refreshed before launch.
pub const REFRESH_MARGIN: Duration = Duration::seconds(120);

/// Issuer of Cloudflare's own sign-in.
pub const CLOUDFLARE_ISSUER: &str = "https://dash.cloudflare.com";

/// The public OAuth client registered for cf-vault at Cloudflare. It is empty until a client is
/// registered (release gate, see research.md R1): a profile that needs it fails with a message
/// naming the alternatives.
pub const CLOUDFLARE_CLIENT_ID: &str = "";

/// What can be done with the session stored for a profile.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CredentialState {
    /// Nothing is stored (or what is stored is for another kind of profile).
    Absent,
    /// Stored for a different issuer or client.
    StaleIdentity,
    /// Can be used as it is.
    Usable,
    /// Expiring or expired, but a refresh token exists.
    Expiring,
    /// Expired and cannot be refreshed.
    Expired,
}

/// A provider ready to sign in with: endpoints, client, redirect port and scopes.
pub struct Resolved {
    /// The provider's endpoints.
    pub provider: Provider,
    /// The public client id.
    pub client_id: String,
    /// Loopback port of the sign-in redirect.
    pub redirect_port: u16,
    /// Scopes to request.
    pub scopes: Vec<String>,
}

/// Applies the resolution matrix of data-model.md and reads the provider's discovery document.
pub fn resolve(profile: &Profile, oauth: &OAuth) -> Result<Resolved> {
    let (issuer, client_id) = match oauth.provider_source() {
        ProviderSource::Explicit { issuer, client_id } => (issuer, client_id),
        ProviderSource::Cloudflare => {
            if CLOUDFLARE_CLIENT_ID.is_empty() {
                return Err(Error::config(format!(
                    "profile \"{}\" signs in with Cloudflare's own OAuth client, which is not \
                     available yet; set oauth2.issuer and oauth2.client_id to your own \
                     registered client, or use a type = \"api_token\" profile",
                    profile.name
                )));
            }
            (
                CLOUDFLARE_ISSUER.to_string(),
                CLOUDFLARE_CLIENT_ID.to_string(),
            )
        }
        ProviderSource::Broker => {
            let exchange = oauth.exchange.as_ref().expect("broker source has exchange");
            let metadata = sts::discover(exchange, true)?;
            let idp = sts::pick_provider(&metadata, exchange.provider.as_deref())?;
            (idp.issuer, idp.client_id)
        }
    };
    let provider = token::discover(&issuer)?;
    let scopes = if oauth.scopes.is_empty() {
        let mut scopes = vec!["openid".to_string()];
        if provider
            .scopes_supported
            .iter()
            .any(|s| s == "offline_access")
        {
            scopes.push("offline_access".to_string());
        }
        scopes
    } else {
        oauth.scopes.clone()
    };
    Ok(Resolved {
        provider,
        client_id,
        redirect_port: oauth.redirect_port,
        scopes,
    })
}

/// Computes the state of `stored` for `profile` at time `now` (see data-model.md).
pub fn state(profile: &Profile, stored: Option<&Session>, now: OffsetDateTime) -> CredentialState {
    let Some(stored) = stored else {
        return CredentialState::Absent;
    };
    match (&profile.kind, stored.kind) {
        (Kind::ApiToken, SessionKind::Token) => CredentialState::Usable,
        (Kind::OAuth2(oauth), SessionKind::Oauth2) => {
            let expected = match oauth.provider_source() {
                ProviderSource::Explicit { issuer, client_id } => {
                    Some((issuer.trim_end_matches('/').to_string(), client_id))
                }
                ProviderSource::Cloudflare => Some((
                    CLOUDFLARE_ISSUER.to_string(),
                    CLOUDFLARE_CLIENT_ID.to_string(),
                )),
                // Discovered from the broker at login; nothing to compare without a network call
                ProviderSource::Broker => None,
            };
            if let Some((issuer, client_id)) = expected {
                if stored.issuer.as_deref() != Some(issuer.as_str())
                    || stored.client_id.as_deref() != Some(client_id.as_str())
                {
                    return CredentialState::StaleIdentity;
                }
            }
            let (have_token, expiry) = if oauth.exchange.is_some() {
                (stored.id_token.is_some(), stored.id_token_expires_at)
            } else {
                (true, stored.expires_at)
            };
            let renewable = stored.refresh_token.is_some();
            if !have_token {
                return if renewable {
                    CredentialState::Expiring
                } else {
                    CredentialState::Expired
                };
            }
            match expiry {
                None => CredentialState::Usable,
                Some(expires_at) if expires_at > now + REFRESH_MARGIN => CredentialState::Usable,
                Some(_) if renewable => CredentialState::Expiring,
                Some(_) => CredentialState::Expired,
            }
        }
        _ => CredentialState::Absent,
    }
}

/// Builds the session to store from a token set. A refresh token the provider did not rotate
/// (`previous_refresh`) is kept.
pub fn session_from_tokens(
    resolved_issuer: &str,
    client_id: &str,
    tokens: TokenSet,
    previous_refresh: Option<Secret>,
) -> Session {
    let now = OffsetDateTime::now_utc();
    let expires_at = tokens
        .expires_in
        .map(|lifetime| now + Duration::seconds(lifetime.as_secs() as i64));
    let id_token_expires_at = tokens
        .id_token
        .as_ref()
        .and_then(token::jwt_expiry)
        .or(expires_at);
    Session {
        version: SCHEMA,
        kind: SessionKind::Oauth2,
        access_token: tokens.access_token,
        id_token: tokens.id_token,
        refresh_token: tokens.refresh_token.or(previous_refresh),
        expires_at,
        id_token_expires_at,
        issuer: Some(resolved_issuer.trim_end_matches('/').to_string()),
        client_id: Some(client_id.to_string()),
    }
}

/// Returns a usable session for an OAuth profile, refreshing it first when it expires within
/// the margin. Refreshing is serialized per profile, the stored entry is re-read under the lock
/// (another process may have refreshed already), and a rotated refresh token is saved before
/// the new access token is returned.
pub fn refresh_profile(
    profile: &Profile,
    store: &CredentialStore,
    state_dir: &Path,
) -> Result<Session> {
    let Kind::OAuth2(oauth) = &profile.kind else {
        return Err(Error::usage(format!(
            "profile \"{}\" is not an OAuth profile",
            profile.name
        )));
    };
    with_profile_lock(state_dir, &profile.name, || {
        let stored = store.load(&profile.name)?;
        let no_credentials = |detail: Option<&str>| Error::NoCredentials {
            profile: profile.name.clone(),
            detail: detail.map(str::to_string),
        };
        match state(profile, stored.as_ref(), OffsetDateTime::now_utc()) {
            CredentialState::Usable => Ok(stored.expect("usable")),
            CredentialState::Expiring => {
                let stored = stored.expect("expiring");
                let old = stored
                    .refresh_token
                    .clone()
                    .ok_or_else(|| no_credentials(Some("expired and cannot be refreshed")))?;
                let refresh_error = |detail: String| Error::Refresh {
                    profile: profile.name.clone(),
                    detail,
                };
                let resolved = resolve(profile, oauth).map_err(|e| refresh_error(e.to_string()))?;
                let tokens = token::refresh(&resolved.provider, &resolved.client_id, &old)
                    .map_err(refresh_error)?;
                if let Some(id_token) = &tokens.id_token {
                    token::check_id_token(
                        id_token,
                        &resolved.provider.issuer,
                        &resolved.client_id,
                        None,
                    )
                    .map_err(refresh_error)?;
                }
                if oauth.exchange.is_some() && tokens.id_token.is_none() {
                    return Err(refresh_error(
                        "the provider issued no new ID token".to_string(),
                    ));
                }
                let session = session_from_tokens(
                    &resolved.provider.issuer,
                    &resolved.client_id,
                    tokens,
                    Some(old),
                );
                store
                    .save(&profile.name, &session)
                    .map_err(|_| Error::Refresh {
                        profile: profile.name.clone(),
                        detail: "the refreshed tokens could not be saved".into(),
                    })?;
                Ok(session)
            }
            CredentialState::Absent => Err(no_credentials(None)),
            CredentialState::StaleIdentity => Err(no_credentials(Some(
                "its issuer or OAuth client changed since the last login",
            ))),
            CredentialState::Expired => {
                Err(no_credentials(Some("expired and cannot be refreshed")))
            }
        }
    })
}

/// Logs in to an OAuth profile: runs the browser flow and, only after it succeeded, replaces the
/// stored session.
pub fn login_oauth(
    profile: &Profile,
    store: &CredentialStore,
    state_dir: &Path,
    no_browser: bool,
) -> Result<()> {
    let Kind::OAuth2(oauth) = &profile.kind else {
        return Err(Error::usage(format!(
            "profile \"{}\" is not an OAuth profile",
            profile.name
        )));
    };
    let resolved = resolve(profile, oauth)?;
    let tokens = code::login(&code::Request {
        profile: &profile.name,
        provider: &resolved.provider,
        client_id: &resolved.client_id,
        redirect_port: resolved.redirect_port,
        scopes: &resolved.scopes,
        no_browser,
    })?;
    if oauth.exchange.is_some() && tokens.id_token.is_none() {
        return Err(Error::Auth(
            "the identity provider returned no ID token, which the broker needs; \
             request the openid scope"
                .into(),
        ));
    }
    let session = session_from_tokens(&resolved.provider.issuer, &resolved.client_id, tokens, None);
    // The old session is replaced only now, after the flow succeeded
    with_profile_lock(state_dir, &profile.name, || {
        store.save(&profile.name, &session)
    })
}

/// Stores a static API token for a `type = "api_token"` profile.
pub fn login_token(
    profile: &Profile,
    store: &CredentialStore,
    state_dir: &Path,
    prompt: &dyn prompt::Prompt,
) -> Result<()> {
    if !matches!(profile.kind, Kind::ApiToken) {
        return Err(Error::usage(format!(
            "profile \"{}\" is not an api_token profile",
            profile.name
        )));
    }
    let token = prompt.token(&profile.name)?;
    let session = Session::token(token);
    with_profile_lock(state_dir, &profile.name, || {
        store.save(&profile.name, &session)
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::vault::config::Config;

    fn profiles() -> (Profile, Profile, Profile) {
        let config = Config::parse(
            "[t]\ntype=\"api_token\"\naccount_id=\"a\"\n\
             [o]\ntype=\"oauth2\"\naccount_id=\"a\"\n[o.oauth2]\nissuer=\"https://id.example\"\nclient_id=\"c\"\n\
             [x]\ntype=\"oauth2\"\naccount_id=\"a\"\n[x.oauth2.exchange]\nissuer=\"https://b.example\"\nscopes=[\"p\"]\n",
        )
        .unwrap();
        (
            config.profiles[0].clone(),
            config.profiles[1].clone(),
            config.profiles[2].clone(),
        )
    }

    fn oauth(
        issuer: &str,
        expires_in: Option<i64>,
        refresh: bool,
        id_expires_in: Option<i64>,
    ) -> Session {
        let now = OffsetDateTime::now_utc();
        Session {
            version: SCHEMA,
            kind: SessionKind::Oauth2,
            access_token: Secret::new("at"),
            id_token: Some(Secret::new("id")),
            refresh_token: refresh.then(|| Secret::new("rt")),
            expires_at: expires_in.map(|s| now + Duration::seconds(s)),
            id_token_expires_at: id_expires_in.map(|s| now + Duration::seconds(s)),
            issuer: Some(issuer.to_string()),
            client_id: Some("c".into()),
        }
    }

    #[test]
    fn state_table() {
        let (token, own, brokered) = profiles();
        let now = OffsetDateTime::now_utc();
        assert_eq!(state(&token, None, now), CredentialState::Absent);
        let stored = Session::token(Secret::new("t"));
        assert_eq!(state(&token, Some(&stored), now), CredentialState::Usable);
        // A token session for an OAuth profile counts as not signed in
        assert_eq!(state(&own, Some(&stored), now), CredentialState::Absent);

        let id = "https://id.example";
        assert_eq!(
            state(&own, Some(&oauth(id, None, false, None)), now),
            CredentialState::Usable
        );
        assert_eq!(
            state(&own, Some(&oauth(id, Some(3600), false, None)), now),
            CredentialState::Usable
        );
        assert_eq!(
            state(&own, Some(&oauth(id, Some(60), true, None)), now),
            CredentialState::Expiring
        );
        assert_eq!(
            state(&own, Some(&oauth(id, Some(-5), false, None)), now),
            CredentialState::Expired
        );
        assert_eq!(
            state(
                &own,
                Some(&oauth("https://other.example", Some(3600), true, None)),
                now
            ),
            CredentialState::StaleIdentity
        );
        // Exchange profiles look at the ID token's expiry, not the access token's
        assert_eq!(
            state(&brokered, Some(&oauth(id, Some(-5), true, Some(3600))), now),
            CredentialState::Usable
        );
        assert_eq!(
            state(&brokered, Some(&oauth(id, Some(3600), true, Some(30))), now),
            CredentialState::Expiring
        );
    }
}
