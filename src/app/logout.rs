//! `logout`: remove the stored session; revoke the refresh token on a best-effort basis.

use crate::{
    app::{args::LogoutCommandArgs, select, warn},
    vault::{
        auth::{self, token},
        config::{Config, Kind},
        store::{CredentialStore, SessionKind},
        Result,
    },
};

/// The `logout` command.
pub struct LogoutCommand {
    /// The validated configuration.
    pub config: Config,
    /// Where sessions are kept.
    pub store: CredentialStore,
}

impl LogoutCommand {
    /// Runs the command.
    pub fn execute(&mut self, args: &LogoutCommandArgs) -> Result<()> {
        let profile = select(&self.config, args.profile.profile.as_deref())?.clone();
        let stored = self.store.load(&profile.name)?;
        // The local copy goes first: logging out must work whatever the network does
        let removed = self.store.remove(&profile.name)?;
        if let (Some(session), Kind::OAuth2(oauth)) = (&stored, &profile.kind) {
            if session.kind == SessionKind::Oauth2 {
                let secret = session
                    .refresh_token
                    .as_ref()
                    .unwrap_or(&session.access_token);
                match auth::resolve(&profile, oauth) {
                    Ok(resolved) => {
                        if let Err(e) =
                            token::revoke(&resolved.provider, &resolved.client_id, secret)
                        {
                            warn(format!("the token was not revoked at the provider ({e})"));
                        }
                    }
                    Err(e) => warn(format!("the token was not revoked at the provider ({e})")),
                }
            }
        }
        if removed {
            println!("Logged out of profile \"{}\".", profile.name);
        } else {
            println!("Profile \"{}\" had no stored session.", profile.name);
        }
        Ok(())
    }
}
