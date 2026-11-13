//! `login`: browser sign-in for OAuth profiles, a hidden prompt for token profiles.

use std::io::IsTerminal;

use crate::{
    app::{args::LoginCommandArgs, select},
    vault::{
        auth::{self, prompt::Prompt},
        config::{Config, Kind},
        store::CredentialStore,
        Error, Result,
    },
};

/// The `login` command.
pub struct LoginCommand {
    /// The validated configuration.
    pub config: Config,
    /// Where sessions are kept.
    pub store: CredentialStore,
    /// Asks for tokens.
    pub prompt: Box<dyn Prompt>,
}

impl LoginCommand {
    /// Runs the command.
    pub fn execute(&mut self, args: &LoginCommandArgs) -> Result<()> {
        let profile = select(&self.config, args.profile.profile.as_deref())?.clone();
        let state_dir = &args.parent.state_dir;
        match &profile.kind {
            Kind::OAuth2(_) => {
                // The browser needs a person; --no-browser prints the URL for one on another screen
                if !args.no_browser && !std::io::stdin().is_terminal() {
                    return Err(Error::Auth(
                        "login needs an interactive terminal to open the browser; run it from a \
                         terminal, or pass --no-browser and open the printed URL yourself"
                            .into(),
                    ));
                }
                auth::login_oauth(&profile, &self.store, state_dir, args.no_browser)?;
            }
            Kind::Token => {
                auth::login_token(&profile, &self.store, state_dir, self.prompt.as_ref())?;
            }
        }
        println!("Logged in to profile \"{}\".", profile.name);
        Ok(())
    }
}
