//! The hidden prompt for static API tokens. Adapted from nix-vault's basic prompt (MIT).

use std::io::IsTerminal;

use crate::vault::{auth::redact::Secret, Error, Result};

/// Asks the user for a token.
pub trait Prompt {
    /// Asks for the API token (hidden).
    fn token(&self, profile: &str) -> Result<Secret>;
}

/// Prompts on the terminal.
pub struct TerminalPrompt;

impl Prompt for TerminalPrompt {
    fn token(&self, profile: &str) -> Result<Secret> {
        if !std::io::stdin().is_terminal() {
            return Err(Error::Auth(
                "login needs an interactive terminal to ask for the token; \
                 run cf-vault login from a terminal"
                    .into(),
            ));
        }
        let token = rpassword::prompt_password(format!("Cloudflare API token for {profile}: "))
            .map_err(|_| Error::Auth("login cancelled".into()))?;
        let token = token.trim().to_string();
        if token.is_empty() {
            return Err(Error::Auth("the token is empty; login cancelled".into()));
        }
        Ok(Secret::new(token))
    }
}
