//! `list`: profiles and the state of their sessions, never a secret.

use std::io::Write;

use time::OffsetDateTime;

use crate::{
    app::args::ListCommandArgs,
    vault::{
        auth::{self, CredentialState},
        config::{Config, Kind, Profile},
        store::{CredentialStore, Session},
        Result,
    },
};

/// The `list` command.
pub struct ListCommand {
    /// Where the output goes.
    pub writer: Box<dyn Write>,
    /// The validated configuration.
    pub config: Config,
    /// Where sessions are kept.
    pub store: CredentialStore,
    /// The time expiry is judged against.
    pub now: OffsetDateTime,
}

/// The label of a profile's session state.
pub fn label(profile: &Profile, stored: Option<&Session>, now: OffsetDateTime) -> &'static str {
    match (auth::state(profile, stored, now), &profile.kind) {
        (CredentialState::Usable, Kind::Token) => "static token",
        (CredentialState::Usable | CredentialState::Expiring, _) => "signed in",
        (CredentialState::Expired, _) => "expired",
        (CredentialState::Absent | CredentialState::StaleIdentity, _) => "not signed in",
    }
}

fn kind_name(profile: &Profile) -> &'static str {
    match profile.kind {
        Kind::Token => "token",
        Kind::OAuth2(_) => "oauth2",
    }
}

impl ListCommand {
    /// Runs the command.
    pub fn execute(&mut self, args: &ListCommandArgs) -> Result<()> {
        let mut rows = Vec::new();
        for profile in &self.config.profiles {
            let stored = self.store.load(&profile.name)?;
            rows.push((
                profile.name.clone(),
                kind_name(profile),
                profile.account_id.clone(),
                profile.exchange().is_some(),
                label(profile, stored.as_ref(), self.now),
            ));
        }
        if args.json {
            let items: Vec<_> = rows
                .iter()
                .map(|(name, kind, account, exchange, state)| {
                    serde_json::json!({
                        "profile": name,
                        "type": kind,
                        "account_id": account,
                        "exchange": exchange,
                        "state": state,
                    })
                })
                .collect();
            writeln!(self.writer, "{}", serde_json::Value::Array(items))?;
            return Ok(());
        }
        let width = |f: fn(&(String, &'static str, String, bool, &'static str)) -> usize| {
            rows.iter().map(f).max().unwrap_or(0)
        };
        let (w_name, w_account) = (width(|r| r.0.len()).max(7), width(|r| r.2.len()).max(7));
        writeln!(
            self.writer,
            "{:<w_name$}  {:<6}  {:<w_account$}  {:<8}  STATE",
            "PROFILE", "TYPE", "ACCOUNT", "EXCHANGE"
        )?;
        for (name, kind, account, exchange, state) in rows {
            writeln!(
                self.writer,
                "{name:<w_name$}  {kind:<6}  {account:<w_account$}  {:<8}  {state}",
                if exchange { "yes" } else { "no" }
            )?;
        }
        Ok(())
    }
}
