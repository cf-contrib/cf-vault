//! The command line -- [`args`], what it parses -- and what it runs: [`login`], [`logout`],
//! [`list`] and [`exec`].

pub mod args;
pub mod exec;
pub mod list;
pub mod login;
pub mod logout;

use crate::vault::config::{Config, Profile};
use crate::vault::Result;

/// Prints a status line on stderr.
pub fn say(message: impl std::fmt::Display) {
    eprintln!("cf-vault: {message}");
}

/// Prints a warning on stderr.
pub fn warn(message: impl std::fmt::Display) {
    eprintln!("cf-vault: warning: {message}");
}

/// Picks the profile named by `-p`/`CF_VAULT_PROFILE`, or fails listing the configured ones.
pub fn select<'a>(config: &'a Config, name: Option<&str>) -> Result<&'a Profile> {
    match name {
        Some(name) => config.profile(name),
        None => Err(config.unknown(None)),
    }
}

/// Formats a time the way the summaries show it.
pub fn show_time(time: time::OffsetDateTime) -> String {
    time.format(&time::format_description::well_known::Rfc3339)
        .unwrap_or_else(|_| "unknown".to_string())
}
