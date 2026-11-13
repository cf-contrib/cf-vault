//! Command line definitions. Adapted from nix-vault (MIT).

use std::path::PathBuf;

use clap::{Args, Parser, Subcommand};

use crate::vault::config;

const PROGRAM_HELP: &str = "Get started:
  cf-vault login -p personal              # sign in (or store a token) for the `personal` profile
  cf-vault exec -p personal -- terraform plan
  cf-vault list                           # profiles and whether a session exists

Profiles live in ~/.config/cf-vault/config.toml (see config.example.toml).";
const LOGIN_EXAMPLES: &str = "Examples:
  cf-vault login -p personal              # browser sign-in for an OAuth profile
  cf-vault login -p ci-state              # hidden prompt for a static API token";
const EXEC_EXAMPLES: &str = "Examples:
  cf-vault exec -p production -- terraform plan
  cf-vault exec -p ci-state --ttl 1h -- tofu apply
  CF_VAULT_PROFILE=production cf-vault exec -- wrangler deploy";
const LOGOUT_EXAMPLES: &str = "Examples:
  cf-vault logout -p personal             # remove the stored session";
const LIST_EXAMPLES: &str = "Examples:
  cf-vault list                           # profile, type, account and session state
  cf-vault list --json                    # the same, for scripts";

/// Program is the main entry point for the cf-vault CLI.
#[derive(Debug, Parser)]
#[command(
    name = "cf-vault",
    about = "Manage Cloudflare credentials.",
    long_about = "Sign in to Cloudflare (or store an API token), keep the session in the system \
                  keychain, and run commands with short-lived credentials in their environment \
                  only.",
    after_help = PROGRAM_HELP,
    version
)]
pub struct Program {
    /// Command specifies the subcommand to execute.
    #[command(subcommand)]
    pub command: ProgramCommand,
}

/// Flags shared by every subcommand.
#[derive(Debug, Args)]
pub struct ProgramArgs {
    /// Path to the cf-vault configuration file.
    #[arg(
        help = "Config file path.",
        env = "CF_VAULT_CONFIG",
        default_value_os_t = config::config_path(None),
        long,
        value_name = "PATH"
    )]
    pub config: PathBuf,

    /// Path to the directory holding the per-profile lock files.
    #[arg(
        help = "State directory path.",
        env = "CF_VAULT_STATE_DIR",
        default_value_os_t = config::state_dir(),
        long,
        value_name = "PATH"
    )]
    pub state_dir: PathBuf,

    /// Only warnings and errors on stderr.
    #[arg(short = 'q', long, conflicts_with = "verbose")]
    pub quiet: bool,

    /// Also details for debugging (still redacted).
    #[arg(short = 'v', long)]
    pub verbose: bool,
}

/// The profile flag: given at most once.
#[derive(Debug, Args)]
pub struct ProfileArg {
    /// Profile to use
    #[arg(short = 'p', long, env = "CF_VAULT_PROFILE", value_name = "NAME")]
    pub profile: Option<String>,
}

/// A requested lifetime such as `10m` or `1h`, at least one minute.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Ttl {
    /// The text as typed, sent to the broker as is.
    pub text: String,
    /// The same in seconds.
    pub secs: u64,
}

fn parse_ttl(text: &str) -> Result<Ttl, String> {
    let (digits, unit) = text.split_at(text.len().saturating_sub(1));
    let unit_secs = match unit {
        "s" => 1,
        "m" => 60,
        "h" => 3600,
        _ => return Err("use a number and a unit, such as 10m or 1h".into()),
    };
    let value: u64 = digits
        .parse()
        .map_err(|_| "use a number and a unit, such as 10m or 1h".to_string())?;
    let secs = value.saturating_mul(unit_secs);
    if secs < 60 {
        return Err("the lifetime must be at least 1m".into());
    }
    Ok(Ttl {
        text: text.to_string(),
        secs,
    })
}

/// Top-level subcommand dispatched by [`Program`].
#[derive(Debug, Subcommand)]
pub enum ProgramCommand {
    /// Sign in, or store an API token, for a profile.
    #[command(
        name = "login",
        after_help = LOGIN_EXAMPLES,
        about = "Sign in, or store an API token, for a profile.",
        long_about = "Run the browser sign-in (Authorization Code with PKCE) of an OAuth profile \
                      and store the session in the system keychain, or ask for a hidden API \
                      token for an api_token profile. The old session is replaced only after the new \
                      sign-in succeeds.",
        next_display_order = 1
    )]
    Login(LoginCommandArgs),

    /// Run a command with the profile's credentials in its environment.
    #[command(
        name = "exec",
        after_help = EXEC_EXAMPLES,
        about = "Run a command with the profile's credentials in its environment.",
        long_about = "Run any command with CLOUDFLARE_API_TOKEN (and, when issued, \
                      CLOUDFLARE_R2_*) in its environment only. Expiring sessions are renewed \
                      first; the command is not started when credentials cannot be obtained. \
                      Without a terminal, credentials come from CLOUDFLARE_API_TOKEN or, for \
                      broker profiles, CF_VAULT_ID_TOKEN.",
        next_display_order = 2
    )]
    Exec(ExecCommandArgs),

    /// Remove the stored session of a profile.
    #[command(
        name = "logout",
        after_help = LOGOUT_EXAMPLES,
        about = "Remove the stored session of a profile.",
        long_about = "Delete the locally stored session of a profile and keep its configuration. \
                      The refresh token is revoked at the provider on a best-effort basis.",
        next_display_order = 3
    )]
    Logout(LogoutCommandArgs),

    /// Show profiles and whether a session exists.
    #[command(
        name = "list",
        after_help = LIST_EXAMPLES,
        about = "Show profiles and whether a session exists.",
        long_about = "Show each profile's type, account and session state. Secrets are never \
                      shown.",
        next_display_order = 4
    )]
    List(ListCommandArgs),
}

/// Arguments of `login`.
#[derive(Debug, Args)]
pub struct LoginCommandArgs {
    /// Shared flags.
    #[command(flatten)]
    pub parent: ProgramArgs,

    /// Profile selection.
    #[command(flatten)]
    pub profile: ProfileArg,

    /// Print the sign-in URL instead of opening a browser
    #[arg(long)]
    pub no_browser: bool,
}

/// Arguments of `exec`.
#[derive(Debug, Args)]
pub struct ExecCommandArgs {
    /// Shared flags.
    #[command(flatten)]
    pub parent: ProgramArgs,

    /// Profile selection.
    #[command(flatten)]
    pub profile: ProfileArg,

    /// Requested lifetime of issued credentials, such as 10m or 1h (at least 1m)
    #[arg(long, value_name = "DURATION", value_parser = parse_ttl)]
    pub ttl: Option<Ttl>,

    /// Command and arguments, after `--`
    #[arg(last = true, num_args = 1.., value_name = "COMMAND")]
    pub command: Vec<String>,
}

/// Arguments of `logout`.
#[derive(Debug, Args)]
pub struct LogoutCommandArgs {
    /// Shared flags.
    #[command(flatten)]
    pub parent: ProgramArgs,

    /// Profile selection.
    #[command(flatten)]
    pub profile: ProfileArg,
}

/// Arguments of `list`.
#[derive(Debug, Args)]
pub struct ListCommandArgs {
    /// Shared flags.
    #[command(flatten)]
    pub parent: ProgramArgs,

    /// Machine-readable output
    #[arg(long)]
    pub json: bool,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ttl_needs_a_unit_and_at_least_a_minute() {
        assert_eq!(parse_ttl("10m").unwrap().secs, 600);
        assert_eq!(parse_ttl("1h").unwrap().secs, 3600);
        assert_eq!(parse_ttl("90s").unwrap().secs, 90);
        assert!(parse_ttl("30s").is_err());
        assert!(parse_ttl("5").is_err());
        assert!(parse_ttl("m").is_err());
        assert!(parse_ttl("1d").is_err());
    }
}
