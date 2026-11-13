mod app;
mod vault;

use std::{
    io::IsTerminal,
    process::{ExitCode, ExitStatus},
};

use clap::Parser;
use time::OffsetDateTime;

use crate::{
    app::{
        args::*, exec::ExecCommand, list::ListCommand, login::LoginCommand, logout::LogoutCommand,
    },
    vault::{auth::static_token::TerminalPrompt, config::Config, store::CredentialStore, Result},
};

fn main() -> ExitCode {
    let program = Program::parse();
    match run(program) {
        Ok(code) => code,
        Err(err) => {
            for line in err.to_string().lines() {
                eprintln!("cf-vault: {line}");
            }
            ExitCode::from(err.exit_code())
        }
    }
}

fn run(program: Program) -> Result<ExitCode> {
    match program.command {
        ProgramCommand::Login(args) => {
            // The configuration is validated before the store is opened or anything is asked
            let config = Config::load(&args.parent.config)?;
            let mut command = LoginCommand {
                config,
                store: CredentialStore::open_lazy(),
                prompt: Box::new(TerminalPrompt),
            };
            command.execute(&args)?;
        }
        ProgramCommand::Exec(args) => {
            let config = Config::load(&args.parent.config)?;
            let mut command = ExecCommand {
                config,
                store: CredentialStore::open_lazy(),
                interactive: is_interactive(),
            };
            return Ok(exit_code(command.execute(&args)?));
        }
        ProgramCommand::Logout(args) => {
            let config = Config::load(&args.parent.config)?;
            let mut command = LogoutCommand {
                config,
                store: CredentialStore::open_lazy(),
            };
            command.execute(&args)?;
        }
        ProgramCommand::List(args) => {
            let config = Config::load(&args.parent.config)?;
            let mut command = ListCommand {
                writer: Box::new(std::io::stdout()),
                config,
                store: CredentialStore::open_lazy(),
                now: OffsetDateTime::now_utc(),
            };
            command.execute(&args)?;
        }
    }
    Ok(ExitCode::SUCCESS)
}

/// Whether a person is at the keyboard: standard input is a terminal. Test builds can force it
/// with `CF_VAULT_FORCE_INTERACTIVE`, so most integration tests need no pty.
fn is_interactive() -> bool {
    #[cfg(feature = "test-store")]
    if std::env::var_os("CF_VAULT_FORCE_INTERACTIVE").is_some() {
        return true;
    }
    std::io::stdin().is_terminal()
}

/// Maps the exit status of the child process to our own, shell style: its code, or `128 + n`
/// when signal `n` killed it.
fn exit_code(status: ExitStatus) -> ExitCode {
    use std::os::unix::process::ExitStatusExt;
    match (status.code(), status.signal()) {
        (Some(code), _) => ExitCode::from(code as u8),
        (None, Some(signal)) => ExitCode::from(128u8.wrapping_add(signal as u8)),
        (None, None) => ExitCode::FAILURE,
    }
}
