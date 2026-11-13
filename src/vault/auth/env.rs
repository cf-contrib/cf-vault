//! Credentials supplied through the environment, for noninteractive use (CI). Nothing is stored:
//! the variables are read when `exec` starts. Adapted from nix-vault (MIT).

use crate::vault::auth::redact::Secret;

/// The variable holding a static API token (also the one `exec` exports).
pub const API_TOKEN: &str = "CLOUDFLARE_API_TOKEN";
/// The variable holding an identity token to exchange at a broker.
pub const ID_TOKEN: &str = "CF_VAULT_ID_TOKEN";

fn read(name: &str) -> Option<Secret> {
    match std::env::var(name) {
        Ok(value) if !value.trim().is_empty() => Some(Secret::new(value.trim().to_string())),
        _ => None,
    }
}

/// The API token supplied in `CLOUDFLARE_API_TOKEN`; empty counts as unset.
pub fn api_token() -> Option<Secret> {
    read(API_TOKEN)
}

/// The identity token supplied in `CF_VAULT_ID_TOKEN`; empty counts as unset.
pub fn id_token() -> Option<Secret> {
    read(ID_TOKEN)
}
