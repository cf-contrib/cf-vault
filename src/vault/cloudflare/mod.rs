//! What cf-vault hands to a command and how it gets it from Cloudflare itself: the in-memory
//! [`creds::CredentialSet`] and the temporary R2 credentials derived from an API token.

pub mod creds;
pub mod r2;
