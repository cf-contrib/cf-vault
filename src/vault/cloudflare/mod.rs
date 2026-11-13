//! What cf-vault hands to a command and how it gets it from Cloudflare itself: the in-memory
//! [`credentials::CredentialSet`] and the temporary R2 credentials derived from an API token.

pub mod credentials;
pub mod r2;
