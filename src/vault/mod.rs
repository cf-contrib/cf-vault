//! Domain layer: configuration, credential storage, authentication, token exchange and R2.

pub mod auth;
pub mod cloudflare;
pub mod config;
pub mod error;
pub mod store;

pub use error::{Error, Result};
