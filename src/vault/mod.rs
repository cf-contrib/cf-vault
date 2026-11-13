//! Domain layer: configuration, credential storage, authentication, token exchange and R2.

pub mod auth;
pub mod config;
pub mod credentials;
pub mod error;
pub mod exchange;
pub mod r2;
pub mod store;

pub use error::{Error, Result};
