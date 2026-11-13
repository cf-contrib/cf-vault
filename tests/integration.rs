//! Integration tests: the real binary (built with the `test-store` feature) against fake
//! credentials and loopback mock services. Run with `cargo test --features test-store`.

#[path = "helpers/mod.rs"]
mod helpers;

#[path = "integration"]
mod areas {
    pub mod aws_untouched;
    pub mod broker_contract;
    pub mod config;
    pub mod env_credentials;
    pub mod exchange;
    pub mod exchange_failures;
    pub mod exec_session;
    pub mod exec_static;
    pub mod list;
    pub mod login;
    pub mod login_oauth;
    pub mod logout;
    pub mod permissions;
    pub mod profile_changes;
    pub mod r2;
    pub mod redaction;
    pub mod refresh;
    pub mod secret_hygiene;
    pub mod startup_time;
    pub mod storage;
}
