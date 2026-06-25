//! Async Rust client for the MYAPP API.
//!
//! Construct an [`ApiClient`] from [`Config`] and call the example endpoint
//! methods. Replace the example `models`, `api`, and `endpoints` with your own.

#![warn(missing_docs)]
#![forbid(unsafe_code)]

/// API path constants.
pub mod api;
/// The [`ApiClient`] HTTP wrapper.
pub mod client;
/// Configuration loading.
pub mod config;
/// Endpoint methods on [`ApiClient`].
pub mod endpoints;
/// Environment-variable source abstraction (testable).
pub mod env;
/// Error types.
pub mod error;
/// Response models.
pub mod models;
/// Pagination envelope.
pub mod pagination;
/// Secret-string wrapper that redacts in `Debug`.
pub mod secret;

pub use client::ApiClient;
pub use config::Config;
pub use error::Error;
pub use secret::SecretString;

/// Crate `Result` alias.
pub type Result<T> = std::result::Result<T, Error>;
