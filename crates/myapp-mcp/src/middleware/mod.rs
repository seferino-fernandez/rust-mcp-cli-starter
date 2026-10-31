//! Tower middleware layers for the HTTP transport.
//!
//! - [`cors`] builds the CORS layer applied to OAuth endpoints.
//! - [`oauth`] enforces OAuth 2.1 Bearer token authentication.
//! - [`static_bearer_auth`] enforces a fixed-secret Bearer token, compared
//!   through a [`SecretDigest`](crate::secret_digest::SecretDigest).

pub mod cors;
pub mod oauth;
pub mod static_bearer_auth;
