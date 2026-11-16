//! Tower middleware layers for the HTTP transport.
//!
// template:begin oauth
//! - [`cors`] builds the CORS layer applied to OAuth endpoints.
//! - [`oauth`] enforces OAuth 2.1 Bearer token authentication.
// template:end oauth
//! - [`static_bearer_auth`] enforces a fixed-secret Bearer token, compared
//!   through a [`SecretDigest`](crate::secret_digest::SecretDigest).

// template:begin oauth
pub mod cors;
pub mod oauth;
// template:end oauth
pub mod static_bearer_auth;
