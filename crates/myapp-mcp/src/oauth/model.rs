//! Request, response and state types for the OAuth endpoints.

use std::sync::{Arc, Mutex};

use serde::Deserialize;

use crate::oauth::limiter::PinLimiter;
use crate::oauth::store::OAuthStore;
use crate::secret_digest::SecretDigest;

/// The consent form posted to `POST /oauth/approve`. Everything it grants
/// comes from the [`PendingAuthorization`] stored under `consent_nonce`.
#[derive(Debug, Deserialize)]
pub struct ApprovalForm {
    /// The single-use nonce naming the pending authorization.
    pub consent_nonce: String,
    /// The user's decision; only `"true"` approves.
    pub approved: String,
    /// The consent PIN, checked when one is configured.
    pub pin: Option<String>,
}

/// An authorization request `GET /oauth/authorize` has validated, held until
/// the consent form is posted with its nonce.
#[derive(Clone, Debug)]
pub struct PendingAuthorization {
    /// The client, which must still be registered when the nonce is taken.
    /// Its name is looked up when the consent page is rendered, not copied.
    pub client_id: String,
    /// The registered redirect URI exactly as the request named it. This is
    /// what the authorization code is bound to, because `/token` compares it
    /// byte for byte.
    pub redirect_uri: String,
    /// `redirect_uri` parsed, used only to build redirects and to display
    /// the host. It may serialise differently from `redirect_uri`.
    pub redirect_url: url::Url,
    /// The requested scopes, kept to `read` and `write`; `read` when none are.
    pub scopes: Vec<String>,
    /// The PKCE challenge the authorization code will be bound to.
    pub code_challenge: String,
    /// The PKCE method of `code_challenge`; always `S256` once validated.
    pub code_challenge_method: String,
    /// The client's `state`, returned unchanged on the redirect.
    pub state: Option<String>,
}

/// Authorization server metadata (RFC 8414), served at
/// `/.well-known/oauth-authorization-server` and
/// `/.well-known/openid-configuration`.
#[derive(serde::Serialize)]
pub struct AuthorizationServerMetadata {
    /// The server's base URL.
    pub issuer: String,
    /// The `/oauth/authorize` URL.
    pub authorization_endpoint: String,
    /// The `/oauth/token` URL.
    pub token_endpoint: String,
    /// The `/oauth/register` URL for dynamic client registration.
    pub registration_endpoint: String,
    /// The scopes a client may request.
    pub scopes_supported: Vec<String>,
    /// The supported `response_type` values.
    pub response_types_supported: Vec<String>,
    /// The supported `grant_type` values.
    pub grant_types_supported: Vec<String>,
    /// The supported PKCE methods.
    pub code_challenge_methods_supported: Vec<String>,
    /// How clients authenticate at the token endpoint.
    pub token_endpoint_auth_methods_supported: Vec<String>,
}

/// The query of a `GET /oauth/authorize` request.
#[derive(Debug, Deserialize)]
pub struct AuthorizeQuery {
    /// Must be `code`.
    pub response_type: String,
    /// The registered client making the request.
    pub client_id: String,
    /// One of the client's registered redirect URIs.
    pub redirect_uri: String,
    /// Space-separated requested scopes.
    pub scope: Option<String>,
    /// Opaque client state, returned on the redirect.
    pub state: Option<String>,
    /// The PKCE code challenge.
    pub code_challenge: Option<String>,
    /// The PKCE method; only `S256` is accepted.
    pub code_challenge_method: Option<String>,
}

/// Shared state for all OAuth endpoint handlers.
#[derive(Clone)]
pub struct OAuthEndpointState {
    /// Clients, pending authorizations, codes and tokens.
    pub store: OAuthStore,
    /// The external base URL the metadata documents advertise.
    pub base_url: String,
    /// The consent PIN's digest; `None` when no PIN is configured.
    pub oauth_pin: Option<SecretDigest>,
    /// Shared by every client, so wrong PINs from all callers add up. Never
    /// held across an `.await`.
    pub pin_limiter: Arc<Mutex<PinLimiter>>,
}

/// Protected resource metadata (RFC 9728), served at
/// `/.well-known/oauth-protected-resource`.
#[derive(serde::Serialize)]
pub struct ProtectedResourceMetadata {
    /// The protected resource's URL.
    pub resource: String,
    /// The authorization servers that issue tokens for it.
    pub authorization_servers: Vec<String>,
    /// The scopes a token may carry.
    pub scopes_supported: Vec<String>,
    /// How a Bearer token may be presented.
    pub bearer_methods_supported: Vec<String>,
}

/// The JSON body of a `POST /oauth/register` request.
#[derive(Debug, Deserialize)]
pub struct RegistrationRequest {
    /// A display name shown on the consent page.
    pub client_name: Option<String>,
    /// The redirect URIs the client may use.
    pub redirect_uris: Vec<String>,
}

/// The form body of a `POST /oauth/token` request.
#[derive(Debug, Deserialize)]
pub struct TokenRequest {
    /// `authorization_code` or `refresh_token`.
    pub grant_type: String,
    /// The authorization code, for the `authorization_code` grant.
    #[serde(default)]
    pub code: String,
    /// The client the code or refresh token was issued to.
    #[serde(default)]
    pub client_id: String,
    /// The redirect URI the code was issued for.
    #[serde(default)]
    pub redirect_uri: String,
    /// The PKCE code verifier, required by the `authorization_code` grant.
    #[serde(default)]
    pub code_verifier: Option<String>,
    /// The refresh token, for the `refresh_token` grant.
    #[serde(default)]
    pub refresh_token: String,
}
