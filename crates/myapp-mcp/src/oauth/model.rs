use std::sync::{Arc, Mutex};

use serde::Deserialize;

use crate::oauth::limiter::PinLimiter;
use crate::oauth::store::OAuthStore;
use crate::secret_digest::SecretDigest;

/// The consent form posted to `POST /oauth/approve`. Everything it grants
/// comes from the [`PendingAuthorization`] stored under `consent_nonce`.
#[derive(Debug, Deserialize)]
pub struct ApprovalForm {
    pub consent_nonce: String,
    pub approved: String,
    pub pin: Option<String>,
}

/// An authorization request `GET /oauth/authorize` has validated, held until
/// the consent form is posted with its nonce.
#[derive(Clone, Debug)]
pub struct PendingAuthorization {
    pub client_id: String,
    /// The name the client registered with, shown on the consent page.
    pub client_name: Option<String>,
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
    pub state: Option<String>,
}

#[derive(serde::Serialize)]
pub struct AuthorizationServerMetadata {
    pub issuer: String,
    pub authorization_endpoint: String,
    pub token_endpoint: String,
    pub registration_endpoint: String,
    pub scopes_supported: Vec<String>,
    pub response_types_supported: Vec<String>,
    pub grant_types_supported: Vec<String>,
    pub code_challenge_methods_supported: Vec<String>,
    pub token_endpoint_auth_methods_supported: Vec<String>,
}

#[derive(Debug, Deserialize)]
pub struct AuthorizeQuery {
    pub response_type: String,
    pub client_id: String,
    pub redirect_uri: String,
    pub scope: Option<String>,
    pub state: Option<String>,
    pub code_challenge: Option<String>,
    pub code_challenge_method: Option<String>,
}

/// Shared state for all OAuth endpoint handlers.
#[derive(Clone)]
pub struct OAuthEndpointState {
    pub store: OAuthStore,
    pub base_url: String,
    /// The consent PIN's digest; `None` when no PIN is configured.
    pub oauth_pin: Option<SecretDigest>,
    /// Shared by every client, so wrong PINs from all callers add up. Never
    /// held across an `.await`.
    pub pin_limiter: Arc<Mutex<PinLimiter>>,
}

#[derive(serde::Serialize)]
pub struct ProtectedResourceMetadata {
    pub resource: String,
    pub authorization_servers: Vec<String>,
    pub scopes_supported: Vec<String>,
    pub bearer_methods_supported: Vec<String>,
}

#[derive(Debug, Deserialize)]
pub struct RegistrationRequest {
    pub client_name: Option<String>,
    pub redirect_uris: Vec<String>,
}

#[derive(Debug, Deserialize)]
pub struct TokenRequest {
    pub grant_type: String,
    #[serde(default)]
    pub code: String,
    #[serde(default)]
    pub client_id: String,
    #[serde(default)]
    pub redirect_uri: String,
    #[serde(default)]
    pub code_verifier: Option<String>,
    #[serde(default)]
    pub refresh_token: String,
}
