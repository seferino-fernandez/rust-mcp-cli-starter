use std::collections::{HashMap, HashSet};
use std::sync::{Arc, Mutex, MutexGuard, PoisonError};
use std::time::{Duration, Instant};

use uuid::Uuid;

use crate::oauth::model::PendingAuthorization;

const CLIENT_ID_PREFIX: &str = "myapp_cid_";
const CONSENT_NONCE_PREFIX: &str = "myapp_consent_";
const AUTH_CODE_PREFIX: &str = "myapp_ac_";
const ACCESS_TOKEN_PREFIX: &str = "myapp_at_";
const REFRESH_TOKEN_PREFIX: &str = "myapp_rt_";

/// How long a refresh token remains valid from its issue, independent of the
/// access token issued with it.
const REFRESH_TOKEN_LIFETIME: Duration = Duration::from_secs(30 * 24 * 60 * 60);

/// The most dynamically registered clients kept at once. `/oauth/register`
/// is unauthenticated, so an unbounded map is a memory-exhaustion vector.
pub const MAX_CLIENTS: usize = 1024;

/// The most pending authorizations held at once. `/oauth/authorize` is
/// unauthenticated, so each one is attacker-sized memory until it expires.
pub const MAX_PENDING_AUTHORIZATIONS: usize = 1024;

/// How long a registered client is kept once it is unused: nothing has named
/// it and it holds no live pending authorization, code or token.
pub const CLIENT_IDLE_TTL: Duration = Duration::from_secs(24 * 60 * 60);

/// Configuration for the in-memory OAuth store's TTL and expiry behavior.
#[derive(Debug, Clone)]
pub struct OAuthStoreConfig {
    /// How long an authorization code remains valid before expiring.
    pub auth_code_ttl: Duration,
    /// How long a pending authorization, and the consent nonce that names it,
    /// remains valid before expiring.
    pub csrf_nonce_ttl: Duration,
    /// How long an access token remains valid (in seconds).
    pub token_expiry_secs: u64,
    /// The most registered clients kept at once; [`MAX_CLIENTS`] by default.
    pub max_clients: usize,
    /// How long an unused client is kept; [`CLIENT_IDLE_TTL`] by default.
    pub client_idle_ttl: Duration,
    /// The most pending authorizations held at once;
    /// [`MAX_PENDING_AUTHORIZATIONS`] by default.
    pub max_pending_authorizations: usize,
}

impl Default for OAuthStoreConfig {
    fn default() -> Self {
        Self {
            auth_code_ttl: Duration::from_secs(60),
            csrf_nonce_ttl: Duration::from_secs(600),
            token_expiry_secs: 3600,
            max_clients: MAX_CLIENTS,
            client_idle_ttl: CLIENT_IDLE_TTL,
            max_pending_authorizations: MAX_PENDING_AUTHORIZATIONS,
        }
    }
}

impl OAuthStoreConfig {
    /// Build an [`OAuthStoreConfig`] from the application's [`McpConfig`](crate::config::McpConfig).
    pub fn from_mcp_config(mcp: &crate::config::McpConfig) -> Self {
        Self {
            auth_code_ttl: Duration::from_secs(mcp.oauth_auth_code_ttl_secs),
            csrf_nonce_ttl: Duration::from_secs(mcp.oauth_csrf_nonce_ttl_secs),
            token_expiry_secs: mcp.oauth_token_expiry_secs,
            ..Self::default()
        }
    }
}

/// In-memory store for OAuth 2.1 state: registered clients, authorization codes,
/// access tokens, refresh tokens, and pending authorizations.
#[derive(Clone)]
pub struct OAuthStore {
    inner: Arc<Mutex<StoreInner>>,
    config: OAuthStoreConfig,
}

struct StoreInner {
    clients: HashMap<String, RegisteredClient>,
    auth_codes: HashMap<String, AuthCode>,
    access_tokens: HashMap<String, AccessToken>,
    refresh_tokens: HashMap<String, RefreshToken>,
    /// Validated authorization requests awaiting consent, keyed by consent
    /// nonce, with when each was created.
    pending_authorizations: HashMap<String, (PendingAuthorization, Instant)>,
}

/// A dynamically registered public OAuth client. It has no secret: it
/// authenticates with PKCE on the authorization-code grant.
#[derive(Clone, Debug)]
pub struct RegisteredClient {
    pub client_id: String,
    pub client_name: Option<String>,
    pub redirect_uris: Vec<String>,
    /// When the client was registered or last named by a request.
    pub last_used: Instant,
}

/// A single-use authorization code issued after user consent.
#[derive(Clone, Debug)]
pub struct AuthCode {
    pub client_id: String,
    pub redirect_uri: String,
    pub scope: Vec<String>,
    pub code_challenge: String,
    pub code_challenge_method: String,
    pub created_at: Instant,
}

/// An issued access token with associated metadata.
#[derive(Clone, Debug)]
pub struct AccessToken {
    pub token: String,
    pub client_id: String,
    pub scope: Vec<String>,
    pub created_at: Instant,
    pub expires_in: u64,
    pub refresh_token: String,
}

/// An issued refresh token, valid for [`REFRESH_TOKEN_LIFETIME`] from `created_at`
/// whether or not the access token issued with it still exists.
#[derive(Clone, Debug)]
struct RefreshToken {
    client_id: String,
    scope: Vec<String>,
    created_at: Instant,
    /// The access token issued alongside this refresh token, revoked on rotation.
    access_token: String,
}

/// Why [`OAuthStore::refresh_access_token`] refused a refresh token.
#[derive(Debug, PartialEq, Eq)]
pub enum RefreshError {
    /// The refresh token is unknown, already used, or expired.
    InvalidToken,
    /// The refresh token was presented by a client other than the one it was
    /// issued to. It has been consumed.
    ClientMismatch {
        /// The client the refresh token was issued to.
        expected_client: String,
    },
}

impl StoreInner {
    /// Issue and store a new access token and refresh token pair.
    fn issue_token_pair(
        &mut self,
        client_id: String,
        scope: Vec<String>,
        expires_in: u64,
    ) -> AccessToken {
        let token_value = format!("{}{}", ACCESS_TOKEN_PREFIX, Uuid::new_v4());
        let refresh_value = format!("{}{}", REFRESH_TOKEN_PREFIX, Uuid::new_v4());
        let now = Instant::now();
        let token = AccessToken {
            token: token_value.clone(),
            client_id: client_id.clone(),
            scope: scope.clone(),
            created_at: now,
            expires_in,
            refresh_token: refresh_value.clone(),
        };
        self.access_tokens
            .insert(token_value.clone(), token.clone());
        self.refresh_tokens.insert(
            refresh_value,
            RefreshToken {
                client_id,
                scope,
                created_at: now,
                access_token: token_value,
            },
        );
        token
    }

    /// Marks `client_id` as used now, if it is registered.
    fn touch_client(&mut self, client_id: &str) {
        if let Some(client) = self.clients.get_mut(client_id) {
            client.last_used = Instant::now();
        }
    }

    /// Drops registered clients unused for longer than `idle_ttl`: not named
    /// by a request in that time and not holding a live pending
    /// authorization, authorization code, access token or refresh token.
    /// Expired entries count as live until swept.
    fn reap_unused_clients(&mut self, idle_ttl: Duration) {
        let referenced: HashSet<&str> = self
            .auth_codes
            .values()
            .map(|code| code.client_id.as_str())
            .chain(
                self.access_tokens
                    .values()
                    .map(|token| token.client_id.as_str()),
            )
            .chain(
                self.refresh_tokens
                    .values()
                    .map(|token| token.client_id.as_str()),
            )
            .chain(
                self.pending_authorizations
                    .values()
                    .map(|(pending, _)| pending.client_id.as_str()),
            )
            .collect();
        let unused: Vec<String> = self
            .clients
            .iter()
            .filter(|(client_id, client)| {
                client.last_used.elapsed() > idle_ttl && !referenced.contains(client_id.as_str())
            })
            .map(|(client_id, _)| client_id.clone())
            .collect();
        for client_id in unused {
            self.clients.remove(&client_id);
        }
    }
}

impl OAuthStore {
    /// Create a new store with the given configuration.
    pub fn new(config: OAuthStoreConfig) -> Self {
        Self {
            inner: Arc::new(Mutex::new(StoreInner {
                clients: HashMap::new(),
                auth_codes: HashMap::new(),
                access_tokens: HashMap::new(),
                refresh_tokens: HashMap::new(),
                pending_authorizations: HashMap::new(),
            })),
            config,
        }
    }

    /// Locks the store. Every critical section is synchronous map work, so the
    /// guard is never held across an `.await`. Those sections do not panic in
    /// practice, so a poisoned lock is recovered rather than propagated.
    fn lock(&self) -> MutexGuard<'_, StoreInner> {
        self.inner.lock().unwrap_or_else(PoisonError::into_inner)
    }

    /// Register a new public dynamic client and return it.
    ///
    /// Returns `None` when the store holds
    /// [`max_clients`](OAuthStoreConfig::max_clients) even after dropping
    /// unused clients: `/oauth/register` is unauthenticated, so registration
    /// must be bounded.
    pub fn register_client(
        &self,
        client_name: Option<String>,
        redirect_uris: Vec<String>,
    ) -> Option<RegisteredClient> {
        let mut inner = self.lock();
        if inner.clients.len() >= self.config.max_clients {
            inner.reap_unused_clients(self.config.client_idle_ttl);
        }
        if inner.clients.len() >= self.config.max_clients {
            return None;
        }
        let client_id = format!("{}{}", CLIENT_ID_PREFIX, Uuid::new_v4());
        let client = RegisteredClient {
            client_id: client_id.clone(),
            client_name,
            redirect_uris,
            last_used: Instant::now(),
        };
        inner.clients.insert(client_id, client.clone());
        Some(client)
    }

    /// Returns the client registered as `client_id` when `redirect_uri` is
    /// one of its redirect URIs, marking it used. `None` for an unknown
    /// client or an unregistered URI.
    pub fn client_for_redirect(
        &self,
        client_id: &str,
        redirect_uri: &str,
    ) -> Option<RegisteredClient> {
        let mut inner = self.lock();
        let client = inner.clients.get_mut(client_id)?;
        if !client.redirect_uris.iter().any(|uri| uri == redirect_uri) {
            return None;
        }
        client.last_used = Instant::now();
        Some(client.clone())
    }

    /// Hold a validated authorization request until consent and return the
    /// fresh, single-use consent nonce that names it.
    ///
    /// Returns `None` when the store holds
    /// [`max_pending_authorizations`](OAuthStoreConfig::max_pending_authorizations)
    /// even after dropping expired ones.
    pub fn begin_authorization(&self, pending: PendingAuthorization) -> Option<String> {
        let mut inner = self.lock();
        if inner.pending_authorizations.len() >= self.config.max_pending_authorizations {
            let csrf_nonce_ttl = self.config.csrf_nonce_ttl;
            inner
                .pending_authorizations
                .retain(|_, (_, created_at)| created_at.elapsed() <= csrf_nonce_ttl);
        }
        if inner.pending_authorizations.len() >= self.config.max_pending_authorizations {
            return None;
        }
        let nonce = format!("{}{}", CONSENT_NONCE_PREFIX, Uuid::new_v4());
        inner
            .pending_authorizations
            .insert(nonce.clone(), (pending, Instant::now()));
        Some(nonce)
    }

    /// Take the pending authorization named by `nonce`, removing it. Returns
    /// `None` if the nonce is unknown, already taken, or expired, or if its
    /// client is no longer registered.
    pub fn take_authorization(&self, nonce: &str) -> Option<PendingAuthorization> {
        let mut inner = self.lock();
        let (pending, created_at) = inner.pending_authorizations.remove(nonce)?;
        if created_at.elapsed() > self.config.csrf_nonce_ttl
            || !inner.clients.contains_key(&pending.client_id)
        {
            return None;
        }
        Some(pending)
    }

    /// Issue a single-use authorization code bound to the given PKCE challenge.
    pub fn create_auth_code(
        &self,
        client_id: String,
        redirect_uri: String,
        scope: Vec<String>,
        code_challenge: String,
        code_challenge_method: String,
    ) -> String {
        let code = format!("{}{}", AUTH_CODE_PREFIX, Uuid::new_v4());
        let auth_code = AuthCode {
            client_id,
            redirect_uri,
            scope,
            code_challenge,
            code_challenge_method,
            created_at: Instant::now(),
        };
        self.lock().auth_codes.insert(code.clone(), auth_code);
        code
    }

    /// Consume a single-use authorization code. Returns `None` if the code is
    /// invalid, already used, or expired.
    pub fn consume_auth_code(&self, code: &str) -> Option<AuthCode> {
        let mut inner = self.lock();
        let auth_code = inner.auth_codes.remove(code)?;
        if auth_code.created_at.elapsed() > self.config.auth_code_ttl {
            return None;
        }
        inner.touch_client(&auth_code.client_id);
        Some(auth_code)
    }

    /// Issue a new access token and refresh token pair for the given client and scopes.
    pub fn create_access_token(&self, client_id: String, scope: Vec<String>) -> AccessToken {
        self.lock()
            .issue_token_pair(client_id, scope, self.config.token_expiry_secs)
    }

    /// Validate an access token. Returns `None` if the token is unknown or expired.
    pub fn validate_access_token(&self, token: &str) -> Option<AccessToken> {
        let inner = self.lock();
        let access_token = inner.access_tokens.get(token)?;
        if access_token.created_at.elapsed() > Duration::from_secs(access_token.expires_in) {
            return None;
        }
        Some(access_token.clone())
    }

    /// Rotate a refresh token presented by `client_id`: consume it, revoke the
    /// access token issued with it if that still exists, and issue a new
    /// access/refresh pair with the same client and scopes.
    ///
    /// Fails if the refresh token is unknown, already used, or expired, or if
    /// `client_id` is not the client it was issued to. A token presented by the
    /// wrong client is consumed all the same, so it cannot be used again. The
    /// access token's own expiry plays no part.
    pub fn refresh_access_token(
        &self,
        refresh_token: &str,
        client_id: &str,
    ) -> Result<AccessToken, RefreshError> {
        let mut inner = self.lock();
        let old_refresh_token = inner
            .refresh_tokens
            .remove(refresh_token)
            .ok_or(RefreshError::InvalidToken)?;
        if old_refresh_token.created_at.elapsed() > REFRESH_TOKEN_LIFETIME {
            return Err(RefreshError::InvalidToken);
        }
        if old_refresh_token.client_id != client_id {
            return Err(RefreshError::ClientMismatch {
                expected_client: old_refresh_token.client_id,
            });
        }
        inner.access_tokens.remove(&old_refresh_token.access_token);
        inner.touch_client(&old_refresh_token.client_id);

        Ok(inner.issue_token_pair(
            old_refresh_token.client_id,
            old_refresh_token.scope,
            self.config.token_expiry_secs,
        ))
    }

    /// Remove all expired auth codes, pending authorizations, access tokens,
    /// and refresh tokens, then every client left unused for
    /// [`client_idle_ttl`](OAuthStoreConfig::client_idle_ttl).
    ///
    /// Access and refresh tokens expire independently: sweeping an expired access
    /// token leaves the refresh token issued with it usable.
    pub fn sweep_expired(&self) {
        let mut inner = self.lock();
        let auth_code_ttl = self.config.auth_code_ttl;
        let csrf_nonce_ttl = self.config.csrf_nonce_ttl;

        inner
            .auth_codes
            .retain(|_, code| code.created_at.elapsed() <= auth_code_ttl);
        inner
            .pending_authorizations
            .retain(|_, (_, created_at)| created_at.elapsed() <= csrf_nonce_ttl);

        inner.access_tokens.retain(|_, access_token| {
            access_token.created_at.elapsed() <= Duration::from_secs(access_token.expires_in)
        });
        inner.refresh_tokens.retain(|_, refresh_token| {
            refresh_token.created_at.elapsed() <= REFRESH_TOKEN_LIFETIME
        });

        inner.reap_unused_clients(self.config.client_idle_ttl);
    }

    /// Move a refresh token's issue time `age` into the past, so tests can cross
    /// the refresh lifetime without waiting.
    #[cfg(test)]
    pub(crate) fn backdate_refresh_token(&self, refresh_token: &str, age: Duration) {
        let mut inner = self.lock();
        let record = inner
            .refresh_tokens
            .get_mut(refresh_token)
            .expect("refresh token to backdate exists");
        record.created_at = record
            .created_at
            .checked_sub(age)
            .expect("backdated instant is representable");
    }

    /// Move a client's last use `age` into the past, so tests can cross the
    /// idle TTL without waiting.
    #[cfg(test)]
    pub(crate) fn backdate_client(&self, client_id: &str, age: Duration) {
        let mut inner = self.lock();
        let client = inner
            .clients
            .get_mut(client_id)
            .expect("client to backdate exists");
        client.last_used = client
            .last_used
            .checked_sub(age)
            .expect("backdated instant is representable");
    }

    /// Remove `client_id` from the store outright (test aid).
    #[cfg(test)]
    pub(crate) fn forget_client(&self, client_id: &str) {
        self.lock().clients.remove(client_id);
    }

    /// Whether `client_id` is still registered (test aid).
    #[cfg(test)]
    pub(crate) fn has_client(&self, client_id: &str) -> bool {
        self.lock().clients.contains_key(client_id)
    }

    /// Number of registered clients currently in the store (test aid).
    #[cfg(test)]
    pub(crate) fn client_count(&self) -> usize {
        self.lock().clients.len()
    }

    /// Poison the store's lock by panicking while holding it (test aid).
    #[cfg(test)]
    pub(crate) fn poison(&self) {
        let store = self.clone();
        let poisoner = std::thread::spawn(move || {
            let _guard = store.lock();
            panic!("poisoning the OAuth store lock on purpose");
        });
        assert!(poisoner.join().is_err(), "the poisoning thread must panic");
        assert!(self.inner.is_poisoned());
    }

    /// Spawn a background task that periodically calls [`sweep_expired`](Self::sweep_expired).
    ///
    /// The task will exit cleanly when `cancel` is cancelled.
    pub fn spawn_sweep_task(
        self,
        interval: Duration,
        cancel: tokio_util::sync::CancellationToken,
    ) -> tokio::task::JoinHandle<()> {
        tokio::spawn(async move {
            loop {
                tokio::select! {
                    () = tokio::time::sleep(interval) => {
                        self.sweep_expired();
                    }
                    () = cancel.cancelled() => {
                        tracing::debug!("OAuth sweep task shutting down");
                        break;
                    }
                }
            }
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const DAY: Duration = Duration::from_secs(24 * 60 * 60);

    fn register(store: &OAuthStore) -> RegisteredClient {
        store
            .register_client(None, vec!["http://localhost/cb".into()])
            .expect("store has room")
    }

    #[test]
    fn register_and_get_client() {
        let store = OAuthStore::new(OAuthStoreConfig::default());
        let client = store
            .register_client(Some("test".into()), vec!["http://localhost/cb".into()])
            .unwrap();
        assert!(client.client_id.starts_with("myapp_cid_"));
        assert_eq!(client.client_name.as_deref(), Some("test"));
    }

    #[test]
    fn client_for_redirect_matches_only_registered_uris() {
        let store = OAuthStore::new(OAuthStoreConfig::default());
        let client = register(&store);
        assert!(
            store
                .client_for_redirect(&client.client_id, "http://localhost/cb")
                .is_some()
        );
        assert!(
            store
                .client_for_redirect(&client.client_id, "http://evil.com/cb")
                .is_none()
        );
        assert!(
            store
                .client_for_redirect("myapp_cid_unknown", "http://localhost/cb")
                .is_none()
        );
    }

    #[test]
    fn default_cap_is_max_clients() {
        let store = OAuthStore::new(OAuthStoreConfig::default());
        for _ in 0..MAX_CLIENTS {
            register(&store);
        }
        assert!(
            store
                .register_client(None, vec!["http://localhost/cb".into()])
                .is_none(),
            "registration past MAX_CLIENTS must be refused"
        );
        assert_eq!(store.client_count(), MAX_CLIENTS);
    }

    #[test]
    fn registration_at_the_cap_makes_room_by_dropping_unused_clients() {
        let store = OAuthStore::new(OAuthStoreConfig {
            max_clients: 2,
            ..Default::default()
        });
        let first = register(&store);
        let second = register(&store);
        assert!(
            store
                .register_client(None, vec!["http://localhost/cb".into()])
                .is_none()
        );

        store.backdate_client(&first.client_id, DAY + Duration::from_secs(1));
        let third = register(&store);
        assert!(!store.has_client(&first.client_id));
        assert!(store.has_client(&second.client_id));
        assert!(store.has_client(&third.client_id));
    }

    #[test]
    fn sweep_drops_a_client_unused_for_a_day() {
        let store = OAuthStore::new(OAuthStoreConfig::default());
        let stale = register(&store);
        let fresh = register(&store);
        store.backdate_client(&stale.client_id, DAY + Duration::from_secs(1));
        store.backdate_client(
            &fresh.client_id,
            DAY.saturating_sub(Duration::from_secs(60)),
        );
        store.sweep_expired();
        assert!(!store.has_client(&stale.client_id));
        assert!(store.has_client(&fresh.client_id));
    }

    #[test]
    fn naming_a_client_counts_as_use() {
        let store = OAuthStore::new(OAuthStoreConfig::default());
        let client = register(&store);
        store.backdate_client(&client.client_id, DAY + Duration::from_secs(1));
        store
            .client_for_redirect(&client.client_id, "http://localhost/cb")
            .unwrap();
        store.sweep_expired();
        assert!(store.has_client(&client.client_id));
    }

    #[test]
    fn sweep_keeps_an_idle_client_holding_a_live_refresh_token() {
        let store = OAuthStore::new(OAuthStoreConfig {
            token_expiry_secs: 0,
            ..Default::default()
        });
        let client = register(&store);
        store.create_access_token(client.client_id.clone(), vec!["read".into()]);
        store.backdate_client(&client.client_id, DAY + Duration::from_secs(1));
        std::thread::sleep(Duration::from_millis(10));
        // The access token is swept; the refresh token keeps the client.
        store.sweep_expired();
        assert!(store.has_client(&client.client_id));
    }

    #[test]
    fn poisoned_lock_is_recovered() {
        let store = OAuthStore::new(OAuthStoreConfig::default());
        let client = register(&store);
        store.poison();

        assert!(
            store
                .client_for_redirect(&client.client_id, "http://localhost/cb")
                .is_some()
        );
        let token = store.create_access_token(client.client_id.clone(), vec!["read".into()]);
        assert!(store.validate_access_token(&token.token).is_some());
        store.sweep_expired();
        store
            .refresh_access_token(&token.refresh_token, &client.client_id)
            .expect("a poisoned store still refreshes");
    }

    /// A pending authorization for a client registered in `store`.
    fn pending_authorization(store: &OAuthStore) -> PendingAuthorization {
        PendingAuthorization {
            client_id: register(store).client_id,
            redirect_uri: "http://localhost/cb".into(),
            redirect_url: url::Url::parse("http://localhost/cb").unwrap(),
            scopes: vec!["read".into()],
            code_challenge: "challenge123".into(),
            code_challenge_method: "S256".into(),
            state: Some("s".into()),
        }
    }

    #[test]
    fn pending_authorization_is_taken_once() {
        let store = OAuthStore::new(OAuthStoreConfig::default());
        let pending = pending_authorization(&store);
        let client_id = pending.client_id.clone();
        let nonce = store.begin_authorization(pending).unwrap();
        assert!(nonce.starts_with("myapp_consent_"));

        let pending = store.take_authorization(&nonce).unwrap();
        assert_eq!(pending.client_id, client_id);
        assert_eq!(pending.code_challenge, "challenge123");

        assert!(store.take_authorization(&nonce).is_none());
        assert!(store.take_authorization("myapp_consent_unknown").is_none());
    }

    #[test]
    fn pending_authorization_past_ttl_is_not_taken() {
        let config = OAuthStoreConfig {
            csrf_nonce_ttl: Duration::ZERO,
            ..Default::default()
        };
        let store = OAuthStore::new(config);
        let nonce = store
            .begin_authorization(pending_authorization(&store))
            .unwrap();
        std::thread::sleep(Duration::from_millis(10));

        assert!(store.take_authorization(&nonce).is_none());
    }

    #[test]
    fn pending_authorization_for_a_removed_client_is_not_taken() {
        let store = OAuthStore::new(OAuthStoreConfig::default());
        let pending = pending_authorization(&store);
        let client_id = pending.client_id.clone();
        let nonce = store.begin_authorization(pending).unwrap();
        store.forget_client(&client_id);

        assert!(store.take_authorization(&nonce).is_none());
    }

    #[test]
    fn pending_authorizations_are_capped() {
        let store = OAuthStore::new(OAuthStoreConfig {
            max_pending_authorizations: 2,
            ..Default::default()
        });
        for _ in 0..2 {
            store
                .begin_authorization(pending_authorization(&store))
                .unwrap();
        }
        assert!(
            store
                .begin_authorization(pending_authorization(&store))
                .is_none(),
            "a pending authorization past the cap must be refused"
        );
        assert_eq!(store.lock().pending_authorizations.len(), 2);
    }

    #[test]
    fn default_pending_cap_is_max_pending_authorizations() {
        assert_eq!(
            OAuthStoreConfig::default().max_pending_authorizations,
            MAX_PENDING_AUTHORIZATIONS
        );
        assert_eq!(MAX_PENDING_AUTHORIZATIONS, 1024);
    }

    #[test]
    fn pending_cap_makes_room_by_dropping_expired_entries_first() {
        let store = OAuthStore::new(OAuthStoreConfig {
            max_pending_authorizations: 1,
            csrf_nonce_ttl: Duration::ZERO,
            ..Default::default()
        });
        let expired = store
            .begin_authorization(pending_authorization(&store))
            .unwrap();
        std::thread::sleep(Duration::from_millis(10));
        let fresh = store
            .begin_authorization(pending_authorization(&store))
            .expect("the expired entry is swept to make room");
        let inner = store.lock();
        assert!(!inner.pending_authorizations.contains_key(&expired));
        assert!(inner.pending_authorizations.contains_key(&fresh));
    }

    #[test]
    fn sweep_removes_only_expired_pending_authorizations() {
        let expiring = OAuthStore::new(OAuthStoreConfig {
            csrf_nonce_ttl: Duration::ZERO,
            ..Default::default()
        });
        let nonce = expiring
            .begin_authorization(pending_authorization(&expiring))
            .unwrap();
        std::thread::sleep(Duration::from_millis(10));
        expiring.sweep_expired();
        assert!(!expiring.lock().pending_authorizations.contains_key(&nonce));

        let lasting = OAuthStore::new(OAuthStoreConfig::default());
        let nonce = lasting
            .begin_authorization(pending_authorization(&lasting))
            .unwrap();
        lasting.sweep_expired();
        assert!(lasting.take_authorization(&nonce).is_some());
    }

    #[test]
    fn auth_code_lifecycle() {
        let store = OAuthStore::new(OAuthStoreConfig::default());
        let code = store.create_auth_code(
            "cid".into(),
            "http://localhost/cb".into(),
            vec!["read".into()],
            "challenge123".into(),
            "S256".into(),
        );
        assert!(code.starts_with("myapp_ac_"));

        let auth_code = store.consume_auth_code(&code).unwrap();
        assert_eq!(auth_code.client_id, "cid");
        assert_eq!(auth_code.code_challenge, "challenge123");
        assert_eq!(auth_code.code_challenge_method, "S256");

        // Second consume fails (single-use)
        assert!(store.consume_auth_code(&code).is_none());
    }

    #[test]
    fn access_token_lifecycle() {
        let store = OAuthStore::new(OAuthStoreConfig::default());
        let access_token = store.create_access_token("cid".into(), vec!["read".into()]);
        assert!(access_token.token.starts_with("myapp_at_"));
        assert!(access_token.refresh_token.starts_with("myapp_rt_"));

        let validated = store.validate_access_token(&access_token.token).unwrap();
        assert_eq!(validated.client_id, "cid");
        assert_eq!(validated.scope, vec!["read"]);
    }

    #[test]
    fn refresh_token_rotates() {
        let store = OAuthStore::new(OAuthStoreConfig::default());
        let first_token = store.create_access_token("cid".into(), vec!["read".into()]);

        let second_token = store
            .refresh_access_token(&first_token.refresh_token, "cid")
            .unwrap();
        assert_ne!(second_token.token, first_token.token);
        assert_ne!(second_token.refresh_token, first_token.refresh_token);

        // Old token is revoked
        assert!(store.validate_access_token(&first_token.token).is_none());

        // Old refresh token is consumed
        assert_eq!(
            store
                .refresh_access_token(&first_token.refresh_token, "cid")
                .unwrap_err(),
            RefreshError::InvalidToken
        );

        // New token works
        assert!(store.validate_access_token(&second_token.token).is_some());
    }

    #[test]
    fn refresh_by_other_client_is_refused_and_consumes_the_token() {
        let store = OAuthStore::new(OAuthStoreConfig::default());
        let first_token = store.create_access_token("cid".into(), vec!["read".into()]);

        assert_eq!(
            store
                .refresh_access_token(&first_token.refresh_token, "other")
                .unwrap_err(),
            RefreshError::ClientMismatch {
                expected_client: "cid".into()
            }
        );
        // The issuing client can no longer use it either
        assert_eq!(
            store
                .refresh_access_token(&first_token.refresh_token, "cid")
                .unwrap_err(),
            RefreshError::InvalidToken
        );
        // The access token issued with it is left alone
        assert!(store.validate_access_token(&first_token.token).is_some());
    }

    #[test]
    fn expired_token_invalid() {
        let config = OAuthStoreConfig {
            token_expiry_secs: 0,
            ..Default::default()
        };
        let store = OAuthStore::new(config);
        let access_token = store.create_access_token("cid".into(), vec!["read".into()]);
        std::thread::sleep(Duration::from_millis(10));
        assert!(store.validate_access_token(&access_token.token).is_none());
    }

    #[test]
    fn sweep_removes_expired() {
        let config = OAuthStoreConfig {
            token_expiry_secs: 0,
            ..Default::default()
        };
        let store = OAuthStore::new(config);
        let access_token = store.create_access_token("cid".into(), vec!["read".into()]);
        std::thread::sleep(Duration::from_millis(10));
        store.sweep_expired();

        assert!(store.validate_access_token(&access_token.token).is_none());
        // The refresh token outlives the access token it was issued with
        store
            .refresh_access_token(&access_token.refresh_token, "cid")
            .expect("refresh token is valid");
    }

    #[test]
    fn refresh_after_access_token_expired_and_swept() {
        let config = OAuthStoreConfig {
            token_expiry_secs: 0,
            ..Default::default()
        };
        let store = OAuthStore::new(config);
        let first_token =
            store.create_access_token("cid".into(), vec!["read".into(), "write".into()]);
        std::thread::sleep(Duration::from_millis(10));
        store.sweep_expired();
        assert!(!store.lock().access_tokens.contains_key(&first_token.token));

        let second_token = store
            .refresh_access_token(&first_token.refresh_token, "cid")
            .unwrap();
        assert_ne!(second_token.token, first_token.token);
        assert_ne!(second_token.refresh_token, first_token.refresh_token);
        assert_eq!(second_token.client_id, "cid");
        assert_eq!(second_token.scope, vec!["read", "write"]);
        assert!(
            store
                .lock()
                .refresh_tokens
                .contains_key(&second_token.refresh_token)
        );
    }

    #[test]
    fn refresh_token_over_lifetime_refused_before_sweep() {
        let store = OAuthStore::new(OAuthStoreConfig::default());
        let access_token = store.create_access_token("cid".into(), vec!["read".into()]);
        store.backdate_refresh_token(
            &access_token.refresh_token,
            REFRESH_TOKEN_LIFETIME + Duration::from_secs(1),
        );

        assert_eq!(
            store
                .refresh_access_token(&access_token.refresh_token, "cid")
                .unwrap_err(),
            RefreshError::InvalidToken
        );
    }

    #[test]
    fn refresh_token_over_lifetime_refused_after_sweep() {
        let store = OAuthStore::new(OAuthStoreConfig::default());
        let access_token = store.create_access_token("cid".into(), vec!["read".into()]);
        store.backdate_refresh_token(
            &access_token.refresh_token,
            REFRESH_TOKEN_LIFETIME + Duration::from_secs(1),
        );
        store.sweep_expired();

        assert_eq!(
            store
                .refresh_access_token(&access_token.refresh_token, "cid")
                .unwrap_err(),
            RefreshError::InvalidToken
        );
    }

    #[test]
    fn refresh_token_just_under_lifetime_refreshes() {
        let store = OAuthStore::new(OAuthStoreConfig::default());
        let access_token = store.create_access_token("cid".into(), vec!["read".into()]);
        store.backdate_refresh_token(
            &access_token.refresh_token,
            REFRESH_TOKEN_LIFETIME.saturating_sub(Duration::from_secs(60)),
        );

        store
            .refresh_access_token(&access_token.refresh_token, "cid")
            .expect("refresh token is valid");
    }

    #[test]
    fn sweep_removes_only_refresh_tokens_over_lifetime() {
        let store = OAuthStore::new(OAuthStoreConfig::default());
        let old_token = store.create_access_token("cid".into(), vec!["read".into()]);
        let young_token = store.create_access_token("cid".into(), vec!["read".into()]);
        store.backdate_refresh_token(
            &old_token.refresh_token,
            REFRESH_TOKEN_LIFETIME + Duration::from_secs(1),
        );
        store.backdate_refresh_token(
            &young_token.refresh_token,
            REFRESH_TOKEN_LIFETIME.saturating_sub(Duration::from_secs(60)),
        );
        store.sweep_expired();

        let inner = store.lock();
        assert!(!inner.refresh_tokens.contains_key(&old_token.refresh_token));
        assert!(
            inner
                .refresh_tokens
                .contains_key(&young_token.refresh_token)
        );
    }

    #[test]
    fn rotated_refresh_token_gets_own_lifetime() {
        let twenty_nine_days = Duration::from_secs(29 * 24 * 60 * 60);
        let store = OAuthStore::new(OAuthStoreConfig::default());
        let first_token = store.create_access_token("cid".into(), vec!["read".into()]);
        store.backdate_refresh_token(&first_token.refresh_token, twenty_nine_days);

        let second_token = store
            .refresh_access_token(&first_token.refresh_token, "cid")
            .unwrap();
        store.backdate_refresh_token(&second_token.refresh_token, twenty_nine_days);

        store
            .refresh_access_token(&second_token.refresh_token, "cid")
            .expect("refresh token is valid");
    }
}
