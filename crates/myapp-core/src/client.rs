//! [`ApiClient`]: a thin authenticated HTTP wrapper.
//!
//! Sends the configured API key as the `X-Api-Key` header on every request.
//! To use bearer auth instead, change `API_KEY_HEADER` to `"Authorization"`
//! and prefix the value with `"Bearer "`.
//!
//! Redirects are never followed: reqwest forwards default headers, the API
//! key included, to a redirect target even on another host, so a 3xx response
//! becomes [`Error::Redirected`]. Every error built from a response has the
//! API key scrubbed from it, and transport errors have the credentials in
//! their URL masked.

use crate::Result;
use crate::config::Config;
use crate::error::{ConfigError, DeserializationError, Error, MAX_ERROR_MESSAGE_BYTES};
use crate::pagination::Page;
use crate::redact::Redacted;
use crate::secret::SecretString;
use reqwest::StatusCode;
use reqwest::header::{HeaderMap, HeaderValue};
use serde::Serialize;
use serde::de::DeserializeOwned;
use std::sync::Arc;
use std::time::Duration;

/// Header carrying the API key.
const API_KEY_HEADER: &str = "X-Api-Key";
/// Default retry-after when the server omits the header on a 429.
const DEFAULT_RETRY_AFTER_SECS: u64 = 60;

/// Authenticated client for the upstream API.
///
/// Cheap to clone (the inner `reqwest::Client` and the secrets are
/// reference-counted).
#[derive(Debug, Clone)]
pub struct ApiClient {
    http: reqwest::Client,
    base_url: String,
    /// Every secret the client sends, scrubbed from errors and from
    /// [`ApiClient::redact`] output.
    secrets: Arc<[SecretString]>,
}

impl ApiClient {
    /// Builds a client from [`Config`].
    ///
    /// # Errors
    ///
    /// Returns [`Error::MissingApiKey`] when no key was resolved,
    /// [`ConfigError::InvalidApiKeyHeader`] (as [`Error::Config`]) when the
    /// key cannot be sent in an HTTP header, and [`Error::Http`] when the
    /// HTTP client cannot be built.
    pub fn new(config: Config) -> Result<Self> {
        let key = config.api_key.ok_or(Error::MissingApiKey)?;
        let mut headers = HeaderMap::new();
        // The source error is intentionally dropped: it can echo raw header
        // bytes, which would leak the secret API key into logs.
        let mut value = HeaderValue::from_str(key.expose_secret())
            .map_err(|_invalid| ConfigError::InvalidApiKeyHeader)?;
        value.set_sensitive(true);
        headers.insert(API_KEY_HEADER, value);

        let http = reqwest::Client::builder()
            .redirect(reqwest::redirect::Policy::none())
            .default_headers(headers)
            .timeout(Duration::from_secs(config.http.request_timeout_secs))
            .connect_timeout(Duration::from_secs(config.http.connect_timeout_secs))
            .build()?;

        Ok(Self {
            http,
            base_url: config.base_url.trim_end_matches('/').to_string(),
            secrets: Arc::from([key]),
        })
    }

    /// Redacts `data` for presentation, as [`Redacted::new`] does, and also
    /// masks every exact representation of the secrets this client holds, in
    /// values and object keys, before and after the key-based and free-text
    /// rules.
    ///
    /// The API key is masked wherever it appears, so a very short key, such
    /// as one character, also masks every occurrence of that text in
    /// unrelated output. An empty or whitespace-only key is refused when the
    /// configuration loads.
    ///
    /// # Errors
    ///
    /// Returns the [`serde_json::Error`] when `data` cannot be serialized to
    /// JSON.
    pub fn redact<T: Serialize>(
        &self,
        data: &T,
    ) -> std::result::Result<Redacted<T>, serde_json::Error> {
        Redacted::scrubbing(data, &self.secrets)
    }

    /// Joins the base URL with a path beginning with `/`.
    fn url(&self, path: &str) -> String {
        format!("{}{}", self.base_url, path)
    }

    /// `GET path` → deserialized JSON.
    ///
    /// # Errors
    ///
    /// Returns [`Error::Http`] when the request cannot be sent or its body
    /// cannot be read, [`Error::Redirected`] on a 3xx,
    /// [`Error::RateLimited`] on a 429, [`Error::Api`] on any other
    /// non-success status, and [`Error::Deserialization`] when a success
    /// body does not parse as `T`.
    pub async fn get<T: DeserializeOwned>(&self, path: &str) -> Result<T> {
        let res = self.http.get(self.url(path)).send().await?;
        self.handle_response(path, res).await
    }

    /// `GET path?<params>` → deserialized JSON.
    ///
    /// # Errors
    ///
    /// Returns [`Error::Http`] when the request cannot be sent or its body
    /// cannot be read, [`Error::Redirected`] on a 3xx,
    /// [`Error::RateLimited`] on a 429, [`Error::Api`] on any other
    /// non-success status, and [`Error::Deserialization`] when a success
    /// body does not parse as `T`.
    pub async fn get_with_params<T: DeserializeOwned>(
        &self,
        path: &str,
        params: &[(&str, &str)],
    ) -> Result<T> {
        let res = self.http.get(self.url(path)).query(params).send().await?;
        self.handle_response(path, res).await
    }

    /// `GET path?<params>` → one [`Page`] of `T`.
    ///
    /// # Errors
    ///
    /// Fails as [`get_with_params`](Self::get_with_params) does, with the
    /// body parsed as a [`Page`] of `T`.
    pub async fn get_page<T: DeserializeOwned>(
        &self,
        path: &str,
        params: &[(&str, &str)],
    ) -> Result<Page<T>> {
        self.get_with_params(path, params).await
    }

    /// `POST path` with a JSON body → deserialized JSON.
    ///
    /// # Errors
    ///
    /// Returns [`Error::Http`] when the request cannot be sent or its body
    /// cannot be read, [`Error::Redirected`] on a 3xx,
    /// [`Error::RateLimited`] on a 429, [`Error::Api`] on any other
    /// non-success status, and [`Error::Deserialization`] when a success
    /// body does not parse as `T`.
    pub async fn post_json<T: DeserializeOwned, B: Serialize + ?Sized>(
        &self,
        path: &str,
        body: &B,
    ) -> Result<T> {
        let res = self.http.post(self.url(path)).json(body).send().await?;
        self.handle_response(path, res).await
    }

    /// `DELETE path`; succeeds on any 2xx (body ignored).
    ///
    /// # Errors
    ///
    /// Returns [`Error::Http`] when the request cannot be sent,
    /// [`Error::Redirected`] on a 3xx, [`Error::RateLimited`] on a 429, and
    /// [`Error::Api`] on any other non-success status.
    pub async fn delete(&self, path: &str) -> Result<()> {
        let res = self.http.delete(self.url(path)).send().await?;
        if res.status().is_success() {
            return Ok(());
        }
        Err(self.error_from(res).await)
    }

    /// Maps a response to `Result<T>`: success → parsed JSON, or
    /// [`Error::Deserialization`] when it does not parse; any other status →
    /// the error [`error_from`](Self::error_from) builds.
    async fn handle_response<T: DeserializeOwned>(
        &self,
        path: &str,
        res: reqwest::Response,
    ) -> Result<T> {
        let response_status = res.status();
        tracing::debug!(status = response_status.as_u16(), path, "API response");
        if !response_status.is_success() {
            return Err(self.error_from(res).await);
        }
        let body = res.bytes().await?;
        serde_json::from_slice::<T>(&body).map_err(|source| Error::Deserialization {
            endpoint: path.to_string(),
            source: DeserializationError::from_serde(&source, &self.secrets),
        })
    }

    /// Builds the error for a non-success response: 3xx →
    /// [`Error::Redirected`], 429 → [`Error::RateLimited`], anything else →
    /// [`Error::Api`] from a body of at most 8 KiB, with the client's secrets
    /// scrubbed.
    async fn error_from(&self, mut res: reqwest::Response) -> Error {
        let status = res.status();
        if status.is_redirection() {
            return Error::Redirected {
                status: status.as_u16(),
            };
        }
        if status == StatusCode::TOO_MANY_REQUESTS {
            let retry_after = res
                .headers()
                .get("retry-after")
                .and_then(|header| header.to_str().ok())
                .and_then(|header_value| header_value.parse().ok())
                .unwrap_or(DEFAULT_RETRY_AFTER_SECS);
            return Error::RateLimited {
                retry_after_secs: retry_after,
            };
        }
        // A body cut short could end inside a secret, leaving a part that no
        // rule recognizes, so a body over the limit is not shown at all.
        let mut body = Vec::new();
        while body.len() <= MAX_ERROR_MESSAGE_BYTES {
            match res.chunk().await {
                Ok(Some(chunk)) => body.extend_from_slice(&chunk),
                Ok(None) => break,
                Err(source) => return source.into(),
            }
        }
        if body.len() > MAX_ERROR_MESSAGE_BYTES {
            return Error::api(
                status.as_u16(),
                "upstream error response exceeded the 8192-byte limit",
            );
        }
        Error::api_with_secrets(
            status.as_u16(),
            &String::from_utf8_lossy(&body),
            &self.secrets,
        )
    }
}

#[cfg(test)]
mod tests {
    use super::ApiClient;
    use crate::error::Error;
    use crate::{Config, SecretString};
    use std::error::Error as _;

    /// Joins the `Display` of `error` and every error in its source chain.
    fn chain_text(error: &Error) -> String {
        let mut text = error.to_string();
        let mut source = error.source();
        while let Some(cause) = source {
            text.push_str(": ");
            text.push_str(&cause.to_string());
            source = cause.source();
        }
        text
    }

    /// A transport error for `url`: nothing listens on port 1.
    async fn connect_error(url: &str) -> Error {
        reqwest::Client::new()
            .get(url)
            .send()
            .await
            .expect_err("nothing listens on port 1")
            .into()
    }

    #[tokio::test]
    async fn transport_error_url_masks_secret_query_values() {
        let error = connect_error(
            "http://127.0.0.1:1/api?page=2&apikey=k1&password=p%262&access_token=t3&pass%77ord=p4",
        )
        .await;
        let text = format!("{}{error:?}", chain_text(&error));
        for secret in ["k1", "p%262", "p&2", "t3", "p4"] {
            assert!(!text.contains(secret), "leaked {secret}: {text}");
        }
        assert!(text.contains("page=2"), "{text}");
        let Error::Http(source) = &error else {
            panic!("a transport failure is Error::Http, got {error:?}");
        };
        let url = source.url().expect("the URL is kept");
        assert_eq!(
            url.query(),
            Some(
                "page=2&apikey=********&password=********&access_token=********&password=********"
            )
        );
    }

    #[tokio::test]
    async fn transport_error_url_masks_user_info_and_path_secrets() {
        let error = connect_error("http://user:hunter2@127.0.0.1:1/passkey/pk-secret/rss").await;
        let text = format!("{}{error:?}", chain_text(&error));
        assert!(!text.contains("hunter2"), "{text}");
        assert!(!text.contains("pk-secret"), "{text}");
    }

    #[tokio::test]
    async fn transport_error_through_the_client_hides_the_api_key() {
        let client = ApiClient::new(Config {
            base_url: "http://127.0.0.1:1".to_string(),
            api_key: Some(SecretString::from("client-secret-key")),
            ..Config::default()
        })
        .expect("client builds");

        let error = client
            .get_item(1)
            .await
            .expect_err("nothing listens on port 1");

        assert!(matches!(error, Error::Http(_)), "{error:?}");
        assert_eq!(error.public_message(), "the upstream request failed");
        let text = format!("{}{error:?}", chain_text(&error));
        assert!(!text.contains("client-secret-key"), "{text}");
    }

    #[test]
    fn redact_masks_the_api_key_in_values_and_map_keys() {
        let client = ApiClient::new(Config {
            api_key: Some(SecretString::from("client-secret-key")),
            ..Config::default()
        })
        .expect("client builds");
        let data = std::collections::BTreeMap::from([
            (
                "client-secret-key".to_string(),
                "uses client-secret-key".to_string(),
            ),
            ("https://u:pw@h".to_string(), "x".to_string()),
        ]);

        let redacted = client.redact(&data).expect("redaction succeeds");

        assert_eq!(
            redacted.as_value(),
            &serde_json::json!({
                "********": "uses ********",
                "https://u:********@h": "x"
            })
        );
    }

    #[test]
    fn an_api_key_that_is_not_a_header_value_is_a_config_error() {
        let error = ApiClient::new(Config {
            api_key: Some(SecretString::from("bad\nkey")),
            ..Config::default()
        })
        .expect_err("a newline cannot go in a header");
        assert!(
            matches!(
                error,
                Error::Config(crate::ConfigError::InvalidApiKeyHeader)
            ),
            "{error:?}"
        );
        assert!(!format!("{error:?}").contains("bad\nkey"));
    }
}
