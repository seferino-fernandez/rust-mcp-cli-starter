//! [`ApiClient`]: a thin authenticated HTTP wrapper.
//!
//! Sends the configured API key as the `X-Api-Key` header on every request.
//! To use bearer auth instead, change [`API_KEY_HEADER`] to `"Authorization"`
//! and prefix the value with `"Bearer "`.

use crate::Result;
use crate::config::Config;
use crate::error::Error;
use crate::pagination::Page;
use reqwest::StatusCode;
use reqwest::header::{HeaderMap, HeaderValue};
use serde::Serialize;
use serde::de::DeserializeOwned;
use std::time::Duration;

/// Header carrying the API key.
const API_KEY_HEADER: &str = "X-Api-Key";
/// Default retry-after when the server omits the header on a 429.
const DEFAULT_RETRY_AFTER_SECS: u64 = 60;

/// Authenticated client for the upstream API.
///
/// Cheap to clone (the inner `reqwest::Client` is reference-counted).
#[derive(Debug, Clone)]
pub struct ApiClient {
    http: reqwest::Client,
    base_url: String,
}

impl ApiClient {
    /// Builds a client from [`Config`]. Fails with [`Error::MissingApiKey`]
    /// when no key was resolved.
    pub fn new(config: Config) -> Result<Self> {
        let key = config.api_key.as_ref().ok_or(Error::MissingApiKey)?;
        let mut headers = HeaderMap::new();
        // The source error is intentionally dropped: it can echo raw header
        // bytes, which would leak the secret API key into logs.
        let mut value = HeaderValue::from_str(key.expose_secret()).map_err(|_invalid| {
            Error::Config("API key contains invalid header characters".into())
        })?;
        value.set_sensitive(true);
        headers.insert(API_KEY_HEADER, value);

        let http = reqwest::Client::builder()
            .default_headers(headers)
            .timeout(Duration::from_secs(config.http.request_timeout_secs))
            .connect_timeout(Duration::from_secs(config.http.connect_timeout_secs))
            .build()?;

        Ok(Self {
            http,
            base_url: config.base_url.trim_end_matches('/').to_string(),
        })
    }

    /// Joins the base URL with a path beginning with `/`.
    fn url(&self, path: &str) -> String {
        format!("{}{}", self.base_url, path)
    }

    /// `GET path` → deserialized JSON.
    pub async fn get<T: DeserializeOwned>(&self, path: &str) -> Result<T> {
        let res = self.http.get(self.url(path)).send().await?;
        handle_response(res).await
    }

    /// `GET path?<params>` → deserialized JSON.
    pub async fn get_with_params<T: DeserializeOwned>(
        &self,
        path: &str,
        params: &[(&str, &str)],
    ) -> Result<T> {
        let res = self.http.get(self.url(path)).query(params).send().await?;
        handle_response(res).await
    }

    /// `GET path?<params>` → one [`Page`] of `T`.
    pub async fn get_page<T: DeserializeOwned>(
        &self,
        path: &str,
        params: &[(&str, &str)],
    ) -> Result<Page<T>> {
        self.get_with_params(path, params).await
    }

    /// `POST path` with a JSON body → deserialized JSON.
    pub async fn post_json<T: DeserializeOwned, B: Serialize + ?Sized>(
        &self,
        path: &str,
        body: &B,
    ) -> Result<T> {
        let res = self.http.post(self.url(path)).json(body).send().await?;
        handle_response(res).await
    }

    /// `DELETE path`; succeeds on any 2xx (body ignored).
    pub async fn delete(&self, path: &str) -> Result<()> {
        let res = self.http.delete(self.url(path)).send().await?;
        if res.status().is_success() {
            return Ok(());
        }
        handle_response::<serde_json::Value>(res).await.map(|_| ())
    }
}

/// Maps a response to `Result<T>`: 429 → [`Error::RateLimited`], other non-2xx
/// → [`Error::Api`], success → parsed JSON.
async fn handle_response<T: DeserializeOwned>(res: reqwest::Response) -> Result<T> {
    let response_status = res.status();
    if response_status == StatusCode::TOO_MANY_REQUESTS {
        let retry_after = res
            .headers()
            .get("retry-after")
            .and_then(|header| header.to_str().ok())
            .and_then(|header_value| header_value.parse().ok())
            .unwrap_or(DEFAULT_RETRY_AFTER_SECS);
        return Err(Error::RateLimited {
            retry_after_secs: retry_after,
        });
    }
    let url = res.url().clone();
    tracing::debug!(status = response_status.as_u16(), %url, "API response");
    let body = res.text().await.unwrap_or_default();
    if !response_status.is_success() {
        return Err(Error::Api {
            status: response_status.as_u16(),
            message: body,
        });
    }
    serde_json::from_str::<T>(&body).map_err(|err| Error::Api {
        status: response_status.as_u16(),
        message: format!("Failed to parse response from {url}: {err}"),
    })
}
