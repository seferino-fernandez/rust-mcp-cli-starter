use anyhow::Context;
use myapp_core::{ApiClient, Config, SecretString};
use std::path::Path;

/// Builds an [`ApiClient`] from config + CLI overrides.
pub fn build_client(
    config_path: Option<&Path>,
    base_url: Option<&str>,
    api_key: Option<&str>,
) -> anyhow::Result<ApiClient> {
    let mut config = Config::load(config_path).context("loading config")?;
    if let Some(url) = base_url {
        config.base_url = url.to_string();
    }
    if let Some(key) = api_key {
        config.api_key = Some(SecretString::from(key.to_string()));
    }
    ApiClient::new(config).context("building API client")
}
