use anyhow::Context;
use myapp_core::{ApiClient, Config, ConfigOverrides, SecretString};
use std::path::Path;

use super::error::safe_core_error;

/// Loads config with the CLI flags as the top layer, above env and TOML.
pub fn load_config(
    config_path: Option<&Path>,
    base_url: Option<&str>,
    api_key: Option<&str>,
) -> anyhow::Result<Config> {
    let overrides = ConfigOverrides {
        base_url: base_url.map(str::to_string),
        api_key: api_key.map(SecretString::from),
    };
    Config::load(config_path, &overrides)
        .map_err(safe_core_error)
        .context("loading config")
}

/// Builds an [`ApiClient`] from loaded config.
pub fn build_client(config: Config) -> anyhow::Result<ApiClient> {
    ApiClient::new(config)
        .map_err(safe_core_error)
        .context("building API client")
}
