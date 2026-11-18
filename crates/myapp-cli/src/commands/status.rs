//! `myapp status`: print server health.

use crate::output::{self, OutputFormat};
use crate::utils::error::safe_core_error;
use myapp_core::ApiClient;

/// Runs the status command.
pub(crate) async fn run(client: &ApiClient, output: OutputFormat) -> anyhow::Result<()> {
    let status = client
        .system_status()
        .await
        .map_err(|error| safe_core_error(&error))?;
    match output {
        OutputFormat::Json => output::print_json(&status)?,
        OutputFormat::Csv => output::print_csv(
            &["app_name", "version"],
            &[vec![status.app_name.clone(), status.version]],
        )?,
        OutputFormat::Table => output::print_table(
            &["App", "Version"],
            &[vec![status.app_name, status.version]],
        )?,
    }
    Ok(())
}
