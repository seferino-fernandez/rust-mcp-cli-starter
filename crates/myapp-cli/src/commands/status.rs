//! `myapp status`: print server health.

use crate::output::{self, OutputFormat};
use myapp_core::ApiClient;

/// Runs the status command.
pub async fn run(client: &ApiClient, output: OutputFormat) -> anyhow::Result<()> {
    let status = client.system_status().await?;
    match output {
        OutputFormat::Json => output::print_json(&status)?,
        OutputFormat::Csv => output::print_csv(
            &["app_name", "version"],
            &[vec![status.app_name.clone(), status.version.clone()]],
        ),
        OutputFormat::Table => output::print_table(
            &["App", "Version"],
            &[vec![status.app_name, status.version]],
        ),
    }
    Ok(())
}
