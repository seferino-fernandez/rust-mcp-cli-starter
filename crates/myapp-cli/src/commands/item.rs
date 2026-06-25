//! `myapp item`: list/get/create/delete example items.

use std::slice;

use crate::output::OutputFormat;
use clap::Subcommand;
use myapp_core::ApiClient;
use myapp_core::models::{Item, NewItem};

/// `item` subcommands.
#[derive(Subcommand)]
pub enum ItemCommand {
    /// List items (paginated).
    List {
        /// Page number (1-based).
        #[arg(long, default_value_t = 1)]
        page: u32,
        /// Page size.
        #[arg(long, default_value_t = 20)]
        page_size: u32,
    },
    /// Get a single item by id.
    Get {
        /// Item id.
        id: i64,
    },
    /// Create an item.
    Create {
        /// Item name.
        name: String,
        /// Start enabled.
        #[arg(long)]
        enabled: bool,
    },
    /// Delete an item by id.
    Delete {
        /// Item id.
        id: i64,
    },
}

/// Runs an `item` subcommand.
pub async fn run(
    command: &ItemCommand,
    client: &ApiClient,
    output: OutputFormat,
) -> anyhow::Result<()> {
    match command {
        ItemCommand::List { page, page_size } => {
            let result = client.list_items(*page, *page_size).await?;
            render_items(&result.records, output)?;
        }
        ItemCommand::Get { id } => {
            let item = client.get_item(*id).await?;
            render_items(slice::from_ref(&item), output)?;
        }
        ItemCommand::Create { name, enabled } => {
            let item = client
                .create_item(&NewItem {
                    name: name.clone(),
                    enabled: *enabled,
                })
                .await?;
            render_items(slice::from_ref(&item), output)?;
        }
        ItemCommand::Delete { id } => {
            client.delete_item(*id).await?;
            println!("Deleted item {id}");
        }
    }
    Ok(())
}

fn render_items(items: &[Item], output: OutputFormat) -> anyhow::Result<()> {
    let rows: Vec<Vec<String>> = items
        .iter()
        .map(|i| vec![i.id.to_string(), i.name.clone(), i.enabled.to_string()])
        .collect();
    match output {
        OutputFormat::Json => crate::output::print_json(&items)?,
        OutputFormat::Csv => crate::output::print_csv(&["id", "name", "enabled"], &rows),
        OutputFormat::Table => crate::output::print_table(&["ID", "Name", "Enabled"], &rows),
    }
    Ok(())
}
