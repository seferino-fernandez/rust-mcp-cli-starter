//! Output formatting helpers for the `myapp` CLI.

use std::io::{ErrorKind, Write};

use comfy_table::{ContentArrangement, Table};
use serde::Serialize;

/// Output format for CLI commands.
#[derive(Debug, Clone, Copy, clap::ValueEnum)]
pub enum OutputFormat {
    /// Human-readable table (default).
    Table,
    /// JSON (pretty-printed).
    Json,
    /// CSV with a header row.
    Csv,
}

/// Writes a single line to stdout, exiting cleanly if the downstream pipe was
/// closed (e.g. `... | head`). Without this, the default `println!` panics on
/// `BrokenPipe`. Other write errors are ignored (best-effort terminal output).
fn write_line(line: &str) {
    let stdout = std::io::stdout();
    let mut lock = stdout.lock();
    match writeln!(lock, "{line}") {
        Ok(()) => {}
        Err(err) if err.kind() == ErrorKind::BrokenPipe => {
            std::process::exit(0);
        }
        Err(_) => {}
    }
}

/// Renders `data` as pretty JSON and writes it to stdout.
pub fn print_json<T: Serialize>(data: &T) -> anyhow::Result<()> {
    let json = serde_json::to_string_pretty(data)?;
    write_line(&json);
    Ok(())
}

/// Renders `rows` as a [`comfy_table`] table with `headers` and writes it to stdout.
pub fn print_table(headers: &[&str], rows: &[Vec<String>]) {
    let mut table = Table::new();
    table.set_content_arrangement(ContentArrangement::Dynamic);
    table.set_header(headers);
    for row in rows {
        table.add_row(row);
    }
    write_line(&table.to_string());
}

/// Escapes a single CSV field, quoting it when necessary.
fn escape_csv_field(field: &str) -> String {
    if field.contains(',') || field.contains('"') || field.contains('\n') {
        format!("\"{}\"", field.replace('"', "\"\""))
    } else {
        field.to_string()
    }
}

/// Renders `rows` as CSV with a `headers` row and writes it to stdout.
pub fn print_csv(headers: &[&str], rows: &[Vec<String>]) {
    let escaped_headers: Vec<String> = headers
        .iter()
        .map(|header| escape_csv_field(header))
        .collect();
    write_line(&escaped_headers.join(","));
    for row in rows {
        let escaped: Vec<String> = row.iter().map(|field| escape_csv_field(field)).collect();
        write_line(&escaped.join(","));
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn escape_csv_plain() {
        assert_eq!(escape_csv_field("hello"), "hello");
    }

    #[test]
    fn escape_csv_with_comma() {
        assert_eq!(escape_csv_field("hello,world"), "\"hello,world\"");
    }

    #[test]
    fn escape_csv_with_quotes() {
        assert_eq!(escape_csv_field(r#"say "hi""#), r#""say ""hi""""#);
    }

    #[test]
    fn escape_csv_with_newline() {
        assert_eq!(escape_csv_field("line1\nline2"), "\"line1\nline2\"");
    }

    #[test]
    fn escape_csv_with_comma_and_quotes() {
        assert_eq!(escape_csv_field(r#"a,"b""#), r#""a,""b""""#);
    }
}
