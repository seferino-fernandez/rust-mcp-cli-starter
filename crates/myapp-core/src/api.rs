//! API path constants. Keep paths in one place so a base-URL or version change is a single edit.

/// `GET` server health/status.
pub const SYSTEM_STATUS: &str = "/api/v3/system/status";
/// Collection path for items (`GET` list, `POST` create).
pub const ITEMS: &str = "/api/v3/item";

/// Path for a single item by id (`GET`, `DELETE`).
pub fn item(id: i64) -> String {
    format!("{ITEMS}/{id}")
}
