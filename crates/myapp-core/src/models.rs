//! Serde response types for the example API.
//!
//! Replace these with your API's real types. The example models a simple
//! resource: a `SystemStatus` health payload and an `Item` resource that can
//! be listed, fetched, created, and deleted.

use serde::{Deserialize, Serialize};

/// Health/status payload returned by `GET /api/v3/system/status`.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[serde(rename_all = "camelCase")]
pub struct SystemStatus {
    /// Application name reported by the server.
    pub app_name: String,
    /// Server version string.
    pub version: String,
}

/// An example resource record.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
pub struct Item {
    /// Server-assigned identifier.
    pub id: i64,
    /// Human-readable name.
    pub name: String,
    /// Whether the item is enabled.
    pub enabled: bool,
}

/// Request body for creating an [`Item`].
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NewItem {
    /// Name for the new item.
    pub name: String,
    /// Whether the item should start enabled.
    pub enabled: bool,
}
