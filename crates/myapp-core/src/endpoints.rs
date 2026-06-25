//! Example endpoint methods on [`ApiClient`]. Replace with your API's calls.

use crate::Result;
use crate::api;
use crate::client::ApiClient;
use crate::models::{Item, NewItem, SystemStatus};
use crate::pagination::Page;

impl ApiClient {
    /// `GET /api/v3/system/status`: server health.
    pub async fn system_status(&self) -> Result<SystemStatus> {
        self.get(api::SYSTEM_STATUS).await
    }

    /// `GET /api/v3/item?page={page}&pageSize={pageSize}`: one page of items.
    pub async fn list_items(&self, page: u32, page_size: u32) -> Result<Page<Item>> {
        self.get_page(
            api::ITEMS,
            &[
                ("page", &page.to_string()),
                ("pageSize", &page_size.to_string()),
            ],
        )
        .await
    }

    /// `GET /api/v3/item/{id}`: a single item.
    pub async fn get_item(&self, id: i64) -> Result<Item> {
        self.get(&api::item(id)).await
    }

    /// `POST /api/v3/item`: create an item.
    pub async fn create_item(&self, body: &NewItem) -> Result<Item> {
        self.post_json(api::ITEMS, body).await
    }

    /// `DELETE /api/v3/item/{id}`: delete an item.
    pub async fn delete_item(&self, id: i64) -> Result<()> {
        self.delete(&api::item(id)).await
    }
}
