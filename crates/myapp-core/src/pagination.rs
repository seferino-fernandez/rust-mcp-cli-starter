//! Generic paginated response wrapper for JSON APIs.

use serde::Deserialize;

/// A page of records using a common pagination envelope:
/// `{ "page", "pageSize", "totalRecords", "records": [...] }`.
#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Page<T> {
    /// 1-based page index.
    pub page: u32,
    /// Number of records requested per page.
    pub page_size: u32,
    /// Total records available across all pages.
    pub total_records: u32,
    /// The records in this page.
    pub records: Vec<T>,
}

#[cfg(test)]
mod tests {
    use super::Page;

    #[test]
    fn page_deserializes_camelcase_envelope() {
        let json = r#"{"page":1,"pageSize":2,"totalRecords":5,"records":[10,20]}"#;
        let page: Page<i32> = serde_json::from_str(json).unwrap();
        assert_eq!(page.page, 1);
        assert_eq!(page.page_size, 2);
        assert_eq!(page.total_records, 5);
        assert_eq!(page.records, vec![10, 20]);
    }
}
