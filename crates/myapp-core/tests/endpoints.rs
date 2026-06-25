//! Offline integration tests for the example endpoints using `wiremock`.
//!
//! Integration test files compile as their own crate without `#[cfg(test)]`,
//! so `clippy.toml`'s `allow-unwrap-in-tests` does not apply here; `unwrap()`
//! is idiomatic for test assertions, so it is allowed crate-wide.
#![expect(clippy::unwrap_used, reason = "unwrap is fine in test assertions")]

use myapp_core::{ApiClient, Config, SecretString};
use wiremock::matchers::{body_json, header, method, path, query_param};
use wiremock::{Mock, MockServer, ResponseTemplate};

fn client_for(base_url: &str) -> ApiClient {
    let config = Config {
        base_url: base_url.to_string(),
        api_key: Some(SecretString::from("test-key".to_string())),
        ..Config::default()
    };
    ApiClient::new(config).unwrap()
}

#[tokio::test]
async fn system_status_sends_api_key_and_parses() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/api/v3/system/status"))
        .and(header("X-Api-Key", "test-key"))
        .respond_with(
            ResponseTemplate::new(200)
                .set_body_json(serde_json::json!({"appName": "MyApp", "version": "1.2.3"})),
        )
        .mount(&server)
        .await;

    let status = client_for(&server.uri()).system_status().await.unwrap();
    assert_eq!(status.app_name, "MyApp");
    assert_eq!(status.version, "1.2.3");
}

#[tokio::test]
async fn list_items_paginates_with_query_params() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/api/v3/item"))
        .and(query_param("page", "1"))
        .and(query_param("pageSize", "2"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "page": 1, "pageSize": 2, "totalRecords": 2,
            "records": [
                {"id": 1, "name": "a", "enabled": true},
                {"id": 2, "name": "b", "enabled": false}
            ]
        })))
        .mount(&server)
        .await;

    let page = client_for(&server.uri()).list_items(1, 2).await.unwrap();
    assert_eq!(page.total_records, 2);
    assert_eq!(page.records.len(), 2);
    assert_eq!(page.records[0].name, "a");
}

#[tokio::test]
async fn create_item_posts_body() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/api/v3/item"))
        .and(body_json(
            serde_json::json!({"name": "new", "enabled": true}),
        ))
        .respond_with(
            ResponseTemplate::new(201)
                .set_body_json(serde_json::json!({"id": 7, "name": "new", "enabled": true})),
        )
        .mount(&server)
        .await;

    let item = client_for(&server.uri())
        .create_item(&myapp_core::models::NewItem {
            name: "new".into(),
            enabled: true,
        })
        .await
        .unwrap();
    assert_eq!(item.id, 7);
}

#[tokio::test]
async fn delete_item_succeeds_on_2xx() {
    let server = MockServer::start().await;
    Mock::given(method("DELETE"))
        .and(path("/api/v3/item/7"))
        .respond_with(ResponseTemplate::new(200))
        .mount(&server)
        .await;

    client_for(&server.uri()).delete_item(7).await.unwrap();
}

#[tokio::test]
async fn get_item_returns_parsed_item() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/api/v3/item/7"))
        .respond_with(
            ResponseTemplate::new(200)
                .set_body_json(serde_json::json!({"id": 7, "name": "widget", "enabled": true})),
        )
        .mount(&server)
        .await;

    let item = client_for(&server.uri()).get_item(7).await.unwrap();
    assert_eq!(item.id, 7);
    assert_eq!(item.name, "widget");
    assert!(item.enabled);
}

#[tokio::test]
async fn rate_limited_surfaces_retry_after() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/api/v3/item/9"))
        .respond_with(ResponseTemplate::new(429).insert_header("retry-after", "30"))
        .mount(&server)
        .await;

    let err = client_for(&server.uri()).get_item(9).await.unwrap_err();
    assert!(matches!(
        err,
        myapp_core::Error::RateLimited {
            retry_after_secs: 30
        }
    ));
}

#[tokio::test]
async fn api_error_body_is_surfaced() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/api/v3/item/9"))
        .respond_with(
            ResponseTemplate::new(404).set_body_json(serde_json::json!({"message": "not found"})),
        )
        .mount(&server)
        .await;

    let err = client_for(&server.uri()).get_item(9).await.unwrap_err();
    assert_eq!(err.to_string(), "API error (404): not found");
}

#[tokio::test]
async fn missing_api_key_is_rejected() {
    let err = ApiClient::new(Config::default()).unwrap_err();
    assert!(matches!(err, myapp_core::Error::MissingApiKey));
}
