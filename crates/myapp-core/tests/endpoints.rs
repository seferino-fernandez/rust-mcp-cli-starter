//! Offline integration tests for the example endpoints using `wiremock`.
//!
//! Integration test files compile as their own crate without `#[cfg(test)]`,
//! so `clippy.toml`'s `allow-unwrap-in-tests` does not apply here; `unwrap()`
//! is idiomatic for test assertions, so it is allowed crate-wide.
#![expect(clippy::unwrap_used, reason = "unwrap is fine in test assertions")]

use myapp_core::{ApiClient, Config, Error, SecretString};
use std::error::Error as _;
use wiremock::matchers::{body_json, header, method, path, query_param};
use wiremock::{Mock, MockServer, ResponseTemplate};

fn client_for(base_url: &str) -> ApiClient {
    client_with_key(base_url, "test-key")
}

fn client_with_key(base_url: &str, api_key: &str) -> ApiClient {
    let config = Config {
        base_url: base_url.to_string(),
        api_key: Some(SecretString::from(api_key)),
        ..Config::default()
    };
    ApiClient::new(config).unwrap()
}

/// Every text an error can be shown as: its `Display`, the `Display` of its
/// whole cause chain, its `Debug`, and its public message.
fn error_texts(error: &Error) -> Vec<String> {
    let mut chain = error.to_string();
    let mut source = error.source();
    while let Some(cause) = source {
        chain.push_str(": ");
        chain.push_str(&cause.to_string());
        source = cause.source();
    }
    vec![
        error.to_string(),
        chain,
        format!("{error:?}"),
        error.public_message().into_owned(),
    ]
}

/// Asserts that none of `needles` appears in any text of `error`.
fn assert_absent(error: &Error, needles: &[&str]) {
    for text in error_texts(error) {
        for needle in needles {
            assert!(!text.contains(needle), "leaked {needle:?}: {text}");
        }
    }
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

#[tokio::test]
async fn upstream_500_body_with_the_api_key_and_a_secret_url_is_redacted() {
    let server = MockServer::start().await;
    let api_key = "configured-api-key-7f3a";
    Mock::given(method("GET"))
        .and(path("/api/v3/item/9"))
        .respond_with(ResponseTemplate::new(500).set_body_json(serde_json::json!({
            "message": format!(
                "key {api_key} rejected by https://backend.internal/check?name=x&password=query-secret"
            ),
            "stack": "at Upstream.Handler()"
        })))
        .mount(&server)
        .await;

    let err = client_with_key(&server.uri(), api_key)
        .get_item(9)
        .await
        .unwrap_err();

    let Error::Api(api) = &err else {
        panic!("expected Error::Api, got {err:?}");
    };
    assert_eq!(api.status(), 500);
    assert_eq!(
        api.message(),
        "key ******** rejected by https://backend.internal/check?name=x&password=********"
    );
    assert_eq!(
        err.public_message(),
        "upstream API request failed with status 500"
    );
    assert_absent(&err, &[api_key, "query-secret"]);
}

#[tokio::test]
async fn api_key_holding_a_delimiter_is_masked_whole_in_an_error_body() {
    // Free-text redaction stops a `password=` value at `&`, so only scrubbing
    // the exact key first keeps its tail out of the message.
    let api_key = "hunter2&strandedtail";
    for response in [
        ResponseTemplate::new(500)
            .insert_header("content-type", "text/plain")
            .set_body_string(format!("rejected password={api_key}")),
        ResponseTemplate::new(500)
            .set_body_json(serde_json::json!({"message": format!("rejected password={api_key}")})),
    ] {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/api/v3/item/9"))
            .and(header("X-Api-Key", api_key))
            .respond_with(response)
            .expect(1)
            .mount(&server)
            .await;

        let err = client_with_key(&server.uri(), api_key)
            .get_item(9)
            .await
            .unwrap_err();

        let Error::Api(api) = &err else {
            panic!("expected Error::Api, got {err:?}");
        };
        assert_eq!(api.message(), "rejected password=********");
        assert_absent(&err, &[api_key, "strandedtail"]);
    }
}

#[tokio::test]
async fn redirect_is_not_followed_and_hides_the_location() {
    let server = MockServer::start().await;
    let elsewhere = MockServer::start().await;
    let location = format!("{}/steal?token=location-secret", elsewhere.uri());
    Mock::given(method("GET"))
        .and(path("/api/v3/item/9"))
        .respond_with(ResponseTemplate::new(302).insert_header("location", location.as_str()))
        .expect(1)
        .mount(&server)
        .await;
    Mock::given(method("GET"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({})))
        .expect(0)
        .mount(&elsewhere)
        .await;

    let err = client_for(&server.uri()).get_item(9).await.unwrap_err();

    assert!(matches!(err, Error::Redirected { status: 302 }), "{err:?}");
    assert_eq!(
        err.public_message(),
        "the upstream server redirected the request (HTTP 302); redirects are not \
         followed, so check base_url and any reverse proxy in front of the server"
    );
    assert_absent(&err, &[&elsewhere.uri(), "location-secret"]);
    assert!(elsewhere.received_requests().await.unwrap().is_empty());
}

#[tokio::test]
async fn redirect_on_delete_is_not_followed() {
    let server = MockServer::start().await;
    Mock::given(method("DELETE"))
        .and(path("/api/v3/item/7"))
        .respond_with(ResponseTemplate::new(307).insert_header("location", "/api/v3/item/8"))
        .expect(1)
        .mount(&server)
        .await;

    let err = client_for(&server.uri()).delete_item(7).await.unwrap_err();

    assert!(matches!(err, Error::Redirected { status: 307 }), "{err:?}");
}

#[tokio::test]
async fn undecodable_success_body_is_a_deserialization_error() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/api/v3/item/9"))
        .respond_with(
            ResponseTemplate::new(200)
                .set_body_json(serde_json::json!({"id": "body-secret", "name": "x"})),
        )
        .mount(&server)
        .await;

    let err = client_for(&server.uri()).get_item(9).await.unwrap_err();

    let Error::Deserialization { endpoint, source } = &err else {
        panic!("expected Error::Deserialization, got {err:?}");
    };
    assert_eq!(endpoint, "/api/v3/item/9");
    assert!(
        source
            .to_string()
            .starts_with("invalid type: string, expected i64")
    );
    assert_eq!(
        err.public_message(),
        "the upstream server returned an unexpected response"
    );
    assert_absent(&err, &["body-secret", &server.uri()]);
}

#[tokio::test]
async fn oversized_error_body_is_not_shown() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/api/v3/item/9"))
        .respond_with(
            ResponseTemplate::new(500).set_body_string(format!("{}apikey=tail", "x".repeat(9000))),
        )
        .mount(&server)
        .await;

    let err = client_for(&server.uri()).get_item(9).await.unwrap_err();

    let Error::Api(api) = &err else {
        panic!("expected Error::Api, got {err:?}");
    };
    assert_eq!(
        api.message(),
        "upstream error response exceeded the 8192-byte limit"
    );
}
