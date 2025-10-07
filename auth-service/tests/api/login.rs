use crate::helpers::TestApp;
use serde_json;

#[tokio::test]
async fn login_returns_200() {
    let app = TestApp::new().await;
    let body = serde_json::json!({
        "email": "user@example.com",
        "password": "string"
    });
    let response = app.login(&body).await;
    assert_eq!(response.status().as_u16(), 200);
}  