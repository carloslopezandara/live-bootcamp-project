use crate::helpers::TestApp;
use serde_json;

#[tokio::test]
async fn verify_2fa_returns_200() {
    let app = TestApp::new().await;
    let body = serde_json::json!({
        "email": "user@example.com",
        "loginAttemptId": "string",
        "2FACode": "string"
    });
    let response = app.verify_2fa(&body).await;
    assert_eq!(response.status().as_u16(), 200);
}