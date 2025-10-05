use crate::helpers::TestApp;
use serde_json;

// Tokio's test macro is used to run the test in an async environment
#[tokio::test]
async fn root_returns_auth_ui() {
    let app = TestApp::new().await;

    let response = app.get_root().await;

    assert_eq!(response.status().as_u16(), 200);
    assert_eq!(response.headers().get("content-type").unwrap(), "text/html");
}

// TODO: Implement tests for all other routes (signup, login, logout, verify-2fa, and verify-token)
// For now, simply assert that each route returns a 200 HTTP status code.
#[tokio::test]
async fn signup_returns_200() {
    let app = TestApp::new().await; // Create a new instance of the test application
    let body = serde_json::json!({
        "email": "user@example.com",
        "password": "string",
        "requires2FA": false
    });
    let response = app.signup(&body).await; // Send a POST request to the /signup route
    assert_eq!(response.status().as_u16(), 200); // Assert that the response status code is 200
}

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

#[tokio::test]
async fn logout_returns_200() {
    let app = TestApp::new().await;
    let token = "dummy_token";
    let response = app.logout(token).await;
    assert_eq!(response.status().as_u16(), 200);
}

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

#[tokio::test]
async fn verify_token_returns_200() {
    let app = TestApp::new().await;
    let token = "dummy_token";
    // let body = serde_json::json!({
    //     "token": "string"
    // });
    let response = app.verify_token(token).await;
    assert_eq!(response.status().as_u16(), 200);
}

