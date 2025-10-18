use crate::helpers::TestApp;
use auth_service::ErrorResponse;
use serde_json;

#[tokio::test]
async fn should_return_422_if_malformed_credentials() {
    let app = TestApp::new().await;
    let body = serde_json::json!({
        "mail": "not-an-email",
        "pass": "string123"
    });
    let response = app.post_login(&body).await;
    assert_eq!(response.status().as_u16(), 422);
}

#[tokio::test]
async fn should_return_400_if_invalid_input() {
    let app = TestApp::new().await;
    let body = serde_json::json!({
        "email": "not-an-email",
        "password": "string123"
    });
    let response = app.post_login(&body).await;
    assert_eq!(response.status().as_u16(), 400);
    assert_eq!(response
        .json::<ErrorResponse>()
        .await
        .expect("Could not deserialize response body to ErrorResponse")
        .error,
        "Invalid credentials".to_owned())
    ;
}

#[tokio::test]
async fn should_return_401_if_incorrect_credentials() {
    // Call the log-in route with incorrect credentials and assert
    // that a 401 HTTP status code is returned along with the appropriate error message.     
    let app = TestApp::new().await;
    let body = serde_json::json!({
        "email": "validmail@gmail.com",
        "password": "rightpassword"
    });
    let response = app.post_login(&body).await;
    assert_eq!(response.status().as_u16(), 401);
    assert_eq!(response
        .json::<ErrorResponse>()
        .await
        .expect("Could not deserialize response body to ErrorResponse")
        .error,
        "Incorrect credentials".to_owned())
    ;
}