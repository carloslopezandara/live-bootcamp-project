use crate::helpers::TestApp;
use serde_json;

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
