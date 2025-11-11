use crate::helpers::{get_random_email, TestApp};
use auth_service::{ErrorResponse};
use secrecy::{Secret, ExposeSecret};
use serde_json;
use auth_service::{
    domain::{Email},
    routes::TwoFactorAuthResponse,
};
use test_macros::auto_cleanup;
use wiremock::{Mock, ResponseTemplate, matchers::{method, path}};

#[auto_cleanup]
#[tokio::test]
async fn should_return_422_if_malformed_credentials() {
    let mut app = TestApp::new().await;
    let body = serde_json::json!({
        "mail": "not-an-email",
        "pass": "string123"
    });
    let response = app.post_login(&body).await;
    assert_eq!(response.status().as_u16(), 422);
}

#[auto_cleanup]
#[tokio::test]
async fn should_return_400_if_invalid_input() {
    let mut app = TestApp::new().await;
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

#[auto_cleanup]
#[tokio::test]
async fn should_return_401_if_incorrect_credentials() {
    // Call the log-in route with incorrect credentials and assert
    // that a 401 HTTP status code is returned along with the appropriate error message.     
    let mut app = TestApp::new().await;
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

#[auto_cleanup]
#[tokio::test]
async fn should_return_200_if_valid_credentials_and_2fa_disabled() {
    let mut app = TestApp::new().await;

    let random_email = get_random_email();

    let signup_body = serde_json::json!({
        "email": random_email,
        "password": "password123",
        "requires2FA": false
    });

    let response = app.post_signup(&signup_body).await;

    assert_eq!(response.status().as_u16(), 201);

    let login_body = serde_json::json!({
        "email": random_email,
        "password": "password123",
    });

    let response = app.post_login(&login_body).await;

    assert_eq!(response.status().as_u16(), 200);
}

#[auto_cleanup]
#[tokio::test]
async fn should_return_206_if_valid_credentials_and_2fa_enabled() {
    let mut app = TestApp::new().await;

    let random_email = Email::parse(Secret::new(get_random_email())).unwrap();

    let signup_body = serde_json::json!({
        "email": random_email.as_ref().expose_secret(),
        "password": "password123",
        "requires2FA": true
    });

    let response = app.post_signup(&signup_body).await;

    assert_eq!(response.status().as_u16(), 201);

    // Define an expectation for the mock server
    Mock::given(path("/email")) // Expect an HTTP request to the "/email" path
        .and(method("POST")) // Expect the HTTP method to be POST
        .respond_with(ResponseTemplate::new(200)) // Respond with an HTTP 200 OK status
        .expect(1) // Expect this request to be made exactly once
        .mount(&app.email_server) // Mount this expectation on the mock email server
        .await; // Await the asynchronous operation to ensure the mock server is set up before proceeding

    let login_body = serde_json::json!({
        "email": random_email.as_ref().expose_secret(),
        "password": "password123",
    });

    let response = app.post_login(&login_body).await;

    assert_eq!(response.status().as_u16(), 206);

    let json_body = response
        .json::<TwoFactorAuthResponse>()
        .await
        .expect("Could not deserialize response body to TwoFactorAuthResponse");

    assert_eq!(json_body.message, "2FA required".to_owned());

    let (login_attempt_id, _) = app.two_fa_code_store.read().await.get_code(&random_email).await.unwrap();
    assert_eq!(login_attempt_id.as_ref().expose_secret(), &json_body.login_attempt_id);
}
