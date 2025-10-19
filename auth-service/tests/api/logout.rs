use auth_service::{utils::constants::JWT_COOKIE_NAME, ErrorResponse};
use axum::response;
use axum_extra::extract::cookie;
use reqwest::Url;

use crate::helpers::TestApp;

#[tokio::test]
async fn should_return_400_if_jwt_cookie_missing() {
    let app = TestApp::new().await;

    let response = app.post_logout().await;
    assert_eq!(response.status().as_u16(), 400);
}

#[tokio::test]
async fn should_return_401_if_invalid_token() {
    let app = TestApp::new().await;

    // add invalid cookie
    app.cookie_jar.add_cookie_str(
        &format!(
            "{}=invalid; HttpOnly; SameSite=Lax; Secure; Path=/",
            JWT_COOKIE_NAME
        ),
        &Url::parse("http://127.0.0.1").expect("Failed to parse URL"),
    );

    let response = app.post_logout().await;
    assert_eq!(response.status().as_u16(), 401);
}


#[tokio::test]
async fn should_return_200_if_valid_jwt_cookie() {
    let app = TestApp::new().await;
    // First, sign up a new user
    let signup_body = serde_json::json!({
        "email": "user@example.com",
        "password": "securepassword",
        "requires2FA": false
    });
    let signup_response = app.post_signup(&signup_body).await;
    assert_eq!(signup_response.status().as_u16(), 201);
    // Then, log in to get the JWT cookie
    let login_body = serde_json::json!({
        "email": "user@example.com",
        "password": "securepassword"
    });
    let login_response = app.post_login(&login_body).await;
    assert_eq!(login_response.status().as_u16(), 200);

    // Now, log out using the JWT cookie
    let response = app.post_logout().await;
    assert_eq!(response.status().as_u16(), 200);
}

#[tokio::test]
async fn should_return_400_if_logout_called_twice_in_a_row() {
    let app = TestApp::new().await;
    // First, sign up a new user
    let signup_body = serde_json::json!({
        "email": "user2@gmail.com",
        "password": "securepassword",
        "requires2FA": false
    });
    let signup_response = app.post_signup(&signup_body).await;
    assert_eq!(signup_response.status().as_u16(), 201);
    // Then, log in to get the JWT cookie
    let login_body = serde_json::json!({
        "email": "user2@gmail.com",
        "password": "securepassword"
    });
    let login_response = app.post_login(&login_body).await;
    assert_eq!(login_response.status().as_u16(), 200);

    // Now, log out using the JWT cookie
    let response = app.post_logout().await;
    assert_eq!(response.status().as_u16(), 200);
    // Try to log out again with the same cookie
    let response = app.post_logout().await;
    assert_eq!(response.status().as_u16(), 400);
}