use auth_service::{utils::constants::JWT_COOKIE_NAME, ErrorResponse};
use reqwest::Url;
use test_macros::auto_cleanup;
use crate::helpers::TestApp;

#[auto_cleanup]
#[tokio::test]
async fn should_return_400_if_jwt_cookie_missing() {
    let mut app = TestApp::new().await;

    let response = app.post_logout().await;
    assert_eq!(response.status().as_u16(), 400);
    assert_eq!(response
        .json::<ErrorResponse>()
        .await
        .expect("Could not deserialize response body to ErrorResponse")
        .error,
        "Missing token".to_owned());
}

#[auto_cleanup]
#[tokio::test]
async fn should_return_401_if_invalid_token() {
    let mut app = TestApp::new().await;

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

#[auto_cleanup]
#[tokio::test]
async fn should_return_200_if_valid_jwt_cookie() {
    let mut app = TestApp::new().await;
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

    // Extract the JWT token from the login response cookies
    let token = login_response
        .cookies()
        .find(|c| c.name() == JWT_COOKIE_NAME)
        .unwrap()
        .value().to_string();

    // Now, log out
    let response = app.post_logout().await;
    assert_eq!(response.status().as_u16(), 200);

    let is_banned = app.banned_token_store.read().await.is_token_banned(&token).await.unwrap();
    assert!(is_banned);
}

#[auto_cleanup]
#[tokio::test]
async fn should_return_400_if_logout_called_twice_in_a_row() {
    let mut app = TestApp::new().await;
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