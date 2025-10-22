use auth_service::{utils::constants::JWT_COOKIE_NAME, ErrorResponse};
use crate::helpers::{get_random_email, TestApp};

#[tokio::test]
async fn should_return_422_if_malformed_input() {
    let app = TestApp::new().await;
    let response = app
        .post_verify_token(&serde_json::json!({
            "invalid_field": "some_value"
        }))
        .await;
    assert_eq!(response.status(), 422);
}

#[tokio::test]
async fn should_return_200_valid_token() {
    let app = TestApp::new().await;
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

    // Extract the JWT cookie from the login response
    let jwt_cookie = response
        .cookies()
        .find(|cookie| cookie.name() == JWT_COOKIE_NAME)
        .expect("JWT cookie not found in login response");
    let token = jwt_cookie.value().to_string();
    let response = app
        .post_verify_token(&serde_json::json!({
            "token": token
        }))
        .await;
    assert_eq!(response.status().as_u16(), 200);
}

#[tokio::test]
async fn should_return_401_if_invalid_token() {
    let app = TestApp::new().await;
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

    let response = app
        .post_verify_token(&serde_json::json!({
            "token": "invalid_token"
        }))
        .await;
    assert_eq!(response.status().as_u16(), 401);
    assert_eq!(response
        .json::<ErrorResponse>()
        .await
        .expect("Could not deserialize response body to ErrorResponse")
        .error,
        "Invalid token".to_owned())
}

#[tokio::test]
async fn should_return_401_if_banned_token() {
    let app = TestApp::new().await;
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

    // Extract the JWT cookie from the login response
    let jwt_cookie = response
        .cookies()
        .find(|cookie| cookie.name() == JWT_COOKIE_NAME)
        .expect("JWT cookie not found in login response");
    let token = jwt_cookie.value().to_string();

    // Log out to ban the token
    let response = app.post_logout().await;
    assert_eq!(response.status().as_u16(), 200);

    // Now, verify the banned token
    let response = app
        .post_verify_token(&serde_json::json!({
            "token": token
        }))
        .await;
    assert_eq!(response.status().as_u16(), 401);
    assert_eq!(response
        .json::<ErrorResponse>()
        .await
        .expect("Could not deserialize response body to ErrorResponse")
        .error,
        "Invalid token".to_owned())
}