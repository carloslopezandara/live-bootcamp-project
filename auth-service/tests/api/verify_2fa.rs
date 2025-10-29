use auth_service::{domain::{Email}, routes::TwoFactorAuthResponse, utils::constants::JWT_COOKIE_NAME,};
use crate::helpers::{get_random_email, TestApp};

#[tokio::test]
async fn should_return_422_if_malformed_input() {
    let app = TestApp::new().await;

    let random_email = Email::parse(get_random_email()).unwrap();

    let signup_body = serde_json::json!({
        "email": random_email.as_ref(),
        "password": "password123",
        "requires2FA": true
    });

    let response = app.post_signup(&signup_body).await;

    assert_eq!(response.status().as_u16(), 201);

    let login_body = serde_json::json!({
        "email": random_email.as_ref(),
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
    assert_eq!(login_attempt_id.as_ref(), json_body.login_attempt_id);

    let verify_2fa_body = serde_json::json!({
        "email": random_email.as_ref(),
        "loginAttemptId": json_body.login_attempt_id,
        "code": "invalid_code"
    });
    let response = app.post_verify_2fa(&verify_2fa_body).await;
    assert_eq!(response.status().as_u16(), 422);
}

#[tokio::test]
async fn should_return_400_if_invalid_input() {
    let app = TestApp::new().await;
    
    let random_email = Email::parse(get_random_email()).unwrap();

    let signup_body = serde_json::json!({
        "email": random_email.as_ref(),
        "password": "password123",
        "requires2FA": true
    });

    let response = app.post_signup(&signup_body).await;

    assert_eq!(response.status().as_u16(), 201);

    let login_body = serde_json::json!({
        "email": random_email.as_ref(),
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
    assert_eq!(login_attempt_id.as_ref(), json_body.login_attempt_id);

    let verify_2fa_body = serde_json::json!({
        "email": random_email.as_ref(),
        "loginAttemptId": login_attempt_id.as_ref(),
        "2FACode": "InvalidCode123"
    });

    let response = app.post_verify_2fa(&verify_2fa_body).await;
    assert_eq!(response.status().as_u16(), 400);
}

#[tokio::test]
async fn should_return_401_if_incorrect_credentials() {
    let app = TestApp::new().await;
    // Call verify_2fa with an email/loginAttemptId/2FACode combo that doesn't exist in the store. This should return a 401.
    
    let random_email = Email::parse(get_random_email()).unwrap();

    let signup_body = serde_json::json!({
        "email": random_email.as_ref(),
        "password": "password123",
        "requires2FA": true
    });

    let response = app.post_signup(&signup_body).await;

    assert_eq!(response.status().as_u16(), 201);

    let login_body = serde_json::json!({
        "email": random_email.as_ref(),
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
    assert_eq!(login_attempt_id.as_ref(), json_body.login_attempt_id);

    let verify_2fa_body = serde_json::json!({
        "email": random_email.as_ref(),
        "loginAttemptId": login_attempt_id.as_ref(),
        "2FACode": "123456"
    });

    let response = app.post_verify_2fa(&verify_2fa_body).await;
    assert_eq!(response.status().as_u16(), 401);
}

#[tokio::test]
async fn should_return_401_if_old_code() {
    // Call login twice. Then, attempt to call verify-fa with the 2FA code from the first login requet. This should fail. 
    let app = TestApp::new().await;
    
    let random_email = Email::parse(get_random_email()).unwrap();

    let signup_body = serde_json::json!({
        "email": random_email.as_ref(),
        "password": "password123",
        "requires2FA": true
    });

    let response = app.post_signup(&signup_body).await;

    assert_eq!(response.status().as_u16(), 201);

    let login_body = serde_json::json!({
        "email": random_email.as_ref(),
        "password": "password123",
    });

    let response = app.post_login(&login_body).await;

    assert_eq!(response.status().as_u16(), 206);

    let json_body = response
        .json::<TwoFactorAuthResponse>()
        .await
        .expect("Could not deserialize response body to TwoFactorAuthResponse");

    assert_eq!(json_body.message, "2FA required".to_owned());

    let (login_attempt_id, two_fa_code) = app.two_fa_code_store.read().await.get_code(&random_email).await.unwrap();
    assert_eq!(login_attempt_id.as_ref(), json_body.login_attempt_id);

    let verify_2fa_body = serde_json::json!({
        "email": random_email.as_ref(),
        "loginAttemptId": login_attempt_id.as_ref(),
        "2FACode": two_fa_code.as_ref()
    });

    let response = app.post_verify_2fa(&verify_2fa_body).await;
    assert_eq!(response.status().as_u16(), 200);

    let verify_2fa_body = serde_json::json!({
        "email": random_email.as_ref(),
        "loginAttemptId": login_attempt_id.as_ref(),
        "2FACode": "123456"
    });

    let response = app.post_verify_2fa(&verify_2fa_body).await;
    assert_eq!(response.status().as_u16(), 401);
}

#[tokio::test]
async fn should_return_200_if_correct_code() {
    let app = TestApp::new().await;
    let random_email = Email::parse(get_random_email()).unwrap();
    let signup_body = serde_json::json!({
        "email": random_email.as_ref(),
        "password": "password123",
        "requires2FA": true
    });
    let response = app.post_signup(&signup_body).await;
    assert_eq!(response.status().as_u16(), 201);
    let login_body = serde_json::json!({
        "email": random_email.as_ref(),
        "password": "password123",
    });
    let response = app.post_login(&login_body).await;
    assert_eq!(response.status().as_u16(), 206);
    let json_body = response
        .json::<TwoFactorAuthResponse>()
        .await
        .expect("Could not deserialize response body to TwoFactorAuthResponse");
    assert_eq!(json_body.message, "2FA required".to_owned());
    let (login_attempt_id, two_fa_code) = app.two_fa_code_store.read().await.get_code(&random_email).await.unwrap();
    assert_eq!(login_attempt_id.as_ref(), json_body.login_attempt_id);
    let verify_2fa_body = serde_json::json!({
        "email": random_email.as_ref(),
        "loginAttemptId": login_attempt_id.as_ref(),
        "2FACode": two_fa_code.as_ref()
    });
    let response = app.post_verify_2fa(&verify_2fa_body).await;
    assert_eq!(response.status().as_u16(), 200);

    // Make sure to assert the auth cookie gets set
    let cookies = response
        .cookies()
        .find(|c| c.name() == JWT_COOKIE_NAME)
        .unwrap()
        .value().to_string();
    assert!(!cookies.is_empty());
}

#[tokio::test]
async fn should_return_401_if_same_code_twice() {    
    let app = TestApp::new().await;
    let random_email = Email::parse(get_random_email()).unwrap();
    let signup_body = serde_json::json!({
        "email": random_email.as_ref(),
        "password": "password123",
        "requires2FA": true
    });
    let response = app.post_signup(&signup_body).await;
    assert_eq!(response.status().as_u16(), 201);
    let login_body = serde_json::json!({
        "email": random_email.as_ref(),
        "password": "password123",
    });
    let response = app.post_login(&login_body).await;
    assert_eq!(response.status().as_u16(), 206);
    let json_body = response
        .json::<TwoFactorAuthResponse>()
        .await
        .expect("Could not deserialize response body to TwoFactorAuthResponse");
    assert_eq!(json_body.message, "2FA required".to_owned());
    let (login_attempt_id, two_fa_code) = app.two_fa_code_store.read().await.get_code(&random_email).await.unwrap();
    assert_eq!(login_attempt_id.as_ref(), json_body.login_attempt_id);
    let verify_2fa_body = serde_json::json!({
        "email": random_email.as_ref(),
        "loginAttemptId": login_attempt_id.as_ref(),
        "2FACode": two_fa_code.as_ref()
    });
    let response = app.post_verify_2fa(&verify_2fa_body).await;
    assert_eq!(response.status().as_u16(), 200);
    let response = app.post_verify_2fa(&verify_2fa_body).await;
    assert_eq!(response.status().as_u16(), 401);
}