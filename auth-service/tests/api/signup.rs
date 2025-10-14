use auth_service::routes::SignupResponse;

use crate::helpers::{get_random_email, TestApp};

#[tokio::test]
async fn should_return_422_if_malformed_input() {
    let app = TestApp::new().await;

    let random_email = get_random_email();

    // TODO: add more malformed input test cases
    let test_cases = [
        serde_json::json!({
            "password": "password123",
            "requires2FA": true
        }),
        serde_json::json!({
            "email": random_email,
            "requires2FA": true
        }),
        serde_json::json!({
            "email": true,
            "password": "short",
            "requires2FA": random_email
        }),
    ];

    for test_case in test_cases.iter() {
        let response = app.post_signup(test_case).await;
        assert_eq!(
            response.status().as_u16(),
            422,
            "Failed for input: {:?}",
            test_case
        );
    }
}


#[tokio::test]
async fn should_return_201_if_valid_input() {
    let app = TestApp::new().await;
    let response = app
        .post_signup(&serde_json::json!({
            "email": get_random_email(),
            "password": "password123",
            "requires2FA": true
        }))
        .await;

    assert_eq!(response.status().as_u16(), 201);

    let expected_response = SignupResponse {
        message: "User created successfully!".to_owned(),
    };

    // Assert that we are getting the correct response body!
    assert_eq!(
        response
            .json::<SignupResponse>()
            .await
            .expect("Could not deserialize response body to UserBody"),
        expected_response
    );
}

#[tokio::test]
async fn should_return_400_if_invalid_input() {
    let app = TestApp::new().await;
    let invalid_mails = [
        serde_json::json!({
            "email": "123carlos.com",
            "password": "password123",
            "requires2FA": true
        }),
        serde_json::json!({
            "email": get_random_email(),
            "password": "short",
            "requires2FA": true
        }),
        serde_json::json!({
            "email": "random_email.es",
            "password": "pass123654",
            "requires2FA": false
        }),
    ];

    for email in invalid_mails.iter() {
        let response = app.post_signup(email).await;
        assert_eq!(
            response.status().as_u16(),
            400,
            "Failed for input: {:?}",
            email
        );
    }
}

#[tokio::test]
async fn should_return_409_if_email_already_exists() {
    let app = TestApp::new().await;
    let random_email = get_random_email();
    let signup_body = serde_json::json!({
        "email": random_email,
        "password": "password123",
        "requires2FA": true
    });
    let first_response = app.post_signup(&signup_body).await;
    assert_eq!(first_response.status().as_u16(), 201);
    
    let second_response = app.post_signup(&signup_body).await;
    assert_eq!(second_response.status().as_u16(), 409);
}