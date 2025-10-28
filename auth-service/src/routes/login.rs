use axum::{extract::State, http::StatusCode, response::IntoResponse, Json};
use axum_extra::extract::CookieJar;
use serde::{Deserialize, Serialize};
use crate::domain::{LoginAttemptId, TwoFACode};

use crate::{
    app_state::AppState, 
    domain::{AuthAPIError,Email, Password},
    utils::auth::generate_auth_cookie,
};

pub async fn login(
    State(state): State<AppState>,
    jar: CookieJar, // New!
    Json(request): Json<LoginRequest>,
) -> (CookieJar, Result<impl IntoResponse, AuthAPIError>) {
    let email = match Email::parse(request.email.clone()) {
        Err(error) => return (jar, Err(error)),
        Ok(email) => email,
    };
    let password = match Password::parse(request.password.clone()){
        Err(error) => return (jar, Err(error)),
        Ok(password) => password,
    };    
    let user_store = state.user_store.read().await;
    
    match user_store.validate_user(&email, &password).await {
        Err(_) => return (jar, Err(AuthAPIError::IncorrectCredentials)),
        Ok(_) => (),
    };

    let user = match user_store.get_user(&email).await {
        Err(_) => return (jar, Err(AuthAPIError::IncorrectCredentials)),
        Ok(user) => user,
    };

    // Handle request based on user's 2FA configuration
    match user.requires_2fa {
        true => handle_2fa(&email,&state,jar).await,
        false => handle_no_2fa(&user.email, jar).await,
    }
}

#[derive(Deserialize)]
pub struct LoginRequest {
    pub email: String,
    pub password: String,
}

// The login route can return 2 possible success responses.
// This enum models each response!
#[derive(Debug, Serialize)]
#[serde(untagged)]
pub enum LoginResponse {
    RegularAuth,
    TwoFactorAuth(TwoFactorAuthResponse),
}

// If a user requires 2FA, this JSON body should be returned!
#[derive(Debug, Serialize, Deserialize)]
pub struct TwoFactorAuthResponse {
    pub message: String,
    #[serde(rename = "loginAttemptId")]
    pub login_attempt_id: String,
}

// New!
async fn handle_2fa(
    email: &Email, // New!
    state: &AppState, // New!
    jar: CookieJar,
) -> (
    CookieJar,
    Result<(StatusCode, Json<LoginResponse>), AuthAPIError>,
) {
    // First, we must generate a new random login attempt ID and 2FA code
    let login_attempt_id = LoginAttemptId::default();
    let two_fa_code = TwoFACode::default();

    // TODO: Store the ID and code in our 2FA code store. Return `AuthAPIError::UnexpectedError` if the operation fails
    let mut two_fa_code_store = state.two_fa_code_store.write().await;
    match two_fa_code_store
        .add_code(email.clone(), login_attempt_id.clone(), two_fa_code.clone())
        .await
    {
        Err(_) => return (jar, Err(AuthAPIError::UnexpectedError)),
        Ok(_) => (),
    };

    // TODO: send 2FA code via the email client. Return `AuthAPIError::UnexpectedError` if the operation fails.
    let email_client = state.email_client.read().await;
    let body = format!("Here is your 2FA code: {}, don't share it with anyone.", two_fa_code.as_ref());
    match email_client.send_email(email, "2FA Code", &body).await {
        Err(_) => return (jar, Err(AuthAPIError::UnexpectedError)),
        Ok(_) => (),
    };

    // Finally, we need to return the login attempt ID to the client
    let response = Json(LoginResponse::TwoFactorAuth(TwoFactorAuthResponse {
        message: "2FA required".to_owned(),
        login_attempt_id: login_attempt_id.as_ref().to_owned(),
    }));

    (jar, Ok((StatusCode::PARTIAL_CONTENT, response)))
}

// New!
async fn handle_no_2fa(
    email: &Email,
    jar: CookieJar,
) -> (
    CookieJar,
    Result<(StatusCode, Json<LoginResponse>), AuthAPIError>,
) {
    let auth_cookie = match generate_auth_cookie(email) {
        Err(_) => return (jar, Err(AuthAPIError::UnexpectedError)),
        Ok(cookie) => cookie,
    };
    let updated_jar = jar.add(auth_cookie);
    (updated_jar, Ok((StatusCode::OK, Json(LoginResponse::RegularAuth))))
}