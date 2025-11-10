use axum::{extract::State, http::StatusCode, response::IntoResponse, Json};
use axum_extra::extract::CookieJar;
use serde::Deserialize;
use crate::{app_state::AppState, domain::{AuthAPIError, Email, LoginAttemptId, TwoFACode}, utils::auth::generate_auth_cookie};

#[tracing::instrument(name = "Verify 2FA endpoint", skip_all)]
pub async fn verify_2fa(
    State(state): State<AppState>, // New!
    jar: CookieJar, // New!
    Json(request): Json<Verify2FARequest>,
) -> (CookieJar, Result<impl IntoResponse, AuthAPIError>) {
    let email = match Email::parse(request.email.clone()) {
        Err(_) => return (jar, Err(AuthAPIError::InvalidCredentials)),
        Ok(email) => email,
    };

    let login_attempt_id = match LoginAttemptId::parse(request.login_attempt_id) {
        Err(_) => return (jar, Err(AuthAPIError::InvalidCredentials)),
        Ok(id) => id,
    };

    let two_fa_code = match TwoFACode::parse(request.two_fa_code) {
        Err(_) => return (jar, Err(AuthAPIError::InvalidCredentials)),
        Ok(code) => code,
    };

    let mut two_fa_code_store = state.two_fa_code_store.write().await;

    let code_tuple = match two_fa_code_store.get_code(&email).await {
        Err(_) => return (jar, Err(AuthAPIError::IncorrectCredentials)),
        Ok(code_tuple) => code_tuple,
    };

    if code_tuple.0 != login_attempt_id || code_tuple.1 != two_fa_code {
        return (jar, Err(AuthAPIError::IncorrectCredentials));
    }

    match two_fa_code_store.remove_code(&email).await {
        Err(_) => return (jar, Err(AuthAPIError::IncorrectCredentials)),
        Ok(_) => (),
    };  

    create_jwt_cookie(&email, jar).await
}

#[derive(Deserialize)]
pub struct Verify2FARequest {
    email: String,
    #[serde(rename = "loginAttemptId")]
    pub login_attempt_id: String,
    #[serde(rename = "2FACode")]
    pub two_fa_code: String,
}

#[tracing::instrument(name = "Create JWT cookie", skip_all)]
async fn create_jwt_cookie(
    email: &Email,
    jar: CookieJar,
) -> (
    CookieJar,
    Result<impl IntoResponse, AuthAPIError>,
) {
    let auth_cookie = match generate_auth_cookie(email) {
        Err(e) => return (jar, Err(AuthAPIError::UnexpectedError(e))),
        Ok(cookie) => cookie,
    };
    let updated_jar = jar.add(auth_cookie);
    (updated_jar, Ok(StatusCode::OK.into_response()))
}