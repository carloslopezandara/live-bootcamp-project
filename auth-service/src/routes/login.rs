use axum::{extract::State, http::StatusCode, response::IntoResponse, Json};
use axum_extra::extract::CookieJar;
use serde::{Deserialize, Serialize};

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

    let _user = match user_store.get_user(&email).await {
        Err(_) => return (jar, Err(AuthAPIError::IncorrectCredentials)),
        Ok(user) => user,
    };

    let auth_cookie = match generate_auth_cookie(&email) {
        Err(_) => return (jar, Err(AuthAPIError::UnexpectedError)),
        Ok(cookie) => cookie,
    };
    let updated_jar = jar.add(auth_cookie);
    (updated_jar, Ok(StatusCode::OK.into_response()))
}

#[derive(Deserialize)]
pub struct LoginRequest {
    pub email: String,
    pub password: String,
}

#[derive(Serialize, Deserialize, PartialEq, Debug)]
pub struct LoginResponse {
    pub message: String,
    #[serde(rename = "loginAttempID")]
    pub login_attemp_id: String,
}

