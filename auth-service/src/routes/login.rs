use axum::{extract::State, http::StatusCode, response::IntoResponse, Json};
use serde::{Deserialize, Serialize};
use uuid::Uuid;
use crate::{app_state::AppState, domain::{AuthAPIError,Email, Password}};

pub async fn login(
    State(state): State<AppState>,
    Json(request): Json<LoginRequest>,
) -> Result<impl IntoResponse, AuthAPIError>  { 
    let email = Email::parse(request.email.clone())?;
    let password = Password::parse(request.password.clone())?;
    let user_store = state.user_store.read().await;

    match user_store.get_user(&email).await {
        Ok(_) => {
            match user_store.validate_user(&email, &password).await {
                Ok(_) => {
                    let response = Json(LoginResponse {
                        message: "Login successful".to_string(),
                        login_attemp_id: Uuid::new_v4().to_string(),
                    });
                    Ok((StatusCode::OK, response))
                },
                Err(_) => Err(AuthAPIError::IncorrectCredentials),
            }
        },
        Err(_) => Err(AuthAPIError::IncorrectCredentials),
    }

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

