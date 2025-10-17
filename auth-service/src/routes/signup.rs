use axum::{extract::State, http::StatusCode, response::IntoResponse, Json};
use serde::{Deserialize, Serialize};
use crate::{app_state::AppState, domain::{AuthAPIError,User}};
use crate::domain::{Email, Password};

pub async fn signup(
    State(state): State<AppState>,
    Json(request): Json<SignupRequest>,
) -> Result<impl IntoResponse, AuthAPIError> {
    let email = request.email;
    let password = request.password;

    // Update signup route to replace validation logic with calls to Email::parse and Password::parse

    let email = Email::parse(email.clone())?;
    let password = Password::parse(password.clone())?;

    let user = User::new(email, password, request.requires_2fa);

    let mut user_store = state.user_store.write().await;

    if let Ok(_) = user_store.get_user(&user.email).await {
        return Err(AuthAPIError::UserAlreadyExists);
    }

    if let Err(e) = user_store.add_user(user.clone()).await {
        println!("Error adding user: {:?}", e);
        return Err(AuthAPIError::UnexpectedError);
    }

    let response = Json(SignupResponse {
        message: "User created successfully!".to_string(),
    });

    Ok((StatusCode::CREATED, response))
}

#[derive(Deserialize)]
pub struct SignupRequest {
    pub email: String,
    pub password: String,
    #[serde(rename = "requires2FA")]
    pub requires_2fa: bool,
}

#[derive(Serialize, Deserialize, PartialEq, Debug)]
pub struct SignupResponse {
    pub message: String,
}