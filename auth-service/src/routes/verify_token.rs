use axum::{extract::State, http::StatusCode, response::IntoResponse, Json};
use serde::{Deserialize, Serialize};
use crate::{app_state::AppState, domain::AuthAPIError, utils::auth::validate_token};

#[tracing::instrument(name = "Verify token endpoint", skip_all)]
pub async fn verify_token(
    State(state): State<AppState>,
    Json(request): Json<VerifytokenRequest>,) -> Result<impl IntoResponse, AuthAPIError>  { 
    let token = request.token;

    // Check token validity and treat authentication failures as InvalidToken
    match validate_token(&token, state.banned_token_store.clone()).await {
        Ok(_claims) => {
            let response = Json(VerifytokenResponse { valid: true });
            Ok((StatusCode::OK, response))
        },
        Err(_) => {
            // Token is invalid, expired, or banned - return InvalidToken
            Err(AuthAPIError::InvalidToken)
        }
    }
}

#[derive(Deserialize)]
pub struct VerifytokenRequest {
    pub token: String,
}

#[derive(Serialize, Deserialize, PartialEq, Debug)]
pub struct VerifytokenResponse {
    pub valid: bool,
}