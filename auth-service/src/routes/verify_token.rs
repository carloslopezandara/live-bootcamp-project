use axum::{http::StatusCode, response::IntoResponse, Json};
use serde::{Deserialize, Serialize};
use crate::{domain::AuthAPIError, utils::auth::validate_token};

pub async fn verify_token(Json(request): Json<VerifytokenRequest>,) -> Result<impl IntoResponse, AuthAPIError>  { 
    let token = request.token;

    if validate_token(&token).await.is_err() {
        return Err(AuthAPIError::InvalidToken);
    }

    let is_valid = true;
    let response = Json(VerifytokenResponse { valid: is_valid });
    Ok((StatusCode::OK, response))    
}

#[derive(Deserialize)]
pub struct VerifytokenRequest {
    pub token: String,
}

#[derive(Serialize, Deserialize, PartialEq, Debug)]
pub struct VerifytokenResponse {
    pub valid: bool,
}