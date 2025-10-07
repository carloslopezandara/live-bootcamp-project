use axum::{response::IntoResponse,http::StatusCode};

pub async fn post_signup() -> impl IntoResponse {
    StatusCode::OK.into_response()
}