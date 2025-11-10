use axum::{extract::State, http::StatusCode, response::IntoResponse};
use axum_extra::extract::CookieJar;
use secrecy::Secret;

use crate::{
    app_state::{AppState}, 
    domain::{AuthAPIError},
    utils::{auth::validate_token, constants::JWT_COOKIE_NAME},
};

#[tracing::instrument(name = "Logout endpoint", skip_all)]
pub async fn logout(
    State(state): State<AppState>,
    jar: CookieJar) -> (CookieJar, Result<impl IntoResponse, AuthAPIError>) {
    // Retrieve JWT cookie from the `CookieJar`
    // Return AuthAPIError::MissingToken is the cookie is not found

    let cookie = match jar.get(JWT_COOKIE_NAME) {
        Some(cookie) => cookie,
        None => return (jar, Err(AuthAPIError::MissingToken)),
    };

    let token = cookie.value().to_string();

    match validate_token(&token, state.banned_token_store.clone()).await {
        Ok(_claims) => (),
        Err(_) => return (jar, Err(AuthAPIError::InvalidToken)),
    }
    
    // Store the token in the banned token store    
    let mut banned_token_store = state.banned_token_store.write().await;
    match banned_token_store.store_token(Secret::new(token)).await {
        Ok(_) => (),
        Err(e) => return (jar, Err(AuthAPIError::UnexpectedError(e.into()))),
    }    

    let jar = jar.remove(JWT_COOKIE_NAME);    

    (jar, Ok(StatusCode::OK))
}