use color_eyre::eyre::Report;
use rand::Rng;
use thiserror::Error;
use uuid::Uuid;
use crate::domain::{Email, Password};
use super::User;

#[async_trait::async_trait]
pub trait UserStore {

    // TODO: Add the `add_user`, `get_user`, and `validate_user` methods.
    // Make sure all methods are async so we can use async user stores in the future

    async fn add_user(&mut self, user: User) -> Result<(), UserStoreError>;

    async fn get_user(&self, email: &Email) -> Result<User, UserStoreError>;

    async fn validate_user(&self, email: &Email, password: &Password) -> Result<(), UserStoreError>;
}

// Add a BannedTokenStore trait to auth-service/src/domain/data_stores.rs 
// The trait should define one method for storing tokens (as Strings) and another method for checking if a token exists within the banned token store. 
// It's up to you to determine the exact API (input parameters & return values).

#[async_trait::async_trait]
pub trait BannedTokenStore {
    async fn store_token(&mut self, token: String) -> Result<(), BannedTokenStoreError>;

    async fn is_token_banned(&self, token: &String) -> Result<bool, BannedTokenStoreError>;

    fn as_ref(&self) -> &dyn BannedTokenStore;
}

// This trait represents the interface all concrete 2FA code stores should implement
#[async_trait::async_trait]
pub trait TwoFACodeStore {
    async fn add_code(
        &mut self,
        email: Email,
        login_attempt_id: LoginAttemptId,
        code: TwoFACode,
    ) -> Result<(), TwoFACodeStoreError>;

    async fn remove_code(&mut self, email: &Email) -> Result<(), TwoFACodeStoreError>;

    async fn get_code(
        &self,
        email: &Email,
    ) -> Result<(LoginAttemptId, TwoFACode), TwoFACodeStoreError>;
}

#[derive(Debug, PartialEq)]
pub enum TwoFACodeStoreError {
    LoginAttemptIdNotFound,
    UnexpectedError,
}

#[derive(Debug, Clone, PartialEq)]
pub struct LoginAttemptId(String);

impl LoginAttemptId {
    pub fn parse(id: String) -> Result<Self, String> {
        // Use the `parse_str` function from the `uuid` crate to ensure `id` is a valid UUID
        match Uuid::parse_str(&id) {
            Ok(id) => Ok(LoginAttemptId(id.to_string())),
            Err(_) => Err("Invalid LoginAttemptId format".to_owned()),
        }
    }
}

impl Default for LoginAttemptId {
    fn default() -> Self {
        // Use the `uuid` crate to generate a random version 4 UUID
        LoginAttemptId(Uuid::new_v4().to_string())
    }
}

impl AsRef<str> for LoginAttemptId {
    fn as_ref(&self) -> &str {
        &self.0
    }
}

#[derive(Clone, Debug, PartialEq)]
pub struct TwoFACode(String);

impl TwoFACode {
    pub fn parse(code: String) -> Result<Self, String> {
        // Ensure `code` is a valid 6-digit code
        match code.len() {
            6 if code.chars().all(|c| c.is_digit(10)) => Ok(TwoFACode(code)),
            _ => Err("Invalid TwoFACode format".to_owned()),
        }
    }
}

impl Default for TwoFACode {
    fn default() -> Self {
        // Use the `rand` crate to generate a random 2FA code.
        // The code should be 6 digits (ex: 834629)
        let mut rng = rand::thread_rng();
        let code: String = (0..6)
            .map(|_| rng.gen_range(0..10).to_string())
            .collect();
        TwoFACode(code)
    }
}

impl AsRef<str> for TwoFACode {
    fn as_ref(&self) -> &str {
        &self.0
    }
}

#[derive(Debug, Error)]
pub enum UserStoreError {
    #[error("User already exists")]
    UserAlreadyExists,
    #[error("User not found")]
    UserNotFound,
    #[error("Invalid credentials")]
    InvalidCredentials,
    #[error("Unexpected error")]
    UnexpectedError(#[source] Report),
}

impl PartialEq for UserStoreError {
    fn eq(&self, other: &Self) -> bool {
        matches!(
            (self, other),
            (Self::UserAlreadyExists, Self::UserAlreadyExists)
                | (Self::UserNotFound, Self::UserNotFound)
                | (Self::InvalidCredentials, Self::InvalidCredentials)
                | (Self::UnexpectedError(_), Self::UnexpectedError(_))
        )
    }
}

#[derive(Debug, PartialEq)]
pub enum BannedTokenStoreError {
    TokenAlreadyExists,
    UnexpectedError,
}

