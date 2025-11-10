use color_eyre::eyre::{eyre, Context, Report, Result};
use rand::Rng;
use secrecy::Secret;
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
    async fn store_token(&mut self, token: Secret<String>) -> Result<(), BannedTokenStoreError>;

    async fn is_token_banned(&self, token: &Secret<String>) -> Result<bool, BannedTokenStoreError>;

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

// Updated!
#[derive(Debug, Error)]
pub enum TwoFACodeStoreError {
    #[error("Login Attempt ID not found")]
    LoginAttemptIdNotFound,
    #[error("Unexpected error")]
    UnexpectedError(#[source] Report),
}

// New!
impl PartialEq for TwoFACodeStoreError {
    fn eq(&self, other: &Self) -> bool {
        matches!(
            (self, other),
            (Self::LoginAttemptIdNotFound, Self::LoginAttemptIdNotFound)
                | (Self::UnexpectedError(_), Self::UnexpectedError(_))
        )
    }
}

#[derive(Debug, Clone)]
pub struct LoginAttemptId(Secret<String>);

impl LoginAttemptId {
    pub fn parse(id: String) -> Result<Self> { // Updated!
        let parsed_id = uuid::Uuid::parse_str(&id).wrap_err("Invalid login attempt id")?; // Updated!
        Ok(Self(Secret::new(parsed_id.to_string())))
    }
}

impl Default for LoginAttemptId {
    fn default() -> Self {
        // Use the `uuid` crate to generate a random version 4 UUID
        LoginAttemptId(Secret::new(Uuid::new_v4().to_string()))
    }
}

impl AsRef<Secret<String>> for LoginAttemptId {
    fn as_ref(&self) -> &Secret<String> {
        &self.0
    }
}

#[derive(Clone, Debug)]
pub struct TwoFACode(Secret<String>);

impl TwoFACode {
    pub fn parse(code: String) -> Result<Self> { // Updated!
        let code_as_u32 = code.parse::<u32>().wrap_err("Invalid 2FA code")?; // Updated!

        if (100_000..=999_999).contains(&code_as_u32) {
            Ok(Self(Secret::new(code)))
        } else {
            Err(eyre!("Invalid 2FA code")) // Updated!
        }
    }
}

impl Default for TwoFACode {
    fn default() -> Self {
        // Use the `rand` crate to generate a random 2FA code.
        // The code should be 6 digits (ex: 834629)
        let mut rng = rand::thread_rng();
        // Generate a number between 100000 and 999999 to ensure valid 2FA code
        let code = rng.gen_range(100_000..=999_999).to_string();
        TwoFACode(Secret::new(code))
    }
}

impl AsRef<Secret<String>> for TwoFACode {
    fn as_ref(&self) -> &Secret<String> {
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

#[derive(Debug, Error)]
pub enum BannedTokenStoreError {
    #[error("Unexpected error")]
    UnexpectedError(#[source] Report),
}
