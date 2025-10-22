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

    async fn is_token_banned(&self, token: &String) -> bool;

    fn as_ref(&self) -> &dyn BannedTokenStore;
}


#[derive(Debug, PartialEq)]
pub enum UserStoreError {
    UserAlreadyExists,
    UserNotFound,
    InvalidCredentials,
    UnexpectedError,
}

#[derive(Debug, PartialEq)]
pub enum BannedTokenStoreError {
    TokenAlreadyExists,
}