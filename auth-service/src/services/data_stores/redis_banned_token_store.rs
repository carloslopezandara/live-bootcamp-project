use std::sync::Arc;
use color_eyre::eyre::{Context, Result};
use redis::{Commands, Connection};
use secrecy::{ExposeSecret, Secret};
use tokio::sync::RwLock;

use crate::{
    domain::{BannedTokenStore, BannedTokenStoreError},
    utils::auth::TOKEN_TTL_SECONDS,
};

pub struct RedisBannedTokenStore {
    conn: Arc<RwLock<Connection>>,
}

impl RedisBannedTokenStore {
    #[tracing::instrument(name = "Creating Redis banned token store", skip_all)]
    pub fn new(conn: Arc<RwLock<Connection>>) -> Self {
        Self { conn }
    }
}

#[async_trait::async_trait]
impl BannedTokenStore for RedisBannedTokenStore {

    #[tracing::instrument(name = "Storing banned token", skip_all)]
    async fn store_token(&mut self, token: Secret<String>) -> Result<(), BannedTokenStoreError> {
        let key = get_key(token.expose_secret());

        let ttl: u64 = TOKEN_TTL_SECONDS
            .try_into()
            .wrap_err("failed to cast TOKEN_TTL_SECONDS to u64") // New!
            .map_err(BannedTokenStoreError::UnexpectedError)?; // Updated!

        let _: () = self
            .conn
            .write()
            .await
            .set_ex(&key, true, ttl)
            .wrap_err("failed to set banned token in Redis") // New!
            .map_err(BannedTokenStoreError::UnexpectedError)?; // Updated!

        Ok(())
    }

    #[tracing::instrument(name = "Checking if token is banned", skip_all)]
    async fn is_token_banned(&self, token: &Secret<String>) -> Result<bool, BannedTokenStoreError> {        
        // Check if the token exists by calling the exists method on the Redis connection
        let key = get_key(token.expose_secret());
        
        let is_banned: bool = self
            .conn
            .write()
            .await
            .exists(&key)
            .wrap_err("failed to check if token exists in Redis") // New!
            .map_err(BannedTokenStoreError::UnexpectedError)?; // Updated!

        Ok(is_banned)
    }

    fn as_ref(&self) -> &dyn BannedTokenStore {
        self
    }
}

// We are using a key prefix to prevent collisions and organize data!
const BANNED_TOKEN_KEY_PREFIX: &str = "banned_token:";

#[tracing::instrument(name = "Generating banned token key", skip_all)]
fn get_key(token: &str) -> String {
    format!("{}{}", BANNED_TOKEN_KEY_PREFIX, token)
}