use std::sync::Arc;

use redis::{Commands, Connection};
use tokio::sync::RwLock;

use crate::{
    domain::{BannedTokenStore, BannedTokenStoreError},
    utils::auth::TOKEN_TTL_SECONDS,
};

pub struct RedisBannedTokenStore {
    conn: Arc<RwLock<Connection>>,
}

impl RedisBannedTokenStore {
    pub fn new(conn: Arc<RwLock<Connection>>) -> Self {
        Self { conn }
    }
}

#[async_trait::async_trait]
impl BannedTokenStore for RedisBannedTokenStore {
    async fn store_token(&mut self, token: String) -> Result<(), BannedTokenStoreError> {
        let key = get_key(&token);
        let mut conn = self.conn.write().await;
        let ttl: u64 = TOKEN_TTL_SECONDS.try_into().map_err(|_| BannedTokenStoreError::UnexpectedError)?;
        let result: Result<(), redis::RedisError> = conn.set_ex(key, true, ttl);
        match result {
            Ok(_) => Ok(()),
            Err(_) => Err(BannedTokenStoreError::UnexpectedError),
        }
    }

    async fn is_token_banned(&self, token: &String) -> Result<bool, BannedTokenStoreError> {
        // Check if the token exists by calling the exists method on the Redis connection
        let key = get_key(token);
        let mut conn = self.conn.write().await;
        let result: Result<bool, redis::RedisError> = conn.exists(key);
        match result {
            Ok(exists) => Ok(exists),
            Err(_) => Err(BannedTokenStoreError::UnexpectedError),
        }
    }

    fn as_ref(&self) -> &dyn BannedTokenStore {
        self
    }
}

// We are using a key prefix to prevent collisions and organize data!
const BANNED_TOKEN_KEY_PREFIX: &str = "banned_token:";

fn get_key(token: &str) -> String {
    format!("{}{}", BANNED_TOKEN_KEY_PREFIX, token)
}