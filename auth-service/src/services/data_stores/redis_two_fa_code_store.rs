use std::sync::Arc;
use color_eyre::eyre::Context;
use redis::{Commands, Connection};
use serde::{Deserialize, Serialize};
use tokio::sync::RwLock;

use crate::domain::{LoginAttemptId, TwoFACode, TwoFACodeStore, TwoFACodeStoreError,Email,};

pub struct RedisTwoFACodeStore {
    conn: Arc<RwLock<Connection>>,
}

impl RedisTwoFACodeStore {
    #[tracing::instrument(name = "Creating Redis 2FA code store", skip_all)]
    pub fn new(conn: Arc<RwLock<Connection>>) -> Self {
        Self { conn }
    }
}

#[async_trait::async_trait]
impl TwoFACodeStore for RedisTwoFACodeStore {
    #[tracing::instrument(name = "Adding 2FA code", skip_all)]
    async fn add_code(
        &mut self,
        email: Email,
        login_attempt_id: LoginAttemptId,
        code: TwoFACode,
    ) -> Result<(), TwoFACodeStoreError> {
        let key = get_key(&email);
        let tuple = TwoFATuple(login_attempt_id.as_ref().to_string(), code.as_ref().to_string());
        let serialized_tuple = serde_json::to_string(&tuple)
            .wrap_err("failed to serialize 2FA tuple") // New!
            .map_err(TwoFACodeStoreError::UnexpectedError)?;

        let _: () = self
            .conn
            .write()
            .await
            .set_ex(&key, serialized_tuple, TEN_MINUTES_IN_SECONDS)
            .wrap_err("failed to set 2FA code in Redis") // New! 
            .map_err(TwoFACodeStoreError::UnexpectedError)?; // Updated!

        Ok(())
    }

    #[tracing::instrument(name = "Removing 2FA code", skip_all)]
    async fn remove_code(&mut self, email: &Email) -> Result<(), TwoFACodeStoreError> {
        let key = get_key(email);
        let _: () = self
            .conn
            .write()
            .await
            .del(&key)
            .wrap_err("failed to delete 2FA code from Redis") // New!
            .map_err(TwoFACodeStoreError::UnexpectedError)?; // Updated!

        Ok(())
    }

    #[tracing::instrument(name = "Getting 2FA code", skip_all)]
    async fn get_code(
        &self,
        email: &Email,
    ) -> Result<(LoginAttemptId, TwoFACode), TwoFACodeStoreError> {
       let key = get_key(email);
       let mut conn = self.conn.write().await;
       let result: Result<String, redis::RedisError> = conn.get(key);
       match result {
           Ok(serialized_tuple) => {
               let tuple: TwoFATuple = serde_json::from_str(&serialized_tuple)
                   .wrap_err("failed to deserialize 2FA tuple") // New!
                   .map_err(TwoFACodeStoreError::UnexpectedError)?;
               let login_attempt_id = LoginAttemptId::parse(tuple.0)
                   .map_err(TwoFACodeStoreError::UnexpectedError)?;
               let code = TwoFACode::parse(tuple.1)
                   .map_err(TwoFACodeStoreError::UnexpectedError)?;
               Ok((login_attempt_id, code))
           }
            Err(_) => Err(TwoFACodeStoreError::LoginAttemptIdNotFound),
       }
    }
}

#[derive(Serialize, Deserialize)]
struct TwoFATuple(pub String, pub String);

const TEN_MINUTES_IN_SECONDS: u64 = 600;
const TWO_FA_CODE_PREFIX: &str = "two_fa_code:";

#[tracing::instrument(name = "Generating 2FA code key", skip_all)]
fn get_key(email: &Email) -> String {
    format!("{}{}", TWO_FA_CODE_PREFIX, email.as_ref())
}