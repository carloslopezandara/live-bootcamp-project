// Create a concrete banned token store implementation that uses a HashSet to store tokens. 
// The concrete type should be a struct called HashsetBannedTokenStore. 
// The struct should be defined in the auth-service/src/services directory. 
// Make sure to add unit tests!

use std::{collections::HashSet};

use crate::domain::{BannedTokenStore, BannedTokenStoreError};

#[derive(Default, Debug)]
pub struct HashsetBannedTokenStore {
    tokens: HashSet<String>,
}

#[async_trait::async_trait]
impl BannedTokenStore for HashsetBannedTokenStore {
    async fn store_token(&mut self, token: String) -> Result<(), BannedTokenStoreError> {
        match self.tokens.get(&token) {
            Some(_) => return Err(BannedTokenStoreError::TokenAlreadyExists), 
            None => {
                self.tokens.insert(token);
            },
        }
        Ok(())
    }

    async fn is_token_banned(&self, token: &String) -> Result<bool, BannedTokenStoreError> {
        // For an in-memory HashSet store this operation cannot fail, so return Ok
        Ok(self.tokens.contains(token))
    }

    fn as_ref(&self) -> &dyn BannedTokenStore {
        self
    }
}   

#[tokio::test]
async fn test_banned_token_store() {
    let mut store = HashsetBannedTokenStore::default();

    // Test storing a token
    let token = "test_token".to_string();
    assert!(store.store_token(token.clone()).await.is_ok());

    // Test storing the same token again
    assert_eq!(store.store_token(token.clone()).await, Err(BannedTokenStoreError::TokenAlreadyExists));

    // Test checking if the token is banned
    assert!(store.is_token_banned(&token).await.unwrap());
}
