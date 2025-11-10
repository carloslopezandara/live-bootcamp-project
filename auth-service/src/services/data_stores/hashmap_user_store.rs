use std::collections::HashMap;
use crate::domain::{User, UserStore, UserStoreError, Email, Password};

// a `HashMap`` of email `String`s mapped to `User` objects.
// Derive the `Default` trait for `HashmapUserStore`.
#[derive(Default, Debug)]
pub struct HashmapUserStore {
    users: HashMap<Email, User>,
}

#[async_trait::async_trait]
impl UserStore for HashmapUserStore {
    async fn add_user(&mut self, user: User) -> Result<(), UserStoreError> {
        match self.get_user(&user.email).await {
            Ok(_) => Err(UserStoreError::UserAlreadyExists),
            Err(UserStoreError::UserNotFound) => {
                self.users.insert(user.email.clone(), user);
                Ok(())
            }
            Err(e) => Err(e), 
        }
    }


    async fn get_user(&self, email: &Email) -> Result<User, UserStoreError> {
        match self.users.get(email) {
            Some(user) => Ok(user.clone()),
            None => Err(UserStoreError::UserNotFound),
        }
    }

    async fn validate_user(&self, email: &Email, password: &Password) -> Result<(), UserStoreError> {
        match self.get_user(email).await {
            Ok(user) => {
                if &user.password == password {
                    Ok(())
                } else {
                    Err(UserStoreError::InvalidCredentials)
                }
            }
            Err(_) => Err(UserStoreError::UserNotFound),
        }
    }
}

// TODO: Add unit tests for your `HashmapUserStore` implementation
#[cfg(test)]
mod tests {
    use super::*;
    use secrecy::Secret;

    #[tokio::test]
    async fn test_add_user() {
        let mut store = HashmapUserStore::default();
        let user = User {
            email: Email::parse(Secret::new("test@gmail.com".to_string())).unwrap(),
            password:Password::parse(Secret::new("password".to_string())).unwrap(),
            requires_2fa: false,
        };
        assert_eq!(store.add_user(user.clone()).await, Ok(()));
        assert_eq!(store.add_user(user).await, Err(UserStoreError::UserAlreadyExists));
    }

    #[tokio::test]
    async fn test_get_user() {
        let mut store = HashmapUserStore::default();
        let user = User {
            email: Email::parse(Secret::new("test@gmail.com".to_string())).unwrap(),
            password:Password::parse(Secret::new("password".to_string())).unwrap(),
            requires_2fa: false,
        };
        assert_eq!(store.get_user(&Email::parse(Secret::new("test@gmail.com".to_string())).unwrap()).await, Err(UserStoreError::UserNotFound));
        assert_eq!(store.add_user(user.clone()).await, Ok(()));
        assert_eq!(store.get_user(&Email::parse(Secret::new("test@gmail.com".to_string())).unwrap()).await, Ok(user));
    }

    #[tokio::test]
    async fn test_validate_user() {
        let mut store = HashmapUserStore::default();
        let user = User {
            email: Email::parse(Secret::new("test@gmail.com".to_string())).unwrap(),
            password:Password::parse(Secret::new("password".to_string())).unwrap(),
            requires_2fa: false,
        };
        assert_eq!(store.validate_user(&Email::parse(Secret::new("test@gmail.com".to_string())).unwrap(), &Password::parse(Secret::new("password".to_string())).unwrap()).await, Err(UserStoreError::UserNotFound));
        store.add_user(user.clone()).await.unwrap();
        assert_eq!(store.validate_user(&Email::parse(Secret::new("test@gmail.com".to_string())).unwrap(), &Password::parse(Secret::new("password".to_string())).unwrap()).await, Ok(()));
        assert_eq!(store.validate_user(&Email::parse(Secret::new("test@gmail.com".to_string())).unwrap(), &Password::parse(Secret::new("wrongpassword".to_string())).unwrap()).await, Err(UserStoreError::InvalidCredentials));
    }
}