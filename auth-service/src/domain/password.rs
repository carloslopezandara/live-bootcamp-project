use validator::validate_length;
use crate::domain::error::AuthAPIError;

pub struct Password(String);

impl Password {
    pub fn parse(pass: String) -> Result<Self, AuthAPIError> {
        if validate_length(&pass, Some(8), None, None) {
            Ok(Self(pass))
        } else {
            Err(AuthAPIError::InvalidCredentials)
        }
    }

    pub fn as_ref(&self) -> &str {
        &self.0
    }
}

// Unit tests for `Password` implementation
#[cfg(test)]
mod tests {
    use super::*;
    use fake::faker::internet::en::{Password as FakePassword};
    use fake::Fake;
    extern crate quickcheck;
    use quickcheck::QuickCheck;

    #[tokio::test]
    async fn test_password_parse_valid() {
        let pass_str: String = FakePassword(8..18).fake();
        let pass = Password::parse(pass_str.clone());
        assert!(pass.is_ok());
        assert_eq!(pass.unwrap().as_ref(), pass_str);
    }

    fn prop_password_parse_valid(pass_str: String) -> bool {
        if validate_length(&pass_str, Some(8), None, None) {
            let pass = Password::parse(pass_str.clone());
            pass.is_ok() && pass.unwrap().as_ref() == pass_str
        } else {
            true // Skip invalid passwords
        }
    }

    #[tokio::test]
    async fn test_password_parse_valid_quickcheck() {
    QuickCheck::new()
        .tests(20)
        .quickcheck(prop_password_parse_valid as fn(String) -> bool);
    }

    #[tokio::test]
    async fn test_password_parse_invalid() {
        let pass_str = "short".to_string();
        let pass = Password::parse(pass_str);
        assert!(pass.is_err());
        assert_eq!(pass.err().unwrap(), AuthAPIError::InvalidCredentials);
    }

    // quickcheck test
    fn prop_password_parse_invalid(pass_str: String) -> bool {
        if !validate_length(&pass_str, Some(8), None, None) {
            let pass = Password::parse(pass_str);
            pass.is_err() && pass.err().unwrap() == AuthAPIError::InvalidCredentials
        } else {
            true // Skip valid passwords
        }
    }

    #[tokio::test]
    async fn test_password_parse_invalid_quickcheck() {
    QuickCheck::new()
        .tests(20)
        .quickcheck(prop_password_parse_invalid as fn(String) -> bool);
    }
}