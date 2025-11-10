use validator::validate_email;
use crate::domain::error::AuthAPIError;

#[derive(Clone, Debug, PartialEq, Hash, Eq)]
pub struct Email(String);

impl Email {
    pub fn parse(email: String) -> Result<Self, AuthAPIError> {
        if validate_email(&email) {
            Ok(Self(email))
        } else {
            Err(AuthAPIError::InvalidCredentials)
        }
    }

    pub fn as_ref(&self) -> &str {
        &self.0
    }
}

// Unit tests for `Email` implementation
#[cfg(test)]
#[macro_use]
mod tests {
    use super::*;
    use fake::faker::internet::en::{SafeEmail};
    use fake::Fake;
    extern crate quickcheck;
    use quickcheck::QuickCheck;

    #[tokio::test]
    async fn test_email_parse_valid() {
        let email_str: String = SafeEmail().fake();
        let email = Email::parse(email_str.clone());
        assert!(email.is_ok());
        assert_eq!(email.unwrap().as_ref(), email_str);
    }

    // quickcheck test
    fn prop_email_parse_valid(email_str: String) -> bool {
        if validate_email(&email_str) {
            let email = Email::parse(email_str.clone());
            email.is_ok() && email.unwrap().as_ref() == email_str
        } else {
            true // Skip invalid emails
        }
    }

    #[tokio::test]
    async fn test_email_parse_valid_quickcheck() {
    QuickCheck::new()
        .tests(20)
        .quickcheck(prop_email_parse_valid as fn(String) -> bool);
    }

    #[tokio::test]
    async fn test_email_parse_invalid() {
        let email_str = "invalid-email-format".to_string();
        let email = Email::parse(email_str);
        assert!(email.is_err());
        //assert_eq!(email.err().unwrap(), AuthAPIError::InvalidCredentials);
    }

    // quickcheck test
    fn prop_email_parse_invalid(email_str: String) -> bool {
        if !validate_email(&email_str) {
            let email = Email::parse(email_str.clone());
            email.is_err() //&& email.err().unwrap() == AuthAPIError::InvalidCredentials
        } else {
            true // Skip valid emails
        }
    }

    #[tokio::test]
    async fn test_email_parse_invalid_quickcheck() {
    QuickCheck::new()
        .tests(20)
        .quickcheck(prop_email_parse_invalid as fn(String) -> bool);
    }

}
