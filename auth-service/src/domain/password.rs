use color_eyre::eyre::{eyre, Result};
use secrecy::{ExposeSecret, Secret};

#[derive(Debug, Clone)] // Updated!
pub struct Password(Secret<String>); // Updated!

impl Password {
    pub fn parse(s: Secret<String>) -> Result<Password> { // Updated!
        if validate_password(&s) {
            Ok(Self(s))
        } else {
            Err(eyre!("Failed to parse string to a Password type"))
        }
    }
}

fn validate_password(s: &Secret<String>) -> bool { // Updated!
    s.expose_secret().len() >= 8
}

impl AsRef<Secret<String>> for Password { // Updated!
    fn as_ref(&self) -> &Secret<String> {
        &self.0
    }
}

impl PartialEq for Password { // New!
    fn eq(&self, other: &Self) -> bool {
        // We can use the expose_secret method to expose the secret in a
        // controlled manner when needed!
        self.0.expose_secret() == other.0.expose_secret() // Updated!
    }
}

// Unit tests for `Password` implementation
#[cfg(test)]
mod tests {
    use super::*;
    use fake::faker::internet::en::{Password as FakePassword};
    use fake::Fake;
    extern crate quickcheck;
    use secrecy::Secret; // New!

    #[test]
    fn empty_string_is_rejected() {
        let password = Secret::new("".to_string()); // Updated!
        assert!(Password::parse(password).is_err());
    }
    #[test]
    fn string_less_than_8_characters_is_rejected() {
        let password = Secret::new("1234567".to_string()); // Updated!
        assert!(Password::parse(password).is_err());
    }

    #[derive(Debug, Clone)]
    struct ValidPasswordFixture(pub Secret<String>); // Updated!

    impl quickcheck::Arbitrary for ValidPasswordFixture {
        fn arbitrary<G: quickcheck::Gen>(g: &mut G) -> Self {
            let password = FakePassword(8..30).fake_with_rng(g);
            Self(Secret::new(password)) // Updated!
        }
    }
    #[quickcheck_macros::quickcheck]
    fn valid_passwords_are_parsed_successfully(valid_password: ValidPasswordFixture) -> bool {
        Password::parse(valid_password.0).is_ok()
    }
}