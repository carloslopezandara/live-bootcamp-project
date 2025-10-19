#[derive(Debug, PartialEq)]
pub enum AuthAPIError {
    UserAlreadyExists,
    InvalidCredentials,
    IncorrectCredentials,
    UnexpectedError,
    MissingToken,
    InvalidToken,
}

