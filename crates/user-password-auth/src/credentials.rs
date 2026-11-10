use std::fmt;

/// Authentication credentials.
#[derive(Clone, Eq, PartialEq)]
pub struct Credentials {
    /// Unique username.
    pub username: String,
    /// Password of target user.
    pub password: String,
}

impl fmt::Debug for Credentials {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("Credentials")
            .field("username", &self.username)
            .field("password", &"[REDACTED]")
            .finish()
    }
}
