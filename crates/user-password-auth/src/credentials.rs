use std::fmt;

/// Authentication credentials.
#[derive(Clone, Eq, PartialEq)]
pub struct Credentials {
    /// Unique username.
    pub username: String,
    /// Password of target user.
    pub password: String,
}

impl Credentials {
    /// Create new credentials.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use user_password_auth::Credentials;
    /// let _ = Credentials::new("username", "password");
    /// ```
    ///
    pub fn new(username: impl Into<String>, password: impl Into<String>) -> Self {
        Self {
            username: username.into(),
            password: password.into(),
        }
    }
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
