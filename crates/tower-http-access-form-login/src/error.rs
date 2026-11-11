/// A rejected form submission or authentication backend failure.
#[derive(Debug, thiserror::Error)]
pub enum FormLoginError {
    #[error("unsupported form content type")]
    UnsupportedMediaType,
    #[error("form body exceeds the configured size limit")]
    BodyTooLarge,
    #[error("failed to read form body")]
    BodyRead,
    #[error("invalid login form")]
    InvalidForm,
    #[error("invalid credentials")]
    InvalidCredentials,
    #[error("authentication backend failed: {0}")]
    Backend(#[source] Box<dyn std::error::Error + Send + Sync + 'static>),
}

/// The configured redirect location must be a valid same-origin absolute path.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct InvalidRedirectPath;

impl std::fmt::Display for InvalidRedirectPath {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("redirect location must be a same-origin absolute path")
    }
}

impl std::error::Error for InvalidRedirectPath {}

#[cfg(test)]
mod tests {
    use super::FormLoginError;
    use std::error::Error;

    #[test]
    fn backend_error_is_available_in_the_source_chain() {
        let error =
            FormLoginError::Backend(Box::new(std::io::Error::other("database unavailable")));
        let source = error.source().unwrap();
        assert!(source.downcast_ref::<std::io::Error>().is_some());
        assert_eq!(source.to_string(), "database unavailable");
        assert_eq!(
            error.to_string(),
            "authentication backend failed: database unavailable"
        );
        assert!(FormLoginError::InvalidCredentials.source().is_none());
    }
}
