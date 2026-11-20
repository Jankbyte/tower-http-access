use futures_util::future::BoxFuture;
use http::{HeaderName, request::Parts};
use std::error::Error as StdError;

/// A CSRF token and the request field names used to submit it.
///
/// Render `token` in a hidden input named `parameter_name`, or submit it using
/// `header_name`. Token generation and persistence belong to the repository.
#[derive(Clone)]
pub struct CsrfToken {
    /// HTTP header that can carry the submitted token, such as `x-csrf-token`.
    pub header_name: HeaderName,
    /// Form field that can carry the submitted token, such as `_csrf`.
    pub parameter_name: String,
    /// The token value to render in the page and validate on submission.
    pub token: String,
}

/// The CSRF-token repository, inspired by [`Spring CSRF-token repository`].
///
/// [`Spring CSRF-token repository`]: https://docs.spring.io/spring-security/reference/api/java/org/springframework/security/web/csrf/CsrfTokenRepository.html
pub trait CsrfTokenRepository: Send + Sync {
    /// An operational failure, such as unavailable storage, invalid stored data,
    /// or a failure to obtain secure randomness. Missing, expired, or mismatched
    /// tokens are not repository errors.
    type Error: StdError + Send + Sync + 'static;

    /// Generate a fresh, unpredictable token and its header and form field names.
    ///
    /// Use a cryptographically secure random source. This method does not persist
    /// the token; callers must use [`Self::save_token`] before relying on it.
    /// Return an error if secure token generation fails.
    fn generate_token(&self) -> Result<CsrfToken, Self::Error>;

    /// Load the expected token from storage associated with this request.
    ///
    /// Return `Ok(Some(token))` when a token exists and has not expired, or
    /// `Ok(None)` when it is missing or expired. Repositories supporting expiry
    /// must not return expired tokens. Do not generate or save a replacement here.
    /// Return an error for storage access or decoding failures.
    ///
    /// This loads the trusted, stored token, not the token submitted in a header
    /// or form field. Comparing the submitted token is the CSRF layer's responsibility.
    fn load_token<'a>(
        &'a self,
        request: &'a Parts,
    ) -> BoxFuture<'a, Result<Option<CsrfToken>, Self::Error>>;

    /// Save or remove the expected token in storage associated with this request.
    ///
    /// `Some(token)` stores the supplied token, replacing any existing value.
    /// `None` removes the stored token; removing an already absent token succeeds.
    /// Subsequent loads for the same storage context must reflect the change,
    /// unless the token expires. Return an error if saving or removal fails.
    /// Implementations must not silently replace the supplied token with a new one.
    fn save_token<'a>(
        &'a self,
        request: &'a Parts,
        token: Option<&'a CsrfToken>,
    ) -> BoxFuture<'a, Result<(), Self::Error>>;
}

/// Forwards repository operations to a shared implementation, including trait objects.
impl<R: CsrfTokenRepository + ?Sized> CsrfTokenRepository for std::sync::Arc<R> {
    type Error = R::Error;

    fn generate_token(&self) -> Result<CsrfToken, Self::Error> {
        self.as_ref().generate_token()
    }

    fn load_token<'a>(
        &'a self,
        request: &'a Parts,
    ) -> BoxFuture<'a, Result<Option<CsrfToken>, Self::Error>> {
        self.as_ref().load_token(request)
    }

    fn save_token<'a>(
        &'a self,
        request: &'a Parts,
        token: Option<&'a CsrfToken>,
    ) -> BoxFuture<'a, Result<(), Self::Error>> {
        self.as_ref().save_token(request, token)
    }
}
