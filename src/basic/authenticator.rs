use super::BasicCredentials;
use super::base64::extract_credentials;
use crate::{
    authentication::{
        AuthenticationAttempt, AuthenticationErrorReason, AuthenticatorError, RequestAuthenticator,
    },
    authorization::AuthenticationEntryPoint,
};
use axum::{
    extract::Request,
    http::{StatusCode, header, request::Parts},
    response::{IntoResponse, Response},
};
use std::{error::Error, future::Future, pin::Pin};

/// The result of username/password authentication.
pub type UsernamePasswordAuthenticationFuture<'a, A, E> =
    Pin<Box<dyn Future<Output = Result<Option<A>, E>> + Send + 'a>>;

/// Authenticates decoded username/password credentials.
///
/// `Ok(Some(authentication))` means the credentials are valid, `Ok(None)` means they are invalid,
/// and `Err(error)` represents an internal backend failure.
pub trait UsernamePasswordAuthenticationProvider: Send + Sync {
    /// Identity produced by successful authentication.
    type Authentication: Clone + Send + Sync + 'static;
    /// Internal authentication backend error.
    type Error: Error + Send + Sync + 'static;

    fn authenticate<'a>(
        &'a self,
        credentials: &'a BasicCredentials,
    ) -> UsernamePasswordAuthenticationFuture<'a, Self::Authentication, Self::Error>;
}

/// HTTP Basic authentication for Axum requests.
///
/// This authenticator implements the [`Basic` authentication scheme defined by RFC 7617](https://www.rfc-editor.org/rfc/rfc7617.html). Basic
/// credentials are only Base64-encoded, not encrypted, so applications must use HTTPS when sending
/// them over a network.
///
/// Credential verification is delegated to a [`UsernamePasswordAuthenticationProvider`]. The
/// provider chooses the resulting identity type and can use local password hashes, a database, or
/// an external authentication service.
///
/// # Behavior
///
/// When request is coming, authenticator check `Authorization` header, and if header is missed or does not start with `Basic`
/// schema - skip this request with [`AuthenticationAttempt::NotApplicable`] as result.
///
/// Otherwise, decode the credentials and pass them to the configured provider.
/// A malformed Basic header, unknown user, or wrong password stops the authenticator chain and
/// returns `401 Unauthorized` with a `WWW-Authenticate: Basic` challenge. This follows the
/// [HTTP authentication requirements in RFC 9110](https://www.rfc-editor.org/rfc/rfc9110.html#section-11.4). A missing header or a different authentication
/// scheme returns [`AuthenticationAttempt::NotApplicable`] so another authenticator can try the
/// request.
///
/// # Example
///
/// ```rust
/// use argon2::Argon2;
/// use axum_auth_chained::basic::{
///     AsyncStringPasswordManager, BasicRequestAuthenticator, InMemoryUserDetailService,
///     UserDetail, UserDetailAuthenticationProvider,
/// };
/// use std::num::NonZeroUsize;
/// use tokio::runtime::Handle;
///
/// # #[tokio::main(flavor = "current_thread")]
/// # async fn main() {
/// let manager: AsyncStringPasswordManager<Argon2> =
///     AsyncStringPasswordManager::new(Handle::current(), Argon2::default(), NonZeroUsize::new(2).unwrap());
///
/// let raw_users = vec![
///     UserDetail::new("alex", "alex123"),
///     UserDetail::new("max", "max123"),
/// ];
///
/// let user_detail_service = InMemoryUserDetailService::new((&manager, raw_users))
///     .await
///     .unwrap();
///
/// let provider = UserDetailAuthenticationProvider::new(manager, user_detail_service)
///     .await
///     .unwrap();
/// let basic_authenticator = BasicRequestAuthenticator::new(provider);
/// # }
/// ```
///
#[derive(Clone)]
pub struct BasicRequestAuthenticator<P> {
    provider: P,
}

impl<P> BasicRequestAuthenticator<P> {
    /// Create a Basic authenticator backed by a username/password provider.
    pub fn new(provider: P) -> Self {
        Self { provider }
    }
}

impl<P> RequestAuthenticator for BasicRequestAuthenticator<P>
where
    P: UsernamePasswordAuthenticationProvider,
{
    type Authentication = P::Authentication;

    fn authenticate<'a>(
        &'a self,
        parts: &'a mut Parts,
    ) -> Pin<
        Box<
            dyn Future<
                    Output = Result<
                        AuthenticationAttempt<Self::Authentication>,
                        AuthenticatorError,
                    >,
                > + Send
                + 'a,
        >,
    > {
        Box::pin(async move {
            let Some(credentials) = extract_credentials(parts).map_err(|_| wrong_credentials())?
            else {
                return Ok(AuthenticationAttempt::NotApplicable);
            };
            match self.provider.authenticate(&credentials).await {
                Ok(Some(authentication)) => {
                    Ok(AuthenticationAttempt::Authenticated(authentication))
                }
                Ok(None) => Err(wrong_credentials()),
                Err(error) => Err(internal_error(error)),
            }
        })
    }
}

impl<P> AuthenticationEntryPoint for BasicRequestAuthenticator<P>
where
    P: Send + Sync + 'static,
{
    fn commence(&self, _: Request) -> Response {
        basic_challenge()
    }
}

fn wrong_credentials() -> AuthenticatorError {
    AuthenticatorError::with_response(
        AuthenticationErrorReason::WrongCredentials,
        basic_challenge(),
    )
}

fn basic_challenge() -> Response {
    (
        StatusCode::UNAUTHORIZED,
        [(header::WWW_AUTHENTICATE, r#"Basic realm="Realm""#)],
    )
        .into_response()
}

fn internal_error(error: impl Error + Send + Sync + 'static) -> AuthenticatorError {
    AuthenticatorError::new(AuthenticationErrorReason::Internal(Box::new(error)))
}

#[cfg(test)]
#[path = "authenticator_tests.rs"]
mod tests;
