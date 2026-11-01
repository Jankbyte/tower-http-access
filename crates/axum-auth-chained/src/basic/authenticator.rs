use super::BasicCredentials;
use super::base64::extract_credentials;
use crate::{SecurityResponse, response::empty_response};
use crate::{
    authentication::{
        AuthenticationAttempt, AuthenticationErrorReason, AuthenticatorError, RequestAuthenticator,
    },
    authorization::AuthenticationEntryPoint,
};
use bytes::Bytes;
use futures_util::future::BoxFuture;
use http::{StatusCode, header, request::Parts};
use std::{error::Error, future::Future, pin::Pin};

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
    ) -> BoxFuture<'a, Result<Option<Self::Authentication>, Self::Error>>;
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
/// ```no_run
/// # #[cfg(feature = "argon2_encoder")]
/// # mod example {
/// use argon2::Argon2;
/// use axum_auth_chained::basic::{
///     Authority, AsyncStringPasswordManager, BasicRequestAuthenticator,
///     InMemoryUserDetailService, UserDetail, UserDetailAuthenticationProvider,
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
///     UserDetail::new("alex", "alex123", vec![Authority::new("Admin")]),
///     UserDetail::new("max", "max123", vec![Authority::new("Reader")]),
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
/// # }
/// # fn main() {}
/// ```
///
#[derive(Clone)]
pub struct BasicRequestAuthenticator<P> {
    realm: String,
    provider: P,
}

impl<P> BasicRequestAuthenticator<P> {
    /// Create a Basic authenticator with the realm `Default`.
    pub fn new(provider: P) -> Self {
        Self {
            provider,
            realm: "Default".to_owned(),
        }
    }

    /// Create a Basic authenticator with a custom realm for its `WWW-Authenticate` challenges.
    /// Quotes and backslashes are escaped when writing the realm to the header.
    pub fn with_realm(provider: P, realm: impl Into<String>) -> Self {
        Self {
            provider,
            realm: realm.into(),
        }
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
            let Some(credentials) =
                extract_credentials(parts).map_err(|_| wrong_credentials(&self.realm))?
            else {
                return Ok(AuthenticationAttempt::NotApplicable);
            };
            match self.provider.authenticate(&credentials).await {
                Ok(Some(authentication)) => {
                    #[cfg(feature = "tracing")]
                    tracing::debug!(username = %credentials.username, "success authenticated");

                    Ok(AuthenticationAttempt::Authenticated(authentication))
                }
                Ok(None) => {
                    #[cfg(feature = "tracing")]
                    tracing::warn!(username = %credentials.username, "invalid or wrong credentials");

                    Err(wrong_credentials(&self.realm))
                }
                Err(error) => {
                    #[cfg(feature = "tracing")]
                    tracing::warn!(error = %error, "authentication failed by internal error");

                    Err(internal_error(error))
                }
            }
        })
    }
}

impl<P> AuthenticationEntryPoint for BasicRequestAuthenticator<P>
where
    P: Send + Sync + 'static,
{
    fn commence(&self, _: &Parts) -> SecurityResponse {
        basic_challenge(&self.realm)
    }
}

fn wrong_credentials(realm: &str) -> AuthenticatorError {
    AuthenticatorError::with_response(
        AuthenticationErrorReason::WrongCredentials,
        basic_challenge(realm),
    )
}

fn basic_challenge(realm: &str) -> SecurityResponse {
    let realm = realm.replace('\\', "\\\\").replace('"', "\\\"");
    let challenge = format!(r#"Basic realm="{realm}""#);
    let Ok(challenge) = http::HeaderValue::from_str(&challenge) else {
        return empty_response(StatusCode::INTERNAL_SERVER_ERROR);
    };
    let mut response = SecurityResponse::new(Bytes::new());
    *response.status_mut() = StatusCode::UNAUTHORIZED;
    response
        .headers_mut()
        .insert(header::WWW_AUTHENTICATE, challenge);
    response
}

fn internal_error(error: impl Error + Send + Sync + 'static) -> AuthenticatorError {
    AuthenticatorError::new(AuthenticationErrorReason::Internal(Box::new(error)))
}

#[cfg(test)]
#[path = "authenticator_tests.rs"]
mod tests;
