//! Authentication contracts, typed identities, errors, and adapters.

use axum::{
    Extension,
    extract::{FromRequestParts, OptionalFromRequestParts, Request, rejection::ExtensionRejection},
    http::request::Parts,
    response::{IntoResponse, Response},
};
use futures_util::future::BoxFuture;
use std::{error::Error, future::Future, sync::Arc};

use crate::authorization::AuthenticationEntryPoint;

pub type BoxError = Box<dyn Error + Send + Sync>;

/// A typed identity produced by successful request authentication.
///
/// Authentication middleware stores this wrapper in request extensions instead of storing `A`
/// directly. This distinguishes an authenticated identity from unrelated extension values of the
/// same type.
///
/// Use it directly as an Axum extractor when authentication is required, or wrap it in [`Option`]
/// when a handler also accepts anonymous requests:
///
/// ```rust
/// use axum_auth_chained::authentication::Authenticated;
///
/// # #[derive(Clone)]
/// # struct User;
/// # async fn required_example(
/// Authenticated(user): Authenticated<User>,
/// # ) {}
/// # async fn optional_example(
/// authentication: Option<Authenticated<User>>,
/// # ) {}
/// ```
///
/// A missing required identity uses Axum's standard extension rejection. Scheme-specific
/// unauthenticated responses, such as a Basic `WWW-Authenticate` challenge, remain the
/// authorization layer's responsibility.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Authenticated<A>(pub A);

impl<A> Authenticated<A> {
    /// Wrap an authenticated identity.
    pub fn new(authentication: A) -> Self {
        Self(authentication)
    }

    /// Borrow the authenticated identity.
    pub fn as_inner(&self) -> &A {
        &self.0
    }

    /// Consume the wrapper and return the authenticated identity.
    pub fn into_inner(self) -> A {
        self.0
    }
}

impl<S, A> FromRequestParts<S> for Authenticated<A>
where
    S: Send + Sync,
    A: Clone + Send + Sync + 'static,
{
    type Rejection = ExtensionRejection;

    async fn from_request_parts(parts: &mut Parts, state: &S) -> Result<Self, Self::Rejection> {
        <Extension<Self> as FromRequestParts<S>>::from_request_parts(parts, state)
            .await
            .map(|Extension(authentication)| authentication)
    }
}

impl<S, A> OptionalFromRequestParts<S> for Authenticated<A>
where
    S: Send + Sync,
    A: Clone + Send + Sync + 'static,
{
    type Rejection = std::convert::Infallible;

    async fn from_request_parts(parts: &mut Parts, _: &S) -> Result<Option<Self>, Self::Rejection> {
        Ok(parts.extensions.get::<Self>().cloned())
    }
}

/// The error, that present reason why authentication failed.
#[derive(Debug, thiserror::Error)]
pub enum AuthenticationErrorReason {
    /// The authentication credentials was wrong.
    ///
    /// For example, username or password was wrong.
    #[error("wrong credentials")]
    WrongCredentials,
    /// Error occurred when internal server error happens.
    ///
    /// For example, it can thrown if database with users disconnected.
    #[error("internal authenticator error: {0}")]
    Internal(#[source] BoxError),
}

/// Authentication failure with an optional custom response.
#[derive(Debug)]
pub struct AuthenticatorError {
    /// The reason of occurred error.
    pub reason: AuthenticationErrorReason,
    /// Custom response sent instead of the default response for [`Self::reason`].
    pub response: Option<Response>,
}

impl AuthenticatorError {
    /// Create an authentication error using the default response for the reason.
    pub fn new(reason: AuthenticationErrorReason) -> Self {
        Self {
            reason,
            response: None,
        }
    }

    /// Create an authentication error with a custom response.
    pub fn with_response(reason: AuthenticationErrorReason, response: impl IntoResponse) -> Self {
        Self {
            reason,
            response: Some(response.into_response()),
        }
    }
}

impl IntoResponse for AuthenticatorError {
    fn into_response(self) -> Response {
        self.response.unwrap_or_else(|| match self.reason {
            AuthenticationErrorReason::WrongCredentials => {
                axum::http::StatusCode::UNAUTHORIZED.into_response()
            }
            AuthenticationErrorReason::Internal(_) => {
                axum::http::StatusCode::INTERNAL_SERVER_ERROR.into_response()
            }
        })
    }
}

/// Present success state of authentication.
///
/// Uses by [`RequestAuthenticator`].
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum AuthenticationAttempt<A> {
    /// The result of authentication, when target authenticator is not applicable.
    ///
    /// For example, [`BasicRequestAuthenticator`] can return that, if your request
    /// does not have `Authorization` header and target schema (`Basic`) in value.
    ///
    /// [`BasicRequestAuthenticator`]: crate::basic::BasicRequestAuthenticator
    ///
    NotApplicable,
    /// Success authenticated, where value is result of authentication.
    Authenticated(A),
}

impl<A> AuthenticationAttempt<A> {
    fn map<B>(self, mapper: impl FnOnce(A) -> B) -> AuthenticationAttempt<B> {
        match self {
            Self::NotApplicable => AuthenticationAttempt::NotApplicable,
            Self::Authenticated(authentication) => {
                AuthenticationAttempt::Authenticated(mapper(authentication))
            }
        }
    }
}

/// Accept HTTP-request and tries to convert into authentication.
///
/// # Contract
/// The every authenticator must be implementated with next contract:
///
/// * If target authenticator does not support current request, it must return success [`Result::Ok`] with [`AuthenticationAttempt::NotApplicable`]
/// * If target authenticator can authenticate this request, but credentials is wrong/invalid, so it must return [`Result::Err`], where reason is
///   [`AuthenticationErrorReason::WrongCredentials`]. Usually, the response code of this sutuations is *401*.
/// * If target authenticator can authenticate this request, but authentication failed by internal reasons, it must return [`Result::Err`] where reason
///   is [`AuthenticationErrorReason::Internal`]. Usually, the response code is *500*.
///
/// # Restrictions
///
/// * The authenticator does not support extracting requet body. For example, it means, if you want implement
///   form-login authentication, you must create your own endpoint in axum that accept `Content-Type: application/x-www-form-urlencoded`.
///
pub trait RequestAuthenticator: Send + Sync {
    /// The result of success authentication.
    ///
    /// For example, it may username or session ID.
    type Authentication: Clone + Send + Sync + 'static;

    /// Authenticate target request and get result.
    fn authenticate<'a>(
        &'a self,
        parts: &'a mut Parts,
    ) -> BoxFuture<'a, Result<AuthenticationAttempt<Self::Authentication>, AuthenticatorError>>;
}

/// Forwards authentication to a shared authenticator, including trait objects.
impl<A: RequestAuthenticator + ?Sized> RequestAuthenticator for Arc<A> {
    type Authentication = A::Authentication;

    fn authenticate<'a>(
        &'a self,
        parts: &'a mut Parts,
    ) -> BoxFuture<'a, Result<AuthenticationAttempt<Self::Authentication>, AuthenticatorError>>
    {
        self.as_ref().authenticate(parts)
    }
}

/// Convert type of authentication to another type.
pub trait RequestAuthenticatorExt: RequestAuthenticator + Sized {
    fn map<F, A>(self, mapper: F) -> MapAuthentication<Self, F>
    where
        F: Fn(Self::Authentication) -> A,
    {
        MapAuthentication {
            inner: self,
            mapper,
        }
    }
}

impl<T: RequestAuthenticator> RequestAuthenticatorExt for T {}

/// Adapter for converting [`AuthenticationAttempt`] to another type.
pub struct MapAuthentication<T, F> {
    inner: T,
    mapper: F,
}

impl<T, F, A> RequestAuthenticator for MapAuthentication<T, F>
where
    T: RequestAuthenticator,
    F: Fn(T::Authentication) -> A + Send + Sync,
    A: Clone + Send + Sync + 'static,
{
    type Authentication = A;

    fn authenticate<'a>(
        &'a self,
        parts: &'a mut Parts,
    ) -> BoxFuture<'a, Result<AuthenticationAttempt<Self::Authentication>, AuthenticatorError>>
    {
        Box::pin(async move {
            self.inner
                .authenticate(parts)
                .await
                .map(|attempt| attempt.map(&self.mapper))
        })
    }
}

impl<T, F> AuthenticationEntryPoint for MapAuthentication<T, F>
where
    T: AuthenticationEntryPoint,
    F: Send + Sync + 'static,
{
    fn commence(&self, request: Request) -> Response {
        self.inner.commence(request)
    }
}

/// Create authenticator from closure.
impl<F, Fut, A> RequestAuthenticator for F
where
    F: Fn(&mut Parts) -> Fut + Send + Sync,
    Fut: Future<Output = Result<AuthenticationAttempt<A>, AuthenticatorError>> + Send + 'static,
    A: Clone + Send + Sync + 'static,
{
    type Authentication = A;

    fn authenticate<'a>(
        &'a self,
        parts: &'a mut Parts,
    ) -> BoxFuture<'a, Result<AuthenticationAttempt<A>, AuthenticatorError>> {
        Box::pin(self(parts))
    }
}

#[cfg(test)]
#[path = "core_tests.rs"]
mod tests;
