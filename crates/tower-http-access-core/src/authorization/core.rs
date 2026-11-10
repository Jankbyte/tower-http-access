//! Shared authorization contracts, identity adapters, decisions, and failure handling.

use crate::{SecurityResponse, response::empty_response};
use futures_util::future::BoxFuture;
use http::{StatusCode, request::Parts};
use std::{future::Future, marker::PhantomData, pin::Pin, sync::Arc};

/// The authentication entrypoint, that uses by [`crate::SecurityService`]
/// to delegate unauthenticated requests. It borrows request metadata and returns buffered bytes.
/// The middleware converts the response body to the type expected by the inner service.
///
/// This should be used for providing schema of authentication, when credentials is not set.
///
/// For example, if endpoint requires `Basic` authentication, but credentials (header) is not provided,
/// service will execute this endpoint, that returns response with `WWW-Authenticate` header.
pub trait AuthenticationEntryPoint: Send + Sync + 'static {
    fn commence(&self, request: &Parts) -> SecurityResponse;
}

/// Create authentication entrypoint from closure.
impl<F> AuthenticationEntryPoint for F
where
    F: Fn(&Parts) -> SecurityResponse + Send + Sync + 'static,
{
    fn commence(&self, request: &Parts) -> SecurityResponse {
        self(request)
    }
}

/// The default implementation of [`AuthenticationEntryPoint`] that just returns *401*.
#[derive(Clone, Copy, Debug, Default)]
pub struct DefaultAuthenticationEntryPoint;

impl AuthenticationEntryPoint for DefaultAuthenticationEntryPoint {
    fn commence(&self, _: &Parts) -> SecurityResponse {
        empty_response(StatusCode::UNAUTHORIZED)
    }
}

/// Authorizes an identity against borrowed HTTP request parts.
///
/// The source of permissions may be, for example:
///
/// * [`Self::Authentication`] - we can store permissions/roles inside authentication, and extract
///   that on authentication layer, but verify here.
/// * Database - we can store permissions in some database, find permissions by [`Self::Authentication`] principals
///   and check the request metadata.
///
pub trait AuthorizationProvider: Send + Sync {
    /// The authentication type.
    type Authentication: Send + Sync;
    /// Error produced by `authorize` method.
    type Error: std::error::Error + Send + Sync;

    fn authorize<'a>(
        &'a self,
        authentication: Option<&'a Self::Authentication>,
        request: &'a Parts,
    ) -> Pin<Box<dyn Future<Output = Result<AuthorizationDecision, Self::Error>> + Send + 'a>>;
}

/// Forwards authorization to a shared provider, including trait objects.
impl<P: AuthorizationProvider + ?Sized> AuthorizationProvider for Arc<P> {
    type Authentication = P::Authentication;
    type Error = P::Error;

    fn authorize<'a>(
        &'a self,
        authentication: Option<&'a Self::Authentication>,
        request: &'a Parts,
    ) -> BoxFuture<'a, Result<AuthorizationDecision, Self::Error>> {
        self.as_ref().authorize(authentication, request)
    }
}

/// Adapters for authorization providers.
pub trait AuthorizationProviderExt: AuthorizationProvider + Sized {
    /// Convert an authenticated identity before passing it to this provider.
    ///
    /// The mapper runs only for authenticated requests. Anonymous requests are passed through as
    /// `None`, and the original identity in request extensions remains available to handlers.
    /// Conversion is synchronous and produces an owned value used only during authorization.
    ///
    /// Use this when an authorization provider from an external crate expects its own principal
    /// type, while your authenticator produces an application-specific identity. The adapted
    /// provider accepts the application's identity and converts it to the external principal
    /// without changing either type or replacing the identity stored by authentication middleware.
    /// The underlying provider's decisions and errors are returned unchanged.
    ///
    /// ```
    /// use tower_http_access_core::authorization::default_auth::AuthenticatedAuthorizationProvider;
    /// use tower_http_access_core::authorization::core::AuthorizationProviderExt;
    ///
    /// struct AppUser { id: u64 }
    ///
    /// let provider = AuthenticatedAuthorizationProvider::<String>::new()
    ///     .map(|user: &AppUser| user.id.to_string());
    /// ```
    ///
    /// For an external authorization integration, adapt a provider whose authentication type is
    /// the external crate's principal. Here `ExternalPrincipal` stands in for that crate's type:
    ///
    /// ```
    /// use tower_http_access_core::authorization::core::AuthorizationProvider;
    /// use tower_http_access_core::authorization::core::AuthorizationProviderExt;
    ///
    /// struct AppUser {
    ///     id: u64,
    ///     roles: Vec<String>,
    /// }
    ///
    /// struct ExternalPrincipal {
    ///     subject: String,
    ///     roles: Vec<String>,
    /// }
    ///
    /// fn adapt_external_provider<P>(provider: P)
    ///     -> impl AuthorizationProvider<Authentication = AppUser, Error = P::Error>
    /// where
    ///     P: AuthorizationProvider<Authentication = ExternalPrincipal>,
    /// {
    ///     provider.map(|user: &AppUser| ExternalPrincipal {
    ///         subject: user.id.to_string(),
    ///         roles: user.roles.clone(),
    ///     })
    /// }
    /// ```
    ///
    /// The external provider must implement [`AuthorizationProvider`] directly or through a local
    /// wrapper. This mapper performs local conversion; conversions requiring asynchronous I/O
    /// need a custom provider implementation.
    fn map<A, F>(self, mapper: F) -> MapAuthorization<Self, F, A>
    where
        A: Send + Sync,
        F: Fn(&A) -> Self::Authentication + Send + Sync,
    {
        MapAuthorization {
            inner: self,
            mapper,
            authentication: PhantomData,
        }
    }
}

impl<P: AuthorizationProvider> AuthorizationProviderExt for P {}

/// An authorization provider that converts its input identity before delegating.
pub struct MapAuthorization<P, F, A> {
    inner: P,
    mapper: F,
    authentication: PhantomData<fn() -> A>,
}

impl<P: Clone, F: Clone, A> Clone for MapAuthorization<P, F, A> {
    fn clone(&self) -> Self {
        Self {
            inner: self.inner.clone(),
            mapper: self.mapper.clone(),
            authentication: PhantomData,
        }
    }
}

impl<P, F, A> AuthorizationProvider for MapAuthorization<P, F, A>
where
    P: AuthorizationProvider,
    A: Send + Sync,
    F: Fn(&A) -> P::Authentication + Send + Sync,
{
    type Authentication = A;
    type Error = P::Error;

    fn authorize<'a>(
        &'a self,
        authentication: Option<&'a A>,
        request: &'a Parts,
    ) -> BoxFuture<'a, Result<AuthorizationDecision, Self::Error>> {
        Box::pin(async move {
            let mapped = authentication.map(&self.mapper);
            self.inner.authorize(mapped.as_ref(), request).await
        })
    }
}

/// Authorization success result, with optional behavior.
///
/// The success result of [`AuthorizationProvider`].
#[derive(Debug)]
pub enum AuthorizationDecision {
    /// Authorization success.
    Allow,
    /// Authorization denied by some reasons.
    Deny(AuthorizationDenial),
}

/// Reasons why authorization failed. Part of [`AuthorizationDecision`].
#[derive(Debug)]
pub enum AuthorizationDenial {
    /// Target request not authenticated, so authentication required.
    AuthenticationRequired,
    /// Request is authenticated, but target authentication does not have
    /// required permissions.
    InsufficientPermissions,
    /// Supply a response to the authorization failure handler. The default handler
    /// returns it unchanged; custom handlers may inspect, modify, or replace it.
    /// The layer adapts its byte body to the inner service's response body type.
    /// Composed providers preserve this response and stop evaluating later policies.
    ///
    /// ```
    /// use bytes::Bytes;
    /// use http::{Response, StatusCode};
    /// use tower_http_access_core::authorization::core::AuthorizationDecision;
    /// use tower_http_access_core::authorization::core::AuthorizationDenial;
    ///
    /// let response = Response::builder()
    ///     .status(StatusCode::FORBIDDEN)
    ///     .header("content-type", "text/plain")
    ///     .body(Bytes::from_static(b"Office network required"))
    ///     .unwrap();
    /// let decision = AuthorizationDecision::Deny(AuthorizationDenial::Custom(response));
    /// ```
    Custom(SecurityResponse),
}

#[derive(Debug, thiserror::Error)]
pub enum AuthorizationFailure<E> {
    #[error("authorization denied: {0:?}")]
    Denied(AuthorizationDenial),
    #[error("authorization provider failed")]
    Provider(#[source] E),
}

/// Renders authorization failures using borrowed request metadata and a byte-backed response.
pub trait AuthorizationFailureHandler<E>: Clone + Send + Sync + 'static {
    fn handle(&self, request: &Parts, failure: AuthorizationFailure<E>) -> SecurityResponse;
}

impl<E, F> AuthorizationFailureHandler<E> for F
where
    F: Fn(&Parts, AuthorizationFailure<E>) -> SecurityResponse + Clone + Send + Sync + 'static,
{
    fn handle(&self, request: &Parts, failure: AuthorizationFailure<E>) -> SecurityResponse {
        self(request, failure)
    }
}

#[derive(Clone, Copy, Debug, Default)]
pub struct DefaultAuthorizationFailureHandler;

impl<E> AuthorizationFailureHandler<E> for DefaultAuthorizationFailureHandler {
    fn handle(&self, _: &Parts, failure: AuthorizationFailure<E>) -> SecurityResponse {
        empty_response(match failure {
            AuthorizationFailure::Denied(AuthorizationDenial::AuthenticationRequired) => {
                // NOTE: never happens, because will be delegated to authentication entry point
                StatusCode::UNAUTHORIZED
            }
            AuthorizationFailure::Denied(AuthorizationDenial::InsufficientPermissions) => {
                StatusCode::FORBIDDEN
            }
            AuthorizationFailure::Provider(_) => StatusCode::INTERNAL_SERVER_ERROR,
            AuthorizationFailure::Denied(AuthorizationDenial::Custom(response)) => return response,
        })
    }
}

/// The implementation for situations, when *T* is not [`Clone`].
impl<T> AuthenticationEntryPoint for Arc<T>
where
    T: AuthenticationEntryPoint,
{
    fn commence(&self, request: &Parts) -> SecurityResponse {
        T::commence(self.as_ref(), request)
    }
}

#[cfg(test)]
pub(super) fn assert_builtin_decision(
    actual: AuthorizationDecision,
    expected: AuthorizationDecision,
) {
    assert!(
        matches!(
            (&actual, &expected),
            (AuthorizationDecision::Allow, AuthorizationDecision::Allow)
                | (
                    AuthorizationDecision::Deny(AuthorizationDenial::AuthenticationRequired),
                    AuthorizationDecision::Deny(AuthorizationDenial::AuthenticationRequired)
                )
                | (
                    AuthorizationDecision::Deny(AuthorizationDenial::InsufficientPermissions),
                    AuthorizationDecision::Deny(AuthorizationDenial::InsufficientPermissions)
                )
        ),
        "expected {expected:?}, got {actual:?}"
    );
}
