//! Shared authorization contracts, identity adapters, decisions, and failure handling.

use axum::{
    extract::Request,
    http::{StatusCode, request::Parts},
    response::{IntoResponse, Response},
};
use futures_util::future::BoxFuture;
use std::{future::Future, marker::PhantomData, pin::Pin, sync::Arc};

/// The authentication entrypoint, that uses by [`super::AuthorizationService`]
/// to delegate unauthenticated requests.
///
/// This should be used for providing schema of authentication, when credentials is not set.
///
/// For example, if endpoint requires `Basic` authentication, but credentials (header) is not provided,
/// service will execute this endpoint, that returns response with `WWW-Authenticate` header.
pub trait AuthenticationEntryPoint: Send + Sync + 'static {
    fn commence(&self, request: Request) -> Response;
}

/// Create authentication entrypoint from closure.
impl<F, R> AuthenticationEntryPoint for F
where
    F: Fn(Request) -> R + Send + Sync + 'static,
    R: IntoResponse,
{
    fn commence(&self, request: Request) -> Response {
        self(request).into_response()
    }
}

/// The default implementation of [`AuthenticationEntryPoint`] that just returns *401*.
#[derive(Clone, Copy, Debug, Default)]
pub struct DefaultAuthenticationEntryPoint;

impl AuthenticationEntryPoint for DefaultAuthenticationEntryPoint {
    fn commence(&self, _: Request) -> Response {
        StatusCode::UNAUTHORIZED.into_response()
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
    /// use axum_auth_chained::authorization::{
    ///     AuthenticatedAuthorizationProvider, AuthorizationProviderExt,
    /// };
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
    /// use axum_auth_chained::authorization::{AuthorizationProvider, AuthorizationProviderExt};
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
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AuthorizationDecision {
    /// Authorization success.
    Allow,
    /// Authorization denied by some reasons.
    Deny(AuthorizationDenial),
}

/// Reasons why authorization failed. Part of [`AuthorizationDecision`].
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AuthorizationDenial {
    /// Target request not authenticated, so authentication required.
    AuthenticationRequired,
    /// Request is authenticated, but target authentication does not have
    /// required permissions.
    InsufficientPermissions,
}

#[derive(Debug, thiserror::Error)]
pub enum AuthorizationFailure<E> {
    #[error("authorization denied: {0:?}")]
    Denied(AuthorizationDenial),
    #[error("authorization provider failed")]
    Provider(#[source] E),
}

pub trait AuthorizationFailureHandler<E>: Clone + Send + Sync + 'static {
    fn handle(&self, request: Request, failure: AuthorizationFailure<E>) -> Response;
}

impl<E, F, R> AuthorizationFailureHandler<E> for F
where
    F: Fn(Request, AuthorizationFailure<E>) -> R + Clone + Send + Sync + 'static,
    R: IntoResponse,
{
    fn handle(&self, request: Request, failure: AuthorizationFailure<E>) -> Response {
        self(request, failure).into_response()
    }
}

#[derive(Clone, Copy, Debug, Default)]
pub struct DefaultAuthorizationFailureHandler;

impl<E> AuthorizationFailureHandler<E> for DefaultAuthorizationFailureHandler {
    fn handle(&self, _: Request, failure: AuthorizationFailure<E>) -> Response {
        match failure {
            AuthorizationFailure::Denied(AuthorizationDenial::AuthenticationRequired) => {
                // NOTE: never happens, because will be delegated to authentication entry point
                StatusCode::UNAUTHORIZED
            }
            AuthorizationFailure::Denied(AuthorizationDenial::InsufficientPermissions) => {
                StatusCode::FORBIDDEN
            }
            AuthorizationFailure::Provider(_) => StatusCode::INTERNAL_SERVER_ERROR,
        }
        .into_response()
    }
}

/// The implementation for situations, when *T* is not [`Clone`].
impl<T> AuthenticationEntryPoint for Arc<T>
where
    T: AuthenticationEntryPoint,
{
    fn commence(&self, request: Request) -> Response {
        T::commence(self.as_ref(), request)
    }
}
