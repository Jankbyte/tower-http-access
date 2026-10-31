//! Request authorization and unauthenticated-request handling.
//!
//! Authorization runs after authentication. It reads the typed identity stored in request
//! extensions and passes the original request parts to an
//! [`AuthorizationProvider`] to decide whether the request is allowed.
//!
//! [`AuthorizationLayer`] returns an [`AuthenticationEntryPoint`] response when authentication is
//! required, or delegates other denials and provider errors to an [`AuthorizationFailureHandler`].
//! Applications that only require a valid identity can use [`AuthenticatedAuthorizationProvider`].

use axum::{
    extract::Request,
    http::{StatusCode, request::Parts},
    response::{IntoResponse, Response},
};
use std::{
    convert::Infallible,
    future::Future,
    marker::PhantomData,
    pin::Pin,
    sync::Arc,
    task::{Context, Poll},
};
use tower_layer::Layer;
use tower_service::Service;

use crate::authentication::Authenticated;

/// The authentication entrypoint, that uses by [`AuthorizationService`]
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

/// Default implementation of [`AuthorizationProvider`], that checks only fact of authentication
/// and does not inspect request metadata.
///
/// The behavior of implementation:
///
/// * If authentication found - request authorized.
/// * Otherwise, it's return [`AuthorizationDecision::Deny`] with [`AuthorizationDenial::AuthenticationRequired`], that equivalent to *401*.
///
pub struct AuthenticatedAuthorizationProvider<A>(PhantomData<fn() -> A>);

impl<A> AuthenticatedAuthorizationProvider<A> {
    pub fn new() -> Self {
        Self(PhantomData)
    }
}

impl<A> Default for AuthenticatedAuthorizationProvider<A> {
    fn default() -> Self {
        Self::new()
    }
}

impl<A> AuthorizationProvider for AuthenticatedAuthorizationProvider<A>
where
    A: Send + Sync,
{
    type Authentication = A;
    type Error = Infallible;

    fn authorize<'a>(
        &'a self,
        authentication: Option<&'a Self::Authentication>,
        _: &'a Parts,
    ) -> Pin<Box<dyn Future<Output = Result<AuthorizationDecision, Self::Error>> + Send + 'a>> {
        Box::pin(async move {
            Ok(match authentication {
                Some(_) => AuthorizationDecision::Allow,
                None => AuthorizationDecision::Deny(AuthorizationDenial::AuthenticationRequired),
            })
        })
    }
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

pub struct AuthorizationLayer<P, H, E> {
    provider: Arc<P>,
    failure_handler: H,
    authentication_entry_point: Arc<E>,
}

pub struct AuthorizationLayerBuilder<
    P,
    E = DefaultAuthenticationEntryPoint,
    H = DefaultAuthorizationFailureHandler,
> {
    provider: P,
    failure_handler: H,
    authentication_entry_point: E,
}

impl AuthorizationLayer<(), (), ()> {
    pub fn builder<P>(
        provider: P,
    ) -> AuthorizationLayerBuilder<
        P,
        DefaultAuthenticationEntryPoint,
        DefaultAuthorizationFailureHandler,
    > {
        AuthorizationLayerBuilder {
            provider,
            failure_handler: DefaultAuthorizationFailureHandler,
            authentication_entry_point: DefaultAuthenticationEntryPoint,
        }
    }
}

impl<P, E, H> AuthorizationLayerBuilder<P, E, H>
where
    P: AuthorizationProvider,
{
    /// Replace default failure handler to custom.
    pub fn failure_handler<NewHandler>(
        self,
        failure_handler: NewHandler,
    ) -> AuthorizationLayerBuilder<P, E, NewHandler> {
        AuthorizationLayerBuilder {
            provider: self.provider,
            failure_handler,
            authentication_entry_point: self.authentication_entry_point,
        }
    }

    /// Replace default authentication entrypoint to custom.
    pub fn authentication_entry_point<NewEntrypoint>(
        self,
        authentication_entry_point: NewEntrypoint,
    ) -> AuthorizationLayerBuilder<P, NewEntrypoint, H> {
        AuthorizationLayerBuilder {
            provider: self.provider,
            failure_handler: self.failure_handler,
            authentication_entry_point,
        }
    }

    /// Build authorization layer.
    pub fn build(self) -> AuthorizationLayer<P, H, E> {
        AuthorizationLayer {
            provider: Arc::new(self.provider),
            failure_handler: self.failure_handler,
            authentication_entry_point: Arc::new(self.authentication_entry_point),
        }
    }
}

impl<P, H: Clone, E> Clone for AuthorizationLayer<P, H, E> {
    fn clone(&self) -> Self {
        Self {
            provider: Arc::clone(&self.provider),
            failure_handler: self.failure_handler.clone(),
            authentication_entry_point: Arc::clone(&self.authentication_entry_point),
        }
    }
}

/// Tower wrapper for [`AuthorizationService`].
impl<S, P, H, E> Layer<S> for AuthorizationLayer<P, H, E>
where
    H: Clone,
{
    type Service = AuthorizationService<S, P, H, E>;

    fn layer(&self, inner: S) -> Self::Service {
        AuthorizationService {
            inner,
            provider: Arc::clone(&self.provider),
            failure_handler: self.failure_handler.clone(),
            authentication_entry_point: Arc::clone(&self.authentication_entry_point),
        }
    }
}

/// Service for authorize HTTP-request.
pub struct AuthorizationService<S, P, H, E> {
    inner: S,
    provider: Arc<P>,
    failure_handler: H,
    authentication_entry_point: Arc<E>,
}

impl<S: Clone, P, H: Clone, E> Clone for AuthorizationService<S, P, H, E> {
    fn clone(&self) -> Self {
        Self {
            inner: self.inner.clone(),
            provider: Arc::clone(&self.provider),
            failure_handler: self.failure_handler.clone(),
            authentication_entry_point: Arc::clone(&self.authentication_entry_point),
        }
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

impl<S, P, H, E> Service<Request> for AuthorizationService<S, P, H, E>
where
    S: Service<Request, Response = Response> + Clone + Send + 'static,
    S::Future: Send + 'static,
    S::Error: Send + 'static,
    P: AuthorizationProvider + 'static,
    P::Authentication: 'static,
    P::Error: 'static,
    H: AuthorizationFailureHandler<P::Error>,
    E: AuthenticationEntryPoint,
{
    type Response = Response;
    type Error = S::Error;
    type Future = Pin<Box<dyn Future<Output = Result<Self::Response, Self::Error>> + Send>>;

    fn poll_ready(&mut self, context: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        self.inner.poll_ready(context)
    }

    fn call(&mut self, request: Request) -> Self::Future {
        let provider = Arc::clone(&self.provider);
        let failure_handler = self.failure_handler.clone();
        let authentication_entry_point = Arc::clone(&self.authentication_entry_point);
        let clone = self.inner.clone();
        let mut inner = std::mem::replace(&mut self.inner, clone);

        Box::pin(async move {
            let (parts, body) = request.into_parts();
            let decision = provider
                .authorize(
                    parts
                        .extensions
                        .get::<Authenticated<P::Authentication>>()
                        .map(Authenticated::as_inner),
                    &parts,
                )
                .await;
            let request = Request::from_parts(parts, body);

            match decision {
                Ok(AuthorizationDecision::Allow) => inner.call(request).await,
                Ok(AuthorizationDecision::Deny(AuthorizationDenial::AuthenticationRequired)) => {
                    Ok(authentication_entry_point.commence(request))
                }
                Ok(AuthorizationDecision::Deny(denial)) => {
                    Ok(failure_handler.handle(request, AuthorizationFailure::Denied(denial)))
                }
                Err(error) => {
                    Ok(failure_handler.handle(request, AuthorizationFailure::Provider(error)))
                }
            }
        })
    }
}

#[cfg(test)]
#[path = "authorization_tests.rs"]
mod tests;
