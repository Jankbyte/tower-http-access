//! Request authorization and unauthenticated-request handling.
//!
//! Authorization runs after authentication. It reads the typed identity stored in request
//! extensions, maps the request into an application-defined context, and asks an
//! [`AuthorizationProvider`] whether the request is allowed.
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

/// The context extractor, used by [`AuthorizationService`] for convert [`axum::http::request::Parts`] into context.
pub trait AuthorizationContextMapper<C>: Clone + Send + Sync + 'static {
    fn map(&self, parts: &Parts) -> C;
}

/// Create context mapper from closure.
impl<C, F> AuthorizationContextMapper<C> for F
where
    F: Fn(&Parts) -> C + Clone + Send + Sync + 'static,
{
    fn map(&self, parts: &Parts) -> C {
        self(parts)
    }
}

/// The stub for empty context. Should be use with [`AuthenticatedAuthorizationProvider`] while creating [`AuthorizationLayer`].
pub fn empty_context_mapper(_: &Parts) {}

/// The authorization provider that authorize target authentication by context.
///
/// The source of permissions may be, for example:
///
/// * [`Self::Authentication`] - we can store permissions/roles inside authentication, and extract
///   that on authentication layer, but verify here.
/// * Database - we can store permissions in some database, find permissions by [`Self::Authentication`] principals
///   and match with [`Self::Context`] data.
///
pub trait AuthorizationProvider: Send + Sync {
    /// The authentication type.
    type Authentication: Send + Sync;
    /// The context.
    ///
    /// For example: it may [`http::request::Parts`].
    type Context: Send;
    /// Error produced by `authorize` method.
    type Error: std::error::Error + Send + Sync;

    fn authorize<'a>(
        &'a self,
        authentication: Option<&'a Self::Authentication>,
        context: Self::Context,
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
/// and does not verify context.
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
    type Context = ();
    type Error = Infallible;

    fn authorize<'a>(
        &'a self,
        authentication: Option<&'a Self::Authentication>,
        _: Self::Context,
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

pub struct AuthorizationLayer<P, F, H, E> {
    provider: Arc<P>,
    context: F,
    failure_handler: H,
    authentication_entry_point: Arc<E>,
}

pub struct AuthorizationLayerBuilder<
    P,
    F,
    E = DefaultAuthenticationEntryPoint,
    H = DefaultAuthorizationFailureHandler,
> {
    provider: P,
    context: F,
    failure_handler: H,
    authentication_entry_point: E,
}

impl AuthorizationLayer<(), (), (), ()> {
    pub fn builder<P, F>(
        provider: P,
        context: F,
    ) -> AuthorizationLayerBuilder<
        P,
        F,
        DefaultAuthenticationEntryPoint,
        DefaultAuthorizationFailureHandler,
    > {
        AuthorizationLayerBuilder {
            provider,
            context,
            failure_handler: DefaultAuthorizationFailureHandler,
            authentication_entry_point: DefaultAuthenticationEntryPoint,
        }
    }
}

impl<P, F, E, H> AuthorizationLayerBuilder<P, F, E, H>
where
    P: AuthorizationProvider,
{
    /// Replace default failure handler to custom.
    pub fn failure_handler<NewHandler>(
        self,
        failure_handler: NewHandler,
    ) -> AuthorizationLayerBuilder<P, F, E, NewHandler> {
        AuthorizationLayerBuilder {
            provider: self.provider,
            context: self.context,
            failure_handler,
            authentication_entry_point: self.authentication_entry_point,
        }
    }

    /// Replace default authentication entrypoint to custom.
    pub fn authentication_entry_point<NewEntrypoint>(
        self,
        authentication_entry_point: NewEntrypoint,
    ) -> AuthorizationLayerBuilder<P, F, NewEntrypoint, H> {
        AuthorizationLayerBuilder {
            provider: self.provider,
            context: self.context,
            failure_handler: self.failure_handler,
            authentication_entry_point,
        }
    }

    /// Build authorization layer.
    pub fn build(self) -> AuthorizationLayer<P, F, H, E> {
        AuthorizationLayer {
            provider: Arc::new(self.provider),
            context: self.context,
            failure_handler: self.failure_handler,
            authentication_entry_point: Arc::new(self.authentication_entry_point),
        }
    }
}

impl<P, F: Clone, H: Clone, E> Clone for AuthorizationLayer<P, F, H, E> {
    fn clone(&self) -> Self {
        Self {
            provider: Arc::clone(&self.provider),
            context: self.context.clone(),
            failure_handler: self.failure_handler.clone(),
            authentication_entry_point: Arc::clone(&self.authentication_entry_point),
        }
    }
}

/// Tower wrapper for [`AuthorizationService`].
impl<S, P, F, H, E> Layer<S> for AuthorizationLayer<P, F, H, E>
where
    F: Clone,
    H: Clone,
{
    type Service = AuthorizationService<S, P, F, H, E>;

    fn layer(&self, inner: S) -> Self::Service {
        AuthorizationService {
            inner,
            provider: Arc::clone(&self.provider),
            context: self.context.clone(),
            failure_handler: self.failure_handler.clone(),
            authentication_entry_point: Arc::clone(&self.authentication_entry_point),
        }
    }
}

/// Service for authorize HTTP-request.
pub struct AuthorizationService<S, P, F, H, E> {
    inner: S,
    provider: Arc<P>,
    context: F,
    failure_handler: H,
    authentication_entry_point: Arc<E>,
}

impl<S: Clone, P, F: Clone, H: Clone, E> Clone for AuthorizationService<S, P, F, H, E> {
    fn clone(&self) -> Self {
        Self {
            inner: self.inner.clone(),
            provider: Arc::clone(&self.provider),
            context: self.context.clone(),
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

impl<S, P, F, H, E> Service<Request> for AuthorizationService<S, P, F, H, E>
where
    S: Service<Request, Response = Response> + Clone + Send + 'static,
    S::Future: Send + 'static,
    S::Error: Send + 'static,
    P: AuthorizationProvider + 'static,
    P::Authentication: 'static,
    P::Context: Send + 'static,
    P::Error: 'static,
    F: AuthorizationContextMapper<P::Context>,
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
        let context = self.context.clone();
        let failure_handler = self.failure_handler.clone();
        let authentication_entry_point = Arc::clone(&self.authentication_entry_point);
        let clone = self.inner.clone();
        let mut inner = std::mem::replace(&mut self.inner, clone);

        Box::pin(async move {
            let (parts, body) = request.into_parts();
            let authorization_context = context.map(&parts);
            let decision = provider
                .authorize(
                    parts
                        .extensions
                        .get::<Authenticated<P::Authentication>>()
                        .map(Authenticated::as_inner),
                    authorization_context,
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
