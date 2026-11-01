//! Tower middleware for applying authorization providers to HTTP requests.
//!
//! Use separate layers when authentication and authorization need independent placement,
//! such as authenticating once before applying different authorization rules to nested routers,
//! or running context-enrichment middleware between the stages. Identity is shared through
//! request extensions. When both stages belong together, [`crate::SecurityLayer`] passes the
//! identity directly to authorization in a single service.

use super::{
    AuthenticationEntryPoint, AuthorizationDecision, AuthorizationDenial, AuthorizationFailure,
    AuthorizationFailureHandler, AuthorizationProvider, DefaultAuthenticationEntryPoint,
    DefaultAuthorizationFailureHandler,
};
use crate::authentication::Authenticated;
use axum::{extract::Request, response::Response};
use std::{
    future::Future,
    pin::Pin,
    sync::Arc,
    task::{Context, Poll},
};
use tower_layer::Layer;
use tower_service::Service;

#[cfg(test)]
#[path = "auth_tower_tests.rs"]
pub(super) mod tests;

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
