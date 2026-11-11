//! Tower middleware for applying authorization providers to HTTP requests.
//!
//! Use separate layers when authentication and authorization need independent placement,
//! such as authenticating once before applying different authorization rules to nested routers,
//! or running context-enrichment middleware between the stages. Identity is shared through
//! request extensions. When both stages belong together, [`crate::SecurityLayer`] passes the
//! identity directly to authorization in a single service.

use crate::authentication::Authenticated;
use crate::authorization::core::AuthenticationEntryPoint;
use crate::authorization::core::AuthorizationDecision;
use crate::authorization::core::AuthorizationDenial;
use crate::authorization::core::AuthorizationFailure;
use crate::authorization::core::AuthorizationFailureHandler;
use crate::authorization::core::AuthorizationProvider;
use crate::authorization::core::DefaultAuthenticationEntryPoint;
use crate::authorization::core::DefaultAuthorizationFailureHandler;
use bytes::Bytes;
use http::{Request, Response};
use std::{
    future::Future,
    pin::Pin,
    sync::Arc,
    task::{Context, Poll},
};
use tower_layer::Layer;
use tower_service::Service;

/// Authorizes HTTP requests using an identity extracted from request extensions.
///
/// For each request, the service looks up [`Authenticated<P::Authentication>`](Authenticated)
/// and passes the borrowed identity and request parts to [`AuthorizationProvider`].
/// If the extension is absent, the provider receives `None` and decides whether
/// anonymous access is allowed. Only allowed requests reach the inner service.
///
/// Run [`AuthenticationLayer`](crate::authentication::AuthenticationLayer) or custom
/// middleware that inserts the matching `Authenticated<T>` before this layer.
/// This layer does not parse the HTTP `Authorization` header or verify credentials;
/// those operations belong to authentication.
///
/// Available with the `split_auth` feature. Use [`SecurityLayer`](crate::SecurityLayer)
/// to combine authentication and authorization in one layer.
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

impl<S, P, H, E, ReqBody, ResBody> Service<Request<ReqBody>> for AuthorizationService<S, P, H, E>
where
    S: Service<Request<ReqBody>, Response = Response<ResBody>> + Clone + Send + 'static,
    S::Future: Send + 'static,
    S::Error: Send + 'static,
    ReqBody: Send + 'static,
    ResBody: From<Bytes> + 'static,
    P: AuthorizationProvider + 'static,
    P::Authentication: 'static,
    P::Error: 'static,
    H: AuthorizationFailureHandler<P::Error>,
    E: AuthenticationEntryPoint,
{
    type Response = Response<ResBody>;
    type Error = S::Error;
    type Future = Pin<Box<dyn Future<Output = Result<Self::Response, Self::Error>> + Send>>;

    fn poll_ready(&mut self, context: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        self.inner.poll_ready(context)
    }

    fn call(&mut self, request: Request<ReqBody>) -> Self::Future {
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

            match decision {
                Ok(AuthorizationDecision::Allow) => {
                    inner.call(Request::from_parts(parts, body)).await
                }
                Ok(AuthorizationDecision::Deny(AuthorizationDenial::AuthenticationRequired)) => {
                    Ok(authentication_entry_point
                        .commence(&parts)
                        .map(ResBody::from))
                }
                Ok(AuthorizationDecision::Deny(denial)) => Ok(failure_handler
                    .handle(&parts, AuthorizationFailure::Denied(denial))
                    .map(ResBody::from)),
                Err(error) => Ok(failure_handler
                    .handle(&parts, AuthorizationFailure::Provider(error))
                    .map(ResBody::from)),
            }
        })
    }
}
