//! Tower middleware for applying authentication to HTTP requests.
//!
//! Use separate layers when authentication and authorization need independent placement,
//! such as authenticating once before applying different authorization rules to nested routers,
//! or running context-enrichment middleware between the stages. Identity is shared through
//! request extensions. When both stages belong together, [`crate::SecurityLayer`] passes the
//! identity directly to authorization in a single service.

use super::{Authenticated, AuthenticationAttempt, RequestAuthenticator};
use axum::{
    extract::Request,
    response::{IntoResponse, Response},
};
use futures_util::future::BoxFuture;
use std::{
    sync::Arc,
    task::{Context, Poll},
};
use tower_layer::Layer;
use tower_service::Service;

/// Wrapper for [`AuthenticationService`].
pub struct AuthenticationLayer<A> {
    authenticator: Arc<A>,
}

impl<A> AuthenticationLayer<A> {
    /// Create new layer from [`RequestAuthenticator`].
    pub fn new(authenticator: A) -> Self {
        Self {
            authenticator: Arc::new(authenticator),
        }
    }

    /// Create new layer from shared authenticator.
    ///
    /// This method can be used for situations, when we want reuse authenticator
    /// in multiple places. For example: put authenticator in multiple layers.
    pub fn new_shared(authenticator: Arc<A>) -> Self {
        Self { authenticator }
    }
}

impl<A> Clone for AuthenticationLayer<A> {
    fn clone(&self) -> Self {
        Self {
            authenticator: Arc::clone(&self.authenticator),
        }
    }
}

impl<S, A> Layer<S> for AuthenticationLayer<A> {
    type Service = AuthenticationService<S, A>;

    fn layer(&self, inner: S) -> Self::Service {
        AuthenticationService {
            inner,
            authenticator: Arc::clone(&self.authenticator),
        }
    }
}

pub struct AuthenticationService<S, A> {
    inner: S,
    authenticator: Arc<A>,
}

impl<S: Clone, A> Clone for AuthenticationService<S, A> {
    fn clone(&self) -> Self {
        Self {
            inner: self.inner.clone(),
            authenticator: Arc::clone(&self.authenticator),
        }
    }
}

impl<S, A> Service<Request> for AuthenticationService<S, A>
where
    S: Service<Request, Response = Response> + Clone + Send + 'static,
    S::Future: Send + 'static,
    S::Error: Send + 'static,
    A: RequestAuthenticator + 'static,
{
    type Response = Response;
    type Error = S::Error;
    type Future = BoxFuture<'static, Result<Response, S::Error>>;

    fn poll_ready(&mut self, context: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        self.inner.poll_ready(context)
    }

    fn call(&mut self, request: Request) -> Self::Future {
        let authenticator = Arc::clone(&self.authenticator);
        let clone = self.inner.clone();
        let mut inner = std::mem::replace(&mut self.inner, clone);

        Box::pin(async move {
            let (mut parts, body) = request.into_parts();
            match authenticator.authenticate(&mut parts).await {
                Ok(AuthenticationAttempt::NotApplicable) => (),
                Ok(AuthenticationAttempt::Authenticated(authentication)) => {
                    parts.extensions.insert(Authenticated(authentication));
                }
                Err(error) => return Ok(error.into_response()),
            }
            inner.call(Request::from_parts(parts, body)).await
        })
    }
}

#[cfg(test)]
#[path = "auth_tower_tests.rs"]
pub(super) mod tests;
