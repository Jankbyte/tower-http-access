//! Select one complete Tower middleware stack using ordered request matchers.
//!
//! The first matching chain is final, including errors and denials. Matchers inspect
//! request parts before any selected middleware runs. Matching uses the URI visible
//! here, so place this layer outside nested routers to match full application paths.
//! Each stack wraps a clone of the same application service. Stacks may use different
//! identity types but must have the same request, response, and error types.
//!
//! A fallback is required: configure another stack, explicit pass-through, or denial.
//!
//! ```
//! use axum::{Router, routing::get};
//! use tower_http_access::{SecurityChainLayer, SecurityLayer,
//!     authentication::{AuthenticationAttempt, AuthenticatorError},
//!     authorization::AuthenticatedAuthorizationProvider,
//!     request_matchers::PathPatternRequestMatcher};
//!
//! let authentication = |_: &mut http::request::Parts| async {
//!     Ok::<_, AuthenticatorError>(AuthenticationAttempt::Authenticated("alice".to_owned()))
//! };
//! let security = SecurityChainLayer::builder()
//!     .chain(PathPatternRequestMatcher::new("/private/{*rest}")?,
//!         SecurityLayer::new(authentication, AuthenticatedAuthorizationProvider::<String>::new()))
//!     .fallback_deny()
//!     .build()?;
//! let app: Router = Router::new()
//!     .route("/private/hello", get(|| async { "hello" }))
//!     .layer(security);
//! # Ok::<(), Box<dyn std::error::Error>>(())
//! ```
//!
//! The implementation inspired by [`FilterChainProxy`](https://docs.spring.io/spring-security/site/docs/current/api/org/springframework/security/web/FilterChainProxy.html) from Java based Spring Security framework.
use crate::request_matchers::RequestMatcher;
use bytes::Bytes;
use futures_util::future::BoxFuture;
use http::{Request, Response, StatusCode};
use std::{
    sync::Arc,
    task::{Context, Poll},
};
use tower::{ServiceExt, util::BoxCloneSyncService};
use tower_layer::Layer;
use tower_service::Service;

type BoxService<B, R, E> = BoxCloneSyncService<Request<B>, Response<R>, E>;
type Factory<S, B, R, E> = Arc<dyn Fn(S) -> BoxService<B, R, E> + Send + Sync>;
type ServiceChain<B, R, E> = (Arc<dyn RequestMatcher>, BoxService<B, R, E>);
type Chain<S, B, R, E> = (Arc<dyn RequestMatcher>, Factory<S, B, R, E>);

/// An ordered collection of middleware stacks and an explicit fallback.
/// Available with the `filter_chain` feature.
pub struct SecurityChainLayer<S, B, R, E> {
    chains: Vec<Chain<S, B, R, E>>,
    fallback: Factory<S, B, R, E>,
}

impl<S, B, R, E> Clone for SecurityChainLayer<S, B, R, E> {
    fn clone(&self) -> Self {
        Self {
            chains: self.chains.clone(),
            fallback: Arc::clone(&self.fallback),
        }
    }
}

/// Configures chains in declaration order. Call a fallback method before `build`.
pub struct SecurityChainBuilder<S, B, R, E> {
    chains: Vec<Chain<S, B, R, E>>,
    fallback: Option<Factory<S, B, R, E>>,
}

/// Returned when no fallback was explicitly configured.
#[derive(Debug, thiserror::Error)]
#[error("configure a security chain fallback before building")]
pub struct MissingSecurityChainFallback;

impl<S, B, R, E> SecurityChainLayer<S, B, R, E> {
    pub fn builder() -> SecurityChainBuilder<S, B, R, E> {
        SecurityChainBuilder {
            chains: Vec::new(),
            fallback: None,
        }
    }
}

fn factory<S, B, R, E, L>(layer: L) -> Factory<S, B, R, E>
where
    L: Layer<S> + Send + Sync + 'static,
    L::Service:
        Service<Request<B>, Response = Response<R>, Error = E> + Clone + Send + Sync + 'static,
    <L::Service as Service<Request<B>>>::Future: Send + 'static,
{
    Arc::new(move |inner| BoxCloneSyncService::new(layer.layer(inner)))
}

impl<S, B, R, E> SecurityChainBuilder<S, B, R, E> {
    /// Add a stack. Earlier matching stacks take precedence, regardless of specificity.
    /// Matchers must be fast and cannot depend on middleware inside their stack.
    pub fn chain<M, L>(mut self, matcher: M, layer: L) -> Self
    where
        M: RequestMatcher + 'static,
        L: Layer<S> + Send + Sync + 'static,
        L::Service:
            Service<Request<B>, Response = Response<R>, Error = E> + Clone + Send + Sync + 'static,
        <L::Service as Service<Request<B>>>::Future: Send + 'static,
    {
        self.chains.push((Arc::new(matcher), factory(layer)));
        self
    }

    /// Use this stack when no matcher applies. Replaces any previous fallback.
    pub fn fallback<L>(mut self, layer: L) -> Self
    where
        L: Layer<S> + Send + Sync + 'static,
        L::Service:
            Service<Request<B>, Response = Response<R>, Error = E> + Clone + Send + Sync + 'static,
        <L::Service as Service<Request<B>>>::Future: Send + 'static,
    {
        self.fallback = Some(factory(layer));
        self
    }

    /// Explicitly allow unmatched requests to reach the unwrapped application.
    pub fn fallback_passthrough(self) -> Self
    where
        S: Service<Request<B>, Response = Response<R>, Error = E> + Clone + Send + Sync + 'static,
        S::Future: Send + 'static,
    {
        self.fallback(tower_layer::Identity::new())
    }

    /// Return an empty HTTP 403 for unmatched requests without calling the application.
    /// For protocol-specific rejection responses, use `fallback` with a custom layer.
    pub fn fallback_deny(mut self) -> Self
    where
        B: 'static,
        R: From<Bytes> + Send + 'static,
        E: 'static,
    {
        self.fallback = Some(Arc::new(|_: S| {
            BoxCloneSyncService::new(tower::service_fn(|_: Request<B>| async {
                let mut response = Response::new(R::from(Bytes::new()));
                *response.status_mut() = StatusCode::FORBIDDEN;
                Ok::<_, E>(response)
            }))
        }));
        self
    }

    pub fn build(self) -> Result<SecurityChainLayer<S, B, R, E>, MissingSecurityChainFallback> {
        Ok(SecurityChainLayer {
            chains: self.chains,
            fallback: self.fallback.ok_or(MissingSecurityChainFallback)?,
        })
    }
}

impl<S: Clone, B, R, E> Layer<S> for SecurityChainLayer<S, B, R, E> {
    type Service = SecurityChainService<B, R, E>;

    fn layer(&self, inner: S) -> Self::Service {
        SecurityChainService {
            chains: self
                .chains
                .iter()
                .map(|(matcher, make)| (Arc::clone(matcher), make(inner.clone())))
                .collect(),
            fallback: (self.fallback)(inner),
        }
    }
}

/// Dispatches to the selected stack and waits for that service's readiness.
///
/// `poll_ready` accepts dispatch immediately; readiness and errors from the selected
/// stack are handled inside the returned future. Unselected stacks are never polled.
/// This does not reserve capacity before accepting a request: put a concurrency
/// limit outside this layer when admission backpressure is required. Service clones
/// must preserve shared resources such as queues and concurrency limits.
pub struct SecurityChainService<B, R, E> {
    chains: Vec<ServiceChain<B, R, E>>,
    fallback: BoxService<B, R, E>,
}

impl<B, R, E> Clone for SecurityChainService<B, R, E> {
    fn clone(&self) -> Self {
        Self {
            chains: self.chains.clone(),
            fallback: self.fallback.clone(),
        }
    }
}

impl<B, R, E> Service<Request<B>> for SecurityChainService<B, R, E>
where
    B: Send + 'static,
    R: 'static,
    E: 'static,
{
    type Response = Response<R>;
    type Error = E;
    type Future = BoxFuture<'static, Result<Self::Response, E>>;

    fn poll_ready(&mut self, _: &mut Context<'_>) -> Poll<Result<(), E>> {
        Poll::Ready(Ok(()))
    }

    fn call(&mut self, request: Request<B>) -> Self::Future {
        let (parts, body) = request.into_parts();
        let selected = self
            .chains
            .iter_mut()
            .find(|(matcher, _)| matcher.matches(&parts))
            .map(|(_, service)| service)
            .unwrap_or(&mut self.fallback);
        // Move the selected instance into the future so readiness and call operate
        // on the same instance; retain a clone for subsequent requests.
        let replacement = selected.clone();
        let service = std::mem::replace(selected, replacement);
        Box::pin(service.oneshot(Request::from_parts(parts, body)))
    }
}

#[cfg(test)]
#[path = "filter_chain_tests.rs"]
mod tests;
