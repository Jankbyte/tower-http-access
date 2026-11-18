//! Authentication entry points and request-based delegation.

use crate::{SecurityResponse, response::empty_response};
use futures_util::future::BoxFuture;
use http::{StatusCode, request::Parts};
use std::{future::Future, sync::Arc};

/// The authentication entrypoint, that uses by [`crate::security_layer::SecurityService`]
/// to delegate unauthenticated requests. It borrows request metadata and returns buffered bytes.
/// The middleware converts the response body to the type expected by the inner service.
///
/// Implementations may await shared state, session operations, or challenge creation.
/// They must not perform blocking I/O or hold blocking mutex guards across awaits.
///
/// This should be used for providing schema of authentication, when credentials is not set.
///
/// For example, if endpoint requires `Basic` authentication, but credentials (header) is not provided,
/// service will execute this endpoint, that returns response with `WWW-Authenticate` header.
pub trait AuthenticationEntryPoint: Send + Sync + 'static {
    fn commence<'a>(&'a self, request: &'a Parts) -> BoxFuture<'a, SecurityResponse>;
}

/// Create an authentication entry point from an asynchronous closure.
///
/// The closure must return an owned future. Clone any needed request metadata
/// before entering its async block; custom trait implementations may borrow it.
impl<F, Fut> AuthenticationEntryPoint for F
where
    F: Fn(&Parts) -> Fut + Send + Sync + 'static,
    Fut: Future<Output = SecurityResponse> + Send + 'static,
{
    fn commence<'a>(&'a self, request: &'a Parts) -> BoxFuture<'a, SecurityResponse> {
        Box::pin(self(request))
    }
}

/// The default implementation of [`AuthenticationEntryPoint`] that just returns *401*.
#[derive(Clone, Copy, Debug, Default)]
pub struct DefaultAuthenticationEntryPoint;

impl AuthenticationEntryPoint for DefaultAuthenticationEntryPoint {
    fn commence<'a>(&'a self, _: &'a Parts) -> BoxFuture<'a, SecurityResponse> {
        Box::pin(async { empty_response(StatusCode::UNAUTHORIZED) })
    }
}

/// The implementation for situations, when *T* is not [`Clone`].
impl<T> AuthenticationEntryPoint for Arc<T>
where
    T: AuthenticationEntryPoint + ?Sized,
{
    fn commence<'a>(&'a self, request: &'a Parts) -> BoxFuture<'a, SecurityResponse> {
        T::commence(self.as_ref(), request)
    }
}

#[cfg(feature = "request_matcher")]
pub use super::delegating::{
    DelegatingAuthenticationEntryPoint, DelegatingAuthenticationEntryPointBuilder,
};
