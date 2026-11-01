//! Authentication and authorization in a single Tower service.

use crate::{
    authentication::{Authenticated, AuthenticationAttempt, RequestAuthenticator},
    authorization::{
        AuthenticationEntryPoint, AuthorizationDecision, AuthorizationDenial, AuthorizationFailure,
        AuthorizationFailureHandler, AuthorizationProvider, DefaultAuthenticationEntryPoint,
        DefaultAuthorizationFailureHandler,
    },
};
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

/// Authenticates and authorizes requests before forwarding them to an inner service.
///
/// The authenticator's result is passed directly to the authorizer, without using
/// request extensions to communicate between stages. After authorization allows the request,
/// the identity is inserted as [`Authenticated`] for downstream handlers.
///
/// # Authentication contract
///
/// This layer owns authentication for `A::Authentication`. Earlier middleware and the configured
/// authenticator must not insert `Authenticated<A::Authentication>` into request extensions.
/// The authenticator returns its identity through [`AuthenticationAttempt`]; the authorizer
/// receives that result directly, with `NotApplicable` represented as `None`. The combined layer
/// inserts the returned identity only after authorization allows access. It does not read or
/// remove existing authentication extensions.
///
/// This layer is independent of [`crate::SecurityLayerBuilder`]. Use an authentication delegator
/// or an all-of authorizer to compose multiple checks.
///
/// ```
/// use axum::http::request::Parts;
/// use axum_auth_chained::{
///     authentication::{AuthenticationAttempt, AuthenticatorError},
///     authorization::AuthenticatedAuthorizationProvider,
///     SecurityLayer,
/// };
///
/// let authenticator = |_: &mut Parts| async {
///     Ok::<_, AuthenticatorError>(AuthenticationAttempt::Authenticated("alex".to_owned()))
/// };
/// let layer = SecurityLayer::new(
///     authenticator,
///     AuthenticatedAuthorizationProvider::<String>::new(),
/// );
/// ```
///
///
/// Authentication failures return the authenticator's response immediately. Anonymous requests
/// reach the authorizer as `None`. Authentication-required denials invoke the configured entry
/// point; other denials and authorizer errors invoke the failure handler. Defaults return HTTP
/// 401, 403, and 500 respectively.
pub struct SecurityLayer<
    A,
    P,
    H = DefaultAuthorizationFailureHandler,
    E = DefaultAuthenticationEntryPoint,
> {
    authenticator: Arc<A>,
    authorizer: Arc<P>,
    failure_handler: H,
    authentication_entry_point: Arc<E>,
}

impl<A, P> SecurityLayer<A, P>
where
    A: RequestAuthenticator,
    P: AuthorizationProvider<Authentication = A::Authentication>,
{
    /// Combine an authenticator and a authorizer accepting the same identity type.
    pub fn new(authenticator: A, authorizer: P) -> Self {
        Self {
            authenticator: Arc::new(authenticator),
            authorizer: Arc::new(authorizer),
            failure_handler: DefaultAuthorizationFailureHandler,
            authentication_entry_point: Arc::new(DefaultAuthenticationEntryPoint),
        }
    }
}

impl<A, P, H, E> SecurityLayer<A, P, H, E> {
    /// Customize the response when authorization requires authentication.
    pub fn authentication_entry_point<NewE>(
        self,
        entry_point: NewE,
    ) -> SecurityLayer<A, P, H, NewE> {
        SecurityLayer {
            authenticator: self.authenticator,
            authorizer: self.authorizer,
            failure_handler: self.failure_handler,
            authentication_entry_point: Arc::new(entry_point),
        }
    }

    /// Customize responses to insufficient permissions and authorizer errors.
    pub fn failure_handler<NewH>(self, handler: NewH) -> SecurityLayer<A, P, NewH, E> {
        SecurityLayer {
            authenticator: self.authenticator,
            authorizer: self.authorizer,
            failure_handler: handler,
            authentication_entry_point: self.authentication_entry_point,
        }
    }
}

impl<A, P, H: Clone, E> Clone for SecurityLayer<A, P, H, E> {
    fn clone(&self) -> Self {
        Self {
            authenticator: Arc::clone(&self.authenticator),
            authorizer: Arc::clone(&self.authorizer),
            failure_handler: self.failure_handler.clone(),
            authentication_entry_point: Arc::clone(&self.authentication_entry_point),
        }
    }
}

impl<S, A, P, H: Clone, E> Layer<S> for SecurityLayer<A, P, H, E> {
    type Service = SecurityService<S, A, P, H, E>;

    fn layer(&self, inner: S) -> Self::Service {
        SecurityService {
            inner,
            layer: self.clone(),
        }
    }
}

/// A service that passes an authenticator's identity directly to an authorization authorizer.
pub struct SecurityService<
    S,
    A,
    P,
    H = DefaultAuthorizationFailureHandler,
    E = DefaultAuthenticationEntryPoint,
> {
    inner: S,
    layer: SecurityLayer<A, P, H, E>,
}

impl<S: Clone, A, P, H: Clone, E> Clone for SecurityService<S, A, P, H, E> {
    fn clone(&self) -> Self {
        Self {
            inner: self.inner.clone(),
            layer: self.layer.clone(),
        }
    }
}

impl<S, A, P, H, E> Service<Request> for SecurityService<S, A, P, H, E>
where
    S: Service<Request, Response = Response> + Clone + Send + 'static,
    S::Future: Send + 'static,
    S::Error: Send + 'static,
    A: RequestAuthenticator + 'static,
    P: AuthorizationProvider<Authentication = A::Authentication> + 'static,
    P::Error: 'static,
    H: AuthorizationFailureHandler<P::Error>,
    E: AuthenticationEntryPoint,
{
    type Response = Response;
    type Error = S::Error;
    type Future = BoxFuture<'static, Result<Response, S::Error>>;

    fn poll_ready(&mut self, context: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        self.inner.poll_ready(context)
    }

    fn call(&mut self, request: Request) -> Self::Future {
        let layer = self.layer.clone();
        let clone = self.inner.clone();
        let mut inner = std::mem::replace(&mut self.inner, clone);

        Box::pin(async move {
            let (mut parts, body) = request.into_parts();
            let authentication = match layer.authenticator.authenticate(&mut parts).await {
                Ok(AuthenticationAttempt::Authenticated(authentication)) => Some(authentication),
                Ok(AuthenticationAttempt::NotApplicable) => None,
                Err(error) => return Ok(error.into_response()),
            };
            let decision = layer
                .authorizer
                .authorize(authentication.as_ref(), &parts)
                .await;
            let mut request = Request::from_parts(parts, body);

            match decision {
                Ok(AuthorizationDecision::Allow) => {
                    if let Some(authentication) = authentication {
                        request
                            .extensions_mut()
                            .insert(Authenticated(authentication));
                    }
                    inner.call(request).await
                }
                Ok(AuthorizationDecision::Deny(AuthorizationDenial::AuthenticationRequired)) => {
                    Ok(layer.authentication_entry_point.commence(request))
                }
                Ok(AuthorizationDecision::Deny(denial)) => Ok(layer
                    .failure_handler
                    .handle(request, AuthorizationFailure::Denied(denial))),
                Err(error) => Ok(layer
                    .failure_handler
                    .handle(request, AuthorizationFailure::Provider(error))),
            }
        })
    }
}

#[cfg(test)]
#[path = "combined_tests.rs"]
mod tests;
