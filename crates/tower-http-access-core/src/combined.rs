//! Authentication and authorization in a single Tower service.

use crate::authentication::Authenticated;
use crate::authentication::AuthenticationAttempt;
use crate::authentication::RequestAuthenticator;
use crate::authorization::core::AuthenticationEntryPoint;
use crate::authorization::core::AuthorizationDecision;
use crate::authorization::core::AuthorizationDenial;
use crate::authorization::core::AuthorizationFailure;
use crate::authorization::core::AuthorizationFailureHandler;
use crate::authorization::core::AuthorizationProvider;
use crate::authorization::core::DefaultAuthenticationEntryPoint;
use crate::authorization::core::DefaultAuthorizationFailureHandler;
use crate::{DefaultSecurityResponseAdapter, SecurityResponseAdapter};
use futures_util::future::BoxFuture;
use http::{Request, Response};
use std::task::{Context, Poll};
use tower_layer::Layer;
use tower_service::Service;

/// Authenticates and authorizes requests before forwarding them to an inner service.
///
/// The service accepts `http::Request<ReqBody>` and preserves successful
/// `http::Response<ResBody>` values, including streaming bodies. `ReqBody` must be `Send + 'static`.
/// With the default adapter, `ResBody` must implement `From<bytes::Bytes>`. Use
/// [`Self::response_adapter`] to support other body types or response protocols.
/// Only security-generated responses are converted.
///
/// The authenticator, authorizer, entry point, response adapter, and failure handler are
/// cloned for each service and request. Use `Arc` for shared authenticators, authorizers,
/// or entry points that do not implement `Clone`.
/// For Axum this conversion uses `axum::body::Body::from`; other Tower services can use `Bytes`,
/// `http_body_util::Full<Bytes>`, or an application body wrapper implementing `From<Bytes>`.
/// Entry points and failure handlers borrow request parts and return [`crate::SecurityResponse`].
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
/// Use [`crate::authentication::DelegatingRequestAuthenticator`] to combine authentication
/// mechanisms, or [`crate::authorization::all::AllAuthorizationProvider`] to combine authorization
/// checks. Use the separate authentication and authorization layers when the stages need
/// independent placement in the middleware stack.
///
/// ```
/// use http::request::Parts;
/// use tower_http_access_core::authentication::AuthenticationAttempt;
/// use tower_http_access_core::authentication::AuthenticatorError;
/// use tower_http_access_core::authorization::default_auth::AuthenticatedAuthorizationProvider;
/// use tower_http_access_core::SecurityLayer;
///
/// let authenticator = |_: &Parts| async {
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
    R = DefaultSecurityResponseAdapter,
> {
    authenticator: A,
    authorizer: P,
    failure_handler: H,
    authentication_entry_point: E,
    response_adapter: R,
}

impl<A, P> SecurityLayer<A, P>
where
    A: RequestAuthenticator,
    P: AuthorizationProvider<Authentication = A::Authentication>,
{
    /// Combine an authenticator and a authorizer accepting the same identity type.
    pub fn new(authenticator: A, authorizer: P) -> Self {
        Self {
            authenticator,
            authorizer,
            failure_handler: DefaultAuthorizationFailureHandler,
            authentication_entry_point: DefaultAuthenticationEntryPoint,
            response_adapter: DefaultSecurityResponseAdapter,
        }
    }
}

impl<A, P, H, E, R> SecurityLayer<A, P, H, E, R> {
    /// Customize the response when authorization requires authentication.
    pub fn authentication_entry_point<NewE>(
        self,
        entry_point: NewE,
    ) -> SecurityLayer<A, P, H, NewE, R> {
        SecurityLayer {
            authenticator: self.authenticator,
            authorizer: self.authorizer,
            failure_handler: self.failure_handler,
            authentication_entry_point: entry_point,
            response_adapter: self.response_adapter,
        }
    }

    /// Adapt all security-generated responses to the inner service's response body or protocol.
    ///
    /// The adapter runs once for authentication failures, authentication-required denials,
    /// permission denials, and authorization backend errors. Successful inner responses bypass it.
    /// An adapter can translate HTTP failures to gRPC responses and supports body types that do
    /// not implement `From<bytes::Bytes>`. It is cloned for each service and request.
    /// To serve requests, the adapter must implement `SecurityResponseAdapter<ResBody>` and be
    /// `Clone + Send + Sync + 'static`.
    ///
    /// ```
    /// use tower_http_access_core::{SecurityLayer, SecurityResponseAdapter};
    /// use tower_http_access_core::authentication::{AuthenticationAttempt, AuthenticatorError};
    /// use tower_http_access_core::authorization::default_auth::AuthenticatedAuthorizationProvider;
    /// use http::request::Parts;
    ///
    /// fn configure<B, R: SecurityResponseAdapter<B>>(adapter: R) {
    ///     let authenticator = |_: &Parts| async {
    ///         Ok::<_, AuthenticatorError>(AuthenticationAttempt::Authenticated("alex".to_owned()))
    ///     };
    ///     let layer = SecurityLayer::new(
    ///         authenticator,
    ///         AuthenticatedAuthorizationProvider::<String>::new(),
    ///     ).response_adapter(adapter);
    /// }
    /// ```
    pub fn response_adapter<NewR>(self, adapter: NewR) -> SecurityLayer<A, P, H, E, NewR> {
        SecurityLayer {
            authenticator: self.authenticator,
            authorizer: self.authorizer,
            failure_handler: self.failure_handler,
            authentication_entry_point: self.authentication_entry_point,
            response_adapter: adapter,
        }
    }

    /// Customize responses to insufficient permissions and authorizer errors.
    pub fn failure_handler<NewH>(self, handler: NewH) -> SecurityLayer<A, P, NewH, E, R> {
        SecurityLayer {
            authenticator: self.authenticator,
            authorizer: self.authorizer,
            failure_handler: handler,
            authentication_entry_point: self.authentication_entry_point,
            response_adapter: self.response_adapter,
        }
    }
}

impl<A: Clone, P: Clone, H: Clone, E: Clone, R: Clone> Clone for SecurityLayer<A, P, H, E, R> {
    fn clone(&self) -> Self {
        Self {
            authenticator: self.authenticator.clone(),
            authorizer: self.authorizer.clone(),
            failure_handler: self.failure_handler.clone(),
            authentication_entry_point: self.authentication_entry_point.clone(),
            response_adapter: self.response_adapter.clone(),
        }
    }
}

impl<S, A: Clone, P: Clone, H: Clone, E: Clone, R: Clone> Layer<S>
    for SecurityLayer<A, P, H, E, R>
{
    type Service = SecurityService<S, A, P, H, E, R>;

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
    R = DefaultSecurityResponseAdapter,
> {
    inner: S,
    layer: SecurityLayer<A, P, H, E, R>,
}

impl<S: Clone, A: Clone, P: Clone, H: Clone, E: Clone, R: Clone> Clone
    for SecurityService<S, A, P, H, E, R>
{
    fn clone(&self) -> Self {
        Self {
            inner: self.inner.clone(),
            layer: self.layer.clone(),
        }
    }
}

impl<S, A, P, H, E, R, ReqBody, ResBody> Service<Request<ReqBody>>
    for SecurityService<S, A, P, H, E, R>
where
    S: Service<Request<ReqBody>, Response = Response<ResBody>> + Clone + Send + 'static,
    S::Future: Send + 'static,
    S::Error: Send + 'static,
    ReqBody: Send + 'static,
    ResBody: 'static,
    R: SecurityResponseAdapter<ResBody> + Clone + Send + Sync + 'static,
    A: RequestAuthenticator + Clone + 'static,
    P: AuthorizationProvider<Authentication = A::Authentication> + Clone + 'static,
    P::Error: 'static,
    H: AuthorizationFailureHandler<P::Error>,
    E: AuthenticationEntryPoint + Clone,
{
    type Response = Response<ResBody>;
    type Error = S::Error;
    type Future = BoxFuture<'static, Result<Response<ResBody>, S::Error>>;

    fn poll_ready(&mut self, context: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        self.inner.poll_ready(context)
    }

    fn call(&mut self, request: Request<ReqBody>) -> Self::Future {
        let layer = self.layer.clone();
        let clone = self.inner.clone();
        let mut inner = std::mem::replace(&mut self.inner, clone);

        Box::pin(async move {
            let (parts, body) = request.into_parts();
            let authentication = match layer.authenticator.authenticate(&parts).await {
                Ok(AuthenticationAttempt::Authenticated(authentication)) => Some(authentication),
                Ok(AuthenticationAttempt::NotApplicable) => None,
                Err(error) => {
                    return Ok(layer.response_adapter.adapt(error.into_security_response()));
                }
            };
            let decision = layer
                .authorizer
                .authorize(authentication.as_ref(), &parts)
                .await;

            match decision {
                Ok(AuthorizationDecision::Allow) => {
                    let mut request = Request::from_parts(parts, body);
                    if let Some(authentication) = authentication {
                        request
                            .extensions_mut()
                            .insert(Authenticated(authentication));
                    }
                    inner.call(request).await
                }
                Ok(AuthorizationDecision::Deny(AuthorizationDenial::AuthenticationRequired)) => {
                    Ok(layer
                        .response_adapter
                        .adapt(layer.authentication_entry_point.commence(&parts)))
                }
                Ok(AuthorizationDecision::Deny(denial)) => Ok(layer.response_adapter.adapt(
                    layer
                        .failure_handler
                        .handle(&parts, AuthorizationFailure::Denied(denial)),
                )),
                Err(error) => Ok(layer.response_adapter.adapt(
                    layer
                        .failure_handler
                        .handle(&parts, AuthorizationFailure::Provider(error)),
                )),
            }
        })
    }
}

#[cfg(test)]
#[path = "combined_tests.rs"]
mod tests;
