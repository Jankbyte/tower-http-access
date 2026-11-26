//! Authentication and authorization in a single Tower service.
use crate::authentication::Authenticated;
#[cfg(feature = "authorizers")]
use crate::authorization::AuthenticatedAuthorizationProvider;
use crate::{
    DefaultSecurityResponseAdapter, SecurityResponseAdapter,
    authentication::{
        AuthenticationAttempt, AuthenticationEntryPoint, DefaultAuthenticationEntryPoint,
        RequestAuthenticator,
    },
    authorization::{
        AuthorizationDecision, AuthorizationDenial, AuthorizationFailure,
        AuthorizationFailureHandler, AuthorizationProvider, DefaultAuthorizationFailureHandler,
    },
};
use futures_util::future::BoxFuture;
use http::{Request, Response, request::Parts};
use std::sync::Arc;
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
/// The authenticator, authorizer, entry point, response adapter, success handler, and failure handler are
/// cloned for each service and request. Use `Arc` for shared authenticators, authorizers,
/// or entry points that do not implement `Clone`.
/// For Axum this conversion uses `axum::body::Body::from`; other Tower services can use `Bytes`,
/// `http_body_util::Full<Bytes>`, or an application body wrapper implementing `From<Bytes>`.
/// Entry points and failure handlers borrow request parts and return [`crate::SecurityResponse`].
///
/// The authenticator's result is passed directly to the authorizer, without using
/// request extensions to communicate between stages. After authorization allows the request,
/// the success handler receives the identity. By default, it inserts
/// [`Authenticated`] for downstream handlers.
///
/// # Authentication contract
///
/// This layer owns authentication for `A::Authentication`. Earlier middleware and the configured
/// authenticator must not insert `Authenticated<A::Authentication>` into request extensions.
/// The authenticator returns its identity through [`AuthenticationAttempt`]; the authorizer
/// receives that result directly, with `NotApplicable` represented as `None`. The combined layer
/// invokes the success handler only after authorization allows access. The default handler
/// inserts the identity into extensions; the layer does not read existing authentication extensions.
///
/// Use `tower_http_access_authorizers::all::AllAuthorizationProvider` to combine
/// authorization checks.
///
/// ```
/// use http::request::Parts;
/// use tower_http_access_core::authentication::AuthenticationAttempt;
/// use tower_http_access_core::authentication::AuthenticatorError;
/// use tower_http_access_core::authorization::AuthenticatedAuthorizationProvider;
/// use tower_http_access_core::security_layer::SecurityLayer;
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
    C = DefaultAuthenticationSuccessHandler,
> {
    components: Components<A, P, H, E, R, C>,
}

#[derive(Clone)]
struct Components<A, P, H, E, R, C> {
    authenticator: A,
    authorizer: P,
    failure_handler: H,
    authentication_entry_point: E,
    response_adapter: R,
    authentication_success_handler: C,
}

#[cfg(feature = "authorizers")]
impl<A: RequestAuthenticator>
    SecurityLayer<A, AuthenticatedAuthorizationProvider<A::Authentication>>
where
    A::Authentication: Send + Sync,
{
    /// Require successful authentication without additional authorization checks.
    /// Available with the default-enabled `authorizers` feature.
    ///
    /// Uses [`AuthenticatedAuthorizationProvider`]. Anonymous requests invoke the
    /// authentication entry point (HTTP 401 by default). Authentication failures
    /// retain their usual error responses. Use [`Self::new`] for a custom policy.
    ///
    /// ```
    /// use http::request::Parts;
    /// use tower_http_access_core::{security_layer::SecurityLayer, authentication::{AuthenticationAttempt, AuthenticatorError}};
    ///
    /// let security = SecurityLayer::authenticated(|_: &Parts| async {
    ///     Ok::<_, AuthenticatorError>(AuthenticationAttempt::Authenticated("alex".to_owned()))
    /// });
    /// # let _: axum::Router = axum::Router::new().layer(security);
    /// ```
    pub fn authenticated(authenticator: A) -> Self {
        Self::new(authenticator, AuthenticatedAuthorizationProvider::new())
    }
}

impl<A, P> SecurityLayer<A, P>
where
    A: RequestAuthenticator,
    P: AuthorizationProvider<Authentication = A::Authentication>,
{
    /// Use one value for both authentication and authentication-required responses.
    ///
    /// Clones the value once to configure the two roles. Pass an `Arc` to share an
    /// authenticator that does not implement `Clone`, or whose state must be shared.
    /// The entry point runs only when authorization requires authentication.
    /// Use [`Self::new`] and [`Self::authentication_entry_point`] for separate values.
    ///
    /// ```
    /// use tower_http_access_core::{security_layer::SecurityLayer, authentication::RequestAuthenticator};
    /// use tower_http_access_core::{authentication::AuthenticationEntryPoint, authorization::AuthorizationProvider};
    ///
    /// fn configure<A, P>(authenticator: A, authorizer: P)
    /// where
    ///     A: RequestAuthenticator + AuthenticationEntryPoint + Clone,
    ///     P: AuthorizationProvider<Authentication = A::Authentication>,
    /// {
    ///     let layer = SecurityLayer::new_with_entry_point(authenticator, authorizer);
    /// }
    /// ```
    pub fn new_with_entry_point(
        authenticator: A,
        authorizer: P,
    ) -> SecurityLayer<A, P, DefaultAuthorizationFailureHandler, A>
    where
        A: AuthenticationEntryPoint + Clone,
    {
        Self::new(authenticator.clone(), authorizer).authentication_entry_point(authenticator)
    }

    /// Combine an authenticator and a authorizer accepting the same identity type.
    pub fn new(authenticator: A, authorizer: P) -> Self {
        Self {
            components: Components {
                authenticator,
                authorizer,
                failure_handler: DefaultAuthorizationFailureHandler,
                authentication_entry_point: DefaultAuthenticationEntryPoint,
                response_adapter: DefaultSecurityResponseAdapter,
                authentication_success_handler: DefaultAuthenticationSuccessHandler,
            },
        }
    }
}

impl<A, P, H, E, R, C> SecurityLayer<A, P, H, E, R, C> {
    /// Choose how an authenticated identity is passed to downstream handlers.
    ///
    /// Runs synchronously after authorization allows an authenticated request. It is
    /// skipped for anonymous or rejected requests and replaces the default insertion
    /// of `Authenticated<A::Authentication>`. The handler is cloned for each service
    /// and request; shared state can be captured through `Arc`.
    ///
    /// ```
    /// use http::request::Parts;
    /// use tower_http_access_core::{security_layer::SecurityLayer, authentication::{AuthenticationAttempt, AuthenticatorError}};
    /// use tower_http_access_core::authorization::AuthenticatedAuthorizationProvider;
    ///
    /// #[derive(Clone)]
    /// struct CurrentUser(String);
    /// let layer = SecurityLayer::new(
    ///     |_: &Parts| async {
    ///         Ok::<_, AuthenticatorError>(AuthenticationAttempt::Authenticated("alex".to_owned()))
    ///     },
    ///     AuthenticatedAuthorizationProvider::<String>::new(),
    /// ).authentication_success_handler(|identity: String, parts: &mut Parts| {
    ///     parts.extensions.insert(CurrentUser(identity));
    /// });
    /// ```
    pub fn authentication_success_handler<NewC>(
        self,
        handler: NewC,
    ) -> SecurityLayer<A, P, H, E, R, NewC> {
        SecurityLayer {
            components: Components {
                authenticator: self.components.authenticator,
                authorizer: self.components.authorizer,
                failure_handler: self.components.failure_handler,
                authentication_entry_point: self.components.authentication_entry_point,
                response_adapter: self.components.response_adapter,
                authentication_success_handler: handler,
            },
        }
    }

    /// Customize the response when authorization requires authentication.
    pub fn authentication_entry_point<NewE>(
        self,
        authentication_entry_point: NewE,
    ) -> SecurityLayer<A, P, H, NewE, R, C> {
        SecurityLayer {
            components: Components {
                authenticator: self.components.authenticator,
                authorizer: self.components.authorizer,
                failure_handler: self.components.failure_handler,
                authentication_entry_point,
                response_adapter: self.components.response_adapter,
                authentication_success_handler: self.components.authentication_success_handler,
            },
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
    /// use tower_http_access_core::{security_layer::SecurityLayer, SecurityResponseAdapter};
    /// use tower_http_access_core::authentication::{AuthenticationAttempt, AuthenticatorError};
    /// use tower_http_access_core::authorization::AuthenticatedAuthorizationProvider;
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
    pub fn response_adapter<NewR>(self, adapter: NewR) -> SecurityLayer<A, P, H, E, NewR, C> {
        SecurityLayer {
            components: Components {
                authenticator: self.components.authenticator,
                authorizer: self.components.authorizer,
                failure_handler: self.components.failure_handler,
                authentication_entry_point: self.components.authentication_entry_point,
                response_adapter: adapter,
                authentication_success_handler: self.components.authentication_success_handler,
            },
        }
    }

    /// Customize responses to insufficient permissions and authorizer errors.
    pub fn failure_handler<NewH>(self, handler: NewH) -> SecurityLayer<A, P, NewH, E, R, C> {
        SecurityLayer {
            components: Components {
                authenticator: self.components.authenticator,
                authorizer: self.components.authorizer,
                failure_handler: handler,
                authentication_entry_point: self.components.authentication_entry_point,
                response_adapter: self.components.response_adapter,
                authentication_success_handler: self.components.authentication_success_handler,
            },
        }
    }
}

impl<A: Clone, P: Clone, H: Clone, E: Clone, R: Clone, C: Clone> Clone
    for SecurityLayer<A, P, H, E, R, C>
{
    fn clone(&self) -> Self {
        Self {
            components: self.components.clone(),
        }
    }
}

impl<S, A: Clone, P: Clone, H: Clone, E: Clone, R: Clone, C: Clone> Layer<S>
    for SecurityLayer<A, P, H, E, R, C>
{
    type Service = SecurityService<S, A, P, H, E, R, C>;

    fn layer(&self, inner: S) -> Self::Service {
        SecurityService {
            inner,
            components: self.components.clone(),
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
    C = DefaultAuthenticationSuccessHandler,
> {
    inner: S,
    components: Components<A, P, H, E, R, C>,
}

impl<S: Clone, A: Clone, P: Clone, H: Clone, E: Clone, R: Clone, C: Clone> Clone
    for SecurityService<S, A, P, H, E, R, C>
{
    fn clone(&self) -> Self {
        Self {
            inner: self.inner.clone(),
            components: self.components.clone(),
        }
    }
}

impl<S, A, P, H, E, R, C, ReqBody, ResBody> Service<Request<ReqBody>>
    for SecurityService<S, A, P, H, E, R, C>
where
    S: Service<Request<ReqBody>, Response = Response<ResBody>> + Clone + Send + 'static,
    S::Future: Send + 'static,
    S::Error: Send + 'static,
    ReqBody: Send + 'static,
    ResBody: 'static,
    R: SecurityResponseAdapter<ResBody> + Clone + Send + Sync + 'static,
    A: RequestAuthenticator + Clone + 'static,
    A::Authentication: Send,
    P: AuthorizationProvider<Authentication = A::Authentication> + Clone + 'static,
    P::Error: Send + 'static,
    H: AuthorizationFailureHandler<P::Error>,
    E: AuthenticationEntryPoint + Clone + 'static,
    C: AuthenticationSuccessHandler<A::Authentication> + Clone,
{
    type Response = Response<ResBody>;
    type Error = S::Error;
    type Future = BoxFuture<'static, Result<Response<ResBody>, S::Error>>;

    fn poll_ready(&mut self, context: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        self.inner.poll_ready(context)
    }

    fn call(&mut self, request: Request<ReqBody>) -> Self::Future {
        let components = self.components.clone();
        let clone = self.inner.clone();
        let mut inner = std::mem::replace(&mut self.inner, clone);

        Box::pin(async move {
            let (parts, body) = request.into_parts();
            let authentication = match components.authenticator.authenticate(&parts).await {
                Ok(AuthenticationAttempt::Authenticated(authentication)) => Some(authentication),
                Ok(AuthenticationAttempt::NotApplicable) => None,
                Err(error) => {
                    #[cfg(feature = "tracing")]
                    tracing::warn!(error = %error, "unexpected error while authentication");

                    return Ok(components
                        .response_adapter
                        .adapt(error.into_security_response()));
                }
            };

            #[cfg(feature = "tracing")]
            {
                let authenticator = std::any::type_name_of_val(&components.authenticator);
                if authentication.is_some() {
                    tracing::debug!(?authenticator, "authenticated");
                } else {
                    tracing::debug!(?authenticator, "not applicable");
                }
            }

            let decision = components
                .authorizer
                .authorize(authentication.as_ref(), &parts)
                .await;

            #[cfg(feature = "tracing")]
            {
                let authorizer = std::any::type_name_of_val(&components.authorizer);
                tracing::debug!(?decision, ?authorizer, "authorization evaluated");
            }

            match decision {
                Ok(AuthorizationDecision::Allow) => {
                    let mut parts = parts;
                    if let Some(authentication) = authentication {
                        components
                            .authentication_success_handler
                            .on_success(authentication, &mut parts);
                    }
                    inner.call(Request::from_parts(parts, body)).await
                }
                Ok(AuthorizationDecision::Deny(AuthorizationDenial::AuthenticationRequired)) => {
                    Ok(components
                        .response_adapter
                        .adapt(components.authentication_entry_point.commence(&parts).await))
                }
                Ok(AuthorizationDecision::Deny(denial)) => Ok(components.response_adapter.adapt(
                    components
                        .failure_handler
                        .handle(&parts, AuthorizationFailure::Denied(denial)),
                )),
                Err(error) => {
                    #[cfg(feature = "tracing")]
                    tracing::warn!(error = %error, "unexpected error while authorize");

                    Ok(components.response_adapter.adapt(
                        components
                            .failure_handler
                            .handle(&parts, AuthorizationFailure::Provider(error)),
                    ))
                }
            }
        })
    }
}

/// Consumes an authenticated identity after authorization allows the request.
///
/// Called once for an allowed, authenticated request, before invoking the inner
/// service. Anonymous requests, authentication failures, and authorization denials
/// or errors skip this handler. Authorization receives the original identity before
/// any changes made here. Implementations may update headers, extensions, or shared
/// application state synchronously; they must not perform blocking I/O.
///
/// A custom handler replaces the default insertion of [`Authenticated<A>`]. It must
/// insert that extension itself if downstream handlers still need the extractor.
/// Configure it with [`crate::security_layer::SecurityLayer::authentication_success_handler`].
pub trait AuthenticationSuccessHandler<A>: Send + Sync + 'static {
    fn on_success(&self, authentication: A, parts: &mut Parts);
}

impl<A, F> AuthenticationSuccessHandler<A> for F
where
    F: Fn(A, &mut Parts) + Send + Sync + 'static,
{
    fn on_success(&self, authentication: A, parts: &mut Parts) {
        self(authentication, parts);
    }
}

impl<A, H: AuthenticationSuccessHandler<A> + ?Sized> AuthenticationSuccessHandler<A> for Arc<H> {
    fn on_success(&self, authentication: A, parts: &mut Parts) {
        self.as_ref().on_success(authentication, parts);
    }
}

/// Stores the identity as [`Authenticated<A>`] in request extensions.
#[derive(Clone, Copy, Debug, Default)]
pub struct DefaultAuthenticationSuccessHandler;

impl<A: Clone + Send + Sync + 'static> AuthenticationSuccessHandler<A>
    for DefaultAuthenticationSuccessHandler
{
    fn on_success(&self, authentication: A, parts: &mut Parts) {
        parts.extensions.insert(Authenticated(authentication));
    }
}
