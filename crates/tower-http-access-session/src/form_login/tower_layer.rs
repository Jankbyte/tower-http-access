//! Framework-independent form login middleware.

use super::{
    DefaultFailureHandler, DefaultSuccessHandler, FailureHandler, FormLoginError, SuccessHandler,
};
use ::tower_layer::Layer;
use bytes::Bytes;
use futures_util::future::BoxFuture;
use http::{Method, Request, Response, StatusCode, header};
use http_body_util::{BodyExt, Limited};
use http_request_matcher::PathPatternRequestMatcher;
use http_request_matcher::RequestMatcher;
use std::{
    sync::Arc,
    task::{Context, Poll},
};
use tower_http_access_core::SecurityResponse;
use tower_service::Service;
use user_password_auth::{Credentials, UsernamePasswordAuthenticationProvider};

/// Intercepts a configured form submission and authenticates its credentials.
///
/// Defaults: `POST /login`, fields `username` and `password`, and a 16 KiB body limit.
/// Success returns 200; invalid credentials return 401. Callbacks may instead persist
/// an identity and return redirects or custom responses. Place session middleware
/// outside this layer if callbacks access a session through request extensions.
/// This layer does not provide CSRF protection; configure it before this layer.
/// Nonmatching requests pass through without reading their bodies.
/// Provider, matcher, and handler types must implement `Clone` to apply the layer.
/// Wrap values in `Arc` when they should be shared instead of cloned.
///
/// ```
/// use bytes::Bytes;
/// use http::{Method, Response, StatusCode, request::Parts};
/// use user_password_auth::UsernamePasswordAuthenticationProvider;
/// use http_request_matcher::PathPatternRequestMatcher;
/// use tower_http_access_session::form_login::FormLoginLayer;
///
/// fn configure<P: UsernamePasswordAuthenticationProvider>(provider: P) {
///     let layer = FormLoginLayer::new(provider)
///         .request_matcher(
///             PathPatternRequestMatcher::new("/ui/login").unwrap()
///                 .with_method(Method::POST),
///         )
///         .username_parameter("username")
///         .password_parameter("password")
///         .on_success(|parts: Parts, identity: P::Authentication| async move {
///             // Persist identity here, using the session in parts.extensions.
///             // Rotate the session ID before establishing the login.
///             Response::builder()
///                 .status(StatusCode::SEE_OTHER)
///                 .header("location", "/ui")
///                 .body(Bytes::new()).unwrap()
///         })
///         .on_failure(|parts: Parts, error: tower_http_access_session::form_login::FormLoginError<P::Error>| async move {
///             // Inspect error to distinguish invalid credentials from backend failure.
///             Response::builder()
///                 .status(StatusCode::UNAUTHORIZED)
///                 .body(Bytes::from_static(b"Login failed")).unwrap()
///         });
/// }
/// ```
#[derive(Clone)]
pub struct FormLoginLayer<
    P,
    M = PathPatternRequestMatcher,
    H = DefaultSuccessHandler,
    F = DefaultFailureHandler,
> {
    provider: P,
    request_matcher: M,
    username_field: Arc<str>,
    password_field: Arc<str>,
    body_limit: usize,
    success: H,
    failure: F,
}

impl<P: UsernamePasswordAuthenticationProvider> FormLoginLayer<P> {
    pub fn new(provider: P) -> Self {
        Self {
            provider,
            request_matcher: PathPatternRequestMatcher::new("/login")
                .expect("the default login path is valid")
                .with_method(Method::POST),
            username_field: "username".into(),
            password_field: "password".into(),
            body_limit: 16 * 1024,
            success: DefaultSuccessHandler,
            failure: DefaultFailureHandler,
        }
    }
}

impl<P, M, H, F> FormLoginLayer<P, M, H, F> {
    /// Select which requests this layer processes. Nonmatching bodies are untouched.
    pub fn request_matcher<N: RequestMatcher>(self, matcher: N) -> FormLoginLayer<P, N, H, F> {
        FormLoginLayer {
            provider: self.provider,
            request_matcher: matcher,
            username_field: self.username_field,
            password_field: self.password_field,
            body_limit: self.body_limit,
            success: self.success,
            failure: self.failure,
        }
    }

    pub fn username_parameter(mut self, name: impl Into<Arc<str>>) -> Self {
        self.username_field = name.into();
        self
    }

    pub fn password_parameter(mut self, name: impl Into<Arc<str>>) -> Self {
        self.password_field = name.into();
        self
    }

    pub fn body_limit(mut self, bytes: usize) -> Self {
        self.body_limit = bytes;
        self
    }

    /// Handle successful login. The callback owns persistence and the response.
    pub fn on_success<N>(self, handler: N) -> FormLoginLayer<P, M, N, F>
    where
        P: UsernamePasswordAuthenticationProvider,
        N: SuccessHandler<P::Authentication>,
    {
        FormLoginLayer {
            provider: self.provider,
            request_matcher: self.request_matcher,
            username_field: self.username_field,
            password_field: self.password_field,
            body_limit: self.body_limit,
            success: handler,
            failure: self.failure,
        }
    }

    /// Handle invalid submissions, invalid credentials, and backend errors.
    pub fn on_failure<N>(self, handler: N) -> FormLoginLayer<P, M, H, N>
    where
        P: UsernamePasswordAuthenticationProvider,
        N: FailureHandler<P::Error>,
    {
        FormLoginLayer {
            provider: self.provider,
            request_matcher: self.request_matcher,
            username_field: self.username_field,
            password_field: self.password_field,
            body_limit: self.body_limit,
            success: self.success,
            failure: handler,
        }
    }
}

impl<S, P: Clone, M: Clone, H: Clone, F: Clone> Layer<S> for FormLoginLayer<P, M, H, F> {
    type Service = FormLoginService<S, P, M, H, F>;
    fn layer(&self, inner: S) -> Self::Service {
        FormLoginService {
            inner,
            config: self.clone(),
        }
    }
}

/// Service produced by [`FormLoginLayer`].
#[derive(Clone)]
pub struct FormLoginService<
    S,
    P,
    M = PathPatternRequestMatcher,
    H = DefaultSuccessHandler,
    F = DefaultFailureHandler,
> {
    inner: S,
    config: FormLoginLayer<P, M, H, F>,
}

impl<S, P, M, H, F, B, R> Service<Request<B>> for FormLoginService<S, P, M, H, F>
where
    S: Service<Request<B>, Response = Response<R>> + Clone + Send + 'static,
    S::Future: Send + 'static,
    S::Error: Send + 'static,
    P: UsernamePasswordAuthenticationProvider + Clone + 'static,
    M: RequestMatcher + Clone + 'static,
    H: SuccessHandler<P::Authentication> + Clone + 'static,
    F: FailureHandler<P::Error> + Clone + 'static,
    B: http_body::Body<Data = Bytes> + Send + 'static,
    B::Error: std::error::Error + Send + Sync + 'static,
    R: From<Bytes> + 'static,
{
    type Response = Response<R>;
    type Error = S::Error;
    type Future = BoxFuture<'static, Result<Self::Response, Self::Error>>;

    fn poll_ready(&mut self, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        self.inner.poll_ready(cx)
    }

    fn call(&mut self, request: Request<B>) -> Self::Future {
        let (parts, body) = request.into_parts();
        if !self.config.request_matcher.matches(&parts) {
            return Box::pin(self.inner.call(Request::from_parts(parts, body)));
        }
        let provider = self.config.provider.clone();
        let success = self.config.success.clone();
        let failure = self.config.failure.clone();
        let username_field = Arc::clone(&self.config.username_field);
        let password_field = Arc::clone(&self.config.password_field);
        let body_limit = self.config.body_limit;
        Box::pin(async move {
            let result = async {
                let content_type = parts
                    .headers
                    .get(header::CONTENT_TYPE)
                    .and_then(|value| value.to_str().ok())
                    .and_then(|value| value.split(';').next());
                if !content_type.is_some_and(|value| {
                    value
                        .trim()
                        .eq_ignore_ascii_case("application/x-www-form-urlencoded")
                }) {
                    return Err(FormLoginError::UnsupportedMediaType);
                }
                let collected =
                    Limited::new(body, body_limit)
                        .collect()
                        .await
                        .map_err(|error| {
                            if error.is::<http_body_util::LengthLimitError>() {
                                FormLoginError::BodyTooLarge
                            } else {
                                FormLoginError::BodyRead
                            }
                        })?;
                let fields: Vec<(String, String)> =
                    serde_urlencoded::from_bytes(&collected.to_bytes())
                        .map_err(|_| FormLoginError::InvalidForm)?;
                let field = |name: &str| {
                    let mut values = fields.iter().filter(|(key, _)| key == name);
                    let value = values.next().ok_or(FormLoginError::InvalidForm)?.1.clone();
                    if values.next().is_some() {
                        return Err(FormLoginError::InvalidForm);
                    }
                    Ok(value)
                };
                let credentials = Credentials {
                    username: field(&username_field)?,
                    password: field(&password_field)?,
                };
                provider
                    .authenticate(&credentials)
                    .await
                    .map_err(FormLoginError::Backend)?
                    .ok_or(FormLoginError::InvalidCredentials)
            }
            .await;
            let response = match result {
                Ok(identity) => success.on_success(parts, identity).await,
                Err(error) => failure.on_failure(parts, error).await,
            };
            Ok(response.map(R::from))
        })
    }
}

pub(super) fn response(status: StatusCode) -> SecurityResponse {
    let mut response = Response::new(Bytes::new());
    *response.status_mut() = status;
    response
}

#[cfg(test)]
#[path = "tests.rs"]
mod tests;
