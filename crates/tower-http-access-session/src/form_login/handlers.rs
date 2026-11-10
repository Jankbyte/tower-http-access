use super::FormLoginError;
use futures_util::future::BoxFuture;
use http::request::Parts;
use std::future::Future;
use tower_http_access_core::SecurityResponse;

/// Handles successful form authentication, including persistence and the response.
///
/// Async closures implement this trait automatically. Implementations may borrow
/// their configuration while preparing the response.
pub trait SuccessHandler<A>: Send + Sync {
    fn on_success(&self, parts: Parts, authentication: A) -> BoxFuture<'_, SecurityResponse>;
}

impl<A, F, Fut> SuccessHandler<A> for F
where
    F: Fn(Parts, A) -> Fut + Send + Sync,
    Fut: Future<Output = SecurityResponse> + Send + 'static,
{
    fn on_success(&self, parts: Parts, authentication: A) -> BoxFuture<'_, SecurityResponse> {
        Box::pin(self(parts, authentication))
    }
}

/// Handles rejected submissions, invalid credentials, and authentication backend errors.
/// Async closures implement this trait automatically.
pub trait FailureHandler<E>: Send + Sync {
    fn on_failure(&self, parts: Parts, error: FormLoginError<E>)
    -> BoxFuture<'_, SecurityResponse>;
}

impl<E, F, Fut> FailureHandler<E> for F
where
    F: Fn(Parts, FormLoginError<E>) -> Fut + Send + Sync,
    Fut: Future<Output = SecurityResponse> + Send + 'static,
{
    fn on_failure(
        &self,
        parts: Parts,
        error: FormLoginError<E>,
    ) -> BoxFuture<'_, SecurityResponse> {
        Box::pin(self(parts, error))
    }
}

/// Returns an empty HTTP 200 response after successful authentication.
#[derive(Clone, Copy, Debug, Default)]
pub struct DefaultSuccessHandler;

impl<A> SuccessHandler<A> for DefaultSuccessHandler {
    fn on_success(&self, _: Parts, _: A) -> BoxFuture<'_, SecurityResponse> {
        Box::pin(async { super::tower_layer::response(http::StatusCode::OK) })
    }
}

/// Redirects successful authentication to a configured same-origin absolute path.
/// Uses HTTP 303 so a form submission is followed by a GET request.
#[derive(Clone, Debug)]
pub struct RedirectSuccessHandler {
    location: http::HeaderValue,
}

impl RedirectSuccessHandler {
    /// Configure a path such as `/private` or `/account?welcome=true`.
    /// External URLs, network-path URLs, and relative paths are rejected.
    pub fn new(path: impl AsRef<str>) -> Result<Self, crate::InvalidLoginPagePath> {
        let path = path.as_ref();
        let uri = path
            .parse::<http::Uri>()
            .map_err(|_| crate::InvalidLoginPagePath)?;
        if !path.starts_with('/')
            || path.starts_with("//")
            || path.contains('\\')
            || path.contains('#')
            || uri.scheme().is_some()
            || uri.authority().is_some()
        {
            return Err(crate::InvalidLoginPagePath);
        }
        let location =
            http::HeaderValue::from_str(path).map_err(|_| crate::InvalidLoginPagePath)?;
        Ok(Self { location })
    }
}

impl<A> SuccessHandler<A> for RedirectSuccessHandler {
    fn on_success(&self, _: Parts, _: A) -> BoxFuture<'_, SecurityResponse> {
        let mut response = super::tower_layer::response(http::StatusCode::SEE_OTHER);
        response
            .headers_mut()
            .insert(http::header::LOCATION, self.location.clone());
        Box::pin(async move { response })
    }
}

/// Returns the standard HTTP status for a form submission failure.
#[derive(Clone, Copy, Debug, Default)]
pub struct DefaultFailureHandler;

impl<E> FailureHandler<E> for DefaultFailureHandler {
    fn on_failure(&self, _: Parts, error: FormLoginError<E>) -> BoxFuture<'_, SecurityResponse> {
        let status = match error {
            FormLoginError::InvalidCredentials => http::StatusCode::UNAUTHORIZED,
            FormLoginError::UnsupportedMediaType => http::StatusCode::UNSUPPORTED_MEDIA_TYPE,
            FormLoginError::BodyTooLarge => http::StatusCode::PAYLOAD_TOO_LARGE,
            FormLoginError::Backend(_) => http::StatusCode::INTERNAL_SERVER_ERROR,
            _ => http::StatusCode::BAD_REQUEST,
        };
        Box::pin(async move { super::tower_layer::response(status) })
    }
}

impl<A, T: SuccessHandler<A> + ?Sized> SuccessHandler<A> for std::sync::Arc<T> {
    fn on_success(&self, parts: Parts, authentication: A) -> BoxFuture<'_, SecurityResponse> {
        self.as_ref().on_success(parts, authentication)
    }
}

impl<E, T: FailureHandler<E> + ?Sized> FailureHandler<E> for std::sync::Arc<T> {
    fn on_failure(
        &self,
        parts: Parts,
        error: FormLoginError<E>,
    ) -> BoxFuture<'_, SecurityResponse> {
        self.as_ref().on_failure(parts, error)
    }
}
