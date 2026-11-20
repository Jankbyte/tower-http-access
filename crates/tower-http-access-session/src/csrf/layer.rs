use super::{CsrfToken, CsrfTokenRepository};
use bytes::Bytes;
use futures_util::{future::BoxFuture, stream};
use http::{Method, Request, Response, StatusCode, header, request::Parts};
use http_body::Frame;
use http_body_util::{BodyExt, Limited, StreamBody, combinators::UnsyncBoxBody};
use http_request_matcher::RequestMatcher;
use rand::TryRngCore;
use std::{
    convert::Infallible,
    error::Error,
    task::{Context, Poll},
};
use subtle::ConstantTimeEq;
use tower_http_access_core::SecurityResponse;
use tower_layer::Layer;
use tower_service::Service;

/// Request body forwarded by CSRF middleware. Uninspected bodies remain streaming;
/// inspected form bodies retain their bytes and trailers.
pub struct CsrfBody(UnsyncBoxBody<Bytes, Box<dyn Error + Send + Sync + 'static>>);

/// An error from the original request body, preserving its source.
#[derive(Debug)]
pub struct CsrfBodyError(Box<dyn Error + Send + Sync + 'static>);

impl std::fmt::Display for CsrfBodyError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        self.0.fmt(f)
    }
}

impl Error for CsrfBodyError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        Some(self.0.as_ref())
    }
}

impl CsrfBody {
    fn new<B>(body: B) -> Self
    where
        B: http_body::Body<Data = Bytes> + Send + 'static,
        B::Error: Into<Box<dyn Error + Send + Sync + 'static>>,
    {
        Self(body.map_err(Into::into).boxed_unsync())
    }
}

impl http_body::Body for CsrfBody {
    type Data = Bytes;
    type Error = CsrfBodyError;

    fn poll_frame(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Option<Result<Frame<Bytes>, Self::Error>>> {
        std::pin::Pin::new(&mut self.0)
            .poll_frame(cx)
            .map(|frame| frame.map(|result| result.map_err(CsrfBodyError)))
    }

    fn is_end_stream(&self) -> bool {
        self.0.is_end_stream()
    }
    fn size_hint(&self) -> http_body::SizeHint {
        self.0.size_hint()
    }
}

/// A CSRF rejection or an operational failure. Submitted and expected token values
/// are deliberately excluded from these errors.
#[derive(Debug)]
pub enum CsrfFailure<E> {
    /// No unexpired token was stored for a protected request.
    MissingToken,
    /// The submitted token was absent, malformed, duplicated, or did not match.
    InvalidToken,
    /// Loading, generating, or saving the repository token failed.
    Repository(E),
    /// Secure randomness for token masking was unavailable.
    MaskGeneration,
    /// A form exceeded the configured buffer limit.
    BodyTooLarge,
    /// Reading a form body failed.
    BodyRead,
    /// The URL-encoded form could not be decoded.
    InvalidForm,
}

/// Formats CSRF failures without disclosing token values. Closures implement this
/// trait automatically; returning a response terminates request processing.
pub trait CsrfFailureHandler<E>: Send + Sync {
    fn handle(&self, request: &Parts, failure: CsrfFailure<E>) -> SecurityResponse;
}

impl<E, F> CsrfFailureHandler<E> for F
where
    F: Fn(&Parts, CsrfFailure<E>) -> SecurityResponse + Send + Sync,
{
    fn handle(&self, request: &Parts, failure: CsrfFailure<E>) -> SecurityResponse {
        self(request, failure)
    }
}

/// Returns 403 for failed validation, 413 for oversized forms, 400 for unreadable
/// or invalid forms, and 500 for repository or masking failures.
#[derive(Clone, Copy, Debug, Default)]
pub struct DefaultCsrfFailureHandler;

impl<E> CsrfFailureHandler<E> for DefaultCsrfFailureHandler {
    fn handle(&self, _: &Parts, failure: CsrfFailure<E>) -> SecurityResponse {
        let status = match failure {
            CsrfFailure::MissingToken | CsrfFailure::InvalidToken => StatusCode::FORBIDDEN,
            CsrfFailure::BodyTooLarge => StatusCode::PAYLOAD_TOO_LARGE,
            CsrfFailure::BodyRead | CsrfFailure::InvalidForm => StatusCode::BAD_REQUEST,
            CsrfFailure::Repository(_) | CsrfFailure::MaskGeneration => {
                StatusCode::INTERNAL_SERVER_ERROR
            }
        };
        let mut response = SecurityResponse::new(Bytes::new());
        *response.status_mut() = status;
        response
    }
}

/// Requires validation for all methods except GET, HEAD, OPTIONS, and TRACE.
#[derive(Clone, Copy, Debug, Default)]
pub struct UnsafeCsrfMethods;

impl RequestMatcher for UnsafeCsrfMethods {
    fn matches(&self, request: &Parts) -> bool {
        !matches!(
            request.method,
            Method::GET | Method::HEAD | Method::OPTIONS | Method::TRACE
        )
    }
}

/// Session-independent, Spring-style synchronizer-token middleware.
///
/// The repository is stored directly and cloned when building services and
/// handling requests. Pass an `Arc<R>` for shared or non-Clone repositories;
/// repository clones must refer to the same logical token storage.
///
/// Every request loads or creates and saves a repository token, then exposes a
/// [`CsrfToken`] in request extensions for page rendering. Unlike Spring's deferred
/// loading, repository access is eager. Session middleware must run outside this
/// layer when the repository uses sessions. Put this layer before form login.
///
/// Protected requests resolve the submitted token from the configured header
/// first, falling back to the configured URL-encoded form field only when the
/// header is absent. Duplicate token headers or fields are rejected. Query-string
/// and multipart tokens are not accepted; those clients must use the header.
/// Successful header checks and safe requests do not buffer the body.
///
/// When the header is absent and the content type is URL-encoded form data, the
/// *entire form body is collected into RAM before extracting the token*. Reading
/// does not stop when the token field is found. Buffering is bounded by
/// [`Self::body_limit`] (16 KiB by default); exceeding it returns 413 with the
/// default failure handler. Other content types, including multipart uploads,
/// are rejected without reading the body when the token header is absent.
///
/// By default, exposed tokens are hex-encoded random-pad/XOR pairs for BREACH
/// protection. Submit the exposed value unchanged; raw repository values are not
/// accepted. This is not Spring's wire encoding. Disable masking only when the
/// application explicitly needs raw tokens. Comparisons use constant-time equality.
/// Token invalidation on login/logout is the application's responsibility.
pub struct CsrfLayer<R, M = UnsafeCsrfMethods, H = DefaultCsrfFailureHandler> {
    repository: R,
    matcher: M,
    failure_handler: H,
    body_limit: usize,
    mask_tokens: bool,
}

impl<R: Clone, M: Clone, H: Clone> Clone for CsrfLayer<R, M, H> {
    fn clone(&self) -> Self {
        Self {
            repository: self.repository.clone(),
            matcher: self.matcher.clone(),
            failure_handler: self.failure_handler.clone(),
            body_limit: self.body_limit,
            mask_tokens: self.mask_tokens,
        }
    }
}

impl<R: CsrfTokenRepository> CsrfLayer<R> {
    pub fn new(repository: R) -> Self {
        Self {
            repository,
            matcher: UnsafeCsrfMethods,
            failure_handler: DefaultCsrfFailureHandler,
            body_limit: 16 * 1024,
            mask_tokens: true,
        }
    }
}

impl<R, M, H> CsrfLayer<R, M, H> {
    /// Select requests requiring validation. Token exposure still runs for every request.
    pub fn request_matcher<N>(self, matcher: N) -> CsrfLayer<R, N, H> {
        CsrfLayer {
            repository: self.repository,
            matcher,
            failure_handler: self.failure_handler,
            body_limit: self.body_limit,
            mask_tokens: self.mask_tokens,
        }
    }

    pub fn failure_handler<N>(self, handler: N) -> CsrfLayer<R, M, N> {
        CsrfLayer {
            repository: self.repository,
            matcher: self.matcher,
            failure_handler: handler,
            body_limit: self.body_limit,
            mask_tokens: self.mask_tokens,
        }
    }

    /// Maximum bytes buffered when resolving a URL-encoded form token; defaults to 16 KiB.
    pub fn body_limit(mut self, limit: usize) -> Self {
        self.body_limit = limit;
        self
    }

    /// Enable per-request XOR masking (default: true). When false, expose and
    /// require raw repository token values instead.
    pub fn mask_tokens(mut self, enabled: bool) -> Self {
        self.mask_tokens = enabled;
        self
    }
}

impl<S, R: Clone, M: Clone, H: Clone> Layer<S> for CsrfLayer<R, M, H> {
    type Service = CsrfService<S, R, M, H>;
    fn layer(&self, inner: S) -> Self::Service {
        CsrfService {
            inner,
            repository: self.repository.clone(),
            matcher: self.matcher.clone(),
            failure_handler: self.failure_handler.clone(),
            body_limit: self.body_limit,
            mask_tokens: self.mask_tokens,
        }
    }
}

/// Service produced by [`CsrfLayer`].
pub struct CsrfService<S, R, M = UnsafeCsrfMethods, H = DefaultCsrfFailureHandler> {
    inner: S,
    repository: R,
    matcher: M,
    failure_handler: H,
    body_limit: usize,
    mask_tokens: bool,
}

impl<S: Clone, R: Clone, M: Clone, H: Clone> Clone for CsrfService<S, R, M, H> {
    fn clone(&self) -> Self {
        Self {
            inner: self.inner.clone(),
            repository: self.repository.clone(),
            matcher: self.matcher.clone(),
            failure_handler: self.failure_handler.clone(),
            body_limit: self.body_limit,
            mask_tokens: self.mask_tokens,
        }
    }
}

impl<S, R, M, H, B, ResBody> Service<Request<B>> for CsrfService<S, R, M, H>
where
    S: Service<Request<CsrfBody>, Response = Response<ResBody>> + Clone + Send + 'static,
    S::Future: Send + 'static,
    S::Error: Send + 'static,
    R: CsrfTokenRepository + Clone + 'static,
    M: RequestMatcher + Clone + 'static,
    H: CsrfFailureHandler<R::Error> + Clone + 'static,
    B: http_body::Body<Data = Bytes> + Send + 'static,
    B::Error: Into<Box<dyn Error + Send + Sync + 'static>>,
    ResBody: From<Bytes> + 'static,
{
    type Response = Response<ResBody>;
    type Error = S::Error;
    type Future = BoxFuture<'static, Result<Self::Response, Self::Error>>;

    fn poll_ready(&mut self, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        self.inner.poll_ready(cx)
    }

    fn call(&mut self, request: Request<B>) -> Self::Future {
        // Move the service whose readiness was polled into the future.
        let replacement = self.inner.clone();
        let mut inner = std::mem::replace(&mut self.inner, replacement);
        let repository = self.repository.clone();
        let handler = self.failure_handler.clone();
        let (mut parts, body) = request.into_parts();
        let protected = self.matcher.matches(&parts);
        let limit = self.body_limit;
        let mask_tokens = self.mask_tokens;
        Box::pin(async move {
            let result = async {
                let (expected, generated) = load_or_generate_token(&repository, &parts).await?;
                expose_token(&mut parts, &expected, mask_tokens)?;
                let body = CsrfBody::new(body);
                if !protected {
                    return Ok(body);
                }
                // Never authenticate a request with a newly generated token.
                if generated {
                    return Err(CsrfFailure::MissingToken);
                }
                let (submitted, body) =
                    extract_submitted_token(&parts, body, &expected, limit).await?;
                validate_token(&submitted, &expected.token, mask_tokens)?;
                Ok(body)
            }
            .await;
            match result {
                Ok(body) => inner.call(Request::from_parts(parts, body)).await,
                Err(failure) => Ok(handler.handle(&parts, failure).map(ResBody::from)),
            }
        })
    }
}

async fn load_or_generate_token<R: CsrfTokenRepository>(
    repository: &R,
    parts: &Parts,
) -> Result<(CsrfToken, bool), CsrfFailure<R::Error>> {
    let stored = repository
        .load_token(parts)
        .await
        .map_err(CsrfFailure::Repository)?;
    let generated = stored.is_none();
    let expected = match stored {
        Some(token) => token,
        None => {
            let token = repository
                .generate_token()
                .map_err(CsrfFailure::Repository)?;
            repository
                .save_token(parts, Some(&token))
                .await
                .map_err(CsrfFailure::Repository)?;
            token
        }
    };
    // Empty repository tokens cannot provide CSRF protection.
    if expected.token.is_empty() {
        return Err(CsrfFailure::InvalidToken);
    }
    Ok((expected, generated))
}

fn expose_token<E>(
    parts: &mut Parts,
    expected: &CsrfToken,
    mask_tokens: bool,
) -> Result<(), CsrfFailure<E>> {
    let mut exposed = expected.clone();
    if mask_tokens {
        exposed.token = mask(&expected.token).map_err(|_| CsrfFailure::MaskGeneration)?;
    }
    parts.extensions.insert(exposed);
    Ok(())
}

async fn extract_submitted_token<E>(
    parts: &Parts,
    body: CsrfBody,
    expected: &CsrfToken,
    limit: usize,
) -> Result<(String, CsrfBody), CsrfFailure<E>> {
    if let Some(token) = token_from_header(parts, &expected.header_name)? {
        return Ok((token, body));
    }
    if !is_urlencoded_form(parts) {
        return Err(CsrfFailure::InvalidToken);
    }
    token_from_body(body, &expected.parameter_name, limit).await
}

fn token_from_header<E>(
    parts: &Parts,
    name: &http::HeaderName,
) -> Result<Option<String>, CsrfFailure<E>> {
    let values = parts.headers.get_all(name);
    let mut values = values.iter();
    let Some(value) = values.next() else {
        return Ok(None);
    };
    if values.next().is_some() {
        return Err(CsrfFailure::InvalidToken);
    }
    let token = value.to_str().map_err(|_| CsrfFailure::InvalidToken)?;
    Ok(Some(token.to_owned()))
}

fn is_urlencoded_form(parts: &Parts) -> bool {
    parts
        .headers
        .get(header::CONTENT_TYPE)
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.split(';').next())
        .is_some_and(|value| {
            value
                .trim()
                .eq_ignore_ascii_case("application/x-www-form-urlencoded")
        })
}

async fn token_from_body<E>(
    body: CsrfBody,
    parameter_name: &str,
    limit: usize,
) -> Result<(String, CsrfBody), CsrfFailure<E>> {
    let collected = Limited::new(body, limit).collect().await.map_err(|error| {
        if error.is::<http_body_util::LengthLimitError>() {
            CsrfFailure::BodyTooLarge
        } else {
            CsrfFailure::BodyRead
        }
    })?;
    let trailers = collected.trailers().cloned();
    let bytes = collected.to_bytes();
    let token = token_from_form(&bytes, parameter_name)?;
    let frames = std::iter::once(Ok::<_, Infallible>(Frame::data(bytes)))
        .chain(trailers.map(|t| Ok(Frame::trailers(t))));
    let body = CsrfBody::new(StreamBody::new(stream::iter(frames)));
    Ok((token, body))
}

fn token_from_form<E>(bytes: &[u8], parameter_name: &str) -> Result<String, CsrfFailure<E>> {
    let fields: Vec<(String, String)> =
        serde_urlencoded::from_bytes(bytes).map_err(|_| CsrfFailure::InvalidForm)?;
    let mut tokens = fields.iter().filter(|(key, _)| key == parameter_name);
    let token = tokens.next().ok_or(CsrfFailure::InvalidToken)?.1.clone();
    if tokens.next().is_some() {
        return Err(CsrfFailure::InvalidToken);
    }
    Ok(token)
}

fn validate_token<E>(
    submitted: &str,
    expected: &str,
    mask_tokens: bool,
) -> Result<(), CsrfFailure<E>> {
    let actual = if mask_tokens {
        unmask(submitted, expected.len()).ok_or(CsrfFailure::InvalidToken)?
    } else {
        submitted.as_bytes().to_vec()
    };
    if !bool::from(expected.as_bytes().ct_eq(&actual)) {
        return Err(CsrfFailure::InvalidToken);
    }
    Ok(())
}

fn mask(token: &str) -> Result<String, rand::rand_core::OsError> {
    let mut bytes = vec![0; token.len() * 2];
    rand::rngs::OsRng.try_fill_bytes(&mut bytes[..token.len()])?;
    let (pad, masked) = bytes.split_at_mut(token.len());
    for ((out, pad), raw) in masked.iter_mut().zip(pad).zip(token.as_bytes()) {
        *out = *pad ^ raw;
    }
    Ok(hex::encode(bytes))
}

fn unmask(value: &str, length: usize) -> Option<Vec<u8>> {
    if value.len() != length.checked_mul(4)? {
        return None;
    }
    let bytes = hex::decode(value).ok()?;
    let (pad, masked) = bytes.split_at(length);
    Some(pad.iter().zip(masked).map(|(a, b)| a ^ b).collect())
}

#[cfg(test)]
#[path = "layer_tests.rs"]
mod tests;
