use super::*;
use http::{HeaderName, HeaderValue};
use http_body_util::Full;
use std::sync::Arc;
use std::{
    io,
    sync::{
        Mutex,
        atomic::{AtomicUsize, Ordering},
    },
};
use tower::{ServiceExt, service_fn};

#[derive(Default)]
struct Repository {
    stored: Mutex<Option<CsrfToken>>,
    generated: AtomicUsize,
    saved: AtomicUsize,
    fail: Option<&'static str>,
}

fn token() -> CsrfToken {
    CsrfToken {
        header_name: HeaderName::from_static("x-csrf-token"),
        parameter_name: "_csrf".into(),
        // Deterministic fixture only; production repositories must use secure randomness.
        token: "test-token".into(),
    }
}

impl Repository {
    fn with_token() -> Self {
        Self {
            stored: Mutex::new(Some(token())),
            ..Self::default()
        }
    }
}

impl CsrfTokenRepository for Repository {
    type Error = io::Error;

    fn generate_token(&self) -> Result<CsrfToken, Self::Error> {
        self.generated.fetch_add(1, Ordering::SeqCst);
        if self.fail == Some("generate") {
            return Err(io::Error::other("generation failed"));
        }
        Ok(token())
    }

    fn load_token<'a>(
        &'a self,
        _: &'a Parts,
    ) -> BoxFuture<'a, Result<Option<CsrfToken>, Self::Error>> {
        Box::pin(async move {
            if self.fail == Some("load") {
                return Err(io::Error::other("load failed"));
            }
            Ok(self.stored.lock().unwrap().clone())
        })
    }

    fn save_token<'a>(
        &'a self,
        _: &'a Parts,
        token: Option<&'a CsrfToken>,
    ) -> BoxFuture<'a, Result<(), Self::Error>> {
        Box::pin(async move {
            self.saved.fetch_add(1, Ordering::SeqCst);
            if self.fail == Some("save") {
                return Err(io::Error::other("save failed"));
            }
            *self.stored.lock().unwrap() = token.cloned();
            Ok(())
        })
    }
}

fn request(method: Method, body: impl Into<Bytes>) -> Request<Full<Bytes>> {
    Request::builder()
        .method(method)
        .uri("/login")
        .header(
            header::CONTENT_TYPE,
            "application/x-www-form-urlencoded; charset=UTF-8",
        )
        .body(Full::new(body.into()))
        .unwrap()
}

async fn echo(request: Request<CsrfBody>) -> Result<Response<Bytes>, Infallible> {
    let token = request
        .extensions()
        .get::<CsrfToken>()
        .unwrap()
        .token
        .clone();
    let collected = request.into_body().collect().await.unwrap();
    let trailers = collected.trailers().cloned();
    let mut response = Response::new(collected.to_bytes());
    response
        .headers_mut()
        .insert("exposed-token", HeaderValue::from_str(&token).unwrap());
    if let Some(trailers) = trailers {
        response.extensions_mut().insert(trailers);
    }
    Ok(response)
}

#[tokio::test]
async fn safe_requests_create_persist_and_expose_masked_tokens() {
    let repository = Arc::new(Repository::default());
    let layer = CsrfLayer::new(repository.clone());
    let mut values = Vec::new();
    for method in [Method::GET, Method::HEAD, Method::OPTIONS, Method::TRACE] {
        let response = layer
            .clone()
            .layer(service_fn(echo))
            .oneshot(request(method, "untouched"))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(response.body(), "untouched");
        let exposed = response.headers()["exposed-token"]
            .to_str()
            .unwrap()
            .to_owned();
        assert_eq!(
            unmask(&exposed, token().token.len()).unwrap(),
            token().token.as_bytes()
        );
        values.push(exposed);
    }
    assert!(values.windows(2).all(|v| v[0] != v[1]));
    assert_eq!(repository.generated.load(Ordering::SeqCst), 1);
    assert_eq!(repository.saved.load(Ordering::SeqCst), 1);
}

#[tokio::test]
async fn validates_headers_and_forms_for_all_unsafe_methods() {
    let layer = CsrfLayer::new(Arc::new(Repository::with_token()));
    let masked = mask(&token().token).unwrap();
    for method in [
        Method::POST,
        Method::PUT,
        Method::PATCH,
        Method::DELETE,
        Method::from_bytes(b"CUSTOM").unwrap(),
    ] {
        let mut header_request = request(method.clone(), "streamed bytes");
        header_request
            .headers_mut()
            .insert("x-csrf-token", masked.parse().unwrap());
        let response = layer
            .layer(service_fn(echo))
            .oneshot(header_request)
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(response.body(), "streamed bytes");
        let body = format!("username=alice&password=secret&_csrf={masked}");
        let response = layer
            .layer(service_fn(echo))
            .oneshot(request(method, body.clone()))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(response.body(), body.as_str());
    }
}

#[tokio::test]
async fn rejects_missing_raw_wrong_and_duplicate_tokens_without_invoking_inner() {
    let layer = CsrfLayer::new(Arc::new(Repository::with_token()));
    let masked = mask(&token().token).unwrap();
    let mut requests = vec![
        request(Method::POST, "username=alice"),
        request(Method::POST, "_csrf=wrong"),
        request(Method::POST, format!("_csrf={}", token().token)),
        request(Method::POST, format!("_csrf={masked}&_csrf={masked}")),
        request(
            Method::POST,
            format!("_csrf={}", mask("other-user").unwrap()),
        ),
    ];
    // An invalid or duplicated header must not fall back to a valid form field.
    for duplicate in [false, true] {
        let mut req = request(Method::POST, format!("_csrf={masked}"));
        req.headers_mut().insert(
            "x-csrf-token",
            if duplicate {
                masked.parse().unwrap()
            } else {
                "wrong".parse().unwrap()
            },
        );
        if duplicate {
            req.headers_mut()
                .append("x-csrf-token", masked.parse().unwrap());
        }
        requests.push(req);
    }
    for req in requests {
        let response = layer
            .layer(service_fn(|_: Request<CsrfBody>| async {
                panic!("rejected requests must not reach the inner service");
                #[allow(unreachable_code)]
                Ok::<_, Infallible>(Response::new(Bytes::new()))
            }))
            .oneshot(req)
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::FORBIDDEN);
        assert!(response.body().is_empty());
    }
}

#[tokio::test]
async fn newly_generated_tokens_never_authenticate_the_current_unsafe_request() {
    let repo = Arc::new(Repository::default());
    let mut req = request(Method::POST, "");
    req.headers_mut()
        .insert("x-csrf-token", token().token.parse().unwrap());
    let response = CsrfLayer::new(repo.clone())
        .mask_tokens(false)
        .layer(service_fn(echo))
        .oneshot(req)
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::FORBIDDEN);
    assert_eq!(repo.saved.load(Ordering::SeqCst), 1);
}

#[tokio::test]
async fn distinguishes_repository_failures_and_limits_form_buffering() {
    for fail in ["load", "generate", "save"] {
        let repo = Repository {
            fail: Some(fail),
            ..Repository::default()
        };
        let response = CsrfLayer::new(Arc::new(repo))
            .layer(service_fn(echo))
            .oneshot(request(Method::GET, ""))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::INTERNAL_SERVER_ERROR);
    }
    let response = CsrfLayer::new(Arc::new(Repository::with_token()))
        .body_limit(4)
        .layer(service_fn(echo))
        .oneshot(request(Method::POST, "_csrf=too-long"))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::PAYLOAD_TOO_LARGE);
    let mut req = request(Method::POST, "_csrf=test-token");
    req.headers_mut().insert(
        header::CONTENT_TYPE,
        "multipart/form-data; boundary=test".parse().unwrap(),
    );
    let response = CsrfLayer::new(Arc::new(Repository::with_token()))
        .mask_tokens(false)
        .layer(service_fn(echo))
        .oneshot(req)
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::FORBIDDEN);
}

#[tokio::test]
async fn supports_raw_tokens_custom_matching_and_failure_handling() {
    #[derive(Clone)]
    struct Never;
    impl RequestMatcher for Never {
        fn matches(&self, _: &Parts) -> bool {
            false
        }
    }
    let response = CsrfLayer::new(Arc::new(Repository::default()))
        .request_matcher(Never)
        .mask_tokens(false)
        .layer(service_fn(echo))
        .oneshot(request(Method::POST, "unchanged"))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(response.headers()["exposed-token"], "test-token");
    let response = CsrfLayer::new(Arc::new(Repository::with_token()))
        .failure_handler(|_: &Parts, failure: CsrfFailure<io::Error>| {
            assert!(matches!(failure, CsrfFailure::InvalidToken));
            Response::builder()
                .status(StatusCode::FORBIDDEN)
                .body(Bytes::from_static(b"csrf rejected"))
                .unwrap()
        })
        .layer(service_fn(echo))
        .oneshot(request(Method::POST, ""))
        .await
        .unwrap();
    assert_eq!(response.body(), "csrf rejected");
    let mut req = request(Method::POST, "");
    req.headers_mut()
        .insert("x-csrf-token", "test-token".parse().unwrap());
    let response = CsrfLayer::new(Arc::new(Repository::with_token()))
        .mask_tokens(false)
        .layer(service_fn(echo))
        .oneshot(req)
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
}

#[tokio::test]
async fn form_buffering_preserves_trailers() {
    let mut trailers = http::HeaderMap::new();
    trailers.insert("x-trailer", "preserved".parse().unwrap());
    let body = StreamBody::new(stream::iter([
        Ok::<_, Infallible>(Frame::data(Bytes::from_static(
            b"_csrf=test-token&username=alice",
        ))),
        Ok(Frame::trailers(trailers.clone())),
    ]));
    let response = CsrfLayer::new(Arc::new(Repository::with_token()))
        .mask_tokens(false)
        .layer(service_fn(echo))
        .oneshot(
            Request::builder()
                .method(Method::POST)
                .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
                .body(body)
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(response.body(), "_csrf=test-token&username=alice");
    assert_eq!(
        response.extensions().get::<http::HeaderMap>(),
        Some(&trailers)
    );
}

#[cfg(feature = "form_login")]
#[tokio::test]
async fn form_login_reads_credentials_after_csrf_validation() {
    use tower_http_access_form_login::FormLoginLayer;
    use user_password_auth::{Credentials, UsernamePasswordAuthenticationProvider};

    #[derive(Clone)]
    struct Provider(Arc<AtomicUsize>);
    impl UsernamePasswordAuthenticationProvider for Provider {
        type Authentication = String;
        type Error = Infallible;
        fn authenticate<'a>(
            &'a self,
            credentials: &'a Credentials,
        ) -> BoxFuture<'a, Result<Option<String>, Infallible>> {
            Box::pin(async move {
                self.0.fetch_add(1, Ordering::SeqCst);
                assert_eq!(credentials.username, "alice");
                assert_eq!(credentials.password, "p+ss word");
                Ok(Some(credentials.username.clone()))
            })
        }
    }
    let calls = Arc::new(AtomicUsize::new(0));
    let service = CsrfLayer::new(Arc::new(Repository::with_token()))
        .layer(FormLoginLayer::new(Provider(calls.clone())).layer(service_fn(echo)));
    let rejected = service
        .clone()
        .oneshot(request(
            Method::POST,
            "username=alice&password=p%2Bss+word&_csrf=wrong",
        ))
        .await
        .unwrap();
    assert_eq!(rejected.status(), StatusCode::FORBIDDEN);
    assert_eq!(calls.load(Ordering::SeqCst), 0);
    let accepted = service
        .oneshot(request(
            Method::POST,
            format!(
                "username=alice&password=p%2Bss+word&_csrf={}",
                mask(&token().token).unwrap()
            ),
        ))
        .await
        .unwrap();
    assert_eq!(accepted.status(), StatusCode::OK);
    assert_eq!(calls.load(Ordering::SeqCst), 1);
}

#[tokio::test]
async fn safe_and_header_authenticated_requests_do_not_poll_the_body() {
    struct UnreadableBody;
    impl http_body::Body for UnreadableBody {
        type Data = Bytes;
        type Error = Infallible;
        fn poll_frame(
            self: std::pin::Pin<&mut Self>,
            _: &mut Context<'_>,
        ) -> Poll<Option<Result<Frame<Bytes>, Infallible>>> {
            panic!("middleware must leave this body streaming")
        }
    }
    for method in [Method::GET, Method::POST] {
        let req = Request::builder()
            .method(method)
            .header("x-csrf-token", mask(&token().token).unwrap())
            .body(UnreadableBody)
            .unwrap();
        let response = CsrfLayer::new(Arc::new(Repository::with_token()))
            .layer(service_fn(|_: Request<CsrfBody>| async {
                Ok::<_, Infallible>(Response::new(Bytes::new()))
            }))
            .oneshot(req)
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
    }
}

#[tokio::test]
async fn forwards_the_service_instance_that_was_polled_ready() {
    struct ReadyService(bool);
    impl Clone for ReadyService {
        fn clone(&self) -> Self {
            Self(false)
        }
    }
    impl Service<Request<CsrfBody>> for ReadyService {
        type Response = Response<Bytes>;
        type Error = Infallible;
        type Future = std::future::Ready<Result<Response<Bytes>, Infallible>>;
        fn poll_ready(&mut self, _: &mut Context<'_>) -> Poll<Result<(), Infallible>> {
            self.0 = true;
            Poll::Ready(Ok(()))
        }
        fn call(&mut self, _: Request<CsrfBody>) -> Self::Future {
            assert!(std::mem::take(&mut self.0));
            std::future::ready(Ok(Response::new(Bytes::new())))
        }
    }
    let response = CsrfLayer::new(Arc::new(Repository::default()))
        .layer(ReadyService(false))
        .oneshot(request(Method::GET, ""))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
}
