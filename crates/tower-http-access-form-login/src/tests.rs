use super::*;
use crate::RedirectSuccessHandler;
use http::request::Parts;
use http_body_util::Full;
use std::convert::Infallible;
use std::sync::Arc;
use tower::ServiceExt;

#[derive(Clone)]
struct Provider;
impl UsernamePasswordAuthenticationProvider for Provider {
    type Authentication = String;
    type Error = std::io::Error;
    fn authenticate<'a>(
        &'a self,
        credentials: &'a Credentials,
    ) -> BoxFuture<'a, Result<Option<String>, Self::Error>> {
        Box::pin(async move {
            if credentials.username == "backend" {
                return Err(std::io::Error::other("backend unavailable"));
            }
            Ok(
                (credentials.username == "alice" && credentials.password == "p+ss word")
                    .then(|| credentials.username.clone()),
            )
        })
    }
}

fn request(method: Method, path: &str, body: &'static str) -> Request<Full<Bytes>> {
    Request::builder()
        .method(method)
        .uri(path)
        .header(
            header::CONTENT_TYPE,
            "application/x-www-form-urlencoded; charset=UTF-8",
        )
        .body(Full::new(Bytes::from_static(body.as_bytes())))
        .unwrap()
}

async fn run<P, M, H, F>(
    layer: FormLoginLayer<P, M, H, F>,
    request: Request<Full<Bytes>>,
) -> Response<Bytes>
where
    P: UsernamePasswordAuthenticationProvider + Clone + 'static,
    M: RequestMatcher + Clone + 'static,
    H: SuccessHandler<P::Authentication> + Clone + 'static,
    F: FailureHandler + Clone + 'static,
{
    layer
        .layer(tower::service_fn(
            |request: Request<Full<Bytes>>| async move {
                let body = request.into_body().collect().await.unwrap().to_bytes();
                Ok::<_, Infallible>(
                    Response::builder()
                        .status(StatusCode::ACCEPTED)
                        .body(body)
                        .unwrap(),
                )
            },
        ))
        .oneshot(request)
        .await
        .unwrap()
}

#[tokio::test]
async fn nonmatching_requests_preserve_body() {
    for (method, path) in [(Method::GET, "/login"), (Method::POST, "/other")] {
        let response = run(
            FormLoginLayer::new(Provider),
            request(method, path, "untouched"),
        )
        .await;
        assert_eq!(response.status(), StatusCode::ACCEPTED);
        assert_eq!(response.body(), "untouched");
    }
}

#[tokio::test]
async fn configured_login_decodes_fields_and_invokes_success() {
    let layer = FormLoginLayer::new(Provider)
        .request_matcher(
            PathPatternRequestMatcher::new("/ui/login")
                .unwrap()
                .with_method(Method::PUT),
        )
        .username_parameter("user")
        .password_parameter("pass")
        .on_success(|parts: Parts, identity: String| async move {
            assert_eq!(parts.uri.path(), "/ui/login");
            assert_eq!(identity, "alice");
            Response::builder()
                .status(StatusCode::SEE_OTHER)
                .header(header::LOCATION, "/ui")
                .body(Bytes::new())
                .unwrap()
        });
    let response = run(
        layer,
        request(
            Method::PUT,
            "/ui/login?next=home",
            "user=alice&pass=p%2Bss+word",
        ),
    )
    .await;
    assert_eq!(response.status(), StatusCode::SEE_OTHER);
    assert_eq!(response.headers()[header::LOCATION], "/ui");
}

#[tokio::test]
async fn failures_are_distinguished_and_customizable() {
    for (body, status) in [
        ("username=alice&password=wrong", StatusCode::UNAUTHORIZED),
        (
            "username=backend&password=x",
            StatusCode::INTERNAL_SERVER_ERROR,
        ),
        ("username=alice", StatusCode::BAD_REQUEST),
        (
            "username=alice&username=bob&password=x",
            StatusCode::BAD_REQUEST,
        ),
    ] {
        assert_eq!(
            run(
                FormLoginLayer::new(Provider),
                request(Method::POST, "/login", body)
            )
            .await
            .status(),
            status
        );
    }
    let layer = FormLoginLayer::new(Provider).on_failure(|_, error| async move {
        assert!(matches!(error, FormLoginError::InvalidCredentials));
        Response::builder()
            .status(StatusCode::SEE_OTHER)
            .header(header::LOCATION, "/login?error")
            .body(Bytes::new())
            .unwrap()
    });
    assert_eq!(
        run(
            layer,
            request(Method::POST, "/login", "username=alice&password=wrong")
        )
        .await
        .headers()[header::LOCATION],
        "/login?error"
    );
}

#[tokio::test]
async fn custom_failure_handler_receives_boxed_backend_error() {
    let layer =
        FormLoginLayer::new(Provider).on_failure(|_: Parts, error: FormLoginError| async move {
            use std::error::Error;

            assert!(matches!(&error, FormLoginError::Backend(_)));
            assert_eq!(error.source().unwrap().to_string(), "backend unavailable");
            response(StatusCode::SERVICE_UNAVAILABLE)
        });
    let result = run(
        layer,
        request(Method::POST, "/login", "username=backend&password=x"),
    )
    .await;
    assert_eq!(result.status(), StatusCode::SERVICE_UNAVAILABLE);
}

#[tokio::test]
async fn rejects_oversized_body_and_wrong_content_type() {
    assert_eq!(
        run(
            FormLoginLayer::new(Provider).body_limit(4),
            request(Method::POST, "/login", "username=alice")
        )
        .await
        .status(),
        StatusCode::PAYLOAD_TOO_LARGE
    );
    let mut req = request(Method::POST, "/login", "username=alice");
    req.headers_mut().remove(header::CONTENT_TYPE);
    assert_eq!(
        run(FormLoginLayer::new(Provider), req).await.status(),
        StatusCode::UNSUPPORTED_MEDIA_TYPE
    );
}

#[derive(Clone)]
struct RedirectSuccess {
    location: String,
}

impl SuccessHandler<String> for RedirectSuccess {
    fn on_success(&self, _: Parts, identity: String) -> BoxFuture<'_, SecurityResponse> {
        Box::pin(async move {
            assert_eq!(identity, "alice");
            Response::builder()
                .status(StatusCode::SEE_OTHER)
                .header(header::LOCATION, &self.location)
                .body(Bytes::new())
                .unwrap()
        })
    }
}

#[derive(Clone)]
struct RejectFailure;

impl FailureHandler for RejectFailure {
    fn on_failure(&self, _: Parts, error: FormLoginError) -> BoxFuture<'_, SecurityResponse> {
        Box::pin(async move {
            assert!(matches!(error, FormLoginError::InvalidCredentials));
            response(StatusCode::FORBIDDEN)
        })
    }
}

#[tokio::test]
async fn accepts_custom_handler_types() {
    let layer = FormLoginLayer::new(Provider)
        .on_success(RedirectSuccess {
            location: "/welcome".into(),
        })
        .on_failure(RejectFailure);
    let success = run(
        layer.clone(),
        request(
            Method::POST,
            "/login",
            "username=alice&password=p%2Bss+word",
        ),
    )
    .await;
    assert_eq!(success.status(), StatusCode::SEE_OTHER);
    assert_eq!(success.headers()[header::LOCATION], "/welcome");
    let failure = run(
        layer,
        request(Method::POST, "/login", "username=alice&password=wrong"),
    )
    .await;
    assert_eq!(failure.status(), StatusCode::FORBIDDEN);
}

#[tokio::test]
async fn matcher_supports_path_patterns_and_method_restrictions() {
    let layer = FormLoginLayer::new(Provider).request_matcher(
        PathPatternRequestMatcher::new("/tenants/{tenant}/login")
            .unwrap()
            .with_method(Method::POST),
    );
    let response = run(
        layer.clone(),
        request(
            Method::POST,
            "/tenants/acme/login",
            "username=alice&password=p%2Bss+word",
        ),
    )
    .await;
    assert_eq!(response.status(), StatusCode::OK);
    let response = run(
        layer,
        request(Method::GET, "/tenants/acme/login", "untouched"),
    )
    .await;
    assert_eq!(response.status(), StatusCode::ACCEPTED);
    assert_eq!(response.body(), "untouched");
}

#[test]
fn redirect_handler_validates_configured_path() {
    for path in [
        "",
        "private",
        "//example.com",
        "https://example.com",
        "/\\example.com",
        "/private#fragment",
        "/private\r\nlocation: evil",
    ] {
        assert!(RedirectSuccessHandler::new(path).is_err(), "{path:?}");
    }
    assert!(RedirectSuccessHandler::new("/").is_ok());
}

#[tokio::test]
async fn shared_trait_objects_support_non_clone_components() {
    use std::sync::atomic::{AtomicUsize, Ordering};
    struct SharedProvider;
    impl UsernamePasswordAuthenticationProvider for SharedProvider {
        type Authentication = String;
        type Error = std::io::Error;
        fn authenticate<'a>(
            &'a self,
            credentials: &'a Credentials,
        ) -> BoxFuture<'a, Result<Option<String>, Self::Error>> {
            Provider.authenticate(credentials)
        }
    }
    struct LoginMatcher;
    impl RequestMatcher for LoginMatcher {
        fn matches(&self, parts: &Parts) -> bool {
            parts.method == Method::POST && parts.uri.path() == "/shared-login"
        }
    }
    struct Handlers(AtomicUsize);
    impl SuccessHandler<String> for Handlers {
        fn on_success(&self, _: Parts, user: String) -> BoxFuture<'_, SecurityResponse> {
            Box::pin(async move {
                assert_eq!(user, "alice");
                self.0.fetch_add(1, Ordering::SeqCst);
                response(StatusCode::NO_CONTENT)
            })
        }
    }
    impl FailureHandler for Handlers {
        fn on_failure(&self, _: Parts, error: FormLoginError) -> BoxFuture<'_, SecurityResponse> {
            Box::pin(async move {
                assert!(matches!(error, FormLoginError::InvalidCredentials));
                self.0.fetch_add(1, Ordering::SeqCst);
                response(StatusCode::FORBIDDEN)
            })
        }
    }
    let provider: Arc<
        dyn UsernamePasswordAuthenticationProvider<Authentication = String, Error = std::io::Error>,
    > = Arc::new(SharedProvider);
    let matcher: Arc<dyn RequestMatcher> = Arc::new(LoginMatcher);
    let handlers = Arc::new(Handlers(AtomicUsize::new(0)));
    let success: Arc<dyn SuccessHandler<String>> = handlers.clone();
    let failure: Arc<dyn FailureHandler> = handlers.clone();
    let layer = FormLoginLayer::new(provider)
        .request_matcher(matcher)
        .on_success(success)
        .on_failure(failure);
    assert_eq!(
        run(
            layer.clone(),
            request(
                Method::POST,
                "/shared-login",
                "username=alice&password=p%2Bss+word"
            )
        )
        .await
        .status(),
        StatusCode::NO_CONTENT
    );
    assert_eq!(
        run(
            layer,
            request(
                Method::POST,
                "/shared-login",
                "username=alice&password=wrong"
            )
        )
        .await
        .status(),
        StatusCode::FORBIDDEN
    );
    assert_eq!(handlers.0.load(Ordering::SeqCst), 2);
}

#[tokio::test]
async fn builtin_success_handlers_return_ok_or_redirect() {
    let body = "username=alice&password=p%2Bss+word";
    let result = run(
        FormLoginLayer::new(Provider).on_success(DefaultSuccessHandler),
        request(Method::POST, "/login", body),
    )
    .await;
    assert_eq!(result.status(), StatusCode::OK);
    assert!(result.body().is_empty());
    assert!(!result.headers().contains_key(header::LOCATION));

    let result = run(
        FormLoginLayer::new(Provider)
            .on_success(RedirectSuccessHandler::new("/private?welcome=true").unwrap()),
        request(Method::POST, "/login", body),
    )
    .await;
    assert_eq!(result.status(), StatusCode::SEE_OTHER);
    assert_eq!(result.headers()[header::LOCATION], "/private?welcome=true");
    assert!(result.body().is_empty());
}
