use super::*;
use crate::form_login::{RedirectSuccessHandler, SessionSetSuccessHandler};
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
    F: FailureHandler<P::Error> + Clone + 'static,
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

impl FailureHandler<std::io::Error> for RejectFailure {
    fn on_failure(
        &self,
        _: Parts,
        error: FormLoginError<std::io::Error>,
    ) -> BoxFuture<'_, SecurityResponse> {
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

#[tokio::test]
async fn session_success_rotates_stores_and_then_delegates() {
    use tower_sessions::{MemoryStore, Session};
    let store = Arc::new(MemoryStore::default());
    let session = Session::new(None, store.clone(), None);
    session.insert("existing", true).await.unwrap();
    session.save().await.unwrap();
    let old_id = session.id();
    let handler = SessionSetSuccessHandler::new(
        |identity: &String| identity.clone(),
        |parts: Parts, identity: String| async move {
            let session = parts.extensions.get::<Session>().unwrap();
            assert_eq!(
                session.get::<String>("user_id").await.unwrap(),
                Some(identity)
            );
            assert_eq!(session.get::<bool>("existing").await.unwrap(), Some(true));
            Response::builder()
                .status(StatusCode::SEE_OTHER)
                .header(header::LOCATION, "/private")
                .body(Bytes::new())
                .unwrap()
        },
    );
    let mut req = request(
        Method::POST,
        "/login",
        "username=alice&password=p%2Bss+word",
    );
    req.extensions_mut().insert(session.clone());
    let result = run(FormLoginLayer::new(Provider).on_success(handler), req).await;
    assert_eq!(result.status(), StatusCode::SEE_OTHER);
    assert_eq!(result.headers()[header::LOCATION], "/private");
    session.save().await.unwrap();
    assert_ne!(session.id(), old_id);
    let restored = Session::new(session.id(), store.clone(), None);
    assert_eq!(
        restored.get::<String>("user_id").await.unwrap().as_deref(),
        Some("alice")
    );
    let previous = Session::new(old_id, store, None);
    assert_eq!(previous.get::<String>("user_id").await.unwrap(), None);
}

#[tokio::test]
async fn session_success_supports_custom_key_and_requires_session() {
    use tower_sessions::{MemoryStore, Session};
    let handler = SessionSetSuccessHandler::new(
        |identity: &String| identity.clone(),
        |_: Parts, _: String| async { response(StatusCode::NO_CONTENT) },
    )
    .with_session_key("principal");
    let layer = FormLoginLayer::new(Provider).on_success(handler);
    let body = "username=alice&password=p%2Bss+word";
    assert_eq!(
        run(layer.clone(), request(Method::POST, "/login", body))
            .await
            .status(),
        StatusCode::INTERNAL_SERVER_ERROR
    );
    let session = Session::new(None, Arc::new(MemoryStore::default()), None);
    let mut req = request(Method::POST, "/login", body);
    req.extensions_mut().insert(session.clone());
    assert_eq!(run(layer, req).await.status(), StatusCode::NO_CONTENT);
    assert_eq!(
        session.get::<String>("principal").await.unwrap().as_deref(),
        Some("alice")
    );
    assert_eq!(session.get::<String>("user_id").await.unwrap(), None);
}

#[tokio::test]
async fn session_success_does_not_delegate_on_serialization_failure() {
    use tower_sessions::{MemoryStore, Session};
    struct Unserializable;
    impl serde::Serialize for Unserializable {
        fn serialize<S: serde::Serializer>(&self, _: S) -> Result<S::Ok, S::Error> {
            Err(serde::ser::Error::custom("cannot serialize identity"))
        }
    }
    let handler = SessionSetSuccessHandler::new(
        |_: &String| Unserializable,
        |_: Parts, _: String| async { panic!("must not delegate after session failure") },
    );
    let mut req = request(
        Method::POST,
        "/login",
        "username=alice&password=p%2Bss+word",
    );
    req.extensions_mut()
        .insert(Session::new(None, Arc::new(MemoryStore::default()), None));
    assert_eq!(
        run(FormLoginLayer::new(Provider).on_success(handler), req)
            .await
            .status(),
        StatusCode::INTERNAL_SERVER_ERROR
    );
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

    let session =
        tower_sessions::Session::new(None, Arc::new(tower_sessions::MemoryStore::default()), None);
    let handler = SessionSetSuccessHandler::new(
        |user: &String| user.clone(),
        RedirectSuccessHandler::new("/private?welcome=true").unwrap(),
    );
    let mut req = request(Method::POST, "/login", body);
    req.extensions_mut().insert(session.clone());
    let result = run(FormLoginLayer::new(Provider).on_success(handler), req).await;
    assert_eq!(result.status(), StatusCode::SEE_OTHER);
    assert_eq!(result.headers()[header::LOCATION], "/private?welcome=true");
    assert!(result.body().is_empty());
    assert_eq!(
        session.get::<String>("user_id").await.unwrap().as_deref(),
        Some("alice")
    );
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
    impl FailureHandler<std::io::Error> for Handlers {
        fn on_failure(
            &self,
            _: Parts,
            error: FormLoginError<std::io::Error>,
        ) -> BoxFuture<'_, SecurityResponse> {
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
    let failure: Arc<dyn FailureHandler<std::io::Error>> = handlers.clone();
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
