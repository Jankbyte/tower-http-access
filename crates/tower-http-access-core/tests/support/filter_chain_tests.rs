use super::*;
use http_request_matcher::PathPatternRequestMatcher;
use std::{
    future::{Ready, ready},
    sync::atomic::{AtomicUsize, Ordering},
};

#[derive(Clone)]
struct App(Arc<AtomicUsize>);
impl Service<Request<Bytes>> for App {
    type Response = Response<Bytes>;
    type Error = &'static str;
    type Future = Ready<Result<Self::Response, Self::Error>>;
    fn poll_ready(&mut self, _: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        Poll::Ready(Ok(()))
    }
    fn call(&mut self, request: Request<Bytes>) -> Self::Future {
        self.0.fetch_add(1, Ordering::SeqCst);
        assert_eq!(request.headers()["x-test"], "preserved");
        assert_eq!(request.extensions().get::<u32>(), Some(&42));
        ready(Ok(Response::new(request.into_body())))
    }
}

#[derive(Clone, Copy)]
enum Mode {
    Deny,
    CallError,
    ReadinessError,
    Pending,
}
#[derive(Clone)]
struct ProbeLayer {
    mode: Mode,
    polls: Arc<AtomicUsize>,
}
impl Layer<App> for ProbeLayer {
    type Service = Probe;
    fn layer(&self, _: App) -> Probe {
        Probe(self.clone())
    }
}
#[derive(Clone)]
struct Probe(ProbeLayer);
impl Service<Request<Bytes>> for Probe {
    type Response = Response<Bytes>;
    type Error = &'static str;
    type Future = Ready<Result<Self::Response, Self::Error>>;
    fn poll_ready(&mut self, _: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        self.0.polls.fetch_add(1, Ordering::SeqCst);
        match self.0.mode {
            Mode::Pending => Poll::Pending,
            Mode::ReadinessError => Poll::Ready(Err("readiness error")),
            _ => Poll::Ready(Ok(())),
        }
    }
    fn call(&mut self, _: Request<Bytes>) -> Self::Future {
        assert!(self.0.polls.load(Ordering::SeqCst) > 0);
        match self.0.mode {
            Mode::CallError => ready(Err("call error")),
            Mode::Deny => {
                let mut response = Response::new(Bytes::new());
                *response.status_mut() = StatusCode::UNAUTHORIZED;
                ready(Ok(response))
            }
            _ => panic!("service should not be called"),
        }
    }
}
fn matcher(path: &str) -> PathPatternRequestMatcher {
    PathPatternRequestMatcher::new(path).unwrap()
}
fn request(path: &str) -> Request<Bytes> {
    let mut request = Request::builder()
        .uri(path)
        .header("x-test", "preserved")
        .body(Bytes::from_static(b"stream contents"))
        .unwrap();
    request.extensions_mut().insert(42_u32);
    request
}

#[tokio::test]
async fn first_match_is_final_for_denials_and_errors() {
    for (mode, error) in [
        (Mode::Deny, None),
        (Mode::CallError, Some("call error")),
        (Mode::ReadinessError, Some("readiness error")),
    ] {
        let calls = Arc::new(AtomicUsize::new(0));
        let polls = Arc::new(AtomicUsize::new(0));
        let later_polls = Arc::new(AtomicUsize::new(0));
        let layer = SecurityChainLayer::builder()
            .chain(
                matcher("/api/{*rest}"),
                ProbeLayer {
                    mode,
                    polls: Arc::clone(&polls),
                },
            )
            .chain(
                matcher("/api/private"),
                ProbeLayer {
                    mode: Mode::Pending,
                    polls: Arc::clone(&later_polls),
                },
            )
            .fallback_passthrough()
            .build()
            .unwrap();
        let response = layer
            .layer(App(Arc::clone(&calls)))
            .oneshot(request("/api/private"))
            .await;
        match error {
            Some(error) => assert_eq!(response.unwrap_err(), error),
            None => assert_eq!(response.unwrap().status(), StatusCode::UNAUTHORIZED),
        }
        assert_eq!(calls.load(Ordering::SeqCst), 0);
        assert_eq!(polls.load(Ordering::SeqCst), 1);
        assert_eq!(later_polls.load(Ordering::SeqCst), 0);
    }
}

#[tokio::test]
async fn only_selected_chain_is_polled_and_request_is_preserved() {
    let polls = Arc::new(AtomicUsize::new(0));
    let calls = Arc::new(AtomicUsize::new(0));
    let layer = SecurityChainLayer::builder()
        .chain(
            matcher("/blocked"),
            ProbeLayer {
                mode: Mode::Pending,
                polls: Arc::clone(&polls),
            },
        )
        .chain(matcher("/api/{*rest}"), tower_layer::Identity::new())
        .fallback_passthrough()
        .build()
        .unwrap();
    let service = layer.clone().layer(App(Arc::clone(&calls)));
    for path in ["/api/hello?x=1", "/public"] {
        let response = service.clone().oneshot(request(path)).await.unwrap();
        assert_eq!(response.into_body(), "stream contents");
    }
    assert_eq!(calls.load(Ordering::SeqCst), 2);
    assert_eq!(polls.load(Ordering::SeqCst), 0);
}

#[tokio::test]
async fn explicit_fallbacks() {
    assert!(
        SecurityChainLayer::<App, Bytes, Bytes, &'static str>::builder()
            .build()
            .is_err()
    );
    let calls = Arc::new(AtomicUsize::new(0));
    let deny = SecurityChainLayer::<App, Bytes, Bytes, &'static str>::builder()
        .fallback_deny()
        .build()
        .unwrap();
    assert_eq!(
        deny.layer(App(Arc::clone(&calls)))
            .oneshot(request("/"))
            .await
            .unwrap()
            .status(),
        StatusCode::FORBIDDEN
    );
    assert_eq!(calls.load(Ordering::SeqCst), 0);
    let polls = Arc::new(AtomicUsize::new(0));
    let custom = SecurityChainLayer::builder()
        .fallback(ProbeLayer {
            mode: Mode::Deny,
            polls,
        })
        .build()
        .unwrap();
    assert_eq!(
        custom
            .layer(App(calls))
            .oneshot(request("/"))
            .await
            .unwrap()
            .status(),
        StatusCode::UNAUTHORIZED
    );
}

#[cfg(feature = "axum")]
#[tokio::test]
async fn different_identity_types_work_with_axum_and_service_builder() {
    use crate::SecurityLayer;
    use crate::authentication::Authenticated;
    use crate::authentication::AuthenticationAttempt;
    use crate::authentication::AuthenticatorError;
    use tower_http_access_authorizers::default_auth::AuthenticatedAuthorizationProvider;
    use axum::{Router, body::Body, routing::get};
    let strings = |_: &http::request::Parts| async {
        Ok::<_, AuthenticatorError>(AuthenticationAttempt::Authenticated("alice".to_owned()))
    };
    let numbers = |_: &http::request::Parts| async {
        Ok::<_, AuthenticatorError>(AuthenticationAttempt::Authenticated(42_u32))
    };
    let layer = SecurityChainLayer::builder()
        .chain(
            matcher("/string"),
            SecurityLayer::new(strings, AuthenticatedAuthorizationProvider::<String>::new()),
        )
        .chain(
            matcher("/number"),
            tower::ServiceBuilder::new().layer(SecurityLayer::new(
                numbers,
                AuthenticatedAuthorizationProvider::<u32>::new(),
            )),
        )
        .fallback_deny()
        .build()
        .unwrap();
    let app: Router = Router::new()
        .route(
            "/string",
            get(|Authenticated(name): Authenticated<String>| async move { name }),
        )
        .route(
            "/number",
            get(|Authenticated(id): Authenticated<u32>| async move { id.to_string() }),
        )
        .layer(layer);
    for (path, expected) in [("/string", "alice"), ("/number", "42")] {
        let response = app
            .clone()
            .oneshot(Request::builder().uri(path).body(Body::empty()).unwrap())
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(
            axum::body::to_bytes(response.into_body(), 1024)
                .await
                .unwrap(),
            expected
        );
    }
}
