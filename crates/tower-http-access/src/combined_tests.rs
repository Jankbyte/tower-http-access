use super::*;
use crate::response::test_response;
use crate::{
    authentication::{
        AuthenticationErrorReason, AuthenticatorError, DelegatingRequestAuthenticator,
    },
    authorization::{
        AllAuthorizationProvider, AuthenticatedAuthorizationProvider, AuthorizationProviderExt,
    },
};
use axum::{
    body::{Body, to_bytes},
    extract::Request,
    http::{StatusCode, request::Parts},
    response::{IntoResponse, Response},
};
use std::{
    future::{poll_fn, ready},
    io,
    sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    },
};

#[derive(Clone)]
struct Authenticator {
    outcome: u8,
}

impl RequestAuthenticator for Authenticator {
    type Authentication = String;

    fn authenticate<'a>(
        &'a self,
        parts: &'a mut Parts,
    ) -> BoxFuture<'a, Result<AuthenticationAttempt<String>, AuthenticatorError>> {
        Box::pin(async move {
            parts.headers.insert("x-auth", "checked".parse().unwrap());
            match self.outcome {
                0 => Ok(AuthenticationAttempt::NotApplicable),
                1 => Ok(AuthenticationAttempt::Authenticated("alex".to_owned())),
                _ => Err(AuthenticatorError::with_response(
                    AuthenticationErrorReason::WrongCredentials,
                    test_response(StatusCode::UNAUTHORIZED, "invalid credentials"),
                )),
            }
        })
    }
}

struct Authorizer {
    identity: Option<&'static str>,
    outcome: u8,
    calls: Arc<AtomicUsize>,
}

impl AuthorizationProvider for Authorizer {
    type Authentication = String;
    type Error = io::Error;

    fn authorize<'a>(
        &'a self,
        identity: Option<&'a String>,
        parts: &'a Parts,
    ) -> BoxFuture<'a, Result<AuthorizationDecision, io::Error>> {
        Box::pin(async move {
            self.calls.fetch_add(1, Ordering::SeqCst);
            assert_eq!(identity.map(String::as_str), self.identity);
            assert!(parts.extensions.get::<Authenticated<String>>().is_none());
            assert_eq!(parts.headers["x-auth"], "checked");
            assert_eq!(parts.uri.path(), "/notes");
            tokio::task::yield_now().await;
            match self.outcome {
                0 => Ok(AuthorizationDecision::Allow),
                1 => Ok(AuthorizationDecision::Deny(
                    AuthorizationDenial::AuthenticationRequired,
                )),
                2 => Ok(AuthorizationDecision::Deny(
                    AuthorizationDenial::InsufficientPermissions,
                )),
                _ => Err(io::Error::other("policy store unavailable")),
            }
        })
    }
}

struct Inner {
    ready: bool,
    calls: Arc<AtomicUsize>,
    fail: bool,
}

impl Clone for Inner {
    fn clone(&self) -> Self {
        Self {
            ready: false,
            calls: Arc::clone(&self.calls),
            fail: self.fail,
        }
    }
}

impl Service<Request> for Inner {
    type Response = Response;
    type Error = io::Error;
    type Future = BoxFuture<'static, Result<Response, io::Error>>;

    fn poll_ready(&mut self, _: &mut Context<'_>) -> Poll<Result<(), io::Error>> {
        self.ready = true;
        Poll::Ready(Ok(()))
    }

    fn call(&mut self, request: Request) -> Self::Future {
        assert!(
            self.ready,
            "must call the service instance that was polled ready"
        );
        self.calls.fetch_add(1, Ordering::SeqCst);
        let fail = self.fail;
        Box::pin(async move {
            if fail {
                return Err(io::Error::other("inner service failed"));
            }
            assert_eq!(request.headers()["x-auth"], "checked");
            let identity = request
                .extensions()
                .get::<Authenticated<String>>()
                .map(|identity| identity.as_inner().clone())
                .unwrap_or("anonymous".to_owned());
            let body = to_bytes(request.into_body(), usize::MAX).await.unwrap();
            Ok(format!("{identity}:{}", String::from_utf8(body.to_vec()).unwrap()).into_response())
        })
    }
}

fn request() -> Request {
    Request::builder()
        .uri("/notes")
        .body(Body::from("payload"))
        .unwrap()
}

async fn execute<S: Service<Request>>(
    service: &mut S,
    request: Request,
) -> Result<S::Response, S::Error> {
    poll_fn(|cx| service.poll_ready(cx)).await?;
    service.call(request).await
}

#[tokio::test]
async fn passes_identity_directly_and_preserves_body_for_handler() {
    let calls = Arc::new(AtomicUsize::new(0));
    let authorizer: Arc<dyn AuthorizationProvider<Authentication = String, Error = io::Error>> =
        Arc::new(Authorizer {
            identity: Some("alex"),
            outcome: 0,
            calls: Arc::clone(&calls),
        });
    let layer = SecurityLayer::new(Authenticator { outcome: 1 }, authorizer);
    // The explicitly shared authorizer does not implement Clone.
    let mut service = layer
        .clone()
        .layer(Inner {
            ready: false,
            calls: Arc::clone(&calls),
            fail: false,
        })
        .clone();
    let response = execute(&mut service, request()).await.unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(
        to_bytes(response.into_body(), usize::MAX).await.unwrap(),
        "alex:payload"
    );
    assert_eq!(calls.load(Ordering::SeqCst), 2);
}

#[tokio::test]
async fn anonymous_request_can_be_allowed_without_inserting_identity() {
    let layer = SecurityLayer::new(
        Authenticator { outcome: 0 },
        Arc::new(Authorizer {
            identity: None,
            outcome: 0,
            calls: Arc::new(AtomicUsize::new(0)),
        }),
    );
    let mut service = layer.layer(Inner {
        ready: false,
        calls: Arc::new(AtomicUsize::new(0)),
        fail: false,
    });
    let response = execute(&mut service, request()).await.unwrap();
    assert_eq!(
        to_bytes(response.into_body(), usize::MAX).await.unwrap(),
        "anonymous:payload"
    );
}

#[tokio::test]
async fn authentication_failure_skips_authorization_and_inner_service() {
    let calls = Arc::new(AtomicUsize::new(0));
    let mut service = SecurityLayer::new(
        Authenticator { outcome: 2 },
        Arc::new(Authorizer {
            identity: None,
            outcome: 0,
            calls: Arc::clone(&calls),
        }),
    )
    .layer(Inner {
        ready: false,
        calls: Arc::clone(&calls),
        fail: false,
    });
    let response = execute(&mut service, request()).await.unwrap();
    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    assert_eq!(
        to_bytes(response.into_body(), usize::MAX).await.unwrap(),
        "invalid credentials"
    );
    assert_eq!(calls.load(Ordering::SeqCst), 0);
}

#[tokio::test]
async fn authorization_failures_use_default_responses_without_calling_inner() {
    for (outcome, status) in [
        (1, StatusCode::UNAUTHORIZED),
        (2, StatusCode::FORBIDDEN),
        (3, StatusCode::INTERNAL_SERVER_ERROR),
    ] {
        let inner_calls = Arc::new(AtomicUsize::new(0));
        let mut service = SecurityLayer::new(
            Authenticator { outcome: 0 },
            Arc::new(Authorizer {
                identity: None,
                outcome,
                calls: Arc::new(AtomicUsize::new(0)),
            }),
        )
        .layer(Inner {
            ready: false,
            calls: Arc::clone(&inner_calls),
            fail: false,
        });
        assert_eq!(
            execute(&mut service, request()).await.unwrap().status(),
            status
        );
        assert_eq!(inner_calls.load(Ordering::SeqCst), 0);
    }
}

#[tokio::test]
async fn custom_failure_handlers_receive_request_and_original_failure() {
    for outcome in 1..=3 {
        let mut service = SecurityLayer::new(
            Authenticator { outcome: 0 },
            Arc::new(Authorizer {
                identity: None,
                outcome,
                calls: Arc::new(AtomicUsize::new(0)),
            }),
        )
        .authentication_entry_point(|request: &Parts| {
            assert_eq!(request.uri.path(), "/notes");
            assert_eq!(request.headers["x-auth"], "checked");
            test_response(StatusCode::FOUND, "")
        })
        .failure_handler(
            move |request: &Parts, failure: AuthorizationFailure<io::Error>| {
                assert_eq!(request.headers["x-auth"], "checked");
                match failure {
                    AuthorizationFailure::Denied(AuthorizationDenial::InsufficientPermissions) => {
                        assert_eq!(outcome, 2)
                    }
                    AuthorizationFailure::Provider(error) => {
                        assert_eq!(outcome, 3);
                        assert_eq!(error.to_string(), "policy store unavailable");
                    }
                    _ => panic!("unexpected failure"),
                }
                test_response(StatusCode::IM_A_TEAPOT, "")
            },
        )
        .layer(Inner {
            ready: false,
            calls: Arc::new(AtomicUsize::new(0)),
            fail: false,
        });
        let expected = if outcome == 1 {
            StatusCode::FOUND
        } else {
            StatusCode::IM_A_TEAPOT
        };
        assert_eq!(
            execute(&mut service, request()).await.unwrap().status(),
            expected
        );
    }
}

#[tokio::test]
async fn supports_composed_and_mapped_authorizers_and_propagates_inner_errors() {
    let authorizer = AllAuthorizationProvider::<String>::builder()
        .with(AuthenticatedAuthorizationProvider::<String>::new())
        .with(
            AuthenticatedAuthorizationProvider::<usize>::new()
                .map(|identity: &String| identity.len()),
        )
        .build()
        .unwrap();
    let mut service = SecurityLayer::new(Authenticator { outcome: 1 }, authorizer).layer(Inner {
        ready: false,
        calls: Arc::new(AtomicUsize::new(0)),
        fail: true,
    });
    assert_eq!(
        execute(&mut service, request())
            .await
            .unwrap_err()
            .to_string(),
        "inner service failed"
    );
}

#[test]
fn applies_to_axum_router() {
    let layer = SecurityLayer::new(
        |_: &mut Parts| {
            ready(Ok::<_, AuthenticatorError>(
                AuthenticationAttempt::Authenticated("alex".to_owned()),
            ))
        },
        AuthenticatedAuthorizationProvider::<String>::new(),
    );
    let _: axum::Router = axum::Router::new()
        .route("/", axum::routing::get(async || "ok"))
        .route_layer(layer);
}

#[tokio::test]
async fn accepts_shared_authenticator() {
    let authenticator = Arc::new(Authenticator { outcome: 1 });
    let calls = Arc::new(AtomicUsize::new(0));
    let mut service = SecurityLayer::new(
        Arc::clone(&authenticator),
        Arc::new(Authorizer {
            identity: Some("alex"),
            outcome: 0,
            calls: Arc::clone(&calls),
        }),
    )
    .layer(Inner {
        ready: false,
        calls: Arc::clone(&calls),
        fail: false,
    });
    let response = execute(&mut service, request()).await.unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(
        to_bytes(response.into_body(), usize::MAX).await.unwrap(),
        "alex:payload"
    );
    assert_eq!(calls.load(Ordering::SeqCst), 2);
}

#[tokio::test]
async fn delegates_to_next_authenticator_and_preserves_request_mutations() {
    let authenticators = DelegatingRequestAuthenticator::builder()
        .authenticator(|parts: &mut Parts| {
            parts
                .headers
                .insert("x-first-attempt", "seen".parse().unwrap());
            ready(Ok::<_, AuthenticatorError>(
                AuthenticationAttempt::<String>::NotApplicable,
            ))
        })
        .authenticator(|parts: &mut Parts| {
            assert_eq!(parts.headers["x-first-attempt"], "seen");
            parts.headers.insert("x-auth", "checked".parse().unwrap());
            ready(Ok::<_, AuthenticatorError>(
                AuthenticationAttempt::Authenticated("alex".to_owned()),
            ))
        })
        .build();
    let calls = Arc::new(AtomicUsize::new(0));
    let mut service = SecurityLayer::new(
        authenticators,
        Arc::new(Authorizer {
            identity: Some("alex"),
            outcome: 0,
            calls: Arc::clone(&calls),
        }),
    )
    .layer(Inner {
        ready: false,
        calls: Arc::clone(&calls),
        fail: false,
    });
    let response = execute(&mut service, request()).await.unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(
        to_bytes(response.into_body(), usize::MAX).await.unwrap(),
        "alex:payload"
    );
    assert_eq!(calls.load(Ordering::SeqCst), 2);
}

#[test]
fn providers_clone_without_requiring_clone_identities() {
    struct Identity;
    fn assert_clone<T: Clone>(_: &T) {}
    assert_clone(&AuthenticatedAuthorizationProvider::<Identity>::new());
    assert_clone(&crate::authorization::AuthorityAuthorizationProvider::<
        Identity,
    >::new("read"));
    assert_clone(&AuthenticatedAuthorizationProvider::<usize>::new().map(|_: &Identity| 1));
    assert_clone(
        &AllAuthorizationProvider::<Identity>::builder()
            .with(AuthenticatedAuthorizationProvider::<Identity>::new())
            .build()
            .unwrap(),
    );
}
