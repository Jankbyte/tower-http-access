use super::*;
use crate::{
    SecurityLayer,
    authentication::{
        Authenticated, AuthenticationAttempt, AuthenticationErrorReason, AuthenticationLayer,
        AuthenticatorError, RequestAuthenticator,
    },
    authorization::{
        AuthenticatedAuthorizationProvider, AuthorizationDecision, AuthorizationDenial,
        AuthorizationFailure, AuthorizationLayer, AuthorizationProvider,
    },
};
use futures_util::future::BoxFuture;
use http::{Request, header, request::Parts};
use http_body::{Body, Frame};
use http_body_util::{BodyExt, Full};
use std::{
    collections::VecDeque,
    convert::Infallible,
    future::{Ready, ready},
    io,
    pin::Pin,
    sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    },
    task::{Context, Poll},
};
use tower::{Layer, Service, ServiceExt, service_fn, util::BoxCloneService};

#[derive(Clone, Debug, Eq, PartialEq)]
struct ResponseMarker;

fn challenge(status: StatusCode, text: impl Into<Bytes>) -> SecurityResponse {
    let mut response = test_response(status, text);
    response.headers_mut().insert(
        header::WWW_AUTHENTICATE,
        "ApiKey realm=\"Notes\"".parse().unwrap(),
    );
    response
        .headers_mut()
        .insert(header::CONTENT_TYPE, "text/plain".parse().unwrap());
    response.extensions_mut().insert(ResponseMarker);
    response
}

struct TokenAuthenticator;

impl RequestAuthenticator for TokenAuthenticator {
    type Authentication = String;

    fn authenticate<'a>(
        &'a self,
        parts: &'a mut Parts,
    ) -> BoxFuture<'a, Result<AuthenticationAttempt<String>, AuthenticatorError>> {
        Box::pin(async move {
            match parts.headers.get("api-key") {
                None => Ok(AuthenticationAttempt::NotApplicable),
                Some(token) if token == "valid" => {
                    Ok(AuthenticationAttempt::Authenticated("alex".to_owned()))
                }
                Some(_) => Err(AuthenticatorError::with_response(
                    AuthenticationErrorReason::WrongCredentials,
                    challenge(StatusCode::UNAUTHORIZED, "invalid token"),
                )),
            }
        })
    }
}

struct DenyProvider(bool);

impl AuthorizationProvider for DenyProvider {
    type Authentication = String;
    type Error = io::Error;

    fn authorize<'a>(
        &'a self,
        _: Option<&'a String>,
        _: &'a Parts,
    ) -> BoxFuture<'a, Result<AuthorizationDecision, io::Error>> {
        Box::pin(async move {
            if self.0 {
                Err(io::Error::other("policy unavailable"))
            } else {
                Ok(AuthorizationDecision::Deny(
                    AuthorizationDenial::InsufficientPermissions,
                ))
            }
        })
    }
}

type Reply<B> = Ready<Result<Response<B>, Infallible>>;

fn inner<B, F>(
    make_body: F,
    calls: Arc<AtomicUsize>,
) -> impl Service<Request<Vec<u8>>, Response = Response<B>, Error = Infallible, Future = Reply<B>> + Clone
where
    B: Send + 'static,
    F: Fn() -> B + Clone + Send + 'static,
{
    service_fn(move |request: Request<Vec<u8>>| {
        calls.fetch_add(1, Ordering::SeqCst);
        assert_eq!(request.body(), b"payload");
        assert_eq!(
            request
                .extensions()
                .get::<Authenticated<String>>()
                .unwrap()
                .as_inner(),
            "alex"
        );
        let mut response = Response::new(make_body());
        *response.status_mut() = StatusCode::ACCEPTED;
        response
            .headers_mut()
            .insert("x-inner", "preserved".parse().unwrap());
        response.extensions_mut().insert(ResponseMarker);
        ready(Ok(response))
    })
}

fn request(token: Option<&str>) -> Request<Vec<u8>> {
    let mut request = Request::builder()
        .uri("/notes")
        .body(b"payload".to_vec())
        .unwrap();
    if let Some(token) = token {
        request
            .headers_mut()
            .insert("api-key", token.parse().unwrap());
    }
    request
}

#[tokio::test]
async fn combined_and_separate_layers_support_plain_byte_responses() {
    let calls = Arc::new(AtomicUsize::new(0));
    let raw = inner(|| Bytes::from_static(b"success"), Arc::clone(&calls));
    let services = [
        BoxCloneService::new(
            SecurityLayer::new(
                TokenAuthenticator,
                AuthenticatedAuthorizationProvider::<String>::new(),
            )
            .layer(raw.clone()),
        ),
        BoxCloneService::new(
            AuthenticationLayer::new(TokenAuthenticator).layer(
                AuthorizationLayer::builder(AuthenticatedAuthorizationProvider::<String>::new())
                    .build()
                    .layer(raw),
            ),
        ),
    ];
    for service in services {
        let response = service.oneshot(request(Some("valid"))).await.unwrap();
        assert_eq!(response.status(), StatusCode::ACCEPTED);
        assert_eq!(response.headers()["x-inner"], "preserved");
        assert_eq!(
            response.extensions().get::<ResponseMarker>(),
            Some(&ResponseMarker)
        );
        assert_eq!(response.into_body(), Bytes::from_static(b"success"));
    }
    assert_eq!(calls.load(Ordering::SeqCst), 2);
}

#[tokio::test]
async fn security_responses_convert_to_full_bodies_and_preserve_http_metadata() {
    let calls = Arc::new(AtomicUsize::new(0));
    let raw = inner(
        || Full::new(Bytes::from_static(b"unused")),
        Arc::clone(&calls),
    );
    let entry_point = |parts: &Parts| {
        assert_eq!(parts.uri.path(), "/notes");
        challenge(StatusCode::UNAUTHORIZED, "authentication required")
    };
    let handler = |parts: &Parts, failure: AuthorizationFailure<io::Error>| {
        assert_eq!(parts.uri.path(), "/notes");
        match failure {
            AuthorizationFailure::Denied(AuthorizationDenial::InsufficientPermissions) => {
                challenge(StatusCode::FORBIDDEN, "denied")
            }
            AuthorizationFailure::Provider(error) => {
                assert_eq!(error.to_string(), "policy unavailable");
                challenge(StatusCode::INTERNAL_SERVER_ERROR, "backend failed")
            }
            _ => panic!("unexpected failure"),
        }
    };
    let cases = [
        (
            BoxCloneService::new(AuthenticationLayer::new(TokenAuthenticator).layer(raw.clone())),
            Some("invalid"),
            StatusCode::UNAUTHORIZED,
            "invalid token",
        ),
        (
            BoxCloneService::new(
                SecurityLayer::new(
                    TokenAuthenticator,
                    AuthenticatedAuthorizationProvider::<String>::new(),
                )
                .layer(raw.clone()),
            ),
            Some("invalid"),
            StatusCode::UNAUTHORIZED,
            "invalid token",
        ),
        (
            BoxCloneService::new(
                SecurityLayer::new(
                    TokenAuthenticator,
                    AuthenticatedAuthorizationProvider::<String>::new(),
                )
                .authentication_entry_point(entry_point)
                .layer(raw.clone()),
            ),
            None,
            StatusCode::UNAUTHORIZED,
            "authentication required",
        ),
        (
            BoxCloneService::new(
                AuthorizationLayer::builder(AuthenticatedAuthorizationProvider::<String>::new())
                    .authentication_entry_point(entry_point)
                    .build()
                    .layer(raw.clone()),
            ),
            None,
            StatusCode::UNAUTHORIZED,
            "authentication required",
        ),
        (
            BoxCloneService::new(
                SecurityLayer::new(TokenAuthenticator, DenyProvider(false))
                    .failure_handler(handler)
                    .layer(raw.clone()),
            ),
            Some("valid"),
            StatusCode::FORBIDDEN,
            "denied",
        ),
        (
            BoxCloneService::new(
                SecurityLayer::new(TokenAuthenticator, DenyProvider(true))
                    .failure_handler(handler)
                    .layer(raw.clone()),
            ),
            Some("valid"),
            StatusCode::INTERNAL_SERVER_ERROR,
            "backend failed",
        ),
        (
            BoxCloneService::new(
                AuthorizationLayer::builder(DenyProvider(false))
                    .failure_handler(handler)
                    .build()
                    .layer(raw.clone()),
            ),
            None,
            StatusCode::FORBIDDEN,
            "denied",
        ),
        (
            BoxCloneService::new(
                AuthorizationLayer::builder(DenyProvider(true))
                    .failure_handler(handler)
                    .build()
                    .layer(raw),
            ),
            None,
            StatusCode::INTERNAL_SERVER_ERROR,
            "backend failed",
        ),
    ];
    for (service, token, status, text) in cases {
        let response = service.oneshot(request(token)).await.unwrap();
        assert_eq!(response.status(), status);
        assert_eq!(
            response.headers()[header::WWW_AUTHENTICATE],
            "ApiKey realm=\"Notes\""
        );
        assert_eq!(response.headers()[header::CONTENT_TYPE], "text/plain");
        assert_eq!(
            response.extensions().get::<ResponseMarker>(),
            Some(&ResponseMarker)
        );
        assert_eq!(
            response.into_body().collect().await.unwrap().to_bytes(),
            text
        );
    }
    assert_eq!(calls.load(Ordering::SeqCst), 0);
}

struct StreamingBody {
    chunks: VecDeque<Bytes>,
    polls: Arc<AtomicUsize>,
}

impl From<Bytes> for StreamingBody {
    fn from(bytes: Bytes) -> Self {
        Self {
            chunks: VecDeque::from([bytes]),
            polls: Arc::new(AtomicUsize::new(0)),
        }
    }
}

impl Body for StreamingBody {
    type Data = Bytes;
    type Error = Infallible;

    fn poll_frame(
        mut self: Pin<&mut Self>,
        _: &mut Context<'_>,
    ) -> Poll<Option<Result<Frame<Bytes>, Infallible>>> {
        self.polls.fetch_add(1, Ordering::SeqCst);
        Poll::Ready(self.chunks.pop_front().map(|chunk| Ok(Frame::data(chunk))))
    }
}

#[tokio::test]
async fn successful_streaming_body_is_forwarded_without_polling_or_replacing_it() {
    for combined in [false, true] {
        let polls = Arc::new(AtomicUsize::new(0));
        let body_polls = Arc::clone(&polls);
        let raw = inner(
            move || StreamingBody {
                chunks: VecDeque::from([
                    Bytes::from_static(b"first"),
                    Bytes::from_static(b"second"),
                ]),
                polls: Arc::clone(&body_polls),
            },
            Arc::new(AtomicUsize::new(0)),
        );
        let service = if combined {
            BoxCloneService::new(
                SecurityLayer::new(
                    TokenAuthenticator,
                    AuthenticatedAuthorizationProvider::<String>::new(),
                )
                .layer(raw),
            )
        } else {
            BoxCloneService::new(AuthenticationLayer::new(TokenAuthenticator).layer(
                AuthorizationLayer::builder(AuthenticatedAuthorizationProvider::<String>::new()).build().layer(raw),
            ))
        };
        let response = service.oneshot(request(Some("valid"))).await.unwrap();
        assert_eq!(polls.load(Ordering::SeqCst), 0);
        assert!(Arc::ptr_eq(&response.body().polls, &polls));
        assert_eq!(
            response.into_body().collect().await.unwrap().to_bytes(),
            "firstsecond"
        );
        assert!(polls.load(Ordering::SeqCst) > 0);
    }
}

// Deliberately has no From<Bytes> implementation.
struct AdaptedBody(Bytes);

// Deliberately has no Clone implementation.
struct RecordingAdapter {
    calls: Arc<AtomicUsize>,
}

impl SecurityResponseAdapter<AdaptedBody> for RecordingAdapter {
    fn adapt(&self, response: SecurityResponse) -> Response<AdaptedBody> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        let original_status = response.status();
        let mut response = response.map(AdaptedBody);
        *response.status_mut() = StatusCode::IM_A_TEAPOT;
        response.headers_mut().insert(
            "x-original-status",
            original_status.as_str().parse().unwrap(),
        );
        response
    }
}

#[tokio::test]
async fn custom_adapter_handles_every_combined_rejection_once_and_supports_non_from_body() {
    let inner_calls = Arc::new(AtomicUsize::new(0));
    let adapter_calls = Arc::new(AtomicUsize::new(0));
    let raw = inner(
        || AdaptedBody(Bytes::from_static(b"unused")),
        Arc::clone(&inner_calls),
    );
    let adapter = || RecordingAdapter {
        calls: Arc::clone(&adapter_calls),
    };
    let handler = |_: &Parts, failure: AuthorizationFailure<io::Error>| match failure {
        AuthorizationFailure::Denied(_) => challenge(StatusCode::FORBIDDEN, "denied"),
        AuthorizationFailure::Provider(_) => {
            challenge(StatusCode::INTERNAL_SERVER_ERROR, "backend failed")
        }
    };
    let cases = [
        (
            BoxCloneService::new(
                SecurityLayer::new(
                    TokenAuthenticator,
                    AuthenticatedAuthorizationProvider::<String>::new(),
                )
                .response_adapter(adapter())
                .clone()
                .layer(raw.clone()),
            ),
            Some("invalid"),
            "401",
            "invalid token",
        ),
        (
            BoxCloneService::new(
                SecurityLayer::new(
                    TokenAuthenticator,
                    AuthenticatedAuthorizationProvider::<String>::new(),
                )
                .response_adapter(adapter())
                .authentication_entry_point(|_: &Parts| {
                    challenge(StatusCode::UNAUTHORIZED, "authentication required")
                })
                .layer(raw.clone()),
            ),
            None,
            "401",
            "authentication required",
        ),
        (
            BoxCloneService::new(
                SecurityLayer::new(TokenAuthenticator, DenyProvider(false))
                    .response_adapter(adapter())
                    .failure_handler(handler)
                    .layer(raw.clone()),
            ),
            Some("valid"),
            "403",
            "denied",
        ),
        (
            BoxCloneService::new(
                SecurityLayer::new(TokenAuthenticator, DenyProvider(true))
                    .failure_handler(handler)
                    .response_adapter(adapter())
                    .layer(raw),
            ),
            Some("valid"),
            "500",
            "backend failed",
        ),
    ];
    for (index, (service, token, original_status, message)) in cases.into_iter().enumerate() {
        let response = service.clone().oneshot(request(token)).await.unwrap();
        assert_eq!(response.status(), StatusCode::IM_A_TEAPOT);
        assert_eq!(response.headers()["x-original-status"], original_status);
        assert_eq!(
            response.headers()[header::WWW_AUTHENTICATE],
            "ApiKey realm=\"Notes\""
        );
        assert_eq!(
            response.extensions().get::<ResponseMarker>(),
            Some(&ResponseMarker)
        );
        assert_eq!(response.into_body().0, message);
        assert_eq!(adapter_calls.load(Ordering::SeqCst), index + 1);
    }
    assert_eq!(inner_calls.load(Ordering::SeqCst), 0);
}

#[tokio::test]
async fn custom_adapter_is_bypassed_for_successful_inner_responses() {
    let inner_calls = Arc::new(AtomicUsize::new(0));
    let adapter_calls = Arc::new(AtomicUsize::new(0));
    let raw = inner(
        || AdaptedBody(Bytes::from_static(b"success")),
        Arc::clone(&inner_calls),
    );
    let service = SecurityLayer::new(
        TokenAuthenticator,
        AuthenticatedAuthorizationProvider::<String>::new(),
    )
    .response_adapter(RecordingAdapter {
        calls: Arc::clone(&adapter_calls),
    })
    .layer(raw);
    let response = service.oneshot(request(Some("valid"))).await.unwrap();
    assert_eq!(response.status(), StatusCode::ACCEPTED);
    assert_eq!(response.headers()["x-inner"], "preserved");
    assert!(!response.headers().contains_key("x-original-status"));
    assert_eq!(response.into_body().0, "success");
    assert_eq!(inner_calls.load(Ordering::SeqCst), 1);
    assert_eq!(adapter_calls.load(Ordering::SeqCst), 0);
}

struct CustomDenialProvider;

impl AuthorizationProvider for CustomDenialProvider {
    type Authentication = String;
    type Error = Infallible;

    fn authorize<'a>(
        &'a self,
        _: Option<&'a String>,
        _: &'a Parts,
    ) -> BoxFuture<'a, Result<AuthorizationDecision, Infallible>> {
        Box::pin(async {
            let mut response = challenge(StatusCode::FORBIDDEN, "office network required");
            response.extensions_mut().insert(ResponseMarker);
            Ok(AuthorizationDecision::Deny(AuthorizationDenial::Custom(
                response,
            )))
        })
    }
}

struct UnreachableProvider;

impl AuthorizationProvider for UnreachableProvider {
    type Authentication = String;
    type Error = Infallible;

    fn authorize<'a>(
        &'a self,
        _: Option<&'a String>,
        _: &'a Parts,
    ) -> BoxFuture<'a, Result<AuthorizationDecision, Infallible>> {
        panic!("providers after a custom denial must not run")
    }
}

fn custom_denial_chain() -> impl AuthorizationProvider<
    Authentication = String,
    Error = crate::authorization::AllAuthorizationError,
> {
    crate::authorization::AllAuthorizationProvider::builder()
        .with(CustomDenialProvider)
        .with(UnreachableProvider)
        .build()
        .unwrap()
}

#[tokio::test]
async fn custom_denial_survives_composition_and_default_failure_handlers() {
    let inner_calls = Arc::new(AtomicUsize::new(0));
    let raw = inner(|| Full::new(Bytes::new()), Arc::clone(&inner_calls));
    let entry_point = |_: &Parts| -> SecurityResponse {
        panic!("custom denials must bypass the authentication entry point")
    };
    let services = [
        BoxCloneService::new(
            AuthorizationLayer::builder(custom_denial_chain())
                .authentication_entry_point(entry_point)
                .build()
                .layer(raw.clone()),
        ),
        BoxCloneService::new(
            SecurityLayer::new(TokenAuthenticator, custom_denial_chain())
                .authentication_entry_point(entry_point)
                .layer(raw),
        ),
    ];
    for service in services {
        let response = service.oneshot(request(None)).await.unwrap();
        assert_eq!(response.status(), StatusCode::FORBIDDEN);
        assert!(response.extensions().get::<ResponseMarker>().is_some());
        assert!(response.headers().contains_key(header::WWW_AUTHENTICATE));
        assert_eq!(
            response.into_body().collect().await.unwrap().to_bytes(),
            "office network required"
        );
    }
    assert_eq!(inner_calls.load(Ordering::SeqCst), 0);
}

#[tokio::test]
async fn custom_denial_uses_combined_response_adapter_once() {
    let calls = Arc::new(AtomicUsize::new(0));
    let inner_calls = Arc::new(AtomicUsize::new(0));
    let response = SecurityLayer::new(TokenAuthenticator, CustomDenialProvider)
        .failure_handler(|_: &Parts, failure: AuthorizationFailure<Infallible>| {
            let AuthorizationFailure::Denied(AuthorizationDenial::Custom(mut response)) = failure
            else {
                panic!("expected a custom denial");
            };
            *response.status_mut() = StatusCode::TOO_MANY_REQUESTS;
            response
        })
        .response_adapter(RecordingAdapter {
            calls: Arc::clone(&calls),
        })
        .layer(inner(
            || AdaptedBody(Bytes::new()),
            Arc::clone(&inner_calls),
        ))
        .oneshot(request(None))
        .await
        .unwrap();
    assert_eq!(calls.load(Ordering::SeqCst), 1);
    assert_eq!(inner_calls.load(Ordering::SeqCst), 0);
    assert_eq!(response.status(), StatusCode::IM_A_TEAPOT);
    assert_eq!(response.headers()["x-original-status"], "429");
    assert!(response.extensions().get::<ResponseMarker>().is_some());
    assert_eq!(response.into_body().0, "office network required");
}

#[cfg(feature = "request_matcher")]
#[tokio::test]
async fn request_rule_preserves_custom_denial_without_falling_through() {
    let provider = crate::authorization::RequestAuthorizationProvider::<String>::builder()
        .request_matchers("/notes")
        .access(CustomDenialProvider)
        .any_request()
        .permit_all()
        .build()
        .unwrap();
    let (parts, _) = request(None).into_parts();
    let AuthorizationDecision::Deny(AuthorizationDenial::Custom(response)) =
        provider.authorize(None, &parts).await.unwrap()
    else {
        panic!("expected the selected provider's custom response");
    };
    assert_eq!(response.status(), StatusCode::FORBIDDEN);
    assert_eq!(response.body(), "office network required");
}

#[tokio::test]
async fn custom_failure_handlers_can_modify_custom_denials_in_both_layers() {
    let handler_calls = Arc::new(AtomicUsize::new(0));
    let inner_calls = Arc::new(AtomicUsize::new(0));
    let raw = inner(|| Full::new(Bytes::new()), Arc::clone(&inner_calls));
    let calls = Arc::clone(&handler_calls);
    let handler = move |parts: &Parts, failure: AuthorizationFailure<Infallible>| {
        assert_eq!(parts.uri.path(), "/notes");
        calls.fetch_add(1, Ordering::SeqCst);
        let AuthorizationFailure::Denied(AuthorizationDenial::Custom(mut response)) = failure
        else {
            panic!("expected a custom denial");
        };
        assert_eq!(response.body(), "office network required");
        *response.status_mut() = StatusCode::LOCKED;
        response
            .headers_mut()
            .insert("x-failure-handler", "processed".parse().unwrap());
        *response.body_mut() = Bytes::from_static(b"modified by failure handler");
        response
    };
    let services = [
        BoxCloneService::new(
            AuthorizationLayer::builder(CustomDenialProvider)
                .failure_handler(handler.clone())
                .build()
                .layer(raw.clone()),
        ),
        BoxCloneService::new(
            SecurityLayer::new(TokenAuthenticator, CustomDenialProvider)
                .failure_handler(handler)
                .layer(raw),
        ),
    ];
    for service in services {
        let response = service.oneshot(request(None)).await.unwrap();
        assert_eq!(response.status(), StatusCode::LOCKED);
        assert_eq!(response.headers()["x-failure-handler"], "processed");
        assert!(response.extensions().get::<ResponseMarker>().is_some());
        assert_eq!(
            response.into_body().collect().await.unwrap().to_bytes(),
            "modified by failure handler"
        );
    }
    assert_eq!(handler_calls.load(Ordering::SeqCst), 2);
    assert_eq!(inner_calls.load(Ordering::SeqCst), 0);
}
