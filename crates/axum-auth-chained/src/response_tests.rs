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
