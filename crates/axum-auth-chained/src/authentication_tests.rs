use super::*;
use axum::{
    Router,
    body::Body,
    extract::{FromRequestParts, OptionalFromRequestParts},
    http::{StatusCode, request::Parts},
    response::IntoResponse,
    routing::method_routing::get,
};
use std::{
    convert::Infallible,
    future::{Ready, ready},
    io,
    task::{Context, Poll},
};
use tower::{Layer, Service};

#[tokio::test]
async fn authenticated_extractor_returns_wrapped_identity() {
    let (mut parts, _) = Request::new(Body::empty()).into_parts();
    parts
        .extensions
        .insert(Authenticated::new("alex".to_owned()));

    let authentication =
        <Authenticated<String> as FromRequestParts<()>>::from_request_parts(&mut parts, &())
            .await
            .unwrap();

    assert_eq!(authentication.into_inner(), "alex");
}

#[tokio::test]
async fn optional_authenticated_extractor_returns_none_for_anonymous_request() {
    let (mut parts, _) = Request::new(Body::empty()).into_parts();

    let authentication =
        <Authenticated<String> as OptionalFromRequestParts<()>>::from_request_parts(
            &mut parts,
            &(),
        )
        .await
        .unwrap();

    assert!(authentication.is_none());
}

#[derive(Clone)]
struct IdentityService;

impl Service<Request> for IdentityService {
    type Response = Response;
    type Error = Infallible;
    type Future = Ready<Result<Response, Infallible>>;

    fn poll_ready(&mut self, _: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        Poll::Ready(Ok(()))
    }

    fn call(&mut self, request: Request) -> Self::Future {
        let identity = request
            .extensions()
            .get::<Authenticated<String>>()
            .map(|authenticated| authenticated.as_inner().clone())
            .unwrap_or_else(|| "anonymous".to_owned());
        ready(Ok(identity.into_response()))
    }
}

#[test]
fn axum_layer_compability_test() {
    let authenticator =
        |_: &mut Parts| async { Ok(AuthenticationAttempt::Authenticated("alex".to_owned())) };
    let service = AuthenticationLayer::new(authenticator);
    // NOTE: check is `AuthenticationLayer` can be applied to Router
    let _: Router<()> = Router::new()
        .route("/", get(async || "Hello"))
        .route_layer(service);
}

#[tokio::test]
async fn authentication_layer_accepts_single_request_authenticator() {
    let authenticator = |_: &mut Parts| async {
        Ok::<_, AuthenticatorError>(AuthenticationAttempt::Authenticated("alex".to_owned()))
    };
    let mut service = AuthenticationLayer::new(authenticator).layer(IdentityService);

    let response = service.call(Request::new(Body::empty())).await.unwrap();

    assert_eq!(
        axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap(),
        "alex"
    );
}

#[tokio::test]
async fn authentication_chain_uses_first_applicable_authenticator() {
    let first = |_: &mut Parts| async {
        Ok::<_, AuthenticatorError>(AuthenticationAttempt::<String>::NotApplicable)
    };
    let second = |_: &mut Parts| async {
        Ok::<_, AuthenticatorError>(AuthenticationAttempt::Authenticated("alex".to_owned()))
    };
    let authenticator = DelegatingRequestAuthenticator::builder()
        .authenticator(first)
        .authenticator(second)
        .build();
    let mut service = AuthenticationLayer::new(authenticator).layer(IdentityService);

    let response = service.call(Request::new(Body::empty())).await.unwrap();

    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(
        axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap(),
        "alex"
    );
}

#[tokio::test]
async fn not_applicable_authenticator_preserves_parts_changes_for_chain() {
    let first = |parts: &mut Parts| {
        parts.headers.insert("x-auth", "ready".parse().unwrap());
        async { Ok::<_, AuthenticatorError>(AuthenticationAttempt::<String>::NotApplicable) }
    };
    let second = |parts: &mut Parts| {
        let authentication = parts.headers["x-auth"].to_str().unwrap().to_owned();
        async move { Ok::<_, AuthenticatorError>(AuthenticationAttempt::Authenticated(authentication)) }
    };
    let authenticator = DelegatingRequestAuthenticator::builder()
        .authenticator(first)
        .authenticator(second)
        .build();
    let mut service = AuthenticationLayer::new(authenticator).layer(IdentityService);

    let response = service.call(Request::new(Body::empty())).await.unwrap();

    assert_eq!(
        axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap(),
        "ready"
    );
}

#[tokio::test]
async fn authentication_chain_without_applicable_authenticator_continues_anonymously() {
    let authenticator = |_: &mut Parts| async {
        Ok::<_, AuthenticatorError>(AuthenticationAttempt::<String>::NotApplicable)
    };
    let authenticator = DelegatingRequestAuthenticator::builder()
        .authenticator(authenticator)
        .build();
    let mut service = AuthenticationLayer::new(authenticator).layer(IdentityService);

    let response = service.call(Request::new(Body::empty())).await.unwrap();

    assert_eq!(
        axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap(),
        "anonymous"
    );
}

#[tokio::test]
async fn authenticator_error_response_stops_chain_and_becomes_service_response() {
    let reject = |_: &mut Parts| async {
        Err::<AuthenticationAttempt<String>, _>(AuthenticatorError::with_response(
            AuthenticationErrorReason::WrongCredentials,
            (StatusCode::UNAUTHORIZED, "invalid token"),
        ))
    };
    let authenticator = DelegatingRequestAuthenticator::builder()
        .authenticator(reject)
        .build();
    let mut service = AuthenticationLayer::new(authenticator).layer(IdentityService);

    let response = service.call(Request::new(Body::empty())).await.unwrap();

    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    assert_eq!(
        axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap(),
        "invalid token"
    );
}

#[test]
fn authenticator_error_preserves_internal_reason_and_custom_response() {
    let error = AuthenticatorError::with_response(
        AuthenticationErrorReason::Internal(Box::new(io::Error::other("database unavailable"))),
        StatusCode::SERVICE_UNAVAILABLE,
    );

    assert!(matches!(
        &error.reason,
        AuthenticationErrorReason::Internal(_)
    ));
    assert_eq!(
        error.into_response().status(),
        StatusCode::SERVICE_UNAVAILABLE
    );
}

#[test]
fn authenticator_error_uses_default_response_for_reason() {
    let wrong_credentials =
        AuthenticatorError::new(AuthenticationErrorReason::WrongCredentials).into_response();
    let internal = AuthenticatorError::new(AuthenticationErrorReason::Internal(Box::new(
        io::Error::other("database unavailable"),
    )))
    .into_response();

    assert_eq!(wrong_credentials.status(), StatusCode::UNAUTHORIZED);
    assert_eq!(internal.status(), StatusCode::INTERNAL_SERVER_ERROR);
}

#[tokio::test]
async fn mapped_authenticator_converts_authenticated_value() {
    #[derive(Clone, Debug, Eq, PartialEq)]
    struct Principal(String);

    let authenticator = (|_: &mut Parts| async {
        Ok::<_, AuthenticatorError>(AuthenticationAttempt::Authenticated(42))
    })
    .map(|user_id| Principal(format!("user-{user_id}")));
    let (mut parts, _) = Request::new(Body::empty()).into_parts();

    let attempt = RequestAuthenticator::authenticate(&authenticator, &mut parts)
        .await
        .unwrap();

    assert_eq!(
        attempt,
        AuthenticationAttempt::Authenticated(Principal("user-42".to_owned()))
    );
}

#[tokio::test]
async fn arc_authenticators_forward_attempts_errors_and_request_mutations() {
    struct SharedAuthenticator(u8);

    impl RequestAuthenticator for SharedAuthenticator {
        type Authentication = String;

        fn authenticate<'a>(
            &'a self,
            parts: &'a mut Parts,
        ) -> BoxFuture<'a, Result<AuthenticationAttempt<Self::Authentication>, AuthenticatorError>>
        {
            Box::pin(async move {
                parts
                    .headers
                    .insert("x-auth-attempt", "seen".parse().unwrap());
                match self.0 {
                    0 => Ok(AuthenticationAttempt::NotApplicable),
                    1 => Ok(AuthenticationAttempt::Authenticated("alex".to_owned())),
                    _ => Err(AuthenticatorError::with_response(
                        AuthenticationErrorReason::WrongCredentials,
                        StatusCode::IM_A_TEAPOT,
                    )),
                }
            })
        }
    }

    async fn check<A: RequestAuthenticator<Authentication = String>>(
        authenticator: A,
        attempt: u8,
    ) {
        let (mut parts, _) = Request::new(Body::empty()).into_parts();
        let result = authenticator.authenticate(&mut parts).await;
        assert_eq!(parts.headers["x-auth-attempt"], "seen");
        match (attempt, result) {
            (0, Ok(AuthenticationAttempt::NotApplicable)) => (),
            (1, Ok(AuthenticationAttempt::Authenticated(user))) => assert_eq!(user, "alex"),
            (2, Err(error)) => {
                assert!(matches!(
                    error.reason,
                    AuthenticationErrorReason::WrongCredentials
                ));
                assert_eq!(error.response.unwrap().status(), StatusCode::IM_A_TEAPOT);
            }
            _ => panic!("shared authenticator changed the result"),
        }
    }

    for attempt in 0..=2 {
        let concrete = Arc::new(SharedAuthenticator(attempt));
        check(Arc::clone(&concrete), attempt).await;
        let erased: Arc<dyn RequestAuthenticator<Authentication = String>> = concrete;
        check(erased, attempt).await;
    }
}
