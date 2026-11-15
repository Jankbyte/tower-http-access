use super::*;
use crate::SecurityLayer;
use crate::authentication::{Authenticated, AuthenticationErrorReason};
use crate::authorization::core::{AuthorizationDecision, AuthorizationProvider};
use crate::response::test_response;
use axum::response::{IntoResponse, Response};
use axum::{body::Body, extract::Request, http::StatusCode};
use std::{
    convert::Infallible,
    future::{Ready, ready},
    task::{Context, Poll},
};
use tower::{Layer, Service};

#[tokio::test]
async fn cloned_chain_accepts_shared_trait_object() {
    let shared: Arc<dyn RequestAuthenticator<Authentication = String>> =
        Arc::new(|_: &Parts| async {
            Ok::<_, AuthenticatorError>(AuthenticationAttempt::Authenticated("alex".to_owned()))
        });
    let chains = [
        DelegatingRequestAuthenticator::builder()
            .authenticator(Arc::clone(&shared))
            .build(),
        DelegatingRequestAuthenticator::builder()
            .authenticator(shared)
            .build(),
    ];

    for chain in chains {
        let cloned = chain.clone();
        drop(chain);
        let (parts, _) = Request::new(Body::empty()).into_parts();
        assert!(matches!(
            cloned.authenticate(&parts).await.unwrap(),
            AuthenticationAttempt::Authenticated(identity) if identity == "alex"
        ));
    }
}

#[tokio::test]
async fn authentication_chain_uses_first_applicable_authenticator() {
    let first = |_: &Parts| async {
        Ok::<_, AuthenticatorError>(AuthenticationAttempt::<String>::NotApplicable)
    };
    let second = |_: &Parts| async {
        Ok::<_, AuthenticatorError>(AuthenticationAttempt::Authenticated("alex".to_owned()))
    };
    let authenticator = DelegatingRequestAuthenticator::builder()
        .authenticator(first)
        .authenticator(second)
        .build();
    let mut service = SecurityLayer::new(authenticator, Allow).layer(IdentityService);

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
async fn authenticators_read_the_same_request_metadata() {
    let first = |parts: &Parts| {
        assert_eq!(parts.headers["x-auth"], "ready");
        async { Ok::<_, AuthenticatorError>(AuthenticationAttempt::<String>::NotApplicable) }
    };
    let second = |parts: &Parts| {
        let authentication = parts.headers["x-auth"].to_str().unwrap().to_owned();
        async move { Ok::<_, AuthenticatorError>(AuthenticationAttempt::Authenticated(authentication)) }
    };
    let authenticator = DelegatingRequestAuthenticator::builder()
        .authenticator(first)
        .authenticator(second)
        .build();
    let mut service = SecurityLayer::new(authenticator, Allow).layer(IdentityService);

    let response = service
        .call(
            Request::builder()
                .header("x-auth", "ready")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(
        axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap(),
        "ready"
    );
}

#[tokio::test]
async fn authentication_chain_without_applicable_authenticator_continues_anonymously() {
    let authenticator = |_: &Parts| async {
        Ok::<_, AuthenticatorError>(AuthenticationAttempt::<String>::NotApplicable)
    };
    let authenticator = DelegatingRequestAuthenticator::builder()
        .authenticator(authenticator)
        .build();
    let mut service = SecurityLayer::new(authenticator, Allow).layer(IdentityService);

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
    let reject = |_: &Parts| async {
        Err::<AuthenticationAttempt<String>, _>(AuthenticatorError::with_response(
            AuthenticationErrorReason::WrongCredentials,
            test_response(StatusCode::UNAUTHORIZED, "invalid token"),
        ))
    };
    let authenticator = DelegatingRequestAuthenticator::builder()
        .authenticator(reject)
        .build();
    let mut service = SecurityLayer::new(authenticator, Allow).layer(IdentityService);

    let response = service.call(Request::new(Body::empty())).await.unwrap();

    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    assert_eq!(
        axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap(),
        "invalid token"
    );
}

#[derive(Clone)]
struct Allow;
impl AuthorizationProvider for Allow {
    type Authentication = String;
    type Error = Infallible;
    fn authorize<'a>(
        &'a self,
        _: Option<&'a String>,
        _: &'a Parts,
    ) -> BoxFuture<'a, Result<AuthorizationDecision, Infallible>> {
        Box::pin(async { Ok(AuthorizationDecision::Allow) })
    }
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
            .map(|value| value.as_inner().clone())
            .unwrap_or_else(|| "anonymous".to_owned());
        ready(Ok(identity.into_response()))
    }
}
