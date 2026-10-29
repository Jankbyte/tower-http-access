use super::*;
use crate::authentication::{
    Authenticated, AuthenticationAttempt, AuthenticationLayer, AuthenticatorError,
};
use axum::{body::Body, response::IntoResponse};
use std::{convert::Infallible, io};

#[derive(Clone)]
struct Inner;

impl Service<Request> for Inner {
    type Response = Response;
    type Error = Infallible;
    type Future = Pin<Box<dyn Future<Output = Result<Self::Response, Self::Error>> + Send>>;

    fn poll_ready(&mut self, _: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        Poll::Ready(Ok(()))
    }

    fn call(&mut self, _: Request) -> Self::Future {
        Box::pin(async { Ok("allowed".into_response()) })
    }
}
fn authenticated_service() -> impl Service<Request, Response = Response, Error = Infallible> {
    AuthorizationLayer::builder(
        AuthenticatedAuthorizationProvider::<String>::new(),
        |_: &Parts| (),
    )
    .build()
    .layer(Inner)
}

#[tokio::test]
async fn authenticated_provider_without_identity_returns_unauthorized() {
    let response = authenticated_service()
        .call(Request::new(Body::empty()))
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn authentication_required_uses_configured_entry_point() {
    let mut service = AuthorizationLayer::builder(
        AuthenticatedAuthorizationProvider::<String>::new(),
        |_: &Parts| (),
    )
    .authentication_entry_point(move |request: Request| {
        (
            StatusCode::UNAUTHORIZED,
            [("x-request-path", request.uri().path().to_owned())],
        )
    })
    .build()
    .layer(Inner);
    let request = Request::builder()
        .uri("/private")
        .body(Body::empty())
        .unwrap();

    let response = service.call(request).await.unwrap();

    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    assert_eq!(response.headers()["x-request-path"], "/private");
}

#[tokio::test]
async fn authenticated_provider_with_identity_forwards_request() {
    let mut request = Request::new(Body::empty());
    request
        .extensions_mut()
        .insert(Authenticated::new("alex".to_owned()));

    let response = authenticated_service().call(request).await.unwrap();

    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(
        axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap(),
        "allowed"
    );
}

#[tokio::test]
async fn authenticated_provider_ignores_unwrapped_extension_of_same_type() {
    let mut request = Request::new(Body::empty());
    request.extensions_mut().insert("alex".to_owned());

    let response = authenticated_service().call(request).await.unwrap();

    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
}

struct DenyProvider;

impl AuthorizationProvider for DenyProvider {
    type Authentication = String;
    type Context = ();
    type Error = Infallible;

    fn authorize<'a>(
        &'a self,
        _: Option<&'a Self::Authentication>,
        _: Self::Context,
    ) -> Pin<Box<dyn Future<Output = Result<AuthorizationDecision, Self::Error>> + Send + 'a>> {
        Box::pin(async {
            Ok(AuthorizationDecision::Deny(
                AuthorizationDenial::InsufficientPermissions,
            ))
        })
    }
}

#[tokio::test]
async fn insufficient_permissions_returns_forbidden() {
    let mut service = AuthorizationLayer::builder(DenyProvider, |_: &Parts| ())
        .build()
        .layer(Inner);

    let response = service.call(Request::new(Body::empty())).await.unwrap();

    assert_eq!(response.status(), StatusCode::FORBIDDEN);
}

#[tokio::test]
async fn custom_failure_handler_receives_request_and_denial() {
    let mut service = AuthorizationLayer::builder(DenyProvider, |_: &Parts| ())
        .failure_handler(
            |request: Request, failure: AuthorizationFailure<Infallible>| {
                let denial = match failure {
                    AuthorizationFailure::Denied(denial) => format!("{denial:?}"),
                    AuthorizationFailure::Provider(error) => match error {},
                };
                (
                    StatusCode::IM_A_TEAPOT,
                    [("x-request-path", request.uri().path().to_owned())],
                    denial,
                )
            },
        )
        .build()
        .layer(Inner);
    let request = Request::builder()
        .uri("/admin")
        .body(Body::empty())
        .unwrap();

    let response = service.call(request).await.unwrap();

    assert_eq!(response.status(), StatusCode::IM_A_TEAPOT);
    assert_eq!(response.headers()["x-request-path"], "/admin");
    assert_eq!(
        axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap(),
        "InsufficientPermissions"
    );
}

struct ErrorProvider;

impl AuthorizationProvider for ErrorProvider {
    type Authentication = String;
    type Context = ();
    type Error = io::Error;

    fn authorize<'a>(
        &'a self,
        _: Option<&'a Self::Authentication>,
        _: Self::Context,
    ) -> Pin<Box<dyn Future<Output = Result<AuthorizationDecision, Self::Error>> + Send + 'a>> {
        Box::pin(async { Err(io::Error::other("policy store unavailable")) })
    }
}

#[tokio::test]
async fn provider_error_returns_internal_server_error() {
    let mut service = AuthorizationLayer::builder(ErrorProvider, |_: &Parts| ())
        .build()
        .layer(Inner);

    let response = service.call(Request::new(Body::empty())).await.unwrap();

    assert_eq!(response.status(), StatusCode::INTERNAL_SERVER_ERROR);
}

#[tokio::test]
async fn authentication_then_authorization_forwards_identity() {
    let authenticator = |_: &mut Parts| async {
        Ok::<_, AuthenticatorError>(AuthenticationAttempt::Authenticated("alex".to_owned()))
    };
    let authorization = AuthorizationLayer::builder(
        AuthenticatedAuthorizationProvider::<String>::new(),
        |_: &Parts| (),
    )
    .build()
    .layer(Inner);
    let mut service = AuthenticationLayer::new(authenticator).layer(authorization);

    let response = service.call(Request::new(Body::empty())).await.unwrap();

    assert_eq!(response.status(), StatusCode::OK);
}
