use std::{
    convert::Infallible,
    future::Future,
    pin::Pin,
    task::{Context, Poll},
};

use axum::{
    body::Body,
    extract::Request,
    http::{StatusCode, request::Parts},
    response::{IntoResponse, Response},
};
use tower_service::Service;

use super::*;
use crate::{
    authentication::{AuthenticationAttempt, AuthenticatorError},
    authorization::AuthenticatedAuthorizationProvider,
};

#[derive(Clone)]
struct Inner;

impl Service<Request> for Inner {
    type Response = Response;
    type Error = Infallible;
    type Future = Pin<Box<dyn Future<Output = Result<Response, Infallible>> + Send>>;

    fn poll_ready(&mut self, _: &mut Context<'_>) -> Poll<Result<(), Infallible>> {
        Poll::Ready(Ok(()))
    }

    fn call(&mut self, _: Request) -> Self::Future {
        Box::pin(async { Ok(StatusCode::OK.into_response()) })
    }
}

#[tokio::test]
async fn security_layer_authenticates_before_authorizing() {
    let authenticator = |_: &mut Parts| async {
        Ok::<_, AuthenticatorError>(AuthenticationAttempt::Authenticated("alex".to_owned()))
    };
    let layer = SecurityLayerBuilder::builder()
        .authenticators(|authenticators| authenticators.authenticator(authenticator))
        .authorization(|authorization| {
            authorization.authorize_with(
                AuthenticatedAuthorizationProvider::<String>::new(),
                |_: &Parts| (),
            )
        })
        .build();

    let response = layer
        .service(Inner)
        .call(Request::new(Body::empty()))
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::OK);
}

#[tokio::test]
async fn security_layer_uses_configured_authentication_entry_point() {
    let authenticator = |_: &mut Parts| async {
        Ok::<_, AuthenticatorError>(AuthenticationAttempt::<String>::NotApplicable)
    };
    let layer = SecurityLayerBuilder::builder()
        .authenticators(|authenticators| authenticators.authenticator(authenticator))
        .authorization(|authorization| {
            authorization
                .authorize_with(
                    AuthenticatedAuthorizationProvider::<String>::new(),
                    |_: &Parts| (),
                )
                .authentication_entry_point(|_: Request| StatusCode::IM_A_TEAPOT)
        })
        .build();

    let response = layer
        .service(Inner)
        .call(Request::new(Body::empty()))
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::IM_A_TEAPOT);
}
