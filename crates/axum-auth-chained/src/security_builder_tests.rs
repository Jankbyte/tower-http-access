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
        .authenticator(authenticator)
        .authorization(|authorization| {
            authorization.authorize_with(AuthenticatedAuthorizationProvider::<String>::new())
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
        .chained_authenticators(|authenticators| authenticators.authenticator(authenticator))
        .authorization(|authorization| {
            authorization
                .authorize_with(AuthenticatedAuthorizationProvider::<String>::new())
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

#[tokio::test]
async fn ready_authorization_layer_preserves_handlers_and_runs_after_authentication() {
    for authenticated in [false, true] {
        let authorization =
            AuthorizationLayer::builder(AuthenticatedAuthorizationProvider::<String>::new())
                .authentication_entry_point(|_: Request| StatusCode::IM_A_TEAPOT)
                .build();
        let security = SecurityLayerBuilder::builder()
            .chained_authenticators(|chain| {
                chain.authenticator(move |_: &mut Parts| async move {
                    Ok::<_, AuthenticatorError>(if authenticated {
                        AuthenticationAttempt::Authenticated("alex".to_owned())
                    } else {
                        AuthenticationAttempt::NotApplicable
                    })
                })
            })
            .authorization_layer(authorization)
            .build();
        let response = security
            .service(Inner)
            .call(Request::new(Body::empty()))
            .await
            .unwrap();
        assert_eq!(
            response.status(),
            if authenticated {
                StatusCode::OK
            } else {
                StatusCode::IM_A_TEAPOT
            }
        );
    }
}

#[tokio::test]
async fn single_non_clone_authenticator_handles_success_anonymous_and_failure() {
    struct SingleAuthenticator(u8);

    impl RequestAuthenticator for SingleAuthenticator {
        type Authentication = String;

        fn authenticate<'a>(
            &'a self,
            _: &'a mut Parts,
        ) -> Pin<
            Box<
                dyn Future<Output = Result<AuthenticationAttempt<String>, AuthenticatorError>>
                    + Send
                    + 'a,
            >,
        > {
            Box::pin(async move {
                match self.0 {
                    0 => Ok(AuthenticationAttempt::NotApplicable),
                    1 => Ok(AuthenticationAttempt::Authenticated("alex".to_owned())),
                    _ => Err(AuthenticatorError::new(
                        crate::authentication::AuthenticationErrorReason::WrongCredentials,
                    )),
                }
            })
        }
    }

    for (attempt, expected) in [
        (0, StatusCode::IM_A_TEAPOT),
        (1, StatusCode::OK),
        (2, StatusCode::UNAUTHORIZED),
    ] {
        let authorization =
            AuthorizationLayer::builder(AuthenticatedAuthorizationProvider::<String>::new())
                .authentication_entry_point(|_: Request| StatusCode::IM_A_TEAPOT)
                .build();
        let layer = SecurityLayerBuilder::builder()
            .authenticator(SingleAuthenticator(attempt))
            .authorization_layer(authorization)
            .build();
        let response = layer
            .clone()
            .service(Inner)
            .call(Request::new(Body::empty()))
            .await
            .unwrap();
        assert_eq!(response.status(), expected);
    }
}

#[tokio::test]
async fn chained_authenticators_try_the_next_applicable_mechanism() {
    let layer = SecurityLayerBuilder::builder()
        .chained_authenticators(|chain| {
            chain
                .authenticator(|parts: &mut Parts| {
                    parts
                        .headers
                        .insert("x-first-attempt", "seen".parse().unwrap());
                    async {
                        Ok::<_, AuthenticatorError>(AuthenticationAttempt::<String>::NotApplicable)
                    }
                })
                .authenticator(|parts: &mut Parts| {
                    assert_eq!(parts.headers["x-first-attempt"], "seen");
                    async {
                        Ok::<_, AuthenticatorError>(AuthenticationAttempt::Authenticated(
                            "alex".to_owned(),
                        ))
                    }
                })
        })
        .authorization(|authorization| {
            authorization.authorize_with(AuthenticatedAuthorizationProvider::<String>::new())
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
async fn single_shared_authenticator_is_accepted_by_builder() {
    let authenticator = std::sync::Arc::new(|_: &mut Parts| async {
        Ok::<_, AuthenticatorError>(AuthenticationAttempt::Authenticated("alex".to_owned()))
    });
    let layer = SecurityLayerBuilder::builder()
        .authenticator(std::sync::Arc::clone(&authenticator))
        .authorization(|authorization| {
            authorization.authorize_with(AuthenticatedAuthorizationProvider::<String>::new())
        })
        .build();
    let response = layer
        .service(Inner)
        .call(Request::new(Body::empty()))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
}
