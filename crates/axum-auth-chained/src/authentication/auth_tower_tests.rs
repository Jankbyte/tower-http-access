use super::*;
use crate::authentication::AuthenticatorError;
use axum::{Router, body::Body, http::request::Parts, routing::method_routing::get};
use std::{
    convert::Infallible,
    future::{Ready, ready},
};

#[derive(Clone)]
pub(in crate::authentication) struct IdentityService;

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
