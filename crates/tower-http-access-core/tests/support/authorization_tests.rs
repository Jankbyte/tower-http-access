use super::*;
use crate::SecurityLayer;
#[cfg(feature = "axum")]
use crate::authentication::Authenticated;
use crate::authentication::{AuthenticationAttempt, AuthenticatorError};
use crate::authorization::AuthorizationProviderExt;
use crate::response::test_response;
use axum::{
    body::Body,
    extract::Request,
    http::{StatusCode, request::Parts},
    response::{IntoResponse, Response},
};
use futures_util::future::BoxFuture;
use std::{
    convert::Infallible,
    io,
    task::{Context, Poll},
};
use std::{future::Future, pin::Pin, sync::Arc};
use tower_http_access_core::authorization::AuthenticatedAuthorizationProvider;
use tower_layer::Layer;
use tower_service::Service;

fn security<P: AuthorizationProvider<Authentication = String> + 'static>(
    provider: P,
) -> SecurityLayer<
    impl crate::authentication::RequestAuthenticator<Authentication = String> + Clone,
    Arc<P>,
> {
    SecurityLayer::new(
        |parts: &Parts| {
            let identity = parts
                .headers
                .get("x-test-identity")
                .map(|v| v.to_str().unwrap().to_owned());
            async move {
                Ok::<_, AuthenticatorError>(match identity {
                    Some(identity) => AuthenticationAttempt::Authenticated(identity),
                    None => AuthenticationAttempt::NotApplicable,
                })
            }
        },
        Arc::new(provider),
    )
}

#[derive(Clone)]
pub(in crate::authorization) struct Inner;

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
    security(AuthenticatedAuthorizationProvider::<String>::new()).layer(Inner)
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
    let mut service = security(AuthenticatedAuthorizationProvider::<String>::new())
        .authentication_entry_point(move |request: &Parts| {
            let mut response = test_response(StatusCode::UNAUTHORIZED, "");
            response
                .headers_mut()
                .insert("x-request-path", request.uri.path().parse().unwrap());
            async move { response }
        })
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
        .headers_mut()
        .insert("x-test-identity", "alex".parse().unwrap());

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
    type Error = Infallible;

    fn authorize<'a>(
        &'a self,
        _: Option<&'a Self::Authentication>,
        _: &'a Parts,
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
    let mut service = security(DenyProvider).layer(Inner);

    let response = service.call(Request::new(Body::empty())).await.unwrap();

    assert_eq!(response.status(), StatusCode::FORBIDDEN);
}

#[tokio::test]
async fn custom_failure_handler_receives_request_and_denial() {
    let mut service = security(DenyProvider)
        .failure_handler(
            |request: &Parts, failure: AuthorizationFailure<Infallible>| {
                let denial = match failure {
                    AuthorizationFailure::Denied(denial) => format!("{denial:?}"),
                    AuthorizationFailure::Provider(error) => match error {},
                };
                let mut response = test_response(StatusCode::IM_A_TEAPOT, denial);
                response
                    .headers_mut()
                    .insert("x-request-path", request.uri.path().parse().unwrap());
                response
            },
        )
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

pub(in crate::authorization) struct ErrorProvider;

impl AuthorizationProvider for ErrorProvider {
    type Authentication = String;
    type Error = io::Error;

    fn authorize<'a>(
        &'a self,
        _: Option<&'a Self::Authentication>,
        _: &'a Parts,
    ) -> Pin<Box<dyn Future<Output = Result<AuthorizationDecision, Self::Error>> + Send + 'a>> {
        Box::pin(async { Err(io::Error::other("policy store unavailable")) })
    }
}

#[tokio::test]
async fn provider_error_returns_internal_server_error() {
    let mut service = security(ErrorProvider).layer(Inner);

    let response = service.call(Request::new(Body::empty())).await.unwrap();

    assert_eq!(response.status(), StatusCode::INTERNAL_SERVER_ERROR);
}

pub(in crate::authorization) struct MappedIdentityProvider;

impl AuthorizationProvider for MappedIdentityProvider {
    type Authentication = usize;
    type Error = io::Error;

    fn authorize<'a>(
        &'a self,
        authentication: Option<&'a usize>,
        request: &'a Parts,
    ) -> BoxFuture<'a, Result<AuthorizationDecision, Self::Error>> {
        Box::pin(async move {
            // Yield so the adapter must retain the mapped value across an await.
            tokio::task::yield_now().await;
            if request.uri.path() == "/error" {
                return Err(io::Error::other("external authorization failed"));
            }
            Ok(match authentication {
                Some(4) => AuthorizationDecision::Allow,
                Some(_) => {
                    AuthorizationDecision::Deny(AuthorizationDenial::InsufficientPermissions)
                }
                None => AuthorizationDecision::Deny(AuthorizationDenial::AuthenticationRequired),
            })
        })
    }
}

#[tokio::test]
async fn mapped_provider_preserves_decisions_errors_and_request_parts() {
    let provider = MappedIdentityProvider.map(|identity: &String| identity.len());
    let (parts, _) = Request::new(Body::empty()).into_parts();

    for (identity, expected) in [
        ("alex", AuthorizationDecision::Allow),
        (
            "a",
            AuthorizationDecision::Deny(AuthorizationDenial::InsufficientPermissions),
        ),
    ] {
        crate::authorization::assert_builtin_decision(
            provider
                .authorize(Some(&identity.to_owned()), &parts)
                .await
                .unwrap(),
            expected,
        );
    }

    let (parts, _) = Request::builder()
        .uri("/error")
        .body(Body::empty())
        .unwrap()
        .into_parts();
    let error = provider
        .authorize(Some(&"alex".to_owned()), &parts)
        .await
        .unwrap_err();
    assert_eq!(error.to_string(), "external authorization failed");
}

#[tokio::test]
async fn mapped_provider_passes_anonymous_requests_without_mapping() {
    let provider = MappedIdentityProvider
        .map(|_: &String| -> usize { panic!("anonymous requests must not invoke the mapper") });
    let (parts, _) = Request::new(Body::empty()).into_parts();
    assert!(matches!(
        provider.authorize(None, &parts).await.unwrap(),
        AuthorizationDecision::Deny(AuthorizationDenial::AuthenticationRequired)
    ));
}

#[cfg(feature = "axum")]
#[tokio::test]
async fn mapped_provider_preserves_handler_identity() {
    let authenticator = |_: &Parts| async {
        Ok::<_, AuthenticatorError>(AuthenticationAttempt::Authenticated("alex".to_owned()))
    };
    let security = SecurityLayer::new(
        authenticator,
        Arc::new(MappedIdentityProvider.map(|identity: &String| identity.len())),
    );
    let router = axum::Router::new().route(
        "/",
        axum::routing::get(
            |Authenticated(identity): Authenticated<String>| async move { identity },
        ),
    );
    let response = security
        .layer(router)
        .call(Request::new(Body::empty()))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(
        axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap(),
        "alex"
    );
}

#[tokio::test]
async fn authentication_entry_point_awaits_shared_state_and_borrows_request() {
    struct LockedEntryPoint(tokio::sync::Mutex<()>);

    impl crate::authorization::AuthenticationEntryPoint for LockedEntryPoint {
        fn commence<'a>(&'a self, request: &'a Parts) -> BoxFuture<'a, tower_http_access_core::SecurityResponse> {
            Box::pin(async move {
                let _guard = self.0.lock().await;
                let mut response = test_response(StatusCode::UNAUTHORIZED, "");
                response.headers_mut().insert(
                    "x-request-path",
                    request.uri.path().parse().unwrap(),
                );
                response
            })
        }
    }

    let entry_point = Arc::new(LockedEntryPoint(tokio::sync::Mutex::new(())));
    let guard = entry_point.0.lock().await;
    let mut service = security(AuthenticatedAuthorizationProvider::<String>::new())
        .authentication_entry_point(Arc::clone(&entry_point))
        .layer(Inner);
    let request = Request::builder().uri("/private").body(Body::empty()).unwrap();
    let response = service.call(request);
    tokio::pin!(response);
    assert!(futures_util::poll!(response.as_mut()).is_pending());
    drop(guard);
    let response = response.await.unwrap();
    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    assert_eq!(response.headers()["x-request-path"], "/private");
}
