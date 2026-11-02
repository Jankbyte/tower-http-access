use super::*;
use crate::authentication::Authenticated;
use crate::authorization::{
    AuthenticatedAuthorizationProvider, AuthorizationDenial, AuthorizationLayer,
    AuthorizationProviderExt,
    auth_tower::tests::{ErrorProvider, Inner, MappedIdentityProvider},
};
use axum::{body::Body, extract::Request, http::StatusCode};
use std::{convert::Infallible, io, sync::Arc};
use tokio::sync::Mutex;
use tower_layer::Layer;
use tower_service::Service;

struct RecordingProvider {
    index: usize,
    calls: Arc<Mutex<Vec<usize>>>,
    decision: fn() -> AuthorizationDecision,
}

impl AuthorizationProvider for RecordingProvider {
    type Authentication = String;
    type Error = Infallible;

    fn authorize<'a>(
        &'a self,
        authentication: Option<&'a String>,
        request: &'a Parts,
    ) -> BoxFuture<'a, Result<AuthorizationDecision, Infallible>> {
        Box::pin(async move {
            assert_eq!(authentication.map(String::as_str), Some("alex"));
            assert_eq!(request.uri.path(), "/private");
            self.calls.lock().await.push(self.index);
            tokio::task::yield_now().await;
            Ok((self.decision)())
        })
    }
}

#[test]
fn all_authorization_rejects_empty_chain() {
    assert!(
        AllAuthorizationProvider::<String>::builder()
            .build()
            .is_err()
    );
}

#[tokio::test]
async fn all_authorization_runs_in_order_and_stops_at_first_denial() {
    for denial in [
        None,
        Some((|| AuthorizationDenial::AuthenticationRequired) as fn() -> AuthorizationDenial),
        Some((|| AuthorizationDenial::InsufficientPermissions) as fn() -> AuthorizationDenial),
    ] {
        let calls = Arc::new(Mutex::new(Vec::new()));
        let mut builder = AllAuthorizationProvider::<String>::builder();
        for index in 0..3 {
            builder = builder.with(RecordingProvider {
                index,
                calls: Arc::clone(&calls),
                decision: if index == 1 {
                    match denial.map(|f| f()) {
                        Some(AuthorizationDenial::AuthenticationRequired) => || {
                            AuthorizationDecision::Deny(AuthorizationDenial::AuthenticationRequired)
                        },
                        Some(AuthorizationDenial::InsufficientPermissions) => || {
                            AuthorizationDecision::Deny(
                                AuthorizationDenial::InsufficientPermissions,
                            )
                        },
                        _ => || AuthorizationDecision::Allow,
                    }
                } else {
                    || AuthorizationDecision::Allow
                },
            });
        }
        let provider = builder.build().unwrap();
        let (parts, _) = Request::builder()
            .uri("/private")
            .body(Body::empty())
            .unwrap()
            .into_parts();
        let decision = provider
            .authorize(Some(&"alex".to_owned()), &parts)
            .await
            .unwrap();
        crate::authorization::core::assert_builtin_decision(
            decision,
            denial
                .map(|f| AuthorizationDecision::Deny(f()))
                .unwrap_or(AuthorizationDecision::Allow),
        );
        assert_eq!(
            *calls.lock().await,
            if denial.is_some() {
                vec![0, 1]
            } else {
                vec![0, 1, 2]
            }
        );
    }
}

#[tokio::test]
async fn all_authorization_preserves_error_source_and_skips_later_providers() {
    let calls = Arc::new(Mutex::new(Vec::new()));
    let provider = AllAuthorizationProvider::<String>::builder()
        .with(AuthenticatedAuthorizationProvider::<String>::new())
        .with(ErrorProvider)
        .with(RecordingProvider {
            index: 0,
            calls: Arc::clone(&calls),
            decision: || AuthorizationDecision::Allow,
        })
        .build()
        .unwrap();
    let (parts, _) = Request::new(Body::empty()).into_parts();
    let error = provider
        .authorize(Some(&"alex".to_owned()), &parts)
        .await
        .unwrap_err();
    let source = std::error::Error::source(&error)
        .unwrap()
        .downcast_ref::<io::Error>()
        .unwrap();
    assert_eq!(source.to_string(), "policy store unavailable");
    assert!(calls.lock().await.is_empty());
}

#[tokio::test]
async fn all_authorization_integrates_with_mapper_and_http_failure_handling() {
    for (identity, path, expected) in [
        (None, "/", StatusCode::UNAUTHORIZED),
        (Some("alex"), "/", StatusCode::OK),
        (Some("a"), "/", StatusCode::FORBIDDEN),
        (Some("alex"), "/error", StatusCode::INTERNAL_SERVER_ERROR),
    ] {
        let provider = AllAuthorizationProvider::<String>::builder()
            .with(AuthenticatedAuthorizationProvider::<String>::new())
            .with(MappedIdentityProvider.map(|identity: &String| identity.len()))
            .build()
            .unwrap();
        let mut service = AuthorizationLayer::builder(provider).build().layer(Inner);
        let mut request = Request::builder().uri(path).body(Body::empty()).unwrap();
        if let Some(identity) = identity {
            request
                .extensions_mut()
                .insert(Authenticated(identity.to_owned()));
        }
        assert_eq!(service.call(request).await.unwrap().status(), expected);
    }
}

#[tokio::test]
async fn all_authorization_passes_anonymous_identity_through_to_provider() {
    let provider = AllAuthorizationProvider::<String>::builder()
        .with(
            AuthenticatedAuthorizationProvider::<String>::new()
                .map(|_: &String| -> String { panic!("anonymous identity must stay None") }),
        )
        .build()
        .unwrap();
    let (parts, _) = Request::new(Body::empty()).into_parts();
    assert!(matches!(
        provider.authorize(None, &parts).await.unwrap(),
        AuthorizationDecision::Deny(AuthorizationDenial::AuthenticationRequired)
    ));
}
