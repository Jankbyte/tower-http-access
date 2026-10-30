use super::*;
use crate::basic::Authority;

async fn decision(
    provider: &RequestAuthorizationProvider<UserDetail>,
    user: Option<&UserDetail>,
    method: Method,
    uri: &str,
) -> AuthorizationDecision {
    provider
        .authorize(
            user,
            RequestContext {
                method,
                uri: uri.parse().unwrap(),
            },
        )
        .await
        .unwrap()
}

#[tokio::test]
async fn ordered_policies_and_identity_requirements() {
    let provider = RequestAuthorizationProvider::<UserDetail>::builder()
        .request_matchers("/public")
        .permit_all()
        .request_matchers("/admin/{*rest}")
        .has_authority("ADMIN")
        .method_matchers(Method::GET, "/notes/{id}")
        .has_any_authority(["ReadNote", "ReadAnyNote"])
        .request_matchers("/private")
        .authenticated()
        .any_request()
        .deny_all()
        .build()
        .unwrap();
    let reader = UserDetail::new("reader", "hash", vec![Authority::new("ReadNote")]);
    let admin = UserDetail::new("admin", "hash", vec![Authority::new("ADMIN")]);
    let allow = AuthorizationDecision::Allow;
    let forbidden = AuthorizationDecision::Deny(AuthorizationDenial::InsufficientPermissions);
    let unauthorized = AuthorizationDecision::Deny(AuthorizationDenial::AuthenticationRequired);
    assert_eq!(
        decision(&provider, None, Method::GET, "/public").await,
        allow
    );
    assert_eq!(
        decision(&provider, None, Method::GET, "/private").await,
        unauthorized
    );
    assert_eq!(
        decision(&provider, Some(&reader), Method::GET, "/private").await,
        allow
    );
    assert_eq!(
        decision(&provider, Some(&reader), Method::GET, "/admin/a").await,
        forbidden
    );
    assert_eq!(
        decision(&provider, Some(&admin), Method::GET, "/admin/dashboard").await,
        allow
    );
    assert_eq!(
        decision(&provider, Some(&reader), Method::GET, "/notes/1?q=x").await,
        allow
    );
    assert_eq!(
        decision(&provider, Some(&reader), Method::DELETE, "/notes/1").await,
        forbidden
    );
    assert_eq!(
        decision(&provider, Some(&admin), Method::GET, "/unknown").await,
        forbidden
    );
}

#[tokio::test]
async fn first_match_is_final_and_unmatched_requests_are_denied() {
    let user = UserDetail::new("user", "hash", vec![]);
    let provider = RequestAuthorizationProvider::builder()
        .request_matchers("/blocked")
        .deny_all()
        .any_request()
        .permit_all()
        .build()
        .unwrap();
    assert_eq!(
        decision(&provider, Some(&user), Method::GET, "/blocked").await,
        AuthorizationDecision::Deny(AuthorizationDenial::InsufficientPermissions)
    );
    assert_eq!(
        decision(&provider, None, Method::GET, "/").await,
        AuthorizationDecision::Allow
    );
    let overlapping = RequestAuthorizationProvider::builder()
        .request_matchers("/notes/{*rest}")
        .deny_all()
        .request_matchers("/notes/public")
        .permit_all()
        .build()
        .unwrap();
    assert_eq!(
        decision(&overlapping, Some(&user), Method::GET, "/notes/public").await,
        AuthorizationDecision::Deny(AuthorizationDenial::InsufficientPermissions)
    );
    let empty = RequestAuthorizationProvider::builder().build().unwrap();
    assert_eq!(
        decision(&empty, None, Method::GET, "/anything").await,
        AuthorizationDecision::Deny(AuthorizationDenial::AuthenticationRequired)
    );
}

#[tokio::test]
async fn all_authorities_requires_authentication_and_every_authority() {
    let provider = RequestAuthorizationProvider::builder()
        .request_matchers("/notes")
        .has_all_authorities(["ReadNote", "WriteNote"])
        .request_matchers("/empty")
        .has_all_authorities(Vec::<String>::new())
        .build()
        .unwrap();
    let reader = UserDetail::new("reader", "hash", vec![Authority::new("ReadNote")]);
    let editor = UserDetail::new(
        "editor",
        "hash",
        vec![Authority::new("ReadNote"), Authority::new("WriteNote")],
    );
    let writer = UserDetail::new("writer", "hash", vec![Authority::new("WriteNote")]);
    let no_authorities = UserDetail::new("user", "hash", vec![]);
    for user in [&reader, &writer, &no_authorities] {
        assert_eq!(
            decision(&provider, Some(user), Method::GET, "/notes").await,
            AuthorizationDecision::Deny(AuthorizationDenial::InsufficientPermissions)
        );
    }
    assert_eq!(
        decision(&provider, Some(&editor), Method::GET, "/notes").await,
        AuthorizationDecision::Allow
    );
    for path in ["/notes", "/empty"] {
        assert_eq!(
            decision(&provider, None, Method::GET, path).await,
            AuthorizationDecision::Deny(AuthorizationDenial::AuthenticationRequired)
        );
    }
    assert_eq!(
        decision(&provider, Some(&no_authorities), Method::GET, "/empty").await,
        AuthorizationDecision::Allow
    );
}

struct TestManager {
    fail: bool,
    calls: std::sync::Arc<std::sync::atomic::AtomicUsize>,
}

impl AuthorizationProvider for TestManager {
    type Authentication = UserDetail;
    type Context = RequestContext;
    type Error = std::io::Error;

    fn authorize<'a>(
        &'a self,
        user: Option<&'a UserDetail>,
        context: RequestContext,
    ) -> Pin<Box<dyn Future<Output = Result<AuthorizationDecision, Self::Error>> + Send + 'a>> {
        Box::pin(async move {
            self.calls.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            tokio::task::yield_now().await;
            assert_eq!(context.method, Method::GET);
            assert_eq!(context.uri, "/notes/7?shared=true");
            if self.fail {
                return Err(std::io::Error::other("policy store unavailable"));
            }
            Ok(match user {
                None => AuthorizationDecision::Deny(AuthorizationDenial::AuthenticationRequired),
                Some(user) if user.username == "owner" => AuthorizationDecision::Allow,
                Some(_) => {
                    AuthorizationDecision::Deny(AuthorizationDenial::InsufficientPermissions)
                }
            })
        })
    }
}

#[tokio::test]
async fn custom_manager_receives_context_and_its_decision_is_final() {
    use std::sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    };
    let calls = Arc::new(AtomicUsize::new(0));
    let provider = RequestAuthorizationProvider::builder()
        .method_matchers(Method::GET, "/notes/{id}")
        .access(TestManager {
            fail: false,
            calls: Arc::clone(&calls),
        })
        .any_request()
        .permit_all()
        .build()
        .unwrap();
    let owner = UserDetail::new("owner", "hash", vec![]);
    let other = UserDetail::new("other", "hash", vec![]);
    for (user, expected) in [
        (
            None,
            AuthorizationDecision::Deny(AuthorizationDenial::AuthenticationRequired),
        ),
        (Some(&owner), AuthorizationDecision::Allow),
        (
            Some(&other),
            AuthorizationDecision::Deny(AuthorizationDenial::InsufficientPermissions),
        ),
    ] {
        assert_eq!(
            decision(&provider, user, Method::GET, "/notes/7?shared=true").await,
            expected
        );
    }
    assert_eq!(calls.load(Ordering::SeqCst), 3);
    assert_eq!(
        decision(&provider, None, Method::POST, "/notes/7").await,
        AuthorizationDecision::Allow
    );
    assert_eq!(
        decision(&provider, None, Method::GET, "/other").await,
        AuthorizationDecision::Allow
    );
    assert_eq!(calls.load(Ordering::SeqCst), 3);
}

#[tokio::test]
async fn custom_manager_errors_preserve_source_and_return_internal_server_error() {
    use axum::{body::Body, http::StatusCode};
    use std::{
        error::Error,
        sync::{Arc, atomic::AtomicUsize},
    };
    use tower_service::Service;
    let provider = RequestAuthorizationProvider::<UserDetail>::builder()
        .request_matchers("/notes/{id}")
        .access(TestManager {
            fail: true,
            calls: Arc::new(AtomicUsize::new(0)),
        })
        .any_request()
        .permit_all()
        .build()
        .unwrap();
    let error = provider
        .authorize(
            None,
            RequestContext {
                method: Method::GET,
                uri: "/notes/7?shared=true".parse().unwrap(),
            },
        )
        .await
        .unwrap_err();
    assert_eq!(
        error
            .source()
            .unwrap()
            .downcast_ref::<std::io::Error>()
            .unwrap()
            .to_string(),
        "policy store unavailable"
    );
    let mut app = axum::Router::new()
        .route(
            "/notes/{id}",
            axum::routing::get(|| async { StatusCode::OK }),
        )
        .layer(
            crate::authorization::AuthorizationLayer::builder(provider, request_context_mapper)
                .build(),
        );
    let response = app
        .call(
            axum::extract::Request::builder()
                .uri("/notes/7?shared=true")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::INTERNAL_SERVER_ERROR);
}

#[test]
fn patterns_have_segment_boundaries_and_validate_at_build_time() {
    for (pattern, path, expected) in [
        ("/{*rest}", "/", false),
        ("/notes/{*rest}", "/notes", false),
        ("/notes/{*rest}", "/notes/", false),
        ("/notes/{*rest}", "/notes/1/a", true),
        ("/notes/{*rest}", "/notes-other", false),
        ("/notes/{id}", "/notes/", false),
        ("/notes/{id}", "/notes/1/a", false),
        ("/notes/{id}", "/notes/1/", false),
        ("/", "/", true),
        ("/notes", "/notes/", false),
        ("/Notes", "/notes", false),
    ] {
        assert_eq!(
            RequestPathMatcher::compile(Some(pattern.to_owned()))
                .unwrap()
                .matches(path),
            expected,
            "{pattern}: {path}"
        );
    }
    for pattern in [
        "notes",
        "/notes/{*rest}/child",
        "/notes/{}",
        "/notes/{id",
        "/notes?q=1",
    ] {
        assert!(
            RequestAuthorizationProvider::<UserDetail>::builder()
                .request_matchers(pattern)
                .permit_all()
                .build()
                .is_err(),
            "{pattern}"
        );
    }
}
