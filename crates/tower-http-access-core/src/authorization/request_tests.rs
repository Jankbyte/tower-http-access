use super::*;
use crate::authorization::core::AuthorizationDecision;
use crate::authorization::core::AuthorizationDenial;
use std::{future::Future, pin::Pin};

struct TestAuthority(String);
impl TestAuthority {
    fn new(value: &str) -> Self {
        Self(value.to_owned())
    }
}

struct TestIdentity {
    username: String,
    authorities: Vec<TestAuthority>,
}
impl TestIdentity {
    fn new(username: &str, _: &str, authorities: Vec<TestAuthority>) -> Self {
        Self {
            username: username.to_owned(),
            authorities,
        }
    }
}
impl HasAuthorities for TestIdentity {
    fn has_authority(&self, authority: &str) -> bool {
        self.authorities.iter().any(|value| value.0 == authority)
    }
}

async fn decision(
    provider: &RequestAuthorizationProvider<TestIdentity>,
    user: Option<&TestIdentity>,
    method: Method,
    uri: &str,
) -> AuthorizationDecision {
    provider
        .authorize(
            user,
            &http::Request::builder()
                .method(method)
                .uri(uri)
                .body(())
                .unwrap()
                .into_parts()
                .0,
        )
        .await
        .unwrap()
}

#[tokio::test]
async fn ordered_policies_and_identity_requirements() {
    let provider = RequestAuthorizationProvider::<TestIdentity>::builder()
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
    let reader = TestIdentity::new("reader", "hash", vec![TestAuthority::new("ReadNote")]);
    let admin = TestIdentity::new("admin", "hash", vec![TestAuthority::new("ADMIN")]);
    assert!(matches!(
        decision(&provider, None, Method::GET, "/public").await,
        AuthorizationDecision::Allow
    ));
    assert!(matches!(
        decision(&provider, None, Method::GET, "/private").await,
        AuthorizationDecision::Deny(AuthorizationDenial::AuthenticationRequired)
    ));
    assert!(matches!(
        decision(&provider, Some(&reader), Method::GET, "/private").await,
        AuthorizationDecision::Allow
    ));
    assert!(matches!(
        decision(&provider, Some(&reader), Method::GET, "/admin/a").await,
        AuthorizationDecision::Deny(AuthorizationDenial::InsufficientPermissions)
    ));
    assert!(matches!(
        decision(&provider, Some(&admin), Method::GET, "/admin/dashboard").await,
        AuthorizationDecision::Allow
    ));
    assert!(matches!(
        decision(&provider, Some(&reader), Method::GET, "/notes/1?q=x").await,
        AuthorizationDecision::Allow
    ));
    assert!(matches!(
        decision(&provider, Some(&reader), Method::DELETE, "/notes/1").await,
        AuthorizationDecision::Deny(AuthorizationDenial::InsufficientPermissions)
    ));
    assert!(matches!(
        decision(&provider, Some(&admin), Method::GET, "/unknown").await,
        AuthorizationDecision::Deny(AuthorizationDenial::InsufficientPermissions)
    ));
}

#[tokio::test]
async fn first_match_is_final_and_unmatched_requests_are_denied() {
    let user = TestIdentity::new("user", "hash", vec![]);
    let provider = RequestAuthorizationProvider::builder()
        .request_matchers("/blocked")
        .deny_all()
        .any_request()
        .permit_all()
        .build()
        .unwrap();
    assert!(matches!(
        decision(&provider, Some(&user), Method::GET, "/blocked").await,
        AuthorizationDecision::Deny(AuthorizationDenial::InsufficientPermissions)
    ));
    assert!(matches!(
        decision(&provider, None, Method::GET, "/").await,
        AuthorizationDecision::Allow
    ));
    let overlapping = RequestAuthorizationProvider::builder()
        .request_matchers("/notes/{*rest}")
        .deny_all()
        .request_matchers("/notes/public")
        .permit_all()
        .build()
        .unwrap();
    assert!(matches!(
        decision(&overlapping, Some(&user), Method::GET, "/notes/public").await,
        AuthorizationDecision::Deny(AuthorizationDenial::InsufficientPermissions)
    ));
    let empty = RequestAuthorizationProvider::builder().build().unwrap();
    assert!(matches!(
        decision(&empty, None, Method::GET, "/anything").await,
        AuthorizationDecision::Deny(AuthorizationDenial::AuthenticationRequired)
    ));
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
    let reader = TestIdentity::new("reader", "hash", vec![TestAuthority::new("ReadNote")]);
    let editor = TestIdentity::new(
        "editor",
        "hash",
        vec![
            TestAuthority::new("ReadNote"),
            TestAuthority::new("WriteNote"),
        ],
    );
    let writer = TestIdentity::new("writer", "hash", vec![TestAuthority::new("WriteNote")]);
    let no_authorities = TestIdentity::new("user", "hash", vec![]);
    for user in [&reader, &writer, &no_authorities] {
        assert!(matches!(
            decision(&provider, Some(user), Method::GET, "/notes").await,
            AuthorizationDecision::Deny(AuthorizationDenial::InsufficientPermissions)
        ));
    }
    assert!(matches!(
        decision(&provider, Some(&editor), Method::GET, "/notes").await,
        AuthorizationDecision::Allow
    ));
    for path in ["/notes", "/empty"] {
        assert!(matches!(
            decision(&provider, None, Method::GET, path).await,
            AuthorizationDecision::Deny(AuthorizationDenial::AuthenticationRequired)
        ));
    }
    assert!(matches!(
        decision(&provider, Some(&no_authorities), Method::GET, "/empty").await,
        AuthorizationDecision::Allow
    ));
}

struct TestManager {
    fail: bool,
    calls: std::sync::Arc<std::sync::atomic::AtomicUsize>,
}

impl AuthorizationProvider for TestManager {
    type Authentication = TestIdentity;
    type Error = std::io::Error;

    fn authorize<'a>(
        &'a self,
        user: Option<&'a TestIdentity>,
        context: &'a Parts,
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
    let owner = TestIdentity::new("owner", "hash", vec![]);
    let other = TestIdentity::new("other", "hash", vec![]);
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
        crate::authorization::core::assert_builtin_decision(
            decision(&provider, user, Method::GET, "/notes/7?shared=true").await,
            expected,
        );
    }
    assert_eq!(calls.load(Ordering::SeqCst), 3);
    assert!(matches!(
        decision(&provider, None, Method::POST, "/notes/7").await,
        AuthorizationDecision::Allow
    ));
    assert!(matches!(
        decision(&provider, None, Method::GET, "/other").await,
        AuthorizationDecision::Allow
    ));
    assert_eq!(calls.load(Ordering::SeqCst), 3);
}

#[cfg(feature = "split_auth")]
#[tokio::test]
async fn custom_manager_errors_preserve_source_and_return_internal_server_error() {
    use axum::{body::Body, http::StatusCode};
    use std::{
        error::Error,
        sync::{Arc, atomic::AtomicUsize},
    };
    use tower_service::Service;
    let provider = RequestAuthorizationProvider::<TestIdentity>::builder()
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
            &http::Request::builder()
                .uri("/notes/7?shared=true")
                .body(())
                .unwrap()
                .into_parts()
                .0,
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
        .layer(crate::authorization::auth_tower::AuthorizationLayer::builder(provider).build());
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
            PathPatternRequestMatcher::new(pattern).unwrap().matches(
                &http::Request::builder()
                    .uri(path)
                    .body(())
                    .unwrap()
                    .into_parts()
                    .0,
            ),
            expected,
        );
    }
    for pattern in [
        "",
        "notes",
        "/notes/{*rest}/child",
        "/notes/{}",
        "/notes/{id",
        "/notes?q=1",
        "/notes#fragment",
    ] {
        assert!(
            PathPatternRequestMatcher::new(pattern).is_err(),
            "{pattern}"
        );
        assert!(
            RequestAuthorizationProvider::<TestIdentity>::builder()
                .request_matchers(pattern)
                .permit_all()
                .build()
                .is_err(),
            "{pattern}"
        );
    }
}

#[tokio::test]
async fn explicit_path_matchers_preserve_order_and_ignore_queries_and_methods() {
    let provider = RequestAuthorizationProvider::<TestIdentity>::builder()
        .matching(PathPatternRequestMatcher::new("/notes/private").unwrap())
        .deny_all()
        .matching(PathPatternRequestMatcher::new("/notes/{id}").unwrap())
        .permit_all()
        .build()
        .unwrap();
    let user = TestIdentity::new("user", "hash", vec![]);
    for method in [Method::GET, Method::POST] {
        assert!(matches!(
            decision(&provider, None, method.clone(), "/notes/42?view=full").await,
            AuthorizationDecision::Allow
        ));
        for path in ["/notes/private", "/other", "/notes/42/"] {
            assert!(matches!(
                decision(&provider, Some(&user), method.clone(), path).await,
                AuthorizationDecision::Deny(AuthorizationDenial::InsufficientPermissions)
            ));
        }
    }
}

#[tokio::test]
async fn user_defined_matcher_can_select_rules() {
    struct PostOnly;
    impl RequestMatcher for PostOnly {
        fn matches(&self, request: &http::request::Parts) -> bool {
            request.method == Method::POST
        }
    }
    let provider = RequestAuthorizationProvider::<TestIdentity>::builder()
        .matching(PostOnly)
        .permit_all()
        .any_request()
        .deny_all()
        .build()
        .unwrap();
    assert!(matches!(
        decision(&provider, None, Method::POST, "/anything").await,
        AuthorizationDecision::Allow
    ));
    assert!(matches!(
        decision(&provider, None, Method::GET, "/anything").await,
        AuthorizationDecision::Deny(AuthorizationDenial::AuthenticationRequired)
    ));
}

#[cfg(feature = "split_auth")]
#[tokio::test]
async fn middleware_matchers_borrow_original_headers_and_extensions() {
    use axum::{body::Body, http::StatusCode};
    use tower_service::Service;

    #[derive(Clone)]
    struct ClientAddress(std::net::IpAddr);

    struct MetadataMatcher;
    impl RequestMatcher for MetadataMatcher {
        fn matches(&self, parts: &http::request::Parts) -> bool {
            parts.method == Method::POST
                && parts.uri.path() == "/notes"
                && parts
                    .headers
                    .get("x-client-kind")
                    .is_some_and(|v| v == "internal")
                && parts
                    .extensions
                    .get::<ClientAddress>()
                    .is_some_and(|address| address.0.is_loopback())
        }
    }

    let provider = RequestAuthorizationProvider::<TestIdentity>::builder()
        .matching(MetadataMatcher)
        .permit_all()
        .any_request()
        .deny_all()
        .build()
        .unwrap();
    let mut app = axum::Router::new()
        .route(
            "/notes",
            axum::routing::post(|request: axum::extract::Request| async move {
                // Matching must preserve the metadata and streaming body for the handler.
                assert!(request.extensions().get::<ClientAddress>().is_some());
                let body = axum::body::to_bytes(request.into_body(), 100)
                    .await
                    .unwrap();
                assert_eq!(body.as_ref(), b"payload");
                StatusCode::OK
            }),
        )
        .layer(crate::authorization::auth_tower::AuthorizationLayer::builder(provider).build());

    for (header, address, expected) in [
        (Some("internal"), Some("127.0.0.1"), StatusCode::OK),
        (None, Some("127.0.0.1"), StatusCode::UNAUTHORIZED),
        (Some("internal"), None, StatusCode::UNAUTHORIZED),
        (
            Some("internal"),
            Some("192.0.2.1"),
            StatusCode::UNAUTHORIZED,
        ),
    ] {
        let mut request = http::Request::builder().method(Method::POST).uri("/notes");
        if let Some(header) = header {
            request = request.header("x-client-kind", header);
        }
        let mut request = request.body(Body::from("payload")).unwrap();
        if let Some(address) = address {
            request
                .extensions_mut()
                .insert(ClientAddress(address.parse().unwrap()));
        }
        assert_eq!(app.call(request).await.unwrap().status(), expected,);
    }
}

#[tokio::test]
async fn custom_manager_borrows_original_parts_across_await() {
    #[derive(Clone)]
    struct Tenant(String);

    struct TenantManager;
    impl AuthorizationProvider for TenantManager {
        type Authentication = TestIdentity;
        type Error = std::convert::Infallible;

        fn authorize<'a>(
            &'a self,
            user: Option<&'a TestIdentity>,
            parts: &'a Parts,
        ) -> Pin<Box<dyn Future<Output = Result<AuthorizationDecision, Self::Error>> + Send + 'a>>
        {
            Box::pin(async move {
                let tenant = parts.extensions.get::<Tenant>().unwrap();
                let header = parts.headers.get("x-tenant").unwrap();
                tokio::task::yield_now().await;
                assert_eq!(user.unwrap().username, "alice");
                assert_eq!(tenant.0, "team-a");
                assert_eq!(header, "team-a");
                assert!(std::ptr::eq(
                    tenant,
                    parts.extensions.get::<Tenant>().unwrap()
                ));
                Ok(AuthorizationDecision::Allow)
            })
        }
    }

    let provider = RequestAuthorizationProvider::builder()
        .request_matchers("/notes/{id}")
        .access(TenantManager)
        .build()
        .unwrap();
    // The same authorize entry point works through an object-safe provider.
    let provider: &dyn AuthorizationProvider<Authentication = TestIdentity, Error = RequestAuthorizationError> =
        &provider;
    let user = TestIdentity::new("alice", "hash", vec![]);
    let (mut parts, _) = http::Request::builder()
        .uri("/notes/42")
        .header("x-tenant", "team-a")
        .body(())
        .unwrap()
        .into_parts();
    parts.extensions.insert(Tenant("team-a".to_owned()));
    assert!(matches!(
        provider.authorize(Some(&user), &parts).await.unwrap(),
        AuthorizationDecision::Allow
    ));
}

#[tokio::test]
async fn string_identities_support_rules_without_authorities() {
    use crate::authorization::core::AuthorizationProviderExt;
    use crate::authorization::default_auth::AuthenticatedAuthorizationProvider;
    let provider = RequestAuthorizationProvider::<String>::builder()
        .request_matchers("/public")
        .permit_all()
        .request_matchers("/private")
        .authenticated()
        .request_matchers("/custom")
        .access(
            AuthenticatedAuthorizationProvider::<usize>::new()
                .map(|identity: &String| identity.len()),
        )
        .request_matchers("/blocked")
        .deny_all()
        .build()
        .unwrap();
    let identity = "alex".to_owned();
    for (path, anonymous, authenticated) in [
        (
            "/public",
            AuthorizationDecision::Allow,
            AuthorizationDecision::Allow,
        ),
        (
            "/private",
            AuthorizationDecision::Deny(AuthorizationDenial::AuthenticationRequired),
            AuthorizationDecision::Allow,
        ),
        (
            "/custom",
            AuthorizationDecision::Deny(AuthorizationDenial::AuthenticationRequired),
            AuthorizationDecision::Allow,
        ),
        (
            "/blocked",
            AuthorizationDecision::Deny(AuthorizationDenial::AuthenticationRequired),
            AuthorizationDecision::Deny(AuthorizationDenial::InsufficientPermissions),
        ),
        (
            "/unmatched",
            AuthorizationDecision::Deny(AuthorizationDenial::AuthenticationRequired),
            AuthorizationDecision::Deny(AuthorizationDenial::InsufficientPermissions),
        ),
    ] {
        let (parts, _) = http::Request::builder()
            .uri(path)
            .body(())
            .unwrap()
            .into_parts();
        crate::authorization::core::assert_builtin_decision(
            provider.authorize(None, &parts).await.unwrap(),
            anonymous,
        );
        crate::authorization::core::assert_builtin_decision(
            provider.authorize(Some(&identity), &parts).await.unwrap(),
            authenticated,
        );
    }
}

#[cfg(feature = "axum")]
#[tokio::test]
async fn string_request_rules_integrate_with_combined_layer_without_basic_authentication() {
    use crate::{
        SecurityLayer,
        authentication::{Authenticated, AuthenticationAttempt, AuthenticatorError},
    };
    use axum::{
        body::{Body, to_bytes},
        extract::Request,
    };
    use tower_service::Service;

    let authenticator = |_: &Parts| async {
        Ok::<_, AuthenticatorError>(AuthenticationAttempt::Authenticated("alex".to_owned()))
    };
    let rules = RequestAuthorizationProvider::<String>::builder()
        .any_request()
        .authenticated()
        .build()
        .unwrap();
    let mut app = axum::Router::new()
        .route(
            "/",
            axum::routing::get(
                |Authenticated(identity): Authenticated<String>| async move { identity },
            ),
        )
        .layer(SecurityLayer::new(
            authenticator,
            std::sync::Arc::new(rules),
        ));
    let response = app.call(Request::new(Body::empty())).await.unwrap();
    assert_eq!(
        to_bytes(response.into_body(), usize::MAX).await.unwrap(),
        "alex"
    );
}

#[tokio::test]
async fn catch_all_rule_applies_after_specific_rules_and_before_later_rules() {
    let provider = RequestAuthorizationProvider::<String>::builder()
        .request_matchers("/public")
        .permit_all()
        .matching(http_request_matcher::AnyRequestMatcher)
        .deny_all()
        .request_matchers("/later")
        .permit_all()
        .build()
        .unwrap();

    for (method, path, allowed) in [
        ("GET", "/public", true),
        ("GET", "/private", false),
        ("POST", "/later", false),
        ("DELETE", "/", false),
    ] {
        let (parts, _) = http::Request::builder()
            .method(method)
            .uri(path)
            .body(())
            .unwrap()
            .into_parts();
        let decision = provider.authorize(None, &parts).await.unwrap();
        assert!(matches!(
            (decision, allowed),
            (AuthorizationDecision::Allow, true) | (AuthorizationDecision::Deny(_), false)
        ));
    }
}
