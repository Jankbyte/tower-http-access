use super::*;
use axum::{
    Router,
    body::{Body, to_bytes},
    http::{Request, StatusCode, header},
    routing::get,
};
use tower::ServiceExt;
use tower_http_access_core::authorization::{AuthorizationDecision, AuthorizationProvider};
use tower_sessions::Session;
use user_password_auth::Authority;

fn test_app() -> Router {
    let security = SecurityLayer::new(
        Arc::new(
            SessionRequestAuthenticator::new(SessionStoredIdentity::<UserDetail>::new())
                .with_session_key(AUTH_SESSION_KEY),
        ),
        Arc::new(create_authorizer()),
    );
    auth::router(AUTH_SESSION_KEY, TestProvider)
        .unwrap()
        .layer(security)
        // Seed a real session outside the authorization layer for this test.
        .route(
            "/seed",
            get(
                |axum::Extension(session): axum::Extension<Session>| async move {
                    session
                        .insert(
                            AUTH_SESSION_KEY,
                            UserDetail::new(
                                "alice",
                                "secret-password-hash",
                                vec![Authority::new("Reader")],
                            ),
                        )
                        .await
                        .unwrap();
                    StatusCode::NO_CONTENT
                },
            ),
        )
        .layer(create_session_layer().unwrap())
}

#[tokio::test]
async fn anonymous_me_returns_401_and_initializes_csrf() {
    let response = test_app()
        .oneshot(
            Request::builder()
                .uri("/v1/ui/auth/me")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    assert!(
        response
            .headers()
            .get_all(header::SET_COOKIE)
            .iter()
            .any(|cookie| {
                let value = cookie.to_str().unwrap();
                value.starts_with("XSRF-TOKEN=") && !value.contains("HttpOnly")
            })
    );
}

#[tokio::test]
async fn authenticated_me_returns_public_identity_without_password_hash() {
    let app = test_app();
    let seeded = app
        .clone()
        .oneshot(Request::builder().uri("/seed").body(Body::empty()).unwrap())
        .await
        .unwrap();
    let cookie = seeded
        .headers()
        .get_all(header::SET_COOKIE)
        .iter()
        .map(|value| value.to_str().unwrap())
        .find(|value| value.starts_with("BROWSERSESSION="))
        .unwrap()
        .split(';')
        .next()
        .unwrap();
    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .uri("/v1/ui/auth/me")
                .header(header::COOKIE, cookie)
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(response.headers()[header::CACHE_CONTROL], "no-store");
    let body = to_bytes(response.into_body(), 4096).await.unwrap();
    assert_eq!(
        std::str::from_utf8(&body).unwrap(),
        r#"{"username":"alice","authorities":["Reader"]}"#
    );
    let removed = app
        .oneshot(
            Request::builder()
                .uri("/v1/ui/auth/csrf")
                .header(header::COOKIE, cookie)
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(removed.status(), StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn authorization_rules_allow_ui_and_require_authentication_for_login_and_me() {
    let authorizer = create_authorizer();
    for path in ["/", "/ui", "/ui/", "/ui/login", "/ui/assets/app.js"] {
        let (parts, _) = Request::builder().uri(path).body(()).unwrap().into_parts();
        assert!(matches!(
            authorizer.authorize(None, &parts).await.unwrap(),
            AuthorizationDecision::Allow
        ));
    }
    let user = UserDetail::new("alice", "hash", vec![]);
    for (method, path) in [
        (Method::POST, auth::LOGIN_PATH),
        (Method::GET, "/v1/ui/auth/me"),
    ] {
        let (parts, _) = Request::builder()
            .method(method)
            .uri(path)
            .body(())
            .unwrap()
            .into_parts();
        assert!(matches!(
            authorizer.authorize(None, &parts).await.unwrap(),
            AuthorizationDecision::Deny(_)
        ));
        assert!(matches!(
            authorizer.authorize(Some(&user), &parts).await.unwrap(),
            AuthorizationDecision::Allow
        ));
    }
}

#[derive(Clone)]
struct TestProvider;

impl user_password_auth::UsernamePasswordAuthenticationProvider for TestProvider {
    type Authentication = UserDetail;
    type Error = std::io::Error;

    fn authenticate<'a>(
        &'a self,
        _: &'a user_password_auth::Credentials,
    ) -> std::pin::Pin<Box<dyn Future<Output = Result<Option<UserDetail>, Self::Error>> + Send + 'a>>
    {
        Box::pin(async { Ok(Some(UserDetail::new("alice", "hash", vec![]))) })
    }
}

#[tokio::test]
async fn auth_router_exposes_login_with_form_login_middleware() {
    let app = test_app();
    let seeded = app
        .clone()
        .oneshot(Request::builder().uri("/seed").body(Body::empty()).unwrap())
        .await
        .unwrap();
    let cookies: Vec<_> = seeded
        .headers()
        .get_all(header::SET_COOKIE)
        .iter()
        .map(|value| value.to_str().unwrap().split(';').next().unwrap())
        .collect();
    let token = cookies
        .iter()
        .find_map(|value| value.strip_prefix("XSRF-TOKEN="))
        .unwrap();
    let response = app
        .oneshot(
            Request::builder()
                .method(Method::POST)
                .uri(auth::LOGIN_PATH)
                .header(header::COOKIE, cookies.join("; "))
                .header("x-xsrf-token", token)
                .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
                .body(Body::from(
                    "username=alice&password=password&rememberme=false",
                ))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
}
