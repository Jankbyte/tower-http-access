use super::*;
use crate::SessionStoredIdentity;
use axum::{
    Router,
    body::Body,
    http::{Request, StatusCode},
    routing::get,
};
use std::sync::Arc;
use tower::ServiceExt;
use tower_http_access::{
    SecurityLayer, authentication::Authenticated, authorization::AuthenticatedAuthorizationProvider,
};
use tower_sessions::{MemoryStore, SessionManagerLayer};

struct Users;
impl SessionIdentityProvider for Users {
    type Id = String;
    type Identity = String;
    type Error = std::io::Error;

    fn load_identity<'a>(
        &'a self,
        id: String,
    ) -> BoxFuture<'a, Result<Option<String>, Self::Error>> {
        Box::pin(async move {
            match id.as_str() {
                "failure" => Err(std::io::Error::other("database unavailable")),
                "alice" => Ok(Some(id)),
                _ => Ok(None),
            }
        })
    }
}

#[tokio::test]
async fn resolves_current_identity_and_distinguishes_anonymous_from_errors() {
    for (value, expected) in [
        (None, 401),
        (Some("alice"), 200),
        (Some("deleted"), 401),
        (Some("failure"), 500),
    ] {
        let session = Session::new(None, Arc::new(MemoryStore::default()), None);
        if let Some(value) = value {
            session.insert("account", value).await.unwrap();
        }
        let app = Router::new()
            .route(
                "/",
                get(|Authenticated(user): Authenticated<String>| async move { user }),
            )
            .layer(SecurityLayer::new(
                SessionRequestAuthenticator::new(Users).with_session_key("account"),
                AuthenticatedAuthorizationProvider::<String>::new(),
            ));
        let mut request = Request::new(Body::empty());
        request.extensions_mut().insert(session);
        let response = app.oneshot(request).await.unwrap();
        assert_eq!(response.status().as_u16(), expected);
        if expected == 200 {
            assert_eq!(
                axum::body::to_bytes(response.into_body(), 1024)
                    .await
                    .unwrap(),
                "alice"
            );
        }
    }
}

#[tokio::test]
async fn missing_middleware_and_malformed_data_are_internal_errors() {
    let authenticator = SessionRequestAuthenticator::new(Users);
    let (mut parts, _) = Request::new(()).into_parts();
    let error = authenticator.authenticate(&mut parts).await.unwrap_err();
    assert_eq!(
        error.into_security_response().status(),
        StatusCode::INTERNAL_SERVER_ERROR
    );
    let session = Session::new(None, Arc::new(MemoryStore::default()), None);
    session.insert("user_id", 42).await.unwrap();
    parts.extensions.insert(session);
    let error = authenticator.authenticate(&mut parts).await.unwrap_err();
    assert_eq!(
        error.into_security_response().status(),
        StatusCode::INTERNAL_SERVER_ERROR
    );
}

#[tokio::test]
async fn cookie_session_round_trip_and_logout() {
    // Login is seeded here; a real login handler must verify credentials first.
    let store = Arc::new(MemoryStore::default());
    let session = Session::new(None, Arc::clone(&store), None);
    session.insert("user_id", "alice").await.unwrap();
    session.save().await.unwrap();
    let cookie = format!("id={}", session.id().unwrap());
    let app = Router::new()
        .route("/", get(|| async { "allowed" }))
        .layer(SecurityLayer::new(
            SessionRequestAuthenticator::new(Users),
            AuthenticatedAuthorizationProvider::<String>::new(),
        ))
        .layer(SessionManagerLayer::new(store.as_ref().clone()).with_secure(false));
    let request = || {
        Request::builder()
            .uri("/")
            .header("cookie", &cookie)
            .body(Body::empty())
            .unwrap()
    };
    assert_eq!(
        app.clone().oneshot(request()).await.unwrap().status(),
        StatusCode::OK
    );
    session.flush().await.unwrap();
    assert_eq!(
        app.oneshot(request()).await.unwrap().status(),
        StatusCode::UNAUTHORIZED
    );
}

#[tokio::test]
async fn initialization_creates_anonymous_session_without_rewriting_existing_session() {
    let store = Arc::new(MemoryStore::default());
    let session = Session::new(None, Arc::clone(&store), None);
    initialize_session(&session).await.unwrap();
    assert!(session.get::<String>("user_id").await.unwrap().is_none());
    session.save().await.unwrap();
    let id = session.id();
    let loaded = Session::new(id, store, None);
    initialize_session(&loaded).await.unwrap();
    assert_eq!(loaded.id(), id);
    assert!(!loaded.is_modified());
    loaded.flush().await.unwrap();
    assert!(loaded.is_empty().await);
}

#[tokio::test]
async fn login_entry_point_redirects_only_when_authentication_is_required() {
    for path in ["/login", "/account/login?next=%2Fprivate"] {
        let auth = Arc::new(
            SessionRequestAuthenticator::new(Users)
                .login_page_path(path)
                .unwrap(),
        );
        let app = Router::new().route("/", get(|| async { "allowed" })).layer(
            SecurityLayer::new(
                Arc::clone(&auth),
                AuthenticatedAuthorizationProvider::<String>::new(),
            )
            .authentication_entry_point(auth),
        );
        for (user, status) in [
            (None, StatusCode::FOUND),
            (Some("alice"), StatusCode::OK),
            (Some("failure"), StatusCode::INTERNAL_SERVER_ERROR),
        ] {
            let session = Session::new(None, Arc::new(MemoryStore::default()), None);
            if let Some(user) = user {
                session.insert("user_id", user).await.unwrap();
            }
            let mut request = Request::new(Body::empty());
            request.extensions_mut().insert(session);
            let response = app.clone().oneshot(request).await.unwrap();
            assert_eq!(response.status(), status);
            if status == StatusCode::FOUND {
                assert_eq!(response.headers()[header::LOCATION], path);
            } else {
                assert!(!response.headers().contains_key(header::LOCATION));
            }
        }
    }
}

#[test]
fn login_paths_reject_external_and_invalid_locations() {
    for path in [
        "",
        "login",
        "https://evil.example/login",
        "//evil.example/login",
        "/\\evil.example",
        "/login\r\nInjected: true",
        "/login#fragment",
    ] {
        assert!(
            SessionRequestAuthenticator::new(Users)
                .login_page_path(path)
                .is_err(),
            "{path:?}"
        );
    }
    let (parts, _) = Request::new(()).into_parts();
    let response = SessionRequestAuthenticator::new(Users).commence(&parts);
    assert_eq!(response.status(), StatusCode::FOUND);
    assert_eq!(response.headers()[header::LOCATION], "/login");
}

// Deliberately has no Deserialize implementation.
struct ApplicationId(String);

struct ApplicationUsers;
impl SessionIdentityProvider for ApplicationUsers {
    type Id = ApplicationId;
    type Identity = String;
    type Error = std::io::Error;

    fn load_identity<'a>(
        &'a self,
        id: ApplicationId,
    ) -> BoxFuture<'a, Result<Option<String>, Self::Error>> {
        Box::pin(async move { Users.load_identity(id.0).await })
    }
}

#[tokio::test]
async fn custom_extractor_supports_non_deserializable_ids_and_preserves_error_semantics() {
    let authenticator = Arc::new(
        SessionRequestAuthenticator::new_with_extractor(ApplicationUsers, |session| async move {
            Ok(session.get::<String>("account").await?.map(ApplicationId))
        })
        .login_page_path("/sign-in")
        .unwrap(),
    );
    let app = Router::new().route("/", get(|| async { "allowed" })).layer(
        SecurityLayer::new(
            Arc::clone(&authenticator),
            AuthenticatedAuthorizationProvider::<String>::new(),
        )
        .authentication_entry_point(authenticator),
    );
    for (value, expected) in [
        (None, StatusCode::FOUND),
        (Some("alice"), StatusCode::OK),
        (Some("deleted"), StatusCode::FOUND),
        (Some("failure"), StatusCode::INTERNAL_SERVER_ERROR),
        (Some("malformed"), StatusCode::INTERNAL_SERVER_ERROR),
    ] {
        let session = Session::new(None, Arc::new(MemoryStore::default()), None);
        if value == Some("malformed") {
            session.insert("account", 42).await.unwrap();
        } else if let Some(value) = value {
            session.insert("account", value).await.unwrap();
        }
        let mut request = Request::new(Body::empty());
        request.extensions_mut().insert(session);
        let response = app.clone().oneshot(request).await.unwrap();
        assert_eq!(response.status(), expected);
        if expected == StatusCode::FOUND {
            assert_eq!(response.headers()[header::LOCATION], "/sign-in");
        }
    }
    let response = app.oneshot(Request::new(Body::empty())).await.unwrap();
    assert_eq!(response.status(), StatusCode::INTERNAL_SERVER_ERROR);
}

#[tokio::test]
async fn stored_identity_authenticates_from_session_backend_without_user_lookup() {
    use std::collections::BTreeMap;
    type Identity = BTreeMap<String, String>;

    let store = MemoryStore::default();
    let app = Router::new()
        .route(
            "/",
            get(|Authenticated(user): Authenticated<Identity>| async move {
                format!("{}:{}", user["username"], user["role"])
            }),
        )
        .layer(SecurityLayer::new(
            Arc::new(
                SessionRequestAuthenticator::new(SessionStoredIdentity::<Identity>::default())
                    .with_session_key("authenticated_user"),
            ),
            AuthenticatedAuthorizationProvider::<Identity>::new(),
        ))
        .layer(SessionManagerLayer::new(store.clone()).with_secure(false));

    for (value, expected) in [
        ("identity", StatusCode::OK),
        ("missing", StatusCode::UNAUTHORIZED),
        ("malformed", StatusCode::INTERNAL_SERVER_ERROR),
    ] {
        let session = Session::new(None, Arc::new(store.clone()), None);
        match value {
            "identity" => {
                let identity = Identity::from([
                    ("username".into(), "alice".into()),
                    ("role".into(), "admin".into()),
                ]);
                session
                    .insert("authenticated_user", identity)
                    .await
                    .unwrap();
            }
            "malformed" => session.insert("authenticated_user", 42).await.unwrap(),
            _ => session.insert("unrelated", true).await.unwrap(),
        }
        session.save().await.unwrap();
        let response = app
            .clone()
            .oneshot(
                Request::builder()
                    .header(header::COOKIE, format!("id={}", session.id().unwrap()))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), expected);
        if expected == StatusCode::OK {
            assert_eq!(
                axum::body::to_bytes(response.into_body(), 1024)
                    .await
                    .unwrap(),
                "alice:admin",
            );
        }
    }
}

#[tokio::test]
async fn stored_identity_accepts_custom_extraction_without_serde_bounds() {
    #[derive(Clone, Debug, PartialEq)]
    struct Identity(String);

    let authenticator = SessionRequestAuthenticator::new_with_extractor(
        SessionStoredIdentity::<Identity>::new(),
        |session| async move { Ok(session.get::<String>("username").await?.map(Identity)) },
    );
    let session = Session::new(None, Arc::new(MemoryStore::default()), None);
    session.insert("username", "alice").await.unwrap();
    let (mut parts, _) = Request::new(()).into_parts();
    parts.extensions.insert(session);
    let result = authenticator.authenticate(&mut parts).await.unwrap();
    match result {
        AuthenticationAttempt::Authenticated(identity) => {
            assert_eq!(identity, Identity("alice".into()));
        }
        AuthenticationAttempt::NotApplicable => panic!("expected stored identity"),
    }
}
