use super::*;
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
