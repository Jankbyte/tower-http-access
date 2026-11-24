use axum::response::IntoResponse;
use std::error::Error as StdError;
use tower::{ServiceBuilder, layer::util::Stack};
use tower_http_access_session::{csrf::CsrfLayer, tower_sessions::csrf::CookieCsrfTokenRepository};
use tower_sessions::{Expiry, MemoryStore, SessionManagerLayer, cookie::time::Duration};

pub(crate) const SESSION_COOKIE: &str = "BROWSERSESSION";

type InitializeSessionFuture =
    std::pin::Pin<Box<dyn std::future::Future<Output = axum::response::Response> + Send>>;
type InitializeSessionFn =
    fn(axum::extract::Request, axum::middleware::Next) -> InitializeSessionFuture;
type InitializeSessionLayer =
    axum::middleware::FromFnLayer<InitializeSessionFn, (), (axum::extract::Request,)>;
pub(crate) type SessionLayer = Stack<
    CsrfLayer<CookieCsrfTokenRepository>,
    Stack<
        InitializeSessionLayer,
        Stack<SessionManagerLayer<MemoryStore>, tower::layer::util::Identity>,
    >,
>;

fn initialize_session(
    request: axum::extract::Request,
    next: axum::middleware::Next,
) -> InitializeSessionFuture {
    Box::pin(async move {
        let session = request
            .extensions()
            .get::<tower_sessions::Session>()
            .expect("session manager must run first")
            .clone();
        // tower-sessions does not persist empty sessions. This marker carries no identity.
        if session.is_empty().await && session.insert("initialized", true).await.is_err() {
            return axum::http::StatusCode::INTERNAL_SERVER_ERROR.into_response();
        }
        next.run(request).await
    })
}

pub(crate) fn create_session_layer() -> Result<SessionLayer, Box<dyn StdError + Send + Sync>> {
    let csrf_repository = CookieCsrfTokenRepository::new()
        .with_cookie_name("XSRF-TOKEN")?
        // For production, is recommend to `true`, but release binary does not support
        // HTTPS (only dev from frontend side), so disable that here...
        .with_secure(false)?
        .with_http_only(false);

    let session_store = MemoryStore::default(); // for scalable & stateless production use Redis/any other distributed storage
    let session_layer = SessionManagerLayer::new(session_store)
        .with_secure(true)
        .with_name(SESSION_COOKIE)
        .with_expiry(Expiry::OnInactivity(Duration::minutes(10))) // change timeout of session to required for testing
        .with_always_save(true);

    Ok(ServiceBuilder::new()
        .layer(session_layer)
        // add layer for initialize empty session for matching requests
        .layer(axum::middleware::from_fn(
            initialize_session as InitializeSessionFn,
        ))
        .layer(CsrfLayer::new(csrf_repository).mask_tokens(false))
        .into_inner())
}
