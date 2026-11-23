mod auth;
#[cfg(not(debug_assertions))]
mod frontend;
mod users;

use axum::{http::Method, serve};
use std::{error::Error as StdError, sync::Arc};
use tokio::net::TcpListener;
use tower::{ServiceBuilder, layer::util::Stack};
use tower_http_access_authorizers::request::RequestAuthorizationProvider;
use tower_http_access_core::security_layer::SecurityLayer;
use tower_http_access_session::{
    csrf::CsrfLayer,
    tower_sessions::{
        SessionRequestAuthenticator, SessionStoredIdentity, csrf::CookieCsrfTokenRepository,
    },
};
use tower_sessions::{Expiry, MemoryStore, SessionManagerLayer, cookie::time::Duration};
use user_password_auth::UserDetail;

const BIND_ADDRESS: &str = "127.0.0.1:3001";
const AUTH_SESSION_KEY: &str = "auth";

#[tokio::main(flavor = "current_thread")]
async fn main() -> Result<(), Box<dyn StdError + Send + Sync>> {
    tracing_subscriber::fmt()
        .with_max_level(tracing::Level::TRACE)
        .init();

    let users = vec![
        UserDetail::new("alex", "alex123", vec![]),
        UserDetail::new("max", "max123", vec![]),
    ];
    let provider = users::create_up_provider(3, users).await;

    let session_layer = create_session_layer()?;

    let router = auth::router(AUTH_SESSION_KEY, provider)?;
    #[cfg(not(debug_assertions))]
    let router = router.merge(frontend::router());

    let security_layer = SecurityLayer::new(
        Arc::new(
            SessionRequestAuthenticator::new(SessionStoredIdentity::<UserDetail>::new())
                .with_session_key(AUTH_SESSION_KEY),
        ),
        Arc::new(create_authorizer()),
    );

    let browser_security_stack = ServiceBuilder::new()
        .layer(session_layer)
        .layer(security_layer);

    let router = router.layer(browser_security_stack);

    let listener = TcpListener::bind(BIND_ADDRESS).await?;
    serve(listener, router).await?;

    Ok(())
}

fn create_authorizer() -> RequestAuthorizationProvider<UserDetail> {
    RequestAuthorizationProvider::builder()
        .request_matchers("/")
        .permit_all()
        .request_matchers("/ui")
        .permit_all()
        .request_matchers("/ui/")
        .permit_all()
        .request_matchers("/ui/{*path}")
        .permit_all()
        .method_matchers(Method::POST, auth::LOGIN_PATH)
        .anonymous()
        .any_request()
        .authenticated()
        .build()
        .expect("valid browser authorization rules")
}

type SessionLayer = Stack<CsrfLayer<CookieCsrfTokenRepository>, SessionManagerLayer<MemoryStore>>;

fn create_session_layer() -> Result<SessionLayer, Box<dyn StdError + Send + Sync>> {
    let csrf_repository = CookieCsrfTokenRepository::new()
        .with_cookie_name("XSRF-TOKEN")?
        // For production, is recommend to `true`, but release binary does not support
        // HTTPS (only dev from frontend side), so disable that here...
        .with_secure(false)?
        .with_http_only(false);

    let session_store = MemoryStore::default(); // for scalable & stateless production use Redis/any other distributed storage
    let session_layer = SessionManagerLayer::new(session_store)
        .with_secure(true)
        .with_name("BROWSERSESSION")
        .with_expiry(Expiry::OnInactivity(Duration::minutes(1)))
        .with_always_save(true);

    Ok(Stack::new(
        CsrfLayer::new(csrf_repository).mask_tokens(false),
        session_layer,
    ))
}

#[cfg(test)]
mod tests;
