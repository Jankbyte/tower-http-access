mod auth;
mod authorization_failure;
mod login;
mod public;
mod users;

use auth::{LOGOUT_PAGE_PATH, ME_PAGE_PATH, get_authenticated, logout};
use authorization_failure::HtmlAuthorizationFailureHandler;
use axum::http::Method;
use axum::{
    Router,
    routing::{get, post},
    serve,
};
use login::{LOGIN_PAGE_PATH, create_form_login_layer, login_page};
use public::{MAIN_PAGE_PATH, main_page};
use std::{error::Error as StdError, sync::Arc};
use tokio::net::TcpListener;
use tower::ServiceBuilder;
use tower_http_access_authorizers::request::RequestAuthorizationProvider;
use tower_http_access_core::{authorization::AuthorizationProvider, security_layer::SecurityLayer};
use tower_http_access_session::{
    csrf::CsrfLayer,
    entry_point::RedirectAuthenticationEntryPoint,
    tower_sessions::{
        SessionRequestAuthenticator, SessionStoredIdentity, csrf::HttpSessionCsrfTokenRepository,
    },
};
use tower_sessions::{Expiry, MemoryStore, SessionManagerLayer, cookie::time::Duration};
use user_password_auth::UserDetail;
use users::create_up_provider;

const BIND_ADDRESS: &str = "127.0.0.1:3000";
const SESSION_COOKIE_ID: &str = "identity";

#[tokio::main(flavor = "current_thread")]
async fn main() -> Result<(), Box<dyn StdError + Send + Sync>> {
    let app = create_app().await?;
    let listener = TcpListener::bind(BIND_ADDRESS).await?;
    serve(listener, app).await?;
    Ok(())
}

async fn create_app() -> Result<Router, Box<dyn StdError + Send + Sync>> {
    tracing_subscriber::fmt()
        .with_max_level(tracing::Level::TRACE)
        .init();

    let session_authenticator = Arc::new(
        SessionRequestAuthenticator::new(SessionStoredIdentity::<SessionIdentity>::default())
            .with_session_key(SESSION_COOKIE_ID),
    );

    let security_layer = SecurityLayer::new(session_authenticator, Arc::new(create_authorizer()))
        .authentication_entry_point(RedirectAuthenticationEntryPoint::new(LOGIN_PAGE_PATH)?)
        .failure_handler(HtmlAuthorizationFailureHandler);

    let session_store = MemoryStore::default();
    let session_layer = SessionManagerLayer::new(session_store)
        .with_secure(false)
        .with_name("BROWSERSESSION")
        .with_expiry(Expiry::OnInactivity(Duration::minutes(1)))
        .with_always_save(true);

    let users = vec![UserDetail::new("crab", "crab123", vec![])];
    let concurrency = 5; // process hashing in max 5 threads
    let provider = create_up_provider(concurrency, users).await;
    let form_login_layer = create_form_login_layer(provider)?;

    let browser_security_stack = ServiceBuilder::new()
        .layer(session_layer)
        .layer(CsrfLayer::new(HttpSessionCsrfTokenRepository::new()))
        .layer(security_layer)
        .layer(form_login_layer);

    let app = Router::new()
        .route(LOGIN_PAGE_PATH, get(login_page))
        .route(ME_PAGE_PATH, get(get_authenticated))
        .route(MAIN_PAGE_PATH, get(main_page))
        .route(LOGOUT_PAGE_PATH, post(logout))
        .layer(browser_security_stack);

    Ok(app)
}

fn create_authorizer() -> impl AuthorizationProvider<Authentication = SessionIdentity> {
    RequestAuthorizationProvider::builder()
        .method_matchers(Method::POST, LOGIN_PAGE_PATH)
        .anonymous() // do not allow authentication while authenticated
        .method_matchers(Method::GET, LOGIN_PAGE_PATH)
        .permit_all()
        .method_matchers(Method::GET, MAIN_PAGE_PATH)
        .permit_all()
        .method_matchers(Method::GET, "/deny") // just for test "403 Forbidden"
        .deny_all()
        .any_request()
        .authenticated()
        .build()
        .expect("build authorization provider")
}

#[derive(Clone, serde::Serialize, serde::Deserialize)]
struct SessionIdentity {
    username: String,
}

#[cfg(test)]
mod tests;
