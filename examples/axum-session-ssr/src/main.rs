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
use public::main_page;
use std::{error::Error as StdError, sync::Arc};
use tokio::net::TcpListener;
use tower_http_access_authorizers::request::RequestAuthorizationProvider;
use tower_http_access_core::{authorization::AuthorizationProvider, security_layer::SecurityLayer};
use tower_http_access_session::{
    csrf::CsrfLayer,
    entry_point::RedirectAuthenticationEntryPoint,
    tower_sessions::{
        SessionRequestAuthenticator, SessionStoredIdentity, csrf::HttpSessionCsrfTokenRepository,
    },
};
use tower_sessions::{MemoryStore, SessionManagerLayer};
use user_password_auth::{Authority, UserDetail};
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
    let session_authenticator = Arc::new(SessionRequestAuthenticator::new_with_extractor(
        SessionStoredIdentity::<SessionIdentity>::default(),
        |session| async move { session.get(SESSION_COOKIE_ID).await },
    ));

    let redirect_entry_point = RedirectAuthenticationEntryPoint::new(LOGIN_PAGE_PATH)?;
    let security_layer = SecurityLayer::new(session_authenticator, Arc::new(create_authorizer()))
        .authentication_entry_point(redirect_entry_point)
        .failure_handler(HtmlAuthorizationFailureHandler);

    let session_store = MemoryStore::default();
    let session_layer = SessionManagerLayer::new(session_store).with_secure(false);

    let users = vec![UserDetail::new(
        "crab",
        "crab123",
        vec![Authority::new("demo")],
    )];
    let concurrency = 5; // process hashing in max 5 threads
    let provider = create_up_provider(concurrency, users).await;
    let form_login_layer = create_form_login_layer(provider)?;

    // Request -> SessionLayer -> CSRF -> FormLogin -> SecurityLayer -> route
    let app = Router::new()
        .route(LOGIN_PAGE_PATH, get(login_page))
        .route(ME_PAGE_PATH, get(get_authenticated))
        .route("/", get(main_page))
        .route(LOGOUT_PAGE_PATH, post(logout))
        .layer(security_layer)
        .layer(form_login_layer)
        .layer(CsrfLayer::new(HttpSessionCsrfTokenRepository::new()))
        .layer(session_layer);
    Ok(app)
}

fn create_authorizer() -> impl AuthorizationProvider<Authentication = SessionIdentity> {
    RequestAuthorizationProvider::builder()
        .method_matchers(Method::GET, LOGIN_PAGE_PATH)
        .permit_all()
        .method_matchers(Method::GET, "/")
        .permit_all()
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
