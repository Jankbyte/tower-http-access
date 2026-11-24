mod auth;
#[cfg(not(debug_assertions))]
mod frontend;
mod note;
mod principal;
mod session;
use principal::Principal;
use session::create_session_layer;
use tower_http_access_core::authentication::RequestAuthenticatorExt;
mod users;

use axum::{http::Method, serve};
use note::{Note, NoteRepository, create_notes_router};
use std::{error::Error as StdError, sync::Arc};
use tokio::net::TcpListener;
use tower::ServiceBuilder;
use tower_http_access_authorizers::{
    authorities::AuthorityRuleExt, request::RequestAuthorizationProvider,
};
use tower_http_access_basic::BasicRequestAuthenticator;
use tower_http_access_core::{filter_chain::SecurityChainLayer, security_layer::SecurityLayer};
use tower_http_access_session::{
    BrowserRequestMatcher,
    tower_sessions::{SessionRequestAuthenticator, SessionStoredIdentity},
};
use user_password_auth::{Authority, UserDetail};

const BIND_ADDRESS: &str = "127.0.0.1:3001";
const AUTH_SESSION_KEY: &str = "auth";

#[tokio::main(flavor = "current_thread")]
async fn main() -> Result<(), Box<dyn StdError + Send + Sync>> {
    tracing_subscriber::fmt()
        .with_max_level(tracing::Level::TRACE)
        .init();

    let users = vec![
        UserDetail::new(
            "alex",
            "alex123",
            vec![
                Authority::new(note::permissions::CREATE_OWN_NOTE),
                Authority::new(note::permissions::REPLACE_OWN_NOTE),
                Authority::new(note::permissions::READ_OWN_NOTE),
                Authority::new(note::permissions::DELETE_OWN_NOTE),
            ],
        ),
        UserDetail::new(
            "cantdelete",
            "cantdelete123",
            vec![
                Authority::new(note::permissions::CREATE_OWN_NOTE),
                Authority::new(note::permissions::REPLACE_OWN_NOTE),
                Authority::new(note::permissions::READ_OWN_NOTE),
            ],
        ),
        UserDetail::new(
            "reader",
            "reader123",
            vec![Authority::new(note::permissions::READ_ALL_NOTES)],
        ),
        UserDetail::new("groovy", "groovy123", vec![]),
    ];
    let provider = users::create_up_provider(3, users).await;

    let notes = vec![
        Note::new("Test note", "Hello world!", "alex"),
        Note::new("One more", "One more test note", "cantdelete"),
    ];
    let note_repo = NoteRepository::new(notes);
    let note_api_router = create_notes_router(note_repo);

    let session_layer = create_session_layer()?;
    let authorizer = Arc::new(create_authorizer());
    let security_layer = SecurityLayer::new(
        Arc::new(
            SessionRequestAuthenticator::new(SessionStoredIdentity::<UserDetail>::new())
                .with_session_key(AUTH_SESSION_KEY)
                .map(Principal::from),
        ),
        Arc::clone(&authorizer),
    );

    let browser_security_stack = ServiceBuilder::new()
        .layer(session_layer)
        .layer(security_layer);

    let router = auth::router(AUTH_SESSION_KEY, provider.clone())?;

    let api_authenticator = BasicRequestAuthenticator::new(provider).map(Principal::from);
    let api_security_stack =
        SecurityLayer::new_with_entry_point(Arc::new(api_authenticator), authorizer);

    let browser_matcher = BrowserRequestMatcher::new(session::SESSION_COOKIE);

    // Vite serves the initial HTML in development, so the first backend fetch
    // needs to enter the browser stack before a session cookie exists.
    #[cfg(debug_assertions)]
    let browser_matcher = http_request_matcher::OrRequestMatcher::new(
        browser_matcher,
        http_request_matcher::PathPatternRequestMatcher::new("/v1/ui/{*path}")?,
    );

    let filter_chain = SecurityChainLayer::builder()
        .chain(browser_matcher, browser_security_stack)
        .fallback(api_security_stack)
        .build()?;

    #[cfg(not(debug_assertions))]
    let router = router.merge(frontend::router()); // add frontend (/ui) routes only for release
    let router = router.merge(note_api_router);
    let router = router.layer(filter_chain);

    let listener = TcpListener::bind(BIND_ADDRESS).await?;
    serve(listener, router).await?;

    Ok(())
}

fn create_authorizer() -> RequestAuthorizationProvider<Principal> {
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
        .method_matchers(Method::POST, "/v1/notes/")
        .has_authority(note::permissions::CREATE_OWN_NOTE)
        .method_matchers(Method::PUT, "/v1/notes/{id}")
        .has_authority(note::permissions::REPLACE_OWN_NOTE)
        .method_matchers(Method::DELETE, "/v1/notes/{id}")
        .has_authority(note::permissions::DELETE_OWN_NOTE)
        .method_matchers(Method::GET, "/v1/notes/")
        .has_any_authority([
            note::permissions::READ_OWN_NOTE,
            note::permissions::READ_ALL_NOTES,
        ])
        .method_matchers(Method::GET, "/v1/notes/{id}")
        .has_any_authority([
            note::permissions::READ_OWN_NOTE,
            note::permissions::READ_ALL_NOTES,
        ])
        .any_request()
        .authenticated()
        .build()
        .expect("valid browser authorization rules")
}
