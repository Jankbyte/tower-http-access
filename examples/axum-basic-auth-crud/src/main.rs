mod note;

use argon2::Argon2;
use axum::{Router, body::Body, serve};
use http::Request;
use note::{NOTES_API_BASE_PATH, Note, NoteRepository, create_notes_router};
use std::{
    sync::Arc,
    num::NonZeroUsize
};
use tokio::{net::TcpListener, runtime::Handle};
use tower_http::{
    request_id::{MakeRequestUuid, PropagateRequestIdLayer, RequestId, SetRequestIdLayer},
    trace::TraceLayer,
};
use tower_http_access_basic::BasicRequestAuthenticator;
use tower_http_access_core::{
    SecurityLayer, authentication::RequestAuthenticator,
    authorization::core::AuthenticationEntryPoint,
};
use user_password_auth::{
    AsyncPasswordHasher, AsyncPasswordVerifier, AsyncStringPasswordManager, Authority,
    InMemoryUserDetailService, UserDetail, UserDetailAuthenticationProvider, UserDetailService,
    UsernamePasswordAuthenticationProvider,
};

const BIND_ADDRESS: &str = "127.0.0.1:3000";

#[tokio::main(flavor = "current_thread")]
async fn main() -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let request_auth = create_basic_authenticator().await;

    let security =
        SecurityLayer::authenticated(request_auth.clone()).authentication_entry_point(request_auth);

    let notes_repo = NoteRepository::new(vec![
        Note::new(
            "The Rust Programming Language",
            "Welcome to The Rust Programming Language, an introductory book about Rust...",
        ),
        Note::new(
            "The Rustonomicon",
            "The Rustonomicon digs into all the awful details that you need to understand when writing Unsafe Rust programs...",
        ),
    ]);

    let notes_router = create_notes_router(notes_repo);

    tracing_subscriber::fmt()
        .with_max_level(tracing::Level::TRACE)
        .init();

    let app_router = Router::new()
        .nest(NOTES_API_BASE_PATH, notes_router)
        .layer(security);

    let app_router = apply_logging_layers(app_router);

    tracing::info!(address = %BIND_ADDRESS, "hosting server at");
    let listener = TcpListener::bind(BIND_ADDRESS).await.unwrap();
    serve(listener, app_router).await?;

    Ok(())
}

fn apply_logging_layers(router: Router) -> Router {
    router
        .layer(PropagateRequestIdLayer::x_request_id())
        .layer(
            TraceLayer::new_for_http().make_span_with(|request: &Request<Body>| {
                let request_id = request
                    .extensions()
                    .get::<RequestId>()
                    .and_then(|id| id.header_value().to_str().ok())
                    .unwrap_or("unknown");
                tracing::info_span!(
                    "request",
                    request_id = %request_id,
                    method = %request.method(),
                    path = %request.uri().path(),
                )
            }),
        )
        // The SetRequestIdLayer must be first in chain for observing request
        .layer(SetRequestIdLayer::x_request_id(MakeRequestUuid))
}

async fn create_basic_authenticator()
-> impl RequestAuthenticator<Authentication = UserDetail> + AuthenticationEntryPoint + Clone {
    let provider = create_up_provider().await;
    Arc::new(BasicRequestAuthenticator::new(provider))
}

async fn create_up_provider()
-> impl UsernamePasswordAuthenticationProvider<Authentication = UserDetail> {
    let password_hasher = create_password_hasher(5);
    let users_service = create_users_service(&password_hasher).await;
    UserDetailAuthenticationProvider::new(password_hasher, users_service)
        .await
        .unwrap()
}

fn create_password_hasher(concurrency: usize) -> impl AsyncPasswordVerifier + AsyncPasswordHasher {
    let argon2 = Argon2::default();
    let handle = Handle::current();
    AsyncStringPasswordManager::new(handle, argon2, NonZeroUsize::new(concurrency).unwrap())
}

async fn create_users_service<T: AsyncPasswordHasher>(
    hasher: &T,
) -> impl UserDetailService + use<T> {
    let users = vec![UserDetail::new(
        "alex",
        "alex123",
        vec![Authority::new("test"), Authority::new("test1")],
    )];
    InMemoryUserDetailService::new((hasher, users))
        .await
        .unwrap()
}
