//! Run with
//!
//! ```not_rust
//! cargo run --example axum_basic_auth --features basic_auth,argon2_encoder
//! # if you care about perfomance
//! cargo run --example axum_basic_auth --features basic_auth,argon2_encoder --release
//! # testing with
//! curl http://localhost:3000/public
//! curl -vu alex:alex123 http://localhost:3000/protected
//! # or with oha
//! oha -z 20s -c 50 -t 300ms --connect-timeout 2s -H 'Authorization: Basic YWxleDphbGV4MTIz' 'http://127.0.0.1:3000/protected'
//! ```

use argon2::{Algorithm, Argon2, Params, Version};
use axum::{Router, response::Html, routing::get};
use axum_auth_chained::{
    SecurityLayerBuilder,
    authentication::{Authenticated, RequestAuthenticatorExt},
    authorization::{AuthenticatedAuthorizationProvider, empty_context_mapper},
    basic::{
        AsyncStringPasswordManager, BasicRequestAuthenticator, InMemoryUserDetailService,
        UserDetail, UserDetailAuthenticationProvider,
    },
};
use std::{num::NonZeroUsize, sync::Arc, thread};
use tokio::runtime::Handle;

#[tokio::main(flavor = "current_thread")]
async fn main() {
    let basic_authenticator = Arc::new(
        create_basic_authenticator()
            .await
            .map(AuthenticatedSession::from),
    );
    let security_layer = SecurityLayerBuilder::builder()
        .authenticators(|authenticators| {
            authenticators.shared_authenticator(Arc::clone(&basic_authenticator))
        })
        .authorization(|authorization| {
            authorization
                .authorize_with(
                    AuthenticatedAuthorizationProvider::<AuthenticatedSession>::new(),
                    empty_context_mapper,
                )
                .authentication_entry_point(basic_authenticator)
        })
        .build();

    let app = Router::new()
        .route("/public", get(handler))
        .route("/protected", get(handler).layer(security_layer));

    let listener = tokio::net::TcpListener::bind("127.0.0.1:3000")
        .await
        .unwrap();
    println!("listening on {}", listener.local_addr().unwrap());
    let _ = axum::serve(listener, app).await;
}

#[derive(Clone)]
struct AuthenticatedSession(String);

impl From<UserDetail> for AuthenticatedSession {
    fn from(user_detail: UserDetail) -> Self {
        Self(user_detail.username)
    }
}

async fn handler(authentication: Option<Authenticated<AuthenticatedSession>>) -> Html<String> {
    let username = authentication
        .map(|Authenticated(authentication)| authentication.0)
        .unwrap_or_else(|| "anonymous".to_owned());

    Html(format!("<h1>Hello, {username}</h1>"))
}

async fn create_basic_authenticator<'a>() -> BasicRequestAuthenticator<
    UserDetailAuthenticationProvider<
        AsyncStringPasswordManager<Argon2<'a>>,
        InMemoryUserDetailService,
    >,
> {
    const ARGON2_MEMORY_KIB: usize = 19 * 1024;
    const PASSWORD_MEMORY_BUDGET_KIB: usize = 128 * 1024;

    let params =
        Params::new(ARGON2_MEMORY_KIB as u32, 2, 1, None).expect("Argon2 parameters must be valid");
    let argon2 = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);
    let memory_limit = NonZeroUsize::new(PASSWORD_MEMORY_BUDGET_KIB / ARGON2_MEMORY_KIB)
        .expect("password memory budget must fit one Argon2 operation");
    let max_concurrent = thread::available_parallelism()
        .expect("available CPU parallelism must be detectable")
        .min(memory_limit);
    println!(
        "Concurrent threads for AsyncStringPasswordManager: {}",
        max_concurrent
    );
    let manager: AsyncStringPasswordManager<Argon2> =
        AsyncStringPasswordManager::new(Handle::current(), argon2, max_concurrent);
    let raw_users = vec![
        UserDetail::new("alex", "alex123"),
        UserDetail::new("max", "max123"),
    ];
    let user_detail_service = InMemoryUserDetailService::new((&manager, raw_users))
        .await
        .unwrap();
    let provider = UserDetailAuthenticationProvider::new(manager, user_detail_service)
        .await
        .unwrap();

    BasicRequestAuthenticator::new(provider)
}
