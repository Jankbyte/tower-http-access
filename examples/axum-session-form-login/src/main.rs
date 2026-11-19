use std::{error::Error as StdError, num::NonZeroUsize};
use tokio::{net::TcpListener, runtime::Handle};
use axum::{Router, routing::method_routing::get};
use user_password_auth::{
    AsyncPasswordHasher, AsyncPasswordVerifier, AsyncStringPasswordManager, Authority,
    InMemoryUserDetailService, UserDetail, UserDetailAuthenticationProvider, UserDetailService,
    UsernamePasswordAuthenticationProvider,
};
use argon2::Argon2;
use tower_http_access_session::tower_sessions::SessionRequestAuthenticator;

const BIND_ADDRESS: &str = "127.0.0.1:3000";

#[tokio::main(flavor = "current_thread")]
async fn main() -> Result<(), Box<dyn StdError + Send + Sync>> {
    let listener = TcpListener::bind(BIND_ADDRESS).await.unwrap();
    Ok(())
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
        "crab",
        "crab123",
        vec![Authority::new("demo")],
    )];
    InMemoryUserDetailService::new((hasher, users))
        .await
        .unwrap()
}
