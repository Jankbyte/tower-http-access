use argon2::Argon2;
use std::num::NonZeroUsize;
use tokio::runtime::Handle;
use user_password_auth::{
    AsyncPasswordHasher, AsyncPasswordVerifier, AsyncStringPasswordManager,
    InMemoryUserDetailService, UserDetail, UserDetailAuthenticationProvider, UserDetailService,
    UsernamePasswordAuthenticationProvider,
};

pub(crate) async fn create_up_provider(
    concurrency: usize,
    users: Vec<UserDetail>,
) -> impl UsernamePasswordAuthenticationProvider<Authentication = UserDetail> + Clone {
    let password_hasher = create_password_hasher(concurrency);
    let users_service = create_users_service(users, &password_hasher).await;
    UserDetailAuthenticationProvider::new(password_hasher, users_service)
        .await
        .unwrap()
}

fn create_password_hasher(
    concurrency: usize,
) -> impl AsyncPasswordVerifier + AsyncPasswordHasher + Clone {
    let argon2 = Argon2::default();
    let handle = Handle::current();
    AsyncStringPasswordManager::new(handle, argon2, NonZeroUsize::new(concurrency).unwrap())
}

async fn create_users_service<T: AsyncPasswordHasher>(
    users: Vec<UserDetail>,
    hasher: &T,
) -> impl UserDetailService + use<T> + Clone {
    InMemoryUserDetailService::new((hasher, users))
        .await
        .unwrap()
}
