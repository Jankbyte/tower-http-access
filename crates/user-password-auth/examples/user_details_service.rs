use argon2::Argon2;
use std::num::NonZeroUsize;
use tokio::runtime::Handle;
use user_password_auth::{
    AsyncPasswordHasher, AsyncPasswordVerifier, AsyncStringPasswordManager, Authority, Credentials,
    InMemoryUserDetailService, UserDetail, UserDetailAuthenticationProvider, UserDetailService,
    UsernamePasswordAuthenticationProvider,
};

#[tokio::main(flavor = "current_thread")]
async fn main() {
    let provider = create_up_provider().await;

    let creds = Credentials::new("wrong", "wrong");
    let result = provider.authenticate(&creds).await;
    assert!(result.is_ok());
    assert!(result.unwrap().is_none());

    let creds = Credentials::new("replacer", "kjwgfkwjdgkjg");
    let result = provider.authenticate(&creds).await;
    match result {
        Ok(Some(user_detail)) => {
            assert_eq!(user_detail.username.as_str(), "replacer");
            assert_eq!(user_detail.authorities.len(), 3);
        }
        _ => panic!("Wrong password or not exists"),
    }
}

async fn create_users_service<T: AsyncPasswordHasher>(
    hasher: &T,
) -> impl UserDetailService + use<T> {
    let users = vec![
        UserDetail::new("user1", "wdjhwdkjvh", vec![Authority::new("Read")]),
        UserDetail::new(
            "replacer",
            "kjwgfkwjdgkjg",
            vec![
                Authority::new("Read"),
                Authority::new("Write"),
                Authority::new("Update"),
            ],
        ),
    ];
    InMemoryUserDetailService::new((hasher, users))
        .await
        .unwrap()
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
