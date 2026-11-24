use argon2::Argon2;
use std::num::NonZeroUsize;
use tokio::runtime::Handle;
use user_password_auth::{AsyncPasswordHasher, AsyncPasswordVerifier, AsyncStringPasswordManager};

#[tokio::main(flavor = "current_thread")]
async fn main() -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let argon2 = Argon2::default();
    let handle = Handle::current();
    let hasher_verifier =
        AsyncStringPasswordManager::new(handle, argon2, NonZeroUsize::new(1).unwrap());

    let hash = hasher_verifier.hash_password("alex123").await?;
    let result = hasher_verifier.matches("alex123", &hash).await;

    match result {
        Ok(is_valid) => assert!(is_valid),
        _ => panic!("Wrong password"),
    }

    let result = hasher_verifier.matches("wrong", &hash).await;

    match result {
        Ok(is_valid) => assert!(!is_valid),
        _ => panic!("Something wrong"),
    }

    Ok(())
}
