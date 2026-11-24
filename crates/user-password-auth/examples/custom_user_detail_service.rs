use argon2::Argon2;
use std::{num::NonZeroUsize, pin::Pin};
use tokio::runtime::Handle;
use user_password_auth::{
    AsyncPasswordHasher, AsyncPasswordVerifier, AsyncStringPasswordManager, Authority, Credentials,
    UserDetail, UserDetailAuthenticationProvider, UserDetailService, UserLoadingError,
    UsernamePasswordAuthenticationProvider,
};

#[tokio::main(flavor = "current_thread")]
async fn main() -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let hasher = create_password_hasher(1);
    let hashed_password = hasher.hash_password("alex123").await?;
    let custom_user_detail_service = SingleUserDetailService(UserDetail::new(
        "alex",
        hashed_password.as_str(),
        vec![Authority::new("Read")],
    ));

    let result = custom_user_detail_service.load_user_by_name("alex").await;
    match result {
        Ok(Some(user_detail)) => assert_eq!("alex", user_detail.username),
        _ => panic!("Wrong"),
    }

    let result = custom_user_detail_service.load_user_by_name("alex1").await;
    match result {
        Ok(None) => (),
        _ => panic!("Wrong"),
    }

    let provider = UserDetailAuthenticationProvider::new(hasher, custom_user_detail_service)
        .await
        .unwrap();

    let creds = Credentials::new("alex", "alex123");
    let result = provider.authenticate(&creds).await;
    match result {
        Ok(Some(user_detail)) => {
            assert_eq!(user_detail.username.as_str(), "alex");
            assert_eq!(user_detail.authorities.len(), 1);
        }
        _ => panic!("Wrong password or not exists"),
    }

    Ok(())
}

struct SingleUserDetailService(UserDetail);

impl UserDetailService for SingleUserDetailService {
    fn load_user_by_name<'a>(
        &'a self,
        username: &'a str,
    ) -> Pin<Box<dyn Future<Output = Result<Option<UserDetail>, UserLoadingError>> + Send + 'a>>
    {
        Box::pin(async move {
            let user_detail = &self.0;
            if user_detail.username.as_str() == username {
                Ok(Some(user_detail.clone()))
            } else {
                Ok(None)
            }
        })
    }
}

fn create_password_hasher(concurrency: usize) -> impl AsyncPasswordVerifier + AsyncPasswordHasher {
    let argon2 = Argon2::default();
    let handle = Handle::current();
    AsyncStringPasswordManager::new(handle, argon2, NonZeroUsize::new(concurrency).unwrap())
}
