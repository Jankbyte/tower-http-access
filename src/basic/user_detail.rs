use super::{
    AsyncPasswordError, AsyncPasswordHasher, AsyncPasswordVerifier, BasicCredentials,
    UsernamePasswordAuthenticationFuture, UsernamePasswordAuthenticationProvider,
};
use std::collections::HashMap;
use std::error::Error as StdError;
use std::pin::Pin;
use std::sync::Arc;

/// The base representation of authenticated user, used by [`BasicRequestAuthenticator`].
///
/// [`BasicRequestAuthenticator`]: crate::basic::BasicRequestAuthenticator
#[derive(Clone, Debug)]
pub struct UserDetail {
    /// Unique name of user.
    pub username: String,
    /// Hashed password by some algorithm (see [`AsyncPasswordHasher`])
    ///
    /// [`AsyncPasswordHasher`]: crate::basic::AsyncPasswordHasher
    pub hashed_password: String,
}

impl UserDetail {
    /// Create new user detail with username and hashed password.
    ///
    /// Password must be hashed with [`AsyncPasswordHasher`].
    pub fn new(username: &str, hashed_password: &str) -> Self {
        Self {
            username: username.to_owned(),
            hashed_password: hashed_password.to_owned(),
        }
    }
}

/// Error occurred while loading users from source.
#[derive(Debug, thiserror::Error)]
pub enum UserLoadingError {
    #[error("error while load user: {0}")]
    Storage(Box<dyn StdError + Send + Sync>),
}

/// The extractor of user detail from specific source.
///
/// It may contain users in any source: database, in memory, text file and e.g.
pub trait UserDetailService: Send + Sync {
    fn load_user_by_name<'a>(
        &'a self,
        username: &'a str,
    ) -> Pin<Box<dyn Future<Output = Result<Option<UserDetail>, UserLoadingError>> + Send + 'a>>;
}

/// Store users in inmemory (RAM) storage.
///
/// This is base implementation of [`UserDetailService`], that can be used with static-configured users.
/// # Example
///
/// ```rust
/// use argon2::Argon2;
/// use axum_auth_chained::basic::{AsyncStringPasswordManager, InMemoryUserDetailService, UserDetail};
/// use std::num::NonZeroUsize;
/// use tokio::runtime::Handle;
///
/// # #[tokio::main(flavor = "current_thread")]
/// # async fn main() {
/// let manager: AsyncStringPasswordManager<Argon2> =
///     AsyncStringPasswordManager::new(Handle::current(), Argon2::default(), NonZeroUsize::new(2).unwrap());
///
/// // Do not encrypt passwords on this phase
/// let raw_users = vec![
///     UserDetail::new("alex", "alex123"),
///     UserDetail::new("max", "max123"),
/// ];
///
/// let user_detail_service = InMemoryUserDetailService::new((&manager, raw_users))
///     .await
///     .unwrap();
/// # }
/// ```
///
#[derive(Clone)]
#[must_use]
pub struct InMemoryUserDetailService {
    users: Arc<HashMap<String, UserDetail>>,
}

impl InMemoryUserDetailService {
    /// Create service with shared (can be used in other parts of application) readonly-users.
    ///
    /// If you use this method, you must manually use [`AsyncPasswordHasher`] for hashing passwords.
    pub fn with_shared_users(users: Arc<HashMap<String, UserDetail>>) -> Self {
        Self { users }
    }

    /// Create new user-service, where users passwords was encrypted with [`AsyncPasswordHasher`] internally.
    pub async fn new<E: AsyncPasswordHasher>(
        (hasher, users): (&E, Vec<UserDetail>),
    ) -> Result<Self, Box<dyn StdError + Send + Sync>> {
        let mut mapped_users = HashMap::new();
        for mut user in users {
            let encoded = hasher
                .hash_password(&user.hashed_password)
                .await
                .map_err(Box::new)?;
            user.hashed_password = encoded;
            mapped_users.insert(user.username.clone(), user);
        }
        Ok(Self::with_shared_users(Arc::new(mapped_users)))
    }
}

impl UserDetailService for InMemoryUserDetailService {
    fn load_user_by_name<'a>(
        &'a self,
        username: &'a str,
    ) -> Pin<Box<dyn Future<Output = Result<Option<UserDetail>, UserLoadingError>> + Send + 'a>>
    {
        Box::pin(async {
            let maybe_user_detail: Option<UserDetail> = self.users.get(username).cloned();
            Ok(maybe_user_detail)
        })
    }
}

/// Errors produced while authenticating a user loaded from a [`UserDetailService`].
#[derive(Debug, thiserror::Error)]
pub enum UserDetailAuthenticationError {
    /// Loading the user failed.
    #[error("failed to load user: {0}")]
    UserLoading(#[from] UserLoadingError),
    /// Password verification failed internally.
    #[error("failed to verify password: {0}")]
    Password(#[from] AsyncPasswordError),
}

/// Authenticates users loaded from a [`UserDetailService`] using stored password hashes.
///
/// Construction creates a dummy password hash. Missing users are verified against that hash so an
/// unknown username performs the same expensive password operation as a known username with a
/// wrong password.
#[derive(Clone)]
pub struct UserDetailAuthenticationProvider<V, U> {
    password_verifier: V,
    user_detail_service: U,
    dummy_password_hash: String,
}

impl<V, U> UserDetailAuthenticationProvider<V, U>
where
    V: AsyncPasswordHasher,
{
    /// Create a provider and prepare the dummy hash used for missing users.
    pub async fn new(
        password_verifier: V,
        user_detail_service: U,
    ) -> Result<Self, AsyncPasswordError> {
        let dummy_password_hash = password_verifier.hash_password("invalid password").await?;

        Ok(Self {
            password_verifier,
            user_detail_service,
            dummy_password_hash,
        })
    }
}

impl<V, U> UsernamePasswordAuthenticationProvider for UserDetailAuthenticationProvider<V, U>
where
    V: AsyncPasswordVerifier,
    U: UserDetailService,
{
    type Authentication = UserDetail;
    type Error = UserDetailAuthenticationError;

    fn authenticate<'a>(
        &'a self,
        credentials: &'a BasicCredentials,
    ) -> UsernamePasswordAuthenticationFuture<'a, Self::Authentication, Self::Error> {
        Box::pin(async move {
            let user = self
                .user_detail_service
                .load_user_by_name(&credentials.username)
                .await?;
            let password_hash = user
                .as_ref()
                .map(|user| user.hashed_password.as_str())
                .unwrap_or(&self.dummy_password_hash);
            let matches = self
                .password_verifier
                .matches(&credentials.password, password_hash)
                .await?;

            Ok(if matches { user } else { None })
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;
    use std::sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    };

    #[derive(Clone)]
    struct CountingPasswordManager {
        verifications: Arc<AtomicUsize>,
    }

    impl AsyncPasswordHasher for CountingPasswordManager {
        fn hash_password<'a>(
            &'a self,
            password: &'a str,
        ) -> Pin<Box<dyn Future<Output = Result<String, AsyncPasswordError>> + Send + 'a>> {
            Box::pin(async move { Ok(password.to_owned()) })
        }
    }

    impl AsyncPasswordVerifier for CountingPasswordManager {
        fn matches<'a>(
            &'a self,
            password: &'a str,
            password_hash: &'a str,
        ) -> Pin<Box<dyn Future<Output = Result<bool, AsyncPasswordError>> + Send + 'a>> {
            self.verifications.fetch_add(1, Ordering::Relaxed);
            Box::pin(async move { Ok(password == password_hash) })
        }
    }

    #[tokio::test]
    async fn in_memory_uds_retrive_existing_user() {
        let mut users = HashMap::new();

        let username = "alex";

        let user_detail = UserDetail {
            username: username.to_owned(),
            hashed_password: "alex123".to_owned(),
        };

        users.insert(username.to_owned(), user_detail);

        let user_detail_service = InMemoryUserDetailService::with_shared_users(Arc::new(users));
        let user_detail = user_detail_service
            .load_user_by_name(username)
            .await
            .expect("Not errors while load user")
            .expect("User exists");

        assert_eq!(user_detail.username.as_str(), username);
    }

    #[test]
    fn in_memory_uds_is_dyn_compatible() {
        let user_detail_service =
            InMemoryUserDetailService::with_shared_users(Arc::new(HashMap::new()));

        // NOTE: just check, UserDetailService trait still dyn compatible.
        let _: Box<dyn UserDetailService> = Box::new(user_detail_service);
    }

    #[tokio::test]
    async fn missing_user_is_verified_against_dummy_password_hash() {
        let verifications = Arc::new(AtomicUsize::new(0));
        let password_manager = CountingPasswordManager {
            verifications: Arc::clone(&verifications),
        };
        let users = InMemoryUserDetailService::with_shared_users(Arc::new(HashMap::new()));
        let provider = UserDetailAuthenticationProvider::new(password_manager, users)
            .await
            .unwrap();
        let credentials = BasicCredentials {
            username: "missing".to_owned(),
            password: "wrong".to_owned(),
        };

        let authentication = provider.authenticate(&credentials).await.unwrap();

        assert!(authentication.is_none());
        assert_eq!(verifications.load(Ordering::Relaxed), 1);
    }
}
