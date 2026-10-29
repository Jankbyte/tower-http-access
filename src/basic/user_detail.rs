use super::AsyncPasswordHasher;
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
        Ok(InMemoryUserDetailService::with_shared_users(Arc::new(
            mapped_users,
        )))
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

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;
    use std::sync::Arc;

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
}
