use std::{future::Future, num::NonZeroUsize, pin::Pin, sync::Arc};

use password_hash::{PasswordHasher, PasswordVerifier, phc::PasswordHash};
use tokio::runtime::Handle;
use tokio::sync::Semaphore;

type AsyncPasswordResult<T> = Result<T, AsyncPasswordError>;

/// Errors list that occurrs while using [`AsyncPasswordVerifier`] and [`AsyncPasswordHasher`].
#[derive(Debug, thiserror::Error)]
pub enum AsyncPasswordError {
    /// Error occurred when hashing password is failed.
    #[error("password hashing failed: {0}")]
    PasswordHash(#[from] password_hash::Error),
    /// Error occurred when join blocking task is failed.
    #[error("password hashing task failed: {0}")]
    Task(#[from] tokio::task::JoinError),
    /// Error occurred when semaphore is closed.
    #[error("password concurrency limiter closed: {0}")]
    ConcurrencyLimiter(#[from] tokio::sync::AcquireError),
}

/// The password hasher that should be used by compontents for encoding
/// password of user.
///
/// For verifying encoded password use [`AsyncPasswordVerifier`].
pub trait AsyncPasswordHasher: Send + Sync {
    fn hash_password<'a>(
        &'a self,
        password: &'a str,
    ) -> Pin<Box<dyn Future<Output = AsyncPasswordResult<String>> + Send + 'a>>;
}

/// Used by [`BasicRequestAuthenticator`] for verifing hashed password.
///
/// For enconding use [`AsyncPasswordHasher`].
///
/// [`BasicRequestAuthenticator`]: crate::BasicRequestAuthenticator
pub trait AsyncPasswordVerifier: Send + Sync {
    fn matches<'a>(
        &'a self,
        password: &'a str,
        password_hash: &'a str,
    ) -> Pin<Box<dyn Future<Output = AsyncPasswordResult<bool>> + Send + 'a>>;
}

/// The async implementation of password hasher/matcher.
///
/// Password hashing is intentionally expensive: Argon2 consumes CPU time and a configured amount
/// of memory to make password guessing costly. It is synchronous work and must not run directly on
/// a Tokio worker thread, where it would prevent unrelated async requests from making progress.
/// This manager uses [`tokio::runtime::Handle::spawn_blocking`] to run each operation on Tokio's
/// blocking pool while exposing an async API to the caller.
///
/// Starting every requested hash at once would still exhaust CPU or memory. The manager therefore
/// uses a semaphore to limit concurrent operations. Requests above the limit wait asynchronously
/// and do not occupy Tokio worker threads.
///
/// # Choosing the concurrency limit
///
/// Choose `max_concurrent` from both available CPU parallelism and the memory reserved for password
/// operations:
///
/// ```text
/// min(available CPU parallelism, password memory budget / memory used by one hash)
/// ```
///
/// The example configures Argon2id with 19 MiB of memory, two passes, and one lane. These are the
/// recommended defaults provided by the `argon2` crate. With a 128 MiB password-work budget, at
/// most six operations fit in memory; the CPU limit may reduce that further. The budget is not an
/// allocation made by this manager—it is an application limit that protects memory needed by the
/// rest of the process.
///
/// Benchmark hashing on production-class hardware and adjust the Argon2 parameters and memory
/// budget together. Increasing the semaphore limit improves throughput only until CPU or memory is
/// saturated; after that it increases latency and can destabilize the service.
///
/// This limit bounds work already admitted to password verification, but it is not protection from
/// unlimited login attempts. Apply rate limiting and request timeouts to the login endpoint because
/// requests waiting for a permit remain queued asynchronously.
///
/// # Example
///
/// ```no_run
/// # mod example {
/// use argon2::{Algorithm, Argon2, Params, Version};
/// use tower_http_access_basic::AsyncStringPasswordManager;
/// use std::{error::Error, num::NonZeroUsize, thread};
/// use tokio::runtime::Handle;
///
/// # fn build_password_manager()
/// #     -> Result<AsyncStringPasswordManager<Argon2<'static>>, Box<dyn Error>> {
/// const ARGON2_MEMORY_KIB: usize = 19 * 1024;
/// const PASSWORD_MEMORY_BUDGET_KIB: usize = 128 * 1024;
///
/// let params = Params::new(ARGON2_MEMORY_KIB as u32, 2, 1, None)?;
/// let argon2 = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);
/// let memory_limit = NonZeroUsize::new(PASSWORD_MEMORY_BUDGET_KIB / ARGON2_MEMORY_KIB)
///     .expect("password memory budget must fit one Argon2 operation");
/// let max_concurrent = thread::available_parallelism()?.min(memory_limit);
///
/// Ok(AsyncStringPasswordManager::new(
///     Handle::current(),
///     argon2,
///     max_concurrent,
/// ))
/// # }
/// # }
/// # fn main() {}
/// ```
#[derive(Clone)]
pub struct AsyncStringPasswordManager<H> {
    handle: Handle,
    hasher: H,
    semaphore: Arc<Semaphore>,
}

impl<H> AsyncStringPasswordManager<H> {
    /// Create new async password manager with runtime handler and maximum allowed threads per this value.
    pub fn new(handle: Handle, hasher: H, max_concurrent: NonZeroUsize) -> Self {
        Self {
            handle,
            hasher,
            semaphore: Arc::new(Semaphore::new(max_concurrent.get())),
        }
    }
}

/// The password manager that does not hash password. The `hash_password` just returns same password as accepter,
/// and `matches` just compare two raw passwords.
///
/// This implementation is not recommended production cases, and should be used
/// only for PoC, testing and benchmarks.
///
/// # Example
///
/// ```rust
/// use tower_http_access_basic::{
///     AsyncPasswordHasher,
///     PlainHashPasswordManager,
///     AsyncPasswordVerifier
/// };
///
/// # #[tokio::main(flavor = "current_thread")]
/// # async fn main() {
/// let hasher_and_matcher = PlainHashPasswordManager;
/// let hashed: String = hasher_and_matcher.hash_password("123").await.unwrap();
///
/// assert_eq!(hashed.as_str(), "123");
/// assert!(hasher_and_matcher.matches("123", hashed.as_str()).await.unwrap());
/// # }
/// ```
///
pub struct PlainHashPasswordManager;

impl AsyncPasswordHasher for PlainHashPasswordManager {
    fn hash_password<'a>(
        &'a self,
        password: &'a str,
    ) -> Pin<Box<dyn Future<Output = AsyncPasswordResult<String>> + Send + 'a>> {
        Box::pin(async move { Ok(password.to_owned()) })
    }
}

impl AsyncPasswordVerifier for PlainHashPasswordManager {
    fn matches<'a>(
        &'a self,
        password: &'a str,
        password_hash: &'a str,
    ) -> Pin<Box<dyn Future<Output = AsyncPasswordResult<bool>> + Send + 'a>> {
        Box::pin(async move { Ok(password == password_hash) })
    }
}

/// The implementation of hasher for [`password-hash`] library types.
///
/// [`password-hash`]: https://docs.rs/password-hash/latest/password_hash/
impl<H> AsyncPasswordHasher for AsyncStringPasswordManager<H>
where
    H: PasswordHasher<PasswordHash> + Clone + Send + Sync + 'static,
{
    fn hash_password<'a>(
        &'a self,
        password: &'a str,
    ) -> Pin<Box<dyn Future<Output = AsyncPasswordResult<String>> + Send + 'a>> {
        let hasher = self.hasher.clone();
        let handle = self.handle.clone();
        let semaphore = Arc::clone(&self.semaphore);
        let password = password.as_bytes().to_owned();

        Box::pin(async move {
            let permit = semaphore.acquire_owned().await?;
            handle
                .spawn_blocking(move || {
                    let _permit = permit;
                    PasswordHasher::hash_password(&hasher, &password)
                        .map(|hash: PasswordHash| hash.to_string())
                })
                .await?
                .map_err(Into::into)
        })
    }
}

/// The implementation of matcher for [`password-hash`] library types.
///
/// [`password-hash`]: https://docs.rs/password-hash/latest/password_hash/
impl<H> AsyncPasswordVerifier for AsyncStringPasswordManager<H>
where
    H: PasswordVerifier<PasswordHash> + Clone + Send + Sync + 'static,
{
    fn matches<'a>(
        &'a self,
        password: &'a str,
        password_hash: &'a str,
    ) -> Pin<Box<dyn Future<Output = AsyncPasswordResult<bool>> + Send + 'a>> {
        let hasher = self.hasher.clone();
        let handle = self.handle.clone();
        let semaphore = Arc::clone(&self.semaphore);
        let password = password.as_bytes().to_owned();
        let password_hash = password_hash.to_owned();

        Box::pin(async move {
            let permit = semaphore.acquire_owned().await?;
            handle
                .spawn_blocking(move || {
                    let _permit = permit;
                    let password_hash =
                        PasswordHash::new(&password_hash).map_err(password_hash::Error::from)?;
                    match PasswordVerifier::verify_password(&hasher, &password, &password_hash) {
                        Ok(()) => Ok(true),
                        Err(password_hash::Error::PasswordInvalid) => Ok(false),
                        Err(error) => Err(error),
                    }
                })
                .await?
                .map_err(Into::into)
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use argon2::{Algorithm, Argon2, Params, Version};

    #[tokio::test]
    async fn hashes_and_verifies_passwords() {
        let argon2 = Argon2::new(Algorithm::Argon2i, Version::V0x13, Params::default());
        let manager: AsyncStringPasswordManager<Argon2> = AsyncStringPasswordManager::new(
            Handle::current(),
            argon2,
            NonZeroUsize::new(1).unwrap(),
        );
        let hash = manager.hash_password("correct password").await.unwrap();

        assert!(hash.starts_with("$argon2i$"));
        assert!(manager.matches("correct password", &hash).await.unwrap());
        assert!(!manager.matches("wrong password", &hash).await.unwrap());
    }
}
