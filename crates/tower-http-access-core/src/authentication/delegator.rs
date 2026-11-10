//! Ordered authentication chains.

use super::{AuthenticationAttempt, AuthenticatorError, RequestAuthenticator};
use futures_util::future::BoxFuture;
use http::request::Parts;
use std::sync::Arc;

/// The implementation of [`RequestAuthenticator`], that accept another
/// authenticators and build ordered chain.
///
/// # Single authenticator per method
///
/// It recommends to keep one authenticator per required method, otherwise next authenticator will be
/// skipped after first failed.
///
/// For example, you *can* add multiple authenticators, that process basic-authentication. But other authenticators
/// in this chain will useless, except first, because first authenticator will return [`super::AuthenticationErrorReason::WrongCredentials`]
/// and that out of the chain.
///
/// Clones share the immutable chain without allocating or cloning individual
/// authenticator handles. The builder also accepts `Arc`-wrapped authenticators
/// through the blanket [`RequestAuthenticator`] implementation.
///
/// # Complexity
///
/// For a chain of `n` authenticators, authentication makes at most `n` sequential
/// attempts: O(n) chain traversal in the worst case, plus the work performed by each
/// attempted authenticator. Evaluation stops at the first identity or error.
/// Cloning a completed chain is O(1) and does not allocate. Building the chain takes
/// O(n) time and O(n) storage for its entries, excluding the authenticators' own data.
///
/// # Ordered authentication
///
/// Return [`AuthenticationAttempt::NotApplicable`] when a mechanism has no credentials
/// to inspect. The next authenticator is tried only in that case; an authenticated
/// identity or an error stops the chain. All authenticators produce the same identity type.
///
/// ```
/// use http::request::Parts;
/// use tower_http_access_core::authentication::{
///     AuthenticationAttempt, AuthenticationErrorReason, AuthenticatorError,
///     DelegatingRequestAuthenticator, RequestAuthenticator,
/// };
/// # #[tokio::main(flavor = "current_thread")]
/// # async fn main() {
///
/// // Demonstration credentials only. A real provider would validate the key
/// // against the application's credential store.
/// let api_key = |parts: &Parts| {
///     let result = match parts.headers.get("x-api-key") {
///         None => Ok(AuthenticationAttempt::<String>::NotApplicable),
///         Some(key) if key == "demo-key" => {
///             Ok(AuthenticationAttempt::Authenticated("alex".to_owned()))
///         }
///         Some(_) => Err(AuthenticatorError::new(
///             AuthenticationErrorReason::WrongCredentials,
///         )),
///     };
///     async move { result }
/// };
/// let fallback = |_: &Parts| async {
///     // Replace with another mechanism, such as session authentication.
///     Ok::<_, AuthenticatorError>(AuthenticationAttempt::<String>::NotApplicable)
/// };
///
/// let chain = DelegatingRequestAuthenticator::builder()
///     .authenticator(api_key)
///     .authenticator(fallback)
///     .build();
///
/// let (parts, _) = http::Request::builder()
///     .header("x-api-key", "demo-key")
///     .body(())
///     .unwrap()
///     .into_parts();
/// let result = chain.authenticate(&parts).await.unwrap();
/// assert!(matches!(result, AuthenticationAttempt::Authenticated(user) if user == "alex"));
/// # }
/// ```
///
/// # Shared authenticators
///
/// Pass an existing `Arc` directly to `.authenticator(...)`. The blanket implementation
/// forwards authentication to its inner value, including trait objects. The chain does
/// not add another `Arc` wrapper.
/// Cloning the completed chain shares its storage and does not clone its entries.
///
/// ```
/// use std::sync::Arc;
/// use http::request::Parts;
/// use tower_http_access_core::authentication::{
///     AuthenticationAttempt, AuthenticatorError, DelegatingRequestAuthenticator,
///     RequestAuthenticator,
/// };
///
/// let shared: Arc<dyn RequestAuthenticator<Authentication = String>> =
///     Arc::new(|_: &Parts| async {
///         Ok::<_, AuthenticatorError>(AuthenticationAttempt::<String>::NotApplicable)
///     });
/// let chain = DelegatingRequestAuthenticator::builder()
///     .authenticator(Arc::clone(&shared))
///     .build();
/// let another_chain = DelegatingRequestAuthenticator::builder()
///     .authenticator(shared)
///     .build();
/// let cloned_chain = chain.clone();
/// ```
pub struct DelegatingRequestAuthenticator<A> {
    authenticators: Arc<[Box<dyn RequestAuthenticator<Authentication = A>>]>,
}

/// Builder of [`DelegatingRequestAuthenticator`].
pub struct DelegatingRequestAuthenticatorBuilder<A> {
    authenticators: Vec<Box<dyn RequestAuthenticator<Authentication = A>>>,
}

impl<A> Clone for DelegatingRequestAuthenticator<A> {
    fn clone(&self) -> Self {
        Self {
            authenticators: Arc::clone(&self.authenticators),
        }
    }
}

impl<A> RequestAuthenticator for DelegatingRequestAuthenticator<A>
where
    A: Clone + Send + Sync + 'static,
{
    type Authentication = A;

    fn authenticate<'a>(
        &'a self,
        parts: &'a Parts,
    ) -> BoxFuture<'a, Result<AuthenticationAttempt<Self::Authentication>, AuthenticatorError>>
    {
        Box::pin(async move {
            for authenticator in self.authenticators.iter() {
                match authenticator.authenticate(parts).await? {
                    AuthenticationAttempt::NotApplicable => continue,
                    AuthenticationAttempt::Authenticated(value) => {
                        return Ok(AuthenticationAttempt::Authenticated(value));
                    }
                }
            }
            Ok(AuthenticationAttempt::NotApplicable)
        })
    }
}

impl DelegatingRequestAuthenticator<()> {
    pub fn builder<A>() -> DelegatingRequestAuthenticatorBuilder<A> {
        DelegatingRequestAuthenticatorBuilder {
            authenticators: Vec::new(),
        }
    }
}

impl<A: Clone + Send + Sync + 'static> DelegatingRequestAuthenticatorBuilder<A> {
    /// Add an owned or `Arc`-wrapped authenticator without adding an `Arc` wrapper.
    pub fn authenticator<T>(mut self, authenticator: T) -> Self
    where
        T: RequestAuthenticator<Authentication = A> + 'static,
    {
        self.authenticators.push(Box::new(authenticator));
        self
    }

    /// Build delegator.
    pub fn build(self) -> DelegatingRequestAuthenticator<A> {
        DelegatingRequestAuthenticator {
            authenticators: self.authenticators.into(),
        }
    }
}

#[cfg(all(test, feature = "split_auth"))]
#[path = "delegator_tests.rs"]
mod tests;
