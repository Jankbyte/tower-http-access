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
pub struct DelegatingRequestAuthenticator<A> {
    authenticators: Vec<Arc<dyn RequestAuthenticator<Authentication = A>>>,
}

/// Builder of [`DelegatingRequestAuthenticator`].
pub struct DelegatingRequestAuthenticatorBuilder<A> {
    authenticators: Vec<Arc<dyn RequestAuthenticator<Authentication = A>>>,
}

impl<A> Clone for DelegatingRequestAuthenticator<A> {
    fn clone(&self) -> Self {
        Self {
            authenticators: self.authenticators.clone(),
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
        parts: &'a mut Parts,
    ) -> BoxFuture<'a, Result<AuthenticationAttempt<Self::Authentication>, AuthenticatorError>>
    {
        Box::pin(async move {
            for authenticator in &self.authenticators {
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
    /// Add authenticator to delegator.
    pub fn authenticator<T>(mut self, authenticator: T) -> Self
    where
        T: RequestAuthenticator<Authentication = A> + 'static,
    {
        self.authenticators.push(Arc::new(authenticator));
        self
    }

    /// Add authenticator to delegator.
    ///
    /// This method can be useful for situations when you need share target authenticator to
    /// multiple places.
    ///
    /// For example, if you want use that as autheticator and share that as entrypoint to authrorization service.
    pub fn shared_authenticator<T>(mut self, authenticator: Arc<T>) -> Self
    where
        T: RequestAuthenticator<Authentication = A> + 'static,
    {
        self.authenticators.push(authenticator);
        self
    }

    /// Build delegator.
    pub fn build(self) -> DelegatingRequestAuthenticator<A> {
        DelegatingRequestAuthenticator {
            authenticators: self.authenticators,
        }
    }
}

#[cfg(all(test, feature = "split_auth"))]
#[path = "delegator_tests.rs"]
mod tests;
