use crate::Credentials;
use futures_util::future::BoxFuture;
use std::{error::Error, sync::Arc};

/// Authenticates decoded username/password credentials.
///
/// `Ok(Some(authentication))` means the credentials are valid, `Ok(None)` means they are invalid,
/// and `Err(error)` represents an internal backend failure.
pub trait UsernamePasswordAuthenticationProvider: Send + Sync {
    /// Identity produced by successful authentication.
    type Authentication: Clone + Send + Sync + 'static;
    /// Internal authentication backend error.
    type Error: Error + Send + Sync + 'static;

    fn authenticate<'a>(
        &'a self,
        credentials: &'a Credentials,
    ) -> BoxFuture<'a, Result<Option<Self::Authentication>, Self::Error>>;
}

/// Implementation for using with values that does not implement `Clone` or it's not cheap.
impl<T> UsernamePasswordAuthenticationProvider for Arc<T>
where
    T: UsernamePasswordAuthenticationProvider + ?Sized,
{
    /// Identity produced by successful authentication.
    type Authentication = T::Authentication;
    /// Internal authentication backend error.
    type Error = T::Error;

    fn authenticate<'a>(
        &'a self,
        credentials: &'a Credentials,
    ) -> BoxFuture<'a, Result<Option<Self::Authentication>, Self::Error>> {
        T::authenticate(self.as_ref(), credentials)
    }
}
