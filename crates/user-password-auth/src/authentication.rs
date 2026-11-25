use crate::Credentials;
use futures_util::future::BoxFuture;
use std::{error::Error, sync::Arc};

/// Authenticates decoded username/password credentials.
///
/// `Ok(Some(authentication))` means the credentials are valid, `Ok(None)` means they are invalid,
/// and `Err(error)` represents an internal backend failure.
pub trait UsernamePasswordAuthenticationProvider {
    /// Identity produced by successful authentication.
    type Authentication;
    /// Internal authentication backend error.
    type Error: Error;

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

#[cfg(test)]
mod tests {
    use super::*;
    use std::{fmt, rc::Rc};

    struct LocalIdentity(Rc<()>);
    #[derive(Debug)]
    struct LocalError(Rc<()>);
    impl fmt::Display for LocalError {
        fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
            write!(f, "local error ({})", Rc::strong_count(&self.0))
        }
    }
    impl Error for LocalError {}
    struct Provider(Rc<()>);
    impl UsernamePasswordAuthenticationProvider for Provider {
        type Authentication = LocalIdentity;
        type Error = LocalError;
        fn authenticate<'a>(
            &'a self,
            _: &'a Credentials,
        ) -> BoxFuture<'a, Result<Option<LocalIdentity>, LocalError>> {
            assert_eq!(Rc::strong_count(&self.0), 1);
            Box::pin(async { Ok(Some(LocalIdentity(Rc::new(())))) })
        }
    }
    #[tokio::test]
    async fn provider_accepts_non_clone_non_send_identity_and_local_error() {
        let identity = Provider(Rc::new(()))
            .authenticate(&Credentials::new("user", "password"))
            .await
            .unwrap()
            .unwrap();
        assert_eq!(Rc::strong_count(&identity.0), 1);
    }
}
