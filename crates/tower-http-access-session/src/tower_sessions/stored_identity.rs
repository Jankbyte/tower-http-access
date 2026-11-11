use std::{convert::Infallible, marker::PhantomData};

use futures_util::future::BoxFuture;

use crate::tower_sessions::SessionIdentityProvider;

/// Uses an identity stored in the session without an additional backend lookup.
///
/// Both `Id` and `Identity` are `T`: the extracted value is returned unchanged.
/// With the default session extractor, `T` must implement `DeserializeOwned`;
/// writing the identity to the session requires `Serialize`. A custom extractor
/// can construct `T` without either serialization bound on this provider.
///
/// Account status and permissions remain as stored until the session is updated,
/// expires, or is invalidated. Use a database-backed [`SessionIdentityProvider`]
/// when authentication must check current account data on each request.
pub struct SessionStoredIdentity<T> {
    identity: PhantomData<fn() -> T>,
}

impl<T> SessionStoredIdentity<T> {
    pub const fn new() -> Self {
        Self {
            identity: PhantomData,
        }
    }
}

impl<T> Default for SessionStoredIdentity<T> {
    fn default() -> Self {
        Self::new()
    }
}

impl<T: Clone + Send + Sync + 'static> SessionIdentityProvider for SessionStoredIdentity<T> {
    type Id = T;
    type Identity = T;
    type Error = Infallible;

    fn load_identity<'a>(&'a self, identity: T) -> BoxFuture<'a, Result<Option<T>, Infallible>> {
        Box::pin(async move { Ok(Some(identity)) })
    }
}
