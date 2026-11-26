use ::tower_sessions::Session;
use futures_util::future::BoxFuture;
use http::request::Parts;
use serde::de::DeserializeOwned;
use std::{error::Error, future::Future};
use tower_http_access_core::authentication::{
    AuthenticationAttempt, AuthenticatorError, RequestAuthenticator,
};

type SessionIdExtractor<Id> = dyn Fn(Session) -> BoxFuture<'static, Result<Option<Id>, tower_sessions::session::Error>>
    + Send
    + Sync;

/// Loads a current identity from the identifier stored in a server-side session.
///
/// This provider is separate from the `tower-sessions` storage backend. The session
/// backend retrieves session data, such as `user_id`; this provider uses that
/// identifier to retrieve the application's user and current permissions. It can
/// query another database or an external identity service, independently of where
/// sessions are stored. For example, sessions can be stored in Redis while users
/// and roles are loaded from PostgreSQL.
///
/// Store a shared database connection pool or service client in the implementation
/// and use it in [`load_identity`](Self::load_identity). The authenticator calls
/// this method on every request for which the extractor returns an identifier,
/// including requests that authorization may allow anonymously. Loading current
/// account data allows role changes and disabled accounts to take effect without
/// rewriting the session. If the provider caches identities, cache freshness
/// determines how soon those changes are observed.
///
/// Return `None` for deleted or disabled users. Backend failures must return an error.
/// To use a complete identity already stored in the session without another lookup,
/// use [`SessionStoredIdentity`](crate::tower_sessions::SessionStoredIdentity).
pub trait SessionIdentityProvider: Send + Sync {
    type Id;
    type Identity;
    type Error: Error;

    /// Look up the current identity using an identifier extracted from the session.
    ///
    /// Return `Ok(Some(identity))` for an active user, `Ok(None)` for an unknown
    /// or disabled user, and `Err` for database or service failures. Errors become
    /// internal authentication errors rather than anonymous access.
    fn load_identity<'a>(
        &'a self,
        id: Self::Id,
    ) -> BoxFuture<'a, Result<Option<Self::Identity>, Self::Error>>;
}

/// Authenticates using a session identifier and an application identity provider.
///
/// The session middleware must run first. A missing session extension is an internal
/// configuration error; an empty session or unknown identity is not applicable.
/// Session decoding, storage, and identity-provider errors produce internal errors.
pub struct SessionRequestAuthenticator<P: SessionIdentityProvider> {
    provider: P,
    extract_id: Box<SessionIdExtractor<P::Id>>,
}

impl<P: SessionIdentityProvider> SessionRequestAuthenticator<P> {
    /// Read the user identifier from `user_id` in the session.
    pub fn new(provider: P) -> Self
    where
        P::Id: DeserializeOwned,
    {
        Self::new_with_extractor(provider, |session| async move {
            session.get::<P::Id>("user_id").await
        })
    }

    /// Extract the identifier using an application-defined async function.
    ///
    /// The extractor receives a cloned session handle. Return `Ok(None)` when
    /// no identifier is present; extraction errors produce internal errors.
    /// Unlike the default extractor, this does not require a deserializable ID.
    pub fn new_with_extractor<F, Fut>(provider: P, extract_id: F) -> Self
    where
        F: Fn(Session) -> Fut + Send + Sync + 'static,
        Fut:
            Future<Output = Result<Option<P::Id>, tower_sessions::session::Error>> + Send + 'static,
    {
        Self {
            provider,
            extract_id: Box::new(move |session| Box::pin(extract_id(session))),
        }
    }

    /// Replace the extractor with `Session::get` using the specified key.
    pub fn with_session_key(mut self, key: impl Into<String>) -> Self
    where
        P::Id: DeserializeOwned,
    {
        let key = key.into();
        self.extract_id = Box::new(move |session| {
            let key = key.clone();
            Box::pin(async move { session.get::<P::Id>(&key).await })
        });
        self
    }
}

fn internal(error: impl Error + Send + Sync + 'static) -> AuthenticatorError {
    AuthenticatorError::internal(error)
}

impl<P: SessionIdentityProvider> RequestAuthenticator for SessionRequestAuthenticator<P>
where
    P::Error: Send + Sync + 'static,
{
    type Authentication = P::Identity;

    fn authenticate<'a>(
        &'a self,
        parts: &'a Parts,
    ) -> BoxFuture<'a, Result<AuthenticationAttempt<Self::Authentication>, AuthenticatorError>>
    {
        Box::pin(async move {
            let session =
                parts
                    .extensions
                    .get::<Session>()
                    .ok_or(internal(std::io::Error::other(
                        "session middleware must run before authentication",
                    )))?;
            let Some(id) = (self.extract_id)(session.clone()).await.map_err(internal)? else {
                #[cfg(feature = "tracing")]
                tracing::trace!("session key is empty, skip authentication");
                return Ok(AuthenticationAttempt::NotApplicable);
            };
            Ok(
                match self.provider.load_identity(id).await.map_err(internal)? {
                    Some(identity) => {
                        #[cfg(feature = "tracing")]
                        tracing::trace!("session authenticated");
                        AuthenticationAttempt::Authenticated(identity)
                    }
                    None => {
                        #[cfg(feature = "tracing")]
                        tracing::trace!("session is not authenticated");
                        AuthenticationAttempt::NotApplicable
                    }
                },
            )
        })
    }
}

#[cfg(test)]
#[path = "tests.rs"]
mod tests;

#[cfg(test)]
mod relaxed_bounds_tests {
    use super::*;
    use std::{fmt, rc::Rc};

    struct Provider;
    struct Identity(Rc<()>);
    #[derive(Debug)]
    struct LocalError(Rc<()>);
    impl fmt::Display for LocalError {
        fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
            write!(f, "local error ({})", Rc::strong_count(&self.0))
        }
    }
    impl Error for LocalError {}
    impl SessionIdentityProvider for Provider {
        type Id = Rc<()>;
        type Identity = Identity;
        type Error = LocalError;
        fn load_identity<'a>(
            &'a self,
            id: Rc<()>,
        ) -> BoxFuture<'a, Result<Option<Identity>, LocalError>> {
            let exists = Rc::strong_count(&id) > 0;
            Box::pin(async move {
                if exists {
                    Ok(Some(Identity(Rc::new(()))))
                } else {
                    Err(LocalError(Rc::new(())))
                }
            })
        }
    }
    #[tokio::test]
    async fn provider_accepts_local_ids_identities_and_errors() {
        let identity = Provider.load_identity(Rc::new(())).await.unwrap().unwrap();
        assert_eq!(Rc::strong_count(&identity.0), 1);
    }
}
