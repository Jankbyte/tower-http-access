use futures_util::future::BoxFuture;
use http::{HeaderValue, StatusCode, Uri, header, request::Parts};
use serde::de::DeserializeOwned;
use std::error::Error;
use tower_http_access::authentication::{
    AuthenticationAttempt, AuthenticationErrorReason, AuthenticatorError, RequestAuthenticator,
};
use tower_http_access::{SecurityResponse, authorization::AuthenticationEntryPoint};
use tower_sessions::Session;

/// Initializes an anonymous session without establishing an authenticated identity.
///
/// Call before the inner handler, after `SessionManagerLayer` has installed the
/// session. A reserved marker makes a new session nonempty; the session manager
/// then saves it and sets its cookie on eligible responses. Sessions already carrying the marker are
/// not modified. This does not eagerly allocate an ID or save the session itself.
/// Calling before the handler also allows logout to flush the session normally.
pub async fn initialize_session(session: &Session) -> Result<(), tower_sessions::session::Error> {
    const KEY: &str = "tower_http_access_session.initialized";
    if session.get::<bool>(KEY).await?.is_none() {
        session.insert(KEY, true).await?;
    }
    Ok(())
}

/// Loads a current identity from the identifier stored in a server-side session.
/// Return `None` for deleted or disabled users. Backend failures must return an error.
pub trait SessionIdentityProvider: Send + Sync {
    type Id: DeserializeOwned + Send;
    type Identity: Clone + Send + Sync + 'static;
    type Error: Error + Send + Sync + 'static;

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
pub struct SessionRequestAuthenticator<P> {
    provider: P,
    key: String,
    login_page: HeaderValue,
}

impl<P> SessionRequestAuthenticator<P> {
    /// Read the user identifier from `user_id` in the session.
    pub fn new(provider: P) -> Self {
        Self {
            provider,
            key: "user_id".into(),
            login_page: HeaderValue::from_static("/login"),
        }
    }

    /// Configure a same-origin absolute login path, such as `/account/login`.
    /// Defaults to `/login`. Relative paths, external URLs, and network-path URLs
    /// are rejected. Query strings are allowed.
    ///
    /// Share this authenticator with `SecurityLayer::authentication_entry_point`
    /// to issue a 302 redirect when authorization requires authentication. Keep
    /// the login endpoint accessible to anonymous users to avoid redirect loops.
    pub fn login_page_path(mut self, path: impl AsRef<str>) -> Result<Self, InvalidLoginPagePath> {
        let path = path.as_ref();
        let uri = path.parse::<Uri>().map_err(|_| InvalidLoginPagePath)?;
        if !path.starts_with('/')
            || path.starts_with("//")
            || path.contains('\\')
            || path.contains('#')
            || uri.scheme().is_some()
            || uri.authority().is_some()
        {
            return Err(InvalidLoginPagePath);
        }
        self.login_page = HeaderValue::from_str(path).map_err(|_| InvalidLoginPagePath)?;
        Ok(self)
    }

    /// Select the session key containing the user identifier.
    pub fn with_session_key(mut self, key: impl Into<String>) -> Self {
        self.key = key.into();
        self
    }
}

/// The configured login location must be a valid same-origin absolute path.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct InvalidLoginPagePath;

impl std::fmt::Display for InvalidLoginPagePath {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("login page must be a same-origin absolute path")
    }
}
impl Error for InvalidLoginPagePath {}

impl<P: Send + Sync + 'static> AuthenticationEntryPoint for SessionRequestAuthenticator<P> {
    fn commence(&self, _: &Parts) -> SecurityResponse {
        let mut response = SecurityResponse::new(Default::default());
        *response.status_mut() = StatusCode::FOUND;
        response
            .headers_mut()
            .insert(header::LOCATION, self.login_page.clone());
        response
    }
}

fn internal(error: impl Error + Send + Sync + 'static) -> AuthenticatorError {
    AuthenticatorError::new(AuthenticationErrorReason::Internal(Box::new(error)))
}

impl<P: SessionIdentityProvider> RequestAuthenticator for SessionRequestAuthenticator<P> {
    type Authentication = P::Identity;

    fn authenticate<'a>(
        &'a self,
        parts: &'a mut Parts,
    ) -> BoxFuture<'a, Result<AuthenticationAttempt<Self::Authentication>, AuthenticatorError>>
    {
        Box::pin(async move {
            let session = parts.extensions.get::<Session>().ok_or_else(|| {
                internal(std::io::Error::other(
                    "session middleware must run before authentication",
                ))
            })?;
            let Some(id) = session.get::<P::Id>(&self.key).await.map_err(internal)? else {
                return Ok(AuthenticationAttempt::NotApplicable);
            };
            Ok(
                match self.provider.load_identity(id).await.map_err(internal)? {
                    Some(identity) => AuthenticationAttempt::Authenticated(identity),
                    None => AuthenticationAttempt::NotApplicable,
                },
            )
        })
    }
}

#[cfg(test)]
#[path = "tests.rs"]
mod tests;
