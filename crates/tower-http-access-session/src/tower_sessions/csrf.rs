//! CSRF repositories for HTML forms and JavaScript applications.
//!
//! [`HttpSessionCsrfTokenRepository`] stores the expected token on the server and
//! works with masked hidden form fields. [`CookieCsrfTokenRepository`] stores a
//! separate double-submit cookie, useful for AJAX clients that copy its value into
//! a header. See the crate README for middleware ordering and masking configuration.

use crate::csrf::{CsrfToken, CsrfTokenRepository};
use futures_util::future::BoxFuture;
use http::{HeaderName, request::Parts};
use rand::TryRngCore;
use tower_cookies::{Cookie, Cookies, cookie::SameSite};
use tower_sessions::Session;

/// An operational or configuration failure in a built-in CSRF repository.
#[derive(Debug, thiserror::Error)]
pub enum CsrfRepositoryError {
    /// SessionManagerLayer did not install the request's session.
    #[error("session middleware must run before the CSRF repository")]
    MissingSession,
    /// CookieManagerLayer (or SessionManagerLayer) did not install a cookie jar.
    #[error("cookie middleware must run before the CSRF repository")]
    MissingCookies,
    /// Secure random token generation failed.
    #[error("secure CSRF token generation failed")]
    Random(#[source] rand::rand_core::OsError),
    /// Session access, storage, or decoding failed.
    #[error("CSRF session operation failed")]
    Session(#[source] tower_sessions::session::Error),
    /// A stored or supplied token is invalid for this repository.
    #[error("invalid CSRF repository token")]
    InvalidToken,
    /// A cookie name contains characters that are not allowed in HTTP cookie names.
    #[error("invalid CSRF cookie name")]
    InvalidCookieName,
    /// A __Host- or __Secure- cookie was configured without Secure.
    #[error("__Host- and __Secure- cookies require Secure")]
    InsecureCookiePrefix,
}

fn generate_token(
    header_name: &HeaderName,
    parameter_name: &str,
) -> Result<CsrfToken, CsrfRepositoryError> {
    let mut bytes = [0u8; 32];
    rand::rngs::OsRng
        .try_fill_bytes(&mut bytes)
        .map_err(CsrfRepositoryError::Random)?;
    Ok(CsrfToken {
        header_name: header_name.clone(),
        parameter_name: parameter_name.to_owned(),
        token: hex::encode(bytes),
    })
}

/// Stores a CSRF token in the server-side tower-sessions session.
///
/// Recommended for server-rendered HTML: use the CsrfToken request extension to
/// render a hidden `_csrf` field. Also works for AJAX if an endpoint exposes the
/// token explicitly. Requires [`SessionManagerLayer`] outside [`CsrfLayer`]. Storage
/// lifetime and invalidation follow the session; flushing a session removes its
/// token. Changing only the session ID does not remove the token.
///
/// This implementation also will initialize session when call `save_token`.
///
/// [`CsrfLayer`]: crate::csrf::CsrfLayer
/// [`SessionManagerLayer`]: https://docs.rs/tower-sessions/latest/tower_sessions/service/struct.SessionManager.html
#[derive(Clone, Debug)]
pub struct HttpSessionCsrfTokenRepository {
    session_key: String,
    header_name: HeaderName,
    parameter_name: String,
}

impl Default for HttpSessionCsrfTokenRepository {
    fn default() -> Self {
        Self::new()
    }
}

impl HttpSessionCsrfTokenRepository {
    /// Defaults to session key `tower_http_access_session.csrf_token`, header
    /// `x-csrf-token`, and form field `_csrf`.
    pub fn new() -> Self {
        Self {
            session_key: "tower_http_access_session.csrf_token".into(),
            header_name: HeaderName::from_static("x-csrf-token"),
            parameter_name: "_csrf".into(),
        }
    }

    pub fn with_session_key(mut self, key: impl Into<String>) -> Self {
        self.session_key = key.into();
        self
    }

    pub fn with_header_name(mut self, name: HeaderName) -> Self {
        self.header_name = name;
        self
    }

    pub fn with_parameter_name(mut self, name: impl Into<String>) -> Self {
        self.parameter_name = name.into();
        self
    }

    fn session<'a>(&self, request: &'a Parts) -> Result<&'a Session, CsrfRepositoryError> {
        request
            .extensions
            .get::<Session>()
            .ok_or(CsrfRepositoryError::MissingSession)
    }
}

impl CsrfTokenRepository for HttpSessionCsrfTokenRepository {
    type Error = CsrfRepositoryError;

    fn generate_token(&self) -> Result<CsrfToken, Self::Error> {
        generate_token(&self.header_name, &self.parameter_name)
    }

    fn load_token<'a>(
        &'a self,
        request: &'a Parts,
    ) -> BoxFuture<'a, Result<Option<CsrfToken>, Self::Error>> {
        Box::pin(async move {
            let token = self
                .session(request)?
                .get::<String>(&self.session_key)
                .await
                .map_err(CsrfRepositoryError::Session)?;
            token
                .map(|token| {
                    if token.is_empty() {
                        return Err(CsrfRepositoryError::InvalidToken);
                    }
                    Ok(CsrfToken {
                        header_name: self.header_name.clone(),
                        parameter_name: self.parameter_name.clone(),
                        token,
                    })
                })
                .transpose()
        })
    }

    fn save_token<'a>(
        &'a self,
        request: &'a Parts,
        token: Option<&'a CsrfToken>,
    ) -> BoxFuture<'a, Result<(), Self::Error>> {
        Box::pin(async move {
            let session = self.session(request)?;
            match token {
                Some(token) => {
                    if token.token.is_empty() {
                        return Err(CsrfRepositoryError::InvalidToken);
                    }
                    session
                        .insert(&self.session_key, &token.token)
                        .await
                        .map_err(CsrfRepositoryError::Session)?;
                }
                None => {
                    session
                        .remove_value(&self.session_key)
                        .await
                        .map_err(CsrfRepositoryError::Session)?;
                }
            }
            Ok(())
        })
    }
}

/// Stores a random token in a separate double-submit cookie, without session storage.
///
/// Useful for AJAX clients: opt into `.with_http_only(false)` so JavaScript can
/// copy the CSRF cookie into the `x-xsrf-token` request header. Configure CsrfLayer
/// with `.mask_tokens(false)` for that raw-cookie workflow. For masked HTML forms,
/// keep the default layer settings and render the CsrfToken request extension.
/// This cookie is separate from the authentication/session cookie.
///
/// Requires CookieManagerLayer outside CsrfLayer. SessionManagerLayer already
/// provides it, so do not add another cookie manager when using sessions.
///
/// Defaults to `__Host-XSRF-TOKEN`, Secure, HttpOnly, SameSite=Lax, Path=/, and no
/// Domain. The __Host- prefix prevents a sibling subdomain from injecting this
/// cookie. Custom names lose that browser-enforced protection; use them only
/// when sibling subdomains are trusted. Tokens are not signed or session-bound.
/// Unlike server-side session tokens, they cannot be revoked server-side: removal
/// expires the browser cookie, but does not invalidate previously copied values.
#[derive(Clone, Debug)]
pub struct CookieCsrfTokenRepository {
    cookie_name: String,
    header_name: HeaderName,
    parameter_name: String,
    secure: bool,
    http_only: bool,
}

impl Default for CookieCsrfTokenRepository {
    fn default() -> Self {
        Self::new()
    }
}

impl CookieCsrfTokenRepository {
    pub fn new() -> Self {
        Self {
            cookie_name: "__Host-XSRF-TOKEN".into(),
            header_name: HeaderName::from_static("x-xsrf-token"),
            parameter_name: "_csrf".into(),
            secure: true,
            http_only: true,
        }
    }

    /// Configure a cookie name. The path is always `/`, and Domain is never set.
    pub fn with_cookie_name(
        mut self,
        name: impl Into<String>,
    ) -> Result<Self, CsrfRepositoryError> {
        let name = name.into();
        if name.is_empty()
            || !name
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b"!#$%&'*+-.^_\x60|~".contains(&b))
        {
            return Err(CsrfRepositoryError::InvalidCookieName);
        }
        if !self.secure && requires_secure(&name) {
            return Err(CsrfRepositoryError::InsecureCookiePrefix);
        }
        self.cookie_name = name;
        Ok(self)
    }

    /// Secure defaults to true. For local HTTP, first choose a name without a
    /// __Host- or __Secure- prefix, then explicitly disable Secure.
    pub fn with_secure(mut self, secure: bool) -> Result<Self, CsrfRepositoryError> {
        if !secure && requires_secure(&self.cookie_name) {
            return Err(CsrfRepositoryError::InsecureCookiePrefix);
        }
        self.secure = secure;
        Ok(self)
    }

    /// Disable HttpOnly only when JavaScript must read the CSRF cookie.
    /// This does not alter the authentication/session cookie's HttpOnly setting.
    pub fn with_http_only(mut self, http_only: bool) -> Self {
        self.http_only = http_only;
        self
    }

    pub fn with_header_name(mut self, name: HeaderName) -> Self {
        self.header_name = name;
        self
    }

    pub fn with_parameter_name(mut self, name: impl Into<String>) -> Self {
        self.parameter_name = name.into();
        self
    }

    fn cookies<'a>(&self, request: &'a Parts) -> Result<&'a Cookies, CsrfRepositoryError> {
        request
            .extensions
            .get::<Cookies>()
            .ok_or(CsrfRepositoryError::MissingCookies)
    }

    fn cookie(&self, value: String) -> Cookie<'static> {
        Cookie::build((self.cookie_name.clone(), value))
            .path("/")
            .secure(self.secure)
            .http_only(self.http_only)
            .same_site(SameSite::Lax)
            .build()
    }
}

fn requires_secure(name: &str) -> bool {
    name.starts_with("__Host-") || name.starts_with("__Secure-")
}

fn valid_cookie_token(token: &str) -> bool {
    token.len() == 64 && token.bytes().all(|b| b.is_ascii_hexdigit())
}

impl CsrfTokenRepository for CookieCsrfTokenRepository {
    type Error = CsrfRepositoryError;

    fn generate_token(&self) -> Result<CsrfToken, Self::Error> {
        generate_token(&self.header_name, &self.parameter_name)
    }

    fn load_token<'a>(
        &'a self,
        request: &'a Parts,
    ) -> BoxFuture<'a, Result<Option<CsrfToken>, Self::Error>> {
        Box::pin(async move {
            let cookie = self.cookies(request)?.get(&self.cookie_name);
            Ok(cookie
                .filter(|cookie| valid_cookie_token(cookie.value()))
                .map(|cookie| CsrfToken {
                    header_name: self.header_name.clone(),
                    parameter_name: self.parameter_name.clone(),
                    token: cookie.value().to_owned(),
                }))
        })
    }

    fn save_token<'a>(
        &'a self,
        request: &'a Parts,
        token: Option<&'a CsrfToken>,
    ) -> BoxFuture<'a, Result<(), Self::Error>> {
        Box::pin(async move {
            let cookies = self.cookies(request)?;
            match token {
                Some(token) => {
                    if !valid_cookie_token(&token.token) {
                        return Err(CsrfRepositoryError::InvalidToken);
                    }
                    cookies.add(self.cookie(token.token.clone()));
                }
                None => cookies.remove(self.cookie(String::new())),
            }
            Ok(())
        })
    }
}

#[cfg(test)]
#[path = "csrf_tests.rs"]
mod tests;
