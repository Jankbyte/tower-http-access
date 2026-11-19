//! Redirect responses for requests requiring authentication.

use futures_util::future::BoxFuture;
use http::{HeaderValue, StatusCode, Uri, header, request::Parts};
use tower_http_access_core::{SecurityResponse, authentication::AuthenticationEntryPoint};

/// Redirects requests requiring authentication to a configured login page.
///
/// This entry point does not depend on a session or authentication mechanism.
/// Keep the login endpoint accessible anonymously to avoid redirect loops.
///
/// ```
/// use tower_http_access_session::entry_point::RedirectAuthenticationEntryPoint;
///
/// let entry_point = RedirectAuthenticationEntryPoint::new("/account/login?next=%2Fprivate")?;
/// # Ok::<(), tower_http_access_session::entry_point::InvalidRedirectPath>(())
/// ```
#[derive(Clone, Debug)]
pub struct RedirectAuthenticationEntryPoint {
    location: HeaderValue,
}

impl RedirectAuthenticationEntryPoint {
    /// Configure a same-origin absolute path. Query strings are allowed;
    /// relative paths, external URLs, network-path URLs, and fragments are rejected.
    pub fn new(path: impl AsRef<str>) -> Result<Self, InvalidRedirectPath> {
        let path = path.as_ref();
        let uri = path.parse::<Uri>().map_err(|_| InvalidRedirectPath)?;
        if !path.starts_with('/')
            || path.starts_with("//")
            || path.contains('\\')
            || path.contains('#')
            || uri.scheme().is_some()
            || uri.authority().is_some()
        {
            return Err(InvalidRedirectPath);
        }
        Ok(Self {
            location: HeaderValue::from_str(path).map_err(|_| InvalidRedirectPath)?,
        })
    }
}

/// The redirect location must be a valid same-origin absolute path.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct InvalidRedirectPath;

impl std::fmt::Display for InvalidRedirectPath {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("redirect location must be a same-origin absolute path")
    }
}

impl std::error::Error for InvalidRedirectPath {}

impl AuthenticationEntryPoint for RedirectAuthenticationEntryPoint {
    fn commence<'a>(&'a self, _: &'a Parts) -> BoxFuture<'a, SecurityResponse> {
        Box::pin(async move {
            let mut response = SecurityResponse::new(Default::default());
            *response.status_mut() = StatusCode::FOUND;
            response
                .headers_mut()
                .insert(header::LOCATION, self.location.clone());
            response
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use http::Request;

    #[test]
    fn rejects_external_and_invalid_locations() {
        for path in [
            "",
            "login",
            "https://evil.example/login",
            "//evil.example/login",
            "/\\evil.example",
            "/login\r\nInjected: true",
            "/login#fragment",
        ] {
            assert!(
                RedirectAuthenticationEntryPoint::new(path).is_err(),
                "{path:?}"
            );
        }
    }

    #[tokio::test]
    async fn redirects_without_session_state() {
        let (parts, _) = Request::new(()).into_parts();
        for path in ["/login", "/account/login?next=%2Fprivate"] {
            let entry_point = RedirectAuthenticationEntryPoint::new(path).unwrap();
            let response = entry_point.clone().commence(&parts).await;
            assert_eq!(response.status(), StatusCode::FOUND);
            assert_eq!(response.headers()[header::LOCATION], path);
            assert!(response.body().is_empty());
        }
    }
}
