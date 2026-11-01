//! Synchronous request matching for ordered authorization rules.
//!
//! A matcher selects a policy; it does not grant or deny access itself.
//! Patterns are compiled once and matching borrows request metadata.

use http::{Method, request::Parts};

/// Selects whether a request is covered by an authorization rule.
///
/// Implementations should perform local, synchronous checks. A `false` result skips
/// the rule rather than denying access; later rules may still allow the request.
///
/// Matchers run on the request's async executor thread and must be fast. Do not
/// perform blocking I/O, database or network calls, or expensive CPU-bound work
/// inside `matches`. Compile patterns and prepare lookup data during configuration.
/// Use a custom [`AuthorizationProvider`](crate::authorization::AuthorizationProvider)
/// for async or CPU-bound access checks, attached to a rule with `.access(provider)`.
/// CPU-bound work in that provider must be offloaded to a blocking or dedicated
/// worker pool; an async function alone does not prevent blocking the executor.
pub trait RequestMatcher: Send + Sync {
    fn matches(&self, request: &Parts) -> bool;
}

/// A malformed path pattern encountered while configuring request rules.
#[derive(Debug, thiserror::Error)]
#[error("invalid request path pattern: {0}")]
pub struct InvalidRequestPattern(pub String);

/// A compiled, case-sensitive URI path pattern using `matchit` syntax.
///
/// `{name}` matches a nonempty segment. A final `/{*rest}` matches a
/// nonempty remainder, excluding the base path and its trailing slash.
/// Trailing slashes are significant; query strings are ignored. All HTTP methods
/// match unless restricted with [`Self::with_method`]. Matching does not decode
/// percent escapes.
///
/// ```
/// use tower_http_access::authorization::request_matcher::{
///     PathPatternRequestMatcher, RequestMatcher,
/// };
/// use http::Request;
///
/// let matcher = PathPatternRequestMatcher::new("/notes/{id}")?;
/// let (parts, _) = Request::builder()
///     .uri("/notes/42?view=full")
///     .body(())
///     .unwrap()
///     .into_parts();
/// assert!(matcher.matches(&parts));
/// # Ok::<(), tower_http_access::authorization::request_matcher::InvalidRequestPattern>(())
/// ```
pub struct PathPatternRequestMatcher {
    router: matchit::Router<()>,
    method: Option<Method>,
}

impl PathPatternRequestMatcher {
    /// Validates and compiles a path pattern before requests are processed.
    pub fn new(pattern: impl Into<String>) -> Result<Self, InvalidRequestPattern> {
        let pattern = pattern.into();
        if !pattern.starts_with('/') || pattern.contains(['?', '#']) {
            return Err(InvalidRequestPattern(pattern));
        }
        let mut router = matchit::Router::new();
        router
            .insert(&pattern, ())
            .map_err(|_| InvalidRequestPattern(pattern))?;
        Ok(Self {
            router,
            method: None,
        })
    }

    /// Restricts matching to this HTTP method as well as the path pattern.
    /// Calling this again replaces the previous method restriction.
    #[must_use]
    pub fn with_method(mut self, method: Method) -> Self {
        self.method = Some(method);
        self
    }
}

impl RequestMatcher for PathPatternRequestMatcher {
    fn matches(&self, request: &Parts) -> bool {
        self.method
            .as_ref()
            .is_none_or(|method| method == request.method)
            && self.router.at(request.uri.path()).is_ok()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn invalid_patterns_preserve_the_input_in_the_error() {
        for pattern in [
            "",
            "notes",
            "https://example.com/notes",
            "/notes?view=full",
            "/notes#section",
            "/notes/{}",
            "/notes/{id",
            "/notes/id}",
            "/notes/{*rest}/child",
        ] {
            let error = match PathPatternRequestMatcher::new(pattern) {
                Err(error) => error,
                Ok(_) => panic!("expected InvalidRequestPattern for {pattern:?}"),
            };
            assert_eq!(error.0, pattern);
            assert_eq!(
                error.to_string(),
                format!("invalid request path pattern: {pattern}"),
            );
        }
    }

    #[test]
    fn method_restrictions_require_both_method_and_path() {
        let unrestricted = PathPatternRequestMatcher::new("/notes/{id}").unwrap();
        let restricted = PathPatternRequestMatcher::new("/notes/{id}")
            .unwrap()
            .with_method(Method::GET);
        for (method, path, expected) in [
            (Method::GET, "/notes/42?view=full", true),
            (Method::POST, "/notes/42", false),
            (Method::HEAD, "/notes/42", false),
            (Method::GET, "/other/42", false),
            (Method::GET, "/notes/42/", false),
        ] {
            let (parts, _) = http::Request::builder()
                .method(method)
                .uri(path)
                .body(())
                .unwrap()
                .into_parts();
            assert_eq!(restricted.matches(&parts), expected);
            if parts.uri.path() == "/notes/42" {
                assert!(unrestricted.matches(&parts));
            }
        }
    }

    #[test]
    fn setting_method_again_replaces_restriction_and_supports_custom_methods() {
        let matcher = PathPatternRequestMatcher::new("/notes/{id}")
            .unwrap()
            .with_method(Method::GET)
            .with_method(Method::from_bytes(b"LIST").unwrap());
        for (method, expected) in [("GET", false), ("LIST", true)] {
            let (parts, _) = http::Request::builder()
                .method(method)
                .uri("/notes/42")
                .body(())
                .unwrap()
                .into_parts();
            assert_eq!(matcher.matches(&parts), expected);
        }
    }
}
