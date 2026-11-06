use http::{Method, request::Parts};

use super::RequestMatcher;

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
/// use tower_http_access::request_matchers::{
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
/// # Ok::<(), tower_http_access::request_matchers::InvalidRequestPattern>(())
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
#[path = "path_pattern_tests.rs"]
mod tests;
