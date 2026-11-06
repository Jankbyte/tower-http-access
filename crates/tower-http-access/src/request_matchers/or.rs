use http::request::Parts;

use super::RequestMatcher;

/// Matches when either child matcher matches, evaluating left to right.
/// The second matcher is skipped when the first matches. Nest instances to
/// combine more matchers without allocating or erasing their types.
///
/// ```
/// use tower_http_access::request_matchers::{OrRequestMatcher, PathPatternRequestMatcher};
/// let matcher = OrRequestMatcher::new(
///     PathPatternRequestMatcher::new("/login")?,
///     PathPatternRequestMatcher::new("/account/{*rest}")?,
/// );
/// # Ok::<(), tower_http_access::request_matchers::InvalidRequestPattern>(())
/// ```
#[derive(Clone, Copy, Debug)]
pub struct OrRequestMatcher<L, R> {
    left: L,
    right: R,
}

impl<L: RequestMatcher, R: RequestMatcher> OrRequestMatcher<L, R> {
    pub fn new(left: L, right: R) -> Self {
        Self { left, right }
    }
}

impl<L: RequestMatcher, R: RequestMatcher> RequestMatcher for OrRequestMatcher<L, R> {
    fn matches(&self, request: &Parts) -> bool {
        self.left.matches(request) || self.right.matches(request)
    }
}

#[cfg(test)]
#[path = "or_tests.rs"]
mod tests;
