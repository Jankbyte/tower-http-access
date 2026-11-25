use http::request::Parts;

use crate::core::RequestMatcher;

/// Matches every request as accepted (`matches` everytime returns *true*).
///
/// # Examples
///
/// ```rust
/// use http_request_matcher::{RequestMatcher, AnyRequestMatcher};
/// use http::Request;
///
/// let matcher = AnyRequestMatcher;
///
/// let (parts, _) = Request::builder()
///     .method("GET")
///     .uri("/v1/test")
///     .body(())
///     .unwrap()
///     .into_parts();
/// let matched = matcher.matches(&parts);
/// assert!(matched);
/// ```
///
#[derive(Clone, Copy, Debug, Default)]
pub struct AnyRequestMatcher;

impl RequestMatcher for AnyRequestMatcher {
    fn matches(&self, _: &Parts) -> bool {
        true
    }
}

#[cfg(test)]
#[path = "any_tests.rs"]
mod tests;
