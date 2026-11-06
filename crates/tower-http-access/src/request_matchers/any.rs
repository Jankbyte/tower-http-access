use http::request::Parts;

use super::RequestMatcher;

/// Matches every request, regardless of method, path, headers, or extensions.
///
/// Use as the last matcher in an ordered chain or policy to handle all remaining
/// requests. Placing it first prevents later entries from being selected.
/// Matching selects a policy; it does not itself grant access.
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
