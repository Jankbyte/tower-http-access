use crate::request_matchers::RequestMatcher;
use http::request::Parts;
use std::sync::Arc;

/// Wrapper for [`RequestMatcher`], for sharing between multiple components.
pub struct SharedRequestMatcher<T>(Arc<T>);

impl<T> Clone for SharedRequestMatcher<T> {
    fn clone(&self) -> Self {
        Self(Arc::clone(&self.0))
    }
}

impl<T> SharedRequestMatcher<T> {
    pub fn new(value: T) -> Self
    where
        T: RequestMatcher,
    {
        Self(Arc::new(value))
    }
}

impl<T: RequestMatcher> RequestMatcher for SharedRequestMatcher<T> {
    fn matches(&self, request: &Parts) -> bool {
        self.0.matches(request)
    }
}
