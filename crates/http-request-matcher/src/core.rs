use http::request::Parts;

/// Selects whether a request is covered by a security chain or authorization rule.
///
/// Implementations should perform local, synchronous checks. A `false` result skips
/// the rule rather than denying access; later rules may still allow the request.
///
/// Matchers run on the request's async executor thread and must be fast. Do not
/// perform blocking I/O, database or network calls, or expensive CPU-bound work
/// inside `matches`. Compile patterns and prepare lookup data during configuration.
/// Delegate asynchronous or expensive checks to the middleware or policy that uses
/// the matcher rather than performing them inside `matches`.
pub trait RequestMatcher: Send + Sync {
    fn matches(&self, request: &Parts) -> bool;
}

impl<T> RequestMatcher for std::sync::Arc<T>
where
    T: RequestMatcher + ?Sized,
{
    fn matches(&self, request: &Parts) -> bool {
        T::matches(self, request)
    }
}
