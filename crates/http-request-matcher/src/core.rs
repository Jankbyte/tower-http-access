use http::request::Parts;

/// Match target HTTP-request.
///
/// Limitations:
///
/// - Matchers *can* run on the request's async executor thread and must be fast. Do not
///   perform blocking I/O, database or network calls, or expensive CPU-bound work
///   inside `matches`. Compile patterns and prepare lookup data during configuration.
///   Delegate asynchronous or expensive checks to the middleware or policy that uses
///   the matcher rather than performing them inside `matches`.
/// - The matcher present API only for verify request meta-data (headers, path and e.g.) without payload/body.
///   If you need verify payload, so you must use other abstraction for that.
///
pub trait RequestMatcher: Send + Sync {
    fn matches(&self, request: &Parts) -> bool;
}

/// Implementation for using with values that does not implement `Clone` or it's not cheap.
///
/// It can be useful when you want share single rich/complex configured matcher between multiple components.
impl<T> RequestMatcher for std::sync::Arc<T>
where
    T: RequestMatcher + ?Sized,
{
    fn matches(&self, request: &Parts) -> bool {
        T::matches(self, request)
    }
}
