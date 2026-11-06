use http::request::Parts;

/// Selects whether a request is covered by a security chain or authorization rule.
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
