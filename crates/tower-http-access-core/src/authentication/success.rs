//! Passing authenticated identities to downstream request handlers.

use super::Authenticated;
use http::request::Parts;
use std::sync::Arc;

/// Consumes an authenticated identity after authorization allows the request.
///
/// Called once for an allowed, authenticated request, before invoking the inner
/// service. Anonymous requests, authentication failures, and authorization denials
/// or errors skip this handler. Authorization receives the original identity before
/// any changes made here. Implementations may update headers, extensions, or shared
/// application state synchronously; they must not perform blocking I/O.
///
/// A custom handler replaces the default insertion of [`Authenticated<A>`]. It must
/// insert that extension itself if downstream handlers still need the extractor.
/// Configure it with [`crate::SecurityLayer::authentication_success_handler`].
pub trait AuthenticationSuccessHandler<A>: Send + Sync + 'static {
    fn on_success(&self, authentication: A, parts: &mut Parts);
}

impl<A, F> AuthenticationSuccessHandler<A> for F
where
    F: Fn(A, &mut Parts) + Send + Sync + 'static,
{
    fn on_success(&self, authentication: A, parts: &mut Parts) {
        self(authentication, parts);
    }
}

impl<A, H: AuthenticationSuccessHandler<A> + ?Sized> AuthenticationSuccessHandler<A> for Arc<H> {
    fn on_success(&self, authentication: A, parts: &mut Parts) {
        self.as_ref().on_success(authentication, parts);
    }
}

/// Stores the identity as [`Authenticated<A>`] in request extensions.
#[derive(Clone, Copy, Debug, Default)]
pub struct DefaultAuthenticationSuccessHandler;

impl<A: Clone + Send + Sync + 'static> AuthenticationSuccessHandler<A>
    for DefaultAuthenticationSuccessHandler
{
    fn on_success(&self, authentication: A, parts: &mut Parts) {
        parts.extensions.insert(Authenticated(authentication));
    }
}
