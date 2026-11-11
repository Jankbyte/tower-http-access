use ::tower_sessions::Session;
use futures_util::future::BoxFuture;
use http::{StatusCode, request::Parts};
use serde::Serialize;
use tower_http_access_core::SecurityResponse;
use tower_http_access_form_login::SuccessHandler;

/// Rotates the session ID and stores a value before invoking another success handler.
///
/// The default key is `user_id`, matching [`crate::tower_sessions::SessionRequestAuthenticator`].
/// Use the mapper to store a user identifier or a complete serializable identity.
/// Session middleware must run before form login. Missing sessions and session
/// operation failures return 500 without invoking the next handler. The surrounding
/// session manager saves the updated session and sets the cookie.
///
/// ```
/// struct User { username: String }
/// use tower_http_access_session::tower_sessions::SessionSetSuccessHandler;
/// use tower_http_access_form_login::RedirectSuccessHandler;
///
/// let handler = SessionSetSuccessHandler::new(
///     |user: &User| user.username.clone(),
///     RedirectSuccessHandler::new("/private").unwrap(),
/// );
/// // FormLoginLayer::new(provider).on_success(handler)
/// ```
#[derive(Clone)]
pub struct SessionSetSuccessHandler<F, H> {
    map_identity: F,
    next: H,
    session_key: String,
}

impl<F, H> SessionSetSuccessHandler<F, H> {
    /// Map the authenticated identity to a stored value, then delegate the response.
    pub fn new(map_identity: F, next: H) -> Self {
        Self {
            map_identity,
            next,
            session_key: "user_id".into(),
        }
    }

    /// Configure the key also used by the session authenticator.
    pub fn with_session_key(mut self, key: impl Into<String>) -> Self {
        self.session_key = key.into();
        self
    }
}

impl<A, Id, F, H> SuccessHandler<A> for SessionSetSuccessHandler<F, H>
where
    A: Send + 'static,
    Id: Serialize + Send,
    F: Fn(&A) -> Id + Send + Sync,
    H: SuccessHandler<A>,
{
    fn on_success(&self, parts: Parts, authentication: A) -> BoxFuture<'_, SecurityResponse> {
        Box::pin(async move {
            let Some(session) = parts.extensions.get::<Session>().cloned() else {
                return internal_error();
            };
            let identity = (self.map_identity)(&authentication);
            if session.cycle_id().await.is_err()
                || session.insert(&self.session_key, identity).await.is_err()
            {
                return internal_error();
            }
            self.next.on_success(parts, authentication).await
        })
    }
}

fn internal_error() -> SecurityResponse {
    let mut response = SecurityResponse::new(Default::default());
    *response.status_mut() = StatusCode::INTERNAL_SERVER_ERROR;
    response
}

#[cfg(test)]
#[path = "session_set_success_handler_tests.rs"]
mod tests;
