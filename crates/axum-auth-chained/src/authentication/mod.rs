//! Request authentication and authenticator chaining.
//!
//! Authentication inspects a request and optionally produces a typed identity. Successful
//! identities are inserted into the request extensions so handlers and the authorization layer can
//! retrieve them by type.
//!
//! Implement [`RequestAuthenticator`] for an authentication mechanism. Use
//! [`DelegatingRequestAuthenticator`] to try multiple mechanisms in order and stop at the first one
//! that authenticates the request. Use [`crate::SecurityLayer`] to run authentication
//! and authorization together, or [`AuthenticationLayer`] when authentication needs independent
//! placement in the middleware stack.

mod core;
pub use core::{
    Authenticated, AuthenticationAttempt, AuthenticationErrorReason, AuthenticatorError, BoxError,
    MapAuthentication, RequestAuthenticator, RequestAuthenticatorExt,
};

mod axum;

mod auth_tower;
pub use auth_tower::{AuthenticationLayer, AuthenticationService};

mod delegator;
pub use delegator::{DelegatingRequestAuthenticator, DelegatingRequestAuthenticatorBuilder};
