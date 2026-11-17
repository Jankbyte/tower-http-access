//! Request authentication and authenticator chaining.
//!
//! Authentication inspects a request and optionally produces a typed identity. Successful
//! identities are passed directly to authorization. After access is allowed, the default
//! [`AuthenticationSuccessHandler`] inserts them into request extensions for downstream handlers.
//!
//! Implement [`RequestAuthenticator`] for an authentication mechanism. Use
//! [`DelegatingRequestAuthenticator`] to try multiple mechanisms in order and stop at the first one
//! that authenticates the request. Use [`crate::SecurityLayer`] to run authentication
//! and authorization together.

mod core;
pub use core::{
    Authenticated, AuthenticationAttempt, AuthenticationErrorReason, AuthenticationResult,
    AuthenticatorError, BoxError, MapAuthentication, RequestAuthenticator, RequestAuthenticatorExt,
};

#[cfg(feature = "axum")]
mod axum;

mod delegator;
pub use delegator::{DelegatingRequestAuthenticator, DelegatingRequestAuthenticatorBuilder};

mod success;
pub use success::{AuthenticationSuccessHandler, DefaultAuthenticationSuccessHandler};
