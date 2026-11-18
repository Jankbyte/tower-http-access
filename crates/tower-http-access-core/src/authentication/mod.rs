//! Request authentication and typed identities.
//!
//! Authentication inspects a request and optionally produces a typed identity. Successful
//! identities are passed directly to authorization. After access is allowed, the default
//! [`AuthenticationSuccessHandler`] inserts them into request extensions for downstream handlers.
//!
//! Implement [`RequestAuthenticator`] for an authentication mechanism. Use
//! [`crate::SecurityLayer`] to run authentication and authorization together.

mod core;
pub use core::{
    Authenticated, AuthenticationAttempt, AuthenticationResult, AuthenticatorError,
    MapAuthentication, Reason, RequestAuthenticator, RequestAuthenticatorExt,
};

#[cfg(feature = "axum")]
mod axum;

mod success;
pub use success::{AuthenticationSuccessHandler, DefaultAuthenticationSuccessHandler};
