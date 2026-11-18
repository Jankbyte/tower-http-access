//! Request authentication and typed identities.
//!
//! Authentication inspects a request and optionally produces a typed identity. Successful
//! identities are passed directly to authorization. After access is allowed, the default
//! [`crate::security_layer::AuthenticationSuccessHandler`] inserts them into request extensions for downstream handlers.
//!
//! Implement [`RequestAuthenticator`] for an authentication mechanism. Use
//! [`crate::security_layer::SecurityLayer`] to run authentication and authorization together.

mod core;
pub use core::{
    Authenticated, AuthenticationAttempt, AuthenticationResult, AuthenticatorError,
    MapAuthentication, Reason, RequestAuthenticator, RequestAuthenticatorExt,
};

#[cfg(feature = "axum")]
mod axum;

pub mod entry_point;
pub use entry_point::{AuthenticationEntryPoint, DefaultAuthenticationEntryPoint};

#[cfg(feature = "request_matcher")]
mod delegating;
#[cfg(feature = "request_matcher")]
pub use delegating::{
    DelegatingAuthenticationEntryPoint, DelegatingAuthenticationEntryPointBuilder,
};
