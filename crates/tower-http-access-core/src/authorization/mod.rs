//! Request authorization and unauthenticated-request handling.
//!
//! [`crate::SecurityLayer`] passes the authenticated identity and request parts to
//! [`core::AuthorizationProvider`] to decide whether a request is allowed.
//! Authentication requirements use [`core::AuthenticationEntryPoint`]; other denials
//! and provider errors use [`core::AuthorizationFailureHandler`].
//!
//! Reusable policies are provided by the `tower-http-access-authorizers` crate.
//! The `split_auth` feature provides a separate authorization layer in [`auth_tower`].

#[cfg(feature = "split_auth")]
pub mod auth_tower;
pub mod core;
#[cfg(feature = "request_matcher")]
pub mod entry_point;
