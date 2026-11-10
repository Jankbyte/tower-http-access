//! Request authorization and unauthenticated-request handling.
//!
//! [`crate::SecurityLayer`] passes the authenticated identity and request parts to
//! [`core::AuthorizationProvider`] to decide whether a request is allowed.
//! Authentication requirements use [`core::AuthenticationEntryPoint`]; other denials
//! and provider errors use [`core::AuthorizationFailureHandler`].
//!
//! Use [`default_auth::AuthenticatedAuthorizationProvider`] to require an identity,
//! or [`all::AllAuthorizationProvider`] to combine independent checks.
//! The `split_auth` feature provides a separate authorization layer in [`auth_tower`].

pub mod all;
#[cfg(feature = "split_auth")]
pub mod auth_tower;
pub mod authorities;
pub mod core;
pub mod default_auth;
#[cfg(feature = "request_matcher")]
pub mod entry_point;
#[cfg(feature = "request_matcher")]
pub mod request;
