//! Request authorization and unauthenticated-request handling.
//!
//! [`crate::SecurityLayer`] passes the authenticated identity and request parts to
//! [`AuthorizationProvider`] to decide whether a request is allowed.
//! Authentication requirements use [`AuthenticationEntryPoint`]; other denials
//! and provider errors use [`AuthorizationFailureHandler`].
//!
//! The default-enabled `authorizers` feature provides basic authentication and permit/deny
//! policies. Request rules, authority checks,
//! and all-of composition are provided by the `tower-http-access-authorizers` crate.

mod core;
pub use core::{
    AuthenticationEntryPoint, AuthorizationDecision, AuthorizationDenial, AuthorizationFailure,
    AuthorizationFailureHandler, AuthorizationProvider, AuthorizationProviderExt,
    DefaultAuthenticationEntryPoint, DefaultAuthorizationFailureHandler, MapAuthorization,
};
#[cfg(feature = "authorizers")]
mod default_auth;
#[cfg(feature = "authorizers")]
pub use default_auth::{
    AuthenticatedAuthorizationProvider, DenyAllAuthorizationProvider,
    PermitAllAuthorizationProvider, denied,
};
#[cfg(feature = "request_matcher")]
pub mod entry_point;
