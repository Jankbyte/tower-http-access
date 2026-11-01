//! Request authorization and unauthenticated-request handling.
//!
//! [`crate::SecurityLayer`] passes the authenticated identity and request parts directly
//! to an [`AuthorizationProvider`] to decide whether the request is allowed.
//!
//! The security layer returns an [`AuthenticationEntryPoint`] response when authentication is
//! required, or delegates other denials and provider errors to an [`AuthorizationFailureHandler`].
//! Use [`AuthorizationLayer`] for independently placed authorization that reads an identity
//! established by earlier authentication middleware from request extensions.
//! Applications that only require a valid identity can use [`AuthenticatedAuthorizationProvider`].
//! Combine independent checks with [`AllAuthorizationProvider`] to require every provider to allow
//! a request, stopping at the first denial or error.

mod auth_tower;
pub use auth_tower::{AuthorizationLayer, AuthorizationLayerBuilder, AuthorizationService};

mod core;
pub use core::{
    AuthenticationEntryPoint, AuthorizationDecision, AuthorizationDenial, AuthorizationFailure,
    AuthorizationFailureHandler, AuthorizationProvider, AuthorizationProviderExt,
    DefaultAuthenticationEntryPoint, DefaultAuthorizationFailureHandler, MapAuthorization,
};

mod all;
pub use all::{
    AllAuthorizationError, AllAuthorizationProvider, AllAuthorizationProviderBuilder,
    EmptyAuthorizationProviders,
};

mod default_auth;
pub use default_auth::AuthenticatedAuthorizationProvider;

#[cfg(feature = "request_matcher")]
pub mod request_matcher;
