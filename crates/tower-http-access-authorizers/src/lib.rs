#![doc = include_str!("../README.md")]

pub mod all;
#[cfg(feature = "authorities")]
pub mod authorities;
pub mod default_auth;
#[cfg(feature = "request_matcher")]
pub mod request;

#[cfg(all(test, feature = "authorities"))]
use tower_http_access_core::authorization::core::{AuthorizationDecision, AuthorizationDenial};

#[cfg(all(test, feature = "authorities"))]
pub(crate) fn assert_builtin_decision(
    actual: AuthorizationDecision,
    expected: AuthorizationDecision,
) {
    assert!(
        matches!(
            (&actual, &expected),
            (AuthorizationDecision::Allow, AuthorizationDecision::Allow)
                | (
                    AuthorizationDecision::Deny(AuthorizationDenial::AuthenticationRequired),
                    AuthorizationDecision::Deny(AuthorizationDenial::AuthenticationRequired)
                )
                | (
                    AuthorizationDecision::Deny(AuthorizationDenial::InsufficientPermissions),
                    AuthorizationDecision::Deny(AuthorizationDenial::InsufficientPermissions)
                )
        ),
        "expected {expected:?}, got {actual:?}"
    );
}
