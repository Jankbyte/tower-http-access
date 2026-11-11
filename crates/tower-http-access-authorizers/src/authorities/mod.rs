//! Reusable authority checks and optional request-builder extensions.
//!
//! With `request_matcher`, import `AuthorityRuleExt` to add authority policies
//! to a selected request rule.

mod providers;
pub use providers::{
    AllAuthoritiesAuthorizationProvider, AnyAuthorityAuthorizationProvider,
    AuthorityAuthorizationProvider, HasAuthorities,
};

#[cfg(feature = "request_matcher")]
mod request;
#[cfg(feature = "request_matcher")]
pub use request::AuthorityRuleExt;
