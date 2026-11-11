//! Authority policies for request-rule builders.

use super::{
    AllAuthoritiesAuthorizationProvider, AnyAuthorityAuthorizationProvider,
    AuthorityAuthorizationProvider, HasAuthorities,
};
use crate::request::{PendingRuleBuilder, RequestAuthorizationBuilder};

/// Extends a selected request rule with authority policies.
///
/// Available when both `authorities` and `request_matcher` are enabled. Import
/// this trait to make the methods available on [`PendingRuleBuilder`]. Each
/// method completes the selected rule through its public `.access(...)` method.
///
/// ```
/// use tower_http_access_authorizers::{
///     authorities::{AuthorityRuleExt, HasAuthorities},
///     request::RequestAuthorizationProvider,
/// };
///
/// struct User { authorities: Vec<String> }
/// impl HasAuthorities for User {
///     fn has_authority(&self, authority: &str) -> bool {
///         self.authorities.iter().any(|granted| granted == authority)
///     }
/// }
///
/// let rules = RequestAuthorizationProvider::<User>::builder()
///     .request_matchers("/admin").has_authority("Admin")
///     .request_matchers("/notes").has_any_authority(["Read", "Write"])
///     .request_matchers("/edit").has_all_authorities(["Read", "Write"])
///     .any_request().deny_all()
///     .build()?;
/// # Ok::<(), http_request_matcher::InvalidRequestPattern>(())
/// ```
pub trait AuthorityRuleExt: Sized {
    /// The builder returned after completing the selected rule.
    type Builder;

    /// Requires an authenticated identity with this exact authority name.
    /// No prefix is added to the supplied name.
    ///
    /// Identities without [`HasAuthorities`] can still use `.authenticated()`,
    /// `.permit_all()`, `.deny_all()`, and `.access(...)`.
    ///
    /// ```compile_fail,E0277
    /// use tower_http_access_authorizers::{
    ///     authorities::AuthorityRuleExt,
    ///     request::RequestAuthorizationProvider,
    /// };
    /// let rules = RequestAuthorizationProvider::<String>::builder()
    ///     .any_request().has_authority("Admin");
    /// ```
    fn has_authority(self, authority: impl Into<String>) -> Self::Builder;

    /// Requires authentication and at least one listed authority.
    /// An empty collection grants no access.
    fn has_any_authority<I, S>(self, authorities: I) -> Self::Builder
    where
        I: IntoIterator<Item = S>,
        S: Into<String>;

    /// Requires authentication and every listed authority.
    /// An empty collection requires authentication but no specific authority.
    fn has_all_authorities<I, S>(self, authorities: I) -> Self::Builder
    where
        I: IntoIterator<Item = S>,
        S: Into<String>;
}

impl<A: HasAuthorities + Send + Sync + 'static> AuthorityRuleExt for PendingRuleBuilder<A> {
    type Builder = RequestAuthorizationBuilder<A>;

    fn has_authority(self, authority: impl Into<String>) -> Self::Builder {
        self.access(AuthorityAuthorizationProvider::<A>::new(authority))
    }

    fn has_any_authority<I, S>(self, authorities: I) -> Self::Builder
    where
        I: IntoIterator<Item = S>,
        S: Into<String>,
    {
        self.access(AnyAuthorityAuthorizationProvider::<A>::new(authorities))
    }

    fn has_all_authorities<I, S>(self, authorities: I) -> Self::Builder
    where
        I: IntoIterator<Item = S>,
        S: Into<String>,
    {
        self.access(AllAuthoritiesAuthorizationProvider::<A>::new(authorities))
    }
}
