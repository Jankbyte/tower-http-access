//! Ordered request authorization, independent of the authentication mechanism.
//!
//! Rules are evaluated in declaration order. The first matching rule's decision is final,
//! including a denial or error. Unmatched requests are denied. Put exceptions before broad
//! patterns, and put `any_request()` last. All checks are authorization providers; use
//! `.access(provider)` to attach custom or composed checks.
//!
//! Authentication-only, permit, deny, and custom rules require no authority trait. Authority
//! methods require [`HasAuthorities`] on the identity. This module needs only the
//! `request_matcher` feature, independently of `basic_auth`.
//!
//! ```
//! use axum_auth_chained::authorization::RequestAuthorizationProvider;
//!
//! let rules = RequestAuthorizationProvider::<String>::builder()
//!     .request_matchers("/health").permit_all()
//!     .any_request().authenticated()
//!     .build()?;
//! # Ok::<(), axum_auth_chained::authorization::InvalidRequestPattern>(())
//! ```
//!
//! # Nested routers
//!
//! Path rules match `Parts.uri` as seen by the middleware, excluding query strings.
//! Axum strips nesting prefixes before running middleware inside a nested router. Attach
//! security after nesting for full application paths, or use local patterns inside the nest.
//! The matcher does not consult `OriginalUri`. Trailing slashes are significant; `{id}` matches
//! one nonempty segment, and `/{*rest}` matches a nonempty remainder, excluding its base path.
//!
//! # Custom providers
//!
//! Custom providers receive the optional identity and original request parts, can perform
//! asynchronous I/O, and decide whether authentication is required. Errors are wrapped in
//! [`RequestAuthorizationError`] with their original source preserved. Matched path parameters
//! are not extracted automatically.

use futures_util::future::BoxFuture;
use http::{Method, request::Parts};
use std::marker::PhantomData;

pub use super::request_matcher::InvalidRequestPattern;
use super::request_matcher::{PathPatternRequestMatcher, RequestMatcher};
use super::{
    AllAuthoritiesAuthorizationProvider, AnyAuthorityAuthorizationProvider,
    AuthenticatedAuthorizationProvider, AuthorityAuthorizationProvider, AuthorizationDecision,
    AuthorizationProvider, DenyAllAuthorizationProvider, HasAuthorities,
    PermitAllAuthorizationProvider,
};

/// An error returned by a request authorization provider.
///
/// The original error is preserved as the source. The default authorization failure
/// handler returns HTTP 500 for these errors; denials remain authorization decisions.
#[derive(Debug, thiserror::Error)]
#[error("custom authorization manager failed")]
pub struct RequestAuthorizationError {
    #[source]
    source: Box<dyn std::error::Error + Send + Sync>,
}

type RuleProvider<A> =
    Box<dyn AuthorizationProvider<Authentication = A, Error = RequestAuthorizationError>>;

struct RuleProviderAdapter<M>(M);

impl<M> AuthorizationProvider for RuleProviderAdapter<M>
where
    M: AuthorizationProvider,
    M::Error: 'static,
{
    type Authentication = M::Authentication;
    type Error = RequestAuthorizationError;

    fn authorize<'a>(
        &'a self,
        authentication: Option<&'a Self::Authentication>,
        request: &'a Parts,
    ) -> BoxFuture<'a, Result<AuthorizationDecision, Self::Error>> {
        Box::pin(async move {
            self.0
                .authorize(authentication, request)
                .await
                .map_err(|error| RequestAuthorizationError {
                    source: Box::new(error),
                })
        })
    }
}

struct Rule<A> {
    matcher: Option<Box<dyn RequestMatcher>>,
    provider: RuleProvider<A>,
}

/// An ordered, first-match authorization provider. Unmatched requests are denied.
///
/// Declaration order determines priority, regardless of path specificity. The first
/// matching rule's decision is final. See the [module documentation](crate::authorization::request) for an example.
/// Path rules use the URI visible to the middleware. Axum strips nesting prefixes
/// inside nested routers; attach security outside the nest for full application
/// paths, or use local patterns inside it. See the module's nested-router guidance.
pub struct RequestAuthorizationProvider<A> {
    rules: Vec<Rule<A>>,
    identity: PhantomData<fn() -> A>,
}

/// Builds an ordered list of request policies.
pub struct RequestAuthorizationBuilder<A> {
    rules: Vec<(Option<MatcherConfiguration>, RuleProvider<A>)>,
    identity: PhantomData<fn() -> A>,
}

/// A matcher awaiting a policy. Only completed rules can be built into a provider.
#[must_use = "select an access policy to complete this rule"]
pub struct PendingRuleBuilder<A> {
    builder: RequestAuthorizationBuilder<A>,
    matcher: Option<MatcherConfiguration>,
}

enum MatcherConfiguration {
    Pattern {
        path: String,
        method: Option<Method>,
    },
    Custom(Box<dyn RequestMatcher>),
}

impl<A> RequestAuthorizationProvider<A> {
    pub fn builder() -> RequestAuthorizationBuilder<A> {
        RequestAuthorizationBuilder {
            rules: Vec::new(),
            identity: PhantomData,
        }
    }
}

impl<A> RequestAuthorizationBuilder<A> {
    /// Selects a rule using a custom synchronous request matcher.
    ///
    /// Only the first matching rule is evaluated, including when its policy denies access.
    /// Matchers borrow the original request parts, including headers and extensions,
    /// without reading the request body.
    /// Keep matching fast: no blocking I/O or expensive CPU-bound work. Use
    /// [`PendingRuleBuilder::access`] with a custom [`AuthorizationProvider`] for
    /// async or CPU-bound access checks, offloading CPU work from the async executor.
    ///
    /// ```
    /// use axum_auth_chained::{
    ///     authorization::RequestAuthorizationProvider,
    ///     authorization::request_matcher::PathPatternRequestMatcher,
    /// };
    ///
    /// let provider = RequestAuthorizationProvider::<String>::builder()
    ///     .matching(PathPatternRequestMatcher::new("/notes/{id}")?)
    ///     .authenticated()
    ///     .any_request().deny_all()
    ///     .build()?;
    /// # Ok::<(), axum_auth_chained::authorization::request_matcher::InvalidRequestPattern>(())
    /// ```
    pub fn matching<M: RequestMatcher + 'static>(self, matcher: M) -> PendingRuleBuilder<A> {
        PendingRuleBuilder {
            builder: self,
            matcher: Some(MatcherConfiguration::Custom(Box::new(matcher))),
        }
    }

    /// Matches a path for every HTTP method.
    ///
    /// Rules are checked in declaration order, with the first match deciding access.
    /// Declare specific exceptions before broader patterns.
    pub fn request_matchers(self, path: impl Into<String>) -> PendingRuleBuilder<A> {
        PendingRuleBuilder {
            builder: self,
            matcher: Some(MatcherConfiguration::Pattern {
                path: path.into(),
                method: None,
            }),
        }
    }

    /// Matches both the HTTP method and path.
    ///
    /// Rules are checked in declaration order, with the first match deciding access.
    /// An exact path does not take priority over an earlier matching parameter path.
    pub fn method_matchers(self, method: Method, path: impl Into<String>) -> PendingRuleBuilder<A> {
        PendingRuleBuilder {
            builder: self,
            matcher: Some(MatcherConfiguration::Pattern {
                path: path.into(),
                method: Some(method),
            }),
        }
    }

    /// Matches all paths and methods. Place this rule last.
    pub fn any_request(self) -> PendingRuleBuilder<A> {
        PendingRuleBuilder {
            builder: self,
            matcher: None,
        }
    }

    /// Validates and compiles all patterns before handling requests.
    pub fn build(self) -> Result<RequestAuthorizationProvider<A>, InvalidRequestPattern> {
        let rules = self
            .rules
            .into_iter()
            .map(|(matcher, provider)| {
                Ok(Rule {
                    matcher: match matcher {
                        None => None,
                        Some(MatcherConfiguration::Pattern { path, method }) => {
                            let matcher = PathPatternRequestMatcher::new(path)?;
                            let matcher = match method {
                                Some(method) => matcher.with_method(method),
                                None => matcher,
                            };
                            Some(Box::new(matcher))
                        }
                        Some(MatcherConfiguration::Custom(matcher)) => Some(matcher),
                    },
                    provider,
                })
            })
            .collect::<Result<_, InvalidRequestPattern>>()?;
        Ok(RequestAuthorizationProvider {
            rules,
            identity: PhantomData,
        })
    }
}

impl<A: Send + Sync + 'static> PendingRuleBuilder<A> {
    /// Delegates the complete decision to a custom async authorization provider.
    ///
    /// The manager receives the optional identity and borrowed request parts, including
    /// for anonymous requests. It is responsible for deciding whether authentication
    /// is required. Only the first matching rule runs; errors and denials do not fall
    /// through to later rules. Errors retain their source in [`RequestAuthorizationError`].
    /// No authority check is added automatically.
    pub fn access<M>(self, manager: M) -> RequestAuthorizationBuilder<A>
    where
        M: AuthorizationProvider<Authentication = A> + 'static,
        M::Error: 'static,
    {
        let mut builder = self.builder;
        builder
            .rules
            .push((self.matcher, Box::new(RuleProviderAdapter(manager))));
        builder
    }

    pub fn permit_all(self) -> RequestAuthorizationBuilder<A> {
        self.access(PermitAllAuthorizationProvider::<A>::new())
    }

    pub fn deny_all(self) -> RequestAuthorizationBuilder<A> {
        self.access(DenyAllAuthorizationProvider::<A>::new())
    }

    pub fn authenticated(self) -> RequestAuthorizationBuilder<A> {
        self.access(AuthenticatedAuthorizationProvider::<A>::new())
    }

    /// Requires an exact authority name, without adding a prefix.
    ///
    /// Only authority rules require [`HasAuthorities`]. An identity without that trait can use
    /// `.authenticated()`, `.permit_all()`, `.deny_all()`, and `.access(...)` instead.
    ///
    /// ```compile_fail,E0277
    /// use axum_auth_chained::authorization::RequestAuthorizationProvider;
    /// let rules = RequestAuthorizationProvider::<String>::builder()
    ///     .any_request().has_authority("Admin");
    /// ```
    pub fn has_authority(self, authority: impl Into<String>) -> RequestAuthorizationBuilder<A>
    where
        A: HasAuthorities,
    {
        self.access(AuthorityAuthorizationProvider::<A>::new(authority))
    }

    /// Requires at least one authority. An empty collection grants no access.
    pub fn has_any_authority<I, S>(self, authorities: I) -> RequestAuthorizationBuilder<A>
    where
        A: HasAuthorities,
        I: IntoIterator<Item = S>,
        S: Into<String>,
    {
        self.access(AnyAuthorityAuthorizationProvider::<A>::new(authorities))
    }

    /// Requires an authenticated identity with every listed authority.
    /// An empty collection requires authentication but no specific authority.
    pub fn has_all_authorities<I, S>(self, authorities: I) -> RequestAuthorizationBuilder<A>
    where
        A: HasAuthorities,
        I: IntoIterator<Item = S>,
        S: Into<String>,
    {
        self.access(AllAuthoritiesAuthorizationProvider::<A>::new(authorities))
    }
}

impl<A: Send + Sync> AuthorizationProvider for RequestAuthorizationProvider<A> {
    type Authentication = A;
    type Error = RequestAuthorizationError;

    fn authorize<'a>(
        &'a self,
        authentication: Option<&'a A>,
        request: &'a Parts,
    ) -> BoxFuture<'a, Result<AuthorizationDecision, Self::Error>> {
        match self.rules.iter().find(|rule| {
            rule.matcher
                .as_ref()
                .is_none_or(|matcher| matcher.matches(request))
        }) {
            Some(rule) => rule.provider.authorize(authentication, request),
            None => Box::pin(async move { Ok(super::default_auth::denied(authentication)) }),
        }
    }
}

#[cfg(test)]
#[path = "request_tests.rs"]
mod tests;
