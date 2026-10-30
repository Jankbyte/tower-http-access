//! Ordered HTTP request authorization rules.
//!
//! Rules use the first matching policy, and unmatched requests are denied. Paths are
//! case-sensitive and exclude the query string. `{name}` matches one nonempty path
//! segment; a final `/{*rest}` matches a nonempty remainder, excluding the base path
//! and its trailing slash. Trailing slashes are significant. Patterns use `matchit`
//! syntax, as in Axum. Use `any_request()` to match every path, including `/`.
//!
//! # Rule ordering
//!
//! Rules are evaluated in declaration order. Only the first matching rule is
//! evaluated: its decision is final, including when it denies access. Later rules
//! cannot override that decision. Path specificity does not affect priority; an
//! exact path declared after a matching parameter or catch-all path is never reached.
//!
//! Put exceptions before broader rules, and put `any_request()` last. For example,
//! the first note can be read anonymously, while other notes require `ReadNote`:
//!
//! ```rust
//! use axum::http::Method;
//! use axum_auth_chained::basic::{RequestAuthorizationProvider, UserDetail};
//!
//! let provider = RequestAuthorizationProvider::<UserDetail>::builder()
//!     .method_matchers(Method::GET, "/v1/notes/1")
//!     .permit_all()
//!     .method_matchers(Method::GET, "/v1/notes/{id}")
//!     .has_authority("ReadNote")
//!     .any_request()
//!     .deny_all()
//!     .build()?;
//! # Ok::<(), axum_auth_chained::basic::InvalidRequestPattern>(())
//! ```
//!
//! Reversing the two note rules would require `ReadNote` for note `1` as well,
//! because `/v1/notes/{id}` also matches `/v1/notes/1`. The later `permit_all()`
//! would never be evaluated. Method matching also applies: the public exception
//! above only permits `GET`, not `PUT` or `DELETE`.
//!
//! # Layer integration
//!
//! ```rust
//! use axum::http::Method;
//! use axum_auth_chained::{
//!     basic::{RequestAuthorizationProvider, UserDetail, request_context_mapper},
//!     authorization::AuthorizationLayer,
//! };
//!
//! let provider = RequestAuthorizationProvider::<UserDetail>::builder()
//!     .request_matchers("/health").permit_all()
//!     .method_matchers(Method::GET, "/v1/notes/{id}").has_authority("ReadNote")
//!     .request_matchers("/admin/{*rest}").has_authority("ADMIN")
//!     .any_request().deny_all()
//!     .build()?;
//! let layer = AuthorizationLayer::builder(provider, request_context_mapper).build();
//! # Ok::<(), axum_auth_chained::basic::InvalidRequestPattern>(())
//! ```

use std::{convert::Infallible, future::Future, marker::PhantomData, pin::Pin};

use axum::http::{Method, Uri, request::Parts};

use crate::authorization::{AuthorizationDecision, AuthorizationDenial, AuthorizationProvider};

use super::UserDetail;

/// An identity whose authorities can be checked by request policies.
pub trait HasAuthorities {
    fn has_authority(&self, authority: &str) -> bool;
}

impl HasAuthorities for UserDetail {
    fn has_authority(&self, authority: &str) -> bool {
        self.authorities
            .iter()
            .any(|granted| granted.0 == authority)
    }
}

/// Owned request metadata used for authorization, without reading the body.
#[derive(Clone, Debug)]
pub struct RequestContext {
    pub method: Method,
    pub uri: Uri,
}

/// Maps request parts into the context expected by [`RequestAuthorizationProvider`].
pub fn request_context_mapper(parts: &Parts) -> RequestContext {
    RequestContext {
        method: parts.method.clone(),
        uri: parts.uri.clone(),
    }
}

/// A malformed path pattern encountered while building request rules.
#[derive(Debug, thiserror::Error)]
#[error("invalid request path pattern: {0}")]
pub struct InvalidRequestPattern(pub String);

enum RequestPathMatcher {
    Any,
    Pattern(matchit::Router<()>),
}

impl RequestPathMatcher {
    fn compile(pattern: Option<String>) -> Result<Self, InvalidRequestPattern> {
        let Some(pattern) = pattern else {
            return Ok(Self::Any);
        };
        // Match URI paths only, consistent with Axum's leading-slash requirement.
        if !pattern.starts_with('/') || pattern.contains(['?', '#']) {
            return Err(InvalidRequestPattern(pattern));
        }
        let mut router = matchit::Router::new();
        router
            .insert(&pattern, ())
            .map_err(|_| InvalidRequestPattern(pattern))?;
        Ok(Self::Pattern(router))
    }

    fn matches(&self, path: &str) -> bool {
        match self {
            Self::Any => true,
            Self::Pattern(router) => router.at(path).is_ok(),
        }
    }
}

enum AccessPolicy {
    PermitAll,
    DenyAll,
    Authenticated,
    HasAuthority(String),
    HasAnyAuthority(Vec<String>),
    HasAllAuthorities(Vec<String>),
}

struct Rule {
    method: Option<Method>,
    path: RequestPathMatcher,
    policy: AccessPolicy,
}

/// An ordered, first-match authorization provider. Unmatched requests are denied.
///
/// Declaration order determines priority, regardless of path specificity. The first
/// matching rule's decision is final. See the [module documentation](self) for an example.
pub struct RequestAuthorizationProvider<A> {
    rules: Vec<Rule>,
    identity: PhantomData<fn() -> A>,
}

/// Builds an ordered list of request policies.
pub struct RequestAuthorizationBuilder<A> {
    rules: Vec<(Option<Method>, Option<String>, AccessPolicy)>,
    identity: PhantomData<fn() -> A>,
}

/// A matcher awaiting a policy. Only completed rules can be built into a provider.
#[must_use = "select an access policy to complete this rule"]
pub struct PendingRuleBuilder<A> {
    builder: RequestAuthorizationBuilder<A>,
    method: Option<Method>,
    path: Option<String>,
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
    /// Matches a path for every HTTP method.
    ///
    /// Rules are checked in declaration order, with the first match deciding access.
    /// Declare specific exceptions before broader patterns.
    pub fn request_matchers(self, path: impl Into<String>) -> PendingRuleBuilder<A> {
        PendingRuleBuilder {
            builder: self,
            method: None,
            path: Some(path.into()),
        }
    }

    /// Matches both the HTTP method and path.
    ///
    /// Rules are checked in declaration order, with the first match deciding access.
    /// An exact path does not take priority over an earlier matching parameter path.
    pub fn method_matchers(self, method: Method, path: impl Into<String>) -> PendingRuleBuilder<A> {
        PendingRuleBuilder {
            builder: self,
            method: Some(method),
            path: Some(path.into()),
        }
    }

    /// Matches all paths and methods. Place this rule last.
    pub fn any_request(self) -> PendingRuleBuilder<A> {
        PendingRuleBuilder {
            builder: self,
            method: None,
            path: None,
        }
    }

    /// Validates and compiles all patterns before handling requests.
    pub fn build(self) -> Result<RequestAuthorizationProvider<A>, InvalidRequestPattern> {
        let rules = self
            .rules
            .into_iter()
            .map(|(method, path, policy)| {
                Ok(Rule {
                    method,
                    path: RequestPathMatcher::compile(path)?,
                    policy,
                })
            })
            .collect::<Result<_, InvalidRequestPattern>>()?;
        Ok(RequestAuthorizationProvider {
            rules,
            identity: PhantomData,
        })
    }
}

impl<A> PendingRuleBuilder<A> {
    fn policy(mut self, policy: AccessPolicy) -> RequestAuthorizationBuilder<A> {
        self.builder.rules.push((self.method, self.path, policy));
        self.builder
    }

    pub fn permit_all(self) -> RequestAuthorizationBuilder<A> {
        self.policy(AccessPolicy::PermitAll)
    }

    pub fn deny_all(self) -> RequestAuthorizationBuilder<A> {
        self.policy(AccessPolicy::DenyAll)
    }

    pub fn authenticated(self) -> RequestAuthorizationBuilder<A> {
        self.policy(AccessPolicy::Authenticated)
    }

    /// Requires an exact authority name, without adding a prefix.
    pub fn has_authority(self, authority: impl Into<String>) -> RequestAuthorizationBuilder<A> {
        self.policy(AccessPolicy::HasAuthority(authority.into()))
    }

    /// Requires at least one authority. An empty collection grants no access.
    pub fn has_any_authority<I, S>(self, authorities: I) -> RequestAuthorizationBuilder<A>
    where
        I: IntoIterator<Item = S>,
        S: Into<String>,
    {
        self.policy(AccessPolicy::HasAnyAuthority(
            authorities.into_iter().map(Into::into).collect(),
        ))
    }

    /// Requires an authenticated identity with every listed authority.
    /// An empty collection requires authentication but no specific authority.
    pub fn has_all_authorities<I, S>(self, authorities: I) -> RequestAuthorizationBuilder<A>
    where
        I: IntoIterator<Item = S>,
        S: Into<String>,
    {
        self.policy(AccessPolicy::HasAllAuthorities(
            authorities.into_iter().map(Into::into).collect(),
        ))
    }
}

impl<A: HasAuthorities + Send + Sync> AuthorizationProvider for RequestAuthorizationProvider<A> {
    type Authentication = A;
    type Context = RequestContext;
    type Error = Infallible;

    fn authorize<'a>(
        &'a self,
        authentication: Option<&'a A>,
        context: RequestContext,
    ) -> Pin<Box<dyn Future<Output = Result<AuthorizationDecision, Infallible>> + Send + 'a>> {
        Box::pin(async move {
            let policy = self
                .rules
                .iter()
                .find(|rule| {
                    rule.method
                        .as_ref()
                        .is_none_or(|method| method == context.method)
                        && rule.path.matches(context.uri.path())
                })
                .map(|rule| &rule.policy);
            let allowed = match policy {
                Some(AccessPolicy::PermitAll) => true,
                Some(AccessPolicy::Authenticated) => authentication.is_some(),
                Some(AccessPolicy::HasAuthority(authority)) => {
                    authentication.is_some_and(|a| a.has_authority(authority))
                }
                Some(AccessPolicy::HasAnyAuthority(authorities)) => {
                    authentication.is_some_and(|a| {
                        authorities
                            .iter()
                            .any(|authority| a.has_authority(authority))
                    })
                }
                Some(AccessPolicy::HasAllAuthorities(authorities)) => {
                    authentication.is_some_and(|a| {
                        authorities
                            .iter()
                            .all(|authority| a.has_authority(authority))
                    })
                }
                Some(AccessPolicy::DenyAll) | None => false,
            };
            Ok(if allowed {
                AuthorizationDecision::Allow
            } else {
                AuthorizationDecision::Deny(if authentication.is_none() {
                    AuthorizationDenial::AuthenticationRequired
                } else {
                    AuthorizationDenial::InsufficientPermissions
                })
            })
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::basic::Authority;

    async fn decision(
        provider: &RequestAuthorizationProvider<UserDetail>,
        user: Option<&UserDetail>,
        method: Method,
        uri: &str,
    ) -> AuthorizationDecision {
        provider
            .authorize(
                user,
                RequestContext {
                    method,
                    uri: uri.parse().unwrap(),
                },
            )
            .await
            .unwrap()
    }

    #[tokio::test]
    async fn ordered_policies_and_identity_requirements() {
        let provider = RequestAuthorizationProvider::<UserDetail>::builder()
            .request_matchers("/public")
            .permit_all()
            .request_matchers("/admin/{*rest}")
            .has_authority("ADMIN")
            .method_matchers(Method::GET, "/notes/{id}")
            .has_any_authority(["ReadNote", "ReadAnyNote"])
            .request_matchers("/private")
            .authenticated()
            .any_request()
            .deny_all()
            .build()
            .unwrap();
        let reader = UserDetail::new("reader", "hash", vec![Authority::new("ReadNote")]);
        let admin = UserDetail::new("admin", "hash", vec![Authority::new("ADMIN")]);
        let allow = AuthorizationDecision::Allow;
        let forbidden = AuthorizationDecision::Deny(AuthorizationDenial::InsufficientPermissions);
        let unauthorized = AuthorizationDecision::Deny(AuthorizationDenial::AuthenticationRequired);
        assert_eq!(
            decision(&provider, None, Method::GET, "/public").await,
            allow
        );
        assert_eq!(
            decision(&provider, None, Method::GET, "/private").await,
            unauthorized
        );
        assert_eq!(
            decision(&provider, Some(&reader), Method::GET, "/private").await,
            allow
        );
        assert_eq!(
            decision(&provider, Some(&reader), Method::GET, "/admin/a").await,
            forbidden
        );
        assert_eq!(
            decision(&provider, Some(&admin), Method::GET, "/admin/dashboard").await,
            allow
        );
        assert_eq!(
            decision(&provider, Some(&reader), Method::GET, "/notes/1?q=x").await,
            allow
        );
        assert_eq!(
            decision(&provider, Some(&reader), Method::DELETE, "/notes/1").await,
            forbidden
        );
        assert_eq!(
            decision(&provider, Some(&admin), Method::GET, "/unknown").await,
            forbidden
        );
    }

    #[tokio::test]
    async fn first_match_is_final_and_unmatched_requests_are_denied() {
        let user = UserDetail::new("user", "hash", vec![]);
        let provider = RequestAuthorizationProvider::builder()
            .request_matchers("/blocked")
            .deny_all()
            .any_request()
            .permit_all()
            .build()
            .unwrap();
        assert_eq!(
            decision(&provider, Some(&user), Method::GET, "/blocked").await,
            AuthorizationDecision::Deny(AuthorizationDenial::InsufficientPermissions)
        );
        assert_eq!(
            decision(&provider, None, Method::GET, "/").await,
            AuthorizationDecision::Allow
        );
        let overlapping = RequestAuthorizationProvider::builder()
            .request_matchers("/notes/{*rest}")
            .deny_all()
            .request_matchers("/notes/public")
            .permit_all()
            .build()
            .unwrap();
        assert_eq!(
            decision(&overlapping, Some(&user), Method::GET, "/notes/public").await,
            AuthorizationDecision::Deny(AuthorizationDenial::InsufficientPermissions)
        );
        let empty = RequestAuthorizationProvider::builder().build().unwrap();
        assert_eq!(
            decision(&empty, None, Method::GET, "/anything").await,
            AuthorizationDecision::Deny(AuthorizationDenial::AuthenticationRequired)
        );
    }

    #[tokio::test]
    async fn all_authorities_requires_authentication_and_every_authority() {
        let provider = RequestAuthorizationProvider::builder()
            .request_matchers("/notes")
            .has_all_authorities(["ReadNote", "WriteNote"])
            .request_matchers("/empty")
            .has_all_authorities(Vec::<String>::new())
            .build()
            .unwrap();
        let reader = UserDetail::new("reader", "hash", vec![Authority::new("ReadNote")]);
        let editor = UserDetail::new(
            "editor",
            "hash",
            vec![Authority::new("ReadNote"), Authority::new("WriteNote")],
        );
        let writer = UserDetail::new("writer", "hash", vec![Authority::new("WriteNote")]);
        let no_authorities = UserDetail::new("user", "hash", vec![]);
        for user in [&reader, &writer, &no_authorities] {
            assert_eq!(
                decision(&provider, Some(user), Method::GET, "/notes").await,
                AuthorizationDecision::Deny(AuthorizationDenial::InsufficientPermissions)
            );
        }
        assert_eq!(
            decision(&provider, Some(&editor), Method::GET, "/notes").await,
            AuthorizationDecision::Allow
        );
        for path in ["/notes", "/empty"] {
            assert_eq!(
                decision(&provider, None, Method::GET, path).await,
                AuthorizationDecision::Deny(AuthorizationDenial::AuthenticationRequired)
            );
        }
        assert_eq!(
            decision(&provider, Some(&no_authorities), Method::GET, "/empty").await,
            AuthorizationDecision::Allow
        );
    }

    #[test]
    fn patterns_have_segment_boundaries_and_validate_at_build_time() {
        for (pattern, path, expected) in [
            ("/{*rest}", "/", false),
            ("/notes/{*rest}", "/notes", false),
            ("/notes/{*rest}", "/notes/", false),
            ("/notes/{*rest}", "/notes/1/a", true),
            ("/notes/{*rest}", "/notes-other", false),
            ("/notes/{id}", "/notes/", false),
            ("/notes/{id}", "/notes/1/a", false),
            ("/notes/{id}", "/notes/1/", false),
            ("/", "/", true),
            ("/notes", "/notes/", false),
            ("/Notes", "/notes", false),
        ] {
            assert_eq!(
                RequestPathMatcher::compile(Some(pattern.to_owned()))
                    .unwrap()
                    .matches(path),
                expected,
                "{pattern}: {path}"
            );
        }
        for pattern in [
            "notes",
            "/notes/{*rest}/child",
            "/notes/{}",
            "/notes/{id",
            "/notes?q=1",
        ] {
            assert!(
                RequestAuthorizationProvider::<UserDetail>::builder()
                    .request_matchers(pattern)
                    .permit_all()
                    .build()
                    .is_err(),
                "{pattern}"
            );
        }
    }
}
