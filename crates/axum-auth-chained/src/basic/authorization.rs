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
//! # Custom authorization managers
//!
//! Use `.access(manager)` to delegate a rule to an [`AuthorizationProvider`] with
//! the same identity type and [`RequestContext`]. The manager may perform async I/O
//! and decides how to handle anonymous callers. It receives the method and URI;
//! matched path parameters are not extracted into the context.
//!
//! ```rust
//! use std::{convert::Infallible, future::Future, pin::Pin};
//! use axum_auth_chained::{
//!     authorization::{AuthorizationDecision, AuthorizationDenial, AuthorizationProvider},
//!     basic::{RequestAuthorizationProvider, RequestContext, UserDetail},
//! };
//!
//! struct NamedUserManager;
//!
//! impl AuthorizationProvider for NamedUserManager {
//!     type Authentication = UserDetail;
//!     type Context = RequestContext;
//!     type Error = Infallible;
//!
//!     fn authorize<'a>(
//!         &'a self,
//!         user: Option<&'a UserDetail>,
//!         context: RequestContext,
//!     ) -> Pin<Box<dyn Future<Output = Result<AuthorizationDecision, Infallible>> + Send + 'a>> {
//!         Box::pin(async move {
//!             Ok(match user {
//!                 None => AuthorizationDecision::Deny(AuthorizationDenial::AuthenticationRequired),
//!                 Some(user) if user.username == "admin" => AuthorizationDecision::Allow,
//!                 Some(_) => AuthorizationDecision::Deny(AuthorizationDenial::InsufficientPermissions),
//!             })
//!         })
//!     }
//! }
//!
//! let provider = RequestAuthorizationProvider::<UserDetail>::builder()
//!     .request_matchers("/notes/{id}").access(NamedUserManager)
//!     .any_request().deny_all()
//!     .build()?;
//! # Ok::<(), axum_auth_chained::basic::InvalidRequestPattern>(())
//! ```
//!
//! Manager errors are wrapped in [`RequestAuthorizationError`], preserving the
//! original error as its source. The default failure handler returns HTTP 500.
//! Returning a denial or error stops evaluation, just as for built-in policies.
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

use std::{future::Future, marker::PhantomData, pin::Pin};

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

/// An error returned by a custom request authorization manager.
///
/// The original error is preserved as the source. The default authorization failure
/// handler returns HTTP 500 for these errors; denials remain authorization decisions.
#[derive(Debug, thiserror::Error)]
#[error("custom authorization manager failed")]
pub struct RequestAuthorizationError {
    #[source]
    source: Box<dyn std::error::Error + Send + Sync>,
}

type CustomManager<A> = Box<
    dyn AuthorizationProvider<
            Authentication = A,
            Context = RequestContext,
            Error = RequestAuthorizationError,
        >,
>;

struct CustomManagerAdapter<M>(M);

impl<M> AuthorizationProvider for CustomManagerAdapter<M>
where
    M: AuthorizationProvider<Context = RequestContext>,
    M::Error: 'static,
{
    type Authentication = M::Authentication;
    type Context = RequestContext;
    type Error = RequestAuthorizationError;

    fn authorize<'a>(
        &'a self,
        authentication: Option<&'a Self::Authentication>,
        context: RequestContext,
    ) -> Pin<Box<dyn Future<Output = Result<AuthorizationDecision, Self::Error>> + Send + 'a>> {
        Box::pin(async move {
            self.0
                .authorize(authentication, context)
                .await
                .map_err(|error| RequestAuthorizationError {
                    source: Box::new(error),
                })
        })
    }
}

enum AccessPolicy<A> {
    PermitAll,
    DenyAll,
    Authenticated,
    HasAuthority(String),
    HasAnyAuthority(Vec<String>),
    HasAllAuthorities(Vec<String>),
    Custom(CustomManager<A>),
}

struct Rule<A> {
    method: Option<Method>,
    path: RequestPathMatcher,
    policy: AccessPolicy<A>,
}

/// An ordered, first-match authorization provider. Unmatched requests are denied.
///
/// Declaration order determines priority, regardless of path specificity. The first
/// matching rule's decision is final. See the [module documentation](self) for an example.
pub struct RequestAuthorizationProvider<A> {
    rules: Vec<Rule<A>>,
    identity: PhantomData<fn() -> A>,
}

/// Builds an ordered list of request policies.
pub struct RequestAuthorizationBuilder<A> {
    rules: Vec<(Option<Method>, Option<String>, AccessPolicy<A>)>,
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
    fn policy(mut self, policy: AccessPolicy<A>) -> RequestAuthorizationBuilder<A> {
        self.builder.rules.push((self.method, self.path, policy));
        self.builder
    }

    /// Delegates the complete decision to a custom async authorization provider.
    ///
    /// The manager receives the optional identity and request method/URI, including
    /// for anonymous requests. It is responsible for deciding whether authentication
    /// is required. Only the first matching rule runs; errors and denials do not fall
    /// through to later rules. Errors retain their source in [`RequestAuthorizationError`].
    /// No authority check is added automatically.
    pub fn access<M>(self, manager: M) -> RequestAuthorizationBuilder<A>
    where
        M: AuthorizationProvider<Authentication = A, Context = RequestContext> + 'static,
        M::Error: 'static,
    {
        self.policy(AccessPolicy::Custom(Box::new(CustomManagerAdapter(
            manager,
        ))))
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
    type Error = RequestAuthorizationError;

    fn authorize<'a>(
        &'a self,
        authentication: Option<&'a A>,
        context: RequestContext,
    ) -> Pin<Box<dyn Future<Output = Result<AuthorizationDecision, Self::Error>> + Send + 'a>> {
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
                Some(AccessPolicy::Custom(manager)) => {
                    return manager.authorize(authentication, context).await;
                }
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
#[path = "authorization_tests.rs"]
mod tests;
