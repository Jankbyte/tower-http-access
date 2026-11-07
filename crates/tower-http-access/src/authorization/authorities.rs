//! Reusable authority checks independent of authentication schemes and request matching.

use super::default_auth::denied;
use super::{AuthorizationDecision, AuthorizationProvider};
use futures_util::future::BoxFuture;
use http::request::Parts;
use std::{convert::Infallible, marker::PhantomData};

/// An identity whose authorities can be checked by authorization providers.
pub trait HasAuthorities {
    /// Check an exact authority name, without adding a prefix.
    fn has_authority(&self, authority: &str) -> bool;
}

/// Requires authentication and one exact authority.
pub struct AuthorityAuthorizationProvider<A> {
    authority: String,
    identity: PhantomData<fn() -> A>,
}

impl<A> AuthorityAuthorizationProvider<A> {
    /// Configure the required authority names.
    pub fn new(authority: impl Into<String>) -> Self {
        Self {
            authority: authority.into(),
            identity: PhantomData,
        }
    }
}

impl<A: HasAuthorities + Send + Sync> AuthorizationProvider for AuthorityAuthorizationProvider<A> {
    type Authentication = A;
    type Error = Infallible;

    fn authorize<'a>(
        &'a self,
        authentication: Option<&'a A>,
        _: &'a Parts,
    ) -> BoxFuture<'a, Result<AuthorizationDecision, Infallible>> {
        Box::pin(async move {
            Ok(
                if authentication.is_some_and(|identity| identity.has_authority(&self.authority)) {
                    AuthorizationDecision::Allow
                } else {
                    denied(authentication)
                },
            )
        })
    }
}

/// Requires authentication and at least one listed authority. An empty list always denies access.
pub struct AnyAuthorityAuthorizationProvider<A> {
    authorities: Vec<String>,
    identity: PhantomData<fn() -> A>,
}

impl<A> AnyAuthorityAuthorizationProvider<A> {
    /// Configure the required authority names.
    pub fn new<I, S>(authorities: I) -> Self
    where
        I: IntoIterator<Item = S>,
        S: Into<String>,
    {
        Self {
            authorities: authorities.into_iter().map(Into::into).collect(),
            identity: PhantomData,
        }
    }
}

impl<A: HasAuthorities + Send + Sync> AuthorizationProvider
    for AnyAuthorityAuthorizationProvider<A>
{
    type Authentication = A;
    type Error = Infallible;

    fn authorize<'a>(
        &'a self,
        authentication: Option<&'a A>,
        _: &'a Parts,
    ) -> BoxFuture<'a, Result<AuthorizationDecision, Infallible>> {
        Box::pin(async move {
            Ok(
                if authentication.is_some_and(|identity| {
                    self.authorities
                        .iter()
                        .any(|authority| identity.has_authority(authority))
                }) {
                    AuthorizationDecision::Allow
                } else {
                    denied(authentication)
                },
            )
        })
    }
}

/// Requires authentication and every listed authority. An empty list allows any authenticated identity.
pub struct AllAuthoritiesAuthorizationProvider<A> {
    authorities: Vec<String>,
    identity: PhantomData<fn() -> A>,
}

impl<A> AllAuthoritiesAuthorizationProvider<A> {
    /// Configure the required authority names.
    pub fn new<I, S>(authorities: I) -> Self
    where
        I: IntoIterator<Item = S>,
        S: Into<String>,
    {
        Self {
            authorities: authorities.into_iter().map(Into::into).collect(),
            identity: PhantomData,
        }
    }
}

impl<A: HasAuthorities + Send + Sync> AuthorizationProvider
    for AllAuthoritiesAuthorizationProvider<A>
{
    type Authentication = A;
    type Error = Infallible;

    fn authorize<'a>(
        &'a self,
        authentication: Option<&'a A>,
        _: &'a Parts,
    ) -> BoxFuture<'a, Result<AuthorizationDecision, Infallible>> {
        Box::pin(async move {
            Ok(
                if authentication.is_some_and(|identity| {
                    self.authorities
                        .iter()
                        .all(|authority| identity.has_authority(authority))
                }) {
                    AuthorizationDecision::Allow
                } else {
                    denied(authentication)
                },
            )
        })
    }
}

#[cfg(test)]
#[path = "authorities_tests.rs"]
mod tests;

impl<A> Clone for AuthorityAuthorizationProvider<A> {
    fn clone(&self) -> Self {
        Self {
            authority: self.authority.clone(),
            identity: PhantomData,
        }
    }
}

impl<A> Clone for AnyAuthorityAuthorizationProvider<A> {
    fn clone(&self) -> Self {
        Self {
            authorities: self.authorities.clone(),
            identity: PhantomData,
        }
    }
}

impl<A> Clone for AllAuthoritiesAuthorizationProvider<A> {
    fn clone(&self) -> Self {
        Self {
            authorities: self.authorities.clone(),
            identity: PhantomData,
        }
    }
}
