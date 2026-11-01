use super::{AuthorizationDecision, AuthorizationDenial, AuthorizationProvider};
use axum::http::request::Parts;
use futures_util::future::BoxFuture;
use std::{convert::Infallible, future::Future, marker::PhantomData, pin::Pin};

/// Default implementation of [`AuthorizationProvider`], that checks only fact of authentication
/// and does not inspect request metadata.
///
/// The behavior of implementation:
///
/// * If authentication found - request authorized.
/// * Otherwise, it's return [`AuthorizationDecision::Deny`] with [`AuthorizationDenial::AuthenticationRequired`], that equivalent to *401*.
///
pub struct AuthenticatedAuthorizationProvider<A>(PhantomData<fn() -> A>);

impl<A> AuthenticatedAuthorizationProvider<A> {
    pub fn new() -> Self {
        Self(PhantomData)
    }
}

impl<A> Default for AuthenticatedAuthorizationProvider<A> {
    fn default() -> Self {
        Self::new()
    }
}

impl<A> AuthorizationProvider for AuthenticatedAuthorizationProvider<A>
where
    A: Send + Sync,
{
    type Authentication = A;
    type Error = Infallible;

    fn authorize<'a>(
        &'a self,
        authentication: Option<&'a Self::Authentication>,
        _: &'a Parts,
    ) -> Pin<Box<dyn Future<Output = Result<AuthorizationDecision, Self::Error>> + Send + 'a>> {
        Box::pin(async move {
            Ok(match authentication {
                Some(_) => AuthorizationDecision::Allow,
                None => AuthorizationDecision::Deny(AuthorizationDenial::AuthenticationRequired),
            })
        })
    }
}

// Keep the existing distinction between anonymous and authenticated denials.
pub(super) fn denied<A>(authentication: Option<&A>) -> AuthorizationDecision {
    AuthorizationDecision::Deny(if authentication.is_none() {
        AuthorizationDenial::AuthenticationRequired
    } else {
        AuthorizationDenial::InsufficientPermissions
    })
}

/// Allows every request, including anonymous requests.
pub struct PermitAllAuthorizationProvider<A>(PhantomData<fn() -> A>);

impl<A> PermitAllAuthorizationProvider<A> {
    /// Create the provider.
    pub fn new() -> Self {
        Self(PhantomData)
    }
}

impl<A> Default for PermitAllAuthorizationProvider<A> {
    fn default() -> Self {
        Self::new()
    }
}

impl<A: Send + Sync> AuthorizationProvider for PermitAllAuthorizationProvider<A> {
    type Authentication = A;
    type Error = Infallible;

    fn authorize<'a>(
        &'a self,
        _authentication: Option<&'a A>,
        _: &'a Parts,
    ) -> BoxFuture<'a, Result<AuthorizationDecision, Infallible>> {
        Box::pin(async move { Ok(AuthorizationDecision::Allow) })
    }
}

/// Denies every request. Anonymous callers require authentication; authenticated callers lack permissions.
pub struct DenyAllAuthorizationProvider<A>(PhantomData<fn() -> A>);

impl<A> DenyAllAuthorizationProvider<A> {
    /// Create the provider.
    pub fn new() -> Self {
        Self(PhantomData)
    }
}

impl<A> Default for DenyAllAuthorizationProvider<A> {
    fn default() -> Self {
        Self::new()
    }
}

impl<A: Send + Sync> AuthorizationProvider for DenyAllAuthorizationProvider<A> {
    type Authentication = A;
    type Error = Infallible;

    fn authorize<'a>(
        &'a self,
        authentication: Option<&'a A>,
        _: &'a Parts,
    ) -> BoxFuture<'a, Result<AuthorizationDecision, Infallible>> {
        Box::pin(async move { Ok(denied(authentication)) })
    }
}
