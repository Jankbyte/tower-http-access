//! Axum extractor implementations for authenticated identities.

use super::Authenticated;
use ::axum::{
    Extension,
    extract::{FromRequestParts, OptionalFromRequestParts, rejection::ExtensionRejection},
    http::request::Parts,
};

impl<S, A> FromRequestParts<S> for Authenticated<A>
where
    S: Send + Sync,
    A: Clone + Send + Sync + 'static,
{
    type Rejection = ExtensionRejection;

    async fn from_request_parts(parts: &mut Parts, state: &S) -> Result<Self, Self::Rejection> {
        <Extension<Self> as FromRequestParts<S>>::from_request_parts(parts, state)
            .await
            .map(|Extension(authentication)| authentication)
    }
}

impl<S, A> OptionalFromRequestParts<S> for Authenticated<A>
where
    S: Send + Sync,
    A: Clone + Send + Sync + 'static,
{
    type Rejection = std::convert::Infallible;

    async fn from_request_parts(parts: &mut Parts, _: &S) -> Result<Option<Self>, Self::Rejection> {
        Ok(parts.extensions.get::<Self>().cloned())
    }
}

#[cfg(test)]
#[path = "axum_tests.rs"]
mod tests;
