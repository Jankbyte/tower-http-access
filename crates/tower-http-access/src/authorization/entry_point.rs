//! Request-based selection of authentication entry points.

use super::AuthenticationEntryPoint;
use crate::{SecurityResponse, request_matcher::RequestMatcher};
use http::request::Parts;
use std::sync::Arc;

type Entry = (Arc<dyn RequestMatcher>, Arc<dyn AuthenticationEntryPoint>);

/// Selects the first matching entry point, or an explicitly configured fallback.
///
/// Available with `request_matcher`. This selects only the response when
/// authentication is required; it does not authenticate or select middleware.
/// For example, match HTML requests to a login redirect and use
/// [`DefaultAuthenticationEntryPoint`](super::DefaultAuthenticationEntryPoint)
/// as the fallback for REST requests.
#[derive(Clone)]
pub struct DelegatingAuthenticationEntryPoint {
    entries: Vec<Entry>,
    fallback: Arc<dyn AuthenticationEntryPoint>,
}

/// Registers entry points in declaration order.
#[derive(Default)]
pub struct DelegatingAuthenticationEntryPointBuilder {
    entries: Vec<Entry>,
}

impl DelegatingAuthenticationEntryPoint {
    pub fn builder() -> DelegatingAuthenticationEntryPointBuilder {
        DelegatingAuthenticationEntryPointBuilder::default()
    }
}

impl DelegatingAuthenticationEntryPointBuilder {
    /// Register a response strategy. The first matching entry is final.
    pub fn entry_point<M, E>(mut self, matcher: M, entry_point: E) -> Self
    where
        M: RequestMatcher + 'static,
        E: AuthenticationEntryPoint,
    {
        self.entries
            .push((Arc::new(matcher), Arc::new(entry_point)));
        self
    }

    /// Complete configuration with an explicit fallback.
    pub fn fallback<E: AuthenticationEntryPoint>(
        self,
        fallback: E,
    ) -> DelegatingAuthenticationEntryPoint {
        DelegatingAuthenticationEntryPoint {
            entries: self.entries,
            fallback: Arc::new(fallback),
        }
    }
}

impl AuthenticationEntryPoint for DelegatingAuthenticationEntryPoint {
    fn commence(&self, request: &Parts) -> SecurityResponse {
        self.entries
            .iter()
            .find(|(matcher, _)| matcher.matches(request))
            .map_or(&self.fallback, |(_, entry)| entry)
            .commence(request)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        authorization::DefaultAuthenticationEntryPoint, request_matcher::PathPatternRequestMatcher,
    };
    use http::{Request, StatusCode};

    #[test]
    fn first_match_is_final_and_preserves_the_selected_response() {
        let entry_point = DelegatingAuthenticationEntryPoint::builder()
            .entry_point(
                PathPatternRequestMatcher::new("/html/{*rest}").unwrap(),
                |_: &Parts| {
                    let mut response = SecurityResponse::new("login".into());
                    *response.status_mut() = StatusCode::FOUND;
                    response
                        .headers_mut()
                        .insert("location", "/login".parse().unwrap());
                    response.extensions_mut().insert(42_u32);
                    response
                },
            )
            .entry_point(
                PathPatternRequestMatcher::new("/html/private").unwrap(),
                |_: &Parts| -> SecurityResponse { panic!("later entry point must not execute") },
            )
            .fallback(DefaultAuthenticationEntryPoint);
        for (path, status) in [
            ("/html/private", StatusCode::FOUND),
            ("/api/private", StatusCode::UNAUTHORIZED),
        ] {
            let (parts, _) = Request::builder().uri(path).body(()).unwrap().into_parts();
            let response = entry_point.clone().commence(&parts);
            assert_eq!(response.status(), status);
            if status == StatusCode::FOUND {
                assert_eq!(response.headers()["location"], "/login");
                assert_eq!(response.body(), "login");
                assert_eq!(response.extensions().get::<u32>(), Some(&42));
            }
        }
        let (parts, _) = Request::new(()).into_parts();
        assert_eq!(
            DelegatingAuthenticationEntryPoint::builder()
                .fallback(DefaultAuthenticationEntryPoint)
                .commence(&parts)
                .status(),
            StatusCode::UNAUTHORIZED
        );
    }
}
