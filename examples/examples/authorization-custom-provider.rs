//! Authorize requests using the connection's peer IP, independently of authentication.
//!
//! ```sh
//! cargo run --package tower-http-access-examples --example authorization-custom-provider
//! # 200: the connection comes from the allowed loopback address.
//! curl -v http://127.0.0.1:3000/private
//! curl -v http://10.0.0.10:3000/private
//! ```
//! `ConnectInfo` must be installed outside the security middleware. Forwarded headers
//! are deliberately ignored: the peer address comes from the server connection.
use axum::{
    Router,
    extract::ConnectInfo,
    http::{StatusCode, header, request::Parts},
    routing::get,
};
use futures_util::future::BoxFuture;
use std::{
    convert::Infallible,
    net::{IpAddr, Ipv4Addr, SocketAddr},
};
use tower_http_access::SecurityResponse;
use tower_http_access::authorization::{
    AuthorizationDecision, AuthorizationDenial, AuthorizationLayer, AuthorizationProvider,
    PendingRuleBuilder, RequestAuthorizationBuilder, RequestAuthorizationProvider,
};

#[tokio::main(flavor = "current_thread")]
async fn main() -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let listener = tokio::net::TcpListener::bind("0.0.0.0:3000").await?;
    axum::serve(
        listener,
        create_app().into_make_service_with_connect_info::<SocketAddr>(),
    )
    .await?;
    Ok(())
}

fn create_app() -> Router {
    let authorizer = RequestAuthorizationProvider::<()>::builder()
        .request_matchers("/private")
        .ip_matches(IpAddr::V4(Ipv4Addr::LOCALHOST))
        .any_request()
        .deny_all()
        .build()
        .expect("valid request patterns");

    Router::new()
        .route("/private", get(|| async { "Your IP is allowed.\n" }))
        // In this example, we dont need authentication, so we can just use
        // only `AuthorizationLayer`
        .route_layer(AuthorizationLayer::builder(authorizer).build())
}

/// Extend the library's builder through its public API, without accessing its fields.
trait IpAuthorizationExt {
    /// Require the connection's peer IP to match. A mismatch returns 403.
    fn ip_matches(self, allowed_ip: IpAddr) -> RequestAuthorizationBuilder<()>;
}

impl IpAuthorizationExt for PendingRuleBuilder<()> {
    fn ip_matches(self, allowed_ip: IpAddr) -> RequestAuthorizationBuilder<()> {
        self.access(IpMatchingAuthorizationProvider::new(allowed_ip))
    }
}

/// An IP restriction, not a rule selector: a mismatch denies access rather than
/// falling through to another rule. Anonymous callers may pass this policy.
struct IpMatchingAuthorizationProvider {
    allowed_ip: IpAddr,
}

impl IpMatchingAuthorizationProvider {
    fn new(allowed_ip: IpAddr) -> Self {
        Self { allowed_ip }
    }
}

impl AuthorizationProvider for IpMatchingAuthorizationProvider {
    type Authentication = ();
    type Error = Infallible;

    fn authorize<'a>(
        &'a self,
        _: Option<&'a Self::Authentication>,
        request: &'a Parts,
    ) -> BoxFuture<'a, Result<AuthorizationDecision, Self::Error>> {
        Box::pin(async move {
            let peer_ip = request
                .extensions
                .get::<ConnectInfo<SocketAddr>>()
                .map(|ConnectInfo(peer)| peer.ip());

            if peer_ip == Some(self.allowed_ip) {
                return Ok(AuthorizationDecision::Allow);
            }

            let message = match peer_ip {
                Some(ip) => format!("Your IP ({ip}) not allowed"),
                None => "Your IP is unavailable; access denied".to_owned(),
            };
            let mut response = SecurityResponse::new(message.into());
            *response.status_mut() = StatusCode::FORBIDDEN;
            response.headers_mut().insert(
                header::CONTENT_TYPE,
                "text/plain; charset=utf-8".parse().unwrap(),
            );
            Ok(AuthorizationDecision::Deny(AuthorizationDenial::Custom(
                response,
            )))
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::{
        body::Body,
        http::{Request, StatusCode},
    };
    use tower::ServiceExt;

    #[tokio::test]
    async fn ip_policy_uses_connection_metadata_and_denies_missing_or_unmatched_peers() {
        for (peer, expected, expected_body) in [
            (
                Some("127.0.0.1:1234"),
                StatusCode::OK,
                "Your IP is allowed.\n",
            ),
            (
                Some("192.0.2.1:1234"),
                StatusCode::FORBIDDEN,
                "Your IP (192.0.2.1) not allowed",
            ),
            (
                None,
                StatusCode::FORBIDDEN,
                "Your IP is unavailable; access denied",
            ),
        ] {
            let mut request = Request::builder()
                .uri("/private")
                // Claiming an allowed address in a header must not bypass the policy.
                .header("x-forwarded-for", "127.0.0.1")
                .body(Body::empty())
                .unwrap();
            if let Some(peer) = peer {
                request
                    .extensions_mut()
                    .insert(ConnectInfo(peer.parse::<SocketAddr>().unwrap()));
            }
            let response = create_app().oneshot(request).await.unwrap();
            assert_eq!(response.status(), expected, "peer: {peer:?}");
            if expected == StatusCode::FORBIDDEN {
                assert_eq!(
                    response.headers()[header::CONTENT_TYPE],
                    "text/plain; charset=utf-8"
                );
            }
            let body = axum::body::to_bytes(response.into_body(), 1024)
                .await
                .unwrap();
            assert_eq!(body, expected_body, "peer: {peer:?}");
        }
    }
}
