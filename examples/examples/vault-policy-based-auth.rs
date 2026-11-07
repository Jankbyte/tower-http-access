//! Vault-inspired token policies with one protected zone: `/secret/team`.
//! This is an in-memory demonstration, not a Vault client or policy-language implementation.
//! Policies grant HTTP methods on path patterns; grants from all bound policies are combined.
//! A trailing `/**` matches nonempty descendants, excluding the base path and trailing slash.
//! Patterns are compiled with matchit when policy records are loaded.
//! Unknown policies grant nothing. Tokens are demonstration values; use HTTPS in deployment.
//!
//! ```sh
//! cargo run -p tower-http-access-examples --example vault-policy-based-auth
//! # 200: {"identity":"alice","path":"/secret/team","policies":["team-reader"]}
//! curl -H 'X-Vault-Token: alice-token' http://127.0.0.1:3000/secret/team
//! # 200: POST is also granted by the policy
//! curl -X POST -H 'X-Vault-Token: alice-token' http://127.0.0.1:3000/secret/team
//! # 403: DELETE is not granted
//! curl -i -X DELETE -H 'X-Vault-Token: alice-token' http://127.0.0.1:3000/secret/team
//! # 403: a valid token with no policy granting this zone
//! curl -i -H 'X-Vault-Token: bob-token' http://127.0.0.1:3000/secret/team
//! # 401: missing or unknown token
//! curl -i http://127.0.0.1:3000/secret/team
//! curl -i -H 'X-Vault-Token: unknown' http://127.0.0.1:3000/secret/team
//! ```
use axum::{Json, Router, extract::OriginalUri, http::request::Parts, routing::any};
use futures_util::future::BoxFuture;
use serde::{Deserialize, Serialize};
use std::{collections::HashMap, convert::Infallible, sync::Arc};
use tower_http_access::{
    SecurityLayer,
    authentication::{
        Authenticated, AuthenticationAttempt, AuthenticationErrorReason, AuthenticatorError,
        RequestAuthenticator,
    },
    authorization::{AuthorizationDecision, AuthorizationDenial, AuthorizationProvider},
    request_matchers::{PathPatternRequestMatcher, RequestMatcher},
};

const ZONE: &str = "/secret/team";

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:3000").await?;
    axum::serve(listener, create_app()).await?;
    Ok(())
}

/// Authentication carries the token to authorization without exposing it in responses.
#[derive(Clone)]
struct Token(String);

#[derive(Clone)]
struct TokenBinding {
    identity: String,
    policies: Vec<String>,
}

/// Owned records can be deserialized from a database document.
#[derive(Deserialize)]
struct Policy {
    name: String,
    paths: Vec<PathPolicy>,
}

#[derive(Deserialize)]
#[serde(try_from = "PathPolicyRecord")]
struct PathPolicy {
    matcher: PathPatternRequestMatcher,
    capabilities: Vec<String>,
}

#[derive(Deserialize)]
struct PathPolicyRecord {
    path: String,
    capabilities: Vec<String>,
}

impl TryFrom<PathPolicyRecord> for PathPolicy {
    type Error = String;

    fn try_from(record: PathPolicyRecord) -> Result<Self, Self::Error> {
        // Accept the familiar /** suffix as an alias for matchit's catch-all.
        let pattern = match record.path.strip_suffix("/**") {
            Some(prefix) => format!("{prefix}/{{*policy_rest}}"),
            None => record.path,
        };
        let matcher = PathPatternRequestMatcher::new(pattern).map_err(|error| error.to_string())?;
        Ok(Self {
            matcher,
            capabilities: record.capabilities,
        })
    }
}

impl Policy {
    fn allows(&self, request: &Parts) -> bool {
        self.paths.iter().any(|rule| {
            rule.matcher.matches(request)
                && rule
                    .capabilities
                    .iter()
                    .any(|method| method == request.method.as_str())
        })
    }
}

struct PolicyStore {
    tokens: HashMap<String, TokenBinding>,
    policies: HashMap<String, Policy>,
}

#[derive(Clone)]
struct TokenAuthenticator(Arc<PolicyStore>);

impl RequestAuthenticator for TokenAuthenticator {
    type Authentication = Token;

    fn authenticate<'a>(
        &'a self,
        request: &'a mut Parts,
    ) -> BoxFuture<'a, Result<AuthenticationAttempt<Token>, AuthenticatorError>> {
        Box::pin(async move {
            let Some(header) = request.headers.get("x-vault-token") else {
                return Ok(AuthenticationAttempt::NotApplicable);
            };
            let invalid = || AuthenticatorError::new(AuthenticationErrorReason::WrongCredentials);
            let token = header.to_str().map_err(|_| invalid())?;
            if !self.0.tokens.contains_key(token) {
                return Err(invalid());
            }
            Ok(AuthenticationAttempt::Authenticated(Token(
                token.to_owned(),
            )))
        })
    }
}

#[derive(Clone)]
struct ZoneAuthorizer(Arc<PolicyStore>);

impl AuthorizationProvider for ZoneAuthorizer {
    type Authentication = Token;
    type Error = Infallible;

    fn authorize<'a>(
        &'a self,
        token: Option<&'a Token>,
        request: &'a Parts,
    ) -> BoxFuture<'a, Result<AuthorizationDecision, Infallible>> {
        Box::pin(async move {
            let Some(binding) = token.and_then(|token| self.0.tokens.get(token.0.as_str())) else {
                return Ok(AuthorizationDecision::Deny(
                    AuthorizationDenial::AuthenticationRequired,
                ));
            };
            // A single bound policy must grant both the path and method.
            // Grants from different policies cannot be combined across these checks.
            let allowed = binding.policies.iter().any(|name| {
                self.0
                    .policies
                    .get(name.as_str())
                    .is_some_and(|policy| policy.allows(request))
            });
            Ok(if allowed {
                AuthorizationDecision::Allow
            } else {
                AuthorizationDecision::Deny(AuthorizationDenial::InsufficientPermissions)
            })
        })
    }
}

#[derive(Serialize)]
struct ZoneResponse {
    identity: String,
    path: String,
    policies: Vec<String>,
}

async fn read_zone(
    axum::extract::State(store): axum::extract::State<Arc<PolicyStore>>,
    Authenticated(token): Authenticated<Token>,
    OriginalUri(uri): OriginalUri,
) -> Json<ZoneResponse> {
    // The immutable store is shared with authentication and authorization.
    let binding = &store.tokens[token.0.as_str()];
    Json(ZoneResponse {
        identity: binding.identity.clone(),
        path: uri.path().to_owned(),
        policies: binding.policies.clone(),
    })
}

fn create_app() -> Router {
    let store = Arc::new(PolicyStore {
        tokens: HashMap::from([
            (
                "alice-token".into(),
                TokenBinding {
                    identity: "alice".into(),
                    policies: vec!["team-reader".into()],
                },
            ),
            (
                "bob-token".into(),
                TokenBinding {
                    identity: "bob".into(),
                    policies: vec!["other-reader".into()],
                },
            ),
        ]),
        // Seed documents stand in for records loaded from a database.
        // Equivalent rule: path "/secret/team" { capabilities = ["GET", "POST"] }
        policies: serde_json::from_str::<Vec<Policy>>(
            r#"[
            {
                "name": "team-reader",
                "paths": [
                    {"path": "/secret/team", "capabilities": ["GET", "POST"]},
                    {"path": "/secret/team/**", "capabilities": ["GET"]},
                    {"path": "/secret/other", "capabilities": ["DELETE"]}
                ]
            },
            {
                "name": "other-reader",
                "paths": [
                    {"path": "/secret/other", "capabilities": ["DELETE"]}
                ]
            }
        ]"#,
        )
        .expect("valid policy seed documents")
        .into_iter()
        .map(|policy| (policy.name.clone(), policy))
        .collect(),
    });
    let security = SecurityLayer::new(
        TokenAuthenticator(Arc::clone(&store)),
        ZoneAuthorizer(Arc::clone(&store)),
    );
    Router::new()
        // Let the policy decide which methods can reach the handler.
        .route(ZONE, any(read_zone))
        .route("/secret/team/{*rest}", any(read_zone))
        .route_layer(security)
        .with_state(store)
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::{
        body::{Body, to_bytes},
        http::{Method, Request, StatusCode},
    };
    use tower::ServiceExt;

    #[test]
    fn policy_patterns_match_descendants_and_keep_method_grants_scoped() {
        let policy: Policy = serde_json::from_str(
            r#"{
            "name": "nested", "paths": [
                {"path": "/secret/team/**", "capabilities": ["GET"]},
                {"path": "/secret/other", "capabilities": ["POST"]}
            ]
        }"#,
        )
        .unwrap();
        for (path, method, allowed) in [
            ("/secret/team/foo", Method::GET, true),
            ("/secret/team/foo/bar", Method::GET, true),
            ("/secret/team/foo?version=1", Method::GET, true),
            ("/secret/team", Method::GET, false),
            ("/secret/team/", Method::GET, false),
            ("/secret/teammate/foo", Method::GET, false),
            ("/secret/team/foo", Method::POST, false),
        ] {
            let (parts, _) = Request::builder()
                .uri(path)
                .method(method)
                .body(())
                .unwrap()
                .into_parts();
            assert_eq!(policy.allows(&parts), allowed, "path: {path}");
        }
        assert!(
            serde_json::from_str::<Policy>(
                r#"{
            "name": "invalid", "paths": [{"path": "/bad/{", "capabilities": ["GET"]}]
        }"#
            )
            .is_err()
        );
    }

    #[tokio::test]
    async fn token_policies_control_zone_access() {
        for (method, token, expected) in [
            (Method::GET, Some("alice-token"), StatusCode::OK),
            (Method::POST, Some("alice-token"), StatusCode::OK),
            (Method::DELETE, Some("alice-token"), StatusCode::FORBIDDEN),
            (Method::HEAD, Some("alice-token"), StatusCode::FORBIDDEN),
            (Method::DELETE, Some("bob-token"), StatusCode::FORBIDDEN),
            (Method::GET, Some("bob-token"), StatusCode::FORBIDDEN),
            (Method::GET, Some("unknown"), StatusCode::UNAUTHORIZED),
            (Method::GET, None, StatusCode::UNAUTHORIZED),
        ] {
            let mut request = Request::builder().method(method.clone()).uri(ZONE);
            if let Some(token) = token {
                request = request.header("x-vault-token", token);
            }
            let response = create_app()
                .oneshot(request.body(Body::empty()).unwrap())
                .await
                .unwrap();
            assert_eq!(
                response.status(),
                expected,
                "method: {method}, token: {token:?}"
            );
            if expected == StatusCode::OK {
                let body = to_bytes(response.into_body(), 1024).await.unwrap();
                assert_eq!(
                    serde_json::from_slice::<serde_json::Value>(&body).unwrap(),
                    serde_json::json!({
                        "identity": "alice", "path": ZONE, "policies": ["team-reader"]
                    })
                );
            }
        }
    }
}
