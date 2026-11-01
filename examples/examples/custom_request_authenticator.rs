//! Authenticate users by looking up the `Api-Key` header in an asynchronous repository.
//! These API keys are demonstration values.
//!
//! ```bash
//! cargo run --package axum-auth-chained-examples --example custom_request_authenticator
//! # Authenticated: Hello, alex!
//! curl -v -H 'Api-Key: alex-api-key' http://127.0.0.1:3000/hello
//! # Anonymous: Hello, anonymous!
//! curl -v http://127.0.0.1:3000/hello
//! # Invalid API key: 401 Unauthorized
//! curl -v -H 'Api-Key: unknown' http://127.0.0.1:3000/hello
//! ```
use axum::{Router, http::request::Parts, routing::get};
use axum_auth_chained::{
    SecurityLayer,
    authentication::{
        Authenticated, AuthenticationAttempt, AuthenticationErrorReason, AuthenticatorError,
        RequestAuthenticator,
    },
    authorization::AuthenticatedAuthorizationProvider,
};
use futures_util::future::BoxFuture;
use std::{collections::HashMap, sync::Arc};
use tokio::sync::RwLock;

#[tokio::main(flavor = "current_thread")]
async fn main() -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:3000").await?;
    axum::serve(listener, create_app()).await?;
    Ok(())
}

fn create_app() -> Router {
    let repository = UserApiKeyRepository {
        inner: Arc::new(RwLock::new(HashMap::from([(
            "alex-api-key".to_owned(),
            User {
                username: "alex".to_owned(),
            },
        )]))),
    };
    let authenticator = ApiKeyRequestAuthenticator { repository };
    let security = SecurityLayer::new(
        authenticator,
        AuthenticatedAuthorizationProvider::<User>::default(),
    );

    Router::new()
        .route("/hello", get(hello))
        .route_layer(security)
}

async fn hello(Authenticated(user): Authenticated<User>) -> String {
    format!("Hello, {}!", user.username)
}

#[derive(Clone)]
struct User {
    username: String,
}

struct UserApiKeyRepository {
    inner: Arc<RwLock<HashMap<String, User>>>,
}

impl UserApiKeyRepository {
    async fn find_by_key(&self, key: &str) -> Option<User> {
        let users = self.inner.read().await;
        users.get(key).cloned()
    }
}

struct ApiKeyRequestAuthenticator {
    repository: UserApiKeyRepository,
}

impl RequestAuthenticator for ApiKeyRequestAuthenticator {
    type Authentication = User;

    fn authenticate<'a>(
        &'a self,
        parts: &'a mut Parts,
    ) -> BoxFuture<'a, Result<AuthenticationAttempt<User>, AuthenticatorError>> {
        Box::pin(async move {
            let Some(header) = parts.headers.get("api-key") else {
                return Ok(AuthenticationAttempt::NotApplicable);
            };
            let token = header.to_str().map_err(|_| {
                AuthenticatorError::new(AuthenticationErrorReason::WrongCredentials)
            })?;
            self.repository
                .find_by_key(token)
                .await
                .map(AuthenticationAttempt::Authenticated)
                .ok_or_else(|| AuthenticatorError::new(AuthenticationErrorReason::WrongCredentials))
        })
    }
}
