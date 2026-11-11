//! The example shows how to implement custom `UsernamePasswordAuthenticationProvider`.
//!
//! ```bash
//! cargo run --package tower-http-access-examples --example basic-auth-custom-source
//! curl -X GET -u alex:alex123 -v http://localhost:3000/hello
//! ```
use axum::{Router, routing::get};
use futures_util::future::BoxFuture;
use std::sync::Arc;
use tower_http_access_authorizers::default_auth::AuthenticatedAuthorizationProvider;
use tower_http_access_core::SecurityLayer;
use tower_http_access_core::authentication::Authenticated;

use tower_http_access_basic::BasicRequestAuthenticator;
use user_password_auth::{Credentials, UsernamePasswordAuthenticationProvider};

#[tokio::main(flavor = "current_thread")]
async fn main() -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:3000").await?;
    axum::serve(listener, create_app()).await?;
    Ok(())
}

fn create_app() -> Router {
    let upp = SingleUsernamePasswordProvider("alex".to_owned(), "alex123".to_owned());
    let authenticator = Arc::new(BasicRequestAuthenticator::with_realm(upp, "Demo"));

    let security = SecurityLayer::new(
        Arc::clone(&authenticator),
        AuthenticatedAuthorizationProvider::<User>::default(),
    )
    .authentication_entry_point(authenticator);

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

struct SingleUsernamePasswordProvider(String, String);

impl UsernamePasswordAuthenticationProvider for SingleUsernamePasswordProvider {
    type Authentication = User;
    type Error = std::convert::Infallible;

    fn authenticate<'a>(
        &'a self,
        credentials: &'a Credentials,
    ) -> BoxFuture<'a, Result<Option<Self::Authentication>, Self::Error>> {
        Box::pin(async {
            if credentials.username == self.0 && credentials.password == self.1 {
                Ok(Some(User {
                    username: self.0.clone(),
                }))
            } else {
                Ok(None)
            }
        })
    }
}
