//! The example where we can get authenticated user.
//! ```bash
//! cargo run --package tower-http-access-examples --example hello_authenticated_user
//! # Authenticated
//! curl -v -u alex:alex123 -X GET http://localhost:3000/hello
//! # Anonymous
//! curl -v -X GET http://localhost:3000/hello
//! ```
use axum::{Router, routing::method_routing::get};
use std::sync::Arc;
use tower_http_access::{
    SecurityLayer,
    authentication::{Authenticated, RequestAuthenticator},
    authorization::{AuthenticationEntryPoint, PermitAllAuthorizationProvider},
};

use tower_http_access_basic::{
    Authority, BasicRequestAuthenticator, InMemoryUserDetailService, PlainHashPasswordManager,
    UserDetail, UserDetailAuthenticationProvider,
};

#[tokio::main(flavor = "current_thread")]
async fn main() {
    tracing_subscriber::fmt()
        .with_max_level(tracing::Level::TRACE)
        .init();

    let authenticator = Arc::new(create_basic_authenticator().await);
    let authorizer = PermitAllAuthorizationProvider::<UserDetail>::default();
    let security_layer = SecurityLayer::new(Arc::clone(&authenticator), authorizer)
        .authentication_entry_point(authenticator);

    let app = Router::new().route(
        "/hello",
        get(hello_authenticated_user).layer(security_layer),
    );

    let listener = tokio::net::TcpListener::bind("127.0.0.1:3000")
        .await
        .unwrap();

    let _ = axum::serve(listener, app).await;
}

async fn hello_authenticated_user(maybe_user_detail: Option<Authenticated<UserDetail>>) -> String {
    tracing::debug!("authenticated as {:?}", maybe_user_detail);
    match maybe_user_detail {
        Some(Authenticated(user_detail)) => {
            let roles = user_detail.authorities;
            format!("Hello, {}! Roles: {:?}", user_detail.username, roles)
        }
        None => "Hello, anonymous!".to_owned(),
    }
}

async fn create_basic_authenticator()
-> impl RequestAuthenticator<Authentication = UserDetail> + AuthenticationEntryPoint {
    let manager = PlainHashPasswordManager; // DONT use in production

    let raw_users = vec![UserDetail::new(
        "max",
        "max123",
        vec![Authority::new("Staff"), Authority::new("Developer")],
    )];

    let user_detail_service = InMemoryUserDetailService::new((&manager, raw_users))
        .await
        .unwrap();

    let provider = UserDetailAuthenticationProvider::new(manager, user_detail_service)
        .await
        .unwrap();

    BasicRequestAuthenticator::new(provider)
}
