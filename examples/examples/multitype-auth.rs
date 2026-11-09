//! Examples show multitype authentication.
//!
//! ```bash
//! cargo run --package tower-http-access-examples --example multitype-auth
//! ```
use std::{
    convert::Infallible,
    sync::Arc
};
use tower_http_access::{
    SecurityLayer,
    filter_chain::SecurityChainLayer,
    authentication::{RequestAuthenticator, RequestAuthenticatorExt},
    authorization::{AuthenticationEntryPoint, DelegatingAuthenticationEntryPoint, AuthenticatedAuthorizationProvider},
};
use tower_http_access_basic::{
    BasicRequestAuthenticator, InMemoryUserDetailService, PlainHashPasswordManager, UserDetail,
    UserDetailAuthenticationProvider, UsernamePasswordAuthenticationProvider,
};
use tower_http_access_session::{
    BrowserRequestMatcher, SessionRequestAuthenticator, SessionStoredIdentity,
};
use tower::ServiceBuilder;
use tower_sessions::{
    Expiry, MemoryStore, Session, SessionManagerLayer,
    cookie::{SameSite, time::Duration},
};
use axum::{
    body::Body,
    routing::Route
};

const COOKIE_SESSION_ID: &str = "APPSESSIONID";

#[tokio::main(flavor = "current_thread")]
async fn main() -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let user_service = Arc::new(create_users_service().await);
    let basic_authenticator = Arc::new(create_basic_authenticator(Arc::clone(&user_service)));

    let session_authenticator = Arc::new(
        SessionRequestAuthenticator::new(SessionStoredIdentity::<SessionAuth>::new())
            .login_page_path("/ui/login")
            .unwrap()
            .map(TargetAuthentication::from),
    );

    let session_matcher = Arc::new(BrowserRequestMatcher::new(COOKIE_SESSION_ID));

    let delegate_auth_entrypoint = DelegatingAuthenticationEntryPoint::builder()
        .entry_point(
            Arc::clone(&session_matcher),
            Arc::clone(&session_authenticator),
        )
        .fallback(Arc::clone(&basic_authenticator)); // default authentication is `basic`.

    let authorizer = Arc::new(AuthenticatedAuthorizationProvider::new());

    let api_security_layer = SecurityLayer::new(basic_authenticator, Arc::clone(&authorizer))
        .authentication_entry_point(delegate_auth_entrypoint.clone());

    let browser_security_layer = SecurityLayer::new(session_authenticator, Arc::clone(&authorizer))
        .authentication_entry_point(delegate_auth_entrypoint);

    let browser_chain = ServiceBuilder::new()
        .layer(
            SessionManagerLayer::new(MemoryStore::default())
                .with_secure(false)
                .with_http_only(true)
                .with_same_site(SameSite::Strict)
                .with_expiry(Expiry::OnInactivity(Duration::minutes(30))),
        )
        .layer(browser_security_layer);

    let security_chain = SecurityChainLayer::<Route, Body, Body, Infallible>::builder()
        .chain(session_matcher, browser_chain)
        .fallback(api_security_layer)
        .build()
        .unwrap();

    let listener = tokio::net::TcpListener::bind("127.0.0.1:3000").await?;
    Ok(())
}

#[derive(Clone, serde::Deserialize, serde::Serialize)]
struct SessionAuth {
    username: String,
    authorities: Vec<String>,
}

#[derive(Clone)]
enum TargetAuthentication {
    Basic(UserDetail),
    HttpSession(SessionAuth),
}

impl From<SessionAuth> for TargetAuthentication {
    fn from(sa: SessionAuth) -> Self {
        Self::HttpSession(sa)
    }
}

impl From<UserDetail> for TargetAuthentication {
    fn from(ud: UserDetail) -> Self {
        Self::Basic(ud)
    }
}

async fn create_users_service()
-> UserDetailAuthenticationProvider<PlainHashPasswordManager, InMemoryUserDetailService> {
    let manager = PlainHashPasswordManager;

    let raw_users = vec![
        UserDetail::new("john", "john123", vec![]),
        UserDetail::new("max", "max123", vec![]),
    ];
    let user_detail_service = InMemoryUserDetailService::new((&manager, raw_users))
        .await
        .unwrap();
    UserDetailAuthenticationProvider::new(manager, user_detail_service)
        .await
        .unwrap()
}

fn create_basic_authenticator<
    T: UsernamePasswordAuthenticationProvider<Authentication = UserDetail> + 'static,
>(
    provider: T,
) -> impl RequestAuthenticator<Authentication = TargetAuthentication> + AuthenticationEntryPoint {
    BasicRequestAuthenticator::new(provider).map(TargetAuthentication::from)
}
