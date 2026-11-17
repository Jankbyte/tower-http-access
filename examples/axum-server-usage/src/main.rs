//! This example uses so many `impl`'s and generics.
//! It's specially, for abstrogate from axum-abstractions.
use argon2::Argon2;
use axum::{Router, routing::method_routing::get};
use axum_server::Server;
use http::{Request, Response};
use http_body::Body;
use std::{error::Error as StdError, net::SocketAddr, num::NonZeroUsize, sync::Arc};
use tokio::{net::TcpListener, runtime::Handle};
use tower::{Layer, Service, ServiceBuilder, make::Shared};
use tower_http::{
    request_id::{MakeRequestUuid, PropagateRequestIdLayer, RequestId, SetRequestIdLayer},
    trace::TraceLayer,
};
use tower_http_access_authorizers::authorities::HasAuthorities;
use tower_http_access_basic::BasicRequestAuthenticator;
use tower_http_access_core::{
    SecurityLayer,
    authentication::{Authenticated, RequestAuthenticator, RequestAuthenticatorExt},
    authorization::AuthenticationEntryPoint,
};
use user_password_auth::{
    AsyncPasswordHasher, AsyncPasswordVerifier, AsyncStringPasswordManager, Authority,
    InMemoryUserDetailService, UserDetail, UserDetailAuthenticationProvider, UserDetailService,
    UsernamePasswordAuthenticationProvider,
};

const BIND_ADDRESS: &str = "127.0.0.1:3000";

#[tokio::main(flavor = "current_thread")]
async fn main() -> Result<(), Box<dyn StdError + Send + Sync>> {
    let request_auth = create_basic_authenticator().await;

    tracing_subscriber::fmt()
        .with_max_level(tracing::Level::TRACE)
        .init();

    let api_router = Router::new().route("/v1/auth/info", get(get_authenticated));

    let app = apply_logging_layers(create_security_layer(request_auth).layer(api_router));

    tracing::info!(address = %BIND_ADDRESS, "hosting server at");
    let listener = TcpListener::bind(BIND_ADDRESS).await.unwrap();

    Server::<SocketAddr>::from_listener(listener)
        .serve(Shared::new(app))
        .await?;

    Ok(())
}

fn create_security_layer<A, S, B, R>(
    authenticator: A,
) -> impl Layer<
    S,
    Service: Service<
        Request<B>,
        Response = http::Response<R>,
        Error = S::Error,
        Future: Send + 'static,
    > + Clone
                 + Send
                 + Sync
                 + 'static,
> + Clone
where
    A: RequestAuthenticator + AuthenticationEntryPoint + Clone + 'static,
    B: Send + 'static,
    R: From<bytes::Bytes> + 'static,
    S: Service<Request<B>, Response = Response<R>> + Clone + Send + Sync + 'static,
    S::Future: Send + 'static,
    S::Error: Send + 'static,
{
    SecurityLayer::authenticated(authenticator.clone()).authentication_entry_point(authenticator)
}

fn apply_logging_layers<S, B, R>(
    service: S,
) -> impl Service<
    Request<B>,
    Response = Response<impl Body<Data = R::Data, Error = R::Error> + Send + 'static>,
    Error = S::Error,
    Future: Send + 'static,
> + Clone
where
    S: Service<Request<B>, Response = Response<R>> + Clone + Send + 'static,
    S::Future: Send + 'static,
    S::Error: std::fmt::Display + 'static,
    B: Body + Send + 'static,
    R: Body + Send + 'static,
    R::Error: std::fmt::Display + 'static,
{
    ServiceBuilder::new()
        // Generate the ID before creating the span or authenticating.
        .layer(SetRequestIdLayer::x_request_id(MakeRequestUuid))
        .layer(
            TraceLayer::new_for_http().make_span_with(|request: &Request<B>| {
                let request_id = request
                    .extensions()
                    .get::<RequestId>()
                    .and_then(|id| id.header_value().to_str().ok())
                    .unwrap_or("unknown");
                tracing::info_span!(
                    "request",
                    request_id = %request_id,
                    method = %request.method(),
                    path = %request.uri().path(),
                )
            }),
        )
        .layer(PropagateRequestIdLayer::x_request_id())
        .service(service)
}

// The wrapper for authentication for implement `HasAuthorities`.
#[derive(Clone, Debug)]
struct Auth<T>(Arc<T>);

impl From<UserDetail> for Auth<UserDetail> {
    fn from(ud: UserDetail) -> Self {
        Auth(Arc::new(ud))
    }
}

impl HasAuthorities for Auth<UserDetail> {
    fn has_authority(&self, authority: &str) -> bool {
        self.0
            .authorities
            .iter()
            .any(|granted| granted.0 == authority)
    }
}

async fn get_authenticated(maybe_user_detail: Option<Authenticated<Auth<UserDetail>>>) -> String {
    tracing::debug!("authenticated as {:?}", maybe_user_detail);
    match maybe_user_detail {
        Some(Authenticated(Auth(ud))) => {
            let roles = &ud.authorities;
            format!("Hello, {}! Roles: {:?}", ud.username, roles)
        }
        None => "Hello, anonymous!".to_owned(),
    }
}

async fn create_basic_authenticator()
-> impl RequestAuthenticator<Authentication = Auth<UserDetail>> + AuthenticationEntryPoint + Clone {
    let provider = create_up_provider().await;
    Arc::new(BasicRequestAuthenticator::new(provider).map(Auth::from))
}

async fn create_up_provider()
-> impl UsernamePasswordAuthenticationProvider<Authentication = UserDetail> {
    let password_hasher = create_password_hasher(5);
    let users_service = create_users_service(&password_hasher).await;
    UserDetailAuthenticationProvider::new(password_hasher, users_service)
        .await
        .unwrap()
}

fn create_password_hasher(concurrency: usize) -> impl AsyncPasswordVerifier + AsyncPasswordHasher {
    let argon2 = Argon2::default();
    let handle = Handle::current();
    AsyncStringPasswordManager::new(handle, argon2, NonZeroUsize::new(concurrency).unwrap())
}

async fn create_users_service<T: AsyncPasswordHasher>(
    hasher: &T,
) -> impl UserDetailService + use<T> {
    let users = vec![UserDetail::new(
        "user",
        "user123",
        vec![Authority::new("demo")],
    )];
    InMemoryUserDetailService::new((hasher, users))
        .await
        .unwrap()
}
