mod note;

use argon2::Argon2;
use axum::{
    Router,
    body::Body,
    response::Response,
    routing::{Route, method_routing::get},
    serve,
};
use http::{Method, Request};
use note::{NOTES_API_BASE_PATH, Note, NoteRepository, create_notes_router};
use std::{convert::Infallible, error::Error as StdError, num::NonZeroUsize, sync::Arc};
use tokio::{net::TcpListener, runtime::Handle};
use tower::{Layer, Service};
use tower_http::{
    request_id::{MakeRequestUuid, PropagateRequestIdLayer, RequestId, SetRequestIdLayer},
    trace::TraceLayer,
};
use tower_http_access_authorizers::{
    authorities::{AuthorityRuleExt, HasAuthorities},
    request::RequestAuthorizationProvider,
};
use tower_http_access_basic::BasicRequestAuthenticator;
use tower_http_access_core::{
    authentication::{
        Authenticated, AuthenticationEntryPoint, RequestAuthenticator, RequestAuthenticatorExt,
    },
    authorization::AuthorizationProvider,
    security_layer::SecurityLayer,
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

    let authorizer = Arc::new(create_authorizer());
    let security = create_security_layer(request_auth, authorizer);

    let notes_repo = NoteRepository::new(vec![
        Note::new(
            "The Rust Programming Language",
            "Welcome to The Rust Programming Language, an introductory book about Rust...",
        ),
        Note::new(
            "The Rustonomicon",
            "The Rustonomicon digs into all the awful details that you need to understand when writing Unsafe Rust programs...",
        ),
    ]);

    let notes_router = create_notes_router(notes_repo);

    tracing_subscriber::fmt()
        .with_max_level(tracing::Level::TRACE)
        .init();

    let app_router = Router::new()
        .route("/v1/auth/info", get(get_authenticated))
        .nest(NOTES_API_BASE_PATH, notes_router)
        .layer(security);

    let app_router = apply_logging_layers(app_router);

    tracing::info!(address = %BIND_ADDRESS, "hosting server at");
    let listener = TcpListener::bind(BIND_ADDRESS).await.unwrap();
    serve(listener, app_router).await?;

    Ok(())
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

fn create_authorizer() -> impl AuthorizationProvider<Authentication = Auth<UserDetail>> {
    RequestAuthorizationProvider::builder()
        .method_matchers(Method::GET, "/v1/notes/1")
        .permit_all() // any user can read first note
        .method_matchers(Method::GET, "/v1/notes/{id}")
        .has_authority("ReadNote") // other notes can be read only with `ReadNote` rule
        .method_matchers(Method::DELETE, "/v1/notes/{id}")
        .has_authority("DeleteNote")
        .method_matchers(Method::PUT, "/v1/notes/{id}")
        .has_authority("ReplaceNote")
        .method_matchers(Method::POST, "/v1/notes")
        .has_authority("CreateNote")
        .method_matchers(Method::GET, "/v1/auth/info")
        .permit_all()
        .any_request()
        .deny_all()
        .build()
        .expect("build authorization provider")
}

async fn create_users_service<T: AsyncPasswordHasher>(
    hasher: &T,
) -> impl UserDetailService + use<T> {
    let users = vec![
        UserDetail::new("reader", "reader123", vec![Authority::new("ReadNote")]),
        UserDetail::new("creator", "creator123", vec![Authority::new("CreateNote")]),
        UserDetail::new("remover", "remover123", vec![Authority::new("DeleteNote")]),
        UserDetail::new(
            "replacer",
            "replacer123",
            vec![Authority::new("ReplaceNote")],
        ),
        UserDetail::new(
            "admin",
            "admin123",
            vec![
                Authority::new("ReadNote"),
                Authority::new("DeleteNote"),
                Authority::new("ReplaceNote"),
                Authority::new("CreateNote"),
            ],
        ),
    ];
    InMemoryUserDetailService::new((hasher, users))
        .await
        .unwrap()
}

fn create_security_layer<A, P>(
    authenticator: A,
    authorizer: P,
) -> impl Layer<
    Route,
    Service: Service<
        Request<Body>,
        Response = Response,
        Error = Infallible,
        Future: Send + 'static,
    > + Clone
                 + Send
                 + Sync
                 + 'static,
> + Clone
where
    A: RequestAuthenticator<Authentication = Auth<UserDetail>>
        + AuthenticationEntryPoint
        + Clone
        + 'static,
    P: AuthorizationProvider<Authentication = Auth<UserDetail>> + Clone + 'static,
    P::Error: 'static,
{
    SecurityLayer::new_with_entry_point(authenticator, authorizer)
}

fn apply_logging_layers(router: Router) -> Router {
    router
        .layer(PropagateRequestIdLayer::x_request_id())
        .layer(
            TraceLayer::new_for_http().make_span_with(|request: &Request<Body>| {
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
        // The SetRequestIdLayer must be first in chain for observing request
        .layer(SetRequestIdLayer::x_request_id(MakeRequestUuid))
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

async fn create_basic_authenticator()
-> impl RequestAuthenticator<Authentication = Auth<UserDetail>> + AuthenticationEntryPoint + Clone {
    let provider = create_up_provider().await;
    Arc::new(BasicRequestAuthenticator::new(provider).map(Auth::from))
}

async fn create_up_provider()
-> impl UsernamePasswordAuthenticationProvider<Authentication = UserDetail, Error: Send + Sync + 'static>
{
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
