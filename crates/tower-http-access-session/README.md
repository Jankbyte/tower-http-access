# Tower HTTP Access Session

Session authentication for Tower HTTP Access using `tower-sessions`.

The `tower_sessions` feature is enabled by default and exposes the integration in
`tower_http_access_session::tower_sessions`. Disable default features to omit this
backend. `SessionSetSuccessHandler` requires both `tower_sessions` and `form_login`.
The `browser_matcher` and `session_matcher` features expose backend-independent
request matchers at the crate root.

Session middleware loads the cookie-backed session into request extensions.
`SessionRequestAuthenticator` reads its `user_id` and calls your
`SessionIdentityProvider` to load the current identity. `SecurityLayer` passes
that identity to your authorization provider and exposes it as `Authenticated<T>`
to handlers. Existing role and path policies work without modification.

`SessionIdentityProvider` is separate from the `tower-sessions` storage backend:

- The session backend retrieves session data, including the stored user identifier.
- The identity provider uses that identifier to retrieve the current user and
  permissions from your application's database or an external identity service.

For example, you can store sessions in Redis and retrieve users and roles from
PostgreSQL. Your provider can hold a shared database connection pool and perform
an async query in `load_identity`; the session backend and user database do not
need to use the same storage technology or database.

The provider is called on every request whose session extractor returns an
identifier, even for public routes that pass through the security layer. This
additional lookup lets role changes and disabled accounts take effect without
rewriting session data. Return `Ok(None)` for unknown or disabled users and `Err`
for database failures. If you cache identities to reduce database traffic, choose
cache freshness according to how quickly account and permission changes must
be observed.

```toml
[dependencies]
tower-http-access-core = "0.0.1"
tower-http-access-authorizers = "0.0.1"
tower-http-access-session = "0.0.1"
tower-sessions = { version = "0.15", features = ["memory-store"] }
axum = "0.8"
futures-util = "0.3"
```

```rust,no_run
# #[cfg(feature = "tower_sessions")]
# fn main() -> Result<(), Box<dyn std::error::Error>> {
use std::{convert::Infallible, sync::Arc};
use axum::{Router, routing::get};
use futures_util::future::BoxFuture;
use tower_http_access_core::SecurityLayer;
use tower_http_access_core::authentication::Authenticated;
use tower_http_access_authorizers::default_auth::AuthenticatedAuthorizationProvider;
use tower_http_access_session::tower_sessions::{SessionIdentityProvider, SessionRequestAuthenticator};
use tower_sessions::{MemoryStore, SessionManagerLayer};

struct Users;
impl SessionIdentityProvider for Users {
    type Id = String;
    type Identity = String;
    type Error = Infallible;

    fn load_identity<'a>(&'a self, id: String)
        -> BoxFuture<'a, Result<Option<String>, Infallible>>
    {
        // Replace with a database lookup; return None for disabled/deleted users.
        Box::pin(async move { Ok((id == "alice").then_some(id)) })
    }
}

let authenticator = Arc::new(
    SessionRequestAuthenticator::new(Users).login_page_path("/login")?,
);
let security = SecurityLayer::new(
    Arc::clone(&authenticator),
    AuthenticatedAuthorizationProvider::<String>::new(),
).authentication_entry_point(authenticator);
let app: Router = Router::new()
    .route("/private", get(|Authenticated(user): Authenticated<String>| async move { user }))
    .route_layer(security)
    // Added last so sessions are available before authentication runs.
    .layer(SessionManagerLayer::new(MemoryStore::default()));
# Ok::<(), Box<dyn std::error::Error>>(())
# }
# #[cfg(not(feature = "tower_sessions"))]
# fn main() {}
```

In your public login handler, verify credentials first, then call
`session.cycle_id().await?` and `session.insert("user_id", user_id).await?`.
Log out with `session.flush().await?`. The identifier type must match the provider's
`Id`. Use `.with_session_key("account_id")` to customize the key.

The default extractor calls `session.get::<P::Id>()` and requires the identifier
to implement `DeserializeOwned`. To use a custom session schema or construct an
identifier that does not implement deserialization, supply an async extractor:

```rust
# #[cfg(feature = "tower_sessions")]
# fn main() -> Result<(), Box<dyn std::error::Error>> {
use tower_http_access_session::tower_sessions::{SessionIdentityProvider, SessionRequestAuthenticator};

fn custom_authenticator<P>(provider: P) -> SessionRequestAuthenticator<P>
where
    P: SessionIdentityProvider<Id = String>,
{
    SessionRequestAuthenticator::new_with_extractor(provider, |session| async move {
        session.get::<String>("account_id").await
    })
}
# Ok(())
# }
# #[cfg(not(feature = "tower_sessions"))]
# fn main() {}
```

The extractor receives an owned, cloned `Session` handle and returns
`Result<Option<P::Id>, tower_sessions::session::Error>`. `Ok(None)` means no
applicable identity; errors produce an internal error. `SessionIdentityProvider`
itself does not require `DeserializeOwned`. Calling `.with_session_key(...)`
replaces the extractor with the default key-based lookup.

Missing identifiers and deleted users are treated as anonymous. Missing session
middleware, malformed session data, and backend failures produce internal errors.
Authorization decides whether anonymous access is permitted.

## Store the identity in the session

Use `tower_sessions::SessionStoredIdentity<T>` when the session already contains the complete
identity needed for authorization. It implements `SessionIdentityProvider` with
both `Id` and `Identity` set to `T`, returning the extracted value unchanged.
`tower-sessions` still loads the session from its configured backend; this provider
performs no additional user database lookup.

```rust,no_run
# #[cfg(feature = "tower_sessions")]
# fn main() -> Result<(), Box<dyn std::error::Error>> {
use tower_http_access_session::tower_sessions::{SessionRequestAuthenticator, SessionStoredIdentity};
use tower_sessions::Session;

// A simple identity consisting of the username and role names.
type Identity = (String, Vec<String>);

let authenticator = SessionRequestAuthenticator::new(
    SessionStoredIdentity::<Identity>::new(),
)
.with_session_key("authenticated_user");

// Call only after credentials have been verified.
async fn establish_session(
    session: &Session,
    identity: Identity,
) -> Result<(), tower_sessions::session::Error> {
    session.cycle_id().await?;
    session.insert("authenticated_user", identity).await
}
# Ok(())
# }
# #[cfg(not(feature = "tower_sessions"))]
# fn main() {}
```

The default extractor requires `T: DeserializeOwned`; inserting the identity
requires `Serialize`. The provider itself only requires
`T: Clone + Send + Sync + 'static`, so custom extractors can construct identities
without serialization support. `new()` and `Default::default()` create the same
provider. Without `.with_session_key(...)`, the authenticator reads `user_id`.

Store only identity and authorization data, excluding passwords and password
hashes. Roles and account status reflect the stored value until the session is
updated, expires, or is invalidated. Keep a database-backed provider when you need
to check current permissions or disabled accounts on each request.

Use a persistent shared session store for multiple application instances. Configure
cookie security and expiry with `SessionManagerLayer`; protect browser mutations,
including login and logout, against CSRF. `MemoryStore` is for the example.

Session identifiers are managed by `tower-sessions` using its `session::Id` type.

Call `initialize_session` from middleware after `SessionManagerLayer` runs and
before calling the next handler to initialize anonymous sessions. It adds a
reserved marker without setting `user_id`; the session manager saves the session
and sets its cookie on eligible responses. Existing initialized sessions are not
rewritten. See the form-login example for Axum middleware placement.

## Browser flow selection

Enable `browser_matcher` to use `BrowserRequestMatcher` with
`SecurityChainLayer` (enable the core crate's `filter_chain` feature):

```toml
tower-http-access-core = { version = "0.0.1", features = ["filter_chain"] }
tower-http-access-session = { version = "0.0.1", features = ["browser_matcher"] }
```

Add `.chain(BrowserRequestMatcher::default(), browser_stack)` to your chain builder. The
browser stack should contain `SessionManagerLayer`, session initialization, and
`SecurityLayer`, in that order. Put Basic or token credential chains first so
those requests skip session middleware even when they accept HTML.

The matcher combines `MediaTypeRequestMatcher` for HTML with
`SessionCookieRequestMatcher` through `OrRequestMatcher`. It selects HTML requests
or requests carrying the session cookie, including REST requests without HTML
in `Accept`. HTML matching ignores `*/*` and `text/*`; parameters, including `q=0`,
are ignored according to the media matcher's compatibility semantics. Invalid
Accept headers do not match the HTML branch, but cookies can still select the chain.
This is a routing heuristic; each stack must enforce authentication and authorization.
See `examples/examples/form-login-session.rs` for the complete composition.

`SessionRequestAuthenticator` also implements `AuthenticationEntryPoint`: share it
through `Arc` and pass it to `.authentication_entry_point(...)` to redirect anonymous
users when authentication is required. The default location is `/login`; configure
a same-origin absolute path with `.login_page_path("/account/login")?`. The response
is HTTP 302. Make the login endpoint public to prevent redirect loops. Omitting
the entry-point configuration retains the layer's default HTTP 401 behavior.

`browser_matcher` also enables `session_matcher`. Use
`BrowserRequestMatcher::default()` for cookie name `id`, or
`BrowserRequestMatcher::new("JSESSIONID")` when the session manager uses that name.
Cookie presence only selects the chain; it never proves authentication. Invalid
or expired sessions remain anonymous. `SessionCookieRequestMatcher` is also
available separately with the `session_matcher` feature.

To redirect only HTML requests while returning 401 to REST clients, configure
`DelegatingAuthenticationEntryPoint` with a `MediaTypeRequestMatcher` for
`text/html`, ignoring `*/*` and `text/*`, and use
`.fallback(DefaultAuthenticationEntryPoint)`. See the form-login example.

## Form login

Use `tower-http-access-form-login` for `FormLoginLayer` and its generic success
and failure handlers. Enable this crate's `form_login` feature to use
`SessionSetSuccessHandler` with that layer:

```rust
# #[cfg(all(feature = "tower_sessions", feature = "form_login"))]
# fn main() -> Result<(), Box<dyn std::error::Error>> {
use tower_http_access_form_login::RedirectSuccessHandler;
use tower_http_access_session::tower_sessions::SessionSetSuccessHandler;

let handler = SessionSetSuccessHandler::new(
    |user: &String| user.clone(),
    RedirectSuccessHandler::new("/private").unwrap(),
);
// FormLoginLayer::new(provider).on_success(handler)
# Ok(())
# }
# #[cfg(not(all(feature = "tower_sessions", feature = "form_login")))]
# fn main() {}
```

The session handler rotates the session ID and stores the mapped identity before
calling the next success handler. Its default key is `user_id`; configure the same
key on the handler and `SessionRequestAuthenticator`. Place `SessionManagerLayer`
outside the form-login layer so the session is available in request extensions.
