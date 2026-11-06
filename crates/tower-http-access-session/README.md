# Tower HTTP Access Session

Session authentication for Tower HTTP Access using `tower-sessions`.

Session middleware loads the cookie-backed session into request extensions.
[`SessionRequestAuthenticator`] reads its `user_id` and calls your
[`SessionIdentityProvider`] to load the current identity. `SecurityLayer` passes
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
tower-http-access = "0.0.1"
tower-http-access-session = "0.0.1"
tower-sessions = { version = "0.15", features = ["memory-store"] }
axum = "0.8"
futures-util = "0.3"
```

```rust,no_run
use std::{convert::Infallible, sync::Arc};
use axum::{Router, routing::get};
use futures_util::future::BoxFuture;
use tower_http_access::{SecurityLayer, authentication::Authenticated,
    authorization::AuthenticatedAuthorizationProvider};
use tower_http_access_session::{SessionIdentityProvider, SessionRequestAuthenticator};
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
```

In your public login handler, verify credentials first, then call
`session.cycle_id().await?` and `session.insert("user_id", user_id).await?`.
Log out with `session.flush().await?`. The identifier type must match the provider's
`Id`. Use `.with_session_key("account_id")` to customize the key.

The default extractor calls `session.get::<P::Id>()` and requires the identifier
to implement `DeserializeOwned`. To use a custom session schema or construct an
identifier that does not implement deserialization, supply an async extractor:

```rust
use tower_http_access_session::{SessionIdentityProvider, SessionRequestAuthenticator};

fn custom_authenticator<P>(provider: P) -> SessionRequestAuthenticator<P>
where
    P: SessionIdentityProvider<Id = String>,
{
    SessionRequestAuthenticator::new_with_extractor(provider, |session| async move {
        session.get::<String>("account_id").await
    })
}
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

Use [`SessionStoredIdentity<T>`] when the session already contains the complete
identity needed for authorization. It implements `SessionIdentityProvider` with
both `Id` and `Identity` set to `T`, returning the extracted value unchanged.
`tower-sessions` still loads the session from its configured backend; this provider
performs no additional user database lookup.

```rust,no_run
use tower_http_access_session::{SessionRequestAuthenticator, SessionStoredIdentity};
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

Call [`initialize_session`] from middleware after `SessionManagerLayer` runs and
before calling the next handler to initialize anonymous sessions. It adds a
reserved marker without setting `user_id`; the session manager saves the session
and sets its cookie on eligible responses. Existing initialized sessions are not
rewritten. See the form-login example for Axum middleware placement.

## Browser flow selection

Enable `browser_matcher` to use [`BrowserRequestMatcher`] with
`SecurityChainLayer` (enable the core crate's `filter_chain` feature):

```toml
tower-http-access = { version = "0.0.1", features = ["filter_chain"] }
tower-http-access-session = { version = "0.0.1", features = ["browser_matcher"] }
```

Add `.chain(BrowserRequestMatcher, browser_stack)` to your chain builder. The
browser stack should contain `SessionManagerLayer`, session initialization, and
`SecurityLayer`, in that order. Put Basic or token credential chains first so
those requests skip session middleware even when they accept HTML.

The matcher selects explicit `Accept: text/html` entries with nonzero quality;
wildcards do not match. This selects browser-style HTML behavior, not a trusted
browser identity. Clients can set the header themselves, and browser fetch calls
may omit it. Each selected stack must enforce its own authentication and authorization.
See `examples/examples/form-login-session.rs` for the complete composition.

`SessionRequestAuthenticator` also implements `AuthenticationEntryPoint`: share it
through `Arc` and pass it to `.authentication_entry_point(...)` to redirect anonymous
users when authentication is required. The default location is `/login`; configure
a same-origin absolute path with `.login_page_path("/account/login")?`. The response
is HTTP 302. Make the login endpoint public to prevent redirect loops. Omitting
the entry-point configuration retains the layer's default HTTP 401 behavior.

Enable `session_matcher` for `SessionCookieRequestMatcher`. Combine it with
`BrowserRequestMatcher` using the core API's `OrRequestMatcher::new(...)` to select
one session chain for HTML navigation **or** requests carrying a session cookie.
Use `SessionCookieRequestMatcher::default()` for `id`, or `::new("JSESSIONID")`
when the session manager uses that name. Cookie presence only selects the chain;
it never proves authentication. Invalid or expired sessions remain anonymous.

A REST request with a valid session cookie can then authenticate without accepting
HTML. Use `DelegatingAuthenticationEntryPoint` from the core authorization API
with `.entry_point(BrowserRequestMatcher, session_authenticator)` and
`.fallback(DefaultAuthenticationEntryPoint)` to redirect unauthenticated HTML
requests while returning 401 to REST clients. See the form-login example.
