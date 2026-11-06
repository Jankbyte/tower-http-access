# Tower HTTP Access Session

Session authentication for Tower HTTP Access using `tower-sessions`.

Session middleware loads the cookie-backed session into request extensions.
[`SessionRequestAuthenticator`] reads its `user_id` and calls your
[`SessionIdentityProvider`] to load the current identity. `SecurityLayer` passes
that identity to your authorization provider and exposes it as `Authenticated<T>`
to handlers. Existing role and path policies work without modification.

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

Missing identifiers and deleted users are treated as anonymous. Missing session
middleware, malformed session data, and backend failures produce internal errors.
Authorization decides whether anonymous access is permitted.

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
