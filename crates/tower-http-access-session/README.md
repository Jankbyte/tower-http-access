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
use tower_http_access_core::security_layer::SecurityLayer;
use tower_http_access_core::authentication::Authenticated;
use tower_http_access_session::entry_point::RedirectAuthenticationEntryPoint;
use tower_http_access_core::authorization::AuthenticatedAuthorizationProvider;
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

let authenticator = Arc::new(SessionRequestAuthenticator::new(Users));
let security = SecurityLayer::new(
    Arc::clone(&authenticator),
    AuthenticatedAuthorizationProvider::<String>::new(),
).authentication_entry_point(RedirectAuthenticationEntryPoint::new("/login")?);
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

Configure this crate's
`entry_point::RedirectAuthenticationEntryPoint::new("/account/login")?`
with `.authentication_entry_point(...)` to redirect anonymous users when authentication
is required. It accepts a same-origin absolute path and returns HTTP 302, independently
of the session authenticator. Make the login endpoint public to prevent redirect loops.
Omitting the entry-point configuration retains the layer's default HTTP 401 behavior.

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
use tower_http_access_form_login::RedirectFormLoginHandler;
use tower_http_access_session::tower_sessions::SessionSetSuccessHandler;

let handler = SessionSetSuccessHandler::new(
    |user: &String| user.clone(),
    RedirectFormLoginHandler::new("/private").unwrap(),
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

## CSRF protection

Enable `csrf` to use `csrf::{CsrfLayer, CsrfTokenRepository, CsrfToken}`.
With `tower_sessions` also enabled, built-in repositories are available in
`tower_sessions::csrf`. Implement `CsrfTokenRepository` for other storage backends;
the layer stores repositories directly and clones them per service/request. Pass
`Arc<R>` for shared or non-Clone repositories.

`CsrfLayer` loads or creates and saves a token, then exposes a `CsrfToken` through
request extensions. A login page can render it without JavaScript:

```rust
# #[cfg(feature = "csrf")]
fn login_app<R>(repository: R) -> axum::Router
where
    R: tower_http_access_session::csrf::CsrfTokenRepository + Clone + 'static,
{
    use axum::{extract::Extension, response::Html, routing::get, Router};
    use tower_http_access_session::csrf::{CsrfLayer, CsrfToken};

    Router::new()
        .route("/login", get(|Extension(csrf): Extension<CsrfToken>| async move {
            // Default masking makes the exposed token a hex string. HTML-escape
            // configured field names when they are not trusted static values.
            Html(format!(
                r#"<form method="post" action="/login">
                    <input type="hidden" name="{}" value="{}">
                    <input name="username" autocomplete="username" required>
                    <input name="password" type="password" autocomplete="current-password" required>
                    <button type="submit">Login</button>
                </form>"#,
                csrf.parameter_name, csrf.token,
            ))
        }))
        // Add FormLoginLayer before this call so CSRF runs before form login.
        .layer(CsrfLayer::new(repository))
        // Add session middleware last when the repository needs sessions.
}
```

The default matcher protects every method except GET, HEAD, OPTIONS, and TRACE.
The layer checks the token's named header first, then its URL-encoded form field
when that header is absent. It rejects duplicate token fields/headers and does
not accept query-string or multipart tokens. A valid header avoids buffering;
form inspection preserves the original bytes and trailers and defaults to a
16 KiB limit, configurable with `.body_limit(...)`.

Validation failures return 403. Repository failures return 500, oversized forms
413, and invalid or unreadable forms 400. Customize matching and responses with
`.request_matcher(...)` and `.failure_handler(...)`.

Like Spring's default request handler, token exposure applies fresh XOR masking
for BREACH protection, and validation uses constant-time comparison. Submit the
exposed token unchanged; its hex encoding is specific to this library. Use
`.mask_tokens(false)` only to explicitly opt into raw-token handling. Unlike
Spring's deferred tokens, repository loading is eager on every request. Revoke
the stored token on login/logout as part of the application's session lifecycle.


### Choosing a CSRF repository

Both implementations are available with `csrf` and `tower_sessions` and generate
32 random bytes using the operating system's secure random source. Their types
are in `tower_http_access_session::tower_sessions::csrf`.

| Repository | Expected-token storage | Typical use | Token delivery |
| --- | --- | --- | --- |
| `HttpSessionCsrfTokenRepository` | Server-side session | Server-rendered HTML and ordinary form POSTs | Render the masked `CsrfToken` extension as a hidden input |
| `CookieCsrfTokenRepository` | Separate browser cookie | AJAX/SPA clients that copy a cookie into a request header | Readable CSRF cookie with raw-token validation, or masked extension for HTML forms |

These are usage choices, not restrictions. A session repository can support AJAX
by serving a token endpoint; a cookie repository can support HTML forms using the
masked extension. Neither repository authenticates the user. Keep the authentication
session cookie HttpOnly even when JavaScript can read the separate CSRF cookie.

**Server-rendered HTML:** use `HttpSessionCsrfTokenRepository` and leave masking
on. Defaults are session key `tower_http_access_session.csrf_token`, request header
`x-csrf-token`, and form field `_csrf`. Customize them with `.with_session_key(...)`,
`.with_header_name(...)`, and `.with_parameter_name(...)`. Tokens live as long as
the session unless explicitly removed. Shared session storage supports multiple
application instances without sticky routing.

```rust
# #[cfg(all(feature = "csrf", feature = "tower_sessions"))]
# fn main() {
use axum::Router;
use tower_http_access_session::csrf::CsrfLayer;
use tower_http_access_session::tower_sessions::csrf::HttpSessionCsrfTokenRepository;
use tower_sessions::{MemoryStore, SessionManagerLayer};

let csrf = CsrfLayer::new(HttpSessionCsrfTokenRepository::new());
let app: Router = Router::new()
    // Register the login page and FormLoginLayer here.
    .layer(csrf)
    .layer(SessionManagerLayer::new(MemoryStore::default()));
# }
# #[cfg(not(all(feature = "csrf", feature = "tower_sessions")))]
# fn main() {}
```

**AJAX/SPA:** use `CookieCsrfTokenRepository::new().with_http_only(false)` when
JavaScript needs to read the token. The default cookie is `__Host-XSRF-TOKEN`,
with Secure, Path=/, no Domain, and SameSite=Lax. Send its value in the
`x-xsrf-token` header, together with the browser's cookies. Because the cookie
contains the raw value, this workflow requires `.mask_tokens(false)`; the default
masked mode expects the value exposed through request extensions instead.
Disabling masking opts out of BREACH token masking, so avoid reflecting the raw
cookie value into compressed HTML. The repository defaults to HttpOnly=true
unless explicitly configured otherwise.

```rust
# #[cfg(all(feature = "csrf", feature = "tower_sessions"))]
# fn main() {
use axum::Router;
use tower_cookies::CookieManagerLayer;
use tower_http_access_session::csrf::CsrfLayer;
use tower_http_access_session::tower_sessions::csrf::CookieCsrfTokenRepository;

let repository = CookieCsrfTokenRepository::new().with_http_only(false);
let csrf = CsrfLayer::new(repository).mask_tokens(false);
let app: Router = Router::new()
    // Register routes and authentication middleware here.
    .layer(csrf)
    .layer(CookieManagerLayer::new());
# }
# #[cfg(not(all(feature = "csrf", feature = "tower_sessions")))]
# fn main() {}
```

Add `tower-cookies = "0.11"` as a direct application dependency for the standalone
cookie-manager example. When using `SessionManagerLayer`, it already installs the
cookie manager: use that outer layer instead of adding another one.

The cookie repository does not use server-side token storage. It implements
cookie/header (or cookie/form) double submission, without signatures or session
binding. Its default `__Host-` prefix prevents sibling subdomains from setting
that cookie. Changing to a conventional name such as `XSRF-TOKEN` removes that
browser protection; only do so when sibling subdomains are trusted. For local HTTP,
explicitly choose a name without a secure prefix before disabling Secure:

```rust
# #[cfg(all(feature = "csrf", feature = "tower_sessions"))]
# fn main() -> Result<(), Box<dyn std::error::Error>> {
use tower_http_access_session::tower_sessions::csrf::CookieCsrfTokenRepository;

let repository = CookieCsrfTokenRepository::new()
    .with_cookie_name("XSRF-TOKEN")?
    .with_secure(false)?
    .with_http_only(false);
# Ok(())
# }
# #[cfg(not(all(feature = "csrf", feature = "tower_sessions")))]
# fn main() {}
```

Both repositories support `save_token(request, None)` for removal. Session removal
invalidates the server-side value; cookie removal expires the browser cookie but
cannot revoke copied token values on the server. Cookie tokens have browser-session
lifetime. Clear or replace tokens on authentication changes; flushing a server
session does not clear a separate CSRF cookie, and merely cycling the session ID
does not remove its stored CSRF token.
