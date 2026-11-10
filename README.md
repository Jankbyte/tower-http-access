<p align="center">
  <img src="https://raw.githubusercontent.com/Jankbyte/axum-auth-chained/HEAD/assets/logo.png" alt="Tower HTTP Access: a Rust-inspired crab holding a chain between an identity-and-key icon and an authorization shield" width="60%">
</p>

# 🦀 Tower HTTP Access

Composable HTTP authentication and authorization middleware for Tower, with optional Axum integration.

Authenticate requests with an ordered chain of authenticators, carry a typed identity into handlers, and authorize access with explicit request rules or your own async policies.

- **Typed identities:** extract `Authenticated<User>` or `Option<Authenticated<User>>` in handlers.
- **Ordered authentication:** combine mechanisms such as HTTP Basic and application-defined sessions.
- **Request authorization:** match paths and methods, then require one, any, or all authorities.
- **Custom decisions:** use `.access(manager)` for async authorization, including database lookups.
- **Configurable responses:** customize authentication challenges and authorization failures.
- **Shared layers:** clone security layers to reuse their configuration across routers.

## 🚀 Quick start

This example uses HTTP Basic authentication with Argon2 password hashing. It exposes a public health endpoint and protects note routes with the `ReadNote` authority.

```toml
[dependencies]
axum = "0.8"
tower-http-access-core = { version = "0.0.1", features = ["request_matcher", "user_password_auth"] }
tower-http-access-basic = "0.0.1"
user-password-auth = { version = "0.0.1", features = ["user_details"] }
argon2 = "0.6"
tokio = { version = "1", features = ["macros", "rt-multi-thread", "net"] }
```

```rust,no_run
# mod example {
use std::{num::NonZeroUsize, sync::Arc};

use argon2::Argon2;
use axum::{Router, http::Method, routing::get};
use tower_http_access_core::SecurityLayer;
use tower_http_access_core::authentication::Authenticated;
use tower_http_access_core::authorization::request::RequestAuthorizationProvider;
use tower_http_access_basic::BasicRequestAuthenticator;
use user_password_auth::{AsyncStringPasswordManager, Authority, InMemoryUserDetailService, UserDetail, UserDetailAuthenticationProvider};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let passwords = AsyncStringPasswordManager::new(
        tokio::runtime::Handle::current(),
        Argon2::default(),
        NonZeroUsize::new(2).unwrap(),
    );
    // This constructor hashes the supplied demonstration password at startup.
    let users = InMemoryUserDetailService::new((
        &passwords,
        vec![UserDetail::new(
            "alex",
            "change-me",
            vec![Authority::new("ReadNote")],
        )],
    ))
    .await?;
    let authenticator = Arc::new(BasicRequestAuthenticator::new(
        UserDetailAuthenticationProvider::new(passwords, users).await?,
    ));

    let rules = RequestAuthorizationProvider::<UserDetail>::builder()
        .method_matchers(Method::GET, "/health")
        .permit_all()
        .method_matchers(Method::GET, "/notes/{id}")
        .has_authority("ReadNote")
        .any_request()
        .deny_all()
        .build()?;

    let security = SecurityLayer::new(Arc::clone(&authenticator), Arc::new(rules))
        .authentication_entry_point(authenticator);

    let app = Router::new()
        .route("/health", get(|| async { "ok" }))
        .route("/notes/{id}", get(read_note))
        .layer(security);

    let listener = tokio::net::TcpListener::bind("127.0.0.1:3000").await?;
    axum::serve(listener, app).await?;
    Ok(())
}

async fn read_note(Authenticated(user): Authenticated<UserDetail>) -> String {
    format!("Authenticated as {}", user.username)
}
# }
# fn main() {}
```

```sh
curl http://127.0.0.1:3000/health
curl -u alex:change-me http://127.0.0.1:3000/notes/1
```

The credentials above are for local demonstration. Use HTTPS when sending Basic credentials. For password-hashing configuration and concurrency limits, see [`AsyncStringPasswordManager`](https://docs.rs/user-password-auth/latest/user_password_auth/struct.AsyncStringPasswordManager.html).

## 🔄 How requests are processed

```text
Request → authentication chain → typed identity → authorization → handler
```

Each `RequestAuthenticator` inspects request parts and returns one of these outcomes:

| Outcome | Behavior |
| --- | --- |
| `NotApplicable` | Try the next authenticator. |
| `Authenticated(identity)` | Store `Authenticated<A>` in request extensions and stop the chain. |
| Invalid credentials or an internal error | Return an error response and stop the chain. |

If none applies, authorization receives an anonymous request. Authenticators in a chain must produce the same identity type; use `RequestAuthenticatorExt::map` to adapt their results.

Authorization runs after authentication. By default, authentication-required decisions return **401**, insufficient permissions return **403**, and provider errors return **500**. Configure an authentication entry point for scheme-specific challenges or login redirects, and a failure handler for other authorization failures.

`permit_all()` permits anonymous access at the authorization step. It does not bypass authentication or suppress errors from invalid credentials.

## ☑️ Request rules and ordering

**The first matching rule decides access.** A denial or error is final. Declaration order determines priority, even when a later path is more specific.

```rust,no_run
# fn main() -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
use axum::http::Method;
use tower_http_access_core::authorization::request::RequestAuthorizationProvider;
use user_password_auth::UserDetail;

let rules = RequestAuthorizationProvider::<UserDetail>::builder()
    .method_matchers(Method::GET, "/notes/1")
    .permit_all() // Anyone can read the first note.
    .method_matchers(Method::GET, "/notes/{id}")
    .has_authority("ReadNote") // Other notes require this authority.
    .any_request()
    .deny_all()
    .build()?;
# Ok(())
# }
```

Reversing the two note rules would require `ReadNote` for note `1` too. Put exceptions before broader patterns and `any_request()` last. Unmatched requests are denied even without an explicit fallback.

Paths use `matchit` syntax, as in Axum:

| Matcher | Meaning |
| --- | --- |
| `/notes/1` | Exact path. |
| `/notes/{id}` | One nonempty path segment. |
| `/notes/{*rest}` | A nonempty remainder, including nested segments; excludes `/notes` and `/notes/`. |
| `any_request()` | Every path and method, including `/`. |

Matching is case-sensitive, ignores query strings, and distinguishes trailing slashes. Rules match the URI visible to the middleware; attach the layer outside nested routers when using full application paths.

Axum strips the nesting prefix before middleware inside a nested router runs.
For `/v1/notes/1`, security attached inside `.nest("/v1/notes", ...)` sees `/1`;
a rule for `/v1/notes/1` will not match. Attach security after nesting to use full paths:

```rust,no_run
use axum::{Router, routing::get};
# use tower_http_access_core::SecurityLayer;
# use tower_http_access_core::authentication::AuthenticationAttempt;
# use tower_http_access_core::authentication::AuthenticatorError;
# use tower_http_access_core::authorization::default_auth::AuthenticatedAuthorizationProvider;
# let authenticator = |_: &axum::http::request::Parts| async { Ok::<_, AuthenticatorError>(AuthenticationAttempt::<String>::NotApplicable) };
# let security_layer = SecurityLayer::new(authenticator, AuthenticatedAuthorizationProvider::<String>::new());
# let notes_api = Router::new().route("/{id}", get(async || "note"));

let app: Router = Router::new()
    .nest("/v1/notes", notes_api)
    .route_layer(security_layer);
```

Alternatively, keep security inside the nested router and write local path rules
such as `/1` and `/{id}`. The built-in path matcher reads `Parts.uri`, not Axum's
`OriginalUri` extension.

Use `.matching(...)` to supply a `RequestMatcher` explicitly:

```rust,no_run
# fn main() -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
use tower_http_access_core::authorization::request::RequestAuthorizationProvider;
use http_request_matcher::PathPatternRequestMatcher;

let rules = RequestAuthorizationProvider::<String>::builder()
    .matching(PathPatternRequestMatcher::new("/notes/{id}")?)
    .authenticated()
    .any_request()
    .deny_all()
    .build()?;
# Ok(())
# }
```

`PathPatternRequestMatcher` compiles its pattern when constructed and matches paths
for every HTTP method by default. Use `.with_method(Method::GET)` to also restrict
the method. Existing `.request_matchers(...)` and `.method_matchers(...)`
helpers use the same implementation and validate patterns at `.build()`.
Custom matchers implement `RequestMatcher::matches(&http::request::Parts)` and borrow
the original method, URI, headers, and extensions. Authorization providers receive
the same borrowed request parts through `authorize`. Matching is synchronous; permission decisions remain in the
authorization policy. A nonmatching rule is skipped, not denied.

Matchers run on the request's async executor thread and must be fast. Do not perform
blocking I/O, database or network calls, or expensive CPU-bound work inside a matcher.
Compile patterns and prepare lookup data during configuration. For async or CPU-bound
access checks, use a custom `AuthorizationProvider` through `.access(provider)`.
Offload CPU-bound work inside that provider to `spawn_blocking` or a dedicated worker
pool; making a function async does not move CPU work off the executor.

The standalone `http-request-matcher` crate provides matchers using `http` types,
without depending on Tower or authentication. Add `http-request-matcher = "0.0.1"`
to your dependencies to use custom matchers directly.

Request authorization is available independently of Basic authentication with
`features = ["request_matcher"]`. Import its builders from `tower_http_access_core::authorization::request`.
Authentication-only and custom rules work with any `Send + Sync + 'static` identity:

```rust,no_run
# fn main() -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
use tower_http_access_core::authorization::request::RequestAuthorizationProvider;

let rules = RequestAuthorizationProvider::<String>::builder()
    .request_matchers("/health").permit_all()
    .any_request().authenticated()
    .build()?;
# Ok(())
# }
```

Only authority methods require `authorization::authorities::HasAuthorities`. Basic authentication and
user-detail helpers are provided by the separate `user-password-auth` crate.

Available policies:

| Builder method | Requirement |
| --- | --- |
| `permit_all()` | Allows anonymous and authenticated requests. |
| `deny_all()` | Denies every matching request. |
| `authenticated()` | Requires an identity. |
| `has_authority("ReadNote")` | Requires that exact authority. |
| `has_any_authority(["ReadNote", "ReadAnyNote"])` | Requires at least one listed authority; an empty list grants no access. |
| `has_all_authorities(["ReadNote", "WriteNote"])` | Requires every listed authority; an empty list requires authentication only. |
| `access(manager)` | Delegates the complete decision to a custom `AuthorizationProvider`. |

Custom identity types can implement `authorization::authorities::HasAuthorities`; `UserDetail` already
implements it. Authority names are compared exactly; no role prefix is added.

Built-in rules delegate to reusable authorization providers:
`PermitAllAuthorizationProvider`, `DenyAllAuthorizationProvider`,
`AuthenticatedAuthorizationProvider`, `AuthorityAuthorizationProvider`,
`AnyAuthorityAuthorizationProvider`, and `AllAuthoritiesAuthorizationProvider`.
These providers are available without `request_matcher` and can be
used directly, composed with `AllAuthorizationProvider`, or adapted with `.map(...)`.

## 🔐 Custom authorization

Implement `AuthorizationProvider` for application-specific decisions. It receives an optional identity and borrowed `http::request::Parts`, and may perform async I/O.

Use `.access(manager)` on a request rule when the manager uses the same identity type. Managers can inspect the method, URI, headers, and extensions without copying them; matched path parameters are not extracted automatically. The manager decides how to handle anonymous callers and whether access is allowed. No authority check is added automatically.

Custom manager errors are wrapped in `RequestAuthorizationError`, preserving their source. For a complete policy engine, pass your own `AuthorizationProvider` to `SecurityLayer::new(authenticator, provider)`. Put application-specific request metadata in extensions before authorization runs.

Check resource ownership and sharing rules in your application service or repository as well. For mutations, enforce access together with the write so a separate earlier check cannot become stale.

## 🧩 Reusing layers

Use `SecurityLayer::new(authenticator, authorizer)` to authenticate and authorize in
one service. The identity is passed directly to the authorizer and, after access is
allowed, stored as `Authenticated<A>` for handlers. Authenticators and authorizers do
not need to implement `Clone`; the layer shares them through `Arc`.

```rust,no_run
# use axum::{extract::Request, http::{StatusCode, request::Parts}};
# use tower_http_access_core::SecurityLayer;
# use tower_http_access_core::authentication::AuthenticationAttempt;
# use tower_http_access_core::authentication::AuthenticatorError;
# use tower_http_access_core::authorization::default_auth::AuthenticatedAuthorizationProvider;
# use tower_http_access_core::authorization::core::AuthorizationFailure;
# let my_authenticator = |_: &Parts| async { Ok::<_, AuthenticatorError>(AuthenticationAttempt::Authenticated("alex".to_owned())) };
# let my_authorizer = AuthenticatedAuthorizationProvider::<String>::new();
# let my_entry_point = |_: &Parts| http::Response::builder().status(StatusCode::UNAUTHORIZED).body(bytes::Bytes::new()).unwrap();
# let my_failure_handler = |_: &Parts, _: AuthorizationFailure<std::convert::Infallible>| http::Response::builder().status(StatusCode::FORBIDDEN).body(bytes::Bytes::new()).unwrap();
let security = SecurityLayer::new(my_authenticator, my_authorizer)
    .authentication_entry_point(my_entry_point)
    .failure_handler(my_failure_handler);
# let _: axum::Router = axum::Router::new().layer(security);
```

For multiple authentication mechanisms, build an ordered chain separately:

```rust,no_run
# use axum::http::request::Parts;
# use tower_http_access_core::authentication::AuthenticationAttempt;
# use tower_http_access_core::authentication::AuthenticatorError;
# use tower_http_access_core::authorization::default_auth::AuthenticatedAuthorizationProvider;
# let session_authenticator = |_: &Parts| async { Ok::<_, AuthenticatorError>(AuthenticationAttempt::<String>::NotApplicable) };
# let basic_authenticator = |_: &Parts| async { Ok::<_, AuthenticatorError>(AuthenticationAttempt::Authenticated("alex".to_owned())) };
# let my_authorizer = AuthenticatedAuthorizationProvider::<String>::new();
use tower_http_access_core::{SecurityLayer, authentication::DelegatingRequestAuthenticator};

let authenticators = DelegatingRequestAuthenticator::builder()
    .authenticator(session_authenticator)
    .authenticator(basic_authenticator)
    .build();
let security = SecurityLayer::new(authenticators, my_authorizer);
# let _: axum::Router = axum::Router::new().layer(security);
```

The chain skips non-applicable authenticators and stops at the first authenticated
identity or error. Use `.authenticator(...)` to add an authenticator already
held in an `Arc`.

Use separate layers when authentication and authorization need independent placement,
for example to authenticate once before applying different authorization rules to
nested routers, or to run context-enrichment middleware between the stages.

The following composition uses `tower::ServiceBuilder` (`tower = "0.5"`).

```rust,no_run
# use axum::{extract::Request, http::{StatusCode, request::Parts}};
# use tower_http_access_core::authentication::AuthenticationAttempt;
# use tower_http_access_core::authentication::AuthenticatorError;
# use tower_http_access_core::authorization::default_auth::AuthenticatedAuthorizationProvider;
# use tower_http_access_core::authorization::core::AuthorizationFailure;
# let my_authenticator = |_: &Parts| async { Ok::<_, AuthenticatorError>(AuthenticationAttempt::Authenticated("alex".to_owned())) };
# let my_authorizer = AuthenticatedAuthorizationProvider::<String>::new();
# let my_entry_point = |_: &Parts| http::Response::builder().status(StatusCode::UNAUTHORIZED).body(bytes::Bytes::new()).unwrap();
# let my_failure_handler = |_: &Parts, _: AuthorizationFailure<std::convert::Infallible>| http::Response::builder().status(StatusCode::FORBIDDEN).body(bytes::Bytes::new()).unwrap();
use tower_http_access_core::authentication::AuthenticationLayer;
use tower_http_access_core::authorization::auth_tower::AuthorizationLayer;
use tower::ServiceBuilder;

let authentication = AuthenticationLayer::new(my_authenticator);
let authorization = AuthorizationLayer::builder(my_authorizer)
    .authentication_entry_point(my_entry_point)
    .failure_handler(my_failure_handler)
    .build();
let security = ServiceBuilder::new()
    .layer(authentication)
    .layer(authorization);
# let _: axum::Router = axum::Router::new().layer(security);
```

For separate layers, authentication must run before authorization, and both must use
the same identity type. They communicate through `Authenticated<A>` in request
extensions. To insert middleware between them, add it between the two `.layer(...)`
calls. Do not stack `AuthenticationLayer` before `SecurityLayer` for the same identity
type; the combined layer obtains its identity from its own authenticator.

Clone a configured layer to attach it to multiple routers. Authentication providers,
authorization rules, and entry points are shared through `Arc`; failure handlers use
their own `Clone` implementations.

## 🪪 Sessions and form login

The library provides extension points for session authentication; it does not include a session store or form-login flow. Implement a login endpoint that verifies credentials, creates a session, and sets a cookie. A custom `RequestAuthenticator` can resolve that cookie into a typed identity on subsequent requests.

Authenticators only inspect request parts, so parse login form bodies in a handler. Cookie-based applications also need CSRF protection, including on login and logout. Add CSRF validation separately from authorization so public endpoints remain protected against forged submissions.

## HTTP responses and framework integration

Security-generated responses use `SecurityResponse`, an alias for `http::Response<bytes::Bytes>`.
Authenticators can return an explicit custom response through `AuthenticatorError::with_response`;
otherwise `into_security_response()` selects the default HTTP 401 or 500 response.
Entry points and failure handlers borrow `&http::request::Parts` and also return `SecurityResponse`.
An authorizer can return `AuthorizationDecision::Deny(AuthorizationDenial::Custom(response))`
to supply its own rejection response to the failure handler. The default handler returns it
unchanged; custom handlers can inspect, modify, or replace it. The combined layer applies its
response adapter afterward. Composed providers stop at this denial and preserve the response.

```rust
use tower_http_access_core::{SecurityResponse, authentication::{AuthenticatorError, AuthenticationErrorReason}};
use bytes::Bytes;
use http::StatusCode;

let challenge: SecurityResponse = http::Response::builder()
    .status(StatusCode::UNAUTHORIZED)
    .header("www-authenticate", "Basic realm=\"Notes\"")
    .body(Bytes::from_static(b"Authentication required"))?;
let error = AuthenticatorError::with_response(AuthenticationErrorReason::WrongCredentials, challenge);
assert_eq!(error.into_security_response().status(), StatusCode::UNAUTHORIZED);
# Ok::<(), http::Error>(())
```

The Tower middleware accepts generic request and response bodies. With the default combined-layer
adapter, or the standalone layers, its inner service must return `http::Response<ResBody>` where
`ResBody: From<Bytes>`. Axum's `Body`, `Bytes` itself, and
`http_body_util::Full<Bytes>` support this conversion. Other body types can be wrapped in an
application type implementing `From<Bytes>`. Successful handler responses are passed through
unchanged, without buffering or polling streaming bodies. Use `Full<Bytes>` rather than plain
`Bytes` when your HTTP transport requires an `http_body::Body` implementation.

`SecurityResponseAdapter<B>` defines a contract for converting an entire security response to
`http::Response<B>`, including protocol-specific changes to status, headers, and body. For example,
an HTTP-to-gRPC adapter could map HTTP 401 to `Unauthenticated`, 403 to `PermissionDenied`, and
500 to `Internal`, then generate a gRPC response using Tonic's `Status::into_http()`. Successful
application responses should bypass adaptation so their streaming bodies remain untouched.
Configure it with `SecurityLayer::new(authenticator, authorizer).response_adapter(adapter)`.
The combined layer invokes the adapter for every security rejection, including authentication
errors, and bypasses it for successful handler responses. Adapters are shared through `Arc` and
need not implement `Clone`. The default `DefaultSecurityResponseAdapter` preserves HTTP metadata
and converts the body through `From<Bytes>`; no gRPC-specific adapter is supplied. A custom adapter
can produce a body type without `From<Bytes>`. The separate authentication and authorization
layers retain their existing body conversion.

For a core-only dependency, use `tower-http-access-core = { version = "0.1", default-features = false }`.
Add `bytes = "1"` and `http = "1"` to your application when constructing custom responses directly.

## ✨ Features

The `axum` integration feature is enabled by default. Disable default features to use the core
HTTP/Tower middleware without depending on Axum. Authentication and authorization traits,
`SecurityLayer`, and the separate layers are always available.

| Feature | Enables |
| --- | --- |
| `axum` (default) | Axum extractors for `Authenticated<A>` and `Option<Authenticated<A>>`, plus `IntoResponse` for authentication errors. |
| `request_matcher` | Ordered request-rule authorization and delegating entry points using `http-request-matcher`. |
| `user_password_auth` | Implements `HasAuthorities` for `user_password_auth::UserDetail`. Enable when using the built-in user details with authority checks. |

The separate `tower-http-access-basic` crate provides HTTP Basic authentication.
The standalone `user-password-auth` crate provides `Credentials`, user details,
credential providers, and password helpers without depending on HTTP or Tower.
The Basic crate’s optional `tracing` feature enables authentication tracing.
Add your chosen hashing implementation, such as `argon2`, directly to your application’s
dependencies and pass it to `AsyncStringPasswordManager`. Import Basic types from `tower_http_access_basic`;
the core crate does not re-export them.

`PlainHashPasswordManager` is intended for demonstrations and tests; use a password-hashing implementation for real credentials.

## 📝 Examples

- [CRUD API with authority-based access](https://github.com/Jankbyte/axum-auth-chained/blob/main/examples/examples/simple_crud_rbac_axum.rs)

Run an example from this checkout:

```sh
cargo run --package tower-http-access-examples --example simple_crud_rbac_axum
```

## 🛠️ Development

```sh
cargo fmt -- --check
cargo clippy --workspace --all-targets --all-features -- -D warnings
cargo test --all-targets --all-features
cargo test --workspace --all-features --doc
cargo doc --all-features --no-deps --open
```

## 📄 License

[MIT](https://github.com/Jankbyte/axum-auth-chained/blob/main/LICENSE)
