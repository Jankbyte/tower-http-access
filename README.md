<p align="center">
  <img src="assets/logo.png" alt="Axum Auth Chained: a Rust-inspired crab holding a chain between an identity-and-key icon and an authorization shield" width="60%">
</p>

# 🦀 Axum Auth Chained

Composable authentication and authorization middleware for Axum and Tower.

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
axum-auth-chained = { version = "0.1", features = ["argon2_encoder"] }
argon2 = "0.6"
tokio = { version = "1", features = ["macros", "rt-multi-thread", "net"] }
```

```rust
use std::{num::NonZeroUsize, sync::Arc};

use argon2::Argon2;
use axum::{Router, http::Method, routing::get};
use axum_auth_chained::{
    SecurityLayerBuilder,
    authentication::Authenticated,
    basic::{
        AsyncStringPasswordManager, Authority, BasicRequestAuthenticator,
        InMemoryUserDetailService, RequestAuthorizationProvider, UserDetail,
        UserDetailAuthenticationProvider,
    },
};

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

    let security = SecurityLayerBuilder::builder()
        .chained_authenticators(|chain| chain.shared_authenticator(Arc::clone(&authenticator)))
        .authorization(|authorization| {
            authorization
                .authorize_with(rules)
                .authentication_entry_point(authenticator)
        })
        .build();

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
```

```sh
curl http://127.0.0.1:3000/health
curl -u alex:change-me http://127.0.0.1:3000/notes/1
```

The credentials above are for local demonstration. Use HTTPS when sending Basic credentials. For password-hashing configuration and concurrency limits, see [the Basic authentication example](examples/examples/axum_basic_auth.rs).

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

```rust
let rules = RequestAuthorizationProvider::<UserDetail>::builder()
    .method_matchers(Method::GET, "/notes/1")
    .permit_all() // Anyone can read the first note.
    .method_matchers(Method::GET, "/notes/{id}")
    .has_authority("ReadNote") // Other notes require this authority.
    .any_request()
    .deny_all()
    .build()?;
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

```rust
let app = Router::new()
    .nest("/v1/notes", notes_api)
    .route_layer(security_layer);
```

Alternatively, keep security inside the nested router and write local path rules
such as `/1` and `/{id}`. The built-in path matcher reads `Parts.uri`, not Axum's
`OriginalUri` extension.

Use `.matching(...)` to supply a `RequestMatcher` explicitly:

```rust
use axum_auth_chained::{
    basic::{RequestAuthorizationProvider, UserDetail},
    request_matcher::PathPatternRequestMatcher,
};

let rules = RequestAuthorizationProvider::<UserDetail>::builder()
    .matching(PathPatternRequestMatcher::new("/notes/{id}")?)
    .has_authority("ReadNote")
    .any_request()
    .deny_all()
    .build()?;
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

The `request_matcher` module uses `http` types and can be enabled independently with
the `request_matcher` feature; `basic_auth` enables it automatically.

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

Custom identity types can implement `HasAuthorities`. Authority names are compared exactly; no role prefix is added.

## 🔐 Custom authorization

Implement `AuthorizationProvider` for application-specific decisions. It receives an optional identity and borrowed `http::request::Parts`, and may perform async I/O.

Use `.access(manager)` on a request rule when the manager uses the same identity type. Managers can inspect the method, URI, headers, and extensions without copying them; matched path parameters are not extracted automatically. The manager decides how to handle anonymous callers and whether access is allowed. No authority check is added automatically.

Custom manager errors are wrapped in `RequestAuthorizationError`, preserving their source. For a complete policy engine, provide your own `AuthorizationProvider` through `.authorize_with(provider)`. Put application-specific request metadata in extensions before authorization runs.

Check resource ownership and sharing rules in your application service or repository as well. For mutations, enforce access together with the write so a separate earlier check cannot become stale.

## 🧩 Reusing layers

Use `.authenticator(my_authenticator)` to set a single authenticator directly,
without wrapping it in a delegating chain. It does not need to implement `Clone`;
the authentication layer shares it through `Arc`.
Use `.chained_authenticators(|chain| ...)` to configure multiple authentication
mechanisms in order, using the chain's `.authenticator(...)` or
`.shared_authenticator(...)` methods. This replaces the former `.authenticators(...)`
builder method.

A preconfigured `AuthorizationLayer` can be supplied directly:

```rust
let security = SecurityLayerBuilder::builder()
    .authenticator(my_authenticator)
    .authorization_layer(my_authorization_layer)
    .build();
```

Clone the resulting layer to attach it to multiple routers. Authentication providers, authorization rules, and entry points are shared through `Arc`; cloning does not duplicate them. Failure handlers use their own `Clone` implementations.

## 🪪 Sessions and form login

The library provides extension points for session authentication; it does not include a session store or form-login flow. Implement a login endpoint that verifies credentials, creates a session, and sets a cookie. A custom `RequestAuthenticator` can resolve that cookie into a typed identity on subsequent requests.

Authenticators only inspect request parts, so parse login form bodies in a handler. Cookie-based applications also need CSRF protection, including on login and logout. Add CSRF validation separately from authorization so public endpoints remain protected against forged submissions.

## ✨ Features

No optional features are enabled by default. Core authentication and authorization traits, layers, and the security builder are always available.

| Feature | Enables |
| --- | --- |
| `basic_auth` | HTTP Basic authentication, user-detail support, password helpers, and request-rule authorization. |
| `argon2_encoder` | Argon2 support; also enables `basic_auth`. |
| `tracing` | Authentication tracing events. |

`PlainHashPasswordManager` is intended for demonstrations and tests; use a password-hashing implementation for real credentials.

## 📝 Examples

- [Basic authentication with Argon2](examples/examples/axum_basic_auth.rs)
- [CRUD API with authority-based access](examples/examples/simple_crud_rbac_axum.rs)

Run an example from this checkout:

```sh
cargo run --package axum-auth-chained-examples --example axum_basic_auth --features axum-auth-chained/argon2_encoder
cargo run --package axum-auth-chained-examples --example simple_crud_rbac_axum --features axum-auth-chained/basic_auth
```

## 🛠️ Development

```sh
cargo fmt -- --check
cargo clippy --workspace --all-targets --all-features -- -D warnings
cargo test --all-targets --all-features
cargo test --all-features --doc
cargo doc --all-features --no-deps --open
```

## 📄 License

[MIT](LICENSE)
