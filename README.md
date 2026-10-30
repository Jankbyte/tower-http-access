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
        UserDetailAuthenticationProvider, request_context_mapper,
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
        .authenticators(|chain| chain.shared_authenticator(Arc::clone(&authenticator)))
        .authorization(|authorization| {
            authorization
                .authorize_with(rules, request_context_mapper)
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

Implement `AuthorizationProvider` for application-specific decisions. It receives an optional identity and an owned context, and may perform async I/O.

Use `.access(manager)` on a request rule when the manager uses the same identity type and `RequestContext`. The context contains the request method and URI; it does not currently expose matched path parameters. The manager decides how to handle anonymous callers and whether access is allowed. No authority check is added automatically.

Custom manager errors are wrapped in `RequestAuthorizationError`, preserving their source. For a different context or a complete policy engine, provide your own `AuthorizationProvider` and `AuthorizationContextMapper` through `.authorize_with(provider, mapper)`.

Check resource ownership and sharing rules in your application service or repository as well. For mutations, enforce access together with the write so a separate earlier check cannot become stale.

## 🧩 Reusing layers

A preconfigured `AuthorizationLayer` can be supplied directly:

```rust
let security = SecurityLayerBuilder::builder()
    .authenticators(|chain| chain.authenticator(my_authenticator))
    .authorization_layer(my_authorization_layer)
    .build();
```

Clone the resulting layer to attach it to multiple routers. Authentication providers, authorization rules, and entry points are shared through `Arc`; cloning does not duplicate them. Context mappers and failure handlers use their own `Clone` implementations.

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
