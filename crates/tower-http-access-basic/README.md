<p align="center">
  <img src="https://raw.githubusercontent.com/Jankbyte/axum-auth-chained/HEAD/assets/logo.png" alt="Tower HTTP Access: a Rust-inspired crab holding a chain between an identity-and-key icon and an authorization shield" width="60%">
</p>

# Tower HTTP Access Basic

HTTP Basic authentication for Tower HTTP Access.

User details, credential providers, and password helpers live in the standalone
`user-password-auth` crate and are imported directly from it. The shared credentials type is
`Credentials`.

[`BasicRequestAuthenticator`] reads Basic credentials from the request and passes them to
[`UserDetailAuthenticationProvider`](https://docs.rs/user-password-auth/latest/user_password_auth/struct.UserDetailAuthenticationProvider.html). The provider loads a [`UserDetail`](https://docs.rs/user-password-auth/latest/user_password_auth/struct.UserDetail.html) through a
[`UserDetailService`](https://docs.rs/user-password-auth/latest/user_password_auth/trait.UserDetailService.html) and verifies the password. On success, the identity is passed to
Tower HTTP Access for authorization and made available to handlers as
[`Authenticated<UserDetail>`](tower_http_access_core::authentication::Authenticated).

[`InMemoryUserDetailService`](https://docs.rs/user-password-auth/latest/user_password_auth/struct.InMemoryUserDetailService.html) provides a simple user store. Implement [`UserDetailService`](https://docs.rs/user-password-auth/latest/user_password_auth/trait.UserDetailService.html)
to load users from your database. [`AsyncStringPasswordManager`](https://docs.rs/user-password-auth/latest/user_password_auth/struct.AsyncStringPasswordManager.html) runs password hashing and
verification on blocking workers with a configurable concurrency limit; supply a hashing
implementation such as Argon2.

## Example

This Axum example allows public health checks and requires the `ReadNote` authority to read notes.

```toml
[dependencies]
axum = "0.8"
tower-http-access-core = "0.0.1"
tower-http-access-authorizers = { version = "0.0.1", features = ["request_matcher", "authorities"] }
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
use tower_http_access_core::authentication::{Authenticated, RequestAuthenticatorExt};
use tower_http_access_authorizers::request::RequestAuthorizationProvider;
use tower_http_access_authorizers::authorities::{AuthorityRuleExt, HasAuthorities};
use tower_http_access_basic::BasicRequestAuthenticator;
use user_password_auth::{AsyncStringPasswordManager, Authority, InMemoryUserDetailService, UserDetail, UserDetailAuthenticationProvider};

#[derive(Clone)]
struct AppUser(UserDetail);

impl HasAuthorities for AppUser {
    fn has_authority(&self, authority: &str) -> bool {
        self.0.authorities.iter().any(|granted| granted.0 == authority)
    }
}


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
    ).map(AppUser));

    let rules = RequestAuthorizationProvider::<AppUser>::builder()
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

async fn read_note(Authenticated(user): Authenticated<AppUser>) -> String {
    format!("Authenticated as {}", user.0.username)
}
# }
# fn main() {}
```

```sh
curl http://127.0.0.1:3000/health
curl -u alex:change-me http://127.0.0.1:3000/notes/1
```

The credentials above are for local demonstration. Use HTTPS when sending Basic credentials.

See the [project guide](https://github.com/Jankbyte/axum-auth-chained#readme)
for more configuration and authorization examples.
