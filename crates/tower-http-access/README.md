<p align="center">
  <img src="https://raw.githubusercontent.com/Jankbyte/axum-auth-chained/HEAD/assets/logo.png" alt="Tower HTTP Access: a Rust-inspired crab holding a chain between an identity-and-key icon and an authorization shield" width="60%">
</p>

# Tower HTTP Access

Composable HTTP authentication and authorization middleware for Tower, with optional Axum integration.

Use [`SecurityLayer`] to authenticate and authorize requests together, or use the separate
[`authentication::AuthenticationLayer`] and [`authorization::AuthorizationLayer`].
Custom authenticators implement [`authentication::RequestAuthenticator`]; custom authorization
policies implement [`authorization::AuthorizationProvider`]. Successful responses retain their
original body type, including streaming bodies.

The default `axum` feature enables identity extractors. Enable `request_matcher` for ordered
path and method authorization rules. Disable default features for framework-independent Tower use.

HTTP Basic authentication, user-detail types, and password helpers live in the separate
[`tower-http-access-basic`](https://docs.rs/tower-http-access-basic) crate. Import those types
from `tower_http_access_basic`. Add a hashing implementation such as `argon2` directly to
your application’s dependencies and pass it to `AsyncStringPasswordManager`.

See the [project guide](https://github.com/Jankbyte/axum-auth-chained#readme) for configuration,
examples, and integration documentation. The guide's Rust examples are compiled as part of
the Basic crate's documentation tests.
