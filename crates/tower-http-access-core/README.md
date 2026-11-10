<p align="center">
  <img src="https://raw.githubusercontent.com/Jankbyte/axum-auth-chained/HEAD/assets/logo.png" alt="Tower HTTP Access: a Rust-inspired crab holding a chain between an identity-and-key icon and an authorization shield" width="60%">
</p>

# Tower HTTP Access Core

Base abstractions for building HTTP authentication and authorization layers with Tower.

[`RequestAuthenticator`](authentication::RequestAuthenticator) and [`AuthorizationProvider`](authorization::core::AuthorizationProvider) define your authentication mechanism and
authorization policy. [`SecurityLayer`](SecurityLayer) connects them and wraps an inner Tower service in a
[`SecurityService`](SecurityService), which coordinates each request:

1. The service calls [`RequestAuthenticator`](authentication::RequestAuthenticator) with borrowed, immutable request parts (headers, URI, and
   extensions). The authenticator returns an identity, reports that authentication does not
   apply, or fails with an error. It does not consume the request body.
2. The service passes the optional identity and request parts to [`AuthorizationProvider`](authorization::core::AuthorizationProvider).
   The provider decides whether to allow the request or deny access. Both components share
   the same `Authentication` type, so the identity flows directly between them.
3. If allowed, the service stores any identity in the request extensions as [`Authenticated<T>`](authentication::Authenticated)
   and forwards the request to the inner service. Authentication errors, authorization denials,
   and provider errors produce a response without calling the inner service.

An authentication-required denial invokes the configured [`AuthenticationEntryPoint`](authorization::core::AuthenticationEntryPoint);
other denials and authorization errors go through [`AuthorizationFailureHandler`](authorization::core::AuthorizationFailureHandler).
This keeps credential handling, access policy, and application request handling separate.

## Features

| Feature name | Adds |
| --- | --- |
| `default` | Enables `axum`. |
| `axum` | Axum extractors for [`Authenticated<T>`](authentication::Authenticated) and `Option<Authenticated<T>>`, plus `IntoResponse` for authentication errors. |
| `request_matcher` | [HTTP request matchers](https://docs.rs/http-request-matcher) and ordered authorization rules through [`RequestAuthorizationProvider`](authorization::request::RequestAuthorizationProvider). |
| `split_auth` | Standalone [`AuthenticationLayer`](authentication::AuthenticationLayer) and [`AuthorizationLayer`](authorization::auth_tower::AuthorizationLayer) for independent middleware placement. |
| `filter_chain` | Selects complete middleware stacks through [`SecurityChainLayer`](filter_chain::SecurityChainLayer). Also enables `request_matcher`. |

Authentication and authorization traits and `SecurityLayer` are always available.
Use `default-features = false` for Tower integration without Axum.

```toml
tower-http-access-core = { version = "0.0.1", features = ["filter_chain"] }
```
