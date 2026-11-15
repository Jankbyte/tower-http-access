<p align="center">
  <img src="https://raw.githubusercontent.com/Jankbyte/axum-auth-chained/HEAD/assets/logo.svg" alt="Tower HTTP Access: a Rust-inspired crab holding a chain between an identity-and-key icon and an authorization shield" width="60%">
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
3. If allowed and authenticated, the service passes the identity to
   [`AuthenticationSuccessHandler`](authentication::AuthenticationSuccessHandler). The default handler
   stores it in request extensions as [`Authenticated<T>`](authentication::Authenticated). Configure
   [`SecurityLayer::authentication_success_handler`] to use custom identity storage. The handler runs
   synchronously before forwarding the request to the inner service. Authentication errors, authorization denials,
   and provider errors produce a response without calling the inner service.

An authentication-required denial invokes the configured [`AuthenticationEntryPoint`](authorization::core::AuthenticationEntryPoint);
other denials and authorization errors go through [`AuthorizationFailureHandler`](authorization::core::AuthorizationFailureHandler).
This keeps credential handling, access policy, and application request handling separate.

## Features

| Feature name | Adds |
| --- | --- |
| `default` | Enables `axum` and `authorizers`. |
| `authorizers` | Built-in authentication and permit/deny policies in [`authorization`], the `denied` helper, and `SecurityLayer::authenticated`. |
| `axum` | Axum extractors for [`Authenticated<T>`](authentication::Authenticated) and `Option<Authenticated<T>>`. |
| `request_matcher` | Request-based authentication entry-point selection using `http-request-matcher`. |
| `filter_chain` | Selects complete middleware stacks through [`SecurityChainLayer`](filter_chain::SecurityChainLayer). Also enables `request_matcher`. |

With the default-enabled `authorizers` feature, use
`SecurityLayer::authenticated(authenticator)` to require authentication without
additional authorization checks, or `SecurityLayer::new(authenticator, policy)` for
a custom policy. Both constructors support the same handler and response customization.

Authentication and authorization traits and `SecurityLayer` are always available.
Use `default-features = false, features = ["authorizers"]` for built-in policies
without Axum, or disable all default features when supplying only custom policies.

```toml
tower-http-access-core = { version = "0.0.1", features = ["filter_chain"] }
```

Basic authentication requirements and permit/deny policies live in
[`authorization`] with the `authorizers` feature. Request rules, authority checks, and all-of composition
live in `tower-http-access-authorizers`. Authority support is
opt-in through that crate's `authorities` feature and includes the `HasAuthorities` trait for application-defined identities.
