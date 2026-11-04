<p align="center">
  <img src="https://raw.githubusercontent.com/Jankbyte/axum-auth-chained/HEAD/assets/logo.png" alt="Tower HTTP Access: a Rust-inspired crab holding a chain between an identity-and-key icon and an authorization shield" width="60%">
</p>

# Tower HTTP Access

Base abstractions for building HTTP authentication and authorization layers with Tower.

[`RequestAuthenticator`](authentication::RequestAuthenticator) and [`AuthorizationProvider`](authorization::AuthorizationProvider) define your authentication mechanism and
authorization policy. [`SecurityLayer`](SecurityLayer) connects them and wraps an inner Tower service in a
[`SecurityService`](SecurityService), which coordinates each request:

1. The service calls [`RequestAuthenticator`](authentication::RequestAuthenticator) with mutable request parts (headers, URI, and
   extensions). The authenticator returns an identity, reports that authentication does not
   apply, or fails with an error. It does not consume the request body.
2. The service passes the optional identity and request parts to [`AuthorizationProvider`](authorization::AuthorizationProvider).
   The provider decides whether to allow the request or deny access. Both components share
   the same `Authentication` type, so the identity flows directly between them.
3. If allowed, the service stores any identity in the request extensions as [`Authenticated<T>`](authentication::Authenticated)
   and forwards the request to the inner service. Authentication errors, authorization denials,
   and provider errors produce a response without calling the inner service.

An authentication-required denial invokes the configured [`AuthenticationEntryPoint`](authorization::AuthenticationEntryPoint);
other denials and authorization errors go through [`AuthorizationFailureHandler`](authorization::AuthorizationFailureHandler).
This keeps credential handling, access policy, and application request handling separate.
