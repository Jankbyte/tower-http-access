# Core abstractions

This have three main abstractions for implementing authentication/authorization in middleware:

* [`RequestAuthenticator`] - the HTTP-request authenticator, that accept HTTP-request metadata (headers and e.g.) and tries
  authenticate user from this request.
* [`AuthorizationProvider`] - executes after [`RequestAuthenticator`] and verify permissions of authenticated/unauthenticated user.
* [`SecurityLayer`] - the security layer for aggregate [`RequestAuthenticator`] and [`AuthorizationProvider`] into single mechanism.

The crate orinted to build middleware layers from [`Service`].
The `Request` and `Response` content must be coeerted to [`Body`] where `Data` is [`Bytes`]. It compatible with [`Incoming`] from `hyper` and [`Axum Body`] from `axum` crate.

[`RequestAuthenticator`]: crate::core::authentication::RequestAuthenticator
[`AuthorizationProvider`]: crate::core::authorization::AuthorizationProvider
[`SecurityLayer`]: crate::core::security_layer::SecurityLayer
[`Service`]: https://docs.rs/tower-service/0.3.3/tower_service/trait.Service.html
[`Body`]: https://docs.rs/http-body/1.1.0/http_body/trait.Body.html
[`AxumBody`]: https://docs.rs/axum/latest/axum/body/struct.Body.html
[`Bytes`]: https://docs.rs/bytes/latest/bytes/struct.Bytes.html
[`Incoming`]: https://docs.rs/hyper/latest/hyper/body/struct.Incoming.html
