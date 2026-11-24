# Username/password auth abstractions

Abstractions for implementing username/password authentication in HTTP-based
applications, including HTTP Basic authentication and form login.

# Base abstractions

## Authentication provider

It's add [`UsernamePasswordAuthenticationProvider`] trait that should authenticate by [`Credentials`].
The default/demo implementation [`UserDetailAuthenticationProvider`] can be enabled by `user_details` feature.

## Password

The feature `password` will enable [`AsyncPasswordHasher`]/[`AsyncPasswordVerifier`] - abstractions for hashing and
verifing passwords.

It has base implementation [`AsyncStringPasswordManager`] that wraps *[password-hash](https://docs.rs/password-hash/latest/password_hash/)* implementations (like *[argon2](https://docs.rs/argon2/latest/argon2/)*).

# Features

Available features:

| Name           | Description                                                            |
|----------------|------------------------------------------------------------------------|
| `user_details` | Enable [`UserDetail`] abstractions.                                    |
| `serde`        | Enable serialization for `UserDetail` (also enable this feature).      |
| `tracing`      | Enable [tracing](https://docs.rs/tracing/latest/tracing/) for logging. |
| `password`     | Enable [`AsyncPasswordHasher`] abstractions.                           |


[`UserDetail`]: crate::UserDetail
[`Credentials`]: crate::Credentials
[`UserDetailAuthenticationProvider`]: crate::UserDetailAuthenticationProvider
[`UsernamePasswordAuthenticationProvider`]: crate::UsernamePasswordAuthenticationProvider
[`AsyncPasswordHasher`]: crate::AsyncPasswordHasher
[`AsyncPasswordVerifier`]: crate::AsyncPasswordVerifier
[`AsyncStringPasswordManager`]: crate::AsyncStringPasswordManager
