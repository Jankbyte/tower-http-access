# user-password-auth

Abstractions for implementing username/password authentication in HTTP-based
applications, including HTTP Basic authentication and form login.

HTTP integrations extract credentials from requests and pass them to a
`UsernamePasswordAuthenticationProvider` for verification. The same provider can
serve multiple authentication mechanisms.

`Credentials`, `UsernamePasswordAuthenticationProvider`, and password hashing and
verification helpers are always available. `Credentials` redacts the password in
its `Debug` output.

Enable `user_details` to use `UserDetail`, `Authority`, `UserDetailService`,
`UserDetailAuthenticationProvider`, `InMemoryUserDetailService`, and their errors:

```toml
user-password-auth = { version = "0.0.1", features = ["user_details"] }
```

`UserDetailAuthenticationProvider` loads users through a `UserDetailService` and
verifies their passwords. Applications implementing their own identity types and
providers can leave `user_details` disabled. No features are enabled by default.

`AsyncStringPasswordManager` runs password operations on Tokio's blocking pool
with a configurable concurrency limit. Password helpers remain available without
`user_details`, including their Tokio and password-hashing dependencies.
