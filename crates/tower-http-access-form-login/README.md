# Tower HTTP Access Form Login

Use `tower_http_access_form_login::{FormLoginLayer, SuccessHandler, FailureHandler}`.
`FormLoginLayer` authenticates form submissions through a
`UsernamePasswordAuthenticationProvider`. Configure request matching, credential
field names, and response handling with `request_matcher` (for example, a `PathPatternRequestMatcher` with `with_method`), `username_parameter`,
`password_parameter`, `on_success`, and `on_failure`.

Both handler traits support custom structs and async closures. Success handlers
own session persistence and the response; failure handlers receive `FormLoginError`. Backend failures carry a boxed error
available through `std::error::Error::source`, so handlers are independent of the
provider's concrete error type.
Place session middleware outside the layer when handlers need session access.

The layer stores concrete provider, matcher, and handler types. These must implement
`Clone` when applying the layer. Wrap components in `Arc` to share them; providers,
matchers, and both handler traits support `Arc`, including trait objects. The default
handlers are `DefaultSuccessHandler` (200) and `DefaultFailureHandler` (a status based
on the failure). Builder methods infer replacement matcher and handler types.

`RedirectFormLoginHandler` returns a 303 redirect to a validated same-origin path.
The layer is independent of session storage. To persist login with `tower-sessions`,
use `tower_http_access_session::tower_sessions::SessionSetSuccessHandler` with the session crate's
`form_login` feature.

```rust
use tower_http_access_form_login::{FormLoginLayer, RedirectFormLoginHandler};
use user_password_auth::UsernamePasswordAuthenticationProvider;

fn login_layer<P: UsernamePasswordAuthenticationProvider>(provider: P) {
    let layer = FormLoginLayer::new(provider)
        .on_success(RedirectFormLoginHandler::new("/private").unwrap());
    // Apply the layer to a Tower service. Add persistence in a custom success
    // handler, or use SessionSetSuccessHandler for tower-sessions.
}
```

By default, the layer handles `POST /login`, reads `username` and `password`, and
limits the form body to 16 KiB. Nonmatching requests pass through unchanged.
Configure CSRF protection before this layer when using browser credentials.


`RedirectFormLoginHandler` redirects all failures, including backend errors, to a
validated same-origin path. It implements both handler traits and can be
configured for either outcome, returning HTTP 303.

```rust
use tower_http_access_form_login::{FormLoginLayer, RedirectFormLoginHandler};
use user_password_auth::UsernamePasswordAuthenticationProvider;

fn login_layer<P: UsernamePasswordAuthenticationProvider>(provider: P) {
    let redirect = RedirectFormLoginHandler::new("/login/result").unwrap();
    let layer = FormLoginLayer::new(provider)
        .on_success(redirect.clone())
        .on_failure(redirect);
}
```

For different destinations, configure
`.on_success(RedirectFormLoginHandler::new("/private")?)` and
`.on_failure(RedirectFormLoginHandler::new("/login?error=true")?)`.
