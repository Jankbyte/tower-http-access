# Tower HTTP Access Authorizers

Reusable authorization policies for `tower-http-access-core`.

Authentication requirements, permit/deny policies, and all-of composition are always
available through `default_auth` and `all`.

| Feature | Enables |
| --- | --- |
| `request_matcher` | Ordered, first-match request policies through `request::RequestAuthorizationProvider`. Unmatched requests are denied. |
| `authorities` | The `HasAuthorities` trait, authority-checking policies, and the `AuthorityRuleExt` extension trait for request rules. |

Both features are opt-in. Request policies work without authority support.
Implement `tower_http_access_authorizers::authorities::HasAuthorities` on a local
identity type. No implementation is supplied for `user_password_auth::UserDetail`.
Because both that type and the trait are external to applications, use a local
newtype around `UserDetail` and adapt the authenticator with
`RequestAuthenticatorExt::map`.

```toml
[dependencies]
tower-http-access-core = "0.0.1"
tower-http-access-authorizers = { version = "0.0.1", features = ["request_matcher", "authorities"] }
```

```rust
# #[cfg(feature = "request_matcher")]
# fn example() -> Result<(), http_request_matcher::InvalidRequestPattern> {
use tower_http_access_authorizers::request::RequestAuthorizationProvider;

let rules = RequestAuthorizationProvider::<String>::builder()
    .request_matchers("/health").permit_all()
    .any_request().authenticated()
    .build()?;
# Ok(())
# }
```

Pass policies to `SecurityLayer::new(authenticator, policy)` in core. Authorization
contracts remain in `tower_http_access_core::authorization::core`.

```rust
# #[cfg(feature = "authorities")]
# fn example() {
use tower_http_access_authorizers::authorities::HasAuthorities;

struct User { authorities: Vec<String> }
impl HasAuthorities for User {
    fn has_authority(&self, authority: &str) -> bool {
        self.authorities.iter().any(|granted| granted == authority)
    }
}
let user = User { authorities: vec!["Read".into()] };
assert!(user.has_authority("Read"));
assert!(!user.has_authority("read"));
# }
```

When both features are enabled, import
`use tower_http_access_authorizers::authorities::AuthorityRuleExt;` to use
`.has_authority(...)`, `.has_any_authority(...)`, and `.has_all_authorities(...)`
on a selected request rule. Applications can add their own extension traits in
exactly the same way, implementing them for `PendingRuleBuilder` and using its
public `.access(...)` method.
