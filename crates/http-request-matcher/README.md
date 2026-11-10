# http-request-matcher

Synchronous HTTP request matching for routing, middleware selection, and policies.
Matchers inspect `http::request::Parts` without consuming the request body.

- `RequestMatcher`: shared matching interface, with support for `Arc`.
- `PathPatternRequestMatcher`: compiled path patterns with optional method restrictions.
- `MediaTypeRequestMatcher`: matching against the request's `Accept` headers.
- `OrRequestMatcher`: combines two matchers with short-circuit evaluation.
- `AnyRequestMatcher`: matches every request.

```rust
use http::{Method, Request};
use http_request_matcher::{RequestMatcher, PathPatternRequestMatcher};

let matcher = PathPatternRequestMatcher::new("/notes/{id}")?
    .with_method(Method::GET);
let (parts, _) = Request::builder().uri("/notes/42").body(())?.into_parts();
assert!(matcher.matches(&parts));
# Ok::<(), Box<dyn std::error::Error>>(())
```

Matchers select behavior; they do not authenticate requests or grant access.
The crate has no dependency on Tower or an authentication library.
