# HTTP-request matcher

The collection of HTTP-request matchers for matching [`Parts`]. It can be used
with components for filtering incoming HTTP-requests.

Inspired by [Spring security RequestMatcher](https://docs.spring.io/spring-security/reference/api/java/org/springframework/security/web/util/matcher/RequestMatcher.html).

# Features

Available features:

| Name             | Description                           |
|------------------|---------------------------------------|
| `media_type`     | Enable [`MediaTypeRequestMatcher`].   |
| `path` (default) | Enable [`PathPatternRequestMatcher`]. |


[`MediaTypeRequestMatcher`]: crate::MediaTypeRequestMatcher
[`PathPatternRequestMatcher`]: crate::PathPatternRequestMatcher
[`Parts`]: https://docs.rs/http/latest/http/request/struct.Parts.html
