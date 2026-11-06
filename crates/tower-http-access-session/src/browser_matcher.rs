use http::{header, request::Parts};
use tower_http_access::request_matchers::RequestMatcher;

/// Selects browser-style HTML flows by checking for an explicit `Accept: text/html`.
///
/// Available with `browser_matcher`. Use this with
/// `SecurityChainLayer::builder().chain(BrowserRequestMatcher, browser_stack)`
/// to run session middleware and form-login security only for HTML requests.
/// Put explicit credential chains, such as HTTP Basic, before this chain.
///
/// Matches media types case-insensitively across multiple header values, excluding
/// entries with `q=0`. Wildcard accept values (`*/*`, `text/*`) do not match.
/// This is a content-negotiation heuristic, not proof of browser identity or an
/// access-control check. Browser fetch requests may not advertise HTML; any client
/// can send this header. Authentication and authorization must still run in the stack.
#[derive(Clone, Copy, Debug, Default)]
pub struct BrowserRequestMatcher;
impl RequestMatcher for BrowserRequestMatcher {
    fn matches(&self, request: &Parts) -> bool {
        request.headers.get_all(header::ACCEPT).iter().any(|value| {
            value.to_str().is_ok_and(|value| {
                value.split(',').any(|range| {
                    let mut parts = range.split(';');
                    parts
                        .next()
                        .is_some_and(|media| media.trim().eq_ignore_ascii_case("text/html"))
                        && !parts.any(|parameter| {
                            parameter
                                .trim()
                                .split_once('=')
                                .is_some_and(|(name, value)| {
                                    name.trim().eq_ignore_ascii_case("q")
                                        && value
                                            .trim()
                                            .parse::<f32>()
                                            .is_ok_and(|quality| quality == 0.0)
                                })
                        })
                })
            })
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn selects_explicit_html_and_excludes_zero_quality_and_wildcards() {
        for (accept, expected) in [
            (None, false),
            (Some("text/html"), true),
            (
                Some("application/json, Text/HTML; charset=utf-8; q=0.8"),
                true,
            ),
            (Some("text/html;q=0"), false),
            (Some("text/html;q=0.000"), false),
            (Some("*/*"), false),
            (Some("text/*"), false),
            (Some("application/json"), false),
        ] {
            let mut request = http::Request::builder();
            if let Some(accept) = accept {
                request = request.header(header::ACCEPT, accept);
            }
            let (parts, _) = request.body(()).unwrap().into_parts();
            assert_eq!(
                BrowserRequestMatcher.matches(&parts),
                expected,
                "{accept:?}"
            );
        }
        let (parts, _) = http::Request::builder()
            .header(header::ACCEPT, "application/json")
            .header(header::ACCEPT, "text/html")
            .body(())
            .unwrap()
            .into_parts();
        assert!(BrowserRequestMatcher.matches(&parts));
    }
}
