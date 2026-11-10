use http::request::Parts;
use http_request_matcher::MediaTypeRequestMatcher;
use http_request_matcher::OrRequestMatcher;
use http_request_matcher::RequestMatcher;

use crate::SessionCookieRequestMatcher;

/// Selects HTML requests or requests carrying a session cookie.
///
/// Available with `browser_matcher`, which also enables `session_matcher`.
/// Put explicit credential chains, such as HTTP Basic, before this chain.
/// The default cookie name is `id`; configure the same name as the session manager.
///
/// HTML matching uses [`MediaTypeRequestMatcher`] compatibility semantics, ignoring
/// requested `*/*` and `text/*` ranges (including the missing-Accept fallback).
/// Parameters are ignored, including `q=0`; malformed Accept headers do not match
/// the media branch. Cookie presence can still match independently.
///
/// This selects a middleware stack, not a trusted browser identity. Cookie presence
/// does not validate a session. Authentication and authorization must still run.
#[derive(Clone, Debug)]
pub struct BrowserRequestMatcher {
    matcher: OrRequestMatcher<MediaTypeRequestMatcher, SessionCookieRequestMatcher>,
}

impl BrowserRequestMatcher {
    /// Select HTML requests or requests carrying the specified session cookie.
    pub fn new(cookie_name: impl Into<String>) -> Self {
        let media = MediaTypeRequestMatcher::new(["text/html"])
            .expect("valid HTML media type")
            .with_ignored_media_types(["*/*", "text/*"])
            .expect("valid ignored media types");
        Self {
            matcher: OrRequestMatcher::new(media, SessionCookieRequestMatcher::new(cookie_name)),
        }
    }
}

impl Default for BrowserRequestMatcher {
    fn default() -> Self {
        Self::new("id")
    }
}

impl RequestMatcher for BrowserRequestMatcher {
    fn matches(&self, request: &Parts) -> bool {
        self.matcher.matches(request)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use http::{Request, header};

    #[test]
    fn selects_html_or_session_cookie() {
        let matcher = BrowserRequestMatcher::default();
        for (accept, cookie, expected) in [
            (None, None, false),
            (Some("text/html"), None, true),
            (
                Some("application/json, Text/HTML; charset=utf-8; q=0.8"),
                None,
                true,
            ),
            (Some("text/html;q=0"), None, true),
            (Some("*/*"), None, false),
            (Some("text/*"), None, false),
            (Some("application/json"), None, false),
            (Some("text/html, invalid"), None, false),
            (None, Some("id=abc"), true),
            (Some("application/json"), Some("id="), true),
            (Some("invalid"), Some("id=expired"), true),
            (Some("application/json"), Some("other_id=abc"), false),
        ] {
            let mut request = Request::builder();
            if let Some(accept) = accept {
                request = request.header(header::ACCEPT, accept);
            }
            if let Some(cookie) = cookie {
                request = request.header(header::COOKIE, cookie);
            }
            let (parts, _) = request.body(()).unwrap().into_parts();
            assert_eq!(matcher.matches(&parts), expected, "{accept:?}, {cookie:?}");
        }
    }

    #[test]
    fn supports_custom_cookie_names_and_multiple_headers() {
        let matcher = BrowserRequestMatcher::new("JSESSIONID");
        let (parts, _) = Request::builder()
            .header(header::ACCEPT, "application/json")
            .header(header::COOKIE, "id=abc")
            .header(header::COOKIE, "JSESSIONID=abc")
            .body(())
            .unwrap()
            .into_parts();
        assert!(matcher.matches(&parts));
        let (parts, _) = Request::builder()
            .header(header::COOKIE, "id=abc")
            .body(())
            .unwrap()
            .into_parts();
        assert!(!matcher.matches(&parts));
        let (parts, _) = Request::builder()
            .header(header::ACCEPT, "application/json")
            .header(header::ACCEPT, "text/html")
            .body(())
            .unwrap()
            .into_parts();
        assert!(matcher.clone().matches(&parts));
    }
}
