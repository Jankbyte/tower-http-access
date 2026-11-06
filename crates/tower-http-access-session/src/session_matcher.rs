use http::{header, request::Parts};
use tower_http_access::request_matcher::RequestMatcher;

/// Selects requests containing the configured session cookie, without validating it.
///
/// Available with `session_matcher`. Names are case-sensitive and matched exactly
/// across all Cookie headers. The default name is `id`; configure the same name
/// as `SessionManagerLayer::with_name` if using a custom cookie name.
///
/// This is a routing check only: even empty, expired, or forged session cookies
/// select the chain. Session authentication must still validate the session.
#[derive(Clone, Debug)]
pub struct SessionCookieRequestMatcher {
    name: String,
}

impl SessionCookieRequestMatcher {
    pub fn new(name: impl Into<String>) -> Self {
        Self { name: name.into() }
    }
}

impl Default for SessionCookieRequestMatcher {
    fn default() -> Self {
        Self::new("id")
    }
}

impl RequestMatcher for SessionCookieRequestMatcher {
    fn matches(&self, request: &Parts) -> bool {
        request
            .headers
            .get_all(header::COOKIE)
            .iter()
            .any(|header| {
                header.to_str().is_ok_and(|cookies| {
                    cookies.split(';').any(|cookie| {
                        cookie
                            .trim()
                            .split_once('=')
                            .is_some_and(|(name, _)| name == self.name)
                    })
                })
            })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn checks_exact_cookie_names_across_headers() {
        for (cookies, expected) in [
            (vec![], false),
            (vec!["id=abc"], true),
            (vec!["theme=dark; id=abc==; other=x"], true),
            (vec!["id="], true),
            (vec!["id"], false),
            (vec!["other_id=abc; ID=abc; theme=id=abc"], false),
            (vec!["theme=dark", "id=abc"], true),
        ] {
            let mut request = http::Request::builder();
            for cookie in cookies {
                request = request.header(header::COOKIE, cookie);
            }
            let (parts, _) = request.body(()).unwrap().into_parts();
            assert_eq!(
                SessionCookieRequestMatcher::default().matches(&parts),
                expected
            );
        }
        let (parts, _) = http::Request::builder()
            .header(header::COOKIE, "JSESSIONID=abc")
            .body(())
            .unwrap()
            .into_parts();
        assert!(SessionCookieRequestMatcher::new("JSESSIONID").matches(&parts));
        assert!(!SessionCookieRequestMatcher::default().matches(&parts));
    }
}
