use super::*;

#[test]
fn invalid_patterns_preserve_the_input_in_the_error() {
    for pattern in [
        "",
        "notes",
        "https://example.com/notes",
        "/notes?view=full",
        "/notes#section",
        "/notes/{}",
        "/notes/{id",
        "/notes/id}",
        "/notes/{*rest}/child",
    ] {
        let error = match PathPatternRequestMatcher::new(pattern) {
            Err(error) => error,
            Ok(_) => panic!("expected InvalidRequestPattern for {pattern:?}"),
        };
        assert_eq!(error.0, pattern);
        assert_eq!(
            error.to_string(),
            format!("invalid request path pattern: {pattern}"),
        );
    }
}

#[test]
fn method_restrictions_require_both_method_and_path() {
    let unrestricted = PathPatternRequestMatcher::new("/notes/{id}").unwrap();
    let restricted = PathPatternRequestMatcher::new("/notes/{id}")
        .unwrap()
        .with_method(Method::GET);
    for (method, path, expected) in [
        (Method::GET, "/notes/42?view=full", true),
        (Method::POST, "/notes/42", false),
        (Method::HEAD, "/notes/42", false),
        (Method::GET, "/other/42", false),
        (Method::GET, "/notes/42/", false),
    ] {
        let (parts, _) = http::Request::builder()
            .method(method)
            .uri(path)
            .body(())
            .unwrap()
            .into_parts();
        assert_eq!(restricted.matches(&parts), expected);
        if parts.uri.path() == "/notes/42" {
            assert!(unrestricted.matches(&parts));
        }
    }
}

#[test]
fn setting_method_again_replaces_restriction_and_supports_custom_methods() {
    let matcher = PathPatternRequestMatcher::new("/notes/{id}")
        .unwrap()
        .with_method(Method::GET)
        .with_method(Method::from_bytes(b"LIST").unwrap());
    for (method, expected) in [("GET", false), ("LIST", true)] {
        let (parts, _) = http::Request::builder()
            .method(method)
            .uri("/notes/42")
            .body(())
            .unwrap()
            .into_parts();
        assert_eq!(matcher.matches(&parts), expected);
    }
}
