use super::*;

#[test]
fn matches_every_request() {
    for (method, path) in [("GET", "/"), ("POST", "/login"), ("DELETE", "/notes/1")] {
        let (parts, _) = http::Request::builder()
            .method(method)
            .uri(path)
            .body(())
            .unwrap()
            .into_parts();
        assert!(AnyRequestMatcher.matches(&parts));
    }
}
