use super::*;
use crate::authorization::{
    AuthorizationDecision, AuthorizationProvider, RequestAuthorizationProvider,
};

#[tokio::test]
async fn catch_all_rule_applies_after_specific_rules_and_before_later_rules() {
    let provider = RequestAuthorizationProvider::<String>::builder()
        .request_matchers("/public")
        .permit_all()
        .matching(AnyRequestMatcher)
        .deny_all()
        .request_matchers("/later")
        .permit_all()
        .build()
        .unwrap();

    for (method, path, allowed) in [
        ("GET", "/public", true),
        ("GET", "/private", false),
        ("POST", "/later", false),
        ("DELETE", "/", false),
    ] {
        let (parts, _) = http::Request::builder()
            .method(method)
            .uri(path)
            .body(())
            .unwrap()
            .into_parts();
        let decision = provider.authorize(None, &parts).await.unwrap();
        assert!(matches!(
            (decision, allowed),
            (AuthorizationDecision::Allow, true) | (AuthorizationDecision::Deny(_), false)
        ));
    }
}
