#![cfg(feature = "request_matcher")]

use http::Request;
use tower_http_access_authorizers::request::RequestAuthorizationProvider;
use tower_http_access_core::authorization::core::{
    AuthorizationDecision, AuthorizationDenial, AuthorizationProvider,
};

#[tokio::test]
async fn request_rules_work_without_authority_support() {
    let rules = RequestAuthorizationProvider::<String>::builder()
        .request_matchers("/health")
        .permit_all()
        .request_matchers("/private")
        .authenticated()
        .build()
        .unwrap();
    let (health, _) = Request::builder()
        .uri("/health")
        .body(())
        .unwrap()
        .into_parts();
    let (private, _) = Request::builder()
        .uri("/private")
        .body(())
        .unwrap()
        .into_parts();
    let (unknown, _) = Request::builder()
        .uri("/unknown")
        .body(())
        .unwrap()
        .into_parts();
    let user = String::from("alex");
    assert!(matches!(
        rules.authorize(None, &health).await.unwrap(),
        AuthorizationDecision::Allow
    ));
    assert!(matches!(
        rules.authorize(None, &private).await.unwrap(),
        AuthorizationDecision::Deny(AuthorizationDenial::AuthenticationRequired)
    ));
    assert!(matches!(
        rules.authorize(Some(&user), &private).await.unwrap(),
        AuthorizationDecision::Allow
    ));
    assert!(matches!(
        rules.authorize(Some(&user), &unknown).await.unwrap(),
        AuthorizationDecision::Deny(AuthorizationDenial::InsufficientPermissions)
    ));
}

#[tokio::test]
async fn first_matching_rule_remains_final() {
    let rules = RequestAuthorizationProvider::<String>::builder()
        .request_matchers("/private")
        .deny_all()
        .any_request()
        .permit_all()
        .build()
        .unwrap();
    let (parts, _) = Request::builder()
        .uri("/private")
        .body(())
        .unwrap()
        .into_parts();
    assert!(matches!(
        rules
            .authorize(Some(&String::from("alex")), &parts)
            .await
            .unwrap(),
        AuthorizationDecision::Deny(AuthorizationDenial::InsufficientPermissions)
    ));
}
