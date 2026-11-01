use super::*;
use crate::authorization::{
    AllAuthorizationProvider, AuthorizationDenial, AuthorizationProviderExt,
    DenyAllAuthorizationProvider, PermitAllAuthorizationProvider,
};

struct Principal(Vec<&'static str>);
impl HasAuthorities for Principal {
    fn has_authority(&self, authority: &str) -> bool {
        self.0.contains(&authority)
    }
}

#[tokio::test]
async fn authority_providers_preserve_anonymous_any_all_and_empty_list_semantics() {
    let providers: Vec<
        Box<dyn AuthorizationProvider<Authentication = Principal, Error = Infallible>>,
    > = vec![
        Box::new(AuthorityAuthorizationProvider::new("Read")),
        Box::new(AnyAuthorityAuthorizationProvider::new(["Read", "Write"])),
        Box::new(AllAuthoritiesAuthorizationProvider::new(["Read", "Write"])),
        Box::new(AnyAuthorityAuthorizationProvider::new(Vec::<String>::new())),
        Box::new(AllAuthoritiesAuthorizationProvider::new(
            Vec::<String>::new(),
        )),
    ];
    let (parts, _) = http::Request::new(()).into_parts();
    for provider in &providers {
        assert_eq!(
            provider.authorize(None, &parts).await.unwrap(),
            AuthorizationDecision::Deny(AuthorizationDenial::AuthenticationRequired)
        );
    }
    for (identity, allowed) in [
        (Principal(vec![]), [false, false, false, false, true]),
        (Principal(vec!["Read"]), [true, true, false, false, true]),
        (
            Principal(vec!["Read", "Write"]),
            [true, true, true, false, true],
        ),
        (Principal(vec!["read"]), [false, false, false, false, true]),
    ] {
        for (provider, allowed) in providers.iter().zip(allowed) {
            let expected = if allowed {
                AuthorizationDecision::Allow
            } else {
                AuthorizationDecision::Deny(AuthorizationDenial::InsufficientPermissions)
            };
            assert_eq!(
                provider.authorize(Some(&identity), &parts).await.unwrap(),
                expected
            );
        }
    }
}

#[tokio::test]
async fn authority_checks_compose_and_map_without_request_matching_or_basic_authentication() {
    let provider = AllAuthorizationProvider::<Principal>::builder()
        .with(AuthorityAuthorizationProvider::new("Read"))
        .with(AllAuthoritiesAuthorizationProvider::new(["Write", "Share"]))
        .build()
        .unwrap()
        .map(|roles: &Vec<&'static str>| Principal(roles.clone()));
    let (parts, _) = http::Request::new(()).into_parts();
    assert_eq!(
        provider
            .authorize(Some(&vec!["Read", "Write", "Share"]), &parts)
            .await
            .unwrap(),
        AuthorizationDecision::Allow
    );
    assert_eq!(
        provider
            .authorize(Some(&vec!["Read"]), &parts)
            .await
            .unwrap(),
        AuthorizationDecision::Deny(AuthorizationDenial::InsufficientPermissions)
    );
}

#[tokio::test]
async fn permit_and_deny_providers_work_without_authority_traits() {
    let permit = PermitAllAuthorizationProvider::<String>::default();
    let deny = DenyAllAuthorizationProvider::<String>::default();
    let (parts, _) = http::Request::new(()).into_parts();
    let identity = "alex".to_owned();
    for (identity, expected) in [
        (
            None,
            AuthorizationDecision::Deny(AuthorizationDenial::AuthenticationRequired),
        ),
        (
            Some(&identity),
            AuthorizationDecision::Deny(AuthorizationDenial::InsufficientPermissions),
        ),
    ] {
        assert_eq!(
            permit.authorize(identity, &parts).await.unwrap(),
            AuthorizationDecision::Allow
        );
        assert_eq!(deny.authorize(identity, &parts).await.unwrap(), expected);
    }
}
