use super::*;
use axum::{body::Body, http::header::AUTHORIZATION};
use std::convert::Infallible;

#[derive(Clone, Debug, Eq, PartialEq)]
struct CustomIdentity(String);

struct CustomProvider;

impl UsernamePasswordAuthenticationProvider for CustomProvider {
    type Authentication = CustomIdentity;
    type Error = Infallible;

    fn authenticate<'a>(
        &'a self,
        credentials: &'a BasicCredentials,
    ) -> UsernamePasswordAuthenticationFuture<'a, Self::Authentication, Self::Error> {
        Box::pin(async move {
            Ok(
                (credentials.username == "alex" && credentials.password == "alex123")
                    .then(|| CustomIdentity(credentials.username.clone())),
            )
        })
    }
}

fn request(authorization: &str) -> Request {
    Request::builder()
        .header(AUTHORIZATION, authorization)
        .body(Body::empty())
        .unwrap()
}

#[tokio::test]
async fn basic_authenticator_returns_provider_identity_type() {
    let authenticator = BasicRequestAuthenticator::new(CustomProvider);
    let (mut parts, _) = request("Basic YWxleDphbGV4MTIz").into_parts();

    let result = authenticator.authenticate(&mut parts).await.unwrap();

    assert_eq!(
        result,
        AuthenticationAttempt::Authenticated(CustomIdentity("alex".to_owned()))
    );
}

#[tokio::test]
async fn basic_authenticator_invalid_credentials_return_basic_challenge() {
    let authenticator = BasicRequestAuthenticator::new(CustomProvider);
    let (mut parts, _) = request("Basic YWxleDpiYWQ=").into_parts();

    let error = authenticator.authenticate(&mut parts).await.unwrap_err();
    let response = error.into_response();

    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    assert_eq!(
        response.headers()[header::WWW_AUTHENTICATE],
        r#"Basic realm="Realm""#
    );
}

#[tokio::test]
async fn basic_authenticator_other_scheme_is_not_applicable() {
    let authenticator = BasicRequestAuthenticator::new(CustomProvider);
    let (mut parts, _) = request("Bearer token").into_parts();

    let result = authenticator.authenticate(&mut parts).await.unwrap();

    assert_eq!(result, AuthenticationAttempt::NotApplicable);
}
