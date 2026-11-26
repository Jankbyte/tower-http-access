use super::*;
use crate::response::test_response;
use axum::{body::Body, extract::Request, http::StatusCode};
use std::io;

#[test]
fn authenticator_error_displays_reason_and_exposes_backend_source() {
    let invalid = AuthenticatorError::invalid_credentials();
    assert_eq!(invalid.to_string(), "wrong credentials");
    assert!(invalid.source().is_none());

    let internal = AuthenticatorError::internal(io::Error::other("database unavailable"));
    assert_eq!(
        internal.to_string(),
        "internal authenticator error: database unavailable"
    );
    let source = internal.source().unwrap();
    assert!(source.downcast_ref::<io::Error>().is_some());
    assert_eq!(source.to_string(), "database unavailable");
}

#[test]
fn authenticator_error_preserves_internal_reason_and_custom_response() {
    let error = AuthenticatorError::with_response(
        Reason::Internal(Box::new(io::Error::other("database unavailable"))),
        test_response(StatusCode::SERVICE_UNAVAILABLE, ""),
    );

    assert!(matches!(&error.reason, Reason::Internal(_)));
    assert_eq!(
        error.into_security_response().status(),
        StatusCode::SERVICE_UNAVAILABLE
    );
}

#[test]
fn authenticator_error_uses_default_response_for_reason() {
    let wrong_credentials = AuthenticatorError::invalid_credentials().into_security_response();
    let internal = AuthenticatorError::internal(io::Error::other("database unavailable"))
        .into_security_response();

    assert_eq!(wrong_credentials.status(), StatusCode::UNAUTHORIZED);
    assert_eq!(internal.status(), StatusCode::INTERNAL_SERVER_ERROR);
}

#[tokio::test]
async fn mapped_authenticator_converts_authenticated_value() {
    #[derive(Clone, Debug, Eq, PartialEq)]
    struct Principal(String);

    let authenticator = (|_: &Parts| async {
        Ok::<_, AuthenticatorError>(AuthenticationAttempt::Authenticated(42))
    })
    .map(|user_id| Principal(format!("user-{user_id}")));
    let (parts, _) = Request::new(Body::empty()).into_parts();

    let attempt = RequestAuthenticator::authenticate(&authenticator, &parts)
        .await
        .unwrap();

    assert_eq!(
        attempt,
        AuthenticationAttempt::Authenticated(Principal("user-42".to_owned()))
    );
}

#[tokio::test]
async fn arc_authenticators_forward_attempts_errors_and_request_metadata() {
    struct SharedAuthenticator(u8);

    impl RequestAuthenticator for SharedAuthenticator {
        type Authentication = String;

        fn authenticate<'a>(
            &'a self,
            parts: &'a Parts,
        ) -> BoxFuture<'a, Result<AuthenticationAttempt<Self::Authentication>, AuthenticatorError>>
        {
            Box::pin(async move {
                assert_eq!(parts.headers["x-auth-attempt"], "seen");
                match self.0 {
                    0 => Ok(AuthenticationAttempt::NotApplicable),
                    1 => Ok(AuthenticationAttempt::Authenticated("alex".to_owned())),
                    _ => Err(AuthenticatorError::with_response(
                        Reason::WrongCredentials,
                        test_response(StatusCode::IM_A_TEAPOT, ""),
                    )),
                }
            })
        }
    }

    async fn check<A: RequestAuthenticator<Authentication = String>>(
        authenticator: A,
        attempt: u8,
    ) {
        let (parts, _) = Request::builder()
            .header("x-auth-attempt", "seen")
            .body(Body::empty())
            .unwrap()
            .into_parts();
        let result = authenticator.authenticate(&parts).await;
        assert_eq!(parts.headers["x-auth-attempt"], "seen");
        match (attempt, result) {
            (0, Ok(AuthenticationAttempt::NotApplicable)) => (),
            (1, Ok(AuthenticationAttempt::Authenticated(user))) => assert_eq!(user, "alex"),
            (2, Err(error)) => {
                assert!(matches!(error.reason, Reason::WrongCredentials));
                assert_eq!(error.response.unwrap().status(), StatusCode::IM_A_TEAPOT);
            }
            _ => panic!("shared authenticator changed the result"),
        }
    }

    for attempt in 0..=2 {
        let concrete = Arc::new(SharedAuthenticator(attempt));
        check(Arc::clone(&concrete), attempt).await;
        let erased: Arc<dyn RequestAuthenticator<Authentication = String>> = concrete;
        check(erased, attempt).await;
    }
}

#[tokio::test]
async fn authenticator_and_mapper_accept_non_send_non_clone_identities() {
    use std::rc::Rc;
    struct Identity(Rc<()>);
    let authenticator = |_: &http::request::Parts| async {
        Ok(AuthenticationAttempt::Authenticated(Identity(Rc::new(()))))
    };
    let mapped = authenticator.map(|identity: Identity| identity);
    let (parts, _) = http::Request::new(()).into_parts();
    match mapped.authenticate(&parts).await.unwrap() {
        AuthenticationAttempt::Authenticated(identity) => {
            assert_eq!(Rc::strong_count(&identity.0), 1)
        }
        _ => panic!("expected identity"),
    }
}
