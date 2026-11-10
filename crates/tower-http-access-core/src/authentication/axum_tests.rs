use super::*;
use ::axum::{body::Body, extract::Request};

#[tokio::test]
async fn authenticated_extractor_returns_wrapped_identity() {
    let (mut parts, _) = Request::new(Body::empty()).into_parts();
    parts
        .extensions
        .insert(Authenticated::new("alex".to_owned()));

    let authentication =
        <Authenticated<String> as FromRequestParts<()>>::from_request_parts(&mut parts, &())
            .await
            .unwrap();

    assert_eq!(authentication.into_inner(), "alex");
}

#[tokio::test]
async fn optional_authenticated_extractor_returns_none_for_anonymous_request() {
    let (mut parts, _) = Request::new(Body::empty()).into_parts();

    let authentication =
        <Authenticated<String> as OptionalFromRequestParts<()>>::from_request_parts(
            &mut parts,
            &(),
        )
        .await
        .unwrap();

    assert!(authentication.is_none());
}

#[tokio::test]
async fn authentication_error_converts_bytes_and_headers_into_axum_response() {
    use crate::authentication::AuthenticationErrorReason;
    use ::axum::http::StatusCode;
    use bytes::Bytes;

    let response = http::Response::builder()
        .status(StatusCode::UNAUTHORIZED)
        .header("www-authenticate", "Basic realm=\"Notes\"")
        .body(Bytes::from_static(b"invalid credentials"))
        .unwrap();
    let error =
        AuthenticatorError::with_response(AuthenticationErrorReason::WrongCredentials, response);
    let response = error.into_response();
    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    assert_eq!(
        response.headers()["www-authenticate"],
        "Basic realm=\"Notes\""
    );
    assert_eq!(
        ::axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap(),
        "invalid credentials"
    );
}
