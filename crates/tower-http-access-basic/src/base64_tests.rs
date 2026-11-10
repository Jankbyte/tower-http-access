use super::*;
use axum::{body::Body, extract::Request, http::HeaderValue};

fn parts(authorization: Option<HeaderValue>) -> Parts {
    let mut request = Request::new(Body::empty());
    if let Some(authorization) = authorization {
        request.headers_mut().insert(AUTHORIZATION, authorization);
    }
    request.into_parts().0
}

#[test]
fn extract_missing_authorization_returns_none() {
    assert!(extract_credentials(&parts(None)).unwrap().is_none());
}

#[test]
fn extract_other_scheme_returns_none() {
    let result =
        extract_credentials(&parts(Some(HeaderValue::from_static("Bearer token")))).unwrap();

    assert!(result.is_none());
}

#[test]
fn extract_basic_scheme_case_insensitively_preserves_colons_in_password() {
    let result = extract_credentials(&parts(Some(HeaderValue::from_static(
        "basic YWxleDpzZWNyZXQ6MTIz",
    ))))
    .unwrap();

    assert_eq!(
        result,
        Some(Credentials {
            username: "alex".to_owned(),
            password: "secret:123".to_owned(),
        })
    );
}

#[test]
fn extract_malformed_base64_returns_error() {
    let result = extract_credentials(&parts(Some(HeaderValue::from_static("Basic !!!"))));

    assert!(matches!(
        result,
        Err(BasicCredentialsError::InvalidBase64(_))
    ));
}

#[test]
fn extract_credentials_without_separator_returns_error() {
    let result = extract_credentials(&parts(Some(HeaderValue::from_static("Basic YWxleA=="))));

    assert!(matches!(
        result,
        Err(BasicCredentialsError::MissingSeparator)
    ));
}

#[test]
fn extract_basic_scheme_without_credentials_returns_error() {
    let result = extract_credentials(&parts(Some(HeaderValue::from_static("Basic"))));

    assert!(matches!(
        result,
        Err(BasicCredentialsError::MissingSeparator)
    ));
}
