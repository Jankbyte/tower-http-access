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
