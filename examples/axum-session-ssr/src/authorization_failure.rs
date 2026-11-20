use axum::http::{StatusCode, header, request::Parts};
use tower_http_access_core::{
    SecurityResponse,
    authorization::{
        AuthorizationDenial, AuthorizationFailure, AuthorizationFailureHandler,
        DefaultAuthorizationFailureHandler,
    },
};

/// Renders permission denials as HTML and preserves default handling for other failures.
#[derive(Clone, Copy)]
pub(crate) struct HtmlAuthorizationFailureHandler;

impl<E> AuthorizationFailureHandler<E> for HtmlAuthorizationFailureHandler {
    fn handle(&self, request: &Parts, failure: AuthorizationFailure<E>) -> SecurityResponse {
        match failure {
            AuthorizationFailure::Denied(AuthorizationDenial::InsufficientPermissions) => {
                let mut response = SecurityResponse::new(
                    r#"<!DOCTYPE html>
<html lang="en">
<head><meta charset="utf-8"><title>403 Forbidden</title></head>
<body>
    <h1>403 Forbidden</h1>
    <p>You do not have permission to access this page.</p>
    <a href="/me">Back to your account</a>
</body>
</html>"#
                        .into(),
                );
                *response.status_mut() = StatusCode::FORBIDDEN;
                response.headers_mut().insert(
                    header::CONTENT_TYPE,
                    "text/html; charset=utf-8".parse().unwrap(),
                );
                response
            }
            other => DefaultAuthorizationFailureHandler.handle(request, other),
        }
    }
}
